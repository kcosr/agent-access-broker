//! Audit database files, schema admission, and offline verification.
//!
//! The broker creates the database file owner-only before SQLite opens it
//! (SQLite is never allowed to create it), opens it without following
//! symlinks, sets `auto_vacuum = INCREMENTAL` and `journal_mode = WAL`
//! outside any transaction before the first migration, and admits the
//! migration ledger. Open-time validation is catalog-level only: it never
//! runs `quick_check`, `integrity_check`, or `foreign_key_check` (which runs
//! only right after a migration), whose cost grows with the database size.
//!
//! File permissions are enforced by path, never through a descriptor of an
//! existing database or sidecar: the writer and reader connections of this
//! and earlier runtime generations may have the files open, and closing any
//! other descriptor for them would release their SQLite locks.

use super::super::AuditOpenMode;
use crate::fs_permissions;
use crate::sqlite_support::{self, SqliteAdmissionError, SqliteMigration, SqliteStoreLabel};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub(super) const AUDIT_BASELINE_VERSION: &str = "001_audit_baseline";
const AUDIT_BASELINE_SQL: &str = include_str!("baseline.sql");
const AUDIT_BASELINE_CHECKSUM: &str =
    "997b0c4b0685353e58875b20d768b54a95408e8bd60bb76f4dca042f139c6de3";
const DATABASE_ID_KEY: &str = "database_id";
/// `PRAGMA auto_vacuum` reports 2 for `INCREMENTAL`.
const AUTO_VACUUM_INCREMENTAL: i64 = 2;

pub(super) const AUDIT_DATABASE_LABEL: SqliteStoreLabel = SqliteStoreLabel {
    name: "audit database",
    incompatible_message: "audit database has an unknown or unrelated schema; the broker never resets or deletes audit data, so point audit.path at a new file or restore the database this broker created",
};

type AuditMigration = SqliteMigration<SqliteAdmissionError>;

const AUDIT_MIGRATIONS: &[AuditMigration] = &[AuditMigration {
    version: AUDIT_BASELINE_VERSION,
    checksum: AUDIT_BASELINE_CHECKSUM,
    sql: AUDIT_BASELINE_SQL,
    seed: Some(seed_database_id),
    structural_validation: validate_baseline_structure,
}];

/// The open flags of every writer and verification connection: never
/// create the file, never follow a symlink.
pub(super) fn audit_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

/// The device and inode of the opened database file, to detect a path that
/// no longer names the database the writer has open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    pub(super) fn of(path: &Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(Self { dev: 0, ino: 0 })
        }
    }
}

pub(super) struct OpenedAuditDatabase {
    pub(super) conn: Connection,
    pub(super) database_id: String,
    /// Whether this open created the database file.
    pub(super) created: bool,
    pub(super) identity: FileIdentity,
}

/// Opens (and at startup creates and migrates) the audit database at
/// `path`. Reload admission never creates or migrates a database.
pub(super) fn open_audit_database(
    path: &Path,
    mode: AuditOpenMode,
) -> Result<OpenedAuditDatabase, String> {
    let label = path.display();
    catalog_is_valid()?;
    let existed = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("failed to inspect audit database {label}: {error}")),
    };
    match mode {
        AuditOpenMode::Startup => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs_permissions::ensure_private_dir(parent).map_err(|error| {
                    format!(
                        "failed to create audit database directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            fs_permissions::ensure_private_file_by_path(path)
                .map_err(|error| format!("failed to create audit database {label}: {error}"))?;
        }
        AuditOpenMode::Reload => {
            fs_permissions::validate_private_parent(path).map_err(|error| {
                format!("failed to validate audit database directory for {label}: {error}")
            })?;
            if !existed {
                return Err(format!(
                    "audit database {label} does not exist; reload never creates or migrates an audit database, so restart the broker to create it"
                ));
            }
        }
    }
    restrict_files(path)?;
    let conn = Connection::open_with_flags(path, audit_open_flags())
        .map_err(|error| format!("failed to open audit database {label}: {error}"))?;
    #[cfg(test)]
    super::tests::trace_if_requested(path, &conn);
    conn.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;")
        .map_err(|error| format!("failed to initialize audit database connection: {error}"))?;
    if mode == AuditOpenMode::Startup {
        // Both must be set outside a transaction, before the first migration
        // creates a table. On an existing database they change nothing.
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")
            .map_err(|error| format!("failed to set audit database auto_vacuum: {error}"))?;
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|error| format!("failed to set audit database journal_mode: {error}"))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(format!(
                "audit database journal_mode is {journal_mode}, expected wal"
            ));
        }
    }
    restrict_files(path)?;
    sqlite_support::admit_schema(
        &conn,
        AUDIT_MIGRATIONS,
        AUDIT_DATABASE_LABEL,
        mode == AuditOpenMode::Startup,
    )
    .map_err(|error| admission_message(error, mode))?;
    check_database_settings(&conn)?;
    let database_id = read_database_id(&conn).map_err(|error| error.to_string())?;
    restrict_files(path)?;
    let identity = FileIdentity::of(path)
        .map_err(|error| format!("failed to inspect audit database {label}: {error}"))?;
    Ok(OpenedAuditDatabase {
        conn,
        database_id,
        created: !existed,
        identity,
    })
}

fn admission_message(error: SqliteAdmissionError, mode: AuditOpenMode) -> String {
    match (error, mode) {
        (SqliteAdmissionError::MigrationRequired, AuditOpenMode::Reload) => {
            "audit database needs a migration; reload never migrates an audit database, so restart the broker to migrate it".to_string()
        }
        (SqliteAdmissionError::MigrationRequired, AuditOpenMode::Startup) => {
            "audit database needs a migration".to_string()
        }
        (SqliteAdmissionError::SchemaInvalid(message), _) => {
            format!("audit database schema is invalid: {message}")
        }
        (SqliteAdmissionError::Unavailable(message), _) => message,
    }
}

fn catalog_is_valid() -> Result<(), String> {
    for migration in AUDIT_MIGRATIONS {
        if migration.checksum != sqlite_support::sha256_hex(migration.sql.as_bytes()) {
            return Err(format!(
                "audit database migration {} checksum is invalid",
                migration.version
            ));
        }
    }
    if AUDIT_MIGRATIONS
        .windows(2)
        .any(|pair| pair[0].version >= pair[1].version)
    {
        return Err("audit database migration order is invalid".to_string());
    }
    Ok(())
}

pub(super) fn restrict_files(path: &Path) -> Result<(), String> {
    sqlite_support::restrict_sqlite_files(path, AUDIT_DATABASE_LABEL).map_err(|error| match error {
        SqliteAdmissionError::Unavailable(message)
        | SqliteAdmissionError::SchemaInvalid(message) => message,
        SqliteAdmissionError::MigrationRequired => error.to_string(),
    })
}

fn seed_database_id(conn: &Connection) -> Result<(), SqliteAdmissionError> {
    conn.execute(
        "INSERT INTO audit_meta(key, value) VALUES (?1, ?2)",
        params![DATABASE_ID_KEY, Uuid::new_v4().to_string()],
    )
    .map_err(sqlite_support::sql_unavailable)?;
    Ok(())
}

/// The baseline schema compared object by object with the expected schema,
/// including the full-text index's shadow tables and the normalized SQL of
/// every index and trigger, plus a well-formed `database_id`.
fn validate_baseline_structure(conn: &Connection) -> Result<(), SqliteAdmissionError> {
    let expected = Connection::open_in_memory().map_err(sqlite_support::sql_unavailable)?;
    expected
        .execute_batch(AUDIT_BASELINE_SQL)
        .map_err(sqlite_support::sql_unavailable)?;
    sqlite_support::compare_schema(conn, &expected, AUDIT_DATABASE_LABEL)?;
    let mut statement = expected
        .prepare(
            "SELECT type, name FROM sqlite_master
             WHERE type IN ('index', 'trigger') AND sql IS NOT NULL
             ORDER BY type, name",
        )
        .map_err(sqlite_support::sql_unavailable)?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_support::sql_unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_support::sql_unavailable)?;
    for (object_type, name) in objects {
        if sqlite_support::normalized_object_sql(conn, &object_type, &name, AUDIT_DATABASE_LABEL)?
            != sqlite_support::normalized_object_sql(
                &expected,
                &object_type,
                &name,
                AUDIT_DATABASE_LABEL,
            )?
        {
            return Err(SqliteAdmissionError::SchemaInvalid(format!(
                "audit database {object_type} {name} has an invalid definition"
            )));
        }
    }
    read_database_id(conn).map(|_| ())
}

fn read_database_id(conn: &Connection) -> Result<String, SqliteAdmissionError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM audit_meta WHERE key = ?1",
            params![DATABASE_ID_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_support::sql_unavailable)?;
    let Some(value) = value else {
        return Err(SqliteAdmissionError::SchemaInvalid(
            "audit database has no database_id".to_string(),
        ));
    };
    match Uuid::try_parse(&value) {
        Ok(uuid) if uuid.hyphenated().to_string() == value => Ok(value),
        _ => Err(SqliteAdmissionError::SchemaInvalid(
            "audit database database_id is malformed".to_string(),
        )),
    }
}

/// `journal_mode = wal` and `auto_vacuum = incremental`.
fn check_database_settings(conn: &Connection) -> Result<(), String> {
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| format!("failed to read audit database journal_mode: {error}"))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(format!(
            "audit database journal_mode is {journal_mode}, expected wal"
        ));
    }
    let auto_vacuum: i64 = conn
        .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
        .map_err(|error| format!("failed to read audit database auto_vacuum: {error}"))?;
    if auto_vacuum != AUTO_VACUUM_INCREMENTAL {
        return Err(format!(
            "audit database auto_vacuum is {auto_vacuum}, expected incremental ({AUTO_VACUUM_INCREMENTAL})"
        ));
    }
    Ok(())
}

/// The result of `agent-access-broker audit verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    /// The database's `database_id`, when it could be read.
    pub database_id: Option<String>,
    /// Each check in the order it ran.
    pub checks: Vec<AuditVerifyCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyCheck {
    /// `schema`, `integrity_check`, or `fts_integrity_check`.
    pub name: &'static str,
    /// Empty when the check passed.
    pub problems: Vec<String>,
}

impl AuditVerifyReport {
    pub fn is_ok(&self) -> bool {
        self.checks.iter().all(|check| check.problems.is_empty())
    }
}

/// Verifies the SQLite audit database at `path` offline: the catalog-level
/// admission checks (without migrating), `PRAGMA integrity_check`, and the
/// full-text index's `integrity-check` command. The caller must hold the
/// audit state lock. Fails only when the database cannot be opened.
pub fn verify_sqlite_audit_database(path: &Path) -> Result<AuditVerifyReport, String> {
    let label = path.display();
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("audit database {label} must not be a symlink"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("audit database {label} does not exist"));
        }
        Err(error) => return Err(format!("failed to inspect audit database {label}: {error}")),
    }
    let conn = Connection::open_with_flags(path, audit_open_flags())
        .map_err(|error| format!("failed to open audit database {label}: {error}"))?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")
        .map_err(|error| format!("failed to initialize audit database connection: {error}"))?;
    let mut checks = Vec::new();

    let mut schema_problems = Vec::new();
    if let Err(error) =
        sqlite_support::admit_schema(&conn, AUDIT_MIGRATIONS, AUDIT_DATABASE_LABEL, false)
    {
        schema_problems.push(admission_message(error, AuditOpenMode::Reload));
    }
    if let Err(message) = check_database_settings(&conn) {
        schema_problems.push(message);
    }
    let database_id = read_database_id(&conn).ok();
    checks.push(AuditVerifyCheck {
        name: "schema",
        problems: schema_problems,
    });

    let integrity = (|| -> rusqlite::Result<Vec<String>> {
        let mut statement = conn.prepare("PRAGMA integrity_check")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().filter(|row| row != "ok").collect())
    })();
    checks.push(AuditVerifyCheck {
        name: "integrity_check",
        problems: integrity.unwrap_or_else(|error| vec![error.to_string()]),
    });

    // For a contentless table, rank 0 checks the index's internal
    // consistency; there is no content to compare it with.
    let fts = conn.execute(
        "INSERT INTO audit_events_fts(audit_events_fts, rank) VALUES ('integrity-check', 0)",
        [],
    );
    checks.push(AuditVerifyCheck {
        name: "fts_integrity_check",
        problems: fts
            .err()
            .map(|error| error.to_string())
            .into_iter()
            .collect(),
    });
    Ok(AuditVerifyReport {
        database_id,
        checks,
    })
}

/// An empty database with the baseline schema and no statistics.
#[cfg(test)]
pub(super) fn baseline_schema_in_memory() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(AUDIT_BASELINE_SQL).unwrap();
    conn
}

#[cfg(test)]
pub(super) fn baseline_checksum_matches() -> (String, &'static str) {
    (
        sqlite_support::sha256_hex(AUDIT_BASELINE_SQL.as_bytes()),
        AUDIT_BASELINE_CHECKSUM,
    )
}
