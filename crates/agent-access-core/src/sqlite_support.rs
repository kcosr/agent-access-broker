//! SQLite helpers shared by the managed store and the audit database: an
//! ordered migration catalog with checksums whose ledger must be a prefix of
//! the catalog, structural schema comparison against an expected in-memory
//! schema (including virtual-table shadow tables), and database file
//! permissions. Store-specific validation stays with each store.

use crate::fs_permissions;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(all(test, unix))]
pub(crate) mod lock_probe;

pub(crate) const SCHEMA_MIGRATIONS_TABLE: &str = "schema_migrations";

/// A failure every SQLite store maps into its own error type.
#[derive(Debug)]
pub(crate) enum SqliteAdmissionError {
    Unavailable(String),
    MigrationRequired,
    SchemaInvalid(String),
}

impl std::fmt::Display for SqliteAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "unavailable: {message}"),
            Self::MigrationRequired => formatter.write_str("migration is required"),
            Self::SchemaInvalid(message) => write!(formatter, "schema is invalid: {message}"),
        }
    }
}

/// How a store names itself in admission and comparison messages.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SqliteStoreLabel {
    /// For example `managed store`.
    pub(crate) name: &'static str,
    /// The message for a ledger that is not a prefix of the catalog, or for
    /// user objects without a ledger.
    pub(crate) incompatible_message: &'static str,
}

/// One catalog migration. `seed` runs in the migration's transaction after
/// `sql` (for data such as generated IDs); `structural_validation` runs after
/// it, before advancing from this migration, and whenever a fully migrated
/// database is admitted.
pub(crate) struct SqliteMigration<E> {
    pub(crate) version: &'static str,
    pub(crate) checksum: &'static str,
    pub(crate) sql: &'static str,
    pub(crate) seed: Option<SqliteSchemaStep<E>>,
    pub(crate) structural_validation: SqliteSchemaStep<E>,
}

/// A migration's seed or structural validation.
pub(crate) type SqliteSchemaStep<E> = fn(&Connection) -> Result<(), E>;

impl<E> Clone for SqliteMigration<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for SqliteMigration<E> {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedMigration {
    version: String,
    checksum: String,
}

#[derive(Debug)]
pub(crate) enum ValidatedLedger {
    EmptyDatabase,
    Prefix(usize),
}

enum MigrationApplyResult {
    Applied(String),
    Reclassify,
    /// Another connection held the write lock for the whole busy timeout.
    Busy,
}

/// Admits `conn` against `migrations`: validates that its ledger is a prefix
/// of the catalog, applies pending migrations one transaction at a time when
/// `allow_migration` is set (otherwise pending migrations fail with
/// `MigrationRequired`). Validates each applied schema before advancing it and
/// each resulting schema afterward, including the latest schema on admission.
/// Returns the versions this call applied.
pub(crate) fn admit_schema<E: From<SqliteAdmissionError>>(
    conn: &Connection,
    migrations: &[SqliteMigration<E>],
    label: SqliteStoreLabel,
    allow_migration: bool,
) -> Result<BTreeSet<String>, E> {
    let latest = migrations.last().ok_or_else(|| {
        SqliteAdmissionError::SchemaInvalid("migration catalog is empty".to_string())
    })?;
    let mut applied_migrations = BTreeSet::new();
    let mut busy_at_applied_len = None;
    loop {
        let applied_len = match read_validated_ledger(conn, migrations, label)? {
            ValidatedLedger::EmptyDatabase => 0,
            ValidatedLedger::Prefix(applied_len) => applied_len,
        };
        if applied_len == migrations.len() {
            (latest.structural_validation)(conn)?;
            return Ok(applied_migrations);
        }
        if !allow_migration {
            return Err(SqliteAdmissionError::MigrationRequired.into());
        }
        match apply_next_migration(conn, migrations, label, applied_len)? {
            MigrationApplyResult::Applied(version) => {
                applied_migrations.insert(version);
            }
            MigrationApplyResult::Reclassify => {}
            MigrationApplyResult::Busy => {
                // A concurrent initializer commits one migration per write
                // transaction; keep waiting only while its ledger advances.
                if busy_at_applied_len == Some(applied_len) {
                    return Err(SqliteAdmissionError::Unavailable(format!(
                        "failed to begin {} migration {}: database is locked (ledger remained at {applied_len} applied migrations)",
                        label.name, migrations[applied_len].version,
                    ))
                    .into());
                }
                busy_at_applied_len = Some(applied_len);
            }
        }
    }
}

pub(crate) fn read_validated_ledger<E: From<SqliteAdmissionError>>(
    conn: &Connection,
    migrations: &[SqliteMigration<E>],
    label: SqliteStoreLabel,
) -> Result<ValidatedLedger, E> {
    if !conn.is_autocommit() {
        return Ok(read_validated_ledger_snapshot(conn, migrations, label)
            .map_err(|error| ledger_read_error(error, label))?);
    }
    // Classify against one snapshot: another initializer may publish the complete
    // baseline between the ledger-presence and user-object queries.
    let tx = conn.unchecked_transaction().map_err(|error| {
        SqliteAdmissionError::Unavailable(format!(
            "failed to begin {} migration ledger snapshot: {error}",
            label.name
        ))
    })?;
    let result = read_validated_ledger_snapshot(&tx, migrations, label)
        .map_err(|error| ledger_read_error(error, label))?;
    tx.commit().map_err(|error| {
        SqliteAdmissionError::Unavailable(format!(
            "failed to finish {} migration ledger snapshot: {error}",
            label.name
        ))
    })?;
    // End the read transaction before admission starts an immediate write transaction.
    Ok(result)
}

fn ledger_read_error(error: SqliteAdmissionError, label: SqliteStoreLabel) -> SqliteAdmissionError {
    match error {
        SqliteAdmissionError::Unavailable(message) => SqliteAdmissionError::Unavailable(format!(
            "failed to read {} migration ledger: {message}",
            label.name
        )),
        other => other,
    }
}

fn read_validated_ledger_snapshot<E>(
    conn: &Connection,
    migrations: &[SqliteMigration<E>],
    label: SqliteStoreLabel,
) -> Result<ValidatedLedger, SqliteAdmissionError> {
    debug_assert!(!conn.is_autocommit());
    if !migrations_table_exists(conn)? {
        if user_sqlite_objects_exist(conn)? {
            return Err(incompatible_error(label));
        }
        return Ok(ValidatedLedger::EmptyDatabase);
    }
    let rows = read_migration_rows(conn, label)?;
    if rows.is_empty() {
        return Err(incompatible_error(label));
    }
    for (row, migration) in rows.iter().zip(migrations) {
        if row.version != migration.version {
            return Err(incompatible_error(label));
        }
        if row.checksum != migration.checksum {
            return Err(SqliteAdmissionError::SchemaInvalid(format!(
                "{} migration checksum mismatch",
                label.name
            )));
        }
    }
    if rows.len() > migrations.len() {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} schema includes migrations newer than this broker supports; preserve the database and use a compatible broker binary or restore a matching pre-upgrade backup",
            label.name
        )));
    }
    Ok(ValidatedLedger::Prefix(rows.len()))
}

fn incompatible_error(label: SqliteStoreLabel) -> SqliteAdmissionError {
    SqliteAdmissionError::SchemaInvalid(label.incompatible_message.to_string())
}

fn apply_next_migration<E: From<SqliteAdmissionError>>(
    conn: &Connection,
    migrations: &[SqliteMigration<E>],
    label: SqliteStoreLabel,
    expected_applied_len: usize,
) -> Result<MigrationApplyResult, E> {
    if let Err(error) = conn.execute_batch("BEGIN IMMEDIATE") {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) {
            return Ok(MigrationApplyResult::Busy);
        }
        return Err(SqliteAdmissionError::Unavailable(format!(
            "failed to begin {} migration transaction: {error}",
            label.name
        ))
        .into());
    }
    let result = (|| -> Result<MigrationApplyResult, E> {
        let actual_applied_len = match read_validated_ledger(conn, migrations, label)? {
            ValidatedLedger::EmptyDatabase => 0,
            ValidatedLedger::Prefix(applied_len) => applied_len,
        };
        if actual_applied_len > expected_applied_len {
            return Ok(MigrationApplyResult::Reclassify);
        }
        if actual_applied_len != expected_applied_len {
            return Err(SqliteAdmissionError::MigrationRequired.into());
        }
        let Some(migration) = migrations.get(actual_applied_len) else {
            return Ok(MigrationApplyResult::Reclassify);
        };
        if let Some(previous) = actual_applied_len
            .checked_sub(1)
            .and_then(|index| migrations.get(index))
        {
            // Validate under the write lock before a rebuild can discard evidence
            // of unsupported schema changes. Keep the resulting-schema check too.
            (previous.structural_validation)(conn)?;
        }
        conn.execute_batch(migration.sql).map_err(|_| {
            SqliteAdmissionError::SchemaInvalid(format!("{} migration failed", label.name))
        })?;
        if let Some(seed) = migration.seed {
            seed(conn)?;
        }
        run_foreign_key_check(conn, label)?;
        (migration.structural_validation)(conn)?;
        conn.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at)
             VALUES (?1, ?2, ?3)",
            params![
                migration.version,
                migration.checksum,
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .map_err(|error| {
            SqliteAdmissionError::Unavailable(format!(
                "failed to record {} migration {}: {error}",
                label.name, migration.version
            ))
        })?;
        Ok(MigrationApplyResult::Applied(migration.version.to_string()))
    })();
    match result {
        Ok(MigrationApplyResult::Applied(version)) => {
            conn.execute_batch("COMMIT").map_err(|error| {
                SqliteAdmissionError::Unavailable(format!(
                    "failed to commit {} migration {version}: {error}",
                    label.name
                ))
            })?;
            Ok(MigrationApplyResult::Applied(version))
        }
        Ok(outcome @ (MigrationApplyResult::Reclassify | MigrationApplyResult::Busy)) => {
            rollback_migration_transaction(conn);
            Ok(outcome)
        }
        Err(error) => {
            rollback_migration_transaction(conn);
            Err(error)
        }
    }
}

fn rollback_migration_transaction(conn: &Connection) {
    let _ = conn.execute_batch("ROLLBACK");
}

/// The checksum of an ordered catalog: the SHA-256 of its migration
/// checksums joined by `:`.
pub(crate) fn catalog_checksum<E>(migrations: &[SqliteMigration<E>]) -> String {
    sha256_hex(
        migrations
            .iter()
            .map(|migration| migration.checksum)
            .collect::<Vec<_>>()
            .join(":")
            .as_bytes(),
    )
}

pub(crate) fn migrations_table_exists(conn: &Connection) -> Result<bool, SqliteAdmissionError> {
    sqlite_object_exists(conn, "table", SCHEMA_MIGRATIONS_TABLE)
}

pub(crate) fn sqlite_object_exists(
    conn: &Connection,
    object_type: &str,
    name: &str,
) -> Result<bool, SqliteAdmissionError> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    Ok(exists.is_some())
}

fn read_migration_rows(
    conn: &Connection,
    label: SqliteStoreLabel,
) -> Result<Vec<AppliedMigration>, SqliteAdmissionError> {
    let malformed = || {
        SqliteAdmissionError::SchemaInvalid(format!("{} migration ledger is malformed", label.name))
    };
    let mut statement = conn
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .map_err(|_| malformed())?;
    let rows = statement
        .query_map([], |row| {
            Ok(AppliedMigration {
                version: row.get(0)?,
                checksum: row.get(1)?,
            })
        })
        .map_err(|_| malformed())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|_| malformed())
}

fn user_sqlite_objects_exist(conn: &Connection) -> Result<bool, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type IN ('table', 'index', 'view', 'trigger')
               AND name NOT LIKE 'sqlite_%'
             LIMIT 1",
        )
        .map_err(sql_unavailable)?;
    let object: Option<String> = statement
        .query_row([], |row| row.get(0))
        .optional()
        .map_err(sql_unavailable)?;
    Ok(object.is_some())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SqliteObject {
    object_type: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColumnInfo {
    pub(crate) cid: i64,
    pub(crate) name: String,
    pub(crate) column_type: String,
    pub(crate) not_null: bool,
    pub(crate) default_value: Option<String>,
    pub(crate) primary_key_position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ForeignKeyInfo {
    id: i64,
    seq: i64,
    table: String,
    from: String,
    to: String,
    on_update: String,
    on_delete: String,
    match_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IndexSignature {
    name: Option<String>,
    unique: bool,
    origin: String,
    partial: bool,
    columns: Vec<String>,
}

/// Compares every user table, index, view, and trigger of `actual` with
/// `expected` by name, then each table's columns, foreign keys, indexes, and
/// normalized `CREATE` SQL. Virtual tables and their shadow tables are
/// ordinary `sqlite_master` tables and are compared the same way.
pub(crate) fn compare_schema(
    actual: &Connection,
    expected: &Connection,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    compare_sqlite_user_objects(actual, expected, label)?;
    for table in schema_table_names(expected)? {
        compare_table_info(actual, expected, &table, label)?;
        compare_foreign_keys(actual, expected, &table, label)?;
        compare_indexes(actual, expected, &table, label)?;
        compare_table_sql(actual, expected, &table, label)?;
    }
    Ok(())
}

fn schema_table_names(conn: &Connection) -> Result<Vec<String>, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table'
               AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn compare_sqlite_user_objects(
    actual: &Connection,
    expected: &Connection,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    let actual_objects = user_sqlite_objects(actual)?;
    let expected_objects = user_sqlite_objects(expected)?;
    if actual_objects != expected_objects {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} contains unexpected or missing SQLite objects",
            label.name
        )));
    }
    Ok(())
}

fn user_sqlite_objects(conn: &Connection) -> Result<BTreeSet<SqliteObject>, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master
             WHERE type IN ('table', 'index', 'view', 'trigger')
               AND name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok(SqliteObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
            })
        })
        .map_err(sql_unavailable)?;
    Ok(collect_rows(rows)?.into_iter().collect())
}

fn compare_table_info(
    actual: &Connection,
    expected: &Connection,
    table: &str,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    if table_info(actual, table)? != table_info(expected, table)? {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} table {table} has an invalid column layout",
            label.name
        )));
    }
    Ok(())
}

pub(crate) fn table_info(
    conn: &Connection,
    table: &str,
) -> Result<Vec<ColumnInfo>, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok(ColumnInfo {
                cid: row.get(0)?,
                name: row.get(1)?,
                column_type: row.get(2)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default_value: row.get(4)?,
                primary_key_position: row.get(5)?,
            })
        })
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn compare_foreign_keys(
    actual: &Connection,
    expected: &Connection,
    table: &str,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    if foreign_keys(actual, table)? != foreign_keys(expected, table)? {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} table {table} has invalid foreign keys",
            label.name
        )));
    }
    Ok(())
}

fn foreign_keys(
    conn: &Connection,
    table: &str,
) -> Result<Vec<ForeignKeyInfo>, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(&format!("PRAGMA foreign_key_list({table})"))
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok(ForeignKeyInfo {
                id: row.get(0)?,
                seq: row.get(1)?,
                table: row.get(2)?,
                from: row.get(3)?,
                to: row.get(4)?,
                on_update: row.get(5)?,
                on_delete: row.get(6)?,
                match_clause: row.get(7)?,
            })
        })
        .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn compare_indexes(
    actual: &Connection,
    expected: &Connection,
    table: &str,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    if index_signatures(actual, table)? != index_signatures(expected, table)? {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} table {table} has invalid indexes",
            label.name
        )));
    }
    Ok(())
}

fn index_signatures(
    conn: &Connection,
    table: &str,
) -> Result<Vec<IndexSignature>, SqliteAdmissionError> {
    let mut statement = conn
        .prepare(&format!("PRAGMA index_list({table})"))
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? != 0,
            ))
        })
        .map_err(sql_unavailable)?;
    let mut signatures = Vec::new();
    for row in rows {
        let (name, unique, origin, partial) = row.map_err(sql_unavailable)?;
        let mut columns_statement = conn
            .prepare(&format!("PRAGMA index_info({name})"))
            .map_err(sql_unavailable)?;
        let column_rows = columns_statement
            .query_map([], |row| row.get::<_, String>(2))
            .map_err(sql_unavailable)?;
        let columns = collect_rows(column_rows)?;
        signatures.push(IndexSignature {
            name: if name.starts_with("sqlite_autoindex_") {
                None
            } else {
                Some(name)
            },
            unique,
            origin,
            partial,
            columns,
        });
    }
    signatures.sort();
    Ok(signatures)
}

fn compare_table_sql(
    actual: &Connection,
    expected: &Connection,
    table: &str,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    if normalized_object_sql(actual, "table", table, label)?
        != normalized_object_sql(expected, "table", table, label)?
    {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} table {table} has invalid constraints",
            label.name
        )));
    }
    Ok(())
}

/// The `CREATE` SQL of a named object, lowercased with whitespace removed.
pub(crate) fn normalized_object_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    label: SqliteStoreLabel,
) -> Result<String, SqliteAdmissionError> {
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    let Some(sql) = sql else {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} {object_type} {name} is missing",
            label.name
        )));
    };
    Ok(normalize_sql(&sql))
}

fn normalize_sql(sql: &str) -> String {
    sql.to_ascii_lowercase()
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

/// `PRAGMA foreign_key_check`; any violation is a schema failure.
pub(crate) fn run_foreign_key_check(
    conn: &Connection,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    let mut statement = conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(sql_unavailable)?;
    let mut rows = statement.query([]).map_err(sql_unavailable)?;
    if rows.next().map_err(sql_unavailable)?.is_some() {
        return Err(SqliteAdmissionError::SchemaInvalid(format!(
            "{} foreign key check failed",
            label.name
        )));
    }
    Ok(())
}

/// `PRAGMA quick_check`. Its cost grows with the database size.
pub(crate) fn run_quick_check(
    conn: &Connection,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    let mut statement = conn
        .prepare("PRAGMA quick_check")
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sql_unavailable)?;
    for row in rows {
        if row.map_err(sql_unavailable)? != "ok" {
            return Err(SqliteAdmissionError::SchemaInvalid(format!(
                "{} quick check failed",
                label.name
            )));
        }
    }
    Ok(())
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>, SqliteAdmissionError> {
    rows.collect::<Result<Vec<_>, _>>().map_err(sql_unavailable)
}

pub(crate) fn sql_unavailable(error: rusqlite::Error) -> SqliteAdmissionError {
    SqliteAdmissionError::Unavailable(error.to_string())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_digest(digest.finalize())
}

pub(crate) fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Restricts the database file and its `-wal`/`-shm` sidecars that exist to
/// owner-only regular files, without following symlinks. A missing database
/// is left for SQLite's open to report.
///
/// This never opens the files: SQLite connections in this process may have
/// them open, and closing any other descriptor for them would release the
/// POSIX locks those connections hold (see
/// [`fs_permissions::restrict_private_file_by_path`]).
pub(crate) fn restrict_sqlite_files(
    path: &Path,
    label: SqliteStoreLabel,
) -> Result<(), SqliteAdmissionError> {
    match fs_permissions::restrict_private_file_by_path(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(SqliteAdmissionError::Unavailable(format!(
                "failed to restrict {} file {}: {error}",
                label.name,
                path.display()
            )));
        }
        _ => {}
    }
    for sidecar in sqlite_sidecar_paths(path) {
        if let Err(error) = fs_permissions::restrict_private_file_by_path(&sidecar) {
            // Another connection closing the database may unlink its
            // sidecars at any time; one that is gone needs no restriction.
            if error.kind() == std::io::ErrorKind::NotFound
                || matches!(
                    std::fs::symlink_metadata(&sidecar),
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound
                )
            {
                continue;
            }
            return Err(SqliteAdmissionError::Unavailable(format!(
                "failed to restrict {} sidecar {}: {error}",
                label.name,
                sidecar.display()
            )));
        }
    }
    Ok(())
}

/// The `-wal` and `-shm` sidecar paths of the database at `path`.
pub(crate) fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    [PathBuf::from(wal), PathBuf::from(shm)]
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;
    use tempfile::TempDir;

    // A deadlock watchdog, not an assertion about migration execution speed.
    const WATCHDOG: Duration = Duration::from_secs(30);
    type Gate = (Sender<()>, Receiver<()>);
    thread_local! {
        // SQLite's callbacks cannot capture state. Per-thread gates keep the
        // interleaving independent of other tests and elapsed wall time.
        static SEED_GATE: RefCell<Option<Gate>> = const { RefCell::new(None) };
        static WRITE_LOCK_GATE: RefCell<Option<Gate>> = const { RefCell::new(None) };
    }

    const LABEL: SqliteStoreLabel = SqliteStoreLabel {
        name: "test database",
        incompatible_message: "test database is incompatible",
    };
    const SCHEMA: &str = "
        CREATE TABLE schema_migrations (
            version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL
        );
        CREATE TABLE seeded_items (id INTEGER PRIMARY KEY);
    ";
    const MIGRATIONS: &[SqliteMigration<SqliteAdmissionError>] = &[SqliteMigration {
        version: "001_seeded_items",
        checksum: "test-checksum",
        sql: SCHEMA,
        seed: Some(seed_and_wait),
        structural_validation: validate_structure,
    }];

    fn seed_and_wait(conn: &Connection) -> Result<(), SqliteAdmissionError> {
        conn.execute("INSERT INTO seeded_items(id) VALUES (1)", [])
            .map_err(sql_unavailable)?;
        SEED_GATE.with(|slot| {
            let (entered, released) = slot
                .borrow_mut()
                .take()
                .expect("only the first initializer may run the seed");
            entered.send(()).unwrap();
            released
                .recv_timeout(WATCHDOG)
                .expect("migration seed was not released");
        });
        Ok(())
    }

    fn validate_structure(conn: &Connection) -> Result<(), SqliteAdmissionError> {
        let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
        expected.execute_batch(SCHEMA).map_err(sql_unavailable)?;
        compare_schema(conn, &expected, LABEL)
    }

    #[test]
    fn concurrent_admission_rechecks_ledger_after_waiting_for_writer() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let writer = Connection::open(&path).unwrap();
        // Isolate migration admission from the separate journal-mode transition.
        writer.execute_batch("PRAGMA journal_mode = WAL").unwrap();
        let waiter = Connection::open(&path).unwrap();
        let (seed_entered, seed_ready) = channel();
        // These release senders stay in the test: unwinding drops them and
        // releases any worker still waiting at a gate.
        let (release_seed, seed_released) = channel();
        let (first_finished, first_done) = channel();
        let first = std::thread::spawn(move || {
            SEED_GATE.with(|slot| *slot.borrow_mut() = Some((seed_entered, seed_released)));
            let result = admit_schema(&writer, MIGRATIONS, LABEL, true);
            drop(writer);
            let _ = first_finished.send(());
            result
        });
        seed_ready
            .recv_timeout(WATCHDOG)
            .expect("first initializer did not enter its migration seed");

        let (write_blocked, write_ready) = channel();
        let (release_write, write_released) = channel();
        let (second_finished, second_done) = channel();
        let second = std::thread::spawn(move || {
            WRITE_LOCK_GATE.with(|slot| {
                *slot.borrow_mut() = Some((write_blocked, write_released));
            });
            waiter
                .busy_handler(Some(|_| {
                    WRITE_LOCK_GATE.with(|slot| {
                        let Some((blocked, released)) = slot.borrow_mut().take() else {
                            return false;
                        };
                        blocked.send(()).is_ok() && released.recv_timeout(WATCHDOG).is_ok()
                    })
                }))
                .unwrap();
            let result = admit_schema(&waiter, MIGRATIONS, LABEL, true);
            drop(waiter);
            let _ = second_finished.send(());
            result
        });
        // The second initializer has classified the uncommitted schema as empty
        // and reached BEGIN IMMEDIATE. Publish the first migration before its
        // write-lock attempt resumes, forcing reclassification under that lock.
        write_ready
            .recv_timeout(WATCHDOG)
            .expect("second initializer did not wait for the migration write lock");
        release_seed.send(()).unwrap();
        first_done
            .recv_timeout(WATCHDOG)
            .expect("first initializer did not finish and close its connection");
        let first_applied = first.join().unwrap().unwrap();
        release_write.send(()).unwrap();
        second_done
            .recv_timeout(WATCHDOG)
            .expect("second initializer did not finish and close its connection");
        let second_applied = second.join().unwrap().unwrap();
        assert_eq!(
            first_applied,
            BTreeSet::from([MIGRATIONS[0].version.to_string()])
        );
        assert!(second_applied.is_empty());

        let conn = Connection::open(&path).unwrap();
        assert_eq!(read_migration_rows(&conn, LABEL).unwrap().len(), 1);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM seeded_items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const LABEL: SqliteStoreLabel = SqliteStoreLabel {
        name: "test database",
        incompatible_message: "test database is incompatible",
    };

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn restricting_sqlite_files_repairs_modes_without_releasing_sqlite_locks() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("live.sqlite");
        let conn = Connection::open(&path).unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY); INSERT INTO items DEFAULT VALUES;",
        )
        .unwrap();
        lock_probe::assert_sqlite_locks_held(&path, "opening the connection");
        let files = std::iter::once(path.clone())
            .chain(sqlite_sidecar_paths(&path))
            .collect::<Vec<_>>();
        for file in &files {
            fs::set_permissions(file, fs::Permissions::from_mode(0o644)).unwrap();
        }

        restrict_sqlite_files(&path, LABEL).unwrap();

        for file in &files {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }
        lock_probe::assert_sqlite_locks_held(&path, "restricting the database files");
        conn.execute("INSERT INTO items DEFAULT VALUES", [])
            .unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn restricting_sqlite_files_skips_missing_files_and_refuses_linked_sidecars() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("store.sqlite");
        // Nothing exists yet: SQLite's open reports a missing database.
        restrict_sqlite_files(&path, LABEL).unwrap();

        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        restrict_sqlite_files(&path, LABEL).unwrap();
        assert_eq!(mode(&path), 0o600);

        let [wal, shm] = sqlite_sidecar_paths(&path);
        let target = temp.path().join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, &wal).unwrap();
        let Err(SqliteAdmissionError::Unavailable(message)) = restrict_sqlite_files(&path, LABEL)
        else {
            panic!("a symlinked sidecar must be refused");
        };
        assert!(
            message.starts_with("failed to restrict test database sidecar"),
            "{message}"
        );
        assert_eq!(mode(&target), 0o644);

        fs::remove_file(&wal).unwrap();
        fs::hard_link(&target, &shm).unwrap();
        let Err(SqliteAdmissionError::Unavailable(message)) = restrict_sqlite_files(&path, LABEL)
        else {
            panic!("a hard-linked sidecar must be refused");
        };
        assert!(
            message.ends_with("sensitive file must not have multiple hard links"),
            "{message}"
        );
        assert_eq!(mode(&target), 0o644);
    }
}
