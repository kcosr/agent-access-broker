//! Helpers for tests in this and dependent crates.

use crate::{AuditQueryLimits, AuditStoreType};
use serde_json::Value;
use std::path::Path;

/// Overrides the reader-pool limits (connections, waiting queries, deadline)
/// of the SQLite audit database at `path`, for runtimes built afterwards.
pub fn override_audit_query_limits(path: &Path, limits: AuditQueryLimits) {
    crate::runtime::override_audit_query_limits(path, limits);
}

/// Every record in the audit store of type `kind` at `path`, in write order.
/// A store that does not exist yet has no records. For JSONL this reads the
/// live file only, not rotated files; for SQLite it reads `record_json` in
/// insertion order.
pub fn read_audit_records(kind: AuditStoreType, path: &Path) -> Vec<Value> {
    match kind {
        AuditStoreType::Jsonl => read_jsonl_audit_records(path),
        AuditStoreType::Sqlite => read_sqlite_audit_records(path),
    }
}

/// The records in the audit store of type `kind` at `path` as JSONL text:
/// the file itself for JSONL, and each stored `record_json` (exactly the line
/// JSONL would write) followed by a newline for SQLite.
pub fn read_audit_text(kind: AuditStoreType, path: &Path) -> String {
    match kind {
        AuditStoreType::Jsonl => match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("failed to read audit file {}: {error}", path.display()),
        },
        AuditStoreType::Sqlite => read_sqlite_record_json(path)
            .into_iter()
            .map(|json| json + "\n")
            .collect(),
    }
}

fn read_jsonl_audit_records(path: &Path) -> Vec<Value> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("failed to read audit file {}: {error}", path.display()),
    };
    contents
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("invalid audit line in {}: {error}: {line}", path.display())
            })
        })
        .collect()
}

fn read_sqlite_audit_records(path: &Path) -> Vec<Value> {
    read_sqlite_record_json(path)
        .into_iter()
        .map(|json| {
            serde_json::from_str(&json).unwrap_or_else(|error| {
                panic!(
                    "invalid audit record in {}: {error}: {json}",
                    path.display()
                )
            })
        })
        .collect()
}

fn read_sqlite_record_json(path: &Path) -> Vec<String> {
    if !path.exists() {
        return Vec::new();
    }
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap_or_else(|error| panic!("failed to open audit database {}: {error}", path.display()));
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let mut statement = match conn.prepare("SELECT record_json FROM audit_events ORDER BY id") {
        Ok(statement) => statement,
        // A database the broker has not initialized yet has no records.
        Err(error) if error.to_string().contains("no such table") => return Vec::new(),
        Err(error) => panic!("failed to read audit database {}: {error}", path.display()),
    };
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
