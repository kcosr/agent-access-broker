//! The SQLite audit storage backend (`audit.type = "sqlite"`): one database
//! at `audit.path`, written in batch transactions by the writer thread's
//! single connection, with failure recovery tied to the failed operation
//! and retention and maintenance run as bounded slices.

mod query;
#[cfg(test)]
mod query_tests;
mod reader;
mod row;
mod schema;
#[cfg(test)]
mod tests;

pub(super) use reader::AuditReaderPool;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use reader::override_limits as override_query_limits;
pub use schema::{AuditVerifyCheck, AuditVerifyReport, verify_sqlite_audit_database};

use super::{
    AUDIT_RETENTION_PRUNE_INTERVAL, AuditAppendEntry, AuditAppendOutcome, AuditFailureClass,
    AuditFailureSet, AuditHealthChange, AuditMaintenanceFailure, AuditMaintenanceOutcome,
    AuditMaintenanceProgress, AuditMaintenanceStatus, AuditOpenMode, AuditStorage,
    AuditStorageConfig, AuditStorageOutcome, AuditWriterTestEventKind,
    emit_audit_writer_test_event,
};
use crate::{
    AuditDurability, AuditEventsPage, AuditEventsQuery, AuditQueryError, AuditVisibility,
    fs_permissions, sqlite_support,
};
use chrono::Utc;
use row::{MAX_PREPARED_BYTES, PreparedRow};
use rusqlite::{Connection, ErrorCode, params};
use schema::FileIdentity;
use serde_json::value::RawValue;
use std::fs;
use std::time::{Duration, Instant};

/// At most one recovery attempt per second per writer.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
/// Rows one delete slice removes at most.
const DELETE_SLICE_ROWS: usize = 2_000;
/// The `merge` command's page budget, and the most merge slices per cycle.
const FTS_MERGE_PAGES: i64 = 64;
const MAX_MERGE_SLICES: u32 = 64;
/// `incremental_vacuum` pages per slice, and the most vacuum slices per cycle.
const VACUUM_PAGES_PER_SLICE: u32 = 1024;
const MAX_VACUUM_SLICES: u32 = 64;
/// Vacuum starts when free pages exceed 25% of the page count and stops
/// once they drop below 10%.
const VACUUM_START_FREE_PERCENT: i64 = 25;
const VACUUM_STOP_FREE_PERCENT: i64 = 10;
/// A WAL still larger than this after a passive checkpoint is deferred.
const WAL_DEFERRAL_BYTES: u64 = 256 * 1024 * 1024;

const INSERT_EVENT_SQL: &str = "INSERT INTO audit_events (
    audit_id, node_id, ts_us, broker_request_id, agent_request_id, principal, service,
    scope_service, action, decision, reason_code, phase, token_id, token_class, grant_id,
    execution_context, upstream_status, upstream_duration_ms, remote, record_bytes, record_json
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)";
const INSERT_FTS_SQL: &str = "INSERT INTO audit_events_fts(rowid, text) VALUES (?1, ?2)";

/// Lists one page of events on a reader of `pool`. The connection is back
/// in the pool before the page's items are built.
pub(super) async fn list_events(
    pool: &AuditReaderPool,
    query: AuditEventsQuery,
) -> Result<AuditEventsPage, AuditQueryError> {
    let page = pool
        .run(move |conn| query::list_events(conn, &query))
        .await?;
    Ok(AuditEventsPage {
        items: raw_records(page.records)?,
        next: page.next,
    })
}

/// The visible records of one broker request, oldest first.
pub(super) async fn request_timeline(
    pool: &AuditReaderPool,
    broker_request_id: String,
    visibility: AuditVisibility,
) -> Result<Vec<Box<RawValue>>, AuditQueryError> {
    let records = pool
        .run(move |conn| query::request_timeline(conn, &broker_request_id, &visibility))
        .await?;
    raw_records(records)
}

/// Each stored record exactly as written.
fn raw_records(records: Vec<String>) -> Result<Vec<Box<RawValue>>, AuditQueryError> {
    records
        .into_iter()
        .map(|record| {
            RawValue::from_string(record).map_err(|error| {
                AuditQueryError::Failed(format!("stored audit record is not JSON: {error}"))
            })
        })
        .collect()
}

pub(super) struct SqliteAuditStorage {
    config: AuditStorageConfig,
    conn: Connection,
    database_id: String,
    identity: FileIdentity,
    /// The largest failed batch since `Append` or `TerminalWrite` was first
    /// recorded, replayed (and rolled back) by recovery transactions.
    retained: Option<RetainedBatch>,
    last_recovery_attempt: Option<Instant>,
    /// The cutoff of the delete slice whose failure recorded `Prune`.
    failed_delete_cutoff: Option<i64>,
    last_cycle_started: Option<Instant>,
    cycle: Option<MaintenanceCycle>,
    maintenance_status: AuditMaintenanceStatus,
    #[cfg(test)]
    test: std::sync::Arc<std::sync::Mutex<tests::SqliteTestControls>>,
}

struct RetainedBatch {
    rows: Vec<PreparedRow>,
    bytes: usize,
}

struct MaintenanceCycle {
    slice: MaintenanceSlice,
    /// Rows whose `ts_us` is older than this expire.
    cutoff_us: i64,
    merge_slices: u32,
    vacuum_slices: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceSlice {
    Delete,
    FtsMerge,
    Vacuum,
    Optimize,
    Checkpoint,
}

impl MaintenanceSlice {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::FtsMerge => "fts_merge",
            Self::Vacuum => "vacuum",
            Self::Optimize => "optimize",
            Self::Checkpoint => "checkpoint",
        }
    }
}

/// What one optional slice did.
enum SliceResult {
    /// It ran; stay at this slice.
    Again,
    /// It ran; continue with the given slice, or finish the cycle with `None`.
    Next(Option<MaintenanceSlice>),
    /// Nothing was due (threshold or budget); continue with the given slice.
    Skipped(MaintenanceSlice),
}

impl SqliteAuditStorage {
    /// Opens the database on the caller's thread: created and migrated at
    /// startup, validated only on reload.
    pub(super) fn open(
        config: AuditStorageConfig,
        mode: AuditOpenMode,
        maintenance_status: AuditMaintenanceStatus,
    ) -> Result<Self, String> {
        #[cfg(test)]
        let test = tests::test_controls(&config.path_label);
        let opened = schema::open_audit_database(&config.path, mode)?;
        let synchronous = match config.durability {
            AuditDurability::Write => "NORMAL",
            AuditDurability::SyncData | AuditDurability::SyncAll => "FULL",
        };
        opened
            .conn
            .execute_batch(&format!(
                "PRAGMA busy_timeout = 5000;
                 PRAGMA foreign_keys = ON;
                 PRAGMA wal_autocheckpoint = 1000;
                 PRAGMA journal_size_limit = 67108864;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA synchronous = {synchronous};"
            ))
            .map_err(|error| format!("failed to configure the audit writer connection: {error}"))?;
        #[cfg(test)]
        {
            test.lock().unwrap().synchronous = opened
                .conn
                .query_row("PRAGMA synchronous", [], |row| row.get(0))
                .ok();
        }
        if opened.created && config.durability == AuditDurability::SyncAll {
            sync_parent_dir(&config)
                .map_err(|error| format!("failed to sync the audit database directory: {error}"))?;
        }
        Ok(Self {
            config,
            conn: opened.conn,
            database_id: opened.database_id,
            identity: opened.identity,
            retained: None,
            last_recovery_attempt: None,
            failed_delete_cutoff: None,
            last_cycle_started: None,
            cycle: None,
            maintenance_status,
            #[cfg(test)]
            test,
        })
    }

    pub(super) fn database_id(&self) -> &str {
        &self.database_id
    }

    /// A reader pool for this database, for the runtime generation that
    /// owns this writer.
    pub(super) fn reader_pool(&self) -> AuditReaderPool {
        AuditReaderPool::new(&self.config.path, &self.database_id, self.identity)
    }

    /// Commits `rows` in one `BEGIN IMMEDIATE` transaction.
    fn write_rows(&mut self, rows: &[PreparedRow]) -> rusqlite::Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = rows
            .iter()
            .try_for_each(|row| insert_row(&self.conn, row, &row.audit_id))
            .and_then(|()| self.commit());
        self.rollback_if_open(&result);
        result
    }

    /// Commits the open transaction. Tests can make it fail.
    fn commit(&self) -> rusqlite::Result<()> {
        #[cfg(test)]
        self.before_test_commit()?;
        self.conn.execute_batch("COMMIT")
    }

    fn rollback_if_open<T>(&self, result: &rusqlite::Result<T>) {
        if result.is_err() && !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }

    /// Commits one batch transaction and records each entry's outcome.
    /// Returns whether it committed.
    fn commit_batch(
        &mut self,
        entries: &[AuditAppendEntry<'_>],
        pending: &mut Vec<(usize, PreparedRow)>,
        outcomes: &mut [Option<AuditStorageOutcome>],
    ) -> bool {
        let (indexes, rows): (Vec<usize>, Vec<PreparedRow>) = pending.drain(..).unzip();
        let bytes = rows.iter().map(PreparedRow::prepared_bytes).sum::<usize>();
        match self.write_rows(&rows) {
            Ok(()) => {
                #[cfg(test)]
                self.test_event(tests::SqliteTestEvent::Commit {
                    records: rows.len(),
                    bytes,
                });
                for index in indexes {
                    outcomes[index] = Some(AuditStorageOutcome {
                        result: Ok(()),
                        health: AuditHealthChange::default(),
                    });
                }
                true
            }
            Err(error) => {
                #[cfg(test)]
                self.test_event(tests::SqliteTestEvent::FailedCommit {
                    records: rows.len(),
                    bytes,
                });
                let message = format!("audit database write failed: {error}");
                for index in indexes {
                    outcomes[index] = Some(failure_outcome(
                        std::io::Error::other(message.clone()),
                        entries[index].kind.failure_class(),
                    ));
                }
                self.retain_failed_batch(rows, bytes);
                false
            }
        }
    }

    /// Keeps the failed batch for recovery unless a larger one is retained.
    fn retain_failed_batch(&mut self, rows: Vec<PreparedRow>, bytes: usize) {
        if self
            .retained
            .as_ref()
            .is_none_or(|retained| bytes >= retained.bytes)
        {
            self.retained = Some(RetainedBatch { rows, bytes });
            #[cfg(test)]
            self.update_test_retained();
        }
    }

    fn recovery_allowed(&self) -> bool {
        self.last_recovery_attempt
            .is_none_or(|attempt| attempt.elapsed() >= RECOVERY_INTERVAL)
    }

    /// One recovery attempt for the recoverable classes in `recorded`. Only
    /// the evidence for a class clears it; a failed attempt changes nothing.
    fn recover(&mut self, recorded: AuditFailureSet) -> (std::io::Result<()>, AuditHealthChange) {
        self.last_recovery_attempt = Some(Instant::now());
        let append_classes =
            AuditFailureSet::of(&[AuditFailureClass::Append, AuditFailureClass::TerminalWrite]);
        let replay_retained = !recorded.intersection(append_classes).is_empty();
        let transaction_classes =
            recorded.intersection(append_classes.with(AuditFailureClass::Probe));
        let mut clear = AuditFailureSet::EMPTY;
        let mut first_error = None;
        if !transaction_classes.is_empty() {
            match self.check_files(true) {
                Err(error) => first_error = Some(error),
                Ok(()) => {
                    let synthetic;
                    let rows = match (&self.retained, replay_retained) {
                        (Some(retained), true) => retained.rows.as_slice(),
                        _ => {
                            synthetic = [PreparedRow::synthetic(&self.config.node_id)];
                            synthetic.as_slice()
                        }
                    };
                    let bytes = rows.iter().map(PreparedRow::prepared_bytes).sum::<usize>();
                    let records = rows.len();
                    let result = recovery_transaction(&self.conn, rows, bytes, || self.commit());
                    #[cfg(test)]
                    self.test_event(tests::SqliteTestEvent::Recovery {
                        records,
                        bytes,
                        ok: result.is_ok(),
                    });
                    #[cfg(not(test))]
                    let _ = records;
                    match result {
                        Ok(()) => {
                            clear = clear.union(transaction_classes);
                            if replay_retained {
                                self.retained = None;
                                #[cfg(test)]
                                self.update_test_retained();
                            }
                        }
                        Err(error) => {
                            first_error = Some(std::io::Error::other(format!(
                                "audit database recovery failed: {error}"
                            )));
                        }
                    }
                }
            }
        }
        if recorded.contains(AuditFailureClass::Prune) {
            match self.failed_delete_cutoff {
                Some(cutoff_us) => match self.delete_slice(cutoff_us) {
                    Ok(_) => {
                        self.failed_delete_cutoff = None;
                        clear = clear.with(AuditFailureClass::Prune);
                    }
                    Err(error) => {
                        first_error.get_or_insert_with(|| {
                            std::io::Error::other(format!(
                                "audit retention delete retry failed: {error}"
                            ))
                        });
                    }
                },
                None => clear = clear.with(AuditFailureClass::Prune),
            }
        }
        let result = match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        };
        (
            result,
            AuditHealthChange {
                mark: AuditFailureSet::EMPTY,
                clear,
            },
        )
    }

    /// The probe's checks: the parent directory and the database files are
    /// private, the path still names the open database, and the connection
    /// can read. With `repair` (recovery only) file modes are restored
    /// first, by path: a descriptor closed here would release the live
    /// connections' SQLite locks. Otherwise nothing is written.
    fn check_files(&self, repair: bool) -> std::io::Result<()> {
        fs_permissions::validate_private_parent(&self.config.path)?;
        if repair {
            schema::restrict_files(&self.config.path).map_err(std::io::Error::other)?;
        }
        fs_permissions::check_private_file(&self.config.path, true)?;
        for sidecar in sqlite_support::sqlite_sidecar_paths(&self.config.path) {
            fs_permissions::check_private_file(&sidecar, false)?;
        }
        if FileIdentity::of(&self.config.path)? != self.identity {
            return Err(std::io::Error::other(
                "the audit database path no longer names the open database",
            ));
        }
        self.conn
            .query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    /// Starts a cycle when none is running and the last one started at
    /// least an hour ago.
    fn maintenance_due(&mut self) -> bool {
        if self.cycle.is_some() {
            return false;
        }
        #[cfg(test)]
        let forced = std::mem::take(&mut self.test.lock().unwrap().force_maintenance);
        #[cfg(not(test))]
        let forced = false;
        let due = forced
            || self
                .last_cycle_started
                .is_none_or(|started| started.elapsed() >= AUDIT_RETENTION_PRUNE_INTERVAL);
        if due {
            let retention_us = i64::from(self.config.retention_days) * 24 * 60 * 60 * 1_000_000;
            self.last_cycle_started = Some(Instant::now());
            self.cycle = Some(MaintenanceCycle {
                slice: MaintenanceSlice::Delete,
                cutoff_us: Utc::now().timestamp_micros().saturating_sub(retention_us),
                merge_slices: 0,
                vacuum_slices: 0,
            });
        }
        due
    }

    /// One transaction deleting at most 2,000 expired rows (and, through
    /// the trigger, their full-text entries). Returns the rows deleted.
    fn delete_slice(&mut self, cutoff_us: i64) -> rusqlite::Result<usize> {
        #[cfg(test)]
        self.inject_slice_failure(MaintenanceSlice::Delete)?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = self
            .conn
            .execute(
                "DELETE FROM audit_events WHERE id IN (
                     SELECT id FROM audit_events WHERE ts_us < ?1 ORDER BY ts_us LIMIT ?2
                 )",
                params![cutoff_us, DELETE_SLICE_ROWS as i64],
            )
            .and_then(|deleted| self.conn.execute_batch("COMMIT").map(|()| deleted));
        self.rollback_if_open(&result);
        result
    }

    fn run_optional_slice(&mut self, slice: MaintenanceSlice) -> rusqlite::Result<SliceResult> {
        #[cfg(test)]
        self.inject_slice_failure(slice)?;
        let cycle = self.cycle.as_mut().expect("maintenance cycle is running");
        match slice {
            MaintenanceSlice::Delete => unreachable!("delete slices are required"),
            MaintenanceSlice::FtsMerge => {
                if cycle.merge_slices >= MAX_MERGE_SLICES {
                    return Ok(SliceResult::Skipped(MaintenanceSlice::Vacuum));
                }
                cycle.merge_slices += 1;
                let before = self.conn.total_changes();
                self.conn.execute(
                    "INSERT INTO audit_events_fts(audit_events_fts, rank) VALUES ('merge', ?1)",
                    params![FTS_MERGE_PAGES],
                )?;
                // FTS5 reports merge work as two or more changes.
                let merged = self.conn.total_changes().saturating_sub(before) >= 2;
                Ok(if merged {
                    SliceResult::Again
                } else {
                    SliceResult::Next(Some(MaintenanceSlice::Vacuum))
                })
            }
            MaintenanceSlice::Vacuum => {
                let free: i64 = self
                    .conn
                    .query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
                let pages: i64 = self
                    .conn
                    .query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let threshold = if cycle.vacuum_slices == 0 {
                    free * 100 > pages * VACUUM_START_FREE_PERCENT
                } else {
                    free * 100 >= pages * VACUUM_STOP_FREE_PERCENT
                };
                if !threshold || cycle.vacuum_slices >= MAX_VACUUM_SLICES {
                    return Ok(SliceResult::Skipped(MaintenanceSlice::Optimize));
                }
                cycle.vacuum_slices += 1;
                // The pragma returns one row per freed page; step it to the end.
                let mut statement = self.conn.prepare(&format!(
                    "PRAGMA incremental_vacuum({VACUUM_PAGES_PER_SLICE})"
                ))?;
                let mut rows = statement.query([])?;
                while rows.next()?.is_some() {}
                Ok(SliceResult::Again)
            }
            MaintenanceSlice::Optimize => {
                self.conn.execute_batch("PRAGMA optimize;")?;
                Ok(SliceResult::Next(Some(MaintenanceSlice::Checkpoint)))
            }
            MaintenanceSlice::Checkpoint => {
                let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = self
                    .conn
                    .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?;
                let [wal, _] = sqlite_support::sqlite_sidecar_paths(&self.config.path);
                let wal_bytes = fs::metadata(&wal)
                    .map(|metadata| metadata.len())
                    .unwrap_or(0);
                if busy != 0
                    || (log_frames > 0 && checkpointed_frames < log_frames)
                    || wal_bytes > WAL_DEFERRAL_BYTES
                {
                    tracing::warn!(
                        event = "audit_wal_checkpoint_deferred",
                        auditPath = self.config.path_label.as_str(),
                        nodeId = self.config.node_id.as_str(),
                        walBytes = wal_bytes,
                        walFrames = log_frames,
                        checkpointedFrames = checkpointed_frames,
                        "audit WAL checkpoint could not finish because readers hold older snapshots; retrying next cycle",
                    );
                }
                Ok(SliceResult::Next(None))
            }
        }
    }

    /// Logs a failed optional slice, keeps it for `config.status`, and ends
    /// this cycle's optional work.
    fn optional_slice_failed(&mut self, slice: MaintenanceSlice, error: &rusqlite::Error) {
        let error_code = sqlite_error_code_name(error);
        tracing::error!(
            event = "audit_maintenance_failed",
            auditPath = self.config.path_label.as_str(),
            nodeId = self.config.node_id.as_str(),
            slice = slice.as_str(),
            sqliteErrorCode = error_code.as_str(),
            error = %error,
        );
        self.maintenance_status.record(AuditMaintenanceFailure {
            slice: slice.as_str().to_string(),
            error_code,
            at: Utc::now().to_rfc3339(),
        });
    }
}

impl AuditStorage for SqliteAuditStorage {
    fn append_batch(
        &mut self,
        entries: &[AuditAppendEntry<'_>],
        recorded: AuditFailureSet,
    ) -> AuditAppendOutcome {
        #[cfg(test)]
        self.apply_test_controls();
        let mut outcomes = entries.iter().map(|_| None).collect::<Vec<_>>();
        let mut pending = Vec::new();
        let mut pending_bytes = 0;
        let mut committed = false;
        let mut marks = AuditFailureSet::EMPTY;
        for (index, entry) in entries.iter().enumerate() {
            let row = match PreparedRow::prepare(entry.record) {
                Ok(row) => row,
                Err(error) => {
                    // No row: recovery stands in the synthetic record.
                    let class = entry.kind.failure_class();
                    marks = marks.with(class);
                    outcomes[index] = Some(failure_outcome(
                        std::io::Error::other(format!("failed to serialize audit record: {error}")),
                        class,
                    ));
                    continue;
                }
            };
            let bytes = row.prepared_bytes();
            if bytes > MAX_PREPARED_BYTES {
                tracing::error!(
                    event = "audit_record_too_large",
                    auditPath = self.config.path_label.as_str(),
                    nodeId = self.config.node_id.as_str(),
                    auditId = entry.record.audit_id.as_str(),
                    brokerRequestId = entry.record.record.broker_request_id.as_str(),
                    preparedBytes = bytes,
                    maxBytes = MAX_PREPARED_BYTES,
                );
                outcomes[index] = Some(AuditStorageOutcome {
                    result: Err(std::io::Error::other(format!(
                        "audit record prepared size of {bytes} bytes exceeds the {MAX_PREPARED_BYTES}-byte limit"
                    ))),
                    health: AuditHealthChange::default(),
                });
                continue;
            }
            if !pending.is_empty() && pending_bytes + bytes > MAX_PREPARED_BYTES {
                committed |= self.commit_batch(entries, &mut pending, &mut outcomes);
                pending_bytes = 0;
            }
            pending_bytes += bytes;
            pending.push((index, row));
        }
        if !pending.is_empty() {
            committed |= self.commit_batch(entries, &mut pending, &mut outcomes);
        }
        for outcome in outcomes.iter().flatten() {
            marks = marks.union(outcome.health.mark);
        }
        let recorded = recorded.union(marks).without(AuditFailureClass::WriterExit);
        // A successful commit clears nothing itself, but triggers recovery.
        let health = if committed && !recorded.is_empty() && self.recovery_allowed() {
            self.recover(recorded).1
        } else {
            AuditHealthChange::default()
        };
        AuditAppendOutcome {
            entries: outcomes
                .into_iter()
                .map(|outcome| outcome.expect("every entry has an outcome"))
                .collect(),
            health,
            maintenance_due: self.maintenance_due(),
        }
    }

    fn probe(&mut self, recorded: AuditFailureSet) -> AuditStorageOutcome {
        #[cfg(test)]
        self.apply_test_controls();
        let recorded = recorded.without(AuditFailureClass::WriterExit);
        if recorded.is_empty() {
            return match self.check_files(false) {
                Ok(()) => AuditStorageOutcome {
                    result: Ok(()),
                    health: AuditHealthChange::default(),
                },
                Err(error) => failure_outcome(error, AuditFailureClass::Probe),
            };
        }
        if !self.recovery_allowed() {
            return AuditStorageOutcome {
                result: Err(std::io::Error::other(format!(
                    "audit writer has unrecovered failures {recorded:?}; recovery is attempted at most once per second"
                ))),
                health: AuditHealthChange::default(),
            };
        }
        let (result, health) = self.recover(recorded);
        AuditStorageOutcome { result, health }
    }

    fn run_maintenance_slice(&mut self) -> AuditMaintenanceOutcome {
        #[cfg(test)]
        self.apply_test_controls();
        let Some(cycle) = self.cycle.as_ref() else {
            return maintenance_outcome(Ok(()), AuditMaintenanceProgress::Done);
        };
        let slice = cycle.slice;
        #[cfg(test)]
        self.enter_test_slice(slice);
        #[cfg(test)]
        let _timer = tests::SliceTimer::start(&self.test, slice);
        if slice == MaintenanceSlice::Delete {
            let cutoff_us = cycle.cutoff_us;
            return match self.delete_slice(cutoff_us) {
                Ok(deleted) => {
                    if deleted < DELETE_SLICE_ROWS
                        && let Some(cycle) = self.cycle.as_mut()
                    {
                        cycle.slice = MaintenanceSlice::FtsMerge;
                    }
                    maintenance_outcome(Ok(()), AuditMaintenanceProgress::More)
                }
                Err(error) if is_busy(&error) => {
                    maintenance_outcome(Ok(()), AuditMaintenanceProgress::Deferred)
                }
                Err(error) => {
                    // Required: record `Prune` and end the cycle.
                    self.failed_delete_cutoff = Some(cutoff_us);
                    self.cycle = None;
                    AuditMaintenanceOutcome {
                        operation: "prune",
                        result: Err(std::io::Error::other(format!(
                            "audit retention delete failed: {error}"
                        ))),
                        health: AuditHealthChange {
                            mark: AuditFailureSet::of(&[AuditFailureClass::Prune]),
                            clear: AuditFailureSet::EMPTY,
                        },
                        progress: AuditMaintenanceProgress::Done,
                    }
                }
            };
        }
        match self.run_optional_slice(slice) {
            Ok(result) => {
                if !matches!(result, SliceResult::Skipped(_)) {
                    self.maintenance_status.clear_slice(slice.as_str());
                }
                let next = match result {
                    SliceResult::Again => Some(slice),
                    SliceResult::Next(next) => next,
                    SliceResult::Skipped(next) => Some(next),
                };
                match next {
                    Some(next) => {
                        if let Some(cycle) = self.cycle.as_mut() {
                            cycle.slice = next;
                        }
                        maintenance_outcome(Ok(()), AuditMaintenanceProgress::More)
                    }
                    None => {
                        self.cycle = None;
                        maintenance_outcome(Ok(()), AuditMaintenanceProgress::Done)
                    }
                }
            }
            Err(error) if is_busy(&error) => {
                maintenance_outcome(Ok(()), AuditMaintenanceProgress::Deferred)
            }
            Err(error) => {
                // Optional: never a health failure. Skip the rest of this
                // cycle's optional work and try again next cycle.
                self.optional_slice_failed(slice, &error);
                self.cycle = None;
                maintenance_outcome(Ok(()), AuditMaintenanceProgress::Done)
            }
        }
    }

    fn finishes_maintenance_at_shutdown(&self) -> bool {
        // An unfinished cycle resumes after the next start instead of
        // delaying shutdown.
        false
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Inserts one event row and its full-text entry with `audit_id`.
fn insert_row(conn: &Connection, row: &PreparedRow, audit_id: &str) -> rusqlite::Result<()> {
    conn.prepare_cached(INSERT_EVENT_SQL)?.execute(params![
        audit_id,
        row.node_id,
        row.ts_us,
        row.broker_request_id,
        row.agent_request_id,
        row.principal,
        row.service,
        row.scope_service,
        row.action,
        row.decision,
        row.reason_code,
        row.phase,
        row.token_id,
        row.token_class,
        row.grant_id,
        row.execution_context,
        row.upstream_status,
        row.upstream_duration_ms,
        row.remote,
        row.record_json.len() as i64,
        row.record_json,
    ])?;
    let id = conn.last_insert_rowid();
    conn.prepare_cached(INSERT_FTS_SQL)?
        .execute(params![id, row.fts_text])?;
    Ok(())
}

/// Repeats the failed storage work without keeping it: inside a savepoint,
/// inserts `rows` (with fresh audit IDs) exactly as a batch would and rolls
/// them back; then commits a padding blob of at least `bytes` with the
/// configured `synchronous`, and empties it in a second transaction.
fn recovery_transaction(
    conn: &Connection,
    rows: &[PreparedRow],
    bytes: usize,
    commit: impl Fn() -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
    let rollback_if_open = |result: &rusqlite::Result<()>| {
        if result.is_err() && !conn.is_autocommit() {
            let _ = conn.execute_batch("ROLLBACK");
        }
    };
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        conn.execute_batch("SAVEPOINT audit_recovery")?;
        let inserted = rows.iter().try_for_each(|row| {
            let audit_id = uuid::Uuid::now_v7().to_string();
            insert_row(conn, row, &audit_id)
        });
        let rolled_back = conn.execute_batch("ROLLBACK TO audit_recovery; RELEASE audit_recovery");
        inserted?;
        rolled_back?;
        conn.execute(
            "INSERT INTO audit_probe(id, probed_at_us, padding) VALUES (1, ?1, zeroblob(?2))
             ON CONFLICT(id) DO UPDATE SET probed_at_us = excluded.probed_at_us,
                                           padding = excluded.padding",
            params![Utc::now().timestamp_micros(), bytes as i64],
        )?;
        commit()
    })();
    rollback_if_open(&result);
    result?;
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = conn
        .execute("UPDATE audit_probe SET padding = x'' WHERE id = 1", [])
        .map(|_| ())
        .and_then(|()| commit());
    rollback_if_open(&result);
    result
}

fn failure_outcome(error: std::io::Error, class: AuditFailureClass) -> AuditStorageOutcome {
    AuditStorageOutcome {
        result: Err(error),
        health: AuditHealthChange {
            mark: AuditFailureSet::of(&[class]),
            clear: AuditFailureSet::EMPTY,
        },
    }
}

fn maintenance_outcome(
    result: std::io::Result<()>,
    progress: AuditMaintenanceProgress,
) -> AuditMaintenanceOutcome {
    AuditMaintenanceOutcome {
        operation: "maintenance",
        result,
        health: AuditHealthChange::default(),
        progress,
    }
}

fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

/// The SQLite primary result code name of `error`, such as `SQLITE_IOERR`.
fn sqlite_error_code_name(error: &rusqlite::Error) -> String {
    let Some(code) = error.sqlite_error_code() else {
        return "SQLITE_ERROR".to_string();
    };
    match code {
        ErrorCode::InternalMalfunction => "SQLITE_INTERNAL",
        ErrorCode::PermissionDenied => "SQLITE_PERM",
        ErrorCode::OperationAborted => "SQLITE_ABORT",
        ErrorCode::DatabaseBusy => "SQLITE_BUSY",
        ErrorCode::DatabaseLocked => "SQLITE_LOCKED",
        ErrorCode::OutOfMemory => "SQLITE_NOMEM",
        ErrorCode::ReadOnly => "SQLITE_READONLY",
        ErrorCode::OperationInterrupted => "SQLITE_INTERRUPT",
        ErrorCode::SystemIoFailure => "SQLITE_IOERR",
        ErrorCode::DatabaseCorrupt => "SQLITE_CORRUPT",
        ErrorCode::NotFound => "SQLITE_NOTFOUND",
        ErrorCode::DiskFull => "SQLITE_FULL",
        ErrorCode::CannotOpen => "SQLITE_CANTOPEN",
        ErrorCode::FileLockingProtocolFailed => "SQLITE_PROTOCOL",
        ErrorCode::SchemaChanged => "SQLITE_SCHEMA",
        ErrorCode::TooBig => "SQLITE_TOOBIG",
        ErrorCode::ConstraintViolation => "SQLITE_CONSTRAINT",
        ErrorCode::TypeMismatch => "SQLITE_MISMATCH",
        ErrorCode::ApiMisuse => "SQLITE_MISUSE",
        ErrorCode::NoLargeFileSupport => "SQLITE_NOLFS",
        ErrorCode::AuthorizationForStatementDenied => "SQLITE_AUTH",
        ErrorCode::ParameterOutOfRange => "SQLITE_RANGE",
        ErrorCode::NotADatabase => "SQLITE_NOTADB",
        _ => "SQLITE_ERROR",
    }
    .to_string()
}

fn sync_parent_dir(config: &AuditStorageConfig) -> std::io::Result<()> {
    let Some(parent) = config.path.parent() else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };
    emit_audit_writer_test_event(
        &config.path_label,
        AuditWriterTestEventKind::ParentDirSync(config.durability),
    );
    fs::File::open(parent)?.sync_all()
}
