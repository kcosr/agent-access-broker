use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// Fault injection and observation for one audit database path, shared by
/// the test and the writer that opens that path.
#[derive(Default)]
pub(super) struct SqliteTestControls {
    /// Every ordinary batch and recovery commit fails.
    pub(super) fail_commits: bool,
    /// The named maintenance slice fails every time it runs.
    pub(super) fail_slice: Option<&'static str>,
    /// Applied to the writer connection before its next operation.
    pub(super) max_page_count: Option<u64>,
    applied_max_page_count: Option<u64>,
    /// The next append starts a maintenance cycle.
    pub(super) force_maintenance: bool,
    /// Each blocks the writer when the named slice first starts until released.
    pub(super) slice_gates: Vec<(&'static str, Arc<Gate>)>,
    /// Blocks the next ordinary or recovery commit until released.
    pub(super) commit_gate: Option<Arc<Gate>>,
    pub(super) events: Vec<SqliteTestEvent>,
    /// How long each maintenance slice ran.
    pub(super) slice_durations: Vec<(&'static str, Duration)>,
    /// The writer connection's `PRAGMA synchronous` after open.
    pub(super) synchronous: Option<i64>,
    /// The retained failed batch: (records, prepared bytes).
    pub(super) retained: Option<(usize, usize)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SqliteTestEvent {
    Commit {
        records: usize,
        bytes: usize,
    },
    FailedCommit {
        records: usize,
        bytes: usize,
    },
    Recovery {
        records: usize,
        bytes: usize,
        ok: bool,
    },
    Slice(&'static str),
}

/// A one-shot gate: the writer signals `entered` and waits for `release`.
#[derive(Default)]
pub(super) struct Gate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn enter_and_wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    pub(super) fn wait_entered(&self, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.0)
            .unwrap();
        state.0
    }

    pub(super) fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

pub(super) fn test_controls(path_label: &str) -> Arc<Mutex<SqliteTestControls>> {
    static CONTROLS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<SqliteTestControls>>>>> =
        OnceLock::new();
    Arc::clone(
        CONTROLS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(path_label.to_string())
            .or_default(),
    )
}

pub(super) fn injected_error(message: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
        Some(message.to_string()),
    )
}

impl SqliteAuditStorage {
    pub(super) fn apply_test_controls(&mut self) {
        let mut controls = self.test.lock().unwrap();
        if controls.max_page_count != controls.applied_max_page_count {
            if let Some(pages) = controls.max_page_count {
                self.conn
                    .query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(()))
                    .unwrap();
            }
            controls.applied_max_page_count = controls.max_page_count;
        }
    }

    pub(super) fn test_event(&self, event: SqliteTestEvent) {
        self.test.lock().unwrap().events.push(event);
    }

    pub(super) fn update_test_retained(&self) {
        self.test.lock().unwrap().retained = self
            .retained
            .as_ref()
            .map(|retained| (retained.rows.len(), retained.bytes));
    }

    pub(super) fn inject_slice_failure(&self, slice: MaintenanceSlice) -> rusqlite::Result<()> {
        if self.test.lock().unwrap().fail_slice == Some(slice.as_str()) {
            return Err(injected_error("injected maintenance failure"));
        }
        Ok(())
    }

    pub(super) fn enter_test_slice(&self, slice: MaintenanceSlice) {
        let gate = {
            let mut controls = self.test.lock().unwrap();
            controls.events.push(SqliteTestEvent::Slice(slice.as_str()));
            controls
                .slice_gates
                .iter()
                .position(|(name, _)| *name == slice.as_str())
                .map(|index| controls.slice_gates.remove(index).1)
        };
        if let Some(gate) = gate {
            gate.enter_and_wait();
        }
    }

    pub(super) fn before_test_commit(&self) -> rusqlite::Result<()> {
        let gate = self.test.lock().unwrap().commit_gate.take();
        if let Some(gate) = gate {
            gate.enter_and_wait();
        }
        if self.test.lock().unwrap().fail_commits {
            return Err(injected_error("injected commit failure"));
        }
        Ok(())
    }
}

/// Records how long a maintenance slice ran when dropped.
pub(super) struct SliceTimer {
    controls: Arc<Mutex<SqliteTestControls>>,
    slice: &'static str,
    started: Instant,
}

impl SliceTimer {
    pub(super) fn start(
        controls: &Arc<Mutex<SqliteTestControls>>,
        slice: MaintenanceSlice,
    ) -> Self {
        Self {
            controls: Arc::clone(controls),
            slice: slice.as_str(),
            started: Instant::now(),
        }
    }
}

impl Drop for SliceTimer {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        self.controls
            .lock()
            .unwrap()
            .slice_durations
            .push((self.slice, elapsed));
    }
}

/// Statements run by connections opened for the path set in [`TRACED_PATH`].
static TRACED_STATEMENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static TRACED_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

pub(super) fn trace_if_requested(path: &std::path::Path, conn: &Connection) {
    if TRACED_PATH.lock().unwrap().as_deref() == Some(path) {
        conn.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| {
                if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
                    TRACED_STATEMENTS.lock().unwrap().push(sql.to_string());
                }
            }),
        );
    }
}

#[test]
fn baseline_checksum_is_the_sha256_of_the_baseline_sql() {
    let (actual, recorded) = schema::baseline_checksum_matches();
    assert_eq!(actual, recorded);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use super::super::tests::{
    CapturedEvents, EventCaptureLayer, TEST_NODE_ID, base_fake_config, install_audit_writer_hook,
    temp_path, test_audit_record, test_audit_sink_lock, test_limits,
};
use super::super::{
    AuditRecord, AuditRuntimeRegistry, AuditSink, AuditWriterTestEventKind, BrokerRuntime,
    GovernedOperationContext, IdentityContext, InvocationControl, InvokeRequest, OperationContext,
    RuntimeError, SourceContext, StampedAuditRecord,
};
use crate::{AuditConfig, AuditStoreType, DEFAULT_EXECUTION_CONTEXT, ExecutionContext};
use agent_access_provider::ReasonCode;
use rusqlite::OpenFlags;
use serde_json::{Value, json};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::task::JoinHandle;
use tracing_subscriber::prelude::*;
use uuid::Uuid;

#[cfg(unix)]
use crate::sqlite_support::lock_probe;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn sqlite_config(path: &Path) -> AuditConfig {
    AuditConfig::new(AuditStoreType::Sqlite, path.display().to_string())
}

fn open_sink(config: &AuditConfig, mode: AuditOpenMode) -> Result<AuditSink, RuntimeError> {
    AuditSink::new(
        Some(config),
        &test_limits(),
        Arc::new(AuditRuntimeRegistry::new()),
        TEST_NODE_ID,
        mode,
    )
}

fn sink(config: &AuditConfig) -> AuditSink {
    open_sink(config, AuditOpenMode::Startup).unwrap()
}

fn controls(path: &Path) -> Arc<Mutex<SqliteTestControls>> {
    test_controls(&path.display().to_string())
}

fn events(path: &Path) -> Vec<SqliteTestEvent> {
    controls(path).lock().unwrap().events.clone()
}

fn take_events(path: &Path) -> Vec<SqliteTestEvent> {
    std::mem::take(&mut controls(path).lock().unwrap().events)
}

fn stored(path: &Path) -> Vec<Value> {
    crate::test_support::read_audit_records(AuditStoreType::Sqlite, path)
}

fn reader(path: &Path) -> Connection {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn recorded(sink: &AuditSink) -> AuditFailureSet {
    sink.writer.as_ref().unwrap().health.recorded()
}

fn set(classes: &[AuditFailureClass]) -> AuditFailureSet {
    AuditFailureSet::of(classes)
}

/// A record whose `providerAudit.payload` is `payload_bytes` long.
fn record_with(broker_request_id: &str, payload_bytes: usize) -> AuditRecord {
    let mut record = test_audit_record();
    record.broker_request_id = broker_request_id.to_string();
    if payload_bytes > 0 {
        record.provider_audit = Some(json!({ "payload": "p".repeat(payload_bytes) }));
    }
    record
}

/// A record whose prepared size is exactly `bytes` (more than the
/// full-text cap).
fn record_with_prepared_bytes(broker_request_id: &str, bytes: usize) -> AuditRecord {
    let probe = PreparedRow::prepare(&StampedAuditRecord::new(
        record_with(broker_request_id, 1),
        TEST_NODE_ID,
    ))
    .unwrap();
    // A one-character payload adds one byte to the JSON and " p" to the
    // full-text text. A payload longer than the full-text cap is one token
    // that the cap drops whole, so it adds only its length to the JSON.
    let base = probe.prepared_bytes() - 3;
    let record = record_with(broker_request_id, bytes - base);
    let prepared =
        PreparedRow::prepare(&StampedAuditRecord::new(record.clone(), TEST_NODE_ID)).unwrap();
    assert_eq!(prepared.prepared_bytes(), bytes);
    record
}

/// A record timestamped `days` days ago.
fn expired_record(broker_request_id: &str, days: i64) -> AuditRecord {
    let mut record = record_with(broker_request_id, 0);
    record.timestamp = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();
    record.principal = "expiredprincipal".to_string();
    record
}

/// Polls `future` once, so an append is queued before this returns, then
/// hands the rest to the runtime. The poll opts out of Tokio's cooperative
/// budget, which would otherwise make the semaphore acquire of a long run of
/// appends return pending before the command is queued.
fn start_now<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let mut future = Box::pin(tokio::task::unconstrained(future));
    let waker = futures_util::task::noop_waker();
    if let Poll::Ready(output) = future.as_mut().poll(&mut Context::from_waker(&waker)) {
        return tokio::spawn(async move { output });
    }
    tokio::spawn(future)
}

fn enqueue_required(sink: &AuditSink, record: AuditRecord) -> JoinHandle<Result<(), RuntimeError>> {
    let sink = sink.clone();
    start_now(async move { sink.append_required(record).await })
}

/// Holds the per-path lock on another thread until the returned sender is
/// dropped, so commands queued meanwhile are drained into batches. Dropping
/// the sender, also when the test unwinds, releases the lock; it is held for
/// a minute at most.
fn hold_writer_lock(sink: &AuditSink) -> std::sync::mpsc::Sender<()> {
    let lock = test_audit_sink_lock(sink);
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let _guard = lock.lock().unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(60));
    });
    locked_rx.recv().unwrap();
    release_tx
}

/// Queues a probe that parks the writer on the held lock, so appends queued
/// after it are drained together once the lock is released. The handle
/// yields the writer's result for the probe itself: `check_writable` also
/// checks health after the writer answers, which can already include the
/// failures of a batch released behind the probe.
fn park_writer(
    sink: &AuditSink,
) -> (
    std::sync::mpsc::Sender<()>,
    JoinHandle<Result<(), RuntimeError>>,
) {
    let release = hold_writer_lock(sink);
    let probe = {
        let writer = Arc::clone(sink.writer.as_ref().unwrap());
        start_now(async move { writer.probe_storage().await })
    };
    (release, probe)
}

async fn shutdown(sink: &AuditSink) {
    sink.shutdown_and_drain(Duration::from_secs(30))
        .await
        .unwrap();
}

/// Starts a maintenance cycle with the next append and waits until it has
/// finished (the probe queued after the last slice's start is answered only
/// once that slice is done).
async fn run_maintenance_cycle(sink: &AuditSink, path: &Path) {
    let before = events(path)
        .iter()
        .filter(|event| **event == SqliteTestEvent::Slice("checkpoint"))
        .count();
    controls(path).lock().unwrap().force_maintenance = true;
    sink.append_required(record_with("maintenance-trigger", 0))
        .await
        .unwrap();
    wait_for_cycle_end(sink, path, before).await;
}

async fn wait_for_cycle_end(sink: &AuditSink, path: &Path, checkpoints_before: usize) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let events = events(path);
        let checkpoints = events
            .iter()
            .filter(|event| **event == SqliteTestEvent::Slice("checkpoint"))
            .count();
        let ended_early = controls(path).lock().unwrap().fail_slice.is_some()
            && events.iter().rev().take(1).any(|event| {
                matches!(event, SqliteTestEvent::Slice(slice) if Some(*slice) == controls(path).lock().unwrap().fail_slice)
            });
        if checkpoints > checkpoints_before || ended_early {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "maintenance cycle did not finish"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Answered only after the slice in progress has finished.
    let _ = sink.check_writable().await;
}

fn capture_events() -> (CapturedEvents, tracing::subscriber::DefaultGuard) {
    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    (captured, tracing::subscriber::set_default(subscriber))
}

fn logged(captured: &CapturedEvents, event: &str) -> Vec<BTreeMap<String, Value>> {
    captured
        .take()
        .into_iter()
        .filter(|fields| fields.get("event").and_then(Value::as_str) == Some(event))
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn startup_creates_an_owner_only_database_and_migrates_it_from_empty() {
    let path = temp_path("created.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(test_audit_record()).await.unwrap();

    assert_eq!(mode(&path), 0o600);
    for sidecar in sqlite_support::sqlite_sidecar_paths(&path) {
        assert_eq!(mode(&sidecar), 0o600, "{}", sidecar.display());
    }
    let conn = reader(&path);
    let ledger = conn
        .query_row(
            "SELECT version, checksum FROM schema_migrations",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    assert_eq!(ledger.0, schema::AUDIT_BASELINE_VERSION);
    assert_eq!(ledger.1, schema::baseline_checksum_matches().1);
    assert_eq!(count(&conn, "PRAGMA auto_vacuum"), 2);
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal");
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_events"), 1);
    let records = stored(&path);
    assert_eq!(records[0]["nodeId"], TEST_NODE_ID);
    // The stored JSON is exactly the JSONL line.
    let json: String = conn
        .query_row("SELECT record_json FROM audit_events", [], |row| row.get(0))
        .unwrap();
    assert!(json.starts_with(r#"{"auditId":""#), "{json}");
    shutdown(&sink).await;
}

#[cfg(unix)]
#[test]
fn opening_refuses_a_symlinked_database_path() {
    let target = temp_path("target.audit.sqlite");
    drop(sink(&sqlite_config(&target)));
    let link = target.with_file_name("link.audit.sqlite");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    for mode in [AuditOpenMode::Startup, AuditOpenMode::Reload] {
        let Err(error) = open_sink(&sqlite_config(&link), mode) else {
            panic!("a symlinked audit database must be refused");
        };
        assert!(matches!(error, RuntimeError::AuditStore { .. }), "{error}");
    }
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn opening_refuses_a_shared_parent_directory() {
    let path = temp_path("shared-parent.audit.sqlite");
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
    let Err(error) = open_sink(&sqlite_config(&path), AuditOpenMode::Startup) else {
        panic!("a shared parent directory must be refused");
    };
    assert!(error.to_string().contains("0700"), "{error}");
    assert!(!path.exists());
}

#[tokio::test]
async fn unknown_or_mismatched_migrations_fail_startup_without_touching_data() {
    let path = temp_path("unknown-migration.audit.sqlite");
    let config = sqlite_config(&path);
    let audit = sink(&config);
    audit.append_required(test_audit_record()).await.unwrap();
    shutdown(&audit).await;
    drop(audit);
    let conn = reader(&path);
    let records = stored(&path);
    assert_eq!(records.len(), 1);
    let database_id = || {
        conn.query_row(
            "SELECT value FROM audit_meta WHERE key = 'database_id'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
    };
    let original_database_id = database_id();
    let migration_rows = || {
        conn.prepare("SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    for (fixture, sql, expected_message) in [
        (
            "recognized newer prefix",
            "INSERT INTO schema_migrations(version, checksum, applied_at) VALUES ('002_future', 'x', 'now');",
            "audit database schema includes migrations newer than this broker supports; preserve the database and use a compatible broker binary or restore a matching pre-upgrade backup",
        ),
        (
            "mismatched checksum",
            "DELETE FROM schema_migrations WHERE version = '002_future';
             UPDATE schema_migrations SET checksum = 'tampered';",
            "audit database migration checksum mismatch",
        ),
        (
            "unrecognized ledger",
            "UPDATE schema_migrations SET version = '999_unrecognized';",
            "audit database has an unknown or unrelated schema",
        ),
    ] {
        conn.execute_batch(sql).unwrap();
        let before_ledger = migration_rows();
        for mode in [AuditOpenMode::Startup, AuditOpenMode::Reload] {
            let Err(error) = open_sink(&config, mode) else {
                panic!("{fixture} must fail admission");
            };
            let message = error.to_string();
            assert!(message.contains(expected_message), "{fixture}: {message}");
            assert!(!message.contains("reset required"), "{message}");
            assert!(!message.contains("recreate"), "{message}");
            assert_eq!(migration_rows(), before_ledger, "{fixture}");
            assert_eq!(stored(&path), records, "{fixture}");
            assert_eq!(database_id(), original_database_id, "{fixture}");
            assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_events_fts"), 1);
        }
    }
}

#[test]
fn a_database_with_other_tables_is_never_adopted() {
    let path = temp_path("foreign.audit.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE credentials (id TEXT PRIMARY KEY);")
        .unwrap();
    drop(conn);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let Err(error) = open_sink(&sqlite_config(&path), AuditOpenMode::Startup) else {
        panic!("a foreign database must be refused");
    };
    assert!(
        error.to_string().contains("unknown or unrelated schema"),
        "{error}"
    );
    assert_eq!(count(&reader(&path), "SELECT COUNT(*) FROM credentials"), 0);
}

#[test]
fn reload_never_creates_or_migrates_an_audit_database() {
    let path = temp_path("reload-new.audit.sqlite");
    let config = sqlite_config(&path);
    let Err(error) = open_sink(&config, AuditOpenMode::Reload) else {
        panic!("reload must not create an audit database");
    };
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert!(!path.exists());

    // An empty file needs the baseline migration, which reload never runs.
    fs::write(&path, b"").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let Err(error) = open_sink(&config, AuditOpenMode::Reload) else {
        panic!("reload must not migrate an audit database");
    };
    assert!(error.to_string().contains("needs a migration"), "{error}");
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);

    drop(sink(&config));
    open_sink(&config, AuditOpenMode::Reload).unwrap();
}

#[test]
fn opening_checks_the_catalog_but_never_scans_the_database() {
    let path = temp_path("no-quick-check.audit.sqlite");
    *TRACED_PATH.lock().unwrap() = Some(path.clone());
    let traced = |statements: &[String], needle: &str| {
        statements
            .iter()
            .any(|statement| statement.to_ascii_lowercase().contains(needle))
    };

    drop(sink(&sqlite_config(&path)));
    let migration = std::mem::take(&mut *TRACED_STATEMENTS.lock().unwrap());
    // The trace sees the open: the migration ran foreign_key_check.
    assert!(traced(&migration, "foreign_key_check"), "{migration:?}");

    for mode in [AuditOpenMode::Startup, AuditOpenMode::Reload] {
        drop(open_sink(&sqlite_config(&path), mode).unwrap());
        let reopen = std::mem::take(&mut *TRACED_STATEMENTS.lock().unwrap());
        assert!(traced(&reopen, "schema_migrations"), "{reopen:?}");
        for scan in ["quick_check", "integrity_check", "foreign_key_check"] {
            assert!(!traced(&reopen, scan), "{mode:?} ran {scan}: {reopen:?}");
        }
    }
    *TRACED_PATH.lock().unwrap() = None;
}

#[tokio::test]
async fn database_id_is_created_once_and_preserved_across_restarts_and_reloads() {
    let path = temp_path("database-id.audit.sqlite");
    let config = sqlite_config(&path);
    let first = sink(&config);
    let database_id = first
        .store
        .as_ref()
        .unwrap()
        .database_id()
        .unwrap()
        .to_string();
    assert_eq!(
        Uuid::parse_str(&database_id).unwrap().to_string(),
        database_id
    );
    first.append_required(test_audit_record()).await.unwrap();
    shutdown(&first).await;

    for mode in [AuditOpenMode::Startup, AuditOpenMode::Reload] {
        let reopened = open_sink(&config, mode).unwrap();
        assert_eq!(
            reopened.store.as_ref().unwrap().database_id(),
            Some(database_id.as_str())
        );
    }
    let other = temp_path("database-id-other.audit.sqlite");
    let other = sink(&sqlite_config(&other));
    assert_ne!(
        other.store.as_ref().unwrap().database_id(),
        Some(database_id.as_str())
    );
    // A malformed database_id fails admission.
    reader(&path)
        .execute("UPDATE audit_meta SET value = 'not-a-uuid'", [])
        .unwrap();
    let Err(error) = open_sink(&config, AuditOpenMode::Startup) else {
        panic!("a malformed database_id must fail admission");
    };
    assert!(error.to_string().contains("database_id"), "{error}");
}

#[tokio::test]
async fn sync_all_durability_syncs_the_parent_directory_after_creating_the_database() {
    let path = temp_path("sync-all.audit.sqlite");
    let label = path.display().to_string();
    let syncs = Arc::new(AtomicUsize::new(0));
    let hook_syncs = Arc::clone(&syncs);
    let hook_label = label.clone();
    let _hook = install_audit_writer_hook(move |event| {
        if event.path == hook_label
            && event.kind == AuditWriterTestEventKind::ParentDirSync(AuditDurability::SyncAll)
        {
            hook_syncs.fetch_add(1, Ordering::SeqCst);
        }
    });
    let config = AuditConfig {
        durability: AuditDurability::SyncAll,
        ..sqlite_config(&path)
    };
    let created = sink(&config);
    assert_eq!(syncs.load(Ordering::SeqCst), 1);
    shutdown(&created).await;
    // Reopening an existing database does not sync the directory again.
    drop(sink(&config));
    assert_eq!(syncs.load(Ordering::SeqCst), 1);

    // write -> NORMAL (1); sync_data and sync_all -> FULL (2).
    for (durability, synchronous) in [
        (AuditDurability::Write, 1),
        (AuditDurability::SyncData, 2),
        (AuditDurability::SyncAll, 2),
    ] {
        let path = temp_path("synchronous.audit.sqlite");
        drop(sink(&AuditConfig {
            durability,
            ..sqlite_config(&path)
        }));
        assert_eq!(
            controls(&path).lock().unwrap().synchronous,
            Some(synchronous),
            "{durability:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_acknowledges_each_record_only_after_its_commit() {
    let path = temp_path("ack-after-commit.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    let gate = Arc::new(Gate::default());
    controls(&path).lock().unwrap().commit_gate = Some(Arc::clone(&gate));

    let mut append = enqueue_required(&sink, record_with("ack-after-commit", 0));
    assert!(gate.wait_entered(Duration::from_secs(10)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut append)
            .await
            .is_err(),
        "acknowledged before commit"
    );
    assert_eq!(
        count(&reader(&path), "SELECT COUNT(*) FROM audit_events"),
        0
    );
    gate.release();
    append.await.unwrap().unwrap();
    assert_eq!(
        count(&reader(&path), "SELECT COUNT(*) FROM audit_events"),
        1
    );
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_commit_fails_every_record_in_its_batch() {
    let path = temp_path("failed-batch.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("before", 0))
        .await
        .unwrap();
    take_events(&path);

    let (release, probe) = park_writer(&sink);
    let first = enqueue_required(&sink, record_with("batch-1", 0));
    let second = enqueue_required(&sink, record_with("batch-2", 0));
    sink.reserve_terminal()
        .await
        .unwrap()
        .send(record_with("batch-terminal", 0));
    controls(&path).lock().unwrap().fail_commits = true;
    drop(release);
    probe.await.unwrap().unwrap();

    assert!(matches!(
        first.await.unwrap(),
        Err(RuntimeError::Audit { .. })
    ));
    assert!(matches!(
        second.await.unwrap(),
        Err(RuntimeError::Audit { .. })
    ));
    let _ = sink.check_writable().await;
    assert!(
        events(&path).contains(&SqliteTestEvent::FailedCommit {
            records: 3,
            bytes: controls(&path).lock().unwrap().retained.unwrap().1,
        }),
        "{:?}",
        events(&path)
    );
    assert_eq!(
        recorded(&sink),
        set(&[AuditFailureClass::Append, AuditFailureClass::TerminalWrite])
    );
    assert_eq!(controls(&path).lock().unwrap().retained.unwrap().0, 3);
    let records = stored(&path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["brokerRequestId"], "before");
    controls(&path).lock().unwrap().fail_commits = false;
    shutdown(&sink).await;
}

#[tokio::test]
async fn a_healthy_probe_writes_nothing() {
    let path = temp_path("healthy-probe.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(test_audit_record()).await.unwrap();
    // The first append also starts the first maintenance cycle.
    wait_for_cycle_end(&sink, &path, 0).await;
    let conn = reader(&path);
    let data_version = count(&conn, "PRAGMA data_version");
    let [wal, _] = sqlite_support::sqlite_sidecar_paths(&path);
    let wal_len = fs::metadata(&wal).unwrap().len();
    let entries = || {
        let mut names = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let files = entries();

    for _ in 0..5 {
        sink.check_writable().await.unwrap();
    }

    assert_eq!(count(&conn, "PRAGMA data_version"), data_version);
    assert_eq!(fs::metadata(&wal).unwrap().len(), wal_len);
    assert_eq!(entries(), files);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_probe"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_events"), 1);
    assert!(
        !events(&path)
            .iter()
            .any(|event| matches!(event, SqliteTestEvent::Recovery { .. }))
    );
    shutdown(&sink).await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_probe_that_finds_loose_permissions_records_probe() {
    let path = temp_path("loose-probe.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(test_audit_record()).await.unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(sink.check_writable().await.is_err());
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Probe]));
    // Recovery repairs the mode, then a synthetic recovery transaction
    // clears Probe.
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.check_writable().await.unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    assert!(events(&path).contains(&SqliteTestEvent::Recovery {
        records: 1,
        bytes: row::SYNTHETIC_RECORD_BYTES,
        ok: true,
    }));
    shutdown(&sink).await;
}

/// The broker request IDs of the records `sink`'s reader pool returns for
/// `broker_request_id`, which leaves a pooled read connection open.
#[cfg(unix)]
async fn timeline(sink: &AuditSink, broker_request_id: &str) -> Vec<String> {
    sink.store
        .as_ref()
        .unwrap()
        .request_timeline(broker_request_id, crate::AuditVisibility::Global)
        .await
        .unwrap()
        .iter()
        .map(|record| {
            let record: Value = serde_json::from_str(record.get()).unwrap();
            record["brokerRequestId"].as_str().unwrap().to_string()
        })
        .collect()
}

#[cfg(unix)]
fn integrity_check(conn: &Connection) -> String {
    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap()
}

// Permission checks and repairs never open an existing database or sidecar:
// closing any descriptor for them would release the POSIX locks the live
// connections of this process hold, which another process then reads as
// "unused". `lock_probe` reads those locks from a separate process.

#[cfg(unix)]
#[tokio::test]
async fn startup_open_keeps_the_sqlite_locks_of_the_writer() {
    let path = temp_path("startup-locks.audit.sqlite");
    let config = sqlite_config(&path);
    let created = sink(&config);
    lock_probe::assert_sqlite_locks_held(&path, "creating and migrating the database");
    created
        .append_required(record_with("created", 0))
        .await
        .unwrap();
    shutdown(&created).await;
    drop(created);

    // A restart opens the existing database.
    let restarted = sink(&config);
    lock_probe::assert_sqlite_locks_held(&path, "reopening the database at startup");
    restarted
        .append_required(record_with("restarted", 0))
        .await
        .unwrap();
    assert_eq!(timeline(&restarted, "restarted").await, ["restarted"]);
    lock_probe::assert_sqlite_locks_held(&path, "appending and querying after a restart");
    shutdown(&restarted).await;
}

#[cfg(unix)]
#[tokio::test]
async fn reload_admission_keeps_the_sqlite_locks_of_the_live_generation() {
    let path = temp_path("reload-locks.audit.sqlite");
    let config = sqlite_config(&path);
    let first = sink(&config);
    first
        .append_required(record_with("first", 0))
        .await
        .unwrap();
    // The first generation's writer and a pooled reader are open.
    assert_eq!(timeline(&first, "first").await, ["first"]);
    lock_probe::assert_sqlite_locks_held(&path, "the first generation's startup open");

    let second = open_sink(&config, AuditOpenMode::Reload).unwrap();
    lock_probe::assert_sqlite_locks_held(&path, "reload admission of a second generation");

    first
        .append_required(record_with("first-after-reload", 0))
        .await
        .unwrap();
    second
        .append_required(record_with("second", 0))
        .await
        .unwrap();
    for sink in [&first, &second] {
        assert_eq!(timeline(sink, "second").await, ["second"]);
        assert_eq!(
            timeline(sink, "first-after-reload").await,
            ["first-after-reload"]
        );
    }
    lock_probe::assert_sqlite_locks_held(&path, "appends and queries on both generations");
    shutdown(&first).await;
    shutdown(&second).await;
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_repairs_loose_modes_without_releasing_the_sqlite_locks() {
    let path = temp_path("repair-locks.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("before-repair", 0))
        .await
        .unwrap();
    assert_eq!(timeline(&sink, "before-repair").await, ["before-repair"]);
    lock_probe::assert_sqlite_locks_held(&path, "opening the database");
    let [wal, shm] = sqlite_support::sqlite_sidecar_paths(&path);

    for loose in [&wal, &shm, &path] {
        fs::set_permissions(loose, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(sink.check_writable().await.is_err());
        assert_eq!(recorded(&sink), set(&[AuditFailureClass::Probe]));
        // Recovery runs `check_files(repair = true)` on the live writer.
        tokio::time::sleep(RECOVERY_INTERVAL).await;
        sink.check_writable().await.unwrap();
        assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
        for file in [&path, &wal, &shm] {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }
        lock_probe::assert_sqlite_locks_held(
            &path,
            &format!("recovery repairing {}", loose.display()),
        );
    }
    sink.append_required(record_with("after-repair", 0))
        .await
        .unwrap();
    assert_eq!(timeline(&sink, "after-repair").await, ["after-repair"]);
    assert_eq!(integrity_check(&reader(&path)), "ok");
    shutdown(&sink).await;
}

#[cfg(unix)]
#[tokio::test]
async fn an_online_backup_by_another_process_leaves_the_live_database_intact() {
    let path = temp_path("online-backup.audit.sqlite");
    let backup = path.with_file_name("backup.sqlite");
    let sink = sink(&sqlite_config(&path));
    let mut appended = 0_i64;
    for _ in 0..20 {
        sink.append_required(record_with(&format!("record-{appended}"), 512))
            .await
            .unwrap();
        appended += 1;
    }

    // The writer keeps appending while another process repeatedly opens the
    // database, backs it up, and closes its connection.
    let mut backups = lock_probe::spawn_online_backup(&path, &backup, 20);
    let before = appended;
    let deadline = Instant::now() + Duration::from_secs(120);
    while backups.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "the online backups did not finish"
        );
        sink.append_required(record_with(&format!("record-{appended}"), 512))
            .await
            .unwrap();
        appended += 1;
    }
    let report = lock_probe::finish_online_backup(backups);
    assert!(appended > before, "no append ran during the online backups");
    assert_eq!(report.source_integrity, "ok");
    assert_eq!(report.backup_integrity, "ok");
    assert!(report.backup_rows >= before, "{report:?}");
    lock_probe::assert_sqlite_locks_held(&path, "online backups by another process");

    // Appends and queries still succeed, the live database is intact, and a
    // backup taken now by another process has every acknowledged record.
    sink.append_required(record_with("after-backup", 0))
        .await
        .unwrap();
    appended += 1;
    assert_eq!(timeline(&sink, "after-backup").await, ["after-backup"]);
    assert_eq!(timeline(&sink, "record-0").await, ["record-0"]);
    let live = reader(&path);
    assert_eq!(integrity_check(&live), "ok");
    assert_eq!(count(&live, "SELECT COUNT(*) FROM audit_events"), appended);
    let last = lock_probe::finish_online_backup(lock_probe::spawn_online_backup(&path, &backup, 1));
    assert_eq!(last.backup_rows, appended);
    assert_eq!(last.backup_integrity, "ok");
    let copy = Connection::open_with_flags(&backup, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(count(&copy, "SELECT COUNT(*) FROM audit_events"), appended);
    assert_eq!(integrity_check(&copy), "ok");
    lock_probe::assert_sqlite_locks_held(&path, "appends and queries after the backups");
    shutdown(&sink).await;
}

#[tokio::test]
async fn derived_columns_follow_the_record() {
    let path = temp_path("columns.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    let mut record = test_audit_record();
    record.service = "broker".to_string();
    record.action = "admin.policy.grants.create".to_string();
    record.timestamp = "2026-09-26T12:00:00.123456+02:00".to_string();
    record.principal = format!("{}é", "a".repeat(1023));
    record.provider_audit = Some(json!({
        "management": {"targetService": "jira", "phase": "preflight", "target": "grant-7"},
        "bodySha256": "shouldnotbeindexed",
    }));
    record.identity_source = Some(super::super::IdentitySourceAudit {
        read_only_access: None,
        namespace: None,
        binding_id: None,
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        token_header: "Authorization".to_string(),
        token_scheme: "Bearer".to_string(),
        token_class: Some(crate::BrokerTokenClass::Admin),
        token_id: Some("tok_1".to_string()),
        token_scopes: None,
    });
    sink.append_required(record.clone()).await.unwrap();
    let mut management = record.clone();
    management.service = "broker".to_string();
    management.provider_audit = Some(json!({"gatewayPhase": "failed", "streamPhase": "started"}));
    management.timestamp = "not a timestamp".to_string();
    sink.append_required(management).await.unwrap();
    let mut invoke = test_audit_record();
    invoke.provider_audit = Some(json!({"gateway": {"phase": "completed"}}));
    invoke.upstream_status = Some(201);
    invoke.upstream_duration_ms = Some(17);
    sink.append_required(invoke).await.unwrap();

    let conn = reader(&path);
    let rows = conn
        .prepare(
            "SELECT ts_us, principal, scope_service, phase, token_id, token_class, upstream_status, upstream_duration_ms, record_bytes, length(CAST(record_json AS BLOB)) FROM audit_events ORDER BY id",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let expected_ts = chrono::DateTime::parse_from_rfc3339("2026-09-26T10:00:00.123456Z")
        .unwrap()
        .timestamp_micros();
    assert_eq!(rows[0].0, expected_ts);
    assert_eq!(rows[0].1, "a".repeat(1023));
    assert_eq!(rows[0].2.as_deref(), Some("jira"));
    assert_eq!(rows[0].3.as_deref(), Some("preflight"));
    assert_eq!(rows[0].4.as_deref(), Some("tok_1"));
    assert_eq!(rows[0].5.as_deref(), Some("admin"));
    assert_eq!(rows[0].8, rows[0].9);
    // Untargeted `broker` events have no scope service; the stream phase comes first; an
    // unparseable timestamp is indexed at the insert time.
    assert_eq!(rows[1].2, None);
    assert_eq!(rows[1].3.as_deref(), Some("started"));
    assert!((Utc::now().timestamp_micros() - rows[1].0).abs() < 60_000_000);
    assert_eq!(rows[2].2.as_deref(), Some("fake"));
    assert_eq!(rows[2].3.as_deref(), Some("completed"));
    assert_eq!((rows[2].6, rows[2].7), (Some(201), Some(17)));

    let matches = |query: &str| {
        count(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM audit_events_fts WHERE audit_events_fts MATCH '{query}'"
            ),
        )
    };
    // management.target is indexed; JSON keys are not.
    assert_eq!(matches("grant"), 1);
    assert_eq!(matches("grants"), 2);
    assert_eq!(matches("tok_1"), 2);
    assert_eq!(matches("targetservice"), 0);
    assert_eq!(matches("shouldnotbeindexed"), 0);
    assert_eq!(matches("payload"), 0);
    shutdown(&sink).await;
}

#[tokio::test]
async fn audit_verify_reports_a_healthy_database_and_fts_corruption() {
    let path = temp_path("verify.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    for index in 0..20 {
        sink.append_required(record_with(&format!("verify-{index}"), 64))
            .await
            .unwrap();
    }
    shutdown(&sink).await;
    drop(sink);

    let report = verify_sqlite_audit_database(&path).unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(
        report
            .checks
            .iter()
            .map(|check| check.name)
            .collect::<Vec<_>>(),
        ["schema", "integrity_check", "fts_integrity_check"]
    );
    assert!(report.database_id.is_some());

    reader(&path)
        .execute("DELETE FROM audit_events_fts_data WHERE id > 10", [])
        .unwrap();
    let report = verify_sqlite_audit_database(&path).unwrap();
    assert!(!report.is_ok());
    let fts = report
        .checks
        .iter()
        .find(|check| check.name == "fts_integrity_check")
        .unwrap();
    assert!(!fts.problems.is_empty(), "{report:?}");

    let missing = verify_sqlite_audit_database(&path.with_file_name("missing.sqlite"));
    assert!(missing.unwrap_err().contains("does not exist"));
}

// ---------------------------------------------------------------------------
// Failure and recovery
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CountingProvider {
    calls: AtomicUsize,
}

impl agent_access_provider::test_support::DescribedProvider for CountingProvider {
    fn descriptor(&self) -> agent_access_provider::ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl agent_access_provider::Provider for CountingProvider {
    async fn resolve_scopes(
        &self,
        request: agent_access_provider::ScopeRequest<'_>,
    ) -> Result<agent_access_provider::ScopeResolution, agent_access_provider::ProviderError> {
        agent_access_provider::Provider::resolve_scopes(&agent_access_fake::FakeProvider, request)
            .await
    }

    async fn invoke(
        &self,
        request: agent_access_provider::ProviderInvocation,
    ) -> Result<agent_access_provider::ProviderResult, agent_access_provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

fn supervised_context(agent_request_id: &str) -> GovernedOperationContext {
    GovernedOperationContext {
        admission: None,
        operation: OperationContext {
            agent_request_id: agent_request_id.to_string(),
            broker_request_id: format!("{agent_request_id}-broker"),
            identity: IdentityContext::anonymous(),
            service: "fake".into(),
            action: "echo".into(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
    }
}

fn supervised_request() -> InvokeRequest {
    serde_json::from_value(json!({"inputs": {"project": "TEST", "message": "hello"}})).unwrap()
}

fn recoveries(path: &Path) -> Vec<(usize, usize, bool)> {
    events(path)
        .into_iter()
        .filter_map(|event| match event {
            SqliteTestEvent::Recovery { records, bytes, ok } => Some((records, bytes, ok)),
            _ => None,
        })
        .collect()
}

fn commits(path: &Path) -> Vec<usize> {
    events(path)
        .into_iter()
        .filter_map(|event| match event {
            SqliteTestEvent::Commit { records, .. } => Some(records),
            _ => None,
        })
        .collect()
}

fn prepared_bytes(record: &AuditRecord) -> usize {
    prepared_bytes_on(record, TEST_NODE_ID)
}

fn prepared_bytes_on(record: &AuditRecord, node_id: &str) -> usize {
    PreparedRow::prepare(&StampedAuditRecord::new(record.clone(), node_id))
        .unwrap()
        .prepared_bytes()
}

async fn wait_for_health(sink: &AuditSink, expected: AuditFailureSet) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while recorded(sink) != expected {
        assert!(
            Instant::now() < deadline,
            "health stayed {:?}, expected {expected:?}",
            recorded(sink)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn append_many(sink: &AuditSink, records: impl IntoIterator<Item = AuditRecord>) {
    let appends = records
        .into_iter()
        .map(|record| enqueue_required(sink, record))
        .collect::<Vec<_>>();
    for append in appends {
        append.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_database_fails_closed_and_recovers_without_a_restart() {
    let path = temp_path("full.audit.sqlite");
    let mut config = base_fake_config();
    config.audit = Some(sqlite_config(&path));
    config.limits.upload_spool_dir = temp_path("full-spool").display().to_string();
    let provider = Arc::new(CountingProvider::default());
    let runtime = BrokerRuntime::with_providers(config, vec![Arc::clone(&provider)]).unwrap();
    let invoke = |id: &str| {
        runtime.invoke_owned(
            supervised_context(id),
            supervised_request(),
            InvocationControl::default(),
            false,
        )
    };
    assert_eq!(invoke("full-warm").await.status, 200);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    wait_for_cycle_end(&runtime.audit, &path, 0).await;

    // Allow no new pages: a single-row write still commits in existing
    // pages, but a realistic record with its full-text entry does not.
    let conn = reader(&path);
    let pages = count(&conn, "PRAGMA page_count");
    let free = count(&conn, "PRAGMA freelist_count");
    let page_size = count(&conn, "PRAGMA page_size") as usize;
    controls(&path).lock().unwrap().max_page_count = Some(pages as u64);
    {
        let limited = reader(&path);
        limited
            .query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(()))
            .unwrap();
        limited
            .execute(
                "INSERT INTO audit_meta(key, value) VALUES ('single-row', 'x')",
                [],
            )
            .unwrap();
        limited
            .execute("DELETE FROM audit_meta WHERE key = 'single-row'", [])
            .unwrap();
    }
    let full_record = record_with("full-record", (free as usize + 4) * page_size);
    let error = runtime.append_audit_record(&full_record).await.unwrap_err();
    assert!(error.to_string().contains("full"), "{error}");
    assert_eq!(recorded(&runtime.audit), set(&[AuditFailureClass::Append]));

    // Recovery attempts fail and readiness stays failing.
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    assert!(runtime.local_state_readiness().await.is_err());
    let full_bytes = prepared_bytes_on(&full_record, runtime.node_id());
    assert_eq!(recoveries(&path), vec![(1, full_bytes, false)]);
    assert_eq!(recorded(&runtime.audit), set(&[AuditFailureClass::Append]));

    // Supervised invocations are not dispatched.
    let denied = invoke("full-denied").await;
    assert_eq!(
        denied.envelope.reason_code,
        Some(ReasonCode::AuditUnavailable.into())
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    // Once the limit is raised, the next probe recovers without a restart.
    controls(&path).lock().unwrap().max_page_count = Some(1 << 30);
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    runtime.local_state_readiness().await.unwrap();
    assert_eq!(recorded(&runtime.audit), AuditFailureSet::EMPTY);
    assert_eq!(recoveries(&path).last(), Some(&(1, full_bytes, true)));
    assert_eq!(invoke("full-recovered").await.status, 200);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    runtime
        .append_audit_record(&test_audit_record())
        .await
        .unwrap();

    // The failed record was never committed, and the padding is empty.
    let records = stored(&path);
    assert!(
        !records
            .iter()
            .any(|record| record["brokerRequestId"] == "full-record")
    );
    assert!(
        records
            .iter()
            .any(|record| record["agentRequestId"] == "full-recovered")
    );
    assert_eq!(count(&conn, "SELECT length(padding) FROM audit_probe"), 0);
}

#[tokio::test]
async fn a_persistent_commit_failure_fails_closed_until_a_recovery_commit_succeeds() {
    let path = temp_path("commit-failure.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;

    controls(&path).lock().unwrap().fail_commits = true;
    assert!(
        sink.append_required(record_with("failed", 0))
            .await
            .is_err()
    );
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Append]));

    // A failed recovery attempt leaves Append recorded, not Probe.
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    assert!(sink.check_writable().await.is_err());
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Append]));
    assert_eq!(recoveries(&path).len(), 1);
    assert!(!recoveries(&path)[0].2);

    // Within the recovery interval a successful ordinary commit clears
    // nothing by itself.
    controls(&path).lock().unwrap().fail_commits = false;
    sink.append_required(record_with("ordinary", 0))
        .await
        .unwrap();
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Append]));
    assert!(sink.check_writable().await.is_err());
    assert_eq!(recoveries(&path).len(), 1);

    // After it, the next ordinary commit triggers a recovery attempt.
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.append_required(record_with("recovering", 0))
        .await
        .unwrap();
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    assert_eq!(recoveries(&path).len(), 2);
    assert!(recoveries(&path)[1].2);
    sink.check_writable().await.unwrap();
    let ids = stored(&path)
        .into_iter()
        .map(|record| record["brokerRequestId"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(!ids.contains(&"failed".to_string()), "{ids:?}");
    shutdown(&sink).await;
}

#[tokio::test]
async fn recovery_is_attempted_at_most_once_per_second() {
    let path = temp_path("recovery-rate.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;
    controls(&path).lock().unwrap().fail_commits = true;
    assert!(
        sink.append_required(record_with("failed", 0))
            .await
            .is_err()
    );

    tokio::time::sleep(RECOVERY_INTERVAL).await;
    for _ in 0..10 {
        assert!(sink.check_writable().await.is_err());
    }
    assert_eq!(recoveries(&path).len(), 1);
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    for _ in 0..10 {
        assert!(sink.check_writable().await.is_err());
    }
    assert_eq!(recoveries(&path).len(), 2);
    controls(&path).lock().unwrap().fail_commits = false;
    shutdown(&sink).await;
}

#[tokio::test]
async fn failure_classes_are_cleared_only_by_their_own_evidence() {
    let path = temp_path("classes.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;

    {
        let controls = controls(&path);
        let mut controls = controls.lock().unwrap();
        controls.fail_commits = true;
        controls.fail_slice = Some("delete");
        controls.force_maintenance = true;
    }
    assert!(
        sink.append_required(record_with("failed", 0))
            .await
            .is_err()
    );
    wait_for_health(
        &sink,
        set(&[AuditFailureClass::Append, AuditFailureClass::Prune]),
    )
    .await;

    // The delete works again but commits still fail: the retried delete
    // clears only Prune, and readiness keeps failing on Append.
    controls(&path).lock().unwrap().fail_slice = None;
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    assert!(sink.check_writable().await.is_err());
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Append]));

    controls(&path).lock().unwrap().fail_commits = false;
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.check_writable().await.unwrap();
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    shutdown(&sink).await;
}

#[tokio::test]
async fn terminal_write_failures_recover_the_same_way() {
    let path = temp_path("terminal-recovery.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;

    controls(&path).lock().unwrap().fail_commits = true;
    let terminal = record_with("terminal", 256);
    sink.reserve_terminal()
        .await
        .unwrap()
        .send(terminal.clone());
    wait_for_health(&sink, set(&[AuditFailureClass::TerminalWrite])).await;
    assert_eq!(
        controls(&path).lock().unwrap().retained,
        Some((1, prepared_bytes(&terminal)))
    );

    controls(&path).lock().unwrap().fail_commits = false;
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.check_writable().await.unwrap();
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    assert_eq!(
        recoveries(&path),
        vec![(1, prepared_bytes(&terminal), true)]
    );
    assert_eq!(controls(&path).lock().unwrap().retained, None);
    shutdown(&sink).await;
}

// ---------------------------------------------------------------------------
// Batch and size boundaries
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_257_records_commit_as_two_batches() {
    let path = temp_path("257.audit.sqlite");
    let sink = sink(&AuditConfig {
        queue_capacity: 1024,
        ..sqlite_config(&path)
    });
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;
    take_events(&path);

    let (release, probe) = park_writer(&sink);
    let appends = (0..257)
        .map(|index| enqueue_required(&sink, record_with(&format!("batch-{index}"), 0)))
        .collect::<Vec<_>>();
    // Every append (and the parked probe) holds a queue permit.
    let writer = sink.writer.as_ref().unwrap();
    assert_eq!(writer.normal_capacity.available_permits(), 1024 - 258);
    drop(release);
    probe.await.unwrap().unwrap();
    for append in appends {
        append.await.unwrap().unwrap();
    }
    assert_eq!(commits(&path), vec![256, 1]);
    assert_eq!(stored(&path).len(), 258);
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_records_over_16_mib_split_at_the_limit() {
    let path = temp_path("16mib-split.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;
    take_events(&path);

    let six_mib = 6 * 1024 * 1024;
    let (release, probe) = park_writer(&sink);
    let appends = (0..3)
        .map(|index| {
            enqueue_required(
                &sink,
                record_with_prepared_bytes(&format!("large-{index}"), six_mib),
            )
        })
        .collect::<Vec<_>>();
    drop(release);
    probe.await.unwrap().unwrap();
    for append in appends {
        append.await.unwrap().unwrap();
    }
    assert_eq!(
        events(&path)
            .into_iter()
            .filter(|event| matches!(event, SqliteTestEvent::Commit { .. }))
            .collect::<Vec<_>>(),
        vec![
            SqliteTestEvent::Commit {
                records: 2,
                bytes: 2 * six_mib
            },
            SqliteTestEvent::Commit {
                records: 1,
                bytes: six_mib
            },
        ]
    );
    shutdown(&sink).await;
}

#[tokio::test]
async fn a_record_at_the_size_limit_commits_on_its_own() {
    let path = temp_path("16mib-record.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    let record = record_with_prepared_bytes("at-limit", MAX_PREPARED_BYTES);
    sink.append_required(record).await.unwrap();
    assert!(events(&path).contains(&SqliteTestEvent::Commit {
        records: 1,
        bytes: MAX_PREPARED_BYTES,
    }));
    assert_eq!(stored(&path)[0]["brokerRequestId"], "at-limit");
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_record_fails_only_its_own_append() {
    let (captured, _guard) = capture_events();
    let path = temp_path("oversized.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;
    take_events(&path);
    captured.take();

    let (release, probe) = park_writer(&sink);
    let before = enqueue_required(&sink, record_with("before-oversized", 0));
    let oversized = enqueue_required(
        &sink,
        record_with_prepared_bytes("oversized", MAX_PREPARED_BYTES + 1),
    );
    let after = enqueue_required(&sink, record_with("after-oversized", 0));
    drop(release);
    probe.await.unwrap().unwrap();

    before.await.unwrap().unwrap();
    let error = oversized.await.unwrap().unwrap_err();
    assert!(matches!(error, RuntimeError::Audit { .. }), "{error}");
    after.await.unwrap().unwrap();
    assert_eq!(commits(&path), vec![2]);
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    assert_eq!(controls(&path).lock().unwrap().retained, None);
    let logs = logged(&captured, "audit_record_too_large");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["brokerRequestId"], "oversized");
    assert_eq!(logs[0]["nodeId"], TEST_NODE_ID);
    assert_eq!(logs[0]["preparedBytes"], (MAX_PREPARED_BYTES + 1) as u64);
    assert!(logs[0]["auditId"].as_str().is_some());
    let ids = stored(&path)
        .into_iter()
        .map(|record| record["brokerRequestId"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["warm", "before-oversized", "after-oversized"]);
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_replays_the_largest_failed_batch_until_it_fits() {
    let path = temp_path("largest-batch.audit.sqlite");
    let sink = sink(&sqlite_config(&path));
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, &path, 0).await;
    controls(&path).lock().unwrap().fail_commits = true;

    // A failed batch of nearly 16 MiB, then a smaller failed batch.
    let half = MAX_PREPARED_BYTES / 2 - 1024;
    let (release, probe) = park_writer(&sink);
    let large = (0..2)
        .map(|index| {
            enqueue_required(
                &sink,
                record_with_prepared_bytes(&format!("large-{index}"), half),
            )
        })
        .collect::<Vec<_>>();
    drop(release);
    probe.await.unwrap().unwrap();
    for append in large {
        assert!(append.await.unwrap().is_err());
    }
    let retained = controls(&path).lock().unwrap().retained;
    assert_eq!(retained, Some((2, 2 * half)));
    assert!(sink.append_required(record_with("small", 0)).await.is_err());
    // Memory stays bounded at one batch: the smaller batch did not replace it.
    assert_eq!(controls(&path).lock().unwrap().retained, retained);

    // Commits work again, and a small transaction fits, but the full batch
    // does not: recovery keeps failing.
    controls(&path).lock().unwrap().fail_commits = false;
    let pages = count(&reader(&path), "PRAGMA page_count");
    controls(&path).lock().unwrap().max_page_count = Some(pages as u64 + 512);
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    assert!(sink.check_writable().await.is_err());
    assert_eq!(recoveries(&path), vec![(2, 2 * half, false)]);
    sink.append_required(record_with("fits", 0)).await.unwrap();
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Append]));

    controls(&path).lock().unwrap().max_page_count = Some(1 << 30);
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.check_writable().await.unwrap();
    assert_eq!(recoveries(&path).last(), Some(&(2, 2 * half, true)));
    assert_eq!(controls(&path).lock().unwrap().retained, None);
    let ids = stored(&path)
        .into_iter()
        .map(|record| record["brokerRequestId"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["warm", "fits"]);
    shutdown(&sink).await;
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

fn retention_config(path: &Path) -> AuditConfig {
    AuditConfig {
        retention_days: 1,
        queue_capacity: 8192,
        ..sqlite_config(path)
    }
}

/// A sink whose first maintenance cycle has finished.
async fn warm_sink(config: &AuditConfig, path: &Path) -> AuditSink {
    let sink = sink(config);
    sink.append_required(record_with("warm", 0)).await.unwrap();
    wait_for_cycle_end(&sink, path, 0).await;
    sink
}

fn slices(path: &Path) -> Vec<&'static str> {
    events(path)
        .into_iter()
        .filter_map(|event| match event {
            SqliteTestEvent::Slice(slice) => Some(slice),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_deletes_remove_expired_rows_and_their_full_text_entries() {
    let path = temp_path("chunked-delete.audit.sqlite");
    let sink = warm_sink(&retention_config(&path), &path).await;
    append_many(
        &sink,
        (0..4_500).map(|index| expired_record(&format!("expired-{index}"), 3)),
    )
    .await;
    append_many(
        &sink,
        (0..10).map(|index| record_with(&format!("fresh-{index}"), 0)),
    )
    .await;
    let conn = reader(&path);
    let expired_matches =
        "SELECT COUNT(*) FROM audit_events_fts WHERE audit_events_fts MATCH 'expiredprincipal'";
    assert_eq!(count(&conn, expired_matches), 4_500);
    take_events(&path);

    run_maintenance_cycle(&sink, &path).await;

    let slices = slices(&path);
    assert_eq!(
        slices.iter().filter(|slice| **slice == "delete").count(),
        3,
        "{slices:?}"
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM audit_events WHERE principal = 'expiredprincipal'"
        ),
        0
    );
    assert_eq!(count(&conn, expired_matches), 0);
    // warm + 10 fresh + the cycle's trigger record remain.
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_events"), 12);
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn appends_during_a_maintenance_cycle_are_acknowledged_between_slices() {
    let path = temp_path("mid-cycle.audit.sqlite");
    let config = AuditConfig {
        enqueue_timeout_ms: 1_000,
        ..retention_config(&path)
    };
    let sink = warm_sink(&config, &path).await;
    append_many(
        &sink,
        (0..3_000).map(|index| {
            let mut record = expired_record(&format!("expired-{index}"), 3);
            record.provider_audit = Some(json!({"payload": "q ".repeat(512)}));
            record
        }),
    )
    .await;
    let merge = Arc::new(Gate::default());
    let vacuum = Arc::new(Gate::default());
    {
        let controls = controls(&path);
        let mut controls = controls.lock().unwrap();
        controls.events.clear();
        controls.slice_gates = vec![
            ("fts_merge", Arc::clone(&merge)),
            ("vacuum", Arc::clone(&vacuum)),
        ];
        controls.force_maintenance = true;
    }
    sink.append_required(record_with("trigger", 0))
        .await
        .unwrap();

    for (slice, gate) in [("fts_merge", &merge), ("vacuum", &vacuum)] {
        assert!(gate.wait_entered(Duration::from_secs(30)), "{slice}");
        let appends = (0..200)
            .map(|index| enqueue_required(&sink, record_with(&format!("{slice}-{index}"), 0)))
            .collect::<Vec<_>>();
        gate.release();
        for append in appends {
            append.await.unwrap().unwrap();
        }
    }
    wait_for_cycle_end(&sink, &path, 0).await;

    // Each gated slice is followed by the appends' commits before the next
    // slice starts.
    let events = events(&path);
    for slice in ["fts_merge", "vacuum"] {
        let position = events
            .iter()
            .position(|event| *event == SqliteTestEvent::Slice(slice))
            .unwrap();
        assert!(
            matches!(events[position + 1], SqliteTestEvent::Commit { .. }),
            "{slice}: {events:?}"
        );
        let committed = events[position + 1..]
            .iter()
            .take_while(|event| matches!(event, SqliteTestEvent::Commit { .. }))
            .map(|event| match event {
                SqliteTestEvent::Commit { records, .. } => *records,
                _ => 0,
            })
            .sum::<usize>();
        assert_eq!(committed, 200, "{slice}: {events:?}");
    }
    // Vacuum actually ran (the last vacuum visit is the threshold check)
    // and brought free pages below 10%.
    assert!(
        events
            .iter()
            .filter(|event| **event == SqliteTestEvent::Slice("vacuum"))
            .count()
            >= 2,
        "{events:?}"
    );
    let conn = reader(&path);
    let (free, pages) = (
        count(&conn, "PRAGMA freelist_count"),
        count(&conn, "PRAGMA page_count"),
    );
    assert!(free * 10 < pages, "{free} free of {pages}");
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passive_checkpoint_blocked_by_a_reader_is_deferred_without_marking_health() {
    let (captured, _guard) = capture_events();
    let path = temp_path("checkpoint.audit.sqlite");
    let sink = warm_sink(&sqlite_config(&path), &path).await;
    let long_reader = reader(&path);
    long_reader.execute_batch("BEGIN").unwrap();
    count(&long_reader, "SELECT COUNT(*) FROM audit_events");
    append_many(
        &sink,
        (0..50).map(|index| record_with(&format!("after-snapshot-{index}"), 256)),
    )
    .await;
    captured.take();

    run_maintenance_cycle(&sink, &path).await;
    let deferred = logged(&captured, "audit_wal_checkpoint_deferred");
    assert_eq!(deferred.len(), 1, "{deferred:?}");
    assert_eq!(deferred[0]["nodeId"], TEST_NODE_ID);
    assert!(deferred[0]["walBytes"].as_u64().unwrap() > 0);
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    sink.check_writable().await.unwrap();
    assert_eq!(sink.store.as_ref().unwrap().maintenance_failure(), None);

    // After the reader finishes, the next cycle checkpoints the WAL.
    long_reader.execute_batch("COMMIT").unwrap();
    captured.take();
    run_maintenance_cycle(&sink, &path).await;
    assert!(logged(&captured, "audit_wal_checkpoint_deferred").is_empty());
    let (busy, log, checkpointed): (i64, i64, i64) = reader(&path)
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!((busy, log), (0, checkpointed));
    shutdown(&sink).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_persistent_optional_slice_failure_never_affects_readiness() {
    let (captured, _guard) = capture_events();
    let path = temp_path("optional-failure.audit.sqlite");
    let sink = warm_sink(&retention_config(&path), &path).await;
    append_many(
        &sink,
        (0..2_000).map(|index| {
            let mut record = expired_record(&format!("expired-{index}"), 3);
            record.provider_audit = Some(json!({"payload": "v ".repeat(512)}));
            record
        }),
    )
    .await;
    let store = sink.store.as_ref().unwrap();
    controls(&path).lock().unwrap().fail_slice = Some("vacuum");

    for cycle in 0..2 {
        captured.take();
        run_maintenance_cycle(&sink, &path).await;
        let failures = logged(&captured, "audit_maintenance_failed");
        assert_eq!(failures.len(), 1, "cycle {cycle}: {failures:?}");
        assert_eq!(failures[0]["slice"], "vacuum");
        assert_eq!(failures[0]["sqliteErrorCode"], "SQLITE_IOERR");
        assert_eq!(failures[0]["nodeId"], TEST_NODE_ID);
        // The cycle's successful delete slices do not report it fixed.
        let failure = store.maintenance_failure().unwrap();
        assert_eq!(
            (failure.slice.as_str(), failure.error_code.as_str()),
            ("vacuum", "SQLITE_IOERR")
        );
        assert!(chrono::DateTime::parse_from_rfc3339(&failure.at).is_ok());
        assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
        sink.check_writable().await.unwrap();
        sink.append_required(record_with("still-writing", 0))
            .await
            .unwrap();
    }

    // The vacuum slice succeeds again, which clears the reported failure.
    controls(&path).lock().unwrap().fail_slice = None;
    run_maintenance_cycle(&sink, &path).await;
    assert_eq!(store.maintenance_failure(), None);

    // The other optional slices behave the same way.
    for slice in ["fts_merge", "optimize", "checkpoint"] {
        controls(&path).lock().unwrap().fail_slice = Some(slice);
        captured.take();
        run_maintenance_cycle(&sink, &path).await;
        let failures = logged(&captured, "audit_maintenance_failed");
        assert_eq!(failures.len(), 1, "{slice}: {failures:?}");
        assert_eq!(failures[0]["slice"], slice);
        assert_eq!(store.maintenance_failure().unwrap().slice, slice);
        sink.check_writable().await.unwrap();
        controls(&path).lock().unwrap().fail_slice = None;
        run_maintenance_cycle(&sink, &path).await;
        assert_eq!(store.maintenance_failure(), None, "{slice}");
    }
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    shutdown(&sink).await;
}

#[tokio::test]
async fn a_failed_delete_slice_records_prune_until_that_delete_succeeds() {
    let path = temp_path("prune-failure.audit.sqlite");
    let sink = warm_sink(&retention_config(&path), &path).await;
    append_many(
        &sink,
        (0..10).map(|index| expired_record(&format!("expired-{index}"), 3)),
    )
    .await;
    controls(&path).lock().unwrap().fail_slice = Some("delete");
    run_maintenance_cycle(&sink, &path).await;
    wait_for_health(&sink, set(&[AuditFailureClass::Prune])).await;
    assert!(sink.check_writable().await.is_err());
    // Neither an ordinary commit nor a successful probe of other classes
    // clears it.
    sink.append_required(record_with("ordinary", 0))
        .await
        .unwrap();
    assert_eq!(recorded(&sink), set(&[AuditFailureClass::Prune]));
    let conn = reader(&path);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM audit_events WHERE principal = 'expiredprincipal'"
        ),
        10
    );

    controls(&path).lock().unwrap().fail_slice = None;
    tokio::time::sleep(RECOVERY_INTERVAL).await;
    sink.check_writable().await.unwrap();
    assert_eq!(recorded(&sink), AuditFailureSet::EMPTY);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM audit_events WHERE principal = 'expiredprincipal'"
        ),
        0
    );
    shutdown(&sink).await;
}

// ---------------------------------------------------------------------------
// Scale (targets, not CI gates): run in a release build, where the bundled
// SQLite is optimized:
// `cargo test --release -p agent-access-core --lib scale_ -- --ignored --nocapture`.
// ---------------------------------------------------------------------------

#[ignore = "scale target; run explicitly"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scale_writer_sustains_2000_acknowledged_records_per_second() {
    let path = temp_path("scale-writer.audit.sqlite");
    let sink = warm_sink(&sqlite_config(&path), &path).await;
    let callers = 64;
    let per_caller = 400;
    let started = Instant::now();
    let tasks = (0..callers)
        .map(|caller| {
            let sink = sink.clone();
            tokio::spawn(async move {
                for index in 0..per_caller {
                    let mut record = test_audit_record();
                    record.broker_request_id = format!("scale-{caller}-{index}");
                    sink.append_required(record).await.unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    let rate = (callers * per_caller) as f64 / elapsed.as_secs_f64();
    println!(
        "scale: {} acknowledged records from {callers} callers in {elapsed:?}: {rate:.0} records/s",
        callers * per_caller
    );
    assert!(rate >= 2_000.0, "{rate:.0} records/s");
    shutdown(&sink).await;
}

#[ignore = "scale target; run explicitly"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scale_prune_of_100k_rows_does_not_delay_acknowledgements() {
    let path = temp_path("scale-prune.audit.sqlite");
    let sink = warm_sink(&retention_config(&path), &path).await;
    let seeded = Instant::now();
    for chunk in 0..25 {
        append_many(
            &sink,
            (0..4_000).map(|index| expired_record(&format!("expired-{chunk}-{index}"), 3)),
        )
        .await;
    }
    println!(
        "scale: seeded 100000 expired rows in {:?}",
        seeded.elapsed()
    );
    take_events(&path);

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = {
        let sink = sink.clone();
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut latencies = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                let started = Instant::now();
                sink.append_required(record_with("during-prune", 0))
                    .await
                    .unwrap();
                latencies.push(started.elapsed());
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            latencies
        })
    };
    let started = Instant::now();
    run_maintenance_cycle(&sink, &path).await;
    let cycle = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    let latencies = probe.await.unwrap();
    let max = latencies.iter().max().copied().unwrap_or_default();
    let deletes = slices(&path)
        .iter()
        .filter(|slice| **slice == "delete")
        .count();
    let mut longest = BTreeMap::<&str, Duration>::new();
    for (slice, duration) in &controls(&path).lock().unwrap().slice_durations {
        let entry = longest.entry(slice).or_default();
        *entry = (*entry).max(*duration);
    }
    println!("scale: longest slice durations {longest:?}");
    println!(
        "scale: pruned 100000 rows in {deletes} delete slices; cycle {cycle:?}; {} acks during it, max ack latency {max:?}",
        latencies.len()
    );
    assert_eq!(
        count(
            &reader(&path),
            "SELECT COUNT(*) FROM audit_events WHERE principal = 'expiredprincipal'"
        ),
        0
    );
    assert!(max <= Duration::from_millis(250), "{max:?}");
    shutdown(&sink).await;
}
