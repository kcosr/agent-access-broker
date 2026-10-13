//! The reader pool of one runtime generation's SQLite audit database.
//!
//! - Up to `connections` read-only connections, separate from the writer's,
//!   opened on first use (`query_only = ON`, `busy_timeout = 2000`,
//!   `temp_store = MEMORY`, never following a symlink).
//! - At most `connections` queries execute at once and at most `waiting`
//!   more wait for a connection; a query that finds the waiting slots full
//!   is rejected immediately.
//! - Each query has a deadline measured from admission that covers waiting
//!   for a connection, waiting for a blocking thread, and execution. A query
//!   whose deadline has passed never starts; one that is executing is
//!   interrupted. Dropping the caller's future (a client disconnect)
//!   interrupts the query the same way.
//! - A query owns its connection from checkout until SQLite has stopped, its
//!   statement is finalized, and its read transaction has ended. Deadline and
//!   disconnect interrupts are disarmed before the connection returns to the
//!   pool, so an interrupt meant for one query never reaches the next.
//! - Dropping the generation's pool admits nothing new (nothing can reach
//!   it), closes idle connections at once, and closes each running query's
//!   connection when that query finishes.

use super::schema::FileIdentity;
use crate::{AuditQueryError, AuditQueryLimits};
use rusqlite::{Connection, ErrorCode, InterruptHandle, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};
use tracing::Instrument;

/// How often an interrupt is repeated until SQLite reports that the query
/// stopped. SQLite clears a pending interrupt when a statement starts on an
/// idle connection, so an interrupt landing just before the first step
/// would otherwise be lost.
const INTERRUPT_RETRY: Duration = Duration::from_millis(5);

/// The per-generation pool handle. The runtime generation owns the only
/// handle; running queries keep the shared state alive until they finish.
pub(in crate::runtime) struct AuditReaderPool {
    shared: Arc<PoolShared>,
}

struct PoolShared {
    path: PathBuf,
    database_id: String,
    identity: FileIdentity,
    limits: AuditQueryLimits,
    /// One permit per connection: a query executes only while it holds one.
    executing: Arc<Semaphore>,
    /// Queries executing or waiting for a connection.
    admitted: AtomicUsize,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    idle: Vec<Connection>,
    /// Connections open now, idle or checked out.
    open: usize,
    closed: bool,
}

impl std::fmt::Debug for AuditReaderPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditReaderPool")
            .field("limits", &self.shared.limits)
            .finish_non_exhaustive()
    }
}

impl AuditReaderPool {
    pub(super) fn new(path: &Path, database_id: &str, identity: FileIdentity) -> Self {
        Self::with_limits(path, database_id, identity, limits_for(path))
    }

    pub(super) fn with_limits(
        path: &Path,
        database_id: &str,
        identity: FileIdentity,
        limits: AuditQueryLimits,
    ) -> Self {
        Self {
            shared: Arc::new(PoolShared {
                path: path.to_path_buf(),
                database_id: database_id.to_string(),
                identity,
                limits,
                executing: Arc::new(Semaphore::new(limits.connections)),
                admitted: AtomicUsize::new(0),
                state: Mutex::new(PoolState::default()),
            }),
        }
    }

    /// Runs `work` on a pooled connection on a blocking thread, inside the
    /// caller's tracing span. `work` must finish (drop) every statement it
    /// prepares, so the read transaction ends before it returns.
    pub(in crate::runtime) async fn run<T, F>(&self, work: F) -> Result<T, AuditQueryError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let admission = Admission::admit(&self.shared)?;
        let deadline = Instant::now() + self.shared.limits.deadline;
        let control = Arc::new(QueryControl::new(deadline));
        // Interrupts the query if this future is dropped before it finishes.
        let _disconnect = CancelOnDrop(Arc::clone(&control));
        tokio::spawn(watchdog(Arc::clone(&control)).in_current_span());
        let tokio_deadline = tokio::time::Instant::from_std(deadline);
        let permit = match tokio::time::timeout_at(
            tokio_deadline,
            Arc::clone(&self.shared.executing).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                control.cancel(Cancel::Deadline);
                return Err(AuditQueryError::Failed(
                    "audit reader pool is closed".to_string(),
                ));
            }
            Err(_) => {
                control.cancel(Cancel::Deadline);
                return Err(AuditQueryError::Timeout);
            }
        };
        let shared = Arc::clone(&self.shared);
        let task_control = Arc::clone(&control);
        // The blocking thread runs in the caller's span, so anything the query
        // logs stays correlated with the request that issued it.
        let span = tracing::Span::current();
        let task = tokio::task::spawn_blocking(move || {
            span.in_scope(|| {
                // Both are released only once the connection is back.
                let _permit = permit;
                let _admission = admission;
                execute(&shared, &task_control, work)
            })
        });
        match tokio::time::timeout_at(tokio_deadline, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(AuditQueryError::Failed(format!(
                "audit query task failed: {error}"
            ))),
            Err(_) => {
                // The blocking task still owns the connection; it returns it
                // once SQLite has stopped (or without starting).
                control.cancel(Cancel::Deadline);
                Err(AuditQueryError::Timeout)
            }
        }
    }

    #[cfg(test)]
    pub(in crate::runtime) fn open_connections(&self) -> usize {
        self.shared.lock_state().open
    }

    /// Queries executing or waiting for a connection.
    #[cfg(test)]
    pub(in crate::runtime) fn admitted(&self) -> usize {
        self.shared.admitted.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::runtime) fn shared_open_connections(&self) -> SharedOpenConnections {
        SharedOpenConnections(Arc::downgrade(&self.shared))
    }
}

impl Drop for AuditReaderPool {
    fn drop(&mut self) {
        self.shared.close();
    }
}

/// Observes a pool's open connections after its handle is dropped.
#[cfg(test)]
pub(in crate::runtime) struct SharedOpenConnections(std::sync::Weak<PoolShared>);

#[cfg(test)]
impl SharedOpenConnections {
    /// `None` once every running query has finished and the pool is gone.
    pub(in crate::runtime) fn get(&self) -> Option<usize> {
        self.0.upgrade().map(|shared| shared.lock_state().open)
    }
}

impl PoolShared {
    fn lock_state(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn checkout(&self) -> Result<Connection, AuditQueryError> {
        {
            let mut state = self.lock_state();
            if state.closed {
                return Err(AuditQueryError::Failed(
                    "audit reader pool is closed".to_string(),
                ));
            }
            if let Some(conn) = state.idle.pop() {
                return Ok(conn);
            }
            state.open += 1;
        }
        open_reader(&self.path, &self.identity, &self.database_id).map_err(|message| {
            self.lock_state().open -= 1;
            AuditQueryError::Failed(message)
        })
    }

    /// Returns a connection whose query has finished, or closes it when the
    /// pool is closed or it still has a transaction open.
    fn checkin(&self, conn: Connection) {
        let mut state = self.lock_state();
        if state.closed || !conn.is_autocommit() {
            state.open -= 1;
            drop(state);
            drop(conn);
            return;
        }
        state.idle.push(conn);
    }

    fn close(&self) {
        let idle = {
            let mut state = self.lock_state();
            state.closed = true;
            let idle = std::mem::take(&mut state.idle);
            state.open -= idle.len();
            idle
        };
        drop(idle);
    }
}

/// Opens one reader: read-only, never following a symlink or creating a
/// file, on the same database the writer opened.
fn open_reader(
    path: &Path,
    identity: &FileIdentity,
    database_id: &str,
) -> Result<Connection, String> {
    let label = path.display();
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("failed to open audit database {label} for reading: {error}"))?;
    conn.execute_batch(
        "PRAGMA query_only = ON; PRAGMA busy_timeout = 2000; PRAGMA temp_store = MEMORY;",
    )
    .map_err(|error| format!("failed to configure an audit database reader: {error}"))?;
    let current = FileIdentity::of(path)
        .map_err(|error| format!("failed to inspect audit database {label}: {error}"))?;
    if current != *identity {
        return Err(format!(
            "audit database {label} is no longer the database this broker opened"
        ));
    }
    let current_id: String = conn
        .query_row(
            "SELECT value FROM audit_meta WHERE key = 'database_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("failed to read the audit database_id: {error}"))?;
    if current_id != database_id {
        return Err(format!(
            "audit database {label} has a different database_id than the database this broker opened"
        ));
    }
    Ok(conn)
}

fn execute<T, F>(shared: &PoolShared, control: &QueryControl, work: F) -> Result<T, AuditQueryError>
where
    F: FnOnce(&Connection) -> rusqlite::Result<T>,
{
    control.check_start()?;
    let conn = shared.checkout()?;
    if let Err(error) = control.start(conn.get_interrupt_handle()) {
        shared.checkin(conn);
        return Err(error);
    }
    let result = work(&conn);
    // SQLite has stopped and `work` finalized its statements, so the read
    // transaction has ended. Disarm interrupts before anyone can reuse the
    // connection.
    control.finish();
    shared.checkin(conn);
    result.map_err(|error| match error.sqlite_error_code() {
        Some(ErrorCode::OperationInterrupted) => AuditQueryError::Timeout,
        _ => AuditQueryError::Failed(error.to_string()),
    })
}

/// Counts a query as admitted (executing or waiting) until dropped.
struct Admission(Arc<PoolShared>);

impl Admission {
    fn admit(shared: &Arc<PoolShared>) -> Result<Self, AuditQueryError> {
        let capacity = shared.limits.connections + shared.limits.waiting;
        shared
            .admitted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |admitted| {
                (admitted < capacity).then_some(admitted + 1)
            })
            .map(|_| Self(Arc::clone(shared)))
            .map_err(|_| AuditQueryError::ConcurrencyLimited)
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cancel {
    Deadline,
    Disconnect,
}

enum Phase {
    /// Admitted; not executing yet.
    Waiting,
    Running(InterruptHandle),
    /// SQLite has stopped; nothing may interrupt this connection for this
    /// query any more.
    Finished,
}

struct ControlState {
    phase: Phase,
    cancel: Option<Cancel>,
}

/// The shared state of one query between its caller, its watchdog, and the
/// blocking thread that executes it. Interrupts are delivered only while
/// holding the lock in the `Running` phase.
struct QueryControl {
    deadline: Instant,
    state: Mutex<ControlState>,
    wake: Notify,
}

impl QueryControl {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            state: Mutex::new(ControlState {
                phase: Phase::Waiting,
                cancel: None,
            }),
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ControlState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn cancelled_before_start(&self, state: &mut ControlState) -> Result<(), AuditQueryError> {
        if state.cancel.is_none() && Instant::now() >= self.deadline {
            state.cancel = Some(Cancel::Deadline);
        }
        match state.cancel {
            Some(_) => Err(AuditQueryError::Timeout),
            None => Ok(()),
        }
    }

    /// On the blocking thread, before checkout: a query past its deadline
    /// or cancelled never starts.
    fn check_start(&self) -> Result<(), AuditQueryError> {
        let mut state = self.lock();
        self.cancelled_before_start(&mut state)
    }

    fn start(&self, handle: InterruptHandle) -> Result<(), AuditQueryError> {
        let mut state = self.lock();
        self.cancelled_before_start(&mut state)?;
        state.phase = Phase::Running(handle);
        Ok(())
    }

    fn finish(&self) {
        self.lock().phase = Phase::Finished;
        self.wake.notify_one();
    }

    /// Records the first cancellation and interrupts a running query.
    fn cancel(&self, cancel: Cancel) {
        {
            let mut state = self.lock();
            if matches!(state.phase, Phase::Finished) {
                return;
            }
            state.cancel.get_or_insert(cancel);
            if let Phase::Running(handle) = &state.phase {
                handle.interrupt();
            }
        }
        self.wake.notify_one();
    }

    /// Repeats the interrupt of a cancelled running query. Returns whether
    /// the watchdog must keep watching.
    fn reinterrupt(&self) -> bool {
        let state = self.lock();
        match (&state.phase, state.cancel) {
            (Phase::Running(handle), Some(_)) => {
                handle.interrupt();
                true
            }
            (Phase::Running(_), None) | (Phase::Waiting, None) => true,
            (Phase::Waiting, Some(_)) | (Phase::Finished, _) => false,
        }
    }

    fn cancelled(&self) -> bool {
        self.lock().cancel.is_some()
    }
}

/// Cancels at the deadline or on disconnect, then repeats the interrupt
/// until SQLite stops. Exits when the query finishes or is cancelled before
/// it started (the blocking thread then never starts it).
async fn watchdog(control: Arc<QueryControl>) {
    let deadline = tokio::time::Instant::from_std(control.deadline);
    while !control.cancelled() {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => control.cancel(Cancel::Deadline),
            _ = control.wake.notified() => {}
        }
        if !control.reinterrupt() {
            return;
        }
    }
    while control.reinterrupt() {
        tokio::select! {
            _ = tokio::time::sleep(INTERRUPT_RETRY) => {}
            _ = control.wake.notified() => {}
        }
    }
}

struct CancelOnDrop(Arc<QueryControl>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel(Cancel::Disconnect);
    }
}

#[cfg(any(test, feature = "test-support"))]
static LIMIT_OVERRIDES: Mutex<Vec<(PathBuf, AuditQueryLimits)>> = Mutex::new(Vec::new());

/// Test builds may override the pool limits of the database at `path`
/// before the runtime that opens it is built.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn override_limits(path: &Path, limits: AuditQueryLimits) {
    let mut overrides = LIMIT_OVERRIDES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    overrides.retain(|(candidate, _)| candidate != path);
    overrides.push((path.to_path_buf(), limits));
}

fn limits_for(path: &Path) -> AuditQueryLimits {
    limits_override(path).unwrap_or_default()
}

#[cfg(any(test, feature = "test-support"))]
fn limits_override(path: &Path) -> Option<AuditQueryLimits> {
    LIMIT_OVERRIDES
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .find(|(candidate, _)| candidate == path)
        .map(|(_, limits)| *limits)
}

#[cfg(not(any(test, feature = "test-support")))]
fn limits_override(_path: &Path) -> Option<AuditQueryLimits> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_connection() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    /// Counts to `n` in a recursive CTE: CPU-bound work SQLite can interrupt.
    fn count_to(conn: &Connection, n: i64) -> rusqlite::Result<i64> {
        conn.query_row(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?1) SELECT count(*) FROM c",
            [n],
            |row| row.get(0),
        )
    }

    #[test]
    fn a_cancel_after_finish_never_interrupts_the_connection() {
        let conn = memory_connection();
        let control = QueryControl::new(Instant::now() + Duration::from_secs(60));
        control.check_start().unwrap();
        control.start(conn.get_interrupt_handle()).unwrap();
        assert_eq!(count_to(&conn, 10).unwrap(), 10);
        control.finish();
        // A deadline or disconnect arriving now must not reach the next
        // query on this connection.
        control.cancel(Cancel::Deadline);
        control.cancel(Cancel::Disconnect);
        assert!(!control.reinterrupt());
        assert_eq!(count_to(&conn, 200_000).unwrap(), 200_000);
    }

    #[test]
    fn a_query_cancelled_or_past_its_deadline_never_starts() {
        let conn = memory_connection();
        let expired = QueryControl::new(Instant::now());
        assert_eq!(expired.check_start(), Err(AuditQueryError::Timeout));
        assert_eq!(
            expired.start(conn.get_interrupt_handle()),
            Err(AuditQueryError::Timeout)
        );
        let cancelled = QueryControl::new(Instant::now() + Duration::from_secs(60));
        cancelled.cancel(Cancel::Disconnect);
        assert_eq!(cancelled.check_start(), Err(AuditQueryError::Timeout));
        // The watchdog has nothing left to interrupt.
        assert!(!cancelled.reinterrupt());
    }

    #[test]
    fn sqlite_clears_an_interrupt_delivered_to_an_idle_connection() {
        // Why a lost race is harmless: an interrupt that lands between
        // queries is cleared when the next statement starts.
        let conn = memory_connection();
        conn.get_interrupt_handle().interrupt();
        assert_eq!(count_to(&conn, 1_000).unwrap(), 1_000);
    }
}
