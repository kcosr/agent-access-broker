//! The OAuth revocation worker: one task per serving process that works
//! through the remote revocations of the OAuth token families the Broker
//! ended. Its first pass at startup resumes any a previous process left
//! pending. It then runs when the OAuth manager signals a newly kept family
//! and whenever the next revocation falls due, through the current
//! generation's OAuth manager, so a reload changes the registrations it
//! revokes with. Shutdown stops it, cancelling a pass in progress: tokens
//! that pass had not recorded stay pending and are revoked again, which is
//! idempotent, by the next process.
use crate::state::ReloadableState;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::instrument::WithSubscriber;

/// The longest the worker waits between passes, so a signal it missed
/// delays a revocation no further.
const MAX_IDLE: Duration = Duration::from_secs(60);
/// The shortest wait after a pass, so a revocation that another pass in
/// this process holds is not polled in a busy loop.
const MIN_IDLE: Duration = Duration::from_secs(1);

/// A running worker, kept by the state that serves it.
pub(crate) struct RevocationWorker {
    stop: CancellationToken,
    task: JoinHandle<()>,
}

/// The state's worker slot: empty until serving starts the worker, and
/// again once shutdown has taken it.
#[derive(Default)]
pub(crate) struct RevocationWorkerSlot(Mutex<Option<RevocationWorker>>);

impl RevocationWorkerSlot {
    /// Starts the worker for `state`, which it reaches weakly so it never
    /// keeps the state alive.
    pub(crate) fn start(&self, state: &Arc<ReloadableState>) {
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(Arc::downgrade(state), stop.clone()).with_current_subscriber());
        *self.0.lock().unwrap() = Some(RevocationWorker { stop, task });
    }

    /// Stops the worker: it starts no further pass and abandons one in
    /// progress.
    pub(crate) fn stop(&self) {
        if let Some(worker) = &*self.0.lock().unwrap() {
            worker.stop.cancel();
        }
    }

    /// Stops the worker and waits up to `timeout` for its task to end,
    /// aborting it after that. Returns whether it ended in time.
    pub(crate) async fn shutdown(&self, timeout: Duration) -> bool {
        let Some(worker) = self.0.lock().unwrap().take() else {
            return true;
        };
        worker.stop.cancel();
        let mut task = worker.task;
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(_) => true,
            Err(_) => {
                task.abort();
                false
            }
        }
    }
}

async fn run(state: Weak<ReloadableState>, stop: CancellationToken) {
    let signal = agent_access_core::oauth_revocation_signal();
    loop {
        // Registered before the pass, so a family kept during it wakes the
        // next one.
        let woken = signal.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        let Some(state) = state.upgrade() else {
            return;
        };
        let snapshot = state.current();
        drop(state);
        let idle = match snapshot.runtime.oauth_manager() {
            Some(manager) => {
                let pass = tokio::select! {
                    () = stop.cancelled() => return,
                    pass = manager.revoke_due() => pass,
                };
                match pass {
                    Ok(next) => next.unwrap_or(MAX_IDLE).clamp(MIN_IDLE, MAX_IDLE),
                    // A generation a reload has replaced, or an unavailable
                    // store: try again with the current one shortly.
                    Err(error) => {
                        tracing::debug!(
                            event = "oauth_revocation_pass_deferred",
                            reason = error.code()
                        );
                        MIN_IDLE
                    }
                }
            }
            None => MAX_IDLE,
        };
        drop(snapshot);
        tokio::select! {
            () = stop.cancelled() => return,
            () = &mut woken => {}
            () = tokio::time::sleep(idle) => {}
        }
    }
}
