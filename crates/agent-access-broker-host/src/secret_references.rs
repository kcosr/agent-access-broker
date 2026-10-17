//! Expiry removes encrypted temporary secrets independently of new requests.
//! Safe issuance receipts remain until their configured retention deadline.

use crate::state::ReloadableState;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::instrument::WithSubscriber;

struct CleanupWorker {
    stop: CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Default)]
pub(crate) struct CleanupWorkerSlot(Mutex<Option<CleanupWorker>>);

impl CleanupWorkerSlot {
    pub(crate) fn start(&self, state: &Arc<ReloadableState>) {
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(Arc::downgrade(state), stop.clone()).with_current_subscriber());
        *self.0.lock().unwrap() = Some(CleanupWorker { stop, task });
    }

    pub(crate) fn stop(&self) {
        if let Some(worker) = &*self.0.lock().unwrap() {
            worker.stop.cancel();
        }
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) -> bool {
        let Some(worker) = self.0.lock().unwrap().take() else {
            return true;
        };
        worker.stop.cancel();
        let mut task = worker.task;
        if tokio::time::timeout(timeout, &mut task).await.is_ok() {
            true
        } else {
            task.abort();
            false
        }
    }
}

async fn run(state: Weak<ReloadableState>, stop: CancellationToken) {
    loop {
        if stop.is_cancelled() {
            return;
        }
        let Some(state) = state.upgrade() else { return };
        let runtime = state.current().runtime.clone();
        drop(state);
        if runtime.managed_store().is_some() {
            // A transaction already started completes before shutdown joins the
            // worker. Cleanup never invokes a provider or exposes a capability.
            match tokio::task::spawn_blocking(move || runtime.cleanup_secret_references()).await {
                Ok(Ok(_)) => {}
                _ => tracing::warn!(event = "secret_reference_cleanup_deferred"),
            }
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
    }
}
