//! Detached owners whose completion audit is their only record: the
//! application token mint and revocation owners and a reload's token
//! reconciliation. Each holds a lease from before it can outlive its waiter
//! until its store work and audit are done, and shutdown drains the leases
//! before the audit writers close.
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct OwnerDrain {
    owners: Mutex<usize>,
    changed: Notify,
}

/// One owner's place in the drain, released when the owner has finished.
pub(crate) struct OwnerLease(Arc<OwnerDrain>);

impl Drop for OwnerLease {
    fn drop(&mut self) {
        *self.0.owners.lock().unwrap() -= 1;
        self.0.changed.notify_waiters();
    }
}

impl OwnerDrain {
    /// Counts an owner. Registration never closes: an owner that starts
    /// while shutdown is under way is still waited for.
    pub(crate) fn register(self: &Arc<Self>) -> OwnerLease {
        *self.owners.lock().unwrap() += 1;
        OwnerLease(self.clone())
    }

    /// Waits up to `budget` for every owner to finish and returns how many
    /// have not: those may commit their store work without its audit record.
    pub(crate) async fn drain(&self, budget: Duration) -> usize {
        let empty = async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if *self.owners.lock().unwrap() == 0 {
                    return;
                }
                changed.await;
            }
        };
        let _ = tokio::time::timeout(budget, empty).await;
        let unfinished = *self.owners.lock().unwrap();
        if unfinished != 0 {
            tracing::error!(
                event = "application_owner_shutdown_unfinalized",
                count = unfinished,
                "application token owners did not finish within the shutdown budget; their store work may commit without its audit record"
            );
        }
        unfinished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_waits_for_leases_and_reports_those_left_at_the_deadline() {
        let drain = Arc::new(OwnerDrain::default());
        assert_eq!(drain.drain(Duration::from_millis(10)).await, 0);
        let first = drain.register();
        let second = drain.register();
        // The deadline passes with both owners unfinished.
        assert_eq!(drain.drain(Duration::from_millis(20)).await, 2);
        drop(first);
        assert_eq!(drain.drain(Duration::from_millis(20)).await, 1);
        // A drain in progress ends as soon as the last owner finishes.
        let waiting = drain.clone();
        let drained = tokio::spawn(async move { waiting.drain(Duration::from_secs(30)).await });
        tokio::task::yield_now().await;
        assert!(!drained.is_finished());
        drop(second);
        assert_eq!(drained.await.unwrap(), 0);
        // An owner that starts later is counted again.
        let late = drain.register();
        assert_eq!(drain.drain(Duration::from_millis(10)).await, 1);
        drop(late);
    }
}
