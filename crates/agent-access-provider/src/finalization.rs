//! Host deadline and the bounded cleanup phase of one provider execution.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::time::Instant;

/// Per-invocation control shared by the host and trusted provider implementation.
/// This carries no provider result or authority to extend the host deadline.
#[derive(Clone, Debug)]
pub struct ProviderFinalizationContext {
    deadline: Option<Instant>,
    active: Arc<AtomicUsize>,
}

impl ProviderFinalizationContext {
    pub fn new(deadline: Option<Instant>) -> Self {
        Self {
            deadline,
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Enter only after the entire main outcome has been captured, when the
    /// remaining asynchronous work is interruptible cleanup. All dispatch must
    /// remain fenced by the deadline. At ordinary expiry the host may poll the
    /// existing execution future once, without waiting, to recover its outcome.
    /// Forced shutdown never grants that poll.
    pub fn enter_finalization(&self) -> ProviderFinalizationGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        ProviderFinalizationGuard {
            active: self.active.clone(),
        }
    }

    pub fn is_finalizing(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }
}

/// Clears this entry on return, cancellation, or unwind.
#[must_use]
pub struct ProviderFinalizationGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ProviderFinalizationGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

tokio::task_local! {
    static CURRENT_PROVIDER_FINALIZATION: ProviderFinalizationContext;
}

pub fn current_provider_finalization() -> Option<ProviderFinalizationContext> {
    CURRENT_PROVIDER_FINALIZATION.try_with(Clone::clone).ok()
}

pub async fn with_provider_finalization<F: std::future::Future>(
    context: ProviderFinalizationContext,
    future: F,
) -> F::Output {
    CURRENT_PROVIDER_FINALIZATION.scope(context, future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvocationScope;
    use futures_util::FutureExt;

    #[tokio::test]
    async fn invocation_scope_preserves_deadline_and_marker_across_tasks() {
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let context = ProviderFinalizationContext::new(Some(deadline));
        let guard = with_provider_finalization(context.clone(), async {
            let scope = InvocationScope::current();
            tokio::spawn(scope.run(async move {
                let inherited = current_provider_finalization().unwrap();
                assert_eq!(inherited.deadline(), Some(deadline));
                inherited.enter_finalization()
            }))
            .await
            .unwrap()
        })
        .await;
        assert!(context.is_finalizing());
        assert!(current_provider_finalization().is_none());
        drop(guard);
        assert!(!context.is_finalizing());
    }

    #[tokio::test]
    async fn guards_clear_after_cancellation_and_unwind_and_contexts_are_isolated() {
        let first = ProviderFinalizationContext::new(None);
        let second = ProviderFinalizationContext::new(None);
        with_provider_finalization(first.clone(), async {
            let mut pending = Box::pin(async {
                let _guard = current_provider_finalization()
                    .unwrap()
                    .enter_finalization();
                std::future::pending::<()>().await;
            });
            assert!(pending.as_mut().now_or_never().is_none());
            assert!(first.is_finalizing());
            with_provider_finalization(second.clone(), async {
                assert!(!current_provider_finalization().unwrap().is_finalizing());
                let _guard = current_provider_finalization()
                    .unwrap()
                    .enter_finalization();
                assert!(first.is_finalizing());
            })
            .await;
            assert!(!second.is_finalizing());
            drop(pending);
            assert!(!first.is_finalizing());
            let result = std::panic::AssertUnwindSafe(async {
                let _guard = current_provider_finalization()
                    .unwrap()
                    .enter_finalization();
                panic!("controlled finalization panic");
            })
            .catch_unwind()
            .await;
            assert!(result.is_err());
            assert!(!first.is_finalizing());
        })
        .await;
        assert!(current_provider_finalization().is_none());
    }
}
