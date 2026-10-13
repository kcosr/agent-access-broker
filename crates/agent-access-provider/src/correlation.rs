//! Request correlation carried from the broker to upstream requests.

pub const REQUEST_ID_HEADER: &str = "X-Agent-Access-Request-Id";

pub const BROKER_REQUEST_ID_HEADER: &str = "X-Agent-Access-Broker-Request-Id";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationContext {
    pub agent_request_id: String,
    pub broker_request_id: String,
}

impl CorrelationContext {
    pub fn new(agent_request_id: String, broker_request_id: String) -> Self {
        Self {
            agent_request_id,
            broker_request_id,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        Self::new(
            "test-agent-request-id".to_string(),
            "test-broker-request-id".to_string(),
        )
    }
}

tokio::task_local! {
    static CURRENT_CORRELATION_CONTEXT: CorrelationContext;
}

tokio::task_local! {
    static CURRENT_PROVIDER_ACTION: (String, String);
}

tokio::task_local! {
    static CURRENT_HOOK: crate::HookContext;
}

/// Runs `future` as the provider hook `context` describes, with its service
/// and action as the current provider action.
pub(crate) async fn with_hook<F: std::future::Future>(
    context: crate::HookContext,
    future: F,
) -> F::Output {
    let action = (context.service().to_owned(), context.action().to_owned());
    CURRENT_HOOK
        .scope(context, CURRENT_PROVIDER_ACTION.scope(action, future))
        .await
}

/// The provider hook the current task runs, if the host is running one.
pub fn current_hook_context() -> Option<crate::HookContext> {
    CURRENT_HOOK.try_with(Clone::clone).ok()
}

pub async fn with_correlation_context<F>(correlation: CorrelationContext, future: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT_CORRELATION_CONTEXT.scope(correlation, future).await
}

pub async fn with_provider_context<F>(
    correlation: CorrelationContext,
    service: String,
    action: String,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    CURRENT_CORRELATION_CONTEXT
        .scope(
            correlation,
            CURRENT_PROVIDER_ACTION.scope((service, action), future),
        )
        .await
}

/// The invocation context of the current task (its correlation, provider
/// action, finalization control, and tracing span), for work the invocation moves onto another
/// task: task-local context does not follow `tokio::spawn`.
#[derive(Debug, Clone)]
pub struct InvocationScope {
    correlation: Option<CorrelationContext>,
    action: Option<(String, String)>,
    hook: Option<crate::HookContext>,
    finalization: Option<crate::ProviderFinalizationContext>,
    span: tracing::Span,
}

impl InvocationScope {
    pub fn current() -> Self {
        Self {
            correlation: current_correlation_context(),
            action: current_provider_action(),
            hook: current_hook_context(),
            finalization: crate::current_provider_finalization(),
            span: tracing::Span::current(),
        }
    }

    /// Runs `future` inside this context.
    pub async fn run<F: std::future::Future>(self, future: F) -> F::Output {
        use tracing::Instrument;
        let future = future.instrument(self.span);
        let future = async {
            match self.hook {
                Some(hook) => CURRENT_HOOK.scope(hook, future).await,
                None => future.await,
            }
        };
        let scoped = async {
            match (self.correlation, self.action) {
                (Some(correlation), Some(action)) => {
                    CURRENT_CORRELATION_CONTEXT
                        .scope(correlation, CURRENT_PROVIDER_ACTION.scope(action, future))
                        .await
                }
                (Some(correlation), None) => {
                    CURRENT_CORRELATION_CONTEXT.scope(correlation, future).await
                }
                (None, Some(action)) => CURRENT_PROVIDER_ACTION.scope(action, future).await,
                (None, None) => future.await,
            }
        };
        match self.finalization {
            Some(context) => crate::with_provider_finalization(context, scoped).await,
            None => scoped.await,
        }
    }
}

pub fn current_correlation_context() -> Option<CorrelationContext> {
    CURRENT_CORRELATION_CONTEXT.try_with(Clone::clone).ok()
}

pub fn current_provider_action() -> Option<(String, String)> {
    CURRENT_PROVIDER_ACTION.try_with(Clone::clone).ok()
}

pub fn apply_current_correlation_headers(
    builder: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    match current_correlation_context() {
        Some(correlation) => builder
            .header(REQUEST_ID_HEADER, correlation.agent_request_id)
            .header(BROKER_REQUEST_ID_HEADER, correlation.broker_request_id),
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invocation_scope_follows_work_onto_spawned_tasks() {
        let (correlation, action) = with_provider_context(
            CorrelationContext::for_tests(),
            "example".to_string(),
            "item.view".to_string(),
            async {
                let scope = InvocationScope::current();
                tokio::spawn(
                    scope.run(async { (current_correlation_context(), current_provider_action()) }),
                )
                .await
                .unwrap()
            },
        )
        .await;
        assert_eq!(correlation, Some(CorrelationContext::for_tests()));
        assert_eq!(
            action,
            Some(("example".to_string(), "item.view".to_string()))
        );
        let (correlation, action) = InvocationScope::current()
            .run(async { (current_correlation_context(), current_provider_action()) })
            .await;
        assert_eq!((correlation, action), (None, None));
    }
}
