//! Supervised invocation ownership, independent of HTTP/SDK response waiters.
use crate::handlers::data::AdmittedInvocation;
use crate::state::{AppState, RequestPermits};
use agent_access_core::{
    BrokerResponse, ErrorBody, InvocationControl, InvokeRequest, ResponseEnvelope,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, oneshot};
use tracing::Instrument;

#[derive(Default)]
pub(crate) struct OperationRegistry {
    inner: Mutex<RegistryState>,
    changed: Notify,
}
#[derive(Default)]
struct RegistryState {
    next: u64,
    closing: bool,
    controls: BTreeMap<u64, InvocationControl>,
}
struct Registration {
    registry: Arc<OperationRegistry>,
    id: u64,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.registry
            .inner
            .lock()
            .unwrap()
            .controls
            .remove(&self.id);
        self.registry.changed.notify_waiters();
    }
}
impl OperationRegistry {
    fn register(self: &Arc<Self>, control: InvocationControl) -> Option<Registration> {
        let mut state = self.inner.lock().unwrap();
        if state.closing {
            return None;
        }
        let id = state.next;
        state.next += 1;
        state.controls.insert(id, control);
        Some(Registration {
            registry: self.clone(),
            id,
        })
    }
    pub(crate) fn close(&self) {
        self.inner.lock().unwrap().closing = true;
    }
    async fn empty(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.inner.lock().unwrap().controls.is_empty() {
                return;
            }
            changed.await;
        }
    }
    pub(crate) async fn shutdown(&self, budget: Duration) -> usize {
        self.close();
        // Leave a fraction of the drain budget for unknown-outcome finalization.
        let finalize_budget = (budget / 4).min(Duration::from_secs(1));
        if tokio::time::timeout(budget.saturating_sub(finalize_budget), self.empty())
            .await
            .is_ok()
        {
            return 0;
        }
        {
            let state = self.inner.lock().unwrap();
            for control in state.controls.values() {
                control.force_stop();
            }
        }
        let _ = tokio::time::timeout(finalize_budget, self.empty()).await;
        let unfinished = self.inner.lock().unwrap().controls.len();
        if unfinished != 0 {
            tracing::error!(
                event = "operation_shutdown_unfinalized",
                count = unfinished,
                "operation audit finalization did not finish within shutdown budget"
            );
        }
        unfinished
    }
}

pub(crate) async fn invoke(
    state: &AppState,
    admitted: AdmittedInvocation,
    request: InvokeRequest,
    control: InvocationControl,
    require_stream: bool,
) -> (BrokerResponse<Value>, Option<RequestPermits>) {
    let context = admitted.context.clone();
    let failed = || supervisor_failure(&context);
    let Some(registration) = state.reloadable.operations.register(control.clone()) else {
        let response = admitted
            .snapshot
            .runtime
            .governed_operation_error_response(
                admitted.context,
                agent_access_provider::ProviderError::error(
                    ReasonCode::ConcurrencyLimited,
                    "broker is shutting down",
                ),
            )
            .await;
        return (response, Some(admitted.permits));
    };
    let (send, receive) = oneshot::channel();
    // Registration is installed before spawning: shutdown cannot overlook a task
    // that has been admitted but has not been scheduled yet.
    tokio::spawn(
        async move {
            let _registration = registration;
            let permits = admitted.permits;
            let invocation = admitted.snapshot.runtime.invoke_owned(
                admitted.context,
                request,
                control,
                require_stream,
            );
            match AssertUnwindSafe(invocation).catch_unwind().await {
                Ok(response) => {
                    // Delivery takes over admission. If the waiter is gone, this
                    // drops both the stream (recording cancellation) and its permits.
                    let _ = send.send((response, permits));
                }
                Err(_) => {
                    // Provider/preparation panics are finalized inside core. This is
                    // a failure in finalization itself; never enqueue a second audit.
                    tracing::error!(
                        event = "operation_owner_failed",
                        "operation finalization failed unexpectedly"
                    );
                }
            }
        }
        .instrument(tracing::Span::current()),
    );
    match receive.await {
        Ok((response, permits)) => (response, Some(permits)),
        Err(_) => (failed(), None),
    }
}

fn supervisor_failure(
    context: &agent_access_core::GovernedOperationContext,
) -> BrokerResponse<Value> {
    BrokerResponse {
        retry_after_seconds: None,
        status: ReasonCode::AuditUnavailable.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id: context.operation.agent_request_id.clone(),
            broker_request_id: context.operation.broker_request_id.clone(),
            decision: Decision::Error,
            service: context.operation.service.clone(),
            action: context.operation.action.clone(),
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(ReasonCode::AuditUnavailable.into()),
            reason: Some("operation finalization failed; outcome must be reconciled".into()),
            result: Some(json!({"executionState":"unknown", "retrySafe":false})),
            error: Some(ErrorBody {
                message: "operation finalization failed; outcome must be reconciled".into(),
            }),
        },
        stream: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[tokio::test]
    async fn shutdown_tracks_owners_after_response_waiter_is_gone() {
        let registry = Arc::new(OperationRegistry::default());
        let control = InvocationControl::default();
        let registration = registry.register(control.clone()).unwrap();
        let registry_clone = registry.clone();
        let waiter =
            tokio::spawn(async move { registry_clone.shutdown(Duration::from_secs(1)).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        assert!(registry.register(InvocationControl::default()).is_none());
        drop(registration);
        assert_eq!(waiter.await.unwrap(), 0);
        assert!(registry.inner.lock().unwrap().controls.is_empty());
    }
    struct PausedProvider {
        invoked: tokio::sync::Semaphore,
        complete: tokio::sync::Semaphore,
        raw: bool,
        stream_dropped: Arc<AtomicBool>,
        stream_polled: Arc<AtomicBool>,
    }
    impl agent_access_provider::test_support::DescribedProvider for PausedProvider {
        fn descriptor(&self) -> agent_access_provider::ServiceDescriptor {
            let mut descriptor = agent_access_fake::fake_descriptor();
            if self.raw {
                for action in &mut descriptor.actions {
                    action.io = agent_access_provider::raw_download_io();
                }
            }
            descriptor
        }
    }

    struct StreamDrop(Arc<AtomicBool>);
    impl Drop for StreamDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl agent_access_provider::Provider for PausedProvider {
        async fn resolve_scopes(
            &self,
            request: agent_access_provider::ScopeRequest<'_>,
        ) -> Result<agent_access_provider::ScopeResolution, agent_access_provider::ProviderError>
        {
            agent_access_provider::Provider::resolve_scopes(
                &agent_access_fake::FakeProvider,
                request,
            )
            .await
        }
        async fn invoke(
            &self,
            request: agent_access_provider::ProviderInvocation,
        ) -> Result<agent_access_provider::ProviderResult, agent_access_provider::ProviderError>
        {
            self.invoked.add_permits(1);
            self.complete.acquire().await.unwrap().forget();
            if self.raw {
                let dropped = StreamDrop(Arc::clone(&self.stream_dropped));
                let polled = Arc::clone(&self.stream_polled);
                return Ok(
                    agent_access_provider::ProviderResult::new(json!({"size":3})).with_stream(
                        agent_access_provider::ProviderResultStream::from_stream(
                            "application/octet-stream",
                            futures_util::stream::once(async move {
                                let _dropped = dropped;
                                polled.store(true, Ordering::SeqCst);
                                Ok(bytes::Bytes::from_static(b"raw"))
                            }),
                        ),
                    ),
                );
            }
            agent_access_fake::FakeProvider.invoke(request).await
        }
    }
    async fn fixture() -> (
        AppState,
        AdmittedInvocation,
        Arc<PausedProvider>,
        tempfile::TempDir,
    ) {
        fixture_with_raw(false).await
    }

    async fn fixture_with_raw(
        raw: bool,
    ) -> (
        AppState,
        AdmittedInvocation,
        Arc<PausedProvider>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = agent_access_core::parse_broker_config_raw(
            "owned-test.toml",
            &format!(
                r#"
[deployment]
environment="development"
enable_fake_service=true

[providers.fake]
[identity]
mode="anonymous"
authority="toml"
[credentials.service.fake]
type="bearer_token"
token_ref="env:UNUSED_OWNED_TEST_TOKEN"
[policy]
authority="toml"
default_decision="deny"
[[policy.resources]]
id="test"
resource_type="fake_project"
selector={{kind="exact",value="TEST"}}
allowed_execution_contexts=["default"]
[[policy.grants]]
subjects=["group:anonymous"]
service="fake"
actions=["echo"]
resources={{resource_ids=["test"]}}
credential_mode="service"
[limits]
upload_spool_dir={spool:?}
"#,
                spool = dir.path().join("spool").display().to_string()
            ),
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        config.audit = Some(agent_access_core::AuditConfig::new(
            agent_access_core::AuditStoreType::Jsonl,
            dir.path().join("audit.jsonl").display().to_string(),
        ));
        config.limits.max_concurrent_requests = 1;
        assert_eq!(
            config
                .audit
                .as_ref()
                .unwrap()
                .effective_terminal_queue_capacity(&config.limits),
            1,
            "owned operations and their streams share one terminal audit slot"
        );
        let provider = Arc::new(PausedProvider {
            invoked: tokio::sync::Semaphore::new(0),
            complete: tokio::sync::Semaphore::new(0),
            raw,
            stream_dropped: Arc::new(AtomicBool::new(false)),
            stream_polled: Arc::new(AtomicBool::new(false)),
        });
        let runtime =
            agent_access_core::BrokerRuntime::with_providers(config, vec![provider.clone()])
                .unwrap();
        let audit_registry = runtime.audit_registry();
        let snapshot = crate::state::RuntimeSnapshot::new(
            1,
            "test".into(),
            runtime,
            agent_access_core::StateLockSet::empty(),
        );
        let state = AppState {
            reloadable: Arc::new(crate::state::ReloadableState::from_snapshot(
                std::path::PathBuf::new(),
                Arc::new(crate::backend_registry()),
                crate::broker_build_status(),
                snapshot.clone(),
                16 * 1024 * 1024,
                Duration::from_secs(1),
                Duration::from_secs(1),
                audit_registry,
            )),
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-agent-access-request-id",
            axum::http::HeaderValue::from_static("owned-test"),
        );
        let admitted = crate::handlers::data::admit_invoke(
            &state,
            snapshot,
            "127.0.0.1:1234".parse().unwrap(),
            &headers,
            "fake".into(),
            "echo".into(),
        )
        .await
        .unwrap();
        (state, admitted, provider, dir)
    }
    fn request() -> InvokeRequest {
        serde_json::from_value(json!({"inputs":{"project":"TEST","message":"hello"}})).unwrap()
    }
    /// Provider startup includes a real audit-writer probe and preparation.
    /// Give that setup scheduling room without changing the two-second
    /// shutdown/finalization contracts asserted after the provider starts.
    async fn wait_for_provider_start(
        provider: &PausedProvider,
        waiter: &mut tokio::task::JoinHandle<BrokerResponse<Value>>,
    ) {
        tokio::select! {
            started = provider.invoked.acquire() => {
                started.expect("provider-start semaphore remains open").forget();
            }
            result = waiter => {
                match result {
                    Ok(response) => panic!(
                        "invocation completed before provider startup: status={}, reason={:?}, result={:?}",
                        response.status, response.envelope.reason_code, response.envelope.result,
                    ),
                    Err(error) => panic!("invocation task failed before provider startup: {error}"),
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                panic!("provider startup did not finish within 10 seconds (including audit admission and preparation)");
            }
        }
    }

    #[tokio::test]
    async fn disconnected_waiter_keeps_permits_until_execution_and_audit_finish() {
        let (state, admitted, provider, dir) = fixture().await;
        let owner_state = state.clone();
        let mut waiter = tokio::spawn(async move {
            invoke(
                &owner_state,
                admitted,
                request(),
                InvocationControl::default(),
                false,
            )
            .await
            .0
        });
        wait_for_provider_start(&provider, &mut waiter).await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_err()
        );
        provider.complete.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), state.reloadable.operations.empty())
            .await
            .unwrap();
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_ok()
        );
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(records.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(records.lines().next().unwrap()).unwrap()["decision"],
            "allow"
        );
    }
    #[tokio::test]
    async fn forced_shutdown_finalizes_unknown_before_releasing_permits() {
        let (state, admitted, provider, dir) = fixture().await;
        let owner_state = state.clone();
        let mut waiter = tokio::spawn(async move {
            invoke(
                &owner_state,
                admitted,
                request(),
                InvocationControl::default(),
                false,
            )
            .await
            .0
        });
        wait_for_provider_start(&provider, &mut waiter).await;
        assert_eq!(
            state
                .reloadable
                // Finalization includes the real audit writer and filesystem;
                // leave the same bounded allowance used by the companion test.
                .shutdown_operations(Duration::from_secs(2))
                .await,
            0
        );
        let response = waiter.await.unwrap();
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationCancelled.into())
        );
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "unknown"
        );
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_ok()
        );
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(records.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(records.lines().next().unwrap()).unwrap()["providerAudit"]
                ["executionState"],
            "unknown"
        );
    }

    #[tokio::test]
    async fn raw_delivery_reuses_owned_terminal_audit_capacity() {
        let (state, admitted, provider, dir) = fixture_with_raw(true).await;
        let control = InvocationControl::default();
        provider.complete.add_permits(1);
        let (mut response, permits) = tokio::time::timeout(
            Duration::from_secs(10),
            invoke(&state, admitted, request(), control.clone(), true),
        )
        .await
        .expect("owned raw invocation completes with one terminal audit slot");
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        assert!(control.dispatched());
        assert!(control.completed());
        assert!(permits.is_some());
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_err(),
            "delivery keeps the invocation's admission permit"
        );
        let response_stream = response.stream.take().expect("raw response has a stream");
        let agent_access_provider::ProviderResultStreamSource::Stream(source) =
            response_stream.source
        else {
            panic!("raw response must preserve streaming delivery");
        };
        let mut stream = source.lock().unwrap().take().unwrap();
        let body = tokio::time::timeout(Duration::from_secs(2), async {
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                body.extend_from_slice(&chunk.unwrap());
            }
            body
        })
        .await
        .expect("delivery finishes with one terminal audit slot");
        assert_eq!(body, b"raw");
        assert!(provider.stream_polled.load(Ordering::SeqCst));
        assert!(provider.stream_dropped.load(Ordering::SeqCst));
        drop(stream);
        drop(permits);
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_ok()
        );
        state
            .reloadable
            .shutdown_audit(Duration::from_secs(2))
            .await
            .unwrap();
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let records: Vec<Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["providerAudit"]["streamPhase"], "started");
        assert_eq!(records[1]["providerAudit"]["streamPhase"], "completed");
        assert_eq!(records[1]["providerAudit"]["streamBytes"], 3);
        assert_eq!(records[0]["brokerRequestId"], records[1]["brokerRequestId"]);
    }

    #[tokio::test]
    async fn disconnected_raw_waiter_completes_owned_execution_and_cancels_undelivered_stream() {
        let (state, admitted, provider, dir) = fixture_with_raw(true).await;
        let control = InvocationControl::default();
        let owner_control = control.clone();
        let owner_state = state.clone();
        let mut waiter = tokio::spawn(async move {
            invoke(&owner_state, admitted, request(), owner_control, true)
                .await
                .0
        });
        wait_for_provider_start(&provider, &mut waiter).await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(control.dispatched());
        assert!(!control.completed());
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_err()
        );
        assert_eq!(
            state
                .reloadable
                .operations
                .inner
                .lock()
                .unwrap()
                .controls
                .len(),
            1
        );

        provider.complete.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), state.reloadable.operations.empty())
            .await
            .unwrap();
        assert!(
            control.completed(),
            "provider completion survives waiter loss"
        );
        assert!(provider.stream_dropped.load(Ordering::SeqCst));
        assert!(
            !provider.stream_polled.load(Ordering::SeqCst),
            "the owner must not drain an undelivered stream"
        );
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_ok()
        );
        state
            .reloadable
            .shutdown_audit(Duration::from_secs(2))
            .await
            .unwrap();
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let records: Vec<Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["providerAudit"]["streamPhase"], "started");
        assert_eq!(records[1]["providerAudit"]["streamPhase"], "canceled");
        assert_eq!(records[1]["providerAudit"]["streamBytes"], 0);
        assert_eq!(records[0]["brokerRequestId"], records[1]["brokerRequestId"]);
    }

    #[tokio::test]
    async fn forced_shutdown_tracks_disconnected_raw_owner_and_finalizes_unknown() {
        let (state, admitted, provider, dir) = fixture_with_raw(true).await;
        let control = InvocationControl::default();
        let owner_control = control.clone();
        let owner_state = state.clone();
        let mut waiter = tokio::spawn(async move {
            invoke(&owner_state, admitted, request(), owner_control, true)
                .await
                .0
        });
        wait_for_provider_start(&provider, &mut waiter).await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_err()
        );

        assert_eq!(
            state
                .reloadable
                .shutdown_operations(Duration::from_secs(2))
                .await,
            0
        );
        assert!(control.dispatched());
        assert!(
            !control.completed(),
            "shutdown must not invent provider completion"
        );
        assert!(!provider.stream_dropped.load(Ordering::SeqCst));
        assert!(!provider.stream_polled.load(Ordering::SeqCst));
        assert!(
            state
                .reloadable
                .shared_ingress
                .try_global_concurrency(1)
                .is_ok()
        );
        state
            .reloadable
            .shutdown_audit(Duration::from_secs(2))
            .await
            .unwrap();
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let records: Vec<Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "error");
        assert_eq!(records[0]["reasonCode"], "operation_cancelled");
        assert_eq!(records[0]["providerAudit"]["executionState"], "unknown");
        assert!(records[0]["providerAudit"].get("streamPhase").is_none());
    }
}
