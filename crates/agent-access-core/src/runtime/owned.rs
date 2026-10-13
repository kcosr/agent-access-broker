//! Owned JSON invocation phases. Preparation never finalizes; finalization is
//! deliberately outside cancellation/deadline selection so an audit cannot be
//! abandoned or repeated after its write has been queued.
use super::*;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicU8;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct InvocationControl {
    inner: Arc<ControlState>,
}
struct ControlState {
    gate: AtomicU8, // 0 preparation, 1 canceled before dispatch, 2 dispatched
    completed: AtomicBool,
    cancel: CancellationToken,
    forced: CancellationToken,
    deadline: Option<tokio::time::Instant>,
}
impl Default for InvocationControl {
    fn default() -> Self {
        Self::new(None)
    }
}
impl InvocationControl {
    pub fn new(timeout: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(ControlState {
                gate: AtomicU8::new(0),
                completed: AtomicBool::new(false),
                cancel: CancellationToken::new(),
                forced: CancellationToken::new(),
                deadline: timeout.map(|duration| tokio::time::Instant::now() + duration),
            }),
        }
    }
    /// Explicit cancellation prevents dispatch only when it wins this atomic gate.
    pub fn cancel(&self) {
        let _ = self
            .inner
            .gate
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        self.inner.cancel.cancel();
    }
    /// Shutdown's hard deadline: stop upstream work, then finalize an unknown outcome.
    pub fn force_stop(&self) {
        self.inner.forced.cancel();
    }
    pub fn dispatched(&self) -> bool {
        self.inner.gate.load(Ordering::SeqCst) == 2
    }
    pub fn completed(&self) -> bool {
        self.inner.completed.load(Ordering::SeqCst)
    }
    fn dispatch(&self) -> bool {
        self.inner
            .gate
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    async fn interrupted(&self, preparing: bool) -> (ReasonCode, &'static str) {
        tokio::select! {
            biased;
            _ = self.inner.forced.cancelled() => (ReasonCode::OperationCancelled, "operation stopped during broker shutdown"),
            _ = self.inner.cancel.cancelled(), if preparing => (ReasonCode::OperationCancelled, "operation canceled before provider dispatch"),
            _ = async {
                if let Some(deadline) = self.inner.deadline { tokio::time::sleep_until(deadline).await; }
                else { std::future::pending::<()>().await; }
            } => (ReasonCode::OperationTimeout, "operation deadline exceeded"),
        }
    }
}

pub(super) struct PreparationFailure {
    pub(super) context: FinalizeContext,
    pub(super) result: Result<ProviderResult, ProviderError>,
}
impl PreparationFailure {
    pub(super) fn new(
        context: FinalizeContext,
        result: Result<ProviderResult, ProviderError>,
    ) -> Self {
        Self { context, result }
    }
}

fn interrupted_error(
    (reason, message): (ReasonCode, &'static str),
    dispatched: bool,
) -> ProviderError {
    ProviderError::error(reason, message)
        .with_result(json!({"executionState": if dispatched {"unknown"} else {"not_dispatched"}, "retrySafe":false}))
        .with_audit(json!({"executionState": if dispatched {"unknown"} else {"not_dispatched"}, "retrySafe":false}))
}

impl BrokerRuntime {
    /// Run within a supervisor that owns this future independently of HTTP/SDK
    /// response delivery. Caller cancellation must use `control`, never drop it.
    pub async fn invoke_owned_json(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
        control: InvocationControl,
    ) -> BrokerResponse<Value> {
        let fallback = FinalizeContext {
            search_authorization: None,
            agent_request_id: context.operation.agent_request_id.clone(),
            broker_request_id: context.operation.broker_request_id.clone(),
            policy_generation: self.policy_generation(),
            identity: context.operation.identity.clone(),
            service: context.operation.service.clone(),
            action: context.operation.action.clone(),
            upstream_resource_ownership: None,
            resource_scopes: ResourceScopes::new(),
            credential_mode: None,
            matched_grant: None,
            source: context.operation.source.clone(),
            execution_context: Some(context.execution_context.clone()),
            redact_error_resource_scopes: false,
            started: Instant::now(),
        };
        // Reserve terminal capacity before provider preparation/dispatch. A health
        // probe enforces the same fail-closed durable audit boundary as existing work.
        let admission = async {
            self.audit.check_writable().await?;
            self.audit.reserve_terminal().await
        };
        let permit = tokio::select! {
            biased;
            message = control.interrupted(true) => {
                return self.finalize(fallback, Err(interrupted_error(message, false))).await;
            }
            result = admission => match result {
                Ok(permit) => permit,
                Err(error) => return trusted_callers::PreDispatchFailure::Admission.apply(audit_unavailable_response(
                    fallback.agent_request_id, fallback.broker_request_id, fallback.service,
                    fallback.action, fallback.resource_scopes, error,
                )),
            }
        };
        let preparation = AssertUnwindSafe(self.prepare_invoke(context, request)).catch_unwind();
        let prepared = tokio::select! {
            biased;
            message = control.interrupted(true) => Err(Box::new(PreparationFailure::new(fallback.clone(), Err(interrupted_error(message, false))))),
            result = preparation => match result {
                Ok(result) => result,
                Err(_) => Err(Box::new(PreparationFailure::new(fallback, Err(interrupted_error((ReasonCode::OperationFailed, "operation failed during preparation"), false))))),
            }
        };
        let (finalize_context, result) = match prepared {
            Err(failure) => (failure.context, failure.result),
            Ok(mut prepared) => {
                let finalize_context = prepared.finalize_context.clone();
                if !control.dispatch() {
                    (
                        finalize_context,
                        Err(interrupted_error(
                            (
                                ReasonCode::OperationCancelled,
                                "operation canceled before provider dispatch",
                            ),
                            false,
                        )),
                    )
                } else {
                    let body_parts = std::mem::take(&mut prepared.body_parts);
                    let finalization = ProviderFinalizationContext::new(control.inner.deadline);
                    let execution = AssertUnwindSafe(with_provider_finalization(
                        finalization.clone(),
                        self.execute_prepared_invoke(prepared, body_parts, false),
                    ))
                    .catch_unwind();
                    tokio::pin!(execution);
                    let result = tokio::select! {
                        biased;
                        message = control.interrupted(false) => {
                            // Only cleanup of an already captured outcome gets one
                            // nonblocking poll. Pending work keeps the ordinary
                            // timeout, and hard shutdown never grants this poll.
                            if message.0 == ReasonCode::OperationTimeout
                                && !control.inner.forced.is_cancelled()
                                && finalization.is_finalizing()
                            {
                                execution.as_mut().now_or_never().ok_or(message)
                            } else {
                                Err(message)
                            }
                        },
                        result = &mut execution => Ok(result),
                    };
                    match result {
                        Ok(Ok(result)) => {
                            control.inner.completed.store(true, Ordering::SeqCst);
                            result
                        }
                        Ok(Err(_)) => (
                            finalize_context,
                            Err(interrupted_error(
                                (
                                    ReasonCode::OperationFailed,
                                    "provider operation failed unexpectedly; outcome is unknown",
                                ),
                                true,
                            )),
                        ),
                        Err(message) => (finalize_context, Err(interrupted_error(message, true))),
                    }
                }
            }
        };
        // No cancellation select around finalization: the reserved terminal append
        // is acknowledged before success and cannot race a second outcome record.
        let applied_unverified = result.as_ref().err().is_some_and(|error| {
            error.reason_code() == ReasonCode::MutationVerificationFailed
                && error
                    .result
                    .as_ref()
                    .and_then(|value| value.get("mutationStatus"))
                    .and_then(Value::as_str)
                    == Some("applied_unverified")
        });
        let mut response = self
            .finalize_with_append_mode(
                finalize_context,
                result,
                AuditAppendMode::OwnedTerminal(permit),
            )
            .await;
        if response.envelope.reason_code == Some(ReasonCode::AuditUnavailable.into()) {
            // A failure to acknowledge audit is not proof that the provider did
            // nothing. Preserve safe completion evidence without copying results.
            let mut evidence = json!({
                "executionState": if control.completed() { "completed" }
                    else if control.dispatched() { "unknown" } else { "not_dispatched" },
                "retrySafe": false,
            });
            if applied_unverified {
                evidence["mutationStatus"] = json!("applied_unverified");
            }
            response.envelope.result = Some(evidence);
        }
        if !control.dispatched()
            && let Some(stage) = response
                .envelope
                .reason_code
                .as_ref()
                .and_then(ReasonCodeId::standard)
                .and_then(trusted_callers::PreDispatchFailure::for_reason)
        {
            response = stage.apply(response);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;
    use tokio::sync::Semaphore;

    #[derive(Clone, Copy)]
    enum FinalizationMode {
        Success,
        Failure,
        Pending,
        Unmarked,
    }

    struct ControlledProvider {
        lookup_started: Semaphore,
        lookup_continue: Semaphore,
        invoked: Semaphore,
        complete: Semaphore,
        calls: AtomicUsize,
        panic_invoke: bool,
        finalization: Option<FinalizationMode>,
        cleanup_started: Semaphore,
        cleanup_polls: AtomicUsize,
        finalization_context: Mutex<Option<ProviderFinalizationContext>>,
    }
    impl ControlledProvider {
        fn new(pause_lookup: bool, panic_invoke: bool) -> Arc<Self> {
            Arc::new(Self {
                lookup_started: Semaphore::new(0),
                lookup_continue: Semaphore::new(usize::from(!pause_lookup)),
                invoked: Semaphore::new(0),
                complete: Semaphore::new(0),
                calls: AtomicUsize::new(0),
                panic_invoke,
                finalization: None,
                cleanup_started: Semaphore::new(0),
                cleanup_polls: AtomicUsize::new(0),
                finalization_context: Mutex::new(None),
            })
        }

        fn finalizing(mode: FinalizationMode) -> Arc<Self> {
            let mut provider = Self::new(false, false);
            Arc::get_mut(&mut provider).unwrap().finalization = Some(mode);
            provider.complete.add_permits(1);
            provider
        }
    }
    impl agent_access_provider::test_support::DescribedProvider for ControlledProvider {
        fn descriptor(&self) -> ServiceDescriptor {
            agent_access_fake::fake_descriptor()
        }
    }

    #[async_trait]
    impl Provider for ControlledProvider {
        async fn resolve_scopes(
            &self,
            request: ScopeRequest<'_>,
        ) -> Result<ScopeResolution, ProviderError> {
            self.lookup_started.add_permits(1);
            self.lookup_continue.acquire().await.unwrap().forget();
            agent_access_fake::FakeProvider
                .echo_scopes(request.action(), request.inputs())
                .map(ScopeResolution::resources)
        }
        async fn invoke(
            &self,
            request: ProviderInvocation,
        ) -> Result<ProviderResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.invoked.add_permits(1);
            assert!(!self.panic_invoke, "controlled provider panic");
            self.complete.acquire().await.unwrap().forget();
            let outcome = if matches!(self.finalization, Some(FinalizationMode::Failure)) {
                Err(
                    ProviderError::error(ReasonCode::UpstreamFailed, "known provider failure")
                        .with_result(json!({"knownOutcome":true}))
                        .with_audit(json!({"knownOutcome":true})),
                )
            } else {
                agent_access_fake::FakeProvider.invoke(request).await
            };
            if let Some(mode) = self.finalization {
                let context = current_provider_finalization().unwrap();
                *self.finalization_context.lock().unwrap() = Some(context.clone());
                let _guard = (!matches!(mode, FinalizationMode::Unmarked))
                    .then(|| context.enter_finalization());
                self.cleanup_started.add_permits(1);
                // No cleanup timer/waker: only the host deadline can poll this
                // future again. This detects a grace period or an extra poll.
                std::future::poll_fn(|_| {
                    self.cleanup_polls.fetch_add(1, Ordering::SeqCst);
                    if !matches!(mode, FinalizationMode::Pending)
                        && context
                            .deadline()
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
                    {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
            outcome
        }
    }
    fn fixture(provider: Arc<ControlledProvider>) -> (BrokerRuntime, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = super::super::tests::base_fake_config();
        config.audit = Some(crate::AuditConfig::new(
            crate::AuditStoreType::Jsonl,
            dir.path().join("audit.jsonl").display().to_string(),
        ));
        config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
        (
            BrokerRuntime::with_providers(config, vec![provider]).unwrap(),
            dir,
        )
    }
    fn context() -> GovernedOperationContext {
        GovernedOperationContext {
            operation: OperationContext {
                agent_request_id: "owned-test".into(),
                broker_request_id: "owned-test-broker".into(),
                identity: IdentityContext::anonymous(),
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            },
            execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
        }
    }
    fn request() -> InvokeRequest {
        serde_json::from_value(json!({"inputs":{"project":"TEST","message":"hello"}})).unwrap()
    }
    fn audit(dir: &TempDir) -> Value {
        let mut records = crate::test_support::read_audit_records(
            crate::AuditStoreType::Jsonl,
            &dir.path().join("audit.jsonl"),
        );
        assert_eq!(records.len(), 1, "exactly one terminal record: {records:?}");
        records.remove(0)
    }
    async fn entered(semaphore: &Semaphore) {
        tokio::time::timeout(Duration::from_secs(10), semaphore.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
    #[tokio::test]
    async fn cancel_during_preparation_prevents_dispatch_and_finalizes_once() {
        let provider = ControlledProvider::new(true, false);
        let (runtime, dir) = fixture(provider.clone());
        let control = InvocationControl::default();
        let operation = {
            let control = control.clone();
            tokio::spawn(async move {
                runtime
                    .invoke_owned_json(context(), request(), control)
                    .await
            })
        };
        entered(&provider.lookup_started).await;
        control.cancel();
        let response = operation.await.unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(!control.dispatched());
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "not_dispatched"
        );
        assert_eq!(
            audit(&dir)["providerAudit"]["executionState"],
            "not_dispatched"
        );
    }
    #[tokio::test]
    async fn deadline_includes_preparation_and_prevents_provider_dispatch() {
        let provider = ControlledProvider::new(true, false);
        let (runtime, dir) = fixture(provider.clone());
        let control = InvocationControl::new(Some(Duration::from_secs(5)));
        let operation = {
            let control = control.clone();
            tokio::spawn(async move {
                runtime
                    .invoke_owned_json(context(), request(), control)
                    .await
            })
        };
        entered(&provider.lookup_started).await;
        let response = operation.await.unwrap();
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationTimeout.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(!control.dispatched());
        assert!(!control.completed());
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "not_dispatched"
        );
        assert_eq!(
            audit(&dir)["providerAudit"]["executionState"],
            "not_dispatched"
        );
    }
    #[tokio::test]
    async fn cancellation_after_dispatch_preserves_completion_and_terminal_audit() {
        let provider = ControlledProvider::new(false, false);
        let (runtime, dir) = fixture(provider.clone());
        let control = InvocationControl::default();
        let operation = {
            let control = control.clone();
            tokio::spawn(async move {
                runtime
                    .invoke_owned_json(context(), request(), control)
                    .await
            })
        };
        entered(&provider.invoked).await;
        control.cancel();
        tokio::task::yield_now().await;
        assert!(!operation.is_finished());
        provider.complete.add_permits(1);
        let response = operation.await.unwrap();
        assert_eq!(response.status, 200);
        assert!(control.completed());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit(&dir)["decision"], "allow");
    }
    #[tokio::test]
    async fn deadline_after_dispatch_reports_unknown_and_audits_once() {
        let provider = ControlledProvider::new(false, false);
        let (runtime, dir) = fixture(provider.clone());
        let control = InvocationControl::new(Some(Duration::from_secs(5)));
        let operation = {
            let control = control.clone();
            tokio::spawn(async move {
                runtime
                    .invoke_owned_json(context(), request(), control)
                    .await
            })
        };
        entered(&provider.invoked).await;
        let response = operation.await.unwrap();
        assert_eq!(response.status, 504);
        assert!(control.dispatched());
        assert!(!control.completed());
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "unknown"
        );
        assert_eq!(audit(&dir)["providerAudit"]["retrySafe"], false);
    }

    #[tokio::test]
    async fn finalization_deadline_preserves_known_success_and_failure() {
        for mode in [FinalizationMode::Success, FinalizationMode::Failure] {
            let provider = ControlledProvider::finalizing(mode);
            let (runtime, dir) = fixture(provider.clone());
            let control = InvocationControl::new(Some(Duration::from_secs(1)));
            let operation = {
                let control = control.clone();
                tokio::spawn(async move {
                    runtime
                        .invoke_owned_json(context(), request(), control)
                        .await
                })
            };
            entered(&provider.cleanup_started).await;
            let response = operation.await.unwrap();
            assert!(control.dispatched());
            assert!(control.completed());
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(provider.cleanup_polls.load(Ordering::SeqCst), 2);
            assert!(
                !provider
                    .finalization_context
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .is_finalizing()
            );
            let record = audit(&dir);
            if matches!(mode, FinalizationMode::Success) {
                assert_eq!(response.status, 200);
                assert_eq!(response.envelope.result.unwrap()["message"], "hello");
                assert_eq!(record["decision"], "allow");
                assert_eq!(record["providerAudit"]["messageLength"], 5);
            } else {
                assert_eq!(
                    response.envelope.reason_code,
                    Some(ReasonCode::UpstreamFailed.into())
                );
                assert_eq!(response.envelope.result.unwrap()["knownOutcome"], true);
                assert_eq!(record["providerAudit"]["knownOutcome"], true);
            }
        }
    }

    #[tokio::test]
    async fn pending_finalization_gets_one_poll_and_unmarked_execution_gets_none() {
        for (mode, polls) in [
            (FinalizationMode::Pending, 2),
            (FinalizationMode::Unmarked, 1),
        ] {
            let provider = ControlledProvider::finalizing(mode);
            let (runtime, dir) = fixture(provider.clone());
            let control = InvocationControl::new(Some(Duration::from_secs(1)));
            let operation = {
                let control = control.clone();
                tokio::spawn(async move {
                    runtime
                        .invoke_owned_json(context(), request(), control)
                        .await
                })
            };
            entered(&provider.cleanup_started).await;
            let response = tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                response.envelope.reason_code,
                Some(ReasonCode::OperationTimeout.into())
            );
            assert_eq!(
                response.envelope.result.unwrap()["executionState"],
                "unknown"
            );
            assert!(control.dispatched());
            assert!(!control.completed());
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(provider.cleanup_polls.load(Ordering::SeqCst), polls);
            assert!(
                !provider
                    .finalization_context
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .is_finalizing()
            );
            assert_eq!(audit(&dir)["providerAudit"]["executionState"], "unknown");
        }
    }

    #[tokio::test]
    async fn forced_shutdown_during_finalization_never_polls_cleanup_again() {
        let provider = ControlledProvider::finalizing(FinalizationMode::Success);
        let (runtime, dir) = fixture(provider.clone());
        let control = InvocationControl::new(Some(Duration::from_secs(60)));
        let operation = {
            let control = control.clone();
            tokio::spawn(async move {
                runtime
                    .invoke_owned_json(context(), request(), control)
                    .await
            })
        };
        entered(&provider.cleanup_started).await;
        control.force_stop();
        let response = operation.await.unwrap();
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationCancelled.into())
        );
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "unknown"
        );
        assert!(!control.completed());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.cleanup_polls.load(Ordering::SeqCst), 1);
        assert!(
            !provider
                .finalization_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_finalizing()
        );
        assert_eq!(audit(&dir)["providerAudit"]["executionState"], "unknown");
    }
    #[tokio::test]
    async fn provider_panic_is_owned_and_finalized_without_replay() {
        let provider = ControlledProvider::new(false, true);
        let (runtime, dir) = fixture(provider.clone());
        runtime.local_state_readiness().await.unwrap();
        let response = runtime
            .invoke_owned_json(context(), request(), InvocationControl::default())
            .await;
        assert!(
            response.envelope.result.is_some(),
            "unexpected response: {}",
            serde_json::to_string(&response.envelope).unwrap()
        );
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "unknown"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        audit(&dir);
    }
    #[tokio::test]
    async fn audit_admission_failure_proves_zero_provider_dispatch() {
        let provider = ControlledProvider::new(false, false);
        let (runtime, dir) = fixture(provider.clone());
        runtime.local_state_readiness().await.unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let response = runtime
            .invoke_owned_json(context(), request(), InvocationControl::default())
            .await;
        assert_eq!(response.status, 503);
        assert_eq!(response.envelope.service, "broker");
        assert_eq!(response.envelope.action, "request.admit");
        assert_eq!(response.envelope.decision, Decision::Error);
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::AuditUnavailable.into())
        );
        assert!(response.envelope.resource_scopes.is_empty());
        assert!(response.envelope.result.is_none());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn audit_failure_after_execution_does_not_erase_completion_evidence() {
        let provider = ControlledProvider::new(false, false);
        let (runtime, dir) = fixture(provider.clone());
        let operation = tokio::spawn(async move {
            runtime
                .invoke_owned_json(context(), request(), InvocationControl::default())
                .await
        });
        entered(&provider.invoked).await;
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::remove_file(&audit_path).unwrap();
        std::fs::create_dir(&audit_path).unwrap();
        provider.complete.add_permits(1);
        let response = operation.await.unwrap();
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::AuditUnavailable.into())
        );
        assert_ne!(response.envelope.service, "broker");
        let result = response.envelope.result.unwrap();
        assert_eq!(result["executionState"], "completed");
        assert_eq!(result["retrySafe"], false);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}
