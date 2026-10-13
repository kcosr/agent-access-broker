//! Provider outcomes are checked at each hook boundary (scope resolution,
//! body admission, invocation, credential verification) against the hook's
//! contract: its phase and decision, the backend's registered domain reasons
//! and host port allowlists. Late stream failures carry only permitted codes.
use super::tests::base_fake_config;
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use agent_access_provider::host::{HostPort, port_failure};
use agent_access_provider::{
    BodyAdmission, ProviderFailureStatus, ScopeRequest, ScopeResolution, StateDisposition,
    parse_backend_config,
};
use async_trait::async_trait;
use futures_util::StreamExt;

static ITEM_LOCKED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("fake_item_locked", ProviderFailureStatus::Conflict);
static QUEUE_PAUSED: ProviderReasonDefinition = ProviderReasonDefinition::error(
    "fake_queue_paused",
    ProviderFailureStatus::ServiceUnavailable,
);
/// Spelled like a registered reason, with another outcome.
static MODIFIED: ProviderReasonDefinition =
    ProviderReasonDefinition::error("fake_item_locked", ProviderFailureStatus::Conflict);
/// Another module's reason.
static FOREIGN: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("jira_item_locked", ProviderFailureStatus::Conflict);

/// The fake backend, registered with domain reasons of its own.
static FAKE_WITH_REASONS: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "fake",
    parse_backend_config::<agent_access_fake::FakeProviderConfig>,
)
.with_resource_types(&[&agent_access_fake::FAKE_PROJECT_RESOURCE])
.with_domain_reasons(&[&ITEM_LOCKED, &QUEUE_PAUSED]);

/// What each hook of [`OutcomeProvider`] returns; a hook without a failure
/// succeeds.
#[derive(Default)]
struct Outcomes {
    scope: Option<ProviderError>,
    admission: Option<ProviderError>,
    invoke: Option<ProviderError>,
    stream: Option<ProviderStreamError>,
    verify: Option<ProviderError>,
}

struct OutcomeProvider(Outcomes);

impl agent_access_provider::test_support::DescribedProvider for OutcomeProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait]
impl Provider for OutcomeProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        if let Some(error) = &self.0.scope {
            return Err(error.clone());
        }
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn authorize_body_parts(
        &self,
        _request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if let Some(error) = &self.0.admission {
            return Err(error.clone());
        }
        Ok(BodyAdmission::new(Vec::new(), StateDisposition::Keep))
    }

    async fn verify_execution_credential(
        &self,
        _credential: &ExecutionCredential,
        _correlation: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        match &self.0.verify {
            Some(error) => Err(error.clone()),
            None => Ok(None),
        }
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if let Some(error) = &self.0.invoke {
            return Err(error.clone());
        }
        let stream = self.0.stream.clone().map(|failure| {
            ProviderResultStream::from_stream(
                "text/plain",
                futures_util::stream::iter([Ok(Bytes::from_static(b"prefix")), Err(failure)]),
            )
        });
        let mut provider_result =
            ProviderResult::new(json!({"provider": "fake"})).with_upstream(Some(200), Some(1));
        provider_result.stream = stream;
        Ok(provider_result)
    }
}

fn runtime(outcomes: Outcomes, audit_path: Option<&Path>) -> BrokerRuntime {
    let mut config = base_fake_config();
    // The linked test backends, with this fake registration in place of
    // the shipped one.
    let registrations = crate::tests::test_backend_registry()
        .registrations()
        .map(|registration| {
            if registration.kind() == "fake" {
                &FAKE_WITH_REASONS
            } else {
                registration
            }
        })
        .collect::<Vec<_>>();
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new(registrations).unwrap()))
        .with(agent_access_fake::FakeProviderConfig::default());
    if let Some(path) = audit_path {
        config.audit = Some(crate::AuditConfig::new(
            crate::AuditStoreType::Jsonl,
            path.display().to_string(),
        ));
    }
    BrokerRuntime::with_providers(config, vec![Arc::new(OutcomeProvider(outcomes))]).unwrap()
}

fn operation() -> GovernedOperationContext {
    GovernedOperationContext {
        operation: OperationContext {
            agent_request_id: "agent-provider-contract".to_string(),
            broker_request_id: "broker-provider-contract".to_string(),
            identity: IdentityContext::anonymous(),
            service: "fake".to_string(),
            action: "echo".to_string(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
    }
}

fn request() -> InvokeRequest {
    InvokeRequest::new(json!({"project": "TEST", "message": "contract"}))
}

async fn invoke(outcomes: Outcomes) -> (u16, Value) {
    let response = runtime(outcomes, None).invoke(operation(), request()).await;
    (
        response.status,
        serde_json::to_value(&response.envelope).unwrap(),
    )
}

async fn admit(outcomes: Outcomes) -> Result<(), (u16, Value)> {
    let runtime = runtime(outcomes, None);
    let prepared = runtime
        .begin_invoke(operation(), request())
        .await
        .unwrap_or_else(|_| panic!("preparation succeeds"));
    match runtime.authorize_body_parts(prepared).await {
        Ok(_) => Ok(()),
        Err(response) => Err((
            response.status,
            serde_json::to_value(&response.envelope).unwrap(),
        )),
    }
}

async fn verify(outcomes: Outcomes) -> Result<(), ProviderError> {
    runtime(outcomes, None)
        .verify_execution_credential(
            "fake",
            &agent_access_provider::test_support::bearer_credential("token"),
            &IdentityContext::anonymous(),
            CredentialVerificationInput::default(),
            CorrelationContext::new("agent-verify".into(), "broker-verify".into()),
        )
        .await
        .map(|_| ())
}

fn deny(code: ReasonCode) -> ProviderError {
    ProviderError::deny(code, "provider text")
}

fn error(code: ReasonCode) -> ProviderError {
    ProviderError::error(code, "provider text")
        .with_result(json!({"providerDetail": "provider result"}))
}

/// The host's contract failure: its own reason, decision and message, with
/// none of the provider's text or result.
fn assert_contract_failure(status: u16, envelope: &Value) {
    assert_eq!(status, 500, "{envelope}");
    assert_eq!(envelope["decision"], "error", "{envelope}");
    assert_eq!(
        envelope["reasonCode"], "broker_provider_contract_failed",
        "{envelope}"
    );
    assert_eq!(envelope["reason"], PROVIDER_CONTRACT_FAILED_MESSAGE);
    assert!(
        !envelope.to_string().contains("provider text"),
        "{envelope}"
    );
    assert!(
        !envelope.to_string().contains("provider result"),
        "{envelope}"
    );
}

fn assert_verify_contract_failure(error: ProviderError) {
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(
        error.reason_code(),
        ReasonCode::BrokerProviderContractFailed
    );
    assert_eq!(error.message, PROVIDER_CONTRACT_FAILED_MESSAGE);
    assert!(error.result.is_none());
}

#[tokio::test]
async fn registered_domain_reasons_keep_their_fixed_outcomes_in_every_hook() {
    for (definition, status, decision) in
        [(&ITEM_LOCKED, 409, "deny"), (&QUEUE_PAUSED, 503, "error")]
    {
        for outcomes in [
            Outcomes {
                scope: Some(ProviderError::domain(definition, "domain")),
                ..Outcomes::default()
            },
            Outcomes {
                invoke: Some(ProviderError::domain(definition, "domain")),
                ..Outcomes::default()
            },
        ] {
            let (actual, envelope) = invoke(outcomes).await;
            assert_eq!(actual, status, "{envelope}");
            assert_eq!(envelope["decision"], decision, "{envelope}");
            assert_eq!(envelope["reasonCode"], definition.code(), "{envelope}");
        }
        let (actual, envelope) = admit(Outcomes {
            admission: Some(ProviderError::domain(definition, "domain")),
            ..Outcomes::default()
        })
        .await
        .unwrap_err();
        assert_eq!(actual, status, "{envelope}");
        assert_eq!(envelope["reasonCode"], definition.code(), "{envelope}");
        let failure = verify(Outcomes {
            verify: Some(ProviderError::domain(definition, "domain")),
            ..Outcomes::default()
        })
        .await
        .unwrap_err();
        assert_eq!(failure.reason_code(), ProviderReason::from(definition));
        assert_eq!(failure.decision().as_str(), decision);
    }
}

#[tokio::test]
async fn foreign_and_modified_domain_definitions_become_contract_failures() {
    for definition in [&FOREIGN, &MODIFIED] {
        let (status, envelope) = invoke(Outcomes {
            invoke: Some(ProviderError::domain(definition, "provider text")),
            ..Outcomes::default()
        })
        .await;
        assert_contract_failure(status, &envelope);
        let (status, envelope) = invoke(Outcomes {
            scope: Some(ProviderError::domain(definition, "provider text")),
            ..Outcomes::default()
        })
        .await;
        assert_contract_failure(status, &envelope);
        assert_verify_contract_failure(
            verify(Outcomes {
                verify: Some(ProviderError::domain(definition, "provider text")),
                ..Outcomes::default()
            })
            .await
            .unwrap_err(),
        );
    }
}

#[tokio::test]
async fn host_only_reasons_become_contract_failures_in_every_hook() {
    for code in [
        ReasonCode::RateLimited,
        ReasonCode::ConcurrencyLimited,
        ReasonCode::AuditUnavailable,
        ReasonCode::ConfigValidationFailed,
        ReasonCode::BrokerProviderContractFailed,
    ] {
        let (status, envelope) = invoke(Outcomes {
            scope: Some(error(code)),
            ..Outcomes::default()
        })
        .await;
        assert_contract_failure(status, &envelope);
        // Nothing was dispatched, so scope resolution claims no execution state.
        assert!(envelope["result"].is_null(), "{envelope}");

        let (status, envelope) = admit(Outcomes {
            admission: Some(error(code)),
            ..Outcomes::default()
        })
        .await
        .unwrap_err();
        assert_contract_failure(status, &envelope);

        // After dispatch the provider may have acted upstream.
        let (status, envelope) = invoke(Outcomes {
            invoke: Some(error(code)),
            ..Outcomes::default()
        })
        .await;
        assert_contract_failure(status, &envelope);
        assert_eq!(
            envelope["result"],
            json!({"executionState": "unknown", "retrySafe": false})
        );

        assert_verify_contract_failure(
            verify(Outcomes {
                verify: Some(error(code)),
                ..Outcomes::default()
            })
            .await
            .unwrap_err(),
        );
    }
}

#[tokio::test]
async fn reasons_outside_their_hook_or_decision_become_contract_failures() {
    // `mutation_verification_failed` is an invocation outcome only.
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(error(ReasonCode::MutationVerificationFailed)),
        ..Outcomes::default()
    })
    .await;
    assert_eq!(status, 409, "{envelope}");
    assert_eq!(envelope["reasonCode"], "mutation_verification_failed");
    let (status, envelope) = invoke(Outcomes {
        scope: Some(error(ReasonCode::MutationVerificationFailed)),
        ..Outcomes::default()
    })
    .await;
    assert_contract_failure(status, &envelope);
    let (status, envelope) = admit(Outcomes {
        admission: Some(error(ReasonCode::MutationVerificationFailed)),
        ..Outcomes::default()
    })
    .await
    .unwrap_err();
    assert_contract_failure(status, &envelope);

    // `cursor_signing_unavailable` never comes from credential verification.
    let (status, envelope) = admit(Outcomes {
        admission: Some(error(ReasonCode::CursorSigningUnavailable)),
        ..Outcomes::default()
    })
    .await
    .unwrap_err();
    assert_eq!(status, 503, "{envelope}");
    assert_eq!(envelope["reasonCode"], "cursor_signing_unavailable");
    assert_verify_contract_failure(
        verify(Outcomes {
            verify: Some(error(ReasonCode::CursorSigningUnavailable)),
            ..Outcomes::default()
        })
        .await
        .unwrap_err(),
    );

    // Single-decision reasons reject the other decision; multi-decision
    // reasons keep either.
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(deny(ReasonCode::UpstreamFailed)),
        ..Outcomes::default()
    })
    .await;
    assert_contract_failure(status, &envelope);
    for (failure, decision) in [
        (deny(ReasonCode::UpstreamProtocolFailed), "deny"),
        (error(ReasonCode::UpstreamProtocolFailed), "error"),
    ] {
        let (status, envelope) = invoke(Outcomes {
            invoke: Some(failure),
            ..Outcomes::default()
        })
        .await;
        assert_eq!(status, 502, "{envelope}");
        assert_eq!(envelope["decision"], decision, "{envelope}");
        assert_eq!(envelope["reasonCode"], "upstream_protocol_failed");
    }
}

#[tokio::test]
async fn only_an_invocation_reports_verification_mismatch_as_allow() {
    let mismatch = || {
        ProviderError::allow_with_result(
            ReasonCode::VerificationMismatch,
            "values differ",
            json!({"verified": false}),
        )
    };
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(mismatch()),
        ..Outcomes::default()
    })
    .await;
    assert_eq!(status, 409, "{envelope}");
    assert_eq!(envelope["decision"], "allow", "{envelope}");
    assert_eq!(envelope["result"], json!({"verified": false}));
    let (status, envelope) = invoke(Outcomes {
        scope: Some(mismatch()),
        ..Outcomes::default()
    })
    .await;
    assert_contract_failure(status, &envelope);
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(ProviderError::allow(
            ReasonCode::VerificationMismatch,
            "no verification result",
        )),
        ..Outcomes::default()
    })
    .await;
    assert_contract_failure(status, &envelope);
}

#[tokio::test]
async fn host_port_failures_pass_through_with_their_own_outcome() {
    let busy = port_failure(
        HostPort::DelegatedLease,
        ProviderError::error(ReasonCode::ConcurrencyLimited, "refresh is busy"),
    );
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(busy.clone()),
        ..Outcomes::default()
    })
    .await;
    assert_eq!(status, 429, "{envelope}");
    assert_eq!(envelope["decision"], "error", "{envelope}");
    assert_eq!(envelope["reasonCode"], "concurrency_limited", "{envelope}");
    assert_eq!(envelope["reason"], "refresh is busy");
    let (status, envelope) = invoke(Outcomes {
        scope: Some(busy),
        ..Outcomes::default()
    })
    .await;
    assert_eq!(status, 429, "{envelope}");

    // A port failure outside the port's allowlist is still rejected.
    let (status, envelope) = invoke(Outcomes {
        invoke: Some(port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::AuditUnavailable, "provider text"),
        )),
        ..Outcomes::default()
    })
    .await;
    assert_contract_failure(status, &envelope);
}

#[tokio::test]
async fn lookup_concealment_hides_contract_failures_but_keeps_their_diagnostic() {
    let hook =
        agent_access_provider::host::hook_context("fake", "echo", HookPhase::ScopeResolution, &[]);
    let failure = run_provider_hook::<()>(hook, async {
        Err(ProviderError::error(
            ReasonCode::RateLimited,
            "lookup detail about PRIVATE-7",
        ))
    })
    .await
    .unwrap_err();
    let public = public_lookup_scope_error(failure);
    assert_eq!(public.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(public.decision(), Decision::Deny);
    assert_eq!(
        public.message,
        "resource scope is not authorized or unavailable"
    );
    assert_eq!(
        public.internal_diagnostic_code,
        Some(ContractViolation::HostOnlyReason.diagnostic_code())
    );
    assert!(!format!("{public:?}").contains("PRIVATE-7"));
}

async fn stream_failure(failure: ProviderStreamError) -> (ProviderStreamError, Value) {
    let audit_path = super::tests::temp_path("provider-contract-stream.audit.jsonl");
    let runtime = runtime(
        Outcomes {
            stream: Some(failure),
            ..Outcomes::default()
        },
        Some(&audit_path),
    );
    let mut response = runtime.invoke_required_stream(operation(), request()).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    let ProviderResultStreamSource::Stream(stream) = response.stream.take().unwrap().source else {
        panic!("expected a stream");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"prefix")
    );
    let error = stream.next().await.unwrap().unwrap_err();
    drop(stream);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let failed = crate::test_support::read_audit_records(crate::AuditStoreType::Jsonl, &audit_path)
        .into_iter()
        .find(|record| record["providerAudit"]["streamPhase"] == "failed")
        .expect("terminal failure record");
    (error, failed)
}

#[tokio::test]
async fn late_stream_failures_carry_only_permitted_codes() {
    for (failure, code, message) in [
        (
            ProviderStreamError::new(ReasonCode::UpstreamTimeout, "upstream stalled"),
            "upstream_timeout",
            "upstream stalled",
        ),
        (
            ProviderStreamError::new(&ITEM_LOCKED, "log locked"),
            "fake_item_locked",
            "log locked",
        ),
    ] {
        let (error, record) = stream_failure(failure).await;
        assert_eq!(error.reason_code.as_str(), code);
        assert_eq!(record["decision"], "error");
        assert_eq!(record["reasonCode"], code);
        assert_eq!(record["providerAudit"]["streamMessage"], message);
    }
    let lease = port_failure(
        HostPort::DelegatedLease,
        ProviderError::error(ReasonCode::UpstreamConnectionFailed, "lease"),
    );
    for failure in [
        ProviderStreamError::new(ReasonCode::RateLimited, "provider text"),
        ProviderStreamError::new(ReasonCode::UpstreamFailed, "provider text"),
        ProviderStreamError::new(&FOREIGN, "provider text"),
        ProviderStreamError::new(lease.reason_code(), "provider text"),
    ] {
        let (error, record) = stream_failure(failure).await;
        assert_eq!(error.reason_code, ReasonCode::BrokerProviderContractFailed);
        // The host keeps its own late-failure decision.
        assert_eq!(record["decision"], "error");
        assert_eq!(record["reasonCode"], "broker_provider_contract_failed");
        assert!(!record.to_string().contains("provider text"), "{record}");
    }
}
