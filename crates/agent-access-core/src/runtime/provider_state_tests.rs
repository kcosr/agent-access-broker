//! Provider state travels from scope resolution through body admission to the
//! same prepared operation's invocation, and nowhere else.
use super::tests::base_fake_config;
use super::*;
use agent_access_provider::{
    BodyAdmission, ProviderState, ProviderStateError, ScopeRequest, ScopeResolution,
    StateDisposition,
};
use async_trait::async_trait;
use std::sync::Mutex;

/// State a provider creates while resolving scopes.
#[derive(Debug)]
struct ScopeState(&'static str);

/// State a provider creates while admitting body metadata.
#[derive(Debug)]
struct AdmissionState(&'static str);

#[derive(Clone, Copy)]
enum Admission {
    Keep,
    Replace,
    Clear,
}

#[derive(Clone, Copy)]
enum Requirement {
    /// Report whichever state arrives.
    Observe,
    /// Fail closed unless admission state arrives.
    AdmissionState,
}

struct StateProvider {
    generation: &'static str,
    admission: Admission,
    requirement: Requirement,
    admitted_with: Mutex<Option<String>>,
    invocations: Mutex<Vec<String>>,
}

impl StateProvider {
    fn new(generation: &'static str, admission: Admission, requirement: Requirement) -> Arc<Self> {
        Arc::new(Self {
            generation,
            admission,
            requirement,
            admitted_with: Mutex::new(None),
            invocations: Mutex::new(Vec::new()),
        })
    }
}

fn describe(state: Option<&ProviderState>) -> String {
    match state {
        None => "none".to_string(),
        Some(state) => match (
            state.downcast_ref::<ScopeState>(),
            state.downcast_ref::<AdmissionState>(),
        ) {
            (Ok(ScopeState(generation)), _) => format!("scope:{generation}"),
            (_, Ok(AdmissionState(generation))) => format!("admission:{generation}"),
            _ => "unknown".to_string(),
        },
    }
}

impl agent_access_provider::test_support::DescribedProvider for StateProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait]
impl Provider for StateProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(|scopes| {
                ScopeResolution::resources(scopes)
                    .with_state(ProviderState::new(ScopeState(self.generation)))
            })
    }

    async fn authorize_body_parts(
        &self,
        _request: &AdmittedRequest,
        state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        *self.admitted_with.lock().unwrap() = Some(describe(state));
        let state = match self.admission {
            Admission::Keep => StateDisposition::Keep,
            Admission::Replace => {
                StateDisposition::Replace(ProviderState::new(AdmissionState(self.generation)))
            }
            Admission::Clear => StateDisposition::Clear,
        };
        Ok(BodyAdmission::new(
            vec![BrokerBodyPartSpec::new(
                "attachment".to_string(),
                "upload.bin".to_string(),
                "application/octet-stream".to_string(),
                7,
                "sha256".to_string(),
            )],
            state,
        ))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let received = describe(request.state());
        self.invocations.lock().unwrap().push(received.clone());
        if let Requirement::AdmissionState = self.requirement {
            ProviderState::require::<AdmissionState>(request.state())?;
        }
        Ok(ProviderResult::new(json!({"state": received})))
    }
}

fn operation() -> GovernedOperationContext {
    GovernedOperationContext {
        operation: OperationContext {
            agent_request_id: "agent-provider-state".to_string(),
            broker_request_id: "broker-provider-state".to_string(),
            identity: IdentityContext::anonymous(),
            service: "fake".to_string(),
            action: "echo".to_string(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
    }
}

fn request() -> InvokeRequest {
    InvokeRequest::new(json!({"project": "TEST", "message": "upload"}))
}

async fn admit(runtime: &BrokerRuntime) -> PreparedInvocation {
    let prepared = runtime
        .begin_invoke(operation(), request())
        .await
        .expect("invoke preparation succeeds");
    runtime
        .authorize_body_parts(prepared)
        .await
        .expect("body admission succeeds")
}

async fn run(admission: Admission, requirement: Requirement) -> (Arc<StateProvider>, Value) {
    let provider = StateProvider::new("first", admission, requirement);
    let runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&provider)]).unwrap();
    let prepared = admit(&runtime).await;
    let response = runtime.finish_prepared_invoke(prepared, Vec::new()).await;
    (provider, serde_json::to_value(&response.envelope).unwrap())
}

#[tokio::test]
async fn admission_keeps_the_scope_state_only_when_it_says_so() {
    let (provider, envelope) = run(Admission::Keep, Requirement::Observe).await;
    assert_eq!(
        provider.admitted_with.lock().unwrap().as_deref(),
        Some("scope:first")
    );
    assert_eq!(envelope["result"]["state"], "scope:first");
}

#[tokio::test]
async fn admission_replaces_the_whole_state() {
    let (provider, envelope) = run(Admission::Replace, Requirement::Observe).await;
    assert_eq!(
        provider.admitted_with.lock().unwrap().as_deref(),
        Some("scope:first")
    );
    assert_eq!(envelope["result"]["state"], "admission:first");
}

#[tokio::test]
async fn admission_clears_the_state() {
    let (provider, envelope) = run(Admission::Clear, Requirement::Observe).await;
    assert_eq!(*provider.invocations.lock().unwrap(), ["none"]);
    assert_eq!(envelope["result"]["state"], "none");
}

#[tokio::test]
async fn missing_required_state_fails_closed_as_a_provider_contract_error() {
    let (provider, envelope) = run(Admission::Clear, Requirement::AdmissionState).await;
    assert_eq!(*provider.invocations.lock().unwrap(), ["none"]);
    assert_eq!(envelope["decision"], "error");
    assert_eq!(envelope["reasonCode"], "broker_provider_contract_failed");
    assert!(envelope.get("result").is_none_or(Value::is_null));
    let expected = ProviderError::from(ProviderStateError::Missing);
    assert_eq!(envelope["reason"], expected.message);
}

#[tokio::test]
async fn state_of_another_type_fails_closed_without_exposing_it() {
    let (provider, envelope) = run(Admission::Keep, Requirement::AdmissionState).await;
    assert_eq!(*provider.invocations.lock().unwrap(), ["scope:first"]);
    assert_eq!(envelope["decision"], "error");
    assert_eq!(envelope["reasonCode"], "broker_provider_contract_failed");
    assert!(!envelope.to_string().contains("first"));
}

#[tokio::test]
async fn admitted_state_stays_with_the_provider_generation_that_created_it() {
    let first = StateProvider::new("first", Admission::Replace, Requirement::AdmissionState);
    let second = StateProvider::new("second", Admission::Replace, Requirement::AdmissionState);
    let first_runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&first)]).unwrap();
    let second_runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&second)]).unwrap();
    let prepared = admit(&first_runtime).await;
    // A newer generation finishing the operation still dispatches to the
    // provider instance that resolved and admitted it.
    let response = second_runtime
        .finish_prepared_invoke(prepared, Vec::new())
        .await;
    assert_eq!(
        response.envelope.result.as_ref().unwrap()["state"],
        "admission:first"
    );
    assert_eq!(*first.invocations.lock().unwrap(), ["admission:first"]);
    assert!(second.invocations.lock().unwrap().is_empty());
    assert!(second.admitted_with.lock().unwrap().is_none());
}

mod admitted_authority {
    use super::super::admitted_authority;
    use super::*;

    fn action() -> ActionDescriptor {
        ActionDescriptor::new("act", "Act", json!({"type": "object"}))
    }

    fn scopes(values: &[&str]) -> ResourceScopes {
        BTreeMap::from([(
            "project".to_string(),
            values.iter().map(ToString::to_string).collect(),
        )])
    }

    #[test]
    fn scoped_actions_receive_their_resources_and_never_empty_authority() {
        let scoped = action().scopes(["project"]);
        let authority = admitted_authority(&scoped, &scopes(&["ENG"]), None).unwrap();
        assert_eq!(authority.resources(), Some(&scopes(&["ENG"])));
        for empty in [ResourceScopes::new(), scopes(&[])] {
            let error = admitted_authority(&scoped, &empty, None).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
        }
    }

    #[test]
    fn action_only_actions_never_inherit_resources() {
        let authority = admitted_authority(&action(), &ResourceScopes::new(), None).unwrap();
        assert!(matches!(authority, InvocationAuthority::ActionOnly));
        let error = admitted_authority(&action(), &scopes(&["*"]), None).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    }

    #[test]
    fn search_actions_receive_the_complete_boundary() {
        let search = action().scopes(["project"]).search_contained();
        let boundary = SearchAuthorization::new(
            "project".to_string(),
            SearchAuthorizationScope::AllExcept {
                excluded_values: vec!["SECRET".to_string()],
            },
        );
        // The envelope summary is lossy; the provider's authority is not.
        let authority =
            admitted_authority(&search, &scopes(&["*"]), Some(boundary.clone())).unwrap();
        assert_eq!(authority.search(), Some(&boundary));
        assert!(authority.resources().is_none());
        assert!(admitted_authority(&search, &scopes(&["*"]), None).is_err());
        assert!(
            admitted_authority(
                &action().scopes(["project"]),
                &scopes(&["ENG"]),
                Some(boundary)
            )
            .is_err()
        );
    }
}
