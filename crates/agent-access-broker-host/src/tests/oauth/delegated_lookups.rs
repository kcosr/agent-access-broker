//! Delegated lookups: a lookup-backed action on an OAuth connection uses one
//! lease for its lookups and its execution, with one recovery budget, and a
//! lease is acquired only once a candidate grant exists.
use super::*;
use agent_access_core::{CreateResourceRequest, ManagedPolicyGrantCreateRequest};
use agent_access_fake::OAUTH_COLLECTION_RESOURCE;
use agent_access_provider::test_support::DescribedProvider;
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, DelegatedAccess, DelegatedAccessError,
    DelegatedBindingId, DelegatedCredential, ExecutionAccess, ExecutionCredential, LookupAccess,
    LookupRequirement, Provider, ProviderError, ProviderInvocation, ProviderResult,
    ResourceScopeCapabilities, ResourceScopes, ResourceSelector, ScopeRequest, ScopeResolution,
    ServiceDescriptor, ServiceProvider,
};
use std::sync::Mutex;

const TARGET: &str = "workspace-one";
const AUDIENCE: &str = "records-api";
const LOOKUP_TOKEN: &str = "shared-lookup-token";

/// The lookup or execution material one hook received.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Nothing,
    Static(ExecutionCredential),
    Delegated(DelegatedBindingId),
}

impl Seen {
    fn lookup(access: Option<&LookupAccess>) -> Self {
        match access {
            None => Self::Nothing,
            Some(LookupAccess::Static(credential)) => Self::Static(credential.clone()),
            Some(LookupAccess::Delegated(credential)) => {
                Self::Delegated(credential.binding_identity())
            }
            Some(other) => panic!("unexpected lookup access {other:?}"),
        }
    }

    fn execution(access: &ExecutionAccess) -> Self {
        match access {
            ExecutionAccess::None => Self::Nothing,
            ExecutionAccess::Static(credential) => Self::Static(credential.clone()),
            ExecutionAccess::Delegated(credential) => {
                Self::Delegated(credential.binding_identity())
            }
            other => panic!("unexpected execution access {other:?}"),
        }
    }
}

/// `oauth_stub` with one lookup-backed action. Scope resolution confirms the
/// collection with the lookup access it receives; execution reads with its
/// execution material. Inputs name the phases whose upstream request answers
/// 401, which the provider handles as the SDK documents: it marks the access
/// rejected and recovers once.
#[derive(Default)]
struct LookupRecordsProvider {
    seen: Arc<Mutex<Vec<(&'static str, Seen)>>>,
}

impl LookupRecordsProvider {
    fn record(&self, phase: &'static str, seen: Seen) {
        self.seen.lock().unwrap().push((phase, seen));
    }
}

impl DescribedProvider for LookupRecordsProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("oauth_stub", "Lookup records")
            .with_resource_scopes(BTreeMap::from([(
                "collection".into(),
                ResourceScopeCapabilities::new(
                    OAUTH_COLLECTION_RESOURCE.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new(
                    "record.locate",
                    "Locate a record's collection",
                    json!({
                        "type": "object",
                        "required": ["collection"],
                        "properties": {
                            "collection": {"type": "string"},
                            "unauthorized": {
                                "type": "array",
                                "items": {"type": "string", "enum": ["lookup", "execution"]}
                            }
                        },
                        "additionalProperties": false
                    }),
                )
                .read_only()
                .scope("collection")
                .credential_modes(["service", "per_user"])
                .lookup(LookupRequirement::ScopeResolution),
            ])
            .with_credentials(
                CredentialDescriptor::default().delegated("Lets agents locate test records."),
            )
    }
}

fn unauthorized_in(inputs: &Value, phase: &str) -> bool {
    inputs["unauthorized"]
        .as_array()
        .is_some_and(|phases| phases.iter().any(|value| value == phase))
}

/// Fresh access for the next upstream request.
async fn present(credential: &DelegatedCredential) -> Result<DelegatedAccess, ProviderError> {
    credential
        .revalidated_access_for(TARGET, AUDIENCE)
        .await
        .map_err(|error| match error {
            DelegatedAccessError::Revalidation(failure) => failure,
            _ => ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "the connection does not grant the test records",
            ),
        })
}

/// The upstream rejected `access`: invalidate it and recover once.
async fn rejected(
    credential: &DelegatedCredential,
    access: &DelegatedAccess,
) -> Result<(), ProviderError> {
    credential.mark_rejected(access.version())?;
    credential.recover_after_unauthorized().await.map(drop)
}

#[async_trait::async_trait]
impl Provider for LookupRecordsProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.record("pre_scope", Seen::lookup(request.lookup_access()));
        match request.lookup_access() {
            Some(LookupAccess::Delegated(credential)) => {
                let access = present(credential).await?;
                if unauthorized_in(request.inputs(), "lookup") {
                    rejected(credential, &access).await?;
                }
            }
            Some(LookupAccess::Static(_)) => {}
            _ => {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "lookup access is required",
                ));
            }
        }
        let collection = request.inputs()["collection"].as_str().unwrap().to_owned();
        Ok(ScopeResolution::resources(ResourceScopes::from([(
            "collection".into(),
            vec![collection],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.record("execution_lookup", Seen::lookup(request.lookup_access()));
        self.record("execution", Seen::execution(request.execution()));
        if let Some(credential) = request.execution().delegated() {
            let access = present(credential).await?;
            if unauthorized_in(request.inputs(), "execution") {
                rejected(credential, &access).await?;
            }
        }
        Ok(ProviderResult::new(
            json!({"collection": request.inputs()["collection"]}),
        ))
    }
}

/// The OAuth fixture serving `provider` as `oauth_stub`, with static
/// service and shared lookup credentials when `service_credentials` is set.
async fn lookup_fixture(
    provider: &Arc<LookupRecordsProvider>,
    service_credentials: bool,
) -> OAuthFixture {
    let fixture = oauth_fixture_with(
        None,
        |dir, config| {
            if service_credentials {
                for (credentials, name, token, read_only) in [
                    (
                        &mut config.credentials.service,
                        "service-token",
                        "shared-service-token",
                        None,
                    ),
                    (
                        &mut config.credentials.lookup,
                        "lookup-token",
                        LOOKUP_TOKEN,
                        Some(true),
                    ),
                ] {
                    let path = dir.join(name);
                    std::fs::write(&path, token).unwrap();
                    credentials.insert(
                        "oauth_stub".into(),
                        CredentialConfig {
                            kind: "bearer_token".into(),
                            username_ref: None,
                            token_ref: Some(format!("file:{}", path.display())),
                            provider: None,
                            path: None,
                            read_only,
                            connection: None,
                        },
                    );
                }
            }
        },
        vec![ServiceProvider::from(Arc::clone(provider))],
    )
    .await;
    for collection in ["alpha", "beta"] {
        fixture
            .runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(format!("collection-{collection}")),
                display_name: None,
                resource_type: OAUTH_COLLECTION_RESOURCE.id().clone(),
                selector: ResourceSelector::Exact {
                    value: collection.into(),
                },
                allowed_execution_contexts: vec!["default".into(), "setup-only".into()],
                enabled: true,
                attributes: Default::default(),
                created_by: "admin".into(),
            })
            .unwrap();
    }
    fixture
}

impl OAuthFixture {
    /// Grants alice `record.locate` on collection `alpha` in `context`.
    fn grant_locate(&self, id: &str, mode: &str, context: &str, priority: Option<i32>) {
        self.runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: Some(id.into()),
                subjects: vec!["user:alice".into()],
                service: "oauth_stub".into(),
                actions: vec!["record.locate".into()],
                resources: ResourceSelection {
                    resource_ids: vec!["collection-alpha".into()],
                    resource_group_ids: Vec::new(),
                },
                execution_contexts: vec![context.into()],
                credential_mode: mode.into(),
                priority,
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }

    /// Answers each refresh-token grant with the next access token, from 2.
    async fn successive_refreshes(&self) {
        let issued = std::sync::atomic::AtomicU32::new(2);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(token(
                    issued.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    3600,
                ))
            })
            .with_priority(1)
            .mount(&self.server)
            .await;
    }

    async fn refreshes_after_consent(&self) -> usize {
        self.requests_after_consent()
            .await
            .iter()
            .filter(|request| request.url.path() == "/oauth/token")
            .count()
    }
}

fn take_seen(provider: &LookupRecordsProvider) -> Vec<(&'static str, Seen)> {
    std::mem::take(&mut *provider.seen.lock().unwrap())
}

/// The three hooks of one invocation all received one delegated binding.
fn assert_one_delegated_binding(seen: &[(&'static str, Seen)]) -> DelegatedBindingId {
    let phases = seen.iter().map(|(phase, _)| *phase).collect::<Vec<_>>();
    assert_eq!(phases, ["pre_scope", "execution_lookup", "execution"]);
    let Seen::Delegated(binding) = seen[0].1.clone() else {
        panic!("scope resolution received no delegated lookup: {seen:?}");
    };
    assert!(
        seen.iter()
            .all(|(_, access)| *access == Seen::Delegated(binding)),
        "{seen:?}"
    );
    binding
}

/// A lookup 401 and an execution 401 share the invocation's one recovery:
/// scope resolution, its lookups and execution hold the same lease. Each
/// invocation has its own lease, and refresh keeps the binding.
#[tokio::test]
async fn lookups_and_execution_share_one_lease_and_one_recovery() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-personal", "per_user", "default", None);
    fixture.connect("").await;
    fixture.successive_refreshes().await;

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-recovered",
            json!({"collection": "alpha", "unauthorized": ["lookup"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["collection"], "alpha");
    let binding = assert_one_delegated_binding(&take_seen(&provider));
    assert_eq!(fixture.refreshes_after_consent().await, 1);

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-twice-rejected",
            json!({"collection": "alpha", "unauthorized": ["lookup", "execution"]}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "credential_invalid");
    assert_eq!(
        body["reason"],
        "delegated credential was already recovered for this invocation"
    );
    assert_eq!(assert_one_delegated_binding(&take_seen(&provider)), binding);
    // Only the lookup's recovery refreshed; the execution 401 found the
    // invocation's budget spent.
    assert_eq!(fixture.refreshes_after_consent().await, 2);
}

/// When a service grant can be viable, scope resolution uses the shared
/// static lookup credential. A higher-priority `per_user` grant then wins
/// final policy, and execution's lookups use the lease acquired after it.
#[tokio::test]
async fn shared_lookup_planning_lends_the_execution_lease_to_execution_lookups() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, true).await;
    fixture.grant_locate("locate-personal", "per_user", "default", Some(10));
    fixture.grant_locate("locate-service", "service", "default", None);
    fixture.connect("").await;

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-shared-plan",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = take_seen(&provider);
    assert_eq!(
        seen[0],
        (
            "pre_scope",
            Seen::Static(agent_access_provider::test_support::bearer_credential(
                LOOKUP_TOKEN
            ))
        )
    );
    let Seen::Delegated(binding) = seen[1].1.clone() else {
        panic!("execution lookups received no delegated lease: {seen:?}");
    };
    assert_eq!(
        seen[1..],
        [
            ("execution_lookup", Seen::Delegated(binding)),
            ("execution", Seen::Delegated(binding)),
        ]
    );
    let audit = read_audit_records(&fixture.audit_path);
    let record = audit.last().unwrap();
    assert_eq!(record["credentialMode"], "per_user");
    assert_eq!(record["credentialConnection"], "oauth_stub");
    assert_eq!(record["matchedGrant"]["grantId"], "locate-personal");
}

/// Without a candidate grant in the caller's context, the request is denied
/// before any acquisition: the connection's due access is not refreshed and
/// the provider sees nothing. A candidate grant then acquires, refreshing.
#[tokio::test]
async fn requests_without_a_candidate_grant_acquire_nothing() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-setup-only", "per_user", "setup-only", None);
    fixture.connect_expiring("", 1).await;
    fixture.successive_refreshes().await;
    // The first access is now due for refresh.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-no-candidate",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved");
    assert_eq!(body["resourceScopes"], json!({}));
    assert!(fixture.requests_after_consent().await.is_empty());
    assert!(take_seen(&provider).is_empty());
    // No personal credential was used, so the record names no connection.
    let audit = read_audit_records(&fixture.audit_path);
    let record = audit.last().unwrap();
    assert_eq!(record["agentRequestId"], "locate-no-candidate");
    assert!(record.get("credentialConnection").is_none(), "{record}");

    fixture.grant_locate("locate-default", "per_user", "default", None);
    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-candidate",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let requests = fixture.requests_after_consent().await;
    assert_eq!(requests[0].url.path(), "/oauth/token");
    assert_eq!(
        header(&requests[0], REQUEST_ID_HEADER),
        Some("locate-candidate")
    );
    assert_one_delegated_binding(&take_seen(&provider));
}

/// A delegated lookup that names a resource no grant covers ends in the
/// concealed lookup denial: execution is never dispatched, the response
/// reveals no scope, and the audit record keeps the resolved scope.
#[tokio::test]
async fn a_final_denial_after_a_delegated_lookup_dispatches_nothing() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-personal", "per_user", "default", None);
    fixture.connect("").await;

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-ungranted",
            json!({"collection": "beta"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved");
    assert_eq!(
        body["reason"],
        "resource scope is not authorized or unavailable"
    );
    assert_eq!(body["resourceScopes"], json!({}));
    let seen = take_seen(&provider);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(matches!(seen[0], ("pre_scope", Seen::Delegated(_))));
    assert!(fixture.requests_after_consent().await.is_empty());

    let audit = read_audit_records(&fixture.audit_path);
    let record = audit.last().unwrap();
    assert_eq!(record["agentRequestId"], "locate-ungranted");
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reasonCode"], "scope_unresolved");
    assert_eq!(record["resourceScopes"], json!({"collection": ["beta"]}));
    assert!(record["matchedGrant"].is_null(), "{record}");
    // The lookup used the caller's lease, so the record names its connection
    // although policy selected no credential mode.
    assert!(record.get("credentialMode").is_none(), "{record}");
    assert_eq!(record["credentialConnection"], "oauth_stub");
}

/// The lease's own failures during a lookup describe the caller's
/// connection, not the resource, so lookup concealment passes them on: a
/// throttled recovery keeps its status and retry metadata.
#[tokio::test]
async fn a_throttled_lookup_recovery_is_reported_with_its_retry_time() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-personal", "per_user", "default", None);
    fixture.connect("").await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
        .with_priority(1)
        .mount(&fixture.server)
        .await;

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-throttled",
            json!({"collection": "alpha", "unauthorized": ["lookup"]}),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reasonCode"], "upstream_rate_limited");
    assert_eq!(body["result"]["retryAfterSeconds"], 30);
    assert_eq!(body["resourceScopes"], json!({}));
    let seen = take_seen(&provider);
    assert_eq!(seen.len(), 1, "{seen:?}");
}

/// Consent pending blocks a delegated lookup at acquisition, before scope
/// resolution runs.
#[tokio::test]
async fn pending_consent_blocks_delegated_lookups_before_scope_resolution() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-personal", "per_user", "default", None);
    fixture.connect("").await;
    let reconnect = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "oauth-reconnect",
            Some(json!({"registration": "stub", "intent": "reconnect"})),
        )
        .await;
    assert_eq!(reconnect.status(), StatusCode::OK);

    let (status, body) = fixture
        .invoke(
            "record.locate",
            "locate-pending",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reasonCode"], "version_conflict");
    assert!(take_seen(&provider).is_empty());
    assert!(fixture.requests_after_consent().await.is_empty());
}

/// Discovery offers a lookup-backed action on an OAuth connection once the
/// caller has connected, judged from local state without contacting
/// upstream.
#[tokio::test]
async fn discovery_offers_lookup_backed_actions_once_connected() {
    let provider = Arc::new(LookupRecordsProvider::default());
    let fixture = lookup_fixture(&provider, false).await;
    fixture.grant_locate("locate-personal", "per_user", "default", None);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", fixture.agent_token).parse().unwrap(),
    );
    let identity = fixture.runtime.resolve_identity(&headers).unwrap();
    let context = ExecutionContext::new("default").unwrap();
    let discover = || {
        fixture
            .runtime
            .service_capabilities(&identity, &context, "oauth_stub")
            .unwrap()
    };

    let unconnected = discover();
    assert!(unconnected.actions.is_empty());
    assert_eq!(unconnected.availability.requirements.len(), 1);
    assert_eq!(unconnected.availability.requirements[0].resolution, "user");

    fixture.connect("").await;
    let connected = discover();
    assert_eq!(
        connected.availability.state,
        agent_access_core::AvailabilityState::Available
    );
    assert_eq!(
        connected
            .actions
            .iter()
            .map(|action| action.action.as_str())
            .collect::<Vec<_>>(),
        ["record.locate"]
    );
    assert!(fixture.requests_after_consent().await.is_empty());
    assert!(take_seen(&provider).is_empty());
}
