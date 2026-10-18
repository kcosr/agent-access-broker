//! Token-only actions under a caller's OAuth selection. Eligibility follows
//! the mode of the grant that wins each region: a `per_user` region refuses a
//! token-only action, a `service` region keeps it usable, and the refusal
//! never falls back to a lower grant or acquires the caller's connection.
//!
//! Each test connects alice with access that has expired by the time it
//! invokes, so acquiring her connection would refresh it at the test server;
//! the test provider contacts no upstream itself and records every hook.
use super::*;
use agent_access_core::{CreateResourceRequest, ManagedPolicyGrantCreateRequest};
use agent_access_fake::OAUTH_COLLECTION_RESOURCE;
use agent_access_provider::test_support::DescribedProvider;
use agent_access_provider::{
    ExecutionCredential, LookupAccess, ResourceScopeCapabilities, ServiceProvider,
};
use std::sync::Mutex;

const SERVICE: &str = "oauth_stub";
const SERVICE_TOKEN: &str = "records-service-token";
const LOOKUP_TOKEN: &str = "records-lookup-token";
const TOKEN_ONLY_DENIAL: &str =
    "this action requires a token credential, and the caller's credential connection uses OAuth";

/// The records service with token-only actions beside ordinary ones,
/// recording what each hook received.
#[derive(Default)]
struct TokenOnlyRecords {
    calls: Mutex<Vec<String>>,
}

impl TokenOnlyRecords {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }
}

impl DescribedProvider for TokenOnlyRecords {
    fn descriptor(&self) -> ServiceDescriptor {
        let scoped = json!({
            "type": "object", "required": ["collection"],
            "properties": {"collection": {"type": "string"}},
            "additionalProperties": false
        });
        let unscoped = json!({"type": "object", "additionalProperties": false});
        let action = |name: &str, schema: &Value| {
            ActionDescriptor::new(name, "Exercise token-only eligibility", schema.clone())
                .credential_modes(["service", "per_user"])
        };
        ServiceDescriptor::new(SERVICE, "OAuth Test Records")
            .with_resource_scopes(BTreeMap::from([(
                "collection".into(),
                ResourceScopeCapabilities::new(
                    OAUTH_COLLECTION_RESOURCE.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                // Both resolve their collection with a lookup before policy.
                action("token.create", &scoped)
                    .scope("collection")
                    .lookup(LookupRequirement::ScopeResolution)
                    .token_only(),
                action("token.rotate", &scoped)
                    .scope("collection")
                    .lookup(LookupRequirement::ScopeResolution)
                    .token_only(),
                action("token.view", &scoped)
                    .scope("collection")
                    .token_only(),
                action("token.search", &unscoped)
                    .scope("collection")
                    .native_search(
                        agent_access_provider::NativeSearchEnforcement::UpstreamConstrained,
                    )
                    .token_only(),
                action("token.status", &unscoped).token_only(),
                action("record.view", &scoped)
                    .scope("collection")
                    .read_only(),
                action("account.view", &unscoped).read_only(),
            ])
            .with_credentials(
                CredentialDescriptor::default()
                    .delegated("Lets agents exercise token-only eligibility."),
            )
    }
}

/// The shared token a static credential is, by name.
fn static_name(credential: &ExecutionCredential) -> &'static str {
    if *credential == bearer_credential(SERVICE_TOKEN) {
        "service-token"
    } else if *credential == bearer_credential(LOOKUP_TOKEN) {
        "lookup-token"
    } else {
        "other-token"
    }
}

fn lookup_name(lookup: Option<&LookupAccess>) -> &'static str {
    match lookup {
        None => "none",
        Some(LookupAccess::Static(credential)) => static_name(credential),
        Some(LookupAccess::Delegated(_)) => "delegated",
        Some(_) => "unsupported",
    }
}

#[async_trait::async_trait]
impl Provider for TokenOnlyRecords {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.record(format!(
            "{} scope lookup={}",
            request.action(),
            lookup_name(request.lookup_access())
        ));
        Ok(
            match request.inputs().get("collection").and_then(Value::as_str) {
                Some(collection) => ScopeResolution::resources(BTreeMap::from([(
                    "collection".to_owned(),
                    vec![collection.to_owned()],
                )])),
                None => ScopeResolution::no_resources(),
            },
        )
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let execution = match (
            request.execution().static_credential(),
            request.execution().delegated(),
        ) {
            (Some(credential), _) => static_name(credential),
            (None, Some(_)) => "delegated",
            (None, None) => "none",
        };
        self.record(format!(
            "{} invoke mode={} execution={execution} lookup={}",
            request.action(),
            request.credential_mode(),
            lookup_name(request.lookup_access())
        ));
        Ok(ProviderResult::new(
            json!({"credentialMode": request.credential_mode().as_str()}),
        ))
    }
}

/// Shared service and lookup tokens for the records service, beside alice's
/// OAuth-only connection.
fn shared_credentials(dir: &Path, config: &mut BrokerConfig) {
    let token = |name: &str, value: &str, read_only: Option<bool>| {
        let path = dir.join(name);
        std::fs::write(&path, value).unwrap();
        CredentialConfig {
            kind: "bearer_token".into(),
            username_ref: None,
            token_ref: Some(format!("file:{}", path.display())),
            provider: None,
            path: None,
            read_only,
            connection: None,
        }
    };
    config.credentials.service.insert(
        SERVICE.into(),
        token("records-service-token", SERVICE_TOKEN, None),
    );
    config.credentials.lookup.insert(
        SERVICE.into(),
        token("records-lookup-token", LOOKUP_TOKEN, Some(true)),
    );
}

async fn token_only_fixture(provider: &Arc<TokenOnlyRecords>) -> OAuthFixture {
    oauth_fixture_with(
        None,
        shared_credentials,
        vec![ServiceProvider::from(Arc::clone(provider))],
    )
    .await
}

impl OAuthFixture {
    fn collection(&self, id: &str, selector: ResourceSelector) {
        self.runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(id.into()),
                display_name: None,
                resource_type: OAUTH_COLLECTION_RESOURCE.id().clone(),
                selector,
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                attributes: Default::default(),
                created_by: "admin".into(),
            })
            .unwrap();
    }

    fn grant(&self, id: &str, mode: &str, priority: i32, actions: &[&str], resources: &[&str]) {
        self.runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: Some(id.into()),
                subjects: vec!["user:alice".into()],
                service: SERVICE.into(),
                actions: actions.iter().map(|action| (*action).into()).collect(),
                resources: ResourceSelection {
                    resource_ids: resources.iter().map(|id| (*id).into()).collect(),
                    resource_group_ids: Vec::new(),
                },
                execution_contexts: vec!["default".into()],
                credential_mode: mode.into(),
                priority: Some(priority),
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }

    /// Connects alice with access that expires before the test invokes:
    /// acquiring the connection then refreshes it at the test server.
    async fn connect_expired(&self) {
        self.connect_expiring("", 1).await;
        self.refreshes().await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }

    /// The actions caller discovery lists for alice: those reaching
    /// `collection`, or every listed action.
    fn discovered(&self, collection: Option<&str>) -> Vec<String> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", self.agent_token).parse().unwrap(),
        );
        let identity = self.runtime.resolve_identity(&headers).unwrap();
        let context = ExecutionContext::new("default").unwrap();
        self.runtime
            .service_discovery(&identity, &context, SERVICE)
            .map(|discovery| discovery.actions(collection, None, None).unwrap().actions)
            .unwrap_or_default()
    }

    /// Paths of the test server's requests after the consent flow.
    async fn upstream_after_consent(&self) -> Vec<String> {
        self.requests_after_consent()
            .await
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect()
    }
}

fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}

fn assert_token_only_denial(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "credential_not_provisioned", "{body}");
    assert_eq!(body["error"]["message"], TOKEN_ONLY_DENIAL, "{body}");
}

/// Alice's own grant on `alpha` outranks a shared grant on every
/// collection. Token-only actions disappear only where her `per_user` grant
/// wins and stay usable through the shared one; ordinary actions use her
/// connection there.
#[tokio::test]
async fn token_only_actions_are_refused_only_where_a_per_user_oauth_grant_wins() {
    let provider = Arc::new(TokenOnlyRecords::default());
    let fixture = token_only_fixture(&provider).await;
    fixture.collection("collection-alpha", exact("alpha"));
    fixture.collection("collections-all", ResourceSelector::All);
    let scoped = ["token.create", "token.view", "token.search", "record.view"];
    fixture.grant(
        "personal-alpha",
        "per_user",
        20,
        &scoped,
        &["collection-alpha"],
    );
    fixture.grant("shared-all", "service", 10, &scoped, &["collections-all"]);
    fixture.grant(
        "personal-unscoped",
        "per_user",
        0,
        &["token.status", "account.view"],
        &[],
    );
    fixture.connect_expired().await;

    // Discovery: the per-user region keeps only the ordinary action, and
    // never falls back to the shared grant below it; the shared region keeps
    // the token-only ones. The search action's top band is per-user, and the
    // per-user-only scope-free action is hidden.
    assert_eq!(fixture.discovered(Some("alpha")), ["record.view"]);
    assert_eq!(
        fixture.discovered(Some("beta")),
        ["record.view", "token.create", "token.view"]
    );
    assert_eq!(
        fixture.discovered(None),
        ["account.view", "record.view", "token.create", "token.view"]
    );

    // Without a lookup before policy, the winning per-user grant is refused
    // once policy selects it.
    let (status, body) = fixture
        .invoke(
            "token.view",
            "token-view-alpha",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_token_only_denial(status, &body);
    let (status, body) = fixture
        .invoke("token.search", "token-search", json!({}))
        .await;
    assert_token_only_denial(status, &body);
    let (status, body) = fixture
        .invoke("token.status", "token-status", json!({}))
        .await;
    assert_token_only_denial(status, &body);
    // The shared lookup runs first here; final policy then selects the
    // per-user grant and refuses it, concealed like every final-policy
    // denial of a lookup-resolved action.
    let (status, body) = fixture
        .invoke(
            "token.create",
            "token-create-alpha",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved", "{body}");
    // Scope resolution ran without lookup access, except for the shared
    // lookup; nothing was invoked.
    assert_eq!(
        provider.calls(),
        [
            "token.view scope lookup=none",
            "token.status scope lookup=none",
            "token.create scope lookup=lookup-token",
        ]
    );
    // Nothing acquired alice's connection, so its expired access was never
    // refreshed.
    assert!(fixture.upstream_after_consent().await.is_empty());

    // The shared region serves the same caller with the service token.
    for (action, request_id) in [
        ("token.create", "token-create-beta"),
        ("token.view", "token-view-beta"),
    ] {
        let (status, body) = fixture
            .invoke(action, request_id, json!({"collection": "beta"}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["credentialMode"], "service");
    }
    assert_eq!(
        provider.calls()[3..],
        [
            "token.create scope lookup=lookup-token",
            "token.create invoke mode=service execution=service-token lookup=lookup-token",
            "token.view scope lookup=none",
            "token.view invoke mode=service execution=service-token lookup=none",
        ]
    );
    assert!(fixture.upstream_after_consent().await.is_empty());

    // An ordinary action in the per-user region uses alice's connection,
    // and acquiring it starts by refreshing the expired access: the
    // refusals above acquired nothing.
    let (status, body) = fixture
        .invoke(
            "record.view",
            "record-view-alpha",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["credentialMode"], "per_user");
    assert_eq!(
        provider.calls()[7..],
        [
            "record.view scope lookup=none",
            "record.view invoke mode=per_user execution=delegated lookup=none",
        ]
    );
    assert_eq!(
        fixture
            .upstream_after_consent()
            .await
            .first()
            .map(String::as_str),
        Some("POST /oauth/token")
    );
}

/// When the pre-scope plan uses the caller's own credential, a token-only
/// action is refused before any lookup or acquisition: under a higher
/// per-user wildcard with a lower shared grant, and with per-user grants
/// alone.
#[tokio::test]
async fn a_personal_pre_scope_plan_refuses_before_acquisition_refresh_or_lookup() {
    let provider = Arc::new(TokenOnlyRecords::default());
    let fixture = token_only_fixture(&provider).await;
    fixture.collection("collections-all", ResourceSelector::All);
    fixture.collection("collection-beta", exact("beta"));
    fixture.grant(
        "personal-all",
        "per_user",
        20,
        &["token.create"],
        &["collections-all"],
    );
    fixture.grant(
        "shared-beta",
        "service",
        10,
        &["token.create"],
        &["collection-beta"],
    );
    fixture.grant(
        "personal-only",
        "per_user",
        0,
        &["token.rotate"],
        &["collection-beta"],
    );
    fixture.connect_expired().await;

    // The wildcard wins every collection, so neither grant reaches discovery.
    assert!(fixture.discovered(Some("beta")).is_empty());
    assert!(fixture.discovered(None).is_empty());

    for (action, request_id) in [
        ("token.create", "token-create-wildcard"),
        ("token.rotate", "token-rotate-personal"),
    ] {
        let (status, body) = fixture
            .invoke(action, request_id, json!({"collection": "beta"}))
            .await;
        assert_token_only_denial(status, &body);
    }
    // No lookup ran, and no acquisition refreshed the expired access.
    assert!(provider.calls().is_empty());
    assert!(fixture.upstream_after_consent().await.is_empty());
    let audit = read_audit_records(&fixture.audit_path);
    let denial = audit
        .iter()
        .find(|record| record["agentRequestId"] == "token-create-wildcard")
        .unwrap();
    assert_eq!(denial["decision"], "deny");
    assert_eq!(denial["reasonCode"], "credential_not_provisioned");
}
