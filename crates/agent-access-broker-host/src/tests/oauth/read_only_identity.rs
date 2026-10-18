//! A read-only identity path refuses a write before acquiring the caller's
//! OAuth connection. Alice's access has expired by the time the test
//! invokes, so acquiring it refreshes it at the test server: the read on the
//! same path does, the refused write does not.
use super::*;
use agent_access_core::{
    CreateResourceRequest, IdentityContext, IdentitySourceAudit, ManagedPolicyGrantCreateRequest,
};
use agent_access_fake::OAUTH_COLLECTION_RESOURCE;
use agent_access_provider::test_support::DescribedProvider;
use agent_access_provider::{ResourceScopeCapabilities, ServiceProvider};
use std::sync::Mutex;

const SERVICE: &str = "oauth_stub";

/// The records service with a reviewed read and an unreviewed write,
/// recording each hook it serves.
#[derive(Default)]
struct Records {
    calls: Mutex<Vec<String>>,
}

impl Records {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl DescribedProvider for Records {
    fn descriptor(&self) -> ServiceDescriptor {
        let scoped = json!({
            "type": "object", "required": ["collection"],
            "properties": {"collection": {"type": "string"}},
            "additionalProperties": false
        });
        ServiceDescriptor::new(SERVICE, "OAuth Test Records")
            .with_resource_scopes(BTreeMap::from([(
                "collection".into(),
                ResourceScopeCapabilities::new(
                    OAUTH_COLLECTION_RESOURCE.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new("record.view", "Read a record", scoped.clone())
                    .scope("collection")
                    .credential_modes(["per_user"])
                    .read_only(),
                ActionDescriptor::new("record.update", "Update a record", scoped)
                    .scope("collection")
                    .credential_modes(["per_user"]),
            ])
            .with_credentials(
                CredentialDescriptor::default().delegated("Lets agents read and update records."),
            )
    }
}

#[async_trait::async_trait]
impl Provider for Records {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{} scope", request.action()));
        let collection = request.inputs()["collection"].as_str().unwrap().to_owned();
        Ok(ScopeResolution::resources(BTreeMap::from([(
            "collection".to_owned(),
            vec![collection],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.calls.lock().unwrap().push(format!(
            "{} invoke delegated={}",
            request.action(),
            request.execution().delegated().is_some()
        ));
        Ok(ProviderResult::new(json!({"action": request.action()})))
    }
}

/// Alice as an attested identity: her managed principal with the synthetic
/// caveats and path setting that trusted-identity resolution attaches.
fn attested(base: &IdentityContext, read_only: bool) -> IdentityContext {
    IdentityContext {
        source: Some(IdentitySourceAudit {
            name: "forwarded_identity".into(),
            kind: "forwarded_identity".into(),
            token_header: "x-aw-identity-token-sha256".into(),
            token_scheme: "sha256".into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: None,
            namespace: None,
            binding_id: None,
            read_only_access: Some(read_only),
            token_scopes: Some(json!({"allowedExecutionContexts": ["default"]})),
        }),
        ..base.clone()
    }
}

#[tokio::test]
async fn read_only_identity_refuses_a_write_before_leasing_the_callers_oauth_access() {
    let provider = Arc::new(Records::default());
    let fixture = oauth_fixture_with(
        None,
        |_, _| {},
        vec![ServiceProvider::from(Arc::clone(&provider))],
    )
    .await;
    fixture
        .runtime
        .create_managed_resource(CreateResourceRequest {
            id: Some("collection-alpha".into()),
            display_name: None,
            resource_type: OAUTH_COLLECTION_RESOURCE.id().clone(),
            selector: ResourceSelector::Exact {
                value: "alpha".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    fixture
        .runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("personal-records".into()),
            subjects: vec!["user:alice".into()],
            service: SERVICE.into(),
            actions: vec!["record.view".into(), "record.update".into()],
            resources: ResourceSelection {
                resource_ids: vec!["collection-alpha".into()],
                resource_group_ids: Vec::new(),
            },
            execution_contexts: vec!["default".into()],
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    // Connect alice with access that expires before the test invokes.
    fixture.connect_expiring("", 1).await;
    fixture.refreshes().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let upstream = || async {
        fixture
            .requests_after_consent()
            .await
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect::<Vec<_>>()
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", fixture.agent_token).parse().unwrap(),
    );
    let alice = fixture.runtime.resolve_identity(&headers).unwrap();
    let invoke = |read_only: bool, action: &str| {
        fixture.runtime.invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: format!("read-only-{action}"),
                    broker_request_id: format!("broker-read-only-{action}"),
                    identity: attested(&alice, read_only),
                    service: SERVICE.into(),
                    action: action.into(),
                    source: agent_access_core::SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new("default").unwrap(),
            },
            InvokeRequest::new(json!({"collection": "alpha"})),
        )
    };

    let denied = invoke(true, "record.update").await;
    assert_eq!(denied.status, 403, "{:?}", denied.envelope);
    assert_eq!(
        denied.envelope.reason.as_deref(),
        Some("identity access is read-only")
    );
    assert!(upstream().await.is_empty());
    assert!(provider.calls().is_empty());

    let read = invoke(true, "record.view").await;
    assert_eq!(read.status, 200, "{:?}", read.envelope);
    // Leasing the expired connection refreshes it first.
    assert_eq!(
        upstream().await.first().map(String::as_str),
        Some("POST /oauth/token")
    );
    assert_eq!(
        provider.calls(),
        ["record.view scope", "record.view invoke delegated=true"]
    );

    // The full-access path writes with the same connection.
    let write = invoke(false, "record.update").await;
    assert_eq!(write.status, 200, "{:?}", write.envelope);
    assert_eq!(
        provider.calls()[2..],
        [
            "record.update scope".to_owned(),
            "record.update invoke delegated=true".to_owned()
        ]
    );
}
