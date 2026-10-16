//! Vendor-level Atlassian token profiles (design section 6.11): one
//! `atlassian` connection serves Jira and Confluence with one stored
//! classic API token on the site route, service accounts' scoped bearer
//! tokens reach each product through the gateway, and rows stored under the
//! retired product profiles are listed as retained, still decrypt, and are
//! never selected.
use super::*;
use agent_access_core::{BrokerTokenClass, PrincipalRole};
use agent_access_provider::{ExecutionCredential, StaticCredentialKind};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::Mutex;

const SITE: &str = "example.atlassian.net";
const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";

/// A stand-in for one Atlassian product: the real backend's descriptor for
/// the configured site, so its token profiles are the ones the product
/// declares, with one per_user read action that records the execution
/// credential each invocation receives.
struct RecordingProduct {
    descriptor: ServiceDescriptor,
    scope: &'static str,
    invoked: Mutex<Vec<Option<ExecutionCredential>>>,
}

impl RecordingProduct {
    fn new(descriptor: ServiceDescriptor, action: &str, scope: &'static str) -> Arc<Self> {
        let descriptor = descriptor.with_actions(vec![
            ActionDescriptor::new(
                action,
                "Read in Atlassian connection tests",
                json!({"type": "object"}),
            )
            .scope(scope)
            .credential_modes(["per_user"])
            .read_only(),
        ]);
        Arc::new(Self {
            descriptor,
            scope,
            invoked: Mutex::default(),
        })
    }

    fn invoked(&self) -> Vec<Option<ExecutionCredential>> {
        self.invoked.lock().unwrap().clone()
    }
}

impl agent_access_provider::test_support::DescribedProvider for RecordingProduct {
    fn descriptor(&self) -> ServiceDescriptor {
        self.descriptor.clone()
    }
}

#[async_trait::async_trait]
impl Provider for RecordingProduct {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        let resource = request.inputs()["resource"]
            .as_str()
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "resource is required"))?;
        Ok(ScopeResolution::resources(BTreeMap::from([(
            self.scope.to_string(),
            vec![resource.to_string()],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invoked
            .lock()
            .unwrap()
            .push(request.execution().static_credential().cloned());
        Ok(ProviderResult::new(json!({"read": true})))
    }
}

struct Fixture {
    _broker: TestBroker,
    app: Router,
    jira: Arc<RecordingProduct>,
    confluence: Arc<RecordingProduct>,
    store: agent_access_core::ManagedStore,
    ring: agent_access_core::CredentialKeyRing,
    /// Alice's `user_manage` and `agent_invoke` tokens, the service account
    /// robot's `agent_invoke` token and the administrator's token.
    alice_manage: String,
    alice_invoke: String,
    robot_invoke: String,
    admin: String,
}

/// Jira and Confluence on one site, routed through the Atlassian gateway
/// when `gateway` is set. `connections` lists each connection with its
/// token profile and consumers. The person alice and the service account
/// robot hold per_user grants on both products.
async fn fixture(gateway: bool, connections: &[(&str, &str, &[&str])]) -> Fixture {
    let hash_key_path = temp_path("atlassian-connections-hash-key");
    let store_path = temp_path("atlassian-connections-store.sqlite");
    let audit_path = temp_path("atlassian-connections.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([47_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.management.enabled = true;
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_user_manage_ttl: Some("8h".to_string()),
        ..Default::default()
    });
    let (jira_hosts, confluence_hosts) = if gateway {
        (
            json!([
                format!("https://{SITE}/rest/api/3/**"),
                format!("https://api.atlassian.com/ex/jira/{CLOUD_ID}/rest/api/3/**")
            ]),
            json!([
                format!("https://{SITE}/wiki/**"),
                format!("https://api.atlassian.com/ex/confluence/{CLOUD_ID}/wiki/**")
            ]),
        )
    } else {
        (
            json!([format!("https://{SITE}/rest/api/3/**")]),
            json!([format!("https://{SITE}/wiki/**")]),
        )
    };
    let jira_config = serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
        "tenant_host": SITE,
        "cloud_id": CLOUD_ID,
        "allowed_upstream_hosts": jira_hosts
    }))
    .unwrap();
    let confluence_config =
        serde_json::from_value::<agent_access_confluence::ConfluenceProviderConfig>(json!({
            "tenant_host": SITE,
            "cloud_id": CLOUD_ID,
            "allowed_upstream_hosts": confluence_hosts
        }))
        .unwrap();
    let jira = RecordingProduct::new(
        agent_access_jira::jira_descriptor(&jira_config),
        "issue.view",
        "project",
    );
    let confluence = RecordingProduct::new(
        agent_access_confluence::confluence_descriptor(&confluence_config),
        "page.view",
        "space",
    );
    config.providers.insert(jira_config);
    config.providers.insert(confluence_config);
    for (connection, profile, consumers) in connections {
        super::use_token_connection(&mut config, connection, profile, consumers);
    }
    let grant = |subject: &str, service: &str, action: &str, resources| PolicyGrantConfig {
        subjects: vec![subject.to_string()],
        execution_contexts: None,
        service: service.to_string(),
        actions: vec![action.to_string()],
        resources,
        credential_mode: "per_user".to_string(),
        priority: None,
    };
    for subject in ["user:alice", "user:robot"] {
        config.policy.grants.push(grant(
            subject,
            "jira",
            "issue.view",
            selected_resources(&[("jira-project", &["TEST"])]),
        ));
        config.policy.grants.push(grant(
            subject,
            "confluence",
            "page.view",
            selected_resources(&[("space", &["ENG"])]),
        ));
    }

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (principal, kind) in [
        ("alice", "user"),
        ("robot", "service_account"),
        ("admin", "user"),
    ] {
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.to_string(),
                kind: kind.to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "admin".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: BrokerTokenClass| {
        let scopes = match token_class {
            BrokerTokenClass::AgentInvoke => json!({"allowedExecutionContexts": ["default"]}),
            _ => json!({}),
        };
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} fixture"),
                    token_class,
                    scopes,
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let alice_manage = issue("alice", BrokerTokenClass::UserManage);
    let alice_invoke = issue("alice", BrokerTokenClass::AgentInvoke);
    let robot_invoke = issue("robot", BrokerTokenClass::AgentInvoke);
    let admin = issue("admin", BrokerTokenClass::Admin);
    let ring =
        agent_access_core::CredentialKeyRing::load(config.credential_encryption.as_ref().unwrap())
            .unwrap();
    let broker =
        TestBroker::start_with_providers(&config, vec![Arc::clone(&jira), Arc::clone(&confluence)])
            .await;
    let store = broker.runtime().managed_store().unwrap().clone();
    Fixture {
        app: broker.app(),
        _broker: broker,
        jira,
        confluence,
        store,
        ring,
        alice_manage,
        alice_invoke,
        robot_invoke,
        admin,
    }
}

impl Fixture {
    async fn request(
        &self,
        token: &str,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let body = body.map(|body| body.to_string());
        let response = authed_json_request(
            self.app.clone(),
            method,
            uri,
            "atlassian-connections",
            "Authorization",
            format!("Bearer {token}"),
            body.as_deref(),
        )
        .await;
        (response.status(), response_json(response).await)
    }

    async fn ok(&self, token: &str, method: Method, uri: &str, body: Option<Value>) -> Value {
        let (status, body) = self.request(token, method.clone(), uri, body).await;
        assert_eq!(status, StatusCode::OK, "{method} {uri}: {body}");
        body["result"].clone()
    }

    /// Invokes each product's read action with `token`.
    async fn read_both(&self, token: &str) -> [(StatusCode, Value); 2] {
        [
            self.request(
                token,
                Method::POST,
                "/v1/invoke/jira/issue.view",
                Some(json!({"inputs": {"resource": "TEST"}})),
            )
            .await,
            self.request(
                token,
                Method::POST,
                "/v1/invoke/confluence/page.view",
                Some(json!({"inputs": {"resource": "ENG"}})),
            )
            .await,
        ]
    }

    /// Stores a row under a retired product profile, as the previous
    /// configuration wrote it.
    fn store_product_row(&self, service: &str, profile: &str, token: &str) -> String {
        self.store
            .upsert_user_credential(
                &self.ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: service.to_string(),
                    name: "default".to_string(),
                    profile: profile.to_string(),
                    credential_kind: "basic_api_token".to_string(),
                    secret: json!({"username": "alice@example.com", "token": token}),
                    metadata: json!({}),
                    actor: "test".to_string(),
                },
                agent_access_core::CredentialManagementPurpose::Administrative,
            )
            .unwrap()
            .credential_id
    }
}

fn retained_ids(list: &Value) -> BTreeSet<String> {
    list["retained"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["credentialId"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn one_stored_atlassian_token_serves_jira_and_confluence_on_the_site_route() {
    let fixture = fixture(
        false,
        &[("atlassian", "atlassian-api-token", &["jira", "confluence"])],
    )
    .await;
    // Rows the product connections stored before the vendor-level profiles.
    let old_jira = fixture.store_product_row("jira", "jira-cloud-api-token", "old-jira-token");
    let old_confluence = fixture.store_product_row(
        "confluence",
        "confluence-cloud-api-token",
        "old-confluence-token",
    );

    // One setup target serves both products.
    let targets = fixture
        .ok(
            &fixture.alice_manage,
            Method::GET,
            "/v1/credentials/targets",
            None,
        )
        .await;
    let targets = targets.as_array().unwrap();
    assert_eq!(targets.len(), 1, "{targets:?}");
    let target = &targets[0];
    assert_eq!(target["connection"], "atlassian");
    assert_eq!(target["profile"], "atlassian-api-token");
    assert_eq!(target["credentialKind"], "basic_api_token");
    let consumers = target["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|consumer| consumer["service"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(consumers, BTreeSet::from(["confluence", "jira"]));
    assert_eq!(target["otherConsumers"], 0);

    // The old product rows are retained, not the connection's token.
    let list = fixture
        .ok(&fixture.alice_manage, Method::GET, "/v1/credentials", None)
        .await;
    let rows = list["connections"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{list}");
    assert_eq!(rows[0]["connection"], "atlassian");
    assert_eq!(rows[0]["credential"], Value::Null);
    assert_eq!(
        retained_ids(&list),
        BTreeSet::from([old_jira.clone(), old_confluence.clone()])
    );
    // Neither product reads them: with no token stored under the
    // connection, both calls fail before reaching the provider.
    for (status, body) in fixture.read_both(&fixture.alice_invoke).await {
        assert!(!status.is_success(), "{body}");
        assert_eq!(body["reasonCode"], "credential_not_found", "{body}");
    }
    assert!(fixture.jira.invoked().is_empty());
    assert!(fixture.confluence.invoked().is_empty());

    // Alice stores one token, which both products receive.
    let stored = fixture
        .ok(
            &fixture.alice_manage,
            Method::PUT,
            "/v1/credentials/connections/atlassian",
            Some(json!({"secret": {"username": "alice@example.com", "token": "shared-token"}})),
        )
        .await;
    assert_eq!(stored["connection"], "atlassian");
    assert_eq!(stored["profile"], "atlassian-api-token");
    for (status, body) in fixture.read_both(&fixture.alice_invoke).await {
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let shared = basic_credential("alice@example.com", "shared-token");
    assert_eq!(fixture.jira.invoked(), [Some(shared.clone())]);
    assert_eq!(fixture.confluence.invoked(), [Some(shared.clone())]);
    // A basic credential, which both products send to the site.
    assert_eq!(shared.kind(), StaticCredentialKind::BasicApiToken);

    // The stored row is the connection's, and the old rows stay retained
    // and decryptable under their own profiles for cleanup and rewrap.
    let list = fixture
        .ok(&fixture.alice_manage, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(
        list["connections"][0]["credential"]["credentialId"],
        stored["credentialId"]
    );
    assert_eq!(
        retained_ids(&list),
        BTreeSet::from([old_jira.clone(), old_confluence.clone()])
    );
    for (service, profile, token) in [
        ("jira", "jira-cloud-api-token", "old-jira-token"),
        (
            "confluence",
            "confluence-cloud-api-token",
            "old-confluence-token",
        ),
    ] {
        assert_eq!(
            fixture
                .store
                .resolve_user_credential(&fixture.ring, "alice", service, "default", profile)
                .unwrap(),
            basic_credential("alice@example.com", token),
            "{service}"
        );
    }

    // The owner deletes retained rows by ID; the active row is refused.
    let (status, refused) = fixture
        .request(
            &fixture.alice_manage,
            Method::DELETE,
            &format!(
                "/v1/credentials/retained/{}",
                stored["credentialId"].as_str().unwrap()
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    for id in [&old_jira, &old_confluence] {
        let deleted = fixture
            .ok(
                &fixture.alice_manage,
                Method::DELETE,
                &format!("/v1/credentials/retained/{id}"),
                None,
            )
            .await;
        assert_eq!(deleted["credentialId"], id.as_str());
    }
    let remaining = fixture.store.list_credentials(Some("alice")).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].service, "atlassian");
}

#[tokio::test]
async fn a_service_account_uses_its_scoped_bearer_token_through_the_gateway() {
    let fixture = fixture(
        true,
        &[
            ("jira", "atlassian-bearer-token", &["jira"]),
            ("confluence", "atlassian-bearer-token", &["confluence"]),
        ],
    )
    .await;
    // An administrator provisions the service account's Jira token.
    let stored = fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            "/v1/admin/principals/robot/credentials/connections/jira",
            Some(json!({"secret": {"token": "robot-jira-token"}})),
        )
        .await;
    assert_eq!(stored["profile"], "atlassian-bearer-token");
    assert_eq!(stored["credentialKind"], "bearer_token");

    let [(jira_status, jira), (confluence_status, confluence)] =
        fixture.read_both(&fixture.robot_invoke).await;
    assert_eq!(jira_status, StatusCode::OK, "{jira}");
    let token = bearer_credential("robot-jira-token");
    assert_eq!(fixture.jira.invoked(), [Some(token.clone())]);
    // A bearer credential, which Jira sends through the gateway.
    assert_eq!(token.kind(), StaticCredentialKind::BearerToken);
    // The Confluence connection is separate: robot has no token there.
    assert!(!confluence_status.is_success(), "{confluence}");
    assert_eq!(
        confluence["reasonCode"], "credential_not_found",
        "{confluence}"
    );
    assert!(fixture.confluence.invoked().is_empty());
}
