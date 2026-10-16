//! Credential connection management (design section 6.6): per-operation
//! authorization for owners, administrators and auditors, first-time
//! provisioning from an empty store, cleanup after grant loss, retained
//! rows deleted only by ID, verification that probes as the owner, the
//! audit scope of connection records, and connection IDs that look like
//! collection routes.
use super::*;
use agent_access_core::{BrokerTokenClass, PrincipalRole};
use agent_access_provider::{
    CorrelationContext, ExecutionCredential, ProviderCredentialVerification,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::Mutex;

const JIRA_PROFILE: &str = "jira-cloud-api-token";

/// A Jira double whose credential probe always answers, recording each
/// credential it verified.
#[derive(Default)]
struct ProbeJira {
    verified: Mutex<Vec<ExecutionCredential>>,
}

impl agent_access_provider::test_support::DescribedProvider for ProbeJira {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Jira")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "issue.view",
                    "View an issue in connection tests",
                    json!({"type": "object"}),
                )
                .scope("project")
                .credential_modes(["per_user"]),
            ])
            .with_credentials(
                CredentialDescriptor::default().profile(JIRA_PROFILE, "basic_api_token"),
            )
    }
}

#[async_trait::async_trait]
impl Provider for ProbeJira {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "the probe double serves no invocations",
        ))
    }

    async fn verify_execution_credential(
        &self,
        credential: &ExecutionCredential,
        _: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        self.verified.lock().unwrap().push(credential.clone());
        Ok(Some(ProviderCredentialVerification::new(
            200,
            1,
            json!({"provider": "jira", "operation": "credential.verify"}),
        )))
    }

    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("the probe double serves no invocations")
    }
}

struct Fixture {
    _broker: TestBroker,
    app: Router,
    probe: Arc<ProbeJira>,
    store: agent_access_core::ManagedStore,
    audit_path: PathBuf,
    /// The Jira connection's ID.
    jira: String,
    /// `user_manage` tokens of alice (granted on every consumer) and bob
    /// (no grants).
    alice: String,
    bob: String,
    /// An administrator who holds a per_user Jira grant of its own, and an
    /// auditor.
    admin: String,
    auditor: String,
}

/// Jira consumes the connection `jira`; GitLab REST and Git share the
/// connection `gitlab`. Alice holds per_user grants on all three, the
/// service account `robot` on Jira, and the administrator on Jira; bob and
/// the service account `idle` hold none.
async fn fixture(jira: &str) -> Fixture {
    let hash_key_path = temp_path("credential-connections-hash-key");
    let store_path = temp_path("credential-connections-store.sqlite");
    let audit_path = temp_path("credential-connections.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([43_u8; 32])).unwrap();

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
    config.providers.insert(
        serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
            "tenant_host": "example.atlassian.net",
            "allowed_upstream_hosts": ["https://example.atlassian.net/rest/api/3/**"]
        }))
        .unwrap(),
    );
    config.providers.insert(
        serde_json::from_value::<agent_access_gitlab::GitlabProviderConfig>(json!({
            "api_base_url": "https://gitlab.example.com/api/v4",
            "web_base_url": "https://gitlab.example.com",
            "allowed_upstream_hosts": ["https://gitlab.example.com/api/v4/**"]
        }))
        .unwrap(),
    );
    let mut gateway = test_git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    super::use_token_connection(&mut config, jira, JIRA_PROFILE, &["jira"]);
    super::use_token_connection(
        &mut config,
        "gitlab",
        "gitlab-access-token",
        &["gitlab", "gitlab_git"],
    );
    let grant = |subject: &str, service: &str, action: &str, resources| PolicyGrantConfig {
        subjects: vec![subject.to_string()],
        execution_contexts: None,
        service: service.to_string(),
        actions: vec![action.to_string()],
        resources,
        credential_mode: "per_user".to_string(),
        priority: None,
    };
    let jira_project = || selected_resources(&[("jira-project", &["TEST"])]);
    let repository = || selected_resources(&[("repository", &["acme/portal"])]);
    config.policy.grants = vec![
        grant("user:alice", "jira", "issue.view", jira_project()),
        grant("user:alice", "gitlab", "issue.view", repository()),
        grant("user:alice", "gitlab_git", "repo.fetch", repository()),
        grant("user:robot", "jira", "issue.view", jira_project()),
        grant("user:admin", "jira", "issue.view", jira_project()),
    ];

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (principal, kind) in [
        ("alice", "user"),
        ("bob", "user"),
        ("admin", "user"),
        ("auditor", "user"),
        ("robot", "service_account"),
        ("idle", "service_account"),
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
    for (principal, role) in [
        ("admin", PrincipalRole::Admin),
        ("auditor", PrincipalRole::Auditor),
    ] {
        store
            .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
                principal_id: principal.into(),
                role: Some(role),
                self_service_enabled: None,
                actor: "test".into(),
            })
            .unwrap();
    }
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: BrokerTokenClass| {
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} fixture"),
                    token_class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let alice = issue("alice", BrokerTokenClass::UserManage);
    let bob = issue("bob", BrokerTokenClass::UserManage);
    let admin = issue("admin", BrokerTokenClass::Admin);
    let auditor = issue("auditor", BrokerTokenClass::Admin);
    let probe = Arc::new(ProbeJira::default());
    let broker = TestBroker::start_with_providers(&config, vec![Arc::clone(&probe)]).await;
    let store = broker.runtime().managed_store().unwrap().clone();
    Fixture {
        app: broker.app(),
        _broker: broker,
        probe,
        store,
        audit_path,
        jira: jira.to_string(),
        alice,
        bob,
        admin,
        auditor,
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
            "credential-connections",
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

    /// Stores a row directly, as an earlier configuration might have.
    fn store_row(&self, owner: &str, service: &str, name: &str, profile: &str) -> String {
        let kind = if profile == JIRA_PROFILE {
            "basic_api_token"
        } else {
            "bearer_token"
        };
        let secret = if kind == "basic_api_token" {
            json!({"username": format!("{owner}@example.com"), "token": format!("{owner}-{service}-{name}")})
        } else {
            json!({"token": format!("{owner}-{service}-{name}")})
        };
        self.store
            .upsert_user_credential(
                &credential_ring(),
                CredentialWriteRequest {
                    owner_principal_id: owner.to_string(),
                    service: service.to_string(),
                    name: name.to_string(),
                    profile: profile.to_string(),
                    credential_kind: kind.to_string(),
                    secret,
                    metadata: json!({}),
                    actor: "test".to_string(),
                },
                agent_access_core::CredentialManagementPurpose::Administrative,
            )
            .unwrap()
            .credential_id
    }

    fn connection(&self) -> String {
        format!("/v1/credentials/connections/{}", self.jira)
    }

    fn admin_connection(&self, principal: &str) -> String {
        format!(
            "/v1/admin/principals/{principal}/credentials/connections/{}",
            self.jira
        )
    }
}

/// The key ring `fake_config` configures.
fn credential_ring() -> agent_access_core::CredentialKeyRing {
    let config = fake_config("unused.audit.jsonl");
    agent_access_core::CredentialKeyRing::load(config.credential_encryption.as_ref().unwrap())
        .unwrap()
}

fn jira_secret(token: &str) -> Value {
    json!({"secret": {"username": "alice@example.com", "token": token}})
}

fn connection_row<'a>(list: &'a Value, connection: &str) -> &'a Value {
    list["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["connection"] == connection)
        .unwrap_or_else(|| panic!("{connection} missing from {list}"))
}

#[tokio::test]
async fn reserved_looking_connection_ids_round_trip_without_shadowing_collection_routes() {
    for id in ["targets", "retained", "connections"] {
        let fixture = fixture(id).await;
        let connection = fixture.connection();
        let schema = fixture
            .ok(
                &fixture.alice,
                Method::GET,
                &format!("{connection}/input-schema"),
                None,
            )
            .await;
        assert_eq!(schema["connection"], id);
        assert_eq!(schema["profile"], JIRA_PROFILE);
        let stored = fixture
            .ok(
                &fixture.alice,
                Method::PUT,
                &connection,
                Some(jira_secret("reserved-token")),
            )
            .await;
        assert_eq!(stored["connection"], id, "{stored}");
        assert!(stored.get("service").is_none(), "{stored}");
        let read = fixture
            .ok(&fixture.alice, Method::GET, &connection, None)
            .await;
        assert_eq!(read["credentialId"], stored["credentialId"]);
        let verified = fixture
            .ok(
                &fixture.alice,
                Method::POST,
                &format!("{connection}/verify"),
                None,
            )
            .await;
        assert_eq!(verified["verificationStatus"], "upstream_verified");
        assert_eq!(verified["probeService"], "jira");

        // The collection routes keep their meaning.
        let targets = fixture
            .ok(&fixture.alice, Method::GET, "/v1/credentials/targets", None)
            .await;
        let ids = targets
            .as_array()
            .unwrap()
            .iter()
            .map(|target| target["connection"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids, BTreeSet::from([id, "gitlab"]), "{targets}");
        let list = fixture
            .ok(&fixture.alice, Method::GET, "/v1/credentials", None)
            .await;
        assert_eq!(
            connection_row(&list, id)["credential"]["credentialId"],
            stored["credentialId"]
        );
        let retained = fixture.store_row("alice", "jira_legacy", "default", JIRA_PROFILE);
        let (status, refused) = fixture
            .request(
                &fixture.alice,
                Method::DELETE,
                &format!(
                    "/v1/credentials/retained/{}",
                    stored["credentialId"].as_str().unwrap()
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        let deleted = fixture
            .ok(
                &fixture.alice,
                Method::DELETE,
                &format!("/v1/credentials/retained/{retained}"),
                None,
            )
            .await;
        assert_eq!(deleted["service"], "jira_legacy");
        let deleted = fixture
            .ok(&fixture.alice, Method::DELETE, &connection, None)
            .await;
        assert_eq!(deleted["connection"], id);
        assert!(
            fixture
                .store
                .list_credentials(Some("alice"))
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn first_provisioning_lists_entitled_consumers_from_an_empty_store() {
    let fixture = fixture("jira").await;
    let list = fixture
        .ok(&fixture.alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(list["retained"], json!([]));
    let jira = connection_row(&list, "jira");
    assert_eq!(jira["method"], "token");
    assert_eq!(jira["credential"], Value::Null);
    assert_eq!(jira["profile"], JIRA_PROFILE);
    assert_eq!(jira["credentialKind"], "basic_api_token");
    let gitlab = connection_row(&list, "gitlab");
    assert_eq!(
        gitlab["consumers"],
        json!([
            {"service": "gitlab", "displayName": "GitLab", "credentialVerificationInputs": []},
            {"service": "gitlab_git", "displayName": "GitLab Git",
                "credentialVerificationInputs": ["repository"]}
        ])
    );
    assert_eq!(gitlab["otherConsumers"], 0);

    // Bob is entitled to nothing: no targets, no rows, no setup.
    assert_eq!(
        fixture
            .ok(&fixture.bob, Method::GET, "/v1/credentials/targets", None)
            .await,
        json!([])
    );
    assert_eq!(
        fixture
            .ok(&fixture.bob, Method::GET, "/v1/credentials", None)
            .await,
        json!({"connections": [], "retained": []})
    );
    let (status, denied) = fixture
        .request(
            &fixture.bob,
            Method::PUT,
            &fixture.connection(),
            Some(jira_secret("bob-token")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["reasonCode"], "service_action_denied");

    // Alice provisions the shared GitLab token once for both consumers.
    let stored = fixture
        .ok(
            &fixture.alice,
            Method::PUT,
            "/v1/credentials/connections/gitlab",
            Some(json!({"secret": {"token": "gitlab-token"}})),
        )
        .await;
    assert_eq!(stored["connection"], "gitlab");
    let rows = fixture.store.list_credentials(Some("alice")).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].service.as_str(), rows[0].name.as_str()),
        ("gitlab", "default")
    );
    // A profile other than the connection's is refused.
    let (status, refused) = fixture
        .request(
            &fixture.alice,
            Method::PUT,
            "/v1/credentials/connections/gitlab",
            Some(json!({"profile": "git-bearer-token", "secret": {"token": "x"}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    // An unknown connection is not configured.
    let (status, unknown) = fixture
        .request(
            &fixture.alice,
            Method::GET,
            "/v1/credentials/connections/gitlab_git",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{unknown}");
    assert_eq!(unknown["reasonCode"], "input_invalid");
}

#[tokio::test]
async fn owners_keep_cleanup_after_grant_loss_but_cannot_set_up_or_verify() {
    let fixture = fixture("jira").await;
    // An administrator provisions bob, who holds no grant.
    fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            &fixture.admin_connection("bob"),
            Some(jira_secret("bob-token")),
        )
        .await;
    let list = fixture
        .ok(&fixture.bob, Method::GET, "/v1/credentials", None)
        .await;
    let jira = connection_row(&list, "jira");
    assert_eq!(jira["consumers"], json!([]));
    assert_eq!(jira["otherConsumers"], 1);
    assert!(jira["credential"]["credentialId"].is_string());
    for (method, suffix) in [
        (Method::GET, "/input-schema"),
        (Method::POST, "/verify"),
        (Method::PUT, ""),
    ] {
        let body = (method == Method::PUT).then(|| jira_secret("bob-token"));
        let (status, denied) = fixture
            .request(
                &fixture.bob,
                method.clone(),
                &format!("{}{suffix}", fixture.connection()),
                body,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {suffix}: {denied}");
    }
    assert!(fixture.probe.verified.lock().unwrap().is_empty());
    fixture
        .ok(&fixture.bob, Method::GET, &fixture.connection(), None)
        .await;
    fixture
        .ok(&fixture.bob, Method::DELETE, &fixture.connection(), None)
        .await;
    assert!(
        fixture
            .store
            .list_credentials(Some("bob"))
            .unwrap()
            .is_empty()
    );

    // Self-service gates still apply to cleanup.
    fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            &fixture.admin_connection("bob"),
            Some(jira_secret("bob-token")),
        )
        .await;
    fixture
        .store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: None,
            self_service_enabled: Some(false),
            actor: "test".into(),
        })
        .unwrap();
    let (status, denied) = fixture
        .request(&fixture.bob, Method::DELETE, &fixture.connection(), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["reasonCode"], "self_service_disabled");
    assert_eq!(
        fixture.store.list_credentials(Some("bob")).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn retained_rows_are_listed_read_only_and_deleted_by_id_never_the_active_row() {
    let fixture = fixture("jira").await;
    let active = fixture.store_row("alice", "jira", "default", JIRA_PROFILE);
    // Another name, a service that no longer names its own connection, and
    // a retired profile under the shared connection's ID.
    let other_name = fixture.store_row("alice", "jira", "secondary", JIRA_PROFILE);
    let git_only = fixture.store_row("alice", "gitlab_git", "default", "git-bearer-token");
    let retired = fixture.store_row("alice", "gitlab", "default", "gitlab-retired-token");
    let list = fixture
        .ok(&fixture.alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(
        connection_row(&list, "jira")["credential"]["credentialId"],
        active.as_str()
    );
    // The retired-profile row is not the GitLab connection's token.
    assert_eq!(connection_row(&list, "gitlab")["credential"], Value::Null);
    let retained = list["retained"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["credentialId"].as_str().unwrap().to_string(),
                row["service"].as_str().unwrap().to_string(),
                row["name"].as_str().unwrap().to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        retained,
        BTreeSet::from([
            (other_name.clone(), "jira".into(), "secondary".into()),
            (git_only.clone(), "gitlab_git".into(), "default".into()),
            (retired.clone(), "gitlab".into(), "default".into()),
        ])
    );
    let (status, inspected) = fixture
        .request(
            &fixture.alice,
            Method::GET,
            "/v1/credentials/connections/gitlab",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{inspected}");

    // The active token cannot be deleted as a retained row.
    let (status, refused) = fixture
        .request(
            &fixture.alice,
            Method::DELETE,
            &format!("/v1/credentials/retained/{active}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["reasonCode"], "credential_invalid");
    assert_eq!(
        refused["target"],
        json!({"principal": "alice", "credentialId": active})
    );
    // Another owner's row is not found.
    let (status, hidden) = fixture
        .request(
            &fixture.bob,
            Method::DELETE,
            &format!("/v1/credentials/retained/{git_only}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{hidden}");
    for id in [&other_name, &git_only, &retired] {
        fixture
            .ok(
                &fixture.alice,
                Method::DELETE,
                &format!("/v1/credentials/retained/{id}"),
                None,
            )
            .await;
    }
    let remaining = fixture.store.list_credentials(Some("alice")).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].credential_id, active);
    // An administrator may delete any row by ID.
    fixture
        .ok(
            &fixture.admin,
            Method::DELETE,
            &format!("/v1/admin/credentials/{active}"),
            None,
        )
        .await;
    let records = read_audit_records(&fixture.audit_path);
    assert!(records.iter().any(|record| {
        record["action"] == "credentials.retained.delete"
            && record["providerAudit"]["management"]["target"]
                == json!({"principal": "alice", "credentialId": other_name})
    }));
}

#[tokio::test]
async fn administrators_verify_a_service_account_only_through_its_own_grants() {
    let fixture = fixture("jira").await;
    // The administrator holds no grant for robot's sake; robot's own grant
    // authorizes the probe.
    let stored = fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            &fixture.admin_connection("robot"),
            Some(json!({"secret": {"username": "robot@example.com", "token": "robot-token"}})),
        )
        .await;
    assert_eq!(stored["ownerPrincipal"], "robot");
    let verified = fixture
        .ok(
            &fixture.admin,
            Method::POST,
            &format!("{}/verify", fixture.admin_connection("robot")),
            None,
        )
        .await;
    assert_eq!(verified["verificationStatus"], "upstream_verified");
    assert_eq!(verified["probeService"], "jira");
    assert_eq!(
        *fixture.probe.verified.lock().unwrap(),
        [basic_credential("robot@example.com", "robot-token")]
    );

    // idle holds no grant: the administrator's own Jira grant never
    // authorizes a probe of idle's token.
    fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            &fixture.admin_connection("idle"),
            Some(json!({"secret": {"username": "idle@example.com", "token": "idle-token"}})),
        )
        .await;
    let (status, denied) = fixture
        .request(
            &fixture.admin,
            Method::POST,
            &format!("{}/verify", fixture.admin_connection("idle")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["reasonCode"], "service_action_denied");
    // Nor may the owner's verification name a service it has no grant on.
    let (status, denied) = fixture
        .request(
            &fixture.admin,
            Method::POST,
            &format!("{}/verify", fixture.admin_connection("robot")),
            Some(json!({"service": "gitlab"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(fixture.probe.verified.lock().unwrap().len(), 1);

    // Targets show what robot can be provisioned with.
    let targets = fixture
        .ok(
            &fixture.admin,
            Method::GET,
            "/v1/admin/principals/robot/credentials/targets",
            None,
        )
        .await;
    assert_eq!(targets.as_array().unwrap().len(), 1, "{targets}");
    assert_eq!(targets[0]["connection"], "jira");
    assert_eq!(
        fixture
            .ok(
                &fixture.admin,
                Method::GET,
                "/v1/admin/principals/idle/credentials/targets",
                None,
            )
            .await,
        json!([])
    );
}

#[tokio::test]
async fn auditors_read_connection_credentials_but_never_change_or_verify_them() {
    let fixture = fixture("jira").await;
    fixture.store_row("alice", "jira", "default", JIRA_PROFILE);
    let read = fixture
        .ok(
            &fixture.auditor,
            Method::GET,
            &fixture.admin_connection("alice"),
            None,
        )
        .await;
    assert_eq!(read["connection"], "jira");
    fixture
        .ok(
            &fixture.auditor,
            Method::GET,
            &format!("{}/input-schema", fixture.admin_connection("alice")),
            None,
        )
        .await;
    for (method, suffix, body) in [
        (Method::PUT, "", Some(jira_secret("audited"))),
        (Method::POST, "/verify", None),
        (Method::DELETE, "", None),
    ] {
        let (status, denied) = fixture
            .request(
                &fixture.auditor,
                method.clone(),
                &format!("{}{suffix}", fixture.admin_connection("alice")),
                body,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {suffix}: {denied}");
        assert_eq!(denied["reasonCode"], "management_denied");
    }
    assert!(fixture.probe.verified.lock().unwrap().is_empty());
    assert_eq!(
        fixture.store.list_credentials(Some("alice")).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn connection_records_name_their_consumers_and_admin_records_a_sole_consumer() {
    let fixture = fixture("jira").await;
    fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            &fixture.admin_connection("alice"),
            Some(jira_secret("admin-set")),
        )
        .await;
    fixture
        .ok(
            &fixture.admin,
            Method::PUT,
            "/v1/admin/principals/alice/credentials/connections/gitlab",
            Some(json!({"secret": {"token": "admin-gitlab"}})),
        )
        .await;
    fixture
        .ok(
            &fixture.alice,
            Method::PUT,
            &fixture.connection(),
            Some(jira_secret("self-set")),
        )
        .await;
    let records = read_audit_records(&fixture.audit_path);
    let management = |action: &str, connection: &str| {
        records
            .iter()
            .filter(|record| {
                record["action"] == action
                    && record["providerAudit"]["management"]["target"]["connection"] == connection
            })
            .map(|record| record["providerAudit"]["management"].clone())
            .collect::<Vec<_>>()
    };
    let admin_jira = management("admin.credentials.put", "jira");
    assert!(!admin_jira.is_empty());
    for record in &admin_jira {
        assert_eq!(
            record["target"],
            json!({"principal": "alice", "connection": "jira"})
        );
        assert_eq!(record["targetServices"], json!(["jira"]));
        assert_eq!(record["targetService"], "jira");
    }
    // A shared connection has no single scope service.
    let admin_gitlab = management("admin.credentials.put", "gitlab");
    assert!(!admin_gitlab.is_empty());
    for record in &admin_gitlab {
        assert_eq!(record["targetServices"], json!(["gitlab", "gitlab_git"]));
        assert!(record.get("targetService").is_none(), "{record}");
    }
    // Self-service records list consumers but stay out of managers' view.
    let personal = management("credentials.put", "jira");
    assert!(!personal.is_empty());
    for record in &personal {
        assert_eq!(record["targetServices"], json!(["jira"]));
        assert!(record.get("targetService").is_none(), "{record}");
    }
}

#[tokio::test]
async fn classless_static_principals_select_no_stored_token() {
    let admin_token_path = temp_path("classless-connections-admin-token");
    let key_path = temp_path("classless-connections-key");
    let store_path = temp_path("classless-connections-store.sqlite");
    let audit_path = temp_path("classless-connections.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();
    let mut config =
        managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);
    config.management.allow_classless_user_management = true;
    let broker =
        TestBroker::start_with_providers(&config, vec![Arc::new(ProbeJira::default())]).await;
    let store = broker.runtime().managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    // Even a write right on (connection, default) gives a configured static
    // principal no personal method.
    store
        .grant_right(agent_access_core::RightGrantRequest {
            principal_id: "alice".into(),
            right: "credentials:self:write".into(),
            service: Some("jira".into()),
            credential_name: Some("default".into()),
            resource_scope_json: None,
            created_by: "admin".into(),
            expires_at: None,
            reason: None,
        })
        .unwrap();
    let app = broker.app();
    let request = |method: Method, uri: &'static str, body: Option<&'static str>| {
        authed_json_request(
            app.clone(),
            method,
            uri,
            "classless-connections",
            "Authorization",
            "Bearer alice-token".to_string(),
            body,
        )
    };
    let targets = request(Method::GET, "/v1/credentials/targets", None).await;
    assert_eq!(targets.status(), StatusCode::OK);
    assert_eq!(response_json(targets).await["result"], json!([]));
    let put = request(
        Method::PUT,
        "/v1/credentials/connections/jira",
        Some(r#"{"secret":{"username":"alice@example.com","token":"t"}}"#),
    )
    .await;
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(put).await["reasonCode"], "input_invalid");
    assert!(store.list_credentials(Some("alice")).unwrap().is_empty());
}
