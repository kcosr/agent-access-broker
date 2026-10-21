//! Credential connections that accept several token profiles (types): the
//! targets and lists offer each accepted profile with its label and input
//! form, a put chooses one and an unaccepted one is refused, principal kind
//! changes between service account and system keep the stored token, and a
//! row whose profile the owner's list no longer accepts is retained until a
//! configuration accepts it again.
use super::*;
use agent_access_core::{BrokerTokenClass, PrincipalRole};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const SITE_TOKEN: &str = "atlassian-api-token";
const GIT_BEARER: &str = "git-bearer-token";
const GIT_BASIC: &str = "git-basic-api-token";

/// A Jira double declaring a label for its token profile.
struct LabeledJira;

impl agent_access_provider::test_support::DescribedProvider for LabeledJira {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Jira")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "issue.view",
                    "View an issue in token type tests",
                    json!({"type": "object"}),
                )
                .scope("project")
                .credential_modes(["per_user"]),
            ])
            .with_credentials(
                CredentialDescriptor::default().with_profile(
                    agent_access_provider::CredentialProfile::new(SITE_TOKEN, "basic_api_token")
                        .with_label("Site API token"),
                ),
            )
    }
}

#[async_trait::async_trait]
impl Provider for LabeledJira {
    async fn resolve_scopes(
        &self,
        _request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::resources(BTreeMap::from([(
            "project".to_string(),
            vec!["TEST".to_string()],
        )])))
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({"key": "TEST-1"})))
    }
}

/// The configuration: the Git gateway consumes `git`, which accepts bearer
/// tokens from people and bearer or basic tokens from service accounts and
/// system principals (`people` overrides the people's list); Jira consumes
/// `jira` with its labeled site token. Alice (a user) and robot (a service
/// account) hold per_user grants on both.
struct Setup {
    config: BrokerConfig,
    alice: String,
    admin: String,
}

fn setup() -> Setup {
    let hash_key_path = temp_path("token-types-hash-key");
    let store_path = temp_path("token-types-store.sqlite");
    let audit_path = temp_path("token-types.audit.jsonl");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([47_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    // The development service is not used here, and its shared credential
    // would not resolve on reload.
    config.credentials.service.clear();
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
    let mut gateway = test_git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    super::use_token_connection(&mut config, "jira", SITE_TOKEN, &["jira"]);
    super::use_token_connection(&mut config, "git", GIT_BEARER, &["gitlab_git"]);
    config
        .credentials
        .connections
        .get_mut("git")
        .unwrap()
        .service_account_token_profiles = Some(vec![GIT_BEARER.into(), GIT_BASIC.into()]);
    let grant = |subject: &str, service: &str, action: &str, resources| PolicyGrantConfig {
        subjects: vec![subject.to_string()],
        execution_contexts: None,
        service: service.to_string(),
        actions: vec![action.to_string()],
        resources,
        credential_mode: "per_user".to_string(),
        priority: None,
    };
    config.policy.grants = ["user:alice", "user:robot"]
        .into_iter()
        .flat_map(|subject| {
            [
                grant(
                    subject,
                    "jira",
                    "issue.view",
                    selected_resources(&[("jira-project", &["TEST"])]),
                ),
                grant(
                    subject,
                    "gitlab_git",
                    "repo.fetch",
                    selected_resources(&[("repository", &["acme/portal"])]),
                ),
            ]
        })
        .collect();

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (principal, kind) in [
        ("alice", "user"),
        ("admin", "user"),
        ("robot", "service_account"),
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
    Setup {
        alice: issue("alice", BrokerTokenClass::UserManage),
        admin: issue("admin", BrokerTokenClass::Admin),
        config,
    }
}

/// A broker serving `config` with the labeled Jira double.
struct Fixture {
    broker: TestBroker,
    app: Router,
}

impl Fixture {
    async fn start(config: &BrokerConfig) -> Self {
        let broker = TestBroker::start_with_providers(config, vec![Arc::new(LabeledJira)]).await;
        Self {
            app: broker.app(),
            broker,
        }
    }

    fn store(&self) -> agent_access_core::ManagedStore {
        self.broker.runtime().managed_store().unwrap().clone()
    }

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
            "credential-token-types",
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

    /// A refusal with HTTP 400 `input_invalid`, returning its message.
    async fn invalid(&self, token: &str, method: Method, uri: &str, body: Option<Value>) -> String {
        let (status, body) = self.request(token, method.clone(), uri, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}: {body}");
        assert_eq!(body["reasonCode"], "input_invalid", "{body}");
        body["error"]["message"].as_str().unwrap().to_string()
    }
}

fn row<'a>(rows: &'a Value, connection: &str) -> &'a Value {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|row| row["connection"] == connection)
        .unwrap_or_else(|| panic!("{connection} missing from {rows}"))
}

/// Each offered profile's name, label, kind and input field names.
fn offered(row: &Value) -> Vec<(String, Value, String, Vec<String>)> {
    row["tokenProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|profile| {
            assert_eq!(profile["inputSchema"]["profile"], profile["profile"]);
            assert_eq!(
                profile["inputSchema"]["credentialKind"],
                profile["credentialKind"]
            );
            (
                profile["profile"].as_str().unwrap().to_string(),
                profile["label"].clone(),
                profile["credentialKind"].as_str().unwrap().to_string(),
                profile["inputSchema"]["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|field| field["name"].as_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

fn bearer() -> (String, Value, String, Vec<String>) {
    (
        GIT_BEARER.into(),
        Value::Null,
        "bearer_token".into(),
        vec!["token".into()],
    )
}

fn basic() -> (String, Value, String, Vec<String>) {
    (
        GIT_BASIC.into(),
        Value::Null,
        "basic_api_token".into(),
        vec!["username".into(), "token".into()],
    )
}

const ROBOT_GIT: &str = "/v1/admin/principals/robot/credentials/connections/git";

#[tokio::test]
async fn targets_and_lists_offer_each_accepted_profile_with_its_label_and_form() {
    let setup = setup();
    let fixture = Fixture::start(&setup.config).await;

    // People: one accepted Git profile, and Jira's labeled site token.
    let targets = fixture
        .ok(&setup.alice, Method::GET, "/v1/credentials/targets", None)
        .await;
    assert_eq!(offered(row(&targets, "git")), [bearer()]);
    assert_eq!(
        offered(row(&targets, "jira")),
        [(
            SITE_TOKEN.to_string(),
            json!("Site API token"),
            "basic_api_token".to_string(),
            vec!["username".to_string(), "token".to_string()]
        )]
    );
    assert!(row(&targets, "git").get("profile").is_none());
    let list = fixture
        .ok(&setup.alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(
        row(&list["connections"], "git")["tokenProfiles"],
        row(&targets, "git")["tokenProfiles"]
    );

    // A service account: both Git profiles, in configuration order.
    let targets = fixture
        .ok(
            &setup.admin,
            Method::GET,
            "/v1/admin/principals/robot/credentials/targets",
            None,
        )
        .await;
    assert_eq!(offered(row(&targets, "git")), [bearer(), basic()]);
    let list = fixture
        .ok(
            &setup.admin,
            Method::GET,
            "/v1/admin/principals/robot/credentials",
            None,
        )
        .await;
    let git = row(&list["connections"], "git");
    assert_eq!(git["method"], "token");
    assert_eq!(git["tokenProfiles"], row(&targets, "git")["tokenProfiles"]);
    assert!(git.get("credentialKind").is_none(), "{git}");
}

#[tokio::test]
async fn a_put_chooses_among_several_accepted_profiles_and_refuses_others() {
    let setup = setup();
    let fixture = Fixture::start(&setup.config).await;
    let admin = setup.admin.as_str();
    const CHOOSE: &str = "credential profile is required: the connection accepts git-bearer-token, git-basic-api-token";

    // Several accepted profiles need a choice, for the form and the put.
    assert_eq!(
        fixture
            .invalid(
                admin,
                Method::GET,
                &format!("{ROBOT_GIT}/input-schema"),
                None
            )
            .await,
        CHOOSE
    );
    let schema = fixture
        .ok(
            admin,
            Method::GET,
            &format!("{ROBOT_GIT}/input-schema?profile={GIT_BASIC}"),
            None,
        )
        .await;
    assert_eq!(schema["profile"], GIT_BASIC);
    assert_eq!(schema["credentialKind"], "basic_api_token");
    let basic_secret = json!({"username": "robot-deploy", "token": "robot-basic"});
    assert_eq!(
        fixture
            .invalid(
                admin,
                Method::PUT,
                ROBOT_GIT,
                Some(json!({"secret": basic_secret}))
            )
            .await,
        CHOOSE
    );
    for unaccepted in ["git-retired-token", SITE_TOKEN] {
        assert_eq!(
            fixture
                .invalid(
                    admin,
                    Method::PUT,
                    ROBOT_GIT,
                    Some(json!({"profile": unaccepted, "secret": basic_secret}))
                )
                .await,
            "credential profile is not accepted for this principal; the connection accepts git-bearer-token, git-basic-api-token"
        );
    }
    assert!(
        fixture
            .store()
            .list_credentials(Some("robot"))
            .unwrap()
            .is_empty()
    );

    // The chosen profile is stored, with its kind, and reported with its
    // label (none is declared here).
    let stored = fixture
        .ok(
            admin,
            Method::PUT,
            ROBOT_GIT,
            Some(json!({"profile": GIT_BASIC, "secret": basic_secret})),
        )
        .await;
    assert_eq!(stored["connection"], "git");
    assert_eq!(stored["profile"], GIT_BASIC);
    assert_eq!(stored["credentialKind"], "basic_api_token");
    assert_eq!(stored["label"], Value::Null);
    // Replacing it with another type keeps the row.
    let replaced = fixture
        .ok(
            admin,
            Method::PUT,
            ROBOT_GIT,
            Some(json!({"profile": GIT_BEARER, "secret": {"token": "robot-bearer"}})),
        )
        .await;
    assert_eq!(replaced["credentialId"], stored["credentialId"]);
    assert_eq!(replaced["profile"], GIT_BEARER);
    assert_eq!(replaced["credentialKind"], "bearer_token");
    assert_eq!(
        fixture.ok(admin, Method::GET, ROBOT_GIT, None).await["profile"],
        GIT_BEARER
    );

    // People accept one Git profile: it needs no choice, and the service
    // accounts' other profile is refused.
    let alice = setup.alice.as_str();
    let alice_git = "/v1/credentials/connections/git";
    let schema = fixture
        .ok(
            alice,
            Method::GET,
            &format!("{alice_git}/input-schema"),
            None,
        )
        .await;
    assert_eq!(schema["profile"], GIT_BEARER);
    assert_eq!(
        fixture
            .invalid(
                alice,
                Method::PUT,
                alice_git,
                Some(json!({"profile": GIT_BASIC, "secret": basic_secret}))
            )
            .await,
        "credential profile is not accepted for this principal; the connection accepts git-bearer-token"
    );
    let stored = fixture
        .ok(
            alice,
            Method::PUT,
            alice_git,
            Some(json!({"secret": {"token": "alice-bearer"}})),
        )
        .await;
    assert_eq!(stored["profile"], GIT_BEARER);
    // The labeled Jira profile is reported with its label.
    let stored = fixture
        .ok(
            alice,
            Method::PUT,
            "/v1/credentials/connections/jira",
            Some(json!({"profile": SITE_TOKEN, "secret": {"username": "alice@example.com", "token": "alice-site"}})),
        )
        .await;
    assert_eq!(stored["label"], "Site API token");
}

#[tokio::test]
async fn kind_changes_keep_tokens_and_unaccepted_rows_stay_retained_until_accepted() {
    let setup = setup();
    let admin = setup.admin.as_str();
    let alice = setup.alice.as_str();
    let fixture = Fixture::start(&setup.config).await;
    let robot = fixture
        .ok(
            admin,
            Method::PUT,
            ROBOT_GIT,
            Some(json!({"profile": GIT_BASIC, "secret": {"username": "robot-deploy", "token": "robot-basic"}})),
        )
        .await;

    // Service accounts and system principals share one list: changing the
    // kind keeps the token active.
    for kind in ["system", "service_account"] {
        fixture
            .store()
            .create_or_update_principal(agent_access_core::PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "robot".to_string(),
                kind: kind.to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
        let list = fixture
            .ok(
                admin,
                Method::GET,
                "/v1/admin/principals/robot/credentials",
                None,
            )
            .await;
        assert_eq!(
            row(&list["connections"], "git")["credential"]["credentialId"],
            robot["credentialId"],
            "{kind}"
        );
        assert_eq!(list["retained"], json!([]), "{kind}");
    }

    // A person's row of a profile the people's list does not accept is
    // retained, with its label, and never the connection's token.
    let retained_id = fixture
        .store()
        .upsert_user_credential(
            fixture.broker.runtime().credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "git".to_string(),
                name: "default".to_string(),
                profile: GIT_BASIC.to_string(),
                credential_kind: "basic_api_token".to_string(),
                secret: json!({"username": "alice-deploy", "token": "alice-basic"}),
                metadata: json!({}),
                actor: "test".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap()
        .credential_id;
    let retained = |list: &Value| {
        list["retained"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["credentialId"].as_str().unwrap().to_string(),
                    row["profile"].as_str().unwrap().to_string(),
                    row["label"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let list = fixture
        .ok(alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(row(&list["connections"], "git")["credential"], Value::Null);
    assert_eq!(
        retained(&list),
        [(retained_id.clone(), GIT_BASIC.to_string(), Value::Null)]
    );
    let (status, _) = fixture
        .request(alice, Method::GET, "/v1/credentials/connections/git", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A reload that accepts the profile again uses the row as stored,
    // without re-entry.
    let mut accepting = setup.config.clone();
    accepting
        .credentials
        .connections
        .get_mut("git")
        .unwrap()
        .user_token_profiles = Some(vec![GIT_BEARER.into(), GIT_BASIC.into()]);
    fixture.broker.reload_config(&accepting).await;
    let list = fixture
        .ok(alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(
        row(&list["connections"], "git")["credential"]["credentialId"],
        retained_id.as_str()
    );
    assert_eq!(retained(&list), []);

    // Removing it again retains the row; it is still stored.
    fixture.broker.reload_config(&setup.config).await;
    let list = fixture
        .ok(alice, Method::GET, "/v1/credentials", None)
        .await;
    assert_eq!(
        retained(&list),
        [(retained_id, GIT_BASIC.to_string(), Value::Null)]
    );
}
