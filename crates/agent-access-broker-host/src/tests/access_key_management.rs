//! The management routes for usernames and access keys, through the
//! production router: administration of names, the fill and confirmation of
//! existing accounts, a person's own tokens from their browser session, an
//! administrator's tokens for people and service accounts, and the
//! configured types.

use super::*;
use agent_access_core::{
    AccessKeyTypeConfig, BrokerTokenClass, PrincipalAccessPatchRequest, PrincipalRole,
    TrustedCallerConfig, TrustedCallerContextMode, http_route_specs,
};

const RESOLVER: &str = "Bearer resolver-caller-credential-0123456789";

struct Management {
    fixture: BrowserRateFixture,
    store: agent_access_core::ManagedStore,
    auditor: String,
}

/// The description of `inference`; the other types have none.
const INFERENCE_DESCRIPTION: &str = "Point your tool at https://gateway.example.com/v1.";

fn access_key_type(display_name: &str, lifetime: &str, self_service: bool) -> AccessKeyTypeConfig {
    AccessKeyTypeConfig {
        display_name: display_name.to_string(),
        description: None,
        lifetime_options: vec!["60s".into(), "600s".into(), "1h".into(), lifetime.into()],
        default_lifetime: lifetime.into(),
        self_service,
    }
}

/// People may create `inference` and `research` tokens themselves; `batch`
/// only an administrator issues. `example.com` derives names, `root` is
/// reserved and `carol` is an ID services already use.
fn configure(config: &mut BrokerConfig, resolver_secret: &Path) {
    config.usernames.email_domains = vec!["example.com".to_string()];
    config.usernames.reserved_names = vec!["root".to_string()];
    config.usernames.existing_usernames = vec!["carol".to_string()];
    config.access_key_types.insert(
        "inference".to_string(),
        AccessKeyTypeConfig {
            description: Some(INFERENCE_DESCRIPTION.to_string()),
            ..access_key_type("Model inference", "30d", true)
        },
    );
    config.access_key_types.insert(
        "research".to_string(),
        access_key_type("Research data", "7d", true),
    );
    config.access_key_types.insert(
        "batch".to_string(),
        access_key_type("Batch jobs", "7d", false),
    );
    config.identity.trusted_callers.insert(
        "proxy".to_string(),
        TrustedCallerConfig {
            credential_ref: format!("file:{}", resolver_secret.display()),
            credential_transport: Default::default(),
            username_namespace: None,
            context_mode: TrustedCallerContextMode::Fixed,
            execution_context: Some("default".to_string()),
            allowed_execution_contexts: None,
            allow_forwarded_identity: false,
            allow_access_key_resolution: true,
        },
    );
}

/// Who may hold what: Alice's own setting allows `inference` and `batch`,
/// and `research` is allowed only to the members of the group `research`,
/// which has none.
fn grant_access(
    store: &agent_access_core::ManagedStore,
    runtime: &agent_access_core::BrokerRuntime,
) {
    super::access_key_resolve::allow_access_key_types(
        store,
        runtime,
        "alice",
        &["inference", "batch"],
    );
    store
        .create_group_with_access(
            agent_access_core::GroupWriteRequest {
                group_id: "research".to_string(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: Default::default(),
                created_by: "admin".to_string(),
            },
            Some(agent_access_core::AccessKeyTypesWrite {
                setting: &agent_access_core::GroupAccessKeyTypes::new(vec!["research".to_string()])
                    .unwrap(),
                configured: runtime.access_key_types(),
            }),
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
}

async fn management() -> Management {
    let resolver_secret = temp_path("access-key-management-caller");
    std::fs::write(&resolver_secret, RESOLVER.strip_prefix("Bearer ").unwrap()).unwrap();
    let fixture =
        browser_rate_fixture_with(test_limits(), |config| configure(config, &resolver_secret))
            .await;
    let runtime = fixture.state.current().runtime.clone();
    let store = runtime.managed_store().unwrap().clone();
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    grant_access(&store, &runtime);
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "olga".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            },
            &contexts,
        )
        .unwrap();
    store
        .patch_principal_access(
            PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: "olga".into(),
                role: Some(PrincipalRole::Auditor),
                self_service_enabled: None,
                actor: "admin".into(),
            },
            &contexts,
        )
        .unwrap();
    let auditor = store
        .issue_broker_token(
            runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "olga".into(),
                name: "auditor".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    Management {
        fixture,
        store,
        auditor,
    }
}

/// What a request authenticates with.
#[derive(Clone, Copy)]
enum As<'a> {
    Admin,
    Auditor,
    /// Alice's browser session, with or without the CSRF header.
    Browser {
        csrf: bool,
    },
    /// A bearer token in the Broker's token header.
    Token(&'a str),
}

impl Management {
    async fn send(
        &self,
        who: As<'_>,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(
                "127.0.0.1:43130".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id);
        builder = match who {
            As::Admin => builder.header(
                "X-Agent-Token",
                format!("Bearer {}", self.fixture.admin_token),
            ),
            As::Auditor => builder.header("X-Agent-Token", format!("Bearer {}", self.auditor)),
            As::Token(token) => builder.header("X-Agent-Token", format!("Bearer {token}")),
            As::Browser { csrf } => {
                let builder = builder
                    .header("Cookie", &self.fixture.cookie)
                    .header("Host", "localhost")
                    .header("Origin", "http://localhost");
                if csrf {
                    builder.header("X-Agent-Access-CSRF", &self.fixture.csrf)
                } else {
                    builder
                }
            }
        };
        let body = match body {
            Some(body) => {
                builder = builder.header(CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .fixture
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store")),
            "{uri}"
        );
        (status, response_json(response).await)
    }

    async fn admin(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.send(As::Admin, method, uri, request_id, body).await
    }

    /// A successful administrator request's `result`, checked against the
    /// result schema the catalog publishes for the operation.
    async fn admin_ok(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> Value {
        let (status, envelope) = self.admin(method, uri, request_id, body).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {envelope}");
        self.checked_result(envelope)
    }

    /// A browser request by Alice with the CSRF header.
    async fn alice(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.send(As::Browser { csrf: true }, method, uri, request_id, body)
            .await
    }

    async fn alice_ok(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> Value {
        let (status, envelope) = self.alice(method, uri, request_id, body).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {envelope}");
        self.checked_result(envelope)
    }

    /// The `result` of a successful envelope, which must satisfy the result
    /// schema of its operation in the route catalog.
    fn checked_result(&self, envelope: Value) -> Value {
        assert_eq!(envelope["ok"], true, "{envelope}");
        let operation = envelope["operation"].as_str().unwrap();
        let routes = http_route_specs(self.fixture.state.current().runtime.resource_types());
        let schema = routes
            .iter()
            .find(|route| route.operation == operation)
            .and_then(|route| route.result_schema.clone())
            .unwrap_or_else(|| panic!("{operation} has no result schema"));
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors = validator
            .iter_errors(&envelope["result"])
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect::<Vec<_>>();
        assert!(
            errors.is_empty(),
            "{operation}: {errors:?}\n{}",
            envelope["result"]
        );
        envelope["result"].clone()
    }

    fn records(&self, operation: &str, request_id: &str) -> Vec<Value> {
        read_audit_records(&self.fixture.audit_path)
            .into_iter()
            .filter(|record| {
                record["action"] == operation && record["agentRequestId"] == request_id
            })
            .collect()
    }

    /// The preflight and the success record of a committed mutation: the
    /// success record's target, which carries the transaction's facts.
    fn completion(&self, operation: &str, request_id: &str) -> Value {
        let records = self.records(operation, request_id);
        let phases = records
            .iter()
            .map(|record| {
                record["providerAudit"]["management"]["phase"]
                    .as_str()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        assert_eq!(phases, ["preflight", "success"], "{records:?}");
        assert!(records.iter().all(|record| record["decision"] == "allow"));
        records[1]["providerAudit"]["management"]["target"].clone()
    }

    /// The single denial record of a refused request, with its details.
    fn denial(&self, operation: &str, request_id: &str) -> Value {
        let records = self
            .records(operation, request_id)
            .into_iter()
            .filter(|record| record["decision"] == "deny")
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "{records:?}");
        records[0]["providerAudit"]["management"].clone()
    }

    async fn create_principal(&self, body: Value) {
        let (status, envelope) = self
            .admin(
                Method::POST,
                "/v1/admin/principals",
                "access-key-management-setup",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{envelope}");
    }

    /// An administrator replaces `principal`'s access key type setting.
    async fn set_access(&self, principal: &str, allow: &[&str], deny: &[&str], request_id: &str) {
        let (status, envelope) = self
            .admin(
                Method::PATCH,
                &format!("/v1/admin/principals/{principal}/access"),
                request_id,
                Some(json!({"accessKeyTypes": {"allow": allow, "deny": deny}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{envelope}");
    }

    /// An administrator sets a person's name by hand.
    async fn set_name(&self, principal: &str, name: &str, request_id: &str) -> Value {
        self.admin_ok(
            Method::PUT,
            &format!("/v1/admin/principals/{principal}/account-username"),
            request_id,
            Some(json!({"mode": "manual", "accountUsername": name})),
        )
        .await
    }

    /// An administrator's request to a route whose result the catalog does
    /// not describe: the `result` of its successful envelope.
    async fn admin_result(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> Value {
        let (status, envelope) = self.admin(method, uri, request_id, body).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {envelope}");
        envelope["result"].clone()
    }

    /// Waits for the owners that outlive their request or reload, the fill
    /// of missing names among them, to finish.
    async fn settled(&self) {
        assert_eq!(
            self.fixture
                .state
                .application_owners
                .drain(Duration::from_secs(10))
                .await,
            0
        );
    }

    async fn resolve(&self, request_id: &str, token: &str) -> Value {
        let response = self
            .fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/access-keys/resolve")
                    .extension(ConnectInfo(
                        "127.0.0.1:43131".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, request_id)
                    .header("x-agent-access-caller-authorization", RESOLVER)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"key": token}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await
    }
}

fn refusal(envelope: &Value) -> (&str, &str) {
    (
        envelope["reasonCode"].as_str().unwrap_or_default(),
        envelope["details"]["refusal"].as_str().unwrap_or_default(),
    )
}

#[tokio::test]
async fn an_administrator_sets_how_a_person_s_name_is_decided_and_the_name_itself() {
    let m = management().await;
    // Created with an email of a listed domain: named at creation.
    m.create_principal(
        json!({"principalId": "usr-bob", "kind": "user", "email": "Bob@example.com",
            "displayName": "Bob Example"}),
    )
    .await;
    m.create_principal(json!({"principalId": "robot", "kind": "service_account"}))
        .await;
    let bob_name = "/v1/admin/principals/usr-bob/account-username";

    let bob = m.admin_ok(Method::GET, bob_name, "name-view", None).await;
    assert_eq!(bob["principalId"], "usr-bob");
    assert_eq!(bob["holderKind"], "user");
    assert_eq!(bob["displayName"], "Bob Example");
    assert_eq!(bob["email"], "Bob@example.com");
    assert_eq!(bob["mode"], "from_email");
    assert_eq!(bob["state"], "usable");
    assert!(bob["reason"].is_null());
    assert_eq!(bob["name"]["accountUsername"], "bob");
    assert_eq!(bob["name"]["state"], "usable");
    assert_eq!(bob["name"]["origin"], "derived");
    assert_eq!(bob["name"]["incarnation"].as_str().unwrap().len(), 32);
    assert!(bob["conflict"].is_null());
    let derived = bob["name"]["incarnation"].clone();
    // A read writes no audit record.
    assert!(
        m.records("admin.principals.account_username.inspect", "name-view")
            .is_empty()
    );
    // The account's own detail reports the same.
    let detail = m
        .admin_result(Method::GET, "/v1/admin/principals/usr-bob", "detail", None)
        .await;
    assert_eq!(detail["accountUsername"], bob);
    // A service account's name is its ID, and it has no mode.
    let robot = m
        .admin_ok(
            Method::GET,
            "/v1/admin/principals/robot/account-username",
            "name-view-robot",
            None,
        )
        .await;
    assert_eq!(robot["name"]["accountUsername"], "robot");
    assert_eq!(robot["name"]["origin"], "service_account");
    assert_eq!(robot["holderKind"], "service_account");
    assert!(robot["mode"].is_null());
    assert_eq!(robot["state"], "usable");

    // To manual: the name held stays, as the one set by hand.
    let manual = m
        .admin_ok(
            Method::PUT,
            bob_name,
            "mode-manual",
            Some(json!({"mode": "manual"})),
        )
        .await;
    assert_eq!(manual["mode"], "manual");
    assert_eq!(manual["name"]["incarnation"], derived);
    // The response says what the change did: nothing to the name.
    assert_eq!(
        manual["accountUsernameChange"],
        json!({
            "previousMode": "from_email",
            "mode": "manual",
            "before": bob["name"],
            "after": bob["name"],
            "renamed": false,
            "endedKeys": 0,
            "reason": null,
            "conflict": null,
        })
    );
    // What following the email would give is still read from the saved
    // email, now that the name is set by hand.
    assert_eq!(
        manual["fromEmail"],
        json!({"accountUsername": "bob", "reason": null, "conflict": null})
    );
    let completion = m.completion("admin.principals.account_username.set", "mode-manual");
    assert_eq!(completion["principal"], "usr-bob");
    assert_eq!(completion["previousMode"], "from_email");
    assert_eq!(completion["mode"], "manual");
    assert_eq!(completion["before"], completion["after"]);

    // A name typed by hand is a new allocation.
    let set = m.set_name("usr-bob", "b.smith", "name-set").await;
    assert_eq!(set["name"]["accountUsername"], "b.smith");
    assert_eq!(set["name"]["origin"], "administrator");
    assert_eq!(set["name"]["assignedBy"], "admin");
    assert_eq!(set["accountUsernameChange"]["renamed"], true);
    assert_eq!(set["accountUsernameChange"]["endedKeys"], 0);
    assert_eq!(
        set["accountUsernameChange"]["before"]["accountUsername"],
        "bob"
    );
    assert_eq!(set["accountUsernameChange"]["after"], set["name"]);
    assert_eq!(set["fromEmail"]["accountUsername"], "bob");
    let typed = set["name"]["incarnation"].clone();
    assert_ne!(typed, derived);
    let completion = m.completion("admin.principals.account_username.set", "name-set");
    assert_eq!(completion["before"]["accountUsername"], "bob");
    assert_eq!(
        completion["after"],
        json!({"accountUsername": "b.smith", "usernameIncarnation": typed, "origin": "administrator",
            "state": "usable"})
    );
    // The same name again changes nothing.
    let same = m.set_name("usr-bob", "b.smith", "name-set-same").await;
    assert_eq!(same["name"]["incarnation"], typed);
    assert_eq!(same["accountUsernameChange"]["renamed"], false);
    assert_eq!(
        same["accountUsernameChange"]["before"],
        same["accountUsernameChange"]["after"]
    );

    // Each refusal has its reason code and says which refusal it is.
    for (request_id, uri, name, status, expected) in [
        (
            "name-taken-by-service-account",
            bob_name,
            "robot",
            StatusCode::CONFLICT,
            ("broker_account_username_conflict", "name_taken"),
        ),
        (
            "name-reserved",
            bob_name,
            "root",
            StatusCode::FORBIDDEN,
            ("broker_account_username_denied", "name_reserved"),
        ),
        (
            "name-invalid",
            bob_name,
            "has space",
            StatusCode::BAD_REQUEST,
            ("input_invalid", "name_invalid"),
        ),
        (
            "name-not-human",
            "/v1/admin/principals/robot/account-username",
            "robot2",
            StatusCode::FORBIDDEN,
            ("broker_account_username_denied", "not_human"),
        ),
    ] {
        let (code, envelope) = m
            .admin(
                Method::PUT,
                uri,
                request_id,
                Some(json!({"mode": "manual", "accountUsername": name})),
            )
            .await;
        assert_eq!(code, status, "{request_id}: {envelope}");
        assert_eq!(refusal(&envelope), expected, "{request_id}");
        assert!(
            envelope["error"]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
        assert_eq!(
            m.denial("admin.principals.account_username.set", request_id)["details"]["refusal"],
            expected.1
        );
    }
    // A body says how the name is decided; a name goes with manual only.
    for (request_id, body) in [
        ("body-empty", json!({})),
        ("body-no-mode", json!({"accountUsername": "bob"})),
        ("body-mode", json!({"mode": "automatic"})),
        (
            "body-name-with-email",
            json!({"mode": "from_email", "accountUsername": "bob"}),
        ),
        (
            "body-null-with-email",
            json!({"mode": "from_email", "accountUsername": null}),
        ),
        (
            "body-extra",
            json!({"mode": "manual", "accountUsername": "bob", "force": true}),
        ),
        (
            "body-number",
            json!({"mode": "manual", "accountUsername": 7}),
        ),
    ] {
        let (status, envelope) = m.admin(Method::PUT, bob_name, request_id, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{request_id}: {envelope}");
        assert_eq!(envelope["reasonCode"], "input_invalid", "{request_id}");
    }
    assert_eq!(
        m.admin_ok(Method::GET, bob_name, "name-after-refusals", None)
            .await["name"]["incarnation"],
        typed
    );

    // No value in manual mode is no name.
    let none = m
        .admin_ok(
            Method::PUT,
            bob_name,
            "name-none",
            Some(json!({"mode": "manual", "accountUsername": null})),
        )
        .await;
    assert!(none["name"].is_null());
    assert_eq!(
        (&none["mode"], &none["state"], &none["reason"]),
        (&json!("manual"), &json!("none"), &json!("not_set"))
    );
    assert_eq!(
        (
            &none["accountUsernameChange"]["renamed"],
            &none["accountUsernameChange"]["after"],
            &none["accountUsernameChange"]["reason"]
        ),
        (&json!(true), &Value::Null, &json!("not_set"))
    );
    assert_eq!(
        none["accountUsernameChange"]["before"]["accountUsername"],
        "b.smith"
    );
    let completion = m.completion("admin.principals.account_username.set", "name-none");
    assert_eq!(completion["before"]["accountUsername"], "b.smith");
    assert!(completion["after"].is_null());

    // Back to the email: derived at once, as a new allocation.
    let followed = m
        .admin_ok(
            Method::PUT,
            bob_name,
            "mode-from-email",
            Some(json!({"mode": "from_email"})),
        )
        .await;
    assert_eq!(followed["mode"], "from_email");
    assert_eq!(followed["name"]["accountUsername"], "bob");
    assert_eq!(followed["name"]["origin"], "derived");
    assert_ne!(followed["name"]["incarnation"], derived);
    assert_ne!(followed["name"]["incarnation"], typed);

    // Administrators change; auditors read; nobody else sees names.
    let (status, envelope) = m
        .send(As::Auditor, Method::GET, bob_name, "auditor-read", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{envelope}");
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::PUT,
            bob_name,
            "auditor-write",
            Some(json!({"mode": "manual"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(envelope["reasonCode"], "management_denied");
    let (status, envelope) = m
        .send(
            As::Token(&m.fixture.management_token),
            Method::GET,
            bob_name,
            "user-read",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    let (status, envelope) = m
        .admin(
            Method::PUT,
            "/v1/admin/principals/missing/account-username",
            "missing",
            Some(json!({"mode": "manual"})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{envelope}");
    assert_eq!(envelope["reasonCode"], "principal_not_found");
}

#[tokio::test]
async fn changing_the_email_of_a_person_who_follows_it_renames_them_and_ends_their_tokens() {
    let m = management().await;
    let alice = "/v1/admin/principals/alice";
    let patch = async |request_id: &str, body: Value| {
        m.admin_result(Method::PATCH, alice, request_id, Some(body))
            .await
    };

    // Alice follows her email and has none: no name, and the reason.
    let before = m.admin_result(Method::GET, alice, "detail", None).await;
    assert_eq!(
        (
            &before["accountUsername"]["mode"],
            &before["accountUsername"]["state"],
            &before["accountUsername"]["reason"]
        ),
        (&json!("from_email"), &json!("none"), &json!("no_email"))
    );

    // An email of a listed domain names her in the same change.
    let named = patch("email-set", json!({"email": "Alice@example.com"})).await;
    assert_eq!(named["email"], "Alice@example.com");
    assert!(named["accountUsernameChange"]["before"].is_null());
    assert_eq!(
        named["accountUsernameChange"]["after"]["accountUsername"],
        "alice"
    );
    assert_eq!(named["accountUsernameChange"]["after"]["origin"], "derived");
    assert_eq!(
        named["accountUsernameChange"]["after"]["assignedBy"],
        "admin"
    );
    assert_eq!(named["accountUsernameChange"]["endedKeys"], 0);
    assert_eq!(named["accountUsernameChange"]["renamed"], true);
    assert_eq!(named["accountUsernameChange"]["previousMode"], "from_email");
    assert_eq!(named["accountUsernameChange"]["mode"], "from_email");
    let first = named["accountUsernameChange"]["after"]["incarnation"].clone();
    let completion = m.completion("admin.principals.patch", "email-set");
    assert_eq!(completion["principal"], "alice");
    assert_eq!(completion["accountUsername"]["principal"], "alice");
    assert!(completion["accountUsername"]["before"].is_null());
    assert_eq!(
        completion["accountUsername"]["after"],
        json!({"accountUsername": "alice", "usernameIncarnation": first, "origin": "derived",
            "state": "usable"})
    );

    // She creates a token under that name.
    let issued = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "issue",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    let token = issued["key"].as_str().unwrap().to_string();
    assert_eq!(m.resolve("resolve-first", &token).await["active"], true);

    // A change of another profile field, or the same email again, renames
    // nobody.
    for (request_id, body) in [
        ("display-name", json!({"displayName": "Alice Example"})),
        ("email-same", json!({"email": "Alice@example.com"})),
    ] {
        let unchanged = patch(request_id, body).await;
        assert!(unchanged["accountUsernameChange"].is_null(), "{request_id}");
        assert!(
            m.completion("admin.principals.patch", request_id)["accountUsername"].is_null(),
            "{request_id}"
        );
    }
    assert_eq!(m.resolve("resolve-unchanged", &token).await["active"], true);

    // A new email renames her: the old name is released, the new one
    // allocated, and her token stops working.
    let renamed = patch("email-changed", json!({"email": "alicia@example.com"})).await;
    assert_eq!(
        renamed["accountUsernameChange"]["before"]["accountUsername"],
        "alice"
    );
    assert_eq!(
        renamed["accountUsernameChange"]["after"]["accountUsername"],
        "alicia"
    );
    assert_ne!(
        renamed["accountUsernameChange"]["after"]["incarnation"],
        first
    );
    assert_eq!(renamed["accountUsernameChange"]["endedKeys"], 1);
    assert_eq!(renamed["accountUsernameChange"]["renamed"], true);
    let completion = m.completion("admin.principals.patch", "email-changed");
    assert_eq!(
        completion["accountUsername"]["before"]["accountUsername"],
        "alice"
    );
    assert_eq!(
        completion["accountUsername"]["after"]["accountUsername"],
        "alicia"
    );
    assert_eq!(completion["accountUsername"]["endedKeys"], 1);
    assert_eq!(
        m.resolve("resolve-renamed", &token).await,
        json!({
            "active": false,
            "keyId": issued["record"]["keyId"],
            "owner": {"kind": "user", "id": "alicia"},
            "reason": "username_incarnation_changed"
        })
    );
    let listed = m
        .alice_ok(Method::GET, "/v1/access-keys", "list-renamed", None)
        .await;
    assert_eq!(listed["keys"][0]["status"], "username_incarnation_changed");
    // The released name is free: another account derives it at creation.
    m.create_principal(
        json!({"principalId": "usr-alice2", "kind": "user", "email": "alice@example.com"}),
    )
    .await;
    assert_eq!(
        m.admin_ok(
            Method::GET,
            "/v1/admin/principals/usr-alice2/account-username",
            "second",
            None
        )
        .await["name"]["accountUsername"],
        "alice"
    );

    // An email that derives a name someone holds leaves her without one,
    // and the conflict is shown on her account: nobody is displaced.
    let conflict = patch("email-conflict", json!({"email": "ALICE@example.com"})).await;
    assert_eq!(
        conflict["accountUsernameChange"]["before"]["accountUsername"],
        "alicia"
    );
    assert!(conflict["accountUsernameChange"]["after"].is_null());
    // The response says why she has none now, and who holds the name.
    assert_eq!(conflict["accountUsernameChange"]["renamed"], true);
    assert_eq!(conflict["accountUsernameChange"]["reason"], "name_taken");
    assert_eq!(
        conflict["accountUsernameChange"]["conflict"],
        json!({"accountUsername": "alice", "heldBy": "usr-alice2"})
    );
    let detail = m
        .admin_result(Method::GET, alice, "detail-conflict", None)
        .await;
    assert_eq!(detail["accountUsername"]["state"], "conflict");
    assert_eq!(detail["accountUsername"]["reason"], "name_taken");
    assert_eq!(
        detail["accountUsername"]["conflict"],
        json!({"accountUsername": "alice", "heldBy": "usr-alice2"})
    );
    // She is told that she has no name and why, never who holds it.
    let options = m
        .alice_ok(Method::GET, "/v1/access-keys/options", "options", None)
        .await;
    assert_eq!(
        options["accountUsername"],
        json!({"name": null, "state": "conflict", "mode": "from_email", "reason": "name_taken",
            "fromEmail": {"accountUsername": null, "reason": "name_taken"}})
    );
    assert_eq!(options["refusal"], "no_account_username");
    assert_eq!(options["problem"], "no_account_username");

    // An email that derives nothing, and no email, leave no name either.
    for (request_id, email, reason) in [
        (
            "email-unlisted",
            json!("alice@contractor.example"),
            "domain_not_listed",
        ),
        ("email-none", Value::Null, "no_email"),
    ] {
        let released = patch(request_id, json!({ "email": email })).await;
        // She held no name before either: nothing was renamed, and the
        // response still says why she has none.
        assert_eq!(
            released["accountUsernameChange"],
            json!({"previousMode": "from_email", "mode": "from_email", "before": null,
                "after": null, "renamed": false, "endedKeys": 0, "reason": reason,
                "conflict": null}),
            "{request_id}"
        );
        let detail = m.admin_result(Method::GET, alice, request_id, None).await;
        assert_eq!(detail["accountUsername"]["state"], "none", "{request_id}");
        assert_eq!(detail["accountUsername"]["reason"], reason, "{request_id}");
        assert_eq!(
            detail["accountUsername"]["fromEmail"],
            json!({"accountUsername": null, "reason": reason, "conflict": null}),
            "{request_id}"
        );
        // Nothing was written about a name, so the audit record has none.
        assert!(
            m.completion("admin.principals.patch", request_id)["accountUsername"].is_null(),
            "{request_id}"
        );
    }

    // A person whose name is set by hand keeps it whatever their email:
    // the response says so, and what the new email would give on switching.
    let manual = m.set_name("alice", "a.manual", "manual").await;
    let unchanged = patch("email-manual", json!({"email": "amy@example.com"})).await;
    assert_eq!(
        unchanged["accountUsernameChange"],
        json!({"previousMode": "manual", "mode": "manual", "before": manual["name"],
            "after": manual["name"], "renamed": false, "endedKeys": 0, "reason": null,
            "conflict": null})
    );
    assert!(m.completion("admin.principals.patch", "email-manual")["accountUsername"].is_null());
    let detail = m
        .admin_result(Method::GET, alice, "detail-manual", None)
        .await;
    assert_eq!(
        detail["accountUsername"]["name"]["incarnation"],
        manual["name"]["incarnation"]
    );
    assert_eq!(
        detail["accountUsername"]["fromEmail"],
        json!({"accountUsername": "amy", "reason": null, "conflict": null})
    );
}

/// A fixture whose configuration a test can change and reload: its provider
/// credential is a file, which a reload can read again. `configure_names`
/// changes the username settings the Broker starts with.
async fn reloadable(configure_names: impl FnOnce(&mut BrokerConfig)) -> (Management, BrokerConfig) {
    let provider_token = temp_path("access-key-management-fake-token");
    std::fs::write(&provider_token, "synthetic-fake-service-token").unwrap();
    let resolver_secret = temp_path("access-key-management-reload-caller");
    std::fs::write(&resolver_secret, RESOLVER.strip_prefix("Bearer ").unwrap()).unwrap();
    let mut captured = None;
    let fixture = browser_rate_fixture_with(test_limits(), |config| {
        configure(config, &resolver_secret);
        configure_names(config);
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", provider_token.display()));
        captured = Some(config.clone());
    })
    .await;
    let runtime = fixture.state.current().runtime.clone();
    let store = runtime.managed_store().unwrap().clone();
    grant_access(&store, &runtime);
    (
        Management {
            fixture,
            store,
            auditor: String::new(),
        },
        captured.unwrap(),
    )
}

#[tokio::test]
async fn an_email_edit_keeps_or_ends_a_person_s_keys_by_the_username_the_new_email_gives() {
    // Two listed domains, so that one local part is the same username under
    // either.
    let (m, _config) = reloadable(|config| {
        config
            .usernames
            .email_domains
            .push("example.net".to_string());
    })
    .await;
    let alice = "/v1/admin/principals/alice";
    let alice_name = "/v1/admin/principals/alice/account-username";
    let patch = async |request_id: &str, email: &str| {
        let result = m
            .admin_result(
                Method::PATCH,
                alice,
                request_id,
                Some(json!({ "email": email })),
            )
            .await;
        assert_eq!(result["email"], email, "{request_id}");
        result["accountUsernameChange"].clone()
    };
    // Alice creates a key; keep its secret, ID and the incarnation it was minted under.
    let issue = async |request_id: &str| {
        let issued = m
            .alice_ok(
                Method::POST,
                "/v1/access-keys",
                request_id,
                issue_body(request_id, &["inference"], 3600),
            )
            .await;
        (
            issued["key"].as_str().unwrap().to_string(),
            issued["record"]["keyId"].clone(),
            issued["record"]["usernameIncarnation"].clone(),
        )
    };
    // Resolution reports the current usable owner and state without auditing.
    let inactive =
        async |request_id: &str, key: &str, key_id: &Value, owner: Option<&str>, reason: &str| {
            assert_eq!(
                m.resolve(request_id, key).await,
                json!({
                    "active": false,
                    "keyId": key_id,
                    "owner": owner.map(|id| json!({"kind": "user", "id": id})),
                    "reason": reason
                }),
                "{request_id}"
            );
            assert!(
                read_audit_records(&m.fixture.audit_path)
                    .into_iter()
                    .all(|record| record["agentRequestId"] != request_id)
            );
        };

    let named = patch("email-first", "alice@example.com").await;
    assert_eq!(named["after"]["accountUsername"], "alice");
    let first_incarnation = named["after"]["incarnation"].clone();
    let (first, first_id, minted_under) = issue("issue-first").await;
    assert_eq!(minted_under, first_incarnation);

    // An edit that gives the same username keeps the username, its
    // incarnation and the keys: a change of letter case only, and a move to
    // another listed domain with the same local part.
    for (request_id, email) in [
        ("email-case-only", "ALICE@Example.COM"),
        ("email-other-domain", "alice@example.net"),
        ("email-other-domain-case", "Alice@EXAMPLE.net"),
    ] {
        let change = patch(request_id, email).await;
        assert_eq!(
            (&change["renamed"], &change["endedKeys"]),
            (&json!(false), &json!(0)),
            "{request_id}: {change}"
        );
        assert_eq!(change["before"], change["after"], "{request_id}");
        assert_eq!(change["after"]["accountUsername"], "alice", "{request_id}");
        assert_eq!(
            change["after"]["incarnation"], first_incarnation,
            "{request_id}"
        );
        // Nothing about a name was written, so the record carries none.
        assert!(
            m.completion("admin.principals.patch", request_id)["accountUsername"].is_null(),
            "{request_id}"
        );
        let resolved = m.resolve(&format!("resolve-{request_id}"), &first).await;
        assert_eq!(resolved["active"], true, "{request_id}");
        assert_eq!(
            resolved["subject"],
            json!({"kind": "user", "id": "alice"}),
            "{request_id}"
        );
        assert_eq!(
            resolved["usernameIncarnation"], first_incarnation,
            "{request_id}"
        );
        let view = m
            .admin_ok(Method::GET, alice_name, &format!("view-{request_id}"), None)
            .await;
        assert_eq!(view["liveKeys"], 1, "{request_id}");
        assert_eq!(view["name"]["incarnation"], first_incarnation);
    }

    // An edit that gives a different username ends the keys.
    let change = patch("email-different", "alicia@example.net").await;
    assert_eq!(
        (&change["renamed"], &change["endedKeys"]),
        (&json!(true), &json!(1)),
        "{change}"
    );
    assert_eq!(change["before"]["accountUsername"], "alice");
    assert_eq!(change["after"]["accountUsername"], "alicia");
    let second_incarnation = change["after"]["incarnation"].clone();
    assert_ne!(second_incarnation, first_incarnation);
    inactive(
        "resolve-after-different",
        &first,
        &first_id,
        Some("alicia"),
        "username_incarnation_changed",
    )
    .await;
    let (second, second_id, minted_under) = issue("issue-second").await;
    assert_eq!(minted_under, second_incarnation);
    assert_eq!(
        m.resolve("resolve-second", &second).await["subject"]["id"],
        "alicia"
    );

    // An edit that gives no username ends them too.
    let change = patch("email-none", "alicia@contractor.example").await;
    assert_eq!(
        (
            &change["renamed"],
            &change["endedKeys"],
            &change["after"],
            &change["reason"]
        ),
        (
            &json!(true),
            &json!(1),
            &Value::Null,
            &json!("domain_not_listed")
        ),
        "{change}"
    );
    inactive(
        "resolve-after-none",
        &second,
        &second_id,
        None,
        "no_account_username",
    )
    .await;

    // A released username taken again has a new incarnation: the key that
    // was minted under the same name before does not come back.
    let change = patch("email-again", "alice@example.com").await;
    assert_eq!(change["after"]["accountUsername"], "alice");
    let third_incarnation = change["after"]["incarnation"].clone();
    assert_ne!(third_incarnation, first_incarnation);
    assert_ne!(third_incarnation, second_incarnation);
    inactive(
        "resolve-first-after-reuse",
        &first,
        &first_id,
        Some("alice"),
        "username_incarnation_changed",
    )
    .await;
    let (third, third_id, minted_under) = issue("issue-third").await;
    assert_eq!(minted_under, third_incarnation);

    // Switching from From email to Set by hand keeps everything: the
    // username, its incarnation and the keys.
    let manual = m
        .admin_ok(
            Method::PUT,
            alice_name,
            "mode-manual",
            Some(json!({"mode": "manual"})),
        )
        .await;
    assert_eq!(manual["mode"], "manual");
    assert_eq!(manual["name"]["accountUsername"], "alice");
    assert_eq!(manual["name"]["incarnation"], third_incarnation);
    assert_eq!(
        (
            &manual["accountUsernameChange"]["previousMode"],
            &manual["accountUsernameChange"]["mode"],
            &manual["accountUsernameChange"]["renamed"],
            &manual["accountUsernameChange"]["endedKeys"]
        ),
        (
            &json!("from_email"),
            &json!("manual"),
            &json!(false),
            &json!(0)
        )
    );
    assert_eq!(manual["liveKeys"], 1);
    let resolved = m.resolve("resolve-after-manual", &third).await;
    assert_eq!(resolved["active"], true);
    assert_eq!(resolved["usernameIncarnation"], third_incarnation);
    // Set by hand, the username no longer follows the email either.
    let change = patch("email-while-manual", "amy@example.com").await;
    assert_eq!(
        (&change["renamed"], &change["endedKeys"]),
        (&json!(false), &json!(0))
    );
    assert_eq!(
        m.resolve("resolve-after-manual-email", &third).await["active"],
        true
    );

    // Released, and taken by another account: a new incarnation again.
    let released = m
        .admin_ok(
            Method::PUT,
            alice_name,
            "release",
            Some(json!({"mode": "manual", "accountUsername": null})),
        )
        .await;
    assert_eq!(released["accountUsernameChange"]["endedKeys"], 1);
    m.create_principal(
        json!({"principalId": "usr-alice2", "kind": "user", "email": "alice@example.com"}),
    )
    .await;
    let taken = m
        .admin_ok(
            Method::GET,
            "/v1/admin/principals/usr-alice2/account-username",
            "taken-again",
            None,
        )
        .await;
    assert_eq!(taken["name"]["accountUsername"], "alice");
    for earlier in [&first_incarnation, &third_incarnation] {
        assert_ne!(&taken["name"]["incarnation"], earlier);
    }
    // Her key does not resolve as the new holder of her old username.
    inactive(
        "resolve-after-taken",
        &third,
        &third_id,
        None,
        "no_account_username",
    )
    .await;
}

/// The audit records of the fill of missing names.
fn fill_records(m: &Management) -> Vec<Value> {
    read_audit_records(&m.fixture.audit_path)
        .into_iter()
        .filter(|record| record["action"] == "account_usernames.assigned")
        .collect()
}

#[tokio::test]
async fn people_who_follow_their_email_are_named_after_a_reload_in_bounded_batches() {
    // No domain is listed yet: the accounts created now get no name, as
    // the accounts that exist when the feature is first configured.
    let (m, mut config) = reloadable(|config| config.usernames.email_domains.clear()).await;
    for (id, email) in [
        ("usr-a", json!("ann@example.com")),
        // A name on the operator's list, twice: the first holder keeps it.
        ("usr-b", json!("carol@example.com")),
        ("usr-c", json!("Carol@example.com")),
        ("usr-d", Value::Null),
        ("usr-e", json!("eve@contractor.example")),
        ("usr-f", Value::Null),
        ("usr-g", Value::Null),
    ] {
        m.create_principal(json!({"principalId": id, "kind": "user", "email": email}))
            .await;
    }
    let names = async |request_id: &str| {
        let list = m
            .admin_ok(Method::GET, "/v1/admin/account-usernames", request_id, None)
            .await;
        list["accountUsernames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["principalId"].as_str().unwrap().to_string(),
                    (
                        entry["name"]["accountUsername"]
                            .as_str()
                            .map(str::to_string),
                        entry["state"].as_str().unwrap().to_string(),
                        entry["reason"].as_str().map(str::to_string),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let expect = |name: Option<&str>, state: &str, reason: Option<&str>| {
        (
            name.map(str::to_string),
            state.to_string(),
            reason.map(str::to_string),
        )
    };
    let before = names("names-before").await;
    assert!(before.values().all(|(name, _, _)| name.is_none()));
    assert_eq!(
        before["usr-a"],
        expect(None, "none", Some("domain_not_listed"))
    );
    m.settled().await;
    assert!(fill_records(&m).is_empty());

    // The operator lists the domain and reloads. The fill walks everyone
    // who follows their email and holds no name, two accounts at a time.
    *m.fixture
        .state
        .account_username_fill_batch_size
        .lock()
        .unwrap() = Some(2);
    config.usernames.email_domains = vec!["example.com".to_string()];
    m.fixture._broker.reload_config(&config).await;
    m.settled().await;
    let after = names("names-after").await;
    assert_eq!(after["usr-a"], expect(Some("ann"), "usable", None));
    assert_eq!(
        after["usr-b"],
        expect(Some("carol"), "awaiting_confirmation", None)
    );
    assert_eq!(after["usr-c"], expect(None, "conflict", Some("name_taken")));
    assert_eq!(after["usr-d"], expect(None, "none", Some("no_email")));
    assert_eq!(
        after["usr-e"],
        expect(None, "none", Some("domain_not_listed"))
    );
    assert_eq!(after["alice"], expect(None, "none", Some("no_email")));
    // Every batch that named somebody is one record of the system's, with
    // the names it allocated; no batch looked at more than its two.
    let records = fill_records(&m);
    assert!(!records.is_empty());
    let mut assigned = Vec::new();
    for record in &records {
        assert_eq!(record["decision"], "allow");
        assert_eq!(record["principal"], "system");
        let details = &record["providerAudit"]["accountUsernames"];
        assert_eq!(details["trigger"], "reload");
        assert!(details["examined"].as_u64().unwrap() <= 2, "{details}");
        for entry in details["assigned"].as_array().unwrap() {
            assigned.push((
                entry["principal"].as_str().unwrap().to_string(),
                entry["derivedAccountUsername"]["accountUsername"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ));
        }
    }
    assert_eq!(
        assigned,
        [
            ("usr-a".to_string(), "ann".to_string()),
            ("usr-b".to_string(), "carol".to_string())
        ]
    );
    let view = m
        .admin_ok(
            Method::GET,
            "/v1/admin/principals/usr-a/account-username",
            "named-view",
            None,
        )
        .await;
    assert_eq!(view["name"]["origin"], "derived");
    assert_eq!(view["name"]["assignedBy"], "system:reload");

    // It only fills in what is missing: another reload examines the people
    // it could not name, names nobody and writes no record.
    config.usernames.reserved_names.push("operator".to_string());
    m.fixture._broker.reload_config(&config).await;
    m.settled().await;
    assert_eq!(fill_records(&m).len(), records.len());
    assert_eq!(names("names-again").await, after);

    // A failed fill is audited and stops nothing: the Broker serves, and
    // the next reload fills in.
    config
        .usernames
        .email_domains
        .push("contractor.example".to_string());
    *m.fixture
        .state
        .account_username_fill_batch_size
        .lock()
        .unwrap() = Some(0);
    m.fixture._broker.reload_config(&config).await;
    m.settled().await;
    let failed = fill_records(&m);
    assert_eq!(failed.len(), records.len() + 1);
    let failure = failed.last().unwrap();
    assert_eq!(failure["decision"], "error");
    assert_eq!(
        failure["providerAudit"]["accountUsernames"],
        json!({"trigger": "reload", "reason": "fill_failed"})
    );
    assert_eq!(
        names("names-failed").await["usr-e"],
        expect(None, "none", Some("not_yet_assigned"))
    );
    *m.fixture
        .state
        .account_username_fill_batch_size
        .lock()
        .unwrap() = Some(2);
    config.usernames.reserved_names.push("staff".to_string());
    m.fixture._broker.reload_config(&config).await;
    m.settled().await;
    assert_eq!(
        names("names-added-domain").await["usr-e"],
        expect(Some("eve"), "usable", None)
    );
    // Delisting the domain takes her name away from nobody.
    config.usernames.email_domains = vec!["example.com".to_string()];
    m.fixture._broker.reload_config(&config).await;
    m.settled().await;
    assert_eq!(
        names("names-delisted").await["usr-e"],
        expect(Some("eve"), "usable", None)
    );
    // Nor does asking again for the mode she already follows: neither her
    // email nor her mode changes, so her name, its incarnation and her
    // token stay.
    let eve = "/v1/admin/principals/usr-e/account-username";
    m.set_access("usr-e", &["inference"], &[], "eve-access")
        .await;
    let issued = m
        .admin_ok(
            Method::POST,
            "/v1/admin/principals/usr-e/access-keys",
            "eve-issue",
            issue_body("handed out", &["inference"], 3600),
        )
        .await;
    let token = issued["key"].as_str().unwrap().to_string();
    let before = m.admin_ok(Method::GET, eve, "eve-before", None).await;
    let same = m
        .admin_ok(
            Method::PUT,
            eve,
            "eve-same-mode",
            Some(json!({"mode": "from_email"})),
        )
        .await;
    assert_eq!(same["mode"], "from_email");
    assert_eq!(same["state"], "usable");
    assert_eq!(same["name"], before["name"]);
    assert_eq!(same["accountUsernameChange"]["endedKeys"], 0);
    assert_eq!(same["accountUsernameChange"]["renamed"], false);
    // Her saved email no longer gives a name, and the view says so beside
    // the name she keeps.
    assert_eq!(
        same["fromEmail"],
        json!({"accountUsername": null, "reason": "domain_not_listed", "conflict": null})
    );
    assert_eq!(same["liveKeys"], 1);
    let target = m.completion("admin.principals.account_username.set", "eve-same-mode");
    assert_eq!(target["before"], target["after"]);
    assert_eq!(target["before"]["accountUsername"], "eve");
    assert_eq!(
        (&target["previousMode"], &target["mode"]),
        (&json!("from_email"), &json!("from_email"))
    );
    let resolved = m.resolve("eve-resolve", &token).await;
    assert_eq!(resolved["active"], true);
    assert_eq!(resolved["subject"], json!({"kind": "user", "id": "eve"}));
}

#[tokio::test]
async fn the_fill_goes_on_when_an_imported_service_change_publishes_between_its_batches() {
    use agent_access_core::ImportedServiceStatus;
    const PEOPLE: [&str; 4] = ["admin", "alice", "bob", "charlie"];

    // A Broker with an imported service. Its people have an email of a
    // domain that is not listed yet, so they hold no name.
    let fixture = super::imports_foundation::fixture();
    {
        let store = fixture.runtime.managed_store().unwrap();
        for principal in &PEOPLE {
            store
                .patch_principal(agent_access_core::PrincipalPatchRequest {
                    principal_id: principal.to_string(),
                    display_name: None,
                    email: Some(Some(format!("{principal}@example.com"))),
                    status: None,
                })
                .unwrap();
        }
    }
    let broker = super::imports_foundation::import_broker(&fixture.config).await;
    let state = broker.state();
    let names = || {
        let store = state.current().runtime.managed_store().unwrap().clone();
        PEOPLE.map(|principal| {
            store
                .principal_account_username(principal)
                .unwrap()
                .name
                .map(|name| name.account_username)
        })
    };
    assert_eq!(names(), [None, None, None, None]);

    // The operator lists the domain and reloads. The fill takes one account
    // at a time and is held before its second batch.
    *state.account_username_fill_batch_size.lock().unwrap() = Some(1);
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *state.account_username_fill_barrier.lock().unwrap() = Some(barrier.clone());
    let mut config = fixture.config.clone();
    config.usernames.email_domains = vec!["example.com".to_string()];
    broker.reload_config(&config).await;
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .expect("the fill reaches its second batch");
    let reloaded = state.current();
    assert_eq!(names(), [Some("admin".to_string()), None, None, None]);
    let first = reloaded
        .runtime
        .managed_store()
        .unwrap()
        .principal_account_username("admin")
        .unwrap()
        .name
        .unwrap();

    // Between two batches an administrator disables the imported service.
    // Its catalog is published in another snapshot of the same
    // configuration generation, and nothing starts a fill for that.
    let request = super::imports_foundation::update(
        reloaded.runtime.imported_catalog(),
        ImportedServiceStatus::Disabled,
    );
    state
        .imported_service_mutation(reloaded.clone(), move |runtime| {
            let mut candidate = runtime
                .imported_catalog()
                .service("observability")
                .unwrap()
                .clone();
            candidate.status = request.status;
            let prepared = runtime.prepare_imported_service_change(&candidate, None)?;
            let result = runtime
                .managed_store()
                .unwrap()
                .update_imported_service(request, |catalog| {
                    runtime.with_imported_catalog(catalog.clone(), prepared)
                })?;
            Ok((result.value, ()))
        })
        .await
        .unwrap();
    let published = state.current();
    assert!(!Arc::ptr_eq(&published, &reloaded));
    assert_eq!(published.generation, reloaded.generation);
    assert_eq!(
        published.runtime.imported_catalog().services[0].status,
        ImportedServiceStatus::Disabled
    );

    // The fill goes on under the snapshot now in force and names everyone
    // it had not reached, each batch in a record of its own.
    barrier.release();
    assert_eq!(
        state
            .application_owners
            .drain(Duration::from_secs(10))
            .await,
        0
    );
    assert_eq!(
        names(),
        [
            Some("admin".to_string()),
            Some("alice".to_string()),
            Some("bob".to_string()),
            Some("charlie".to_string())
        ]
    );
    assert_eq!(
        state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .principal_account_username("admin")
            .unwrap()
            .name
            .unwrap(),
        first
    );
    let audit_path = PathBuf::from(&fixture.config.audit.as_ref().unwrap().path);
    let records = read_audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["action"] == "account_usernames.assigned")
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 4, "{records:?}");
    for (record, principal) in records.iter().zip(&PEOPLE) {
        assert_eq!(record["decision"], "allow");
        assert_eq!(record["configGeneration"], json!(reloaded.generation));
        let details = &record["providerAudit"]["accountUsernames"];
        assert_eq!(details["trigger"], "reload");
        assert_eq!(details["assigned"].as_array().unwrap().len(), 1);
        assert_eq!(details["assigned"][0]["principal"], json!(principal));
    }
}

#[tokio::test]
async fn the_mode_of_a_name_is_read_from_a_string_only() {
    let m = management().await;
    let name = "/v1/admin/principals/alice/account-username";
    m.set_name("alice", "alice", "mode-name").await;
    let before = m.admin_ok(Method::GET, name, "mode-before", None).await;
    assert_eq!(before["mode"], "manual");
    assert_eq!(before["name"]["accountUsername"], "alice");

    // A mode is one of two strings. An object whose one key is a mode, the
    // other form in which a derived enum is read, is not a mode, whatever
    // comes with it; nor is anything else.
    for body in [
        json!({"mode": {"manual": null}, "accountUsername": null}),
        json!({"mode": {"manual": null}, "accountUsername": "carol"}),
        json!({"mode": {"manual": null}}),
        json!({"mode": {"from_email": null}}),
        json!({"mode": {"manual": {}}}),
        json!({"mode": ["manual"]}),
        json!({"mode": "automatic"}),
        json!({"mode": "Manual"}),
        json!({"mode": null}),
        json!({"mode": 1}),
        json!({"accountUsername": null}),
    ] {
        let (status, envelope) = m
            .admin(Method::PUT, name, "mode-refused", Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {envelope}");
        assert_eq!(envelope["reasonCode"], "input_invalid", "{body}");
    }
    // Nothing was read as a change: the name, its incarnation and the mode
    // are as they were.
    let after = m.admin_ok(Method::GET, name, "mode-after", None).await;
    assert_eq!(after, before);

    // The strings are read.
    let followed = m
        .admin_ok(
            Method::PUT,
            name,
            "mode-from-email",
            Some(json!({"mode": "from_email"})),
        )
        .await;
    assert_eq!(followed["mode"], "from_email");
    let manual = m
        .admin_ok(
            Method::PUT,
            name,
            "mode-manual",
            Some(json!({"mode": "manual", "accountUsername": null})),
        )
        .await;
    assert_eq!(manual["mode"], "manual");
    assert!(manual["name"].is_null());
}

#[tokio::test]
async fn an_administrator_confirms_that_an_account_is_the_person_a_listed_name_belongs_to() {
    let m = management().await;
    // `carol` is on the operator's list: derived, it awaits confirmation.
    m.create_principal(
        json!({"principalId": "usr-b", "kind": "user", "email": "carol@example.com"}),
    )
    .await;
    m.create_principal(json!({"principalId": "usr-a", "kind": "user", "email": "ann@example.com"}))
        .await;
    m.create_principal(json!({"principalId": "usr-d", "kind": "user"}))
        .await;
    let confirm =
        |principal: &str| format!("/v1/admin/principals/{principal}/account-username/confirm");
    let view = m
        .admin_ok(
            Method::GET,
            "/v1/admin/principals/usr-b/account-username",
            "awaiting",
            None,
        )
        .await;
    assert_eq!(view["state"], "awaiting_confirmation");
    let incarnation = view["name"]["incarnation"].clone();

    for (request_id, principal, name, status, expected) in [
        (
            "confirm-wrong-name",
            "usr-b",
            "caroline",
            StatusCode::CONFLICT,
            ("broker_account_username_conflict", "name_changed"),
        ),
        (
            "confirm-not-listed",
            "usr-a",
            "ann",
            StatusCode::FORBIDDEN,
            (
                "broker_account_username_denied",
                "confirmation_not_required",
            ),
        ),
        (
            "confirm-no-name",
            "usr-d",
            "carol",
            StatusCode::NOT_FOUND,
            ("broker_account_username_not_found", "no_name"),
        ),
    ] {
        let (code, envelope) = m
            .admin(
                Method::POST,
                &confirm(principal),
                request_id,
                Some(json!({ "accountUsername": name })),
            )
            .await;
        assert_eq!(code, status, "{request_id}: {envelope}");
        assert_eq!(refusal(&envelope), expected, "{request_id}");
    }
    for (request_id, body) in [
        ("confirm-empty", json!({})),
        (
            "confirm-extra",
            json!({"accountUsername": "carol", "force": true}),
        ),
        (
            "confirm-list",
            json!({"confirmations": [{"principalId": "usr-b", "accountUsername": "carol"}]}),
        ),
    ] {
        let (status, envelope) = m
            .admin(Method::POST, &confirm("usr-b"), request_id, Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{request_id}: {envelope}");
        assert_eq!(envelope["reasonCode"], "input_invalid");
    }
    assert_eq!(
        m.store
            .principal_account_username("usr-b")
            .unwrap()
            .name
            .unwrap()
            .state,
        agent_access_core::AccountUsernameState::AwaitingConfirmation
    );

    let confirmed = m
        .admin_ok(
            Method::POST,
            &confirm("usr-b"),
            "confirm",
            Some(json!({"accountUsername": "carol"})),
        )
        .await;
    assert_eq!(confirmed["state"], "usable");
    assert_eq!(confirmed["name"]["confirmedBy"], "admin");
    // Confirming keeps the incarnation: it is the same allocation.
    assert_eq!(confirmed["name"]["incarnation"], incarnation);
    let completion = m.completion("admin.principals.account_username.confirm", "confirm");
    assert_eq!(completion["principal"], "usr-b");
    assert_eq!(completion["before"]["state"], "awaiting_confirmation");
    assert_eq!(completion["after"]["state"], "usable");
    // Only an administrator confirms.
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::POST,
            &confirm("usr-b"),
            "confirm-auditor",
            Some(json!({"accountUsername": "carol"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
}

fn issue_body(name: &str, access_key_types: &[&str], lifetime_seconds: u64) -> Option<Value> {
    Some(
        json!({"name": name, "accessKeyTypes": access_key_types, "lifetime": format!("{lifetime_seconds}s")}),
    )
}

#[tokio::test]
async fn a_person_lists_creates_and_revokes_their_own_access_keys_from_a_browser_session() {
    let m = management().await;
    let tokens = "/v1/access-keys";
    let options = "/v1/access-keys/options";

    // Alice holds no username: she is told so, with the reason, before
    // and when she asks.
    let before = m
        .alice_ok(Method::GET, options, "options-unnamed", None)
        .await;
    assert_eq!(
        before["accountUsername"],
        json!({"name": null, "state": "none", "mode": "from_email", "reason": "no_email",
            "fromEmail": {"accountUsername": null, "reason": "no_email"}})
    );
    assert_eq!(before["refusal"], "no_account_username");
    let (status, envelope) = m
        .alice(
            Method::POST,
            tokens,
            "issue-unnamed",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        ("broker_access_key_denied", "no_account_username")
    );
    assert_eq!(
        envelope["error"]["message"],
        "the account has no username; an administrator can set one"
    );
    assert_eq!(
        m.denial("access_keys.issue", "issue-unnamed")["details"]["refusal"],
        "no_account_username"
    );

    // A listed name is not hers to use until an administrator confirms it.
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name-listed",
        Some(json!({"mode": "manual", "accountUsername": "carol"})),
    )
    .await;
    let awaiting = m
        .alice_ok(Method::GET, options, "options-awaiting", None)
        .await;
    assert_eq!(
        awaiting["accountUsername"],
        json!({"name": "carol", "state": "awaiting_confirmation", "mode": "manual", "reason": null,
            "fromEmail": {"accountUsername": null, "reason": "no_email"}})
    );
    assert_eq!(
        awaiting["refusal"],
        "account_username_awaiting_confirmation"
    );
    let (status, envelope) = m
        .alice(
            Method::POST,
            tokens,
            "issue-awaiting",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        (
            "broker_access_key_denied",
            "account_username_awaiting_confirmation"
        )
    );
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name",
        Some(json!({"mode": "manual", "accountUsername": "alice"})),
    )
    .await;

    // Her choices: the types she may hold, each saying whether she may
    // create a token of it herself. `research` is not hers to hold.
    let ready = m.alice_ok(Method::GET, options, "options", None).await;
    assert_eq!(
        ready["accountUsername"],
        json!({"name": "alice", "state": "usable", "mode": "manual", "reason": null,
            "fromEmail": {"accountUsername": null, "reason": "no_email"}})
    );
    assert!(ready["refusal"].is_null());
    assert_eq!(
        ready["accessKeyTypes"],
        json!([
            {"id": "batch", "displayName": "Batch jobs", "description": null,
                "lifetimeOptions": ["60s", "600s", "1h", "7d"], "defaultLifetime": "7d", "selfService": false},
            {"id": "inference", "displayName": "Model inference", "description": INFERENCE_DESCRIPTION,
                "lifetimeOptions": ["60s", "600s", "1h", "30d"], "defaultLifetime": "30d", "selfService": true},
        ])
    );

    // Each refusal of a request says why; nothing is trimmed to fit. A type
    // that is not configured is refused in the words of one she may not
    // hold.
    let mut not_eligible = Vec::new();
    for (request_id, body, expected, detail) in [
        (
            "issue-unknown",
            issue_body("laptop", &["inference", "telemetry"], 3600),
            "access_key_type_not_eligible",
            json!({"accessKeyType": "telemetry"}),
        ),
        (
            "issue-admin-only",
            issue_body("laptop", &["batch"], 3600),
            "access_key_type_not_self_service",
            json!({"accessKeyType": "batch"}),
        ),
        (
            "issue-not-eligible",
            issue_body("laptop", &["inference", "research"], 3600),
            "access_key_type_not_eligible",
            json!({"accessKeyType": "research"}),
        ),
        (
            "issue-too-long",
            issue_body("laptop", &["inference"], 31 * 24 * 3600),
            "lifetime_not_offered",
            json!({"accessKeyType": "inference"}),
        ),
    ] {
        let (status, envelope) = m.alice(Method::POST, tokens, request_id, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{request_id}: {envelope}");
        assert_eq!(refusal(&envelope), ("broker_access_key_denied", expected));
        for (member, value) in detail.as_object().unwrap() {
            assert_eq!(&envelope["details"][member], value, "{request_id}");
        }
        if expected == "access_key_type_not_eligible" {
            not_eligible.push((
                envelope["error"]["message"].clone(),
                envelope["details"]["refusal"].clone(),
                envelope["details"].as_object().unwrap().len(),
            ));
        }
    }
    assert_eq!(not_eligible.len(), 2);
    assert_eq!(not_eligible[0], not_eligible[1]);
    for (request_id, body) in [
        (
            "issue-no-lifetime",
            json!({"name": "laptop", "accessKeyTypes": ["inference"]}),
        ),
        (
            "issue-zero",
            json!({"name": "laptop", "accessKeyTypes": ["inference"], "lifetime": 0}),
        ),
        (
            "issue-no-type",
            json!({"name": "laptop", "accessKeyTypes": [], "lifetime": "60s"}),
        ),
        (
            "issue-blank-name",
            json!({"name": " ", "accessKeyTypes": ["inference"], "lifetime": "60s"}),
        ),
        (
            "issue-extra",
            json!({"name": "laptop", "accessKeyTypes": ["inference"], "lifetime": "60s", "principal": "bob"}),
        ),
    ] {
        let (status, envelope) = m.alice(Method::POST, tokens, request_id, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{request_id}: {envelope}");
        assert_eq!(envelope["reasonCode"], "input_invalid", "{request_id}");
        // What the person reads speaks of an access key, the word the
        // page uses, never of a token.
        let message = envelope["error"]["message"].as_str().unwrap();
        assert!(
            !message.to_lowercase().contains("token"),
            "{request_id}: {message}"
        );
    }
    assert_eq!(
        m.alice_ok(Method::GET, tokens, "list-empty", None).await["keys"],
        json!([])
    );

    // The request-forgery header is required for a write, and only a
    // browser session may use these routes: her own bearer token may not.
    let (status, envelope) = m
        .send(
            As::Browser { csrf: false },
            Method::POST,
            tokens,
            "issue-no-csrf",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(envelope["reasonCode"], "csrf_invalid");
    let manage = m.fixture.management_token.clone();
    for (request_id, method, uri, body) in [
        ("bearer-list", Method::GET, tokens, None),
        ("bearer-options", Method::GET, options, None),
        (
            "bearer-issue",
            Method::POST,
            tokens,
            issue_body("laptop", &["inference"], 3600),
        ),
        (
            "bearer-revoke",
            Method::DELETE,
            "/v1/access-keys/ak_0",
            None,
        ),
    ] {
        let (status, envelope) = m
            .send(As::Token(&manage), method, uri, request_id, body)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{request_id}: {envelope}");
        assert_eq!(
            refusal(&envelope),
            ("broker_access_key_denied", "session_required"),
            "{request_id}"
        );
    }
    let (status, envelope) = m
        .send(
            As::Token(&m.fixture.agent_tokens[0]),
            Method::GET,
            tokens,
            "agent-token-list",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(envelope["reasonCode"], "broker_token_class_denied");
    assert!(
        m.store
            .portal_access_key_options(
                m.fixture.state.current().runtime.access_key_types(),
                "alice"
            )
            .is_ok()
    );

    // She creates a token: the secret is in the response once and nowhere
    // else.
    let issued = m
        .alice_ok(
            Method::POST,
            tokens,
            "issue",
            issue_body("laptop models", &["inference"], 3600),
        )
        .await;
    let token = issued["key"].as_str().unwrap().to_string();
    assert!(agent_access_core::is_access_key(&token));
    let record = &issued["record"];
    let key_id = record["keyId"].as_str().unwrap().to_string();
    assert_eq!(record["principalId"], "alice");
    assert_eq!(record["origin"], "portal");
    assert_eq!(record["name"], "laptop models");
    assert_eq!(record["accessKeyTypes"], json!(["inference"]));
    assert_eq!(record["createdBy"], "alice");
    let records = m.records("access_keys.issue", "issue");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    let target = &records[0]["providerAudit"]["management"]["target"];
    assert_eq!(target["keyId"], json!(key_id));
    assert_eq!(target["principal"], "alice");
    assert_eq!(target["origin"], "portal");
    assert_eq!(target["accessKeyTypes"], json!(["inference"]));
    assert_eq!(target["name"], "laptop models");
    assert_eq!(target["expiresAt"], record["expiresAt"]);
    assert!(!read_audit_text(&m.fixture.audit_path).contains(&token));

    // It resolves at the resolution route as her, and the Broker itself does
    // not accept it.
    let resolved = m.resolve("resolve-own", &token).await;
    assert_eq!(resolved["active"], true);
    assert_eq!(resolved["subject"], json!({"kind": "user", "id": "alice"}));
    assert_eq!(resolved["origin"], "portal");
    assert_eq!(resolved["keyId"], json!(key_id));
    let (status, envelope) = m
        .send(
            As::Token(&token),
            Method::GET,
            tokens,
            "access-key-as-credential",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{envelope}");

    // Her list shows it with what it resolves as now.
    let listed = m.alice_ok(Method::GET, tokens, "list", None).await;
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    let view = &listed["keys"][0];
    assert_eq!(view["keyId"], json!(key_id));
    assert_eq!(view["status"], "active");
    assert_eq!(
        view["usableAccessKeyTypes"],
        json!([{"name": "inference", "validUntil": view["expiresAt"]}])
    );
    assert!(view["lastUsedAt"].is_string());
    assert!(view.get("key").is_none());
    // The routes do not depend on self-service for the account.
    let (status, envelope) = m
        .admin(
            Method::PATCH,
            "/v1/admin/principals/alice/access",
            "self-service-off",
            Some(json!({"selfServiceEnabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{envelope}");
    let second = m
        .alice_ok(
            Method::POST,
            tokens,
            "issue-second",
            issue_body("notebook", &["inference"], 60),
        )
        .await;
    let second_id = second["record"]["keyId"].as_str().unwrap().to_string();

    // Another person's token, and an unknown one, are not hers to revoke.
    m.create_principal(json!({"principalId": "robot", "kind": "service_account"}))
        .await;
    m.set_access("robot", &["inference"], &[], "robot-access")
        .await;
    let robot = m
        .store
        .mint_administrator_access_key(
            m.fixture
                .state
                .current()
                .runtime
                .broker_token_hasher()
                .unwrap(),
            m.fixture.state.current().runtime.access_key_types(),
            &agent_access_core::AdministratorAccessKeyRequest {
                principal_id: "robot".to_string(),
                name: "nightly".to_string(),
                access_key_types: vec!["inference".to_string()],
                lifetime: "600s".into(),
                created_by: "admin".to_string(),
            },
        )
        .unwrap()
        .unwrap();
    for (request_id, id) in [
        ("revoke-other", robot.record.key_id.as_str()),
        ("revoke-unknown", "ak_00000000000000000000000000000000"),
        ("revoke-malformed", "not-a-token-id"),
    ] {
        let (status, envelope) = m
            .alice(Method::DELETE, &format!("{tokens}/{id}"), request_id, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{request_id}: {envelope}");
        assert_eq!(envelope["reasonCode"], "broker_access_key_not_found");
    }
    assert_eq!(m.resolve("resolve-robot", &robot.key).await["active"], true);

    // Revocation is final and audited; the token no longer resolves.
    let revoked = m
        .alice_ok(
            Method::DELETE,
            &format!("{tokens}/{key_id}"),
            "revoke",
            None,
        )
        .await;
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["newlyRevoked"], true);
    assert_eq!(revoked["record"]["revokedBy"], "alice");
    let completion = m.completion("access_keys.revoke", "revoke");
    assert_eq!(completion["keyId"], json!(key_id));
    assert_eq!(completion["principal"], "alice");
    assert_eq!(completion["newlyRevoked"], true);
    let again = m
        .alice_ok(
            Method::DELETE,
            &format!("{tokens}/{key_id}"),
            "revoke-again",
            None,
        )
        .await;
    assert_eq!(again["newlyRevoked"], false);
    assert_eq!(again["record"], revoked["record"]);
    assert_eq!(
        m.resolve("resolve-revoked", &token).await,
        json!({
            "active": false,
            "keyId": key_id,
            "owner": {"kind": "user", "id": "alice"},
            "reason": "revoked"
        })
    );
    let listed = m.alice_ok(Method::GET, tokens, "list-after", None).await;
    assert_eq!(
        listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|view| view["keyId"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [second_id.as_str()]
    );
    let all = m
        .alice_ok(
            Method::GET,
            &format!("{tokens}?includeRevoked=true"),
            "list-revoked",
            None,
        )
        .await;
    let statuses = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|view| {
            (
                view["keyId"].as_str().unwrap(),
                view["status"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        statuses,
        BTreeMap::from([(second_id.as_str(), "active"), (key_id.as_str(), "revoked")])
    );
    let (status, envelope) = m
        .alice(
            Method::GET,
            &format!("{tokens}?principal=robot"),
            "list-other",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}");

    // What she may hold follows her access at once. Joining a group that
    // allows a type gives it to her.
    let held = |options: Value| {
        options["accessKeyTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|access_key_type| access_key_type["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let statuses = |listed: Value| {
        listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|view| {
                (
                    view["name"].as_str().unwrap().to_string(),
                    view["status"].as_str().unwrap().to_string(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let both = |notebook: &str, data: &str| {
        BTreeMap::from([
            ("notebook".to_string(), notebook.to_string()),
            ("research data".to_string(), data.to_string()),
        ])
    };
    m.store.add_group("alice", "research", "admin").unwrap();
    assert_eq!(
        held(
            m.alice_ok(Method::GET, options, "options-member", None)
                .await
        ),
        ["batch", "inference", "research"]
    );
    let research = m
        .alice_ok(
            Method::POST,
            tokens,
            "issue-research",
            issue_body("research data", &["research"], 600),
        )
        .await;
    let research_token = research["key"].as_str().unwrap().to_string();
    assert_eq!(
        m.resolve("resolve-research", &research_token).await["active"],
        true
    );
    // An administrator withdraws both types: her account denies one and no
    // longer allows the other. The tokens stay hers and stop working.
    m.set_access("alice", &["batch"], &["research"], "access-withdrawn")
        .await;
    assert_eq!(
        held(
            m.alice_ok(Method::GET, options, "options-withdrawn", None)
                .await
        ),
        ["batch"]
    );
    assert_eq!(
        statuses(
            m.alice_ok(Method::GET, tokens, "list-withdrawn", None)
                .await
        ),
        both("no_access_key_type", "no_access_key_type")
    );
    assert_eq!(
        m.resolve("resolve-withdrawn", &research_token).await,
        json!({
            "active": false,
            "keyId": research["record"]["keyId"],
            "owner": {"kind": "user", "id": "alice"},
            "reason": "no_access_key_type"
        })
    );
    let (status, envelope) = m
        .alice(
            Method::POST,
            tokens,
            "issue-withdrawn",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        ("broker_access_key_denied", "access_key_type_not_eligible")
    );
    // Restored access resumes the same tokens.
    m.set_access("alice", &["batch", "inference"], &[], "access-restored")
        .await;
    assert_eq!(
        statuses(m.alice_ok(Method::GET, tokens, "list-restored", None).await),
        both("active", "active")
    );
    assert_eq!(
        m.resolve("resolve-restored", &research_token).await["active"],
        true
    );

    // A changed name ends her tokens without revoking them, and the list
    // says why they no longer work.
    let renamed = m
        .admin_ok(
            Method::PUT,
            "/v1/admin/principals/alice/account-username",
            "alice-rename",
            Some(json!({"mode": "manual", "accountUsername": "alice.r"})),
        )
        .await;
    assert_eq!(renamed["accountUsernameChange"]["endedKeys"], 2);
    assert_eq!(renamed["accountUsernameChange"]["renamed"], true);
    assert_eq!(
        renamed["accountUsernameChange"]["before"]["accountUsername"],
        "alice"
    );
    assert_eq!(
        renamed["accountUsernameChange"]["after"]["accountUsername"],
        "alice.r"
    );
    // The keys that ended are the ones the view counted as live before,
    // and the new name starts with none.
    assert_eq!(renamed["liveKeys"], 0);
    assert_eq!(
        m.completion("admin.principals.account_username.set", "alice-rename")["endedKeys"],
        2
    );
    let listed = m.alice_ok(Method::GET, tokens, "list-renamed", None).await;
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{listed}");
    for key in keys {
        assert_eq!(key["status"], "username_incarnation_changed", "{key}");
        assert_eq!(key["usableAccessKeyTypes"], json!([]), "{key}");
        assert_eq!(key["access"], "none", "{key}");
        // Nothing was taken from the keys' types: the name is what changed.
        assert!(
            key["accessKeyTypeStates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|state| state["held"] == true),
            "{key}"
        );
    }
}

#[tokio::test]
async fn an_administrator_issues_for_service_accounts_and_lists_and_revokes_any_token() {
    let m = management().await;
    m.create_principal(json!({"principalId": "robot", "kind": "service_account"}))
        .await;
    // Neither a person nor a service account: it owns no access key.
    m.create_principal(json!({"principalId": "sys", "kind": "system"}))
        .await;
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name",
        Some(json!({"mode": "manual", "accountUsername": "alice"})),
    )
    .await;

    // The configured types and whether people may create them, for
    // administrators and auditors.
    let types = m
        .admin_ok(Method::GET, "/v1/admin/access-key-types", "types", None)
        .await;
    assert_eq!(
        types["accessKeyTypes"],
        json!([
            {"id": "batch", "displayName": "Batch jobs", "description": null,
                "lifetimeOptions": ["60s", "600s", "1h", "7d"], "defaultLifetime": "7d", "selfService": false},
            {"id": "inference", "displayName": "Model inference", "description": INFERENCE_DESCRIPTION,
                "lifetimeOptions": ["60s", "600s", "1h", "30d"], "defaultLifetime": "30d", "selfService": true},
            {"id": "research", "displayName": "Research data", "description": null,
                "lifetimeOptions": ["60s", "600s", "1h", "7d"], "defaultLifetime": "7d", "selfService": true},
        ])
    );
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::GET,
            "/v1/admin/access-key-types",
            "types-auditor",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{envelope}");
    assert_eq!(envelope["result"], types);
    let (status, envelope) = m
        .send(
            As::Token(&m.fixture.management_token),
            Method::GET,
            "/v1/admin/access-key-types",
            "types-user",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");

    // An administrator issues only what the service account's own access
    // allows: a configured type is not enough.
    let robot_tokens = "/v1/admin/principals/robot/access-keys";
    let (status, envelope) = m
        .admin(
            Method::POST,
            robot_tokens,
            "admin-issue-no-access",
            issue_body("nightly", &["batch"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        ("broker_access_key_denied", "access_key_type_not_eligible")
    );
    assert_eq!(envelope["details"]["accessKeyType"], "batch");
    m.set_access("robot", &["batch", "inference"], &[], "robot-access")
        .await;

    // A token for a service account, of a type people cannot create.
    let issued = m
        .admin_ok(
            Method::POST,
            robot_tokens,
            "admin-issue",
            issue_body("nightly", &["batch", "inference"], 3600),
        )
        .await;
    let token = issued["key"].as_str().unwrap().to_string();
    let key_id = issued["record"]["keyId"].as_str().unwrap().to_string();
    assert_eq!(issued["record"]["origin"], "administrator");
    assert_eq!(issued["record"]["principalId"], "robot");
    assert_eq!(issued["record"]["createdBy"], "admin");
    let records = m.records("admin.principals.access_keys.issue", "admin-issue");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["principal"], "admin");
    let target = &records[0]["providerAudit"]["management"]["target"];
    assert_eq!(target["principal"], "robot");
    assert_eq!(target["keyId"], json!(key_id));
    assert_eq!(target["accessKeyTypes"], json!(["batch", "inference"]));
    assert!(!read_audit_text(&m.fixture.audit_path).contains(&token));
    let resolved = m.resolve("resolve-robot", &token).await;
    assert_eq!(
        resolved["subject"],
        json!({"kind": "service_account", "id": "robot"})
    );
    assert_eq!(resolved["origin"], "administrator");
    assert_eq!(
        resolved["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|access_key_type| access_key_type["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["batch", "inference"]
    );

    for (request_id, uri, body, status, expected) in [
        (
            "admin-issue-system",
            "/v1/admin/principals/sys/access-keys",
            issue_body("laptop", &["inference"], 3600),
            StatusCode::FORBIDDEN,
            ("broker_access_key_denied", "owner_kind"),
        ),
        (
            "admin-issue-not-eligible",
            robot_tokens,
            issue_body("nightly", &["research"], 3600),
            StatusCode::FORBIDDEN,
            ("broker_access_key_denied", "access_key_type_not_eligible"),
        ),
        (
            "admin-issue-too-long",
            robot_tokens,
            issue_body("nightly", &["batch", "inference"], 8 * 24 * 3600),
            StatusCode::FORBIDDEN,
            ("broker_access_key_denied", "lifetime_not_offered"),
        ),
        (
            "admin-issue-missing",
            "/v1/admin/principals/missing/access-keys",
            issue_body("nightly", &["inference"], 3600),
            StatusCode::NOT_FOUND,
            ("principal_not_found", ""),
        ),
        (
            "admin-issue-body",
            robot_tokens,
            Some(json!({"name": "nightly"})),
            StatusCode::BAD_REQUEST,
            ("input_invalid", ""),
        ),
    ] {
        let (code, envelope) = m.admin(Method::POST, uri, request_id, body).await;
        assert_eq!(code, status, "{request_id}: {envelope}");
        assert_eq!(refusal(&envelope), expected, "{request_id}");
        assert!(envelope["result"].is_null());
    }
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::POST,
            robot_tokens,
            "auditor-issue",
            issue_body("nightly", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(envelope["reasonCode"], "management_denied");

    // A person's token, to list and revoke as an administrator.
    let own = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "alice-issue",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    let own_id = own["record"]["keyId"].as_str().unwrap().to_string();
    let all = "/v1/admin/access-keys";
    let ids = |listed: &Value| {
        listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|view| view["keyId"].as_str().unwrap().to_string())
            .collect::<BTreeSet<_>>()
    };
    let listed = m.admin_ok(Method::GET, all, "admin-list", None).await;
    assert_eq!(
        ids(&listed),
        BTreeSet::from([key_id.clone(), own_id.clone()])
    );
    assert!(
        listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|view| view["status"] == "active")
    );
    let listed = m
        .admin_ok(
            Method::GET,
            &format!("{all}?principal=robot"),
            "admin-list-robot",
            None,
        )
        .await;
    assert_eq!(ids(&listed), BTreeSet::from([key_id.clone()]));
    let (status, envelope) = m
        .send(As::Auditor, Method::GET, all, "auditor-list", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{envelope}");
    for (request_id, query, status, reason) in [
        (
            "admin-list-unknown",
            "?principal=missing",
            StatusCode::NOT_FOUND,
            "principal_not_found",
        ),
        (
            "admin-list-query",
            "?owner=robot",
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
        (
            "admin-list-flag",
            "?includeRevoked=yes",
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
        (
            "admin-list-twice",
            "?includeRevoked=true&includeRevoked=true",
            StatusCode::BAD_REQUEST,
            "input_invalid",
        ),
    ] {
        let (code, envelope) = m
            .admin(Method::GET, &format!("{all}{query}"), request_id, None)
            .await;
        assert_eq!(code, status, "{request_id}: {envelope}");
        assert_eq!(envelope["reasonCode"], reason, "{request_id}");
    }

    // An administrator revokes any token; an auditor none.
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::DELETE,
            &format!("{all}/{own_id}"),
            "auditor-revoke",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    let revoked = m
        .admin_ok(
            Method::DELETE,
            &format!("{all}/{own_id}"),
            "admin-revoke",
            None,
        )
        .await;
    assert_eq!(revoked["newlyRevoked"], true);
    assert_eq!(revoked["record"]["revokedBy"], "admin");
    let completion = m.completion("admin.access_keys.revoke", "admin-revoke");
    assert_eq!(completion["keyId"], json!(own_id));
    assert_eq!(completion["principal"], "alice");
    assert_eq!(
        m.resolve("resolve-revoked", own["key"].as_str().unwrap())
            .await,
        json!({
            "active": false,
            "keyId": own_id,
            "owner": {"kind": "user", "id": "alice"},
            "reason": "revoked"
        })
    );
    let (status, envelope) = m
        .admin(
            Method::DELETE,
            &format!("{all}/ak_00000000000000000000000000000000"),
            "admin-revoke-unknown",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{envelope}");
    assert_eq!(envelope["reasonCode"], "broker_access_key_not_found");
    let listed = m
        .admin_ok(
            Method::GET,
            &format!("{all}?includeRevoked=true&includeExpired=true"),
            "admin-list-all",
            None,
        )
        .await;
    assert_eq!(
        listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|view| view["keyId"] == json!(own_id))
            .unwrap()["status"],
        "revoked"
    );
}

#[tokio::test]
async fn no_route_reads_a_positional_array_as_its_body() {
    let m = management().await;
    m.create_principal(json!({"principalId": "robot", "kind": "service_account"}))
        .await;
    m.set_access("robot", &["inference"], &[], "positional-robot-access")
        .await;
    let name = "/v1/admin/principals/alice/account-username";
    let confirm = "/v1/admin/principals/alice/account-username/confirm";
    // Alice holds a listed name that awaits confirmation.
    m.admin_ok(
        Method::PUT,
        name,
        "positional-name",
        Some(json!({"mode": "manual", "accountUsername": "carol"})),
    )
    .await;
    let refused = async |who: As<'static>, method: Method, uri: &str, body: Value| {
        let request_id = "positional-refused";
        let (status, envelope) = m
            .send(who, method.clone(), uri, request_id, Some(body.clone()))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{method} {uri} {body}: {envelope}"
        );
        assert_eq!(
            envelope["reasonCode"], "input_invalid",
            "{method} {uri} {body}"
        );
    };
    let browser = As::Browser { csrf: true };

    // Each body as its members in order.
    refused(As::Admin, Method::PUT, name, json!(["manual", "alice"])).await;
    refused(As::Admin, Method::PUT, name, json!(["manual"])).await;
    refused(As::Admin, Method::PUT, name, json!(["from_email"])).await;
    refused(As::Admin, Method::POST, confirm, json!(["carol"])).await;
    refused(As::Admin, Method::POST, confirm, json!([["carol"]])).await;
    let view = m
        .admin_ok(Method::GET, name, "positional-name-after", None)
        .await;
    assert_eq!(view["name"]["accountUsername"], "carol");
    assert_eq!(view["name"]["state"], "awaiting_confirmation");
    assert_eq!(view["mode"], "manual");

    // The same member in an object confirms her.
    let confirmed = m
        .admin_ok(
            Method::POST,
            confirm,
            "positional-confirm",
            Some(json!({"accountUsername": "carol"})),
        )
        .await;
    assert_eq!(confirmed["name"]["state"], "usable");

    // A mint, a person's own and an administrator's.
    refused(
        browser,
        Method::POST,
        "/v1/access-keys",
        json!(["laptop", ["inference"], 3600]),
    )
    .await;
    refused(
        As::Admin,
        Method::POST,
        "/v1/admin/principals/robot/access-keys",
        json!(["nightly", ["inference"], 3600]),
    )
    .await;
    let all = m
        .admin_ok(
            Method::GET,
            "/v1/admin/access-keys?includeRevoked=true&includeExpired=true",
            "positional-tokens",
            None,
        )
        .await;
    assert_eq!(all["keys"], json!([]));
    // The same members as objects mint.
    m.alice_ok(
        Method::POST,
        "/v1/access-keys",
        "positional-issue",
        issue_body("laptop", &["inference"], 3600),
    )
    .await;
    m.admin_ok(
        Method::POST,
        "/v1/admin/principals/robot/access-keys",
        "positional-admin-issue",
        issue_body("nightly", &["inference"], 3600),
    )
    .await;
}

#[tokio::test]
async fn neither_route_issues_a_key_for_an_account_whose_keys_could_not_resolve() {
    let m = management().await;
    let own = "/v1/access-keys";
    let for_alice = "/v1/admin/principals/alice/access-keys";
    m.set_name("alice", "alice", "name").await;
    // A key she holds already: nothing below may end it or change it.
    let held = m
        .alice_ok(
            Method::POST,
            own,
            "issue-held",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    let key = held["key"].as_str().unwrap().to_string();
    // Her keys that are neither revoked nor expired.
    let listed = async |request_id: &str| {
        m.admin_ok(
            Method::GET,
            "/v1/admin/access-keys?principal=alice",
            request_id,
            None,
        )
        .await["keys"]
            .as_array()
            .unwrap()
            .clone()
    };
    // The administrator's request is refused with the account's problem,
    // the code principal detail reports, and issues nothing. The key she
    // holds lists the same code and is not revoked.
    let refused_for_her = async |cause: &'static str| {
        let (status, envelope) = m
            .admin(
                Method::POST,
                for_alice,
                &format!("admin-issue-{cause}"),
                issue_body("from the administrator", &["batch", "inference"], 3600),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{cause}: {envelope}");
        assert_eq!(refusal(&envelope), ("broker_access_key_denied", cause));
        assert!(
            envelope["details"].get("accessKeyType").is_none(),
            "{cause}"
        );
        assert!(!envelope.to_string().contains("aab_ak_"), "{cause}");
        let detail = m
            .admin_result(
                Method::GET,
                "/v1/admin/principals/alice",
                &format!("detail-{cause}"),
                None,
            )
            .await;
        assert_eq!(detail["accessKeyProblem"], cause);
        let keys = listed(&format!("list-{cause}")).await;
        assert_eq!(keys.len(), 1, "{cause}: {keys:?}");
        assert_eq!(
            (&keys[0]["keyId"], &keys[0]["status"], &keys[0]["revokedAt"]),
            (&held["record"]["keyId"], &json!(cause), &Value::Null),
            "{cause}"
        );
        assert_eq!(
            m.resolve(&format!("resolve-{cause}"), &key).await,
            json!({
                "active": false,
                "keyId": held["record"]["keyId"],
                "owner": {"kind": "user", "id": "alice"},
                "reason": cause
            }),
            "{cause}"
        );
    };
    // Her own request, while her session is one she can use: the same
    // code, which her options give beforehand, for a type she may create,
    // one only an administrator issues, one she may not hold and one that
    // does not exist alike.
    let refused_to_her = async |cause: &'static str| {
        let options = m
            .alice_ok(
                Method::GET,
                "/v1/access-keys/options",
                &format!("options-{cause}"),
                None,
            )
            .await;
        assert_eq!(
            (&options["refusal"], &options["problem"]),
            (&json!(cause), &json!(cause))
        );
        for requested in ["inference", "batch", "research", "nonesuch"] {
            let (status, envelope) = m
                .alice(
                    Method::POST,
                    own,
                    &format!("own-issue-{cause}-{requested}"),
                    issue_body("another", &[requested], 3600),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{cause}: {envelope}");
            assert_eq!(
                refusal(&envelope),
                ("broker_access_key_denied", cause),
                "{requested}"
            );
            assert!(
                envelope["details"].get("accessKeyType").is_none(),
                "{requested}"
            );
        }
    };
    // With the problem gone both routes issue, and the key she held works.
    let issues = async |request_id: &str| {
        assert_eq!(m.resolve(request_id, &key).await["active"], true);
        for (who, route, types) in [
            (As::Admin, for_alice, &["batch", "inference"][..]),
            (As::Browser { csrf: true }, own, &["inference"]),
        ] {
            let (status, envelope) = m
                .send(
                    who,
                    Method::POST,
                    route,
                    request_id,
                    issue_body("another", types, 3600),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{request_id}: {envelope}");
            let issued = envelope["result"]["record"]["keyId"].as_str().unwrap();
            let (status, envelope) = m
                .admin(
                    Method::DELETE,
                    &format!("/v1/admin/access-keys/{issued}"),
                    request_id,
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{envelope}");
        }
    };

    // More local groups than a resolution returns.
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    for index in 0..65 {
        let group_id = format!("team-{index:02}");
        m.store
            .create_group(
                agent_access_core::GroupWriteRequest {
                    group_id: group_id.clone(),
                    display_name: None,
                    description: None,
                    auto_enroll_new_microsoft_users: false,
                    agent_token_issuance: Default::default(),
                    created_by: "admin".to_string(),
                },
                &contexts,
            )
            .unwrap();
        m.store.add_group("alice", &group_id, "admin").unwrap();
    }
    refused_for_her("group_limit_exceeded").await;
    refused_to_her("group_limit_exceeded").await;
    m.store.remove_group("alice", "team-64").unwrap();
    issues("issues-64-groups").await;

    // A person whose identity access is paused, and a disabled account:
    // her session is of no use then, so only the administrator can ask.
    let pause = |paused: bool| {
        let version = m.store.identity_access("alice").unwrap().version;
        m.store
            .set_identity_access_paused("alice", paused, version, "admin")
            .unwrap();
    };
    pause(true);
    refused_for_her("identity_access_paused").await;
    pause(false);
    m.store.set_principal_enabled("alice", false).unwrap();
    refused_for_her("principal_disabled").await;
    m.store.set_principal_enabled("alice", true).unwrap();

    // A person whose identity access has no record at all: no key of
    // hers resolves, so none is issued.
    rusqlite::Connection::open(&m.fixture.store_path)
        .unwrap()
        .execute(
            "DELETE FROM principal_identity_access WHERE principal_id = 'alice'",
            [],
        )
        .unwrap();
    refused_for_her("identity_access_missing").await;
}

#[tokio::test]
async fn neither_route_issues_a_key_while_the_account_s_name_cannot_be_used() {
    let m = management().await;
    let own = "/v1/access-keys";
    let for_alice = "/v1/admin/principals/alice/access-keys";
    let both_refuse = async |cause: &'static str| {
        let options = m
            .alice_ok(
                Method::GET,
                "/v1/access-keys/options",
                &format!("options-{cause}"),
                None,
            )
            .await;
        assert_eq!(
            (&options["refusal"], &options["problem"]),
            (&json!(cause), &json!(cause))
        );
        let detail = m
            .admin_result(
                Method::GET,
                "/v1/admin/principals/alice",
                &format!("detail-{cause}"),
                None,
            )
            .await;
        assert_eq!(detail["accessKeyProblem"], cause);
        for (who, route, types) in [
            (As::Admin, for_alice, &["batch", "inference"][..]),
            (As::Browser { csrf: true }, own, &["inference"]),
            // A type she may not hold is not said before the name is.
            (As::Browser { csrf: true }, own, &["research"]),
        ] {
            let (status, envelope) = m
                .send(
                    who,
                    Method::POST,
                    route,
                    &format!("issue-{cause}"),
                    issue_body("another", types, 3600),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{cause}: {envelope}");
            assert_eq!(refusal(&envelope), ("broker_access_key_denied", cause));
            assert!(envelope["details"].get("accessKeyType").is_none());
        }
    };
    // No username yet; then one that is listed and awaits confirmation.
    both_refuse("no_account_username").await;
    m.set_name("alice", "carol", "name-listed").await;
    both_refuse("account_username_awaiting_confirmation").await;
    // Confirmed, it is hers to issue under.
    m.admin_ok(
        Method::POST,
        "/v1/admin/principals/alice/account-username/confirm",
        "confirm",
        Some(json!({"accountUsername": "carol"})),
    )
    .await;
    for (who, route, types) in [
        (As::Admin, for_alice, &["batch", "inference"][..]),
        (As::Browser { csrf: true }, own, &["inference"]),
    ] {
        let (status, envelope) = m
            .send(
                who,
                Method::POST,
                route,
                "issue-confirmed",
                issue_body("another", types, 3600),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{envelope}");
    }
}

#[tokio::test]
async fn an_administrator_issues_for_a_person_and_the_token_is_the_person_s_own() {
    let m = management().await;
    let for_alice = "/v1/admin/principals/alice/access-keys";
    let own = "/v1/access-keys";
    let options = async |request_id: &str| {
        m.alice_ok(Method::GET, "/v1/access-keys/options", request_id, None)
            .await
    };
    let facts = |options: &Value| {
        (
            options["hasSelfServiceType"].as_bool().unwrap(),
            options["hasKeys"].as_bool().unwrap(),
            options["problem"].clone(),
        )
    };

    // What an administrator is shown about the account: why no key of it
    // can work now, in the code her own options and her keys' status use.
    let account_problem = async |request_id: &str| {
        m.admin_result(Method::GET, "/v1/admin/principals/alice", request_id, None)
            .await["accessKeyProblem"]
            .clone()
    };

    // Alice may hold types and has no name: nothing is issued for her, and
    // her options say there is a type she could create, no token, and a
    // name an administrator must act on.
    assert_eq!(
        facts(&options("options-unnamed").await),
        (true, false, json!("no_account_username"))
    );
    assert_eq!(
        account_problem("detail-unnamed").await,
        "no_account_username"
    );
    let (status, envelope) = m
        .admin(
            Method::POST,
            for_alice,
            "admin-issue-unnamed",
            issue_body("from the administrator", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        ("broker_access_key_denied", "no_account_username")
    );
    // A name that awaits confirmation is not usable either.
    m.set_name("alice", "carol", "name-listed").await;
    assert_eq!(
        facts(&options("options-awaiting").await),
        (true, false, json!("account_username_awaiting_confirmation"))
    );
    assert_eq!(
        account_problem("detail-awaiting").await,
        "account_username_awaiting_confirmation"
    );
    let (status, envelope) = m
        .admin(
            Method::POST,
            for_alice,
            "admin-issue-awaiting",
            issue_body("from the administrator", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        (
            "broker_access_key_denied",
            "account_username_awaiting_confirmation"
        )
    );
    m.set_name("alice", "alice", "name").await;

    // No session of hers is needed, and `batch` is a type people cannot
    // create themselves: only an administrator hands it out.
    assert!(account_problem("detail-named").await.is_null());
    let issued = m
        .admin_ok(
            Method::POST,
            for_alice,
            "admin-issue-person",
            issue_body("from the administrator", &["batch", "inference"], 3600),
        )
        .await;
    let token = issued["key"].as_str().unwrap().to_string();
    let key_id = issued["record"]["keyId"].as_str().unwrap().to_string();
    assert_eq!(issued["record"]["principalId"], "alice");
    assert_eq!(issued["record"]["origin"], "administrator");
    assert_eq!(issued["record"]["createdBy"], "admin");
    // The administrator is the audit actor and the person the owner.
    let records = m.records("admin.principals.access_keys.issue", "admin-issue-person");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["principal"], "admin");
    let target = &records[0]["providerAudit"]["management"]["target"];
    assert_eq!(target["principal"], "alice");
    assert_eq!(target["origin"], "administrator");
    assert_eq!(target["keyId"], json!(key_id));
    assert!(!read_audit_text(&m.fixture.audit_path).contains(&token));
    let resolved = m.resolve("resolve-person", &token).await;
    assert_eq!(resolved["active"], true);
    assert_eq!(resolved["subject"], json!({"kind": "user", "id": "alice"}));
    assert_eq!(resolved["origin"], "administrator");
    assert_eq!(
        resolved["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|access_key_type| access_key_type["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["batch", "inference"]
    );
    let (status, envelope) = m
        .alice(
            Method::POST,
            own,
            "own-issue-batch",
            issue_body("laptop", &["batch"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        (
            "broker_access_key_denied",
            "access_key_type_not_self_service"
        )
    );

    // The token is hers: her own list shows it with who issued it, and her
    // options say she has a token.
    let listed = m.alice_ok(Method::GET, own, "own-list", None).await;
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["keyId"], json!(key_id));
    assert_eq!(listed["keys"][0]["origin"], "administrator");
    assert_eq!(listed["keys"][0]["createdBy"], "admin");
    assert_eq!(listed["keys"][0]["status"], "active");
    // Each type the key carries, with the name people read and whether the
    // key still holds it.
    assert_eq!(listed["keys"][0]["access"], "full");
    assert_eq!(
        listed["keys"][0]["accessKeyTypeStates"],
        json!([
            {"id": "batch", "displayName": "Batch jobs", "held": true},
            {"id": "inference", "displayName": "Model inference", "held": true},
        ])
    );
    assert_eq!(
        facts(&options("options-owned").await),
        (true, true, Value::Null)
    );
    // An administrator's listing of her keys is the same view.
    assert_eq!(
        m.admin_ok(
            Method::GET,
            "/v1/admin/access-keys?principal=alice",
            "admin-list-person",
            None
        )
        .await,
        listed
    );

    // The same checks as her own mint, apart from her session and the
    // self-service switch; nothing is trimmed.
    for (request_id, body, expected, detail) in [
        (
            "admin-issue-not-allowed",
            issue_body("extra", &["inference", "research"], 3600),
            "access_key_type_not_eligible",
            json!({"accessKeyType": "research"}),
        ),
        (
            "admin-issue-unknown",
            issue_body("extra", &["inference", "telemetry"], 3600),
            "access_key_type_unknown",
            json!({"accessKeyType": "telemetry"}),
        ),
        (
            "admin-issue-too-long",
            issue_body("extra", &["batch", "inference"], 8 * 24 * 3600),
            "lifetime_not_offered",
            json!({"accessKeyType": "batch"}),
        ),
    ] {
        let (status, envelope) = m.admin(Method::POST, for_alice, request_id, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{request_id}: {envelope}");
        assert_eq!(refusal(&envelope), ("broker_access_key_denied", expected));
        for (member, value) in detail.as_object().unwrap() {
            assert_eq!(&envelope["details"][member], value, "{request_id}");
        }
    }
    let (status, envelope) = m
        .send(
            As::Auditor,
            Method::POST,
            for_alice,
            "auditor-issue-person",
            issue_body("extra", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        listed,
        m.alice_ok(Method::GET, own, "own-list-again", None).await
    );

    // It stops working by the rules of a token she created, here her
    // access to one type withdrawn, and she revokes it herself.
    m.set_access("alice", &["inference"], &["batch"], "access-narrowed")
        .await;
    let narrowed = m.resolve("resolve-narrowed", &token).await;
    assert_eq!(narrowed["types"].as_array().unwrap().len(), 1);
    assert_eq!(narrowed["types"][0]["name"], "inference");
    // Her list says which type the key no longer holds, in the same words.
    let partial = m
        .alice_ok(Method::GET, own, "own-list-narrowed", None)
        .await;
    assert_eq!(partial["keys"][0]["status"], "active");
    assert_eq!(partial["keys"][0]["access"], "partial");
    assert_eq!(
        partial["keys"][0]["accessKeyTypeStates"],
        json!([
            {"id": "batch", "displayName": "Batch jobs", "held": false},
            {"id": "inference", "displayName": "Model inference", "held": true},
        ])
    );

    // In more local groups than a resolution returns, no key of hers
    // works: her options name the problem with the status her keys list.
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    for index in 0..65 {
        let group_id = format!("team-{index:02}");
        m.store
            .create_group(
                agent_access_core::GroupWriteRequest {
                    group_id: group_id.clone(),
                    display_name: None,
                    description: None,
                    auto_enroll_new_microsoft_users: false,
                    agent_token_issuance: Default::default(),
                    created_by: "admin".to_string(),
                },
                &contexts,
            )
            .unwrap();
        m.store.add_group("alice", &group_id, "admin").unwrap();
    }
    let crowded = options("options-too-many-groups").await;
    assert_eq!(facts(&crowded), (true, true, json!("group_limit_exceeded")));
    assert_eq!(crowded["refusal"], "group_limit_exceeded");
    // The administrator's view of her account says the same, and no key
    // that could not work is issued.
    assert_eq!(
        account_problem("detail-too-many-groups").await,
        "group_limit_exceeded"
    );
    let crowded = m
        .alice_ok(Method::GET, own, "own-list-too-many-groups", None)
        .await;
    assert_eq!(crowded["keys"][0]["status"], "group_limit_exceeded");
    assert_eq!(crowded["keys"][0]["access"], "none");
    assert_eq!(
        m.resolve("resolve-too-many-groups", &token).await,
        json!({
            "active": false,
            "keyId": key_id,
            "owner": {"kind": "user", "id": "alice"},
            "reason": "group_limit_exceeded"
        })
    );
    m.store.remove_group("alice", "team-64").unwrap();
    assert_eq!(
        facts(&options("options-64-groups").await),
        (true, true, Value::Null)
    );
    assert!(account_problem("detail-64-groups").await.is_null());
    assert_eq!(m.resolve("resolve-64-groups", &token).await["active"], true);
    let revoked = m
        .alice_ok(
            Method::DELETE,
            &format!("{own}/{key_id}"),
            "own-revoke",
            None,
        )
        .await;
    assert_eq!(revoked["newlyRevoked"], true);
    assert_eq!(revoked["record"]["revokedBy"], "alice");
    assert_eq!(
        m.resolve("resolve-revoked", &token).await,
        json!({
            "active": false,
            "keyId": key_id,
            "owner": {"kind": "user", "id": "alice"},
            "reason": "revoked"
        })
    );
    // A revoked token is still one she owns.
    assert_eq!(
        facts(&options("options-revoked").await),
        (true, true, Value::Null)
    );
}

#[tokio::test]
async fn a_mint_whose_success_record_cannot_be_written_withholds_the_secret() {
    let m = management().await;
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name",
        Some(json!({"mode": "manual", "accountUsername": "alice"})),
    )
    .await;
    let db = rusqlite::Connection::open(&m.fixture.audit_path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_issue_audit BEFORE INSERT ON audit_events
         WHEN NEW.action = 'access_keys.issue'
         BEGIN SELECT RAISE(ABORT, 'private-audit-failure'); END;",
    )
    .unwrap();
    let (status, envelope) = m
        .alice(
            Method::POST,
            "/v1/access-keys",
            "issue-unaudited",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{envelope}");
    assert_eq!(envelope["reasonCode"], "audit_unavailable");
    let text = envelope.to_string();
    assert!(!text.contains("aab_ak_"), "{text}");
    assert!(!text.contains("private-audit-failure"), "{text}");
    // The token was committed and is never revealed: it is listed, so that
    // its owner can revoke it, and the request is not retried.
    db.execute_batch("DROP TRIGGER fail_issue_audit;").unwrap();
    let listed = m
        .alice_ok(Method::GET, "/v1/access-keys", "list", None)
        .await;
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["name"], "laptop");
}

/// The JSON pointers of every string in `value` that holds an access key.
fn access_key_pointers(value: &Value, at: &str, found: &mut Vec<String>) {
    match value {
        Value::String(text) if text.contains("aab_ak_") => found.push(at.to_string()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                access_key_pointers(item, &format!("{at}/{index}"), found);
            }
        }
        Value::Object(members) => {
            for (name, member) in members {
                access_key_pointers(member, &format!("{at}/{name}"), found);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn a_mint_s_advertised_sensitive_pointer_is_where_its_response_carries_the_key() {
    let m = management().await;
    m.set_name("alice", "alice", "alice-name").await;
    let (own_status, own) = m
        .alice(
            Method::POST,
            "/v1/access-keys",
            "pointer-own",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    let (admin_status, admin) = m
        .admin(
            Method::POST,
            "/v1/admin/principals/alice/access-keys",
            "pointer-admin",
            issue_body("from the administrator", &["batch"], 3600),
        )
        .await;
    assert_eq!((own_status, admin_status), (StatusCode::OK, StatusCode::OK));
    let routes = http_route_specs(m.fixture.state.current().runtime.resource_types());
    let response = authed_json_request(
        m.fixture.app.clone(),
        Method::GET,
        "/v1/spec/openapi.json?visibility=all",
        "pointer-openapi",
        "X-Agent-Token",
        format!("Bearer {}", m.fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let openapi = response_json(response).await;
    let (status, catalog) = m
        .admin(
            Method::GET,
            "/v1/spec/catalog?visibility=all",
            "pointer-catalog",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    for (envelope, path) in [
        (&own, "/v1/access-keys"),
        (&admin, "/v1/admin/principals/{principal}/access-keys"),
    ] {
        let operation = envelope["operation"].as_str().unwrap();
        let route = routes
            .iter()
            .find(|route| route.operation == operation)
            .unwrap();
        // What the catalog marks is exactly where the real response holds
        // the secret, and the secret is nowhere else in it.
        let mut carried = Vec::new();
        access_key_pointers(envelope, "", &mut carried);
        assert_eq!(
            carried, route.sensitive_response_pointers,
            "{operation}: {envelope}"
        );
        for pointer in &route.sensitive_response_pointers {
            let secret = envelope
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{operation}: {pointer} is not in the response"));
            assert_eq!(
                m.resolve(&format!("pointer-resolve-{operation}"), secret)
                    .await["keyId"],
                envelope["result"]["record"]["keyId"],
                "{operation}"
            );
            // The pointer names a member the published result schema has.
            let member = pointer.strip_prefix("/result/").unwrap();
            assert!(
                route.result_schema.as_ref().unwrap()["properties"]
                    .get(member)
                    .is_some(),
                "{operation}: {pointer}"
            );
        }
        // The same pointers reach every projection of the route.
        let expected = json!(route.sensitive_response_pointers);
        assert_eq!(
            openapi["paths"][path]["post"]["x-agent-access-sensitive-output-pointers"], expected,
            "{operation}"
        );
        let listed = catalog["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|listed| listed["operation"] == operation)
            .unwrap();
        assert_eq!(listed["sensitiveResponsePointers"], expected, "{operation}");
    }
}

fn browser_issue_request(m: &Management, request_id: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/access-keys")
        .extension(ConnectInfo(
            "127.0.0.1:43130".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header("Cookie", &m.fixture.cookie)
        .header("Host", "localhost")
        .header("Origin", "http://localhost")
        .header("X-Agent-Access-CSRF", &m.fixture.csrf)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            issue_body("laptop", &["inference"], 3600)
                .unwrap()
                .to_string(),
        ))
        .unwrap()
}

/// Holds the next mint's owner before its fenced store call. The guard
/// releases the owner when a failed assertion unwinds.
struct HeldMint(Arc<crate::state::McpBlockingBarrier>);

impl Drop for HeldMint {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn hold_mint(m: &Management) -> HeldMint {
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *m.fixture.state.access_key_mint_barrier.lock().unwrap() = Some(barrier.clone());
    HeldMint(barrier)
}

async fn reached(barrier: &HeldMint) {
    tokio::time::timeout(Duration::from_secs(10), barrier.0.reached.notified())
        .await
        .expect("the mint's owner reaches its store call");
}

fn alice_tokens(m: &Management) -> Vec<agent_access_core::AccessKeyView> {
    m.fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .list_access_key_views(
            m.fixture.state.current().runtime.access_key_types(),
            &agent_access_core::AccessKeyListFilter {
                principal_id: Some("alice".to_string()),
                include_revoked: true,
                include_expired: true,
            },
        )
        .unwrap()
}

#[tokio::test]
async fn a_cancelled_mint_is_still_committed_and_audited_by_its_owner() {
    let m = management().await;
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name",
        Some(json!({"mode": "manual", "accountUsername": "alice"})),
    )
    .await;
    let held = hold_mint(&m);
    let app = m.fixture.app.clone();
    let request = browser_issue_request(&m, "issue-cancelled");
    let waiter = tokio::spawn(async move { app.oneshot(request).await });
    reached(&held).await;
    *m.fixture.state.access_key_mint_barrier.lock().unwrap() = None;
    assert!(alice_tokens(&m).is_empty());
    // The client goes away before anything is minted.
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    held.0.release();
    tokio::time::timeout(Duration::from_secs(10), held.0.completed.notified())
        .await
        .expect("the mint's owner finishes without its request");

    let tokens = alice_tokens(&m);
    assert_eq!(tokens.len(), 1);
    let records = m.records("access_keys.issue", "issue-cancelled");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(
        records[0]["providerAudit"]["management"]["target"]["keyId"],
        json!(tokens[0].record.key_id)
    );
}

#[tokio::test]
async fn shutdown_waits_for_the_completion_audit_of_a_mint_whose_request_was_cancelled() {
    let m = management().await;
    m.admin_ok(
        Method::PUT,
        "/v1/admin/principals/alice/account-username",
        "alice-name",
        Some(json!({"mode": "manual", "accountUsername": "alice"})),
    )
    .await;
    let held = hold_mint(&m);
    let app = m.fixture.app.clone();
    let request = browser_issue_request(&m, "issue-at-shutdown");
    let waiter = tokio::spawn(async move { app.oneshot(request).await });
    reached(&held).await;
    // The client goes away while the mint's owner is blocked before its
    // store call: nothing is minted or audited yet.
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(alice_tokens(&m).is_empty());
    assert!(
        m.records("access_keys.issue", "issue-at-shutdown")
            .is_empty()
    );

    let Management { fixture, store, .. } = m;
    let BrowserRateFixture {
        _broker: broker,
        app,
        state,
        ingress,
        audit_path,
        store_path,
        ..
    } = fixture;
    drop((app, state, ingress, store));
    // Shutdown waits for the owner instead of closing the audit under it.
    let stopping = tokio::spawn(broker.stop());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !stopping.is_finished(),
        "shutdown finished while the mint's owner was still running"
    );
    held.0.release();
    let report = tokio::time::timeout(Duration::from_secs(30), stopping)
        .await
        .expect("shutdown completes once the owner has finished")
        .unwrap();
    assert_eq!(report.unfinished_application_owners(), 0);
    assert!(report.is_clean(), "{report:?}");

    // The owner's mint and its only audit record both completed.
    let key_id: String = rusqlite::Connection::open(&store_path)
        .unwrap()
        .query_row(
            "SELECT key_id FROM access_keys WHERE principal_id = 'alice'",
            [],
            |row| row.get(0),
        )
        .expect("exactly one token was minted");
    let records = read_audit_records(&audit_path)
        .into_iter()
        .filter(|record| {
            record["action"] == "access_keys.issue"
                && record["agentRequestId"] == "issue-at-shutdown"
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(
        records[0]["providerAudit"]["management"]["target"]["keyId"],
        json!(key_id)
    );
}

#[tokio::test]
async fn a_cancelled_name_change_stays_in_the_shutdown_drain_until_it_is_audited() {
    use crate::handlers::management::common::{
        ManagementAccess, management_context, management_write_audit_preflight,
    };
    use crate::handlers::management::identity_access::committed_identity_mutation;
    use crate::state::AppState;

    let m = management().await;
    let operation = "admin.principals.account_username.set";
    let state = AppState {
        reloadable: m.fixture.state.clone(),
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "X-Agent-Token",
        format!("Bearer {}", m.fixture.admin_token).parse().unwrap(),
    );
    headers.insert(REQUEST_ID_HEADER, "name-change-cancelled".parse().unwrap());
    let context = management_context(
        &state,
        "127.0.0.1:43131".parse().unwrap(),
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(&context, operation, None)
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let waiter = tokio::spawn(committed_identity_mutation(
        state,
        context,
        operation,
        None,
        move |store| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let change = store
                .set_account_username("alice", "alice", "admin")?
                .unwrap();
            Ok((json!({}), change.audit_details()))
        },
    ));
    entered_rx.await.unwrap();
    // The request is cancelled while its owner is inside the store call.
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let owners = m.fixture.state.application_owners.clone();
    assert_eq!(owners.drain(Duration::from_millis(20)).await, 1);
    release_tx.send(()).unwrap();
    assert_eq!(owners.drain(Duration::from_secs(10)).await, 0);
    // The owner finished: the name is set and its success record written.
    assert_eq!(
        m.store
            .principal_account_username("alice")
            .unwrap()
            .name
            .unwrap()
            .account_username,
        "alice"
    );
    assert_eq!(
        m.completion(operation, "name-change-cancelled")["principal"],
        "alice"
    );
}

#[tokio::test]
async fn a_cancelled_access_key_type_change_stays_in_the_shutdown_drain_until_it_is_audited() {
    use crate::handlers::management::admin::{
        committed_group_mutation, committed_principal_mutation,
    };
    use crate::handlers::management::common::{
        ManagementAccess, management_context, management_write_audit_preflight,
    };
    use crate::state::AppState;
    use agent_access_core::{AccessKeyTypesWrite, GroupAccessKeyTypes, PrincipalAccessKeyTypes};

    let m = management().await;
    let state = AppState {
        reloadable: m.fixture.state.clone(),
    };
    let owners = m.fixture.state.application_owners.clone();
    let context = async |operation: &'static str, request_id: &'static str| {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "X-Agent-Token",
            format!("Bearer {}", m.fixture.admin_token).parse().unwrap(),
        );
        headers.insert(REQUEST_ID_HEADER, request_id.parse().unwrap());
        let context = management_context(
            &state,
            "127.0.0.1:43131".parse().unwrap(),
            &headers,
            operation,
            ManagementAccess::AdminWrite,
        )
        .await
        .unwrap();
        management_write_audit_preflight(&context, operation, None)
            .await
            .unwrap();
        context
    };
    let runtime = m.fixture.state.current().runtime.clone();

    // An account's setting: the request is cancelled while its owner is
    // inside the store call. Shutdown waits for the owner, which finishes
    // the change and writes the record that says what it changed.
    let operation = "admin.principals.access.patch";
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let configured = runtime.clone();
    let waiter = tokio::spawn(committed_principal_mutation(
        state.clone(),
        context(operation, "account-setting-cancelled").await,
        operation,
        None,
        move |store, environment| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let setting = PrincipalAccessKeyTypes::new(vec!["research".into()], vec![]).unwrap();
            let change = store.patch_principal_access_with_access_key_types(
                PrincipalAccessPatchRequest {
                    agent_token_issuance: None,
                    principal_id: "alice".into(),
                    role: None,
                    self_service_enabled: None,
                    actor: "admin".into(),
                },
                Some(AccessKeyTypesWrite {
                    setting: &setting,
                    configured: configured.access_key_types(),
                }),
                environment.contexts(),
            )?;
            Ok((
                json!({}),
                json!({"principal": "alice", "accessKeyTypes": change.access_key_types.map(|access| access.current)}),
            ))
        },
    ));
    entered_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(owners.drain(Duration::from_millis(20)).await, 1);
    release_tx.send(()).unwrap();
    assert_eq!(owners.drain(Duration::from_secs(10)).await, 0);
    assert_eq!(
        m.completion(operation, "account-setting-cancelled")["accessKeyTypes"],
        json!({"allow": ["research"], "deny": []})
    );

    // A group's setting, the same.
    let operation = "admin.groups.patch";
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let waiter = tokio::spawn(committed_group_mutation(
        state.clone(),
        context(operation, "group-setting-cancelled").await,
        operation,
        None,
        move |store, environment| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            store.patch_group_with_access(
                agent_access_core::GroupPatchRequest {
                    group_id: "research".into(),
                    display_name: None,
                    description: None,
                    status: None,
                    auto_enroll_new_microsoft_users: None,
                    agent_token_issuance: None,
                    updated_by: "admin".into(),
                },
                Some(AccessKeyTypesWrite {
                    setting: &GroupAccessKeyTypes::new(vec!["batch".into()]).unwrap(),
                    configured: runtime.access_key_types(),
                }),
                environment.contexts(),
            )
        },
    ));
    entered_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(owners.drain(Duration::from_millis(20)).await, 1);
    release_tx.send(()).unwrap();
    assert_eq!(owners.drain(Duration::from_secs(10)).await, 0);
    assert_eq!(
        m.completion(operation, "group-setting-cancelled")["accessKeyTypes"],
        json!({"previous": {"allow": ["research"]}, "current": {"allow": ["batch"]}})
    );
}

#[tokio::test]
async fn a_mint_that_began_before_a_reload_mints_nothing_under_the_retired_settings() {
    // A file reference, so that a reload can load the provider credential
    // again.
    let provider_token = temp_path("access-key-management-fake-token");
    std::fs::write(&provider_token, "synthetic-fake-service-token").unwrap();
    let resolver_secret = temp_path("access-key-management-stale-caller");
    std::fs::write(&resolver_secret, RESOLVER.strip_prefix("Bearer ").unwrap()).unwrap();
    let mut captured = None;
    let fixture = browser_rate_fixture_with(test_limits(), |config| {
        configure(config, &resolver_secret);
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", provider_token.display()));
        captured = Some(config.clone());
    })
    .await;
    let runtime = fixture.state.current().runtime.clone();
    let store = runtime.managed_store().unwrap().clone();
    grant_access(&store, &runtime);
    store
        .set_account_username("alice", "alice", "admin")
        .unwrap()
        .unwrap();
    let m = Management {
        fixture,
        store,
        auditor: String::new(),
    };
    let held = hold_mint(&m);
    let app = m.fixture.app.clone();
    let request = browser_issue_request(&m, "issue-stale");
    let waiter = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    reached(&held).await;
    *m.fixture.state.access_key_mint_barrier.lock().unwrap() = None;
    // While the request waits, the operator closes the type to people.
    let mut retired = captured.unwrap();
    retired
        .access_key_types
        .get_mut("inference")
        .unwrap()
        .self_service = false;
    let generation = m.fixture.state.current().generation;
    m.fixture._broker.reload_config(&retired).await;
    assert_eq!(m.fixture.state.current().generation, generation + 1);
    held.0.release();
    let response = waiter.await.unwrap();

    // The stale request is refused before its transaction, not minted under
    // the settings it began with.
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let envelope = response_json(response).await;
    assert_eq!(envelope["reasonCode"], "version_conflict", "{envelope}");
    assert!(envelope["result"].is_null());
    assert!(alice_tokens(&m).is_empty());
    // The same request under the current settings is refused for what they
    // say.
    let (status, envelope) = m
        .alice(
            Method::POST,
            "/v1/access-keys",
            "issue-current",
            issue_body("laptop", &["inference"], 3600),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        (
            "broker_access_key_denied",
            "access_key_type_not_self_service"
        )
    );
}

#[tokio::test]
async fn the_catalog_lists_the_routes_for_those_who_may_use_them() {
    let m = management().await;
    let catalog = |who: As<'static>| {
        let m = &m;
        async move {
            let (status, catalog) = m
                .send(who, Method::GET, "/v1/spec/catalog", "catalog", None)
                .await;
            assert_eq!(status, StatusCode::OK, "{catalog}");
            catalog["routes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|route| route["operation"].as_str().unwrap().to_string())
                .collect::<BTreeSet<_>>()
        }
    };
    let personal = [
        "access_keys.list",
        "access_keys.options",
        "access_keys.issue",
        "access_keys.revoke",
    ];
    let reads = [
        "admin.access_key_types.list",
        "admin.access_keys.list",
        "admin.account_usernames.list",
        "admin.principals.account_username.inspect",
    ];
    let writes = [
        "admin.access_keys.revoke",
        "admin.principals.access_keys.issue",
        "admin.principals.account_username.set",
        "admin.principals.account_username.confirm",
    ];
    // A signed-in person sees their own routes and no administration.
    let alice = catalog(As::Browser { csrf: false }).await;
    assert!(
        personal.iter().all(|operation| alice.contains(*operation)),
        "{alice:?}"
    );
    assert!(
        reads
            .iter()
            .chain(&writes)
            .all(|operation| !alice.contains(*operation))
    );
    // An agent token sees none of them.
    let agent = m.fixture.agent_tokens[0].clone();
    let (status, catalog_json) = m
        .send(
            As::Token(&agent),
            Method::GET,
            "/v1/spec/catalog",
            "catalog-agent",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog_json}");
    let agent_operations = catalog_json["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| route["operation"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(
        personal
            .iter()
            .chain(&reads)
            .chain(&writes)
            .all(|operation| !agent_operations.contains(*operation))
    );
    // A person's own bearer token is offered none of their access key
    // routes: each of them takes a browser session only, and says so to it.
    let own_token = m.fixture.management_token.clone();
    let (status, catalog_json) = m
        .send(
            As::Token(&own_token),
            Method::GET,
            "/v1/spec/catalog",
            "catalog-own-token",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog_json}");
    let offered = catalog_json["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| route["operation"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(
        personal
            .iter()
            .all(|operation| !offered.contains(*operation)),
        "{offered:?}"
    );
    let (status, envelope) = m
        .send(
            As::Token(&own_token),
            Method::GET,
            "/v1/access-keys",
            "own-token-list",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
    assert_eq!(
        refusal(&envelope),
        ("broker_access_key_denied", "session_required")
    );
    // The catalog and the OpenAPI document say that the routes take a
    // browser session.
    let (status, catalog_json) = m
        .send(
            As::Browser { csrf: false },
            Method::GET,
            "/v1/spec/catalog",
            "catalog-session",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog_json}");
    for route in catalog_json["routes"].as_array().unwrap() {
        assert_eq!(
            route["browserSessionOnly"] == true,
            personal.contains(&route["operation"].as_str().unwrap()),
            "{route}"
        );
    }
    let response = m
        .fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/spec/openapi.json")
                .extension(ConnectInfo(
                    "127.0.0.1:43130".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "openapi-session")
                .header("Cookie", &m.fixture.cookie)
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let openapi = response_json(response).await;
    for (path, method) in [
        ("/v1/access-keys", "get"),
        ("/v1/access-keys", "post"),
        ("/v1/access-keys/options", "get"),
        ("/v1/access-keys/{key_id}", "delete"),
    ] {
        let operation = &openapi["paths"][path][method];
        assert_eq!(
            operation["security"],
            json!([{"browserSession": []}]),
            "{method} {path}: {operation}"
        );
        assert!(
            operation["description"]
                .as_str()
                .is_some_and(|text| text.contains("browser session")),
            "{method} {path}"
        );
    }
    // The scheme the routes name is defined in the same document, although
    // this configuration has no other route that takes a browser session:
    // every security requirement of the document names a defined scheme.
    let schemes = openapi["components"]["securitySchemes"]
        .as_object()
        .unwrap();
    assert_eq!(
        schemes["browserSession"]["in"],
        "cookie",
        "{:?}",
        schemes.keys().collect::<Vec<_>>()
    );
    for (path, item) in openapi["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            for requirement in operation["security"].as_array().into_iter().flatten() {
                for scheme in requirement.as_object().unwrap().keys() {
                    assert!(schemes.contains_key(scheme), "{method} {path}: {scheme}");
                }
            }
        }
    }
    // An auditor sees the reads; an administrator the writes too.
    let auditor = catalog(As::Auditor).await;
    assert!(reads.iter().all(|operation| auditor.contains(*operation)));
    assert!(writes.iter().all(|operation| !auditor.contains(*operation)));
    let admin = catalog(As::Admin).await;
    assert!(
        reads
            .iter()
            .chain(&writes)
            .all(|operation| admin.contains(*operation))
    );
    // Resolution uses its own trusted-caller protocol, outside generic discovery.
    assert!(!admin.contains("access_keys.resolve"));
    assert!(openapi["paths"].get("/v1/access-keys/resolve").is_none());
    let (status, send_schema) = m
        .send(
            As::Admin,
            Method::GET,
            "/v1/spec/send-schema.json",
            "access-key-send-schema",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!send_schema.to_string().contains("access_keys.resolve"));

    // The published shape of the two mint routes marks the secret, and the
    // request body they document is the one they accept.
    let routes = http_route_specs(m.fixture.state.current().runtime.resource_types());
    for operation in ["access_keys.issue", "admin.principals.access_keys.issue"] {
        let route = routes
            .iter()
            .find(|route| route.operation == operation)
            .unwrap();
        assert_eq!(route.sensitive_response_pointers, ["/result/key"]);
        let validator =
            jsonschema::validator_for(route.request_body_schema.as_ref().unwrap()).unwrap();
        assert!(validator.is_valid(&issue_body("laptop", &["inference"], 60).unwrap()));
        for body in [
            json!({"name": "laptop", "accessKeyTypes": ["inference"]}),
            json!({"name": "laptop", "accessKeyTypes": [], "lifetime": "60s"}),
            json!({"name": "laptop", "accessKeyTypes": ["inference"], "lifetime": 0}),
            json!({"name": "laptop", "accessKeyTypes": ["inference"], "lifetime": "60s", "ttl": "1h"}),
        ] {
            assert!(!validator.is_valid(&body), "{operation}: {body}");
        }
    }
    // The body that sets how a name is decided: a name goes with manual
    // only, as the route itself requires.
    let route = routes
        .iter()
        .find(|route| route.operation == "admin.principals.account_username.set")
        .unwrap();
    let validator = jsonschema::validator_for(route.request_body_schema.as_ref().unwrap()).unwrap();
    for body in [
        json!({"mode": "from_email"}),
        json!({"mode": "manual"}),
        json!({"mode": "manual", "accountUsername": "a.smith"}),
        json!({"mode": "manual", "accountUsername": null}),
    ] {
        assert!(validator.is_valid(&body), "{body}");
    }
    for body in [
        json!({}),
        json!({"accountUsername": "a.smith"}),
        json!({"mode": "automatic"}),
        json!({"mode": "from_email", "accountUsername": "a.smith"}),
        json!({"mode": "from_email", "accountUsername": null}),
        json!({"mode": "manual", "accountUsername": "has space"}),
        json!({"mode": "manual", "accountUsername": ""}),
        json!({"mode": "manual", "force": true}),
        json!(["manual", "a.smith"]),
    ] {
        assert!(!validator.is_valid(&body), "{body}");
    }
}

#[tokio::test]
async fn personal_routes_are_listed_only_while_an_access_key_type_is_configured() {
    // No access key type: a person's own access key routes are not offered,
    // and the administrator's are, with an empty list of types.
    let fixture = browser_rate_fixture(test_limits()).await;
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    let m = Management {
        fixture,
        store,
        auditor: String::new(),
    };
    let (status, catalog) = m
        .send(
            As::Browser { csrf: false },
            Method::GET,
            "/v1/spec/catalog",
            "catalog",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert!(catalog["routes"].as_array().unwrap().iter().all(|route| {
        !route["operation"]
            .as_str()
            .unwrap()
            .starts_with("access_keys.")
    }));
    let types = m
        .admin_ok(Method::GET, "/v1/admin/access-key-types", "types", None)
        .await;
    assert_eq!(types["accessKeyTypes"], json!([]));
    // The routes themselves answer for a signed-in person: nothing to choose.
    let options = m
        .alice_ok(Method::GET, "/v1/access-keys/options", "options", None)
        .await;
    assert_eq!(options["accessKeyTypes"], json!([]));
    assert_eq!(options["refusal"], "no_account_username");
    // No type the person may hold and no token: nothing to show this
    // person, and the missing name is nobody's problem.
    assert_eq!(
        (
            &options["hasSelfServiceType"],
            &options["hasKeys"],
            &options["problem"]
        ),
        (&json!(false), &json!(false), &Value::Null)
    );
}

#[tokio::test]
async fn pasted_access_keys_are_not_recorded_as_revoke_targets() {
    let m = management().await;
    m.set_name("alice", "alice", "pasted-name").await;
    let issued = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "pasted-issue",
            issue_body("notebook", &["inference"], 600),
        )
        .await;
    let secret = issued["key"].as_str().unwrap();
    let captured = install_trace_capture().start();
    for (who, prefix, request_id) in [
        (As::Browser { csrf: true }, "/v1/access-keys", "pasted-own"),
        (As::Admin, "/v1/admin/access-keys", "pasted-admin"),
    ] {
        let (status, response) = captured
            .run(m.send(
                who,
                Method::DELETE,
                &format!("{prefix}/{secret}"),
                request_id,
                None,
            ))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(response["reasonCode"], "broker_access_key_not_found");
        assert!(response.get("target").is_none_or(Value::is_null));
        assert!(!response.to_string().contains(secret));
    }
    assert!(
        !serde_json::to_string(&read_audit_records(&m.fixture.audit_path))
            .unwrap()
            .contains(secret)
    );
    assert!(
        !serde_json::to_string(&captured.take_events())
            .unwrap()
            .contains(secret)
    );
    assert_eq!(
        m.resolve("pasted-still-active", secret).await["active"],
        true
    );
    let id = issued["record"]["keyId"].as_str().unwrap();
    m.alice_ok(
        Method::DELETE,
        &format!("/v1/access-keys/{id}"),
        "pasted-valid-id",
        None,
    )
    .await;
    assert_eq!(
        m.resolve("pasted-now-revoked", secret).await["active"],
        false
    );
}

#[tokio::test]
async fn pasted_access_keys_are_not_recorded_as_other_identifiers() {
    let m = management().await;
    m.set_name("alice", "alice", "identifier-name").await;
    let issued = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "identifier-issue",
            issue_body("notebook", &["inference"], 600),
        )
        .await;
    let secret = issued["key"].as_str().unwrap();
    let captured = install_trace_capture().start();
    let name_path = "/v1/admin/principals/alice/account-username";
    let cases = [
        (
            Method::GET,
            format!("/v1/admin/access-keys?principal={secret}"),
            None,
        ),
        (
            Method::GET,
            format!("/v1/admin/access-keys?{secret}=true"),
            None,
        ),
        (
            Method::POST,
            format!("/v1/admin/principals/{secret}/access-keys"),
            issue_body("notebook", &["inference"], 600),
        ),
        (
            Method::GET,
            format!("/v1/admin/principals/{secret}/account-username"),
            None,
        ),
        (
            Method::PUT,
            format!("/v1/admin/principals/{secret}/account-username"),
            Some(json!({"mode":"manual", "accountUsername":"alice"})),
        ),
        (
            Method::POST,
            format!("/v1/admin/principals/{secret}/account-username/confirm"),
            Some(json!({"accountUsername":"alice"})),
        ),
        (
            Method::PUT,
            name_path.to_string(),
            Some(json!({"mode":"manual", "accountUsername":secret})),
        ),
        (
            Method::POST,
            format!("{name_path}/confirm"),
            Some(json!({"accountUsername":secret})),
        ),
        (
            Method::POST,
            "/v1/admin/principals/alice/access-keys".to_string(),
            issue_body("notebook", &[secret], 600),
        ),
        (
            Method::POST,
            "/v1/admin/principals/alice/access-keys".to_string(),
            issue_body(secret, &["inference"], 600),
        ),
    ];
    for (i, (method, uri, body)) in cases.into_iter().enumerate() {
        let (status, response) = captured
            .run(m.admin(method, &uri, &format!("pasted-identifier-{i}"), body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {i}");
        assert!(!response.to_string().contains(secret), "case {i}");
    }
    assert!(
        !serde_json::to_string(&read_audit_records(&m.fixture.audit_path))
            .unwrap()
            .contains(secret)
    );
    assert!(
        !serde_json::to_string(&captured.take_events())
            .unwrap()
            .contains(secret)
    );
    assert_eq!(
        m.resolve("identifiers-still-active", secret).await["active"],
        true
    );
}

#[tokio::test]
async fn broker_secrets_are_not_management_identifiers_or_usernames() {
    let m = management().await;
    m.set_name("alice", "alice", "secret-namespace-name").await;
    let issued = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "secret-namespace-issue",
            issue_body("notebook", &["inference"], 600),
        )
        .await;
    let key = issued["key"].as_str().unwrap();
    let captured = install_trace_capture().start();
    for (n, secret) in [
        key,
        &m.fixture.agent_tokens[0],
        &m.fixture.management_token,
        &m.fixture.admin_token,
    ]
    .into_iter()
    .enumerate()
    {
        let cases = [
            (
                Method::GET,
                format!("/v1/admin/access-keys?principal={secret}"),
                None,
            ),
            (
                Method::POST,
                format!("/v1/admin/principals/{secret}/access-keys"),
                issue_body("notebook", &["inference"], 600),
            ),
            (
                Method::GET,
                format!("/v1/admin/principals/{secret}/account-username"),
                None,
            ),
            (
                Method::PUT,
                format!("/v1/admin/principals/{secret}/account-username"),
                Some(json!({"mode":"manual", "accountUsername":"alice"})),
            ),
            (
                Method::POST,
                format!("/v1/admin/principals/{secret}/account-username/confirm"),
                Some(json!({"accountUsername":"alice"})),
            ),
            // These existing routes acquired username or access-key settings in this feature.
            (Method::GET, format!("/v1/admin/principals/{secret}"), None),
            (
                Method::PATCH,
                format!("/v1/admin/principals/{secret}"),
                Some(json!({"email":"alice@example.com"})),
            ),
            (
                Method::PATCH,
                format!("/v1/admin/principals/{secret}/access"),
                Some(json!({"accessKeyTypes":{"allow":["inference"],"deny":[]}})),
            ),
            (
                Method::POST,
                "/v1/admin/principals".into(),
                Some(json!({"principalId":secret,"kind":"service_account"})),
            ),
            (Method::GET, format!("/v1/admin/groups/{secret}"), None),
            (
                Method::PATCH,
                format!("/v1/admin/groups/{secret}"),
                Some(json!({"accessKeyTypes":{"allow":["inference"]}})),
            ),
            (
                Method::POST,
                "/v1/admin/groups".into(),
                Some(json!({"groupId":secret,"accessKeyTypes":{"allow":["inference"]}})),
            ),
            (
                Method::POST,
                "/v1/admin/principals/alice/access-keys".into(),
                issue_body(secret, &["inference"], 600),
            ),
            (
                Method::POST,
                "/v1/admin/principals/alice/access-keys".into(),
                issue_body("notebook", &[secret], 600),
            ),
        ];
        for (i, (method, uri, body)) in cases.into_iter().enumerate() {
            let (status, response) = captured
                .run(m.admin(method, &uri, &format!("secret-namespace-{n}-{i}"), body))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "class {n}, case {i}");
            assert!(
                !response.to_string().contains(secret),
                "class {n}, case {i}"
            );
        }
        for (i, (method, suffix, body)) in [
            (
                Method::PUT,
                "",
                json!({"mode":"manual", "accountUsername":secret}),
            ),
            (Method::POST, "/confirm", json!({"accountUsername":secret})),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, response) = captured
                .run(m.admin(
                    method,
                    &format!("/v1/admin/principals/alice/account-username{suffix}"),
                    &format!("secret-username-{n}-{i}"),
                    Some(body),
                ))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(response["details"]["refusal"], "name_invalid");
            assert!(!response.to_string().contains(secret));
        }
        assert!(
            !serde_json::to_string(&read_audit_records(&m.fixture.audit_path))
                .unwrap()
                .contains(secret)
        );
        assert!(
            !serde_json::to_string(&captured.take_events())
                .unwrap()
                .contains(secret)
        );
        let saved = m.store.principal_account_username("alice").unwrap();
        assert_eq!(saved.name.unwrap().account_username, "alice");
        let resolved = m
            .resolve(&format!("secret-namespace-resolution-{n}"), key)
            .await;
        assert_eq!(resolved["active"], true);
        assert!(!resolved.to_string().contains(secret));
    }
}

#[tokio::test]
async fn access_key_id_wrapping_a_broker_secret_is_not_echoed_or_audited() {
    let m = management().await;
    m.set_name("alice", "alice", "wrapped-secret-name").await;
    let issued = m
        .alice_ok(
            Method::POST,
            "/v1/access-keys",
            "wrapped-secret-issue",
            issue_body("notebook", &["inference"], 600),
        )
        .await;
    let key = issued["key"].as_str().unwrap();
    let captured = install_trace_capture().start();
    for (n, secret) in [
        key,
        &m.fixture.agent_tokens[0],
        &m.fixture.management_token,
        &m.fixture.admin_token,
    ]
    .into_iter()
    .enumerate()
    {
        for (i, (who, prefix)) in [
            (As::Browser { csrf: true }, "/v1/access-keys"),
            (As::Admin, "/v1/admin/access-keys"),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, response) = captured
                .run(m.send(
                    who,
                    Method::DELETE,
                    &format!("{prefix}/ak_{secret}"),
                    &format!("wrapped-secret-{n}-{i}"),
                    None,
                ))
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(response["reasonCode"], "broker_access_key_not_found");
            assert!(response.get("target").is_none_or(Value::is_null));
            assert!(!response.to_string().contains(secret));
        }
        assert!(
            !serde_json::to_string(&read_audit_records(&m.fixture.audit_path))
                .unwrap()
                .contains(secret)
        );
        assert!(
            !serde_json::to_string(&captured.take_events())
                .unwrap()
                .contains(secret)
        );
    }
    assert_eq!(
        m.resolve("wrapped-secret-active", key).await["active"],
        true
    );
    let id = issued["record"]["keyId"].as_str().unwrap();
    m.alice_ok(
        Method::DELETE,
        &format!("/v1/access-keys/{id}"),
        "wrapped-secret-valid",
        None,
    )
    .await;
    assert_eq!(
        m.resolve("wrapped-secret-revoked", key).await["active"],
        false
    );
}

#[tokio::test]
async fn issuance_routes_accept_offered_lifetime_strings_and_keep_null_expiry_in_every_projection()
{
    let (m, _) = reloadable(|config| {
        let inference = config.access_key_types.get_mut("inference").unwrap();
        inference.lifetime_options = vec!["never".into(), "60m".into()];
        inference.default_lifetime = "never".into();
    })
    .await;
    m.store
        .set_account_username("alice", "alice", "admin")
        .unwrap()
        .unwrap();
    for (who, path, list_path) in [
        (
            As::Admin,
            "/v1/admin/principals/alice/access-keys",
            "/v1/admin/access-keys?principal=alice",
        ),
        (
            As::Browser { csrf: true },
            "/v1/access-keys",
            "/v1/access-keys",
        ),
    ] {
        for lifetime in ["never", "1h"] {
            let (status, envelope) = m.send(who, Method::POST, path, "lifetime-issue",
                Some(json!({"name": "chosen lifetime", "accessKeyTypes": ["inference"], "lifetime": lifetime}))).await;
            assert_eq!(status, StatusCode::OK, "{envelope}");
            let issued = m.checked_result(envelope);
            let record = &issued["record"];
            assert!(record.as_object().unwrap().contains_key("expiresAt"));
            assert_eq!(record["expiresAt"].is_null(), lifetime == "never");
            let (status, listing) = m
                .send(who, Method::GET, list_path, "lifetime-list", None)
                .await;
            assert_eq!(status, StatusCode::OK, "{listing}");
            let listing = m.checked_result(listing);
            let listed = listing["keys"]
                .as_array()
                .unwrap()
                .iter()
                .find(|key| key["keyId"] == record["keyId"])
                .unwrap();
            assert_eq!(listed["expiresAt"], record["expiresAt"]);
            assert_eq!(
                listed["usableAccessKeyTypes"][0]["validUntil"],
                record["expiresAt"]
            );
        }
        for body in [
            json!({"name": "missing lifetime", "accessKeyTypes": ["inference"]}),
            json!({"name": "old lifetime", "accessKeyTypes": ["inference"], "lifetimeSeconds": 3600}),
            json!({"name": "numeric lifetime", "accessKeyTypes": ["inference"], "lifetime": 3600}),
            json!({"name": "null lifetime", "accessKeyTypes": ["inference"], "lifetime": null}),
            json!({"name": "dual lifetime", "accessKeyTypes": ["inference"], "lifetime": "1h", "lifetimeSeconds": 3600}),
        ] {
            let (status, envelope) = m
                .send(
                    who,
                    Method::POST,
                    path,
                    "invalid-lifetime-shape",
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}");
        }
        for lifetime in [
            "",
            "0s",
            "-1h",
            "1 h",
            "Never",
            "3651d",
            "18446744073709551615d",
            "aab_ak_must_not_echo",
        ] {
            let (status, envelope) = m.send(who, Method::POST, path, "malformed-lifetime",
                Some(json!({"name": "malformed duration", "accessKeyTypes": ["missing"], "lifetime": lifetime}))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}");
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(
                envelope["error"]["message"],
                "request body requires name, accessKeyTypes (a list of access key type IDs) and lifetime (a duration string or never)"
            );
            assert!(!envelope.to_string().contains("aab_ak_must_not_echo"));
        }
        let (status, envelope) = m.send(who, Method::POST, path, "unoffered-lifetime",
            Some(json!({"name": "short lifetime", "accessKeyTypes": ["inference"], "lifetime": "30m"}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}");
        assert_eq!(envelope["details"]["refusal"], "lifetime_not_offered");
        assert_eq!(envelope["details"]["accessKeyType"], "inference");
    }
}
