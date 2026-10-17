//! The audit query routes end to end: availability and catalog gating,
//! visibility tiers, cursor paging and binding, the not-audited success
//! path, and queries while audit writes fail.
use super::*;
use agent_access_core::{AuditQueryLimits, AuditRecord};
use agent_access_provider::Decision;

const ADMIN_EVENTS: &str = "/v1/admin/audit/events";
const SELF_EVENTS: &str = "/v1/audit/events";
const ADMIN_OPTIONS: &str = "/v1/admin/audit/options";
const SELF_OPTIONS: &str = "/v1/audit/options";
const CURSOR_INVALID: &str = "cursor is invalid or stale; repeat the request without cursor";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Backend {
    Sqlite,
    Jsonl,
    Disabled,
}

/// Managed identity and policy with SQLite (or other) audit: `admin`
/// (admin role), `bob` (service policy manager of `fake`), and `alice` and
/// `carol` (plain managed users).
pub(super) struct AuditFixture {
    pub(super) broker: TestBroker,
    pub(super) app: Router,
    pub(super) state: Arc<ReloadableState>,
    pub(super) audit_path: Option<PathBuf>,
    pub(super) admin: String,
    pub(super) alice: String,
    pub(super) alice_agent: String,
    pub(super) bob: String,
    pub(super) carol: String,
}

pub(super) async fn audit_fixture(backend: Backend) -> AuditFixture {
    audit_fixture_with(backend, |_, _| {}).await
}

pub(super) async fn audit_fixture_with(
    backend: Backend,
    configure: impl FnOnce(&mut BrokerConfig, Option<&Path>),
) -> AuditFixture {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let hash_key_path = temp_path("audit-query-hash-key");
    let store_path = temp_path("audit-query-store.sqlite");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([43_u8; 32])).unwrap();
    let audit_path = match backend {
        Backend::Sqlite => Some(temp_path("audit-query.audit.sqlite")),
        Backend::Jsonl => Some(temp_path("audit-query.audit.jsonl")),
        Backend::Disabled => None,
    };
    let mut config = fake_config(
        audit_path
            .as_deref()
            .map(|path| path.to_str().unwrap())
            .unwrap_or(""),
    );
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
    let managed_store = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store.clone());
    config.management.enabled = true;
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.policy = PolicyConfig {
        resources: vec![],
        resource_groups: vec![],
        authority: "managed".to_string(),
        default_decision: "deny".to_string(),
        grants: vec![],
    };
    configure(&mut config, audit_path.as_deref());

    let store = agent_access_core::ManagedStore::open(
        &managed_store,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    seed_managed_fixture_resources(&store);
    for principal in ["admin", "alice", "bob", "carol"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: Some(agent_access_core::PrincipalRole::ServicePolicyManager),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    store
        .put_service_policy_management_assignment(
            agent_access_core::ServicePolicyManagementAssignmentPutRequest {
                service: "fake".to_string(),
                principal_id: "bob".to_string(),
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: agent_access_core::BrokerTokenClass| {
        let scopes = if token_class == agent_access_core::BrokerTokenClass::AgentInvoke {
            json!({"allowedExecutionContexts": ["default"]})
        } else {
            json!({})
        };
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} audit fixture"),
                    token_class,
                    scopes,
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    use agent_access_core::BrokerTokenClass::{Admin, AgentInvoke, UserManage};
    let admin = issue("admin", Admin);
    let alice = issue("alice", UserManage);
    let alice_agent = issue("alice", AgentInvoke);
    let bob = issue("bob", UserManage);
    let carol = issue("carol", UserManage);
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    let state = broker.state();
    AuditFixture {
        app: broker.app(),
        broker,
        state,
        audit_path,
        admin,
        alice,
        alice_agent,
        bob,
        carol,
    }
}

impl AuditFixture {
    async fn get(&self, token: &str, uri: &str) -> (StatusCode, Value) {
        self.request(Method::GET, token, uri, None, "audit-query-request")
            .await
    }

    pub(super) async fn request(
        &self,
        method: Method,
        token: &str,
        uri: &str,
        body: Option<&str>,
        request_id: &str,
    ) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app.clone(),
            method,
            uri,
            request_id,
            "Authorization",
            format!("Bearer {token}"),
            body,
        )
        .await;
        (response.status(), response_json(response).await)
    }

    async fn items(&self, token: &str, uri: &str) -> Vec<Value> {
        let (status, body) = self.get(token, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        body["result"]["items"].as_array().unwrap().clone()
    }

    pub(super) fn records(&self) -> Vec<Value> {
        read_audit_records(self.audit_path.as_deref().unwrap())
    }

    async fn append(&self, record: AuditRecord) {
        self.state
            .current()
            .runtime
            .append_audit_record(&record)
            .await
            .unwrap();
    }
}

fn synthetic(id: &str, seconds: i64, principal: &str, service: &str, action: &str) -> AuditRecord {
    AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: timestamp(seconds),
        agent_request_id: format!("agent-{id}"),
        broker_request_id: id.to_string(),
        config_generation: None,
        policy_generation: None,
        principal: principal.to_string(),
        principal_subject: None,
        groups: vec![],
        service: service.to_string(),
        action: action.to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: None,
        credential_connection: None,
        decision: Decision::Allow,
        reason_code: None,
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: None,
        source: SourceContext::unknown(),
        execution_context: None,
        provider_audit: None,
    }
}

/// One recent epoch per test process preserves exact ordering and cursor bounds
/// across appends/reloads without aging out of the real retention/query window.
fn timestamp(seconds: i64) -> String {
    static EPOCH: OnceLock<chrono::DateTime<chrono::Utc>> = OnceLock::new();
    let epoch = EPOCH.get_or_init(|| chrono::Utc::now() - chrono::Duration::hours(1));
    (*epoch + chrono::Duration::seconds(seconds)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn request_ids(items: &[Value]) -> Vec<&str> {
    items
        .iter()
        .map(|item| item["brokerRequestId"].as_str().unwrap())
        .collect()
}

fn query_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn has_route(document: &Value, route: &str) -> bool {
    document["routes"]
        .as_array()
        .map(|routes| routes.iter().any(|candidate| candidate["route"] == route))
        .unwrap_or_else(|| document["paths"].get(route).is_some())
}

fn send_has_route(send: &Value, route: &str) -> bool {
    send["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .any(|variant| variant["properties"]["route"]["const"] == route)
}

const AUDIT_ROUTES: [&str; 6] = [
    ADMIN_OPTIONS,
    "/v1/admin/audit/events",
    "/v1/admin/audit/requests/{brokerRequestId}",
    SELF_OPTIONS,
    "/v1/audit/events",
    "/v1/audit/requests/{brokerRequestId}",
];

/// The caller's catalog, OpenAPI projection, and send schema.
async fn spec_documents(fixture: &AuditFixture, token: &str, query: &str) -> [Value; 3] {
    let mut documents = Vec::new();
    for path in [
        "/v1/spec/catalog",
        "/v1/spec/openapi.json",
        "/v1/spec/send-schema.json",
    ] {
        let response = spec_get(
            fixture.app.clone(),
            &format!("{path}{query}"),
            "audit-query-spec",
            Some(token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        documents.push(response_json(response).await);
    }
    documents.try_into().unwrap()
}

async fn audit_routes_in_specs(
    fixture: &AuditFixture,
    token: &str,
    query: &str,
) -> Vec<&'static str> {
    let [catalog, openapi, send] = spec_documents(fixture, token, query).await;
    let visible = AUDIT_ROUTES
        .into_iter()
        .filter(|route| has_route(&catalog, route))
        .collect::<Vec<_>>();
    for route in AUDIT_ROUTES {
        assert_eq!(
            has_route(&openapi, route),
            visible.contains(&route),
            "{route}"
        );
        assert_eq!(
            send_has_route(&send, route),
            visible.contains(&route),
            "{route}"
        );
    }
    visible
}

#[tokio::test]
async fn audit_query_routes_exist_only_with_sqlite_audit_and_management() {
    let sqlite = audit_fixture(Backend::Sqlite).await;
    assert_eq!(
        audit_routes_in_specs(&sqlite, &sqlite.admin, "").await,
        [
            ADMIN_OPTIONS,
            "/v1/admin/audit/events",
            "/v1/admin/audit/requests/{brokerRequestId}"
        ]
    );
    assert_eq!(
        audit_routes_in_specs(&sqlite, &sqlite.admin, "?visibility=all").await,
        AUDIT_ROUTES
    );
    assert_eq!(
        audit_routes_in_specs(&sqlite, &sqlite.alice, "").await,
        [
            SELF_OPTIONS,
            "/v1/audit/events",
            "/v1/audit/requests/{brokerRequestId}"
        ]
    );
    assert_eq!(
        audit_routes_in_specs(&sqlite, &sqlite.bob, "").await,
        AUDIT_ROUTES
    );
    let [catalog, _, _] = spec_documents(&sqlite, &sqlite.bob, "").await;
    let route = catalog["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["route"] == ADMIN_EVENTS)
        .unwrap();
    assert_eq!(route["operation"], "admin.audit.events.list");
    assert_eq!(route["access"], "policy_read");
    assert_eq!(route["requiredFeature"], "audit_query");
    assert!(route["resultSchema"]["properties"]["nextCursor"].is_object());

    for backend in [Backend::Jsonl, Backend::Disabled] {
        let fixture = audit_fixture(backend).await;
        for (token, query) in [
            (&fixture.admin, ""),
            (&fixture.admin, "?visibility=all"),
            (&fixture.alice, ""),
            (&fixture.bob, ""),
        ] {
            assert!(
                audit_routes_in_specs(&fixture, token, query)
                    .await
                    .is_empty()
            );
        }
        let uuid = "0b5d4a4e-2b4e-4d67-9d5b-0a0f3f1c2d3e";
        for (token, uri) in [
            (&fixture.admin, ADMIN_OPTIONS.to_string()),
            (&fixture.alice, SELF_OPTIONS.to_string()),
            (&fixture.admin, ADMIN_EVENTS.to_string()),
            (&fixture.bob, format!("/v1/admin/audit/requests/{uuid}")),
            (&fixture.alice, SELF_EVENTS.to_string()),
            (&fixture.alice, format!("/v1/audit/requests/{uuid}")),
        ] {
            let (status, body) = fixture.get(token, &uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body["reasonCode"], "audit_query_unavailable");
            assert_eq!(body["decision"], "deny");
        }
        // The unavailable response is audited like any management error.
        if backend == Backend::Jsonl {
            assert!(fixture.records().iter().any(|record| {
                record["action"] == "admin.audit.events.list"
                    && record["reasonCode"] == "audit_query_unavailable"
                    && record["principal"] == "admin"
            }));
        }
    }

    // Management disabled keeps today's response.
    let disabled = audit_fixture_with(Backend::Sqlite, |config, _| {
        config.management.enabled = false;
    })
    .await;
    for route in [ADMIN_EVENTS, ADMIN_OPTIONS, SELF_OPTIONS] {
        let (status, body) = disabled.get(&disabled.admin, route).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["reasonCode"], "management_denied");
        assert_eq!(body["error"]["message"], "management routes are disabled");
    }
}

#[tokio::test]
async fn the_browser_session_reports_whether_audit_is_queryable() {
    for (backend, expected) in [("sqlite", true), ("jsonl", false), ("disabled", false)] {
        let fixture = browser_rate_fixture_with(test_limits(), |config| {
            let path = temp_path(&format!("session-audit.audit.{backend}"));
            config.audit = match backend {
                "sqlite" => Some(agent_access_core::AuditConfig::new(
                    agent_access_core::AuditStoreType::Sqlite,
                    path.display().to_string(),
                )),
                "jsonl" => Some(agent_access_core::AuditConfig::new(
                    agent_access_core::AuditStoreType::Jsonl,
                    path.display().to_string(),
                )),
                _ => None,
            };
        })
        .await;
        let session = fixture
            .browser_request(Method::GET, "/v1/auth/session", None)
            .await;
        assert_eq!(session.status(), StatusCode::OK);
        let session = response_json(session).await;
        assert_eq!(session["result"]["auditQueryable"], expected, "{backend}");
    }
}

#[tokio::test]
async fn browser_sessions_read_audit_without_the_csrf_header() {
    let fixture = browser_rate_fixture(test_limits()).await;
    for uri in [
        SELF_OPTIONS.to_string(),
        "/v1/audit/events".to_string(),
        format!("/v1/audit/requests/{}", uuid::Uuid::new_v4()),
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&uri)
                    .extension(ConnectInfo(
                        "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "audit-query-cookie")
                    .header("Cookie", &fixture.cookie)
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response_json(response).await;
        assert_ne!(body["reasonCode"], "csrf_invalid", "{uri}: {body}");
        assert!(
            status == StatusCode::OK || body["reasonCode"] == "audit_request_not_found",
            "{uri}: {body}"
        );
    }
}

#[tokio::test]
async fn visibility_follows_admin_service_manager_and_self_tiers() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    // Real requests: the admin grants alice fake.echo (policy records
    // scoped to fake), alice invokes it with her agent token and issues
    // herself a token (no scope service), and bob manages a grant for fake.
    let (status, _) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/policy/grants",
            Some(
                r#"{"subjects":["user:alice"],"executionContexts":["default"],"service":"fake",
                   "actions":["echo"],"resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                   "credentialMode":"service"}"#,
            ),
            "audit-scope-admin-grant",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, invoked) = fixture
        .request(
            Method::POST,
            &fixture.alice_agent,
            "/v1/invoke/fake/echo",
            Some(r#"{"inputs":{"project":"TEST","message":"hello"}}"#),
            "audit-scope-alice-invoke",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{invoked}");
    let invocation = invoked["brokerRequestId"].as_str().unwrap().to_string();
    let (status, issued) = fixture
        .request(
            Method::POST,
            &fixture.alice,
            "/v1/tokens",
            Some(r#"{"name":"alice scope","ttl":"8h","allowedExecutionContexts":["default"]}"#),
            "audit-scope-alice-token-issue",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token_issue = issued["brokerRequestId"].as_str().unwrap().to_string();
    let (status, _) = fixture
        .request(
            Method::POST,
            &fixture.bob,
            "/v1/admin/policy/grants",
            Some(
                r#"{"subjects":["user:bob"],"executionContexts":["default"],"service":"fake",
                   "actions":["echo"],"resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},
                   "credentialMode":"service"}"#,
            ),
            "audit-scope-bob-grant",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // A gateway record for another service.
    let gateway = uuid::Uuid::new_v4().to_string();
    fixture
        .append(synthetic(
            &gateway,
            0,
            "carol",
            "gitlab_git",
            "git.upload_pack",
        ))
        .await;

    // Admins see everything.
    let all = fixture.items(&fixture.admin, ADMIN_EVENTS).await;
    let all_ids = request_ids(&all);
    for id in [&invocation, &token_issue, &gateway] {
        assert!(all_ids.contains(&id.as_str()), "{id}");
    }
    assert!(all.iter().any(|record| record["principal"] == "bob"));

    // Bob sees exactly the records scoped to fake, including policy
    // records that name it as their target, and nothing without a scope.
    let managed = fixture.items(&fixture.bob, ADMIN_EVENTS).await;
    assert!(!managed.is_empty());
    for record in &managed {
        let scope = if record["service"] == "broker" {
            record["providerAudit"]["management"]["targetService"].clone()
        } else {
            record["service"].clone()
        };
        assert_eq!(scope, "fake", "{record}");
    }
    let managed_ids = request_ids(&managed);
    assert!(managed_ids.contains(&invocation.as_str()));
    assert!(!managed_ids.contains(&token_issue.as_str()));
    assert!(!managed_ids.contains(&gateway.as_str()));
    assert!(managed.iter().any(|record| {
        record["principal"] == "admin" && record["action"] == "admin.policy.grants.create"
    }));
    assert!(managed.iter().any(|record| {
        record["principal"] == "bob"
            && record["providerAudit"]["management"]["phase"] == "preflight"
    }));
    // Filters cannot widen the tier.
    assert!(
        fixture
            .items(
                &fixture.bob,
                &format!("{ADMIN_EVENTS}?scopeService=gitlab_git")
            )
            .await
            .is_empty()
    );

    // Timelines apply the same visibility.
    async fn timeline(
        fixture: &AuditFixture,
        token: &str,
        id: &str,
        admin: bool,
    ) -> (StatusCode, Value) {
        let prefix = if admin {
            "/v1/admin/audit"
        } else {
            "/v1/audit"
        };
        fixture.get(token, &format!("{prefix}/requests/{id}")).await
    }
    let (status, body) = timeline(&fixture, &fixture.bob, &gateway, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reasonCode"], "audit_request_not_found");
    let (status, body) = timeline(&fixture, &fixture.admin, &gateway, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["operation"], "admin.audit.requests.inspect");
    assert_eq!(body["result"]["brokerRequestId"], gateway);
    assert_eq!(body["result"]["items"].as_array().unwrap().len(), 1);
    let (status, body) = timeline(&fixture, &fixture.bob, &invocation, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["items"][0]["principal"], "alice");

    // Alice sees her own records, including those without a scope
    // service, and nobody else's.
    let own = fixture.items(&fixture.alice, SELF_EVENTS).await;
    assert!(own.iter().all(|record| record["principal"] == "alice"));
    let own_ids = request_ids(&own);
    assert!(own_ids.contains(&invocation.as_str()));
    assert!(own_ids.contains(&token_issue.as_str()));
    let (status, body) = timeline(&fixture, &fixture.alice, &invocation, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["operation"], "audit.requests.inspect");
    let (status, body) = timeline(&fixture, &fixture.alice, &gateway, false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reasonCode"], "audit_request_not_found");
    let (status, body) = fixture
        .get(&fixture.alice, &format!("{SELF_EVENTS}?principal=bob"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reasonCode"], "input_invalid");
    // The agent token's records are alice's own.
    let by_token = fixture
        .items(
            &fixture.alice,
            &format!("{SELF_EVENTS}?requestId={invocation}"),
        )
        .await;
    assert_eq!(by_token.len(), 1);
    assert_eq!(by_token[0]["identitySource"]["tokenClass"], "agent_invoke");

    // Everyone else gets today's denials.
    for (token, uri, reason) in [
        (&fixture.carol, ADMIN_EVENTS, "management_denied"),
        (&fixture.alice, ADMIN_EVENTS, "management_denied"),
        (
            &fixture.alice_agent,
            ADMIN_EVENTS,
            "broker_token_class_denied",
        ),
        (
            &fixture.alice_agent,
            SELF_EVENTS,
            "broker_token_class_denied",
        ),
        (&fixture.admin, SELF_EVENTS, "broker_token_class_denied"),
    ] {
        let (status, body) = fixture.get(token, uri).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert_eq!(body["reasonCode"], reason, "{uri}");
    }
}

#[tokio::test]
async fn timelines_validate_the_request_id_and_parameters() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let id = uuid::Uuid::new_v4().to_string();
    fixture
        .append(synthetic(&id, 20, "alice", "fake", "echo"))
        .await;
    fixture
        .append(synthetic(&id, 10, "alice", "fake", "echo"))
        .await;
    let (status, body) = fixture
        .get(&fixture.admin, "/v1/admin/audit/requests/not-a-uuid")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reasonCode"], "input_invalid");
    let (status, body) = fixture
        .get(
            &fixture.admin,
            &format!("/v1/admin/audit/requests/{id}?limit=5"),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reasonCode"], "input_invalid");
    // Upper-case UUIDs name the same request; records come oldest first.
    let (status, body) = fixture
        .get(
            &fixture.admin,
            &format!("/v1/admin/audit/requests/{}", id.to_uppercase()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["brokerRequestId"], id);
    let items = body["result"]["items"].as_array().unwrap();
    assert_eq!(items[0]["timestamp"], timestamp(10));
    assert_eq!(items[1]["timestamp"], timestamp(20));
}

#[tokio::test]
async fn cursors_continue_with_the_first_request_bounds_and_bind_route_and_caller() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    for (id, seconds) in [("p1", 10), ("p2", 20), ("p3", 30), ("p4", 40), ("p5", 50)] {
        fixture
            .append(synthetic(id, seconds, "pager", "fake", "echo"))
            .await;
    }
    let first_uri = format!(
        "{ADMIN_EVENTS}?principal=pager&from={}&to={}&limit=2",
        query_encode(&timestamp(0)),
        query_encode(&timestamp(100))
    );
    let (status, first) = fixture.get(&fixture.admin, &first_uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["operation"], "admin.audit.events.list");
    assert_eq!(first["principal"], "admin");
    assert_eq!(
        request_ids(first["result"]["items"].as_array().unwrap()),
        ["p5", "p4"]
    );
    let cursor = first["result"]["nextCursor"].as_str().unwrap().to_string();
    assert!(cursor.len() <= 4096);

    // Written after the first page: newer records, a late record with an
    // older timestamp, and records outside the first request's bounds.
    for (id, seconds) in [
        ("newer", 60),
        ("late", 35),
        ("after-to", 150),
        ("before-from", -10),
    ] {
        fixture
            .append(synthetic(id, seconds, "pager", "fake", "echo"))
            .await;
    }
    let (status, second) = fixture
        .get(
            &fixture.admin,
            &format!("{ADMIN_EVENTS}?cursor={cursor}&limit=2"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        request_ids(second["result"]["items"].as_array().unwrap()),
        ["late", "p3"]
    );
    let cursor = second["result"]["nextCursor"].as_str().unwrap().to_string();
    // Without limit the default applies; the bounds still come from the
    // cursor, so the pages end at `from`.
    let (status, third) = fixture
        .get(&fixture.admin, &format!("{ADMIN_EVENTS}?cursor={cursor}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        request_ids(third["result"]["items"].as_array().unwrap()),
        ["p2", "p1"]
    );
    assert!(third["result"]["nextCursor"].is_null());

    // Only limit may accompany a cursor.
    let (status, body) = fixture
        .get(
            &fixture.admin,
            &format!("{ADMIN_EVENTS}?cursor={cursor}&principal=pager"),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reasonCode"], "input_invalid");
    assert_eq!(
        body["error"]["message"],
        "cursor may be combined only with limit"
    );

    // Another caller, another route, or a malformed cursor is stale.
    for (token, route, cursor) in [
        (&fixture.bob, ADMIN_EVENTS, cursor.as_str()),
        (&fixture.alice, SELF_EVENTS, cursor.as_str()),
        (&fixture.admin, ADMIN_EVENTS, "not-a-cursor"),
    ] {
        let (status, body) = fixture
            .get(token, &format!("{route}?cursor={cursor}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["reasonCode"], "input_invalid");
        assert_eq!(body["error"]["message"], CURSOR_INVALID);
    }

    // Self-route cursors work the same way for the caller's own records.
    for (id, seconds) in [("own1", 10), ("own2", 20), ("own3", 30)] {
        fixture
            .append(synthetic(id, seconds, "alice", "broker", "tokens.list"))
            .await;
    }
    let (status, page) = fixture
        .get(
            &fixture.alice,
            &format!("{SELF_EVENTS}?action=tokens.*&limit=2"),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        request_ids(page["result"]["items"].as_array().unwrap()),
        ["own3", "own2"]
    );
    let cursor = page["result"]["nextCursor"].as_str().unwrap();
    let (status, page) = fixture
        .get(&fixture.alice, &format!("{SELF_EVENTS}?cursor={cursor}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        request_ids(page["result"]["items"].as_array().unwrap()),
        ["own1"]
    );
    let (status, _) = fixture
        .get(&fixture.admin, &format!("{ADMIN_EVENTS}?cursor={cursor}"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn successful_queries_are_neither_audited_nor_logged() {
    let captured = install_trace_capture().start();
    let fixture = audit_fixture(Backend::Sqlite).await;
    let id = uuid::Uuid::new_v4().to_string();
    for seconds in [10, 20, 30] {
        fixture
            .append(synthetic(&id, seconds, "alice", "fake", "echo"))
            .await;
    }
    let before = fixture.records().len();
    let secret = "zebra-secret-words";
    let (status, first) = captured
        .run(fixture.request(
            Method::GET,
            &fixture.admin,
            &format!("{ADMIN_EVENTS}?service=fake&q={secret}+OR+echo&limit=1"),
            None,
            "audit-quiet-list",
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(first["result"]["items"].as_array().unwrap().is_empty());
    let (status, first) = captured
        .run(fixture.request(
            Method::GET,
            &fixture.admin,
            &format!("{ADMIN_EVENTS}?service=fake&q=echo&limit=1"),
            None,
            "audit-quiet-first",
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let cursor = first["result"]["nextCursor"].as_str().unwrap().to_string();
    let (status, _) = captured
        .run(fixture.request(
            Method::GET,
            &fixture.admin,
            &format!("{ADMIN_EVENTS}?cursor={cursor}"),
            None,
            "audit-quiet-next",
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    for (token, uri, request_id) in [
        (
            &fixture.admin,
            format!("/v1/admin/audit/requests/{id}"),
            "audit-quiet-timeline",
        ),
        (&fixture.alice, SELF_EVENTS.to_string(), "audit-quiet-self"),
        (
            &fixture.alice,
            format!("/v1/audit/requests/{id}"),
            "audit-quiet-self-timeline",
        ),
    ] {
        let (status, _) = captured
            .run(fixture.request(Method::GET, token, &uri, None, request_id))
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}");
    }
    assert_eq!(fixture.records().len(), before);
    // A query on the same routes whose stored record cannot be read is
    // logged, so the capture observes how these routes are handled. The
    // database work itself runs in the request's span on the audit reader's
    // blocking thread (core `query_work_runs_in_the_callers_span`).
    let unreadable = uuid::Uuid::new_v4().to_string();
    fixture
        .append(synthetic(&unreadable, 40, "alice", "fake", "echo"))
        .await;
    let store = rusqlite::Connection::open(fixture.audit_path.as_deref().unwrap()).unwrap();
    store.busy_timeout(Duration::from_secs(10)).unwrap();
    store
        .execute(
            "UPDATE audit_events SET record_json = 'not json' WHERE broker_request_id = ?1",
            [&unreadable],
        )
        .unwrap();
    let (status, failed) = captured
        .run(fixture.request(
            Method::GET,
            &fixture.admin,
            &format!("/v1/admin/audit/requests/{unreadable}"),
            None,
            "audit-failed-control",
        ))
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{failed}");

    // No replacement log event either: nothing names these requests, the
    // search text, or the cursor.
    let events = captured.take_events();
    event_by_name_and_agent(&events, "audit_query_failed", "audit-failed-control");
    let quiet = [
        "audit-quiet-list",
        "audit-quiet-first",
        "audit-quiet-next",
        "audit-quiet-timeline",
        "audit-quiet-self",
        "audit-quiet-self-timeline",
    ];
    assert!(
        events.iter().all(|event| {
            string_field(event, "agentRequestId").is_none_or(|id| !quiet.contains(&id))
        }),
        "{events:?}"
    );
    let logged = serde_json::to_string(&events).unwrap();
    assert!(!logged.contains(secret));
    assert!(!logged.contains(&cursor));
}

#[tokio::test]
async fn denied_and_invalid_audit_queries_are_audited() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let secret = "private-search-text";
    for (token, uri, status, reason) in [
        (
            &fixture.carol,
            ADMIN_OPTIONS.to_string(),
            403,
            "management_denied",
        ),
        (
            &fixture.alice_agent,
            SELF_OPTIONS.to_string(),
            403,
            "broker_token_class_denied",
        ),
        (
            &fixture.admin,
            SELF_OPTIONS.to_string(),
            403,
            "broker_token_class_denied",
        ),
        (
            &fixture.bob,
            format!("{ADMIN_OPTIONS}?service=fake"),
            400,
            "input_invalid",
        ),
        (
            &fixture.alice,
            format!("{SELF_OPTIONS}?principal=carol"),
            400,
            "input_invalid",
        ),
        (
            &fixture.carol,
            ADMIN_EVENTS.to_string(),
            403,
            "management_denied",
        ),
        (
            &fixture.alice_agent,
            SELF_EVENTS.to_string(),
            403,
            "broker_token_class_denied",
        ),
        (
            &fixture.admin,
            format!("{ADMIN_EVENTS}?limit=0"),
            400,
            "input_invalid",
        ),
        (
            &fixture.admin,
            format!("{ADMIN_EVENTS}?cursor=stale&q={secret}"),
            400,
            "input_invalid",
        ),
        (
            &fixture.admin,
            format!("{ADMIN_EVENTS}?cursor=stale"),
            400,
            "input_invalid",
        ),
        (
            &fixture.alice,
            format!("{SELF_EVENTS}?principal=alice"),
            400,
            "input_invalid",
        ),
        (
            &fixture.bob,
            format!("/v1/admin/audit/requests/{}", uuid::Uuid::new_v4()),
            404,
            "audit_request_not_found",
        ),
    ] {
        let (actual, body) = fixture.get(token, &uri).await;
        assert_eq!(actual.as_u16(), status, "{uri}: {body}");
        assert_eq!(body["reasonCode"], reason, "{uri}");
        let broker_request_id = body["brokerRequestId"].as_str().unwrap();
        let record = fixture
            .records()
            .into_iter()
            .find(|record| record["brokerRequestId"] == broker_request_id)
            .unwrap_or_else(|| panic!("{uri} is audited"));
        assert_eq!(record["reasonCode"], reason);
        assert_eq!(record["decision"], "deny");
    }
    // Neither the search text nor a cursor reaches the audit store.
    let text = read_audit_text(fixture.audit_path.as_deref().unwrap());
    assert!(!text.contains(secret));
    assert!(!text.contains("stale"));
}

#[tokio::test]
async fn busy_and_slow_audit_queries_fail_as_documented_and_are_audited() {
    let limited = audit_fixture_with(Backend::Sqlite, |_, path| {
        agent_access_core::test_support::override_audit_query_limits(
            path.unwrap(),
            AuditQueryLimits {
                connections: 0,
                waiting: 0,
                deadline: Duration::from_secs(5),
            },
        );
    })
    .await;
    for route in [ADMIN_EVENTS] {
        let (status, body) = limited.get(&limited.admin, route).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["reasonCode"], "concurrency_limited");
    }
    assert!(limited.records().iter().any(|record| {
        record["action"] == "admin.audit.events.list"
            && record["reasonCode"] == "concurrency_limited"
    }));

    let slow = audit_fixture_with(Backend::Sqlite, |_, path| {
        agent_access_core::test_support::override_audit_query_limits(
            path.unwrap(),
            AuditQueryLimits {
                deadline: Duration::ZERO,
                ..AuditQueryLimits::default()
            },
        );
    })
    .await;
    for (token, uri) in [
        (&slow.admin, ADMIN_EVENTS.to_string()),
        (
            &slow.alice,
            format!("/v1/audit/requests/{}", uuid::Uuid::new_v4()),
        ),
    ] {
        let (status, body) = slow.get(token, &uri).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(body["reasonCode"], "audit_query_timeout");
        assert_eq!(body["decision"], "error");
    }
    assert!(slow.records().iter().any(|record| {
        record["action"] == "audit.requests.inspect"
            && record["reasonCode"] == "audit_query_timeout"
            && record["decision"] == "error"
    }));
}

#[tokio::test]
async fn audit_queries_work_while_audit_writes_fail() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let id = uuid::Uuid::new_v4().to_string();
    fixture
        .append(synthetic(&id, 10, "alice", "fake", "echo"))
        .await;
    // Another connection holds the database's write lock, so every audit
    // append fails after the writer's busy timeout. Readers are unaffected.
    let blocker = rusqlite::Connection::open(fixture.audit_path.as_deref().unwrap()).unwrap();
    blocker.busy_timeout(Duration::from_secs(10)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    // A failed read is still audited, so it fails closed.
    let audited = {
        let app = fixture.app.clone();
        let token = fixture.alice.clone();
        tokio::spawn(async move {
            let response = authed_json_request(
                app,
                Method::GET,
                "/v1/tokens?includeRevoked=maybe",
                "audit-blocked-tokens",
                "Authorization",
                format!("Bearer {token}"),
                None,
            )
            .await;
            (response.status(), response_json(response).await)
        })
    };
    let started = Instant::now();
    let items = fixture.items(&fixture.admin, ADMIN_EVENTS).await;
    assert!(request_ids(&items).contains(&id.as_str()));
    let (status, _) = fixture
        .get(&fixture.alice, &format!("/v1/audit/requests/{id}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(started.elapsed() < Duration::from_secs(4));

    let (status, body) = audited.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reasonCode"], "audit_unavailable");
    blocker.execute_batch("ROLLBACK").unwrap();
}

#[tokio::test]
async fn config_status_reports_the_node_and_audit_store_without_its_path() {
    for (backend, expected) in [
        (
            Backend::Sqlite,
            json!({"type": "sqlite", "maintenanceFailure": null}),
        ),
        (Backend::Jsonl, json!({"type": "jsonl"})),
        (Backend::Disabled, Value::Null),
    ] {
        let fixture = audit_fixture(backend).await;
        let (status, body) = fixture.get(&fixture.admin, "/v1/admin/config/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["nodeId"], fixture.state.node_id());
        assert_eq!(body["result"]["audit"], expected);
        if let Some(path) = &fixture.audit_path {
            assert!(!body.to_string().contains(&path.display().to_string()));
        }
    }
}

#[tokio::test]
async fn cursors_are_bound_to_the_audit_database_across_reloads_and_restarts() {
    let captured = install_trace_capture().start();
    let config_path = temp_path("audit-cursor-reload.toml");
    let first_db = temp_path("audit-cursor-first.audit.sqlite");
    let second_db = temp_path("audit-cursor-second.audit.sqlite");
    let spool_dir = temp_path("audit-cursor-spool");
    let service_token = temp_path("audit-cursor-service-token");
    std::fs::write(&service_token, "service-token").unwrap();
    let write_config = |project: &str, audit_path: &Path| {
        write_reload_config(
            &config_path,
            project,
            audit_path,
            &service_token,
            &spool_dir,
            1024,
        );
    };
    write_config("TEST", &first_db);
    let state_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let state = state_broker.state();
    let records = ["c1", "c2", "c3"]
        .into_iter()
        .enumerate()
        .map(|(index, id)| synthetic(id, index as i64 * 10, "pager", "fake", "echo"))
        .collect::<Vec<_>>();
    for record in &records {
        state
            .current()
            .runtime
            .append_audit_record(record)
            .await
            .unwrap();
    }
    // Another database with the same records: the same insertion IDs and
    // timestamps.
    let creator = BrokerRuntime::new(fake_config(second_db.to_str().unwrap())).unwrap();
    for record in &records {
        creator.append_audit_record(record).await.unwrap();
    }
    creator
        .shutdown_own_audit(Duration::from_secs(5))
        .await
        .unwrap();
    drop(creator);

    let list = |broker: &TestBroker, query: String, request_id: &'static str| {
        let app = broker.app();
        async move {
            let response = admin_request(
                app,
                Method::GET,
                &format!("{ADMIN_EVENTS}?{query}"),
                Some(request_id),
                Some("admin-token"),
            )
            .await;
            (response.status(), response_json(response).await)
        }
    };
    let reload = |broker: &TestBroker, request_id: &'static str| {
        let app = broker.app();
        async move {
            let response = admin_request(
                app,
                Method::POST,
                "/v1/admin/config/reload",
                Some(request_id),
                Some("admin-token"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            response_json(response).await
        }
    };
    let (status, first) = list(
        &state_broker,
        "principal=pager&limit=1".to_string(),
        "audit-cursor-first",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        request_ids(first["result"]["items"].as_array().unwrap()),
        ["c3"]
    );
    let cursor = first["result"]["nextCursor"].as_str().unwrap().to_string();
    let continue_query = format!("cursor={cursor}&limit=1");

    // A reload of the same database keeps the cursor valid.
    write_config("NEXT", &first_db);
    let reloaded = captured
        .run(reload(&state_broker, "audit-cursor-reload-same"))
        .await;
    assert_eq!(reloaded["result"]["nodeId"], state.node_id());
    assert_eq!(
        reloaded["result"]["audit"],
        json!({"type": "sqlite", "maintenanceFailure": null})
    );
    let completed = event_by_name_and_agent(
        &captured.take_events(),
        "config_reload_completed",
        "audit-cursor-reload-same",
    )
    .clone();
    assert_eq!(
        string_field(&completed, "nodeId"),
        Some(state.node_id().as_str())
    );
    let (status, page) = list(&state_broker, continue_query.clone(), "audit-cursor-same").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        request_ids(page["result"]["items"].as_array().unwrap()),
        ["c2"]
    );

    // Another database rejects it, although its IDs and timestamps match.
    write_config("TEST", &second_db);
    reload(&state_broker, "audit-cursor-reload-other").await;
    let (status, page) = list(&state_broker, continue_query.clone(), "audit-cursor-other").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(page["error"]["message"], CURSOR_INVALID);

    // Back on the first database, and after a restart, it is valid again.
    write_config("NEXT", &first_db);
    reload(&state_broker, "audit-cursor-reload-back").await;
    let (status, page) = list(&state_broker, continue_query.clone(), "audit-cursor-back").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        request_ids(page["result"]["items"].as_array().unwrap()),
        ["c2"]
    );
    drop(state);
    state_broker.stop().await;
    let restarted_broker = reload_test_broker(config_path.clone(), Some(4096))
        .await
        .unwrap();
    let (status, page) = list(&restarted_broker, continue_query, "audit-cursor-restart").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        request_ids(page["result"]["items"].as_array().unwrap()),
        ["c2"]
    );
}

#[tokio::test]
async fn service_managers_see_admin_actions_on_their_services() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    // Admin-only actions that name `fake`: a manager assignment and a
    // per-principal service limit.
    let (status, designated) = fixture
        .request(
            Method::PATCH,
            &fixture.admin,
            "/v1/admin/principals/carol/access",
            Some(r#"{"role":"service_policy_manager"}"#),
            "audit-designate-carol",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{designated}");
    let (status, assigned) = fixture
        .request(
            Method::PUT,
            &fixture.admin,
            "/v1/admin/policy/services/fake/managers/carol",
            None,
            "audit-admin-manager-grant",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{assigned}");
    let assignment = assigned["brokerRequestId"].as_str().unwrap().to_string();
    let (status, limited) = fixture
        .request(
            Method::PUT,
            &fixture.admin,
            "/v1/admin/principals/alice/service-limits/fake",
            Some(r#"{"requests":10,"windowSeconds":60}"#),
            "audit-admin-service-limit",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{limited}");
    let limit = limited["brokerRequestId"].as_str().unwrap().to_string();
    // An admin action on another service, and a user's own self-service
    // action that names `fake`.
    let (_, other) = fixture
        .request(
            Method::PUT,
            &fixture.admin,
            "/v1/admin/principals/alice/service-limits/not-configured",
            Some(r#"{"requests":10,"windowSeconds":60}"#),
            "audit-admin-other-service",
        )
        .await;
    let other = other["brokerRequestId"].as_str().unwrap().to_string();
    let (_, own) = fixture
        .request(
            Method::GET,
            &fixture.alice,
            "/v1/credentials/connections/fake",
            None,
            "audit-self-credential",
        )
        .await;
    let own = own["brokerRequestId"].as_str().unwrap().to_string();

    // Admin records carry the service they act on as `targetService`;
    // self-service records do not.
    let all = fixture.items(&fixture.admin, ADMIN_EVENTS).await;
    let record = |id: &str| {
        all.iter()
            .find(|record| record["brokerRequestId"] == id)
            .unwrap_or_else(|| panic!("record {id} missing"))
            .clone()
    };
    for (id, action) in [
        (&assignment, "admin.policy.service_managers.grant"),
        (&limit, "admin.principals.service_limits.set"),
    ] {
        let record = record(id);
        assert_eq!(record["action"], action);
        assert_eq!(
            record["providerAudit"]["management"]["targetService"], "fake",
            "{record}"
        );
    }
    assert_eq!(
        record(&other)["providerAudit"]["management"]["targetService"],
        "not-configured"
    );
    let own_record = record(&own);
    assert_eq!(
        own_record["providerAudit"]["management"]["target"]["connection"],
        "fake"
    );
    assert!(
        own_record["providerAudit"]["management"]
            .get("targetService")
            .is_none(),
        "{own_record}"
    );

    // Bob manages `fake`: he sees the admin actions on it, but neither the
    // admin action on another service nor alice's own credential activity.
    let managed = fixture.items(&fixture.bob, ADMIN_EVENTS).await;
    let managed_ids = request_ids(&managed);
    assert!(managed_ids.contains(&assignment.as_str()));
    assert!(managed_ids.contains(&limit.as_str()));
    assert!(!managed_ids.contains(&other.as_str()));
    assert!(!managed_ids.contains(&own.as_str()));
}

#[tokio::test]
async fn audit_options_are_canonical_before_history_and_obey_audit_visibility() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    assert!(fixture.records().is_empty());
    let (status, global) = fixture.get(&fixture.admin, ADMIN_OPTIONS).await;
    assert_eq!(status, StatusCode::OK);
    let actions = global["result"]["services"][0]["actions"]
        .as_array()
        .unwrap();
    assert_eq!(global["result"]["services"].as_array().unwrap().len(), 1);
    assert_eq!(global["result"]["services"][0]["service"], "broker");
    for expected in [
        "auth.local.login",
        "auth.local.password.change",
        "auth.logout",
        "auth.session",
        "tokens.issue",
        "config.status",
        "config.reload",
        "oidc.login.succeeded",
        "oidc.login.failed",
        "admin.tokens.issue_principal_agent",
        "admin.credentials.put",
        "oauth.connections.callback",
        "status",
        "resource_types",
        "caller.authenticate",
    ] {
        assert!(actions.contains(&json!(expected)), "{expected}");
    }
    assert!(!actions.contains(&json!("admin.config.status")));
    assert!(!actions.contains(&json!("admin.principals.agent_tokens.issue")));
    // Activity can show failed admin calls and records from a previous role.
    let (status, own) = fixture.get(&fixture.alice, SELF_OPTIONS).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(own["result"], global["result"]);
    let (status, managed) = fixture.get(&fixture.bob, ADMIN_OPTIONS).await;
    assert_eq!(status, StatusCode::OK);
    let managed_actions = managed["result"]["services"][0]["actions"]
        .as_array()
        .unwrap();
    for expected in [
        "admin.policy.grants.create",
        "admin.policy.service_managers.grant",
        "admin.credentials.put",
        "admin.principals.service_limits.set",
        "admin.rights.grant",
    ] {
        assert!(managed_actions.contains(&json!(expected)), "{expected}");
    }
    for hidden in [
        "auth.local.login",
        "tokens.issue",
        "config.status",
        "admin.principals.create",
        "admin.credentials.rewrap",
        "status",
        "resource_types",
        "caller.authenticate",
    ] {
        assert!(!managed_actions.contains(&json!(hidden)), "{hidden}");
    }
    assert!(
        fixture.records().is_empty(),
        "successful metadata reads stay unaudited"
    );

    // Unknown/retired records do not become suggestions or displace canonical
    // names. Free text can still query them exactly, including beyond a page.
    for index in 0..210 {
        fixture
            .append(synthetic(
                &format!("junk-{index}"),
                index,
                "alice",
                "fake",
                &format!("unsupported.{index}"),
            ))
            .await;
    }
    fixture
        .append(synthetic(
            "old-login",
            -1,
            "alice",
            "broker",
            "auth.local.login",
        ))
        .await;
    let (_, after) = fixture.get(&fixture.admin, ADMIN_OPTIONS).await;
    assert_eq!(after["result"], global["result"]);
    let unknown = fixture
        .items(
            &fixture.alice,
            &format!("{SELF_EVENTS}?service=fake&action=unsupported.0"),
        )
        .await;
    assert_eq!(request_ids(&unknown), ["junk-0"]);
    let own = fixture
        .items(
            &fixture.alice,
            &format!("{SELF_EVENTS}?service=broker&action=auth.*"),
        )
        .await;
    assert_eq!(request_ids(&own), ["old-login"]);
    let mut scoped = synthetic(
        "scoped",
        220,
        "admin",
        "broker",
        "admin.policy.grants.create",
    );
    scoped.provider_audit = Some(json!({"management": {"targetService": "fake"}}));
    fixture.append(scoped).await;
    let broker = fixture
        .items(&fixture.bob, &format!("{ADMIN_EVENTS}?service=broker"))
        .await;
    assert_eq!(request_ids(&broker), ["scoped"]);
}

#[tokio::test]
async fn canonical_audit_options_never_acquire_an_audit_reader() {
    let fixture = audit_fixture_with(Backend::Sqlite, |_, path| {
        agent_access_core::test_support::override_audit_query_limits(
            path.unwrap(),
            AuditQueryLimits {
                connections: 0,
                waiting: 0,
                deadline: Duration::ZERO,
            },
        );
    })
    .await;
    for (token, route) in [
        (&fixture.admin, ADMIN_OPTIONS),
        (&fixture.bob, ADMIN_OPTIONS),
        (&fixture.alice, SELF_OPTIONS),
    ] {
        let (status, body) = fixture.get(token, route).await;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert!(
            !body["result"]["services"][0]["actions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    assert!(fixture.records().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn management_caller_rejections_use_broker_in_response_logs_and_audit_without_widening_visibility()
 {
    let captured = install_trace_capture().start();
    let fixture = audit_fixture_with(Backend::Sqlite, |config, _| {
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    // Bob is authorized for this management route, so admission reaches the
    // per-caller limiter. Alice would fail authorization before that guard.
    // Authenticated callers are exempt from authentication-attempt rate limits.
    let permit = fixture
        .state
        .shared_ingress
        .try_principal_concurrency("bob", 1)
        .unwrap();
    let (status, rejected) = captured
        .run(fixture.request(
            Method::GET,
            &fixture.bob,
            "/v1/admin/policy/grants",
            None,
            "management-caller-rejection",
        ))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{rejected}");
    assert_eq!(rejected["service"], "broker");
    assert_eq!(rejected["reasonCode"], "concurrency_limited");
    let id = rejected["brokerRequestId"].as_str().unwrap();
    let records = fixture.records();
    let record = records
        .iter()
        .find(|record| record["brokerRequestId"] == id)
        .unwrap();
    assert_eq!(record["service"], "broker");
    assert_eq!(record["principal"], "bob");
    assert!(record["providerAudit"]["management"]["targetService"].is_null());
    let events = captured.take_events();
    let event = event_by_name_and_agent(&events, "request_limited", "management-caller-rejection");
    assert_eq!(string_field(event, "service"), Some("broker"));
    assert_eq!(
        string_field(event, "limitKind"),
        Some("principal_concurrency")
    );

    drop(permit);
    let own = fixture
        .items(&fixture.bob, &format!("{SELF_EVENTS}?service=broker"))
        .await;
    assert!(request_ids(&own).contains(&id));
    let managed = fixture
        .items(&fixture.bob, &format!("{ADMIN_EVENTS}?service=broker"))
        .await;
    assert!(!request_ids(&managed).contains(&id));
}

#[tokio::test]
async fn management_authentication_rate_rejections_remain_anonymous_broker_events() {
    let fixture = audit_fixture_with(Backend::Sqlite, |config, _| {
        config.limits.auth_requests_per_source_per_minute = 1;
    })
    .await;
    let (status, _) = fixture
        .get("invalid-token", "/v1/admin/policy/grants")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, rejected) = fixture
        .get("invalid-token", "/v1/admin/policy/grants")
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{rejected}");
    assert_eq!(rejected["service"], "broker");
    assert_eq!(rejected["reasonCode"], "rate_limited");
    let id = rejected["brokerRequestId"].as_str().unwrap();
    for (token, route) in [(&fixture.alice, SELF_EVENTS), (&fixture.bob, ADMIN_EVENTS)] {
        let items = fixture
            .items(token, &format!("{route}?service=broker"))
            .await;
        assert!(!request_ids(&items).contains(&id));
    }
    let global = fixture
        .items(&fixture.admin, &format!("{ADMIN_EVENTS}?service=broker"))
        .await;
    let record = global
        .iter()
        .find(|record| record["brokerRequestId"] == id)
        .unwrap();
    assert_eq!(record["principal"], "anonymous");
    assert_eq!(record["service"], "broker");
}

#[tokio::test]
async fn anonymous_management_concurrency_rejections_remain_global_admin_only() {
    let fixture = audit_fixture_with(Backend::Sqlite, |config, _| {
        config.limits.max_concurrent_requests = 1;
    })
    .await;
    let permit = fixture
        .state
        .shared_ingress
        .try_global_concurrency(1)
        .unwrap();
    let (status, rejected) = fixture.get(&fixture.alice, "/v1/admin/policy/grants").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected["service"], "broker");
    assert_eq!(rejected["reasonCode"], "concurrency_limited");
    let id = rejected["brokerRequestId"].as_str().unwrap();
    drop(permit);
    let own = fixture
        .items(&fixture.alice, &format!("{SELF_EVENTS}?service=broker"))
        .await;
    assert!(!request_ids(&own).contains(&id));
    let managed = fixture
        .items(&fixture.bob, &format!("{ADMIN_EVENTS}?service=broker"))
        .await;
    assert!(!request_ids(&managed).contains(&id));
    let global = fixture
        .items(&fixture.admin, &format!("{ADMIN_EVENTS}?service=broker"))
        .await;
    let record = global
        .iter()
        .find(|record| record["brokerRequestId"] == id)
        .unwrap();
    assert_eq!(record["principal"], "anonymous");
}
