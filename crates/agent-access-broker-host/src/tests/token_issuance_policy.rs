//! Issuance permission is a creation gate; an issued read-only token keeps its
//! own ceiling while grants and account issuance settings change.
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::atomic::AtomicBool;

#[derive(Default)]
struct ProbeProvider {
    scopes: AtomicUsize,
    calls: AtomicUsize,
}

impl ProbeProvider {
    fn work(&self) -> (usize, usize) {
        (
            self.scopes.load(Ordering::SeqCst),
            self.calls.load(Ordering::SeqCst),
        )
    }
}

impl agent_access_provider::test_support::DescribedProvider for ProbeProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        for (action, read_only) in [("status.view", true), ("note.write", false)] {
            let mut added = descriptor.actions[0].clone();
            added.action = action.into();
            added.read_only = read_only;
            descriptor.actions.push(added);
        }
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for ProbeProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scopes.fetch_add(1, Ordering::SeqCst);
        Ok(ScopeResolution::resources(ResourceScopes::from([(
            "project".into(),
            vec![request.inputs()["project"].as_str().unwrap().into()],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderResult::new(json!({"action": request.action()})))
    }
}

struct Fixture {
    broker: TestBroker,
    app: Router,
    admin: String,
    alice: String,
    probe: Arc<ProbeProvider>,
    sequence: AtomicUsize,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        create_private_dir(directory.path());
        let key = directory.path().join("hash-key");
        std::fs::write(&key, URL_SAFE_NO_PAD.encode([83_u8; 32])).unwrap();
        let mut config = fake_config(directory.path().join("audit.jsonl").to_str().unwrap());
        config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
        config.identity = IdentityConfig {
            mode: "required".into(),
            authority: "managed".into(),
            sources: vec![IdentitySourceConfig {
                name: "broker".into(),
                kind: "broker_tokens".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                principals: vec![],
            }],
            groups: vec![],
            trusted_callers: Default::default(),
        };
        config.managed_store = Some(ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory
                .path()
                .join("managed.sqlite")
                .display()
                .to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: true,
        });
        config.broker_tokens = Some(BrokerTokensConfig {
            hash_key_ref: format!("file:{}", key.display()),
            default_agent_invoke_ttl: Some("8h".into()),
            default_user_manage_ttl: Some("8h".into()),
            ..Default::default()
        });
        config.management.enabled = true;
        config.policy = PolicyConfig {
            authority: "managed".into(),
            default_decision: "deny".into(),
            grants: vec![],
            resources: vec![],
            resource_groups: vec![],
        };
        config.mcp.enabled = true;
        config.mcp.public_url = Some("https://broker.example.test/mcp".into());
        let mut gateway = test_git_gateway_config();
        gateway.git.as_mut().unwrap().allow_push = true;
        config.gateways.insert("gitlab_git".into(), gateway);
        let upstream_key = directory.path().join("git-key");
        std::fs::write(&upstream_key, "synthetic-gateway-credential").unwrap();
        config.credentials.service.insert(
            "gitlab_git".into(),
            CredentialConfig {
                kind: "bearer_token".into(),
                token_ref: Some(format!("file:{}", upstream_key.display())),
                username_ref: None,
                provider: None,
                path: None,
                read_only: None,
                connection: None,
                profile: None,
            },
        );
        let store = ManagedStore::open(
            config.managed_store.as_ref().unwrap(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        seed_managed_fixture_resources(&store);
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: "admin".into(),
                kind: "user".into(),
                role: PrincipalRole::Admin,
                self_service_enabled: None,
                agent_token_issuance: Default::default(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
        let admin = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "admin".into(),
                    name: "fixture administration".into(),
                    token_class: BrokerTokenClass::Admin,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token;
        drop(store);
        let probe = Arc::new(ProbeProvider::default());
        let broker = TestBroker::start_with(with_provider_instances(
            TestBroker::config_builder(&config)
                .gateway_listener()
                .expect("loopback gateway listener"),
            [Arc::clone(&probe)],
        ))
        .await;
        let mut fixture = Self {
            app: broker.app(),
            broker,
            admin,
            alice: String::new(),
            probe,
            sequence: AtomicUsize::new(0),
            _directory: directory,
        };
        let created = fixture
            .admin_ok(
                Method::POST,
                "/v1/admin/principals",
                Some(json!({"principalId":"alice"})),
            )
            .await;
        assert_eq!(created["result"]["agentTokenIssuance"], "inherit");
        let setup = fixture
            .admin_ok(
                Method::POST,
                "/v1/admin/principals/alice/tokens",
                Some(json!({"name":"setup", "tokenClass":"user_manage"})),
            )
            .await;
        fixture.alice = setup["result"]["token"].as_str().unwrap().into();
        fixture
    }

    async fn request(
        &self,
        token: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let body = body.map(|value| value.to_string());
        let request_id = format!(
            "issuance-policy-{}",
            self.sequence.fetch_add(1, Ordering::SeqCst)
        );
        let response = authed_json_request(
            self.app.clone(),
            method,
            path,
            &request_id,
            "Authorization",
            format!("Bearer {token}"),
            body.as_deref(),
        )
        .await;
        let status = response.status();
        (status, response_json(response).await)
    }

    async fn ok(&self, token: &str, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, result) = self.request(token, method, path, body).await;
        assert_eq!(status, StatusCode::OK, "{path}: {result}");
        result
    }

    async fn admin_ok(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        self.ok(&self.admin, method, path, body).await
    }

    async fn policy(&self, mode: &str) {
        self.admin_ok(
            Method::PATCH,
            "/v1/admin/principals/alice/access",
            Some(json!({"agentTokenIssuance":mode})),
        )
        .await;
    }

    async fn grant(&self, service: &str, actions: &[&str], resource: &str) -> String {
        let response = self
            .admin_ok(
                Method::POST,
                "/v1/admin/policy/grants",
                Some(json!({
                    "subjects":["user:alice"], "executionContexts":["default"],
                    "service":service, "actions":actions,
                    "resources":{"resourceIds":[resource],"resourceGroupIds":[]},
                    "credentialMode":"service"
                })),
            )
            .await;
        response["result"]["grant"]["grantId"]
            .as_str()
            .unwrap()
            .into()
    }

    async fn issue(&self, read_only: bool) -> Value {
        self.ok(
            &self.alice,
            Method::POST,
            "/v1/tokens",
            Some(issue_body(read_only)),
        )
        .await["result"]
            .clone()
    }

    async fn invoke(&self, token: &str, action: &str, project: &str) -> (StatusCode, Value) {
        self.request(
            token,
            Method::POST,
            &format!("/v1/invoke/fake/{action}"),
            Some(json!({"inputs":{"project":project,"message":"test"}})),
        )
        .await
    }

    async fn initialize(&self, token: &str) -> String {
        let response = self
            .app
            .clone()
            .oneshot(mcp::request(
                Method::POST,
                Some(token),
                None,
                Some(json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                        "protocolVersion":"2025-11-25","capabilities":{},
                        "clientInfo":{"name":"issuance-policy-test","version":"1"}
                    }
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let result = mcp::rpc_body(response).await;
        assert!(
            result["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("This connection is read-only"),
            "{result}"
        );
        let initialized = self
            .app
            .clone()
            .oneshot(mcp::request(
                Method::POST,
                Some(token),
                Some(&session),
                Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            ))
            .await
            .unwrap();
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);
        session
    }

    async fn rpc(&self, token: &str, session: &str, method: &str, params: Value) -> Value {
        let response = self
            .app
            .clone()
            .oneshot(mcp::request(
                Method::POST,
                Some(token),
                Some(session),
                Some(json!({"jsonrpc":"2.0","id":2,"method":method,"params":params})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        mcp::rpc_body(response).await
    }
}

fn issue_body(read_only: bool) -> Value {
    json!({"name":"inherited access","allowedExecutionContexts":["default"],"readOnly":read_only})
}

#[tokio::test]
async fn default_denial_and_strict_input_precedence_keep_options_and_admin_issuance_available() {
    let fixture = Fixture::new().await;
    let (status, no_grants) = fixture
        .request(
            &fixture.alice,
            Method::POST,
            "/v1/tokens",
            Some(issue_body(true)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(no_grants["reasonCode"], "service_action_denied");
    fixture
        .grant("fake", &["echo", "note.write"], "project-test")
        .await;
    for read_only in [true, false] {
        let (status, denied) = fixture
            .request(
                &fixture.alice,
                Method::POST,
                "/v1/tokens",
                Some(issue_body(read_only)),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["reasonCode"], "token_issuance_denied");
        assert_eq!(denied["details"]["category"], "disabled");
    }
    let options = fixture
        .ok(&fixture.alice, Method::GET, "/v1/tokens/options", None)
        .await;
    assert_eq!(
        options["result"]["agentTokenIssuancePolicy"],
        json!({"mode":"disabled","source":"default","groupIds":[]})
    );
    assert_eq!(
        options["result"]["services"][0]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for invalid in [Value::Null, json!(0), json!("true")] {
        let mut body = issue_body(true);
        body["readOnly"] = invalid;
        let (status, result) = fixture
            .request(&fixture.alice, Method::POST, "/v1/tokens", Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        assert_eq!(result["reasonCode"], "input_invalid");
    }
    let mut missing = issue_body(true);
    missing.as_object_mut().unwrap().remove("readOnly");
    let (status, _) = fixture
        .request(&fixture.alice, Method::POST, "/v1/tokens", Some(missing))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut selected_write = issue_body(true);
    selected_write["allowedServices"] = json!(["fake"]);
    selected_write["serviceRestrictions"] = json!({"fake":{"actions":["note.write"]}});
    let (status, invalid) = fixture
        .request(
            &fixture.alice,
            Method::POST,
            "/v1/tokens",
            Some(selected_write),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
    assert_eq!(invalid["reasonCode"], "input_invalid");

    // Both administrative routes can issue for an owner whose personal policy denies.
    for read_only in [false, true] {
        let issued = fixture
            .admin_ok(
                Method::POST,
                "/v1/admin/principals/alice/agent-tokens",
                Some(issue_body(read_only)),
            )
            .await;
        assert_eq!(issued["result"]["record"]["scopes"]["readOnly"], read_only);
        let generic = fixture.admin_ok(Method::POST, "/v1/admin/principals/alice/tokens", Some(json!({"name":"admin generic","tokenClass":"agent_invoke","scopes":{"allowedExecutionContexts":["default"],"readOnly":read_only}}))).await;
        assert_eq!(generic["result"]["record"]["scopes"]["readOnly"], read_only);
    }
    for class in ["admin", "user_manage"] {
        let (status, invalid) = fixture.request(&fixture.admin, Method::POST, "/v1/admin/principals/admin/tokens", Some(json!({"name":"bad management scope","tokenClass":class,"scopes":{"readOnly":false}}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
    }
}

#[tokio::test]
async fn group_maximum_and_user_override_are_live_creation_controls_without_hiding_inventory() {
    let fixture = Fixture::new().await;
    fixture
        .grant("fake", &["echo", "note.write"], "project-test")
        .await;
    for (group, mode) in [("readers", "read_only"), ("writers", "write_capable")] {
        fixture
            .admin_ok(
                Method::POST,
                "/v1/admin/groups",
                Some(json!({"groupId":group,"agentTokenIssuance":mode})),
            )
            .await;
        fixture
            .admin_ok(
                Method::PUT,
                &format!("/v1/admin/groups/{group}/members/alice"),
                None,
            )
            .await;
    }
    let options = fixture
        .ok(&fixture.alice, Method::GET, "/v1/tokens/options", None)
        .await;
    assert_eq!(
        options["result"]["agentTokenIssuancePolicy"],
        json!({"mode":"write_capable","source":"groups","groupIds":["writers"]})
    );
    fixture.policy("read_only").await;
    let (status, denied) = fixture
        .request(
            &fixture.alice,
            Method::POST,
            "/v1/tokens",
            Some(issue_body(false)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["details"]["category"], "read_only_required");
    fixture.issue(true).await;
    fixture.policy("disabled").await;
    let (status, duplicate) = fixture.request(&fixture.admin, Method::POST, "/v1/admin/principals", Some(json!({"principalId":"alice","displayName":"Renamed","agentTokenIssuance":"write_capable"}))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{duplicate}");
    assert_eq!(duplicate["reasonCode"], "version_conflict");
    let account = fixture
        .admin_ok(Method::GET, "/v1/admin/principals/alice", None)
        .await;
    assert_eq!(account["result"]["agentTokenIssuance"], "disabled");
    let options = fixture
        .ok(&fixture.alice, Method::GET, "/v1/tokens/options", None)
        .await;
    assert_eq!(
        options["result"]["agentTokenIssuancePolicy"],
        json!({"mode":"disabled","source":"user","groupIds":[]})
    );
    assert_eq!(
        options["result"]["services"][0]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    fixture.policy("inherit").await;
    fixture
        .admin_ok(
            Method::PATCH,
            "/v1/admin/groups/writers",
            Some(json!({"status":"disabled"})),
        )
        .await;
    let options = fixture
        .ok(&fixture.alice, Method::GET, "/v1/tokens/options", None)
        .await;
    assert_eq!(
        options["result"]["agentTokenIssuancePolicy"],
        json!({"mode":"read_only","source":"groups","groupIds":["readers"]})
    );
}

#[tokio::test]
async fn inherited_read_only_token_gains_later_reads_and_preserves_open_mcp_after_policy_edits() {
    let fixture = Fixture::new().await;
    fixture.grant("fake", &["echo"], "project-test").await;
    fixture
        .admin_ok(
            Method::POST,
            "/v1/admin/groups",
            Some(json!({"groupId":"readers","agentTokenIssuance":"read_only"})),
        )
        .await;
    fixture
        .admin_ok(Method::PUT, "/v1/admin/groups/readers/members/alice", None)
        .await;
    let issued = fixture.issue(true).await;
    let token = issued["token"].as_str().unwrap();
    assert!(issued["record"]["scopes"].get("allowedServices").is_none());
    assert!(
        issued["record"]["scopes"]
            .get("serviceRestrictions")
            .is_none()
    );
    let session = fixture.initialize(token).await;
    let (status, _) = fixture.invoke(token, "status.view", "OPS").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let grant = fixture.grant("fake", &["status.view"], "project-ops").await;
    fixture.grant("fake", &["note.write"], "project-test").await;
    let (status, result) = fixture.invoke(token, "status.view", "OPS").await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let listing = fixture.rpc(token, &session, "tools/list", json!({})).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    let read_tool = tools
        .iter()
        .find(|tool| tool["name"].as_str().unwrap().ends_with("status_view"))
        .unwrap_or_else(|| panic!("{listing}"))["name"]
        .as_str()
        .unwrap();
    assert!(
        !tools
            .iter()
            .any(|tool| tool["name"].as_str().unwrap().contains("note_write"))
    );
    let mcp_read = fixture
        .rpc(
            token,
            &session,
            "tools/call",
            json!({"name":read_tool,"arguments":{"inputs":{"project":"OPS","message":"read"}}}),
        )
        .await;
    assert_eq!(
        mcp::structured(&mcp_read)["decision"],
        "allow",
        "{mcp_read}"
    );
    let before = fixture.probe.work();
    let (status, denied) = fixture.invoke(token, "note.write", "TEST").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["reasonCode"], "service_action_denied");
    assert_eq!(denied["error"]["message"], "broker token is read-only");
    assert_eq!(
        fixture.probe.work(),
        before,
        "denied writes must not resolve scopes or dispatch"
    );

    // Group policy is also issuance-only: an existing MCP owner stays admitted.
    fixture
        .admin_ok(
            Method::PATCH,
            "/v1/admin/groups/readers",
            Some(json!({"agentTokenIssuance":"disabled"})),
        )
        .await;
    let after_group_edit = fixture.rpc(token, &session, "tools/call", json!({"name":read_tool,"arguments":{"inputs":{"project":"OPS","message":"group policy changed"}}})).await;
    assert_eq!(
        mcp::structured(&after_group_edit)["decision"],
        "allow",
        "{after_group_edit}"
    );

    fixture.policy("write_capable").await;
    let writable = fixture.issue(false).await;
    fixture.policy("disabled").await;
    assert_eq!(
        fixture
            .invoke(writable["token"].as_str().unwrap(), "note.write", "TEST")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        fixture.invoke(token, "note.write", "TEST").await.0,
        StatusCode::FORBIDDEN
    );
    let still_open = fixture.rpc(token, &session, "tools/call", json!({"name":read_tool,"arguments":{"inputs":{"project":"OPS","message":"same session"}}})).await;
    assert_eq!(
        mcp::structured(&still_open)["decision"],
        "allow",
        "{still_open}"
    );
    let me = fixture.ok(token, Method::GET, "/v1/me", None).await;
    assert_eq!(me["brokerToken"], json!({"readOnly":true}));
    assert!(me.get("readOnlyAccess").is_none());
    let setup = fixture
        .ok(&fixture.alice, Method::GET, "/v1/me", None)
        .await;
    assert!(setup.get("brokerToken").is_none());
    fixture
        .admin_ok(
            Method::POST,
            &format!("/v1/admin/policy/grants/{grant}/disable"),
            Some(json!({"expectedVersion":1})),
        )
        .await;
    assert_eq!(
        fixture.invoke(token, "status.view", "OPS").await.0,
        StatusCode::FORBIDDEN
    );
    let after = fixture.rpc(token, &session, "tools/list", json!({})).await;
    assert!(
        !after["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == read_tool)
    );
}

#[tokio::test]
async fn inherited_read_only_token_may_start_without_a_current_read() {
    let fixture = Fixture::new().await;
    fixture.grant("fake", &["note.write"], "project-test").await;
    fixture.policy("read_only").await;
    let issued = fixture.issue(true).await;
    let token = issued["token"].as_str().unwrap();
    assert_eq!(
        fixture.invoke(token, "note.write", "TEST").await.0,
        StatusCode::FORBIDDEN
    );
    fixture.grant("fake", &["echo"], "project-test").await;
    assert_eq!(
        fixture.invoke(token, "echo", "TEST").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn issued_read_only_git_token_denies_push_discovery_and_post_before_pack_parsing() {
    let fixture = Fixture::new().await;
    fixture
        .grant(
            "gitlab_git",
            &["repo.fetch", "repo.push"],
            "repository-sip-service",
        )
        .await;
    fixture.policy("read_only").await;
    let issued = fixture.issue(true).await;
    let authorization = format!(
        "Basic {}",
        BASE64.encode(format!(
            "agent-access:{}",
            issued["token"].as_str().unwrap()
        ))
    );
    for (uri, status, reason) in [
        (
            "/sip/service.git/info/refs?service=git-upload-pack",
            StatusCode::BAD_GATEWAY,
            ReasonCode::GatewayUpstreamDenied,
        ),
        (
            "/sip/service.git/info/refs?service=git-receive-pack",
            StatusCode::FORBIDDEN,
            ReasonCode::ServiceActionDenied,
        ),
    ] {
        let response = gateway_get(
            fixture.broker.gateway_app(),
            uri,
            "git.example.test",
            "issuance-git-discovery",
            Some(&authorization),
        )
        .await;
        assert_eq!(response.status(), status, "{uri}");
        assert_eq!(response.headers()[REASON_CODE_HEADER], reason.as_str());
    }
    // Fetch reached the deliberately denied upstream destination above; it was
    // admitted by the read-only ceiling. No external network request is made.
    let polled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&polled);
    let body = Body::from_stream(stream::poll_fn(move |_| {
        observed.store(true, Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok::<Bytes, std::io::Error>(Bytes::from_static(
            b"invalid receive-pack body",
        ))))
    }));
    let response = gateway_request(GatewayRequestSpec {
        app: fixture.broker.gateway_app(),
        method: Method::POST,
        uri: "/sip/service.git/git-receive-pack".parse().unwrap(),
        host: Some("git.example.test"),
        request_id: Some("issuance-git-push"),
        authorization: Some(&authorization),
        headers: &[("Content-Type", "application/x-git-receive-pack-request")],
        body,
    })
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "service_action_denied"
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "token ceiling must precede pack parsing"
    );
}
