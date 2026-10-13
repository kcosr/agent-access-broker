//! Real router + SDK wire tests. No external services or caller configuration.
use super::*;
use agent_access_provider::{ScopeRequest, ScopeResolution};
use axum::http::HeaderValue;

mod names;
mod trusted_user;

const HOST: &str = "broker.example.test";
pub(super) const TOKEN_A: &str = "mcp-test-token-alpha";
const TOKEN_B: &str = "mcp-test-token-bravo";
const VERSION: &str = "2025-11-25";

pub(super) struct Fixture {
    pub(super) app: Router,
    token_path: PathBuf,
    state: Arc<ReloadableState>,
    audit_path: PathBuf,
    _directory: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn new(configure: impl FnOnce(&mut BrokerConfig)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        create_private_dir(directory.path());
        let token_path = directory.path().join("token-a");
        let token_b_path = directory.path().join("token-b");
        let provider_path = directory.path().join("provider-token");
        let audit_path = directory.path().join("audit.jsonl");
        std::fs::write(&token_path, TOKEN_A).unwrap();
        std::fs::write(&token_b_path, TOKEN_B).unwrap();
        std::fs::write(&provider_path, "synthetic-upstream-token").unwrap();
        let mut config = fake_config(audit_path.to_str().unwrap());
        config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
        config.identity = IdentityConfig {
            trusted_callers: Default::default(),
            mode: "required".into(),
            authority: "toml".into(),
            sources: vec![IdentitySourceConfig {
                name: "mcp-test".into(),
                kind: "static_principals".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                principals: vec![StaticPrincipalConfig {
                    principal: "mcp-user".into(),
                    token_refs: vec![
                        format!("file:{}", token_path.display()),
                        format!("file:{}", token_b_path.display()),
                    ],
                }],
            }],
            groups: vec![],
        };
        config.policy.grants[0].subjects = vec!["user:mcp-user".into()];
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", provider_path.display()));
        config.mcp.enabled = true;
        config.mcp.public_url = Some(format!("https://{HOST}/mcp"));
        configure(&mut config);
        let runtime = BrokerRuntime::new(config).unwrap();
        let state = Arc::new(ReloadableState::from_snapshot(
            PathBuf::new(),
            std::sync::Arc::new(crate::backend_registry()),
            broker_build_status(),
            RuntimeSnapshot::new(
                1,
                "mcp-wire-fixture".into(),
                runtime.clone().with_config_generation(1),
                StateLockSet::empty(),
            ),
            runtime.max_http_body_bytes(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            runtime.audit_registry(),
        ));
        Self {
            app: build_public_router(state.clone()),
            state,
            token_path,
            audit_path,
            _directory: directory,
        }
    }

    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        tokio::time::timeout(Duration::from_secs(10), self.app.clone().oneshot(request))
            .await
            .expect("MCP HTTP response timed out")
            .unwrap()
    }

    async fn initialize_version(&self, token: &str, version: &str) -> String {
        let response = self
            .send(request(
                Method::POST,
                Some(token),
                None,
                Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"broker-wire-tests","version":"1"}
                }})),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_string();
        assert!(!session.is_empty());
        let body = rpc_body(response).await;
        assert_eq!(body["result"]["protocolVersion"], VERSION);
        assert!(body["result"]["capabilities"]["tools"].is_object());
        assert_ne!(body["result"]["capabilities"]["tools"]["listChanged"], true);
        for capability in ["resources", "prompts", "tasks"] {
            assert!(body["result"]["capabilities"].get(capability).is_none());
        }
        let notification = self
            .send(request(
                Method::POST,
                Some(token),
                Some(&session),
                Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            ))
            .await;
        assert_eq!(notification.status(), StatusCode::ACCEPTED);
        assert!(
            axum::body::to_bytes(notification.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
        session
    }

    pub(super) async fn initialize(&self) -> String {
        self.initialize_version(TOKEN_A, VERSION).await
    }

    pub(super) async fn rpc(&self, session: &str, id: u64, method: &str, params: Value) -> Value {
        let response = self
            .send(request(
                Method::POST,
                Some(TOKEN_A),
                Some(session),
                Some(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "method {method}");
        let body = rpc_body(response).await;
        assert_eq!(body["id"], id);
        body
    }

    pub(super) async fn call(&self, session: &str, id: u64, name: &str, arguments: Value) -> Value {
        self.rpc(
            session,
            id,
            "tools/call",
            json!({"name":name,"arguments":arguments}),
        )
        .await
    }
}

pub(super) fn request(
    method: Method,
    token: Option<&str>,
    session: Option<&str>,
    message: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri("/mcp")
        .extension(ConnectInfo(
            "127.0.0.1:45000".parse::<SocketAddr>().unwrap(),
        ))
        .header("host", HOST)
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(session) = session {
        builder = builder
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", VERSION);
    }
    builder
        .body(message.map_or_else(Body::empty, |value| Body::from(value.to_string())))
        .unwrap()
}

pub(super) async fn rpc_body(response: axum::response::Response) -> Value {
    let content_type = response.headers()[CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024),
    )
    .await
    .expect("MCP response body did not terminate")
    .unwrap();
    if content_type.starts_with("application/json") {
        return serde_json::from_slice(&bytes).unwrap();
    }
    assert!(
        content_type.starts_with("text/event-stream"),
        "{content_type}"
    );
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let messages: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("SSE data contains JSON-RPC"))
        .filter(|value: &Value| value.get("id").is_some())
        .collect();
    assert_eq!(messages.len(), 1, "{text}");
    messages.into_iter().next().unwrap()
}

pub(super) fn structured(result: &Value) -> &Value {
    assert!(result.get("error").is_none(), "{result}");
    let value = &result["result"]["structuredContent"];
    assert!(value.is_object(), "{result}");
    let text: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, value, "text and structured tool outcomes differ");
    value
}

#[tokio::test]
async fn mcp_discovery_and_native_calls_use_real_policy_and_shared_definitions() {
    let fixture = Fixture::new(|_| {});
    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    for name in [
        "services_list",
        "resources_list",
        "actions_list",
        "actions_describe",
        "services_describe",
    ] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "missing {name}"
        );
    }
    let native = tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "echo")
        .unwrap();
    let native_name = native["name"].as_str().unwrap();
    assert_eq!(native_name, "fake_echo");
    assert_eq!(native["inputSchema"]["required"], json!(["inputs"]));
    assert!(
        native["inputSchema"]["properties"]
            .get("requestFile")
            .is_none()
    );
    let services = fixture.call(&session, 3, "services_list", json!({})).await;
    assert!(
        structured(&services)["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["service"] == "fake" && s["actions"] == json!(["echo"]))
    );
    let resources = fixture
        .call(
            &session,
            4,
            "resources_list",
            json!({"service":"fake","limit":1}),
        )
        .await;
    assert_eq!(structured(&resources)["resources"][0]["value"], "TEST");
    let actions = fixture
        .call(
            &session,
            5,
            "actions_list",
            json!({"service":"fake","resource":"TEST"}),
        )
        .await;
    assert_eq!(structured(&actions)["actions"], json!(["echo"]));
    let denied_actions = fixture
        .call(
            &session,
            6,
            "actions_list",
            json!({"service":"fake","resource":"OTHER"}),
        )
        .await;
    assert_eq!(structured(&denied_actions)["actions"], json!([]));
    let detail = fixture
        .call(
            &session,
            7,
            "actions_describe",
            json!({"service":"fake","action":"echo"}),
        )
        .await;
    assert_eq!(structured(&detail)["mcpTool"]["name"], native_name);
    assert_eq!(
        structured(&detail)["mcpTool"]["inputSchema"],
        native["inputSchema"]
    );
    let service = fixture
        .call(&session, 8, "services_describe", json!({"service":"fake"}))
        .await;
    assert_eq!(structured(&service)["service"], "fake");
    let allowed = fixture
        .call(
            &session,
            9,
            native_name,
            json!({"inputs":{"project":"TEST","message":"wire-test"}}),
        )
        .await;
    assert_eq!(structured(&allowed)["decision"], "allow");
    assert_eq!(structured(&allowed)["result"]["message"], "wire-test");
    assert_ne!(allowed["result"]["isError"], true);
    let denied = fixture
        .call(
            &session,
            10,
            native_name,
            json!({"inputs":{"project":"OTHER","message":"must-not-run"}}),
        )
        .await;
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(structured(&denied)["decision"], "deny");
    let audit = read_audit_records(&fixture.audit_path);
    assert!(audit.iter().any(|entry| entry["service"] == "fake"
        && entry["action"] == "echo"
        && entry["decision"] == "allow"));
}

#[tokio::test]
async fn mcp_file_fields_and_helper_errors_are_rejected_without_poisoning_session() {
    let fixture = Fixture::new(|_| {});
    let session = fixture.initialize().await;
    let name = agent_access_core::mcp::tool_name("fake", "echo");
    for (index, arguments) in [
        json!({"requestFile":"/etc/passwd"}),
        json!({"inputs":{"project":"TEST","message":"x"},"files":[]}),
        json!({"inputs":{"project":"TEST","message":"x"},"outputPath":"/tmp/never-create"}),
        json!({"inputs":{"project":"TEST","message":"x"},"secretSources":[]}),
    ]
    .into_iter()
    .enumerate()
    {
        let result = fixture
            .call(&session, index as u64 + 2, &name, arguments)
            .await;
        assert_eq!(result["result"]["isError"], true, "{result}");
    }
    let malformed_helper = fixture
        .call(
            &session,
            10,
            "resources_list",
            json!({"service":"fake","limit":101}),
        )
        .await;
    assert_eq!(malformed_helper["result"]["isError"], true);
    let unknown = fixture.call(&session, 11, "unknown_tool", json!({})).await;
    assert!(unknown.get("error").is_some(), "{unknown}");
    let legacy = fixture
        .call(&session, 13, "fake_echo_245a0744f1fbd877", json!({}))
        .await;
    assert_eq!(legacy["error"]["code"], -32602, "{legacy}");
    let recovery = fixture.call(&session, 12, "services_list", json!({})).await;
    assert!(structured(&recovery)["services"].is_array());
    assert!(
        !fixture.audit_path.exists()
            || !read_audit_records(&fixture.audit_path)
                .iter()
                .any(|entry| entry["service"] == "fake"
                    && entry["action"] == "echo"
                    && entry["decision"] == "allow")
    );
}

#[tokio::test]
async fn mcp_auth_host_origin_and_duplicate_security_headers_fail_closed() {
    let fixture = Fixture::new(|config| {
        config.mcp.allowed_origins = vec!["https://client.example.test".into()]
    });
    for token in [None, Some("not-a-valid-token")] {
        let response = fixture
            .send(request(Method::POST, token, None, Some(json!({}))))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(WWW_AUTHENTICATE));
    }
    let mut cookie = request(Method::POST, None, None, Some(json!({})));
    cookie.headers_mut().insert(
        "cookie",
        HeaderValue::from_static("agent-access-session=synthetic"),
    );
    assert_eq!(
        fixture.send(cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    for (header, value) in [
        ("origin", "https://attacker.example.test"),
        ("host", "attacker.example.test"),
    ] {
        let mut invalid = request(Method::POST, Some(TOKEN_A), None, Some(json!({})));
        invalid
            .headers_mut()
            .insert(header, HeaderValue::from_static(value));
        assert_eq!(fixture.send(invalid).await.status(), StatusCode::FORBIDDEN);
    }
    for header in ["authorization", "host", "origin", "mcp-protocol-version"] {
        let mut invalid = request(Method::POST, Some(TOKEN_A), None, Some(json!({})));
        if !invalid.headers().contains_key(header) {
            invalid
                .headers_mut()
                .insert(header, HeaderValue::from_static("one"));
        }
        invalid
            .headers_mut()
            .append(header, HeaderValue::from_static("duplicate"));
        assert_eq!(
            fixture.send(invalid).await.status(),
            StatusCode::BAD_REQUEST,
            "{header}"
        );
    }
    let session = fixture.initialize().await; // Native requests without Origin work.
    let mut allowed = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","id":2,"method":"ping"})),
    );
    allowed.headers_mut().insert(
        "origin",
        HeaderValue::from_static("https://client.example.test"),
    );
    assert_eq!(fixture.send(allowed).await.status(), StatusCode::OK);
    let mut lowercase = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","id":3,"method":"ping"})),
    );
    lowercase.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("bearer {TOKEN_A}")).unwrap(),
    );
    assert_eq!(fixture.send(lowercase).await.status(), StatusCode::OK);
    let mut conflicting = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","id":4,"method":"ping"})),
    );
    *conflicting.uri_mut() = "https://attacker.example.test/mcp".parse().unwrap();
    assert_eq!(
        fixture.send(conflicting).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut http2 = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","id":5,"method":"ping"})),
    );
    *http2.uri_mut() = "https://broker.example.test/mcp".parse().unwrap();
    *http2.version_mut() = axum::http::Version::HTTP_2;
    http2.headers_mut().remove("host");
    assert_eq!(fixture.send(http2).await.status(), StatusCode::OK);
    let mut query = request(Method::POST, Some(TOKEN_A), Some(&session), Some(json!({})));
    *query.uri_mut() = "/mcp?token=must-not-be-used".parse().unwrap();
    assert_eq!(fixture.send(query).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mcp_sessions_are_token_bound_and_get_delete_follow_the_selected_profile() {
    let fixture = Fixture::new(|_| {});
    let session = fixture.initialize().await;
    let mut origin = request(Method::GET, Some(TOKEN_A), Some(&session), None);
    origin.headers_mut().insert(
        "origin",
        HeaderValue::from_static("https://broker.example.test"),
    );
    assert_eq!(
        fixture.send(origin).await.status(),
        StatusCode::FORBIDDEN,
        "empty origin allowlist rejects every present Origin"
    );
    let get = fixture
        .send(request(Method::GET, Some(TOKEN_A), Some(&session), None))
        .await;
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    for method in [Method::POST, Method::DELETE] {
        let message =
            (method == Method::POST).then(|| json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
        let cross = fixture
            .send(request(method, Some(TOKEN_B), Some(&session), message))
            .await;
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    }
    let ping = fixture.rpc(&session, 3, "ping", json!({})).await;
    assert!(ping.get("error").is_none());
    let closed = fixture
        .send(request(Method::DELETE, Some(TOKEN_A), Some(&session), None))
        .await;
    assert_eq!(closed.status(), StatusCode::ACCEPTED);
    let stale = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_A),
            Some(&session),
            Some(json!({"jsonrpc":"2.0","id":4,"method":"ping"})),
        ))
        .await;
    assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    fixture.initialize().await;
}

#[tokio::test]
async fn mcp_protocol_negotiation_and_unknown_method_errors_preserve_session() {
    let fixture = Fixture::new(|_| {});
    let session = fixture.initialize_version(TOKEN_A, "2099-01-01").await;
    let mut invalid = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","id":2,"method":"ping"})),
    );
    invalid.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2026-07-28"),
    );
    assert_eq!(
        fixture.send(invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response=fixture.send(request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","id":3,"method":"unsupported-method","params":{"secret":"must-not-echo-this"}})))).await;
    let body = rpc_body(response).await;
    assert_eq!(body["error"]["code"], -32601);
    assert_eq!(body["id"], 3);
    assert!(!body.to_string().contains("must-not-echo-this"));
    let recovery = fixture.rpc(&session, 4, "ping", json!({})).await;
    assert!(recovery.get("error").is_none());
}

#[tokio::test]
async fn mcp_static_token_reload_and_idle_expiry_do_not_keep_stale_authority() {
    let fixture = Fixture::new(|config| config.mcp.session_idle_timeout_ms = 1000);
    let session = fixture.initialize().await;
    std::fs::write(&fixture.token_path, "replacement-token-after-rotation").unwrap();
    // Static token references load with the runtime, so publish a new runtime
    // generation just as successful config reload does. Managed tokens instead
    // validate their current store state on each request.
    let previous = fixture.state.current();
    let runtime =
        BrokerRuntime::new_for_reload(previous.runtime.config().clone(), &previous.runtime)
            .unwrap()
            .with_config_generation(2);
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        2,
        "rotated-token".into(),
        runtime,
        StateLockSet::empty(),
    ));
    let revoked = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_A),
            Some(&session),
            Some(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})),
        ))
        .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let other = fixture.initialize_version(TOKEN_B, VERSION).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let expired = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_B),
            Some(&other),
            Some(json!({"jsonrpc":"2.0","id":3,"method":"ping"})),
        ))
        .await;
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    fixture.initialize_version(TOKEN_B, VERSION).await;
}

#[tokio::test]
async fn mcp_request_and_result_budgets_are_enforced_without_replaying_provider_work() {
    let tiny = Fixture::new(|config| config.mcp.max_request_bytes = 1024);
    let session = tiny.initialize().await;
    let too_large=tiny.send(request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":agent_access_core::mcp::tool_name("fake","echo"),"arguments":{"inputs":{"project":"TEST","message":"x".repeat(2048)}}}})))).await;
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        tiny.rpc(&session, 3, "ping", json!({}))
            .await
            .get("error")
            .is_none()
    );

    let bounded = Fixture::new(|config| config.mcp.max_response_bytes = 64 * 1024);
    let session = bounded.initialize().await;
    let result = bounded
        .call(
            &session,
            2,
            &agent_access_core::mcp::tool_name("fake", "echo"),
            json!({"inputs":{"project":"TEST","message":"x".repeat(40*1024)}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], true, "{result}");
    let value = structured(&result);
    assert!(value.to_string().contains("mcp_response_too_large"));
    assert_eq!(value["resultAvailable"], false);
    assert_eq!(value["retrySafe"], false);
    assert!(result.to_string().len() < 64 * 1024);
    let executions = read_audit_records(&bounded.audit_path)
        .into_iter()
        .filter(|entry| {
            entry["service"] == "fake" && entry["action"] == "echo" && entry["decision"] == "allow"
        })
        .count();
    assert_eq!(
        executions, 1,
        "overflow must not cause re-execution or duplicate execution audits"
    );
    assert!(
        bounded
            .rpc(&session, 3, "ping", json!({}))
            .await
            .get("error")
            .is_none()
    );
}

#[tokio::test]
async fn mcp_session_quota_is_shared_by_tokens_for_one_principal_and_released_on_delete() {
    let fixture = Fixture::new(|config| {
        config.mcp.max_sessions = 1;
        config.mcp.max_sessions_per_principal = 1;
    });
    let session = fixture.initialize().await;
    let second=fixture.send(request(Method::POST,Some(TOKEN_B),None,Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"second-token","version":"1"}}})))).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        fixture
            .send(request(Method::DELETE, Some(TOKEN_A), Some(&session), None))
            .await
            .status()
            .is_success()
    );
    fixture.initialize_version(TOKEN_B, VERSION).await;
}

#[tokio::test]
async fn mcp_disabled_route_is_reserved_and_exposes_no_tools() {
    let fixture = Fixture::new(|config| config.mcp.enabled = false);
    for path in ["/mcp", "/mcp/fake"] {
        let mut request = request(
            Method::POST,
            Some(TOKEN_A),
            None,
            Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})),
        );
        *request.uri_mut() = path.parse().unwrap();
        let response = fixture.send(request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("mcp-session-id").is_none());
        assert_eq!(
            response_json(response).await,
            json!({"error":"MCP endpoint is disabled"})
        );
    }
}

fn fake_invocation_limit(config: &mut BrokerConfig, requests: u64) {
    config.limits.invocations.services.insert(
        "fake".into(),
        agent_access_core::InvocationLimitConfig {
            requests,
            window: "1m".into(),
        },
    );
}

#[tokio::test]
async fn mcp_tool_calls_are_counted_once_and_protocol_messages_are_not_counted() {
    let fixture = Fixture::new(|config| fake_invocation_limit(config, 2));
    let session = fixture.initialize().await;
    let native = agent_access_core::mcp::tool_name("fake", "echo");
    let arguments = json!({"inputs":{"project":"TEST","message":"counted"}});
    for id in 2..6 {
        assert!(
            fixture
                .rpc(&session, id, "ping", json!({}))
                .await
                .get("error")
                .is_none()
        );
        assert!(
            fixture
                .rpc(&session, id + 10, "tools/list", json!({}))
                .await["result"]["tools"]
                .is_array()
        );
        let helper = fixture
            .call(&session, id + 20, "services_list", json!({}))
            .await;
        assert_ne!(helper["result"]["isError"], true, "{helper}");
    }
    // Two action calls fit a budget of two only if each is charged once.
    for id in [30, 31] {
        let call = fixture.call(&session, id, &native, arguments.clone()).await;
        assert_eq!(structured(&call)["decision"], "allow", "{call}");
    }
    let limited = fixture.call(&session, 32, &native, arguments.clone()).await;
    assert_eq!(limited["result"]["isError"], true, "{limited}");
    let envelope = &limited["result"]["structuredContent"];
    assert_eq!(envelope["reasonCode"], "rate_limited");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "Rate limit reached for service \"fake\": 2 requests per 1m. Retry after "
        ),
        "{message}"
    );
    assert_eq!(limited["result"]["content"][0]["text"], message);
    assert_eq!(envelope["service"], "broker");
    assert_eq!(envelope["action"], "request.admit");
    assert_eq!(envelope["decision"], "error");
    assert_eq!(envelope["resourceScopes"], json!({}));
    assert!(envelope.get("result").is_none_or(Value::is_null));
    // Protocol traffic keeps working after the invocation budget is spent.
    assert_eq!(
        fixture.rpc(&session, 40, "ping", json!({})).await["result"],
        json!({})
    );
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["reasonCode"] == "rate_limited")
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count(),
        2
    );
    assert!(
        fixture
            .send(request(Method::DELETE, Some(TOKEN_A), Some(&session), None))
            .await
            .status()
            .is_success()
    );
}

struct ControlledProvider {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    executions: AtomicUsize,
    pause_before_dispatch: bool,
}
impl ControlledProvider {
    fn new(pause_before_dispatch: bool) -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            executions: AtomicUsize::new(0),
            pause_before_dispatch,
        })
    }
    async fn pause(&self) {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
    }
    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.acquire())
            .await
            .expect("controlled provider did not enter")
            .unwrap()
            .forget();
    }
}
impl agent_access_provider::test_support::DescribedProvider for ControlledProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for ControlledProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        if self.pause_before_dispatch {
            self.pause().await;
        }
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        if !self.pause_before_dispatch {
            self.pause().await;
        }
        agent_access_fake::FakeProvider.invoke(request).await
    }
}
fn controlled_fixture(provider: Arc<ControlledProvider>) -> Fixture {
    let fixture = Fixture::new(|config| {
        config.limits.max_concurrent_requests = 1;
        config.limits.max_concurrent_requests_per_principal = 1;
    });
    let previous = fixture.state.current();
    let runtime =
        BrokerRuntime::with_providers(previous.runtime.config().clone(), vec![provider]).unwrap();
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "controlled-mcp".into(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    ));
    fixture
}
async fn start_controlled_call(
    fixture: &Fixture,
    session: &str,
    id: u64,
) -> axum::response::Response {
    let response = fixture.send(request(Method::POST, Some(TOKEN_A), Some(session), Some(json!({
        "jsonrpc":"2.0","id":id,"method":"tools/call","params":{
            "name":agent_access_core::mcp::tool_name("fake", "echo"),"arguments":{"inputs":{"project":"TEST","message":"controlled"}}
        }
    })))).await;
    assert_eq!(response.status(), StatusCode::OK);
    response
}
async fn cancel_controlled_call(fixture: &Fixture, session: &str, id: u64) {
    let response = fixture.send(request(Method::POST, Some(TOKEN_A), Some(session), Some(json!({
        "jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id,"reason":"test cancellation"}
    })))).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
#[tokio::test]
async fn mcp_disconnect_preserves_dispatched_work_permit_and_one_terminal_audit() {
    let provider = ControlledProvider::new(false);
    let fixture = controlled_fixture(provider.clone());
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 20).await;
    provider.wait_entered().await;
    drop(response);
    assert!(
        fixture
            .state
            .shared_ingress
            .try_global_concurrency(1)
            .is_err()
    );
    // Control-plane ping still succeeds while the provider slot is occupied.
    assert_eq!(
        fixture.rpc(&session, 21, "ping", json!({})).await["result"],
        json!({})
    );
    provider.release.add_permits(1);
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "allow");
    assert!(
        fixture
            .state
            .shared_ingress
            .try_global_concurrency(1)
            .is_ok()
    );
}
#[tokio::test]
async fn mcp_cancellation_after_dispatch_is_advisory_and_does_not_repeat_work() {
    let provider = ControlledProvider::new(false);
    let fixture = controlled_fixture(provider.clone());
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 30).await;
    provider.wait_entered().await;
    cancel_controlled_call(&fixture, &session, 30).await;
    drop(response);
    assert!(
        fixture
            .state
            .shared_ingress
            .try_global_concurrency(1)
            .is_err()
    );
    provider.release.add_permits(1);
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "allow");
}
#[tokio::test]
async fn mcp_cancellation_before_dispatch_skips_provider_and_finalizes_audit() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture(provider.clone());
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 40).await;
    provider.wait_entered().await;
    cancel_controlled_call(&fixture, &session, 40).await;
    drop(response);
    // Cancellation can finish the owned preparation without releasing the provider barrier.
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reasonCode"], "operation_cancelled");
}

struct CatalogProvider;
impl agent_access_provider::test_support::DescribedProvider for CatalogProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        // A valid action whose large description forces response-byte pagination
        // without inventing actions outside the Broker's canonical catalog.
        descriptor.actions[0].description = "x".repeat(55_600);
        descriptor.actions[0].input_schema = json!({"type":"object"});
        descriptor.credentials = CredentialDescriptor::default();
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for CatalogProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("catalog-only provider must not be invoked")
    }
}
#[tokio::test]
async fn mcp_tools_pagination_is_complete_and_cursor_is_credential_bound_and_authenticated() {
    let fixture = Fixture::new(|config| config.mcp.max_response_bytes = 64 * 1024);
    let previous = fixture.state.current();
    let runtime = BrokerRuntime::with_providers(
        previous.runtime.config().clone(),
        vec![Arc::new(CatalogProvider)],
    )
    .unwrap();
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "catalog-mcp".into(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    ));
    let session = fixture.initialize().await;
    let first = fixture.rpc(&session, 50, "tools/list", json!({})).await;
    let first_tools = first["result"]["tools"].as_array().unwrap();
    assert!(!first_tools.is_empty() && first_tools.len() < 6);
    let cursor = first["result"]["nextCursor"].as_str().unwrap();
    let mut names: BTreeSet<String> = first_tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    let mut next_cursor = Some(cursor.to_owned());
    for id in 51..57 {
        let Some(page_cursor) = next_cursor.take() else {
            break;
        };
        let page = fixture
            .rpc(&session, id, "tools/list", json!({"cursor":page_cursor}))
            .await;
        for tool in page["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("{page}"))
        {
            assert!(names.insert(tool["name"].as_str().unwrap().to_owned()));
        }
        next_cursor = page["result"]["nextCursor"].as_str().map(str::to_owned);
    }
    assert!(next_cursor.is_none());
    assert_eq!(names.len(), 6);

    let other_session = fixture.initialize_version(TOKEN_B, VERSION).await;
    let other_response = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_B),
            Some(&other_session),
            Some(json!({
                "jsonrpc":"2.0","id":52,"method":"tools/list","params":{"cursor":cursor}
            })),
        ))
        .await;
    assert_eq!(rpc_body(other_response).await["error"]["code"], -32602);
    let mut forged = cursor.to_owned();
    let replacement = if forged.ends_with('0') { '1' } else { '0' };
    forged.pop();
    forged.push(replacement);
    assert_eq!(
        fixture
            .rpc(&session, 53, "tools/list", json!({"cursor":forged}))
            .await["error"]["code"],
        -32602
    );
    assert_eq!(
        fixture.rpc(&session, 54, "ping", json!({})).await["result"],
        json!({})
    );
}

#[tokio::test]
async fn mcp_intake_deadline_cannot_be_extended_by_trickling_body_bytes() {
    let fixture = Fixture::new(|config| {
        config.mcp.protocol_timeout_ms = 200;
        config.limits.streaming_idle_timeout_ms = 1000;
    });
    let session = fixture.initialize().await;
    let mut slow = request(Method::POST, Some(TOKEN_A), Some(&session), None);
    *slow.body_mut() = Body::from_stream(stream::unfold(0, |sent| async move {
        if sent >= 100 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        Some((Ok::<_, std::io::Error>(Bytes::from_static(b" ")), sent + 1))
    }));
    let response = fixture.send(slow).await;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&bytes).unwrap().contains("deadline"));
    assert_eq!(
        fixture.rpc(&session, 60, "ping", json!({})).await["result"],
        json!({})
    );
}
#[tokio::test]
async fn mcp_stalled_intake_is_bounded_per_principal_and_drop_releases_capacity() {
    let fixture = Fixture::new(|config| {
        config.mcp.max_control_requests = 1;
        config.mcp.max_control_requests_per_principal = 1;
    });
    let session = fixture.initialize().await;
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let mut stalled = request(Method::POST, Some(TOKEN_A), Some(&session), None);
    let entered_body = entered.clone();
    *stalled.body_mut() = Body::from_stream(stream::once(async move {
        entered_body.add_permits(1);
        std::future::pending::<Result<Bytes, std::io::Error>>().await
    }));
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move { app.oneshot(stalled).await });
    tokio::time::timeout(Duration::from_secs(2), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let response = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_B),
            Some(&session),
            Some(json!({"jsonrpc":"2.0","id":61,"method":"ping"})),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(
        fixture.rpc(&session, 62, "ping", json!({})).await["result"],
        json!({})
    );
}

struct FileCatalogProvider;
impl agent_access_provider::test_support::DescribedProvider for FileCatalogProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.service = "jira".into();
        descriptor.display_name = "Jira file boundary fixture".into();
        descriptor.credentials = CredentialDescriptor::default();
        let echo = descriptor.actions[0].clone();
        let action = |name: &str| ActionDescriptor {
            action: name.into(),
            documentation: Some(json!({"examples": ["extended fixture usage"]})),
            read_only: matches!(name, "issue.view" | "attachment.download"),
            ..echo.clone()
        };
        descriptor.actions = vec![
            action("issue.view"),
            action("attachment.add").multipart_upload(attachment_upload_plan(&["project"], None)),
            action("attachment.download").raw_download(),
        ];
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for FileCatalogProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("file actions must never reach this HTTP MCP provider")
    }
}
#[tokio::test]
async fn mcp_file_actions_remain_describable_but_are_not_native_http_tools() {
    let fixture = Fixture::new(|_| {});
    let previous = fixture.state.current();
    let mut config = previous.runtime.config().clone();
    config.policy.grants[0].service = "jira".into();
    config.policy.grants[0].actions = vec![
        "issue.view".into(),
        "attachment.add".into(),
        "attachment.download".into(),
    ];
    let mut credential = config.credentials.service["fake"].clone();
    credential.kind = "basic_api_token".into();
    credential.username_ref = credential.token_ref.clone();
    config
        .credentials
        .service
        .insert("jira".into(), credential.clone());
    credential.read_only = Some(true);
    config.credentials.lookup.insert("jira".into(), credential);
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".into(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".into()],
            attachments: Default::default(),
            content: Default::default(),
            search: Default::default(),
            comments: Default::default(),
            issue_links: Default::default(),
        });
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(FileCatalogProvider)]).unwrap();
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "file-catalog-mcp".into(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    ));
    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 70, "tools/list", json!({})).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6);
    assert!(
        !serde_json::to_string(tools)
            .unwrap()
            .contains("extended fixture usage")
    );
    let described = fixture
        .call(
            &session,
            69,
            "actions_describe",
            json!({"service":"jira","action":"issue.view"}),
        )
        .await;
    assert_eq!(
        structured(&described)["documentation"],
        json!({"examples":["extended fixture usage"]})
    );
    assert!(
        structured(&described)["mcpTool"]
            .get("documentation")
            .is_none()
    );
    for (index, action) in ["attachment.add", "attachment.download"]
        .into_iter()
        .enumerate()
    {
        let name = agent_access_core::mcp::tool_name("jira", action);
        assert!(!tools.iter().any(|tool| tool["name"] == name));
        let described = fixture
            .call(
                &session,
                71 + index as u64,
                "actions_describe",
                json!({"service":"jira","action":action}),
            )
            .await;
        assert_eq!(structured(&described)["action"], action);
        assert!(structured(&described).get("mcpTool").is_none());
        assert!(structured(&described).get("mcpToolUnavailable").is_none());
        let direct = fixture
            .call(
                &session,
                73 + index as u64,
                &name,
                json!({"inputs":{"project":"TEST"}}),
            )
            .await;
        assert_eq!(direct["error"]["code"], -32602);
    }
    assert!(!fixture.audit_path.exists());
}

fn publish_reload(fixture: &Fixture, configure: impl FnOnce(&mut BrokerConfig)) {
    let previous = fixture.state.current();
    let mut config = previous.runtime.config().clone();
    configure(&mut config);
    let generation = previous.generation + 1;
    let runtime = BrokerRuntime::new_for_reload(config, &previous.runtime)
        .unwrap()
        .with_config_generation(generation);
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        generation,
        "wire-reload".into(),
        runtime,
        StateLockSet::empty(),
    ));
}
#[tokio::test]
async fn mcp_ordinary_reload_preserves_session_and_admitted_preparation_delivery() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture(provider.clone());
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 80).await;
    provider.wait_entered().await;
    publish_reload(&fixture, |_| {});
    assert_eq!(
        fixture.rpc(&session, 81, "ping", json!({})).await["result"],
        json!({})
    );
    provider.release.add_permits(1);
    assert_eq!(structured(&rpc_body(response).await)["decision"], "allow");
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    assert_eq!(read_audit_records(&fixture.audit_path).len(), 1);
}
#[tokio::test]
async fn mcp_policy_reload_preserves_session_and_refreshes_discovery() {
    let fixture = Fixture::new(|_| {});
    let session = fixture.initialize().await;
    publish_reload(&fixture, |config| config.policy.grants.clear());
    let listing = fixture.rpc(&session, 82, "tools/list", json!({})).await;
    assert_eq!(listing["result"]["tools"].as_array().unwrap().len(), 5);
    let resources = fixture.call(&session, 83, "services_list", json!({})).await;
    assert_eq!(structured(&resources)["services"], json!([]));
}
#[tokio::test]
async fn mcp_security_reload_expires_session_but_drains_admitted_preparation() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture(provider.clone());
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 84).await;
    provider.wait_entered().await;
    publish_reload(&fixture, |config| {
        config.mcp.allowed_origins = vec!["https://allowed.example.test".into()]
    });
    let stale = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_A),
            Some(&session),
            Some(json!({"jsonrpc":"2.0","id":85,"method":"ping"})),
        ))
        .await;
    assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    drop(response);
    provider.release.add_permits(1);
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "allow");
}
#[tokio::test]
async fn mcp_auth_failure_budget_does_not_charge_or_block_successful_requests() {
    let fixture = Fixture::new(|config| config.limits.auth_requests_per_source_per_minute = 1);
    let session = fixture.initialize().await;
    for id in 90..94 {
        assert_eq!(
            fixture.rpc(&session, id, "ping", json!({})).await["result"],
            json!({})
        );
    }
    let first = fixture
        .send(request(
            Method::POST,
            Some("invalid-mcp-token"),
            None,
            Some(json!({})),
        ))
        .await;
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    let second = fixture
        .send(request(
            Method::POST,
            Some("invalid-mcp-token"),
            None,
            Some(json!({})),
        ))
        .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        fixture.rpc(&session, 94, "ping", json!({})).await["result"],
        json!({})
    );
}
#[tokio::test]
async fn mcp_cancellation_and_delete_survive_invocation_exhaustion_and_keep_explicit_cancel() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture(provider.clone());
    // Publish a one-call invocation budget before creating any session.
    let previous = fixture.state.current();
    let mut config = previous.runtime.config().clone();
    fake_invocation_limit(&mut config, 1);
    let runtime = BrokerRuntime::with_providers(config, vec![provider.clone()])
        .unwrap()
        .with_config_generation(1);
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "cancel-rate-wire".into(),
        runtime,
        StateLockSet::empty(),
    ));
    let session = fixture.initialize().await; // Protocol messages are not counted.
    let response = start_controlled_call(&fixture, &session, 95).await; // Spends the budget.
    provider.wait_entered().await;
    assert_eq!(
        fixture.rpc(&session, 96, "ping", json!({})).await["result"],
        json!({})
    );
    cancel_controlled_call(&fixture, &session, 95).await;
    assert_eq!(
        fixture
            .send(request(Method::DELETE, Some(TOKEN_A), Some(&session), None))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    drop(response);
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reasonCode"], "operation_cancelled");
    // The cancelled call was admitted, so it spent the one-call budget.
    assert!(
        fixture
            .state
            .shared_invocations
            .try_admit(
                "mcp-user",
                "fake",
                agent_access_core::InvocationLimit::new(1, 60).unwrap()
            )
            .is_err()
    );
}
#[tokio::test]
async fn mcp_sse_keepalives_preserve_long_calls_with_short_transport_idle_timeout() {
    let provider = ControlledProvider::new(false);
    let fixture = controlled_fixture(provider.clone());
    let previous = fixture.state.current();
    let mut config = previous.runtime.config().clone();
    config.limits.streaming_idle_timeout_ms = 200;
    let runtime = BrokerRuntime::with_providers(config, vec![provider.clone()])
        .unwrap()
        .with_config_generation(1);
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "short-idle-wire".into(),
        runtime,
        StateLockSet::empty(),
    ));
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 97).await;
    provider.wait_entered().await;
    let reading = tokio::spawn(rpc_body(response));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !reading.is_finished(),
        "SSE closed before the provider finished"
    );
    provider.release.add_permits(1);
    assert_eq!(structured(&reading.await.unwrap())["decision"], "allow");
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
}

#[path = "mcp/scoped.rs"]
pub(super) mod scoped;

#[tokio::test]
async fn mcp_sessions_bind_trusted_caller_and_loaded_secret_revision() {
    use agent_access_core::{
        CALLER_AUTHORIZATION_HEADER, TrustedCallerConfig, TrustedCallerContextMode,
    };
    let directory = tempfile::tempdir().unwrap();
    let caller_path = directory.path().join("caller");
    let other_path = directory.path().join("other");
    let secret = "caller-mcp-secret-0123456789";
    let other = "other-mcp-secret-0123456789";
    let rotated = "rotated-mcp-secret-0123456789";
    std::fs::write(&caller_path, secret).unwrap();
    std::fs::write(&other_path, other).unwrap();
    let fixture = Fixture::new(|config| {
        for (name, path) in [("dispatch", &caller_path), ("other", &other_path)] {
            config.identity.trusted_callers.insert(
                name.into(),
                TrustedCallerConfig {
                    credential_transport: Default::default(),
                    username_namespace: None,
                    credential_ref: format!("file:{}", path.display()),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: false,
                },
            );
        }
    });
    let send = |secret: &str, session: Option<&str>, initialize: bool| {
        let mut request = request(
            Method::POST,
            Some(TOKEN_A),
            session,
            Some(if initialize {
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"caller-binding","version":"1"}}})
            } else {
                json!({"jsonrpc":"2.0","id":2,"method":"ping"})
            }),
        );
        request.headers_mut().insert(
            CALLER_AUTHORIZATION_HEADER,
            HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
        );
        request
    };
    let response = fixture.send(send(secret, None, true)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let _ = rpc_body(response).await;
    let mut notification = request(
        Method::POST,
        Some(TOKEN_A),
        Some(&session),
        Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
    );
    notification.headers_mut().insert(
        CALLER_AUTHORIZATION_HEADER,
        HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
    );
    assert_eq!(
        fixture.send(notification).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        fixture
            .send(send(other, Some(&session), false))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .send(send(secret, Some(&session), false))
            .await
            .status(),
        StatusCode::OK
    );
    // The reference and all capabilities stay unchanged. Only loaded secret
    // material changes, so config-profile hashing alone cannot invalidate it.
    std::fs::write(&caller_path, rotated).unwrap();
    publish_reload(&fixture, |_| {});
    assert_eq!(
        fixture
            .send(send(secret, Some(&session), false))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .send(send(rotated, Some(&session), false))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.send(send(rotated, None, true)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn http_caller_admission_envelopes_prove_zero_provider_invocations() {
    use agent_access_core::{
        CALLER_AUTHORIZATION_HEADER, TrustedCallerConfig, TrustedCallerContextMode,
    };
    let directory = tempfile::tempdir().unwrap();
    let caller_path = directory.path().join("caller");
    std::fs::write(&caller_path, "caller-test-secret-0123456789").unwrap();
    let fixture = Fixture::new(|config| {
        config.execution_context = Some(ExecutionContextConfig {
            allowed_values: vec!["default".into(), "internal".into()],
            default_context: Some("default".into()),
        });
        config.policy.grants[0].execution_contexts = Some(vec!["default".into()]);
        config.identity.trusted_callers.insert(
            "dispatch".into(),
            TrustedCallerConfig {
                credential_transport: Default::default(),
                username_namespace: None,
                credential_ref: format!("file:{}", caller_path.display()),
                context_mode: TrustedCallerContextMode::Asserted,
                execution_context: None,
                allowed_execution_contexts: Some(vec!["default".into()]),
                allow_forwarded_identity: false,
            },
        );
    });
    let provider = ControlledProvider::new(false);
    let previous = fixture.state.current();
    let runtime =
        BrokerRuntime::with_providers(previous.runtime.config().clone(), vec![provider.clone()])
            .unwrap();
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "admission-proof".into(),
        runtime,
        StateLockSet::empty(),
    ));
    let caller = (
        CALLER_AUTHORIZATION_HEADER,
        "Bearer caller-test-secret-0123456789",
    );
    let auth = ("authorization", "Bearer mcp-test-token-alpha");
    let context = (EXECUTION_CONTEXT_HEADER, "default");
    for (headers, action, reason, status) in [
        (
            vec![auth, context],
            "caller.authenticate",
            "caller_authentication_required",
            StatusCode::UNAUTHORIZED,
        ),
        (
            vec![auth, context, (CALLER_AUTHORIZATION_HEADER, "Bearer bad")],
            "caller.authenticate",
            "caller_authentication_invalid",
            StatusCode::UNAUTHORIZED,
        ),
        (
            vec![auth, caller],
            "caller.authenticate",
            "execution_context_required",
            StatusCode::FORBIDDEN,
        ),
        (
            vec![auth, caller, (EXECUTION_CONTEXT_HEADER, "INTERNAL")],
            "caller.authenticate",
            "execution_context_invalid",
            StatusCode::FORBIDDEN,
        ),
        (
            vec![auth, caller, (EXECUTION_CONTEXT_HEADER, "internal")],
            "caller.authenticate",
            "execution_context_denied",
            StatusCode::FORBIDDEN,
        ),
        (
            vec![
                auth,
                caller,
                context,
                ("x-aw-identity-token-sha256", "sha256:forbidden"),
            ],
            "caller.authenticate",
            "caller_identity_forwarding_denied",
            StatusCode::FORBIDDEN,
        ),
        (
            vec![caller, context],
            "identity.authenticate",
            "identity_required",
            StatusCode::UNAUTHORIZED,
        ),
        (
            vec![caller, context, ("authorization", "Bearer invalid")],
            "identity.authenticate",
            "identity_invalid",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/v1/invoke/fake/echo")
            .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
            .header(REQUEST_ID_HEADER, "zero-provider-proof")
            .header(CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = fixture
            .send(
                request
                    .body(Body::from(json!({"inputs":{"project":"TEST"}}).to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), status, "{reason}");
        let body = response_json(response).await;
        assert_eq!(body["service"], "broker");
        assert_eq!(body["action"], action);
        assert_eq!(body["reasonCode"], reason);
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["resourceScopes"], json!({}));
        assert_eq!(body["agentRequestId"], "zero-provider-proof");
        assert!(body.get("result").is_none_or(Value::is_null));
        assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    }
}

/// A provider reporting ingress admission's host-only reason codes after work
/// was dispatched never produces an admission proof: the Broker reports its
/// provider contract failure, attributed to the provider operation.
struct PostDispatchReasonProvider {
    reason: ReasonCode,
    raw_download: bool,
    executions: AtomicUsize,
}

impl agent_access_provider::test_support::DescribedProvider for PostDispatchReasonProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        if self.raw_download {
            descriptor.actions[0] = descriptor.actions[0].clone().raw_download();
        }
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for PostDispatchReasonProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let error = match self.reason {
            ReasonCode::RateLimited | ReasonCode::ConcurrencyLimited => {
                ProviderError::error(self.reason, "provider failed after dispatch")
            }
            _ => ProviderError::deny(self.reason, "provider failed after dispatch"),
        };
        Err(error.with_result(json!({
            "executionState": "unknown",
            "retrySafe": false,
            "providerReceipt": "invoked"
        })))
    }
}

#[tokio::test]
async fn post_dispatch_reasons_never_become_admission_proofs_on_http_or_mcp() {
    for reason in [
        ReasonCode::RateLimited,
        ReasonCode::ConcurrencyLimited,
        ReasonCode::IdentityInvalid,
        ReasonCode::ExecutionContextDenied,
    ] {
        // Keep the canonical fake.echo action so configuration validation uses
        // its real policy contract; vary only the injected transport descriptor.
        for raw_download in [false, true] {
            let fixture = Fixture::new(|_| {});
            let provider = Arc::new(PostDispatchReasonProvider {
                reason,
                raw_download,
                executions: AtomicUsize::new(0),
            });
            let previous = fixture.state.current();
            let runtime = BrokerRuntime::with_providers(
                previous.runtime.config().clone(),
                vec![provider.clone()],
            )
            .unwrap();
            fixture.state.publish_snapshot(RuntimeSnapshot::new(
                1,
                "post-dispatch-reason".into(),
                runtime,
                StateLockSet::empty(),
            ));
            // A provider cannot report these host-only reasons: the Broker
            // replaces them with its provider contract failure, still
            // attributed to the provider operation and with an unknown,
            // not retry-safe execution state, never the provider's receipt.
            let assert_provider_error = |envelope: &Value| {
                assert_eq!(envelope["service"], "fake", "{envelope}");
                assert_eq!(envelope["action"], "echo", "{envelope}");
                assert_eq!(envelope["decision"], "error", "{envelope}");
                assert_eq!(
                    envelope["reasonCode"], "broker_provider_contract_failed",
                    "{envelope}"
                );
                assert_eq!(envelope["resourceScopes"], json!({"project":["TEST"]}));
                assert_eq!(
                    envelope["result"],
                    json!({
                        "executionState": "unknown",
                        "retrySafe": false
                    })
                );
                assert!(
                    !envelope
                        .to_string()
                        .contains("provider failed after dispatch"),
                    "{envelope}"
                );
            };
            // JSON goes through owned operation dispatch; raw download uses the
            // nonowned invocation path and must retain the same failure contract.
            let accept = if raw_download {
                "application/octet-stream"
            } else {
                "application/json"
            };
            let request = Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "post-dispatch-proof")
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, accept)
                .body(Body::from(
                    json!({"inputs":{"project":"TEST","message":"fail after dispatch"}})
                        .to_string(),
                ))
                .unwrap();
            let response = fixture.send(request).await;
            assert_eq!(
                response.status().as_u16(),
                ReasonCode::BrokerProviderContractFailed.http_status()
            );
            let envelope = response_json(response).await;
            assert_eq!(envelope["agentRequestId"], "post-dispatch-proof");
            assert_provider_error(&envelope);
            if !raw_download {
                let session = fixture.initialize().await;
                let response = fixture
                    .call(
                        &session,
                        51,
                        &agent_access_core::mcp::tool_name("fake", "echo"),
                        json!({"inputs":{"project":"TEST","message":"fail after dispatch"}}),
                    )
                    .await;
                assert_eq!(response["result"]["isError"], true, "{response}");
                assert_provider_error(&response["result"]["structuredContent"]);
            }
            let expected_calls = if raw_download { 1 } else { 2 };
            assert_eq!(provider.executions.load(Ordering::SeqCst), expected_calls);
            let records = read_audit_records(&fixture.audit_path);
            assert_eq!(records.len(), expected_calls);
            assert!(records.iter().all(|record| record["service"] == "fake"
                && record["reasonCode"] == "broker_provider_contract_failed"));
        }
    }
}
