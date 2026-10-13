//! Wire-level interoperability fixtures. These deliberately exercise the adapter
//! through its public discovery, verification and invocation entry points.
use super::*;
use axum::body::{Body, Bytes};
use http::Method;
use std::borrow::Cow;

const PREVIOUS: &str = "2025-11-25";
const SESSION: &str = "private-initialized-session";
const PROBE_SESSION: &str = "private-rejected-probe-session";

#[derive(Clone)]
enum ReplyBody {
    Result(Value),
    Error(Value),
    Raw(String),
}
#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: ReplyBody,
    headers: Vec<(&'static str, String)>,
    sse: bool,
    delay: Duration,
}
impl Reply {
    fn raw(status: StatusCode, body: impl Into<String>) -> Self {
        Self {
            status,
            body: ReplyBody::Raw(body.into()),
            headers: vec![],
            sse: false,
            delay: Duration::ZERO,
        }
    }
    fn result(result: Value) -> Self {
        Self {
            body: ReplyBody::Result(result),
            ..Self::raw(StatusCode::OK, "")
        }
    }
    fn error(status: StatusCode, code: i32, data: Option<Value>) -> Self {
        let mut error = json!({"code":code,"message":"private-upstream-error-message"});
        if let Some(data) = data {
            error["data"] = data;
        }
        Self {
            body: ReplyBody::Error(error),
            ..Self::raw(status, "")
        }
    }
    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
    async fn respond(&self, request: &Value) -> Response {
        tokio::time::sleep(self.delay).await;
        let (body, mut content_type) = match &self.body {
            ReplyBody::Result(result) => (
                json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string(),
                "application/json",
            ),
            ReplyBody::Error(error) => (
                json!({"jsonrpc":"2.0","id":request["id"],"error":error}).to_string(),
                "application/json",
            ),
            ReplyBody::Raw(body) => (body.clone(), "application/json"),
        };
        let body = if self.sse {
            content_type = "text/event-stream";
            format!(
                ":priming\r\nevent: message\r\ndata:\r\n\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"data\":\"private-opaque-notification\"}}}}\r\n\r\ndata: {body}\r\n\r\n"
            )
        } else {
            body
        };
        let mut response = Response::builder().status(self.status);
        if !self.headers.iter().any(|(name, _)| *name == "content-type") {
            response = response.header("content-type", content_type);
        }
        for (name, value) in &self.headers {
            response = response.header(*name, value);
        }
        response.body(Body::from(body)).unwrap()
    }
}

#[derive(Clone)]
struct Plan {
    probe: Reply,
    initialize: Reply,
    initialized: Reply,
    call: Reply,
    cleanup: Reply,
    pages: Vec<Value>,
    list_failure: Option<Reply>,
    sse_lists: bool,
    later_sessions: Vec<String>,
    unique_sessions: bool,
}
impl Default for Plan {
    fn default() -> Self {
        Self {
            probe: Reply::raw(StatusCode::NOT_FOUND, "legacy endpoint"),
            initialize: Reply::result(json!({
                "protocolVersion":PREVIOUS,"capabilities":{"tools":{}},
                "serverInfo":{"name":"Legacy synthetic server","version":"1","title":"Legacy title", "icons":[{"src":"https://private.example/icon"}]},
                "instructions":"private-server-instructions", "_meta":{"private":"private-server-extension"}
            })).header("mcp-session-id", SESSION),
            initialized: Reply::raw(StatusCode::ACCEPTED, ""),
            call: Reply::result(json!({"content":[{"type":"text","text":"private-tool-output"}],"structuredContent":null})),
            cleanup: Reply::raw(StatusCode::NO_CONTENT, ""),
            pages: vec![json!({"tools":[tool()]})],
            list_failure: None,
            sse_lists: false,
            later_sessions: vec![],
            unique_sessions: false,
        }
    }
}
#[derive(Clone, Debug)]
struct Recorded {
    http_method: Method,
    headers: HeaderMap,
    body: Value,
}
impl Recorded {
    fn method(&self) -> &str {
        if self.http_method == Method::DELETE {
            "DELETE"
        } else {
            self.body["method"].as_str().unwrap()
        }
    }
}
#[derive(Clone)]
struct CompatState {
    plan: Plan,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    initializes: Arc<AtomicUsize>,
}
struct CompatFixture {
    endpoint: String,
    state: CompatState,
    server: JoinHandle<()>,
}
impl Drop for CompatFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl CompatFixture {
    async fn new(plan: Plan) -> Self {
        let state = CompatState {
            plan,
            recorded: Default::default(),
            initializes: Default::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/mcp", post(compat_handler).delete(compat_handler))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            endpoint,
            state,
            server,
        }
    }
    fn requests(&self) -> Vec<Recorded> {
        self.state.recorded.lock().unwrap().clone()
    }
    fn methods(&self) -> Vec<String> {
        self.requests().iter().map(|r| r.method().into()).collect()
    }
    fn count(&self, method: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method() == method)
            .count()
    }
    fn provider(&self, host: &test_support::TestHost) -> Arc<dyn Provider> {
        McpAdapter
            .build(
                &definition(&self.endpoint),
                &[action()],
                None,
                &host.context(),
            )
            .unwrap()
    }
    async fn invoke(&self) -> Result<ProviderResult, ProviderError> {
        self.provider(&test_host())
            .invoke(invocation(
                json!({"region":"private-tool-input"}),
                "private-static-token",
            ))
            .await
    }
    async fn discover(&self) -> Result<ImportedDiscovery, ProviderError> {
        McpAdapter
            .discover(
                &definition(&self.endpoint),
                &ImportedDiscoveryAuthentication::Static(credential("private-discovery-token")),
                None,
                &test_host().context(),
            )
            .await
            .map_err(|error| match error {
                AdapterDiscoveryError::Failed(error) => error,
                other => panic!("unexpected discovery failure: {other:?}"),
            })
    }
}
async fn compat_handler(
    State(state): State<CompatState>,
    http_method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    state.recorded.lock().unwrap().push(Recorded {
        http_method: http_method.clone(),
        headers,
        body: request.clone(),
    });
    let method = request["method"].as_str().unwrap_or("");
    let mut reply = if http_method == Method::DELETE {
        state.plan.cleanup.clone()
    } else {
        match method {
            "server/discover" => state.plan.probe.clone(),
            "initialize" => {
                let mut reply = state.plan.initialize.clone();
                if state.plan.unique_sessions {
                    reply.headers.retain(|(name, _)| *name != "mcp-session-id");
                    reply.headers.push((
                        "mcp-session-id",
                        format!(
                            "private-session-{}",
                            state.initializes.fetch_add(1, Ordering::SeqCst)
                        ),
                    ));
                }
                reply
            }
            "notifications/initialized" => state.plan.initialized.clone(),
            "tools/list" => {
                if let Some(reply) = &state.plan.list_failure {
                    reply.clone()
                } else {
                    let page = request
                        .pointer("/params/cursor")
                        .and_then(Value::as_str)
                        .map(|v| v.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    let mut reply = Reply::result(state.plan.pages[page].clone());
                    reply.sse = state.plan.sse_lists;
                    reply
                }
            }
            "tools/call" => state.plan.call.clone(),
            other => panic!("unexpected compatibility request {other}"),
        }
    };
    if matches!(
        method,
        "notifications/initialized" | "tools/list" | "tools/call"
    ) {
        for session in &state.plan.later_sessions {
            reply.headers.push(("mcp-session-id", session.clone()));
        }
    }
    reply.respond(&request).await
}
fn assert_write(error: &ProviderError, dispatched: bool) {
    let result = error.result.as_ref().unwrap();
    assert_eq!(
        result["mutationStatus"],
        if dispatched { "unknown" } else { "not_applied" }
    );
    assert_eq!(result["retrySafe"], false);
    assert_eq!(result["toolDispatched"], dispatched);
}
fn assert_legacy_requests(fixture: &CompatFixture, session: Option<&str>) {
    for request in fixture.requests() {
        match request.method() {
            "server/discover" => {
                assert_eq!(request.headers["mcp-protocol-version"], PROTOCOL_VERSION);
                assert!(!request.headers.contains_key("mcp-session-id"));
                assert!(request.body.pointer("/params/arguments").is_none());
            }
            "initialize" => {
                assert!(!request.headers.contains_key("mcp-protocol-version"));
                assert!(!request.headers.contains_key("mcp-session-id"));
                assert_eq!(request.body["params"]["protocolVersion"], PREVIOUS);
                assert_eq!(request.body["params"]["capabilities"], json!({}));
                assert_eq!(
                    request.body["params"]["clientInfo"],
                    json!({"name": "agent-access-broker-host", "version": env!("CARGO_PKG_VERSION")})
                );
            }
            _ => {
                assert_eq!(request.headers["mcp-protocol-version"], PREVIOUS);
                assert_eq!(
                    request
                        .headers
                        .get("mcp-session-id")
                        .map(|v| v.to_str().unwrap()),
                    session
                );
            }
        }
        if request.method() != "server/discover" {
            assert!(
                !request
                    .headers
                    .keys()
                    .any(|key| matches!(key.as_str(), "mcp-method" | "mcp-name")
                        || key.as_str().starts_with("mcp-param-"))
            );
            for key in ["protocolVersion", "clientInfo", "clientCapabilities"] {
                assert!(
                    request
                        .body
                        .pointer(&format!("/params/_meta/io.modelcontextprotocol~1{key}"))
                        .is_none()
                );
            }
        }
        if request.method() == "notifications/initialized" {
            assert!(request.body.get("id").is_none());
        }
        if request.method() == "tools/call" {
            assert_eq!(
                request.body["params"]["arguments"]["region"],
                "private-tool-input"
            );
        }
        assert!(!request.headers.contains_key("last-event-id"));
    }
}

#[tokio::test]
async fn legacy_json_and_sse_discovery_verification_and_invocation_share_the_lifecycle() {
    for sse in [false, true] {
        for session in [false, true] {
            let mut plan = Plan {
                sse_lists: sse,
                ..Plan::default()
            };
            plan.initialize.sse = sse;
            plan.call.sse = sse;
            if !session {
                plan.initialize.headers.clear();
            }
            plan.pages = vec![
                json!({"tools":[],"nextCursor":"1"}),
                json!({"tools":[tool()]}),
            ];
            let fixture = CompatFixture::new(plan).await;
            let discovery = fixture.discover().await.unwrap();
            assert_eq!(discovery.protocol_version, PREVIOUS);
            assert_eq!(discovery.tools.len(), 1);
            assert_eq!(
                discovery.metadata["serverInfo"],
                json!({"name":"Legacy synthetic server","version":"1","title":"Legacy title"})
            );
            assert_eq!(discovery.metadata["pages"], 2);
            assert!(
                !serde_json::to_string(&discovery)
                    .unwrap()
                    .contains("private-")
            );
            let provider = fixture.provider(&test_host());
            let verification = provider
                .verify_execution_credential(
                    &credential("private-verification-token"),
                    &CorrelationContext::for_tests(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(verification.audit["protocolVersion"], PREVIOUS);
            let result = fixture.invoke().await.unwrap();
            assert!(result.result["upstreamMcp"]["structuredContent"].is_null());
            assert_eq!(result.result["mutationStatus"], "applied_unverified");
            assert_eq!(result.audit.as_ref().unwrap()["protocolVersion"], PREVIOUS);
            assert_eq!(fixture.count("server/discover"), 3);
            assert_eq!(fixture.count("initialize"), 3);
            assert_eq!(fixture.count("notifications/initialized"), 3);
            assert_eq!(fixture.count("tools/list"), 4);
            assert_eq!(fixture.count("tools/call"), 1);
            assert_eq!(fixture.count("DELETE"), if session { 3 } else { 0 });
            assert_legacy_requests(&fixture, session.then_some(SESSION));
        }
    }
}

#[tokio::test]
async fn discovery_probe_rejections_have_one_bounded_legacy_attempt() {
    let mut probes = vec![
        Reply::raw(StatusCode::BAD_REQUEST, ""),
        Reply::raw(StatusCode::NOT_FOUND, "<html>unsupported</html>"),
        Reply::raw(StatusCode::METHOD_NOT_ALLOWED, "{malformed"),
        Reply::raw(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unknown method cannot deserialize"),
        Reply::raw(StatusCode::UNPROCESSABLE_ENTITY, "Unexpected message, expect initialize request"),
        Reply::raw(StatusCode::BAD_REQUEST, json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"private-rejection"}}).to_string()),
        Reply::raw(StatusCode::BAD_REQUEST, json!({"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"private-rejection"}}).to_string()),
        Reply::raw(StatusCode::BAD_REQUEST, json!({"anything":"not an RPC envelope"}).to_string()),
        Reply::error(StatusCode::OK, -32601, None),
        Reply::error(StatusCode::OK, -32600, None),
        Reply::result(json!({"supportedVersions":[PREVIOUS],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})),
    ];
    for status in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        for versions in [json!([PREVIOUS]), json!([PROTOCOL_VERSION, PREVIOUS])] {
            probes.push(Reply::error(
                status,
                -32022,
                Some(json!({"supported":versions,"requested":PROTOCOL_VERSION})),
            ));
            probes.push(Reply::error(
                status,
                -32000,
                Some(json!({"supported":versions})),
            ));
        }
    }
    for probe in probes {
        let fixture = CompatFixture::new(Plan {
            probe,
            ..Plan::default()
        })
        .await;
        fixture.invoke().await.unwrap();
        assert_eq!(
            fixture.methods(),
            [
                "server/discover",
                "initialize",
                "notifications/initialized",
                "tools/call",
                "DELETE"
            ]
        );
        assert_legacy_requests(&fixture, Some(SESSION));
    }
}

#[tokio::test]
async fn forbidden_probe_failures_never_downgrade_or_dispatch() {
    let mut probes = Vec::new();
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::NOT_ACCEPTABLE,
        StatusCode::ACCEPTED,
    ] {
        probes.push(Reply::error(status, -32601, None));
    }
    for status in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        for code in [-32020, -32021] {
            probes.push(Reply::error(
                status,
                code,
                Some(json!({"supported":[PREVIOUS]})),
            ));
        }
        for supported in [
            json!([]),
            json!([PREVIOUS, PREVIOUS]),
            json!(["2025-06-18"]),
            json!([PROTOCOL_VERSION]),
            json!([null]),
            json!([""]),
            json!(["é"]),
            json!(["x".repeat(65)]),
            json!("2025-11-25"),
            json!((0..33).map(|v| format!("version-{v}")).collect::<Vec<_>>()),
        ] {
            probes.push(Reply::error(
                status,
                -32022,
                Some(json!({"supported":supported})),
            ));
        }
        probes.push(Reply::error(
            status,
            -32022,
            Some(json!({"supported":[PREVIOUS],"requested":PREVIOUS})),
        ));
        probes.push(Reply::error(status, -32022, None));
        probes.push(
            Reply::error(status, -32601, None)
                .header("www-authenticate", "Bearer error=invalid_request"),
        );
    }
    probes.extend([
        Reply::error(StatusCode::OK, -32000, None),
        Reply::result(json!({"supportedVersions":[PREVIOUS],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}))
            .header("www-authenticate", "Bearer error=invalid_request"),
        Reply::raw(StatusCode::OK, "{bad json"),
        Reply::raw(StatusCode::OK, json!({"jsonrpc":"2.0","id":"wrong","error":{"code":-32601,"message":"private-error"}}).to_string()),
        Reply::raw(StatusCode::OK, json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"private-error"}}).to_string()),
        Reply::result(json!({"supportedVersions":[PREVIOUS],"capabilities":{},"ttlMs":0,"cacheScope":"private"})),
        Reply::result(json!({"supportedVersions":[PREVIOUS,PREVIOUS],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})),
        Reply::result(json!({"supportedVersions":["2025-06-18"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})),
    ]);
    for probe in probes {
        let fixture = CompatFixture::new(Plan {
            probe,
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.expect_err("probe must fail");
        assert_write(&error, false);
        assert!(
            error
                .audit
                .as_deref()
                .and_then(|audit| audit.get("protocolVersion"))
                .is_none_or(Value::is_null),
            "failed startup must not claim a negotiated version"
        );
        assert_eq!(fixture.methods(), ["server/discover"]);
    }
}

#[tokio::test]
async fn initialized_acknowledgements_are_notifications_with_bounded_body_rules() {
    for initialized in [
        Reply::raw(StatusCode::ACCEPTED, ""),
        Reply::raw(StatusCode::NO_CONTENT, ""),
        Reply::raw(StatusCode::OK, ""),
        Reply::raw(
            StatusCode::ACCEPTED,
            "discarded private notification acknowledgement",
        ),
    ] {
        let fixture = CompatFixture::new(Plan {
            initialized,
            ..Plan::default()
        })
        .await;
        fixture.invoke().await.unwrap();
        assert_eq!(
            fixture.methods(),
            [
                "server/discover",
                "initialize",
                "notifications/initialized",
                "tools/call",
                "DELETE"
            ]
        );
        assert_legacy_requests(&fixture, Some(SESSION));
    }
    for initialized in [
        Reply::raw(StatusCode::OK, " "),
        Reply::raw(StatusCode::OK, "{}"),
        Reply::raw(StatusCode::CREATED, ""),
        Reply::raw(StatusCode::BAD_REQUEST, ""),
        Reply::raw(StatusCode::INTERNAL_SERVER_ERROR, ""),
    ] {
        let fixture = CompatFixture::new(Plan {
            initialized,
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, false);
        assert_eq!(
            fixture.methods(),
            [
                "server/discover",
                "initialize",
                "notifications/initialized",
                "DELETE"
            ]
        );
    }
}

#[tokio::test]
async fn initialize_validates_versions_required_fields_and_session_headers_before_acknowledging() {
    let valid = match Plan::default().initialize.body {
        ReplyBody::Result(value) => value,
        _ => unreachable!(),
    };
    let mut results = Vec::new();
    for version in [
        json!("2025-06-18"),
        json!(PROTOCOL_VERSION),
        Value::Null,
        json!(5),
    ] {
        let mut result = valid.clone();
        result["protocolVersion"] = version;
        results.push(result);
    }
    for capabilities in [json!({}), json!([]), json!({"tools":"invalid"})] {
        let mut result = valid.clone();
        result["capabilities"] = capabilities;
        results.push(result);
    }
    for info in [
        json!({}),
        json!({"name":2,"version":"1"}),
        json!({"name":"x","version":false}),
        json!({"name":"x","version":"1","title":12}),
    ] {
        let mut result = valid.clone();
        result["serverInfo"] = info;
        results.push(result);
    }
    for result in results {
        let fixture = CompatFixture::new(Plan {
            initialize: Reply::result(result).header("mcp-session-id", SESSION),
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, false);
        assert_eq!(
            fixture.methods(),
            ["server/discover", "initialize", "DELETE"]
        );
    }
    for sessions in [
        vec!["".into()],
        vec!["bad session".into()],
        vec!["bad\tvalue".into()],
        vec!["é".into()],
        vec!["x".repeat(4097)],
        vec![SESSION.into(), SESSION.into()],
        vec![SESSION.into(), "different".into()],
    ] {
        let mut plan = Plan::default();
        plan.initialize.headers = sessions
            .into_iter()
            .map(|value| ("mcp-session-id", value))
            .collect();
        let fixture = CompatFixture::new(plan).await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, false);
        assert_eq!(fixture.methods(), ["server/discover", "initialize"]);
    }
    let mut plan = Plan::default();
    plan.initialize.headers = vec![("mcp-session-id", "x".repeat(4096))];
    let fixture = CompatFixture::new(plan).await;
    fixture.invoke().await.unwrap();
    assert_eq!(fixture.count("DELETE"), 1);
}

#[tokio::test]
async fn malformed_or_uncorrelated_initialize_never_authorizes_acknowledgement_or_cleanup() {
    for initialize in [
        Reply::raw(StatusCode::OK, "{broken"),
        Reply::raw(StatusCode::OK, json!({"jsonrpc":"2.0","id":"wrong","result":{"protocolVersion":PREVIOUS,"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}).to_string()),
        Reply::raw(StatusCode::OK, json!({"jsonrpc":"2.0","id":null,"result":{}}).to_string()),
        Reply::result(json!([])),
        Reply::error(StatusCode::BAD_REQUEST, -32601, None),
    ] {
        let fixture = CompatFixture::new(Plan { initialize: initialize.header("mcp-session-id", SESSION), ..Plan::default() }).await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, false);
        assert_eq!(fixture.methods(), ["server/discover", "initialize"]);
    }
}

#[tokio::test]
async fn python_style_probe_session_is_cleanup_only_and_later_headers_are_ignored() {
    let probe = Reply::raw(StatusCode::BAD_REQUEST, json!({"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"private-probe-rejection"}}).to_string()).header("mcp-session-id", PROBE_SESSION);
    let fixture = CompatFixture::new(Plan {
        probe,
        later_sessions: vec![SESSION.into(), "private-ignored-replacement".into()],
        ..Plan::default()
    })
    .await;
    let result = fixture.invoke().await.unwrap();
    assert_eq!(
        fixture.methods(),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "DELETE",
            "DELETE"
        ]
    );
    let requests = fixture.requests();
    for request in &requests {
        match request.method() {
            "server/discover" | "initialize" => {
                assert!(!request.headers.contains_key("mcp-session-id"))
            }
            "notifications/initialized" | "tools/call" => {
                assert_eq!(request.headers["mcp-session-id"], SESSION)
            }
            _ => {}
        }
    }
    let deleted = requests
        .iter()
        .filter(|r| r.method() == "DELETE")
        .map(|r| r.headers["mcp-session-id"].to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(deleted, [SESSION, PROBE_SESSION]);
    assert!(
        !serde_json::to_string(&result.audit)
            .unwrap()
            .contains("private-")
    );
}

#[tokio::test]
async fn cleanup_candidates_are_bounded_validated_and_deduplicated() {
    for sessions in [
        vec!["".into()],
        vec!["bad session".into()],
        vec!["x".repeat(4097)],
        vec![PROBE_SESSION.into(), PROBE_SESSION.into()],
    ] {
        let mut plan = Plan::default();
        plan.probe.headers = sessions
            .into_iter()
            .map(|value| ("mcp-session-id", value))
            .collect();
        let fixture = CompatFixture::new(plan).await;
        fixture.invoke().await.unwrap();
        assert_eq!(fixture.count("DELETE"), 1);
        assert_eq!(
            fixture.requests().last().unwrap().headers["mcp-session-id"],
            SESSION
        );
    }
    let plan = Plan {
        probe: Reply::raw(StatusCode::NOT_FOUND, "").header("mcp-session-id", SESSION),
        ..Plan::default()
    };
    let fixture = CompatFixture::new(plan).await;
    fixture.invoke().await.unwrap();
    assert_eq!(fixture.count("DELETE"), 1);
    let plan = Plan {
        probe: Reply::error(StatusCode::OK, -32601, None).header("mcp-session-id", PROBE_SESSION),
        ..Plan::default()
    };
    let fixture = CompatFixture::new(plan).await;
    fixture.invoke().await.unwrap();
    assert_eq!(
        fixture.count("DELETE"),
        1,
        "HTTP 200 never creates a probe cleanup candidate"
    );
    for probe in [
        Reply::raw(StatusCode::UNAUTHORIZED, ""),
        Reply::error(StatusCode::BAD_REQUEST, -32020, None),
        Reply::raw(StatusCode::BAD_REQUEST, "").header("www-authenticate", "Bearer"),
    ] {
        let fixture = CompatFixture::new(Plan {
            probe: probe.header("mcp-session-id", PROBE_SESSION),
            ..Plan::default()
        })
        .await;
        fixture.invoke().await.unwrap_err();
        assert_eq!(fixture.methods(), ["server/discover"]);
    }
}

#[tokio::test]
async fn cleanup_failures_never_replace_success_or_the_original_tool_failure() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::NOT_FOUND,
        StatusCode::METHOD_NOT_ALLOWED,
        StatusCode::UNAUTHORIZED,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        for failed_call in [false, true] {
            let mut plan = Plan {
                cleanup: Reply::raw(status, "private-cleanup-error"),
                ..Plan::default()
            };
            if failed_call {
                plan.call = Reply::raw(StatusCode::BAD_GATEWAY, "private-call-error");
            }
            let fixture = CompatFixture::new(plan).await;
            match fixture.invoke().await {
                Ok(result) => {
                    assert!(!failed_call);
                    assert_eq!(result.upstream_status, Some(200));
                    assert_eq!(result.result["mutationStatus"], "applied_unverified");
                }
                Err(error) => {
                    assert!(failed_call);
                    assert_eq!(error.upstream_status, Some(502));
                    assert_write(&error, true);
                }
            }
            assert_eq!(fixture.count("tools/call"), 1);
            assert_eq!(fixture.count("DELETE"), 1);
        }
    }
}

#[tokio::test]
async fn cleanup_deadline_keeps_the_known_success_and_all_candidates_share_one_budget() {
    // A deliberately stalled cleanup must not turn a known tool result into a timeout.
    let mut plan = Plan::default();
    plan.probe = plan.probe.header("mcp-session-id", PROBE_SESSION);
    plan.cleanup.delay = Duration::from_secs(5);
    let fixture = CompatFixture::new(plan).await;
    let mut host = test_host();
    host.limits.request_timeout_ms = 250;
    let started = Instant::now();
    let result = fixture
        .provider(&host)
        .invoke(invocation(json!({"region":"east"}), "secret"))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    assert_eq!(result.upstream_status, Some(200));
    assert_eq!(fixture.count("DELETE"), 1);
    let requests_at_return = fixture.requests().len();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        fixture.requests().len(),
        requests_at_return,
        "no cleanup continues after return"
    );

    let mut plan = Plan::default();
    plan.probe = plan.probe.header("mcp-session-id", PROBE_SESSION);
    plan.cleanup.delay = Duration::from_millis(1_500);
    let fixture = CompatFixture::new(plan).await;
    let mut host = test_host();
    host.limits.request_timeout_ms = 5_000;
    let started = Instant::now();
    fixture
        .provider(&host)
        .invoke(invocation(json!({"region":"east"}), "secret"))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_800),
        "fixture must consume the shared cleanup budget: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2_800),
        "cleanup must share one two-second budget: {elapsed:?}"
    );
    assert_eq!(fixture.count("DELETE"), 2);
}

#[tokio::test]
async fn legacy_call_errors_have_one_dispatch_and_no_session_recovery() {
    for call in [
        Reply::raw(StatusCode::UNAUTHORIZED, ""),
        Reply::raw(StatusCode::NOT_FOUND, "session expired"),
        Reply::raw(StatusCode::INTERNAL_SERVER_ERROR, ""),
        Reply::raw(StatusCode::OK, "{malformed"),
        Reply::result(json!({"content":[],"isError":true})),
        Reply::result(json!({"content":[],"structuredContent":"wrong-schema"})),
        Reply::result(json!({"resultType":"input_required","inputRequests":[]})),
    ] {
        let skip_cleanup = matches!(
            call.status,
            StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND
        );
        let fixture = CompatFixture::new(Plan {
            call,
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, true);
        assert_eq!(fixture.count("server/discover"), 1);
        assert_eq!(fixture.count("initialize"), 1);
        assert_eq!(fixture.count("tools/call"), 1);
        assert_eq!(fixture.count("DELETE"), usize::from(!skip_cleanup));
    }
    let mut plan = Plan::default();
    plan.call.delay = Duration::from_secs(1);
    let fixture = CompatFixture::new(plan).await;
    let mut host = test_host();
    host.limits.request_timeout_ms = 100;
    let error = fixture
        .provider(&host)
        .invoke(invocation(json!({"region":"east"}), "secret"))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_write(&error, true);
    assert_eq!(fixture.count("tools/call"), 1);
    assert_eq!(fixture.count("DELETE"), 0);
}

#[tokio::test]
async fn legacy_server_requests_and_closed_priming_streams_fail_without_resumption() {
    for body in [
        "data: {\"jsonrpc\":\"2.0\",\"id\":\"server-ping\",\"method\":\"ping\"}\n\n",
        ": priming\nevent: message\ndata:\n\n",
    ] {
        let fixture = CompatFixture::new(Plan {
            call: Reply::raw(StatusCode::OK, body).header("content-type", "text/event-stream"),
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.unwrap_err();
        assert_write(&error, true);
        assert_eq!(fixture.count("tools/call"), 1);
        assert_eq!(fixture.count("initialize"), 1);
        assert!(
            !fixture
                .requests()
                .iter()
                .any(|r| r.http_method == Method::GET)
        );
    }
}

#[tokio::test]
async fn legacy_oauth_revalidates_every_phase_and_never_recovers_or_replays() {
    for permitted_requests in 0..=4 {
        let fixture = CompatFixture::new(Plan::default()).await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &oauth_definition(&fixture.endpoint),
                &[action()],
                None,
                &host.context(),
            )
            .unwrap();
        let (request, lease) = leased_invocation(&fixture.endpoint, false);
        lease
            .reject_after
            .store(permitted_requests, Ordering::SeqCst);
        let outcome = provider.invoke(request).await;
        if permitted_requests == 4 {
            let result = outcome.unwrap();
            assert_eq!(result.result["mutationStatus"], "applied_unverified");
            assert_eq!(
                fixture.count("DELETE"),
                0,
                "a revoked cleanup lease is not sent"
            );
        } else {
            let error = outcome.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
            assert_write(&error, false);
            assert_eq!(fixture.count("tools/call"), 0);
        }
        assert_eq!(fixture.requests().len(), permitted_requests);
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
        assert!(lease.rejected.lock().unwrap().is_empty());
    }
    let fixture = CompatFixture::new(Plan {
        probe: Reply::raw(StatusCode::BAD_REQUEST, "").header("mcp-session-id", PROBE_SESSION),
        ..Plan::default()
    })
    .await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &oauth_definition(&fixture.endpoint),
            &[action()],
            None,
            &host.context(),
        )
        .unwrap();
    let (request, lease) = leased_invocation(&fixture.endpoint, false);
    provider.invoke(request).await.unwrap();
    assert_eq!(lease.validations.load(Ordering::SeqCst), 6);
    assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
    assert!(lease.rejected.lock().unwrap().is_empty());
    for (index, request) in fixture.requests().iter().enumerate() {
        assert_eq!(
            request.headers["authorization"],
            if index == 0 {
                "Bearer initial-delegated-token"
            } else {
                "Bearer renewed-delegated-token"
            }
        );
    }
}

#[tokio::test]
async fn oauth_401_marks_only_the_normal_request_access_version_and_cleanup_401_is_isolated() {
    for phase in ["probe", "initialize", "initialized", "call", "cleanup"] {
        let mut plan = Plan::default();
        let unauthorized = Reply::raw(StatusCode::UNAUTHORIZED, "private-rejected-token");
        match phase {
            "probe" => plan.probe = unauthorized,
            "initialize" => plan.initialize = unauthorized,
            "initialized" => plan.initialized = unauthorized,
            "call" => plan.call = unauthorized,
            "cleanup" => plan.cleanup = unauthorized,
            _ => unreachable!(),
        }
        let fixture = CompatFixture::new(plan).await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &oauth_definition(&fixture.endpoint),
                &[action()],
                None,
                &host.context(),
            )
            .unwrap();
        let (request, lease) = leased_invocation(&fixture.endpoint, false);
        let outcome = provider.invoke(request).await;
        if phase == "cleanup" {
            let result = outcome.unwrap();
            assert_eq!(result.upstream_status, Some(200));
            assert!(lease.rejected.lock().unwrap().is_empty());
            assert_eq!(fixture.count("DELETE"), 1);
        } else {
            let error = outcome.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamUnauthorized);
            assert_eq!(error.upstream_status, Some(401));
            assert_write(&error, phase == "call");
            assert_eq!(
                *lease.rejected.lock().unwrap(),
                [if phase == "probe" {
                    "version-one"
                } else {
                    "version-two"
                }]
            );
            assert_eq!(fixture.count("DELETE"), 0);
        }
        assert_eq!(
            fixture.count("tools/call"),
            usize::from(matches!(phase, "call" | "cleanup"))
        );
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn legacy_startup_failure_owns_status_and_preserves_rate_limit_details() {
    for status in [StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS] {
        let fixture = CompatFixture::new(Plan {
            initialize: Reply::raw(status, "private-initialize-error").header("retry-after", "7"),
            ..Plan::default()
        })
        .await;
        let error = fixture.invoke().await.unwrap_err();
        assert_eq!(error.upstream_status, Some(status.as_u16()));
        assert_write(&error, false);
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
            assert_eq!(error.result.as_ref().unwrap()["retryAfterSeconds"], 7);
        } else {
            assert_eq!(error.reason_code(), ReasonCode::UpstreamUnauthorized);
        }
        assert_eq!(fixture.methods(), ["server/discover", "initialize"]);
    }
    let fixture = CompatFixture::new(Plan::default()).await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &oauth_definition(&fixture.endpoint),
            &[action()],
            None,
            &host.context(),
        )
        .unwrap();
    let (request, lease) = leased_invocation(&fixture.endpoint, false);
    lease.reject_after.store(1, Ordering::SeqCst);
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(
        error.upstream_status, None,
        "pre-send initialize failure must not inherit probe 404"
    );
}

#[tokio::test]
async fn concurrent_users_and_discovery_have_independent_sessions() {
    let fixture = CompatFixture::new(Plan {
        unique_sessions: true,
        ..Plan::default()
    })
    .await;
    let host = test_host();
    let mut def = definition(&fixture.endpoint);
    def.execution_bindings
        .push(ImportedCredentialBinding::token(
            ImportedCredentialMode::PerUser,
            ImportedCredentialDelivery::Bearer,
        ));
    let provider = McpAdapter
        .build(&def, &[action()], None, &host.context())
        .unwrap();
    let mut alice = invocation(json!({"region":"east"}), "alice-private-token");
    alice = InvocationBuilder::from(alice)
        .credential_mode(CredentialMode::PerUser)
        .build();
    let mut bob = invocation(json!({"region":"west"}), "bob-private-token");
    bob = InvocationBuilder::from(bob)
        .credential_mode(CredentialMode::PerUser)
        .build();
    bob = InvocationBuilder::from(bob).principal("bob").build();
    let (discovery, alice, bob) = tokio::join!(
        fixture.discover(),
        provider.invoke(alice),
        provider.invoke(bob)
    );
    discovery.unwrap();
    alice.unwrap();
    bob.unwrap();
    let mut sessions = BTreeSet::new();
    for token in [
        "private-discovery-token",
        "alice-private-token",
        "bob-private-token",
    ] {
        let requests = fixture
            .requests()
            .into_iter()
            .filter(|r| r.headers["authorization"] == format!("Bearer {token}"))
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[0].method(), "server/discover");
        assert_eq!(requests[1].method(), "initialize");
        assert_eq!(requests[2].method(), "notifications/initialized");
        let session = requests[2].headers["mcp-session-id"].to_str().unwrap();
        assert!(sessions.insert(session.to_owned()));
        for request in &requests[2..] {
            assert_eq!(request.headers["mcp-session-id"], session);
        }
        for request in &requests[..2] {
            assert!(!request.headers.contains_key("mcp-session-id"));
        }
        assert_eq!(requests[4].method(), "DELETE");
    }
    assert_eq!(fixture.count("tools/call"), 2);
    assert_eq!(fixture.count("tools/list"), 1);
}

#[tokio::test]
async fn legacy_trace_projection_keeps_sessions_errors_payloads_and_instructions_private() {
    let fixture = CompatFixture::new(Plan {
        probe: Reply::error(StatusCode::BAD_REQUEST, -32600, None)
            .header("mcp-session-id", PROBE_SESSION),
        call: Reply {
            sse: true,
            ..Plan::default().call
        },
        ..Plan::default()
    })
    .await;
    let capture = test_support::install_trace_capture().start();
    let result = capture
        .run(agent_access_provider::host::with_provider_context(
            CorrelationContext::for_tests(),
            "example".into(),
            "item.update".into(),
            fixture.invoke(),
        ))
        .await
        .unwrap();
    assert_eq!(
        result.result["upstreamMcp"]["content"][0]["text"],
        "private-tool-output"
    );
    let logged = serde_json::to_string(&capture.take_events()).unwrap();
    for private in [
        SESSION,
        PROBE_SESSION,
        "private-upstream-error-message",
        "private-server-instructions",
        "private-server-extension",
        "private-opaque-notification",
        "private-tool-input",
        "private-tool-output",
        "private-static-token",
    ] {
        assert!(
            !logged.contains(private),
            "private wire value leaked: {private}"
        );
    }
    assert!(logged.contains("upstream_request_completed"));
    assert!(
        !serde_json::to_string(&result.audit)
            .unwrap()
            .contains("private-")
    );
}

#[derive(Clone)]
struct VersionedSdkServer {
    versions: Vec<ProtocolVersion>,
}
impl ServerHandler for VersionedSdkServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(self.versions.clone())
    }
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(self.versions[0].clone())
            .with_server_info(Implementation::new("Pinned SDK fixture", "1"))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        SdkServer.get_tool(name)
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        SdkServer.list_tools(request, context).await
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        SdkServer.call_tool(request, context).await
    }
}
async fn record_sdk_requests(
    State(recorded): State<Arc<Mutex<Vec<Recorded>>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    recorded.lock().unwrap().push(Recorded {
        http_method: parts.method.clone(),
        headers: parts.headers.clone(),
        body,
    });
    next.run(axum::extract::Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[tokio::test]
async fn pinned_sdk_previous_only_servers_support_sessions_and_sessionless_json_and_sse() {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };
    for sessions in [false, true] {
        for json_response in [false, true] {
            let config = StreamableHttpServerConfig::default()
                .with_legacy_session_mode(sessions)
                .with_json_response(json_response)
                .with_sse_keep_alive(None);
            let service: StreamableHttpService<VersionedSdkServer, LocalSessionManager> =
                StreamableHttpService::new(
                    || {
                        Ok(VersionedSdkServer {
                            versions: vec![ProtocolVersion::V_2025_11_25],
                        })
                    },
                    Default::default(),
                    config,
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
            let recorded: Arc<Mutex<Vec<Recorded>>> = Default::default();
            let app = Router::new().nest_service("/mcp", service).layer(
                axum::middleware::from_fn_with_state(recorded.clone(), record_sdk_requests),
            );
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let host = test_host();
            let discovery = McpAdapter
                .discover(
                    &definition(&endpoint),
                    &ImportedDiscoveryAuthentication::Static(credential("sdk-secret")),
                    None,
                    &host.context(),
                )
                .await
                .unwrap();
            assert_eq!(discovery.protocol_version, PREVIOUS);
            assert_eq!(discovery.tools.len(), 1);
            assert_eq!(
                discovery.metadata["serverInfo"]["name"],
                "Pinned SDK fixture"
            );
            let provider = McpAdapter
                .build(&definition(&endpoint), &[action()], None, &host.context())
                .unwrap();
            let result = provider
                .invoke(invocation(json!({"region":"sdk-east"}), "sdk-secret"))
                .await
                .unwrap();
            assert_eq!(
                result.result["upstreamMcp"]["structuredContent"]["region"],
                "sdk-east"
            );
            assert_eq!(result.audit.as_ref().unwrap()["protocolVersion"], PREVIOUS);
            let requests = recorded.lock().unwrap().clone();
            for method in ["server/discover", "initialize", "notifications/initialized"] {
                assert_eq!(requests.iter().filter(|r| r.method() == method).count(), 2);
            }
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.method() == "tools/call")
                    .count(),
                1
            );
            assert_eq!(
                requests.iter().filter(|r| r.method() == "DELETE").count(),
                if sessions { 2 } else { 0 }
            );
            let mut used_sessions = BTreeSet::new();
            for request in requests.iter().filter(|r| {
                matches!(
                    r.method(),
                    "notifications/initialized" | "tools/list" | "tools/call"
                )
            }) {
                assert_eq!(request.headers["mcp-protocol-version"], PREVIOUS);
                assert_eq!(request.headers.contains_key("mcp-session-id"), sessions);
                assert!(!request.headers.contains_key("mcp-method"));
                if sessions {
                    used_sessions.insert(
                        request.headers["mcp-session-id"]
                            .to_str()
                            .unwrap()
                            .to_owned(),
                    );
                }
            }
            assert_eq!(used_sessions.len(), if sessions { 2 } else { 0 });
            server.abort();
        }
    }
}

#[tokio::test]
async fn pinned_sdk_both_versions_prefers_current_without_legacy_state() {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(true)
        .with_json_response(true)
        .with_sse_keep_alive(None);
    let service: StreamableHttpService<VersionedSdkServer, LocalSessionManager> =
        StreamableHttpService::new(
            || {
                Ok(VersionedSdkServer {
                    versions: vec![ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28],
                })
            },
            Default::default(),
            config,
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let recorded: Arc<Mutex<Vec<Recorded>>> = Default::default();
    let app =
        Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn_with_state(
                recorded.clone(),
                record_sdk_requests,
            ));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let host = test_host();
    let discovery = McpAdapter
        .discover(
            &definition(&endpoint),
            &ImportedDiscoveryAuthentication::Static(credential("sdk-secret")),
            None,
            &host.context(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.protocol_version, PROTOCOL_VERSION);
    let provider = McpAdapter
        .build(&definition(&endpoint), &[action()], None, &host.context())
        .unwrap();
    let result = provider
        .invoke(invocation(json!({"region":"sdk-east"}), "sdk-secret"))
        .await
        .unwrap();
    assert_eq!(
        result.audit.as_ref().unwrap()["protocolVersion"],
        PROTOCOL_VERSION
    );
    let requests = recorded.lock().unwrap().clone();
    assert_eq!(
        requests.iter().map(Recorded::method).collect::<Vec<_>>(),
        [
            "server/discover",
            "tools/list",
            "server/discover",
            "tools/call"
        ]
    );
    for request in requests.iter() {
        assert_eq!(request.headers["mcp-protocol-version"], PROTOCOL_VERSION);
        assert!(!request.headers.contains_key("mcp-session-id"));
    }
    server.abort();
}

#[tokio::test]
async fn eligible_4xx_version_evidence_and_terminal_codes_do_not_require_rpc_correlation() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::NOT_FOUND,
        StatusCode::METHOD_NOT_ALLOWED,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        StatusCode::UNPROCESSABLE_ENTITY,
    ] {
        for (code, data, allowed) in [
            (-32022, json!({"supported":[PREVIOUS]}), true),
            (
                -32000,
                json!({"supported":[PROTOCOL_VERSION,PREVIOUS],"requested":PROTOCOL_VERSION}),
                true,
            ),
            (-32020, json!({"supported":[PREVIOUS]}), false),
            (-32021, json!({"supported":[PREVIOUS]}), false),
            (
                -32022,
                json!({"supported":[PREVIOUS],"requested":"different"}),
                false,
            ),
        ] {
            let probe = Reply::raw(status, json!({"jsonrpc":"2.0","id":"server-error","error":{"code":code,"message":"private-middleware-error","data":data}}).to_string());
            let fixture = CompatFixture::new(Plan {
                probe,
                ..Plan::default()
            })
            .await;
            assert_eq!(fixture.invoke().await.is_ok(), allowed, "{status}/{code}");
            assert_eq!(fixture.count("server/discover"), 1);
            assert_eq!(fixture.count("initialize"), usize::from(allowed));
            assert_eq!(fixture.count("tools/call"), usize::from(allowed));
        }
    }
}

#[tokio::test]
async fn startup_and_notification_bodies_retain_response_budgets() {
    for phase in ["probe", "initialize", "initialized"] {
        let oversized = "x".repeat(4096);
        let mut plan = Plan::default();
        match phase {
            "probe" => plan.probe = Reply::raw(StatusCode::BAD_REQUEST, oversized),
            "initialize" => {
                plan.initialize =
                    Reply::raw(StatusCode::OK, oversized).header("mcp-session-id", SESSION)
            }
            "initialized" => plan.initialized = Reply::raw(StatusCode::ACCEPTED, oversized),
            _ => unreachable!(),
        }
        let fixture = CompatFixture::new(plan).await;
        let mut host = test_host();
        host.limits.max_upstream_response_bytes = 1500;
        let error = fixture
            .provider(&host)
            .invoke(invocation(json!({"region":"east"}), "secret"))
            .await
            .unwrap_err();
        assert_write(&error, false);
        assert_eq!(fixture.count("initialize"), usize::from(phase != "probe"));
        assert_eq!(fixture.count("tools/call"), 0);
        assert_eq!(fixture.count("DELETE"), usize::from(phase == "initialized"));
    }
    let mut plan = Plan::default();
    plan.probe.delay = Duration::from_secs(1);
    let fixture = CompatFixture::new(plan).await;
    let mut host = test_host();
    host.limits.request_timeout_ms = 100;
    let error = fixture
        .provider(&host)
        .invoke(invocation(json!({"region":"east"}), "secret"))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_write(&error, false);
    assert_eq!(fixture.methods(), ["server/discover"]);
}

#[tokio::test]
async fn legacy_oauth_discovery_rechecks_authority_between_list_pages() {
    for permitted_requests in [4, 5, usize::MAX] {
        let fixture = CompatFixture::new(Plan {
            pages: vec![
                json!({"tools":[],"nextCursor":"1"}),
                json!({"tools":[tool()]}),
            ],
            ..Plan::default()
        })
        .await;
        let (request, lease) = leased_invocation(&fixture.endpoint, false);
        lease
            .reject_after
            .store(permitted_requests, Ordering::SeqCst);
        let outcome = McpAdapter
            .discover(
                &oauth_definition(&fixture.endpoint),
                &ImportedDiscoveryAuthentication::Delegated(
                    request.execution().delegated().cloned().unwrap(),
                ),
                None,
                &test_host().context(),
            )
            .await;
        if permitted_requests == 4 {
            assert!(matches!(
                outcome.unwrap_err(),
                AdapterDiscoveryError::Failed(error) if error.reason_code() == ReasonCode::CredentialInvalid
            ));
            assert_eq!(fixture.count("tools/list"), 1);
        } else {
            assert_eq!(outcome.unwrap().tools.len(), 1);
            assert_eq!(fixture.count("tools/list"), 2);
        }
        assert_eq!(
            fixture.count("DELETE"),
            usize::from(permitted_requests == usize::MAX)
        );
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
        assert!(lease.rejected.lock().unwrap().is_empty());
    }
}

struct ChangingBindingLease {
    inner: Arc<TestLease>,
    after: usize,
    change_audience: bool,
}
#[async_trait]
impl DelegatedLease for ChangingBindingLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        self.inner.binding_identity()
    }
    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        self.inner.mark_rejected(version)
    }
    fn access(&self) -> DelegatedAccess {
        self.inner.access()
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        self.inner.revalidate().await?;
        if self.inner.validations.load(Ordering::SeqCst) > self.after {
            let mut access = self.inner.access.lock().unwrap();
            if self.change_audience {
                access.audience = "https://different.example/mcp".into();
            } else {
                access.target = "https://different.example/mcp".into();
            }
        }
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        self.inner.recover_after_unauthorized().await
    }
}

#[tokio::test]
async fn legacy_requests_reject_changed_resource_or_audience_after_each_startup_phase() {
    for after in 1..=3 {
        for change_audience in [false, true] {
            let fixture = CompatFixture::new(Plan::default()).await;
            let (mut request, lease) = leased_invocation(&fixture.endpoint, false);
            request = InvocationBuilder::from(request)
                .execution(ExecutionAccess::Delegated(
                    agent_access_provider::host::delegated_credential(Arc::new(
                        ChangingBindingLease {
                            inner: lease.clone(),
                            after,
                            change_audience,
                        },
                    )),
                ))
                .build();
            let provider = McpAdapter
                .build(
                    &oauth_definition(&fixture.endpoint),
                    &[action()],
                    None,
                    &test_host().context(),
                )
                .unwrap();
            let error = provider.invoke(request).await.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
            assert_write(&error, false);
            assert_eq!(fixture.requests().len(), after);
            assert_eq!(fixture.count("tools/call"), 0);
            assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
            assert!(lease.rejected.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn normal_http_error_statuses_preserve_existing_categories_in_both_lifecycles() {
    for legacy in [false, true] {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            for method in ["tools/list", "tools/call"] {
                let mut plan = Plan::default();
                if !legacy {
                    plan.probe = Reply::result(json!({
                        "supportedVersions":[PROTOCOL_VERSION],
                        "capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"
                    }));
                }
                let rejected = Reply::raw(status, "private-normal-operation-rejection");
                if method == "tools/call" {
                    plan.call = rejected;
                } else {
                    plan.list_failure = Some(rejected);
                }
                let fixture = CompatFixture::new(plan).await;
                let error = if method == "tools/call" {
                    let error = fixture.invoke().await.unwrap_err();
                    assert_write(&error, true);
                    error
                } else {
                    fixture.discover().await.unwrap_err()
                };
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::UpstreamFailed,
                    "legacy={legacy}, method={method}, status={status}"
                );
                assert_eq!(error.reason_code().http_status(), 424);
                assert_eq!(error.upstream_status, Some(status.as_u16()));
                assert_eq!(fixture.count("server/discover"), 1);
                assert_eq!(fixture.count("initialize"), usize::from(legacy));
                assert_eq!(fixture.count(method), 1);
                assert_eq!(
                    fixture.count("tools/call"),
                    usize::from(method == "tools/call")
                );
                assert_eq!(
                    fixture.count("DELETE"),
                    usize::from(legacy),
                    "an upstream 408 is a completed HTTP response, not local deadline expiry"
                );
                if legacy {
                    assert_eq!(
                        fixture.requests().last().unwrap().headers["mcp-session-id"],
                        SESSION
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn legacy_handshake_http_rejections_preserve_status_categories_and_session_cleanup() {
    for status in [
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        StatusCode::UNPROCESSABLE_ENTITY,
    ] {
        for initialized in [false, true] {
            let mut plan = Plan::default();
            let rejected = Reply::raw(status, "private-handshake-rejection");
            if initialized {
                plan.initialized = rejected;
            } else {
                // An error status cannot mint an adopted session, even if it carries a header.
                plan.initialize = rejected.header("mcp-session-id", SESSION);
            }
            let fixture = CompatFixture::new(plan).await;
            let error = fixture.invoke().await.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
            assert_eq!(error.reason_code().http_status(), 424);
            assert_eq!(error.upstream_status, Some(status.as_u16()));
            assert_write(&error, false);
            assert_eq!(fixture.count("server/discover"), 1);
            assert_eq!(fixture.count("initialize"), 1);
            assert_eq!(
                fixture.count("notifications/initialized"),
                usize::from(initialized)
            );
            assert_eq!(fixture.count("tools/call"), 0);
            assert_eq!(fixture.count("DELETE"), usize::from(initialized));
        }
    }
}

#[tokio::test]
async fn successful_discovery_with_a_challenge_cannot_select_legacy() {
    for current in [false, true] {
        let versions = if current {
            json!([PREVIOUS, PROTOCOL_VERSION])
        } else {
            json!([PREVIOUS])
        };
        let probe = Reply::result(json!({
            "supportedVersions":versions,
            "capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"
        }))
        .header("www-authenticate", "Bearer");
        let fixture = CompatFixture::new(Plan {
            probe,
            ..Plan::default()
        })
        .await;
        if current {
            let result = fixture.invoke().await.unwrap();
            assert_eq!(
                result.audit.as_ref().unwrap()["protocolVersion"],
                PROTOCOL_VERSION
            );
            assert_eq!(fixture.methods(), ["server/discover", "tools/call"]);
        } else {
            let error = fixture.invoke().await.unwrap_err();
            assert_write(&error, false);
            assert_eq!(fixture.methods(), ["server/discover"]);
        }
    }
}
