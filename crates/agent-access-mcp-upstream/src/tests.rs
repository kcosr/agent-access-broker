use super::*;
use agent_access_provider::test_support::{InvocationBuilder, bearer_credential};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use http::HeaderMap;
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolResponse, CallToolResult, ListToolsResult, ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task::JoinHandle;

mod compatibility;

/// The build host imported MCP tests share: a short request timeout and a
/// 256 KiB response cap.
fn test_host() -> test_support::TestHost {
    test_support::TestHost::with_limits(
        ProviderLimits::default()
            .with_max_upstream_response_bytes(256 * 1024)
            .with_request_timeout_ms(1_000),
    )
}

fn definition(endpoint: &str) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "example".into(),
        display_name: "Example".into(),
        adapter_kind: "mcp_http".into(),
        endpoint: endpoint.into(),
        connection_settings: Default::default(),
        execution_bindings: vec![ImportedCredentialBinding::token(
            ImportedCredentialMode::Service,
            ImportedCredentialDelivery::Bearer,
        )],
        discovery: ImportedDiscoveryCredential::Execution,
        transport_auth: false,
        invocation_limit: None,
    }
}
fn credential(token: &str) -> ExecutionCredential {
    bearer_credential(token)
}
fn action() -> ImportedActionDefinition {
    ImportedActionDefinition {
        action: "item.update".into(),
        source: json!({"toolName":"update_item"}),
        label: None,
        description: "Updates one item".into(),
        input_schema: json!({"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}},"required":["region"],"additionalProperties":false}),
        output_schema: Some(json!({"type":["object","null"]})),
        annotations: json!({}),
        read_only: false,
        download: false,
    }
}
fn invocation(inputs: Value, token: &str) -> ProviderInvocation {
    InvocationBuilder::new("example", "item.update")
        .inputs(inputs)
        .identity(InvocationIdentity::new("alice", true))
        .credential(credential(token))
        .build()
}
fn tool() -> Value {
    let action = action();
    json!({"name":"update_item", "description":action.description,"inputSchema":action.input_schema,"outputSchema":action.output_schema,"annotations":{"readOnlyHint":true}})
}

#[derive(Clone)]
struct FixtureState {
    recorded: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    pages: Vec<Value>,
    result: Value,
    sse: bool,
    delay: Duration,
    status: StatusCode,
    wrong_id: bool,
    version: &'static str,
}
impl Default for FixtureState {
    fn default() -> Self {
        Self {
            recorded: Default::default(),
            pages: vec![json!({"tools":[tool()]})],
            result: json!({"content":[{"type":"text","text":"done"}],"structuredContent":{"ok":true}}),
            sse: false,
            delay: Duration::ZERO,
            status: StatusCode::OK,
            wrong_id: false,
            version: PROTOCOL_VERSION,
        }
    }
}
struct Fixture {
    endpoint: String,
    state: FixtureState,
    server: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(state: FixtureState) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/mcp", post(fixture_handler))
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
    fn calls(&self) -> usize {
        self.state
            .recorded
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| r["method"] == "tools/call")
            .count()
    }
}
async fn fixture_handler(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    state
        .recorded
        .lock()
        .unwrap()
        .push((headers.clone(), request.clone()));
    assert_eq!(headers["mcp-protocol-version"], PROTOCOL_VERSION);
    assert_eq!(headers["mcp-method"], request["method"].as_str().unwrap());
    assert_eq!(
        request
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .unwrap(),
        PROTOCOL_VERSION
    );
    assert_eq!(
        request
            .pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities")
            .unwrap(),
        &json!({})
    );
    // The client names the Broker host and its version, not this adapter.
    assert_eq!(
        request
            .pointer("/params/_meta/io.modelcontextprotocol~1clientInfo")
            .unwrap(),
        &json!({"name": "agent-access-broker-host", "version": env!("CARGO_PKG_VERSION")})
    );
    assert!(!headers.contains_key("mcp-session-id"));
    assert!(!headers.contains_key("last-event-id"));
    let result = match request["method"].as_str().unwrap() {
        "server/discover" => {
            json!({"resultType":"complete","supportedVersions":[state.version],"capabilities":{"tools":{}},"ttlMs":60000,"cacheScope":"public", "instructions":"secret-instructions-not-for-logs", "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"Synthetic MCP","version":"1","title":"Test server","instructions":"opaque-not-retained"},"opaque":"not-retained"}})
        }
        "tools/list" => {
            let page = request
                .pointer("/params/cursor")
                .and_then(Value::as_str)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            state.pages[page.min(state.pages.len() - 1)].clone()
        }
        "tools/call" => {
            assert_eq!(headers["mcp-name"], "update_item");
            assert_eq!(
                headers["mcp-param-region"],
                schema::encode_header(
                    request
                        .pointer("/params/arguments/region")
                        .unwrap()
                        .as_str()
                        .unwrap()
                )
            );
            tokio::time::sleep(state.delay).await;
            if state.status != StatusCode::OK {
                return (
                    state.status,
                    [("retry-after", "7"), ("location", "http://127.0.0.1/other")],
                    "not retried",
                )
                    .into_response();
            }
            state.result.clone()
        }
        method => panic!("unexpected method {method}"),
    };
    let id = if state.wrong_id && request["method"] == "tools/call" {
        json!(777)
    } else {
        request["id"].clone()
    };
    let body = json!({"jsonrpc":"2.0","id":id,"result":result});
    if state.sse {
        ([("content-type","text/event-stream"),("mcp-session-id","ignored")],format!(":hello\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"data\":\"hidden-secret\"}}}}\r\n\r\ndata: {body}\r\n\r\n")).into_response()
    } else {
        ([("mcp-session-id", "ignored")], Json(body)).into_response()
    }
}

#[tokio::test]
async fn discovers_every_page_retains_unsupported_rows_and_requires_reviewed_reads() {
    let invalid = json!({"name":"bad", "inputSchema":{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"No"}}}});
    let fixture = Fixture::new(FixtureState {
        pages: vec![
            json!({"tools":[tool()],"nextCursor":"1","cacheScope":"private","ttlMs":5000}),
            json!({"tools":[invalid],"cacheScope":"public","ttlMs":0}),
        ],
        ..Default::default()
    })
    .await;
    let host = test_host();
    let discovered = McpAdapter
        .discover(
            &definition(&fixture.endpoint),
            &ImportedDiscoveryAuthentication::Static(credential("discovery-only")),
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .await
        .unwrap();
    assert_eq!(discovered.tools.len(), 2);
    assert_eq!(
        discovered.metadata["serverInfo"],
        json!({"name":"Synthetic MCP","version":"1","title":"Test server"})
    );
    assert!(!discovered.metadata.to_string().contains("not-retained"));
    assert_eq!(
        discovered.metadata["listings"],
        json!([
            {"cacheScope":"private","ttlMs":5000}, {"cacheScope":"public","ttlMs":0}
        ])
    );
    assert_eq!(discovered.tools[0].read_only_hint, Some(true));
    assert!(!discovered.tools[0].definition.read_only);
    assert!(discovered.tools[0].unsupported_reason.is_none());
    assert!(discovered.tools[1].unsupported_reason.is_some());
    assert_eq!(fixture.calls(), 0);
    assert_eq!(fixture.state.recorded.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn invoke_uses_accepted_schema_no_listing_and_preserves_nullable_result() {
    let fixture = Fixture::new(FixtureState {
        result: json!({"structuredContent":null}),
        sse: true,
        ..Default::default()
    })
    .await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &definition(&fixture.endpoint),
            &[action()],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    let result = agent_access_provider::host::with_provider_context(
        CorrelationContext::for_tests(),
        "example".into(),
        "item.update".into(),
        provider.invoke(invocation(json!({"region":" café "}), "execution-secret")),
    )
    .await
    .unwrap();
    assert!(
        result.result["upstreamMcp"]
            .get("structuredContent")
            .unwrap()
            .is_null()
    );
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    assert_eq!(result.result["retrySafe"], false);
    let calls = fixture.state.recorded.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1["method"], "server/discover");
    assert_eq!(calls[1].1["method"], "tools/call");
    for (headers, _) in calls.iter() {
        assert_eq!(headers["authorization"], "Bearer execution-secret");
        assert_eq!(
            headers["x-agent-access-request-id"],
            "test-agent-request-id"
        );
    }
}

#[tokio::test]
async fn missing_or_invalid_output_and_continuations_are_unknown_writes_without_replay() {
    for raw in [
        json!({"content":[]}),
        json!({"structuredContent":"wrong"}),
        json!({"resultType":"input_required","inputRequests":[]}),
        json!({"resultType":"other"}),
        json!({"content":[{"type":"unknown","text":"x"}]}),
        json!({"isError":true,"content":[]}),
    ] {
        let fixture = Fixture::new(FixtureState {
            result: raw,
            ..Default::default()
        })
        .await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let error = provider
            .invoke(invocation(json!({"region":"east"}), "secret"))
            .await
            .unwrap_err();
        assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
        assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
        assert_eq!(fixture.calls(), 1);
    }
}

#[tokio::test]
async fn input_and_credential_rejections_dispatch_nothing() {
    let fixture = Fixture::new(Default::default()).await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &definition(&fixture.endpoint),
            &[action()],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    assert_eq!(
        provider
            .invoke(invocation(json!({}), "secret"))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );
    let mut request = invocation(json!({"region":"east"}), "secret");
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::None)
        .build();
    assert_eq!(
        provider.invoke(request).await.unwrap_err().reason_code(),
        ReasonCode::CredentialInvalid
    );
    let mut request = invocation(json!({"region":"east"}), "secret");
    request = InvocationBuilder::from(request)
        .credential_mode(CredentialMode::PerUser)
        .build();
    assert!(provider.invoke(request).await.is_err());
    assert!(fixture.state.recorded.lock().unwrap().is_empty());
}

#[tokio::test]
async fn independent_credentials_and_transport_auth_are_never_reused() {
    let fixture = Fixture::new(Default::default()).await;
    let host = test_host();
    let mut def = definition(&fixture.endpoint);
    def.transport_auth = true;
    def.execution_bindings[0].delivery = ImportedCredentialDelivery::RawHeader {
        name: "X-Backend-Token".into(),
    };
    def.execution_bindings
        .push(ImportedCredentialBinding::token(
            ImportedCredentialMode::PerUser,
            def.execution_bindings[0].delivery.clone(),
        ));
    let provider = McpAdapter
        .build(
            &def,
            &[action()],
            Some(credential("front-door")),
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    for token in ["alice-token", "bob-token"] {
        let mut request = invocation(json!({"region":"east"}), token);
        request = InvocationBuilder::from(request)
            .credential_mode(CredentialMode::PerUser)
            .build();
        provider.invoke(request).await.unwrap();
    }
    let calls = fixture.state.recorded.lock().unwrap();
    assert_eq!(calls.len(), 4);
    for (index, (headers, _)) in calls.iter().enumerate() {
        assert_eq!(headers["authorization"], "Bearer front-door");
        assert_eq!(
            headers["x-backend-token"],
            if index < 2 {
                "alice-token"
            } else {
                "bob-token"
            }
        );
    }
}

#[tokio::test]
async fn timeouts_status_errors_redirects_and_mismatched_ids_are_not_retried() {
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let fixture = Fixture::new(FixtureState {
            status,
            ..Default::default()
        })
        .await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let error = provider
            .invoke(invocation(json!({"region":"east"}), "secret"))
            .await
            .unwrap_err();
        assert_eq!(fixture.calls(), 1);
        assert_eq!(error.upstream_status, Some(status.as_u16()));
        assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        }
    }
    for state in [
        FixtureState {
            delay: Duration::from_millis(250),
            ..Default::default()
        },
        FixtureState {
            wrong_id: true,
            ..Default::default()
        },
    ] {
        let fixture = Fixture::new(state).await;
        let mut host = test_host();
        host.limits.request_timeout_ms = 100;
        let provider = McpAdapter
            .build(
                &definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let error = provider
            .invoke(invocation(json!({"region":"east"}), "secret"))
            .await
            .unwrap_err();
        assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
        assert_eq!(fixture.calls(), 1);
    }
}

#[tokio::test]
async fn duplicate_tools_repeated_cursors_and_malformed_metadata_fail_discovery() {
    for state in [
        FixtureState {
            pages: vec![json!({"tools":[tool(),tool()]})],
            ..Default::default()
        },
        FixtureState {
            pages: vec![json!({"tools":[],"nextCursor":"1"})],
            ..Default::default()
        },
        FixtureState {
            pages: vec![json!({"tools":[],"resultType":"input_required"})],
            ..Default::default()
        },
        FixtureState {
            pages: vec![json!({"tools":[],"cacheScope":"other"})],
            ..Default::default()
        },
        FixtureState {
            pages: vec![json!({"tools":[],"ttlMs":"invalid"})],
            ..Default::default()
        },
    ] {
        let fixture = Fixture::new(state).await;
        let host = test_host();
        assert!(
            McpAdapter
                .discover(
                    &definition(&fixture.endpoint),
                    &ImportedDiscoveryAuthentication::Static(credential("secret")),
                    None,
                    &ImportedAdapterContext::default(),
                    &host.context()
                )
                .await
                .is_err()
        );
        assert_eq!(fixture.calls(), 0);
        assert!(fixture.state.recorded.lock().unwrap().len() <= 3);
    }
}

#[tokio::test]
async fn bounded_json_and_sse_results_include_discarded_bytes() {
    for sse in [false, true] {
        let fixture=Fixture::new(FixtureState{result:json!({"content":[{"type":"text","text":"x".repeat(4000)}],"structuredContent":null}),sse,..Default::default()}).await;
        let mut host = test_host();
        host.limits.max_upstream_response_bytes = 1500;
        let provider = McpAdapter
            .build(
                &definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let error = provider
            .invoke(invocation(json!({"region":"east"}), "secret"))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(fixture.calls(), 1);
    }
}

#[tokio::test]
async fn sdk_and_host_trace_events_do_not_include_wire_credentials_inputs_or_results() {
    let fixture = Fixture::new(FixtureState {
        result: json!({"structuredContent":{"secret":"upstream-sensitive-result"}}),
        sse: true,
        ..Default::default()
    })
    .await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &definition(&fixture.endpoint),
            &[action()],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    let capture = test_support::install_trace_capture().start();
    let result = capture
        .run(agent_access_provider::host::with_provider_context(
            CorrelationContext::for_tests(),
            "example".into(),
            "item.update".into(),
            provider.invoke(invocation(
                json!({"region":"private-input-value"}),
                "private-execution-token",
            )),
        ))
        .await
        .unwrap();
    assert_eq!(
        result.result["upstreamMcp"]["structuredContent"]["secret"],
        "upstream-sensitive-result"
    );
    let logged = serde_json::to_string(&capture.take_events()).unwrap();
    for secret in [
        "private-input-value",
        "private-execution-token",
        "upstream-sensitive-result",
        "hidden-secret",
        "secret-instructions-not-for-logs",
    ] {
        assert!(!logged.contains(secret), "secret leaked into trace events");
    }
    assert!(
        logged.contains("upstream_request_completed"),
        "host transport trace must remain enabled: {logged}"
    );
}

#[test]
fn bounded_content_preserves_media_and_structured_values_but_drops_extension_metadata() {
    let mut definition = action();
    definition.output_schema = None;
    let compiled = CompiledAction::new(&definition).unwrap();
    let raw = json!({"_meta":{"brokerOverride":true},"structuredContent":false,"content":[
        {"type":"image","data":"aGVsbG8=","mimeType":"image/png","_meta":{"secret":true}},
        {"type":"audio","data":"aGVsbG8=","mimeType":"audio/wav"},
        {"type":"resource_link","name":"log","uri":"https://example.test/log"},
        {"type":"resource","resource":{"uri":"https://example.test/blob","blob":"aGVsbG8=","_meta":{"secret":true}}}
    ]});
    let result = normalize_result(raw, &compiled).unwrap();
    assert_eq!(result["upstreamMcp"]["structuredContent"], false);
    assert_eq!(
        result["upstreamMcp"]["content"].as_array().unwrap().len(),
        4
    );
    assert!(result["upstreamMcp"].get("_meta").is_none());
    assert!(result["upstreamMcp"]["content"][0].get("_meta").is_none());
    assert!(
        result["upstreamMcp"]["content"][3]["resource"]
            .get("_meta")
            .is_none()
    );
    assert!(
        normalize_result(
            json!({"content":[{"type":"image","data":"not-base64!","mimeType":"image/png"}]}),
            &compiled
        )
        .is_err()
    );
}

#[derive(Clone)]
struct SdkServer;
impl ServerHandler for SdkServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        (name == "update_item").then(|| {
            let mut tool = tool();
            tool["inputSchema"]["properties"]["count"] =
                json!({"type":"integer","x-mcp-header":"Count"});
            serde_json::from_value(tool).unwrap()
        })
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        Ok(ListToolsResult::with_all_items(vec![
            self.get_tool("update_item").unwrap(),
        ]))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        assert_eq!(request.name, "update_item");
        let arguments = request.arguments.unwrap();
        if let Some(count) = arguments.get("count") {
            assert!(
                count.as_i64().is_some(),
                "mirrored body numbers must be canonical integers"
            );
        }
        Ok(CallToolResult::structured(Value::Object(arguments)).into())
    }
}

#[tokio::test]
async fn official_sdk_current_server_accepts_generated_headers_and_rejects_mismatch() {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None);
    let service: StreamableHttpService<SdkServer, LocalSessionManager> =
        StreamableHttpService::new(|| Ok(SdkServer), Default::default(), config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().nest_service("/mcp", service))
            .await
            .unwrap();
    });
    let host = test_host();
    let def = definition(&endpoint);
    let discovery = McpAdapter
        .discover(
            &def,
            &ImportedDiscoveryAuthentication::Static(credential("secret")),
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.tools.len(), 1);
    let mut accepted = action();
    accepted.input_schema["properties"]["count"] = json!({"type":"integer","x-mcp-header":"Count"});
    let provider = McpAdapter
        .build(
            &def,
            &[accepted],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    for region in ["east", " café ", "=?base64?YQ==?=", "line\r\nbreak"] {
        let result = provider
            .invoke(invocation(json!({"region":region}), "secret"))
            .await
            .unwrap();
        assert_eq!(
            result.result["upstreamMcp"]["structuredContent"]["region"],
            region
        );
    }
    for count in [42.0, 1e3, -0.0] {
        let result = provider
            .invoke(invocation(
                json!({"region":"east", "count":count}),
                "secret",
            ))
            .await
            .unwrap();
        assert_eq!(
            result.result["upstreamMcp"]["structuredContent"]["count"].as_i64(),
            Some(count as i64)
        );
    }
    let response=reqwest::Client::new().post(&endpoint).header("content-type","application/json")
        .header("accept","application/json, text/event-stream").header("mcp-protocol-version",PROTOCOL_VERSION)
        .header("mcp-method","tools/list").header("mcp-name","update_item").json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"update_item","arguments":{"region":"east"},"_meta":{"io.modelcontextprotocol/protocolVersion":PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}})).send().await.unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        -32020
    );
    server.abort();
}

#[test]
fn discovery_retains_nested_mirrored_headers_as_unsupported_tools() {
    let row = discovered_tool(&json!({"name":"nested", "inputSchema":{"type":"object","properties":{"outer":{"type":"object","properties":{"inner":{"type":"string","x-mcp-header":"Inner"}}}}}})).unwrap();
    assert!(
        row.unsupported_reason
            .unwrap()
            .contains("direct root property")
    );
}

struct TestLease {
    access: Mutex<DelegatedAccess>,
    validations: AtomicUsize,
    recoveries: AtomicUsize,
    rejected: Mutex<Vec<String>>,
    reject_after: AtomicUsize,
}
#[async_trait]
impl DelegatedLease for TestLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        agent_access_provider::test_support::delegated_binding_id("mcp-test-binding")
    }
    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        self.rejected.lock().unwrap().push(version.into());
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        self.access.lock().unwrap().clone()
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        let count = self.validations.fetch_add(1, Ordering::SeqCst) + 1;
        if count > self.reject_after.load(Ordering::SeqCst) {
            return Err(credential_error());
        }
        if count > 1 {
            let mut access = self.access.lock().unwrap();
            *access = DelegatedAccess::new(
                "renewed-delegated-token",
                access.target(),
                access.audience(),
                "version-two",
                access.expires_at(),
            );
        }
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        Err(credential_error())
    }
}
fn oauth_definition(endpoint: &str) -> ImportedServiceDefinition {
    let mut definition = definition(endpoint);
    definition.execution_bindings = vec![ImportedCredentialBinding {
        owner_mode: ImportedCredentialMode::PerUser,
        mechanism: ImportedAuthMechanism::Oauth,
        delivery: ImportedCredentialDelivery::Bearer,
        status: ImportedBindingStatus::Configured,
        adapter_id: Some("mcp_oauth".into()),
        registration_id: Some("mcp".into()),
        profile: Some("read".into()),
    }];
    definition.discovery = ImportedDiscoveryCredential::PerUser {
        principal: "admin".into(),
    };
    definition
}
fn leased_invocation(
    endpoint: &str,
    reject_after_handshake: bool,
) -> (ProviderInvocation, Arc<TestLease>) {
    let lease = Arc::new(TestLease {
        access: Mutex::new(DelegatedAccess::new(
            "initial-delegated-token",
            endpoint,
            endpoint,
            "version-one",
            i64::MAX,
        )),
        validations: AtomicUsize::new(0),
        recoveries: AtomicUsize::new(0),
        rejected: Mutex::new(Vec::new()),
        reject_after: AtomicUsize::new(if reject_after_handshake {
            1
        } else {
            usize::MAX
        }),
    });
    let mut request = invocation(json!({"region":"east"}), "unused-static-token");
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::None)
        .build();
    request = InvocationBuilder::from(request)
        .credential_mode(CredentialMode::PerUser)
        .build();
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::Delegated(
            agent_access_provider::host::delegated_credential(lease.clone()),
        ))
        .build();
    (request, lease)
}

#[tokio::test]
async fn oauth_discovery_revalidates_each_page_and_stops_when_lease_is_revoked() {
    for revoke_after_first_page in [false, true] {
        let fixture = Fixture::new(FixtureState {
            pages: vec![
                json!({"tools":[],"nextCursor":"1"}),
                json!({"tools":[tool()]}),
            ],
            ..Default::default()
        })
        .await;
        let host = test_host();
        let (request, lease) = leased_invocation(&fixture.endpoint, false);
        if revoke_after_first_page {
            lease.reject_after.store(2, Ordering::SeqCst);
        }
        let result = McpAdapter
            .discover(
                &oauth_definition(&fixture.endpoint),
                &ImportedDiscoveryAuthentication::Delegated(
                    request.execution().delegated().cloned().unwrap(),
                ),
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .await;
        if revoke_after_first_page {
            assert!(matches!(
                result.unwrap_err(),
                AdapterDiscoveryError::Failed(error) if error.reason_code() == ReasonCode::CredentialInvalid
            ));
        } else {
            assert_eq!(result.unwrap().tools.len(), 1);
        }
        assert_eq!(lease.validations.load(Ordering::SeqCst), 3);
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
        let requests = fixture.state.recorded.lock().unwrap();
        assert_eq!(requests.len(), if revoke_after_first_page { 2 } else { 3 });
        assert_eq!(
            requests[0].0["authorization"],
            "Bearer initial-delegated-token"
        );
        for (headers, _) in requests.iter().skip(1) {
            assert_eq!(headers["authorization"], "Bearer renewed-delegated-token");
        }
    }
}

/// A lease whose refresh is already in progress for the same connection.
struct BusyLease(DelegatedAccess);
#[async_trait]
impl DelegatedLease for BusyLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        agent_access_provider::test_support::delegated_binding_id("mcp-busy-binding")
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        self.0.clone()
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Err(agent_access_provider::host::port_failure(
            agent_access_provider::host::HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
        ))
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        Err(credential_error())
    }
}

#[tokio::test]
async fn a_busy_refresh_passes_through_as_the_leases_concurrency_limit() {
    let fixture = Fixture::new(FixtureState::default()).await;
    let host = test_host();
    let provider = McpAdapter
        .build(
            &oauth_definition(&fixture.endpoint),
            &[action()],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    let (request, _) = leased_invocation(&fixture.endpoint, false);
    let request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::Delegated(
            agent_access_provider::host::delegated_credential(Arc::new(BusyLease(
                DelegatedAccess::new(
                    "busy-delegated-token",
                    fixture.endpoint.clone(),
                    fixture.endpoint.clone(),
                    "version-one",
                    i64::MAX,
                ),
            ))),
        ))
        .build();
    let action = request.action().to_owned();
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.decision(), agent_access_provider::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::ConcurrencyLimited);
    assert_eq!(
        error.reason_code().host_port(),
        Some(agent_access_provider::host::HostPort::DelegatedLease)
    );
    assert_eq!(fixture.calls(), 0);
    // Imported services register no domain reasons; the host accepts the
    // lease's failure at the invocation boundary.
    let hook = agent_access_provider::host::hook_context(
        "imported",
        action,
        agent_access_provider::HookPhase::Invocation,
        &[],
    );
    assert_eq!(hook.check_failure(&error), Ok(()));
}

#[tokio::test]
async fn oauth_lease_revalidates_every_post_and_never_recovers_or_replays_a_401_write() {
    for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
        let fixture = Fixture::new(FixtureState {
            status,
            ..Default::default()
        })
        .await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &oauth_definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let (request, lease) = leased_invocation(&fixture.endpoint, false);
        let result = provider.invoke(request).await;
        if status == StatusCode::OK {
            assert!(result.is_ok());
        } else {
            let error = result.err().unwrap();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamUnauthorized);
            assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
            assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
        }
        assert_eq!(fixture.calls(), 1);
        assert_eq!(lease.validations.load(Ordering::SeqCst), 2);
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
        assert_eq!(
            *lease.rejected.lock().unwrap(),
            if status == StatusCode::UNAUTHORIZED {
                vec!["version-two".to_owned()]
            } else {
                vec![]
            }
        );
        let requests = fixture.state.recorded.lock().unwrap();
        assert_eq!(
            requests[0].0["authorization"],
            "Bearer initial-delegated-token"
        );
        assert_eq!(
            requests[1].0["authorization"],
            "Bearer renewed-delegated-token"
        );
    }
}

#[tokio::test]
async fn oauth_lease_binding_revocation_and_static_fallback_fail_before_tool_dispatch() {
    for failure in ["resource", "audience", "revoked", "fallback"] {
        let fixture = Fixture::new(Default::default()).await;
        let host = test_host();
        let provider = McpAdapter
            .build(
                &oauth_definition(&fixture.endpoint),
                &[action()],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        let (mut request, lease) = leased_invocation(&fixture.endpoint, failure == "revoked");
        if failure == "resource" {
            let mut access = lease.access.lock().unwrap();
            *access = DelegatedAccess::new(
                "initial-delegated-token",
                "https://other.example/mcp",
                access.audience(),
                access.version(),
                access.expires_at(),
            );
        }
        if failure == "audience" {
            let mut access = lease.access.lock().unwrap();
            *access = DelegatedAccess::new(
                "initial-delegated-token",
                access.target(),
                "https://other.example/mcp",
                access.version(),
                access.expires_at(),
            );
        }
        if failure == "fallback" {
            request = InvocationBuilder::from(request)
                .execution(ExecutionAccess::Static(credential(
                    "shared-fallback-is-forbidden",
                )))
                .build();
        }
        let error = provider.invoke(request).await.err().unwrap();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
        assert_eq!(fixture.calls(), 0);
        assert_eq!(
            fixture.state.recorded.lock().unwrap().len(),
            usize::from(failure == "revoked")
        );
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn scoped_mcp_names_preserve_accepted_source_text_without_canonical_fallback() {
    let mut action = action();
    for raw in [
        "Original.Name-1",
        "source name/with space",
        "é",
        &"x".repeat(256),
    ] {
        action.source = json!({"toolName":raw});
        McpAdapter.validate_action(&action).unwrap();
        assert_eq!(McpAdapter.scoped_mcp_name(&action).unwrap(), raw);
    }
    for source in [
        json!({}),
        json!({"toolName":null}),
        json!({"toolName":""}),
        json!({"toolName":"ok","extra":true}),
        json!({"toolName":"x".repeat(257)}),
    ] {
        action.source = source;
        assert!(McpAdapter.validate_action(&action).is_err());
        assert!(McpAdapter.scoped_mcp_name(&action).is_err());
    }
}

#[test]
fn accepted_download_semantics_are_rejected_by_mcp() {
    let mut definition = action();
    definition.download = true;
    assert!(
        McpAdapter
            .validate_action(&definition)
            .unwrap_err()
            .contains("download")
    );
    assert!(CompiledAction::new(&definition).is_err());
}
