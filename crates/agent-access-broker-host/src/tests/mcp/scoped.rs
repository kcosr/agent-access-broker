//! Service connection boundaries through the real HTTP router and SDK sessions.
use super::*;
use agent_access_provider::{ScopeRequest, ScopeResolution, ServiceProvider};

const SCOPED: &str = "/mcp/fake";

fn at(path: &str, mut request: Request<Body>) -> Request<Body> {
    *request.uri_mut() = path.parse().unwrap();
    request
}
fn initialize_message() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"scoped-tests","version":"1"}}})
}
pub(in crate::tests) async fn initialize(fixture: &Fixture, path: &str, token: &str) -> String {
    let response = fixture
        .send(at(
            path,
            request(Method::POST, Some(token), None, Some(initialize_message())),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = rpc_body(response).await;
    // The assembly, not the host package, names and versions the server.
    let (assembly, version) = crate::test_composition::TEST_ASSEMBLY;
    assert_eq!(
        body["result"]["serverInfo"]["name"],
        path.strip_prefix("/mcp/").unwrap_or(assembly)
    );
    assert_eq!(body["result"]["serverInfo"]["version"], version);
    assert_eq!(body["result"]["protocolVersion"], VERSION);
    assert_ne!(body["result"]["capabilities"]["tools"]["listChanged"], true);
    assert_eq!(
        fixture
            .send(at(
                path,
                request(
                    Method::POST,
                    Some(token),
                    Some(&session),
                    Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                )
            ))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    session
}
async fn rpc(
    fixture: &Fixture,
    path: &str,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let response = fixture
        .send(at(
            path,
            request(
                Method::POST,
                Some(TOKEN_A),
                Some(session),
                Some(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})),
            ),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    rpc_body(response).await
}
pub(in crate::tests) async fn call(
    fixture: &Fixture,
    path: &str,
    session: &str,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
    rpc(
        fixture,
        path,
        session,
        id,
        "tools/call",
        json!({"name":name,"arguments":arguments}),
    )
    .await
}

#[tokio::test]
async fn scoped_http_names_helpers_calls_and_aggregate_limits_share_one_boundary() {
    let fixture = Fixture::new(|config| fake_invocation_limit(config, 2)).await;
    let scoped = initialize(&fixture, SCOPED, TOKEN_A).await;
    let aggregate = initialize(&fixture, "/mcp", TOKEN_A).await;
    let listing = rpc(&fixture, SCOPED, &scoped, 2, "tools/list", json!({})).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6);
    let echo = tools.iter().find(|tool| tool["name"] == "echo").unwrap();
    assert_eq!(echo["_meta"]["agent-access/service"], "fake");
    assert_eq!(echo["_meta"]["agent-access/action"], "echo");
    for helper in tools
        .iter()
        .filter(|tool| tool["name"] != "echo" && tool["name"] != "services_list")
    {
        assert_eq!(
            helper["inputSchema"]["properties"]["service"]["const"],
            "fake"
        );
    }
    let services = call(&fixture, SCOPED, &scoped, 3, "services_list", json!({})).await;
    assert_eq!(
        structured(&services)["services"].as_array().unwrap().len(),
        1
    );
    assert_eq!(structured(&services)["services"][0]["service"], "fake");
    let filtered = call(
        &fixture,
        SCOPED,
        &scoped,
        4,
        "services_list",
        json!({"prefix":"unrelated"}),
    )
    .await;
    assert_eq!(structured(&filtered)["services"], json!([]));
    let detail = call(
        &fixture,
        SCOPED,
        &scoped,
        5,
        "actions_describe",
        json!({"service":"fake","action":"echo"}),
    )
    .await;
    assert_eq!(structured(&detail)["mcpTool"]["name"], "echo");
    assert_eq!(
        structured(&detail)["mcpTool"]["inputSchema"],
        echo["inputSchema"]
    );
    assert!(structured(&detail).get("scopedMcpName").is_none());
    for (index, helper) in [
        "resource_access_describe",
        "actions_list",
        "actions_describe",
        "services_describe",
    ]
    .into_iter()
    .enumerate()
    {
        let mut arguments = json!({"service":"another"});
        if helper == "actions_describe" {
            arguments["action"] = json!("echo");
        }
        let rejected = call(
            &fixture,
            SCOPED,
            &scoped,
            10 + index as u64,
            helper,
            arguments,
        )
        .await;
        assert_eq!(rejected["result"]["isError"], true, "{rejected}");
    }
    let aggregate_name = "fake_echo";
    for (path, session, name) in [
        (SCOPED, &scoped, aggregate_name),
        ("/mcp", &aggregate, "echo"),
    ] {
        let rejected = call(
            &fixture,
            path,
            session,
            20,
            name,
            json!({"inputs":{"project":"TEST","message":"no"}}),
        )
        .await;
        assert_eq!(rejected["error"]["code"], -32602);
    }
    let arguments = json!({"inputs":{"project":"TEST","message":"same canonical action"}});
    let first = call(&fixture, SCOPED, &scoped, 21, "echo", arguments.clone()).await;
    assert_eq!(structured(&first)["decision"], "allow");
    let second = call(
        &fixture,
        "/mcp",
        &aggregate,
        22,
        aggregate_name,
        arguments.clone(),
    )
    .await;
    assert_eq!(structured(&second)["decision"], "allow");
    let limited = call(&fixture, SCOPED, &scoped, 23, "echo", arguments).await;
    // Admission errors carry human-readable text plus the structured envelope.
    assert_eq!(limited["result"]["isError"], true);
    assert_eq!(
        limited["result"]["structuredContent"]["reasonCode"],
        "rate_limited"
    );
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count(),
        2
    );
    assert!(
        records
            .iter()
            .all(|record| record["service"] == "fake" && record["action"] == "echo")
    );
}

#[tokio::test]
async fn scoped_http_sessions_are_view_bound_and_quotas_span_both_routes() {
    let fixture = Fixture::new(|config| {
        config.mcp.max_sessions = 2;
        config.mcp.max_sessions_per_principal = 2;
    })
    .await;
    let scoped = initialize(&fixture, SCOPED, TOKEN_A).await;
    let aggregate = initialize(&fixture, "/mcp", TOKEN_A).await;
    let full = fixture
        .send(at(
            SCOPED,
            request(
                Method::POST,
                Some(TOKEN_B),
                None,
                Some(initialize_message()),
            ),
        ))
        .await;
    assert_eq!(full.status(), StatusCode::TOO_MANY_REQUESTS);
    for (path, session) in [
        ("/mcp", &scoped),
        (SCOPED, &aggregate),
        ("/mcp/other", &scoped),
    ] {
        for method in [Method::POST, Method::DELETE] {
            let message =
                (method == Method::POST).then(|| json!({"jsonrpc":"2.0","id":8,"method":"ping"}));
            assert_eq!(
                fixture
                    .send(at(
                        path,
                        request(method, Some(TOKEN_A), Some(session), message)
                    ))
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        let cancel=fixture.send(at(path,request(Method::POST,Some(TOKEN_A),Some(session),Some(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":8}}))))).await;
        assert_eq!(cancel.status(), StatusCode::NOT_FOUND);
    }
    for (path, session) in [(SCOPED, &scoped), ("/mcp", &aggregate)] {
        assert_eq!(
            rpc(&fixture, path, session, 9, "ping", json!({})).await["result"],
            json!({})
        );
    }
    assert_eq!(
        fixture
            .send(at(
                SCOPED,
                request(Method::DELETE, Some(TOKEN_A), Some(&scoped), None)
            ))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    initialize(&fixture, SCOPED, TOKEN_B).await;
}

#[tokio::test]
async fn scoped_http_rejects_noncanonical_paths_and_authenticates_before_target_discovery() {
    let fixture = Fixture::new(|_| {}).await;
    for path in [
        "/mcp/%66ake",
        "/mcp/f%61ke",
        "/mcp/fake%2Fother",
        "/mcp/fake/",
        "/mcp/fake/extra",
        "/mcp/FAKE",
        "/mcp/fake?query=1",
        "/mcp?query=1",
        "/mcp/fake%00",
    ] {
        let response = fixture
            .send(at(
                path,
                request(
                    Method::POST,
                    Some(TOKEN_A),
                    None,
                    Some(initialize_message()),
                ),
            ))
            .await;
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
            ),
            "{path}: {}",
            response.status()
        );
        assert!(response.headers().get("location").is_none());
        assert!(response.headers().get("mcp-session-id").is_none());
    }
    for path in [SCOPED, "/mcp/unknown"] {
        assert_eq!(
            fixture
                .send(at(
                    path,
                    request(Method::POST, None, None, Some(initialize_message()))
                ))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let unknown = fixture
        .send(at(
            "/mcp/unknown",
            request(
                Method::POST,
                Some(TOKEN_A),
                None,
                Some(initialize_message()),
            ),
        ))
        .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let unknown_body = response_json(unknown).await;
    publish_reload(&fixture, |config| config.policy.grants.clear()).await;
    let hidden = fixture
        .send(at(
            SCOPED,
            request(
                Method::POST,
                Some(TOKEN_A),
                None,
                Some(initialize_message()),
            ),
        ))
        .await;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(hidden).await, unknown_body);
    // Nothing but the reload is recorded.
    assert!(read_audit_records_without_reloads(&fixture.audit_path).is_empty());
}

#[tokio::test]
async fn scoped_http_hidden_session_keeps_ping_cancel_and_delete_without_canceling_other_views() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture(provider.clone()).await;
    let session = initialize(&fixture, SCOPED, TOKEN_A).await;
    let response=fixture.send(at(SCOPED,request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"echo","arguments":{"inputs":{"project":"TEST","message":"controlled"}}}}))))).await;
    assert_eq!(response.status(), StatusCode::OK);
    provider.wait_entered().await;
    // Cross-view cancellation never reaches the pending operation.
    let wrong=fixture.send(request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":30}})))).await;
    assert_eq!(wrong.status(), StatusCode::NOT_FOUND);
    publish_reload(&fixture, |config| config.policy.grants.clear()).await;
    assert_eq!(
        rpc(&fixture, SCOPED, &session, 31, "ping", json!({})).await["result"],
        json!({})
    );
    for (id, method, params) in [
        (32, "tools/list", json!({})),
        (
            33,
            "tools/call",
            json!({"name":"services_list","arguments":{}}),
        ),
    ] {
        let failure = rpc(&fixture, SCOPED, &session, id, method, params).await;
        assert_eq!(
            failure["error"]["message"],
            "Service MCP view is unavailable"
        );
    }
    // The pending operation still owns the sole native-response permit. A
    // second provider call remains capacity-limited, while control cleanup works.
    let limited = fixture.send(at(SCOPED, request(Method::POST, Some(TOKEN_A), Some(&session), Some(json!({"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"echo","arguments":{"inputs":{"project":"TEST","message":"no"}}}}))))).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let cancel=fixture.send(at(SCOPED,request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":30}}))))).await;
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    assert_eq!(
        fixture
            .send(at(
                SCOPED,
                request(Method::DELETE, Some(TOKEN_A), Some(&session), None)
            ))
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
    let records = read_audit_records_without_reloads(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reasonCode"], "operation_cancelled");
}

#[derive(Clone)]
struct ScopedCatalogProvider {
    file_only: bool,
    reserved: bool,
    revision: u32,
}
impl agent_access_provider::test_support::DescribedProvider for ScopedCatalogProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.credentials = CredentialDescriptor::default();
        if self.file_only {
            descriptor.actions[0] = descriptor.actions[0].clone().raw_download();
        }
        if self.reserved {
            let mut hidden = descriptor.actions[0].clone();
            hidden.action = "services_list".into();
            descriptor.actions.push(hidden);
        }
        if self.revision > 0 {
            descriptor.actions[0].description = "x".repeat(55_600);
            descriptor.actions[0].input_schema =
                json!({"type":"object","properties":{"revision":{"const":self.revision}}});
        }
        descriptor
    }
}
#[async_trait::async_trait]
impl Provider for ScopedCatalogProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("catalog fixture must not execute")
    }
}
/// The catalog provider the fixture's next generations serve as `fake`; until
/// one is published, `fake` is the registration's own provider.
#[derive(Clone, Default)]
struct CatalogSlot(Arc<std::sync::Mutex<Option<ScopedCatalogProvider>>>);

async fn catalog_fixture(configure: impl FnOnce(&mut BrokerConfig)) -> (Fixture, CatalogSlot) {
    let slot = CatalogSlot::default();
    let served = slot.clone();
    let fixture = Fixture::start(configure, |application| {
        application.provider_fixture(
            "fake",
            ProviderFixture::factory(move |context| match served.0.lock().unwrap().clone() {
                Some(provider) => ServiceProvider::from(Arc::new(provider)),
                None => context.registered_provider().unwrap(),
            }),
        )
    })
    .await;
    (fixture, slot)
}

/// Reloads with `provider` serving `fake`.
async fn publish_catalog(fixture: &Fixture, slot: &CatalogSlot, provider: ScopedCatalogProvider) {
    *slot.0.lock().unwrap() = Some(provider);
    publish_reload(fixture, |_| {}).await;
}

#[tokio::test]
async fn scoped_http_file_only_view_is_describable_and_unready_view_keeps_cleanup() {
    let (fixture, catalog) = catalog_fixture(|_| {}).await;
    publish_catalog(
        &fixture,
        &catalog,
        ScopedCatalogProvider {
            file_only: true,
            reserved: false,
            revision: 0,
        },
    )
    .await;
    let session = initialize(&fixture, SCOPED, TOKEN_A).await;
    assert_eq!(
        rpc(&fixture, SCOPED, &session, 40, "tools/list", json!({})).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    let detail = call(
        &fixture,
        SCOPED,
        &session,
        41,
        "actions_describe",
        json!({"service":"fake","action":"echo"}),
    )
    .await;
    assert_eq!(structured(&detail)["action"], "echo");
    assert!(structured(&detail).get("mcpTool").is_none());
    assert_eq!(
        call(&fixture, SCOPED, &session, 42, "echo", json!({"inputs":{}})).await["error"]["code"],
        -32602
    );
    publish_catalog(
        &fixture,
        &catalog,
        ScopedCatalogProvider {
            file_only: false,
            reserved: true,
            revision: 0,
        },
    )
    .await;
    // The reserved provider is caller-hidden, but makes the whole service unready.
    assert_eq!(
        rpc(&fixture, SCOPED, &session, 43, "tools/list", json!({})).await["error"]["message"],
        "Service MCP view is unavailable"
    );
    assert_eq!(
        call(&fixture, SCOPED, &session, 44, "services_list", json!({})).await["error"]["message"],
        "Service MCP view is unavailable"
    );
    assert_eq!(
        call(
            &fixture,
            SCOPED,
            &session,
            47,
            "echo",
            json!({"inputs":{"project":"TEST","message":"no"}})
        )
        .await["error"]["message"],
        "Service MCP view is unavailable"
    );
    assert_eq!(
        rpc(&fixture, SCOPED, &session, 45, "ping", json!({})).await["result"],
        json!({})
    );
    assert_eq!(fixture.send(at(SCOPED,request(Method::POST,Some(TOKEN_A),Some(&session),Some(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}))))).await.status(),StatusCode::ACCEPTED);
    assert_eq!(
        fixture
            .send(at(
                SCOPED,
                request(Method::DELETE, Some(TOKEN_A), Some(&session), None)
            ))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let aggregate = initialize(&fixture, "/mcp", TOKEN_A).await;
    assert_eq!(
        rpc(&fixture, "/mcp", &aggregate, 46, "tools/list", json!({})).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
}

#[tokio::test]
async fn scoped_http_cursor_rejects_other_view_and_changed_definitions() {
    let (fixture, catalog) =
        catalog_fixture(|config| config.mcp.max_response_bytes = 64 * 1024).await;
    publish_catalog(
        &fixture,
        &catalog,
        ScopedCatalogProvider {
            file_only: false,
            reserved: false,
            revision: 1,
        },
    )
    .await;
    let scoped = initialize(&fixture, SCOPED, TOKEN_A).await;
    let aggregate = initialize(&fixture, "/mcp", TOKEN_A).await;
    let first = rpc(&fixture, SCOPED, &scoped, 50, "tools/list", json!({})).await;
    let cursor = first["result"]["nextCursor"].as_str().unwrap();
    assert!(
        rpc(
            &fixture,
            SCOPED,
            &scoped,
            51,
            "tools/list",
            json!({"cursor":cursor})
        )
        .await
        .get("error")
        .is_none()
    );
    assert_eq!(
        rpc(
            &fixture,
            "/mcp",
            &aggregate,
            52,
            "tools/list",
            json!({"cursor":cursor})
        )
        .await["error"]["code"],
        -32602
    );
    publish_catalog(
        &fixture,
        &catalog,
        ScopedCatalogProvider {
            file_only: false,
            reserved: false,
            revision: 2,
        },
    )
    .await;
    assert_eq!(
        rpc(
            &fixture,
            SCOPED,
            &scoped,
            53,
            "tools/list",
            json!({"cursor":cursor})
        )
        .await["error"]["code"],
        -32602
    );
    assert!(
        rpc(&fixture, SCOPED, &scoped, 54, "tools/list", json!({}))
            .await
            .get("error")
            .is_none()
    );
}
