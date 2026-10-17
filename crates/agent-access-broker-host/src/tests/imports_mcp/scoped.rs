//! Accepted source names resolve independently on each imported service view.
use super::*;
use crate::tests::mcp;
use axum::http::HeaderValue;

async fn fixture_http() -> Fixture {
    let mut fixture = fixture(None).await;
    // The parent fixture seeds synthetic accepted records directly. Match the
    // real adapter's accepted annotation shape so a later refresh can isolate a
    // changed read schema without spuriously quarantining the unchanged write.
    let store = fixture.runtime.managed_store().unwrap();
    for service in ["one", "two"] {
        let catalog = store.imported_catalog().unwrap();
        let record = catalog.service(service).unwrap();
        let actions = record
            .actions
            .iter()
            .map(|action| {
                let mut definition = action.definition.clone();
                definition.annotations = json!({"toolAnnotations":{},"execution":null});
                ImportedActionWrite {
                    secret_inputs: Vec::new(),
                    definition,
                    status: action.status,
                }
            })
            .collect();
        store
            .update_imported_service(
                ImportedServiceUpdateRequest {
                    definition: record.definition.clone(),
                    status: record.status,
                    actions,
                    expected_version: record.version,
                    expected_catalog_revision: catalog.revision,
                    accepted_preview: None,
                    actor: "admin".into(),
                },
                |_| Ok(()),
            )
            .unwrap();
    }
    let mut config = fixture.runtime.config().clone();
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    fixture.broker.reload_config(&config).await;
    fixture.runtime = fixture.broker.runtime();
    fixture
}
fn wire(
    fixture: &Fixture,
    principal: &str,
    service: &str,
    session: Option<&str>,
    message: Value,
) -> Request<Body> {
    let mut request = mcp::request(
        Method::POST,
        Some(&fixture.tokens[principal]),
        session,
        Some(message),
    );
    *request.uri_mut() = format!("/mcp/{service}").parse().unwrap();
    request.headers_mut().insert(
        CONTEXT_CALLER_HEADER,
        HeaderValue::from_static(CONTEXT_CALLER_AUTH),
    );
    request.headers_mut().insert(
        agent_access_core::EXECUTION_CONTEXT_HEADER,
        HeaderValue::from_static("internal"),
    );
    request
}
async fn initialize(fixture: &Fixture, principal: &str, service: &str) -> String {
    let response=fixture.app.clone().oneshot(wire(fixture,principal,service,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"scoped-import-tests","version":"1"}}}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp::rpc_body(response).await["result"]["serverInfo"]["name"],
        service
    );
    let response = fixture
        .app
        .clone()
        .oneshot(wire(
            fixture,
            principal,
            service,
            Some(&session),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    session
}
async fn rpc(
    fixture: &Fixture,
    principal: &str,
    service: &str,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let response = fixture
        .app
        .clone()
        .oneshot(wire(
            fixture,
            principal,
            service,
            Some(session),
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    mcp::rpc_body(response).await
}
async fn read(fixture: &Fixture, principal: &str, service: &str, session: &str, id: u64) -> Value {
    rpc(
        fixture,
        principal,
        service,
        session,
        id,
        "tools/call",
        json!({"name":"read_item","arguments":{"inputs":{"message":"scoped call"}}}),
    )
    .await
}
fn admin_token(fixture: &Fixture) -> String {
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            &BrokerTokenHasher::load(fixture.runtime.config().broker_tokens.as_ref().unwrap())
                .unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "scoped imports".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}
async fn management(
    fixture: &Fixture,
    token: &str,
    method: Method,
    suffix: &str,
    body: Option<Value>,
) -> Value {
    let serialized = body.map(|value| value.to_string());
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        &format!("/v1/admin/imports/one{suffix}"),
        "scoped-http-admin",
        "Authorization",
        format!("Bearer {token}"),
        serialized.as_deref(),
    )
    .await;
    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["result"].clone()
}
fn versions(value: &Value) -> Value {
    json!({"expectedVersion":value["service"]["version"],"expectedCatalogRevision":value["catalogRevision"]})
}
fn tool(read: bool) -> Value {
    let definition = action(read);
    json!({"name":definition.source["toolName"],"description":definition.description,"inputSchema":definition.input_schema,"outputSchema":definition.output_schema})
}

#[tokio::test]
async fn scoped_imports_same_raw_name_uses_selected_service_current_credentials_and_audit() {
    let fixture = fixture_http().await;
    let one = initialize(&fixture, "alice", "one").await;
    let two = initialize(&fixture, "alice", "two").await;
    for (service, session) in [("one", &one), ("two", &two)] {
        let listing = rpc(
            &fixture,
            "alice",
            service,
            session,
            2,
            "tools/list",
            json!({}),
        )
        .await;
        let tools = listing["result"]["tools"].as_array().unwrap();
        let read = tools
            .iter()
            .find(|tool| tool["name"] == "read_item")
            .unwrap();
        assert_eq!(read["_meta"]["agent-access/action"], "inspect");
        assert_eq!(read["_meta"]["agent-access/service"], service);
        assert_eq!(
            read["_meta"]["agent-access/sensitive-output-pointers"],
            json!(["/result/upstreamMcp"])
        );
        assert!(!tools.iter().any(|tool| tool["name"] == "inspect"));
    }
    let services = rpc(
        &fixture,
        "alice",
        "one",
        &one,
        3,
        "tools/call",
        json!({"name":"services_list","arguments":{}}),
    )
    .await;
    assert_eq!(
        mcp::structured(&services)["services"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(mcp::structured(&services)["services"][0]["service"], "one");
    let cross = rpc(
        &fixture,
        "alice",
        "one",
        &one,
        4,
        "tools/call",
        json!({"name":"services_describe","arguments":{"service":"two"}}),
    )
    .await;
    assert_eq!(cross["result"]["isError"], true);
    let wrong_session = fixture
        .app
        .clone()
        .oneshot(wire(
            &fixture,
            "alice",
            "two",
            Some(&one),
            json!({"jsonrpc":"2.0","id":5,"method":"ping"}),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_session.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        mcp::structured(&read(&fixture, "alice", "one", &one, 6).await)["decision"],
        "allow"
    );
    assert_eq!(
        mcp::structured(&read(&fixture, "alice", "two", &two, 7).await)["decision"],
        "allow"
    );
    let bob = initialize(&fixture, "bob", "one").await;
    assert_eq!(
        mcp::structured(&read(&fixture, "bob", "one", &bob, 8).await)["decision"],
        "allow"
    );
    let calls = fixture
        .upstream
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, request)| request["method"] == "tools/call")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 3);
    for ((path, headers, request), (expected_path, expected_token)) in calls.iter().zip([
        ("/one", "Bearer service-one-secret"),
        ("/two", "Bearer service-two-secret"),
        ("/one", "Bearer bob-one-secret"),
    ]) {
        assert_eq!(path, expected_path);
        assert_eq!(headers["authorization"], expected_token);
        assert_eq!(request["params"]["name"], "read_item");
    }
    // The fixture enables HTTP MCP by a reload, which is audited too.
    let records = read_audit_records_without_reloads(&fixture.audit_path);
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| record["action"] == "inspect"
        && record["providerAudit"]["importedService"].is_object()));
    assert!(records.iter().any(|record| record["service"] == "one"));
    assert!(records.iter().any(|record| record["service"] == "two"));
}

#[tokio::test]
async fn scoped_imports_refresh_quarantine_same_id_review_and_replacement_recheck_grants() {
    let fixture = fixture_http().await;
    let admin = admin_token(&fixture);
    let alice = initialize(&fixture, "alice", "one").await;
    let bob = initialize(&fixture, "bob", "one").await;
    assert_eq!(
        mcp::structured(&read(&fixture, "alice", "one", &alice, 10).await)["decision"],
        "allow"
    );
    let mut changed = tool(true);
    changed["inputSchema"]["properties"]["reviewedFlag"] = json!({"type":"boolean"});
    *fixture.upstream.discovery_tools.lock().unwrap() = Some(vec![changed, tool(false)]);
    let current = management(&fixture, &admin, Method::GET, "", None).await;
    let preview = management(
        &fixture,
        &admin,
        Method::POST,
        "/discover",
        Some(versions(&current)),
    )
    .await;
    assert!(
        preview["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["definition"]["action"] == "inspect"
                && action["status"] == "quarantined")
    );
    assert_eq!(
        read(&fixture, "alice", "one", &alice, 11).await["error"]["code"],
        -32602
    );
    assert_eq!(
        rpc(&fixture, "bob", "one", &bob, 12, "tools/list", json!({})).await["error"]["message"],
        "Service MCP view is unavailable"
    );
    let mut accept = versions(&preview);
    accept["manifestHash"] = preview["preview"]["manifestHash"].clone();
    accept["selections"] = json!([{"source":{"toolName":"read_item"},"action":"inspect","readOnly":true,"secretInputs":[]}]);
    accept["confirmAffectedGrants"] = json!(true);
    let accepted = management(&fixture, &admin, Method::POST, "/accept", Some(accept)).await;
    assert_eq!(
        mcp::structured(&read(&fixture, "bob", "one", &bob, 13).await)["decision"],
        "allow"
    );
    let detail = rpc(
        &fixture,
        "bob",
        "one",
        &bob,
        14,
        "tools/call",
        json!({"name":"actions_describe","arguments":{"service":"one","action":"inspect"}}),
    )
    .await;
    assert_eq!(mcp::structured(&detail)["mcpTool"]["name"], "read_item");
    assert_eq!(
        mcp::structured(&detail)["inputSchema"]["properties"]["reviewedFlag"]["type"],
        "boolean"
    );
    let mut retire = versions(&accepted);
    retire["status"] = json!("retired");
    retire["confirm"] = json!(true);
    let retired = management(
        &fixture,
        &admin,
        Method::POST,
        "/actions/inspect/status",
        Some(retire),
    )
    .await;
    let replacement = management(
        &fixture,
        &admin,
        Method::POST,
        "/discover",
        Some(versions(&retired)),
    )
    .await;
    let replacement_action = replacement["preview"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["definition"]["source"]["toolName"] == "read_item")
        .unwrap()["definition"]["action"]
        .as_str()
        .unwrap();
    assert_ne!(replacement_action, "inspect");
    let mut accept = versions(&replacement);
    accept["manifestHash"] = replacement["preview"]["manifestHash"].clone();
    accept["selections"] = json!([{"source":{"toolName":"read_item"},"action":replacement_action,"readOnly":true,"secretInputs":[]}]);
    accept["confirmAffectedGrants"] = json!(true);
    management(&fixture, &admin, Method::POST, "/accept", Some(accept)).await;
    // A cached raw name cannot inherit the retired canonical action's grants.
    assert_eq!(
        read(&fixture, "alice", "one", &alice, 15).await["error"]["code"],
        -32602
    );
    assert_eq!(
        read(&fixture, "bob", "one", &bob, 16).await["error"]["message"],
        "Service MCP view is unavailable"
    );
    let count = fixture
        .upstream
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, request)| request["method"] == "tools/call")
        .count();
    assert_eq!(
        count, 2,
        "quarantine and replacement calls must not reach upstream"
    );
}

#[tokio::test]
async fn scoped_imports_operator_reload_blocks_existing_sessions_and_preserves_grants() {
    let fixture = fixture_http().await;
    let base_config = fixture.runtime.config().clone();
    let state = fixture.broker.state();
    let session = initialize(&fixture, "alice", "one").await;
    assert_eq!(
        mcp::structured(&read(&fixture, "alice", "one", &session, 30).await)["decision"],
        "allow"
    );
    let upstream_count = fixture.upstream.requests.lock().unwrap().len();
    let stored_record = fixture
        .runtime
        .imported_catalog()
        .service("one")
        .unwrap()
        .clone();
    let stored_revision = fixture.runtime.import_catalog_revision();
    let store = fixture.runtime.managed_store().unwrap();
    let grants = serde_json::to_value(store.policy_grants().unwrap()).unwrap();

    for gate in ["endpoint", "kind", "service", "imports"] {
        let mut config = base_config.clone();
        match gate {
            "endpoint" => config
                .imports
                .allowed_endpoints
                .retain(|endpoint| endpoint != &stored_record.definition.endpoint),
            "kind" => config.imports.allowed_kinds = vec!["openapi_http".into()],
            "service" => config.imports.disabled_services = vec!["one".into()],
            "imports" => config.imports.enabled = false,
            _ => unreachable!(),
        }
        fixture.broker.reload_config(&config).await;
        let listing = rpc(
            &fixture,
            "alice",
            "one",
            &session,
            31,
            "tools/list",
            json!({}),
        )
        .await;
        assert_eq!(
            listing["error"]["message"], "Service MCP view is unavailable",
            "{gate}"
        );
        assert_eq!(
            read(&fixture, "alice", "one", &session, 32).await["error"]["message"],
            "Service MCP view is unavailable",
            "{gate}"
        );
        let helper = rpc(
            &fixture,
            "alice",
            "one",
            &session,
            33,
            "tools/call",
            json!({"name":"services_list","arguments":{}}),
        )
        .await;
        assert_eq!(
            helper["error"]["message"], "Service MCP view is unavailable",
            "{gate}"
        );
        let initialize = fixture.app.clone().oneshot(wire(&fixture, "alice", "one", None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"blocked-view","version":"1"}}}))).await.unwrap();
        assert_eq!(initialize.status(), StatusCode::NOT_FOUND, "{gate}");
        assert!(initialize.headers().get("mcp-session-id").is_none());
        assert_eq!(
            response_json(initialize).await,
            json!({"error":"Service MCP view is unavailable"})
        );
        assert_eq!(
            rpc(&fixture, "alice", "one", &session, 34, "ping", json!({})).await["result"],
            json!({})
        );
        assert_eq!(
            fixture.upstream.requests.lock().unwrap().len(),
            upstream_count,
            "{gate} must fail before contacting upstream"
        );
        assert_eq!(
            serde_json::to_value(store.policy_grants().unwrap()).unwrap(),
            grants
        );
        let current = state.current();
        assert_eq!(current.runtime.import_catalog_revision(), stored_revision);
        assert_eq!(
            current.runtime.imported_catalog().service("one"),
            Some(&stored_record)
        );
    }
    // Restoring operator permission reuses the same session and retained grant.
    fixture.broker.reload_config(&base_config).await;
    assert_eq!(
        mcp::structured(&read(&fixture, "alice", "one", &session, 35).await)["decision"],
        "allow"
    );
}
