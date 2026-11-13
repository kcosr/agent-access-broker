//! Credential-free imports keep real Broker admission, CLI/MCP and stored plans.
use super::*;

async fn anonymous_api_call(
    State(state): State<ApiRequests>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.0.lock().unwrap().push(WireRequest {
        method: method.to_string(),
        path: uri.to_string(),
        authorization: headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().into()),
        content_type: headers
            .get("content-type")
            .map(|v| v.to_str().unwrap().into()),
        body: body.to_vec(),
    });
    Json(json!({"value":PAYLOAD})).into_response()
}
fn assert_anonymous_call(requests: &ApiRequests, before: usize, path: &str) {
    assert_eq!(requests.len(), before + 1);
    assert_eq!(requests.last().path, path);
    assert_eq!(requests.last().authorization, None);
}
fn invoke_read(config: &Path) -> Value {
    run(
        config,
        &[
            "invoke",
            "readers.item.read",
            "--input-json",
            r#"{"path":{"id":"ABC-12"}}"#,
        ],
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_openapi_actions_keep_admission_and_restart_offline() {
    exercise_anonymous(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_swagger_actions_keep_admission_and_restart_offline() {
    exercise_anonymous(true).await;
}
async fn exercise_anonymous(swagger: bool) {
    let requests = ApiRequests::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api", listener.local_addr().unwrap());
    let api = Router::new()
        .fallback(anonymous_api_call)
        .with_state(requests.clone());
    let _api = ServerTask(tokio::spawn(async move {
        axum::serve(listener, api).await.unwrap()
    }));
    let application = isolated_broker();
    let directory = application.directory().clone();
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([68u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([69u8; 32]))
        .unwrap();
    let (admin, agent, _, _) = seed_import_identities(&directory, &hash);
    let admin_config = config_file(directory.path(), "admin", &base, &admin);
    let agent_config = config_file(directory.path(), "agent", &base, &agent);
    let permissions = ImportPermissions {
        allowed_kinds: vec!["openapi_http".into()],
        allowed_endpoints: vec![endpoint.clone()],
    };
    let broker = application
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    let request = write_request(
        directory.path(),
        "create-anonymous.json",
        json!({
            "service":"readers", "displayName":"Anonymous API", "adapterKind":"openapi_http", "endpoint":endpoint,
            "connectionSettings":{"definitionSource":"upload"}, "executionBindings":[], "discovery":{"kind":"anonymous"}
        }),
    );
    let created = run(
        &admin_config,
        &["admin", "imports", "create", "--request-file", &request],
    );
    assert_eq!(created["result"]["service"]["credentialInputs"], json!({}));
    let (version, revision) = versions(&created);
    let secret = directory
        .secret_file("unexpected.secret", "unused-token")
        .unwrap();
    let put = command(&admin_config)
        .args([
            "admin",
            "imports",
            "credentials",
            "put",
            "readers",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--secret-file",
            secret.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !put.status.success(),
        "anonymous imports have no execution slot"
    );
    let mut doc = document(swagger, &endpoint);
    doc["security"] = json!([]);
    let source = directory.join("anonymous.json");
    std::fs::write(&source, serde_json::to_vec(&doc).unwrap()).unwrap();
    let preview = upload(&admin_config, &source, &created);
    let accepted = accept(&directory, &admin_config, &preview);
    let (version, revision) = versions(&accepted);
    run(
        &admin_config,
        &[
            "admin",
            "imports",
            "status",
            "readers",
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_eq!(requests.len(), 0, "configuration needs no upstream calls");
    let denied = command(&agent_config)
        .args([
            "invoke",
            "readers.item.read",
            "--input-json",
            r#"{"path":{"id":"ABC-12"}}"#,
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success(), "Broker grants remain required");
    let denied = reqwest::Client::new()
        .post(format!("{base}/v1/invoke/readers/item.read"))
        .header(
            "X-Agent-Access-Request-Id",
            uuid::Uuid::new_v4().to_string(),
        )
        .json(&json!({"inputs":{"path":{"id":"ABC-12"}}}))
        .send()
        .await
        .unwrap();
    let status = denied.status();
    let body = denied.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{body}");
    let rejected = command(&admin_config)
        .args([
            "admin",
            "policy",
            "grants",
            "create",
            "--subject",
            "user:agent",
            "--service",
            "readers",
            "--credential-mode",
            "per_user",
            "--execution-context",
            "default",
            "--action",
            "item.read",
        ])
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "anonymous execution is service mode only"
    );
    assert_eq!(requests.len(), 0);
    grant(
        &admin_config,
        "agent",
        "readers",
        "service",
        &["item.read", "item.search"],
    );
    let result = invoke_read(&agent_config);
    assert_eq!(result["result"]["upstreamHttp"]["body"]["value"], PAYLOAD);
    assert_anonymous_call(&requests, 0, "/api/items/ABC-12");
    let mut http = HttpMcp::start(&base, &agent, true).await;
    let before = requests.len();
    let result = http
        .call(
            "tools/call",
            json!({"name":"readItem","arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_anonymous_call(&requests, before, "/api/items/ABC-12");
    let mut stdio = McpProcess::start_scoped(&agent_config, "readers");
    stdio.initialize().await;
    let tools = stdio.request("tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "searchItems")
    );
    let before = requests.len();
    let result = stdio
        .request(
            "tools/call",
            json!({"name":"searchItems","arguments":{"inputs":form_inputs()}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_anonymous_call(&requests, before, "/api/search");
    assert_eq!(requests.last().body, FORM_BYTES);
    stdio.finish().await;

    // A source auth change quarantines the action; cached MCP tools cannot
    // continue using the previously accepted anonymous plan.
    let current = run(&admin_config, &["admin", "imports", "get", "readers"]);
    doc["paths"]["/items/{id}"]["get"]["security"] = json!([{"access":[]}]);
    std::fs::write(&source, serde_json::to_vec(&doc).unwrap()).unwrap();
    let before = requests.len();
    let changed = upload(&admin_config, &source, &current);
    assert_eq!(action(&changed, "item.read")["status"], "quarantined");
    let denied = http
        .call(
            "tools/call",
            json!({"name":"readItem","arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
        )
        .await;
    assert!(
        denied.get("error").is_some() || denied["result"]["isError"] == true,
        "{denied}"
    );
    assert_eq!(requests.len(), before);
    doc["paths"]["/items/{id}"]["get"]["security"] = json!([]);
    std::fs::write(&source, serde_json::to_vec(&doc).unwrap()).unwrap();
    let restored = upload(&admin_config, &source, &changed);
    let accepted = accept(&directory, &admin_config, &restored);
    assert_eq!(action(&accepted, "item.read")["status"], "enabled");
    assert_eq!(accepted["result"]["service"]["slotVersions"], json!({}));
    std::fs::remove_file(&source).unwrap();
    drop(http);
    stop(broker).await;

    let application = isolated_broker().in_directory(directory.clone());
    let base = application.public_url();
    let before = requests.len();
    let broker = application
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    assert_eq!(
        requests.len(),
        before,
        "offline startup uses retained plans"
    );
    let admin_config = config_file(directory.path(), "restarted-admin", &base, &admin);
    let agent_config = config_file(directory.path(), "restarted-agent", &base, &agent);
    let current = run(&admin_config, &["admin", "imports", "get", "readers"]);
    let (version, revision) = versions(&current);
    let refreshed = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "discover",
            "readers",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_eq!(action(&refreshed, "item.read")["status"], "enabled");
    assert_eq!(
        requests.len(),
        before,
        "retained upload discovery performs no network I/O"
    );
    invoke_read(&agent_config);
    assert_anonymous_call(&requests, before, "/api/items/ABC-12");
    stop(broker).await;
}
