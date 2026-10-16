//! Generic import setup and invocation through the shipped CLI and both MCP surfaces.
use super::{McpProcess, ServerTask, isolated_broker, stop, toml_string};
use agent_access_broker_host::test_support::FixtureDir;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole,
    PrincipalWriteRequest,
};
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

const CURRENT_MCP: &str = "2026-07-28";
const DOWNSTREAM_MCP: &str = "2025-11-25";
const PAYLOAD: &str = "synthetic-sensitive-import-output";
const RAW_MCP_READ: &str =
    "OriginalRead.with_a_name_longer_than_sixty_four_characters_for_scoped_mcp_protocol_coverage";

#[derive(Clone, Default)]
struct Upstream(Arc<Mutex<Vec<Value>>>);
async fn upstream(
    State(state): State<Upstream>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer imported-backend-token");
    assert_eq!(headers["mcp-protocol-version"], CURRENT_MCP);
    let result = match request["method"].as_str().unwrap() {
        "server/discover" => {
            json!({"supportedVersions":[CURRENT_MCP],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})
        }
        "tools/list" => {
            let schema = json!({"type":"object","$defs":{"message":{"type":"string","enum":["read","write","http MCP read","stdio MCP write"]}},"properties":{"message":{"$ref":"#/$defs/message"}},"required":["message"],"additionalProperties":false});
            json!({"tools":[
                {"name":RAW_MCP_READ,"description":"Reads an item","inputSchema":schema,"annotations":{"readOnlyHint":true}},
                {"name":"update_item","description":"Updates an item","inputSchema":schema}
            ]})
        }
        "tools/call" => {
            json!({"content":[{"type":"text","text":PAYLOAD}],"structuredContent":{"value":PAYLOAD}})
        }
        method => panic!("unexpected upstream method {method}"),
    };
    state.0.lock().unwrap().push(request.clone());
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
}
fn command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.arg("--config").arg(config);
    command
}
fn run(config: &Path, args: &[&str]) -> Value {
    let output = command(config).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "args={args:?} stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn write_request(directory: &Path, name: &str, value: Value) -> String {
    let path = directory.join(name);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path.display().to_string()
}
fn versions(response: &Value) -> (String, String) {
    (
        response["result"]["service"]["version"]
            .as_u64()
            .unwrap()
            .to_string(),
        response["result"]["catalogRevision"]
            .as_u64()
            .unwrap()
            .to_string(),
    )
}
/// Which import kinds and destinations the operator allows.
#[derive(Clone)]
struct ImportPermissions {
    allowed_kinds: Vec<String>,
    allowed_endpoints: Vec<String>,
}

/// Managed identity, policy and store with management, imports limited to
/// `permissions`, and HTTP MCP served at `mcp_public_url`. The credential
/// encryption key and the broker token hash key are the files `key` and
/// `hash` in `directory`.
fn import_document(
    directory: &FixtureDir,
    permissions: &ImportPermissions,
    mcp_public_url: &str,
) -> String {
    let key = directory.join("key");
    format!(
        r#"
[deployment]
enable_fake_service = true

[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
require_registered_principal_for_invocation = true

[broker_tokens]
hash_key_ref = {hash_key}

[credential_encryption]
active_key = "test"

[[credential_encryption.keys]]
id = "test"
provider = "file"
path = {key}

[management]
enabled = true

[policy]
authority = "managed"
default_decision = "deny"

[imports]
enabled = true
allowed_kinds = {allowed_kinds}
allowed_endpoints = {allowed_endpoints}

[mcp]
enabled = true
public_url = {mcp_public_url}

[limits]
upload_spool_dir = {spool}
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = toml_string(format_args!("file:{}", directory.join("hash").display())),
        key = toml_string(key.display()),
        allowed_kinds = serde_json::to_string(&permissions.allowed_kinds).unwrap(),
        allowed_endpoints = serde_json::to_string(&permissions.allowed_endpoints).unwrap(),
        mcp_public_url = toml_string(mcp_public_url),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

fn config_file(directory: &Path, name: &str, base: &str, token: &str) -> std::path::PathBuf {
    let token_path = directory.join(format!("{name}.token"));
    std::fs::write(&token_path, token).unwrap();
    let path = directory.join(format!("{name}.toml"));
    std::fs::write(&path,format!("[service]\nurl={base:?}\n[identity]\nheader=\"Authorization\"\nscheme=\"Bearer\"\ndisabled=false\ntoken_file={:?}\n",token_path.display().to_string())).unwrap();
    path
}
async fn rpc_response(response: reqwest::Response) -> Value {
    assert!(response.status().is_success());
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let text = tokio::time::timeout(Duration::from_secs(10), response.text())
        .await
        .unwrap()
        .unwrap();
    if content_type.starts_with("application/json") {
        return serde_json::from_str(&text).unwrap();
    }
    assert!(content_type.starts_with("text/event-stream"));
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|message| message.get("id").is_some())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_service_cli_setup_invoke_send_and_http_stdio_mcp_share_the_accepted_actions() {
    exercise_import(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_openapi_cli_setup_invoke_send_and_http_stdio_mcp_share_the_accepted_actions() {
    exercise_import(true).await;
}
async fn openapi_call(
    State(state): State<Upstream>,
    headers: HeaderMap,
    method: axum::http::Method,
) -> Json<Value> {
    let authorization = headers["authorization"].to_str().unwrap();
    assert!(
        [
            "Bearer imported-backend-token",
            "Bearer imported-personal-token"
        ]
        .contains(&authorization)
    );
    state
        .0
        .lock()
        .unwrap()
        .push(json!({"method":"api","verb":method.as_str(),"authorization":authorization}));
    Json(json!({"value":PAYLOAD}))
}
async fn exercise_import(openapi: bool) {
    let kind = if openapi { "openapi_http" } else { "mcp_http" };
    let inputs = |value: Value| {
        if openapi && value != json!({}) {
            json!({"query":value})
        } else {
            value
        }
    };
    let sensitive_pointer = if openapi {
        "/result/upstreamHttp"
    } else {
        "/result/upstreamMcp"
    };
    let payload_pointer = if openapi {
        "/result/upstreamHttp/body/value"
    } else {
        "/result/upstreamMcp/structuredContent/value"
    };
    let upstream_state = Upstream::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let endpoint = format!("{origin}/{}", if openapi { "api" } else { "mcp" });
    let definition_url = format!("{origin}/definition.json");
    let message_schema =
        json!({"type":"string","enum":["read","write","http MCP read","stdio MCP write"]});
    let operation = |id: &str| {
        json!({"operationId":id,"parameters":[{"in":"query","name":"message","required":true,"schema":message_schema}],
        "responses":{"200":{"description":"success","content":{"application/json":{"schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}}}}}})
    };
    let mut unnamed = operation("unused");
    unnamed.as_object_mut().unwrap().remove("operationId");
    let document = json!({"openapi":"3.1.1","info":{"title":"Synthetic API","version":"1"},"servers":[{"url":endpoint}],
        "components":{"securitySchemes":{"access":{"type":"http","scheme":"bearer"}}},"security":[{"access":[]}],
        "paths":{"/items":{"get":operation("Read.Item-V1"),"post":operation("update_item")},"/unnamed":{"get":unnamed}}});
    let discovery_state = upstream_state.clone();
    let upstream_app = Router::new()
        .route("/mcp", post(upstream))
        .route("/api/items", get(openapi_call).post(openapi_call))
        .route("/api/unnamed", get(openapi_call))
        .route(
            "/definition.json",
            get(move |headers: HeaderMap| {
                let document = document.clone();
                let state = discovery_state.clone();
                async move {
                    assert!(!headers.contains_key("authorization"));
                    state.0.lock().unwrap().push(json!({"method":"definition"}));
                    Json(document)
                }
            }),
        )
        .with_state(upstream_state.clone());
    let _upstream = ServerTask(tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap()
    }));
    let application = isolated_broker();
    let directory = application.directory().clone();
    // The listener is already bound, so HTTP MCP can name its address.
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([62u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([63u8; 32]))
        .unwrap();
    let permissions = ImportPermissions {
        allowed_kinds: vec![kind.into()],
        allowed_endpoints: if openapi {
            vec![endpoint.clone(), definition_url.clone()]
        } else {
            vec![endpoint.clone()]
        },
    };

    // Seed the managed store before the broker opens and locks it.
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for principal in ["admin", "agent", "personal", "missing"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "admin".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash.display()),
        ..Default::default()
    })
    .unwrap();
    let issue = |principal: &str, class, scopes| {
        store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "import smoke".into(),
                    token_class: class,
                    scopes,
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap()
            .token
    };
    let admin = issue("admin", BrokerTokenClass::Admin, json!({}));
    let agent = issue(
        "agent",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts":["default"]}),
    );
    let personal = issue(
        "personal",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts":["default"]}),
    );
    let missing = issue(
        "missing",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts":["default"]}),
    );
    drop(store);
    let personal_config = config_file(directory.path(), "personal", &base, &personal);
    let missing_config = config_file(directory.path(), "missing", &base, &missing);
    let admin_config = config_file(directory.path(), "admin", &base, &admin);
    let agent_config = config_file(directory.path(), "agent", &base, &agent);
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
        "create.json",
        json!({"service":"imported","displayName":"Imported tools","adapterKind":kind,"endpoint":endpoint,
            "connectionSettings":if openapi { json!({"definitionUrl":definition_url,"securityScheme":"access","definitionAuthKind":"none"}) } else { json!({}) },
            "executionBindings":if openapi { json!([
                {"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"},
                {"ownerMode":"per_user","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"}
            ]) } else { json!([{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"}]) },"discovery":{"kind":if openapi {"anonymous"} else {"execution"}}}),
    );
    let created = run(
        &admin_config,
        &["admin", "imports", "create", "--request-file", &request],
    );
    assert_eq!(created["result"]["service"]["status"], "draft");
    let (version, revision) = versions(&created);
    let token_file = directory.path().join("backend.token");
    std::fs::write(&token_file, "imported-backend-token\n").unwrap();
    let configured = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "credentials",
            "put",
            "imported",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--secret-file",
            token_file.to_str().unwrap(),
        ],
    );
    assert!(!configured.to_string().contains("imported-backend-token"));
    let (version, revision) = versions(&configured);
    let discovered = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "discover",
            "imported",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    let preview = &discovered["result"]["preview"];
    assert_eq!(
        preview["manifest"]["tools"].as_array().unwrap().len(),
        if openapi { 3 } else { 2 }
    );
    let (version, revision) = versions(&discovered);
    let mut selections = vec![
        json!({"source":if openapi {json!({"operationId":"Read.Item-V1"})} else {json!({"toolName":RAW_MCP_READ})},"action":"item.read","readOnly":true}),
        json!({"source":if openapi {json!({"operationId":"update_item"})} else {json!({"toolName":"update_item"})},"action":"item.update","readOnly":false}),
    ];
    if openapi {
        selections.push(json!({"source":{"method":"GET","path":"/unnamed"},"action":"item.unnamed","readOnly":true}));
    }
    let request = write_request(
        directory.path(),
        "accept.json",
        json!({"expectedVersion":version.parse::<u64>().unwrap(),"expectedCatalogRevision":revision.parse::<u64>().unwrap(),"manifestHash":preview["manifestHash"],"selections":selections}),
    );
    let accepted = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "accept",
            "imported",
            "--request-file",
            &request,
        ],
    );
    let (version, revision) = versions(&accepted);
    let enabled = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "status",
            "imported",
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_eq!(enabled["result"]["service"]["status"], "enabled");
    let listed = run(&admin_config, &["admin", "imports", "list"]);
    assert_eq!(listed["result"]["services"].as_array().unwrap().len(), 1);
    let get = run(&admin_config, &["admin", "imports", "get", "imported"]);
    assert_eq!(get["result"]["operatorAllowed"], true);
    for (name, read_only) in [("item.read", true), ("item.update", false)] {
        let definition = &get["result"]["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|action| action["definition"]["action"] == name)
            .unwrap()["definition"];
        assert_eq!(definition["readOnly"], read_only);
    }
    let grant = run(
        &admin_config,
        &[
            "admin",
            "policy",
            "grants",
            "create",
            "--subject",
            "user:agent",
            "--service",
            "imported",
            "--action",
            "item.read",
            "--action",
            "item.update",
            "--credential-mode",
            "service",
            "--execution-context",
            "default",
        ],
    );
    assert_eq!(grant["ok"], true);

    if openapi {
        run(
            &admin_config,
            &[
                "admin",
                "policy",
                "grants",
                "create",
                "--subject",
                "user:agent",
                "--service",
                "imported",
                "--action",
                "item.unnamed",
                "--credential-mode",
                "service",
                "--execution-context",
                "default",
            ],
        );
    }

    if openapi {
        // The administrator stores the personal principal's own token.
        let personal_token = directory
            .secret_file("personal-backend.token", "imported-personal-token")
            .unwrap();
        run(
            &admin_config,
            &[
                "admin",
                "credentials",
                "put",
                "personal",
                "imported",
                "--profile",
                "token",
                "--field-file",
                &format!("token={}", personal_token.display()),
            ],
        );
        for principal in ["personal", "missing"] {
            let subject = format!("user:{principal}");
            run(
                &admin_config,
                &[
                    "admin",
                    "policy",
                    "grants",
                    "create",
                    "--subject",
                    &subject,
                    "--service",
                    "imported",
                    "--action",
                    "item.read",
                    "--credential-mode",
                    "per_user",
                    "--execution-context",
                    "default",
                ],
            );
        }
        let read = run(
            &personal_config,
            &[
                "invoke",
                "imported.item.read",
                "--input-json",
                &inputs(json!({"message":"read"})).to_string(),
            ],
        );
        assert_eq!(read.pointer(payload_pointer).unwrap(), PAYLOAD);
        let missing = command(&missing_config)
            .args([
                "invoke",
                "imported.item.read",
                "--input-json",
                &inputs(json!({"message":"read"})).to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            !missing.status.success(),
            "missing personal credential must never fall back to service token"
        );
    }

    let read = run(
        &agent_config,
        &[
            "invoke",
            "imported.item.read",
            "--input-json",
            &inputs(json!({"message":"read"})).to_string(),
        ],
    );
    assert_eq!(read.pointer(payload_pointer).unwrap(), PAYLOAD);
    let output = directory.path().join("write-result.json");
    let send = write_request(
        directory.path(),
        "send.json",
        json!({"version":"agent-access.send.v1","kind":"invoke","service":"imported","action":"item.update","inputs":inputs(json!({"message":"write"})),"output":{"type":"file","path":output}}),
    );
    let receipt = run(&agent_config, &["send", "--request-file", &send]);
    assert!(!receipt.to_string().contains(PAYLOAD));
    assert!(std::fs::read_to_string(&output).unwrap().contains(PAYLOAD));

    let invalid_inputs = [
        json!({}),
        inputs(json!({"message":7})),
        inputs(json!({"message":"outside enum"})),
    ];
    for inputs in &invalid_inputs {
        let denied = command(&agent_config)
            .args([
                "invoke",
                "imported.item.read",
                "--input-json",
                &inputs.to_string(),
            ])
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stdout).contains("input_invalid"));
        let request = write_request(
            directory.path(),
            "invalid-send.json",
            json!({"version":"agent-access.send.v1","kind":"invoke","service":"imported","action":"item.update","inputs":inputs}),
        );
        let denied = command(&agent_config)
            .args(["send", "--request-file", &request])
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stdout).contains("input_invalid"));
    }

    let client = reqwest::Client::new();
    let request = |body: Value| {
        client
            .post(format!("{base}/mcp"))
            .bearer_auth(&agent)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
    };
    let initialized=request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":DOWNSTREAM_MCP,"capabilities":{},"clientInfo":{"name":"import-smoke","version":"1"}}})).send().await.unwrap();
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        rpc_response(initialized).await["result"]["protocolVersion"],
        DOWNSTREAM_MCP
    );
    let notification = request(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", DOWNSTREAM_MCP)
        .send()
        .await
        .unwrap();
    assert!(notification.status().is_success());
    let response = request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", DOWNSTREAM_MCP)
        .send()
        .await
        .unwrap();
    let tools = rpc_response(response).await;
    let read_name = agent_access_core::mcp::tool_name("imported", "item.read");
    let write_name = agent_access_core::mcp::tool_name("imported", "item.update");
    let read_tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == read_name)
        .unwrap();
    assert_eq!(
        read_tool["_meta"]["agent-access/sensitive-output-pointers"],
        json!([sensitive_pointer])
    );
    let response=request(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":read_name,"arguments":{"inputs":inputs(json!({"message":"http MCP read"}))}}})).header("mcp-session-id",&session).header("mcp-protocol-version",DOWNSTREAM_MCP).send().await.unwrap();
    assert_eq!(
        rpc_response(response).await["result"]["structuredContent"]
            .pointer(payload_pointer)
            .unwrap(),
        PAYLOAD
    );
    for (index, inputs) in invalid_inputs.iter().enumerate() {
        let response = request(json!({"jsonrpc":"2.0","id":10+index,"method":"tools/call","params":{"name":read_name,"arguments":{"inputs":inputs}}}))
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", DOWNSTREAM_MCP)
            .send().await.unwrap();
        let denied = rpc_response(response).await;
        assert_eq!(denied["result"]["isError"], true, "{denied}");
        assert!(denied.to_string().contains("input_invalid"));
    }

    let mut stdio = McpProcess::start(&agent_config);
    stdio.initialize().await;
    let tools = stdio.request("tools/list", json!({})).await;
    let write_tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == write_name)
        .unwrap();
    assert_eq!(
        write_tool["_meta"]["agent-access/sensitive-output-pointers"],
        json!([sensitive_pointer])
    );
    let write = stdio
        .request(
            "tools/call",
            json!({"name":write_name,"arguments":{"inputs":inputs(json!({"message":"stdio MCP write"}))}}),
        )
        .await;
    assert_eq!(
        write["result"]["structuredContent"]["result"]["mutationStatus"],
        "applied_unverified"
    );
    for inputs in invalid_inputs {
        let denied = stdio
            .request(
                "tools/call",
                json!({"name":write_name,"arguments":{"inputs":inputs}}),
            )
            .await;
        assert_eq!(denied["result"]["isError"], true, "{denied}");
        assert!(denied.to_string().contains("input_invalid"));
    }
    stdio.finish().await;

    let raw_read = if openapi {
        "Read.Item-V1"
    } else {
        RAW_MCP_READ
    };
    let scoped_request = |body: Value| {
        client
            .post(format!("{base}/mcp/imported"))
            .bearer_auth(&agent)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
    };
    let initialized = scoped_request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":DOWNSTREAM_MCP,"capabilities":{},"clientInfo":{"name":"scoped-import-smoke","version":"1"}}})).send().await.unwrap();
    let scoped_session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        rpc_response(initialized).await["result"]["serverInfo"]["name"],
        "imported"
    );
    let initialized = scoped_request(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .header("mcp-session-id", &scoped_session)
        .header("mcp-protocol-version", DOWNSTREAM_MCP)
        .send()
        .await
        .unwrap();
    assert!(initialized.status().is_success());
    let listed = scoped_request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .header("mcp-session-id", &scoped_session)
        .header("mcp-protocol-version", DOWNSTREAM_MCP)
        .send()
        .await
        .unwrap();
    let listed = rpc_response(listed).await;
    let scoped_tools = listed["result"]["tools"].as_array().unwrap();
    assert!(scoped_tools.iter().any(|tool| tool["name"] == raw_read));
    assert!(!scoped_tools.iter().any(|tool| tool["name"] == read_name));
    let detail = scoped_request(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"actions_describe","arguments":{"service":"imported","action":"item.read"}}}))
        .header("mcp-session-id",&scoped_session).header("mcp-protocol-version",DOWNSTREAM_MCP).send().await.unwrap();
    let detail = rpc_response(detail).await;
    assert_eq!(
        detail["result"]["structuredContent"]["mcpTool"]["name"],
        raw_read
    );
    assert!(
        detail["result"]["structuredContent"]
            .get("scopedMcpName")
            .is_none()
    );
    let read = scoped_request(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":raw_read,"arguments":{"inputs":inputs(json!({"message":"http MCP read"}))}}}))
        .header("mcp-session-id",&scoped_session).header("mcp-protocol-version",DOWNSTREAM_MCP).send().await.unwrap();
    assert_eq!(
        rpc_response(read).await["result"]["structuredContent"]
            .pointer(payload_pointer)
            .unwrap(),
        PAYLOAD
    );

    let mut scoped = McpProcess::start_scoped(&agent_config, "imported");
    scoped.initialize().await;
    let listed = scoped.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let raw_tool = tools.iter().find(|tool| tool["name"] == raw_read).unwrap();
    assert_eq!(raw_tool["_meta"]["agent-access/action"], "item.read");
    assert_eq!(
        raw_tool["_meta"]["agent-access/sensitive-output-pointers"],
        json!([sensitive_pointer])
    );
    let detail = scoped.request("tools/call",json!({"name":"actions_describe","arguments":{"service":"imported","action":"item.read"}})).await;
    assert_eq!(
        detail["result"]["structuredContent"]["mcpTool"]["name"],
        raw_read
    );
    assert_eq!(
        detail["result"]["structuredContent"]["mcpTool"]["inputSchema"],
        raw_tool["inputSchema"]
    );
    assert!(
        detail["result"]["structuredContent"]
            .get("scopedMcpName")
            .is_none()
    );
    let output = directory.path().join("scoped-write.json");
    let write = scoped.request("tools/call",json!({"name":"update_item","arguments":{"inputs":inputs(json!({"message":"stdio MCP write"})),"outputPath":output}})).await;
    assert_eq!(write["result"]["isError"], false, "{write}");
    assert_eq!(
        write["result"]["structuredContent"]["operationStatus"],
        "applied_unverified"
    );
    assert!(!write.to_string().contains(PAYLOAD));
    let saved: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(saved.pointer(payload_pointer).unwrap(), PAYLOAD);
    if openapi {
        assert!(tools.iter().any(|tool| tool["name"] == "item.unnamed"));
        let unnamed = scoped.request("tools/call",json!({"name":"item.unnamed","arguments":{"inputs":inputs(json!({"message":"read"}))}})).await;
        assert_eq!(
            unnamed["result"]["structuredContent"]
                .pointer(payload_pointer)
                .unwrap(),
            PAYLOAD
        );
    }
    scoped.finish().await;
    if openapi {
        for (configuration, succeeds) in [(&personal_config, true), (&missing_config, false)] {
            let mut personal = McpProcess::start_scoped(configuration, "imported");
            personal.initialize().await;
            let result = personal.request("tools/call",json!({"name":raw_read,"arguments":{"inputs":inputs(json!({"message":"read"}))}})).await;
            if succeeds {
                assert_eq!(result["result"]["isError"], false, "{result}");
                assert_eq!(
                    result["result"]["structuredContent"]
                        .pointer(payload_pointer)
                        .unwrap(),
                    PAYLOAD
                );
            } else {
                assert_eq!(result["error"]["code"], -32602, "{result}");
                let listed = personal.request("tools/list", json!({})).await;
                assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 5);
            }
            personal.finish().await;
        }
    }
    let request_count = {
        let requests = upstream_state.0.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == if openapi { "definition" } else { "tools/list" })
                .count(),
            1,
            "only explicit import discovery lists upstream tools"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == if openapi { "api" } else { "tools/call" })
                .count(),
            if openapi { 9 } else { 6 },
            "each invocation dispatches exactly once across all clients"
        );
        if openapi {
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r["authorization"] == "Bearer imported-personal-token")
                    .count(),
                2
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r["authorization"] == "Bearer imported-backend-token")
                    .count(),
                7
            );
        }
        requests.len()
    };
    let retained = broker.managed_store().unwrap();
    let retained_grants = retained.policy_grants().unwrap();
    assert!(retained_grants.iter().any(
        |grant| grant.service == "imported" && grant.actions.contains(&"item.read".to_owned())
    ));
    let retained_grants = serde_json::to_value(retained_grants).unwrap();
    let retained_catalog = retained.imported_catalog().unwrap();
    drop(retained);
    // Each gated broker restarts on this broker's state.
    stop(broker).await;
    let gates: &[&str] = if openapi {
        &["endpoint", "definition", "kind"]
    } else {
        &["endpoint", "kind"]
    };
    for gate in gates {
        let mut gated = permissions.clone();
        match *gate {
            "endpoint" => {
                gated.allowed_endpoints.retain(|url| url != &endpoint);
                // Keep enabled-import configuration valid while removing this
                // destination's permission. No request should reach this URL.
                if gated.allowed_endpoints.is_empty() {
                    gated
                        .allowed_endpoints
                        .push(format!("{origin}/operator-disabled"));
                }
            }
            "definition" => gated.allowed_endpoints.retain(|url| url != &definition_url),
            "kind" => {
                gated.allowed_kinds = vec![if openapi { "mcp_http" } else { "openapi_http" }.into()]
            }
            _ => unreachable!(),
        }
        let application = isolated_broker().in_directory(directory.clone());
        let gated_base = application.public_url();
        let restarted = application
            .config_document(import_document(
                &directory,
                &gated,
                &format!("{gated_base}/mcp"),
            ))
            .start()
            .await
            .unwrap();
        // The restarted broker reports its own availability through management.
        let gated_admin = config_file(
            directory.path(),
            &format!("gated-admin-{gate}"),
            &gated_base,
            &admin,
        );
        let policy_catalog = run(&gated_admin, &["admin", "policy", "catalog"]);
        let service = policy_catalog["result"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|service| service["service"] == "imported")
            .unwrap();
        // An action is offered when it is available and a credential mode is
        // configured; with a mode configured, `available` is the action's own.
        assert!(
            !service["configuredCredentialModes"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{gate}: {service}"
        );
        for action in ["item.read", "item.update"] {
            let action = service["actions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["action"] == action)
                .unwrap();
            assert_eq!(action["available"], false, "{gate}: {action}");
        }
        let record = run(&gated_admin, &["admin", "imports", "get", "imported"]);
        assert!(
            record["result"]["unavailableReason"]
                .as_str()
                .unwrap()
                .contains("operator"),
            "{gate}: {record}"
        );
        let store = restarted.managed_store().unwrap();
        assert_eq!(store.imported_catalog().unwrap(), retained_catalog);
        assert_eq!(
            serde_json::to_value(store.policy_grants().unwrap()).unwrap(),
            retained_grants
        );
        assert_eq!(
            upstream_state.0.lock().unwrap().len(),
            request_count,
            "{gate}: restart must be offline"
        );
        let blocked = client.post(format!("{gated_base}/mcp/imported"))
            .bearer_auth(&agent).header("accept","application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":DOWNSTREAM_MCP,"capabilities":{},"clientInfo":{"name":"operator-gate","version":"1"}}}))
            .send().await.unwrap();
        assert_eq!(blocked.status(), reqwest::StatusCode::NOT_FOUND, "{gate}");
        assert!(blocked.headers().get("mcp-session-id").is_none());
        assert_eq!(
            blocked.json::<Value>().await.unwrap(),
            json!({"error":"Service MCP view is unavailable"})
        );
        let gated_config = config_file(
            directory.path(),
            &format!("gated-{gate}"),
            &gated_base,
            &agent,
        );
        let mut blocked = McpProcess::start_scoped(&gated_config, "imported");
        blocked.initialize().await;
        let listing = blocked.request("tools/list", json!({})).await;
        assert_eq!(
            listing["error"]["message"], "service view is unavailable",
            "{gate}"
        );
        let call = blocked
            .request(
                "tools/call",
                json!({"name":raw_read,"arguments":{"inputs":inputs(json!({"message":"read"}))}}),
            )
            .await;
        assert_eq!(call["result"]["isError"], true, "{gate}: {call}");
        assert_eq!(
            call["result"]["content"],
            json!([{"type":"text","text":"service view is unavailable"}])
        );
        blocked.finish().await;
        assert_eq!(
            upstream_state.0.lock().unwrap().len(),
            request_count,
            "{gate}: scoped transports must not reach the upstream"
        );
        assert_eq!(
            serde_json::to_value(store.policy_grants().unwrap()).unwrap(),
            retained_grants
        );
        drop(store);
        stop(restarted).await;
    }
}
