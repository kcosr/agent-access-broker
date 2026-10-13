//! Managed endpoint, real CLI and stdio MCP against an offline Teams transport.
use agent_access_broker::{backend_registry, broker_build_status};
use agent_access_broker_host::build_router;
use agent_access_core::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const ORIGIN: &str = "https://synthetic.environment.api.powerplatform.com";
const ENDPOINT: &str = "https://synthetic.environment.api.powerplatform.com/opaque/fixture/trigger?sig=SYNTHETIC_SIGNED_SECRET";

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
fn run(config: &Path, args: &[&str]) -> std::process::Output {
    command(config).args(args).output().unwrap()
}
fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_SIGNED_SECRET"));
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: tokio::sync::mpsc::UnboundedReceiver<Value>,
    id: u64,
}
impl Mcp {
    fn start(config: &Path) -> Self {
        let mut child = command(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, messages) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let value: Value = serde_json::from_str(&line).expect("MCP stdout must be JSON");
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            messages,
            id: 0,
        }
    }
    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let value = self.messages.recv().await.expect("MCP closed stdout");
                if value["id"] == id {
                    return value;
                }
                assert!(value.get("id").is_none());
            }
        })
        .await
        .expect("MCP response timed out")
    }
}
impl Drop for Mcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    _server: Server,
    runtime: BrokerRuntime,
    agent_config: PathBuf,
    admin_config: PathBuf,
    base: String,
    agent_token: String,
    calls: Arc<Mutex<Vec<Value>>>,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = dir.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([37_u8; 32])).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut config = parse_broker_config_raw(
        "teams-smoke",
        r#"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[policy]
authority = "managed"
[providers.teams]
allowed_upstream_hosts = ["https://synthetic.environment.api.powerplatform.com/**"]
"#,
        &Arc::new(backend_registry()),
    )
    .unwrap();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
    config.management.enabled = true;
    config.mcp.enabled = true;
    config.mcp.public_url = Some(format!("{base}/mcp"));
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["default".into()],
        default_context: Some("default".into()),
    });
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: dir.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            env: None,
            path: Some(key.display().to_string()),
        }],
    });
    let store = ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let captured = calls.clone();
    let runtime = BrokerRuntime::with_providers(
        config,
        [agent_access_teams::test_support::provider(
            ORIGIN,
            Arc::new(move |endpoint, body| {
                assert_eq!(endpoint, ENDPOINT);
                captured.lock().unwrap().push(body.clone());
                202
            }),
        )],
    )
    .unwrap();
    for (id, selector, attributes) in [
        (
            "destination",
            ResourceSelector::Exact {
                value: "release-alerts".into(),
            },
            ResourceAttributes::from(BTreeMap::from([("webhookUrl".into(), ENDPOINT.into())])),
        ),
        (
            "all-destinations",
            ResourceSelector::All,
            ResourceAttributes::default(),
        ),
    ] {
        runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(id.into()),
                display_name: Some("Release announcements".into()),
                resource_type: agent_access_teams::TEAMS_DESTINATION_RESOURCE.id.clone(),
                selector,
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                attributes,
                created_by: "test".into(),
            })
            .unwrap();
    }
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: None,
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "teams".into(),
            actions: vec!["notification.send".into()],
            resources: ResourceSelection {
                resource_ids: vec!["all-destinations".into()],
                resource_group_ids: vec![],
            },
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "test".into(),
        })
        .unwrap();
    let app = build_router(runtime.clone(), broker_build_status());
    let server = Server(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    }));
    let make_config = |class, name: &str| {
        let token = store
            .issue_broker_token(
                runtime.broker_token_hasher().unwrap(),
                BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: name.into(),
                    token_class: class,
                    scopes: json!({"allowedExecutionContexts":["default"]}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token;
        let token_file = dir.path().join(format!("{name}-token"));
        std::fs::write(&token_file, &token).unwrap();
        let path = dir.path().join(format!("{name}.toml"));
        std::fs::write(&path, format!("[service]\nurl = {base:?}\n[identity]\nheader = \"Authorization\"\nscheme = \"Bearer\"\ntoken_file = {:?}\n", token_file.display().to_string())).unwrap();
        (path, token)
    };
    let (agent_config, agent_token) = make_config(BrokerTokenClass::AgentInvoke, "agent");
    let (admin_config, _) = make_config(BrokerTokenClass::Admin, "admin");
    Fixture {
        _dir: dir,
        _server: server,
        runtime,
        agent_config,
        admin_config,
        base,
        agent_token,
        calls,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn teams_cli_and_mcp_use_managed_destinations_without_execution_credentials() {
    let f = fixture().await;
    let resource_list = success(run(
        &f.agent_config,
        &["resources", "list", "--service", "teams"],
    ));
    assert!(resource_list.to_string().contains("release-alerts"));
    let action = success(run(
        &f.agent_config,
        &[
            "actions",
            "describe",
            "--service",
            "teams",
            "notification.send",
        ],
    ));
    assert!(action.to_string().contains("microsoft"));
    let response = success(run(
        &f.agent_config,
        &[
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--title",
            "Release",
            "--text",
            "Version 2.3",
        ],
    ));
    assert_eq!(response["result"]["accepted"], true);
    assert_eq!(
        f.calls.lock().unwrap()[0]["attachments"][0]["content"]["body"][0]["text"],
        "Release"
    );
    let card = json!({"@type":"MessageCard","@context":"http://schema.org/extensions","summary":"Release","themeColor":"008000"});
    let card_file = f._dir.path().join("card.json");
    std::fs::write(&card_file, card.to_string()).unwrap();
    success(run(
        &f.agent_config,
        &[
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--content-file",
            card_file.to_str().unwrap(),
        ],
    ));
    assert_eq!(f.calls.lock().unwrap()[1], card);
    let input = json!({"destination":"release-alerts","contentFormat":"microsoft","content":card});
    let input_file = f._dir.path().join("notification.json");
    std::fs::write(&input_file, input.to_string()).unwrap();
    success(run(
        &f.agent_config,
        &[
            "invoke",
            "teams.notification.send",
            "--input-file",
            input_file.to_str().unwrap(),
        ],
    ));
    let mut mcp = Mcp::start(&f.agent_config);
    let initialized = mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"teams-smoke","version":"1"}})).await;
    assert!(initialized.get("error").is_none());
    mcp.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let tools = mcp.request("tools/list", json!({})).await;
    let name = agent_access_core::mcp::tool_name("teams", "notification.send");
    let tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap();
    assert_ne!(tool["annotations"]["readOnlyHint"], true);
    let result = mcp
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"requestFile":input_file}}),
        )
        .await;
    assert_ne!(result["result"]["isError"], true, "{result}");
    assert!(result.to_string().contains("accepted"));
    assert!(!result.to_string().contains("SYNTHETIC_SIGNED_SECRET"));
    assert_eq!(f.calls.lock().unwrap().len(), 4);
    let client = reqwest::Client::new();
    let rpc = |message: Value, session: Option<&str>| {
        let mut request = client
            .post(format!("{}/mcp", f.base))
            .bearer_auth(&f.agent_token)
            .header("Accept", "application/json, text/event-stream")
            .json(&message);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        request
    };
    let initialized = rpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"teams-smoke","version":"1"}}}), None).send().await.unwrap();
    assert!(initialized.status().is_success());
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let _ = initialized.bytes().await.unwrap();
    assert!(
        rpc(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            Some(&session)
        )
        .send()
        .await
        .unwrap()
        .status()
        .is_success()
    );
    let tools = rpc_response(
        rpc(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            Some(&session),
        )
        .send()
        .await
        .unwrap(),
    )
    .await;
    let tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap();
    assert_ne!(tool["annotations"]["readOnlyHint"], true);
    let receipt = rpc_response(rpc(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{"inputs":input}}}), Some(&session)).send().await.unwrap()).await;
    assert_eq!(
        receipt["result"]["structuredContent"]["result"]["accepted"], true,
        "{receipt}"
    );
    assert!(!receipt.to_string().contains("SYNTHETIC_SIGNED_SECRET"));
    assert_eq!(f.calls.lock().unwrap().len(), 5);
    let send_file = f._dir.path().join("send.json");
    std::fs::write(&send_file, json!({"version":"agent-access.send.v1","kind":"invoke","service":"teams","action":"notification.send","inputs":input}).to_string()).unwrap();
    success(run(
        &f.agent_config,
        &["send", "--request-file", send_file.to_str().unwrap()],
    ));
    assert_eq!(f.calls.lock().unwrap().len(), 6);
    let destination = f._dir.path().join("accepted.json");
    let saved = success(run(
        &f.agent_config,
        &[
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--text",
            "hello",
            "--output",
            destination.to_str().unwrap(),
        ],
    ));
    assert_eq!(saved["operationStatus"], "succeeded");
    assert_eq!(saved["output"]["status"], "succeeded");
    assert!(saved.get("result").is_none());
    let response: Value = serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert_eq!(response["result"]["accepted"], true);
    assert!(!response.to_string().contains("SYNTHETIC_SIGNED_SECRET"));
    assert_eq!(
        f.calls.lock().unwrap().len(),
        7,
        "saving the response must not duplicate the notification"
    );
    let failed_destination = f._dir.path().join("missing/accepted.json");
    let failed_save = run(
        &f.agent_config,
        &[
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--text",
            "hello",
            "--output",
            failed_destination.to_str().unwrap(),
        ],
    );
    assert_eq!(failed_save.status.code(), Some(3));
    assert!(failed_save.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&failed_save.stderr).contains("SYNTHETIC_SIGNED_SECRET"));
    assert_eq!(
        f.calls.lock().unwrap().len(),
        7,
        "invalid output must not send a notification"
    );
    let stdout = success(run(
        &f.agent_config,
        &[
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--text",
            "hello",
            "--output",
            "-",
        ],
    ));
    assert_eq!(stdout["result"]["accepted"], true);
    assert!(stdout.get("output").is_none());
    assert_eq!(f.calls.lock().unwrap().len(), 8);
    for args in [
        vec![
            "teams",
            "notification",
            "send",
            "unknown",
            "--text",
            "hello",
        ],
        vec![
            "teams",
            "notification",
            "send",
            "release-alerts",
            "--text",
            "hello",
            "--content-file",
            card_file.to_str().unwrap(),
        ],
    ] {
        assert!(!run(&f.agent_config, &args).status.success());
    }
    assert_eq!(f.calls.lock().unwrap().len(), 8);
    f.runtime
        .patch_managed_resource(PatchResourceRequest {
            id: "destination".into(),
            expected_version: 1,
            display_name: None,
            resource_type: None,
            selector: None,
            allowed_execution_contexts: None,
            enabled: Some(false),
            attributes: ResourceAttributes::default(),
            updated_by: "test".into(),
        })
        .unwrap();
    assert!(
        !run(
            &f.agent_config,
            &[
                "teams",
                "notification",
                "send",
                "release-alerts",
                "--text",
                "hello"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        f.calls.lock().unwrap().len(),
        8,
        "broad grants cannot execute disabled bindings"
    );
    let attributes = f._dir.path().join("attributes.json");
    std::fs::write(&attributes, json!({"webhookUrl":ENDPOINT}).to_string()).unwrap();
    let created = success(run(
        &f.admin_config,
        &[
            "admin",
            "policy",
            "resources",
            "create",
            "--id",
            "admin-destination",
            "--resource-type",
            "teams_notification_destination",
            "--selector-kind",
            "exact",
            "--selector-value",
            "admin-alerts",
            "--execution-context",
            "default",
            "--attributes-file",
            attributes.to_str().unwrap(),
        ],
    ));
    assert!(created.to_string().contains("configuredAttributes"));
    let revealed = run(
        &f.admin_config,
        &[
            "admin",
            "policy",
            "resources",
            "reveal",
            "admin-destination",
            "webhookUrl",
        ],
    );
    assert!(revealed.status.success());
    let revealed: Value = serde_json::from_slice(&revealed.stdout).unwrap();
    assert_eq!(revealed["result"]["value"], ENDPOINT);
    assert!(
        !run(
            &f.agent_config,
            &[
                "admin",
                "policy",
                "resources",
                "reveal",
                "admin-destination",
                "webhookUrl"
            ]
        )
        .status
        .success()
    );
}

async fn rpc_response(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    if let Ok(value) = serde_json::from_str(&text) {
        return value;
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .find_map(|line| {
            serde_json::from_str::<Value>(line.trim())
                .ok()
                .filter(|value| value.get("id").is_some())
        })
        .unwrap_or_else(|| panic!("Invalid MCP response: {text}"))
}
