//! Exercise the published stdio command through a real broker, including its
//! caller-filtered catalog and resource authorization (not a mock MCP handler).
#[path = "mcp_stdio/imported_oauth.rs"]
mod imported_oauth;
#[path = "mcp_stdio/imports.rs"]
mod imports;
#[path = "mcp_stdio/names.rs"]
mod names;
#[path = "mcp_stdio/rate_wait.rs"]
mod rate_wait;

use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker, RunningBroker};
use agent_access_fake::FAKE_PROJECT_RESOURCE;
use serde_json::{Value, json};
use std::fmt::Display;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: mpsc::UnboundedReceiver<String>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
    service: Option<String>,
}

impl McpProcess {
    fn start(config: &Path) -> Self {
        Self::start_view(config, None)
    }

    fn start_scoped(config: &Path, service: &str) -> Self {
        Self::start_view(config, Some(service))
    }

    fn start_view(config: &Path, service: Option<&str>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        // A developer's ambient broker/token configuration must never change
        // the broker or identity exercised by this subprocess test.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        command.arg("--config").arg(config).args(["mcp", "serve"]);
        if let Some(service) = service {
            command.args(["--service", service]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, messages) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let captured = stderr.clone();
        let error_stream = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = error_stream.take(65536).read_to_string(&mut text);
            *captured.lock().unwrap() = text;
        });
        Self {
            child,
            stdin,
            messages,
            stderr,
            next_id: 1,
            service: service.map(str::to_owned),
        }
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &message).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = tokio::time::timeout(RPC_TIMEOUT, async {
            loop {
                let line = self.messages.recv().await.unwrap_or_else(|| {
                    panic!("MCP stdout closed: {}", self.stderr.lock().unwrap())
                });
                let message: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("MCP stdout contained non-protocol output: {line}"));
                assert_eq!(message["jsonrpc"], "2.0");
                if message["id"] == id {
                    return message;
                }
                assert!(
                    message.get("id").is_none(),
                    "unexpected response: {message}"
                );
            }
        })
        .await;
        response
            .unwrap_or_else(|_| panic!("MCP request timed out: {}", self.stderr.lock().unwrap()))
    }

    async fn initialize(&mut self) {
        let response = self
            .request(
                "initialize",
                json!({
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"agent-access-integration-test","version":"1"}
                }),
            )
            .await;
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            response["result"]["serverInfo"]["name"],
            self.service.as_deref().unwrap_or("agent-access")
        );
        assert!(response["result"]["capabilities"].get("tools").is_some());
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }

    async fn finish(mut self) {
        self.stdin.take();
        let status = tokio::time::timeout(RPC_TIMEOUT, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("MCP child did not exit after stdin closed");
        assert!(
            status.success(),
            "MCP shutdown: {}",
            self.stderr.lock().unwrap()
        );
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        // Also runs during test panics/timeouts: never leave an MCP child alive.
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A test-owned upstream server, aborted when dropped.
struct ServerTask(tokio::task::JoinHandle<()>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An isolated application of this broker assembly.
fn isolated_broker() -> IsolatedBroker {
    IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap()
}

/// Shuts `broker` down and waits until it has released its state.
async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_discovers_authorized_actions_and_enforces_resources_with_live_token_rotation() {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let first_token = directory
        .secret_file("principal-one.token", "mcp-principal-one-token")
        .unwrap();
    let second_token = directory
        .secret_file("principal-two.token", "mcp-principal-two-token")
        .unwrap();
    let client_token = directory.join("client.token");
    std::fs::write(&client_token, "mcp-principal-one-token").unwrap();
    let broker = application
        .config_document(fake_document(&directory, &first_token, &second_token))
        .start()
        .await
        .unwrap();
    let base = broker.public_url();
    let config = directory.join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = \"{base}\"\n[identity]\ndisabled = false\ntoken_file = {}\n",
            toml::Value::String(client_token.to_string_lossy().into_owned())
        ),
    )
    .unwrap();
    let mut client = McpProcess::start(&config);
    client.initialize().await;
    let discovered = client.request("tools/list", json!({})).await;
    assert!(discovered.get("error").is_none(), "{discovered}");
    let tools = discovered["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6, "{discovered}");
    assert!(!tools.iter().any(|tool| tool["name"] == "resources_list"));
    let tool = tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "echo")
        .unwrap();
    assert_eq!(tool["_meta"]["agent-access/service"], "fake");
    assert_eq!(tool["_meta"]["agent-access/action"], "echo");
    assert_eq!(
        tool["inputSchema"]["properties"]["inputs"]["properties"]["project"]["type"],
        "string"
    );
    let name = tool["name"].as_str().unwrap().to_owned();
    assert_eq!(name, "fake_echo");
    let legacy = client.request("tools/call", json!({"name":"fake_echo_245a0744f1fbd877","arguments":{"inputs":{"project":"TEST","message":"old name"}}})).await;
    assert_eq!(legacy["error"]["code"], -32602, "{legacy}");
    let retired = client
        .request(
            "tools/call",
            json!({"name":"resources_list","arguments":{"service":"fake"}}),
        )
        .await;
    assert_eq!(retired["error"]["code"], -32602, "{retired}");

    for helper in [
        "services_list",
        "resource_access_describe",
        "actions_list",
        "actions_describe",
        "services_describe",
    ] {
        let definition = tools.iter().find(|tool| tool["name"] == helper).unwrap();
        assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        assert!(
            definition["inputSchema"]["properties"]
                .get("inputs")
                .is_none()
        );
        assert_eq!(definition["annotations"]["readOnlyHint"], false);
        assert_eq!(definition["annotations"]["idempotentHint"], true);
        assert_eq!(definition["annotations"]["destructiveHint"], true);
    }
    // The CLI projects the same authenticated policy fixture as the MCP helpers.
    let cli_call = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        command
            .arg("--config")
            .arg(&config)
            .args(args)
            .output()
            .unwrap()
    };
    let cli_resources = cli_call(&[
        "resource-access",
        "describe",
        "--service",
        "fake",
        "--action",
        "echo",
        "--limit",
        "1",
    ]);
    assert!(
        cli_resources.status.success(),
        "{}",
        String::from_utf8_lossy(&cli_resources.stderr)
    );
    let cli_page: Value = serde_json::from_slice(&cli_resources.stdout).unwrap();
    assert_eq!(
        cli_page["registeredResources"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(cli_page["registeredResources"]["nextCursor"].is_string());
    assert_eq!(cli_page["coverageSemantics"], "single_target");
    assert_eq!(cli_page["executionContext"], "default");
    assert_eq!(cli_page["availability"]["state"], "available");
    assert_eq!(cli_page["access"].as_array().unwrap().len(), 1);
    assert_eq!(cli_page["access"][0]["action"], "echo");
    assert_eq!(cli_page["access"][0]["enforcement"], "request");
    let http_page: Value = reqwest::Client::new()
        .get(format!("{base}/v1/services/fake/resource-access"))
        .header("X-Agent-Access-Identity-Token", "mcp-principal-one-token")
        .header("X-Agent-Access-Request-Id", "resource-access-parity")
        .query(&[("action", "echo"), ("limit", "1")])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(http_page, cli_page);
    assert_eq!(
        cli_call(&["resources", "list", "--service", "fake"])
            .status
            .code(),
        Some(2)
    );
    let cli_actions = cli_call(&["actions", "list", "--service", "fake", "--resource", "TEST"]);
    assert!(cli_actions.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&cli_actions.stdout).unwrap(),
        json!({"service":"fake","resource":"TEST","actions":["echo"]})
    );
    let cli_verbose = cli_call(&[
        "actions",
        "list",
        "--service",
        "fake",
        "--resource",
        "OTHER",
        "--verbose",
    ]);
    assert!(cli_verbose.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&cli_verbose.stdout).unwrap(),
        json!([])
    );
    let cli_detail = cli_call(&["actions", "describe", "--service", "fake", "echo"]);
    assert!(cli_detail.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&cli_detail.stdout).unwrap()["mcpTool"]["inputSchema"],
        tool["inputSchema"]
    );
    assert_eq!(
        cli_call(&["actions", "describe", "--service", "fake", "missing"])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(
        cli_call(&["resource-access", "describe", "--service", "hidden"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        cli_call(&[
            "resource-access",
            "describe",
            "--service",
            "fake",
            "--cursor",
            "invalid"
        ])
        .status
        .code(),
        Some(3)
    );
    assert_eq!(
        cli_call(&["services", "list", "--names-only"])
            .status
            .code(),
        Some(2)
    );

    let native_schema = tool["inputSchema"].clone();
    let services = client
        .request("tools/call", json!({"name":"services_list","arguments":{}}))
        .await;
    assert_eq!(
        services["result"]["structuredContent"]["services"][0]["actions"],
        json!(["echo"])
    );
    assert_eq!(
        services["result"]["structuredContent"]["services"][0]["surface"],
        "invoke"
    );
    let description = client
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
        )
        .await;
    assert_eq!(
        description["result"]["structuredContent"]["mcpTool"]["inputSchema"],
        native_schema
    );
    assert_eq!(
        description["result"]["structuredContent"]["mcpTool"]["name"],
        name
    );
    assert!(
        description["result"]["structuredContent"]
            .get("io")
            .is_some()
    );
    let service_description = client
        .request(
            "tools/call",
            json!({"name":"services_describe","arguments":{"service":"fake"}}),
        )
        .await;
    assert_eq!(
        service_description["result"]["structuredContent"]["actions"][0]["action"],
        "echo"
    );
    let page = client
        .request(
            "tools/call",
            json!({"name":"resource_access_describe","arguments":{"service":"fake","action":"echo","limit":1}}),
        )
        .await;
    assert_eq!(page["result"]["isError"], false, "{page}");
    assert_eq!(page["result"]["structuredContent"], cli_page);
    assert_eq!(
        page["result"]["structuredContent"]["registeredResources"]["items"][0]["value"],
        "TEST"
    );
    assert!(
        page["result"]["structuredContent"]["registeredResources"]["items"][0]
            .get("actions")
            .is_none()
    );
    let cursor = page["result"]["structuredContent"]["registeredResources"]["nextCursor"]
        .as_str()
        .unwrap();
    let continuation = client.request("tools/call", json!({"name":"resource_access_describe","arguments":{"service":"fake","action":"echo","limit":1,"cursor":cursor}})).await;
    assert_eq!(
        continuation["result"]["structuredContent"]["access"],
        cli_page["access"]
    );
    assert_eq!(
        continuation["result"]["structuredContent"]["coverageSemantics"],
        "single_target"
    );
    assert_eq!(
        continuation["result"]["structuredContent"]["registeredResources"]["items"][0]["value"],
        "TEST2"
    );
    assert!(
        continuation["result"]["structuredContent"]["registeredResources"]["nextCursor"].is_null()
    );
    let invalid_cursor = client
        .request(
            "tools/call",
            json!({"name":"resource_access_describe","arguments":{"service":"fake","cursor":cursor}}),
        )
        .await;
    assert_eq!(invalid_cursor["result"]["isError"], true);
    assert_eq!(
        invalid_cursor["result"]["structuredContent"]["reasonCode"],
        "input_invalid"
    );
    // An action filter is part of the cursor binding even if the unfiltered
    // service happens to have the same single visible action.
    let changed_action = client.request("tools/call", json!({"name":"resource_access_describe","arguments":{"service":"fake","limit":1,"cursor":cursor}})).await;
    assert_eq!(changed_action["result"]["isError"], true);
    let hidden_action = client.request("tools/call", json!({"name":"resource_access_describe","arguments":{"service":"fake","action":"missing"}})).await;
    assert_eq!(hidden_action["result"]["isError"], true);
    assert_eq!(
        hidden_action["result"]["structuredContent"]["error"]["message"],
        "action is not available"
    );
    for (resource, expected) in [("TEST", json!(["echo"])), ("OTHER", json!([]))] {
        let actions = client
            .request(
                "tools/call",
                json!({"name":"actions_list","arguments":{"service":"fake","resource":resource}}),
            )
            .await;
        assert_eq!(actions["result"]["structuredContent"]["actions"], expected);
        let text: Value =
            serde_json::from_str(actions["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text, actions["result"]["structuredContent"]);
    }
    for args in [
        json!({"service":"fake","inputs":{}}),
        json!({"service":"fake","limit":0}),
        json!({"service":"fake","prefix":null}),
    ] {
        let invalid = client
            .request(
                "tools/call",
                json!({"name":"resource_access_describe","arguments":args}),
            )
            .await;
        assert_eq!(invalid["result"]["isError"], true, "{invalid}");
        assert!(invalid.get("error").is_none());
    }
    let hidden = client
        .request(
            "tools/call",
            json!({"name":"actions_list","arguments":{"service":"hidden"}}),
        )
        .await;
    assert_eq!(
        hidden["result"]["structuredContent"]["reasonCode"],
        "service_action_denied"
    );
    assert_eq!(hidden["result"]["isError"], true);
    let recovered_helpers = client
        .request("tools/call", json!({"name":"services_list","arguments":{}}))
        .await;
    assert_eq!(recovered_helpers["result"]["isError"], false);

    // File content is read by the actual local MCP process; only its path is
    // transmitted through MCP, and the actual broker authorizes TEST.
    let request_file = directory.join("inputs.json");
    std::fs::write(
        &request_file,
        br#"{"project":"TEST","message":"first file revision"}"#,
    )
    .unwrap();
    let allowed = client
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"requestFile":request_file}}),
        )
        .await;
    assert_eq!(allowed["result"]["isError"], false, "{allowed}");
    assert_eq!(allowed["result"]["structuredContent"]["decision"], "allow");
    assert_eq!(
        allowed["result"]["structuredContent"]["result"]["message"],
        "first file revision"
    );
    assert_eq!(
        allowed["result"]["structuredContent"]["result"]["principal"],
        "agent-one"
    );

    std::fs::write(
        &request_file,
        br#"{"project":"TEST","message":"edited file revision"}"#,
    )
    .unwrap();
    let edited = client
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"requestFile":request_file}}),
        )
        .await;
    assert_eq!(
        edited["result"]["structuredContent"]["result"]["message"],
        "edited file revision"
    );

    // Discovery advertises a potentially usable action; it cannot promise
    // authorization for this different resource supplied later in the inputs.
    let denied = client.request("tools/call", json!({"name":name,"arguments":{"inputs":{"project":"OTHER","message":"resource denial"}}})).await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    assert_eq!(denied["result"]["structuredContent"]["decision"], "deny");
    assert_eq!(
        denied["result"]["structuredContent"]["reasonCode"],
        "service_action_denied"
    );

    let malformed = client
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"inputs":[],"requestFile":request_file}}),
        )
        .await;
    assert_eq!(malformed["result"]["isError"], true, "{malformed}");
    let unknown = client
        .request("tools/call", json!({"name":"unknown_tool","arguments":{}}))
        .await;
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");
    assert_eq!(
        client.request("tools/list", json!({})).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        6
    );

    // Reload the CLI token file in the same MCP session. The second identity
    // authenticates successfully but has no grant, so its catalog is empty.
    std::fs::write(&client_token, "mcp-principal-two-token").unwrap();
    let rotated = client.request("tools/list", json!({})).await;
    assert_eq!(
        rotated["result"]["tools"].as_array().unwrap().len(),
        5,
        "{rotated}"
    );
    let rotated_services = client
        .request("tools/call", json!({"name":"services_list","arguments":{}}))
        .await;
    assert_eq!(
        rotated_services["result"]["structuredContent"],
        json!({"services":[]})
    );
    let revoked = client.request("tools/call", json!({"name":"resource_access_describe","arguments":{"service":"fake","limit":1,"cursor":cursor}})).await;
    assert_eq!(revoked["result"]["isError"], true);
    assert_eq!(
        revoked["result"]["structuredContent"]["reasonCode"],
        "service_action_denied"
    );
    let stale = client
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"inputs":{"project":"TEST","message":"stale tool"}}}),
        )
        .await;
    assert_eq!(stale["error"]["code"], -32602, "{stale}");

    // A temporarily missing token fails one request without terminating stdio.
    std::fs::remove_file(&client_token).unwrap();
    assert!(
        client
            .request("tools/list", json!({}))
            .await
            .get("error")
            .is_some()
    );
    std::fs::write(&client_token, "mcp-principal-one-token").unwrap();
    let restored = client.request("tools/list", json!({})).await;
    assert!(
        restored["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == name),
        "{restored}"
    );
    let recovered = client
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"inputs":{"project":"TEST","message":"recovered"}}}),
        )
        .await;
    assert_eq!(recovered["result"]["isError"], false, "{recovered}");
    client.finish().await;
    stop(broker).await;
}

/// The fake provider with its service credential, the static principals
/// `agent-one` (in group `agents`) and `agent-two` with the tokens in
/// `first_token` and `second_token`, the TEST and TEST2 project resources, and
/// the `agents` group's `echo` grant on both.
fn fake_document(directory: &FixtureDir, first_token: &Path, second_token: &Path) -> String {
    format!(
        r#"
[deployment]
enable_fake_service = true

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"

[[identity.sources.principals]]
principal = "agent-one"
token_refs = [{first_token}]

[[identity.sources.principals]]
principal = "agent-two"
token_refs = [{second_token}]

[[identity.groups]]
id = "agents"
status = "active"
members = ["agent-one"]

[credentials.service.fake]
type = "bearer_token"
token_ref = "env:FAKE_SERVICE_TOKEN"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "project-test"
resource_type = "{resource_type}"
selector = {{ kind = "exact", value = "TEST" }}
allowed_execution_contexts = ["default"]

[[policy.resources]]
id = "project-test2"
resource_type = "{resource_type}"
selector = {{ kind = "exact", value = "TEST2" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:agents"]
service = "fake"
actions = ["echo"]
resources = {{ resource_ids = ["project-test", "project-test2"] }}
credential_mode = "service"

[providers.fake]

[limits]
upload_spool_dir = {spool}
"#,
        first_token = toml_string(format_args!("file:{}", first_token.display())),
        second_token = toml_string(format_args!("file:{}", second_token.display())),
        resource_type = FAKE_PROJECT_RESOURCE.id().as_str(),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_helpers_describe_noninvoke_services_without_exposing_execution_tools() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    let broker = MockServer::start().await;
    let service = json!({"service":"git","displayName":"Git gateway","surface":"gateway","gatewayKind":"git_http","availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":["repository"],"actions":[{
        "action":"repo.fetch", "scopedMcpName":"repo.fetch","readOnly":true,"description":"Fetch repository","requiredScopeTypes":["repository"],"credentialModes":["service"],"lookupRequired":false,"inputSchema":{"type":"object"}
    }]});
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(agent_access_core::empty_catalog(json!({}))),
        )
        .expect(1)
        .mount(&broker)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([service])))
        .mount(&broker)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/services/git"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service))
        .mount(&broker)
        .await;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = {:?}\n[identity]\ndisabled = true\n",
            broker.uri()
        ),
    )
    .unwrap();
    let mut client = McpProcess::start(&config);
    client.initialize().await;
    let tools = client.request("tools/list", json!({})).await;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 5);
    let listed = client
        .request("tools/call", json!({"name":"services_list","arguments":{}}))
        .await;
    assert_eq!(
        listed["result"]["structuredContent"]["services"][0]["surface"],
        "gateway"
    );
    assert_eq!(
        listed["result"]["structuredContent"]["services"][0]["actions"],
        json!(["repo.fetch"])
    );
    let detail = client
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"git","action":"repo.fetch"}}),
        )
        .await;
    assert_eq!(detail["result"]["isError"], false, "{detail}");
    assert_eq!(detail["result"]["structuredContent"]["service"], "git");
    assert!(
        detail["result"]["structuredContent"]
            .get("mcpTool")
            .is_none()
    );
    assert!(detail["result"]["structuredContent"].get("io").is_none());
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_output_failure_is_structured_and_does_not_repeat_the_operation() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    let server = MockServer::start().await;
    // A deterministic broker response isolates a completed mutation from local output failure.
    let catalog = json!({
        "version":"agent-access.catalog.v2","identity":{},"routes":[],
        "send":{"version":"agent-access.send.v1","catalogRequired":true},
        "services":[{"service":"jira","displayName":"Jira","surface":"invoke", "scopedMcpReady":true,"availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":[],"actions":[{
            "action":"issue.update", "scopedMcpName":"issue.update","readOnly":false,"description":"Update an issue","requiredScopeTypes":[],"credentialModes":[],
            "inputSchema":{"type":"object"},"io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision",
            "sensitiveOutputPointers":["/result/secret"]
        }]}]
    });
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("output.json");
    let race_destination = destination.clone();
    Mock::given(method("POST")).and(path("/v1/invoke/jira/issue.update"))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::create_dir(&race_destination).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({"decision":"allow","agentRequestId":"agent","brokerRequestId":"broker","result":{"secret":"not-in-receipt","updated":true}}))
        }).expect(1).mount(&server).await;
    let token = directory.path().join("token");
    std::fs::write(&token, "broker-token").unwrap();
    let config = directory.path().join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = {:?}\n[identity]\ntoken_file = {:?}\n",
            server.uri(),
            token.to_str().unwrap()
        ),
    )
    .unwrap();
    let mut mcp = McpProcess::start(&config);
    mcp.initialize().await;
    let result = mcp.request("tools/call", json!({"name":agent_access_core::mcp::tool_name("jira","issue.update"),"arguments":{"inputs":{"issue":"ABC-1"},"outputPath":destination}})).await;
    assert_eq!(result["result"]["isError"], true, "{result}");
    let details = &result["result"]["structuredContent"];
    assert_eq!(details["operationStatus"], "succeeded");
    assert_eq!(details["output"]["status"], "failed");
    assert_eq!(details["output"]["destinationReplaced"], false);
    assert_eq!(details["agentRequestId"], "agent");
    assert_eq!(details["brokerRequestId"], "broker");
    assert!(
        details["message"]
            .as_str()
            .unwrap()
            .contains("Do not repeat")
    );
    assert!(!result.to_string().contains("not-in-receipt"));
    mcp.finish().await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_initialization_names_an_unavailable_service_without_catalog_probe() {
    let broker = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .expect(0)
        .mount(&broker)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl={:?}\n[identity]\ndisabled=true\n",
            broker.uri()
        ),
    )
    .unwrap();
    let mut process = McpProcess::start_scoped(&config, "unavailable");
    process.initialize().await;
    process.finish().await;
    broker.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_stdio_recovers_after_token_rotation_without_broadening_or_local_side_effects() {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let one = directory.secret_file("one.token", "principal-one").unwrap();
    let two = directory.secret_file("two.token", "principal-two").unwrap();
    let rotating = directory.join("rotating.token");
    std::fs::write(&rotating, "principal-two").unwrap();
    let broker = application
        .config_document(fake_document(&directory, &one, &two))
        .start()
        .await
        .unwrap();
    let base = broker.public_url();
    let config = directory.join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl=\"{base}\"\n[identity]\ndisabled=false\ntoken_file={:?}\n",
            rotating.display().to_string()
        ),
    )
    .unwrap();
    let mut process = McpProcess::start_scoped(&config, "fake");
    process.initialize().await;
    let unavailable = process.request("tools/list", json!({})).await;
    assert!(
        unavailable["error"]["message"]
            .as_str()
            .unwrap()
            .contains("service view is unavailable")
    );
    let output = directory.join("saved.json");
    std::fs::write(&output, "preserve").unwrap();
    let denied = process
        .request(
            "tools/call",
            json!({"name":"services_list","arguments":{"outputPath":output}}),
        )
        .await;
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "preserve");
    std::fs::write(&rotating, "principal-one").unwrap();
    let listed = process.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6);
    let action = tools.iter().find(|tool| tool["name"] == "echo").unwrap();
    assert_eq!(action["_meta"]["agent-access/service"], "fake");
    for name in [
        agent_access_core::mcp::tool_name("fake", "echo"),
        "unknown".into(),
    ] {
        let denied = process.request("tools/call",json!({"name":name,"arguments":{"requestFile":directory.join("missing.json"),"outputPath":output}})).await;
        assert_eq!(denied["error"]["code"], -32602);
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "preserve");
    }
    let wrong = process
        .request(
            "tools/call",
            json!({"name":"resource_access_describe","arguments":{"service":"other","outputPath":output}}),
        )
        .await;
    assert_eq!(wrong["result"]["isError"], true);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "preserve");
    let detail = process
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
        )
        .await;
    assert_eq!(
        detail["result"]["structuredContent"]["mcpTool"]["name"],
        "echo"
    );
    assert!(
        detail["result"]["structuredContent"]
            .get("scopedMcpName")
            .is_none()
    );
    let result = process
        .request(
            "tools/call",
            json!({"name":"echo","arguments":{"inputs":{"project":"TEST","message":"selected"}}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(
        result["result"]["structuredContent"]["result"]["principal"],
        "agent-one"
    );
    std::fs::write(&rotating, "principal-two").unwrap();
    assert!(
        process
            .request("tools/list", json!({}))
            .await
            .get("error")
            .is_some()
    );
    std::fs::write(&rotating, "principal-one").unwrap();
    let saved = process
        .request(
            "tools/call",
            json!({"name":"services_list","arguments":{"outputPath":output}}),
        )
        .await;
    assert_eq!(saved["result"]["isError"], false);
    let file: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(file["services"].as_array().unwrap().len(), 1);
    assert_eq!(file["services"][0]["service"], "fake");
    process.finish().await;
    stop(broker).await;
}
