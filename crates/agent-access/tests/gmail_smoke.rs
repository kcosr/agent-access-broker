//! Real CLI, stdio MCP, HTTP MCP and HTTP against the managed Gmail fixture.
use agent_access_broker_host::test_support::{
    FixtureDir, IsolatedBroker, ProviderFixture, RunningBroker,
};
use agent_access_broker_host::{AssemblyIdentity, BrokerComposition};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path, query_param, query_param_is_missing},
};
#[path = "../../agent-access-broker-host/tests/support/gmail.rs"]
mod fixture;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: mpsc::UnboundedReceiver<String>,
    stderr: Arc<Mutex<String>>,
    next_id: u64,
}

impl McpProcess {
    fn start(config: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        // A developer's ambient broker/token configuration must never change
        // the broker or identity exercised by this subprocess test.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        let mut child = command
            .arg("--config")
            .arg(config)
            .args(["mcp", "serve"])
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
        assert_eq!(response["result"]["serverInfo"]["name"], "agent-access");
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

fn run(config: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap()
}
fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gmail_all_agent_surfaces_preserve_actions_and_deny_unsupported_effects() {
    let f = fixture::gmail_fixture().await;
    f.connect("").await;
    // Alice's own connection list reports the Google registration's subject.
    let connections = fixture::body_json(
        f.browser(
            Method::GET,
            "/v1/oauth/connections",
            "oauth-connections",
            None,
        )
        .await,
    )
    .await;
    let connection = &connections["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["service"] == "gmail")
        .unwrap()["connection"];
    assert_eq!(connection["registration"], "google", "{connections}");
    assert_eq!(
        connection["subjectId"].as_str(),
        Some("google-sub-alice"),
        "{connections}"
    );
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/threads/abc/trash"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":"abc","messages":[{"id":"def","labelIds":["TRASH"]}]})),
        )
        .mount(&f.server)
        .await;
    let base = f.broker.public_url();
    let directory = f.broker.directory();
    let token = directory.join("agent-token");
    std::fs::write(&token, &f.agent_token).unwrap();
    let config = directory.join("cli.toml");
    std::fs::write(&config,format!("[service]\nurl = {base:?}\n[identity]\nheader = \"Authorization\"\nscheme = \"Bearer\"\ntoken_file = {:?}\n",token.display().to_string())).unwrap();
    let value = success(run(&config, &["gmail", "account"]));
    assert_eq!(value["result"]["emailAddress"], "alice@example.test");
    let read_file = directory.join("account.json");
    success(run(
        &config,
        &["gmail", "account", "--output", read_file.to_str().unwrap()],
    ));
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(read_file).unwrap()).unwrap()["result"]["emailAddress"],
        "alice@example.test"
    );
    let inputs = r#"{"id":"abc"}"#;
    let send=json!({"version":"agent-access.send.v1","kind":"invoke","service":"gmail","action":"thread.trash","inputs":{"id":"abc"}}).to_string();
    for args in [
        vec!["gmail", "thread", "trash", "abc"],
        vec!["invoke", "gmail.thread.trash", "--input-json", inputs],
        vec!["send", "--request-json", &send],
    ] {
        let r = success(run(&config, &args));
        assert_eq!(r["result"]["operation"], "trash");
    }
    // A typed search page continues through canonical invoke: the Broker
    // envelope binds the typed command's explicit defaults as omitted ones.
    let messages = || Mock::given(method("GET")).and(path("/gmail/v1/users/me/messages"));
    messages()
        .and(query_param_is_missing("pageToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nextPageToken":"page-2"})))
        .expect(1)
        .mount(&f.server)
        .await;
    messages()
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&f.server)
        .await;
    let page = success(run(
        &config,
        &["gmail", "message", "search", "--query", "in:inbox"],
    ));
    let page_token = page["result"]["nextPageToken"].as_str().unwrap();
    assert_ne!(page_token, "page-2");
    let next = json!({"query":"in:inbox","pageToken":page_token}).to_string();
    let next = success(run(
        &config,
        &["invoke", "gmail.message.search", "--input-json", &next],
    ));
    assert!(next["result"]["nextPageToken"].is_null(), "{next}");
    let before = f.server.received_requests().await.unwrap().len();
    for action in ["message.send", "message.delete", "thread.delete"] {
        assert!(
            !run(
                &config,
                &["invoke", &format!("gmail.{action}"), "--input-json", inputs]
            )
            .status
            .success()
        );
        let request=json!({"version":"agent-access.send.v1","kind":"invoke","service":"gmail","action":action,"inputs":{"id":"abc"}}).to_string();
        assert!(
            !run(&config, &["send", "--request-json", &request])
                .status
                .success()
        );
    }
    assert!(
        !run(&config, &["gmail", "message", "delete", "abc"])
            .status
            .success()
    );
    assert_eq!(f.server.received_requests().await.unwrap().len(), before);
    let mut mcp = McpProcess::start(&config);
    mcp.initialize().await;
    let tools = mcp.request("tools/list", json!({})).await;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    let trash = agent_access_core::mcp::tool_name("gmail", "thread.trash");
    assert!(names.contains(&trash.as_str()));
    let r = mcp
        .request(
            "tools/call",
            json!({"name":trash,"arguments":{"inputs":{"id":"abc"}}}),
        )
        .await;
    assert_eq!(
        r["result"]["structuredContent"]["result"]["operation"], "trash",
        "{r}"
    );
    for action in ["message.send", "message.delete", "thread.delete"] {
        let r=mcp.request("tools/call",json!({"name":agent_access_core::mcp::tool_name("gmail",action),"arguments":{"inputs":{"id":"abc"}}})).await;
        assert!(
            r.get("error").is_some() || r["result"]["isError"] == true,
            "{r}"
        );
    }
    mcp.finish().await;
    assert_eq!(
        f.invoke("thread.trash", json!({"id":"abc"})).await.0,
        axum::http::StatusCode::OK
    );
    // HTTP MCP has its own session/auth boundary and shares the same descriptor.
    let client = reqwest::Client::new();
    let rpc = |message: Value, session: Option<&str>| {
        let mut r = client
            .post(format!("{base}/mcp"))
            .header("Host", "127.0.0.1")
            .bearer_auth(&f.agent_token)
            .header("Accept", "application/json, text/event-stream")
            .json(&message);
        if let Some(session) = session {
            r = r
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        r
    };
    let init=rpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"gmail-test","version":"1"}}}),None).send().await.unwrap();
    assert!(init.status().is_success(), "{}", init.status());
    let session = init.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let _ = init.bytes().await.unwrap();
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
    let r=rpc(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":agent_access_core::mcp::tool_name("gmail","thread.trash"),"arguments":{"inputs":{"id":"abc"}}}}),Some(&session)).send().await.unwrap();
    let r = rpc_response(r).await;
    assert_eq!(
        r["result"]["structuredContent"]["result"]["operation"], "trash",
        "{r}"
    );
    for (i, action) in ["message.send", "message.delete", "thread.delete"]
        .iter()
        .enumerate()
    {
        let r=rpc(json!({"jsonrpc":"2.0","id":3+i,"method":"tools/call","params":{"name":agent_access_core::mcp::tool_name("gmail",action),"arguments":{"inputs":{"id":"abc"}}}}),Some(&session)).send().await.unwrap();
        let r = rpc_response(r).await;
        assert!(
            r.get("error").is_some() || r["result"]["isError"] == true,
            "{r}"
        );
    }
    // Catalog/OpenAPI/send-schema all expose the same eleven actions and read annotations.
    for endpoint in ["catalog", "openapi.json", "send-schema.json"] {
        let response = client
            .get(format!("{base}/v1/spec/{endpoint}"))
            .bearer_auth(&f.agent_token)
            .header(agent_access_provider::REQUEST_ID_HEADER, "gmail-spec")
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{endpoint}: {}",
            response.status()
        );
        let value: Value = response.json().await.unwrap();
        let text = value.to_string();
        assert!(text.contains("thread.trash"), "{endpoint}: {text}");
        assert!(!text.contains("message.delete"));
    }
    f.stop().await;
}
async fn rpc_response(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    if let Ok(value) = serde_json::from_str(&text) {
        return value;
    }
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .find_map(|l| {
            serde_json::from_str::<Value>(l.trim())
                .ok()
                .filter(|v| v.get("id").is_some())
        })
        .unwrap_or_else(|| panic!("Invalid MCP response: {text}"))
}
