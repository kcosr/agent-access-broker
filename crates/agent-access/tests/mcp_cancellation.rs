//! Exercise cancellation and current-protocol discovery through the actual CLI
//! subprocess. The delayed HTTP response makes cancellation observable at EOF.
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;
use tokio::sync::mpsc;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Client {
    process: Child,
    stdin: Option<ChildStdin>,
    messages: mpsc::UnboundedReceiver<Value>,
}

impl Client {
    fn start(config: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(name);
            }
        }
        let mut process = command
            .arg("--config")
            .arg(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = process.stdin.take();
        let stdout = process.stdout.take().unwrap();
        let (sender, messages) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let message = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(message).is_err() {
                    break;
                }
            }
        });
        Self {
            process,
            stdin,
            messages,
        }
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &message).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    async fn response(&mut self, id: u64) -> Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let message = self.messages.recv().await.expect("MCP stdout closed");
                assert_eq!(message["jsonrpc"], "2.0");
                if message["id"] == id {
                    return message;
                }
                // The cancelled call deliberately has id 3. Depending on the
                // wire race, an SDK may suppress its result or deliver an error.
                assert!(
                    message.get("id").is_none() || message["id"] == 3,
                    "unexpected response: {message}"
                );
            }
        })
        .await
        .expect("MCP response timed out")
    }

    async fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        self.response(id).await
    }

    async fn finish(mut self) {
        self.stdin.take();
        // rmcp waits up to five seconds for pending handlers on EOF. Finishing
        // before that deadline proves cancellation released the delayed call,
        // rather than merely allowing concurrent ping/list responses.
        let status = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if let Some(status) = self.process.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("MCP retained an in-flight handler after cancellation/EOF");
        assert!(status.success(), "MCP exited unsuccessfully: {status}");
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

async fn broker_fixture() -> MockServer {
    let broker = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version":"agent-access.catalog.v2", "identity":{}, "routes":[],
            "send":{"version":"agent-access.send.v1","catalogRequired":true},
            "services":[{
                "service":"fake", "displayName":"Cancellation fixture", "surface":"invoke", "scopedMcpReady":true,
                "scopeTypes":[], "actions":[{
                    "action":"echo", "scopedMcpName":"echo", "readOnly":true, "description":"Echo an input", "requiredScopeTypes":[],
                    "credentialModes":[], "inputSchema":{"type":"object"},
                    "io":{"type":"json"}, "responseKind":"response_envelope",
                    "exitPolicy":"invoke_decision"
                }]
            }]
        })))
        .mount(&broker)
        .await;
    broker
}

fn config(directory: &Path, broker: &MockServer) -> std::path::PathBuf {
    let path = directory.join("client.toml");
    std::fs::write(
        &path,
        format!(
            "[service]\nurl = {:?}\n[identity]\ndisabled = true\n",
            broker.uri()
        ),
    )
    .unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_call_releases_handler_without_retry_and_keeps_stdio_usable() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("response.json");
    std::fs::write(&destination, b"keep existing response").unwrap();
    let broker = broker_fixture().await;
    Mock::given(method("POST"))
        .and(path("/v1/invoke/fake/echo"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .expect(1)
        .mount(&broker)
        .await;
    let mut client = Client::start(&config(directory.path(), &broker));
    let original_entries = directory_entries(directory.path());
    let initialized = client
        .request(
            1,
            "initialize",
            json!({
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"cancellation-test","version":"1"}
            }),
        )
        .await;
    assert!(initialized.get("error").is_none(), "{initialized}");
    client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let listed = client.request(2, "tools/list", json!({})).await;
    let tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool.get("_meta").is_some())
        .unwrap()["name"]
        .as_str()
        .unwrap();
    client.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":tool,"arguments":{"inputs":{"message":"cancel me"},"outputPath":destination}}}));
    // Cancel only after the request reaches HTTP: this verifies an in-flight
    // invocation, not cancellation before catalog lookup or tool validation.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if broker
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path() == "/v1/invoke/fake/echo")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("tool did not reach broker before cancellation");
    let pending_entries = directory_entries(directory.path());
    let reservations = pending_entries
        .difference(&original_entries)
        .collect::<Vec<_>>();
    assert_eq!(
        reservations.len(),
        1,
        "output must be reserved before dispatch"
    );
    assert_eq!(
        std::fs::metadata(directory.path().join(reservations[0]))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"keep existing response"
    );
    client.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":3,"reason":"test cancellation"}}));
    tokio::time::timeout(Duration::from_secs(3), async {
        while directory_entries(directory.path()) != original_entries {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled tool left its output reservation behind");
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"keep existing response"
    );
    let ping = client.request(4, "ping", json!({})).await;
    assert_eq!(ping["result"], json!({}), "{ping}");
    let listed_again = client.request(5, "tools/list", json!({})).await;
    assert!(
        listed_again["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["name"] == tool)
    );
    client.finish().await;
    broker.verify().await;
}

fn directory_entries(path: &Path) -> std::collections::BTreeSet<std::ffi::OsString> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_protocol_discovers_and_lists_tools_without_initialize() {
    let directory = tempfile::tempdir().unwrap();
    let broker = broker_fixture().await;
    let mut client = Client::start(&config(directory.path(), &broker));
    let metadata = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"discovery-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    let discovery = client
        .request(1, "server/discover", json!({"_meta":metadata}))
        .await;
    assert!(discovery.get("error").is_none(), "{discovery}");
    assert!(
        discovery["result"]["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|version| version == "2026-07-28")
    );
    assert!(discovery["result"]["capabilities"].get("tools").is_some());
    let listed = client
        .request(2, "tools/list", json!({"_meta":metadata}))
        .await;
    assert!(listed.get("error").is_none(), "{listed}");
    assert_eq!(listed["result"]["resultType"], "complete");
    assert_eq!(listed["result"]["ttlMs"], 0);
    assert_eq!(listed["result"]["cacheScope"], "private");
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 6);
    client.finish().await;
}
