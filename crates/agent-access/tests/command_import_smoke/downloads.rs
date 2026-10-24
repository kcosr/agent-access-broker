//! Real command, CLI, HTTP and stdio MCP download paths. The executable reads
//! exact response bytes from a file so malformed protocol responses cross the
//! same process and transport boundaries as valid ones.
use super::*;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, Stdio};

const WARNING: &str = "Only completed synthetic records are included.";
const SENTINEL: &[u8] = b"\0\xfffile-payload-sentinel-7331\x80\n";
const COMMAND: &str = r#"#!/bin/sh
if [ "$1" = describe ]; then cat "$MANIFEST"; exit 0; fi
umask 077
cat > "$REQUESTS/$$.json"
if [ -e "$BLOCK_COMMIT" ]; then mkdir "$(cat "$BLOCK_COMMIT")"; fi
cat "$RESPONSE"
"#;

struct Downloads {
    directory: FixtureDir,
    base: String,
    admin: PathBuf,
    agent: PathBuf,
    token: String,
    broker: RunningBroker,
}

impl Downloads {
    async fn start() -> Self {
        let application = IsolatedBroker::new(
            agent_access_broker::composition().unwrap(),
            agent_access_broker::build_identity(),
        )
        .unwrap();
        let directory = application.directory().clone();
        let base = application.public_url();
        directory
            .secret_file("key", URL_SAFE_NO_PAD.encode([71u8; 32]))
            .unwrap();
        let hash = directory
            .secret_file("hash", URL_SAFE_NO_PAD.encode([72u8; 32]))
            .unwrap();
        let seeded = seed(&directory, &hash);
        let files = directory.path();
        let script = write_file(files, "downloads.sh", COMMAND);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(files.join("requests")).unwrap();
        let actions = ["report.download", "issue.create", "report.denied", "report.info"]
            .map(|action| {
                let mut definition = json!({"name":action, "description":"Synthetic report.",
                    "readOnly":action != "issue.create", "inputSchema":{"type":"object",
                        "properties":{"reportId":{"type":"string"}},
                        "required":["reportId"], "additionalProperties":false},
                    "outputSchema":{"type":"object", "properties":{"warnings":{"type":"array", "items":{"type":"string"}}}, "additionalProperties":false}});
                if action != "report.info" { definition["download"] = json!(true); }
                definition
            });
        let manifest =
            json!({"format":"agent-access-command/1", "version":"1.0.0", "actions":actions});
        write_file(files, "manifest.json", manifest.to_string());
        let config = broker_document(&directory, &format!("{base}/mcp"))
            .replace(
                &toml_string(reference_command().display()),
                &toml_string(&script),
            )
            .replace(
                "timeout = \"30s\"",
                "timeout = \"30s\"\nmax_download_bytes = 1024",
            )
            .replace(
                &format!(
                    "TICKETING_PROFILE_FILE = {}",
                    toml_string(files.join("profile").display())
                ),
                &format!(
                    "MANIFEST = {}\nRESPONSE = {}\nREQUESTS = {}\nBLOCK_COMMIT = {}",
                    toml_string(files.join("manifest.json").display()),
                    toml_string(files.join("response.json").display()),
                    toml_string(files.join("requests").display()),
                    toml_string(files.join("block-commit").display())
                ),
            );
        let admin = client_config(files, "admin", &base, &seeded.admin);
        let agent = client_config(files, "agent", &base, &seeded.agent);
        let broker = application.config_document(config).start().await.unwrap();
        let created = run(&admin, &["admin", "imports", "create", "--request-file", &write_file(files, "create.json",
            json!({"service":"ticketing", "displayName":"Report downloads", "adapterKind":"command",
                "endpoint":"command:ticketing", "executionBindings":[], "discovery":{"kind":"anonymous"}}).to_string())]);
        let (version, revision) = versions(&created);
        let discovered = run(
            &admin,
            &[
                "admin",
                "imports",
                "discover",
                "ticketing",
                "--expected-version",
                &version,
                "--expected-catalog-revision",
                &revision,
            ],
        );
        assert!(
            discovered["result"]["preview"]["manifest"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .all(|tool| tool["unsupportedReason"].is_null()),
            "{discovered}"
        );
        let accepted = accept_all(&admin, files, &discovered);
        let (version, revision) = versions(&accepted);
        run(
            &admin,
            &[
                "admin",
                "imports",
                "status",
                "ticketing",
                "enabled",
                "--expected-version",
                &version,
                "--expected-catalog-revision",
                &revision,
            ],
        );
        run(
            &admin,
            &[
                "admin",
                "policy",
                "grants",
                "create",
                "--grant-id",
                "reports",
                "--subject",
                "user:avery",
                "--service",
                "ticketing",
                "--credential-mode",
                "service",
                "--execution-context",
                "default",
                "--action",
                "report.download",
                "--action",
                "issue.create",
                "--action",
                "report.info",
            ],
        );
        Self {
            directory,
            base,
            admin,
            agent,
            token: seeded.agent,
            broker,
        }
    }

    fn response(&self, response: impl AsRef<[u8]>) {
        std::fs::write(self.directory.join("response.json"), response).unwrap();
    }

    fn success(&self, bytes: &[u8]) {
        self.response(success(bytes).to_string());
    }

    fn requests(&self) -> Vec<String> {
        std::fs::read_dir(self.directory.join("requests"))
            .unwrap()
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }

    fn invoke(&self, action: &str, output: &Path) -> std::process::Output {
        cli(&self.agent)
            .args([
                "invoke",
                &format!("ticketing.{action}"),
                "--input-json",
                r#"{"reportId":"monthly"}"#,
                "--output",
            ])
            .arg(output)
            .output()
            .unwrap()
    }

    fn send_request(&self, output: &Path) -> Value {
        json!({"version":"agent-access.send.v1", "kind":"invoke", "responseMode":"stream",
            "service":"ticketing", "action":"report.download", "inputs":{"reportId":"monthly"},
            "output":{"type":"file", "path":output}})
    }

    fn send(&self, request: &Value) -> std::process::Output {
        cli(&self.agent)
            .args(["send", "--request-json", &request.to_string()])
            .output()
            .unwrap()
    }

    async fn http(&self, action: &str) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/invoke/ticketing/{action}", self.base))
            .bearer_auth(&self.token)
            .header("X-Agent-Access-Request-Id", request_id())
            .header("Accept", "application/octet-stream")
            .json(&json!({"inputs":{"reportId":"monthly"}}))
            .send()
            .await
            .unwrap()
    }
}

fn success(bytes: &[u8]) -> Value {
    json!({"ok":true, "result":{"warnings":[WARNING]}, "download":{
        "content":STANDARD.encode(bytes), "filename":"report.bin", "contentType":"application/octet-stream"}})
}

fn decoded(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn no_payload(text: &str) {
    assert!(
        !text.contains("file-payload-sentinel-7331"),
        "payload leaked"
    );
    assert!(
        !text.contains(&STANDARD.encode(SENTINEL)),
        "encoded payload leaked"
    );
}

fn receipt(value: &Value, output: &Path, bytes: &[u8]) {
    let hash = format!("{:x}", Sha256::digest(bytes));
    assert_eq!(value["result"]["size"], bytes.len());
    assert_eq!(value["result"]["sha256"], hash);
    assert_eq!(value["result"]["contentType"], "application/octet-stream");
    assert_eq!(
        value["result"]["upstreamCommand"]["warnings"],
        json!([WARNING])
    );
    assert_eq!(value["output"]["path"], output.to_str().unwrap());
    assert_eq!(value["output"]["size"], bytes.len());
    assert_eq!(value["output"]["sha256"], hash);
    assert_eq!(value["output"]["sensitive"], true);
    assert!(value["brokerRequestId"].is_string());
    assert!(value["agentRequestId"].is_string());
    assert!(value["result"].get("mutationStatus").is_none());
    assert_eq!(std::fs::read(output).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    no_payload(&value.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_downloads_cross_real_cli_http_and_stdio_boundaries() {
    let fixture = Downloads::start().await;
    let destination = fixture.directory.join("local-only-destination-8423.bin");
    for bytes in [
        vec![],
        vec![0],
        vec![0, 255],
        vec![0, 255, 128],
        (0..=255).collect(),
        vec![0x82; 1024],
        SENTINEL.to_vec(),
    ] {
        fixture.success(&bytes);
        let result = fixture.invoke("report.download", &destination);
        receipt(&decoded(&result), &destination, &bytes);
        no_payload(&String::from_utf8_lossy(&result.stderr));
    }
    fixture.success(SENTINEL);
    let metadata_path = fixture.directory.join("local-only-metadata-2718.json");
    let mut send = fixture.send_request(&destination);
    send["metadataOutput"] = json!({"type":"file", "path":metadata_path});
    let result = fixture.send(&send);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: Value = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    receipt(&metadata, &destination, SENTINEL);
    no_payload(&String::from_utf8_lossy(&result.stdout));
    no_payload(&String::from_utf8_lossy(&result.stderr));

    let stdout = fixture.invoke("report.download", Path::new("-"));
    assert!(
        stdout.status.success(),
        "{}",
        String::from_utf8_lossy(&stdout.stderr)
    );
    assert_eq!(stdout.stdout, SENTINEL);
    no_payload(&String::from_utf8_lossy(&stdout.stderr));

    let mut stdout_send = fixture.send_request(Path::new("unused"));
    stdout_send["output"] = json!({"type":"stdout"});
    let stdout = fixture.send(&stdout_send);
    assert!(stdout.status.success());
    assert_eq!(stdout.stdout, SENTINEL);
    no_payload(&String::from_utf8_lossy(&stdout.stderr));

    let relative = cli(&fixture.agent)
        .current_dir(fixture.directory.path())
        .args([
            "invoke",
            "ticketing.report.download",
            "--input-json",
            r#"{"reportId":"monthly"}"#,
            "--output",
            "local-only-relative.bin",
        ])
        .output()
        .unwrap();
    assert_eq!(
        decoded(&relative)["output"]["path"],
        "local-only-relative.bin"
    );
    assert_eq!(
        std::fs::read(fixture.directory.join("local-only-relative.bin")).unwrap(),
        SENTINEL
    );

    let response = fixture.http("report.download").await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let encoded = response.headers()["x-agent-access-result-metadata"]
        .to_str()
        .unwrap();
    let metadata: Value = serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    no_payload(&metadata.to_string());
    assert_eq!(
        metadata["result"]["upstreamCommand"]["warnings"],
        json!([WARNING])
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), SENTINEL);

    let mut mcp = StdioMcp::start(&fixture.agent);
    mcp.request("initialize", json!({"protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":{"name":"command-download-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let listing = mcp.request("tools/list", json!({})).await;
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "report.download")
        .unwrap();
    assert!(
        tool["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("outputPath"))
    );
    let downloaded = mcp.request("tools/call", json!({"name":tool["name"],"arguments":{"inputs":{"reportId":"monthly"},"outputPath":destination}})).await;
    assert_eq!(downloaded["result"]["isError"], false, "{downloaded}");
    receipt(
        &downloaded["result"]["structuredContent"],
        &destination,
        SENTINEL,
    );
    no_payload(&downloaded.to_string());
    let before = fixture.requests().len();
    for output in [
        "relative.bin".to_owned(),
        "-".to_owned(),
        fixture
            .directory
            .join("missing/output.bin")
            .display()
            .to_string(),
    ] {
        let rejected = mcp.request("tools/call", json!({"name":tool["name"],"arguments":{"inputs":{"reportId":"monthly"},"outputPath":output}})).await;
        assert_eq!(rejected["result"]["isError"], true, "{rejected}");
        assert_eq!(fixture.requests().len(), before);
    }
    fixture.response(r#"{"ok":false,"error":{"code":"resource_not_found","message":"The requested download was not found."}}"#);
    let missing = mcp.request("tools/call", json!({"name":tool["name"],"arguments":{"inputs":{"reportId":"monthly"},"outputPath":destination}})).await;
    assert_eq!(missing["result"]["isError"], true, "{missing}");
    assert_eq!(
        missing["result"]["structuredContent"]["reasonCode"],
        "resource_not_found"
    );
    assert_eq!(std::fs::read(&destination).unwrap(), SENTINEL);
    let stderr = mcp.finish().await;
    no_payload(&stderr);

    assert!(
        !mcp_tool_names(&fixture.base, &fixture.token)
            .await
            .iter()
            .any(|name| name.contains("download") || name.contains("create"))
    );
    for request in fixture.requests() {
        let parsed: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(parsed["inputs"], json!({"reportId":"monthly"}));
        assert!(!request.contains("local-only-"));
        assert!(!request.contains("outputPath"));
        assert!(!request.contains("metadataOutput"));
    }
    let audit = std::fs::read_to_string(fixture.directory.join("audit.jsonl")).unwrap();
    no_payload(&audit);
    assert!(!audit.contains(WARNING));
    assert!(!audit.contains("local-only-"));
    stop(fixture.broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_and_local_failures_preserve_files_and_never_replay_commands() {
    let fixture = Downloads::start().await;
    let destination = fixture.directory.join("preserved.bin");
    std::fs::write(&destination, b"original file").unwrap();
    fixture.success(SENTINEL);
    let missing_parent = fixture.directory.join("missing/output.bin");
    let directory = fixture.directory.join("directory");
    std::fs::create_dir(&directory).unwrap();
    for invalid in [&missing_parent, &directory] {
        let before = fixture.requests().len();
        let result = fixture.invoke("report.download", invalid);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(fixture.requests().len(), before);
        let mut send = fixture.send_request(&destination);
        send["metadataOutput"] = json!({"type":"file", "path":invalid});
        assert!(!fixture.send(&send).status.success());
        assert_eq!(fixture.requests().len(), before);
        assert_eq!(std::fs::read(&destination).unwrap(), b"original file");
    }
    let before = fixture.requests().len();
    assert!(
        !fixture
            .invoke("report.denied", &destination)
            .status
            .success()
    );
    assert!(!fixture.invoke("not.present", &destination).status.success());
    assert_eq!(fixture.requests().len(), before);
    let denied = fixture.http("report.denied").await;
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(fixture.requests().len(), before);
    let no_output = cli(&fixture.agent)
        .args([
            "invoke",
            "ticketing.report.download",
            "--input-json",
            r#"{"reportId":"monthly"}"#,
        ])
        .output()
        .unwrap();
    assert!(!no_output.status.success());
    assert_eq!(fixture.requests().len(), before);

    let normal_error = r#"{"ok":false,"error":{"code":"resource_not_found","message":"The requested download was not found."}}"#;
    fixture.response(normal_error);
    let missing = fixture.http("report.download").await;
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        !missing
            .headers()
            .contains_key("x-agent-access-result-metadata")
    );
    let missing: Value = missing.json().await.unwrap();
    assert_eq!(missing["reasonCode"], "resource_not_found");
    assert!(missing["result"].get("mutationStatus").is_none());

    let mut mismatch = success(SENTINEL);
    mismatch["download"]["size"] = json!(123);
    let mut invalid_base64 = success(SENTINEL);
    invalid_base64["download"]["content"] = json!("not%base64");
    let oversized = success(&vec![0x81; 1025]);
    let valid = success(SENTINEL).to_string();
    for response in [
        normal_error.to_owned(),
        mismatch.to_string(),
        invalid_base64.to_string(),
        oversized.to_string(),
        format!("{valid} {{}}"),
        valid.replacen("\"ok\":true", "\"ok\":true,\"ok\":true", 1),
    ] {
        fixture.response(response);
        for use_send in [false, true] {
            let before = fixture.requests().len();
            let result = if use_send {
                fixture.send(&fixture.send_request(&destination))
            } else {
                fixture.invoke("report.download", &destination)
            };
            assert!(!result.status.success());
            assert_eq!(
                fixture.requests().len(),
                before + 1,
                "one dispatch, no retry"
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"original file");
            no_payload(&String::from_utf8_lossy(&result.stdout));
            no_payload(&String::from_utf8_lossy(&result.stderr));
        }
    }
    // A write returns its explicit outcome with the file; malformed/remote
    // failures above must not cause a second dispatch to retrieve any result.
    let mut written = success(SENTINEL);
    written["receipt"] = json!({"safeLocators":{"report":"monthly"}});
    fixture.response(written.to_string());
    let written = decoded(&fixture.invoke("issue.create", &destination));
    assert_eq!(written["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(written["result"]["safeLocators"]["report"], "monthly");
    assert_eq!(written["output"]["sensitive"], true);
    assert_eq!(std::fs::read(&destination).unwrap(), SENTINEL);
    no_payload(&written.to_string());
    // The real command makes the reserved destination a directory after local
    // preflight. Both clients must retain its known write receipt on commit
    // failure, without invoking it again to try to obtain another copy.
    for use_send in [false, true] {
        let target = fixture
            .directory
            .join(format!("commit-failure-{use_send}.bin"));
        std::fs::write(
            fixture.directory.join("block-commit"),
            target.to_str().unwrap(),
        )
        .unwrap();
        let before = fixture.requests().len();
        let output = if use_send {
            let mut request = fixture.send_request(&target);
            request["action"] = json!("issue.create");
            fixture.send(&request)
        } else {
            fixture.invoke("issue.create", &target)
        };
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(failure["operationStatus"], "applied_unverified");
        assert_eq!(failure["mutationStatus"], "applied_unverified");
        assert_eq!(failure["safeLocators"]["report"], "monthly");
        assert_eq!(failure["output"]["status"], "failed");
        assert_eq!(failure["output"]["destinationReplaced"], false);
        assert_eq!(fixture.requests().len(), before + 1);
        no_payload(&failure.to_string());
        std::fs::remove_file(fixture.directory.join("block-commit")).unwrap();
    }
    let current = run(&fixture.admin, &["admin", "imports", "get", "ticketing"]);
    let (version, revision) = versions(&current);
    run(
        &fixture.admin,
        &[
            "admin",
            "imports",
            "status",
            "ticketing",
            "disabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    let before = fixture.requests().len();
    assert!(
        !fixture
            .invoke("report.download", &destination)
            .status
            .success()
    );
    assert_eq!(fixture.requests().len(), before);
    stop(fixture.broker).await;
}

struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: tokio::sync::mpsc::UnboundedReceiver<String>,
    next_id: u64,
}

impl StdioMcp {
    fn start(config: &Path) -> Self {
        let mut child = cli(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
            next_id: 1,
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc":"2.0", "method":method, "params":params}));
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}));
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let line = self.responses.recv().await.expect("stdio MCP closed");
                let value: Value =
                    serde_json::from_str(&line).expect("protocol stdout must be JSON");
                if value["id"] == id {
                    return value;
                }
                assert!(
                    value.get("id").is_none(),
                    "unexpected MCP response: {value}"
                );
            }
        })
        .await
        .expect("stdio MCP response timed out")
    }

    async fn finish(mut self) -> String {
        self.stdin.take();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "stdio MCP failed: {status}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stdio MCP did not exit");
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        stderr
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
