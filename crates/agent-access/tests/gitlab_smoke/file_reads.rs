//! File reads through the production GitLab HTTP adapter and real Broker/CLI.
use super::*;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TEXT: &str = "\u{feff}private-gitlab-file-text\r\nsecond line without final newline";
const CONTENT_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UNICODE_PATH: &str = "docs/日本語.md";

#[derive(Clone)]
struct FileHttp;

fn bytes(path: &str) -> Option<Vec<u8>> {
    Some(match path {
        "README.md" | UNICODE_PATH => TEXT.as_bytes().to_vec(),
        "large.txt" => "private-large-file-line\n".repeat(4096).into_bytes(),
        "quoted.txt" => b"\"".repeat(20_000),
        "latin1.txt" => vec![0x63, 0x61, 0x66, 0xe9],
        "nul.txt" => b"text\0text".to_vec(),
        "empty.txt" | "huge.bin" => Vec::new(),
        _ => return None,
    })
}

impl Respond for FileHttp {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let path = percent_decode_str(request.url.path())
            .decode_utf8()
            .unwrap();
        if matches!(
            path.as_ref(),
            "/api/v4/projects/sip/service" | "/api/v4/projects/42"
        ) {
            return ResponseTemplate::new(200).set_body_json(json!({
                "id":42,"path_with_namespace":"sip/service","name":"service",
                "default_branch":"main"
            }));
        }
        let Some(tail) = path.strip_prefix("/api/v4/projects/42/repository/files/") else {
            return ResponseTemplate::new(404);
        };
        // File identity and bytes must both use the selected execution identity,
        // never the deliberately distinct lookup credential.
        assert_eq!(
            request.headers["authorization"].to_str().unwrap(),
            "Bearer gitlab-per-user-token"
        );
        assert_eq!(
            request
                .url
                .query_pairs()
                .find(|(key, _)| key == "ref")
                .unwrap()
                .1,
            "main"
        );
        let (file, raw) = tail
            .strip_suffix("/raw")
            .map_or((tail, false), |file| (file, true));
        let Some(body) = bytes(file) else {
            return ResponseTemplate::new(404);
        };
        let head = request.method.as_str() == "HEAD";
        if !(head && !raw || request.method.as_str() == "GET" && raw) {
            // Catch accidental use of the JSON endpoint for content/preflight.
            return ResponseTemplate::new(500);
        }
        let size = if file == "huge.bin" {
            200 * 1024 * 1024
        } else {
            body.len()
        };
        let response = ResponseTemplate::new(200)
            .insert_header("x-gitlab-file-name", file.rsplit('/').next().unwrap())
            .insert_header("x-gitlab-file-path", file)
            .insert_header("x-gitlab-size", size.to_string())
            .insert_header("x-gitlab-commit-id", TEST_SHA)
            .insert_header("x-gitlab-blob-id", TEST_SHA)
            .insert_header("x-gitlab-last-commit-id", TEST_SHA)
            .insert_header("x-gitlab-ref", "main")
            .insert_header("x-gitlab-execute-filemode", "false")
            // Intentionally differs from the raw bytes: GitLab can hash a
            // converted representation, including on HEAD/raw responses.
            .insert_header("x-gitlab-content-sha256", CONTENT_HASH)
            .insert_header("content-type", "text/plain");
        if head {
            response.insert_header("content-length", size.to_string())
        } else {
            response.set_body_bytes(body)
        }
    }
}

struct Fixture {
    server: MockServer,
    broker: RunningBroker,
}

impl Fixture {
    async fn start(mcp_limit: usize) -> Self {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(FileHttp)
            .mount(&server)
            .await;
        let application = IsolatedBroker::new(
            agent_access_broker::composition().unwrap(),
            agent_access_broker::build_identity(),
        )
        .unwrap();
        let mut document = gitlab_per_user_document();
        document.default_invocation_limit = Some((1000, "1m"));
        document.provider.api_base_url = format!("{}/api/v4", server.uri());
        document.provider.web_base_url = server.uri();
        document.provider.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
        for grant in &mut document.grants {
            grant.actions = vec!["file.view".into(), "file.raw.download".into()];
        }
        let mut config: toml::Value =
            toml::from_str(&document.render(application.directory())).unwrap();
        config["identity"]["sources"][0]["header"] = "Authorization".into();
        config["identity"]["sources"][0]["scheme"] = "Bearer".into();
        config.as_table_mut().unwrap().insert(
            "mcp".into(),
            toml::Value::try_from(json!({
                "enabled":true, "public_url":format!("{}/mcp", application.public_url()),
                "max_response_bytes":mcp_limit
            }))
            .unwrap(),
        );
        let broker = application
            .config_document(toml::to_string(&config).unwrap())
            .start()
            .await
            .unwrap();
        Self { server, broker }
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        command.args([
            "--url",
            &self.broker.public_url(),
            "--token-value",
            "agent-token",
            "--identity-header",
            "Authorization",
            "--identity-scheme",
            "Bearer",
        ]);
        command
    }

    async fn invoke(&self, action: &str, inputs: Value) -> (reqwest::StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(format!(
                "{}/v1/invoke/gitlab/{action}",
                self.broker.public_url()
            ))
            .bearer_auth("agent-token")
            .header(
                agent_access_provider::REQUEST_ID_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }

    async fn view(&self, path: &str, extra: Value) -> Value {
        let mut inputs = json!({"project":"sip/service","path":path,"ref":"main"});
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, result) = self.invoke("file.view", inputs).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{result}");
        result
    }

    async fn file_requests(&self) -> Vec<(String, String)> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().contains("/repository/files/"))
            .map(|r| {
                (
                    r.method.to_string(),
                    percent_decode_str(r.url.path())
                        .decode_utf8()
                        .unwrap()
                        .into_owned(),
                )
            })
            .collect()
    }

    async fn rpc(&self, session: Option<&str>, value: Value) -> reqwest::Response {
        let mut request = reqwest::Client::new()
            .post(format!("{}/mcp", self.broker.public_url()))
            .bearer_auth("agent-token")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .header(
                agent_access_provider::REQUEST_ID_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .json(&value);
        if let Some(session) = session {
            request = request.header("Mcp-Session-Id", session);
        }
        request.send().await.unwrap()
    }

    async fn http_mcp(&self) -> (String, String) {
        let init = self.rpc(None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"file-read-smoke","version":"1"}
        }})).await;
        assert_eq!(init.status(), reqwest::StatusCode::OK);
        let session = init.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let _ = rpc_json(init).await;
        let initialized = self
            .rpc(
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await;
        assert_eq!(initialized.status(), reqwest::StatusCode::ACCEPTED);
        let listing = rpc_json(
            self.rpc(
                Some(&session),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            )
            .await,
        )
        .await;
        let tools = listing["result"]["tools"].as_array().unwrap();
        assert!(
            !tools
                .iter()
                .any(|tool| tool["_meta"]["agent-access/action"] == "file.raw.download")
        );
        let view = tools
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == "file.view")
            .unwrap();
        assert_eq!(
            view["inputSchema"]["properties"]["inputs"]["properties"]["maxContentBytes"]["maximum"],
            1024 * 1024
        );
        (session, view["name"].as_str().unwrap().to_owned())
    }

    async fn close(self) {
        stop(self.broker).await;
    }
}

async fn rpc_json(response: reqwest::Response) -> Value {
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(&body).unwrap();
    }
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|message| message.get("id").is_some())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_views_use_metadata_defaults_and_explicit_complete_text_budgets() {
    let fixture = Fixture::start(16 * 1024 * 1024).await;
    let metadata = fixture.view("huge.bin", json!({})).await;
    assert_eq!(metadata["result"]["file"]["size"], 200 * 1024 * 1024);
    assert_eq!(metadata["result"]["file"]["contentStatus"], "not_requested");
    assert!(metadata["result"]["file"].get("content").is_none());
    assert!(metadata["result"]["file"].get("contentBase64").is_none());
    assert_eq!(
        fixture.file_requests().await,
        [(
            "HEAD".into(),
            "/api/v4/projects/42/repository/files/huge.bin".into()
        )]
    );

    for path in ["README.md", UNICODE_PATH] {
        let result = fixture.view(path, json!({"includeContent":true})).await;
        assert_eq!(result["result"]["file"]["contentStatus"], "included");
        assert_eq!(result["result"]["file"]["content"], TEXT);
        assert_eq!(result["result"]["file"]["commitId"], TEST_SHA);
        assert_eq!(result["result"]["file"]["contentSha256"], CONTENT_HASH);
        assert!(result["result"]["file"].get("encoding").is_none());
    }
    let empty = fixture
        .view("empty.txt", json!({"includeContent":true}))
        .await;
    assert_eq!(empty["result"]["file"]["contentStatus"], "included");
    assert_eq!(empty["result"]["file"]["content"], "");
    for path in ["latin1.txt", "nul.txt"] {
        let result = fixture.view(path, json!({"includeContent":true})).await;
        assert_eq!(
            result["result"]["file"]["contentStatus"],
            "unsupported_text"
        );
        assert!(result["result"]["file"].get("content").is_none());
    }

    let too_large = fixture
        .view("large.txt", json!({"includeContent":true}))
        .await;
    assert_eq!(too_large["result"]["file"]["contentStatus"], "too_large");
    assert_eq!(too_large["result"]["file"]["contentBudgetBytes"], 65536);
    assert!(too_large["result"]["file"].get("content").is_none());
    let large = bytes("large.txt").unwrap();
    let exact = fixture
        .view(
            "large.txt",
            json!({"includeContent":true,"maxContentBytes":large.len()}),
        )
        .await;
    assert_eq!(
        exact["result"]["file"]["content"],
        String::from_utf8(large.clone()).unwrap()
    );
    let one_short = fixture
        .view(
            "large.txt",
            json!({"includeContent":true,"maxContentBytes":large.len()-1}),
        )
        .await;
    assert_eq!(one_short["result"]["file"]["contentStatus"], "too_large");
    assert_eq!(
        one_short["result"]["file"]["contentBudgetBytes"],
        large.len() - 1
    );
    let requests = fixture.file_requests().await;
    assert_eq!(requests.len(), 9);
    assert!(
        requests[1..]
            .iter()
            .all(|(method, path)| method == "GET" && path.ends_with("/raw"))
    );

    for extra in [
        json!({"maxContentBytes":10}),
        json!({"includeContent":true,"maxContentBytes":0}),
        json!({"includeContent":true,"maxContentBytes":1024*1024+1}),
        json!({"includeContent":true,"maxContentBytes":1.5}),
    ] {
        let mut inputs = json!({"project":"sip/service","path":"README.md","ref":"main"});
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (_, denied) = fixture.invoke("file.view", inputs).await;
        assert_eq!(denied["reasonCode"], "input_invalid", "{denied}");
    }
    let output = fixture
        .cli()
        .args([
            "gitlab",
            "file",
            "view",
            "sip/service",
            "--path",
            "large.txt",
            "--ref",
            "main",
            "--include-content",
            "--max-content-bytes",
            &large.len().to_string(),
        ])
        .output()
        .unwrap();
    assert_success("typed explicit whole-file budget", &output);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["result"]["file"]["contentStatus"], "included");
    assert_eq!(
        result["result"]["file"]["content"],
        String::from_utf8(large).unwrap()
    );
    for args in [
        vec!["--max-content-bytes", "10"],
        vec!["--include-content", "--max-content-bytes", "0"],
    ] {
        let output = fixture
            .cli()
            .args([
                "gitlab",
                "file",
                "view",
                "sip/service",
                "--path",
                "README.md",
                "--ref",
                "main",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
    let audit = fixture.broker.audit().unwrap().text();
    assert!(!audit.contains("private-gitlab-file-text"));
    assert!(!audit.contains("private-large-file-line"));
    assert!(audit.contains("includeContent"));
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_file_downloads_report_actual_local_digest_without_transcoded_hash_expectations() {
    let fixture = Fixture::start(16 * 1024 * 1024).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("latin1.bin");
    let output = fixture
        .cli()
        .args([
            "gitlab",
            "file",
            "raw",
            "sip/service",
            "--path",
            "latin1.txt",
            "--ref",
            "main",
            "--output",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("raw non-UTF8 file", &output);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["result"].get("sha256").is_none());
    let raw = bytes("latin1.txt").unwrap();
    let digest = format!("{:x}", Sha256::digest(&raw));
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    assert_eq!(result["output"]["sha256"], digest);
    assert_ne!(digest, CONTENT_HASH);
    assert_eq!(result["result"]["resolvedRef"], TEST_SHA);

    let mut mcp = list_mcp::StdioMcp::start(fixture.cli());
    mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"file-download-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let listing = mcp.request("tools/list", json!({})).await;
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "file.raw.download")
        .unwrap();
    let name = tool["name"].as_str().unwrap();
    let path = dir.path().join("stdio-latin1.bin");
    let reply = mcp
        .request(
            "tools/call",
            json!({"name":name,"arguments":{
                "inputs":{"project":"sip/service","path":"latin1.txt","ref":"main"},
                "outputPath":path
            }}),
        )
        .await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["output"]["sha256"],
        digest
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes("latin1.txt").unwrap());
    let rejected = mcp.request("tools/call", json!({"name":name,"arguments":{
        "inputs":{"project":"sip/service","path":"README.md","ref":"main","includeContent":true},
        "outputPath":dir.path().join("must-not-exist")
    }})).await;
    assert_eq!(rejected["result"]["isError"], true, "{rejected}");
    assert!(!dir.path().join("must-not-exist").exists());
    mcp.finish().await;
    assert!(
        fixture
            .file_requests()
            .await
            .iter()
            .all(|(method, path)| method == "GET" && path.ends_with("/raw"))
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_mcp_file_views_allow_raised_budgets_and_enforce_serialized_wire_limits() {
    let fixture = Fixture::start(16 * 1024 * 1024).await;
    let (session, name) = fixture.http_mcp().await;
    for (id, extra, expected) in [
        (3, json!({}), "not_requested"),
        (4, json!({"includeContent":true}), "too_large"),
        (
            5,
            json!({"includeContent":true,"maxContentBytes":128*1024}),
            "included",
        ),
    ] {
        let mut inputs = json!({"project":"sip/service","path":"large.txt","ref":"main"});
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let reply = rpc_json(fixture.rpc(Some(&session), json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":{"inputs":inputs}}})).await).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(
            reply["result"]["structuredContent"]["result"]["file"]["contentStatus"],
            expected
        );
    }
    fixture.close().await;

    let fixture = Fixture::start(64 * 1024).await;
    let (session, name) = fixture.http_mcp().await;
    for (id, path, error) in [(3, "README.md", false), (4, "quoted.txt", true)] {
        let reply = rpc_json(fixture.rpc(Some(&session), json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":{"inputs":{
            "project":"sip/service","path":path,"ref":"main","includeContent":true
        }}}})).await).await;
        assert_eq!(reply["result"]["isError"], error, "{reply}");
        if error {
            assert_eq!(
                reply["result"]["structuredContent"]["error"]["code"],
                "mcp_response_too_large"
            );
            assert!(reply["result"]["structuredContent"].get("result").is_none());
        } else {
            assert_eq!(
                reply["result"]["structuredContent"]["result"]["file"]["content"],
                TEXT
            );
        }
    }
    fixture.close().await;
}
