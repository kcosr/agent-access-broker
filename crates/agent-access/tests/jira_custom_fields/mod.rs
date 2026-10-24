//! Custom-field delivery through the real CLI and isolated Broker application.
use super::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Stdio};

#[path = "../../../agent-access-jira/tests/fixtures/custom_fields.rs"]
mod large_fixture;

fn backend_for(fields: Vec<Value>) -> Arc<StubJiraBackend> {
    Arc::new(StubJiraBackend {
        issues: BTreeMap::from([(
            "PROJ-1".to_string(),
            JiraIssue {
                id: "10001".to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: Some("Custom field issue".to_string()),
                status: Some("Open".to_string()),
                issue_type: Some("Task".to_string()),
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
                description: Some(jira_adf_text("ROOT_DESCRIPTION")),
            },
        )]),
        custom_fields: fields,
        ..StubJiraBackend::default()
    })
}

fn small_fields() -> Vec<Value> {
    vec![
        json!({"id":"customfield_2","name":"Business *impact*","type":"text","status":"supported","value":"CUSTOM_VALUE [launch]"}),
        json!({"id":"customfield_10","name":"Duplicate name","type":"adf","status":"supported","value":jira_adf_text("CUSTOM_ADF_BODY")}),
        json!({"id":"customfield_11","name":"Duplicate name","type":"text","status":"supported","value":null}),
        json!({"id":"customfield_12","name":null,"type":"options","status":"supported","value":[]}),
        json!({"id":"customfield_13","name":"External object","type":null,"status":"unsupported"}),
        json!({"id":"customfield_14","name":"Malformed option","type":"option","status":"withheld"}),
        json!({"id":"customfield_15","name":"Empty external object","type":null,"status":"unsupported","value":null}),
        json!({"id":"customfield_16","name":"Empty notes","type":"adf","status":"supported","value":null}),
    ]
}

fn assert_small_result(result: &Value, format: Option<&str>) {
    let fields = result["customFields"].as_array().unwrap();
    assert_eq!(fields.len(), 8);
    let mut expected = small_fields();
    if let Some(format) = format {
        let body = if format == "markdown" {
            r"CUSTOM\_ADF\_BODY"
        } else {
            "CUSTOM_ADF_BODY"
        };
        let description = if format == "markdown" {
            r"ROOT\_DESCRIPTION"
        } else {
            "ROOT_DESCRIPTION"
        };
        expected[1]["renderedBody"] = json!({"format":format,"value":body});
        assert_eq!(
            result["renderedBody"],
            json!({"format":format,"value":description})
        );
    } else {
        assert!(result.get("renderedBody").is_none());
    }
    assert_eq!(fields, &expected);
    assert!(fields[7].get("renderedBody").is_none());
}

fn assert_small_markdown(markdown: &str) {
    for text in [
        "## Custom fields",
        "customfield_2",
        "customfield_10",
        "customfield_16",
        "Business \\*impact\\*",
        r"CUSTOM\_VALUE \[launch\]",
        r"CUSTOM\_ADF\_BODY",
        "Duplicate name",
        "unsupported",
        "withheld",
    ] {
        assert!(
            markdown.to_lowercase().contains(&text.to_lowercase()),
            "missing {text} in {markdown}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_fields_cross_typed_invoke_send_and_http_with_three_calls_and_count_only_audit() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let backend = backend_for(small_fields());
        let broker = start_broker(
            access,
            jira_service(jira_provider_config(2), Default::default(), backend.clone()),
        )
        .await;
        let base_url = broker.public_url();
        let mut cursor = 0;
        let run = |args: &[&str]| {
            let output = authenticated_jira_cli(&base_url)
                .args(args)
                .output()
                .unwrap();
            assert_success("custom field CLI", &output);
            output
        };
        let native = run(&["jira", "issue", "view", "PROJ-1"]);
        let native: Value = serde_json::from_slice(&native.stdout).unwrap();
        assert_small_result(&native["result"], None);
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );

        let normalized = run(&[
            "invoke",
            "jira.issue.view",
            "--input-json",
            r#"{"issue":"PROJ-1"}"#,
            "--read-content-format",
            "text",
        ]);
        let normalized: Value = serde_json::from_slice(&normalized.stdout).unwrap();
        assert_small_result(&normalized["result"], Some("text"));
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );

        let request = temp_path("jira-custom-fields-send.json");
        std::fs::write(&request, json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"PROJ-1"},"responseFormat":"markdown"}).to_string()).unwrap();
        let markdown = run(&["send", "--request-file", request.to_str().unwrap()]);
        let markdown: Value = serde_json::from_slice(&markdown.stdout).unwrap();
        assert_eq!(markdown["result"]["format"], "markdown");
        assert_small_markdown(markdown["result"]["value"].as_str().unwrap());
        std::fs::remove_file(request).unwrap();
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );

        let client = reqwest::Client::new();
        for (options, format) in [
            (json!({}), None),
            (json!({"readContentFormat":"markdown"}), Some("markdown")),
        ] {
            let mut body = options;
            body["inputs"] = json!({"issue":"PROJ-1"});
            let response = client
                .post(format!("{base_url}/v1/invoke/jira/issue.view"))
                .header("X-Agent-Access-Identity-Token", "agent-token")
                .header(REQUEST_ID_HEADER, "jira-custom-fields-http")
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            let response: Value = response.json().await.unwrap();
            assert_eq!(status, reqwest::StatusCode::OK, "{response}");
            assert_small_result(&response["result"], format);
            assert_new_backend_operations(
                &backend,
                &mut cursor,
                &["issue_metadata", "issue_metadata", "issue"],
            );
        }
        let expected_credential = match access {
            JiraAccess::AgentPerUser => "jira-per-user-token",
            _ => "jira-token",
        };
        for chunk in backend
            .credential_observations
            .lock()
            .unwrap()
            .as_chunks::<3>()
            .0
        {
            let lookup = if matches!(access, JiraAccess::AgentPerUser) {
                expected_credential
            } else {
                "jira-lookup-token"
            };
            assert_eq!(chunk[0].credential, jira_credential(lookup));
            assert_eq!(chunk[1].credential, jira_credential(lookup));
            assert_eq!(chunk[2].credential, jira_credential(expected_credential));
        }
        assert_eq!(
            *backend.issue_view_requests.lock().unwrap(),
            vec![matches!(access, JiraAccess::AgentPerUser); 5]
        );
        let audit = broker.audit().unwrap().text();
        for secret in [
            "CUSTOM_VALUE",
            "CUSTOM_ADF_BODY",
            "Business",
            "Duplicate name",
            "customfield_",
            "External object",
        ] {
            assert!(!audit.contains(secret));
        }
        let records = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        let counters = records
            .iter()
            .filter_map(find_custom_field_counts)
            .collect::<Vec<_>>();
        assert_eq!(counters.len(), 5);
        assert!(
            counters
                .iter()
                .all(|counts| **counts == json!({"count":8,"unsupported":2,"withheld":1}))
        );
        stop(broker).await;
    }
}

fn find_custom_field_counts(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(map) => map
            .get("customFields")
            .or_else(|| map.values().find_map(find_custom_field_counts)),
        Value::Array(values) => values.iter().find_map(find_custom_field_counts),
        _ => None,
    }
}

async fn start_mcp_broker(backend: Arc<StubJiraBackend>, max_response_bytes: u64) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document = jira_document(application.directory(), JiraAccess::AgentService)
        .replace(
            "header = \"X-Agent-Access-Identity-Token\"",
            "header = \"Authorization\"",
        )
        .replace("scheme = \"raw\"", "scheme = \"Bearer\"");
    document.push_str(&format!(
        "\n[mcp]\nenabled = true\npublic_url = {}\nmax_response_bytes = {max_response_bytes}\n",
        toml_string(format!("{}/mcp", application.public_url()))
    ));
    application
        .config_document(document)
        .provider_fixture(
            "jira",
            ProviderFixture::instance(jira_service(
                jira_provider_config(2),
                Default::default(),
                backend,
            )),
        )
        .start()
        .await
        .unwrap()
}

fn mcp_cli(base_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.args([
        "--url",
        base_url,
        "--token-value",
        "agent-token",
        "--identity-header",
        "Authorization",
        "--identity-scheme",
        "Bearer",
    ]);
    command
}

fn assert_complete_large(result: &Value, normalized: bool) {
    let expected = large_fixture::realistic_issue_view();
    let fields = result["customFields"].as_array().unwrap();
    assert_eq!(fields.len(), 256);
    for (actual, expected) in fields
        .iter()
        .zip(expected["customFields"].as_array().unwrap())
    {
        assert_eq!(actual["id"], expected["id"]);
        assert_eq!(actual["value"], expected["value"]);
        if normalized && actual["type"] == "adf" {
            let number = actual["id"]
                .as_str()
                .unwrap()
                .strip_prefix("customfield_")
                .unwrap();
            let body = actual["renderedBody"]["value"].as_str().unwrap();
            for block in 0..128 {
                assert!(body.contains(&format!(r"FIELD{number}\_BLOCK{block}\_START")));
                assert!(body.contains(&format!(r"FIELD{number}\_BLOCK{block}\_END")));
            }
        } else {
            assert!(actual.get("renderedBody").is_none());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_custom_fields_are_complete_in_cli_and_both_mcp_transports() {
    let fixture = large_fixture::realistic_issue_view();
    assert!(serde_json::to_vec(&fixture).unwrap().len() > 2 * 1024 * 1024);
    let backend = backend_for(fixture["customFields"].as_array().unwrap().clone());
    let broker = start_mcp_broker(backend.clone(), 16 * 1024 * 1024).await;
    let base_url = broker.public_url();
    let mut cursor = 0;
    for (args, normalized) in [
        (vec!["jira", "issue", "view", "PROJ-1"], false),
        (
            vec![
                "jira",
                "issue",
                "view",
                "PROJ-1",
                "--read-content-format",
                "markdown",
            ],
            true,
        ),
    ] {
        let output = mcp_cli(&base_url).args(args).output().unwrap();
        assert_success("large custom field CLI", &output);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_complete_large(&response["result"], normalized);
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );
    }
    let output = mcp_cli(&base_url)
        .args([
            "jira",
            "issue",
            "view",
            "PROJ-1",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("large custom field Markdown", &output);
    let markdown = String::from_utf8(output.stdout).unwrap();
    for field in 1..=256 {
        assert!(markdown.contains(&format!("`customfield_{field}`")));
        if field % 32 == 0 {
            for block in 0..128 {
                assert!(markdown.contains(&format!(r"FIELD{field}\_BLOCK{block}\_START")));
                assert!(markdown.contains(&format!(r"FIELD{field}\_BLOCK{block}\_END")));
            }
        }
    }
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let mut stdio = StdioMcp::start(&base_url);
    let initialize = stdio.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"jira-custom-fields-smoke","version":"1"}})).await;
    assert!(initialize.get("error").is_none());
    stdio.notify("notifications/initialized", json!({}));
    for normalized in [false, true] {
        let mut arguments = json!({"inputs":{"issue":"PROJ-1"}});
        if normalized {
            arguments["readContentFormat"] = json!("markdown");
        }
        let response = stdio.request("tools/call", json!({"name":agent_access_core::mcp::tool_name("jira","issue.view"),"arguments":arguments})).await;
        assert_eq!(response["result"]["isError"], false);
        assert_complete_large(
            &response["result"]["structuredContent"]["result"],
            normalized,
        );
        let text_copy: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text_copy, response["result"]["structuredContent"]);
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );
    }
    stdio.finish().await;
    let (client, session) = initialize_http_mcp(&base_url).await;
    let response = http_mcp_call(&client, &base_url, &session).await;
    assert_eq!(response["result"]["isError"], false);
    assert_complete_large(&response["result"]["structuredContent"]["result"], false);
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );
    let audit = broker.audit().unwrap().text();
    for secret in [
        "FIELD256",
        "Field 256",
        "ROOT_DESCRIPTION",
        "customfield_256",
    ] {
        assert!(!audit.contains(secret));
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_mcp_custom_field_overflow_fails_explicitly_without_replay_or_partial_values() {
    let fixture = large_fixture::realistic_issue_view();
    let backend = backend_for(fixture["customFields"].as_array().unwrap().clone());
    let broker = start_mcp_broker(backend.clone(), 64 * 1024).await;
    let base_url = broker.public_url();
    let (client, session) = initialize_http_mcp(&base_url).await;
    let response = http_mcp_call(&client, &base_url, &session).await;
    assert_eq!(response["result"]["isError"], true);
    let receipt = &response["result"]["structuredContent"];
    assert_eq!(receipt["error"]["code"], "mcp_response_too_large");
    assert_eq!(receipt["resultAvailable"], false);
    assert_eq!(receipt["retrySafe"], false);
    assert_eq!(receipt["execution"]["completion"], "completed");
    assert!(receipt.get("result").is_none());
    let encoded = response.to_string();
    assert!(encoded.len() < 64 * 1024);
    assert!(!encoded.contains("FIELD"));
    assert_new_backend_operations(
        &backend,
        &mut 0,
        &["issue_metadata", "issue_metadata", "issue"],
    );
    let audit = broker.audit().unwrap().text();
    assert_eq!(
        audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|record| record["service"] == "jira"
                && record["action"] == "issue.view"
                && record["decision"] == "allow")
            .count(),
        1
    );
    stop(broker).await;
}

fn http_rpc(
    client: &reqwest::Client,
    base_url: &str,
    session: Option<&str>,
    value: Value,
) -> reqwest::RequestBuilder {
    let request = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth("agent-token")
        .header("Accept", "application/json, text/event-stream");
    let request = if let Some(session) = session {
        request
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25")
    } else {
        request
    };
    request.json(&value)
}

async fn initialize_http_mcp(base_url: &str) -> (reqwest::Client, String) {
    let client = reqwest::Client::new();
    let response = http_rpc(&client, base_url, None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"jira-custom-fields-smoke","version":"1"}}})).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(decode_http_rpc(response).await.get("error").is_none());
    let response = http_rpc(
        &client,
        base_url,
        Some(&session),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);
    (client, session)
}

async fn http_mcp_call(client: &reqwest::Client, base_url: &str, session: &str) -> Value {
    let response = http_rpc(client, base_url, Some(session), json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":agent_access_core::mcp::tool_name("jira","issue.view"),"arguments":{"inputs":{"issue":"PROJ-1"}}}})).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    decode_http_rpc(response).await
}

async fn decode_http_rpc(response: reqwest::Response) -> Value {
    let body = response.text().await.unwrap();
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(&body).unwrap();
    }
    let mut values = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|value| value.get("id").is_some());
    let value = values.next().expect("MCP response event");
    assert!(values.next().is_none());
    value
}

struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: tokio::sync::mpsc::UnboundedReceiver<String>,
    next_id: u64,
}

impl StdioMcp {
    fn start(base_url: &str) -> Self {
        let mut child = mcp_cli(base_url)
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
        self.send(json!({"jsonrpc":"2.0","method":method,"params":params}));
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let line = self.responses.recv().await.expect("stdio MCP closed");
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["id"] == id {
                    return value;
                }
                assert!(value.get("id").is_none());
            }
        })
        .await
        .expect("stdio MCP response timed out")
    }

    async fn finish(mut self) {
        self.stdin.take();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "stdio MCP failed: {status}");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stdio MCP did not exit");
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
