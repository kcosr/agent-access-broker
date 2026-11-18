//! The stdio `--output-schemas` selection: off by default, fixed for each
//! process, and changing only MCP output-schema metadata.
use super::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const SELECTIONS: [Option<OutputSchemas>; 3] =
    [Some(OutputSchemas::On), Some(OutputSchemas::Off), None];

fn without_output_schema(tool: &Value) -> Value {
    let mut tool = tool.clone();
    tool.as_object_mut().unwrap().remove("outputSchema");
    tool
}

/// A tool result without per-request correlation, live limits or the
/// identity of the local file a receipt names.
fn comparable(response: &Value) -> Value {
    fn normalize(value: &mut Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        for key in ["agentRequestId", "brokerRequestId", "limits"] {
            object.remove(key);
        }
        if let Some(output) = object.get_mut("output").and_then(Value::as_object_mut) {
            for key in ["path", "sha256", "size"] {
                output.remove(key);
            }
        }
    }
    let mut result = response["result"].clone();
    if let Some(structured) = result.get_mut("structuredContent") {
        normalize(structured);
    }
    if let Some(text) = result["content"][0]["text"].as_str()
        && let Ok(mut parsed) = serde_json::from_str::<Value>(text)
    {
        normalize(&mut parsed);
        result["content"][0]["text"] = parsed;
    }
    result
}

async fn list_all(process: &mut McpProcess) -> (Vec<Value>, Option<String>) {
    let mut tools = Vec::new();
    let mut params = json!({});
    let mut first_cursor = None;
    loop {
        let page = process.request("tools/list", params).await;
        assert!(page.get("error").is_none(), "{page}");
        tools.extend(page["result"]["tools"].as_array().unwrap().iter().cloned());
        match page["result"]["nextCursor"].as_str() {
            Some(cursor) => {
                first_cursor.get_or_insert_with(|| cursor.to_owned());
                params = json!({"cursor": cursor});
            }
            None => break,
        }
    }
    (tools, first_cursor)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_selection_is_per_process_off_by_default_and_never_changes_results() {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let first_token = directory
        .secret_file("principal-one.token", "mcp-principal-one-token")
        .unwrap();
    let second_token = directory
        .secret_file("principal-two.token", "mcp-principal-two-token")
        .unwrap();
    let broker = application
        .config_document(fake_document(&directory, &first_token, &second_token))
        .start()
        .await
        .unwrap();
    let config = directory.join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = \"{}\"\n[identity]\ndisabled = false\ntoken_file = {}\n",
            broker.public_url(),
            toml_string(first_token.display())
        ),
    )
    .unwrap();
    let request_file = directory.join("echo-request.json");
    std::fs::write(
        &request_file,
        json!({"project":"TEST","message":"from a file"}).to_string(),
    )
    .unwrap();
    for view in [None, Some("fake")] {
        let echo = if view.is_some() { "echo" } else { "fake_echo" };
        // Three simultaneous connections, one per selection.
        let mut processes = Vec::new();
        for selection in SELECTIONS {
            let mut process = McpProcess::start_selecting(&config, view, selection);
            process.initialize().await;
            processes.push(process);
        }
        let mut listings = Vec::new();
        for process in &mut processes {
            listings.push(list_all(process).await.0);
        }
        let [with, without, default] = &listings[..] else {
            unreachable!()
        };
        assert_eq!(with.len(), 6);
        assert!(with.iter().all(|tool| tool.get("outputSchema").is_some()));
        assert!(
            without
                .iter()
                .all(|tool| tool.get("outputSchema").is_none())
        );
        assert_eq!(without, default);
        assert_eq!(
            &with.iter().map(without_output_schema).collect::<Vec<_>>(),
            without
        );

        let calls = [
            ("services_list", json!({})),
            ("actions_list", json!({"service":"fake","resource":"TEST"})),
            ("resource_access_describe", json!({"service":"fake"})),
            ("services_describe", json!({"service":"fake"})),
            ("actions_list", json!({"service":"fake","unexpected":true})),
            (
                echo,
                json!({"inputs":{"project":"TEST","message":"parity"}}),
            ),
            (
                echo,
                json!({"inputs":{"project":"OTHER","message":"denied"}}),
            ),
            (echo, json!({"inputs":{"project":"TEST"}})),
            (echo, json!({"requestFile":request_file})),
            (
                echo,
                json!({"inputs":{"project":"TEST","message":"x"},"requestFile":request_file}),
            ),
        ];
        for (name, arguments) in calls {
            let mut results = Vec::new();
            for process in &mut processes {
                let response = process
                    .request(
                        "tools/call",
                        json!({"name":name,"arguments":arguments.clone()}),
                    )
                    .await;
                assert!(response.get("error").is_none(), "{response}");
                results.push(comparable(&response));
            }
            assert_eq!(results[0], results[1], "{view:?} {name} {arguments}");
            assert_eq!(results[1], results[2], "{view:?} {name} {arguments}");
        }
        // Local file receipts and the saved responses are identical too.
        let mut saved = Vec::new();
        let mut receipts = Vec::new();
        for (index, process) in processes.iter_mut().enumerate() {
            let output = directory.join(format!("receipt-{}-{index}.json", view.unwrap_or("all")));
            let response = process
                .request(
                    "tools/call",
                    json!({"name":echo,"arguments":{"inputs":{"project":"TEST","message":"saved"},"outputPath":output}}),
                )
                .await;
            assert_eq!(
                response["result"]["structuredContent"]["operationStatus"], "succeeded",
                "{response}"
            );
            receipts.push(comparable(&response));
            let mut file: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
            for key in ["agentRequestId", "brokerRequestId"] {
                file.as_object_mut().unwrap().remove(key);
            }
            saved.push(file);
        }
        assert_eq!(receipts[0], receipts[1]);
        assert_eq!(receipts[1], receipts[2]);
        assert_eq!(saved[0], saved[1]);
        assert_eq!(saved[1], saved[2]);

        // Action details follow each process's selection.
        let mut details = Vec::new();
        for process in &mut processes {
            let response = process
                .request(
                    "tools/call",
                    json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
                )
                .await;
            details.push(response["result"]["structuredContent"].clone());
        }
        let listed_echo = with.iter().find(|tool| tool["name"] == echo).unwrap();
        assert_eq!(
            details[0]["mcpTool"]["outputSchema"],
            listed_echo["outputSchema"]
        );
        assert!(details[0].get("resultSchemas").is_none());
        for detail in &details[1..] {
            assert!(detail["mcpTool"].get("outputSchema").is_none(), "{detail}");
            assert!(detail.get("resultSchemas").is_none(), "{detail}");
            assert_eq!(detail["mcpTool"]["name"], echo);
        }
        let mut stripped = details[0].clone();
        stripped["mcpTool"]
            .as_object_mut()
            .unwrap()
            .remove("outputSchema");
        assert_eq!(stripped, details[1]);
        assert_eq!(details[1], details[2]);
        for process in processes {
            process.finish().await;
        }
    }
    // Non-MCP CLI action details keep the schema-bearing projection.
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    let output = command
        .arg("--config")
        .arg(&config)
        .args(["actions", "describe", "--service", "fake", "echo"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let detail: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(detail["mcpTool"]["outputSchema"].is_object(), "{detail}");
    assert!(detail.get("resultSchemas").is_none());
    stop(broker).await;
}

fn typed_action(name: &str) -> Value {
    json!({
        "action":name,"scopedMcpName":name,"description":"Synthetic paged action","readOnly":true,
        "requiredScopeTypes":[],"credentialModes":[],"lookupRequired":false,
        "inputSchema":{"type":"object","additionalProperties":false},
        "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision",
        "resultSchemas":{"success":{"type":"object","properties":{"item":{"type":"string"}}}}
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_pagination_completes_per_selection_and_cursors_never_cross_modes() {
    let server = MockServer::start().await;
    let mut catalog = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
    catalog["services"] = json!([{
        "service":"paged","displayName":"Paged fixture","surface":"invoke","credentialVerificationSupported":true,
        "scopedMcpReady":true,"availability":{"state":"available","requirements":[],"message":"Locally available"},
        "scopeTypes":[],
        "actions":(0..150).map(|index| typed_action(&format!("item{index:03}.read"))).collect::<Vec<_>>()
    }]);
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = {:?}\n[identity]\ndisabled = true\n",
            server.uri()
        ),
    )
    .unwrap();
    for view in [None, Some("paged")] {
        let mut processes = Vec::new();
        let mut listings = Vec::new();
        let mut cursors = Vec::new();
        for selection in SELECTIONS {
            let mut process = McpProcess::start_selecting(&config, view, selection);
            process.initialize().await;
            let (tools, cursor) = list_all(&mut process).await;
            assert_eq!(tools.len(), 155);
            listings.push(tools);
            cursors.push(cursor.expect("paginated listing"));
            processes.push(process);
        }
        assert!(
            listings[0]
                .iter()
                .all(|tool| tool.get("outputSchema").is_some())
        );
        assert_eq!(
            listings[0]
                .iter()
                .map(without_output_schema)
                .collect::<Vec<_>>(),
            listings[1]
        );
        assert_eq!(listings[1], listings[2]);
        let invalid = "Invalid or stale catalog cursor; restart tools/list without a cursor";
        for (issued, used) in [(0, 1), (0, 2), (1, 0), (2, 0)] {
            let rejected = processes[used]
                .request("tools/list", json!({"cursor": cursors[issued]}))
                .await;
            assert_eq!(rejected["error"]["code"], -32602, "{rejected}");
            assert_eq!(rejected["error"]["message"], invalid);
        }
        // Omitted and explicit off are one projection, so their cursors agree.
        for (issued, used) in [(1, 2), (2, 1)] {
            let accepted = processes[used]
                .request("tools/list", json!({"cursor": cursors[issued]}))
                .await;
            assert_eq!(accepted["result"]["tools"].as_array().unwrap().len(), 55);
        }
        for process in processes {
            process.finish().await;
        }
    }
}
