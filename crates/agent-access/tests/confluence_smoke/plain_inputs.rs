//! The real CLI and stdio adapter retain provider validation after schema relaxation.
use super::*;
use serde_json::{Value, json};

#[path = "../common/list_mcp.rs"]
mod list_mcp;

const PAGE_URL: &str = "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook";

fn cli(base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.args(["--url", base, "--token-value", "plain-input-token"]);
    command
}

async fn start() -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value = toml::from_str(&confluence_document(
        application.directory(),
        &["page.view", "page.create", "page.move", "attachment.add"],
    ))
    .unwrap();
    document["identity"] = toml::from_str(&format!(
        r#"
mode = "required"
authority = "toml"
[[sources]]
name = "local"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"
[[sources.principals]]
principal = "plain-input-user"
token_refs = [{}]
"#,
        secret_ref(
            application.directory(),
            "agent-token.txt",
            "plain-input-token"
        )
    ))
    .unwrap();
    document["policy"]["grants"][0]["subjects"] =
        toml::Value::try_from(vec!["user:plain-input-user"]).unwrap();
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".into(),
            title: "Runbook".into(),
            space: "ENG".into(),
            web_url: None,
            space_web_url: None,
            space_alias: None,
            status: Some("current".into()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".into(), "<p>Runbook</p>".into())]),
        },
        search_page: Mutex::new(None),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture("confluence", confluence_fixture(backend))
        .start()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_plain_inputs_preserve_stdio_and_send_validation() {
    let broker = start().await;
    let base = broker.public_url();
    let mut mcp = list_mcp::StdioMcp::start(cli(&base));
    mcp.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "confluence-input-smoke", "version": "1"}
        }),
    )
    .await;
    mcp.notify("notifications/initialized", json!({}));
    let listing = mcp.request("tools/list", json!({})).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "page.view")
        .unwrap();
    let name = tool["name"].as_str().unwrap();
    let schema = &tool["inputSchema"]["properties"]["inputs"];
    for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
        assert!(schema.get(keyword).is_none());
    }
    for field in ["pageId", "url"] {
        assert_eq!(schema["properties"][field]["type"], "string");
        assert!(
            schema["properties"][field]["description"]
                .as_str()
                .unwrap()
                .contains("Give exactly one of pageId or url.")
        );
    }
    let upload = tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "attachment.add")
        .unwrap();
    assert_eq!(
        upload["inputSchema"]["properties"]["inputs"]["properties"]["pageId"]["type"],
        "string"
    );
    assert_eq!(upload["inputSchema"]["properties"]["files"]["minItems"], 1);
    assert!(
        upload["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("files"))
    );
    let described = mcp.request("tools/call", json!({
        "name": "actions_describe", "arguments": {"service": "confluence", "action": "page.view"}
    })).await;
    assert_eq!(
        described["result"]["structuredContent"]["mcpTool"]["inputSchema"],
        tool["inputSchema"]
    );

    let missing = mcp
        .request("tools/call", json!({"name": name, "arguments": {}}))
        .await;
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(
        missing["result"]["content"][0]["text"],
        "provide exactly one of inputs or requestFile"
    );
    for (inputs, reason) in [
        (json!({}), "confluence.page.view requires pageId or url"),
        (
            json!({"pageId": "123456", "url": PAGE_URL}),
            "confluence.page.view accepts pageId or url, not both",
        ),
        (
            json!({"pageId": 7}),
            "confluence.page.view inputs are invalid: inputs.pageId must be a string",
        ),
    ] {
        let response = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"inputs": inputs}}),
            )
            .await;
        assert_eq!(response["result"]["isError"], true, "{response}");
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(envelope["decision"], "deny");
        assert_eq!(envelope["reasonCode"], "input_invalid");
        assert_eq!(envelope["reason"], reason);
        assert!(envelope.get("result").is_none());
    }

    for inputs in [
        json!({"pageId": "123456"}),
        json!({"url": PAGE_URL}),
        json!({"pageId": "123456", "url": null}),
    ] {
        let response = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"inputs": inputs}}),
            )
            .await;
        assert_eq!(response["result"]["isError"], false, "{response}");
        assert_eq!(
            response["result"]["structuredContent"]["result"]["id"],
            "123456"
        );
    }
    let request_file = broker.directory().join("page-inputs.json");
    std::fs::write(&request_file, json!({"url": PAGE_URL}).to_string()).unwrap();
    let from_file = mcp
        .request(
            "tools/call",
            json!({"name": name, "arguments": {"requestFile": request_file}}),
        )
        .await;
    assert_eq!(from_file["result"]["isError"], false, "{from_file}");
    assert_eq!(
        from_file["result"]["structuredContent"]["result"]["id"],
        "123456"
    );
    let both = mcp
        .request(
            "tools/call",
            json!({"name": name, "arguments": {"inputs": {}, "requestFile": request_file}}),
        )
        .await;
    assert_eq!(both["result"]["isError"], true);
    assert_eq!(
        both["result"]["content"][0]["text"],
        "provide exactly one of inputs or requestFile"
    );
    mcp.finish().await;

    // Generic invocation and JSON send keep their own omitted-input default;
    // the relaxed published schema lets the provider explain the missing locator.
    for inputs in [None, Some("{}")] {
        let mut command = cli(&base);
        command.args(["invoke", "confluence.page.view"]);
        if let Some(inputs) = inputs {
            command.args(["--input-json", inputs]);
        }
        let invoked = command.output().unwrap();
        assert!(!invoked.status.success());
        let invoked: Value = serde_json::from_slice(&invoked.stdout).unwrap();
        assert_eq!(invoked["decision"], "deny");
        assert_eq!(invoked["reasonCode"], "input_invalid");
        assert_eq!(
            invoked["reason"],
            "confluence.page.view requires pageId or url"
        );
    }
    for inputs in [None, Some(json!({})), Some(json!({"url": PAGE_URL}))] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "confluence", "action": "page.view"});
        if let Some(inputs) = inputs {
            request["inputs"] = inputs;
        }
        let success = request["inputs"].get("url").is_some();
        let output = cli(&base)
            .args(["send", "--request-json", &request.to_string()])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        if success {
            assert_eq!(envelope["result"]["id"], "123456");
        } else {
            assert_eq!(envelope["decision"], "deny");
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(
                envelope["reason"],
                "confluence.page.view requires pageId or url"
            );
        }
    }
    assert!(
        broker
            .audit()
            .unwrap()
            .require_action("confluence", "page.view")
            .iter()
            .any(|record| record["reasonCode"] == "input_invalid")
    );
    broker.shutdown();
    broker.join().await.unwrap();
}
