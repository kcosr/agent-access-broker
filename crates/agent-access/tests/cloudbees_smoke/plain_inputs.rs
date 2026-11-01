//! Real CLI and stdio keep provider validation after discovery is flattened.
use super::*;

fn command(config: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.arg("--config").arg(config);
    command
}

fn denial(value: &Value, reason: &str, category: &str, field: &str) {
    assert_eq!(value["decision"], "deny", "{value}");
    assert_eq!(value["reasonCode"], "input_invalid");
    assert_eq!(value["reason"], reason);
    assert_eq!(
        value["result"],
        json!({"inputCategory": category, "field": field})
    );
    assert!(!value.to_string().contains("private-cursor-sentinel"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloudbees_plain_inputs_keep_stdio_invoke_send_and_categorized_denials() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("fixture log\n", "text/plain"))
        .expect(3)
        .mount(&controller)
        .await;
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let token = broker
        .directory()
        .secret_file("plain-principal-token", "ci-principal-token")
        .unwrap();
    let config = broker.directory().secret_file("plain-client.toml", format!(
        "[service]\nurl = {:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n",
        broker.public_url(), token.display().to_string()
    )).unwrap();
    let mut mcp = StdioMcp::start(&config);
    let initialized = mcp.request("initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "plain-inputs", "version": "1"}})).await;
    assert!(initialized.get("error").is_none());
    mcp.notify("notifications/initialized", json!({}));
    let listing = mcp.request("tools/list", json!({})).await;
    assert!(listing["result"].get("nextCursor").is_none());
    let name = agent_access_core::mcp::tool_name("cloudbees_ci", "build.log.read");
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap();
    let schema = &tool["inputSchema"]["properties"]["inputs"];
    assert_log_input_schema(schema);
    for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
        assert!(schema.get(keyword).is_none());
    }
    for field in [
        "controller",
        "job",
        "url",
        "buildNumber",
        "buildSelector",
        "cursor",
        "query",
        "maxMatches",
    ] {
        assert!(
            schema["properties"][field]["description"].is_string(),
            "{field}"
        );
    }
    let missing = mcp
        .request("tools/call", json!({"name": name, "arguments": {}}))
        .await;
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(
        missing["result"]["content"][0]["text"],
        "provide exactly one of inputs or requestFile"
    );
    for (inputs, reason, category, field) in [
        (
            json!({}),
            "pass controller and job, or a job or build url",
            "locator_missing",
            "controller",
        ),
        (
            json!({"controller": "team-ci", "job": JOB}),
            "this action needs a build: pass buildNumber or buildSelector, or a build url",
            "build_missing",
            "buildNumber",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "buildSelector": "lastBuild"}),
            "pass buildNumber or buildSelector, not both",
            "build_conflict",
            "buildSelector",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "mode": "search"}),
            "mode search needs a nonempty literal query of at most 256 UTF-8 bytes",
            "value_invalid",
            "query",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "cursor": "private-cursor-sentinel"}),
            "tail reads have no cursor; continue a head or search read with the same mode",
            "option_conflict",
            "cursor",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 0}),
            "cloudbees_ci.build.log.read inputs are invalid: inputs.buildNumber must be at least 1",
            "value_invalid",
            "buildNumber",
        ),
    ] {
        let called = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"inputs": inputs}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        denial(
            &called["result"]["structuredContent"],
            reason,
            category,
            field,
        );
        let invoke = command(&config)
            .args([
                "invoke",
                "cloudbees_ci.build.log.read",
                "--input-json",
                &inputs.to_string(),
            ])
            .output()
            .unwrap();
        assert_eq!(invoke.status.code(), Some(3));
        denial(
            &serde_json::from_slice::<Value>(&invoke.stdout).unwrap(),
            reason,
            category,
            field,
        );
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "cloudbees_ci", "action": "build.log.read", "inputs": inputs});
        let sent = command(&config)
            .args(["send", "--request-json", &request.to_string()])
            .output()
            .unwrap();
        assert_eq!(sent.status.code(), Some(3));
        denial(
            &serde_json::from_slice::<Value>(&sent.stdout).unwrap(),
            reason,
            category,
            field,
        );
    }
    assert!(
        controller.received_requests().await.unwrap().is_empty(),
        "invalid relationships must not reach the controller"
    );
    for args in [
        vec!["invoke", "cloudbees_ci.build.log.read"],
        vec![
            "send",
            "--request-json",
            r#"{"version":"agent-access.send.v1","kind":"invoke","service":"cloudbees_ci","action":"build.log.read"}"#,
        ],
    ] {
        let output = command(&config).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        denial(
            &serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            "pass controller and job, or a job or build url",
            "locator_missing",
            "controller",
        );
    }
    let inputs = json!({"url": format!("{}/team-ci/job/payments/job/build-api/42/", controller.uri()), "mode": "head"});
    let input_file = broker
        .directory()
        .secret_file("plain-log-input.json", inputs.to_string())
        .unwrap();
    let called = mcp
        .request(
            "tools/call",
            json!({"name": name, "arguments": {"requestFile": input_file}}),
        )
        .await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    assert_eq!(
        called["result"]["structuredContent"]["result"]["text"],
        "fixture log\n"
    );
    let invoked = command(&config)
        .args(["invoke", "cloudbees_ci.build.log.read", "--input-file"])
        .arg(&input_file)
        .output()
        .unwrap();
    assert_success("plain input URL invoke", &invoked);
    let sent = command(&config).args(["send", "--request-json", &json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "cloudbees_ci", "action": "build.log.read", "inputs": inputs}).to_string()]).output().unwrap();
    assert_success("plain input URL send", &sent);
    let audit = broker.audit().unwrap();
    let records = audit.require_action("cloudbees_ci", "build.log.read");
    assert_eq!(
        records
            .iter()
            .filter(|record| record["reasonCode"] == "input_invalid")
            .count(),
        20
    );
    for record in records
        .iter()
        .filter(|record| record["reasonCode"] == "input_invalid")
    {
        assert_eq!(record["decision"], "deny");
        assert!(record.get("upstreamStatus").is_none());
        assert!(record.get("objectIds").is_none());
    }
    for marker in ["private-cursor-sentinel", "fixture log", "basic-secret"] {
        assert!(!audit.text().contains(marker));
    }
    mcp.finish().await;
    stop(broker).await;
}
