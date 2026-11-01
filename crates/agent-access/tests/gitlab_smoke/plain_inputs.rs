//! Exercise relaxed discovery and unchanged provider validation through real
//! CLI invocation, JSON send and the stdio MCP subprocess.
use super::*;
use serde_json::{Value, json};

const PROJECT_URL: &str = "https://gitlab.example.com/sip/service";
const SECRET: &str = "private-gitlab-plain-input-content";

fn cli(base: &str) -> Command {
    let mut command = gitlab_cli(base);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command
}

fn document() -> GitlabDocument {
    // Runtime catalog reads require an authenticated caller. Keep execution on
    // the service credential so these tests isolate argument handling.
    let mut document = gitlab_per_user_document();
    for grant in &mut document.grants {
        grant.credential_mode = "service".into();
    }
    document
}

async fn mcp(base: &str) -> list_mcp::StdioMcp {
    let mut mcp = list_mcp::StdioMcp::start(cli(base));
    mcp.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "gitlab-input-smoke", "version": "1"}
        }),
    )
    .await;
    mcp.notify("notifications/initialized", json!({}));
    mcp
}

async fn tools(mcp: &mut list_mcp::StdioMcp) -> Vec<Value> {
    let mut tools = Vec::new();
    let mut params = json!({});
    for page in 0..20 {
        let listing = mcp.request("tools/list", params).await;
        tools.extend(
            listing["result"]["tools"]
                .as_array()
                .unwrap_or_else(|| panic!("stdio MCP listing failed: {listing}"))
                .iter()
                .cloned(),
        );
        let Some(cursor) = listing["result"].get("nextCursor") else {
            return tools;
        };
        params = json!({"cursor": cursor});
        assert!(page < 19, "stdio MCP catalog did not finish");
    }
    unreachable!()
}

fn tool<'a>(tools: &'a [Value], action: &str) -> &'a Value {
    tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == action)
        .unwrap()
}

fn assert_denial(envelope: &Value, reason: &str) {
    assert_eq!(envelope["decision"], "deny", "{envelope}");
    assert_eq!(envelope["reasonCode"], "input_invalid", "{envelope}");
    assert_eq!(envelope["reason"], reason);
    assert!(envelope.get("result").is_none(), "{envelope}");
    assert!(!envelope.to_string().contains(SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_plain_inputs_preserve_stdio_invoke_and_send_contracts() {
    let backend = stub_backend();
    let broker = start_broker(
        &document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base = broker.public_url();
    let mut mcp = mcp(&base).await;
    let tools = tools(&mut mcp).await;
    let view = tool(&tools, "project.view");
    let name = view["name"].as_str().unwrap();
    let schema = &view["inputSchema"]["properties"]["inputs"];
    for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
        assert!(schema.get(keyword).is_none());
    }
    for field in ["project", "url"] {
        assert!(
            schema["properties"][field]["description"]
                .as_str()
                .unwrap()
                .contains("Give exactly one of project or url.")
        );
    }
    let upload = tool(&tools, "project.upload");
    let upload_schema = &upload["inputSchema"];
    for field in ["project", "url"] {
        assert!(
            upload_schema["properties"]["inputs"]["properties"]
                .get(field)
                .is_some()
        );
    }
    assert!(
        upload_schema["properties"]["inputs"]["properties"]
            .get("attachments")
            .is_none()
    );
    assert_eq!(upload_schema["properties"]["files"]["minItems"], 1);
    assert_eq!(upload_schema["properties"]["files"]["maxItems"], 1);
    assert!(
        upload_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("files"))
    );
    let described = mcp.request("tools/call", json!({
        "name": "actions_describe", "arguments": {"service": "gitlab", "action": "project.view"}
    })).await;
    assert_eq!(
        described["result"]["structuredContent"]["mcpTool"]["inputSchema"],
        view["inputSchema"]
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
        (json!({}), "gitlab project.view requires project or url"),
        (
            json!({"project": "sip/service", "url": PROJECT_URL}),
            "gitlab project.view accepts project or url, not both",
        ),
        (
            json!({"url": 7}),
            "gitlab.project.view inputs are invalid: inputs.url must be a string",
        ),
        (
            json!({"project": "sip/service", "url": null}),
            "gitlab.project.view inputs are invalid: inputs.url must be a string",
        ),
    ] {
        let called = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"inputs": inputs}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        assert_denial(&called["result"]["structuredContent"], reason);
    }
    for inputs in [
        json!({"project": "sip/service"}),
        json!({"url": PROJECT_URL}),
    ] {
        let called = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"inputs": inputs}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["result"]["project"]["id"],
            42
        );
    }
    let request_file = broker.directory().join("project-inputs.json");
    std::fs::write(&request_file, json!({"url": PROJECT_URL}).to_string()).unwrap();
    let from_file = mcp
        .request(
            "tools/call",
            json!({"name": name, "arguments": {"requestFile": request_file}}),
        )
        .await;
    assert_eq!(from_file["result"]["isError"], false, "{from_file}");
    assert_eq!(
        from_file["result"]["structuredContent"]["result"]["project"]["id"],
        42
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

    // The stdio upload adapter generates metadata while leaving both root
    // locators visible. A missing locator reaches the action-specific parser.
    let attachment = broker.directory().join("attachment.txt");
    std::fs::write(&attachment, b"bounded attachment").unwrap();
    for inputs in [json!({}), json!({"url": PROJECT_URL})] {
        let success = inputs.get("url").is_some();
        let called = mcp.request("tools/call", json!({
            "name": upload["name"], "arguments": {"inputs": inputs,
                "files": [{"role": "attachment", "path": attachment, "contentType": "text/plain"}]}
        })).await;
        assert_eq!(called["result"]["isError"], !success, "{called}");
        if success {
            assert_eq!(
                called["result"]["structuredContent"]["result"]["upload"]["id"],
                101
            );
        } else {
            assert_denial(
                &called["result"]["structuredContent"],
                "gitlab project.upload requires project or url",
            );
        }
    }
    assert_eq!(backend.uploaded_projects.lock().unwrap().len(), 1);
    mcp.finish().await;

    for inputs in [None, Some("{}")] {
        let mut command = cli(&base);
        command.args(["invoke", "gitlab.project.view"]);
        if let Some(inputs) = inputs {
            command.args(["--input-json", inputs]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert_denial(
            &serde_json::from_slice(&output.stdout).unwrap(),
            "gitlab project.view requires project or url",
        );
    }
    for inputs in [None, Some(json!({})), Some(json!({"url": PROJECT_URL}))] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "gitlab", "action": "project.view"});
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
            assert_eq!(envelope["result"]["project"]["id"], 42);
        } else {
            assert_denial(&envelope, "gitlab project.view requires project or url");
        }
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_plain_relationships_preserve_provider_denials_and_audit_after_policy() {
    let backend = stub_backend();
    let broker = start_broker(
        &document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base = broker.public_url();
    let mut mcp = mcp(&base).await;
    let tools = tools(&mut mcp).await;
    let cases = [
        (
            "issue.update",
            json!({"project": "sip/service", "iid": 7, "content": SECRET}),
            "gitlab issue.update requires content and contentFormat together",
        ),
        (
            "merge_request.update",
            json!({"project": "sip/service", "iid": 5, "contentFormat": "markdown"}),
            "gitlab merge_request.update requires content and contentFormat together",
        ),
        (
            "merge_request.draft_note.add",
            json!({"project": "sip/service", "iid": 5, "content": SECRET, "contentFormat": "markdown", "expectedHeadSha": TEST_SHA}),
            "gitlab merge_request.draft_note.add requires position and expectedHeadSha together",
        ),
        (
            "merge_request.draft_note.add",
            json!({"project": "sip/service", "iid": 5, "content": SECRET, "contentFormat": "markdown", "resolveDiscussion": false}),
            "gitlab merge_request.draft_note.add resolveDiscussion requires inReplyToDiscussionId",
        ),
        (
            "merge_request.draft_note.update",
            json!({"project": "sip/service", "iid": 5, "draftNoteId": 20}),
            "gitlab merge_request.draft_note.update requires content with contentFormat or position with expectedHeadSha",
        ),
        (
            "merge_request.draft_note.publish_all",
            json!({"project": "sip/service", "iid": 5, "internal": false}),
            "gitlab merge_request.draft_note.publish_all internal requires content and contentFormat",
        ),
        (
            "merge_request.review.submit",
            json!({"project": "sip/service", "iid": 5, "internal": false, "reviewerState": "reviewed"}),
            "gitlab merge_request.review.submit internal requires content and contentFormat",
        ),
        (
            "webhook.update",
            json!({"project": "sip/service", "webhookId": 42, "token": SECRET, "clearToken": true}),
            "gitlab webhook.update token and clearToken: true cannot be combined",
        ),
        (
            "webhook.update",
            json!({"project": "sip/service", "webhookId": 42, "confirmDestinationReset": true}),
            "gitlab webhook.update requires at least one of url, events, name, description, enableSslVerification, branchFilterStrategy, pushEventsBranchFilter, customWebhookTemplate, token, signingToken or clearToken: true; confirmDestinationReset does not count",
        ),
    ];
    for (action, inputs, expected) in cases {
        let action_tool = tool(&tools, action);
        let sensitive = action == "webhook.update" && inputs.get("token").is_some();
        let arguments = if sensitive {
            // Sensitive inline fields are rejected by the local adapter before
            // dispatch. A private input file lets this case reach the provider.
            let path = broker
                .directory()
                .secret_file(
                    "webhook-conflict-inputs.json",
                    serde_json::to_vec(&inputs).unwrap(),
                )
                .unwrap();
            json!({"requestFile": path})
        } else {
            json!({"inputs": inputs})
        };
        let called = mcp
            .request(
                "tools/call",
                json!({"name": action_tool["name"], "arguments": arguments}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true, "{called}");
        let envelope = &called["result"]["structuredContent"];
        assert_denial(envelope, expected);
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "gitlab", "action": action, "inputs": inputs});
        let mut command = cli(&base);
        if sensitive {
            let path = broker
                .directory()
                .secret_file(
                    "webhook-conflict-send.json",
                    serde_json::to_vec(&request).unwrap(),
                )
                .unwrap();
            command.args(["send", "--request-file"]).arg(path);
        } else {
            command.args(["send", "--request-json", &request.to_string()]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
        let sent: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_denial(&sent, expected);
        for response in [envelope, &sent] {
            let audit = broker.audit().unwrap();
            let records = audit.require_action("gitlab", action);
            let record = records
                .iter()
                .find(|record| record["agentRequestId"] == response["agentRequestId"])
                .unwrap();
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["reasonCode"], "input_invalid");
            assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
            assert!(record.get("upstreamStatus").is_none());
            assert!(record.get("objectIds").is_none());
        }
    }
    assert!(
        take_backend_operations(&backend)
            .iter()
            .all(|operation| operation == "project")
    );
    assert!(!broker.audit().unwrap().text().contains(SECRET));
    mcp.finish().await;
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_plain_webhook_schema_keeps_local_secret_injection_and_false_clear_token() {
    let backend = stub_backend();
    let broker = start_broker(
        &document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base = broker.public_url();
    let token_path = broker.directory().join("webhook-token.txt");
    std::fs::write(&token_path, SECRET).unwrap();
    let inputs = json!({"project": "sip/service", "webhookId": 42, "clearToken": false});
    let sources =
        json!([{"pointer": "/inputs/token", "source": {"type": "file", "path": token_path}}]);
    let mut mcp = mcp(&base).await;
    let tools = tools(&mut mcp).await;
    let update = tool(&tools, "webhook.update");
    assert!(
        update["inputSchema"]["properties"]
            .get("secretSources")
            .is_some()
    );
    // The retained const:true is a pre-existing schema/parser difference;
    // neither local adapter validates successful provider input against it.
    assert_eq!(
        update["inputSchema"]["properties"]["inputs"]["properties"]["clearToken"]["const"],
        true
    );
    let called = mcp.request("tools/call", json!({"name": update["name"], "arguments": {"inputs": inputs, "secretSources": sources}})).await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    assert_eq!(called["result"]["structuredContent"]["decision"], "allow");
    assert!(!called.to_string().contains(SECRET));
    assert_eq!(
        backend
            .last_webhook_write
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .token
            .as_deref(),
        Some(SECRET)
    );
    let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "gitlab", "action": "webhook.update", "inputs": inputs, "secretSources": sources});
    let output = cli(&base)
        .args(["send", "--request-json", &request.to_string()])
        .output()
        .unwrap();
    assert_success(
        "webhook send with local token and clearToken:false",
        &output,
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["decision"], "allow");
    assert!(!envelope.to_string().contains(SECRET));
    assert!(!broker.audit().unwrap().text().contains(SECRET));
    mcp.finish().await;
    stop(broker).await;
}
