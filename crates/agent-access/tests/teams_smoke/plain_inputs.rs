//! Real transports use the plain schema while the production payload parser
//! enforces format relationships. The fixture transport is entirely offline.
use super::*;

const CONTENT_MARKER: &str = "private-teams-payload-sentinel";

async fn stdio(fixture: &Fixture) -> Mcp {
    let mut mcp = Mcp::start(&fixture.agent_config);
    let initialized = mcp.request("initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "teams-plain", "version": "1"}})).await;
    assert!(initialized.get("error").is_none());
    mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    mcp
}

async fn http_session(fixture: &Fixture) -> String {
    let client = reqwest::Client::new();
    let response = client.post(format!("{}/mcp", fixture.base))
        .bearer_auth(&fixture.agent_token)
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "teams-plain", "version": "1"}}}))
        .send().await.unwrap();
    assert!(response.status().is_success());
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let _ = response.bytes().await.unwrap();
    let initialized = client
        .post(format!("{}/mcp", fixture.base))
        .bearer_auth(&fixture.agent_token)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert!(initialized.status().is_success());
    session
}

async fn rpc(fixture: &Fixture, session: &str, id: u64, method: &str, params: Value) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{}/mcp", fixture.base))
        .bearer_auth(&fixture.agent_token)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    rpc_response(response).await
}

async fn spec(fixture: &Fixture, name: &str) -> Value {
    let response = reqwest::Client::new()
        .get(format!("{}/v1/spec/{name}", fixture.base))
        .header(
            "x-agent-access-request-id",
            format!("teams-plain-spec-{name}"),
        )
        .bearer_auth(&fixture.agent_token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert!(status.is_success(), "spec {name}: {status} {body}");
    body
}

fn action(catalog: &Value) -> &Value {
    catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "teams")
        .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "notification.send")
        .unwrap()
}

fn tool(listing: &Value) -> &Value {
    assert!(listing["result"].get("nextCursor").is_none());
    let name = agent_access_core::mcp::tool_name("teams", "notification.send");
    listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap()
}

fn required(schema: &Value, field: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|fields| fields.contains(&json!(field)))
}

fn assert_denial(envelope: &Value, expected: &str) {
    assert_eq!(envelope["decision"], "deny", "{envelope}");
    assert_eq!(envelope["reasonCode"], "input_invalid");
    assert_eq!(envelope["reason"], expected);
    assert!(envelope.get("result").is_none());
    assert!(!envelope.to_string().contains(CONTENT_MARKER));
    assert!(!envelope.to_string().contains("SYNTHETIC_SIGNED_SECRET"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn teams_plain_inputs_project_and_preserve_relationship_denials_across_transports() {
    let f = fixture().await;
    let mut mcp = stdio(&f).await;
    let session = http_session(&f).await;
    let catalog = spec(&f, "catalog").await;
    let schema = &action(&catalog)["inputSchema"];
    let listing = mcp.request("tools/list", json!({})).await;
    let stdio = &tool(&listing)["inputSchema"];
    let listing = rpc(&f, &session, 2, "tools/list", json!({})).await;
    let http = &tool(&listing)["inputSchema"];
    assert_eq!(&http["properties"]["inputs"], schema);
    for key in ["type", "properties", "required", "additionalProperties"] {
        assert_eq!(
            stdio["properties"]["inputs"].get(key),
            schema.get(key),
            "stdio {key}"
        );
    }
    assert!(!required(stdio, "inputs"));
    assert!(required(http, "inputs"));
    assert_eq!(stdio["properties"]["requestFile"]["type"], "string");
    let send = spec(&f, "send-schema.json").await;
    let variant = send["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"] == "teams"
                && variant["properties"]["action"]["const"] == "notification.send"
        })
        .unwrap();
    assert_eq!(&variant["properties"]["inputs"], schema);
    assert!(required(variant, "inputs"));
    let openapi = spec(&f, "openapi.json").await;
    assert_eq!(
        &openapi["paths"]["/v1/invoke/teams/notification.send"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["inputs"],
        schema
    );
    for object in [schema, &schema["properties"]["content"]] {
        assert_eq!(object["type"], "object");
        for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
            assert!(object.get(keyword).is_none());
        }
    }
    let content = &schema["properties"]["content"];
    assert_ne!(content["additionalProperties"], false);
    assert_eq!(content["properties"].as_object().unwrap().len(), 7);
    for field in ["title", "text", "summary", "attachments", "@context"] {
        let property = content["properties"][field].as_object().unwrap();
        assert_eq!(property.len(), 1);
        assert!(property["description"].is_string());
    }
    let validator = jsonschema::validator_for(schema).unwrap();
    let name = agent_access_core::mcp::tool_name("teams", "notification.send");
    for (index, (format, content, expected, schema_valid)) in [
        ("simple", json!({"text": CONTENT_MARKER, "extra": true}), "teams.notification.send content with contentFormat simple accepts only title and text", true),
        ("simple", json!({"text": " ", "title": CONTENT_MARKER}), "teams.notification.send content.text must be a nonempty string with contentFormat simple", true),
        // Retained discriminator constants explain these rejected simple
        // payloads before the provider's extra-field relationship message.
        ("simple", json!({"text": CONTENT_MARKER, "type": "wrong"}), "teams.notification.send inputs are invalid: inputs.content.type must be message", false),
        ("simple", json!({"text": CONTENT_MARKER, "@type": "wrong"}), "teams.notification.send inputs are invalid: inputs.content.@type must be MessageCard", false),
        ("microsoft", json!({"type": "message", "@type": "MessageCard", "text": CONTENT_MARKER}), "teams.notification.send content accepts type or @type, not both", true),
        ("microsoft", json!({"type": "message", "text": CONTENT_MARKER}), "teams.notification.send content.attachments must be a nonempty array with type message", true),
        ("microsoft", json!({"@type": "MessageCard", "@context": "http://schema.org/extensions", "title": CONTENT_MARKER}), "teams.notification.send MessageCard requires content.summary or content.text", true),
        ("microsoft", json!({"type": null, "@type": "MessageCard", "text": CONTENT_MARKER}), "teams.notification.send inputs are invalid: inputs.content.type must be message", false),
    ].into_iter().enumerate() {
        let inputs = json!({"destination": "release-alerts", "contentFormat": format, "content": content});
        assert_eq!(validator.is_valid(&inputs), schema_valid);
        let called = mcp.request("tools/call", json!({"name": name, "arguments": {"inputs": inputs}})).await;
        assert_eq!(called["result"]["isError"], true);
        let http_called = rpc(&f, &session, 10 + index as u64, "tools/call", json!({"name": name, "arguments": {"inputs": inputs}})).await;
        assert_eq!(http_called["result"]["isError"], true);
        let response = reqwest::Client::new().post(format!("{}/v1/invoke/teams/notification.send", f.base))
            .header("x-agent-access-request-id", format!("teams-plain-denial-{index}"))
            .bearer_auth(&f.agent_token).json(&json!({"inputs": inputs})).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let http_envelope: Value = response.json().await.unwrap();
        let input_file = f.broker.directory().secret_file(format!("invalid-{index}.json"), inputs.to_string()).unwrap();
        let invoked = run(&f.agent_config, &["invoke", "teams.notification.send", "--input-file", input_file.to_str().unwrap()]);
        assert_eq!(invoked.status.code(), Some(3));
        let invoked: Value = serde_json::from_slice(&invoked.stdout).unwrap();
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "teams", "action": "notification.send", "inputs": inputs});
        let request_file = f.broker.directory().secret_file(format!("invalid-send-{index}.json"), request.to_string()).unwrap();
        let sent = run(&f.agent_config, &["send", "--request-file", request_file.to_str().unwrap()]);
        assert_eq!(sent.status.code(), Some(3));
        let sent: Value = serde_json::from_slice(&sent.stdout).unwrap();
        for envelope in [&called["result"]["structuredContent"], &http_called["result"]["structuredContent"], &http_envelope, &invoked, &sent] {
            assert_denial(envelope, expected);
        }
    }
    assert!(f.calls.lock().unwrap().is_empty());
    let missing = mcp
        .request("tools/call", json!({"name": name, "arguments": {}}))
        .await;
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(
        missing["result"]["content"][0]["text"],
        "provide exactly one of inputs or requestFile"
    );
    let missing = rpc(
        &f,
        &session,
        100,
        "tools/call",
        json!({"name": name, "arguments": {}}),
    )
    .await;
    assert_eq!(
        missing["result"]["structuredContent"],
        json!({"error": {"code": "mcp_tool_error", "message": "inputs is required and must be a JSON object"}})
    );
    let send_validator = jsonschema::validator_for(&send).unwrap();
    for inputs in [None, Some(json!({}))] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "teams", "action": "notification.send"});
        let mut command = command(&f.agent_config);
        command.args(["invoke", "teams.notification.send"]);
        if let Some(inputs) = inputs {
            request["inputs"] = inputs;
            command.args(["--input-json", "{}"]);
        }
        assert!(!send_validator.is_valid(&request));
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["decision"], "deny");
        assert_eq!(envelope["reasonCode"], "input_invalid");
        assert!(envelope["reason"].as_str().unwrap().contains("is required"));
        let sent = run(
            &f.agent_config,
            &["send", "--request-json", &request.to_string()],
        );
        assert!(!sent.status.success());
    }
    let audit = f.broker.audit().unwrap();
    let records = audit.require_action("teams", "notification.send");
    for record in records {
        assert_eq!(record["decision"], "deny");
        assert_eq!(record["reasonCode"], "input_invalid");
        assert!(record.get("upstreamStatus").is_none());
        assert!(record.get("objectIds").is_none());
        if record.get("auditInputs").is_some() {
            assert_eq!(
                record["auditInputs"],
                json!([{"input": "destination", "label": "Destination", "value": "release-alerts"}])
            );
        }
    }
    for marker in [CONTENT_MARKER, "SYNTHETIC_SIGNED_SECRET"] {
        assert!(!audit.text().contains(marker));
    }
    drop(mcp);
    f.broker.shutdown();
    f.broker.join().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn teams_plain_content_extensions_execute_and_are_forwarded_unchanged() {
    let f = fixture().await;
    let mut mcp = stdio(&f).await;
    let session = http_session(&f).await;
    let catalog = spec(&f, "catalog").await;
    let validator = jsonschema::validator_for(&action(&catalog)["inputSchema"]).unwrap();
    let name = agent_access_core::mcp::tool_name("teams", "notification.send");
    let contents = [
        json!({"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": CONTENT_MARKER, "title": 7, "attachments": "extension", "extra": {"kept": true}}),
        json!({"type": "message", "text": 7, "title": null, "summary": [CONTENT_MARKER], "@context": {"kept": true}, "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {"type": "AdaptiveCard", "version": "00.02", "body": [{}], "extra": true}}]}),
    ];
    for (index, content) in contents.into_iter().enumerate() {
        let inputs = json!({"destination": "release-alerts", "contentFormat": "microsoft", "content": content});
        assert!(validator.is_valid(&inputs));
        let content_file = f
            .broker
            .directory()
            .secret_file(format!("extensions-card-{index}.json"), content.to_string())
            .unwrap();
        success(run(
            &f.agent_config,
            &[
                "teams",
                "notification",
                "send",
                "release-alerts",
                "--content-file",
                content_file.to_str().unwrap(),
            ],
        ));
        let input_file = f
            .broker
            .directory()
            .secret_file(format!("extensions-input-{index}.json"), inputs.to_string())
            .unwrap();
        success(run(
            &f.agent_config,
            &[
                "invoke",
                "teams.notification.send",
                "--input-file",
                input_file.to_str().unwrap(),
            ],
        ));
        let called = mcp
            .request(
                "tools/call",
                json!({"name": name, "arguments": {"requestFile": input_file}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        let called = rpc(
            &f,
            &session,
            10 + index as u64,
            "tools/call",
            json!({"name": name, "arguments": {"inputs": inputs}}),
        )
        .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "teams", "action": "notification.send", "inputs": inputs});
        let request_file = f
            .broker
            .directory()
            .secret_file(format!("extensions-send-{index}.json"), request.to_string())
            .unwrap();
        success(run(
            &f.agent_config,
            &["send", "--request-file", request_file.to_str().unwrap()],
        ));
        let response = reqwest::Client::new()
            .post(format!("{}/v1/invoke/teams/notification.send", f.base))
            .header(
                "x-agent-access-request-id",
                format!("teams-plain-extension-{index}"),
            )
            .bearer_auth(&f.agent_token)
            .json(&json!({"inputs": inputs}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let envelope: Value = response.json().await.unwrap();
        assert_eq!(envelope["decision"], "allow");
        assert_eq!(envelope["result"]["accepted"], true);
        assert!(!envelope.to_string().contains(CONTENT_MARKER));
        assert!(!envelope.to_string().contains("SYNTHETIC_SIGNED_SECRET"));
        let calls = f.calls.lock().unwrap();
        assert_eq!(calls.len(), (index + 1) * 6);
        for sent in &calls[index * 6..] {
            assert_eq!(sent, &content);
        }
    }
    let audit = f.broker.audit().unwrap();
    let records = audit.require_action("teams", "notification.send");
    assert_eq!(records.len(), 12);
    for record in records {
        assert_eq!(record["decision"], "allow");
        assert_eq!(
            record["auditInputs"],
            json!([{"input": "destination", "label": "Destination", "value": "release-alerts"}])
        );
    }
    for marker in [CONTENT_MARKER, "SYNTHETIC_SIGNED_SECRET"] {
        assert!(!audit.text().contains(marker));
    }
    drop(mcp);
    f.broker.shutdown();
    f.broker.join().await.unwrap();
}
