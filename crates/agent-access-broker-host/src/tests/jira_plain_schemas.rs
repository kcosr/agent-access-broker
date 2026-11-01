//! Jira's published inputs stay visible across transports while the real
//! provider enforces relationships that are documented in field descriptions.
use super::input_explanations::invoke;
use super::mcp::{Fixture, TOKEN_A, structured};
use super::*;
use agent_access_core::ApiCatalog;
use agent_access_core::mcp::{ProjectionMode, project_catalog, tool_name};
use agent_access_provider::ActionIo;

async fn fixture() -> Fixture {
    Fixture::new(|config| {
        let mut credential = config.credentials.service["fake"].clone();
        credential.kind = "basic_api_token".into();
        credential.username_ref = credential.token_ref.clone();
        let mut lookup = credential.clone();
        lookup.read_only = Some(true);
        config.credentials.service.insert("jira".into(), credential);
        config.credentials.lookup.insert("jira".into(), lookup);
        let jira_config = serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
            "tenant_host": "example.atlassian.net",
            "allowed_upstream_hosts": ["https://example.atlassian.net/rest/api/3/**"],
            "content": {"comment_formats": ["adf"]}
        }))
        .unwrap();
        let actions = agent_access_jira::jira_descriptor(&jira_config)
            .actions
            .into_iter()
            .map(|action| action.action)
            .collect();
        config.providers.insert(jira_config);
        config.policy.grants = vec![PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            execution_contexts: None,
            service: "jira".into(),
            actions,
            resources: selected_resources(&[("jira-project", &["PROJ"])]),
            credential_mode: "service".into(),
            priority: None,
        }];
    })
    .await
}

async fn spec(fixture: &Fixture, name: &str) -> Value {
    let response = spec_get(
        fixture.app.clone(),
        &format!("/v1/spec/{name}"),
        &format!("jira-plain-{name}"),
        Some(TOKEN_A),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

fn requires(schema: &Value, field: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|value| value == field))
}

fn tool<'a>(tools: &'a [Value], action: &str) -> &'a Value {
    let name = tool_name("jira", action);
    tools.iter().find(|tool| tool["name"] == name).unwrap()
}

#[tokio::test]
async fn jira_plain_inputs_project_through_stdio_http_send_and_openapi() {
    let fixture = fixture().await;
    let catalog_value = spec(&fixture, "catalog").await;
    let catalog: ApiCatalog = serde_json::from_value(catalog_value.clone()).unwrap();
    let openapi = spec(&fixture, "openapi.json").await;
    let send = spec(&fixture, "send-schema.json").await;
    let stdio = project_catalog(&catalog, ProjectionMode::Stdio).unwrap();
    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    assert!(listing["result"].get("nextCursor").is_none());
    let http = listing["result"]["tools"].as_array().unwrap();
    let jira = catalog
        .services
        .iter()
        .find(|service| service.service == "jira")
        .unwrap();
    assert_eq!(jira.actions.len(), 24);
    for action in &jira.actions {
        let schema = &action.input_schema;
        assert_eq!(schema["type"], "object", "{}", action.action);
        assert_eq!(schema["additionalProperties"], false, "{}", action.action);
        for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
            assert!(
                schema.get(keyword).is_none(),
                "{}: {keyword}",
                action.action
            );
        }
        let stdio_arguments = &tool(&stdio, &action.action)["inputSchema"];
        let stdio_inputs = &stdio_arguments["properties"]["inputs"];
        let send_variant = send_action_variant(&send, "jira", &action.action);
        let send_inputs = &send_variant["properties"]["inputs"];
        let operation = &openapi["paths"][format!("/v1/invoke/jira/{}", action.action)]["post"];
        let content = &operation["requestBody"]["content"];
        let mut local_schema = schema.clone();
        let openapi_inputs = if let ActionIo::MultipartUpload { plan } = &action.io {
            assert_eq!(*plan, attachment_upload_plan(&["issue"], None));
            assert_eq!(plan.metadata_pointer, "/attachments");
            assert_eq!(plan.locator_inputs, ["issue"]);
            assert_eq!(schema["properties"]["issue"]["type"], "string");
            assert!(requires(schema, "issue"));
            assert!(requires(schema, "attachments"));
            local_schema["properties"]
                .as_object_mut()
                .unwrap()
                .remove("attachments");
            local_schema["required"]
                .as_array_mut()
                .unwrap()
                .retain(|field| field != "attachments");
            assert!(requires(stdio_arguments, "files"));
            assert!(requires(send_variant, "files"));
            assert_eq!(stdio_arguments["properties"]["files"]["minItems"], 1);
            &content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]["properties"]
                ["inputs"]
        } else {
            &content["application/json"]["schema"]["properties"]["inputs"]
        };
        assert_eq!(openapi_inputs, schema, "OpenAPI {}", action.action);
        assert_eq!(send_inputs, &local_schema, "send {}", action.action);
        for key in ["type", "properties", "required", "additionalProperties"] {
            assert_eq!(
                stdio_inputs.get(key),
                local_schema.get(key),
                "stdio {}: {key}",
                action.action
            );
        }
        let has_required_inputs = local_schema["required"]
            .as_array()
            .is_some_and(|fields| !fields.is_empty());
        assert_eq!(
            requires(send_variant, "inputs"),
            has_required_inputs,
            "send {}",
            action.action
        );
        assert!(!requires(stdio_arguments, "inputs"));
        assert_eq!(
            stdio_arguments["properties"]["requestFile"]["type"],
            "string"
        );
        if matches!(action.io, ActionIo::Json) {
            let http_arguments = &tool(http, &action.action)["inputSchema"];
            assert_eq!(
                &http_arguments["properties"]["inputs"], schema,
                "HTTP MCP {}",
                action.action
            );
            assert!(requires(http_arguments, "inputs"));
        } else {
            assert!(
                !http
                    .iter()
                    .any(|tool| tool["name"] == tool_name("jira", &action.action))
            );
        }
    }

    let list = &catalog_action(&catalog_value, "jira", "comment.list")["inputSchema"];
    for field in ["issue", "url"] {
        assert_eq!(list["properties"][field]["type"], "string");
        assert!(!requires(list, field));
        assert!(
            list["properties"][field]["description"]
                .as_str()
                .unwrap()
                .contains("Give exactly one of issue or url.")
        );
    }
    let list_validator = jsonschema::validator_for(list).unwrap();
    for locator in [
        json!({"issue": "PROJ-1"}),
        json!({"url": "https://example.atlassian.net/browse/PROJ-1"}),
    ] {
        assert!(list_validator.is_valid(&locator));
    }
    let view = &catalog_action(&catalog_value, "jira", "issue.view")["inputSchema"];
    assert_eq!(view["properties"]["includeComments"]["type"], "boolean");
    assert_eq!(view["properties"]["includeComments"]["default"], false);
    let comment = &catalog_action(&catalog_value, "jira", "comment.add")["inputSchema"];
    assert!(requires(comment, "content"));
    assert!(requires(comment, "contentFormat"));
    let update = &catalog_action(&catalog_value, "jira", "issue.update")["inputSchema"];
    assert!(!requires(update, "content"));
    assert!(!requires(update, "summary"));
    for field in ["summary", "content"] {
        assert!(
            update["properties"][field]["description"]
                .as_str()
                .unwrap()
                .contains("Give at least one of summary or content.")
        );
    }
    let update_validator = jsonschema::validator_for(update).unwrap();
    for (content, format) in [
        (json!("Text"), "plain_text"),
        (
            json!({"type": "doc", "version": 1, "content": [], "extension": true}),
            "adf",
        ),
    ] {
        assert!(
            update_validator
                .is_valid(&json!({"issue": "PROJ-1", "content": content, "contentFormat": format}))
        );
    }
    for content in [json!(null), json!(true), json!(7), json!([])] {
        assert!(
            !update_validator
                .is_valid(&json!({"issue": "PROJ-1", "content": content, "contentFormat": "adf"}))
        );
    }

    let send_validator = jsonschema::validator_for(&send).unwrap();
    for action in ["comment.list", "issue.update"] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "jira", "action": action});
        assert!(send_validator.is_valid(&request));
        request["inputs"] = json!({});
        assert!(send_validator.is_valid(&request));
        request["inputs"] = json!(null);
        assert!(!send_validator.is_valid(&request));
    }
    for inputs in [
        json!({}),
        json!({"content": "text", "contentFormat": "plain_text"}),
    ] {
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "jira", "action": "comment.add", "inputs": inputs});
        assert_eq!(
            send_validator.is_valid(&request),
            inputs.get("content").is_some()
        );
    }
    assert!(!send_validator.is_valid(&json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "jira", "action": "comment.add"})));
}

#[tokio::test]
async fn jira_schema_accepts_relations_that_the_provider_still_refuses() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let session = fixture.initialize().await;
    let cases = [
        (
            "comment.list",
            json!({}),
            "jira.comment.list requires issue or url",
        ),
        (
            "comment.list",
            json!({"issue": "PROJ-1", "url": "https://example.atlassian.net/browse/PROJ-1"}),
            "jira.comment.list accepts issue or url, not both",
        ),
        (
            "issue.update",
            json!({"issue": "PROJ-1"}),
            "jira.issue.update requires summary or content with contentFormat",
        ),
        (
            "issue.update",
            json!({"issue": "PROJ-1", "content": "private-body-sentinel"}),
            "jira.issue.update requires content and contentFormat together",
        ),
        (
            "issue.update",
            json!({"issue": "PROJ-1", "contentFormat": "plain_text"}),
            "jira.issue.update requires content and contentFormat together",
        ),
        (
            "issue.update",
            json!({"issue": "PROJ-1", "content": "private-body-sentinel", "contentFormat": "adf"}),
            "jira.issue.update content must be an object for adf",
        ),
        (
            "issue.update",
            json!({"issue": "PROJ-1", "content": {"extension": "private-body-sentinel"}, "contentFormat": "markdown"}),
            "jira.issue.update content must be a string for markdown",
        ),
    ];
    for (index, (action, inputs, message)) in cases.into_iter().enumerate() {
        let schema = &catalog_action(&catalog, "jira", action)["inputSchema"];
        assert!(
            jsonschema::validator_for(schema).unwrap().is_valid(&inputs),
            "{action}: {inputs}"
        );
        let response = invoke(
            &fixture,
            &format!("jira-plain-refusal-{index}"),
            "jira",
            action,
            inputs.clone(),
        )
        .await;
        assert_eq!(response["reason"], message);
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("jira", action),
                json!({"inputs": inputs}),
            )
            .await;
        let envelope = structured(&called);
        assert_eq!(called["result"]["isError"], true);
        assert_eq!(envelope["reason"], message);
        assert_eq!(envelope["decision"], "deny");
        assert_eq!(envelope["reasonCode"], "input_invalid");
        assert!(envelope.get("result").is_none());
        assert!(!called.to_string().contains("private-body-sentinel"));
        assert!(!response.to_string().contains("private-body-sentinel"));
    }
    assert!(!read_audit_text(&fixture.audit_path).contains("private-body-sentinel"));

    // JSON invocation still normalizes omitted inputs to an object; HTTP MCP
    // requires its explicit inputs argument before invoking the provider.
    let omitted: agent_access_core::InvokeRequest = serde_json::from_value(json!({})).unwrap();
    assert_eq!(omitted.inputs, json!({}));
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/jira/comment.list")
                .extension(ConnectInfo(
                    "127.0.0.1:45010".parse::<SocketAddr>().unwrap(),
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(CONTENT_TYPE, "application/json")
                .header(REQUEST_ID_HEADER, "jira-plain-omitted-inputs")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["reason"],
        "jira.comment.list requires issue or url"
    );
    for arguments in [json!({}), json!({"inputs": null}), json!({"inputs": []})] {
        let result = fixture
            .call(&session, 30, &tool_name("jira", "comment.list"), arguments)
            .await;
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["content"][0]["text"],
            "inputs is required and must be a JSON object"
        );
    }
}
