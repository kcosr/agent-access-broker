//! GitLab's published inputs stay plain while the production provider enforces
//! locator and search relationships before making any upstream request.
use super::input_explanations::invoke;
use super::mcp::{Fixture, TOKEN_A, structured};
use super::*;
use agent_access_core::ApiCatalog;
use agent_access_core::mcp::{ProjectionMode, project_catalog, tool_name};
use agent_access_provider::ActionIo;

const PROJECT_URL: &str = "https://gitlab.example.com/acme/portal";
const SECRET: &str = "private-gitlab-input-sentinel";

fn provider_config() -> agent_access_gitlab::GitlabProviderConfig {
    serde_json::from_value(json!({
        "api_base_url": "https://gitlab.example.com/api/v4",
        "web_base_url": "https://gitlab.example.com",
        "allowed_upstream_hosts": ["https://gitlab.example.com/api/v4/**"],
        "provisioning": {"enabled": true},
        "search": {"engines": {"zoekt": {"instance_categories": ["code"]}}}
    }))
    .unwrap()
}

async fn fixture() -> Fixture {
    Fixture::new(|config| {
        let mut credential = config.credentials.service["fake"].clone();
        credential.kind = "bearer_token".into();
        let mut lookup = credential.clone();
        lookup.read_only = Some(true);
        config
            .credentials
            .service
            .insert("gitlab".into(), credential);
        config.credentials.lookup.insert("gitlab".into(), lookup);
        config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
            hash_key_ref: format!(
                "file:{}",
                config.credential_encryption.as_ref().unwrap().keys[0]
                    .path
                    .as_ref()
                    .unwrap()
            ),
            ..Default::default()
        });
        let provider = provider_config();
        let actions = agent_access_gitlab::gitlab_descriptor(&provider)
            .actions
            .into_iter()
            .map(|action| action.action)
            .collect();
        config.providers.insert(provider);
        config.policy.grants = vec![PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            execution_contexts: None,
            service: "gitlab".into(),
            actions,
            resources: selected_resources(&[("repository", &["acme/portal"])]),
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
        &format!("gitlab-plain-{name}"),
        Some(TOKEN_A),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

fn requires(schema: &Value, field: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|fields| fields.iter().any(|v| v == field))
}

fn tool<'a>(tools: &'a [Value], action: &str) -> &'a Value {
    let name = tool_name("gitlab", action);
    tools.iter().find(|tool| tool["name"] == name).unwrap()
}

#[tokio::test]
async fn gitlab_plain_inputs_project_through_stdio_http_send_and_openapi() {
    let fixture = fixture().await;
    let catalog_value = spec(&fixture, "catalog").await;
    let catalog: ApiCatalog = serde_json::from_value(catalog_value.clone()).unwrap();
    let openapi = spec(&fixture, "openapi.json").await;
    let send = spec(&fixture, "send-schema.json").await;
    let stdio = project_catalog(&catalog, ProjectionMode::Stdio).unwrap();
    let session = fixture.initialize().await;
    let mut http = Vec::new();
    let mut params = json!({});
    for id in 2..20 {
        let listing = fixture.rpc(&session, id, "tools/list", params).await;
        http.extend(
            listing["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
        let Some(cursor) = listing["result"].get("nextCursor") else {
            break;
        };
        params = json!({"cursor": cursor});
        assert!(id < 19, "HTTP MCP catalog did not finish");
    }
    let gitlab = catalog
        .services
        .iter()
        .find(|service| service.service == "gitlab")
        .unwrap();
    assert_eq!(gitlab.actions.len(), 110);
    for action in &gitlab.actions {
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
        let send_variant = send_action_variant(&send, "gitlab", &action.action);
        let operation = &openapi["paths"][format!("/v1/invoke/gitlab/{}", action.action)]["post"];
        let content = &operation["requestBody"]["content"];
        let mut local_schema = schema.clone();
        let openapi_inputs = if let ActionIo::MultipartUpload { plan } = &action.io {
            assert_eq!(action.action, "project.upload");
            assert_eq!(plan.metadata_pointer, "/attachments");
            assert_eq!(plan.locator_inputs, ["project", "url"]);
            for locator in ["project", "url"] {
                assert!(schema["properties"].get(locator).is_some());
                assert!(!requires(schema, locator));
            }
            assert!(requires(schema, "attachments"));
            local_schema["properties"]
                .as_object_mut()
                .unwrap()
                .remove("attachments");
            local_schema["required"]
                .as_array_mut()
                .unwrap()
                .retain(|v| v != "attachments");
            assert!(requires(stdio_arguments, "files"));
            assert!(requires(send_variant, "files"));
            assert_eq!(stdio_arguments["properties"]["files"]["minItems"], 1);
            assert_eq!(stdio_arguments["properties"]["files"]["maxItems"], 1);
            &content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]["properties"]
                ["inputs"]
        } else {
            &content["application/json"]["schema"]["properties"]["inputs"]
        };
        assert_eq!(openapi_inputs, schema, "OpenAPI {}", action.action);
        let mut send_inputs = local_schema.clone();
        if matches!(action.io, ActionIo::MultipartUpload { .. })
            && send_inputs["required"]
                .as_array()
                .is_some_and(Vec::is_empty)
        {
            // JSON send removes an empty required list after generated upload
            // metadata is stripped; stdio keeps the empty list.
            send_inputs.as_object_mut().unwrap().remove("required");
        }
        for pointer in &action.sensitive_input_pointers {
            let field = pointer.strip_prefix("/inputs/").unwrap();
            assert!(
                !field.contains('/'),
                "fixture expects top-level sensitive inputs"
            );
            if let Some(required) = local_schema
                .get_mut("required")
                .and_then(Value::as_array_mut)
            {
                required.retain(|v| v != field);
            }
        }
        assert_eq!(
            &send_variant["properties"]["inputs"], &send_inputs,
            "send {}",
            action.action
        );
        for key in ["type", "properties", "required", "additionalProperties"] {
            assert_eq!(
                stdio_arguments["properties"]["inputs"].get(key),
                local_schema.get(key),
                "stdio {}: {key}",
                action.action
            );
        }
        let has_required_inputs = send_inputs["required"]
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
        assert_eq!(
            stdio_arguments["properties"].get("secretSources").is_some(),
            !action.sensitive_input_pointers.is_empty()
        );
        if matches!(action.io, ActionIo::Json) {
            let http_arguments = &tool(&http, &action.action)["inputSchema"];
            assert_eq!(
                &http_arguments["properties"]["inputs"], schema,
                "HTTP MCP {}",
                action.action
            );
            assert!(requires(http_arguments, "inputs"));
            assert!(http_arguments["properties"].get("secretSources").is_none());
        } else {
            assert!(
                !http
                    .iter()
                    .any(|tool| tool["name"] == tool_name("gitlab", &action.action))
            );
        }
    }
    let webhook = catalog_action(&catalog_value, "gitlab", "webhook.update");
    assert_eq!(
        webhook["sensitiveInputPointers"],
        json!(["/inputs/signingToken", "/inputs/token"])
    );
    let secret_source = &tool(&stdio, "webhook.update")["inputSchema"]["properties"]["secretSources"]
        ["items"]["properties"]["source"];
    assert_eq!(secret_source["oneOf"].as_array().unwrap().len(), 2);
    let status = &catalog_action(&catalog_value, "gitlab", "webhook.event.list")["inputSchema"]["properties"]
        ["status"];
    assert!(
        status.get("oneOf").is_some(),
        "the scalar status union remains supported"
    );

    let validator = jsonschema::validator_for(&send).unwrap();
    for action in ["project.view", "issue.view", "merge_request.view"] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "gitlab", "action": action});
        assert!(validator.is_valid(&request));
        request["inputs"] = json!({});
        assert!(validator.is_valid(&request));
        request["inputs"] = json!(null);
        assert!(!validator.is_valid(&request));
    }
    for action in ["issue.create", "merge_request.update"] {
        let request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "gitlab", "action": action});
        assert!(!validator.is_valid(&request));
    }
}

fn assert_denial_audit(fixture: &Fixture, envelope: &Value, action: &str, inputs: &Value) {
    let records = require_audit_request(
        &fixture.audit_path,
        envelope["agentRequestId"].as_str().unwrap(),
        "gitlab",
        action,
    );
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reasonCode"], envelope["reasonCode"]);
    assert!(record.get("upstreamStatus").is_none(), "{record}");
    assert!(record.get("objectIds").is_none(), "{record}");
    assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
    let fields: &[(&str, &str)] = if action.starts_with("search.") {
        &[
            ("project", "Project"),
            ("search", "Search"),
            ("regex", "Regex"),
        ]
    } else if action == "project.view" {
        &[("project", "Project"), ("url", "URL")]
    } else if action == "issue.view" {
        &[("project", "Project"), ("iid", "Issue"), ("url", "URL")]
    } else {
        &[
            ("project", "Project"),
            ("iid", "Merge request"),
            ("url", "URL"),
        ]
    };
    let expected: Vec<Value> = fields
        .iter()
        .filter_map(|(input, label)| {
            inputs
                .get(input)
                .map(|value| json!({"input": input, "label": label, "value": value}))
        })
        .collect();
    assert_eq!(
        record
            .get("auditInputs")
            .cloned()
            .unwrap_or_else(|| json!([])),
        json!(expected)
    );
}

#[tokio::test]
async fn gitlab_locator_relationship_denials_keep_provider_messages_over_http_and_mcp() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let session = fixture.initialize().await;
    let mut cases = vec![
        (
            "project.view",
            json!({}),
            "gitlab project.view requires project or url".to_string(),
        ),
        (
            "project.view",
            json!({"project": "acme/portal", "url": PROJECT_URL}),
            "gitlab project.view accepts project or url, not both".to_string(),
        ),
    ];
    for action in ["issue.view", "merge_request.view"] {
        for (inputs, reason) in [
            (json!({}), "requires project with iid or url"),
            (
                json!({"project": "acme/portal"}),
                "requires project and iid together",
            ),
            (json!({"iid": 7}), "requires project and iid together"),
            (
                json!({"project": "acme/portal", "iid": 7, "url": PROJECT_URL}),
                "accepts project with iid or url, not both",
            ),
        ] {
            cases.push((action, inputs, format!("gitlab {action} {reason}")));
        }
    }
    for (index, (action, inputs, expected)) in cases.into_iter().enumerate() {
        let schema = &catalog_action(&catalog, "gitlab", action)["inputSchema"];
        assert!(jsonschema::validator_for(schema).unwrap().is_valid(&inputs));
        let response = invoke(
            &fixture,
            &format!("gitlab-plain-refusal-{index}"),
            "gitlab",
            action,
            inputs.clone(),
        )
        .await;
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("gitlab", action),
                json!({"inputs": inputs}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["reason"], expected);
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(envelope["decision"], "deny");
            assert!(envelope.get("result").is_none());
            assert_denial_audit(&fixture, envelope, action, &inputs);
        }
    }
}

#[tokio::test]
async fn gitlab_retained_constraints_still_explain_input_denials() {
    let fixture = fixture().await;
    let session = fixture.initialize().await;
    for (index, (action, inputs, expected)) in [
        ("project.view", json!({"url": 7}), "gitlab.project.view inputs are invalid: inputs.url must be a string"),
        ("issue.view", json!({"project": "acme/portal", "iid": false}), "gitlab.issue.view inputs are invalid: inputs.iid must be an integer or a string"),
        ("project.view", json!({"unknown": SECRET}), "gitlab.project.view inputs are invalid: inputs.unknown is not allowed; allowed: project, url"),
    ].into_iter().enumerate() {
        let response = invoke(&fixture, &format!("gitlab-plain-type-{index}"), "gitlab", action, inputs.clone()).await;
        let called = fixture.call(&session, 10 + index as u64, &tool_name("gitlab", action), json!({"inputs": inputs})).await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["reason"], expected);
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(envelope["decision"], "deny");
            assert!(envelope.get("result").is_none());
            assert!(!envelope.to_string().contains(SECRET));
            assert_denial_audit(&fixture, envelope, action, &inputs);
        }
    }
    assert!(!read_audit_text(&fixture.audit_path).contains(SECRET));
}

#[tokio::test]
async fn gitlab_search_route_and_regex_relationships_still_fail_before_upstream() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let schema = &catalog_action(&catalog, "gitlab", "search.code")["inputSchema"];
    let session = fixture.initialize().await;
    for (index, (inputs, expected)) in [
        (
            json!({"search": "handler"}),
            "GitLab search.code requires project with engine basic",
        ),
        (
            json!({"search": "handler", "engine": "zoekt", "project": "acme/portal"}),
            "GitLab search.code does not accept project with engine zoekt; omit project",
        ),
        (
            json!({"search": "handler", "project": "acme/portal", "regex": false}),
            "GitLab search regex is accepted only with engine zoekt, including regex: false",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(jsonschema::validator_for(schema).unwrap().is_valid(&inputs));
        let response = invoke(
            &fixture,
            &format!("gitlab-plain-search-{index}"),
            "gitlab",
            "search.code",
            inputs.clone(),
        )
        .await;
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("gitlab", "search.code"),
                json!({"inputs": inputs}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["reason"], expected);
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(envelope["decision"], "deny");
            assert!(envelope.get("result").is_none());
            assert_denial_audit(&fixture, envelope, "search.code", &inputs);
        }
    }
}

#[tokio::test]
async fn gitlab_http_and_http_mcp_keep_omitted_input_contracts() {
    let fixture = fixture().await;
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/gitlab/project.view")
                .extension(ConnectInfo(
                    "127.0.0.1:45010".parse::<SocketAddr>().unwrap(),
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(CONTENT_TYPE, "application/json")
                .header(REQUEST_ID_HEADER, "gitlab-plain-omitted-inputs")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["reason"],
        "gitlab project.view requires project or url"
    );
    let session = fixture.initialize().await;
    for (index, arguments) in [json!({}), json!({"inputs": null}), json!({"inputs": []})]
        .into_iter()
        .enumerate()
    {
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("gitlab", "project.view"),
                arguments,
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        assert_eq!(
            structured(&called),
            &json!({"error": {
                "code": "mcp_tool_error", "message": "inputs is required and must be a JSON object"
            }})
        );
    }
}
