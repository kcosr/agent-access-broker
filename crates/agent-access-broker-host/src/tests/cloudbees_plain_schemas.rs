//! Plain discovery retains CloudBees' categorized provider refusals.
use super::mcp::{Fixture, TOKEN_A, structured};
use super::*;
use agent_access_core::ApiCatalog;
use agent_access_core::mcp::{ProjectionMode, project_catalog, tool_name};
use agent_access_provider::ActionIo;

const JOB: &str = "payments/build-api";
const JOB_URL: &str = "https://ci.example.com/team-ci/job/payments/job/build-api/";

async fn fixture() -> Fixture {
    Fixture::new(|config| {
        let mut credential = config.credentials.service["fake"].clone();
        credential.kind = "basic_api_token".into();
        credential.username_ref = credential.token_ref.clone();
        config
            .credentials
            .service
            .insert("cloudbees_ci".into(), credential);
        let provider: agent_access_cloudbees_ci::CloudbeesCiProviderConfig =
            serde_json::from_value(json!({
                "controllers": {"team-ci": {"base_url": "https://ci.example.com/team-ci/"}},
                "allowed_upstream_hosts": ["https://ci.example.com/team-ci/**"]
            }))
            .unwrap();
        let actions = agent_access_cloudbees_ci::cloudbees_ci_descriptor(&provider)
            .actions
            .into_iter()
            .map(|action| action.action)
            .collect();
        config.providers.insert(provider);
        config.policy.resources.push(ResourceDefinition {
            id: "ci-job".into(),
            display_name: None,
            resource_type: CLOUDBEES_CI_JOB_RESOURCE.id().clone(),
            selector: ResourceSelector::Exact {
                value: format!("team-ci/{JOB}"),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
        });
        config.policy.grants = vec![PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            execution_contexts: None,
            service: "cloudbees_ci".into(),
            actions,
            resources: ResourceSelection {
                resource_ids: vec!["ci-job".into()],
                resource_group_ids: vec![],
            },
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
        &format!("cloudbees-plain-{name}"),
        Some(TOKEN_A),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

fn tool<'a>(tools: &'a [Value], action: &str) -> &'a Value {
    let name = tool_name("cloudbees_ci", action);
    tools.iter().find(|tool| tool["name"] == name).unwrap()
}

#[tokio::test]
async fn cloudbees_plain_inputs_project_through_stdio_http_send_and_openapi() {
    let fixture = fixture().await;
    let catalog: ApiCatalog = serde_json::from_value(spec(&fixture, "catalog").await).unwrap();
    let openapi = spec(&fixture, "openapi.json").await;
    let send = spec(&fixture, "send-schema.json").await;
    let stdio = project_catalog(&catalog, ProjectionMode::Stdio).unwrap();
    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    assert!(listing["result"].get("nextCursor").is_none());
    let http = listing["result"]["tools"].as_array().unwrap();
    let cloudbees = catalog
        .services
        .iter()
        .find(|service| service.service == "cloudbees_ci")
        .unwrap();
    assert_eq!(cloudbees.actions.len(), 17);
    for action in &cloudbees.actions {
        let schema = &action.input_schema;
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
            assert!(
                schema.get(keyword).is_none(),
                "{}: {keyword}",
                action.action
            );
        }
        let arguments = &tool(&stdio, &action.action)["inputSchema"];
        let inputs = &arguments["properties"]["inputs"];
        for key in ["type", "properties", "required", "additionalProperties"] {
            assert_eq!(
                inputs.get(key),
                schema.get(key),
                "stdio {} {key}",
                action.action
            );
        }
        assert!(
            arguments["required"]
                .as_array()
                .is_none_or(|required| !required.contains(&json!("inputs")))
        );
        assert_eq!(arguments["properties"]["requestFile"]["type"], "string");
        let send_variant = send_action_variant(&send, "cloudbees_ci", &action.action);
        assert_eq!(
            &send_variant["properties"]["inputs"], schema,
            "send {}",
            action.action
        );
        let required_inputs = schema["required"]
            .as_array()
            .is_some_and(|fields| !fields.is_empty());
        assert_eq!(
            send_variant["required"]
                .as_array()
                .unwrap()
                .contains(&json!("inputs")),
            required_inputs
        );
        let operation =
            &openapi["paths"][format!("/v1/invoke/cloudbees_ci/{}", action.action)]["post"];
        assert_eq!(
            &operation["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"],
            schema
        );
        if matches!(action.io, ActionIo::Json) {
            let http_arguments = &tool(http, &action.action)["inputSchema"];
            assert_eq!(&http_arguments["properties"]["inputs"], schema);
            assert!(
                http_arguments["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("inputs"))
            );
        } else {
            assert!(
                !http
                    .iter()
                    .any(|tool| tool["name"] == tool_name("cloudbees_ci", &action.action))
            );
        }
    }
    let log = &tool(&stdio, "build.log.read")["inputSchema"]["properties"]["inputs"];
    assert!(
        log["properties"]["query"]["description"]
            .as_str()
            .unwrap()
            .contains("search")
    );
    assert!(
        log["properties"]["cursor"]["description"]
            .as_str()
            .unwrap()
            .contains("buildSelector")
    );
    assert_eq!(log["properties"]["maxBytes"]["minimum"], 1024);
    assert_eq!(log["properties"]["maxBytes"]["maximum"], 65536);
}

async fn invoke(fixture: &Fixture, request_id: &str, action: &str, body: Value) -> Value {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/invoke/cloudbees_ci/{action}"))
                .extension(ConnectInfo(
                    "127.0.0.1:45010".parse::<SocketAddr>().unwrap(),
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(REQUEST_ID_HEADER, request_id)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
    response_json(response).await
}

#[tokio::test]
async fn cloudbees_relationship_denials_keep_messages_categories_and_audit_on_http_and_mcp() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let session = fixture.initialize().await;
    for (index, (action, inputs, expected, category, field)) in [
        ("build.log.read", json!({}), "pass controller and job, or a job or build url", "locator_missing", "controller"),
        ("build.log.read", json!({"controller": "team-ci"}), "job is required with controller; or pass a job or build url instead", "locator_missing", "job"),
        ("build.log.read", json!({"url": JOB_URL, "controller": "team-ci"}), "pass either url or controller and job, not both", "locator_conflict", "url"),
        ("build.log.read", json!({"controller": "team-ci", "job": JOB}), "this action needs a build: pass buildNumber or buildSelector, or a build url", "build_missing", "buildNumber"),
        ("build.log.read", json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "buildSelector": "lastBuild"}), "pass buildNumber or buildSelector, not both", "build_conflict", "buildSelector"),
        ("build.log.read", json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "mode": "search"}), "mode search needs a nonempty literal query of at most 256 UTF-8 bytes", "value_invalid", "query"),
        ("build.log.read", json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "cursor": "private-cursor-sentinel"}), "tail reads have no cursor; continue a head or search read with the same mode", "option_conflict", "cursor"),
    ].into_iter().enumerate() {
        let schema = &catalog_action(&catalog, "cloudbees_ci", action)["inputSchema"];
        assert!(jsonschema::validator_for(schema).unwrap().is_valid(&inputs));
        let response = invoke(&fixture, &format!("cloudbees-plain-{index}"), action, json!({"inputs": inputs})).await;
        let called = fixture.call(&session, 10 + index as u64, &tool_name("cloudbees_ci", action), json!({"inputs": inputs})).await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["reason"], expected);
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(envelope["decision"], "deny");
            assert_eq!(envelope["result"], json!({"inputCategory": category, "field": field}));
            assert!(!envelope.to_string().contains("private-cursor-sentinel"));
            let records = read_audit_records(&fixture.audit_path);
            let record = records.iter().find(|record| record["agentRequestId"] == envelope["agentRequestId"]).unwrap();
            assert_eq!(record["reasonCode"], "input_invalid");
            assert_eq!(record["decision"], "deny");
            assert!(record.get("upstreamStatus").is_none());
            assert!(record.get("objectIds").is_none());
            assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
        }
    }
    assert!(!read_audit_text(&fixture.audit_path).contains("private-cursor-sentinel"));
}

#[tokio::test]
async fn cloudbees_retained_constraints_explain_denials_without_changing_categories() {
    let fixture = fixture().await;
    let session = fixture.initialize().await;
    for (index, (inputs, message, category, field)) in [
        (
            json!({"controller": null, "job": JOB, "buildNumber": 42}),
            "inputs.controller must be a string",
            "value_invalid",
            "controller",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 0}),
            "inputs.buildNumber must be at least 1",
            "value_invalid",
            "buildNumber",
        ),
        (
            json!({"controller": "team-ci", "job": JOB, "buildNumber": 42, "query": null}),
            "inputs.query must be a string",
            "value_invalid",
            "query",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let response = invoke(
            &fixture,
            &format!("cloudbees-type-{index}"),
            "build.log.read",
            json!({"inputs": inputs}),
        )
        .await;
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("cloudbees_ci", "build.log.read"),
                json!({"inputs": inputs}),
            )
            .await;
        for envelope in [&response, structured(&called)] {
            assert_eq!(
                envelope["reason"],
                format!("cloudbees_ci.build.log.read inputs are invalid: {message}")
            );
            assert_eq!(
                envelope["result"],
                json!({"inputCategory": category, "field": field})
            );
            assert_eq!(envelope["decision"], "deny");
            assert_eq!(envelope["reasonCode"], "input_invalid");
        }
    }
    let omitted = invoke(&fixture, "cloudbees-omitted", "build.log.read", json!({})).await;
    assert_eq!(
        omitted["result"],
        json!({"inputCategory": "locator_missing", "field": "controller"})
    );
    let called = fixture
        .call(
            &session,
            50,
            &tool_name("cloudbees_ci", "build.log.read"),
            json!({}),
        )
        .await;
    assert_eq!(
        structured(&called),
        &json!({"error": {"code": "mcp_tool_error", "message": "inputs is required and must be a JSON object"}})
    );
}
