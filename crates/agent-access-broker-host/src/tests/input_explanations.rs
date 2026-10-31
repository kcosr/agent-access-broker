//! `input_invalid` explanations through the real HTTP and MCP invocation
//! paths with the production Jira and Confluence providers. Every request
//! here is refused before any upstream request, so no upstream is served.
use super::mcp::{Fixture, TOKEN_A, structured};
use super::*;

/// A secret-like value that must never reach a message, log or audit record.
const SECRET: &str = "secret-value-123";

const COMMENT_LIST_ALLOWED: &str =
    "allowed: includeBodies, issue, maxResults, orderBy, startAt, url";

/// Grants `user:mcp-user` Jira `comment.list` on `PROJ` and Confluence
/// `search` on `ENG`, with synthetic static credentials. `issue_type.list`
/// stays ungranted.
async fn fixture() -> Fixture {
    Fixture::new(|config| {
        let mut credential = config.credentials.service["fake"].clone();
        credential.kind = "basic_api_token".into();
        credential.username_ref = credential.token_ref.clone();
        let mut lookup = credential.clone();
        lookup.read_only = Some(true);
        for service in ["jira", "confluence"] {
            config
                .credentials
                .service
                .insert(service.into(), credential.clone());
            config
                .credentials
                .lookup
                .insert(service.into(), lookup.clone());
        }
        config.providers.insert(
            serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
                "tenant_host": "example.atlassian.net",
                "allowed_upstream_hosts": ["https://example.atlassian.net/rest/api/3/**"]
            }))
            .unwrap(),
        );
        config.providers.insert(
            serde_json::from_value::<agent_access_confluence::ConfluenceProviderConfig>(json!({
                "tenant_host": "example.atlassian.net",
                "allowed_upstream_hosts": [
                    "https://example.atlassian.net/wiki/api/v2/**",
                    "https://example.atlassian.net/wiki/rest/api/**"
                ]
            }))
            .unwrap(),
        );
        let grant = |service: &str, action: &str, resources| PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            execution_contexts: None,
            service: service.into(),
            actions: vec![action.into()],
            resources,
            credential_mode: "service".into(),
            priority: None,
        };
        config.policy.grants = vec![
            grant(
                "jira",
                "comment.list",
                selected_resources(&[("jira-project", &["PROJ"])]),
            ),
            grant(
                "confluence",
                "search",
                selected_resources(&[("space", &["ENG"])]),
            ),
        ];
    })
    .await
}

/// The HTTP API's denial of `inputs` for `service`/`action`.
async fn invoke(
    fixture: &Fixture,
    request_id: &str,
    service: &str,
    action: &str,
    inputs: Value,
) -> Value {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/invoke/{service}/{action}"))
                .extension(ConnectInfo(
                    "127.0.0.1:45010".parse::<SocketAddr>().unwrap(),
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(REQUEST_ID_HEADER, request_id)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "inputs": inputs }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request_id}");
    let body = response_json(response).await;
    assert_eq!(body["decision"], "deny", "{body}");
    assert_eq!(body["reasonCode"], "input_invalid", "{body}");
    assert_eq!(body["reason"], body["error"]["message"], "{body}");
    body
}

#[tokio::test]
async fn native_input_denials_name_the_problems_on_http_and_mcp() {
    let fixture = fixture().await;
    let session = fixture.initialize().await;
    let comment_list = agent_access_core::mcp::tool_name("jira", "comment.list");
    let search = agent_access_core::mcp::tool_name("confluence", "search");
    let cases = [
        // Scope resolution of a looked-up action: an extra key, a wrong type
        // and a non-identifier key.
        (
            "jira",
            "comment.list",
            comment_list.as_str(),
            json!({"issue": "PROJ-1", "readContentFormat": "markdown", "maxResults": SECRET, SECRET: 1}),
            format!(
                "jira.comment.list inputs are invalid: inputs.maxResults must be an integer; \
                 inputs.readContentFormat and 1 other unexpected property are not allowed; {COMMENT_LIST_ALLOWED}"
            ),
        ),
        // A missing locator form.
        (
            "jira",
            "comment.list",
            comment_list.as_str(),
            json!({"orderBy": "newest"}),
            "jira.comment.list inputs are invalid: inputs.orderBy must be one of: \
             created, -created, +created; inputs must include issue or url"
                .to_owned(),
        ),
        // The invocation of a native search: a missing nested property, a
        // wrong type and an extra key.
        (
            "confluence",
            "search",
            search.as_str(),
            json!({"query": {"type": "cql"}, "maxResults": "ten", "extra": true}),
            "confluence.search inputs are invalid: inputs.maxResults must be an integer; \
             inputs.query.value is required; inputs.extra is not allowed; \
             allowed: maxResults, nextPageToken, query, spaces"
                .to_owned(),
        ),
    ];
    for (index, (service, action, tool, inputs, expected)) in cases.into_iter().enumerate() {
        let body = invoke(
            &fixture,
            &format!("input-explanation-http-{index}"),
            service,
            action,
            inputs.clone(),
        )
        .await;
        assert_eq!(body["reason"], expected, "{body}");
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                tool,
                json!({ "inputs": inputs }),
            )
            .await;
        assert_eq!(called["result"]["isError"], true, "{called}");
        let envelope = structured(&called);
        assert_eq!(envelope["reasonCode"], "input_invalid", "{envelope}");
        assert_eq!(envelope["decision"], "deny", "{envelope}");
        assert_eq!(envelope["reason"], expected, "{envelope}");
        assert!(!called.to_string().contains(SECRET), "{called}");
    }
}

#[tokio::test]
async fn provider_rules_the_schema_cannot_express_keep_their_message() {
    let fixture = fixture().await;
    // The schema accepts an empty text query; the provider does not.
    let body = invoke(
        &fixture,
        "input-explanation-provider-rule",
        "confluence",
        "search",
        json!({"query": {"type": "text", "value": ""}}),
    )
    .await;
    assert_eq!(
        body["reason"],
        "confluence.search text query must not be empty"
    );
}

#[tokio::test]
async fn a_caller_without_a_grant_for_the_action_gets_the_provider_message() {
    let fixture = fixture().await;
    // Scope resolution runs before policy for this ungranted action.
    let body = invoke(
        &fixture,
        "input-explanation-ungranted",
        "jira",
        "issue_type.list",
        json!({"project": "PROJ", "extra": true}),
    )
    .await;
    assert_eq!(body["reason"], "jira.issue_type.list inputs are invalid");
}

/// Secret-like values in wrong-type fields, as the values of extra keys and
/// as non-identifier keys reach neither the response, the service log nor
/// the audit record. Values go only in inputs the actions do not audit.
#[tokio::test(flavor = "current_thread")]
async fn supplied_values_stay_out_of_responses_logs_and_audit() {
    let captured = install_trace_capture().start();
    let fixture = fixture().await;
    let requests = [
        (
            "input-explanation-secret-scope",
            "jira",
            "comment.list",
            json!({"issue": "PROJ-1", "maxResults": SECRET, "extra": SECRET, SECRET: SECRET}),
        ),
        (
            "input-explanation-secret-invoke",
            "confluence",
            "search",
            json!({"query": {"type": "cql", "value": ""}, "maxResults": SECRET, "nextPageToken": 7, "extra": SECRET, SECRET: [SECRET]}),
        ),
    ];
    for (request_id, service, action, inputs) in &requests {
        let body = captured
            .run(invoke(
                &fixture,
                request_id,
                service,
                action,
                inputs.clone(),
            ))
            .await;
        let reason = body["reason"].as_str().unwrap();
        assert!(
            reason.starts_with(&format!("{service}.{action} inputs are invalid: ")),
            "{reason}"
        );
        assert!(
            reason.contains("inputs.maxResults must be an integer"),
            "{reason}"
        );
        assert!(!body.to_string().contains(SECRET), "{body}");
    }
    let events = captured.take_events();
    for (request_id, _, _, _) in &requests {
        event_by_name_and_agent(&events, "invoke_completed", request_id);
    }
    assert!(!serde_json::to_string(&events).unwrap().contains(SECRET));
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    for (request_id, service, action, _) in &requests {
        let records = require_audit_request(&fixture.audit_path, request_id, service, action);
        assert!(
            records
                .iter()
                .all(|record| record["reasonCode"] == "input_invalid"),
            "{records:?}"
        );
    }
    assert!(!audit.contains(SECRET));
}
