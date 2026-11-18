//! Real Broker admission, projections, audit and CLI around the Jira provider.
//! The in-memory Jira seam records mutations without contacting an upstream.
use super::*;
use serde_json::{Value, json};

const ACTION: &str = "issue.custom_field.set";
const FIELD: &str = "customfield_12345";
const ISSUE_ID: &str = "10001";
const PRIVATE: &str = "private-custom-field-value";
const BODY_LIMIT: usize = 128;

async fn start(backend: Arc<StubJiraBackend>, allowed_field_ids: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value = toml::from_str(&jira_document(
        application.directory(),
        JiraAccess::AgentService,
    ))
    .unwrap();
    document["identity"]["sources"][0]["header"] = "Authorization".into();
    document["identity"]["sources"][0]["scheme"] = "Bearer".into();
    document.as_table_mut().unwrap().insert(
        "mcp".into(),
        toml::Value::try_from(json!({
            "enabled":true, "public_url":format!("{}/mcp", application.public_url())
        }))
        .unwrap(),
    );
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert(
            "custom_fields".into(),
            toml::Value::try_from(json!({"allowed_field_ids":allowed_field_ids})).unwrap(),
        );
    document["providers"]["jira"]["content"]
        .as_table_mut()
        .unwrap()
        .insert("max_body_bytes".into(), (BODY_LIMIT as i64).into());
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        grant["actions"] = toml::Value::try_from(vec![ACTION]).unwrap();
    }
    let config = document["providers"]["jira"].clone().try_into().unwrap();
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "jira",
            ProviderFixture::instance(jira_service(config, Default::default(), backend)),
        )
        .start()
        .await
        .unwrap()
}

fn command(base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base,
        "--token-value",
        "agent-token",
        "--identity-header",
        "Authorization",
        "--identity-scheme",
        "Bearer",
    ]);
    command
}

fn run(base: &str, arguments: &[&str]) -> Value {
    let output = command(base).args(arguments).output().unwrap();
    assert_success("custom-field CLI", &output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn backend() -> Arc<StubJiraBackend> {
    Arc::new(StubJiraBackend {
        issues: BTreeMap::from([(
            "PROJ-1".to_string(),
            JiraIssue {
                id: ISSUE_ID.to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: None,
                status: None,
                issue_type: None,
                description: None,
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
            },
        )]),
        ..Default::default()
    })
}

fn acknowledgement(response: &Value) {
    assert_eq!(response["decision"], "allow", "{response}");
    assert_eq!(
        response["result"],
        json!({
            "operation":ACTION,
            "issue":{"id":ISSUE_ID,"key":"PROJ-1","project":"PROJ","webUrl":"https://example.atlassian.net/browse/PROJ-1"},
            "fieldId":FIELD, "status":"set"
        })
    );
}

fn denial(response: &Value, reason: &str) {
    assert_eq!(response["decision"], "deny", "{response}");
    assert_eq!(response["reasonCode"], reason, "{response}");
    assert!(response["result"].is_null(), "{response}");
    assert!(!response.to_string().contains(PRIVATE));
}

fn refused(base: &str, arguments: &[&str], reason: &str) -> Value {
    let output = command(base).args(arguments).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(if reason == "input_invalid" { 3 } else { 2 }),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value = serde_json::from_slice(&output.stdout).unwrap();
    denial(&value, reason);
    value
}

fn inputs(value: Value) -> Value {
    json!({"issue":"PROJ-1","expectedIssueId":ISSUE_ID,"fieldId":FIELD,"value":value})
}

fn send(inputs: &Value) -> Value {
    json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":ACTION,"inputs":inputs})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_custom_field_set_projects_write_authority_and_preserves_values_and_private_audit() {
    let backend = backend();
    let broker = start(backend.clone(), &[FIELD]).await;
    let base = broker.public_url();
    let catalog = run(&base, &["spec", "catalog"]);
    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .unwrap()["actions"]
        .as_array()
        .unwrap();
    assert_eq!(
        actions.len(),
        1,
        "the grant authorizes only custom-field writes"
    );
    let action = &actions[0];
    assert_eq!(action["action"], ACTION);
    assert_eq!(action["readOnly"], false);
    assert_eq!(action["lookupRequired"], true);
    assert_eq!(action["requiredScopeTypes"], json!(["project"]));
    assert_eq!(action["documentation"]["allowedFieldIds"], json!([FIELD]));
    assert_eq!(
        action["inputSchema"]["required"],
        json!(["fieldId", "value"])
    );
    assert!(
        action["inputSchema"]["properties"]["value"]
            .get("type")
            .is_none()
    );
    let openapi = run(&base, &["spec", "openapi"]);
    let operation = &openapi["paths"]["/v1/invoke/jira/issue.custom_field.set"]["post"];
    assert_eq!(operation["x-agent-access-read-only"], false);
    assert_eq!(
        operation["x-agent-access-documentation"],
        action["documentation"]
    );
    let schema = run(&base, &["spec", "send-schema"]);
    let variant = schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"] == "jira"
                && variant["properties"]["action"]["const"] == ACTION
        })
        .unwrap();
    assert_eq!(variant["x-agent-access-read-only"], false);
    assert_eq!(
        variant["x-agent-access-documentation"],
        action["documentation"]
    );
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    let values = [
        Value::Null,
        json!(PRIVATE),
        json!({"id":PRIVATE}),
        json!([PRIVATE, null]),
        json!(false),
        json!(12.5),
        json!("{\"id\":\"private-custom-field-value\"}"),
    ];
    for (index, value) in values.iter().enumerate() {
        let request = inputs(value.clone());
        let written = match index % 3 {
            0 => run(
                &base,
                &[
                    "jira",
                    "issue",
                    "custom-field",
                    "set",
                    "PROJ-1",
                    "--expected-issue-id",
                    ISSUE_ID,
                    "--field-id",
                    FIELD,
                    "--value-json",
                    &value.to_string(),
                ],
            ),
            1 => run(
                &base,
                &[
                    "invoke",
                    "jira.issue.custom_field.set",
                    "--input-json",
                    &request.to_string(),
                ],
            ),
            _ => run(
                &base,
                &["send", "--request-json", &send(&request).to_string()],
            ),
        };
        acknowledgement(&written);
    }
    // Every accepted request is one write, including an identical repeated value.
    acknowledgement(&run(
        &base,
        &[
            "invoke",
            "jira.issue.custom_field.set",
            "--input-json",
            &inputs(json!(PRIVATE)).to_string(),
        ],
    ));
    let mut expected = values
        .iter()
        .cloned()
        .map(|value| (ISSUE_ID.to_string(), FIELD.to_string(), value))
        .collect::<Vec<_>>();
    expected.push((ISSUE_ID.to_string(), FIELD.to_string(), json!(PRIVATE)));
    assert_eq!(*backend.custom_field_updates.lock().unwrap(), expected);
    let observations = backend.credential_observations.lock().unwrap().clone();
    assert_eq!(
        observations.len(),
        expected.len() * 3,
        "scope lookup, identity reconfirmation and PUT only"
    );
    for group in observations.as_chunks::<3>().0 {
        assert_eq!(group[0].operation, "issue_metadata");
        assert_eq!(group[1].operation, "issue_metadata");
        assert_eq!(group[2].operation, "set_issue_custom_field");
        assert_eq!(group[0].credential, jira_credential("jira-lookup-token"));
        assert_eq!(group[1].credential, jira_credential("jira-lookup-token"));
        assert_eq!(group[2].credential, jira_credential("jira-token"));
    }
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.custom_field.set\""));
    assert!(audit.contains(FIELD));
    assert!(!audit.contains(PRIVATE));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_custom_field_allowlist_refusal_survives_admission_without_write() {
    for (allowed, requested) in [
        (&[] as &[&str], FIELD),
        (&[FIELD] as &[&str], "customfield_99999"),
    ] {
        let backend = backend();
        let broker = start(backend.clone(), allowed).await;
        let base = broker.public_url();
        let catalog = run(&base, &["spec", "catalog"]);
        assert!(
            catalog["services"]
                .as_array()
                .unwrap()
                .iter()
                .any(|service| {
                    service["service"] == "jira"
                        && service["actions"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|action| action["action"] == ACTION)
                }),
            "an empty allowlist does not remove discovery"
        );
        let request = json!({"issue":"PROJ-1", "fieldId":requested, "value":PRIVATE});
        refused(
            &base,
            &[
                "invoke",
                "jira.issue.custom_field.set",
                "--input-json",
                &request.to_string(),
            ],
            "jira_custom_field_not_allowed",
        );
        assert!(backend.custom_field_updates.lock().unwrap().is_empty());
        assert_credential_observations(&backend, &[("issue_metadata", "jira-lookup-token")]);
        let audit = broker.audit().unwrap().text();
        assert!(audit.contains("jira_custom_field_not_allowed"));
        assert!(audit.contains(requested));
        assert!(!audit.contains(PRIVATE));
        stop(broker).await;
    }
}

async fn rpc_body(response: reqwest::Response) -> Value {
    assert!(response.status().is_success(), "{}", response.status());
    let body = response.text().await.unwrap();
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(&body).unwrap();
    }
    let responses = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|value| value.get("id").is_some())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 1, "{body}");
    responses.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_custom_field_missing_value_and_size_are_visible_across_invoke_send_and_mcp() {
    let backend = backend();
    let broker = start(backend.clone(), &[FIELD]).await;
    let base = broker.public_url();
    let initialize = json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"custom-field-smoke","version":"1"}});
    let mut stdio = list_mcp::StdioMcp::start(command(&base));
    assert!(
        stdio
            .request("initialize", initialize.clone())
            .await
            .get("error")
            .is_none()
    );
    stdio.notify("notifications/initialized", json!({}));
    let listing = stdio.request("tools/list", json!({})).await;
    let name = agent_access_core::mcp::tool_name("jira", ACTION);
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap();
    let described = stdio
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"jira","action":ACTION}}),
        )
        .await;
    assert_eq!(described["result"]["structuredContent"]["readOnly"], false);
    assert_eq!(
        tool["inputSchema"]["properties"]["inputs"]["required"],
        json!(["fieldId", "value"])
    );
    let client = reqwest::Client::new();
    let endpoint = format!("{base}/mcp");
    let rpc = |message: Value, session: Option<&str>| {
        let mut request = client
            .post(&endpoint)
            .bearer_auth("agent-token")
            .header("Accept", "application/json, text/event-stream")
            .json(&message);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        request
    };
    let initialized = rpc(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":initialize}),
        None,
    )
    .send()
    .await
    .unwrap();
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        rpc_body(initialized).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    assert!(
        rpc(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            Some(&session)
        )
        .send()
        .await
        .unwrap()
        .status()
        .is_success()
    );
    let http_listing = rpc_body(
        rpc(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            Some(&session),
        )
        .send()
        .await
        .unwrap(),
    )
    .await;
    let http_tool = http_listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap();
    let described = rpc_body(rpc(json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"actions_describe","arguments":{"service":"jira","action":ACTION}}}), Some(&session)).send().await.unwrap()).await;
    assert_eq!(described["result"]["structuredContent"]["readOnly"], false);
    assert_eq!(
        http_tool["inputSchema"]["properties"]["inputs"]["required"],
        json!(["fieldId", "value"])
    );
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    for (index, (request, reason)) in [
        (json!({"issue":"PROJ-1","fieldId":FIELD}), "input_invalid"),
        (
            inputs(json!(PRIVATE.repeat(BODY_LIMIT))),
            "body_size_denied",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        refused(
            &base,
            &[
                "invoke",
                "jira.issue.custom_field.set",
                "--input-json",
                &request.to_string(),
            ],
            reason,
        );
        refused(
            &base,
            &["send", "--request-json", &send(&request).to_string()],
            reason,
        );
        let called = stdio
            .request(
                "tools/call",
                json!({"name":name,"arguments":{"inputs":request}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true, "{called}");
        denial(&called["result"]["structuredContent"], reason);
        let called = rpc_body(rpc(json!({"jsonrpc":"2.0","id":3+index,"method":"tools/call","params":{"name":name,"arguments":{"inputs":request}}}), Some(&session)).send().await.unwrap()).await;
        assert_eq!(called["result"]["isError"], true, "{called}");
        denial(&called["result"]["structuredContent"], reason);
        if index == 0 {
            assert!(
                backend.credential_observations.lock().unwrap().is_empty(),
                "missing value must not perform even a scope lookup"
            );
        } else {
            assert_credential_observations(&backend, &[("issue_metadata", "jira-lookup-token"); 4]);
        }
        assert!(backend.custom_field_updates.lock().unwrap().is_empty());
    }
    // Explicit null is accepted by both MCP surfaces, unlike omitted value.
    let request = inputs(Value::Null);
    let called = stdio
        .request(
            "tools/call",
            json!({"name":name,"arguments":{"inputs":request}}),
        )
        .await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    acknowledgement(&called["result"]["structuredContent"]);
    let called = rpc_body(rpc(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":name,"arguments":{"inputs":request}}}), Some(&session)).send().await.unwrap()).await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    acknowledgement(&called["result"]["structuredContent"]);
    assert_eq!(
        *backend.custom_field_updates.lock().unwrap(),
        vec![(ISSUE_ID.to_string(), FIELD.to_string(), Value::Null); 2]
    );
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("body_size_denied"));
    assert!(audit.contains("input_invalid"));
    assert!(!audit.contains(PRIVATE));
    stdio.finish().await;
    assert!(
        client
            .delete(&endpoint)
            .bearer_auth("agent-token")
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    stop(broker).await;
}
