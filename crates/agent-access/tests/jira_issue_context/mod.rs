//! View-only Jira context across real Broker admission and public clients.
use super::*;
use serde_json::{Value, json};

pub(super) fn complete_context() -> JiraIssueViewContext {
    JiraIssueViewContext {
        resolution: Some(JiraIssueViewNamedValue {
            id: "resolution-1".into(),
            name: Some("Resolved context".into()),
        }),
        resolution_date: Some("2026-10-23T12:30:00.000+0530".into()),
        due_date: Some("2026-10-30".into()),
        components: Some(vec![
            JiraIssueViewNamedValue {
                id: "component-1".into(),
                name: Some("API context".into()),
            },
            JiraIssueViewNamedValue {
                id: "component-2".into(),
                name: None,
            },
            JiraIssueViewNamedValue {
                id: "component-1".into(),
                name: Some("API context".into()),
            },
        ]),
        fix_versions: Some(vec![JiraIssueViewNamedValue {
            id: "release-1".into(),
            name: Some("Release context".into()),
        }]),
        affected_versions: Some(vec![]),
        status_category: Some(JiraIssueViewStatusCategory {
            id: 3,
            key: "custom-done".into(),
            name: Some("Completed context".into()),
        }),
        parent: Some(JiraIssueViewReference {
            key: "PARENT-42".into(),
            summary: Some("PARENT_CONTEXT_SENTINEL".into()),
            issue_type: Some("Story".into()),
        }),
        subtasks: Some(vec![
            JiraIssueViewReference {
                key: "CHILD-42".into(),
                summary: Some("CHILD_CONTEXT_SENTINEL".into()),
                issue_type: Some("Sub-task".into()),
            },
            JiraIssueViewReference {
                key: "CHILD-42".into(),
                summary: Some("CHILD_CONTEXT_SENTINEL".into()),
                issue_type: Some("Sub-task".into()),
            },
        ]),
    }
}

pub(super) fn assert_context(result: &Value, disclose: bool) {
    assert_eq!(
        result["resolution"],
        json!({"id":"resolution-1","name":"Resolved context"})
    );
    assert_eq!(result["resolutionDate"], "2026-10-23T12:30:00.000+0530");
    assert_eq!(result["dueDate"], "2026-10-30");
    assert_eq!(
        result["components"],
        json!([
            {"id":"component-1","name":"API context"}, {"id":"component-2","name":null}, {"id":"component-1","name":"API context"}
        ])
    );
    assert_eq!(
        result["fixVersions"],
        json!([{"id":"release-1","name":"Release context"}])
    );
    assert_eq!(result["affectedVersions"], json!([]));
    assert_eq!(
        result["statusCategory"],
        json!({"id":3,"key":"custom-done","name":"Completed context"})
    );
    if disclose {
        assert_eq!(
            result["parent"],
            json!({"key":"PARENT-42","summary":"PARENT_CONTEXT_SENTINEL","issueType":"Story"})
        );
        assert_eq!(
            result["subtasks"],
            json!([
                {"key":"CHILD-42","summary":"CHILD_CONTEXT_SENTINEL","issueType":"Sub-task"},
                {"key":"CHILD-42","summary":"CHILD_CONTEXT_SENTINEL","issueType":"Sub-task"}
            ])
        );
    } else {
        for key in ["parent", "subtasks"] {
            assert!(result.get(key).is_none());
        }
        for secret in [
            "PARENT-42",
            "CHILD-42",
            "PARENT_CONTEXT_SENTINEL",
            "CHILD_CONTEXT_SENTINEL",
        ] {
            assert!(!result.to_string().contains(secret));
        }
    }
    assert!(result.get("epic").is_none());
}

fn assert_context_markdown(markdown: &str, disclose: bool) {
    for text in [
        "resolution-1",
        "Resolved context",
        "2026-10-23T12:30:00.000+0530",
        "2026-10-30",
        "## Components",
        "component-2",
        "## Fix versions",
        "Release context",
        "## Affected versions\n\nNone.",
        "custom-done",
        "Completed context",
    ] {
        assert!(markdown.contains(text), "missing {text} in {markdown}");
    }
    for section in ["## Parent", "## Subtasks"] {
        assert_eq!(markdown.contains(section), disclose);
    }
    for secret in ["PARENT-42", "CHILD-42"] {
        assert_eq!(markdown.contains(secret), disclose);
    }
    assert!(!markdown.to_lowercase().contains("epic children"));
}

fn context_backend() -> Arc<StubJiraBackend> {
    let mut backend = renamed_issue_backend("PROJ-1", "PROJ-1", "PROJ", "Context source");
    *backend.issue_view_context.lock().unwrap() = complete_context();
    *backend.issue_view_links.lock().unwrap() = Some(vec![JiraIssueViewLink {
        key: "LINK-42".into(),
        link_type: "Blocks".into(),
        direction: JiraIssueLinkDirection::Outward,
        relationship: "blocks".into(),
        summary: Some("LINK_CONTEXT_SENTINEL".into()),
        issue_type: None,
    }]);
    backend.custom_fields.clear();
    Arc::new(backend)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_crosses_typed_invoke_send_and_http_with_unchanged_credentials_and_call_counts() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let disclose = matches!(access, JiraAccess::AgentPerUser);
        let backend = context_backend();
        let broker = start_broker(
            access,
            jira_service(jira_provider_config(2), Default::default(), backend.clone()),
        )
        .await;
        let base_url = broker.public_url();
        let mut cursor = 0;
        for args in [
            vec!["jira", "issue", "view", "PROJ-1"],
            vec![
                "invoke",
                "jira.issue.view",
                "--input-json",
                r#"{"issue":"PROJ-1"}"#,
                "--read-content-format",
                "markdown",
            ],
        ] {
            let normalized = args.contains(&"--read-content-format");
            let output = authenticated_jira_cli(&base_url)
                .args(args)
                .output()
                .unwrap();
            assert_success("Jira issue context", &output);
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_context(&response["result"], disclose);
            assert_eq!(response["result"].get("issueLinks").is_some(), disclose);
            assert_eq!(response["result"].get("renderedBody").is_some(), normalized);
            assert_new_backend_operations(
                &backend,
                &mut cursor,
                &["issue_metadata", "issue_metadata", "issue"],
            );
        }
        let request = temp_path("jira-issue-context-send.json");
        std::fs::write(&request, json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"PROJ-1"},"responseFormat":"markdown"}).to_string()).unwrap();
        let output = authenticated_jira_cli(&base_url)
            .args(["send", "--request-file", request.to_str().unwrap()])
            .output()
            .unwrap();
        assert_success("Jira context Markdown", &output);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_context_markdown(response["result"]["value"].as_str().unwrap(), disclose);
        std::fs::remove_file(request).unwrap();
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );

        let response = reqwest::Client::new()
            .post(format!("{base_url}/v1/invoke/jira/issue.view"))
            .header("X-Agent-Access-Identity-Token", "agent-token")
            .header(REQUEST_ID_HEADER, "jira-issue-context-http")
            .json(&json!({"inputs":{"issue":"PROJ-1"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let response: Value = response.json().await.unwrap();
        assert_context(&response["result"], disclose);
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );
        let (lookup, execution) = if disclose {
            ("jira-per-user-token", "jira-per-user-token")
        } else {
            ("jira-lookup-token", "jira-token")
        };
        let expected = [
            ("issue_metadata", lookup),
            ("issue_metadata", lookup),
            ("issue", execution),
        ]
        .repeat(4);
        assert_credential_observations(&backend, &expected);
        assert_eq!(
            *backend.issue_view_requests.lock().unwrap(),
            vec![disclose; 4]
        );
        let audit = broker.audit().unwrap();
        audit.require_action("jira", "issue.view");
        assert_audit_has_no_context(&audit.text());
        stop(broker).await;
    }
}

fn assert_audit_has_no_context(audit: &str) {
    for secret in [
        "PARENT-42",
        "CHILD-42",
        "LINK-42",
        "CONTEXT_SENTINEL",
        "Resolved context",
        "API context",
        "Release context",
        "custom-done",
        "Completed context",
    ] {
        assert!(!audit.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_and_links_share_exclusion_union_and_competing_mode_admission() {
    for (case, disclose) in [
        ("exclusion", false),
        ("restored-union", true),
        ("competing-mode", false),
    ] {
        let backend = context_backend();
        let application = IsolatedBroker::new(
            agent_access_broker::composition().unwrap(),
            agent_access_broker::build_identity(),
        )
        .unwrap();
        let access = if case == "competing-mode" {
            JiraAccess::AgentPerUser
        } else {
            JiraAccess::AgentService
        };
        let mut document = jira_document(application.directory(), access);
        if case == "competing-mode" {
            // The source PROJ read still selects service access, but OTHER's
            // higher-precedence user grant selects a different credential mode.
            document = document.replace(
                "resources = { resource_ids = [\"all-projects\"] }",
                "resources = { resource_ids = [\"project-other\"] }",
            );
        }
        document.push_str(&format!(
            r#"
[[policy.resources]]
id = "project-other"
resource_type = "{}"
selector = {{ kind = "exact", value = "OTHER" }}
allowed_execution_contexts = ["default"]

[[policy.resource_groups]]
id = "except-other"
name = "All except OTHER"
included_resource_ids = ["all-projects"]
excluded_resource_ids = ["project-other"]

[[policy.grants]]
subjects = ["group:agents"]
service = "jira"
actions = ["issue.view"]
resources = {{ {} }}
credential_mode = "service"
"#,
            JIRA_PROJECT_RESOURCE.id().as_str(),
            if case == "competing-mode" {
                "resource_ids = [\"all-projects\"]"
            } else {
                "resource_group_ids = [\"except-other\"]"
            }
        ));
        if case == "restored-union" {
            document.push_str(
                r#"
[[policy.grants]]
subjects = ["group:agents"]
service = "jira"
actions = ["issue.view"]
resources = { resource_ids = ["project-other"] }
credential_mode = "service"
"#,
            );
        }
        let broker = application
            .config_document(document)
            .provider_fixture(
                "jira",
                ProviderFixture::instance(jira_service(
                    jira_provider_config(2),
                    Default::default(),
                    backend.clone(),
                )),
            )
            .start()
            .await
            .unwrap();
        let output = authenticated_jira_cli(&broker.public_url())
            .args(["jira", "issue", "view", "PROJ-1"])
            .output()
            .unwrap();
        assert_success(case, &output);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_context(&response["result"], disclose);
        assert_eq!(response["result"].get("issueLinks").is_some(), disclose);
        assert_eq!(*backend.issue_view_requests.lock().unwrap(), vec![disclose]);
        assert_new_backend_operations(
            &backend,
            &mut 0,
            &["issue_metadata", "issue_metadata", "issue"],
        );
        assert_credential_observations(
            &backend,
            &[
                ("issue_metadata", "jira-lookup-token"),
                ("issue_metadata", "jira-lookup-token"),
                ("issue", "jira-token"),
            ],
        );
        let audit = broker.audit().unwrap();
        audit.require_action("jira", "issue.view");
        assert_audit_has_no_context(&audit.text());
        stop(broker).await;
    }
}

fn assert_eligible_mcp_context(response: &Value, parent_returned: bool) {
    assert_eq!(response["result"]["isError"], false, "{response}");
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(envelope["decision"], "allow");
    let result = &envelope["result"];
    let mut expected = serde_json::to_value(complete_context()).unwrap();
    if !parent_returned {
        expected["parent"] = Value::Null;
    }
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(result.get(key), Some(value), "{key}");
    }
    assert_eq!(
        result["issueLinks"],
        json!([{
            "key":"LINK-42", "type":"Blocks", "direction":"outward",
            "relationship":"blocks", "summary":"LINK_CONTEXT_SENTINEL", "issueType":null
        }])
    );
    assert!(result.get("epic").is_none());
    if !parent_returned {
        assert!(!result.to_string().contains("PARENT_CONTEXT_SENTINEL"));
    }
    let text_copy: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text_copy, envelope);
}

fn assert_per_user_mcp_calls(backend: &StubJiraBackend, cursor: &mut usize, calls: usize) {
    assert_new_backend_operations(
        backend,
        cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );
    assert_credential_observations(
        backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("issue", "jira-per-user-token"),
        ]
        .repeat(calls),
    );
    assert_eq!(
        *backend.issue_view_requests.lock().unwrap(),
        vec![true; calls]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_mcp_discloses_authorized_hierarchy_and_preserves_null_parent() {
    use super::custom_fields::{StdioMcp, start_mcp_broker};

    let backend = context_backend();
    let broker =
        start_mcp_broker(JiraAccess::AgentPerUser, backend.clone(), 16 * 1024 * 1024).await;
    let mut stdio = StdioMcp::start(&broker.public_url());
    let initialize = stdio
        .request(
            "initialize",
            json!({
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"jira-issue-context-smoke","version":"1"}
            }),
        )
        .await;
    assert!(initialize.get("error").is_none());
    stdio.notify("notifications/initialized", json!({}));
    let mut cursor = 0;
    for (index, parent_returned) in [true, false].into_iter().enumerate() {
        if !parent_returned {
            backend.issue_view_context.lock().unwrap().parent = None;
        }
        let response = stdio
            .request(
                "tools/call",
                json!({
                    "name":agent_access_core::mcp::tool_name("jira","issue.view"),
                    "arguments":{"inputs":{"issue":"PROJ-1"}}
                }),
            )
            .await;
        assert_eligible_mcp_context(&response, parent_returned);
        assert_per_user_mcp_calls(&backend, &mut cursor, index + 1);
    }
    stdio.finish().await;
    let audit = broker.audit().unwrap();
    audit.require_action("jira", "issue.view");
    assert_audit_has_no_context(&audit.text());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_mcp_discloses_authorized_hierarchy_and_preserves_null_parent() {
    use super::custom_fields::{http_mcp_call, initialize_http_mcp, start_mcp_broker};

    let backend = context_backend();
    let broker =
        start_mcp_broker(JiraAccess::AgentPerUser, backend.clone(), 16 * 1024 * 1024).await;
    let base_url = broker.public_url();
    let (client, session) = initialize_http_mcp(&base_url).await;
    let mut cursor = 0;
    for (index, parent_returned) in [true, false].into_iter().enumerate() {
        if !parent_returned {
            backend.issue_view_context.lock().unwrap().parent = None;
        }
        let response = http_mcp_call(&client, &base_url, &session, 2 + index).await;
        assert_eligible_mcp_context(&response, parent_returned);
        assert_per_user_mcp_calls(&backend, &mut cursor, index + 1);
    }
    let audit = broker.audit().unwrap();
    audit.require_action("jira", "issue.view");
    assert_audit_has_no_context(&audit.text());
    stop(broker).await;
}
