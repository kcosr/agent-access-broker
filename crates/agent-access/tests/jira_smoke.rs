#[path = "jira_smoke/project_list.rs"]
mod project_listing;
#[path = "jira_smoke/project_view.rs"]
mod project_view;
use agent_access_broker_host::test_support::{
    FixtureDir, IsolatedBroker, ProviderFixture, RunningBroker,
};
use agent_access_jira::{
    JIRA_PROJECT_RESOURCE, JiraAttachment, JiraAttachmentContent, JiraAttachmentUpload,
    JiraBackend, JiraBackendError, JiraBackendResponse, JiraComment, JiraCommentAddRequest,
    JiraCommentListRequest, JiraCommentPage, JiraCommentPropertyKeys, JiraCommentSummary,
    JiraCommentUpdateRequest, JiraCreatedIssue, JiraIssue, JiraIssueAttachmentList,
    JiraIssueCreateRequest, JiraIssueLink, JiraIssueLinkCreateRequest, JiraIssueLinkDirection,
    JiraIssueLinkType, JiraIssueLinks, JiraIssueParent, JiraIssueParentReadback,
    JiraIssueParentSetRequest, JiraIssueType, JiraIssueTypeListRequest, JiraIssueTypePage,
    JiraIssueUpdateRequest, JiraIssueView, JiraIssueViewContext, JiraIssueViewLink,
    JiraIssueViewNamedValue, JiraIssueViewReference, JiraIssueViewStatusCategory,
    JiraPrioritySummary, JiraProvider, JiraProviderConfig, JiraSearchPage, JiraSearchRequest,
    JiraUserSummary,
};
use agent_access_provider::test_support::basic_credential;
use agent_access_provider::{REQUEST_ID_HEADER, RESULT_METADATA_HEADER, SearchLimitsConfig};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// The Jira provider around `backend`, paired with its configuration's
/// descriptor.
fn jira_service(
    config: agent_access_jira::JiraProviderConfig,
    limits: agent_access_provider::ProviderLimits,
    backend: Arc<dyn agent_access_jira::JiraBackend>,
) -> agent_access_provider::ServiceProvider {
    agent_access_provider::ServiceProvider::new(
        agent_access_jira::jira_descriptor(&config),
        Arc::new(JiraProvider::with_backend(config, limits, backend)),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_issue_type_discovery_surfaces_paging_authorization_and_create() {
    use serde_json::json;
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([(
            "PROJ-1".to_string(),
            JiraIssue {
                id: "20001".to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: Some("Created from discovery".to_string()),
                issue_type: Some("Task".to_string()),
                status: None,
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
        created_issue: Mutex::new(Some(JiraCreatedIssue {
            id: "20001".to_string(),
            key: "PROJ-1".to_string(),
        })),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AgentService,
        jira_service(jira_provider_config(2), Default::default(), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let run = |args: &[&str]| {
        let output = authenticated_jira_cli(&base_url)
            .args(args)
            .output()
            .unwrap();
        assert_success("issue type discovery", &output);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let catalog = run(&["spec", "catalog"]);
    let action = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "issue_type.list")
        .unwrap();
    assert_eq!(action["readOnly"], true);
    assert_eq!(action["lookupRequired"], false);
    assert_eq!(action["requiredScopeTypes"], json!(["project"]));
    assert_eq!(action["inputSchema"]["required"], json!(["project"]));
    let typed_catalog: agent_access_core::ApiCatalog = serde_json::from_value(catalog).unwrap();
    for mode in [
        agent_access_core::mcp::ProjectionMode::Http,
        agent_access_core::mcp::ProjectionMode::Stdio,
    ] {
        let tools = agent_access_core::mcp::project_catalog(&typed_catalog, mode).unwrap();
        let name = agent_access_core::mcp::tool_name("jira", "issue_type.list");
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        assert_eq!(tool["_meta"]["agent-access/action"], "issue_type.list");
        assert_eq!(
            tool["inputSchema"]["properties"]["inputs"]["required"],
            json!(["project"])
        );
    }
    let openapi = run(&["spec", "openapi"]);
    assert_eq!(
        openapi["paths"]["/v1/invoke/jira/issue_type.list"]["post"]["x-agent-access-read-only"],
        true
    );
    let schema = run(&["spec", "send-schema"]);
    let variant = schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"] == "jira"
                && variant["properties"]["action"]["const"] == "issue_type.list"
        })
        .unwrap();
    assert_eq!(variant["x-agent-access-read-only"], true);
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    let first = run(&[
        "jira",
        "issue-type",
        "list",
        "--project",
        "PROJ",
        "--max-results",
        "1",
    ]);
    assert_eq!(
        first["result"]["issueTypes"],
        json!([{
            "id":"10001", "name":"Task", "description":"Work to complete", "subtask":false
        }])
    );
    assert_eq!(first["result"]["nextStartAt"], 1);
    assert_eq!(first["result"]["isLast"], false);
    let second = run(&[
        "jira",
        "issue-type",
        "list",
        "--project",
        "PROJ",
        "--start-at",
        "1",
        "--max-results",
        "1",
    ]);
    assert_eq!(second["result"]["issueTypes"][0]["subtask"], true);
    assert_eq!(second["result"]["issueTypes"][0]["description"], "");
    assert_eq!(second["result"]["isLast"], true);
    assert!(second["result"]["nextStartAt"].is_null());
    let invoked = run(&[
        "invoke",
        "jira.issue_type.list",
        "--input-json",
        r#"{"project":"PROJ"}"#,
    ]);
    assert_eq!(invoked["result"]["maxResults"], 50);
    assert_eq!(invoked["result"]["count"], 2);
    let request_path = temp_path("jira-issue-types-send.json");
    std::fs::write(
        &request_path,
        json!({
            "version":"agent-access.send.v1", "kind":"invoke", "service":"jira",
            "action":"issue_type.list", "inputs":{"project":"PROJ"}
        })
        .to_string(),
    )
    .unwrap();
    let sent = run(&["send", "--request-file", request_path.to_str().unwrap()]);
    assert_eq!(sent["result"], invoked["result"]);
    std::fs::remove_file(request_path).unwrap();

    let client = reqwest::Client::new();
    let http = client
        .post(format!("{base_url}/v1/invoke/jira/issue_type.list"))
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .header(REQUEST_ID_HEADER, "jira-issue-types-http")
        .json(&json!({"inputs":{"project":"PROJ"}}))
        .send()
        .await
        .unwrap();
    let status = http.status();
    let http: serde_json::Value = http.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{http}");
    assert_eq!(http["result"], invoked["result"]);
    let markdown = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue-type",
            "list",
            "--project",
            "PROJ",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("issue type Markdown", &markdown);
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.contains("10001"));
    assert!(markdown.contains("Work to complete"));
    let calls = backend.credential_observations.lock().unwrap().len();
    let denied = client
        .post(format!("{base_url}/v1/invoke/jira/issue_type.list"))
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .header(REQUEST_ID_HEADER, "jira-issue-types-denied")
        .json(&json!({"inputs":{"project":"OPS"}}))
        .send()
        .await
        .unwrap();
    let denied_status = denied.status();
    let denied: serde_json::Value = denied.json().await.unwrap();
    assert_eq!(denied_status, reqwest::StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(backend.credential_observations.lock().unwrap().len(), calls);
    let malformed = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue-type",
            "list",
            "--project",
            "PROJ",
            "--max-results",
            "101",
        ])
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert_eq!(backend.credential_observations.lock().unwrap().len(), calls);
    assert!(
        backend
            .credential_observations
            .lock()
            .unwrap()
            .iter()
            .all(|call| call.operation == "issue_types"
                && call.credential == jira_credential("jira-token"))
    );

    let id = first["result"]["issueTypes"][0]["id"].as_str().unwrap();
    let created = run(&[
        "jira",
        "issue",
        "create",
        "--project",
        "PROJ",
        "--issue-type-id",
        id,
        "--summary",
        "Created from discovery",
    ]);
    assert_eq!(created["decision"], "allow");
    assert_eq!(backend.created_issues.lock().unwrap()[0].issue_type_id, id);
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("issue_type.list"));
    assert!(!audit.contains("Work to complete"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_jira_read_actions_against_stubbed_backend() {
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([
            (
                "PROJ-1".to_string(),
                JiraIssue {
                    id: "10001".to_string(),
                    key: "PROJ-1".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("visible summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: Some("2026-06-01T10:00:00.000+0000".to_string()),
                    updated: Some("2026-06-02T11:00:00.000+0000".to_string()),
                    creator: Some(JiraUserSummary {
                        account_id: Some("creator-1".to_string()),
                        display_name: Some("Creator One".to_string()),
                    }),
                    reporter: Some(JiraUserSummary {
                        account_id: Some("reporter-1".to_string()),
                        display_name: Some("Reporter One".to_string()),
                    }),
                    assignee: Some(JiraUserSummary {
                        account_id: Some("assignee-1".to_string()),
                        display_name: Some("Assignee One".to_string()),
                    }),
                    priority: Some(JiraPrioritySummary {
                        id: Some("3".to_string()),
                        name: Some("Medium".to_string()),
                    }),
                    labels: Some(vec!["agent".to_string(), "metadata".to_string()]),
                    description: Some(jira_adf_text("visible issue description")),
                },
            ),
            (
                "PROJ-2".to_string(),
                JiraIssue {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("created issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: Some(jira_adf_text("secret issue description")),
                },
            ),
            (
                "PROJ-3".to_string(),
                JiraIssue {
                    id: "10003".to_string(),
                    key: "PROJ-3".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("blocked issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: None,
                },
            ),
        ]),
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![JiraIssue {
                id: "10001".to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: Some("visible summary".to_string()),
                status: Some("Open".to_string()),
                issue_type: Some("Task".to_string()),
                created: Some("2026-06-01T10:00:00.000+0000".to_string()),
                updated: Some("2026-06-02T11:00:00.000+0000".to_string()),
                creator: Some(JiraUserSummary {
                    account_id: Some("creator-1".to_string()),
                    display_name: Some("Creator One".to_string()),
                }),
                reporter: Some(JiraUserSummary {
                    account_id: Some("reporter-1".to_string()),
                    display_name: Some("Reporter One".to_string()),
                }),
                assignee: Some(JiraUserSummary {
                    account_id: Some("assignee-1".to_string()),
                    display_name: Some("Assignee One".to_string()),
                }),
                priority: Some(JiraPrioritySummary {
                    id: Some("3".to_string()),
                    name: Some("Medium".to_string()),
                }),
                labels: Some(vec!["agent".to_string(), "metadata".to_string()]),
                description: Some(jira_adf_text("search issue description")),
            }],
            max_results: 2,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        last_search: Mutex::new(None),
        issue_link_types: Mutex::new(vec![JiraIssueLinkType {
            name: "Blocks".to_string(),
            outward: "blocks".to_string(),
            inward: "is blocked by".to_string(),
        }]),
        issue_link_readbacks: Mutex::new(BTreeMap::from([(
            "PROJ-2".to_string(),
            JiraIssueLinks {
                issue: agent_access_jira::JiraIssueMetadata {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                },
                links: vec![JiraIssueLink {
                    link_type: "Blocks".to_string(),
                    outward_issue: Some("PROJ-3".to_string()),
                    inward_issue: None,
                }],
            },
        )])),
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "evidence.txt".to_string(),
            size: 16,
            content_type: "text/plain".to_string(),
        }]),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AnonymousService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();

    let issue = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "view",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        issue.status.success(),
        "issue view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&issue.stdout),
        String::from_utf8_lossy(&issue.stderr)
    );
    let issue_json: serde_json::Value = serde_json::from_slice(&issue.stdout).unwrap();
    assert_eq!(issue_json["decision"], "allow");
    assert_eq!(issue_json["result"]["key"], "PROJ-1");
    assert_eq!(issue_json["result"]["summary"], "visible summary");
    assert_eq!(
        issue_json["result"]["created"],
        "2026-06-01T10:00:00.000+0000"
    );
    assert_eq!(
        issue_json["result"]["creator"]["displayName"],
        "Creator One"
    );
    assert_eq!(issue_json["result"]["assignee"]["accountId"], "assignee-1");
    assert_eq!(issue_json["result"]["priority"]["name"], "Medium");
    assert_eq!(issue_json["result"]["labels"][0], "agent");
    assert_eq!(
        issue_json["result"]["description"]["content"][0]["content"][0]["text"],
        "visible issue description"
    );

    let issue_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "view",
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        issue_by_url.status.success(),
        "issue view by locator URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&issue_by_url.stdout),
        String::from_utf8_lossy(&issue_by_url.stderr)
    );
    let issue_by_url_json: serde_json::Value =
        serde_json::from_slice(&issue_by_url.stdout).unwrap();
    assert_eq!(issue_by_url_json["result"]["key"], "PROJ-1");
    assert_eq!(
        issue_by_url_json["result"]["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );
    assert_eq!(
        issue_by_url_json["result"]["description"]["content"][0]["content"][0]["text"],
        "visible issue description"
    );

    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "search",
            "--text",
            "PROJ-1",
            "--max-results",
            "100",
        ])
        .output()
        .unwrap();
    assert!(
        search.status.success(),
        "search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&search.stdout),
        String::from_utf8_lossy(&search.stderr)
    );
    let search_json: serde_json::Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search_json["decision"], "allow");
    assert_eq!(search_json["result"]["issues"][0]["key"], "PROJ-1");
    assert_eq!(
        search_json["result"]["issues"][0]["updated"],
        "2026-06-02T11:00:00.000+0000"
    );
    assert_eq!(
        search_json["result"]["issues"][0]["reporter"]["displayName"],
        "Reporter One"
    );
    assert_eq!(search_json["result"]["issues"][0]["priority"]["id"], "3");
    assert_eq!(
        search_json["result"]["issues"][0]["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );
    assert!(
        search_json["result"]["issues"][0]
            .get("description")
            .is_none()
    );
    let last_search = backend
        .last_search
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(last_search.jql, "(key = PROJ-1) AND project IN (PROJ)");
    assert_eq!(last_search.projects, vec!["PROJ"]);
    assert_eq!(last_search.max_results, 2);

    for (query, expected) in [
        ("", "project IN (PROJ)"),
        (
            "ORDER BY updated DESC",
            "project IN (PROJ) ORDER BY updated DESC",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--no-token",
                "jira",
                "issue",
                "search",
                "--jql",
                query,
            ])
            .output()
            .unwrap();
        assert_success("scope-only Jira search without explicit projects", &output);
        assert_eq!(
            backend.last_search.lock().unwrap().as_ref().unwrap().jql,
            expected
        );
    }

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "list",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list_json["decision"], "allow");
    assert_eq!(
        list_json["result"]["attachments"][0]["attachmentId"],
        "10055"
    );
    assert_eq!(
        list_json["result"]["attachments"][0]["filename"],
        "evidence.txt"
    );

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"service\":\"jira\""));
    assert!(audit.contains("\"action\":\"issue.view\""));
    assert!(audit.contains("\"action\":\"search\""));
    assert!(audit.contains("\"action\":\"attachment.list\""));
    assert!(audit.contains("\"objectIds\""));
    assert!(!audit.contains("visible summary"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_issue_links_require_universal_token_authority_and_preserve_absence() {
    use agent_access_core::{
        BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
        ManagedResourceCatalog, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
        PrincipalRole, PrincipalWriteRequest,
    };
    use serde_json::json;

    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([(
            "PROJ-1".to_string(),
            JiraIssue {
                id: "10001".to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: Some("Source issue".to_string()),
                status: None,
                issue_type: Some("Task".to_string()),
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
        issue_view_context: Mutex::new(issue_context::complete_context()),
        issue_view_links: Mutex::new(Some(vec![
            JiraIssueViewLink {
                key: "CM-42".to_string(),
                link_type: "Blocks".to_string(),
                direction: JiraIssueLinkDirection::Outward,
                relationship: "blocks".to_string(),
                summary: Some("Linked release title".to_string()),
                issue_type: Some("Change".to_string()),
            },
            JiraIssueViewLink {
                key: "OPS-7".to_string(),
                link_type: "Blocks".to_string(),
                direction: JiraIssueLinkDirection::Inward,
                relationship: "is blocked by".to_string(),
                summary: None,
                issue_type: None,
            },
        ])),
        ..StubJiraBackend::default()
    });
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let key = directory
        .secret_file(
            "broker-key",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([37_u8; 32]),
        )
        .unwrap();
    let store_path = directory.join("tokens.sqlite");
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "agent-one".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    })
    .unwrap();
    // Token restrictions reference this fixture's TOML-owned catalog, which
    // is not mirrored into the managed store used for token storage.
    let catalog: ManagedResourceCatalog = serde_json::from_value(json!({
        "resources": [{
            "id": "project-proj",
            "resourceType": JIRA_PROJECT_RESOURCE.id().as_str(),
            "selector": {"kind": "exact", "value": "PROJ"},
            "allowedExecutionContexts": ["default"],
            "enabled": true
        }],
        "resourceGroups": []
    }))
    .unwrap();
    let issue_token = |name: &str, restriction: serde_json::Value| {
        store
            .issue_broker_token_with_catalog(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "agent-one".to_string(),
                    name: name.to_string(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedExecutionContexts": ["default"],
                        "allowedServices": ["jira"],
                        "serviceRestrictions": {"jira": restriction}
                    }),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
                Some(&catalog),
            )
            .unwrap()
            .token
    };
    let unrestricted_token = issue_token("all-projects", json!({"actions": ["issue.view"]}));
    let scoped_token = issue_token(
        "one-project",
        json!({
            "actions": ["issue.view"],
            "resources": {"resourceIds": ["project-proj"]}
        }),
    );
    drop(store);
    // Keep the existing positive PROJ grant as well as the all-projects grant.
    // Universal access is effective coverage, not a single grant shape.
    let base_document = jira_document(&directory, JiraAccess::AnonymousService)
        .replace(
            "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"",
            "[identity]\nmode = \"required\"\nauthority = \"managed\"",
        )
        .replace("group:anonymous", "user:agent-one")
        .replace(
            "credential_mode = \"service\"",
            "credential_mode = \"service\"\nexecution_contexts = [\"default\"]",
        );
    let document = format!(
        r#"{base}
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[execution_context]
allowed_values = ["default"]
default_context = "default"

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true

[broker_tokens]
hash_key_ref = {hash_key}

[credential_encryption]
active_key = "test"
[[credential_encryption.keys]]
id = "test"
provider = "file"
path = {key}

[[policy.grants]]
subjects = ["user:agent-one"]
service = "jira"
actions = ["issue.view"]
resources = {{ resource_ids = ["all-projects"] }}
credential_mode = "service"
execution_contexts = ["default"]
"#,
        base = base_document,
        store = toml_string(store_path.display()),
        hash_key = toml_string(format!("file:{}", key.display())),
        key = toml_string(key.display()),
    );
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
    let base_url = broker.public_url();
    let run = |token: &str, format: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--token-value",
                token,
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "jira",
                "issue",
                "view",
                "PROJ-1",
                "--output-format",
                format,
            ])
            .output()
            .unwrap();
        assert_success("Jira linked issue view", &output);
        output.stdout
    };
    let mut cursor = 0;
    let result: serde_json::Value =
        serde_json::from_slice(&run(&unrestricted_token, "json")).unwrap();
    assert_eq!(
        result["result"]["issueLinks"],
        json!([
            {"key": "CM-42", "type": "Blocks", "direction": "outward",
             "relationship": "blocks", "summary": "Linked release title", "issueType": "Change"},
            {"key": "OPS-7", "type": "Blocks", "direction": "inward",
             "relationship": "is blocked by", "summary": null, "issueType": null}
        ])
    );
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );
    issue_context::assert_context(&result["result"], true);
    let markdown = String::from_utf8(run(&unrestricted_token, "markdown")).unwrap();
    assert!(markdown.contains("## Issue links"));
    assert!(markdown.contains("## Parent"));
    assert!(markdown.contains("## Subtasks"));
    assert!(markdown.contains("PARENT-42"));
    assert!(markdown.contains("CHILD-42"));
    for text in [
        "CM-42",
        "Linked release title",
        "Change",
        "OPS-7",
        "is blocked by",
    ] {
        assert!(markdown.contains(text), "{markdown}");
    }
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );
    let scoped: serde_json::Value = serde_json::from_slice(&run(&scoped_token, "json")).unwrap();
    assert!(scoped["result"].get("issueLinks").is_none(), "{scoped}");
    assert_eq!(scoped["result"]["summary"], "Source issue");
    issue_context::assert_context(&scoped["result"], false);
    let scoped_markdown = String::from_utf8(run(&scoped_token, "markdown")).unwrap();
    assert!(!scoped_markdown.contains("## Issue links"));
    assert!(!scoped_markdown.contains("## Parent"));
    assert!(!scoped_markdown.contains("## Subtasks"));
    assert!(!scoped_markdown.contains("PARENT-42"));
    assert!(!scoped_markdown.contains("CHILD-42"));
    for text in ["CM-42", "OPS-7", "Linked release title", "is blocked by"] {
        assert!(!scoped_markdown.contains(text), "{scoped_markdown}");
    }
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &[
            "issue_metadata",
            "issue_metadata",
            "issue",
            "issue_metadata",
            "issue_metadata",
            "issue",
        ],
    );

    *backend.issue_view_links.lock().unwrap() = Some(vec![]);
    {
        let mut context = backend.issue_view_context.lock().unwrap();
        context.parent = None;
        context.subtasks = Some(vec![]);
    }
    let empty: serde_json::Value =
        serde_json::from_slice(&run(&unrestricted_token, "json")).unwrap();
    assert_eq!(empty["result"]["issueLinks"], json!([]));
    assert_eq!(
        empty["result"].get("parent"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(empty["result"]["subtasks"], json!([]));
    let empty_markdown = String::from_utf8(run(&unrestricted_token, "markdown")).unwrap();
    assert!(empty_markdown.contains("## Issue links\n\nNone."));
    assert!(empty_markdown.contains("## Parent\n\nNo parent returned."));
    assert!(empty_markdown.contains("## Subtasks\n\nNone."));
    *backend.issue_view_links.lock().unwrap() = None;
    backend.issue_view_context.lock().unwrap().subtasks = None;
    let absent: serde_json::Value =
        serde_json::from_slice(&run(&unrestricted_token, "json")).unwrap();
    assert!(absent["result"].get("issueLinks").is_none(), "{absent}");
    assert!(absent["result"].get("subtasks").is_none());
    assert_eq!(
        absent["result"].get("parent"),
        Some(&serde_json::Value::Null)
    );
    let absent_markdown = String::from_utf8(run(&unrestricted_token, "markdown")).unwrap();
    assert!(!absent_markdown.contains("## Issue links"));
    assert!(!absent_markdown.contains("## Subtasks"));
    assert!(absent_markdown.contains("No parent returned."));
    assert_eq!(
        *backend.issue_view_requests.lock().unwrap(),
        vec![true, true, false, false, true, true, true, true]
    );
    assert_new_backend_operations(
        &backend,
        &mut cursor,
        &[
            "issue_metadata",
            "issue_metadata",
            "issue",
            "issue_metadata",
            "issue_metadata",
            "issue",
            "issue_metadata",
            "issue_metadata",
            "issue",
            "issue_metadata",
            "issue_metadata",
            "issue",
        ],
    );
    let audit = broker.audit().unwrap().text();
    for hidden in [
        "Linked release title",
        "CM-42",
        "OPS-7",
        "PARENT-42",
        "CHILD-42",
        "CONTEXT_SENTINEL",
        "API context",
        "Resolved context",
    ] {
        assert!(!audit.contains(hidden), "{audit}");
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_normalized_reads_work_across_cli_send_and_http_without_extra_provider_calls() {
    const ISSUE_BODY: &str = "normalizedreadissuebody";
    const COMMENT_BODY: &str = "normalizedreadcommentbody";
    const SEARCH_BODY: &str = "bodyfreesearchmustnotrenderthis";

    let issue = JiraIssue {
        id: "10001".to_string(),
        key: "PROJ-1".to_string(),
        project: "PROJ".to_string(),
        summary: Some("Normalized read issue".to_string()),
        status: Some("Open".to_string()),
        issue_type: Some("Task".to_string()),
        created: None,
        updated: None,
        creator: None,
        reporter: None,
        assignee: None,
        priority: None,
        labels: None,
        description: Some(jira_adf_text(ISSUE_BODY)),
    };
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([("PROJ-1".to_string(), issue.clone())]),
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![JiraIssue {
                description: Some(jira_adf_text(SEARCH_BODY)),
                ..issue
            }],
            max_results: 2,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AgentService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();
    let mut provider_call_cursor = 0;

    let native = authenticated_jira_cli(&base_url)
        .args(["jira", "issue", "view", "PROJ-1"])
        .output()
        .unwrap();
    assert_success("native issue view", &native);
    let native_json: serde_json::Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(
        native_json["result"]["description"]["content"][0]["content"][0]["text"],
        ISSUE_BODY
    );
    assert!(native_json["result"].get("renderedBody").is_none());
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let typed_embedded = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue",
            "view",
            "PROJ-1",
            "--read-content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed embedded issue view", &typed_embedded);
    let typed_embedded_json: serde_json::Value =
        serde_json::from_slice(&typed_embedded.stdout).unwrap();
    assert_eq!(
        typed_embedded_json["result"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_BODY})
    );
    assert_eq!(
        typed_embedded_json["result"]["description"]["content"][0]["content"][0]["text"],
        ISSUE_BODY
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let typed_markdown = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue",
            "view",
            "PROJ-1",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed Markdown issue view", &typed_markdown);
    let typed_markdown_stdout = String::from_utf8(typed_markdown.stdout).unwrap();
    assert!(typed_markdown.stderr.is_empty());
    assert!(typed_markdown_stdout.starts_with("# `PROJ-1` — Normalized read issue\n"));
    assert!(typed_markdown_stdout.contains("## Description\n\nnormalizedreadissuebody\n"));
    assert!(!typed_markdown_stdout.contains("\"decision\""));
    assert!(!typed_markdown_stdout.contains("\"type\":\"doc\""));
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let generic_embedded = authenticated_jira_cli(&base_url)
        .args([
            "invoke",
            "jira.issue.view",
            "--input-json",
            r#"{"issue":"PROJ-1"}"#,
            "--read-content-format",
            "text",
        ])
        .output()
        .unwrap();
    assert_success("generic embedded issue view", &generic_embedded);
    let generic_embedded_json: serde_json::Value =
        serde_json::from_slice(&generic_embedded.stdout).unwrap();
    assert_eq!(
        generic_embedded_json["result"]["renderedBody"],
        serde_json::json!({"format":"text", "value":ISSUE_BODY})
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let generic_markdown = authenticated_jira_cli(&base_url)
        .args([
            "invoke",
            "jira.issue.view",
            "--input-json",
            r#"{"issue":"PROJ-1"}"#,
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("generic Markdown issue view", &generic_markdown);
    let generic_markdown_stdout = String::from_utf8(generic_markdown.stdout).unwrap();
    assert!(generic_markdown.stderr.is_empty());
    assert!(generic_markdown_stdout.starts_with("# `PROJ-1` — Normalized read issue\n"));
    assert!(generic_markdown_stdout.contains(ISSUE_BODY));
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let send_embedded_path = temp_path("jira-normalized-read-send-embedded.json");
    std::fs::write(
        &send_embedded_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"PROJ-1"},"readContentFormat":"markdown"}"#,
    )
    .unwrap();
    let send_embedded = authenticated_jira_cli(&base_url)
        .args([
            "send",
            "--request-file",
            send_embedded_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("send embedded issue view", &send_embedded);
    let send_embedded_json: serde_json::Value =
        serde_json::from_slice(&send_embedded.stdout).unwrap();
    assert_eq!(
        send_embedded_json["result"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_BODY})
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let send_markdown_path = temp_path("jira-normalized-read-send-markdown.json");
    std::fs::write(
        &send_markdown_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"PROJ-1"},"responseFormat":"markdown"}"#,
    )
    .unwrap();
    let send_markdown = authenticated_jira_cli(&base_url)
        .args([
            "send",
            "--request-file",
            send_markdown_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("send Markdown issue view", &send_markdown);
    let send_markdown_json: serde_json::Value =
        serde_json::from_slice(&send_markdown.stdout).unwrap();
    assert_eq!(send_markdown_json["result"]["format"], "markdown");
    assert!(
        send_markdown_json["result"]["value"]
            .as_str()
            .unwrap()
            .contains(ISSUE_BODY)
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let client = reqwest::Client::new();
    let direct_embedded = client
        .post(format!("{base_url}/v1/invoke/jira/issue.view"))
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .header(REQUEST_ID_HEADER, "direct-http-jira-embedded")
        .json(&serde_json::json!({
            "inputs":{"issue":"PROJ-1"},
            "readContentFormat":"markdown"
        }))
        .send()
        .await
        .unwrap();
    let direct_embedded_status = direct_embedded.status();
    let direct_embedded_json: serde_json::Value = direct_embedded.json().await.unwrap();
    assert_eq!(
        direct_embedded_status,
        reqwest::StatusCode::OK,
        "direct embedded response: {direct_embedded_json}"
    );
    assert_eq!(
        direct_embedded_json["result"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_BODY})
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let direct_markdown = client
        .post(format!("{base_url}/v1/invoke/jira/issue.view"))
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .header(REQUEST_ID_HEADER, "direct-http-jira-markdown")
        .json(&serde_json::json!({
            "inputs":{"issue":"PROJ-1"},
            "responseFormat":"markdown"
        }))
        .send()
        .await
        .unwrap();
    let direct_markdown_status = direct_markdown.status();
    let direct_markdown_json: serde_json::Value = direct_markdown.json().await.unwrap();
    assert_eq!(
        direct_markdown_status,
        reqwest::StatusCode::OK,
        "direct Markdown response: {direct_markdown_json}"
    );
    assert_eq!(direct_markdown_json["result"]["format"], "markdown");
    assert!(
        direct_markdown_json["result"]["value"]
            .as_str()
            .unwrap()
            .contains(ISSUE_BODY)
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "issue"],
    );

    let search_markdown = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue",
            "search",
            "--project",
            "PROJ",
            "--jql",
            "project = PROJ",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("body-free search Markdown", &search_markdown);
    let search_markdown_stdout = String::from_utf8(search_markdown.stdout).unwrap();
    assert!(search_markdown.stderr.is_empty());
    assert!(search_markdown_stdout.starts_with("# Jira issue search\n"));
    assert!(search_markdown_stdout.contains("## `PROJ-1` — Normalized read issue\n"));
    assert!(!search_markdown_stdout.contains("## Description"));
    assert!(!search_markdown_stdout.contains(SEARCH_BODY));
    assert_new_backend_operations(&backend, &mut provider_call_cursor, &["search"]);

    let comment_add = authenticated_jira_cli(&base_url)
        .args([
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "PROJ-1",
            "--content",
            COMMENT_BODY,
            "--content-format",
            "plain_text",
            "--read-content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("mutation readback embedded Markdown", &comment_add);
    let comment_add_json: serde_json::Value = serde_json::from_slice(&comment_add.stdout).unwrap();
    assert_eq!(
        comment_add_json["result"]["comment"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":COMMENT_BODY})
    );
    assert_eq!(
        comment_add_json["result"]["comment"]["body"]["content"][0]["content"][0]["text"],
        COMMENT_BODY
    );
    assert_new_backend_operations(
        &backend,
        &mut provider_call_cursor,
        &["issue_metadata", "issue_metadata", "add_comment"],
    );

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.view\""));
    assert!(audit.contains("\"action\":\"search\""));
    assert!(audit.contains("\"action\":\"comment.add\""));
    assert!(!audit.contains(ISSUE_BODY));
    assert!(!audit.contains(COMMENT_BODY));
    assert!(!audit.contains(SEARCH_BODY));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_moved_issue_denial_does_not_leak_content() {
    let backend = Arc::new(StubJiraBackend {
        custom_fields: vec![serde_json::json!({
            "id":"customfield_10001", "name":"secret moved custom name",
            "type":"text", "status":"supported", "value":"secret moved custom value"
        })],
        issues: BTreeMap::from([(
            "PROJ-2".to_string(),
            JiraIssue {
                id: "10002".to_string(),
                key: "OTHER-2".to_string(),
                project: "OTHER".to_string(),
                summary: Some("secret moved issue summary".to_string()),
                status: Some("Open".to_string()),
                issue_type: Some("Task".to_string()),
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
                description: Some(jira_adf_text("secret moved issue description")),
            },
        )]),
        search_page: Mutex::new(None),
        last_search: Mutex::new(None),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AnonymousService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend,
        ),
    )
    .await;
    let base_url = broker.public_url();

    let issue = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "view",
            "PROJ-2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        issue.status.code(),
        Some(2),
        "moved issue denial: stdout={} stderr={}",
        String::from_utf8_lossy(&issue.stdout),
        String::from_utf8_lossy(&issue.stderr)
    );
    let issue_json: serde_json::Value = serde_json::from_slice(&issue.stdout).unwrap();
    assert_eq!(issue_json["decision"], "deny");
    assert_eq!(issue_json["reasonCode"], "scope_unresolved");
    assert!(!String::from_utf8_lossy(&issue.stdout).contains("secret moved issue summary"));
    assert!(!String::from_utf8_lossy(&issue.stdout).contains("secret moved custom"));

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"reasonCode\":\"scope_unresolved\""));
    assert!(!audit.contains("secret moved issue summary"));
    assert!(!audit.contains("secret moved custom"));

    stop(broker).await;
}

/// One issue of a project whose key changed: Jira resolves both `alias` and
/// the issue's current `key` to it.
fn renamed_issue_backend(alias: &str, key: &str, project: &str, secret: &str) -> StubJiraBackend {
    let issue = JiraIssue {
        id: "10007".to_string(),
        key: key.to_string(),
        project: project.to_string(),
        summary: Some(format!("{secret} summary")),
        status: Some("Open".to_string()),
        issue_type: Some("Task".to_string()),
        created: None,
        updated: None,
        creator: None,
        reporter: None,
        assignee: None,
        priority: None,
        labels: None,
        description: Some(jira_adf_text(&format!("{secret} description"))),
    };
    StubJiraBackend {
        issues: BTreeMap::from([(alias.to_string(), issue.clone()), (key.to_string(), issue)]),
        custom_fields: vec![serde_json::json!({
            "id":"customfield_10001", "name":format!("{secret} custom name"),
            "type":"text", "status":"supported", "value":format!("{secret} custom value")
        })],
        // The comment belongs to the current key, so listing it proves the
        // Broker sends the key Jira confirmed rather than the alias.
        comments: Mutex::new(BTreeMap::from([(
            "10070".to_string(),
            jira_comment_with_body("10070", &format!("{secret} comment")),
        )])),
        comment_issue_keys: Mutex::new(BTreeMap::from([("10070".to_string(), key.to_string())])),
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10071".to_string(),
            filename: "notes.txt".to_string(),
            size: 13,
            content_type: "text/plain".to_string(),
        }]),
        attachment_content: Mutex::new(BTreeMap::from([(
            "10071".to_string(),
            JiraAttachmentContent::from_bytes("notes.txt", "text/plain", b"renamed notes".to_vec()),
        )])),
        search_page: Mutex::new(None),
        last_search: Mutex::new(None),
        ..StubJiraBackend::default()
    }
}

fn jira_cli(base_url: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", base_url, "--no-token", "jira"])
        .args(args)
        .output()
        .unwrap()
}

/// Project `LEGACY` was renamed to `PROJ`, which the grant names. Old keys and
/// old browser links resolve through Jira to `PROJ-7` and are authorized by
/// `PROJ`; results report the current key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_renamed_project_keys_resolve_to_the_current_issue() {
    let backend = Arc::new(renamed_issue_backend(
        "LEGACY-7", "PROJ-7", "PROJ", "renamed",
    ));
    let broker = start_broker(
        JiraAccess::AnonymousService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();
    let mut cursor = 0;

    for locator in [
        vec!["LEGACY-7"],
        vec![
            "--issue-url",
            "https://example.atlassian.net/browse/LEGACY-7",
        ],
        vec![
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/LEGACY/issues/LEGACY-7",
        ],
        vec![
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/LEGACY/issues/PROJ-7",
        ],
        vec![
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/LEGACY-7",
        ],
    ] {
        let mut args = vec!["issue", "view"];
        args.extend(&locator);
        let view = jira_cli(&base_url, &args);
        assert_success(&format!("renamed issue view {locator:?}"), &view);
        let view: serde_json::Value = serde_json::from_slice(&view.stdout).unwrap();
        assert_eq!(view["result"]["key"], "PROJ-7", "{locator:?}");
        assert_eq!(view["result"]["project"], "PROJ");
        assert_eq!(
            view["result"]["webUrl"],
            "https://example.atlassian.net/browse/PROJ-7"
        );
        assert_new_backend_operations(
            &backend,
            &mut cursor,
            &["issue_metadata", "issue_metadata", "issue"],
        );
    }

    let comments = jira_cli(
        &base_url,
        &["issue", "comment", "list", "--issue", "LEGACY-7"],
    );
    assert_success("renamed comment list", &comments);
    let comments: serde_json::Value = serde_json::from_slice(&comments.stdout).unwrap();
    assert_eq!(comments["result"]["issue"]["key"], "PROJ-7");
    assert_eq!(comments["result"]["comments"][0]["commentId"], "10070");

    let comment = jira_cli(
        &base_url,
        &[
            "issue",
            "comment",
            "view",
            "10070",
            "--issue-url",
            "https://example.atlassian.net/browse/LEGACY-7",
        ],
    );
    assert_success("renamed comment view", &comment);
    let comment: serde_json::Value = serde_json::from_slice(&comment.stdout).unwrap();
    assert_eq!(comment["result"]["issue"]["key"], "PROJ-7");
    assert_eq!(comment["result"]["comment"]["commentId"], "10070");

    let attachments = jira_cli(
        &base_url,
        &[
            "issue",
            "attachment",
            "list",
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/LEGACY/issues/LEGACY-7",
        ],
    );
    assert_success("renamed attachment list", &attachments);
    let attachments: serde_json::Value = serde_json::from_slice(&attachments.stdout).unwrap();
    assert_eq!(attachments["result"]["issue"]["key"], "PROJ-7");
    assert_eq!(
        attachments["result"]["attachments"][0]["attachmentId"],
        "10071"
    );

    let download = jira_cli(
        &base_url,
        &[
            "issue",
            "attachment",
            "download",
            "LEGACY-7",
            "10071",
            "--output",
            "-",
        ],
    );
    assert_success("renamed attachment download", &download);
    assert_eq!(download.stdout, b"renamed notes");

    stop(broker).await;
}

/// Project `PROJ`, which the grant names, was renamed to `OTHER`. Its old keys
/// and links now resolve to `OTHER-2`, which no grant covers: every issue path
/// denies after the lookup without reading content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_renamed_project_outside_the_grant_is_denied_on_every_issue_path() {
    let backend = Arc::new(renamed_issue_backend(
        "PROJ-2",
        "OTHER-2",
        "OTHER",
        "secret renamed",
    ));
    let broker = start_broker(
        JiraAccess::AnonymousService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();
    let mut cursor = 0;

    for args in [
        vec!["issue", "view", "PROJ-2"],
        vec![
            "issue",
            "view",
            "--issue-url",
            "https://example.atlassian.net/browse/PROJ-2",
        ],
        vec![
            "issue",
            "view",
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-2",
        ],
        vec![
            "issue",
            "view",
            "--issue-url",
            "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/OTHER-2",
        ],
        vec!["issue", "comment", "list", "--issue", "PROJ-2"],
        vec!["issue", "comment", "view", "10070", "--issue", "PROJ-2"],
        vec!["issue", "attachment", "list", "PROJ-2"],
        vec![
            "issue",
            "attachment",
            "download",
            "PROJ-2",
            "10071",
            "--output",
            "-",
        ],
    ] {
        let output = jira_cli(&base_url, &args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let denial: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(denial["decision"], "deny", "{args:?}");
        assert_eq!(denial["reasonCode"], "scope_unresolved", "{args:?}");
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!printed.contains("secret renamed"), "{args:?}");
        assert!(!printed.contains("renamed notes"), "{args:?}");
        // Only the scope-resolution lookup ran.
        assert_new_backend_operations(&backend, &mut cursor, &["issue_metadata"]);
    }

    let audit = broker.audit().unwrap().text();
    assert!(!audit.contains("secret renamed"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_jira_write_stream_and_verify_actions_against_stubbed_backend() {
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([
            (
                "PROJ-1".to_string(),
                JiraIssue {
                    id: "10001".to_string(),
                    key: "PROJ-1".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("visible summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: Some(jira_adf_text("visible issue description")),
                },
            ),
            (
                "PROJ-2".to_string(),
                JiraIssue {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("secret created summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: Some(jira_adf_text("secret created description")),
                },
            ),
            (
                "PROJ-3".to_string(),
                JiraIssue {
                    id: "10003".to_string(),
                    key: "PROJ-3".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("blocked issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: None,
                },
            ),
        ]),
        issue_link_types: Mutex::new(vec![JiraIssueLinkType {
            name: "Blocks".to_string(),
            outward: "blocks".to_string(),
            inward: "is blocked by".to_string(),
        }]),
        issue_link_readbacks: Mutex::new(BTreeMap::from([(
            "PROJ-2".to_string(),
            JiraIssueLinks {
                issue: agent_access_jira::JiraIssueMetadata {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                },
                links: vec![JiraIssueLink {
                    link_type: "Blocks".to_string(),
                    outward_issue: Some("PROJ-3".to_string()),
                    inward_issue: None,
                }],
            },
        )])),
        issue_parent_readbacks: Mutex::new(BTreeMap::from([
            (
                "PROJ-2".to_string(),
                jira_parent_readback(
                    jira_issue_metadata("10002", "PROJ-2", "PROJ"),
                    jira_issue_metadata("10001", "PROJ-1", "PROJ"),
                ),
            ),
            (
                "PROJ-3".to_string(),
                jira_parent_readback(
                    jira_issue_metadata("10003", "PROJ-3", "PROJ"),
                    jira_issue_metadata("10001", "PROJ-1", "PROJ"),
                ),
            ),
        ])),
        comments: Mutex::new(BTreeMap::from([(
            "10042".to_string(),
            jira_comment_with_body("10042", "existing secret comment body"),
        )])),
        property_keys: Mutex::new(vec![
            "agent-access.review".to_string(),
            "jira.hidden".to_string(),
        ]),
        properties: Mutex::new(BTreeMap::from([(
            "agent-access.review".to_string(),
            serde_json::json!({"status": "existing-secret-property"}),
        )])),
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "evidence.txt".to_string(),
            size: 16,
            content_type: "text/plain".to_string(),
        }]),
        attachment_content: Mutex::new(BTreeMap::from([(
            "10055".to_string(),
            JiraAttachmentContent::from_bytes(
                "evidence.txt",
                "text/plain",
                b"downloaded bytes".to_vec(),
            ),
        )])),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AnonymousService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();

    let issue_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
            "--summary",
            "secret issue summary",
            "--suppress-notifications",
        ])
        .output()
        .unwrap();
    assert!(
        issue_update.status.success(),
        "issue update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&issue_update.stdout),
        String::from_utf8_lossy(&issue_update.stderr)
    );
    let issue_update_json: serde_json::Value =
        serde_json::from_slice(&issue_update.stdout).unwrap();
    assert_eq!(issue_update_json["decision"], "allow");
    assert_eq!(issue_update_json["result"]["operation"], "issue.update");
    assert_eq!(
        issue_update_json["result"]["changedFields"],
        serde_json::json!(["summary"])
    );
    assert_eq!(issue_update_json["result"]["notifyUsers"], false);

    let description_path = temp_path("jira-description.adf.json");
    std::fs::write(
        &description_path,
        r#"{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"secret issue description"}]}]}"#,
    )
    .unwrap();
    let description_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "update",
            "--issue-url",
            "https://example.atlassian.net/browse/PROJ-1",
            "--content",
            "**secret issue description**",
            "--content-format",
            "markdown",
            "--notify-users",
        ])
        .output()
        .unwrap();
    assert!(
        description_update.status.success(),
        "description update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&description_update.stdout),
        String::from_utf8_lossy(&description_update.stderr)
    );
    let description_update_json: serde_json::Value =
        serde_json::from_slice(&description_update.stdout).unwrap();
    assert_eq!(
        description_update_json["result"]["changedFields"],
        serde_json::json!(["description"])
    );
    assert_eq!(description_update_json["result"]["notifyUsers"], true);
    {
        let issue_updates = backend.updated_issues.lock().unwrap();
        assert_eq!(issue_updates.len(), 2);
        assert_eq!(issue_updates[0].0, "PROJ-1");
        assert_eq!(
            issue_updates[0].1.summary.as_deref(),
            Some("secret issue summary")
        );
        assert!(issue_updates[0].1.description.is_none());
        assert_eq!(issue_updates[0].1.notify_users, Some(false));
        assert!(issue_updates[1].1.summary.is_none());
        assert_eq!(
            issue_updates[1].1.description.as_ref().unwrap()["content"][0]["content"][0]["text"],
            "secret issue description"
        );
        assert_eq!(issue_updates[1].1.notify_users, Some(true));
    }

    let issue_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "create",
            "--project",
            "PROJ",
            "--issue-type-id",
            "10001",
            "--summary",
            "secret created summary",
            "--content-file",
            description_path.to_str().unwrap(),
            "--content-format",
            "adf",
        ])
        .output()
        .unwrap();
    assert_success("issue create", &issue_create);
    let issue_create_json: serde_json::Value =
        serde_json::from_slice(&issue_create.stdout).unwrap();
    assert_eq!(issue_create_json["decision"], "allow");
    assert_eq!(issue_create_json["result"]["operation"], "issue.create");
    assert_eq!(issue_create_json["result"]["issue"]["key"], "PROJ-2");
    {
        let created_issues = backend.created_issues.lock().unwrap();
        assert_eq!(created_issues.len(), 1);
        assert_eq!(created_issues[0].project, "PROJ");
        assert_eq!(created_issues[0].issue_type_id, "10001");
        assert_eq!(created_issues[0].summary, "secret created summary");
        assert!(created_issues[0].parent_issue.is_none());
        assert_eq!(
            created_issues[0].description.as_ref().unwrap()["content"][0]["content"][0]["text"],
            "secret issue description"
        );
    }

    let child_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "child",
            "create",
            "--project",
            "PROJ",
            "--issue-type-id",
            "10001",
            "--summary",
            "secret child summary",
            "--parent",
            "PROJ-1",
            "--content",
            "secret child description",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success("issue child create", &child_create);
    let child_create_json: serde_json::Value =
        serde_json::from_slice(&child_create.stdout).unwrap();
    assert_eq!(child_create_json["decision"], "allow");
    assert_eq!(
        child_create_json["result"]["operation"],
        "issue.child.create"
    );
    assert_eq!(child_create_json["result"]["issue"]["key"], "PROJ-2");
    assert_eq!(child_create_json["result"]["parentIssue"]["key"], "PROJ-1");
    assert_eq!(
        child_create_json["result"]["verification"]["status"],
        "matched"
    );

    let child_invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "jira.issue.child.create",
            "--input-json",
            r#"{"project":"PROJ","issueTypeId":"10001","summary":"secret child invoke summary","parentIssue":"PROJ-1"}"#,
        ])
        .output()
        .unwrap();
    assert_success("issue child generic invoke", &child_invoke);
    let child_invoke_json: serde_json::Value =
        serde_json::from_slice(&child_invoke.stdout).unwrap();
    assert_eq!(
        child_invoke_json["result"]["verification"]["status"],
        "matched"
    );
    {
        let created_issues = backend.created_issues.lock().unwrap();
        assert_eq!(created_issues.len(), 3);
        assert_eq!(created_issues[1].summary, "secret child summary");
        assert_eq!(created_issues[1].parent_issue.as_deref(), Some("PROJ-1"));
        assert_eq!(
            created_issues[1].description.as_ref().unwrap()["content"][0]["content"][0]["text"],
            "secret child description"
        );
        assert_eq!(created_issues[2].parent_issue.as_deref(), Some("PROJ-1"));
    }

    let parent_set = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "parent",
            "set",
            "PROJ-3",
            "--parent",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert_success("issue parent set", &parent_set);
    let parent_set_json: serde_json::Value = serde_json::from_slice(&parent_set.stdout).unwrap();
    assert_eq!(parent_set_json["decision"], "allow");
    assert_eq!(parent_set_json["result"]["operation"], "issue.parent.set");
    assert_eq!(parent_set_json["result"]["issue"]["key"], "PROJ-3");
    assert_eq!(parent_set_json["result"]["parentIssue"]["key"], "PROJ-1");

    let parent_invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "jira.issue.parent.set",
            "--input-json",
            r#"{"issue":"PROJ-3","parentIssue":"PROJ-1"}"#,
        ])
        .output()
        .unwrap();
    assert_success("issue parent generic invoke", &parent_invoke);
    let parent_invoke_json: serde_json::Value =
        serde_json::from_slice(&parent_invoke.stdout).unwrap();
    assert_eq!(
        parent_invoke_json["result"]["verification"]["status"],
        "matched"
    );
    {
        let parent_updates = backend.parent_updates.lock().unwrap();
        assert_eq!(parent_updates.len(), 2);
        assert_eq!(parent_updates[0].0, "PROJ-3");
        assert_eq!(parent_updates[0].1.parent_issue, "PROJ-1");
    }

    let dependency = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "dependency",
            "add",
            "--blocking",
            "PROJ-2",
            "--blocked",
            "PROJ-3",
        ])
        .output()
        .unwrap();
    assert_success("issue dependency add", &dependency);
    let dependency_json: serde_json::Value = serde_json::from_slice(&dependency.stdout).unwrap();
    assert_eq!(dependency_json["decision"], "allow");
    assert_eq!(
        dependency_json["result"]["operation"],
        "issue.dependency.add"
    );
    assert_eq!(dependency_json["result"]["status"], "present");
    assert_eq!(dependency_json["result"]["blockingIssue"]["key"], "PROJ-2");
    assert_eq!(dependency_json["result"]["blockedIssue"]["key"], "PROJ-3");

    let dependency_invoke = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "jira.issue.dependency.add",
            "--input-json",
            r#"{"blockingIssue":"PROJ-2","blockedIssue":"PROJ-3"}"#,
        ])
        .output()
        .unwrap();
    assert_success("issue dependency generic invoke", &dependency_invoke);
    let dependency_invoke_json: serde_json::Value =
        serde_json::from_slice(&dependency_invoke.stdout).unwrap();
    assert_eq!(
        dependency_invoke_json["result"]["verification"]["status"],
        "matched"
    );
    {
        let created_links = backend.created_issue_links.lock().unwrap();
        assert_eq!(created_links.len(), 2);
        assert_eq!(created_links[0].link_type, "Blocks");
        assert_eq!(created_links[0].outward_issue, "PROJ-2");
        assert_eq!(created_links[0].inward_issue, "PROJ-3");
    }

    let body_path = temp_path("jira-comment.md");
    std::fs::write(&body_path, "## secret comment body\n\nMarkdown content.").unwrap();
    let comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "PROJ-1",
            "--content-file",
            body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        comment.status.success(),
        "comment add failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment.stdout),
        String::from_utf8_lossy(&comment.stderr)
    );
    {
        let added_comments = backend.added_comments.lock().unwrap();
        assert_eq!(added_comments.len(), 1);
        assert_eq!(added_comments[0].body["type"], "doc");
        assert_eq!(added_comments[0].body["version"], 1);
        assert_eq!(added_comments[0].body["content"][0]["type"], "heading");
        assert_eq!(
            added_comments[0].body["content"][0]["content"][0]["text"],
            "secret comment body"
        );
    }

    let comment_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "list",
            "--issue-url",
            "https://example.atlassian.net/browse/PROJ-1",
            "--max-results",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        comment_list.status.success(),
        "comment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment_list.stdout),
        String::from_utf8_lossy(&comment_list.stderr)
    );
    let comment_list_value: serde_json::Value =
        serde_json::from_slice(&comment_list.stdout).unwrap();
    assert_eq!(
        comment_list_value["result"]["comments"][0]["commentId"],
        "10042"
    );
    assert!(
        comment_list_value["result"]["comments"][0]
            .get("body")
            .is_none()
    );

    let comment_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "view",
            "10042",
            "--issue",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        comment_view.status.success(),
        "comment view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment_view.stdout),
        String::from_utf8_lossy(&comment_view.stderr)
    );
    let comment_view_json: serde_json::Value =
        serde_json::from_slice(&comment_view.stdout).unwrap();
    assert_eq!(
        comment_view_json["result"]["comment"]["body"]["content"][0]["content"][0]["text"],
        "existing secret comment body"
    );

    let reply_body_path = temp_path("jira-comment-reply.txt");
    std::fs::write(
        &reply_body_path,
        "secret reply body with *literal* punctuation",
    )
    .unwrap();
    let comment_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "reply",
            "10042",
            "--issue",
            "PROJ-1",
            "--content-file",
            reply_body_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert!(
        comment_reply.status.success(),
        "comment reply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment_reply.stdout),
        String::from_utf8_lossy(&comment_reply.stderr)
    );
    let comment_reply_json: serde_json::Value =
        serde_json::from_slice(&comment_reply.stdout).unwrap();
    assert_eq!(comment_reply_json["result"]["operation"], "comment.reply");
    assert_eq!(comment_reply_json["result"]["parentCommentId"], "10042");
    assert_eq!(
        comment_reply_json["result"]["comment"]["parentCommentId"],
        "10042"
    );
    {
        let added_comments = backend.added_comments.lock().unwrap();
        assert_eq!(added_comments.len(), 2);
        assert_eq!(added_comments[1].parent_id.as_deref(), Some("10042"));
        assert_eq!(
            added_comments[1].body["content"][0]["content"][0]["text"],
            "secret reply body with *literal* punctuation"
        );
        assert!(
            added_comments[1].body["content"][0]["content"][0]
                .get("marks")
                .is_none()
        );
    }

    let comment_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "update",
            "10042",
            "--issue",
            "PROJ-1",
            "--content",
            r#"{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"updated secret comment body"}]}]}"#,
            "--content-format",
            "adf",
            "--notify-users",
            "false",
        ])
        .output()
        .unwrap();
    assert!(
        comment_update.status.success(),
        "comment update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment_update.stdout),
        String::from_utf8_lossy(&comment_update.stderr)
    );
    assert_eq!(backend.updated_comments.lock().unwrap().len(), 1);
    assert!(!backend.updated_comments.lock().unwrap()[0].1.notify_users);
    assert_eq!(
        backend.updated_comments.lock().unwrap()[0].1.body["content"][0]["content"][0]["text"],
        "updated secret comment body"
    );

    let property_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "property",
            "list",
            "10042",
            "--issue",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        property_list.status.success(),
        "property list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&property_list.stdout),
        String::from_utf8_lossy(&property_list.stderr)
    );
    let property_list_value: serde_json::Value =
        serde_json::from_slice(&property_list.stdout).unwrap();
    assert_eq!(
        property_list_value["result"]["keys"][0]["key"],
        "agent-access.review"
    );
    assert_eq!(
        property_list_value["result"]["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let property_get = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "property",
            "get",
            "10042",
            "agent-access.review",
            "--issue",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        property_get.status.success(),
        "property get failed: stdout={} stderr={}",
        String::from_utf8_lossy(&property_get.stdout),
        String::from_utf8_lossy(&property_get.stderr)
    );
    let property_get_json: serde_json::Value =
        serde_json::from_slice(&property_get.stdout).unwrap();
    assert_eq!(
        property_get_json["result"]["value"]["status"],
        "existing-secret-property"
    );

    let property_value_path = temp_path("jira-comment-property.json");
    std::fs::write(&property_value_path, r#"{"status":"set-secret-property"}"#).unwrap();
    let property_set = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "property",
            "set",
            "10042",
            "agent-access.review",
            "--issue",
            "PROJ-1",
            "--value-file",
            property_value_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        property_set.status.success(),
        "property set failed: stdout={} stderr={}",
        String::from_utf8_lossy(&property_set.stdout),
        String::from_utf8_lossy(&property_set.stderr)
    );
    assert_eq!(backend.set_properties.lock().unwrap().len(), 1);

    let property_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "property",
            "delete",
            "10042",
            "agent-access.review",
            "--issue",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        property_delete.status.success(),
        "property delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&property_delete.stdout),
        String::from_utf8_lossy(&property_delete.stderr)
    );
    assert_eq!(
        *backend.deleted_properties.lock().unwrap(),
        vec!["agent-access.review".to_string()]
    );

    let comment_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "delete",
            "10042",
            "--issue",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        comment_delete.status.success(),
        "comment delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&comment_delete.stdout),
        String::from_utf8_lossy(&comment_delete.stderr)
    );
    assert_eq!(
        *backend.deleted_comments.lock().unwrap(),
        vec!["10042".to_string()]
    );

    let legacy_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "PROJ-1",
            "--content-file",
            body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        !legacy_comment.status.success(),
        "legacy comment shape unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&legacy_comment.stdout),
        String::from_utf8_lossy(&legacy_comment.stderr)
    );

    let missing_locator = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "comment",
            "view",
            "10042",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_locator.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&missing_locator.stderr)
            .contains("requires exactly one of --issue or --issue-url")
    );

    let upload_path = temp_path("evidence.txt");
    std::fs::write(&upload_path, b"upload bytes").unwrap();
    let upload = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "attach",
            "PROJ-1",
            upload_path.to_str().unwrap(),
            "--content-type",
            "text/plain",
        ])
        .output()
        .unwrap();
    assert!(
        upload.status.success(),
        "attachment upload failed: stdout={} stderr={}",
        String::from_utf8_lossy(&upload.stdout),
        String::from_utf8_lossy(&upload.stderr)
    );
    assert_eq!(backend.uploaded_attachments.lock().unwrap().len(), 1);
    assert_eq!(
        backend.uploaded_attachments.lock().unwrap()[0].bytes,
        b"upload bytes"
    );

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "list",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        list_json["result"]["attachments"][0]["attachmentId"],
        "10055"
    );
    assert_eq!(
        list_json["result"]["issue"]["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );

    let output_path = temp_path("downloaded-evidence.txt");
    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "PROJ-1",
            "10055",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        download.status.success(),
        "attachment download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&download.stdout),
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), b"downloaded bytes");
    let download_json: serde_json::Value = serde_json::from_slice(&download.stdout).unwrap();
    assert_eq!(download_json["result"]["filename"], "evidence.txt");
    assert!(
        download_json["result"].get("contentBase64").is_none(),
        "download JSON must not echo attachment bytes when --output writes a file"
    );
    let stdout_download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "PROJ-1",
            "10055",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert!(
        stdout_download.status.success(),
        "stdout attachment download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&stdout_download.stdout),
        String::from_utf8_lossy(&stdout_download.stderr)
    );
    assert_eq!(stdout_download.stdout, b"downloaded bytes");

    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "jira",
            "issue",
            "verify",
            "PROJ-1",
            "--expect-comment-id",
            "99999",
        ])
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(2));
    let verify_json: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_json["decision"], "allow");
    assert_eq!(verify_json["reasonCode"], "verification_mismatch");
    assert_eq!(verify_json["result"]["verification"]["status"], "mismatch");

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.create\""));
    assert!(audit.contains("\"action\":\"issue.child.create\""));
    assert!(audit.contains("\"action\":\"issue.update\""));
    assert!(audit.contains("\"action\":\"issue.parent.set\""));
    assert!(!audit.contains("secret created summary"));
    assert!(!audit.contains("secret created description"));
    assert!(!audit.contains("secret child summary"));
    assert!(!audit.contains("secret child invoke summary"));
    assert!(!audit.contains("secret issue summary"));
    assert!(!audit.contains("secret issue description"));
    assert!(!audit.contains("secret comment body"));
    assert!(!audit.contains("existing secret comment body"));
    assert!(!audit.contains("secret reply body"));
    assert!(!audit.contains("updated secret comment body"));
    assert!(!audit.contains("existing-secret-property"));
    assert!(!audit.contains("set-secret-property"));
    assert!(audit.contains("\"action\":\"comment.reply\""));
    assert!(!audit.contains("upload bytes"));
    assert!(!audit.contains("downloaded bytes"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_send_invokes_jira_relationship_actions_against_stubbed_backend() {
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([
            (
                "PROJ-1".to_string(),
                JiraIssue {
                    id: "10001".to_string(),
                    key: "PROJ-1".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("parent issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Epic".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: None,
                },
            ),
            (
                "PROJ-2".to_string(),
                JiraIssue {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("blocking issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: None,
                },
            ),
            (
                "PROJ-3".to_string(),
                JiraIssue {
                    id: "10003".to_string(),
                    key: "PROJ-3".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("blocked issue summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: None,
                },
            ),
        ]),
        issue_link_types: Mutex::new(vec![JiraIssueLinkType {
            name: "Blocks".to_string(),
            outward: "blocks".to_string(),
            inward: "is blocked by".to_string(),
        }]),
        issue_link_readbacks: Mutex::new(BTreeMap::from([(
            "PROJ-2".to_string(),
            JiraIssueLinks {
                issue: agent_access_jira::JiraIssueMetadata {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                    project: "PROJ".to_string(),
                },
                links: vec![JiraIssueLink {
                    link_type: "Blocks".to_string(),
                    outward_issue: Some("PROJ-3".to_string()),
                    inward_issue: None,
                }],
            },
        )])),
        issue_parent_readbacks: Mutex::new(BTreeMap::from([
            (
                "PROJ-2".to_string(),
                jira_parent_readback(
                    jira_issue_metadata("10002", "PROJ-2", "PROJ"),
                    jira_issue_metadata("10001", "PROJ-1", "PROJ"),
                ),
            ),
            (
                "PROJ-3".to_string(),
                jira_parent_readback(
                    jira_issue_metadata("10003", "PROJ-3", "PROJ"),
                    jira_issue_metadata("10001", "PROJ-1", "PROJ"),
                ),
            ),
        ])),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AgentService,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();

    let request_path = temp_path("jira-send-dependency.json");
    std::fs::write(
        &request_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.dependency.add","inputs":{"blockingIssue":"PROJ-2","blockedIssue":"PROJ-3"}}"#,
    )
    .unwrap();
    let send = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("send issue dependency add", &send);
    let send_json: serde_json::Value = serde_json::from_slice(&send.stdout).unwrap();
    assert_eq!(send_json["decision"], "allow");
    assert_eq!(send_json["result"]["operation"], "issue.dependency.add");
    assert_eq!(send_json["result"]["verification"]["status"], "matched");
    {
        let created_links = backend.created_issue_links.lock().unwrap();
        assert_eq!(created_links.len(), 1);
        assert_eq!(created_links[0].outward_issue, "PROJ-2");
        assert_eq!(created_links[0].inward_issue, "PROJ-3");
    }

    let parent_request_path = temp_path("jira-send-parent.json");
    std::fs::write(
        &parent_request_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.parent.set","inputs":{"issue":"PROJ-3","parentIssue":"PROJ-1"}}"#,
    )
    .unwrap();
    let parent_send = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            parent_request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("send issue parent set", &parent_send);
    let parent_send_json: serde_json::Value = serde_json::from_slice(&parent_send.stdout).unwrap();
    assert_eq!(parent_send_json["decision"], "allow");
    assert_eq!(parent_send_json["result"]["operation"], "issue.parent.set");
    assert_eq!(
        parent_send_json["result"]["verification"]["status"],
        "matched"
    );
    {
        let parent_updates = backend.parent_updates.lock().unwrap();
        assert_eq!(parent_updates.len(), 1);
        assert_eq!(parent_updates[0].0, "PROJ-3");
        assert_eq!(parent_updates[0].1.parent_issue, "PROJ-1");
    }

    let child_request_path = temp_path("jira-send-child.json");
    std::fs::write(
        &child_request_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.child.create","inputs":{"project":"PROJ","issueTypeId":"10001","summary":"send child summary","parentIssue":"PROJ-1"}}"#,
    )
    .unwrap();
    let child_send = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            child_request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("send issue child create", &child_send);
    let child_send_json: serde_json::Value = serde_json::from_slice(&child_send.stdout).unwrap();
    assert_eq!(child_send_json["decision"], "allow");
    assert_eq!(child_send_json["result"]["operation"], "issue.child.create");
    assert_eq!(
        child_send_json["result"]["verification"]["status"],
        "matched"
    );
    {
        let created_issues = backend.created_issues.lock().unwrap();
        assert_eq!(created_issues.len(), 1);
        assert_eq!(created_issues[0].parent_issue.as_deref(), Some("PROJ-1"));
    }
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.child.create\""));
    assert!(!audit.contains("send child summary"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_jira_per_user_actions_against_stubbed_backend() {
    let backend = Arc::new(StubJiraBackend {
        issues: BTreeMap::from([
            (
                "PROJ-1".to_string(),
                JiraIssue {
                    id: "10001".to_string(),
                    key: "PROJ-1".to_string(),
                    project: "PROJ".to_string(),
                    summary: Some("service visible summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: Some(jira_adf_text("service visible description")),
                },
            ),
            (
                "OPS-1".to_string(),
                JiraIssue {
                    id: "10002".to_string(),
                    key: "OPS-1".to_string(),
                    project: "OPS".to_string(),
                    summary: Some("per-user visible summary".to_string()),
                    status: Some("Open".to_string()),
                    issue_type: Some("Task".to_string()),
                    created: None,
                    updated: None,
                    creator: None,
                    reporter: None,
                    assignee: None,
                    priority: None,
                    labels: None,
                    description: Some(jira_adf_text("per-user visible description")),
                },
            ),
        ]),
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![JiraIssue {
                id: "10002".to_string(),
                key: "OPS-1".to_string(),
                project: "OPS".to_string(),
                summary: Some("per-user visible summary".to_string()),
                status: Some("Open".to_string()),
                issue_type: Some("Task".to_string()),
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
                description: Some(jira_adf_text("search issue description")),
            }],
            max_results: 2,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        comments: Mutex::new(BTreeMap::from([(
            "10042".to_string(),
            jira_comment_with_body("10042", "per-user existing secret body"),
        )])),
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "evidence.txt".to_string(),
            size: 16,
            content_type: "text/plain".to_string(),
        }]),
        attachment_content: Mutex::new(BTreeMap::from([(
            "10055".to_string(),
            JiraAttachmentContent::from_bytes(
                "evidence.txt",
                "text/plain",
                b"downloaded bytes".to_vec(),
            ),
        )])),
        ..StubJiraBackend::default()
    });
    let broker = start_broker(
        JiraAccess::AgentPerUser,
        jira_service(
            jira_provider_config(2),
            agent_access_provider::ProviderLimits::default(),
            backend.clone(),
        ),
    )
    .await;
    let base_url = broker.public_url();

    let service_issue = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "view",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira issue view on PROJ", &service_issue);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("issue", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let issue = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "view",
            "OPS-1",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira issue view", &issue);
    let issue_json: serde_json::Value = serde_json::from_slice(&issue.stdout).unwrap();
    assert_eq!(issue_json["result"]["key"], "OPS-1");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("issue", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "search",
            "--project",
            "OPS",
            "--jql",
            "project = OPS",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira search", &search);
    assert_credential_observations(&backend, &[("search", "jira-per-user-token")]);

    backend.credential_observations.lock().unwrap().clear();
    let body_path = temp_path("jira-per-user-comment.md");
    std::fs::write(&body_path, "**per-user secret body**").unwrap();
    let comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "OPS-1",
            "--content-file",
            body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira comment add", &comment);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("add_comment", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let upload_path = temp_path("per-user-evidence.txt");
    std::fs::write(&upload_path, b"upload bytes").unwrap();
    let upload = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "attach",
            "OPS-1",
            upload_path.to_str().unwrap(),
            "--content-type",
            "text/plain",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira attachment upload", &upload);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("add_attachment", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let output_path = temp_path("per-user-downloaded-evidence.txt");
    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "attachment",
            "download",
            "OPS-1",
            "10055",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira attachment download", &download);
    assert_eq!(std::fs::read(&output_path).unwrap(), b"downloaded bytes");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("issue_attachment_metadata", "jira-per-user-token"),
            ("attachment_content", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "attachment",
            "list",
            "OPS-1",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira attachment list", &list);
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        list_json["result"]["attachments"][0]["attachmentId"],
        "10055"
    );
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("issue_attachment_list", "jira-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "jira",
            "issue",
            "verify",
            "OPS-1",
            "--expect-comment-id",
            "10042",
            "--expect-attachment-id",
            "10055",
        ])
        .output()
        .unwrap();
    assert_success("per-user Jira verify", &verify);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "jira-per-user-token"),
            ("issue_metadata", "jira-per-user-token"),
            ("comment", "jira-per-user-token"),
            ("issue_attachment_metadata", "jira-per-user-token"),
        ],
    );

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"credentialMode\":\"per_user\""));
    assert!(!audit.contains("agent-token"));
    assert!(!audit.contains("jira-per-user-token"));
    assert!(!audit.contains("per-user secret body"));

    stop(broker).await;
}

#[test]
fn cli_jira_issue_update_rejects_local_input_conflicts() {
    let missing_field = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_field.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&missing_field.stderr).contains("requires --summary or content")
    );

    let locator_conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
            "--issue-url",
            "https://example.atlassian.net/browse/PROJ-1",
            "--summary",
            "updated",
        ])
        .output()
        .unwrap();
    assert_eq!(locator_conflict.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&locator_conflict.stderr)
            .contains("requires exactly one issue argument or --issue-url")
    );

    let notify_conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
            "--summary",
            "updated",
            "--notify-users",
            "--suppress-notifications",
        ])
        .output()
        .unwrap();
    assert_eq!(notify_conflict.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&notify_conflict.stderr)
            .contains("rejects --notify-users with --suppress-notifications")
    );

    let missing_format = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
            "--content",
            "content without a format",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_format.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_format.stderr).contains("required"));

    let format_without_content = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "update",
            "PROJ-1",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(format_without_content.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&format_without_content.stderr).contains("required"));

    let conflict_path = temp_path("jira-content-source-conflict.md");
    std::fs::write(&conflict_path, "file content").unwrap();
    let source_conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "PROJ-1",
            "--content",
            "inline content",
            "--content-file",
            conflict_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(source_conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&source_conflict.stderr).contains("cannot be used with"));

    let malformed_adf = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "PROJ-1",
            "--content",
            "{not-json",
            "--content-format",
            "adf",
        ])
        .output()
        .unwrap();
    assert_eq!(malformed_adf.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&malformed_adf.stderr).contains("JSON"));

    for removed_flag in ["--description-adf-file", "--body-file"] {
        let removed = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "jira",
                "issue",
                "update",
                "PROJ-1",
                removed_flag,
                conflict_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !removed.status.success(),
            "removed flag {removed_flag} survived"
        );
        assert!(String::from_utf8_lossy(&removed.stderr).contains("unexpected argument"));
    }
}

#[test]
fn cli_download_short_body_exits_5_and_preserves_existing_output_file_against_stubbed_broker() {
    let output_path = temp_path("jira-short-download-output.txt");
    std::fs::write(&output_path, b"original").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let metadata = serde_json::json!({
        "agentRequestId": "agent",
        "brokerRequestId": "broker",
        "decision": "allow",
        "result": {
            "filename": "evidence.txt",
            "contentType": "text/plain",
            "size": 5
        }
    });
    let encoded_metadata = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{RESULT_METADATA_HEADER}: {encoded_metadata}\r\nContent-Length: 4\r\n\r\nbody"
        )
        .unwrap();
    });

    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &format!("http://{address}"),
            "--no-token",
            "jira",
            "issue",
            "attachment",
            "download",
            "PROJ-1",
            "10055",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        download.status.code(),
        Some(5),
        "short download should exit 5: stdout={} stderr={}",
        String::from_utf8_lossy(&download.stdout),
        String::from_utf8_lossy(&download.stderr)
    );
    assert!(
        String::from_utf8_lossy(&download.stderr).contains("download size mismatch"),
        "stderr={}",
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), b"original");
    server.join().unwrap();
    std::fs::remove_file(output_path).unwrap();
}

#[derive(Default)]
struct StubJiraBackend {
    issue_type_requests: Mutex<Vec<(String, JiraIssueTypeListRequest)>>,
    issues: BTreeMap<String, JiraIssue>,
    issue_view_requests: Mutex<Vec<bool>>,
    issue_view_links: Mutex<Option<Vec<JiraIssueViewLink>>>,
    issue_view_context: Mutex<JiraIssueViewContext>,
    custom_fields: Vec<serde_json::Value>,
    created_issue: Mutex<Option<JiraCreatedIssue>>,
    created_issues: Mutex<Vec<JiraIssueCreateRequest>>,
    updated_issues: Mutex<Vec<(String, JiraIssueUpdateRequest)>>,
    parent_updates: Mutex<Vec<(String, JiraIssueParentSetRequest)>>,
    issue_parent_readbacks: Mutex<BTreeMap<String, JiraIssueParentReadback>>,
    issue_link_types: Mutex<Vec<JiraIssueLinkType>>,
    created_issue_links: Mutex<Vec<JiraIssueLinkCreateRequest>>,
    issue_link_readbacks: Mutex<BTreeMap<String, JiraIssueLinks>>,
    search_page: Mutex<Option<JiraSearchPage>>,
    last_search: Mutex<Option<JiraSearchRequest>>,
    last_comment_list: Mutex<Option<JiraCommentListRequest>>,
    comments: Mutex<BTreeMap<String, JiraComment>>,
    comment_issue_keys: Mutex<BTreeMap<String, String>>,
    added_comments: Mutex<Vec<JiraCommentAddRequest>>,
    updated_comments: Mutex<Vec<(String, JiraCommentUpdateRequest)>>,
    deleted_comments: Mutex<Vec<String>>,
    property_keys: Mutex<Vec<String>>,
    properties: Mutex<BTreeMap<String, serde_json::Value>>,
    set_properties: Mutex<Vec<(String, serde_json::Value)>>,
    deleted_properties: Mutex<Vec<String>>,
    attachments: Mutex<Vec<JiraAttachment>>,
    attachment_content: Mutex<BTreeMap<String, JiraAttachmentContent>>,
    uploaded_attachments: Mutex<Vec<JiraAttachmentUpload>>,
    credential_observations: Mutex<Vec<CredentialObservation>>,
}

/// One credential the stub backend received. Credentials compare by kind
/// and material, so tests check which one arrived without reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialObservation {
    operation: String,
    credential: agent_access_provider::ExecutionCredential,
}

impl StubJiraBackend {
    fn record_credential(
        &self,
        operation: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) {
        self.credential_observations
            .lock()
            .unwrap()
            .push(CredentialObservation {
                operation: operation.to_string(),
                credential: credential
                    .static_credential()
                    .expect("the stub backend receives static tokens")
                    .clone(),
            });
    }
}

#[async_trait]
impl JiraBackend for StubJiraBackend {
    async fn project_list(
        &self,
        _request: agent_access_jira::JiraProjectListRequest,
        _credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<serde_json::Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "unexpected project listing in this fixture".to_string(),
        ))
    }

    async fn issue_types(
        &self,
        project: &str,
        request: JiraIssueTypeListRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueTypePage>, JiraBackendError> {
        self.record_credential("issue_types", credential);
        let start_at = request.start_at;
        let max_results = request.max_results;
        self.issue_type_requests
            .lock()
            .unwrap()
            .push((project.to_string(), request));
        let issue_types = vec![
            JiraIssueType {
                id: "10001".to_string(),
                name: "Task".to_string(),
                description: "Work to complete".to_string(),
                subtask: false,
            },
            JiraIssueType {
                id: "10002".to_string(),
                name: "Subtask".to_string(),
                description: String::new(),
                subtask: true,
            },
        ]
        .into_iter()
        .skip(start_at as usize)
        .take(max_results as usize)
        .collect::<Vec<_>>();
        Ok(JiraBackendResponse {
            value: JiraIssueTypePage {
                issue_types,
                start_at,
                max_results,
                total: 2,
            },
            status: 200,
            duration_ms: 2,
        })
    }

    async fn issue_metadata(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<agent_access_jira::JiraIssueMetadata>, JiraBackendError> {
        self.record_credential("issue_metadata", credential);
        let issue = self
            .issues
            .get(issue_key)
            .cloned()
            .ok_or(JiraBackendError::NotFound)?;
        Ok(JiraBackendResponse {
            value: agent_access_jira::JiraIssueMetadata {
                id: issue.id,
                key: issue.key,
                project: issue.project,
            },
            status: 200,
            duration_ms: 2,
        })
    }

    async fn issue(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError> {
        self.record_credential("issue", credential);
        Ok(JiraBackendResponse {
            value: self
                .issues
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 3,
        })
    }

    async fn issue_view(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
        include_issue_references: bool,
    ) -> Result<JiraBackendResponse<JiraIssueView>, JiraBackendError> {
        self.issue_view_requests
            .lock()
            .unwrap()
            .push(include_issue_references);
        let response = self.issue(issue_key, credential).await?;
        Ok(JiraBackendResponse {
            value: JiraIssueView {
                issue: response.value,
                // Deliberately return references even when not requested, so
                // smoke tests exercise the provider output boundary too.
                context: self.issue_view_context.lock().unwrap().clone(),
                custom_fields: self.custom_fields.clone(),
                issue_links: if include_issue_references {
                    self.issue_view_links.lock().unwrap().clone()
                } else {
                    None
                },
            },
            status: response.status,
            duration_ms: response.duration_ms,
        })
    }

    async fn create_issue(
        &self,
        request: JiraIssueCreateRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCreatedIssue>, JiraBackendError> {
        self.record_credential("create_issue", credential);
        self.created_issues.lock().unwrap().push(request);
        Ok(JiraBackendResponse {
            value: self
                .created_issue
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(JiraCreatedIssue {
                    id: "10002".to_string(),
                    key: "PROJ-2".to_string(),
                }),
            status: 201,
            duration_ms: 4,
        })
    }

    async fn update_issue(
        &self,
        issue_key: &str,
        request: JiraIssueUpdateRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("update_issue", credential);
        self.updated_issues
            .lock()
            .unwrap()
            .push((issue_key.to_string(), request));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 4,
        })
    }

    async fn set_issue_parent(
        &self,
        issue_key: &str,
        request: JiraIssueParentSetRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("set_issue_parent", credential);
        self.parent_updates
            .lock()
            .unwrap()
            .push((issue_key.to_string(), request));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 4,
        })
    }

    async fn issue_parent(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueParentReadback>, JiraBackendError> {
        self.record_credential("issue_parent", credential);
        Ok(JiraBackendResponse {
            value: self
                .issue_parent_readbacks
                .lock()
                .unwrap()
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn issue_link_types(
        &self,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraIssueLinkType>>, JiraBackendError> {
        self.record_credential("issue_link_types", credential);
        Ok(JiraBackendResponse {
            value: self.issue_link_types.lock().unwrap().clone(),
            status: 200,
            duration_ms: 4,
        })
    }

    async fn create_issue_link(
        &self,
        request: JiraIssueLinkCreateRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("create_issue_link", credential);
        self.created_issue_links.lock().unwrap().push(request);
        Ok(JiraBackendResponse {
            value: (),
            status: 201,
            duration_ms: 4,
        })
    }

    async fn issue_links(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueLinks>, JiraBackendError> {
        self.record_credential("issue_links", credential);
        Ok(JiraBackendResponse {
            value: self
                .issue_link_readbacks
                .lock()
                .unwrap()
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn search(
        &self,
        request: JiraSearchRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError> {
        self.record_credential("search", credential);
        *self.last_search.lock().unwrap() = Some(request);
        Ok(JiraBackendResponse {
            value: self.search_page.lock().unwrap().clone().unwrap(),
            status: 200,
            duration_ms: 4,
        })
    }

    async fn comments(
        &self,
        issue_key: &str,
        request: JiraCommentListRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPage>, JiraBackendError> {
        self.record_credential("comments", credential);
        *self.last_comment_list.lock().unwrap() = Some(request.clone());
        let comment_issue_keys = self.comment_issue_keys.lock().unwrap().clone();
        let comments = self
            .comments
            .lock()
            .unwrap()
            .values()
            .filter(|comment| {
                comment_issue_keys
                    .get(&comment.id)
                    .is_none_or(|owner_issue_key| owner_issue_key.as_str() == issue_key)
            })
            .take(request.max_results as usize)
            .map(|comment| JiraCommentSummary {
                id: comment.id.clone(),
                parent_id: comment.parent_id.clone(),
                author: comment.author.clone(),
                created: comment.created.clone(),
                updated: comment.updated.clone(),
                visibility: comment.visibility.clone(),
            })
            .collect::<Vec<_>>();
        Ok(JiraBackendResponse {
            value: JiraCommentPage {
                comments,
                max_results: request.max_results,
                start_at: request.start_at,
                total: Some(
                    self.comments
                        .lock()
                        .unwrap()
                        .values()
                        .filter(|comment| {
                            comment_issue_keys
                                .get(&comment.id)
                                .is_none_or(|owner_issue_key| owner_issue_key.as_str() == issue_key)
                        })
                        .count() as u32,
                ),
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn add_comment(
        &self,
        _issue_key: &str,
        request: JiraCommentAddRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("add_comment", credential);
        self.added_comments.lock().unwrap().push(request.clone());
        let mut comment = jira_comment("10042");
        comment.body = Some(request.body);
        comment.visibility = request.visibility;
        comment.parent_id = request.parent_id;
        Ok(JiraBackendResponse {
            value: comment,
            status: 201,
            duration_ms: 5,
        })
    }

    async fn update_comment(
        &self,
        _issue_key: &str,
        comment_id: &str,
        request: JiraCommentUpdateRequest,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("update_comment", credential);
        self.updated_comments
            .lock()
            .unwrap()
            .push((comment_id.to_string(), request.clone()));
        let mut comment = jira_comment(comment_id);
        comment.body = Some(request.body);
        comment.visibility = request.visibility;
        Ok(JiraBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 5,
        })
    }

    async fn delete_comment(
        &self,
        _issue_key: &str,
        comment_id: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("delete_comment", credential);
        self.deleted_comments
            .lock()
            .unwrap()
            .push(comment_id.to_string());
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 5,
        })
    }

    async fn add_attachment(
        &self,
        _issue_key: &str,
        attachment: JiraAttachmentUpload,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError> {
        self.record_credential("add_attachment", credential);
        let mut attachment = attachment;
        attachment.bytes = attachment.read_bytes().unwrap();
        attachment.temp_file = None;
        self.uploaded_attachments
            .lock()
            .unwrap()
            .push(attachment.clone());
        Ok(JiraBackendResponse {
            value: JiraAttachment {
                id: "10055".to_string(),
                filename: attachment.filename,
                size: attachment.size,
                content_type: attachment.content_type,
            },
            status: 200,
            duration_ms: 6,
        })
    }

    async fn issue_attachment_metadata(
        &self,
        _issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError> {
        self.record_credential("issue_attachment_metadata", credential);
        Ok(JiraBackendResponse {
            value: self.attachments.lock().unwrap().clone(),
            status: 200,
            duration_ms: 7,
        })
    }

    async fn issue_attachment_list(
        &self,
        issue_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError> {
        self.record_credential("issue_attachment_list", credential);
        let issue = self
            .issues
            .get(issue_key)
            .cloned()
            .ok_or(JiraBackendError::NotFound)?;
        Ok(JiraBackendResponse {
            value: JiraIssueAttachmentList {
                issue: agent_access_jira::JiraIssueMetadata {
                    id: issue.id,
                    key: issue.key,
                    project: issue.project,
                },
                attachments: self.attachments.lock().unwrap().clone(),
            },
            status: 200,
            duration_ms: 7,
        })
    }

    async fn attachment_content(
        &self,
        attachment_id: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachmentContent>, JiraBackendError> {
        self.record_credential("attachment_content", credential);
        Ok(JiraBackendResponse {
            value: self
                .attachment_content
                .lock()
                .unwrap()
                .get(attachment_id)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 8,
        })
    }

    async fn comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("comment", credential);
        let comment = self
            .comments
            .lock()
            .unwrap()
            .get(comment_id)
            .cloned()
            .ok_or(JiraBackendError::NotFound)?;
        if self
            .comment_issue_keys
            .lock()
            .unwrap()
            .get(comment_id)
            .is_some_and(|owner_issue_key| owner_issue_key.as_str() != issue_key)
        {
            return Err(JiraBackendError::NotFound);
        }
        Ok(JiraBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn comment_property_keys(
        &self,
        _comment_id: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPropertyKeys>, JiraBackendError> {
        self.record_credential("comment_property_keys", credential);
        Ok(JiraBackendResponse {
            value: JiraCommentPropertyKeys {
                keys: self.property_keys.lock().unwrap().clone(),
            },
            status: 200,
            duration_ms: 10,
        })
    }

    async fn comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<serde_json::Value>, JiraBackendError> {
        self.record_credential("comment_property", credential);
        Ok(JiraBackendResponse {
            value: self
                .properties
                .lock()
                .unwrap()
                .get(property_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 10,
        })
    }

    async fn set_comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        value: serde_json::Value,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("set_comment_property", credential);
        self.set_properties
            .lock()
            .unwrap()
            .push((property_key.to_string(), value));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 10,
        })
    }

    async fn delete_comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        credential: &agent_access_jira::AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("delete_comment_property", credential);
        self.deleted_properties
            .lock()
            .unwrap()
            .push(property_key.to_string());
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 10,
        })
    }
}

/// Starts the broker assembly on `access`'s configuration, serving `jira` in
/// place of the Jira provider its configuration would build.
async fn start_broker(
    access: JiraAccess,
    jira: agent_access_provider::ServiceProvider,
) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let document = jira_document(application.directory(), access);
    application
        .config_document(document)
        .provider_fixture("jira", ProviderFixture::instance(jira))
        .start()
        .await
        .unwrap()
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

/// Who may call the broker, and with which Jira grants.
#[derive(Clone, Copy, Debug)]
enum JiraAccess {
    /// Anonymous callers use the service credential on project PROJ.
    AnonymousService,
    /// The static principal `agent-one`, a member of group `agents`, uses the
    /// service credential on PROJ.
    AgentService,
    /// As [`Self::AgentService`], and `agent-one` also uses its own
    /// credential on every project.
    AgentPerUser,
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A `file:` secret reference to a new private file in `directory`.
fn secret_ref(directory: &FixtureDir, name: &str, contents: &str) -> String {
    let path = directory.secret_file(name, contents).unwrap();
    toml_string(format_args!("file:{}", path.display()))
}

/// The Jira provider (`jira_provider_config(2)`), its service and read-only
/// lookup credentials, the PROJ and all-projects resources, JSONL audit in
/// `audit.jsonl`, and `access`'s identity and grants.
fn jira_document(directory: &FixtureDir, access: JiraAccess) -> String {
    let actions = serde_json::to_string(&jira_actions()).unwrap();
    let mut document = format!(
        r#"
[credentials.service.jira]
type = "basic_api_token"
username_ref = {service_username}
token_ref = {service_token}

[credentials.lookup.jira]
type = "basic_api_token"
username_ref = {lookup_username}
token_ref = {lookup_token}
read_only = true

[providers.jira]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/rest/api/3/**"]
attachments = {{ media_types = ["text/plain"] }}
content = {{ comment_formats = ["adf"] }}
search = {{ max_results = 2 }}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "project-proj"
resource_type = "{resource_type}"
selector = {{ kind = "exact", value = "PROJ" }}
allowed_execution_contexts = ["default"]

[[policy.resources]]
id = "all-projects"
resource_type = "{resource_type}"
selector = {{ kind = "all" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = [{service_subject}]
service = "jira"
actions = {actions}
resources = {{ resource_ids = ["project-proj"] }}
credential_mode = "service"

[limits]
upload_spool_dir = {spool}

[audit]
type = "jsonl"
path = {audit}
"#,
        service_username = secret_ref(directory, "jira-username.txt", "service@example.com"),
        service_token = secret_ref(directory, "jira-token.txt", "jira-token"),
        lookup_username = secret_ref(directory, "jira-lookup-username.txt", "lookup@example.com"),
        lookup_token = secret_ref(directory, "jira-lookup-token.txt", "jira-lookup-token"),
        resource_type = JIRA_PROJECT_RESOURCE.id().as_str(),
        service_subject = toml_string(match access {
            JiraAccess::AnonymousService => "group:anonymous",
            JiraAccess::AgentService | JiraAccess::AgentPerUser => "group:agents",
        }),
        spool = toml_string(directory.join("upload-spool").display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
    );
    document.push_str(&match access {
        JiraAccess::AnonymousService => r#"
[identity]
mode = "anonymous"
authority = "toml"
"#
        .to_string(),
        JiraAccess::AgentService | JiraAccess::AgentPerUser => format!(
            r#"
[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"

[[identity.sources.principals]]
principal = "agent-one"
token_refs = [{agent_token}]

[[identity.groups]]
id = "agents"
status = "active"
members = ["agent-one"]
"#,
            agent_token = secret_ref(directory, "agent-token.txt", "agent-token"),
        ),
    });
    if let JiraAccess::AgentPerUser = access {
        let username = directory
            .secret_file("jira-per-user-username.txt", "agent-one@example.com")
            .unwrap();
        let token = directory
            .secret_file("jira-per-user-token.txt", "jira-per-user-token")
            .unwrap();
        let credentials = serde_json::json!({"credentials": [{
            "principal": "agent-one",
            "type": "basic_api_token",
            "username_ref": format!("file:{}", username.display()),
            "token_ref": format!("file:{}", token.display()),
        }]});
        let store = directory
            .secret_file("jira-per-user-store.json", credentials.to_string())
            .unwrap();
        document.push_str(&format!(
            r#"
[credentials.per_user.jira]
type = "secret_store"
provider = "local_file"
path = {store}

[[policy.grants]]
subjects = ["user:agent-one"]
service = "jira"
actions = {actions}
resources = {{ resource_ids = ["all-projects"] }}
credential_mode = "per_user"
"#,
            store = toml_string(store.display()),
        ));
    }
    document
}

fn jira_actions() -> Vec<String> {
    [
        "issue_type.list",
        "issue.view",
        "issue.create",
        "issue.child.create",
        "issue.update",
        "issue.parent.set",
        "issue.dependency.add",
        "search",
        "comment.list",
        "comment.view",
        "comment.add",
        "comment.reply",
        "comment.update",
        "comment.delete",
        "comment.property.list",
        "comment.property.get",
        "comment.property.set",
        "comment.property.delete",
        "attachment.add",
        "attachment.download",
        "attachment.list",
        "verify",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn jira_issue_metadata(id: &str, key: &str, project: &str) -> agent_access_jira::JiraIssueMetadata {
    agent_access_jira::JiraIssueMetadata {
        id: id.to_string(),
        key: key.to_string(),
        project: project.to_string(),
    }
}

fn jira_parent_readback(
    issue: agent_access_jira::JiraIssueMetadata,
    parent: agent_access_jira::JiraIssueMetadata,
) -> JiraIssueParentReadback {
    JiraIssueParentReadback {
        issue,
        parent: Some(JiraIssueParent {
            id: Some(parent.id),
            key: Some(parent.key),
        }),
    }
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn authenticated_jira_cli(base_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base_url,
        "--token-value",
        "agent-token",
        "--identity-header",
        "X-Agent-Access-Identity-Token",
        "--identity-scheme",
        "raw",
    ]);
    command
}

/// Asserts the operations the stub backend served and the configured
/// credential, named by its token, each one received.
fn assert_credential_observations(backend: &StubJiraBackend, expected: &[(&str, &str)]) {
    let actual = backend.credential_observations.lock().unwrap().clone();
    let expected = expected
        .iter()
        .map(|(operation, token)| CredentialObservation {
            operation: operation.to_string(),
            credential: jira_credential(token),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

/// The configured Jira credential whose token is `token` (see
/// `jira_document`).
fn jira_credential(token: &str) -> agent_access_provider::ExecutionCredential {
    let username = match token {
        "jira-token" => "service@example.com",
        "jira-lookup-token" => "lookup@example.com",
        "jira-per-user-token" => "agent-one@example.com",
        other => panic!("no configured Jira credential has the token {other}"),
    };
    basic_credential(username, token)
}

fn jira_provider_config(max_results: u32) -> JiraProviderConfig {
    JiraProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
        attachments: agent_access_provider::AttachmentLimitsConfig {
            media_types: vec!["text/plain".to_string()],
            ..agent_access_provider::AttachmentLimitsConfig::default()
        },
        content: agent_access_jira::JiraContentConfig {
            comment_formats: vec!["adf".to_string()],
            ..agent_access_jira::JiraContentConfig::default()
        },
        search: SearchLimitsConfig { max_results },
        listing: Default::default(),
        comments: agent_access_jira::JiraCommentsConfig::default(),
        issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
    }
}

fn jira_comment(id: &str) -> JiraComment {
    JiraComment {
        id: id.to_string(),
        parent_id: None,
        body: None,
        author: None,
        created: None,
        updated: None,
        visibility: None,
    }
}

fn jira_comment_with_body(id: &str, text: &str) -> JiraComment {
    let mut comment = jira_comment(id);
    comment.body = Some(jira_adf_text(text));
    comment
}

fn jira_adf_text(text: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": text
            }]
        }]
    })
}

fn assert_new_backend_operations(backend: &StubJiraBackend, cursor: &mut usize, expected: &[&str]) {
    let observations = backend.credential_observations.lock().unwrap();
    let actual = observations[*cursor..]
        .iter()
        .map(|observation| observation.operation.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    *cursor = observations.len();
}

#[path = "support/temp_dirs.rs"]
mod temp_dirs;
use temp_dirs::temp_path;

#[path = "jira_custom_fields/mod.rs"]
mod custom_fields;

#[path = "jira_issue_context/mod.rs"]
mod issue_context;
