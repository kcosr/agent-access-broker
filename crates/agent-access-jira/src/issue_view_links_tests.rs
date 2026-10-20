use super::*;
use agent_access_provider::presentation::{
    ReadContentFormat, ResponseFormat, ResponseOptions, present_result,
};
use wiremock::matchers::{header, query_param};

const ISSUE_FIELDS: &str = "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels,description";

fn source_issue(links: Option<Value>) -> Value {
    let mut value = json!({
        "id": "10001", "key": "PROJ-1",
        "fields": {
            "project": {"key": "PROJ"},
            "summary": "Source title",
            "issuetype": {"name": "Task"}
        }
    });
    if let Some(links) = links {
        value["fields"]["issuelinks"] = links;
    }
    value
}

fn linked_issue() -> Value {
    json!({
        "id": "private-link-id",
        "self": "https://private.invalid/link",
        "type": {
            "id": "private-type-id", "name": "Blocks",
            "inward": "is blocked by", "outward": "blocks",
            "self": "https://private.invalid/type"
        },
        "outwardIssue": {
            "id": "private-issue-id", "key": "CM-42",
            "self": "https://private.invalid/issue",
            "fields": {
                "summary": "Linked title",
                "issuetype": {
                    "name": "Bug", "description": "private-type-description",
                    "scope": {"project": {"key": "private-type-project"}}
                },
                "issueType": {"name": "private-alias-type"},
                "project": {"key": "private-project"},
                "status": {"name": "private-status"},
                "priority": {"name": "private-priority"},
                "assignee": {"displayName": "private-assignee"},
                "description": "private-description",
                "unknown": "private-unknown"
            }
        }
    })
}

fn expected_link() -> Value {
    json!({
        "key": "CM-42", "type": "Blocks", "direction": "outward",
        "relationship": "blocks", "summary": "Linked title", "issueType": "Bug"
    })
}

fn http_backend(api: &MockServer, limits: ProviderLimits) -> HttpJiraBackend {
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/**", api.uri())];
    HttpJiraBackend::new_with_api_base(
        config,
        limits,
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    )
}

fn view_invocation(universal_reach: bool) -> ProviderInvocation {
    InvocationBuilder::new("jira", "issue.view")
        .inputs(json!({"issue": "PROJ-1"}))
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .universal_reach(universal_reach)
        .credential(bearer_credential("execution-token"))
        .lookup_credential(bearer_credential("lookup-token"))
        .build()
}

async fn mount_source_reads(api: &MockServer, value: Value, include_links: bool) {
    // Metadata lookup intentionally has other linked content; only execution may disclose it.
    let mut metadata = source_issue(None);
    metadata["fields"]["issuelinks"] = json!("private-lookup-only-content");
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .and(query_param("fields", "project"))
        .and(header("Authorization", "Bearer lookup-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .expect(1)
        .mount(api)
        .await;
    let fields = if include_links {
        format!("{ISSUE_FIELDS},issuelinks")
    } else {
        ISSUE_FIELDS.to_string()
    };
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .and(query_param("fields", fields))
        .and(header("Authorization", "Bearer execution-token"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .expect(1)
        .mount(api)
        .await;
}

fn markdown(mut result: Value, limit: u64) -> Result<Value, ProviderError> {
    present_result(
        present::presentation("issue.view").as_ref(),
        &mut result,
        ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
        4096,
        limit,
    )?;
    Ok(result)
}

#[test]
fn issue_view_alone_reports_universal_reach_and_documents_omission() {
    let descriptor = jira_descriptor(&jira_config());
    assert_eq!(
        descriptor
            .actions
            .iter()
            .filter(|action| action.reports_universal_reach)
            .map(|action| action.action.as_str())
            .collect::<Vec<_>>(),
        ["issue.view"]
    );
    let view = descriptor
        .actions
        .iter()
        .find(|action| action.action == "issue.view")
        .unwrap();
    assert!(
        view.documentation.as_ref().unwrap()["omission"]
            .as_str()
            .unwrap()
            .contains("not that no links exist")
    );
    assert!(
        view.input_schema["properties"]
            .get("universalReach")
            .is_none()
    );
}

#[test]
fn viewed_links_allowlist_both_directions_and_preserve_duplicates() {
    let outward = linked_issue();
    let mut inward = outward.clone();
    let issue = inward
        .as_object_mut()
        .unwrap()
        .remove("outwardIssue")
        .unwrap();
    inward["inwardIssue"] = issue;
    inward["inwardIssue"]["key"] = json!("APP_TEAM-7");
    let value = source_issue(Some(json!([outward, inward, linked_issue()])));
    let parsed = viewed_issue_links_from_value(&value).unwrap().unwrap();
    let expected_inward = json!({
        "key": "APP_TEAM-7", "type": "Blocks", "direction": "inward",
        "relationship": "is blocked by", "summary": "Linked title", "issueType": "Bug"
    });
    let projected = json!(parsed);
    assert_eq!(
        projected,
        json!([expected_link(), expected_inward, expected_link()])
    );
    assert!(!projected.to_string().contains("private"));
    let many = source_issue(Some(json!(vec![linked_issue(); 101])));
    assert_eq!(
        viewed_issue_links_from_value(&many).unwrap().unwrap().len(),
        101
    );
}

#[test]
fn viewed_links_distinguish_absence_empty_and_nullable_metadata() {
    assert_eq!(
        viewed_issue_links_from_value(&source_issue(None)).unwrap(),
        None
    );
    assert_eq!(
        viewed_issue_links_from_value(&source_issue(Some(json!([])))).unwrap(),
        Some(Vec::new())
    );
    for fields in [
        None,
        Some(Value::Null),
        Some(json!({})),
        Some(json!({"summary": null, "issuetype": null})),
        Some(json!({"issueType": {"name": "private-alias-type"}})),
    ] {
        let mut link = linked_issue();
        let object = link["outwardIssue"].as_object_mut().unwrap();
        object.remove("fields");
        if let Some(fields) = fields {
            object.insert("fields".to_string(), fields);
        }
        let links = viewed_issue_links_from_value(&source_issue(Some(json!([link]))))
            .unwrap()
            .unwrap();
        assert_eq!(links[0].summary, None);
        assert_eq!(links[0].issue_type, None);
        assert_eq!(json!(links)[0]["summary"], Value::Null);
        assert_eq!(json!(links)[0]["issueType"], Value::Null);
    }
}

#[test]
fn viewed_links_reject_malformed_supplied_shapes_without_echoing_content() {
    let mut malformed = vec![
        Value::Null,
        json!({}),
        json!("private-container"),
        json!([null]),
        json!([{"type":{"name":"Blocks","outward":"blocks"}}]),
    ];
    for (pointer, invalid) in [
        ("/type", Value::Null),
        ("/type", json!("private-type")),
        ("/type/name", Value::Null),
        ("/type/name", json!(["private-name"])),
        ("/type/name", json!(" \n ")),
        ("/type/outward", Value::Null),
        ("/type/outward", json!({"private-label": true})),
        ("/type/outward", json!("")),
        ("/outwardIssue", Value::Null),
        ("/outwardIssue", json!("private-issue")),
        ("/outwardIssue/key", json!("private-key")),
        ("/outwardIssue/key", json!("CM-0")),
        ("/outwardIssue/key", json!(42)),
        ("/outwardIssue/fields", json!("private-fields")),
        ("/outwardIssue/fields", json!([])),
        (
            "/outwardIssue/fields/summary",
            json!({"private-summary": true}),
        ),
        ("/outwardIssue/fields/summary", json!(1)),
        ("/outwardIssue/fields/issuetype", json!("private-issuetype")),
        ("/outwardIssue/fields/issuetype", json!([])),
        ("/outwardIssue/fields/issuetype", json!({})),
        ("/outwardIssue/fields/issuetype/name", Value::Null),
        (
            "/outwardIssue/fields/issuetype/name",
            json!(["private-name"]),
        ),
    ] {
        let mut link = linked_issue();
        *link.pointer_mut(pointer).unwrap() = invalid;
        malformed.push(json!([link]));
    }
    for field in ["type", "outwardIssue"] {
        let mut link = linked_issue();
        link.as_object_mut().unwrap().remove(field);
        malformed.push(json!([link]));
    }
    for other_direction in [Value::Null, json!({"key": "OTHER-1"})] {
        let mut link = linked_issue();
        link["inwardIssue"] = other_direction;
        malformed.push(json!([link]));
    }
    for links in malformed {
        let error = viewed_issue_links_from_value(&source_issue(Some(links))).unwrap_err();
        assert!(matches!(error, JiraBackendError::Protocol(_)));
        assert!(!format!("{error:?}").contains("private"));
        let error = jira_backend_error(error);
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, "Jira response protocol error");
    }
}

#[tokio::test]
async fn issue_view_fetches_links_only_with_universal_reach_using_execution_access() {
    for universal_reach in [false, true] {
        let api = MockServer::start().await;
        let source = source_issue(Some(if universal_reach {
            json!([linked_issue()])
        } else {
            // A withheld field must not even be parsed.
            json!({"private-invalid-links": true})
        }));
        mount_source_reads(&api, source.clone(), universal_reach).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let result = provider
            .invoke(view_invocation(universal_reach))
            .await
            .unwrap();
        if universal_reach {
            assert_eq!(result.result["issueLinks"], json!([expected_link()]));
            assert_eq!(
                result.audit.as_ref().unwrap()["issueLinks"],
                json!({"status": "disclosed", "count": 1})
            );
        } else {
            let baseline = issue_view_result(&issue_from_value(source).unwrap(), &jira_config());
            assert_eq!(result.result, baseline);
            assert_eq!(
                markdown(result.result.clone(), 16384).unwrap(),
                markdown(baseline, 16384).unwrap()
            );
            assert_eq!(
                result.audit.as_ref().unwrap()["issueLinks"],
                json!({"status": "withheld"})
            );
        }
        assert!(!result.result.to_string().contains("private"));
        let audit = result.audit.as_ref().unwrap().to_string();
        for secret in ["CM-42", "Linked title", "private"] {
            assert!(!audit.contains(secret));
        }
        let presented = markdown(result.result, 16384).unwrap();
        assert!(!presented.to_string().contains("private"));
        if universal_reach {
            assert!(
                presented["value"]
                    .as_str()
                    .unwrap()
                    .contains("- This issue blocks `CM-42` (type: Blocks; direction: outward")
            );
        }
        let requests = api.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.body.is_empty()));
    }
}

#[tokio::test]
async fn issue_view_records_only_disclosed_counts_and_rejects_null_links() {
    for (links, expected_status, expected_count) in [
        (None, "not-returned", None),
        (Some(json!([])), "disclosed", Some(0)),
        (Some(Value::Null), "error", None),
    ] {
        let api = MockServer::start().await;
        mount_source_reads(&api, source_issue(links), true).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let response = provider.invoke(view_invocation(true)).await;
        if expected_status == "error" {
            let error = response.unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert!(error.result.is_none());
        } else {
            let response = response.unwrap();
            let audit = &response.audit.as_ref().unwrap()["issueLinks"];
            assert_eq!(audit["status"], expected_status);
            if let Some(count) = expected_count {
                assert_eq!(audit["count"], count);
                assert_eq!(response.result["issueLinks"], json!([]));
            } else {
                assert!(audit.get("count").is_none());
                assert!(response.result.get("issueLinks").is_none());
            }
        }
        assert_eq!(api.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn issue_view_links_keep_source_identity_confirmation_and_byte_bounds() {
    for (mut source, limits, expected_reason) in [
        (
            source_issue(Some(json!([linked_issue()]))),
            ProviderLimits::default(),
            ReasonCode::ScopeUnresolved,
        ),
        (
            source_issue(Some(json!([linked_issue()]))),
            ProviderLimits::default().with_max_upstream_response_bytes(512),
            ReasonCode::UpstreamProtocolFailed,
        ),
    ] {
        if expected_reason == ReasonCode::ScopeUnresolved {
            source["id"] = json!("different-source-id");
        }
        let api = MockServer::start().await;
        mount_source_reads(&api, source, true).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            limits.clone(),
            Arc::new(http_backend(&api, limits)),
        );
        let error = provider.invoke(view_invocation(true)).await.unwrap_err();
        assert_eq!(error.reason_code(), expected_reason);
        assert!(error.result.is_none());
        assert!(!error.message.contains("Linked title"));
        assert_eq!(api.received_requests().await.unwrap().len(), 2);
    }

    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.issue_view_links.lock().unwrap() =
        viewed_issue_links_from_value(&source_issue(Some(json!([linked_issue()])))).unwrap();
    let baseline = issue_view_result(&visible_issue(), &jira_config());
    let cap = serde_json::to_vec(&baseline).unwrap().len() as u64;
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default().with_max_upstream_response_bytes(cap),
        Arc::new(backend),
    );
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .universal_reach(true)
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(error.result.is_none());
}

#[tokio::test]
async fn mutation_readbacks_and_search_ignore_unsolicited_links() {
    let api = MockServer::start().await;
    let source = source_issue(Some(json!({"private-malformed-links": true})));
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .and(query_param("fields", ISSUE_FIELDS))
        .respond_with(ResponseTemplate::new(200).set_body_json(source.clone()))
        .expect(2)
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .and(query_param("fields", "project"))
        .respond_with(ResponseTemplate::new(200).set_body_json(source.clone()))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001", "key": "PROJ-1"
        })))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .and(query_param(
            "fields",
            "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [source], "isLast": true
        })))
        .expect(1)
        .mount(&api)
        .await;
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(http_backend(&api, ProviderLimits::default())),
    );
    for (action, inputs) in [
        (
            "issue.create",
            json!({"project":"PROJ","issueTypeId":"10001","summary":"Source title"}),
        ),
        (
            "issue.update",
            json!({"issue":"PROJ-1","summary":"Source title"}),
        ),
    ] {
        let result = provider
            .invoke(
                InvocationBuilder::new("jira", action)
                    .inputs(inputs)
                    .resources(BTreeMap::from([(
                        "project".to_string(),
                        vec!["PROJ".to_string()],
                    )]))
                    .universal_reach(true)
                    .credential(test_credential())
                    .lookup_credential(test_lookup_credential())
                    .build(),
            )
            .await
            .unwrap();
        assert!(result.result["issue"].get("issueLinks").is_none());
        assert!(!result.result.to_string().contains("private"));
    }
    let result = provider
        .invoke(
            InvocationBuilder::new("jira", "search")
                .inputs(json!({"query":{"type":"jql","value":"project = PROJ"}}))
                .search(search_preflight(["PROJ"]))
                .universal_reach(true)
                .credential(test_credential())
                .build(),
        )
        .await
        .unwrap();
    assert!(result.result["issues"][0].get("issueLinks").is_none());
    assert!(!result.result.to_string().contains("private"));
    assert_eq!(api.received_requests().await.unwrap().len(), 6);
}

#[test]
fn issue_links_markdown_has_omission_empty_metadata_escaping_and_bounds() {
    let base = issue_view_result(&visible_issue(), &jira_config());
    let absent = markdown(base.clone(), 16384).unwrap();
    assert!(!absent["value"].as_str().unwrap().contains("## Issue links"));
    let mut empty = base.clone();
    empty["issueLinks"] = json!([]);
    assert!(
        markdown(empty, 16384).unwrap()["value"]
            .as_str()
            .unwrap()
            .contains("\n## Issue links\n\nNone.\n")
    );
    let mut result = base;
    result["issueLinks"] = json!([{
        "key": "CM-42", "type": "Blocks\n## private-forged",
        "direction": "outward", "relationship": "blocks *work*",
        "summary": "Fix **bug**\n# forged", "issueType": "Bug\n- forged"
    }, {
        "key": "CM-42", "type": "Blocks", "direction": "inward",
        "relationship": "is blocked by", "summary": null, "issueType": null
    }]);
    let rendered = markdown(result.clone(), 16384).unwrap();
    let text = rendered["value"].as_str().unwrap();
    assert!(text.contains("- This issue blocks \\*work\\* `CM-42`"));
    assert!(text.contains("type: Blocks ## private-forged; direction: outward"));
    assert!(text.contains("issue type: Bug - forged"));
    assert!(text.contains("Fix \\*\\*bug\\*\\* # forged"));
    assert!(text.contains("- This issue is blocked by `CM-42` (type: Blocks; direction: inward)"));
    assert!(!text.contains("\n## private-forged"));
    assert!(!text.contains("\n# forged"));
    assert!(!text.contains("\n- forged"));
    let exact = serde_json::to_vec(&rendered).unwrap().len() as u64;
    assert_eq!(markdown(result.clone(), exact).unwrap(), rendered);
    assert_eq!(
        markdown(result, exact - 1).unwrap_err().reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}
