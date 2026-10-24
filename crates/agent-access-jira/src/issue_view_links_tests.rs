use super::*;
use agent_access_provider::presentation::{
    ReadContentFormat, ResponseFormat, ResponseOptions, present_result,
};
use wiremock::matchers::{header, query_param};

const ISSUE_FIELDS: &str = "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels,description";

const CONTEXT_KEYS: &[&str] = &[
    "resolution",
    "resolutionDate",
    "dueDate",
    "components",
    "fixVersions",
    "affectedVersions",
    "statusCategory",
];

fn view_baseline(issue: &JiraIssue) -> Value {
    let mut result = issue_view_result(issue, &jira_config());
    result["customFields"] = json!([]);
    for key in CONTEXT_KEYS {
        result[*key] = Value::Null;
    }
    result
}

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
        "*all,-comment,-attachment,-worklog".to_string()
    } else {
        "*all,-comment,-attachment,-worklog,-subtasks,-parent,-issuelinks".to_string()
    };
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .and(query_param("fields", fields))
        .and(query_param("expand", "names,schema"))
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
    let omission = view.documentation.as_ref().unwrap()["omission"]
        .as_str()
        .unwrap();
    for meaning in [
        "Missing parent means hierarchy was withheld",
        "A null parent is not independent proof",
        "Missing subtasks or issueLinks means withheld or not returned",
        "universal same-mode authority withholds all links, parent and subtasks",
    ] {
        assert!(omission.contains(meaning));
    }
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
            let baseline = view_baseline(&issue_from_value(source).unwrap());
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
        source["fields"]["parent"] =
            json!({"key":"PRIVATE-42","fields":{"summary":"private parent summary"}});
        source["fields"]["subtasks"] =
            json!([{"key":"PRIVATE-43","fields":{"summary":"private child summary"}}]);
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
        assert!(!format!("{error:?}").contains("PRIVATE-"));
        assert!(!format!("{error:?}").contains("private parent"));
        assert_eq!(api.received_requests().await.unwrap().len(), 2);
    }

    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.issue_view_links.lock().unwrap() =
        viewed_issue_links_from_value(&source_issue(Some(json!([linked_issue()])))).unwrap();
    let baseline = view_baseline(&visible_issue());
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
async fn mutation_readbacks_and_search_ignore_unsolicited_links_and_custom_fields() {
    let api = MockServer::start().await;
    let mut source = issue_context_source();
    source["fields"]["issuelinks"] = json!({"private-malformed-links": true});
    source["fields"]["customfield_10001"] = json!("private-custom-value");
    source["names"] = json!({"customfield_10001": "private-custom-name"});
    source["schema"] = json!({"customfield_10001": {"type":"string", "custom":"com.atlassian.jira.plugin.system.customfieldtypes:textfield"}});
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
        assert!(result.result["issue"].get("customFields").is_none());
        for key in CONTEXT_KEYS.iter().copied().chain(["parent", "subtasks"]) {
            assert!(result.result["issue"].get(key).is_none(), "{action}: {key}");
        }
        assert!(result.audit.as_ref().unwrap().get("customFields").is_none());
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
    assert!(result.result["issues"][0].get("customFields").is_none());
    for key in CONTEXT_KEYS.iter().copied().chain(["parent", "subtasks"]) {
        assert!(
            result.result["issues"][0].get(key).is_none(),
            "search: {key}"
        );
    }
    assert!(result.audit.as_ref().unwrap().get("customFields").is_none());
    assert!(!result.result.to_string().contains("private"));
    assert_eq!(api.received_requests().await.unwrap().len(), 6);
}

#[test]
fn issue_links_markdown_has_omission_empty_metadata_escaping_and_bounds() {
    let base = view_baseline(&visible_issue());
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

#[tokio::test]
async fn expanded_issue_view_projects_custom_fields_without_releasing_other_fetched_fields() {
    for universal_reach in [false, true] {
        let api = MockServer::start().await;
        let mut source = source_issue(Some(if universal_reach {
            json!([])
        } else {
            json!({"private-links": true})
        }));
        source["fields"]["customfield_10"] = json!("Visible custom value");
        source["fields"]["customfield_2"] = json!(null);
        source["fields"]["customfield_11"] = json!({"private-app-object": "private-value"});
        source["fields"]["customfield_12"] = json!(123);
        source["fields"]["customfield_13"] = json!([]);
        source["fields"]["customfield_14"] = json!("Unnamed value");
        source["fields"]["customfield_01"] = json!("private-invalid-id");
        for field in ["comment", "attachment", "worklog", "environment"] {
            source["fields"][field] = json!({"private-standard-field": "private-content"});
        }
        source["names"] = json!({
            "customfield_2": "Duplicate label", "customfield_10": "Duplicate label",
            "customfield_11": "App label", "customfield_12": "Invalid known value",
            "customfield_13": "Empty app value", "customfield_99": "private-metadata-only"
        });
        let text_schema = json!({"type":"string", "custom":"com.atlassian.jira.plugin.system.customfieldtypes:textfield"});
        source["schema"] = json!({
            "customfield_2": text_schema, "customfield_10": text_schema,
            "customfield_11": {"type":"string", "custom":"private:app"},
            "customfield_12": text_schema,
            "customfield_13": {"type":"array", "items":"string", "custom":"private:app"},
            "customfield_14": text_schema
        });
        mount_source_reads(&api, source, universal_reach).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let response = provider
            .invoke(view_invocation(universal_reach))
            .await
            .unwrap();
        assert_eq!(
            response.result["customFields"],
            json!([
                {"id":"customfield_2", "name":"Duplicate label", "type":"text", "status":"supported", "value":null},
                {"id":"customfield_10", "name":"Duplicate label", "type":"text", "status":"supported", "value":"Visible custom value"},
                {"id":"customfield_11", "name":"App label", "type":null, "status":"unsupported"},
                {"id":"customfield_12", "name":"Invalid known value", "type":"text", "status":"withheld"},
                {"id":"customfield_13", "name":"Empty app value", "type":null, "status":"unsupported", "value":[]},
                {"id":"customfield_14", "name":null, "type":"text", "status":"supported", "value":"Unnamed value"}
            ])
        );
        assert_eq!(
            response.audit.as_ref().unwrap()["customFields"],
            json!({"count":6, "unsupported":2, "withheld":1})
        );
        assert!(!response.result.to_string().contains("private"));
        let audit = response.audit.unwrap().to_string();
        for secret in [
            "Duplicate label",
            "Visible custom value",
            "App label",
            "Unnamed value",
            "customfield_",
            "private",
        ] {
            assert!(!audit.contains(secret), "custom data escaped into audit");
        }
        let requests = api.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].url.query_pairs().collect::<Vec<_>>(),
            [("fields".into(), "project".into())]
        );
        assert_eq!(requests[1].url.query_pairs().count(), 2);
    }
}

#[tokio::test]
async fn custom_field_view_limits_fail_the_whole_response_without_partial_values() {
    // Empty paragraphs keep the byte size modest while reaching the renderer's
    // actual per-document node guard, independently of the content byte guard.
    let dense = |paragraphs| {
        json!({
            "type":"doc", "version":1,
            "content": vec![json!({"type":"paragraph", "content":[]}); paragraphs]
        })
    };
    for case in [
        "body-bytes",
        "result-bytes",
        "document-nodes",
        "shared-nodes",
    ] {
        let api = MockServer::start().await;
        let mut source = source_issue(None);
        source["fields"]["customfield_1"] = json!("private-before-the-failure");
        source["names"] =
            json!({"customfield_1":"private-label-before", "customfield_2":"private-label-after"});
        source["schema"] = json!({
            "customfield_1":{"type":"string","custom":"com.atlassian.jira.plugin.system.customfieldtypes:textfield"},
            "customfield_2":{"type":"string","custom":"com.atlassian.jira.plugin.system.customfieldtypes:textarea"}
        });
        let mut config = jira_config();
        config.content.max_body_bytes = 16 * 1024 * 1024;
        let mut limits = ProviderLimits::default();
        match case {
            "body-bytes" => {
                config.content.max_body_bytes = 128;
                source["fields"]["customfield_2"] = adf_text(&"private-custom-body".repeat(128));
            }
            "result-bytes" => {
                limits = limits.with_max_upstream_response_bytes(512);
                source["schema"]["customfield_2"]["custom"] =
                    json!("com.atlassian.jira.plugin.system.customfieldtypes:textfield");
                source["fields"]["customfield_2"] = json!("private-custom-body".repeat(128));
            }
            "document-nodes" => {
                let document = dense(65_536);
                assert!(matches!(
                    agent_access_content::render_adf_bounded_with_budget(
                        &document,
                        ReadContentFormat::Native,
                        config.content.max_body_bytes,
                        config.content.max_body_bytes,
                        &mut agent_access_provider::presentation::RenderBudget::default(),
                    ),
                    Err(agent_access_content::ContentRenderError::NodeLimitExceeded)
                ));
                source["fields"]["customfield_2"] = document;
            }
            "shared-nodes" => {
                let document = dense(50_000);
                agent_access_content::render_adf_bounded_with_budget(
                    &document,
                    ReadContentFormat::Native,
                    config.content.max_body_bytes,
                    config.content.max_body_bytes,
                    &mut agent_access_provider::presentation::RenderBudget::default(),
                )
                .unwrap();
                source["fields"]["description"] = document.clone();
                source["fields"]["customfield_2"] = document.clone();
                source["fields"]["customfield_3"] = document;
                source["schema"]["customfield_3"] = source["schema"]["customfield_2"].clone();
            }
            _ => unreachable!(),
        }
        mount_source_reads(&api, source, false).await;
        // Give the fixture HTTP receiver its ordinary cap so result-bytes
        // specifically exercises the provider's final projected-result guard.
        let provider = JiraProvider::with_backend(
            config,
            limits,
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let error = provider.invoke(view_invocation(false)).await.unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::UpstreamProtocolFailed,
            "{case}"
        );
        assert!(
            error.result.is_none(),
            "{case} must not return partial fields"
        );
        assert!(!format!("{error:?}").contains("private"), "{case}");
        assert_eq!(
            api.received_requests().await.unwrap().len(),
            2,
            "{case} must not retry"
        );
    }
}

#[tokio::test]
async fn malformed_custom_adf_is_withheld_after_fetch_while_valid_custom_fields_survive() {
    let api = MockServer::start().await;
    let mut source = source_issue(None);
    source["fields"]["customfield_1"] = json!({
        "type":"doc", "version":1,
        "content":[{"type":"paragraph", "content":[{"type":"text", "text":{"private-malformed-content":true}}]}]
    });
    source["fields"]["customfield_2"] = adf_text("valid custom notes");
    source["schema"] = json!({
        "customfield_1":{"type":"string","custom":"com.atlassian.jira.plugin.system.customfieldtypes:textarea"},
        "customfield_2":{"type":"string","custom":"com.atlassian.jira.plugin.system.customfieldtypes:textarea"}
    });
    mount_source_reads(&api, source, false).await;
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(http_backend(&api, ProviderLimits::default())),
    );
    let result = provider.invoke(view_invocation(false)).await.unwrap();
    assert_eq!(
        result.result["customFields"][0],
        json!({
            "id":"customfield_1", "name":null, "type":"adf", "status":"withheld"
        })
    );
    assert_eq!(result.result["customFields"][1]["status"], "supported");
    assert_eq!(
        result.result["customFields"][1]["value"],
        adf_text("valid custom notes")
    );
    assert_eq!(
        result.audit.unwrap()["customFields"],
        json!({"count":2,"unsupported":0,"withheld":1})
    );
    assert!(!result.result.to_string().contains("private"));
    assert_eq!(api.received_requests().await.unwrap().len(), 2);
}

fn issue_context_source() -> Value {
    let mut source = source_issue(Some(json!([linked_issue()])));
    source["fields"]["resolution"] =
        json!({"id":"1", "name":"Resolved", "description":"private-resolution-description"});
    source["fields"]["resolutiondate"] = json!("2026-10-23T12:30:00.000+0530");
    source["fields"]["duedate"] = json!("2026-10-30");
    source["fields"]["components"] = json!([
        {"id":"20", "name":"API", "lead":{"emailAddress":"private@example.test"}},
        {"id":"21", "self":"https://private.invalid/component"},
        {"id":"20", "name":"API"}
    ]);
    source["fields"]["fixVersions"] = json!([
        {"id":"30", "name":"Release one", "description":"private-release-description", "released":true}
    ]);
    source["fields"]["versions"] = json!([]);
    source["fields"]["status"] = json!({
        "name":"Closed", "statusCategory":{"id":3,"key":"custom-done","name":"Complete","colorName":"private-color"}
    });
    source["fields"]["parent"] = json!({
        "id":"private-parent-id", "key":"EPIC-42", "self":"https://private.invalid/parent",
        "fields":{
            "summary":"Parent context summary", "issuetype":{"name":"Portfolio work", "hierarchyLevel":1},
            "description":"private-parent-body", "project":{"key":"private-project"}
        }
    });
    source["fields"]["subtasks"] = json!([
        {"key":"CHILD-2","self":"https://private.invalid/child","fields":{"summary":"Child context summary","issuetype":{"name":"Sub-task"},"assignee":{"emailAddress":"private@example.test"}}},
        {"key":"CHILD-2","fields":{"summary":"Child context summary","issuetype":{"name":"Sub-task"}}},
        {"key":"PROJ-12"}
    ]);
    // Legacy Epic Link must remain unsupported; a modern parent never promotes
    // a separate custom implementation into a generally disclosed reference.
    source["fields"]["customfield_10001"] = json!("PRIVATE-9");
    source["names"] = json!({"customfield_10001":"Epic Link"});
    source["schema"] = json!({"customfield_10001":{"type":"string","custom":"com.pyxis.greenhopper.jira:gh-epic-link"}});
    source
}

fn assert_standard_context(result: &Value) {
    assert_eq!(result["resolution"], json!({"id":"1","name":"Resolved"}));
    assert_eq!(result["resolutionDate"], "2026-10-23T12:30:00.000+0530");
    assert_eq!(result["dueDate"], "2026-10-30");
    assert_eq!(
        result["components"],
        json!([
            {"id":"20","name":"API"}, {"id":"21","name":null}, {"id":"20","name":"API"}
        ])
    );
    assert_eq!(
        result["fixVersions"],
        json!([{"id":"30","name":"Release one"}])
    );
    assert_eq!(result["affectedVersions"], json!([]));
    assert_eq!(
        result["statusCategory"],
        json!({"id":3,"key":"custom-done","name":"Complete"})
    );
}

#[tokio::test]
async fn context_is_view_only_and_hierarchy_uses_the_same_fetch_and_gate_as_links() {
    for universal_reach in [false, true] {
        let api = MockServer::start().await;
        let mut source = issue_context_source();
        if !universal_reach {
            // Unrequested references must not be parsed, including malformed
            // unsolicited containers that would fail an eligible view.
            source["fields"]["parent"] = json!("private-unrequested-parent");
            source["fields"]["subtasks"] = json!({"private-unrequested-subtasks":true});
            source["fields"]["issuelinks"] = json!(null);
        }
        mount_source_reads(&api, source, universal_reach).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let response = provider
            .invoke(view_invocation(universal_reach))
            .await
            .unwrap();
        assert_standard_context(&response.result);
        assert_eq!(
            response.result["customFields"],
            json!([
                {"id":"customfield_10001","name":"Epic Link","type":null,"status":"unsupported"}
            ])
        );
        let audit = response.audit.as_ref().unwrap();
        if universal_reach {
            assert_eq!(
                response.result["parent"],
                json!({"key":"EPIC-42","summary":"Parent context summary","issueType":"Portfolio work"})
            );
            assert_eq!(
                response.result["subtasks"],
                json!([
                    {"key":"CHILD-2","summary":"Child context summary","issueType":"Sub-task"},
                    {"key":"CHILD-2","summary":"Child context summary","issueType":"Sub-task"},
                    {"key":"PROJ-12","summary":null,"issueType":null}
                ])
            );
            assert_eq!(response.result["issueLinks"], json!([expected_link()]));
            assert_eq!(audit["parent"], json!({"status":"disclosed","count":1}));
            assert_eq!(audit["subtasks"], json!({"status":"disclosed","count":3}));
        } else {
            for key in ["parent", "subtasks", "issueLinks"] {
                assert!(response.result.get(key).is_none());
                assert_eq!(audit[key], json!({"status":"withheld"}));
            }
        }
        for secret in ["private", "PRIVATE-9", "hierarchyLevel"] {
            assert!(!response.result.to_string().contains(secret));
        }
        assert!(response.result.get("epic").is_none());
        for secret in [
            "Resolved",
            "Release one",
            "EPIC-42",
            "CHILD-2",
            "context summary",
            "Epic Link",
            "custom-done",
            "private",
        ] {
            assert!(!audit.to_string().contains(secret));
        }
        let requests = api.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() == "/rest/api/3/issue/PROJ-1")
        );
        assert_eq!(requests[0].url.query_pairs().count(), 1);
        assert_eq!(requests[1].url.query_pairs().count(), 2);
    }
}

#[tokio::test]
async fn eligible_parent_and_subtask_absence_have_explicit_output_and_audit_semantics() {
    for (parent, subtasks, expected_subtasks) in [
        (None, None, None),
        (Some(Value::Null), Some(json!([])), Some(json!([]))),
    ] {
        let api = MockServer::start().await;
        let mut source = source_issue(None);
        if let Some(parent) = parent {
            source["fields"]["parent"] = parent;
        }
        if let Some(subtasks) = subtasks {
            source["fields"]["subtasks"] = subtasks;
        }
        mount_source_reads(&api, source, true).await;
        let provider = JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            Arc::new(http_backend(&api, ProviderLimits::default())),
        );
        let response = provider.invoke(view_invocation(true)).await.unwrap();
        assert_eq!(response.result.get("parent"), Some(&Value::Null));
        assert_eq!(response.result.get("subtasks"), expected_subtasks.as_ref());
        assert_eq!(
            response.audit.as_ref().unwrap()["parent"],
            json!({"status":"disclosed","count":0})
        );
        assert_eq!(
            response.audit.as_ref().unwrap()["subtasks"],
            if expected_subtasks.is_some() {
                json!({"status":"disclosed","count":0})
            } else {
                json!({"status":"not-returned"})
            }
        );
        for key in CONTEXT_KEYS {
            assert_eq!(response.result.get(*key), Some(&Value::Null));
        }
        let rendered = markdown(response.result, 16384).unwrap();
        let text = rendered["value"].as_str().unwrap();
        assert!(text.contains("## Parent\n\nNo parent returned."));
        assert_eq!(text.contains("## Subtasks"), expected_subtasks.is_some());
        assert_eq!(api.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn provider_suppresses_hierarchy_from_a_backend_that_ignores_the_disclosure_flag() {
    for (universal, returned_parent) in [(false, true), (true, true), (true, false)] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".into(), visible_issue());
        *backend.issue_view_context.lock().unwrap() = JiraIssueViewContext {
            parent: returned_parent.then(|| JiraIssueViewReference {
                key: "PARENT-42".into(),
                summary: Some("private parent summary".into()),
                issue_type: None,
            }),
            subtasks: Some(vec![JiraIssueViewReference {
                key: "CHILD-42".into(),
                summary: Some("private child summary".into()),
                issue_type: None,
            }]),
            ..Default::default()
        };
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let response = provider.invoke(view_invocation(universal)).await.unwrap();
        assert_eq!(
            *backend.issue_view_link_requests.lock().unwrap(),
            vec![universal]
        );
        if universal {
            assert_eq!(response.result["parent"].is_null(), !returned_parent);
            assert!(response.result.get("parent").is_some());
            assert_eq!(response.result["subtasks"][0]["key"], "CHILD-42");
            assert_eq!(
                response.audit.as_ref().unwrap()["parent"],
                json!({"status":"disclosed","count":usize::from(returned_parent)})
            );
        } else {
            assert!(response.result.get("parent").is_none());
            assert!(response.result.get("subtasks").is_none());
            let text = markdown(response.result, 16384).unwrap().to_string();
            for secret in ["PARENT-42", "CHILD-42", "private"] {
                assert!(!text.contains(secret));
            }
            assert_eq!(
                response.audit.as_ref().unwrap()["parent"],
                json!({"status":"withheld"})
            );
            assert_eq!(
                response.audit.as_ref().unwrap()["subtasks"],
                json!({"status":"withheld"})
            );
        }
    }
}
