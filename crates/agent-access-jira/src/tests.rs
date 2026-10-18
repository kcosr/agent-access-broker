use super::*;
use agent_access_provider::test_support::{InvocationBuilder, basic_credential, bearer_credential};
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "issue_type_tests.rs"]
mod issue_type_tests;

#[path = "underscore_key_tests.rs"]
mod underscore_key_tests;

#[path = "renamed_project_key_tests.rs"]
mod renamed_project_key_tests;

#[path = "moved_issue_tests.rs"]
mod moved_issue_tests;

#[path = "search_continuation_tests.rs"]
mod search_continuation_tests;

#[test]
fn parses_issue_keys_and_rejects_lowercase_or_zero_numbers() {
    assert!(is_issue_key("PROJ-1"));
    assert!(!is_issue_key("proj-1"));
    assert!(!is_issue_key("Proj-1"));
    assert!(!is_issue_key("PROJ-0"));
    assert!(!is_issue_key("P-1"));
    assert_eq!(
        issue_locator_from_key("proj-1").unwrap_err().reason_code(),
        ReasonCode::LocatorInvalid
    );
}

#[test]
fn parses_jira_issue_url_for_configured_tenant_only() {
    let config = jira_config();
    let locator =
        issue_locator_from_url("https://example.atlassian.net/browse/PROJ-123", &config).unwrap();
    assert_eq!(locator.issue_key, "PROJ-123");
    let modern = issue_locator_from_url(
        "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-123",
        &config,
    )
    .unwrap();
    assert_eq!(modern.issue_key, "PROJ-123");
    assert_eq!(
        issue_locator_from_url("https://other.atlassian.net/browse/PROJ-123", &config)
            .unwrap_err()
            .reason_code(),
        ReasonCode::LocatorInvalid
    );
    for raw in [
        "https://user@example.atlassian.net/browse/PROJ-123",
        "https://example.atlassian.net:443/browse/PROJ-123",
        "https://example.atlassian.net/jira/software/c/projects/proj/issues/PROJ-123",
        "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/proj-123",
        "https://example.atlassian.net/rest/api/3/issue/662790",
        "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-123?selectedIssue=PROJ-123",
    ] {
        assert_eq!(
            issue_locator_from_url(raw, &config)
                .unwrap_err()
                .reason_code(),
            ReasonCode::LocatorInvalid
        );
    }
}

#[test]
fn parses_restricted_jql_project_scopes() {
    assert_eq!(projects("key = PROJ-124"), set(["PROJ"]));
    assert_eq!(projects("key in (PROJ-124, PROJ-125)"), set(["PROJ"]));
    assert_eq!(projects("project = PROJ"), set(["PROJ"]));
    assert_eq!(
        projects("(project = PROJ AND key = PROJ-124) OR (project = PROJ AND key = PROJ-125)"),
        set(["PROJ"])
    );
    assert_eq!(
        projects("key = PROJ-124 OR project = OTHER"),
        set(["PROJ", "OTHER"])
    );
}

#[test]
fn rejects_unsafe_jql_shapes() {
    for jql in [
        "project = PROJ AND key = PROJ-124 OR project = OTHER",
        "project != OTHER",
        "filter = 12345",
        "key = proj-124",
        "issueFunction in linkedIssuesOf(\"project = PROJ\")",
        "description !~ \"secret\"",
        "NOT project = PROJ",
        "updated WAS \"2024-01-01\"",
        "cf[12345] = value",
        "key = PROJ-124 ORDER BY unknown DESC",
        "(key = PROJ-124 ORDER BY updated DESC)",
        "status = foo:bar",
        "labels = +urgent",
    ] {
        assert!(parse_jql_projects(jql).is_err(), "{jql}");
    }
}

#[test]
fn expanded_jql_canonicalizes_allowed_fields_without_folding() {
    assert_eq!(canonical_jql("status = Done"), "status = Done");
    assert_eq!(canonical_jql("status = \"Done\""), "status = Done");
    assert_eq!(canonical_jql("labels = \"AND\""), "labels = \"AND\"");
    assert_eq!(canonical_jql("labels = AND"), "labels = \"AND\"");
    assert_eq!(
        canonical_jql("assignee = \"EMPTY\""),
        "assignee = \"EMPTY\""
    );
    assert_eq!(canonical_jql("assignee = EMPTY"), "assignee = \"EMPTY\"");
    assert_eq!(
        canonical_jql("labels = \"-urgent\""),
        "labels = \"-urgent\""
    );
    assert_eq!(
        canonical_jql("statusCategory = Done"),
        "statusCategory = Done"
    );
    assert_eq!(
        canonical_jql("type IN (Bug, \"Story\")"),
        "issuetype IN (Bug, Story)"
    );
    assert_eq!(
        canonical_jql("reporter = alice AND creator = bob"),
        "reporter = alice AND creator = bob"
    );
    assert_eq!(
        canonical_jql("fixVersions = \"1.0\" AND affectedVersions = \"2.0\""),
        "fixVersion = 1.0 AND affectedVersion = 2.0"
    );
}

#[test]
fn expanded_jql_accepts_field_operator_groups_and_ordering() {
    assert_eq!(
        canonical_jql("status = \"In Progress\" AND (priority = High OR priority = Highest)"),
        "status = \"In Progress\" AND (priority = High OR priority = Highest)"
    );
    assert_eq!(
        canonical_jql("labels NOT IN (security, \"needs triage\")"),
        "labels NOT IN (security, \"needs triage\")"
    );
    assert_eq!(
        canonical_jql("resolution IS NOT EMPTY"),
        "resolution IS NOT EMPTY"
    );
    assert_eq!(
        canonical_jql("updated >= startOfDay(-7d) ORDER BY updated DESC, key"),
        "updated >= startOfDay(-7d) ORDER BY updated DESC, key ASC"
    );
    assert_eq!(
        canonical_jql("updated >= \"2024-01-01 12:30\""),
        "updated >= \"2024-01-01 12:30\""
    );
    assert_eq!(canonical_jql("updated >= -7d"), "updated >= -7d");
    assert_eq!(canonical_jql("updated >= +1d"), "updated >= +1d");
    assert_eq!(
        canonical_jql("summary ~ \"deploy checklist\""),
        "summary ~ \"deploy checklist\""
    );
}

#[test]
fn current_user_function_requires_per_user_credential_mode() {
    let service_error =
        parse_jql_query("assignee = currentUser()", CredentialMode::Service).unwrap_err();
    assert_eq!(service_error.reason_code(), ReasonCode::InputInvalid);

    let per_user = parse_jql_query("assignee = currentUser()", CredentialMode::PerUser).unwrap();
    assert_eq!(per_user.emit(), "assignee = currentUser()");
}

#[test]
fn rejects_expanded_jql_caps_and_function_edges() {
    let long_string = format!(
        "summary ~ \"{}\"",
        "a".repeat(MAX_JIRA_STRING_LITERAL_BYTES + 1)
    );
    assert_eq!(
        parse_jql_expression(&long_string)
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );

    let long_tokens = "A ".repeat(MAX_JIRA_QUERY_TOKENS + 1);
    assert_eq!(
        parse_jql_expression(&long_tokens)
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );

    let in_values = (0..=MAX_JIRA_IN_LIST_VALUES)
        .map(|index| format!("S{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(parse_jql_expression(&format!("status IN ({in_values})")).is_err());

    assert!(
        parse_jql_expression(
            "status = Done ORDER BY key, updated, created, status, priority, issuetype"
        )
        .is_err()
    );
    assert!(parse_jql_expression("updated >= startOfDay(-1M)").is_err());
    assert!(parse_jql_expression("updated >= startOfDay(now())").is_err());
    assert!(parse_jql_expression("updated >= 2024-01-01T12:30:00Z").is_err());
    assert!(parse_jql_expression("status CHANGED FROM Open").is_err());
}

#[test]
fn canonical_hash_is_stable_across_equivalent_quote_styles() {
    let quoted = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = \"Done\"".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    let bare = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = Done".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();

    assert_eq!(quoted.jql, "status = Done");
    assert_eq!(bare.jql, "status = Done");
    assert_eq!(
        quoted.canonical_caller_jql_hash,
        bare.canonical_caller_jql_hash
    );

    let quoted_reserved = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "labels = \"AND\"".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    let bare_reserved = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "labels = AND".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();

    assert_eq!(quoted_reserved.jql, "labels = \"AND\"");
    assert_eq!(bare_reserved.jql, "labels = \"AND\"");
    assert_eq!(
        quoted_reserved.canonical_caller_jql_hash,
        bare_reserved.canonical_caller_jql_hash
    );
}

#[test]
fn search_inputs_reject_unknown_nested_query_fields() {
    let error = parse_search_inputs(&json!({
        "query": {
            "type": "jql",
            "value": "project = PROJ",
            "extra": true
        }
    }))
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn jira_transport_error_message_is_sanitized() {
    let error = jira_backend_error(JiraBackendError::Transport(
        "error sending request for url (https://example.atlassian.net/rest/api/3/search/jql?jql=summary%20~%20%22secret%22)".to_string(),
    ));
    assert_eq!(error.message, "Jira request failed");
}

#[test]
fn jira_protocol_error_message_is_sanitized() {
    let error = jira_backend_error(JiraBackendError::Protocol(
        "missing field `id` at line 1 column 42".to_string(),
    ));

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.message, "Jira response protocol error");
    assert!(!error.message.contains("missing field"));
}

#[test]
fn comment_parser_preserves_body_and_id_mismatches_fail_closed() {
    let comment = comment_from_value(json!({
        "id": "10042",
        "parentId": 10041,
        "body": adf_table()
    }))
    .unwrap();
    assert_eq!(comment.id, "10042");
    assert_eq!(comment.parent_id.as_deref(), Some("10041"));
    assert_eq!(
        comment.body.as_ref().unwrap()["content"][0]["type"],
        "table"
    );
    assert_eq!(comment_result(&comment)["parentCommentId"], "10041");

    let error = validate_returned_comment_id("99999", Some("10042")).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[test]
fn returned_body_validation_has_exact_serialized_caps_and_sanitized_failures() {
    let empty_document = json!({"type": "doc", "version": 1, "content": []});
    let exact_size = serde_json::to_vec(&empty_document).unwrap().len() as u64;

    let mut issue = visible_issue();
    issue.description = Some(empty_document.clone());
    let mut config = jira_config();
    config.content.max_body_bytes = exact_size;
    validate_returned_issue_description(&issue, &config).unwrap();
    config.content.max_body_bytes = exact_size - 1;
    let issue_error = validate_returned_issue_description(&issue, &config).unwrap_err();
    assert_eq!(
        issue_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(issue_error.reason_code().http_status(), 502);
    assert_eq!(
        issue_error.message,
        "Jira issue description response was invalid"
    );

    issue.description = None;
    config.content.max_body_bytes = 0;
    validate_returned_issue_description(&issue, &config).unwrap();

    let mut comment = test_comment("10042");
    comment.body = Some(empty_document);
    validate_returned_comment_body(&comment, exact_size).unwrap();
    let comment_error = validate_returned_comment_body(&comment, exact_size - 1).unwrap_err();
    assert_eq!(
        comment_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(comment_error.reason_code().http_status(), 502);
    assert_eq!(
        comment_error.message,
        "Jira comment response body was invalid"
    );

    comment.body = None;
    validate_returned_comment_body(&comment, 0).unwrap();

    comment.body = Some(json!({"type": "doc", "version": 1, "content": "sentinel"}));
    let malformed = validate_returned_comment_body(&comment, u64::MAX).unwrap_err();
    assert_eq!(malformed.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(malformed.message, "Jira comment response body was invalid");
    assert!(!malformed.message.contains("sentinel"));
}

fn projects(jql: &str) -> BTreeSet<String> {
    parse_jql_projects(jql).unwrap()
}

fn canonical_jql(jql: &str) -> String {
    parse_jql_query(jql, CredentialMode::Service)
        .unwrap()
        .emit()
}

fn set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(ToString::to_string).collect()
}

#[derive(Default)]
struct StubJiraBackend {
    issue_type_page: Mutex<Option<JiraIssueTypePage>>,
    issue_type_requests: Mutex<Vec<(String, JiraIssueTypeListRequest)>>,
    issues: BTreeMap<String, JiraIssue>,
    issue_readbacks: Mutex<BTreeMap<String, JiraIssue>>,
    /// Errors for `issue` reads of a key, such as a throttled read-back.
    issue_errors: Mutex<BTreeMap<String, JiraBackendError>>,
    created_issue: Mutex<Option<JiraCreatedIssue>>,
    issue_create_error: Mutex<Option<JiraBackendError>>,
    created_issues: Mutex<Vec<JiraIssueCreateRequest>>,
    updated_issues: Mutex<Vec<(String, JiraIssueUpdateRequest)>>,
    issue_update_error: Mutex<Option<JiraBackendError>>,
    parent_updates: Mutex<Vec<(String, JiraIssueParentSetRequest)>>,
    issue_parent_update_error: Mutex<Option<JiraBackendError>>,
    issue_parent_readbacks: Mutex<BTreeMap<String, JiraIssueParentReadback>>,
    issue_parent_error: Mutex<Option<JiraBackendError>>,
    issue_link_types: Mutex<Vec<JiraIssueLinkType>>,
    created_issue_links: Mutex<Vec<JiraIssueLinkCreateRequest>>,
    issue_link_readbacks: Mutex<BTreeMap<String, JiraIssueLinks>>,
    issue_links_error: Mutex<Option<JiraBackendError>>,
    search_page: Mutex<Option<JiraSearchPage>>,
    last_search: Mutex<Option<JiraSearchRequest>>,
    last_comment_list: Mutex<Option<JiraCommentListRequest>>,
    comments: Mutex<BTreeMap<String, JiraComment>>,
    comment_issue_keys: Mutex<BTreeMap<String, String>>,
    added_comments: Mutex<Vec<JiraCommentAddRequest>>,
    add_comment_parent_override: Mutex<Option<Option<String>>>,
    returned_comment_body: Mutex<Option<Value>>,
    updated_comments: Mutex<Vec<(String, JiraCommentUpdateRequest)>>,
    deleted_comments: Mutex<Vec<String>>,
    property_keys: Mutex<Vec<String>>,
    properties: Mutex<BTreeMap<String, Value>>,
    set_properties: Mutex<Vec<(String, Value)>>,
    deleted_properties: Mutex<Vec<String>>,
    attachments: Mutex<Vec<JiraAttachment>>,
    attachment_list_issue: Mutex<Option<JiraIssueMetadata>>,
    attachment_content: Mutex<BTreeMap<String, JiraAttachmentContent>>,
    uploaded_attachments: Mutex<Vec<JiraAttachmentUpload>>,
    fail_upload_after_successes: Mutex<Option<usize>>,
    upload_error: Mutex<Option<JiraBackendError>>,
    comment_error: Mutex<Option<JiraBackendError>>,
    credential_observations: Mutex<Vec<CredentialObservation>>,
}

/// One credential the stub backend received. Credentials compare by kind
/// and material, so tests check which one arrived without reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialObservation {
    operation: String,
    credential: ExecutionCredential,
}

impl StubJiraBackend {
    fn record_credential(&self, operation: &str, credential: &AtlassianCredential) {
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
    async fn issue_types(
        &self,
        project: &str,
        request: JiraIssueTypeListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueTypePage>, JiraBackendError> {
        self.record_credential("issue_types", credential);
        self.issue_type_requests
            .lock()
            .unwrap()
            .push((project.to_string(), request));
        Ok(JiraBackendResponse {
            value: self
                .issue_type_page
                .lock()
                .unwrap()
                .clone()
                .expect("issue type page fixture"),
            status: 200,
            duration_ms: 7,
        })
    }

    async fn current_user(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        self.record_credential("current_user", credential);
        Ok(JiraBackendResponse {
            value: json!({"accountId": "alice-account"}),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn issue_metadata(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, JiraBackendError> {
        self.record_credential("issue_metadata", credential);
        let issue = self
            .issues
            .get(issue_key)
            .cloned()
            .ok_or(JiraBackendError::NotFound)?;
        Ok(JiraBackendResponse {
            value: JiraIssueMetadata {
                id: issue.id,
                key: issue.key,
                project: issue.project,
            },
            status: 200,
            duration_ms: 3,
        })
    }

    async fn issue(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError> {
        self.record_credential("issue", credential);
        if let Some(error) = self.issue_errors.lock().unwrap().get(issue_key).cloned() {
            return Err(error);
        }
        if let Some(issue) = self.issue_readbacks.lock().unwrap().get(issue_key).cloned() {
            return Ok(JiraBackendResponse {
                value: issue,
                status: 200,
                duration_ms: 7,
            });
        }
        Ok(JiraBackendResponse {
            value: self
                .issues
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn create_issue(
        &self,
        request: JiraIssueCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCreatedIssue>, JiraBackendError> {
        self.record_credential("create_issue", credential);
        self.created_issues.lock().unwrap().push(request);
        if let Some(error) = self.issue_create_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(JiraBackendResponse {
            value: self
                .created_issue
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(JiraCreatedIssue {
                    id: "10001".to_string(),
                    key: "PROJ-2".to_string(),
                }),
            status: 201,
            duration_ms: 11,
        })
    }

    async fn update_issue(
        &self,
        issue_key: &str,
        request: JiraIssueUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("update_issue", credential);
        if let Some(error) = self.issue_update_error.lock().unwrap().clone() {
            return Err(error);
        }
        self.updated_issues
            .lock()
            .unwrap()
            .push((issue_key.to_string(), request));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 13,
        })
    }

    async fn set_issue_parent(
        &self,
        issue_key: &str,
        request: JiraIssueParentSetRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("set_issue_parent", credential);
        if let Some(error) = self.issue_parent_update_error.lock().unwrap().clone() {
            return Err(error);
        }
        self.parent_updates
            .lock()
            .unwrap()
            .push((issue_key.to_string(), request));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 13,
        })
    }

    async fn issue_parent(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueParentReadback>, JiraBackendError> {
        self.record_credential("issue_parent", credential);
        if let Some(error) = self.issue_parent_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(JiraBackendResponse {
            value: self
                .issue_parent_readbacks
                .lock()
                .unwrap()
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn issue_link_types(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraIssueLinkType>>, JiraBackendError> {
        self.record_credential("issue_link_types", credential);
        Ok(JiraBackendResponse {
            value: self.issue_link_types.lock().unwrap().clone(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn create_issue_link(
        &self,
        request: JiraIssueLinkCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("create_issue_link", credential);
        self.created_issue_links.lock().unwrap().push(request);
        Ok(JiraBackendResponse {
            value: (),
            status: 201,
            duration_ms: 6,
        })
    }

    async fn issue_links(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueLinks>, JiraBackendError> {
        self.record_credential("issue_links", credential);
        if let Some(error) = self.issue_links_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(JiraBackendResponse {
            value: self
                .issue_link_readbacks
                .lock()
                .unwrap()
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn search(
        &self,
        request: JiraSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError> {
        self.record_credential("search", credential);
        *self.last_search.lock().unwrap() = Some(request);
        Ok(JiraBackendResponse {
            value: self.search_page.lock().unwrap().clone().unwrap(),
            status: 200,
            duration_ms: 9,
        })
    }

    async fn comments(
        &self,
        issue_key: &str,
        request: JiraCommentListRequest,
        credential: &AtlassianCredential,
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
            duration_ms: 10,
        })
    }

    async fn add_comment(
        &self,
        _issue_key: &str,
        request: JiraCommentAddRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("add_comment", credential);
        self.added_comments.lock().unwrap().push(request.clone());
        let mut comment = test_comment("10042");
        comment.body = Some(
            self.returned_comment_body
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(request.body),
        );
        comment.visibility = request.visibility;
        comment.parent_id = self
            .add_comment_parent_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(request.parent_id);
        Ok(JiraBackendResponse {
            value: comment,
            status: 201,
            duration_ms: 11,
        })
    }

    async fn update_comment(
        &self,
        _issue_key: &str,
        comment_id: &str,
        request: JiraCommentUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("update_comment", credential);
        self.updated_comments
            .lock()
            .unwrap()
            .push((comment_id.to_string(), request.clone()));
        let mut comment = test_comment(comment_id);
        comment.body = Some(
            self.returned_comment_body
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(request.body),
        );
        comment.visibility = request.visibility;
        Ok(JiraBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 12,
        })
    }

    async fn delete_comment(
        &self,
        _issue_key: &str,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("delete_comment", credential);
        self.deleted_comments
            .lock()
            .unwrap()
            .push(comment_id.to_string());
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 12,
        })
    }

    async fn add_attachment(
        &self,
        _issue_key: &str,
        attachment: JiraAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError> {
        self.record_credential("add_attachment", credential);
        let mut uploaded = self.uploaded_attachments.lock().unwrap();
        if self
            .fail_upload_after_successes
            .lock()
            .unwrap()
            .is_some_and(|count| uploaded.len() >= count)
        {
            return Err(self
                .upload_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(JiraBackendError::HttpStatus(500)));
        }
        let id = format!("{}", 10050 + uploaded.len());
        let value = JiraAttachment {
            id,
            filename: attachment.filename.clone(),
            size: attachment.size,
            content_type: attachment.content_type.clone(),
        };
        let mut attachment = attachment;
        attachment.bytes = attachment.read_bytes().map_err(|error| {
            JiraBackendError::Protocol(format!("failed to read uploaded attachment: {error}"))
        })?;
        attachment.temp_file = None;
        uploaded.push(attachment);
        Ok(JiraBackendResponse {
            value,
            status: 200,
            duration_ms: 13,
        })
    }

    async fn issue_attachment_metadata(
        &self,
        _issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError> {
        self.record_credential("issue_attachment_metadata", credential);
        Ok(JiraBackendResponse {
            value: self.attachments.lock().unwrap().clone(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn issue_attachment_list(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError> {
        self.record_credential("issue_attachment_list", credential);
        let issue = if let Some(issue) = self.attachment_list_issue.lock().unwrap().clone() {
            issue
        } else {
            let issue = self
                .issues
                .get(issue_key)
                .cloned()
                .ok_or(JiraBackendError::NotFound)?;
            JiraIssueMetadata {
                id: issue.id,
                key: issue.key,
                project: issue.project,
            }
        };
        Ok(JiraBackendResponse {
            value: JiraIssueAttachmentList {
                issue,
                attachments: self.attachments.lock().unwrap().clone(),
            },
            status: 200,
            duration_ms: 6,
        })
    }

    async fn attachment_content(
        &self,
        attachment_id: &str,
        credential: &AtlassianCredential,
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
            duration_ms: 17,
        })
    }

    async fn comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.record_credential("comment", credential);
        if let Some(error) = self.comment_error.lock().unwrap().clone() {
            return Err(error);
        }
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
            duration_ms: 19,
        })
    }

    async fn comment_property_keys(
        &self,
        _comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPropertyKeys>, JiraBackendError> {
        self.record_credential("comment_property_keys", credential);
        Ok(JiraBackendResponse {
            value: JiraCommentPropertyKeys {
                keys: self.property_keys.lock().unwrap().clone(),
            },
            status: 200,
            duration_ms: 20,
        })
    }

    async fn comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
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
            duration_ms: 21,
        })
    }

    async fn set_comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        value: Value,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("set_comment_property", credential);
        self.set_properties
            .lock()
            .unwrap()
            .push((property_key.to_string(), value));
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 22,
        })
    }

    async fn delete_comment_property(
        &self,
        _comment_id: &str,
        property_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        self.record_credential("delete_comment_property", credential);
        self.deleted_properties
            .lock()
            .unwrap()
            .push(property_key.to_string());
        Ok(JiraBackendResponse {
            value: (),
            status: 204,
            duration_ms: 23,
        })
    }
}

#[tokio::test]
async fn issue_view_returns_generated_browser_url() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let response = provider
        .invoke(InvocationBuilder::new("jira", "issue.view")
            .inputs(json!({
                "url": "https://example.atlassian.net/jira/software/c/projects/PROJ/issues/PROJ-1"
            }))
            .resources(BTreeMap::from([("project".to_string(), vec!["PROJ".to_string()])]))
            .credential(test_credential())
            .lookup_credential(test_lookup_credential())
            .build())
        .await
        .unwrap();

    assert_eq!(response.result["key"], "PROJ-1");
    assert_eq!(
        response.result["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );
    assert_eq!(
        response.result["description"]["content"][0]["content"][0]["text"],
        "visible description body"
    );
    assert!(
        !response
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("visible description body")
    );
}

#[tokio::test]
async fn issue_view_returns_null_description_when_jira_omits_description() {
    let mut backend = StubJiraBackend::default();
    let mut issue = visible_issue();
    issue.description = None;
    backend.issues.insert("PROJ-1".to_string(), issue);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert!(response.result["description"].is_null());
}

#[test]
fn issue_create_capability_is_project_scoped_without_lookup() {
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(StubJiraBackend::default()),
    );
    let action = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue.create")
        .unwrap();
    assert_eq!(action.required_scope_types(), vec!["project".to_string()]);
    assert_eq!(action.lookup, LookupRequirement::None);
    assert_eq!(
        action.input_schema["required"],
        json!(["project", "issueTypeId", "summary"])
    );
}

#[tokio::test]
async fn issue_create_uses_authorized_project_and_returns_readback_issue() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut issue = visible_issue();
    issue.id = "10002".to_string();
    issue.key = "PROJ-2".to_string();
    issue.project = "PROJ".to_string();
    issue.summary = Some("Created issue".to_string());
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), issue);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Created issue",
                    "contentFormat": "adf",
                    "content": adf_text("create body")
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(response.result["operation"], "issue.create");
    assert_eq!(response.result["issue"]["key"], "PROJ-2");
    assert_eq!(
        response.audit.as_ref().unwrap()["descriptionProvided"],
        true
    );
    assert!(
        !response
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("Created issue")
    );
    assert_eq!(
        response.object_ids,
        Some(json!({"issueId": "10002", "issueKey": "PROJ-2"}))
    );
    let created = backend.created_issues.lock().unwrap().clone();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].project, "PROJ");
    assert_eq!(created[0].issue_type_id, "10001");
    assert_eq!(created[0].summary, "Created issue");
    assert_eq!(created[0].description.as_ref().unwrap()["type"], "doc");
    assert_credential_observations(&backend, &[("create_issue", "token"), ("issue", "token")]);
}

#[test]
fn issue_create_rejects_invalid_inputs_before_backend() {
    let config = jira_config();
    for inputs in [
        json!({}),
        json!({"issueTypeId": "10001", "summary": "summary"}),
        json!({"project": "PROJ", "summary": "summary"}),
        json!({"project": "PROJ", "issueTypeId": "10001"}),
        json!({"project": "proj", "issueTypeId": "10001", "summary": "summary"}),
        json!({"project": "PROJ", "issueTypeId": "", "summary": "summary"}),
        json!({"project": "PROJ", "issueTypeId": "Task", "summary": "summary"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": ""}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "   "}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "bad\u{0000}summary"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "bad\nsummary"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "x".repeat(MAX_JIRA_ISSUE_SUMMARY_BYTES + 1)}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "contentFormat": "adf"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "content": []}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "contentFormat": "adf", "content": {}}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "extra": true}),
    ] {
        assert!(
            parse_issue_create_inputs(&inputs, &config).is_err(),
            "inputs should reject: {inputs}"
        );
    }
}

#[tokio::test]
async fn issue_create_fails_closed_when_created_key_leaves_requested_project() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "NEW-2".to_string(),
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Created issue"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .build(),
        )
        .await
        .unwrap_err();

    // A valid key in another project is Jira resolving a previous project key:
    // the issue exists outside the authorized project, not a protocol failure.
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.message,
        "Jira created the issue outside the authorized project"
    );
    let receipt = error.result.as_deref().unwrap();
    assert_eq!(receipt["mutationStatus"], "applied_unverified");
    assert_eq!(receipt["retrySafe"], false);
    assert_eq!(receipt["verificationStage"], "mutation_response");
    assert_eq!(receipt["safeLocators"], json!({"project": "PROJ"}));
    let audit = error.audit.unwrap();
    assert_eq!(audit["failurePhase"], "create_response_validation");
    assert_eq!(audit["issueId"], "10002");
    assert_eq!(audit["issueKey"], "NEW-2");
    assert_eq!(audit["descriptionProvided"], false);
    assert!(!audit.to_string().contains("Created issue"));
}

#[tokio::test]
async fn issue_create_malformed_response_emits_side_effect_failure_audit() {
    let backend = StubJiraBackend::default();
    *backend.issue_create_error.lock().unwrap() =
        Some(JiraBackendError::IssueCreateResponseInvalid {
            id: Some("10002".to_string()),
            key: None,
            status: Some(201),
            duration_ms: 11,
        });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Created issue",
                    "contentFormat": "adf",
                    "content": adf_text("created body")
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(error.upstream_duration_ms, Some(11));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({"issueId": "10002"})))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.create");
    assert_eq!(audit["project"], "PROJ");
    assert_eq!(audit["issueTypeId"], "10001");
    assert_eq!(audit["descriptionProvided"], true);
    assert_eq!(audit["failurePhase"], "create_response_validation");
    assert_eq!(audit["issueId"], "10002");
    assert!(audit.get("issueKey").is_none());
    let audit_text = audit.to_string();
    assert!(!audit_text.contains("Created issue"));
    assert!(!audit_text.contains("created body"));
}

#[tokio::test]
async fn issue_create_non_201_success_emits_side_effect_failure_audit() {
    let backend = StubJiraBackend::default();
    *backend.issue_create_error.lock().unwrap() =
        Some(JiraBackendError::IssueCreateResponseInvalid {
            id: Some("10002".to_string()),
            key: Some("PROJ-2".to_string()),
            status: Some(200),
            duration_ms: 11,
        });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(200));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({"issueId": "10002", "issueKey": "PROJ-2"})))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["failurePhase"], "create_response_validation");
    assert_eq!(audit["issueId"], "10002");
    assert_eq!(audit["issueKey"], "PROJ-2");
    assert!(!audit.to_string().contains("Created issue"));
}

#[tokio::test]
async fn issue_create_readback_failure_emits_reconciliation_audit() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue",
            "contentFormat": "adf",
            "content": adf_text("created body")
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2"
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["failurePhase"], "post_create_readback");
    assert_eq!(audit["upstreamFailure"], "not_found");
    assert_eq!(audit["descriptionProvided"], true);
    let audit_text = audit.to_string();
    assert!(!audit_text.contains("Created issue"));
    assert!(!audit_text.contains("created body"));
}

#[tokio::test]
async fn issue_create_readback_invalid_key_or_project_fails_protocol() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "10002".to_string();
    readback.key = "invalid-key".to_string();
    readback.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error.audit.as_ref().unwrap()["failurePhase"],
        "post_create_readback"
    );
    assert_eq!(error.audit.as_ref().unwrap()["issueKey"], "PROJ-2");
}

#[tokio::test]
async fn issue_create_readback_mismatch_fails_scope_unresolved() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "99999".to_string();
    readback.key = "PROJ-2".to_string();
    readback.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.audit.as_ref().unwrap()["failurePhase"],
        "post_create_readback"
    );
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({"issueId": "10002", "issueKey": "PROJ-2"})))
    );
}

#[tokio::test]
async fn issue_create_result_size_failure_keeps_side_effect_audit() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "10002".to_string();
    readback.key = "PROJ-2".to_string();
    readback.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let limits = ProviderLimits::default().with_max_upstream_response_bytes(64);
    let provider = JiraProvider::with_backend(jira_config(), limits, Arc::new(backend));

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.audit.as_ref().unwrap()["failurePhase"],
        "post_create_readback"
    );
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({"issueId": "10002", "issueKey": "PROJ-2"})))
    );
}

#[tokio::test]
async fn issue_create_rejects_project_scope_mismatch_before_backend() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let invocation = InvocationBuilder::from(issue_create_invocation(json!({
        "project": "PROJ",
        "issueTypeId": "10001",
        "summary": "Created issue"
    })))
    .resources(BTreeMap::from([(
        "project".to_string(),
        vec!["OTHER".to_string()],
    )]))
    .build();

    let error = provider.invoke(invocation).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.created_issues.lock().unwrap().is_empty());
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_create_attribution_is_applied_to_description() {
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let expected_description =
        added_attributed_adf_text("description before attribution", broker_request_id);
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "10002".to_string();
    readback.key = "PROJ-2".to_string();
    readback.project = "PROJ".to_string();
    readback.description = Some(expected_description.clone());
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("issue.create")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };
    let mut invocation = issue_create_invocation(json!({
        "project": "PROJ",
        "issueTypeId": "10001",
        "summary": "Created issue",
        "contentFormat": "adf",
        "content": adf_text("description before attribution")
    }));
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let response = provider.invoke(invocation).await.unwrap();

    let created = backend.created_issues.lock().unwrap();
    assert_eq!(
        created[0].description.as_ref().unwrap(),
        &expected_description
    );
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["verb"], "add");
    assert_eq!(audit["attribution"]["target"], "description");
    assert_eq!(audit["attribution"]["representation"], "adf");
    assert!(!audit.to_string().contains("description before attribution"));
}

#[tokio::test]
async fn issue_create_attribution_target_absent_when_description_omitted() {
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "10002".to_string();
    readback.key = "PROJ-2".to_string();
    readback.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("issue.create")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };

    let response = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap();

    assert!(
        backend.created_issues.lock().unwrap()[0]
            .description
            .is_none()
    );
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], false);
    assert_eq!(audit["attribution"]["skipReason"], "target_absent");
}

#[tokio::test]
async fn issue_create_enforces_description_body_cap_after_attribution() {
    let backend = Arc::new(StubJiraBackend::default());
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let attribution = ProviderAttributionConfig::from_patterns(
        &jira_descriptor(&config),
        &[String::from("issue.create")],
    );
    let provider = JiraProvider {
        attribution,
        ..JiraProvider::from_backend(config, ProviderLimits::default(), backend.clone())
    };
    let mut invocation = issue_create_invocation(json!({
        "project": "PROJ",
        "issueTypeId": "10001",
        "summary": "Created issue",
        "contentFormat": "adf",
        "content": adf_text("x")
    }));
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        ))
        .build();

    let error = provider.invoke(invocation).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
    assert!(backend.created_issues.lock().unwrap().is_empty());
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_child_create_attribution_is_applied_to_description() {
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let expected_description =
        added_attributed_adf_text("description before attribution", broker_request_id);
    let mut backend = StubJiraBackend::default();
    seed_child_create_success(&mut backend, Some(expected_description.clone()));
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("issue.child.create")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };
    let mut invocation = issue_child_create_invocation(json!({
        "project": "PROJ",
        "issueTypeId": "10001",
        "summary": "Child issue",
        "parentIssue": "PROJ-1",
        "contentFormat": "adf",
        "content": adf_text("description before attribution")
    }));
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let response = provider.invoke(invocation).await.unwrap();

    let created = backend.created_issues.lock().unwrap();
    assert_eq!(
        created[0].description.as_ref().unwrap(),
        &expected_description
    );
    assert_eq!(created[0].parent_issue.as_deref(), Some("PROJ-1"));
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["verb"], "add");
    assert_eq!(audit["attribution"]["target"], "description");
    assert_eq!(audit["attribution"]["representation"], "adf");
    assert!(!audit.to_string().contains("description before attribution"));
}

#[tokio::test]
async fn issue_child_create_attribution_target_absent_when_description_omitted() {
    let mut backend = StubJiraBackend::default();
    seed_child_create_success(&mut backend, None);
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("issue.child.create")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };

    let response = provider
        .invoke(issue_child_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Child issue",
            "parentIssue": "PROJ-1"
        })))
        .await
        .unwrap();

    assert!(
        backend.created_issues.lock().unwrap()[0]
            .description
            .is_none()
    );
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], false);
    assert_eq!(audit["attribution"]["skipReason"], "target_absent");
}

#[tokio::test]
async fn issue_child_create_enforces_description_body_cap_after_attribution() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let attribution = ProviderAttributionConfig::from_patterns(
        &jira_descriptor(&config),
        &[String::from("issue.child.create")],
    );
    let provider = JiraProvider {
        attribution,
        ..JiraProvider::from_backend(config, ProviderLimits::default(), backend.clone())
    };
    let mut invocation = issue_child_create_invocation(json!({
        "project": "PROJ",
        "issueTypeId": "10001",
        "summary": "Child issue",
        "parentIssue": "PROJ-1",
        "contentFormat": "adf",
        "content": adf_text("x")
    }));
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        ))
        .build();

    let error = provider.invoke(invocation).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
    assert!(backend.created_issues.lock().unwrap().is_empty());
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[tokio::test]
async fn issue_child_create_capability_and_scope_resolution_use_lookup_metadata() {
    let mut backend = StubJiraBackend::default();
    let mut parent = visible_issue();
    parent.id = "10010".to_string();
    parent.key = "OPS-100".to_string();
    parent.project = "OPS".to_string();
    backend.issues.insert("OLD-100".to_string(), parent);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let capability = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue.child.create")
        .unwrap();
    assert_eq!(capability.lookup, LookupRequirement::ScopeResolution);
    assert_eq!(
        capability.required_scope_types(),
        vec!["project".to_string()]
    );
    assert_eq!(
        capability.input_schema["properties"]["parentIssue"]["type"],
        "string"
    );

    let scopes = provider
        .lookup_scopes(
            "issue.child.create",
            &json!({
                "project": "ENG",
                "issueTypeId": "10001",
                "summary": "Child issue",
                "parentIssue": "OLD-100"
            }),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();

    assert_eq!(
        scopes["project"],
        vec!["ENG".to_string(), "OPS".to_string()]
    );
    assert!(!scopes.contains_key("issue"));
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[tokio::test]
async fn issue_child_create_uses_authorized_parent_and_verifies_readback() {
    let mut backend = StubJiraBackend::default();
    let parent = issue_metadata("10001", "PROJ-1", "PROJ");
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut child = visible_issue();
    child.id = "10002".to_string();
    child.key = "PROJ-2".to_string();
    child.project = "PROJ".to_string();
    child.summary = Some("Child issue".to_string());
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), child);
    backend.issue_parent_readbacks.lock().unwrap().insert(
        "PROJ-2".to_string(),
        parent_readback(&issue_metadata("10002", "PROJ-2", "PROJ"), Some(&parent)),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.child.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "PROJ-1",
                    "contentFormat": "adf",
                    "content": adf_text("child body")
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(response.result["operation"], "issue.child.create");
    assert_eq!(response.result["issue"]["key"], "PROJ-2");
    assert_eq!(response.result["parentIssue"]["key"], "PROJ-1");
    assert_eq!(response.result["verification"]["status"], "matched");
    assert_eq!(
        response.object_ids,
        Some(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2",
            "parentIssueId": "10001",
            "parentIssueKey": "PROJ-1",
        }))
    );
    let created = backend.created_issues.lock().unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].project, "PROJ");
    assert_eq!(created[0].issue_type_id, "10001");
    assert_eq!(created[0].summary, "Child issue");
    assert_eq!(created[0].parent_issue.as_deref(), Some("PROJ-1"));
    assert_eq!(created[0].description.as_ref().unwrap()["type"], "doc");
    drop(created);
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["operation"], "issue.child.create");
    assert_eq!(audit["issueKey"], "PROJ-2");
    assert_eq!(audit["parentIssueKey"], "PROJ-1");
    assert_eq!(audit["verificationStatus"], "matched");
    assert!(!audit.to_string().contains("Child issue"));
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("create_issue", "token"),
            ("issue", "token"),
            ("issue_parent", "token"),
        ],
    );
}

#[tokio::test]
async fn issue_child_create_rejects_oversize_returned_description_after_one_mutation() {
    let sentinel = "returned-child-description-sentinel".repeat(16);
    let mut backend = StubJiraBackend::default();
    seed_child_create_success(&mut backend, Some(adf_text(&sentinel)));
    let backend = Arc::new(backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(issue_child_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Child issue",
            "parentIssue": "PROJ-1"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.reason_code().http_status(), 502);
    assert_eq!(error.message, "Jira issue description response was invalid");
    assert!(!error.message.contains(&sentinel));
    assert_eq!(backend.created_issues.lock().unwrap().len(), 1);
    assert!(!error.audit.unwrap().to_string().contains(&sentinel));
}

#[tokio::test]
async fn issue_child_create_requires_target_and_parent_scope_before_mutation() {
    let mut backend = StubJiraBackend::default();
    let mut parent = visible_issue();
    parent.id = "10010".to_string();
    parent.key = "OPS-100".to_string();
    parent.project = "OPS".to_string();
    backend.issues.insert("OPS-100".to_string(), parent);
    let backend = Arc::new(backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 8;
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.child.create")
                .inputs(json!({
                    "project": "ENG",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "OPS-100",
                    "contentFormat": "markdown",
                    "content": "content that exceeds the configured cap"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["ENG".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.created_issues.lock().unwrap().is_empty());
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[tokio::test]
async fn issue_child_create_requires_target_project_scope_before_mutation() {
    let mut backend = StubJiraBackend::default();
    let mut parent = visible_issue();
    parent.id = "10010".to_string();
    parent.key = "OPS-100".to_string();
    parent.project = "OPS".to_string();
    backend.issues.insert("OPS-100".to_string(), parent);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.child.create")
                .inputs(json!({
                    "project": "ENG",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "OPS-100"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["OPS".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.created_issues.lock().unwrap().is_empty());
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[test]
fn issue_child_create_rejects_invalid_inputs() {
    let config = jira_config();
    for inputs in [
        json!({}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "parentIssue": "PROJ-1", "parentUrl": "https://example.atlassian.net/browse/PROJ-1"}),
        json!({"project": "proj", "issueTypeId": "10001", "summary": "summary", "parentIssue": "PROJ-1"}),
        json!({"project": "PROJ", "issueTypeId": "Task", "summary": "summary", "parentIssue": "PROJ-1"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "", "parentIssue": "PROJ-1"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "parentIssue": "PROJ-1", "contentFormat": "adf"}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "parentIssue": "PROJ-1", "content": []}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "parentIssue": "PROJ-1", "fields": {"parent": {"key": "PROJ-1"}}}),
        json!({"project": "PROJ", "issueTypeId": "10001", "summary": "summary", "parent": "PROJ-1"}),
    ] {
        assert!(
            parse_issue_child_create_inputs(&inputs, &config).is_err(),
            "inputs should reject: {inputs}"
        );
    }
}

#[tokio::test]
async fn issue_child_create_parent_readback_failure_emits_side_effect_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut child = visible_issue();
    child.id = "10002".to_string();
    child.key = "PROJ-2".to_string();
    child.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), child);
    backend.issue_parent_readbacks.lock().unwrap().insert(
        "PROJ-2".to_string(),
        parent_readback(&issue_metadata("10002", "PROJ-2", "PROJ"), None),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.child.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "PROJ-1"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2",
            "parentIssueId": "10001",
            "parentIssueKey": "PROJ-1",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.child.create");
    assert_eq!(audit["failurePhase"], "post_parent_readback");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["parentIssueKey"], "PROJ-1");
    assert_eq!(backend.created_issues.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn issue_create_rejects_oversize_returned_description_after_one_mutation() {
    let sentinel = "returned-create-description-sentinel".repeat(16);
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut readback = visible_issue();
    readback.id = "10002".to_string();
    readback.key = "PROJ-2".to_string();
    readback.description = Some(adf_text(&sentinel));
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), readback);
    let backend = Arc::new(backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(issue_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Created issue"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.reason_code().http_status(), 502);
    assert_eq!(error.message, "Jira issue description response was invalid");
    assert!(!error.message.contains(&sentinel));
    assert_eq!(backend.created_issues.lock().unwrap().len(), 1);
    assert!(!error.audit.unwrap().to_string().contains(&sentinel));
}

#[tokio::test]
async fn issue_child_create_created_project_mismatch_emits_side_effect_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "OTHER-2".to_string(),
    });
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(issue_child_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Child issue",
            "parentIssue": "PROJ-1"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.result.as_deref().unwrap()["mutationStatus"],
        "applied_unverified"
    );
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10002",
            "issueKey": "OTHER-2",
            "parentIssueId": "10001",
            "parentIssueKey": "PROJ-1",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.child.create");
    assert_eq!(audit["failurePhase"], "create_response_validation");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["parentIssueKey"], "PROJ-1");
    assert!(!audit.to_string().contains("Child issue"));
}

#[tokio::test]
async fn issue_child_create_readback_failure_emits_side_effect_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(issue_child_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Child issue",
            "parentIssue": "PROJ-1"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2",
            "parentIssueId": "10001",
            "parentIssueKey": "PROJ-1",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.child.create");
    assert_eq!(audit["failurePhase"], "post_create_readback");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["upstreamFailure"], "not_found");
    assert_eq!(audit["parentIssueKey"], "PROJ-1");
    assert!(!audit.to_string().contains("Child issue"));
}

#[tokio::test]
async fn issue_child_create_readback_mismatch_fails_scope_unresolved() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut child = visible_issue();
    child.id = "99999".to_string();
    child.key = "PROJ-2".to_string();
    child.project = "PROJ".to_string();
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), child);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(issue_child_create_invocation(json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "Child issue",
            "parentIssue": "PROJ-1"
        })))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10002",
            "issueKey": "PROJ-2",
            "parentIssueId": "10001",
            "parentIssueKey": "PROJ-1",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.child.create");
    assert_eq!(audit["failurePhase"], "post_create_readback");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["parentIssueKey"], "PROJ-1");
}

#[test]
fn issue_parsers_expose_metadata_and_search_omits_description() {
    let value = json!({
        "id": "10001",
        "key": "PROJ-1",
        "fields": {
            "project": { "key": "PROJ" },
            "summary": "visible summary",
            "status": { "name": "In Progress" },
            "issuetype": { "name": "Task" },
            "description": adf_text("body visible only on view"),
            "created": "2026-06-01T10:00:00.000+0000",
            "updated": "2026-06-02T11:00:00.000+0000",
            "creator": { "accountId": "creator-1", "displayName": "Creator One" },
            "reporter": { "accountId": "reporter-1", "displayName": "Reporter One" },
            "assignee": { "accountId": "assignee-1", "displayName": "Assignee One" },
            "priority": { "id": "3", "name": "Medium" },
            "labels": ["agent", "metadata"]
        }
    });

    let viewed = issue_from_value(value.clone()).unwrap();
    assert_eq!(
        viewed.created.as_deref(),
        Some("2026-06-01T10:00:00.000+0000")
    );
    assert_eq!(
        viewed.updated.as_deref(),
        Some("2026-06-02T11:00:00.000+0000")
    );
    assert_eq!(
        viewed
            .creator
            .as_ref()
            .and_then(|user| user.display_name.as_deref()),
        Some("Creator One")
    );
    assert_eq!(
        viewed
            .assignee
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("assignee-1")
    );
    assert_eq!(
        viewed
            .priority
            .as_ref()
            .and_then(|priority| priority.name.as_deref()),
        Some("Medium")
    );
    assert_eq!(
        viewed.labels.as_deref(),
        Some(&["agent".to_string(), "metadata".to_string()][..])
    );
    assert!(viewed.description.is_some());

    let summary = issue_summary_from_value(value).unwrap();
    assert!(summary.description.is_none());
    let result = issue_search_result(&summary, &jira_config());
    assert!(result.get("description").is_none());
    assert_eq!(result["created"], "2026-06-01T10:00:00.000+0000");
    assert_eq!(result["reporter"]["displayName"], "Reporter One");
    assert_eq!(result["labels"], json!(["agent", "metadata"]));

    let malformed_optional = issue_summary_from_value(json!({
        "id": "10002",
        "key": "PROJ-2",
        "fields": {
            "project": { "key": "PROJ" },
            "summary": "malformed optional metadata",
            "status": { "name": "Open" },
            "issuetype": { "name": "Task" },
            "creator": {},
            "reporter": "not an object",
            "assignee": { "emailAddress": "hidden@example.com" },
            "priority": {},
            "labels": ["ok", 42]
        }
    }))
    .unwrap();
    assert!(malformed_optional.creator.is_none());
    assert!(malformed_optional.reporter.is_none());
    assert!(malformed_optional.assignee.is_none());
    assert!(malformed_optional.priority.is_none());
    assert!(malformed_optional.labels.is_none());
}

#[tokio::test]
async fn issue_view_validates_returned_description_without_write_allowlist() {
    let mut backend = StubJiraBackend::default();
    let mut issue = visible_issue();
    issue.description = Some(json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "table",
            "content": [{
                "type": "tableRow",
                "content": [{
                    "type": "tableCell",
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "table body" }]
                    }]
                }]
            }]
        }]
    }));
    backend.issues.insert("PROJ-1".to_string(), issue);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.result["description"]["content"][0]["type"],
        "table"
    );
}

#[tokio::test]
async fn issue_view_rejects_malformed_or_oversize_returned_description() {
    let mut malformed_backend = StubJiraBackend::default();
    let mut malformed = visible_issue();
    malformed.description = Some(json!({"type": "doc", "version": 1, "content": "bad"}));
    malformed_backend
        .issues
        .insert("PROJ-1".to_string(), malformed);
    let malformed_provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(malformed_backend),
    );
    let malformed_error = malformed_provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        malformed_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert!(!malformed_error.message.contains("bad"));

    let mut oversize_backend = StubJiraBackend::default();
    let mut oversize = visible_issue();
    oversize.description = Some(adf_text(&"x".repeat(200)));
    oversize_backend
        .issues
        .insert("PROJ-1".to_string(), oversize);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let oversize_provider = JiraProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(oversize_backend),
    );
    let oversize_error = oversize_provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        oversize_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(oversize_error.reason_code().http_status(), 502);
    assert!(!oversize_error.message.contains(&"x".repeat(16)));
}

#[tokio::test]
async fn issue_view_confirms_authoritative_project_before_returning_content() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert(
        "PROJ-1".to_string(),
        JiraIssue {
            id: "10001".to_string(),
            key: "OTHER-1".to_string(),
            project: "OTHER".to_string(),
            summary: Some("must not leak".to_string()),
            status: Some("Open".to_string()),
            issue_type: Some("Task".to_string()),
            created: None,
            updated: None,
            creator: None,
            reporter: None,
            assignee: None,
            priority: None,
            labels: None,
            description: Some(adf_text("must not leak description")),
        },
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(response.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(!response.message.contains("must not leak"));
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[tokio::test]
async fn issue_update_capability_and_scope_resolution_use_lookup_metadata() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert(
        "OLD-1".to_string(),
        JiraIssue {
            id: "10001".to_string(),
            key: "PROJ-1".to_string(),
            project: "PROJ".to_string(),
            summary: None,
            status: None,
            issue_type: None,
            created: None,
            updated: None,
            creator: None,
            reporter: None,
            assignee: None,
            priority: None,
            labels: None,
            description: None,
        },
    );
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let capability = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue.update")
        .unwrap();
    assert_eq!(capability.required_scope_types(), vec!["project"]);
    assert!(capability.lookup.credential_required());

    let scopes = provider
        .lookup_scopes(
            "issue.update",
            &json!({"issue": "OLD-1", "summary": "Updated summary"}),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();

    assert_eq!(scopes["project"], vec!["PROJ".to_string()]);
    assert!(!scopes.contains_key("issue"));
}

#[tokio::test]
async fn issue_dependency_add_capability_and_scope_resolution_use_lookup_metadata() {
    let mut backend = StubJiraBackend::default();
    let mut blocking = visible_issue();
    blocking.key = "ENG-101".to_string();
    blocking.project = "ENG".to_string();
    backend.issues.insert("OLD-101".to_string(), blocking);
    let mut blocked = visible_issue();
    blocked.id = "10002".to_string();
    blocked.key = "OPS-8".to_string();
    blocked.project = "OPS".to_string();
    backend.issues.insert("OPS-8".to_string(), blocked);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let capability = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue.dependency.add")
        .unwrap();
    assert_eq!(capability.required_scope_types(), vec!["project"]);
    assert!(capability.lookup.credential_required());
    assert_eq!(
        capability.input_schema["properties"]["blockingIssue"]["type"],
        "string"
    );

    let scopes = provider
        .lookup_scopes(
            "issue.dependency.add",
            &json!({
                "blockingIssue": "OLD-101",
                "blockedUrl": "https://example.atlassian.net/browse/OPS-8"
            }),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();

    assert_eq!(
        scopes["project"],
        vec!["ENG".to_string(), "OPS".to_string()]
    );
    assert!(!scopes.contains_key("issue"));
}

#[tokio::test]
async fn issue_dependency_add_creates_cross_project_outward_link_and_verifies_readback() {
    let mut backend = StubJiraBackend::default();
    let blocking = issue_metadata("10001", "ENG-1", "ENG");
    let blocked = issue_metadata("10002", "OPS-2", "OPS");
    let mut blocking_issue = visible_issue();
    blocking_issue.key = blocking.key.clone();
    blocking_issue.project = blocking.project.clone();
    backend.issues.insert(blocking.key.clone(), blocking_issue);
    let mut blocked_issue = visible_issue();
    blocked_issue.id = blocked.id.clone();
    blocked_issue.key = blocked.key.clone();
    blocked_issue.project = blocked.project.clone();
    backend.issues.insert(blocked.key.clone(), blocked_issue);
    *backend.issue_link_types.lock().unwrap() = vec![blocks_link_type()];
    backend.issue_link_readbacks.lock().unwrap().insert(
        blocking.key.clone(),
        dependency_readback(&blocking, &blocked.key),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.dependency.add")
                .inputs(json!({
                    "blockingIssue": "ENG-1",
                    "blockedIssue": "OPS-2"
                }))
                .credential_mode(CredentialMode::PerUser)
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["ENG".to_string(), "OPS".to_string()],
                )]))
                .credential(test_per_user_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(response.result["operation"], "issue.dependency.add");
    assert_eq!(response.result["status"], "present");
    assert_eq!(response.result["linkType"], "Blocks");
    assert_eq!(response.result["blockingIssue"]["key"], "ENG-1");
    assert_eq!(response.result["blockingIssue"]["project"], "ENG");
    assert_eq!(response.result["blockedIssue"]["key"], "OPS-2");
    assert_eq!(response.result["blockedIssue"]["project"], "OPS");
    assert_eq!(response.result["verification"]["status"], "matched");
    assert_eq!(response.upstream_status, Some(201));
    assert_eq!(
        response.object_ids,
        Some(json!({
            "blockingIssueId": "10001",
            "blockingIssueKey": "ENG-1",
            "blockedIssueId": "10002",
            "blockedIssueKey": "OPS-2",
        }))
    );
    let created = backend.created_issue_links.lock().unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(
        created[0],
        JiraIssueLinkCreateRequest {
            link_type: "Blocks".to_string(),
            outward_issue: "ENG-1".to_string(),
            inward_issue: "OPS-2".to_string(),
        }
    );
    drop(created);
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["operation"], "issue.dependency.add");
    assert_eq!(audit["blockingIssueKey"], "ENG-1");
    assert_eq!(audit["blockingProject"], "ENG");
    assert_eq!(audit["blockedIssueKey"], "OPS-2");
    assert_eq!(audit["blockedProject"], "OPS");
    assert!(!audit.to_string().contains("comment"));
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
            ("issue_link_types", "per-user-token"),
            ("create_issue_link", "per-user-token"),
            ("issue_links", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn issue_dependency_add_requires_both_projects_in_authorized_scope_before_mutation() {
    let mut backend = StubJiraBackend::default();
    let blocking = issue_metadata("10001", "ENG-1", "ENG");
    let blocked = issue_metadata("10002", "OPS-2", "OPS");
    let mut blocking_issue = visible_issue();
    blocking_issue.key = blocking.key.clone();
    blocking_issue.project = blocking.project.clone();
    backend.issues.insert(blocking.key.clone(), blocking_issue);
    let mut blocked_issue = visible_issue();
    blocked_issue.id = blocked.id.clone();
    blocked_issue.key = blocked.key.clone();
    blocked_issue.project = blocked.project.clone();
    backend.issues.insert(blocked.key.clone(), blocked_issue);
    *backend.issue_link_types.lock().unwrap() = vec![blocks_link_type()];
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.dependency.add")
                .inputs(json!({
                    "blockingIssue": "ENG-1",
                    "blockedIssue": "OPS-2"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["ENG".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.created_issue_links.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
        ],
    );
}

#[test]
fn issue_dependency_add_rejects_invalid_inputs() {
    let config = jira_config();
    for inputs in [
        json!({}),
        json!({"blockingIssue": "PROJ-1"}),
        json!({"blockedIssue": "PROJ-2"}),
        json!({"blockingIssue": "PROJ-1", "blockingUrl": "https://example.atlassian.net/browse/PROJ-1", "blockedIssue": "PROJ-2"}),
        json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-1"}),
        json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2", "comment": "must not be accepted"}),
        json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2", "linkType": "Blocks"}),
    ] {
        assert!(
            parse_issue_dependency_add_inputs(&inputs, &config).is_err(),
            "inputs should reject: {inputs}"
        );
    }
}

#[tokio::test]
async fn issue_dependency_add_rejects_same_canonical_issue_after_lookup() {
    let mut backend = StubJiraBackend::default();
    let mut canonical = visible_issue();
    canonical.key = "PROJ-1".to_string();
    canonical.project = "PROJ".to_string();
    backend
        .issues
        .insert("OLD-1".to_string(), canonical.clone());
    backend.issues.insert("PROJ-1".to_string(), canonical);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .lookup_scopes(
            "issue.dependency.add",
            &json!({"blockingIssue": "OLD-1", "blockedIssue": "PROJ-1"}),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert!(backend.created_issue_links.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_dependency_add_rejects_link_direction_mismatch_before_mutation() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut blocked = visible_issue();
    blocked.id = "10002".to_string();
    blocked.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), blocked);
    *backend.issue_link_types.lock().unwrap() = vec![JiraIssueLinkType {
        name: "Blocks".to_string(),
        outward: "relates to".to_string(),
        inward: "relates to".to_string(),
    }];
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.dependency.add")
                .inputs(json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(backend.created_issue_links.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
            ("issue_link_types", "token"),
        ],
    );
}

#[tokio::test]
async fn issue_dependency_add_rejects_unavailable_link_type_before_mutation() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut blocked = visible_issue();
    blocked.id = "10002".to_string();
    blocked.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), blocked);
    *backend.issue_link_types.lock().unwrap() = vec![JiraIssueLinkType {
        name: "Relates".to_string(),
        outward: "relates to".to_string(),
        inward: "relates to".to_string(),
    }];
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.dependency.add")
                .inputs(json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(backend.created_issue_links.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
            ("issue_link_types", "token"),
        ],
    );
}

#[tokio::test]
async fn issue_dependency_add_readback_failure_emits_side_effect_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut blocked = visible_issue();
    blocked.id = "10002".to_string();
    blocked.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), blocked);
    *backend.issue_link_types.lock().unwrap() = vec![blocks_link_type()];
    *backend.issue_links_error.lock().unwrap() = Some(JiraBackendError::NotFound);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.dependency.add")
                .inputs(json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(error.upstream_status, Some(201));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "blockingIssueId": "10001",
            "blockingIssueKey": "PROJ-1",
            "blockedIssueId": "10002",
            "blockedIssueKey": "PROJ-2",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.dependency.add");
    assert_eq!(audit["failurePhase"], "post_dependency_readback");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["upstreamFailure"], "not_found");
    assert_eq!(backend.created_issue_links.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn issue_dependency_add_readback_mismatch_fails_closed() {
    let blocking = issue_metadata("10001", "ENG-1", "ENG");
    let blocked = issue_metadata("10002", "OPS-2", "OPS");
    for (readback, expected_reason) in [
        (
            dependency_readback(&issue_metadata("10099", "ENG-99", "ENG"), &blocked.key),
            ReasonCode::ScopeUnresolved,
        ),
        (
            JiraIssueLinks {
                issue: blocking.clone(),
                links: vec![],
            },
            ReasonCode::UpstreamProtocolFailed,
        ),
    ] {
        let mut backend = StubJiraBackend::default();
        let mut blocking_issue = visible_issue();
        blocking_issue.key = blocking.key.clone();
        blocking_issue.project = blocking.project.clone();
        backend.issues.insert(blocking.key.clone(), blocking_issue);
        let mut blocked_issue = visible_issue();
        blocked_issue.id = blocked.id.clone();
        blocked_issue.key = blocked.key.clone();
        blocked_issue.project = blocked.project.clone();
        backend.issues.insert(blocked.key.clone(), blocked_issue);
        *backend.issue_link_types.lock().unwrap() = vec![blocks_link_type()];
        backend
            .issue_link_readbacks
            .lock()
            .unwrap()
            .insert(blocking.key.clone(), readback);
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

        let error = provider
            .invoke(
                InvocationBuilder::new("jira", "issue.dependency.add")
                    .inputs(json!({
                        "blockingIssue": "ENG-1",
                        "blockedIssue": "OPS-2"
                    }))
                    .resources(BTreeMap::from([(
                        "project".to_string(),
                        vec!["ENG".to_string(), "OPS".to_string()],
                    )]))
                    .credential(test_credential())
                    .lookup_credential(test_lookup_credential())
                    .build(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.reason_code(), expected_reason);
        assert_eq!(error.upstream_status, Some(201));
        assert_eq!(
            error.audit.as_ref().unwrap()["failurePhase"],
            "post_dependency_readback"
        );
        assert_eq!(backend.created_issue_links.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn issue_parent_set_capability_and_scope_resolution_use_lookup_metadata() {
    let mut backend = StubJiraBackend::default();
    let mut issue = visible_issue();
    issue.key = "ENG-102".to_string();
    issue.project = "ENG".to_string();
    backend.issues.insert("OLD-102".to_string(), issue);
    let mut parent = visible_issue();
    parent.id = "10010".to_string();
    parent.key = "OPS-100".to_string();
    parent.project = "OPS".to_string();
    backend.issues.insert("OPS-100".to_string(), parent);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let capability = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue.parent.set")
        .unwrap();
    assert_eq!(capability.required_scope_types(), vec!["project"]);
    assert!(capability.lookup.credential_required());
    assert_eq!(
        capability.input_schema["properties"]["parentIssue"]["type"],
        "string"
    );

    let scopes = provider
        .lookup_scopes(
            "issue.parent.set",
            &json!({
                "issue": "OLD-102",
                "parentUrl": "https://example.atlassian.net/browse/OPS-100"
            }),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();

    assert_eq!(
        scopes["project"],
        vec!["ENG".to_string(), "OPS".to_string()]
    );
    assert!(!scopes.contains_key("issue"));
}

#[tokio::test]
async fn issue_parent_set_creates_cross_project_parent_and_verifies_readback() {
    let mut backend = StubJiraBackend::default();
    let issue = issue_metadata("10002", "ENG-2", "ENG");
    let parent = issue_metadata("10010", "OPS-100", "OPS");
    let mut child_issue = visible_issue();
    child_issue.id = issue.id.clone();
    child_issue.key = issue.key.clone();
    child_issue.project = issue.project.clone();
    backend.issues.insert(issue.key.clone(), child_issue);
    let mut parent_issue = visible_issue();
    parent_issue.id = parent.id.clone();
    parent_issue.key = parent.key.clone();
    parent_issue.project = parent.project.clone();
    backend.issues.insert(parent.key.clone(), parent_issue);
    backend
        .issue_parent_readbacks
        .lock()
        .unwrap()
        .insert(issue.key.clone(), parent_readback(&issue, Some(&parent)));
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.parent.set")
                .inputs(json!({
                    "issue": "ENG-2",
                    "parentIssue": "OPS-100"
                }))
                .credential_mode(CredentialMode::PerUser)
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["ENG".to_string(), "OPS".to_string()],
                )]))
                .credential(test_per_user_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(response.result["operation"], "issue.parent.set");
    assert_eq!(response.result["issue"]["key"], "ENG-2");
    assert_eq!(response.result["issue"]["project"], "ENG");
    assert_eq!(response.result["parentIssue"]["key"], "OPS-100");
    assert_eq!(response.result["parentIssue"]["project"], "OPS");
    assert_eq!(response.result["verification"]["status"], "matched");
    assert_eq!(response.upstream_status, Some(204));
    assert_eq!(
        response.object_ids,
        Some(json!({
            "issueId": "10002",
            "issueKey": "ENG-2",
            "parentIssueId": "10010",
            "parentIssueKey": "OPS-100",
        }))
    );
    let updates = backend.parent_updates.lock().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].0, "ENG-2");
    assert_eq!(
        updates[0].1,
        JiraIssueParentSetRequest {
            parent_issue: "OPS-100".to_string(),
        }
    );
    drop(updates);
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["operation"], "issue.parent.set");
    assert_eq!(audit["issueKey"], "ENG-2");
    assert_eq!(audit["project"], "ENG");
    assert_eq!(audit["parentIssueKey"], "OPS-100");
    assert_eq!(audit["parentProject"], "OPS");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
            ("set_issue_parent", "per-user-token"),
            ("issue_parent", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn issue_parent_set_requires_both_projects_in_authorized_scope_before_mutation() {
    let mut backend = StubJiraBackend::default();
    let issue = issue_metadata("10002", "ENG-2", "ENG");
    let parent = issue_metadata("10010", "OPS-100", "OPS");
    let mut child_issue = visible_issue();
    child_issue.id = issue.id.clone();
    child_issue.key = issue.key.clone();
    child_issue.project = issue.project.clone();
    backend.issues.insert(issue.key.clone(), child_issue);
    let mut parent_issue = visible_issue();
    parent_issue.id = parent.id.clone();
    parent_issue.key = parent.key.clone();
    parent_issue.project = parent.project.clone();
    backend.issues.insert(parent.key.clone(), parent_issue);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.parent.set")
                .inputs(json!({
                    "issue": "ENG-2",
                    "parentIssue": "OPS-100"
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["ENG".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.parent_updates.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_metadata", "lookup-token"),
        ],
    );
}

#[test]
fn issue_parent_set_rejects_invalid_inputs() {
    let config = jira_config();
    for inputs in [
        json!({}),
        json!({"issue": "PROJ-1"}),
        json!({"parentIssue": "PROJ-2"}),
        json!({"issue": "PROJ-1", "url": "https://example.atlassian.net/browse/PROJ-1", "parentIssue": "PROJ-2"}),
        json!({"issue": "PROJ-1", "parentIssue": "PROJ-2", "parentUrl": "https://example.atlassian.net/browse/PROJ-2"}),
        json!({"issue": "PROJ-1", "parentIssue": "PROJ-1"}),
        json!({"issue": "PROJ-1", "parentIssue": "PROJ-2", "fields": {"parent": {"key": "PROJ-2"}}}),
        json!({"issue": "PROJ-1", "parent": "PROJ-2"}),
    ] {
        assert!(
            parse_issue_parent_set_inputs(&inputs, &config).is_err(),
            "inputs should reject: {inputs}"
        );
    }
}

#[tokio::test]
async fn issue_parent_set_rejects_same_canonical_issue_after_lookup() {
    let mut backend = StubJiraBackend::default();
    let mut canonical = visible_issue();
    canonical.key = "PROJ-1".to_string();
    canonical.project = "PROJ".to_string();
    backend
        .issues
        .insert("OLD-1".to_string(), canonical.clone());
    backend.issues.insert("PROJ-1".to_string(), canonical);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .lookup_scopes(
            "issue.parent.set",
            &json!({"issue": "OLD-1", "parentIssue": "PROJ-1"}),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert!(backend.parent_updates.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_parent_set_readback_failure_emits_side_effect_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut parent = visible_issue();
    parent.id = "10002".to_string();
    parent.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), parent);
    *backend.issue_parent_error.lock().unwrap() = Some(JiraBackendError::NotFound);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let invocation = per_user_invocation(
        "issue.parent.set",
        json!({"issue": "PROJ-1", "parentIssue": "PROJ-2"}),
        vec![],
    );
    let error = provider.invoke(invocation).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(error.upstream_status, Some(204));
    assert_eq!(
        error.object_ids,
        Some(Box::new(json!({
            "issueId": "10001",
            "issueKey": "PROJ-1",
            "parentIssueId": "10002",
            "parentIssueKey": "PROJ-2",
        })))
    );
    let audit = error.audit.unwrap();
    assert_eq!(audit["operation"], "issue.parent.set");
    assert_eq!(audit["failurePhase"], "post_parent_readback");
    assert_eq!(audit["verificationStatus"], "failed");
    assert_eq!(audit["upstreamFailure"], "not_found");
    assert_eq!(backend.parent_updates.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn issue_parent_set_readback_mismatch_fails_closed() {
    for (readback, expected_reason) in [
        (
            parent_readback(&issue_metadata("10001", "PROJ-1", "PROJ"), None),
            ReasonCode::UpstreamProtocolFailed,
        ),
        (
            parent_readback(
                &issue_metadata("10001", "PROJ-1", "PROJ"),
                Some(&issue_metadata("10003", "PROJ-3", "PROJ")),
            ),
            ReasonCode::UpstreamProtocolFailed,
        ),
        (
            parent_readback(
                &issue_metadata("10099", "PROJ-99", "PROJ"),
                Some(&issue_metadata("10002", "PROJ-2", "PROJ")),
            ),
            ReasonCode::ScopeUnresolved,
        ),
    ] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        let mut parent = visible_issue();
        parent.id = "10002".to_string();
        parent.key = "PROJ-2".to_string();
        backend.issues.insert("PROJ-2".to_string(), parent);
        backend
            .issue_parent_readbacks
            .lock()
            .unwrap()
            .insert("PROJ-1".to_string(), readback);
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let invocation = per_user_invocation(
            "issue.parent.set",
            json!({"issue": "PROJ-1", "parentIssue": "PROJ-2"}),
            vec![],
        );

        let error = provider.invoke(invocation).await.unwrap_err();

        assert_eq!(error.reason_code(), expected_reason);
        assert_eq!(
            error.audit.as_ref().unwrap()["failurePhase"],
            "post_parent_readback"
        );
        assert_eq!(backend.parent_updates.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn issue_update_uses_current_key_and_redacts_submitted_content_from_audit() {
    let mut backend = StubJiraBackend::default();
    let updated_issue = JiraIssue {
        id: "10001".to_string(),
        key: "PROJ-1".to_string(),
        project: "PROJ".to_string(),
        summary: Some("  updated summary  ".to_string()),
        status: Some("In Progress".to_string()),
        issue_type: Some("Task".to_string()),
        created: None,
        updated: None,
        creator: None,
        reporter: None,
        assignee: None,
        priority: None,
        labels: None,
        description: Some(adf_text("secret description body")),
    };
    backend
        .issues
        .insert("OLD-1".to_string(), updated_issue.clone());
    backend
        .issues
        .insert("PROJ-1".to_string(), updated_issue.clone());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let response = provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({
                "issue": "OLD-1",
                "summary": "  updated summary  ",
                "contentFormat": "adf",
                "content": adf_text("secret description body"),
                "notifyUsers": false
            }),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(response.result["operation"], "issue.update");
    assert_eq!(response.result["issue"]["key"], "PROJ-1");
    assert_eq!(response.result["issue"]["summary"], "  updated summary  ");
    assert_eq!(
        response.result["issue"]["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );
    assert_eq!(
        response.result["issue"]["description"]["content"][0]["content"][0]["text"],
        "secret description body"
    );
    assert_eq!(
        response.result["changedFields"],
        json!(["summary", "description"])
    );
    assert_eq!(response.result["notifyUsers"], false);
    assert_eq!(response.upstream_status, Some(204));
    assert_eq!(response.upstream_duration_ms, Some(23));

    let updated = backend.updated_issues.lock().unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].0, "PROJ-1");
    assert_eq!(updated[0].1.summary.as_deref(), Some("  updated summary  "));
    assert_eq!(
        updated[0].1.description.as_ref().unwrap()["content"][0]["content"][0]["text"],
        "secret description body"
    );
    assert_eq!(updated[0].1.notify_users, Some(false));
    drop(updated);

    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["operation"], "issue.update");
    assert_eq!(audit["changedFields"], json!(["summary", "description"]));
    assert_eq!(audit["summaryChanged"], true);
    assert_eq!(audit["descriptionChanged"], true);
    assert_eq!(audit["notifyUsers"], false);
    let audit_text = audit.to_string();
    assert!(!audit_text.contains("updated summary"));
    assert!(!audit_text.contains("secret description body"));
    assert_eq!(response.object_ids.unwrap()["issueKey"], "PROJ-1");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("update_issue", "per-user-token"),
            ("issue", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn issue_update_notify_users_tristate_and_payload_fields_are_controlled() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let omitted = provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "Summary only"}),
            vec![],
        ))
        .await
        .unwrap();
    assert!(omitted.result["notifyUsers"].is_null());
    assert_eq!(omitted.result["changedFields"], json!(["summary"]));

    let explicit_true = provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": adf_text("description only"),
                "notifyUsers": true
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(explicit_true.result["notifyUsers"], true);
    assert_eq!(
        explicit_true.result["changedFields"],
        json!(["description"])
    );

    let updated = backend.updated_issues.lock().unwrap();
    assert_eq!(updated.len(), 2);
    assert_eq!(updated[0].1.summary.as_deref(), Some("Summary only"));
    assert!(updated[0].1.description.is_none());
    assert_eq!(updated[0].1.notify_users, None);
    assert!(updated[1].1.summary.is_none());
    assert!(updated[1].1.description.is_some());
    assert_eq!(updated[1].1.notify_users, Some(true));
}

#[tokio::test]
async fn issue_update_enforces_description_body_cap_after_attribution() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let attribution = ProviderAttributionConfig::from_patterns(
        &jira_descriptor(&config),
        &[String::from("issue.update")],
    );
    let provider = JiraProvider {
        attribution,
        ..JiraProvider::from_backend(config, ProviderLimits::default(), backend.clone())
    };
    let mut invocation = per_user_invocation(
        "issue.update",
        json!({
            "issue": "PROJ-1",
            "contentFormat": "adf",
            "content": adf_text("x")
        }),
        vec![],
    );
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        ))
        .build();

    let error = provider.invoke(invocation).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
    assert!(backend.updated_issues.lock().unwrap().is_empty());
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_update_attribution_is_visible_in_update_readback_and_issue_view() {
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let expected_description =
        attributed_adf_text("description before attribution", broker_request_id);
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut readback = visible_issue();
    readback.description = Some(expected_description.clone());
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-1".to_string(), readback);
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("issue.update")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };
    let mut update_invocation = per_user_invocation(
        "issue.update",
        json!({
            "issue": "PROJ-1",
            "contentFormat": "adf",
            "content": adf_text("description before attribution")
        }),
        vec![],
    );
    update_invocation = InvocationBuilder::from(update_invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let update_response = provider.invoke(update_invocation).await.unwrap();

    assert_eq!(
        update_response.result["issue"]["description"],
        expected_description
    );
    {
        let updated = backend.updated_issues.lock().unwrap();
        assert_eq!(
            updated[0].1.description.as_ref().unwrap(),
            &expected_description
        );
    }
    let audit = update_response.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["verb"], "update");
    let audit_text = audit.to_string();
    assert!(!audit_text.contains("description before attribution"));
    assert!(!audit_text.contains("Updated via Agent Access Broker"));

    let view_response = provider
        .invoke(per_user_invocation(
            "issue.view",
            json!({"issue": "PROJ-1"}),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(view_response.result["description"], expected_description);
}

#[test]
fn issue_update_input_validation_is_narrow_and_format_explicit() {
    let config = jira_config();
    for inputs in [
        json!({"issue": "PROJ-1", "summary": "x", "unexpected": true}),
        json!({"issue": "PROJ-1", "url": "https://example.atlassian.net/browse/PROJ-1", "summary": "x"}),
        json!({"summary": "x"}),
        json!({"issue": "PROJ-1"}),
        json!({"issue": "PROJ-1", "summary": "with\nnewline"}),
        json!({"issue": "PROJ-1", "summary": "with\0nul"}),
        json!({"issue": "PROJ-1", "summary": "   "}),
        json!({"issue": "PROJ-1", "summary": "x".repeat(MAX_JIRA_ISSUE_SUMMARY_BYTES + 1)}),
        json!({"issue": "PROJ-1", "summary": null, "description": {"type": "doc", "version": 1, "content": []}}),
        json!({"issue": "PROJ-1", "description": null}),
        json!({"issue": "PROJ-1", "summary": "x", "notifyUsers": null}),
        json!({"issue": "PROJ-1", "summary": "x", "notifyUsers": "false"}),
    ] {
        let error = parse_issue_update_inputs(&inputs, &config).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }

    let error = parse_issue_update_inputs(
        &json!({"issue": "PROJ-1", "contentFormat": "adf", "content": []}),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let error = parse_issue_update_inputs(
        &json!({"issue": "PROJ-1", "contentFormat": "adf", "content": {}}),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);
}

#[tokio::test]
async fn issue_update_readback_failures_fail_closed_without_body_leakage() {
    for (readback, expected_reason) in [
        (
            JiraIssue {
                id: "10001".to_string(),
                key: "not-a-key".to_string(),
                project: "PROJ".to_string(),
                summary: Some("secret readback summary".to_string()),
                status: None,
                issue_type: None,
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
                description: Some(adf_text("secret readback description")),
            },
            ReasonCode::UpstreamProtocolFailed,
        ),
        (
            JiraIssue {
                id: "10002".to_string(),
                key: "OTHER-1".to_string(),
                project: "OTHER".to_string(),
                summary: Some("secret readback summary".to_string()),
                status: None,
                issue_type: None,
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
                description: Some(adf_text("secret readback description")),
            },
            ReasonCode::ScopeUnresolved,
        ),
    ] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        backend
            .issue_readbacks
            .lock()
            .unwrap()
            .insert("PROJ-1".to_string(), readback);
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

        let error = provider
            .invoke(per_user_invocation(
                "issue.update",
                json!({"issue": "PROJ-1", "summary": "Updated summary"}),
                vec![],
            ))
            .await
            .unwrap_err();

        assert_eq!(error.reason_code(), expected_reason);
        assert!(!error.message.contains("secret readback summary"));
        assert_eq!(backend.updated_issues.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn issue_update_readback_validates_returned_description() {
    let mut malformed_backend = StubJiraBackend::default();
    malformed_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    let mut malformed = visible_issue();
    malformed.description = Some(json!({"type": "doc", "version": 1, "content": "bad"}));
    malformed_backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-1".to_string(), malformed);
    let malformed_backend = Arc::new(malformed_backend);
    let malformed_provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        malformed_backend.clone(),
    );

    let malformed_error = malformed_provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "Updated summary"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(
        malformed_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert!(!malformed_error.message.contains("bad"));
    assert_eq!(malformed_backend.updated_issues.lock().unwrap().len(), 1);

    let mut oversize_backend = StubJiraBackend::default();
    oversize_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    let mut oversize = visible_issue();
    oversize.description = Some(adf_text(&"x".repeat(200)));
    oversize_backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-1".to_string(), oversize);
    let oversize_backend = Arc::new(oversize_backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 120;
    let oversize_provider =
        JiraProvider::with_backend(config, ProviderLimits::default(), oversize_backend.clone());

    let oversize_error = oversize_provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "Updated summary"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(
        oversize_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(oversize_error.reason_code().http_status(), 502);
    assert_eq!(oversize_backend.updated_issues.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn issue_update_rejects_reconfirmed_issue_outside_authorized_scope_before_put() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert(
        "PROJ-1".to_string(),
        JiraIssue {
            id: "10001".to_string(),
            key: "OTHER-1".to_string(),
            project: "OTHER".to_string(),
            summary: Some("moved issue summary must not update".to_string()),
            status: Some("Open".to_string()),
            issue_type: Some("Task".to_string()),
            created: None,
            updated: None,
            creator: None,
            reporter: None,
            assignee: None,
            priority: None,
            labels: None,
            description: Some(adf_text("moved description must not update")),
        },
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "Updated summary"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(!error.message.contains("moved issue summary"));
    assert!(backend.updated_issues.lock().unwrap().is_empty());
    assert_credential_observations(&backend, &[("issue_metadata", "lookup-token")]);
}

#[tokio::test]
async fn issue_update_upstream_failure_is_sanitized() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.issue_update_error.lock().unwrap() = Some(JiraBackendError::Forbidden);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "secret rejected summary"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamForbidden);
    assert_eq!(error.message, "Jira forbade the selected credential");
    assert!(!error.message.contains("secret rejected summary"));
    assert!(backend.updated_issues.lock().unwrap().is_empty());
}

#[tokio::test]
async fn attachment_list_rejects_execution_metadata_for_different_parent() {
    let mut backend = StubJiraBackend {
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "evidence.txt".to_string(),
            size: 5,
            content_type: "text/plain".to_string(),
        }]),
        attachment_list_issue: Mutex::new(Some(JiraIssueMetadata {
            id: "99999".to_string(),
            key: "OTHER-1".to_string(),
            project: "OTHER".to_string(),
        })),
        ..StubJiraBackend::default()
    };
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.list")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!error.message.contains("evidence.txt"));
}

#[tokio::test]
async fn attachment_list_scope_resolution_uses_authoritative_current_project() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert(
        "PROJ-1".to_string(),
        JiraIssue {
            id: "10001".to_string(),
            key: "OTHER-1".to_string(),
            project: "OTHER".to_string(),
            summary: None,
            status: None,
            issue_type: None,
            created: None,
            updated: None,
            creator: None,
            reporter: None,
            assignee: None,
            priority: None,
            labels: None,
            description: None,
        },
    );
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let scopes = provider
        .lookup_scopes(
            "attachment.list",
            &json!({"issue": "PROJ-1"}),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();

    assert_eq!(scopes["project"], vec!["OTHER".to_string()]);
    assert!(!scopes.contains_key("issue"));
}

#[tokio::test]
async fn attachment_list_rejects_unknown_input_fields() {
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(StubJiraBackend::default()),
    );

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.list")
                .inputs(json!({"issue": "PROJ-1", "maxResults": 1}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[tokio::test]
async fn search_caps_pagination_and_rejects_out_of_scope_results() {
    let backend = StubJiraBackend {
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![JiraIssue {
                id: "10001".to_string(),
                key: "OTHER-1".to_string(),
                project: "OTHER".to_string(),
                summary: Some("must not leak".to_string()),
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
            }],
            max_results: 1,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        ..StubJiraBackend::default()
    };
    let backend = Arc::new(backend);
    let provider = JiraProvider::with_backend(
        jira_config_with_search_cap(2),
        ProviderLimits::default(),
        backend.clone(),
    );
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "search")
                .inputs(json!({
                    "projects": ["PROJ"],
                    "query": {
                        "type": "jql",
                        "value": "project = PROJ"
                    },
                    "maxResults": 100
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .search(search_preflight(["PROJ"]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(!error.message.contains("must not leak"));
    assert_eq!(
        backend
            .last_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .max_results,
        2
    );
}

#[test]
fn scope_only_jql_uses_authorized_projects_without_an_empty_filter() {
    for (input, expected) in [
        ("", "project IN (OTHER, PROJ)"),
        ("   ", "project IN (OTHER, PROJ)"),
        (
            "ORDER BY updated DESC",
            "project IN (OTHER, PROJ) ORDER BY updated DESC",
        ),
        (
            "order by created, key desc",
            "project IN (OTHER, PROJ) ORDER BY created ASC, key DESC",
        ),
    ] {
        let inputs =
            parse_search_inputs(&json!({"query": {"type": "jql", "value": input}})).unwrap();
        let scope = effective_search_scope(
            &search_preflight(["PROJ", "OTHER"]),
            &requested_projects(&inputs).unwrap(),
        )
        .unwrap();
        let query = build_jira_search_query(
            &inputs.query,
            &scope,
            &SearchLimitsConfig::default(),
            CredentialMode::Service,
        )
        .unwrap();
        assert_eq!(query.jql, expected);
        assert!(query.query_shape["filter"].is_null());
        assert!(query.text_operand_hashes.is_empty());
        assert_eq!(query.injected_scope_predicate, "project_in");
    }
    // Empty nested expressions and partial clauses are still invalid.
    for invalid in [
        "()",
        "(ORDER BY updated)",
        "status = Done AND ORDER BY updated",
        "ORDER BY",
    ] {
        assert_eq!(
            parse_jql_query(invalid, CredentialMode::Service)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[test]
fn scope_only_jql_requires_positive_bound_for_all_project_access() {
    for excluded in [BTreeSet::new(), set(["PRIVATE"])] {
        let authorization = SearchAuthorization::new(
            "project".to_string(),
            SearchAuthorizationScope::excluding_exact_values(excluded.iter().cloned().collect()),
        );
        for value in ["", "ORDER BY updated DESC"] {
            let inputs =
                parse_search_inputs(&json!({"query": {"type": "jql", "value": value}})).unwrap();
            let scope =
                effective_search_scope(&authorization, &requested_projects(&inputs).unwrap())
                    .unwrap();
            let error = build_jira_search_query(
                &inputs.query,
                &scope,
                &SearchLimitsConfig::default(),
                CredentialMode::Service,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
            assert!(error.message.contains("provide projects or a filter"));
            let narrowed = effective_search_scope(&authorization, &set(["PROJ"])).unwrap();
            let query = build_jira_search_query(
                &inputs.query,
                &narrowed,
                &SearchLimitsConfig::default(),
                CredentialMode::Service,
            )
            .unwrap();
            assert!(query.jql.starts_with("project IN (PROJ)"));
            assert_eq!(narrowed, EffectiveSearchScope::Finite(set(["PROJ"])));
            // Returned issues are checked against the authorized boundary, not
            // the explicit selection.
            assert_eq!(
                authorized_search_scope(&authorization).unwrap(),
                EffectiveSearchScope::AllExcept(excluded.clone())
            );
        }
        if !excluded.is_empty() {
            assert_eq!(
                effective_search_scope(&authorization, &set(["PRIVATE"]))
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::ServiceActionDenied
            );
        }
    }
    let inputs =
        parse_search_inputs(&json!({"query": {"type": "jql", "value": ""}, "projects": []}))
            .unwrap();
    assert_eq!(
        requested_projects(&inputs).unwrap_err().reason_code(),
        ReasonCode::InputInvalid
    );
}

#[test]
fn jql_input_errors_give_safe_locations_and_supported_choices() {
    for (query, diagnostic) in [
        (
            "privateField = secretValue",
            "supported fields: project, key",
        ),
        (
            "status CHANGED secretValue",
            "supported operators: =, !=, IN, NOT IN",
        ),
        (
            "project != PROJ",
            "operator != is unsupported for project; supported operators: =, IN",
        ),
        (
            "updated >= privateFunction(secretValue)",
            "supported functions: currentUser, now",
        ),
        (
            "ORDER BY privateField",
            "supported sort fields: created, updated",
        ),
        ("status = secretValue AND", "missing a field"),
    ] {
        let error = parse_jql_query(query, CredentialMode::Service).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(error.message.contains(diagnostic), "{}", error.message);
        assert!(error.message.contains("near token"));
        for private in ["privateField", "privateFunction", "secretValue"] {
            assert!(!error.message.contains(private));
        }
    }
}

#[test]
fn jira_documented_aliases_preserve_field_and_sort_grammar() {
    let documentation = jql_documentation();
    assert_eq!(
        documentation["jql"]["aliases"],
        json!({
            "issuekey": "key", "type": "issuetype", "label": "labels", "components": "component",
            "fixVersions": "fixVersion", "affectedVersions": "affectedVersion"
        })
    );
    assert_eq!(
        documentation["jql"]["orderBy"]["aliases"],
        json!({"type": "issuetype", "issuekey": "key"})
    );
    for (alias, canonical) in documentation["jql"]["aliases"].as_object().unwrap() {
        let canonical = canonical.as_str().unwrap();
        for spelling in [alias.clone(), alias.to_ascii_uppercase()] {
            let field = JqlField::from_input(&spelling).unwrap();
            assert_eq!(field.canonical(), canonical);
            assert_eq!(JqlField::from_input(field.canonical()), Some(field));
            let operand = if canonical == "key" {
                "PROJ-1"
            } else {
                "example"
            };
            assert_eq!(
                canonical_jql(&format!("{spelling} = {operand}")),
                format!("{canonical} = {operand}")
            );
        }
    }
    for (alias, canonical) in documentation["jql"]["orderBy"]["aliases"]
        .as_object()
        .unwrap()
    {
        let canonical = canonical.as_str().unwrap();
        for spelling in [alias.clone(), alias.to_ascii_uppercase()] {
            let field = JqlSortField::from_input(&spelling).unwrap();
            assert_eq!(field.canonical(), canonical);
            assert_eq!(JqlSortField::from_input(field.canonical()), Some(field));
            assert_eq!(
                canonical_jql(&format!("ORDER BY {spelling} DESC")),
                format!("ORDER BY {canonical} DESC")
            );
        }
    }
}

#[test]
fn jira_search_documentation_advertises_parser_supported_grammar() {
    let descriptor = jira_descriptor(&jira_config());
    let search = descriptor
        .actions
        .iter()
        .find(|action| action.action == "search")
        .unwrap();
    let documentation = search.documentation.as_ref().unwrap();
    let fields = documentation["jql"]["fields"].as_array().unwrap();
    assert_eq!(fields.len(), JqlField::ALL.len());
    for field in fields {
        let parsed = JqlField::from_input(field["name"].as_str().unwrap()).unwrap();
        assert_eq!(field["operators"], json!(parsed.operator_names()));
    }
    for field in documentation["jql"]["orderBy"]["fields"]
        .as_array()
        .unwrap()
    {
        assert!(JqlSortField::from_input(field.as_str().unwrap()).is_some());
    }
    for function in documentation["jql"]["functions"].as_array().unwrap() {
        assert!(JqlFunctionName::from_input(function["name"].as_str().unwrap()).is_some());
    }
    for example in documentation["examples"].as_array().unwrap() {
        let inputs = parse_search_inputs(example).unwrap();
        build_jira_search_query(
            &inputs.query,
            &EffectiveSearchScope::Finite(set(["PROJ"])),
            &SearchLimitsConfig::default(),
            CredentialMode::Service,
        )
        .unwrap();
    }
    assert!(
        search.input_schema["properties"]["projects"]["description"]
            .as_str()
            .unwrap()
            .contains("Omit")
    );
    assert!(search.input_schema.get("documentation").is_none());
}

#[tokio::test]
async fn scope_only_jira_search_checks_returned_containment() {
    for (project, key, allowed) in [("PROJ", "PROJ-1", true), ("OTHER", "OTHER-1", false)] {
        let mut issue = visible_issue();
        issue.project = project.to_string();
        issue.key = key.to_string();
        let backend = Arc::new(StubJiraBackend {
            search_page: Mutex::new(Some(JiraSearchPage {
                issues: vec![issue],
                max_results: 1,
                start_at: 0,
                total: Some(1),
                next_page_token: None,
                is_last: Some(true),
            })),
            ..StubJiraBackend::default()
        });
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let mut request = per_user_invocation(
            "search",
            json!({"query": {"type": "jql", "value": "ORDER BY updated DESC"}, "maxResults": 1}),
            vec![],
        );
        request = InvocationBuilder::from(request)
            .search(search_preflight(["PROJ"]))
            .build();
        let result = provider.invoke(request).await;
        assert_eq!(result.is_ok(), allowed, "{result:?}");
        if let Err(error) = result {
            assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        }
        assert_eq!(
            backend.last_search.lock().unwrap().as_ref().unwrap().jql,
            "project IN (PROJ) ORDER BY updated DESC"
        );
    }
}

#[test]
fn search_intersects_raw_jql_with_effective_scope() {
    let query = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "key = PROJ-1 OR project = OTHER".to_string(),
        },
        &EffectiveSearchScope::Finite(set(["PROJ"])),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();

    assert_eq!(
        query.jql,
        "(key = PROJ-1 OR project = OTHER) AND project IN (PROJ)"
    );
    assert_eq!(query.injected_scope_predicate, "project_in");

    let ordered = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = Done ORDER BY updated DESC".to_string(),
        },
        &EffectiveSearchScope::Finite(set(["PROJ"])),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(
        ordered.jql,
        "(status = Done) AND project IN (PROJ) ORDER BY updated DESC"
    );

    let reserved_project_key = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = Done".to_string(),
        },
        &EffectiveSearchScope::Finite(set(["IN"])),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(
        reserved_project_key.jql,
        "(status = Done) AND project IN (\"IN\")"
    );

    let wildcard = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = Done ORDER BY updated DESC".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(wildcard.jql, "status = Done ORDER BY updated DESC");
    assert_eq!(wildcard.injected_scope_predicate, "none");

    let wildcard_project_narrowed = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "status = Done AND project = PROJ".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(
        wildcard_project_narrowed.jql,
        "status = Done AND project = PROJ"
    );
    assert_eq!(wildcard_project_narrowed.injected_scope_predicate, "none");

    let wildcard_unbounded_or = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "project = PROJ OR status = Done".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(wildcard_unbounded_or.jql, "project = PROJ OR status = Done");
}

#[test]
fn all_except_jql_preserves_caller_grouping_and_exclusions() {
    let boundary = EffectiveSearchScope::AllExcept(set(["PRIVATE", "IN"]));
    let query = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "project = PRIVATE OR status = Done ORDER BY updated DESC".to_string(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(
        query.jql,
        "(project = PRIVATE OR status = Done) AND project NOT IN (\"IN\", PRIVATE) ORDER BY updated DESC"
    );
    assert_eq!(query.injected_scope_predicate, "project_not_in");
    assert!(!boundary.authorizes_value("PRIVATE"));
    assert!(boundary.authorizes_value("NEW"));
    assert_eq!(
        boundary.audit_value("project")["excludedValues"],
        json!(["IN", "PRIVATE"])
    );

    let narrowed = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: "project IN (PRIVATE, PROJ)".to_string(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
        CredentialMode::Service,
    )
    .unwrap();
    assert_eq!(
        narrowed.jql,
        "(project IN (PRIVATE, PROJ)) AND project NOT IN (\"IN\", PRIVATE)"
    );
    let authorization = SearchAuthorization::new(
        "project".to_string(),
        SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".to_string()]),
    );
    assert!(effective_search_scope(&authorization, &set(["PRIVATE"])).is_err());
    assert_eq!(
        effective_search_scope(&authorization, &set(["NEW"])).unwrap(),
        EffectiveSearchScope::Finite(set(["NEW"]))
    );
}

#[tokio::test]
async fn all_except_jira_search_constrains_upstream_and_checks_returned_containment() {
    for (project, key, allowed) in [
        ("NEW", "NEW-1", true),
        ("PRIVATE", "PRIVATE-1", false),
        ("", "NEW-1", false),
        ("NEW", "OTHER-1", false),
    ] {
        let mut issue = visible_issue();
        issue.project = project.to_string();
        issue.key = key.to_string();
        let backend = Arc::new(StubJiraBackend {
            search_page: Mutex::new(Some(JiraSearchPage {
                issues: vec![issue],
                max_results: 1,
                start_at: 0,
                total: Some(1),
                next_page_token: None,
                is_last: Some(true),
            })),
            ..StubJiraBackend::default()
        });
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let mut request = per_user_invocation(
            "search",
            json!({"query":{"type":"jql","value":"status = Done"},"maxResults":1}),
            vec![],
        );
        request = InvocationBuilder::from(request)
            .search(SearchAuthorization::new(
                "project".to_string(),
                SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".to_string()]),
            ))
            .build();
        let result = provider.invoke(request).await;
        assert_eq!(result.is_ok(), allowed, "{project}/{key}: {result:?}");
        if let Err(error) = result {
            assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        }
        let search = backend.last_search.lock().unwrap();
        let search = search.as_ref().unwrap();
        assert_eq!(search.jql, "(status = Done) AND project NOT IN (PRIVATE)");
        assert_eq!(search.max_results, 1);
    }
}

#[test]
fn raw_jql_rejects_length_and_nesting_caps() {
    let long = "project = PROJ ".repeat(MAX_JIRA_RAW_QUERY_BYTES / 4);
    let error = parse_jql_expression(&long).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let padded = format!("{}project = PROJ", " ".repeat(MAX_JIRA_RAW_QUERY_BYTES + 1));
    let error = parse_jql_expression(&padded).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let deep = format!(
        "{}project = PROJ{}",
        "(".repeat(MAX_JIRA_QUERY_DEPTH + 1),
        ")".repeat(MAX_JIRA_QUERY_DEPTH + 1)
    );
    let error = parse_jql_expression(&deep).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[tokio::test]
async fn search_rejection_diagnostics_distinguish_metadata_and_authorization_failures() {
    for (project, key, excluded, code, checks) in [
        (
            "P",
            "P-1",
            vec![],
            "jira_search_issue_key_invalid",
            [false, true, true],
        ),
        (
            "proj",
            "proj-1",
            vec![],
            "jira_search_issue_key_invalid",
            [false, true, true],
        ),
        (
            "PR.OJ",
            "PR.OJ-1",
            vec![],
            "jira_search_issue_key_invalid",
            [false, true, true],
        ),
        (
            "OTHER",
            "PROJ-2",
            vec![],
            "jira_search_issue_project_mismatch",
            [true, false, true],
        ),
        (
            "PRIVATE",
            "PRIVATE-1",
            vec!["PRIVATE"],
            "jira_search_project_unauthorized",
            [true, true, false],
        ),
        (
            "PRIVATE",
            "invalid-key",
            vec!["PRIVATE"],
            "jira_search_issue_key_invalid",
            [false, false, false],
        ),
    ] {
        let mut issue = visible_issue();
        issue.project = project.to_string();
        issue.key = key.to_string();
        issue.summary = Some("private-summary-must-not-appear".to_string());
        let backend = Arc::new(StubJiraBackend {
            search_page: Mutex::new(Some(JiraSearchPage {
                issues: vec![visible_issue(), issue],
                max_results: 50,
                start_at: 0,
                total: None,
                next_page_token: Some("private-response-page-token".to_string()),
                is_last: Some(false),
            })),
            ..StubJiraBackend::default()
        });
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let request = |token: Option<&str>| {
            let mut inputs = json!({
                "query": {"type":"jql", "value":"created >= startOfWeek(-1w) AND created <= endOfWeek(-1w) ORDER BY created DESC"},
                "maxResults":50
            });
            if let Some(token) = token {
                inputs["nextPageToken"] = json!(token);
            }
            InvocationBuilder::from(per_user_invocation("search", inputs, vec![]))
                .search(SearchAuthorization::new(
                    "project".to_string(),
                    SearchAuthorizationScope::excluding_exact_values(
                        excluded.iter().map(|v| (*v).to_string()).collect(),
                    ),
                ))
                .build()
        };
        let failing_page = backend
            .search_page
            .lock()
            .unwrap()
            .replace(page_with_upstream_token("private-request-page-token"));
        let first = provider.invoke(request(None)).await.unwrap();
        *backend.search_page.lock().unwrap() = failing_page;
        let sealed = first.result["nextPageToken"].as_str().unwrap().to_string();
        let error = provider.invoke(request(Some(&sealed))).await.unwrap_err();
        assert_eq!(
            backend
                .last_search
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .next_page_token
                .as_deref(),
            Some("private-request-page-token")
        );
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        assert_eq!(
            error.message,
            "Jira search returned an issue outside the authorized project scope"
        );
        assert_eq!(error.internal_diagnostic_code, Some(code));
        assert_eq!(error.upstream_status, Some(200));
        assert_eq!(error.upstream_duration_ms, Some(9));
        assert!(error.result.is_none());
        assert!(error.object_ids.is_none());
        let audit = error.audit.unwrap();
        let validation = &audit["searchResultValidation"];
        assert_eq!(validation["issueIndex"], 1);
        assert_eq!(validation["issueKeyValid"], checks[0]);
        assert_eq!(validation["keyProjectMatches"], checks[1]);
        assert_eq!(validation["projectAuthorized"], checks[2]);
        assert_eq!(validation["issueKey"]["sha256"], sha256_hex(key.as_bytes()));
        assert_eq!(
            validation["reportedProject"]["sha256"],
            sha256_hex(project.as_bytes())
        );
        assert_eq!(
            audit["effectiveSearchScope"]["excludedValues"],
            json!(excluded)
        );
        assert_eq!(
            audit["injectedScopePredicate"],
            if excluded.is_empty() {
                "none"
            } else {
                "project_not_in"
            }
        );
        assert_eq!(audit["pageTokenPresent"], true);
        assert_eq!(audit["resultCount"], 2);
        assert_eq!(backend.credential_observations.lock().unwrap().len(), 2);
        let serialized = format!("{audit} {}", error.message);
        for private_value in [
            key,
            "private-summary-must-not-appear",
            "private-request-page-token",
            "private-response-page-token",
            sealed.as_str(),
            "startOfWeek",
            code,
        ] {
            assert!(
                !serialized.contains(private_value),
                "unexpected diagnostic disclosure: {private_value}"
            );
        }
    }
}

#[tokio::test]
async fn successful_search_returns_bounded_sanitized_issue_fields() {
    let backend = StubJiraBackend {
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![JiraIssue {
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
                description: None,
            }],
            max_results: 1,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        ..StubJiraBackend::default()
    };
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let response = provider
        .invoke(
            InvocationBuilder::new("jira", "search")
                .inputs(json!({
                    "projects": ["PROJ"],
                    "query": {
                        "type": "jql",
                        "value": "key in (PROJ-1)"
                    }
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .search(search_preflight(["PROJ"]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();

    assert_eq!(response.result["issues"][0]["key"], "PROJ-1");
    assert_eq!(
        response.result["issues"][0]["webUrl"],
        "https://example.atlassian.net/browse/PROJ-1"
    );
    assert!(response.result["issues"][0].get("description").is_none());
    assert_eq!(response.upstream_status, Some(200));
    let audit = response.audit.as_ref().unwrap();
    assert_eq!(audit["queryAstVersion"], JIRA_QUERY_AST_VERSION);
    assert_eq!(audit["queryType"], "jql");
    assert_eq!(audit["canonicalCallerJqlHash"].as_str().unwrap().len(), 64);
    assert_eq!(audit["queryShape"]["filter"]["field"], "key");
    assert_eq!(audit["queryShape"]["filter"]["operator"], "IN");
    assert_eq!(audit["textOperandHashes"].as_array().unwrap().len(), 0);
    assert_eq!(response.object_ids.unwrap()["issueKeys"][0], "PROJ-1");
}

#[tokio::test]
async fn per_user_actions_use_selected_execution_credential_after_lookup() {
    let mut backend = StubJiraBackend {
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![visible_issue()],
            max_results: 1,
            start_at: 0,
            total: Some(1),
            next_page_token: None,
            is_last: Some(true),
        })),
        comments: Mutex::new(BTreeMap::from([(
            "10042".to_string(),
            test_comment("10042"),
        )])),
        attachments: Mutex::new(vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "evidence.txt".to_string(),
            size: 5,
            content_type: "text/plain".to_string(),
        }]),
        attachment_content: Mutex::new(BTreeMap::from([(
            "10055".to_string(),
            JiraAttachmentContent::from_bytes("evidence.txt", "text/plain", b"hello".to_vec()),
        )])),
        ..StubJiraBackend::default()
    };
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    provider
        .invoke(per_user_invocation(
            "issue.view",
            json!({"issue": "PROJ-1"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    provider
        .invoke(per_user_invocation(
            "search",
            json!({
                "projects": ["PROJ"],
                "query": {
                    "type": "jql",
                    "value": "project = PROJ"
                },
                "maxResults": 1
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(&backend, &[("search", "per-user-token")]);

    backend.credential_observations.lock().unwrap().clear();
    provider
        .invoke(per_user_invocation(
            "comment.add",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": {"type": "doc", "version": 1, "content": []}
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("add_comment", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let upload = b"upload".to_vec();
    provider
        .invoke(per_user_invocation(
            "attachment.add",
            json!({
                "issue": "PROJ-1",
                "attachments": [{
                    "field": "file0",
                    "filename": "evidence.txt",
                    "contentType": "text/plain",
                    "size": upload.len(),
                    "sha256": sha256_hex(&upload)
                }]
            }),
            vec![BrokerBodyPart::in_memory(
                "file0".to_string(),
                Some("evidence.txt".to_string()),
                Some("text/plain".to_string()),
                upload,
            )],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("add_attachment", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    provider
        .invoke(per_user_invocation(
            "attachment.download",
            json!({"issue": "PROJ-1", "attachmentId": "10055"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_attachment_metadata", "lookup-token"),
            ("attachment_content", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    provider
        .invoke(per_user_invocation(
            "attachment.list",
            json!({"issue": "PROJ-1"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue_attachment_list", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    provider
        .invoke(per_user_invocation(
            "verify",
            json!({
                "issue": "PROJ-1",
                "expectCommentId": "10042",
                "expectAttachmentId": "10055"
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
            ("issue_attachment_metadata", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_list_is_metadata_only_and_view_returns_body() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut reply = test_comment_with_body("10042", "secret list body");
    reply.parent_id = Some("10040".to_string());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), reply);
    backend.comments.lock().unwrap().insert(
        "10043".to_string(),
        test_comment_with_body("10043", "other issue secret list body"),
    );
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10042".to_string(), "PROJ-1".to_string());
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10043".to_string(), "PROJ-2".to_string());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let list = provider
        .invoke(per_user_invocation(
            "comment.list",
            json!({"issue": "PROJ-1", "maxResults": 5, "orderBy": "-created"}),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(list.result["operation"], "comment.list");
    assert_eq!(list.result["comments"].as_array().unwrap().len(), 1);
    assert_eq!(list.result["count"], 1);
    assert_eq!(list.result["total"], 1);
    assert_eq!(list.result["comments"][0]["commentId"], "10042");
    assert_eq!(list.result["comments"][0]["parentCommentId"], "10040");
    assert!(list.result["comments"][0].get("body").is_none());
    assert!(!list.result.to_string().contains("secret list body"));
    assert!(
        !list
            .result
            .to_string()
            .contains("other issue secret list body")
    );
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comments", "per-user-token"),
        ],
    );
    assert_eq!(
        backend
            .last_comment_list
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .order_by
            .as_deref(),
        Some("-created")
    );

    backend.credential_observations.lock().unwrap().clear();
    let view = provider
        .invoke(per_user_invocation(
            "comment.view",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(view.result["operation"], "comment.view");
    assert_eq!(
        view.result["comment"]["body"]["content"][0]["content"][0]["text"],
        "secret list body"
    );
    assert_eq!(view.result["comment"]["parentCommentId"], "10040");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_view_rejects_non_adf_upstream_body() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut comment = test_comment("10042");
    comment.body = Some(json!({"type": "paragraph"}));
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), comment);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(per_user_invocation(
            "comment.view",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn comment_view_rejects_oversize_upstream_body_as_sanitized_502() {
    let sentinel = "returned-comment-view-sentinel".repeat(16);
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend.comments.lock().unwrap().insert(
        "10042".to_string(),
        test_comment_with_body("10042", &sentinel),
    );
    let mut config = jira_config();
    config.content.max_body_bytes = 140;
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend));

    let error = provider
        .invoke(per_user_invocation(
            "comment.view",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.reason_code().http_status(), 502);
    assert_eq!(error.message, "Jira comment response body was invalid");
    assert!(!error.message.contains(&sentinel));
}

#[tokio::test]
async fn table_comment_body_is_valid_for_view_verify_and_property_membership() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut comment = test_comment("10042");
    comment.body = Some(adf_table());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), comment);
    backend
        .properties
        .lock()
        .unwrap()
        .insert("agent-access.review".to_string(), json!({"status": "ok"}));
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let verify = provider
        .invoke(per_user_invocation(
            "verify",
            json!({"issue": "PROJ-1", "expectCommentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(verify.result["verification"]["status"], "matched");

    backend.credential_observations.lock().unwrap().clear();
    let property = provider
        .invoke(per_user_invocation(
            "comment.property.get",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": "agent-access.review"
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(property.result["value"]["status"], "ok");
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
            ("comment_property", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let view = provider
        .invoke(per_user_invocation(
            "comment.view",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(view.result["comment"]["body"], adf_table());
}

#[tokio::test]
async fn scoped_comment_path_denies_comment_on_different_issue() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend.issues.insert(
        "PROJ-2".to_string(),
        JiraIssue {
            id: "10002".to_string(),
            key: "PROJ-2".to_string(),
            project: "PROJ".to_string(),
            summary: Some("other visible summary".to_string()),
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
    );
    backend.comments.lock().unwrap().insert(
        "10042".to_string(),
        test_comment_with_body("10042", "other issue"),
    );
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10042".to_string(), "PROJ-2".to_string());
    backend.properties.lock().unwrap().insert(
        "agent-access.review".to_string(),
        json!({"status": "hidden"}),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let view_error = provider
        .invoke(per_user_invocation(
            "comment.view",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(view_error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let property_error = provider
        .invoke(per_user_invocation(
            "comment.property.get",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": "agent-access.review"
            }),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(property_error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_reply_denies_parent_on_different_issue() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend.comments.lock().unwrap().insert(
        "10042".to_string(),
        test_comment_with_body("10042", "other issue"),
    );
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10042".to_string(), "PROJ-2".to_string());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.reply",
            json!({
                "issue": "PROJ-1",
                "parentCommentId": "10042",
                "contentFormat": "adf",
                "content": adf_text("reply secret")
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.added_comments.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_reply_rejects_missing_or_mismatched_created_parent() {
    for (override_parent, expected_message) in [
        (None, "Jira reply response did not include a parent id"),
        (
            Some("10099".to_string()),
            "Jira reply response parent id did not match the requested parent",
        ),
    ] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        backend
            .comments
            .lock()
            .unwrap()
            .insert("10040".to_string(), test_comment("10040"));
        *backend.add_comment_parent_override.lock().unwrap() = Some(override_parent);
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

        let error = provider
            .invoke(per_user_invocation(
                "comment.reply",
                json!({
                    "issue": "PROJ-1",
                    "parentCommentId": "10040",
                    "contentFormat": "adf",
                    "content": adf_text("reply secret")
                }),
                vec![],
            ))
            .await
            .unwrap_err();

        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, expected_message);
        assert_eq!(backend.added_comments.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn comment_reply_rejects_non_top_level_thread_root() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut child = test_comment("10041");
    child.parent_id = Some("10040".to_string());
    let mut non_root = test_comment("10040");
    non_root.parent_id = Some("10039".to_string());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10041".to_string(), child);
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10040".to_string(), non_root);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.reply",
            json!({
                "issue": "PROJ-1",
                "parentCommentId": "10041",
                "contentFormat": "adf",
                "content": adf_text("reply secret")
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error.message,
        "Jira comment thread root was not a top-level comment"
    );
    assert!(backend.added_comments.lock().unwrap().is_empty());
}

#[tokio::test]
async fn comment_reply_denies_thread_root_on_different_issue() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut child = test_comment("10041");
    child.parent_id = Some("10040".to_string());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10041".to_string(), child);
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10040".to_string(), test_comment("10040"));
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10041".to_string(), "PROJ-1".to_string());
    backend
        .comment_issue_keys
        .lock()
        .unwrap()
        .insert("10040".to_string(), "PROJ-2".to_string());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.reply",
            json!({
                "issue": "PROJ-1",
                "parentCommentId": "10041",
                "contentFormat": "adf",
                "content": adf_text("reply secret")
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.added_comments.lock().unwrap().is_empty());
}

#[tokio::test]
async fn comment_add_rejects_created_parent() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.add_comment_parent_override.lock().unwrap() = Some(Some("10040".to_string()));
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.add",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": adf_text("top-level secret")
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error.message,
        "Jira top-level comment response unexpectedly included a parent id"
    );
    assert_eq!(backend.added_comments.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn comment_mutations_reject_oversize_returned_bodies_after_one_side_effect() {
    let sentinel = "returned-comment-mutation-sentinel".repeat(16);
    let returned_body = adf_text(&sentinel);

    let mut add_backend = StubJiraBackend::default();
    add_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    *add_backend.returned_comment_body.lock().unwrap() = Some(returned_body.clone());
    let add_backend = Arc::new(add_backend);
    let mut config = jira_config();
    config.content.max_body_bytes = 140;
    let add_provider = JiraProvider::with_backend(
        config.clone(),
        ProviderLimits::default(),
        add_backend.clone(),
    );
    let add_error = add_provider
        .invoke(per_user_invocation(
            "comment.add",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": adf_text("ok")
            }),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(add_error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(add_error.reason_code().http_status(), 502);
    assert_eq!(add_backend.added_comments.lock().unwrap().len(), 1);

    let mut reply_backend = StubJiraBackend::default();
    reply_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    reply_backend
        .comments
        .lock()
        .unwrap()
        .insert("10040".to_string(), test_comment("10040"));
    *reply_backend.returned_comment_body.lock().unwrap() = Some(returned_body.clone());
    let reply_backend = Arc::new(reply_backend);
    let reply_provider = JiraProvider::with_backend(
        config.clone(),
        ProviderLimits::default(),
        reply_backend.clone(),
    );
    let reply_error = reply_provider
        .invoke(per_user_invocation(
            "comment.reply",
            json!({
                "issue": "PROJ-1",
                "parentCommentId": "10040",
                "contentFormat": "adf",
                "content": adf_text("ok")
            }),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        reply_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(reply_error.reason_code().http_status(), 502);
    assert_eq!(reply_backend.added_comments.lock().unwrap().len(), 1);

    let mut update_backend = StubJiraBackend::default();
    update_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    update_backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), test_comment("10042"));
    *update_backend.returned_comment_body.lock().unwrap() = Some(returned_body);
    let update_backend = Arc::new(update_backend);
    let update_provider =
        JiraProvider::with_backend(config, ProviderLimits::default(), update_backend.clone());
    let update_error = update_provider
        .invoke(per_user_invocation(
            "comment.update",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "contentFormat": "adf",
                "content": adf_text("ok")
            }),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        update_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(update_error.reason_code().http_status(), 502);
    assert_eq!(update_backend.updated_comments.lock().unwrap().len(), 1);

    for error in [add_error, reply_error, update_error] {
        assert_eq!(error.message, "Jira comment response body was invalid");
        assert!(!error.message.contains(&sentinel));
    }
}

#[tokio::test]
async fn comment_update_preserves_visibility_and_defaults_notify_false() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut existing = test_comment("10042");
    existing.body = Some(adf_table());
    existing.visibility = Some(JiraCommentVisibility {
        visibility_type: "group".to_string(),
        value: Some("Developers".to_string()),
        identifier: Some("group-id".to_string()),
    });
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), existing);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let result = provider
        .invoke(per_user_invocation(
            "comment.update",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "contentFormat": "adf",
                "content": adf_text("updated secret")
            }),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(result.result["operation"], "comment.update");
    assert!(
        !result
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("updated secret")
    );
    assert_eq!(result.audit.as_ref().unwrap()["visibilityRestricted"], true);
    assert_eq!(result.audit.as_ref().unwrap()["visibilityMode"], "preserve");
    let updated = backend.updated_comments.lock().unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].0, "10042");
    assert!(!updated[0].1.notify_users);
    assert_eq!(
        updated[0]
            .1
            .visibility
            .as_ref()
            .unwrap()
            .identifier
            .as_deref(),
        Some("group-id")
    );
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
            ("update_comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_update_preserve_fails_before_put_when_current_comment_unreadable() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.comment_error.lock().unwrap() = Some(JiraBackendError::Forbidden);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.update",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "contentFormat": "adf",
                "content": adf_text("updated secret")
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamForbidden);
    assert!(backend.updated_comments.lock().unwrap().is_empty());
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_add_visibility_requires_allowlist_and_serializes_group_identifier() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let denied = provider
        .invoke(per_user_invocation(
            "comment.add",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": adf_text("restricted"),
                "visibility": {"type": "group", "identifier": "group-id"}
            }),
            vec![],
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.reason_code(), ReasonCode::InputInvalid);
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    let mut config = jira_config();
    config.comments.allowed_visibility = vec![crate::JiraCommentVisibilityConfig {
        visibility_type: "group".to_string(),
        value: Some("Developers".to_string()),
        identifier: Some("group-id".to_string()),
    }];
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());
    let allowed = provider
        .invoke(per_user_invocation(
            "comment.add",
            json!({
                "issue": "PROJ-1",
                "contentFormat": "adf",
                "content": adf_text("restricted"),
                "visibility": {"type": "group", "identifier": "group-id"}
            }),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(
        allowed.audit.as_ref().unwrap()["visibilityRestricted"],
        true
    );
    let added = backend.added_comments.lock().unwrap();
    assert_eq!(
        added[0].visibility.as_ref().unwrap().identifier.as_deref(),
        Some("group-id")
    );
    assert_eq!(
        added[0].visibility.as_ref().unwrap().value.as_deref(),
        Some("Developers")
    );
}

#[tokio::test]
async fn comment_add_applies_configured_attribution_footer() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider = JiraProvider {
        attribution: ProviderAttributionConfig::from_patterns(
            &jira_descriptor(&jira_config()),
            &[String::from("comment.add")],
        ),
        ..JiraProvider::from_backend(jira_config(), ProviderLimits::default(), backend.clone())
    };
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let mut invocation = per_user_invocation(
        "comment.add",
        json!({
            "issue": "PROJ-1",
            "contentFormat": "adf",
            "content": adf_text("body before attribution")
        }),
        vec![],
    );
    invocation = InvocationBuilder::from(invocation)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let result = provider.invoke(invocation).await.unwrap();

    assert_eq!(
        result.audit.as_ref().unwrap()["attribution"]["applied"],
        true
    );
    assert_eq!(
        result.audit.as_ref().unwrap()["attribution"]["representation"],
        "adf"
    );
    assert_eq!(result.audit.as_ref().unwrap()["contentFormat"], "adf");
    assert_eq!(result.audit.as_ref().unwrap()["nativeContentFormat"], "adf");
    assert!(result.audit.as_ref().unwrap()["sourceContentBytes"].is_u64());
    assert!(result.audit.as_ref().unwrap()["finalNativeContentBytes"].is_u64());
    assert!(
        !result
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("body before attribution")
    );
    let added = backend.added_comments.lock().unwrap();
    let content = added[0].body["content"].as_array().unwrap();
    assert_eq!(content[0]["content"][0]["text"], "body before attribution");
    assert_eq!(content[content.len() - 2]["type"], "rule");
    assert_eq!(
        content[content.len() - 1]["content"][0]["text"],
        format!("Added via Agent Access Broker. Request ID: {broker_request_id}")
    );
}

#[tokio::test]
async fn comment_reply_resolves_child_parent_to_thread_root() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10040".to_string(), test_comment("10040"));
    let mut child = test_comment("10041");
    child.parent_id = Some("10040".to_string());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10041".to_string(), child);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let result = provider
        .invoke(per_user_invocation(
            "comment.reply",
            json!({
                "issue": "PROJ-1",
                "parentCommentId": "10041",
                "contentFormat": "adf",
                "content": adf_text("reply secret")
            }),
            vec![],
        ))
        .await
        .unwrap();

    assert_eq!(result.result["operation"], "comment.reply");
    assert_eq!(result.result["requestedParentCommentId"], "10041");
    assert_eq!(result.result["parentCommentId"], "10040");
    assert_eq!(result.result["comment"]["parentCommentId"], "10040");
    assert!(
        !result
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("reply secret")
    );
    let added = backend.added_comments.lock().unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].parent_id.as_deref(), Some("10040"));
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
            ("comment", "per-user-token"),
            ("add_comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn comment_property_actions_filter_keys_and_exclude_values_from_audit() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".to_string(), test_comment("10042"));
    *backend.property_keys.lock().unwrap() = vec![
        "agent-access.review".to_string(),
        "agent-access.bad key".to_string(),
        "agent-access.bad/key".to_string(),
        "jira.hidden".to_string(),
        "other.hidden".to_string(),
    ];
    backend.properties.lock().unwrap().insert(
        "agent-access.review".to_string(),
        json!({"status": "secret-property-value"}),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let list = provider
        .invoke(per_user_invocation(
            "comment.property.list",
            json!({"issue": "PROJ-1", "commentId": "10042"}),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(list.result["keys"].as_array().unwrap().len(), 1);
    assert_eq!(list.result["keys"][0]["key"], "agent-access.review");
    assert!(!list.result.to_string().contains("bad key"));
    assert!(!list.result.to_string().contains("bad/key"));
    assert!(!list.result.to_string().contains("jira.hidden"));
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
            ("comment_property_keys", "per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let get = provider
        .invoke(per_user_invocation(
            "comment.property.get",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": "agent-access.review"
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(get.result["value"]["status"], "secret-property-value");
    assert!(
        !get.audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("secret-property-value")
    );

    let set = provider
        .invoke(per_user_invocation(
            "comment.property.set",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": "agent-access.review",
                "value": {"status": "new-secret-property-value"}
            }),
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(set.result["status"], "set");
    assert!(
        !set.audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("new-secret-property-value")
    );
    assert_eq!(backend.set_properties.lock().unwrap().len(), 1);
}

#[test]
fn comment_property_inputs_reject_disallowed_reserved_null_and_oversized_values() {
    let config = jira_config();
    for property_key in ["jira.hidden", "other.hidden", "agent-access.bad/key"] {
        let error = parse_comment_property_inputs(
            "comment.property.get",
            &json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": property_key,
            }),
            &config,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }

    let error = parse_comment_property_inputs(
        "comment.property.set",
        &json!({
            "issue": "PROJ-1",
            "commentId": "10042",
            "propertyKey": "agent-access.review",
            "value": null,
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let mut config = jira_config();
    config.comments.max_property_value_bytes = 4;
    let error = parse_comment_property_inputs(
        "comment.property.set",
        &json!({
            "issue": "PROJ-1",
            "commentId": "10042",
            "propertyKey": "agent-access.review",
            "value": {"status": "too-large"},
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);
}

#[tokio::test]
async fn comment_property_membership_proof_uses_execution_credential() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.comment_error.lock().unwrap() = Some(JiraBackendError::NotFound);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(per_user_invocation(
            "comment.property.get",
            json!({
                "issue": "PROJ-1",
                "commentId": "10042",
                "propertyKey": "agent-access.review"
            }),
            vec![],
        ))
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comment", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn response_byte_cap_fails_without_returning_content() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert(
        "PROJ-1".to_string(),
        JiraIssue {
            id: "10001".to_string(),
            key: "PROJ-1".to_string(),
            project: "PROJ".to_string(),
            summary: Some("large visible summary".to_string()),
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
    );
    let limits = ProviderLimits::default().with_max_upstream_response_bytes(8);
    let provider = JiraProvider::with_backend(jira_config(), limits, Arc::new(backend));
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.view")
                .inputs(json!({"issue": "PROJ-1"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!error.message.contains("large visible summary"));
}

#[tokio::test]
async fn comment_add_rejects_malformed_body_before_upstream() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "comment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "contentFormat": "adf",
                    "content": {"type": "paragraph"}
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "comment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "contentFormat": "adf",
                    "content": {
                        "type": "doc",
                        "version": 1,
                        "content": [{"type": "unknownNode"}]
                    }
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);

    let mut config = jira_config();
    config.content.comment_formats.clear();
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend);
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "comment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "contentFormat": "adf",
                    "content": {"type": "doc", "version": 1, "content": []}
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodyFormatUnsupported);
}

#[tokio::test]
async fn attachment_add_checks_integrity_and_reports_partial_without_retry() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.fail_upload_after_successes.lock().unwrap() = Some(1);
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let first = b"first upload".to_vec();
    let second = b"second upload".to_vec();
    let third = b"third upload".to_vec();
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "attachments": [
                        {
                            "field": "file0",
                            "filename": "first.txt",
                            "contentType": "text/plain",
                            "size": first.len(),
                            "sha256": sha256_hex(&first)
                        },
                        {
                            "field": "file1",
                            "filename": "second.txt",
                            "contentType": "text/plain",
                            "size": second.len(),
                            "sha256": sha256_hex(&second)
                        },
                        {
                            "field": "file2",
                            "filename": "third.txt",
                            "contentType": "text/plain",
                            "size": third.len(),
                            "sha256": sha256_hex(&third)
                        }
                    ]
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .body_parts(vec![
                    BrokerBodyPart::in_memory(
                        "file0".to_string(),
                        Some("first.txt".to_string()),
                        Some("text/plain".to_string()),
                        first,
                    ),
                    BrokerBodyPart::in_memory(
                        "file1".to_string(),
                        Some("second.txt".to_string()),
                        Some("text/plain".to_string()),
                        second,
                    ),
                    BrokerBodyPart::in_memory(
                        "file2".to_string(),
                        Some("third.txt".to_string()),
                        Some("text/plain".to_string()),
                        third,
                    ),
                ])
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
    let result = error.result.as_ref().unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(result["failures"].as_array().unwrap().len(), 2);
    assert_eq!(result["failures"][0]["status"], "failed");
    assert_eq!(result["failures"][1]["status"], "skipped");
    assert_eq!(
        result["failures"][1]["reason"],
        "not_attempted_after_previous_failure"
    );
    assert_eq!(
        error.audit.as_ref().unwrap()["attachments"][0]["attachment"]["sha256"],
        json!(sha256_hex(b"first upload".as_ref()))
    );
    assert_eq!(
        error.audit.as_ref().unwrap()["attachments"][1]["status"],
        json!("failed")
    );
    assert_eq!(
        error.audit.as_ref().unwrap()["attachments"][2]["status"],
        json!("skipped")
    );
    assert_eq!(backend.uploaded_attachments.lock().unwrap().len(), 1);

    let bad = b"tampered".to_vec();
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "attachments": [{
                        "field": "file0",
                        "filename": "bad.txt",
                        "contentType": "text/plain",
                        "size": bad.len(),
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                    }]
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .body_parts(vec![BrokerBodyPart::in_memory(
                    "file0".to_string(),
                    Some("bad.txt".to_string()),
                    Some("text/plain".to_string()),
                    bad,
                )])
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentIntegrityMismatch);

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": ""}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let duplicate = b"duplicate".to_vec();
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "attachments": [
                        {
                            "field": "file0",
                            "filename": "duplicate.txt",
                            "contentType": "text/plain",
                            "size": duplicate.len(),
                            "sha256": sha256_hex(&duplicate)
                        },
                        {
                            "field": "file0",
                            "filename": "duplicate.txt",
                            "contentType": "text/plain",
                            "size": duplicate.len(),
                            "sha256": sha256_hex(&duplicate)
                        }
                    ]
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .body_parts(vec![
                    BrokerBodyPart::in_memory(
                        "file0".to_string(),
                        Some("duplicate.txt".to_string()),
                        Some("text/plain".to_string()),
                        duplicate.clone(),
                    ),
                    BrokerBodyPart::in_memory(
                        "file0".to_string(),
                        Some("duplicate.txt".to_string()),
                        Some("text/plain".to_string()),
                        duplicate,
                    ),
                ])
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let mut failing_backend = StubJiraBackend::default();
    failing_backend
        .issues
        .insert("PROJ-1".to_string(), visible_issue());
    *failing_backend.fail_upload_after_successes.lock().unwrap() = Some(0);
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(failing_backend),
    );
    let bytes = b"first failure".to_vec();
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.add")
                .inputs(json!({
                    "issue": "PROJ-1",
                    "attachments": [{
                        "field": "file0",
                        "filename": "failure.txt",
                        "contentType": "text/plain",
                        "size": bytes.len(),
                        "sha256": sha256_hex(&bytes)
                    }]
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .body_parts(vec![BrokerBodyPart::in_memory(
                    "file0".to_string(),
                    Some("failure.txt".to_string()),
                    Some("text/plain".to_string()),
                    bytes,
                )])
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
    let audit = error.audit.unwrap();
    assert_eq!(
        audit["attachments"][0]["attachment"]["filename"],
        "failure.txt"
    );
}

fn attachment_add_invocation(names: &[&str]) -> ProviderInvocation {
    let attachments = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            json!({
                "field": format!("file{index}"),
                "filename": format!("{name}.txt"),
                "contentType": "text/plain",
                "size": name.len(),
                "sha256": sha256_hex(name.as_bytes())
            })
        })
        .collect::<Vec<_>>();
    let body_parts = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            BrokerBodyPart::in_memory(
                format!("file{index}"),
                Some(format!("{name}.txt")),
                Some("text/plain".to_string()),
                name.as_bytes().to_vec(),
            )
        })
        .collect();
    InvocationBuilder::new("jira", "attachment.add")
        .inputs(json!({"issue": "PROJ-1", "attachments": attachments}))
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .body_parts(body_parts)
        .build()
}

#[tokio::test]
async fn attachment_add_throttling_after_applied_uploads_is_unverified_not_rate_limited() {
    let wait = UpstreamRetryAfter::after_seconds(45);
    let throttled_backend = |successes| {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        *backend.fail_upload_after_successes.lock().unwrap() = Some(successes);
        *backend.upload_error.lock().unwrap() = Some(JiraBackendError::RateLimited(Some(wait)));
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend))
    };

    // An upload applied before a later one was throttled: repeating the batch
    // after the wait would upload it again, so this is not a rate limit.
    let error = throttled_backend(1)
        .invoke(attachment_add_invocation(&["first", "second", "third"]))
        .await
        .unwrap_err();
    assert_eq!(error.decision(), crate::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(
        error.message,
        "Jira attachment upload partially failed: part of the batch was applied before jira \
         started rate limiting requests. Do not repeat the batch; inspect result.safeLocators first."
    );
    let result = error.result.as_deref().unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["attachments"].as_array().unwrap().len(), 1);
    let created = result["attachments"][0]["attachmentId"].clone();
    assert_eq!(result["failures"][0]["reason"], "upstream_rate_limited");
    assert_eq!(
        result["failures"][1]["reason"],
        "not_attempted_after_previous_failure"
    );
    assert_eq!(result["mutationStatus"], "applied_unverified");
    assert_eq!(result["retrySafe"], false);
    assert_eq!(result["verificationStage"], "attachment_upload");
    assert_eq!(
        result["safeLocators"],
        json!({"issueId": "10001", "issueKey": "PROJ-1", "attachmentIds": [created]})
    );
    for field in ["limitScope", "service", "retryAfterSeconds", "retryAt"] {
        assert!(result.get(field).is_none(), "{field}: {result}");
    }
    assert!(result.get("executionState").is_none());

    // Nothing applied: the throttled first upload stays a rate limit.

    let error = throttled_backend(0)
        .invoke(attachment_add_invocation(&["only"]))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
    assert_eq!(
        error.message,
        format!(
            "Jira attachment upload failed: jira is rate limiting requests. Retry after 45s (at {}).",
            wait.retry_at()
        )
    );
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "limitScope": "upstream",
            "service": "jira",
            "retryAfterSeconds": 45,
            "retryAt": wait.retry_at(),
        }))
    );
    assert_eq!(
        error.audit.as_ref().unwrap()["attachments"][0]["reason"],
        "upstream_rate_limited"
    );
}

#[tokio::test]
async fn write_receipts_follow_what_jira_may_have_applied() {
    let not_applied = json!({"mutationStatus": "not_applied", "retrySafe": true});
    let unknown = json!({"mutationStatus": "unknown", "retrySafe": false});
    let write = JiraWrite::new(json!({"issueId": "10001", "issueKey": "PROJ-1"}));
    let unverified = |stage: &str| {
        json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": stage,
            "safeLocators": {"issueId": "10001", "issueKey": "PROJ-1"},
        })
    };
    // Only the SDK's not-sent proof becomes `NotSent`; a send that may have
    // reached Jira becomes `NoResponse`. Both keep the reason and message a
    // timeout or transport failure reports.
    for (timed_out, reason, message) in [
        (
            false,
            ReasonCode::UpstreamConnectionFailed,
            "Jira request failed",
        ),
        (true, ReasonCode::UpstreamTimeout, "Jira request timed out"),
    ] {
        let unsent = jira_upstream_error(UpstreamError::NotSent {
            timed_out,
            detail: "connection refused".to_string(),
        });
        assert_eq!(unsent, JiraBackendError::NotSent { timed_out });
        let unanswered = jira_upstream_error(if timed_out {
            UpstreamError::Timeout
        } else {
            UpstreamError::Transport("reset".to_string())
        });
        assert_eq!(unanswered, JiraBackendError::NoResponse { timed_out });
        for (error, receipt) in [(unsent, &not_applied), (unanswered, &unknown)] {
            assert_eq!(jira_backend_reason_code(&error), reason);
            assert_eq!(sanitized_backend_reason(&error), reason.as_str());
            let failure = write.failed(error.clone());
            assert_eq!(failure.decision(), crate::Decision::Error);
            assert_eq!(failure.reason_code(), reason);
            assert_eq!(failure.message, message);
            assert_eq!(failure.result.as_deref(), Some(receipt));
            // Reads carry no mutation receipt.
            let read = jira_backend_error(error);
            assert_eq!(read.reason_code(), reason);
            assert_eq!(read.message, message);
            assert!(read.result.is_none());
        }
    }
    // A 5xx may follow a committed write; a success status followed by an
    // unreadable response means Jira accepted it.
    let server_error = write.failed(JiraBackendError::HttpStatus(502));
    assert_eq!(server_error.reason_code(), ReasonCode::UpstreamFailed);
    assert_eq!(server_error.result.as_deref(), Some(&unknown));
    // The Broker never follows a redirect: the write may have committed.
    let redirected = write.failed(JiraBackendError::Redirected);
    assert_eq!(redirected.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(redirected.message, "Jira response protocol error");
    assert_eq!(redirected.result.as_deref(), Some(&unknown));
    assert_eq!(
        sanitized_backend_reason(&JiraBackendError::Redirected),
        "upstream_protocol_failed"
    );
    for (error, reason) in [
        (JiraBackendError::Timeout, ReasonCode::UpstreamTimeout),
        (
            JiraBackendError::Transport("body".to_string()),
            ReasonCode::UpstreamConnectionFailed,
        ),
        (
            JiraBackendError::ResponseTooLarge,
            ReasonCode::UpstreamProtocolFailed,
        ),
        (
            JiraBackendError::Protocol("shape".to_string()),
            ReasonCode::UpstreamProtocolFailed,
        ),
    ] {
        let accepted = accepted_if_success(201)(error.clone());
        assert_eq!(jira_backend_reason_code(&accepted), reason);
        let failure = write.failed(accepted);
        assert_eq!(failure.reason_code(), reason);
        assert_eq!(failure.message, jira_backend_error(error.clone()).message);
        assert_eq!(
            failure.result.as_deref(),
            Some(&unverified("mutation_response"))
        );
        // The same failure after an error status, or before sending, is not
        // an accepted write.
        assert_eq!(accepted_if_success(400)(error.clone()), error);
        assert!(write.failed(error).result.is_none());
    }
    // Rejections and throttling carry no receipt.
    for error in [
        JiraBackendError::HttpStatus(409),
        JiraBackendError::Forbidden,
        JiraBackendError::NotFound,
        JiraBackendError::RateLimited(None),
        jira_upstream_error(UpstreamError::NotAllowed),
    ] {
        assert!(
            write
                .failed(error)
                .result
                .as_deref()
                .is_none_or(|result| result.get("mutationStatus").is_none())
        );
    }

    let update = |error: Option<JiraBackendError>, readback: Option<JiraBackendError>| {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        *backend.issue_update_error.lock().unwrap() = error;
        if let Some(readback) = readback {
            backend
                .issue_errors
                .lock()
                .unwrap()
                .insert("PROJ-1".to_string(), readback);
        }
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend))
    };
    let update_invocation = || {
        per_user_invocation(
            "issue.update",
            json!({"issue": "PROJ-1", "summary": "new summary"}),
            vec![],
        )
    };
    for (error, reason, receipt) in [
        (
            JiraBackendError::NotSent { timed_out: false },
            ReasonCode::UpstreamConnectionFailed,
            not_applied.clone(),
        ),
        (
            JiraBackendError::NoResponse { timed_out: true },
            ReasonCode::UpstreamTimeout,
            unknown.clone(),
        ),
        (
            JiraBackendError::HttpStatus(503),
            ReasonCode::UpstreamFailed,
            unknown.clone(),
        ),
        (
            accepted_if_success(204)(JiraBackendError::Transport("body".to_string())),
            ReasonCode::UpstreamConnectionFailed,
            unverified("mutation_response"),
        ),
    ] {
        let failure = update(Some(error), None)
            .invoke(update_invocation())
            .await
            .unwrap_err();
        assert_eq!(failure.reason_code(), reason);
        assert_eq!(failure.result.as_deref(), Some(&receipt));
    }
    // A read-back that times out after the update applied leaves it
    // unverified at the read-back stage, with its own reason.
    let failure = update(None, Some(JiraBackendError::NoResponse { timed_out: true }))
        .invoke(update_invocation())
        .await
        .unwrap_err();
    assert_eq!(failure.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(
        failure.result.as_deref(),
        Some(&unverified("post_update_readback"))
    );

    // A created comment that does not match the request was still created.
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.add_comment_parent_override.lock().unwrap() = Some(Some("10040".to_string()));
    let failure =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend))
            .invoke(per_user_invocation(
                "comment.add",
                json!({"issue": "PROJ-1", "contentFormat": "adf", "content": adf_text("hello")}),
                vec![],
            ))
            .await
            .unwrap_err();
    assert_eq!(failure.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        failure.result.as_deref(),
        Some(&unverified("mutation_response"))
    );

    // An attachment batch whose first upload was unsent applied nothing; one
    // whose first upload may have applied, or that stopped after an applied
    // upload, has an unknown outcome. A rejected first upload applied
    // nothing either.
    let stopped_after = |successes, error| {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        *backend.fail_upload_after_successes.lock().unwrap() = Some(successes);
        *backend.upload_error.lock().unwrap() = Some(error);
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend))
    };
    for (successes, error, receipt) in [
        (
            0,
            JiraBackendError::NotSent { timed_out: true },
            Some(&not_applied),
        ),
        (
            0,
            JiraBackendError::NoResponse { timed_out: false },
            Some(&unknown),
        ),
        (0, JiraBackendError::HttpStatus(500), Some(&unknown)),
        (0, JiraBackendError::Redirected, Some(&unknown)),
        (
            0,
            accepted_if_success(200)(JiraBackendError::Timeout),
            Some(&unknown),
        ),
        (0, JiraBackendError::HttpStatus(413), None),
    ] {
        let failure = stopped_after(successes, error.clone())
            .invoke(attachment_add_invocation(&["first", "second"]))
            .await
            .unwrap_err();
        assert_eq!(failure.reason_code(), ReasonCode::UpstreamFailed);
        assert_eq!(failure.message, "Jira attachment upload failed");
        assert_eq!(failure.result.as_deref(), receipt, "{error:?}");
    }
    assert_eq!(
        stopped_after(0, JiraBackendError::NotSent { timed_out: true })
            .invoke(attachment_add_invocation(&["first", "second"]))
            .await
            .unwrap_err()
            .audit
            .unwrap()["attachments"][0]["reason"],
        "upstream_timeout"
    );
    for error in [
        JiraBackendError::NotSent { timed_out: true },
        JiraBackendError::HttpStatus(413),
    ] {
        let failure = stopped_after(1, error)
            .invoke(attachment_add_invocation(&["first", "second"]))
            .await
            .unwrap_err();
        assert_eq!(failure.reason_code(), ReasonCode::UpstreamFailed);
        assert_eq!(failure.message, "Jira attachment upload partially failed");
        let result = failure.result.as_deref().unwrap();
        assert_eq!(result["status"], "partial");
        assert_eq!(result["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(result["mutationStatus"], "unknown", "{result}");
        assert_eq!(result["retrySafe"], false);
    }
}

/// Throttling after an applied write reports the write as applied but
/// unverified, never as a rate limit to wait out and retry.
fn assert_unverified_after_throttling(error: &ProviderError, stage: &str, locators: Value) {
    assert_eq!(error.decision(), crate::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(
        error.message,
        mutation_unverified_after_throttling_message("jira")
    );
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": stage,
            "safeLocators": locators,
        }))
    );
    if let Some(audit) = error.audit.as_deref() {
        assert_eq!(audit["upstreamFailure"], "upstream_rate_limited");
        assert_eq!(audit["failurePhase"], stage);
    }
}

#[tokio::test]
async fn throttled_readbacks_after_applied_writes_are_unverified_not_rate_limited() {
    let throttled = || JiraBackendError::RateLimited(Some(UpstreamRetryAfter::after_seconds(30)));

    // issue.create: the create applied, its read-back was throttled.
    let backend = StubJiraBackend::default();
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    backend
        .issue_errors
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), throttled());
    let backend = Arc::new(backend);
    let error =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone())
            .invoke(issue_create_invocation(json!({
                "project": "PROJ",
                "issueTypeId": "10001",
                "summary": "Created issue",
            })))
            .await
            .unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_create_readback",
        json!({"issueId": "10002", "issueKey": "PROJ-2"}),
    );
    assert_eq!(error.upstream_status, Some(201));
    assert!(error.audit.is_some());
    assert_eq!(backend.created_issues.lock().unwrap().len(), 1);

    // issue.child.create: the child read-back, then the parent read-back.
    for (child_throttled, stage) in [
        (true, "post_create_readback"),
        (false, "post_parent_readback"),
    ] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
            id: "10002".to_string(),
            key: "PROJ-2".to_string(),
        });
        let mut child = visible_issue();
        child.id = "10002".to_string();
        child.key = "PROJ-2".to_string();
        backend
            .issue_readbacks
            .lock()
            .unwrap()
            .insert("PROJ-2".to_string(), child);
        if child_throttled {
            backend
                .issue_errors
                .lock()
                .unwrap()
                .insert("PROJ-2".to_string(), throttled());
        } else {
            *backend.issue_parent_error.lock().unwrap() = Some(throttled());
        }
        let backend = Arc::new(backend);
        let error =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone())
                .invoke(issue_child_create_invocation(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "PROJ-1"
                })))
                .await
                .unwrap_err();
        assert_unverified_after_throttling(
            &error,
            stage,
            json!({
                "issueId": "10002",
                "issueKey": "PROJ-2",
                "parentIssueId": "10001",
                "parentIssueKey": "PROJ-1",
            }),
        );
        assert!(error.audit.is_some());
        assert_eq!(backend.created_issues.lock().unwrap().len(), 1);
    }

    // issue.update: the update applied, its read-back was throttled.
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    backend
        .issue_errors
        .lock()
        .unwrap()
        .insert("PROJ-1".to_string(), throttled());
    let backend = Arc::new(backend);
    let error =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone())
            .invoke(per_user_invocation(
                "issue.update",
                json!({"issue": "PROJ-1", "summary": "Renamed"}),
                vec![],
            ))
            .await
            .unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_update_readback",
        json!({"issueId": "10001", "issueKey": "PROJ-1"}),
    );
    assert_eq!(backend.updated_issues.lock().unwrap().len(), 1);

    // issue.parent.set: the parent change applied, its read-back was throttled.
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut parent = visible_issue();
    parent.id = "10002".to_string();
    parent.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), parent);
    *backend.issue_parent_error.lock().unwrap() = Some(throttled());
    let backend = Arc::new(backend);
    let error =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone())
            .invoke(per_user_invocation(
                "issue.parent.set",
                json!({"issue": "PROJ-1", "parentIssue": "PROJ-2"}),
                vec![],
            ))
            .await
            .unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_parent_readback",
        json!({
            "issueId": "10001",
            "issueKey": "PROJ-1",
            "parentIssueId": "10002",
            "parentIssueKey": "PROJ-2",
        }),
    );
    assert_eq!(backend.parent_updates.lock().unwrap().len(), 1);

    // issue.dependency.add: the link applied, its read-back was throttled.
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let mut blocked = visible_issue();
    blocked.id = "10002".to_string();
    blocked.key = "PROJ-2".to_string();
    backend.issues.insert("PROJ-2".to_string(), blocked);
    *backend.issue_link_types.lock().unwrap() = vec![blocks_link_type()];
    *backend.issue_links_error.lock().unwrap() = Some(throttled());
    let backend = Arc::new(backend);
    let error =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone())
            .invoke(per_user_invocation(
                "issue.dependency.add",
                json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2"}),
                vec![],
            ))
            .await
            .unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_dependency_readback",
        json!({
            "blockingIssueId": "10001",
            "blockingIssueKey": "PROJ-1",
            "blockedIssueId": "10002",
            "blockedIssueKey": "PROJ-2",
        }),
    );
    assert_eq!(backend.created_issue_links.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn throttled_writes_before_anything_applied_stay_upstream_rate_limited() {
    let backend = StubJiraBackend::default();
    *backend.issue_create_error.lock().unwrap() = Some(JiraBackendError::RateLimited(Some(
        UpstreamRetryAfter::after_seconds(30),
    )));
    let error =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend))
            .invoke(issue_create_invocation(json!({
                "project": "PROJ",
                "issueTypeId": "10001",
                "summary": "Created issue",
            })))
            .await
            .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
    assert_eq!(error.result.as_deref().unwrap()["retryAfterSeconds"], 30);
}

#[tokio::test]
async fn http_backend_maps_upstream_429_to_upstream_rate_limited() {
    let later = UpstreamRetryAfter::after_seconds(120)
        .at()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    for (retry_after, expected_seconds) in [
        (Some("30".to_string()), Some(30..=30)),
        (Some(later), Some(118..=121)),
        (None, None),
        (Some("604800".to_string()), Some(86_400..=86_400)),
        (Some("soon".to_string()), None),
    ] {
        let api = MockServer::start().await;
        let mut template = ResponseTemplate::new(429).set_body_string("quota secret detail");
        if let Some(value) = &retry_after {
            template = template.insert_header("Retry-After", value.as_str());
        }
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .respond_with(template)
            .expect(1)
            .mount(&api)
            .await;
        let mut config = jira_config();
        config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
        let backend = HttpJiraBackend::new_with_api_base(
            config,
            ProviderLimits::default(),
            Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
        );

        let backend_error = backend
            .issue(
                "PROJ-1",
                &AtlassianCredential::from_static(test_credential()),
            )
            .await
            .unwrap_err();
        let JiraBackendError::RateLimited(wait) = &backend_error else {
            panic!("expected rate limit, got {backend_error:?}");
        };
        assert_eq!(
            wait.map(|wait| wait.seconds()).is_some(),
            expected_seconds.is_some(),
            "{retry_after:?}"
        );
        let error = jira_backend_error(backend_error.clone());
        assert_eq!(error.decision(), crate::Decision::Error);
        assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        assert_eq!(error.reason_code().http_status(), 429);
        assert!(!error.message.contains("secret"));
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "jira");
        assert!(result.get("retrySafe").is_none());
        assert!(result.get("executionState").is_none());
        match expected_seconds {
            Some(range) => {
                let seconds = result["retryAfterSeconds"].as_u64().unwrap();
                assert!(range.contains(&seconds), "{retry_after:?}: {seconds}");
                let retry_at = result["retryAt"].as_str().unwrap();
                assert!(retry_at.ends_with('Z') && !retry_at.contains('.'));
                assert_eq!(
                    error.message,
                    format!(
                        "jira is rate limiting requests. Retry after {seconds}s (at {retry_at})."
                    )
                );
            }
            None => {
                assert!(result.get("retryAfterSeconds").is_none());
                assert!(result.get("retryAt").is_none());
                assert_eq!(
                    error.message,
                    "jira is rate limiting requests. Retry later."
                );
            }
        }
    }
}

#[tokio::test]
async fn attachment_download_requires_membership_and_enforces_download_cap() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.attachments.lock().unwrap() = vec![JiraAttachment {
        id: "10055".to_string(),
        filename: "evidence.txt".to_string(),
        size: 5,
        content_type: "text/plain".to_string(),
    }];
    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent::from_bytes("evidence.txt", "text/plain", b"hello".to_vec()),
    );
    let backend = Arc::new(backend);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "99999"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);

    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent::from_bytes("evidence.txt", "application/json", b"hello".to_vec()),
    );
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);

    let mut config = jira_config();
    config.attachments.media_types = vec![
        "text/plain".to_string(),
        "application/octet-stream".to_string(),
    ];
    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent {
            filename: "evidence.txt".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: Some(6),
            sha256: None,
            stream: ProviderResultStream::from_bytes("application/octet-stream", b"hello".to_vec()),
        },
    );
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);

    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent::from_bytes(
            "evidence.txt",
            "text/plain; charset=utf-8",
            b"hello".to_vec(),
        ),
    );

    let limits = ProviderLimits::default().with_max_download_bytes(4);
    let provider = JiraProvider::with_backend(jira_config(), limits, backend);
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);

    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let large_bytes = vec![b'x'; 80];
    *backend.attachments.lock().unwrap() = vec![JiraAttachment {
        id: "10055".to_string(),
        filename: "evidence.txt".to_string(),
        size: large_bytes.len() as u64,
        content_type: "text/plain".to_string(),
    }];
    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent::from_bytes("evidence.txt", "text/plain", large_bytes),
    );
    let limits = ProviderLimits::default()
        .with_max_upstream_response_bytes(64)
        .with_max_download_bytes(128);
    let provider = JiraProvider::with_backend(jira_config(), limits, Arc::new(backend));
    let result = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(result.result["size"], 80);
    assert!(result.result.get("contentBase64").is_none());
    let stream = result.stream.unwrap();
    assert_eq!(stream.content_type, "text/plain");
    assert_eq!(stream.memory_len(), Some(80));

    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.attachments.lock().unwrap() = vec![JiraAttachment {
        id: "10055".to_string(),
        filename: "evidence.txt".to_string(),
        size: 5,
        content_type: "text/plain".to_string(),
    }];
    backend.attachment_content.lock().unwrap().insert(
        "10055".to_string(),
        JiraAttachmentContent {
            filename: "evidence.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: None,
            sha256: None,
            stream: ProviderResultStream::from_stream(
                "text/plain",
                stream::iter([Ok(Bytes::from_static(b"hell"))]),
            ),
        },
    );
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let result = provider
        .invoke(
            InvocationBuilder::new("jira", "attachment.download")
                .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap();
    let stream = result.stream.unwrap();
    let crate::ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected live stream");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"hell")
    );
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
    assert!(error.message.contains("metadata"));
}

#[tokio::test]
async fn verify_mismatch_returns_allow_decision_with_conflict_reason() {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "verify")
                .inputs(json!({"issue": "PROJ-1", "expectCommentId": "10042"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.decision(), crate::Decision::Allow);
    assert_eq!(error.reason_code(), ReasonCode::VerificationMismatch);
    assert_eq!(error.audit.as_ref().unwrap()["status"], "mismatch");
    assert_eq!(
        error.audit.as_ref().unwrap()["mismatch"],
        json!({"type": "comment", "id": "10042"})
    );
    assert_eq!(error.object_ids.as_ref().unwrap()["commentId"], "10042");
    let result = error.result.unwrap();
    assert_eq!(result["verification"]["status"], "mismatch");
    assert_eq!(result["verification"]["mismatch"]["type"], "comment");
    assert_eq!(result["verification"]["mismatch"]["id"], "10042");

    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.comment_error.lock().unwrap() = Some(JiraBackendError::Forbidden);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "verify")
                .inputs(json!({"issue": "PROJ-1", "expectCommentId": "10042"}))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["PROJ".to_string()],
                )]))
                .credential(test_credential())
                .lookup_credential(test_lookup_credential())
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.decision(), crate::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::UpstreamForbidden);
}

/// Jira declares the vendor-level Atlassian profiles Confluence declares:
/// the classic API token on every site, reaching the site route, and the
/// service-account bearer token only when the site uses the gateway,
/// reaching it. It accepts delegated (OAuth) access on every site; validation
/// requires the gateway for it.
#[test]
fn descriptor_declares_vendor_profiles_whose_kinds_select_the_route() {
    let mut config = jira_config();
    let site = jira_descriptor(&config);
    assert_eq!(
        site.credentials,
        agent_access_provider::CredentialDescriptor::default()
            .profile("atlassian-api-token", "basic_api_token")
            .delegated(JIRA_OAUTH_CONNECTION)
    );
    let cloud_id = "11111111-1111-1111-1111-111111111111";
    config.cloud_id = Some(cloud_id.to_string());
    config.allowed_upstream_hosts.push(format!(
        "https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/**"
    ));
    let descriptor = jira_descriptor(&config);
    let backend = HttpJiraBackend::for_tests(config, ProviderLimits::default());
    for (profile, credential, base) in [
        (
            "atlassian-api-token",
            test_credential(),
            "https://example.atlassian.net/rest/api/3/".to_string(),
        ),
        (
            "atlassian-bearer-token",
            bearer_credential("token"),
            format!("https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/"),
        ),
    ] {
        assert_eq!(
            descriptor.credential_profile_kind(profile),
            Some(credential.kind().as_str()),
            "{profile}"
        );
        assert_eq!(
            backend
                .api_base(&AtlassianCredential::from_static(credential.clone()))
                .unwrap()
                .as_str(),
            base,
            "{profile}"
        );
    }
    for retired in ["jira-cloud-api-token", "jira-bearer-token"] {
        assert_eq!(
            descriptor.credential_profile_kind(retired),
            None,
            "{retired}"
        );
    }
}

#[test]
fn http_backend_routes_basic_and_bearer_credentials_to_matching_api_bases() {
    let cloud_id = "11111111-1111-1111-1111-111111111111";
    let mut config = jira_config();
    config.cloud_id = Some(cloud_id.to_string());
    config.allowed_upstream_hosts.push(format!(
        "https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/**"
    ));
    let backend = HttpJiraBackend::for_tests(config, ProviderLimits::default());

    assert_eq!(
        backend
            .api_base(&AtlassianCredential::from_static(test_credential()))
            .unwrap()
            .as_str(),
        "https://example.atlassian.net/rest/api/3/"
    );
    assert_eq!(
        backend
            .api_base(&AtlassianCredential::from_static(bearer_credential(
                "token"
            )))
            .unwrap()
            .as_str(),
        "https://api.atlassian.com/ex/jira/11111111-1111-1111-1111-111111111111/rest/api/3/"
    );
}

#[test]
fn build_creates_request_and_stream_clients_for_each_api_base() {
    let cloud_id = "11111111-1111-1111-1111-111111111111";
    let mut config = jira_config();
    config.cloud_id = Some(cloud_id.to_string());
    config.allowed_upstream_hosts.push(format!(
        "https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/**"
    ));
    let host = agent_access_provider::test_support::TestHost::default();
    config.build(&host.context()).unwrap();
    let built = host
        .built_clients()
        .into_iter()
        .map(|client| (client.label, client.base.to_string(), client.profile))
        .collect::<Vec<_>>();
    let label = "providers.jira.egress_proxy".to_string();
    let tenant = "https://example.atlassian.net/rest/api/3/".to_string();
    let gateway = format!("https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/");
    assert_eq!(
        built,
        [
            (label.clone(), tenant.clone(), ClientProfile::Request),
            (label.clone(), tenant, ClientProfile::Stream),
            (label.clone(), gateway.clone(), ClientProfile::Request),
            (label, gateway, ClientProfile::Stream),
        ]
    );
}

#[tokio::test]
async fn http_backend_issue_metadata_requests_project_only_without_body() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-1",
            "fields": {
                "project": { "key": "PROJ" }
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let response = backend
        .issue_metadata(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    assert_eq!(response.value.key, "PROJ-1");
    assert_eq!(response.value.project, "PROJ");
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
    let query = requests[0]
        .url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(query.get("fields").map(String::as_str), Some("project"));
}

#[tokio::test]
async fn http_backend_search_requests_bounded_output_fields() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{
                "id": "10001",
                "key": "PROJ-1",
                "fields": {
                    "project": { "key": "PROJ" },
                    "summary": "visible summary",
                    "status": { "name": "Done" },
                    "issuetype": { "name": "Task" }
                }
            }],
            "maxResults": 1,
            "startAt": 0,
            "total": 1,
            "isLast": true
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let response = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        backend.search(
            JiraSearchRequest {
                jql: "summary ~ \"secret\"".to_string(),
                projects: vec![],
                max_results: 1,
                next_page_token: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        ),
    )
    .await
    .unwrap();

    assert_eq!(
        response.value.issues[0].summary.as_deref(),
        Some("visible summary")
    );
    assert_eq!(response.value.issues[0].status.as_deref(), Some("Done"));
    assert_eq!(response.value.issues[0].issue_type.as_deref(), Some("Task"));
    assert!(response.value.issues[0].description.is_none());
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
    let query = requests[0]
        .url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        query.get("fields").map(String::as_str),
        Some(
            "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels"
        )
    );
    assert_eq!(
        query.get("jql").map(String::as_str),
        Some("summary ~ \"secret\"")
    );
    assert_eq!(
        requests[0]
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        requests[0]
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );
}

#[tokio::test]
async fn http_backend_issue_update_sends_controlled_fields_and_optional_notify_query() {
    let api = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    backend
        .update_issue(
            "PROJ-1",
            JiraIssueUpdateRequest {
                summary: Some("Preserve surrounding spaces ".to_string()),
                description: Some(adf_text("description secret")),
                notify_users: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    backend
        .update_issue(
            "PROJ-1",
            JiraIssueUpdateRequest {
                summary: Some("Notify".to_string()),
                description: None,
                notify_users: Some(true),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    backend
        .update_issue(
            "PROJ-1",
            JiraIssueUpdateRequest {
                summary: None,
                description: Some(adf_text("quiet description")),
                notify_users: Some(false),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert_eq!(request.method.as_str(), "PUT");
        assert_eq!(request.url.path(), "/rest/api/3/issue/PROJ-1");
    }
    assert!(
        !requests[0]
            .url
            .query_pairs()
            .any(|(key, _)| key == "notifyUsers")
    );
    assert_eq!(
        requests[1]
            .url
            .query_pairs()
            .find(|(key, _)| key == "notifyUsers")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        requests[2]
            .url
            .query_pairs()
            .find(|(key, _)| key == "notifyUsers")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("false")
    );
    let first_body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        first_body,
        json!({
            "fields": {
                "summary": "Preserve surrounding spaces ",
                "description": adf_text("description secret")
            }
        })
    );
    assert!(first_body.get("update").is_none());
    assert!(first_body.get("historyMetadata").is_none());
    let second_body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(second_body, json!({"fields": {"summary": "Notify"}}));
    let third_body: Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(
        third_body,
        json!({"fields": {"description": adf_text("quiet description")}})
    );
}

#[tokio::test]
async fn http_backend_issue_parent_set_uses_parent_field_and_readback_route() {
    let api = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/3/issue/PROJ-2"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10002",
            "key": "PROJ-2",
            "fields": {
                "project": { "key": "PROJ" },
                "parent": {
                    "id": "10010",
                    "key": "PROJ-100"
                }
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    backend
        .set_issue_parent(
            "PROJ-2",
            JiraIssueParentSetRequest {
                parent_issue: "PROJ-100".to_string(),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    let readback = backend
        .issue_parent(
            "PROJ-2",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    assert_eq!(readback.value.issue.key, "PROJ-2");
    assert_eq!(
        readback.value.parent.as_ref().unwrap().key.as_deref(),
        Some("PROJ-100")
    );
    assert_eq!(
        readback.value.parent.as_ref().unwrap().id.as_deref(),
        Some("10010")
    );

    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method.as_str(), "PUT");
    assert_eq!(requests[0].url.path(), "/rest/api/3/issue/PROJ-2");
    let update_body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        update_body,
        json!({
            "fields": {
                "parent": { "key": "PROJ-100" }
            }
        })
    );
    assert!(update_body.get("update").is_none());
    assert_eq!(requests[1].method.as_str(), "GET");
    assert_eq!(requests[1].url.path(), "/rest/api/3/issue/PROJ-2");
    let query = requests[1]
        .url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        query.get("fields").map(String::as_str),
        Some("project,parent")
    );
}

#[test]
fn issue_parent_readback_parser_accepts_null_missing_id_and_key_shapes() {
    for value in [
        json!({
            "id": "10002",
            "key": "PROJ-2",
            "fields": { "project": { "key": "PROJ" } }
        }),
        json!({
            "id": "10002",
            "key": "PROJ-2",
            "fields": {
                "project": { "key": "PROJ" },
                "parent": null
            }
        }),
    ] {
        let readback = issue_parent_readback_from_value(value).unwrap();
        assert!(readback.parent.is_none());
    }

    let id_only = issue_parent_readback_from_value(json!({
        "id": "10002",
        "key": "PROJ-2",
        "fields": {
            "project": { "key": "PROJ" },
            "parent": { "id": "10010" }
        }
    }))
    .unwrap();
    assert_eq!(id_only.parent.unwrap().id.as_deref(), Some("10010"));

    let key_only = issue_parent_readback_from_value(json!({
        "id": "10002",
        "key": "PROJ-2",
        "fields": {
            "project": { "key": "PROJ" },
            "parent": { "key": "PROJ-100" }
        }
    }))
    .unwrap();
    assert_eq!(key_only.parent.unwrap().key.as_deref(), Some("PROJ-100"));
}

#[tokio::test]
async fn http_backend_issue_dependency_uses_link_type_create_and_readback_routes() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issueLinkType"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issueLinkTypes": [{
                "id": "10000",
                "name": "Blocks",
                "outward": "blocks",
                "inward": "is blocked by"
            }]
        })))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issueLink"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-1",
            "fields": {
                "project": { "key": "PROJ" },
                "issuelinks": [{
                    "id": "20001",
                    "type": {
                        "id": "10000",
                        "name": "Blocks",
                        "outward": "blocks",
                        "inward": "is blocked by"
                    },
                    "outwardIssue": {
                        "id": "10002",
                        "key": "PROJ-2"
                    }
                }]
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let link_types = backend
        .issue_link_types(&AtlassianCredential::from_static(test_credential()))
        .await
        .unwrap();
    assert_eq!(link_types.value, vec![blocks_link_type()]);
    backend
        .create_issue_link(
            JiraIssueLinkCreateRequest {
                link_type: "Blocks".to_string(),
                outward_issue: "PROJ-1".to_string(),
                inward_issue: "PROJ-2".to_string(),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    let readback = backend
        .issue_links(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    assert_eq!(readback.value.issue.key, "PROJ-1");
    assert_eq!(
        readback.value.links[0].outward_issue.as_deref(),
        Some("PROJ-2")
    );

    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method.as_str(), "GET");
    assert_eq!(requests[0].url.path(), "/rest/api/3/issueLinkType");
    assert_eq!(requests[1].method.as_str(), "POST");
    assert_eq!(requests[1].url.path(), "/rest/api/3/issueLink");
    let create_body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        create_body,
        json!({
            "type": { "name": "Blocks" },
            "outwardIssue": { "key": "PROJ-1" },
            "inwardIssue": { "key": "PROJ-2" },
        })
    );
    assert!(create_body.get("comment").is_none());
    assert_eq!(requests[2].method.as_str(), "GET");
    assert_eq!(requests[2].url.path(), "/rest/api/3/issue/PROJ-1");
    let query = requests[2]
        .url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        query.get("fields").map(String::as_str),
        Some("project,issuelinks")
    );
}

#[tokio::test]
async fn http_backend_issue_create_sends_controlled_fields_without_query() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10002",
            "key": "PROJ-2",
            "self": "https://example.atlassian.net/rest/api/3/issue/10002"
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let response = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Preserve surrounding spaces ".to_string(),
                parent_issue: None,
                description: Some(adf_text("description secret")),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    let response_without_description = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Summary only".to_string(),
                parent_issue: None,
                description: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    let response_with_parent = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Child summary".to_string(),
                parent_issue: Some("PROJ-1".to_string()),
                description: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    assert_eq!(
        response.value,
        JiraCreatedIssue {
            id: "10002".to_string(),
            key: "PROJ-2".to_string(),
        }
    );
    assert_eq!(response_without_description.status, 201);
    assert_eq!(response_with_parent.status, 201);
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.url.path(), "/rest/api/3/issue");
        assert!(request.url.query().is_none());
    }
    let first_body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        first_body,
        json!({
            "fields": {
                "project": { "key": "PROJ" },
                "issuetype": { "id": "10001" },
                "summary": "Preserve surrounding spaces ",
                "description": adf_text("description secret")
            }
        })
    );
    assert!(first_body.get("update").is_none());
    assert!(first_body.get("transition").is_none());
    assert!(first_body.get("parent").is_none());
    assert!(first_body.get("properties").is_none());
    assert!(first_body.get("historyMetadata").is_none());
    let second_body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        second_body,
        json!({
            "fields": {
                "project": { "key": "PROJ" },
                "issuetype": { "id": "10001" },
                "summary": "Summary only"
            }
        })
    );
    let third_body: Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(
        third_body,
        json!({
            "fields": {
                "project": { "key": "PROJ" },
                "issuetype": { "id": "10001" },
                "summary": "Child summary",
                "parent": { "key": "PROJ-1" }
            }
        })
    );
    assert!(third_body.get("update").is_none());
    assert!(third_body.get("transition").is_none());
    assert!(third_body.get("properties").is_none());
    assert!(third_body.get("historyMetadata").is_none());
}

#[tokio::test]
async fn http_backend_issue_create_rejects_non_201_success_status() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10002",
            "key": "PROJ-2"
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let error = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Summary".to_string(),
                parent_issue: None,
                description: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JiraBackendError::IssueCreateResponseInvalid {
            id: Some(id),
            key: Some(key),
            status: Some(200),
            ..
        } if id == "10002" && key == "PROJ-2"
    ));
}

#[tokio::test]
async fn http_backend_issue_create_ignores_ambiguous_error_messages() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errorMessages": ["summary contains secret value"]
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let error = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "secret value".to_string(),
                parent_issue: None,
                description: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(error, JiraBackendError::HttpStatus(400));
    let provider_error = jira_backend_error(error);
    assert_eq!(provider_error.reason_code(), ReasonCode::UpstreamFailed);
    assert_eq!(provider_error.message, "Jira returned non-success");
    assert!(!provider_error.message.contains("secret value"));
}

#[tokio::test]
async fn http_backend_issue_create_exposes_structured_body_validation() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errorMessages": ["ambiguous secret is hidden"],
            "errors": {
                "description": "content must be valid ADF",
                "project": "hidden scope detail"
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let backend_error = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Summary".to_string(),
                parent_issue: None,
                description: Some(adf_text("malformed")),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(
        backend_error,
        JiraBackendError::Validation {
            status: 400,
            message: "description: content must be valid ADF".to_string(),
            body_malformed: true,
        }
    );

    let provider_error = jira_backend_error(backend_error);
    assert_eq!(provider_error.reason_code(), ReasonCode::BodyMalformed);
    assert_eq!(
        provider_error.message,
        "Jira rejected the request: description: content must be valid ADF"
    );
    assert_eq!(provider_error.upstream_status, Some(400));
    assert!(!provider_error.message.contains("ambiguous secret"));
    assert!(!provider_error.message.contains("scope detail"));
}

#[tokio::test]
async fn http_backend_lookup_does_not_expose_structured_validation_body() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errors": {
                "description": "lookup scope secret"
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let backend_error = backend
        .issue(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(backend_error, JiraBackendError::HttpStatus(400));
    let provider_error = jira_backend_error(backend_error);
    assert_eq!(provider_error.reason_code(), ReasonCode::UpstreamFailed);
    assert_eq!(provider_error.message, "Jira returned non-success");
    assert!(!provider_error.message.contains("scope secret"));
}

#[tokio::test]
async fn http_backend_mutation_ignores_non_json_validation_body() {
    let api = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(
            ResponseTemplate::new(422)
                .insert_header("Content-Type", "text/plain")
                .set_body_string(r#"{"errors":{"description":"untrusted detail"}}"#),
        )
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let backend_error = backend
        .update_issue(
            "PROJ-1",
            JiraIssueUpdateRequest {
                summary: None,
                description: Some(adf_text("malformed")),
                notify_users: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(backend_error, JiraBackendError::HttpStatus(422));
    let provider_error = jira_backend_error(backend_error);
    assert_eq!(provider_error.reason_code(), ReasonCode::UpstreamFailed);
    assert!(!provider_error.message.contains("untrusted detail"));
}

#[tokio::test]
async fn http_backend_issue_create_invalid_201_carries_partial_created_issue() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10002"
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let error = backend
        .create_issue(
            JiraIssueCreateRequest {
                project: "PROJ".to_string(),
                issue_type_id: "10001".to_string(),
                summary: "Summary".to_string(),
                parent_issue: None,
                description: None,
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JiraBackendError::IssueCreateResponseInvalid {
            id: Some(id),
            key: None,
            status: Some(201),
            ..
        } if id == "10002"
    ));
}

#[tokio::test]
async fn http_backend_issue_update_permission_failure_is_sanitized() {
    let api = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(403).set_body_string(
            r#"{"errorMessages":["cannot suppress notifications for secret summary"]}"#,
        ))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let backend_error = backend
        .update_issue(
            "PROJ-1",
            JiraIssueUpdateRequest {
                summary: Some("secret summary".to_string()),
                description: None,
                notify_users: Some(false),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(backend_error, JiraBackendError::Forbidden);
    let provider_error = jira_backend_error(backend_error);
    assert_eq!(provider_error.reason_code(), ReasonCode::UpstreamForbidden);
    assert_eq!(
        provider_error.message,
        "Jira forbade the selected credential"
    );
    assert!(!provider_error.message.contains("secret summary"));
}

#[tokio::test]
async fn http_backend_attachment_list_requests_project_and_attachment_fields() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-1",
            "fields": {
                "project": { "key": "PROJ" },
                "attachment": [{
                    "id": "10055",
                    "filename": "evidence.txt",
                    "mimeType": "text/plain",
                    "size": 21
                }]
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let response = backend
        .issue_attachment_list(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    assert_eq!(response.value.issue.project, "PROJ");
    assert_eq!(response.value.attachments[0].id, "10055");
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let query = requests[0]
        .url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        query.get("fields").map(String::as_str),
        Some("project,attachment")
    );
}

#[tokio::test]
async fn http_backend_streams_jira_attachment_upload_from_file() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue/PROJ-1/attachments"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(25))
                .set_body_json(json!([{
                    "id": "10055",
                    "filename": "evidence.txt",
                    "mimeType": "text/plain",
                    "size": 21
                }])),
        )
        .mount(&api)
        .await;
    let bytes = b"streamed upload bytes";
    let upload_path =
        std::env::temp_dir().join(format!("agent-access-jira-upload-{}.txt", Uuid::new_v4()));
    std::fs::write(&upload_path, bytes).unwrap();
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default().with_request_timeout_ms(1),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let uploaded = backend
        .add_attachment(
            "PROJ-1",
            JiraAttachmentUpload {
                filename: "evidence.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: bytes.len() as u64,
                bytes: Vec::new(),
                temp_file: Some(Arc::new(agent_access_provider::host::spooled_body_file(
                    upload_path.clone(),
                    bytes.len() as u64,
                    sha256_hex(bytes),
                ))),
                sha256: sha256_hex(bytes),
            },
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.value.id, "10055");
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request
            .headers
            .get("x-atlassian-token")
            .and_then(|value| value.to_str().ok()),
        Some("no-check")
    );
    assert!(
        request
            .body
            .windows(bytes.len())
            .any(|window| window == bytes)
    );
    assert!(!upload_path.exists());
}

#[test]
fn redirect_allowlist_matches_only_explicit_origins_and_paths() {
    let patterns = vec![
        "https://example.atlassian.net/rest/api/3/**".to_string(),
        "https://api.media.atlassian.com/file/*".to_string(),
        "https://api.media.atlassian.com/file/**/binary".to_string(),
    ];

    assert!(crate::url_allowed_by_patterns(
        &Url::parse("https://example.atlassian.net/rest/api/3/attachment/content/10055").unwrap(),
        &patterns
    ));
    assert!(crate::url_allowed_by_patterns(
        &Url::parse("https://api.media.atlassian.com/file/blob123").unwrap(),
        &patterns
    ));
    assert!(!crate::url_allowed_by_patterns(
        &Url::parse("https://api.media.atlassian.com/file/nested/blob123").unwrap(),
        &patterns
    ));
    assert!(crate::url_allowed_by_patterns(
        &Url::parse("https://api.media.atlassian.com/file/nested/blob123/binary").unwrap(),
        &patterns
    ));
    assert!(!crate::url_allowed_by_patterns(
        &Url::parse("https://api.media.atlassian.com/file/nested/blob123/metadata").unwrap(),
        &patterns
    ));
    assert!(!crate::url_allowed_by_patterns(
        &Url::parse("https://evil.example/rest/api/3/attachment/content/10055").unwrap(),
        &patterns
    ));
}

#[tokio::test]
async fn credential_verification_current_user_url_must_be_allowlisted() {
    let api = MockServer::start().await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/issue/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let error = backend
        .current_user(&AtlassianCredential::from_static(test_credential()))
        .await
        .unwrap_err();

    assert!(
        matches!(error, JiraBackendError::Protocol(message) if message.contains("not allowlisted"))
    );
    assert!(api.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn attachment_content_redirects_are_allowlisted_and_strip_cross_origin_credentials() {
    let api = MockServer::start().await;
    let media = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(303).insert_header("Location", format!("{}/blob", media.uri())),
        )
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_bytes(b"downloaded".as_slice()),
        )
        .mount(&media)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts =
        vec![format!("{}/**", api.uri()), format!("{}/**", media.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let response = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        backend.attachment_content_response(
            Url::parse(&format!("{}/redirect", api.uri())).unwrap(),
            &AtlassianCredential::from_static(test_credential()),
        ),
    )
    .await
    .unwrap();
    let bytes = jira_response_bytes(response, 1024).await.unwrap();
    assert_eq!(bytes, b"downloaded");
    let api_requests = api.received_requests().await.unwrap();
    assert_eq!(api_requests.len(), 1);
    assert_eq!(
        api_requests[0]
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        api_requests[0]
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );
    let media_requests = media.received_requests().await.unwrap();
    assert_eq!(media_requests.len(), 1);
    assert!(media_requests[0].headers.get("authorization").is_none());
    assert_eq!(
        media_requests[0]
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        media_requests[0]
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );

    let denied_api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(303).insert_header("Location", "https://evil.example/blob"),
        )
        .mount(&denied_api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/**", denied_api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", denied_api.uri())).unwrap(),
    );
    let error = backend
        .attachment_content_response(
            Url::parse(&format!("{}/redirect", denied_api.uri())).unwrap(),
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, JiraBackendError::Protocol(message) if message.contains("redirect is invalid"))
    );
}

#[tokio::test]
async fn attachment_content_redirect_limit_is_enforced() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/loop"))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let error = backend
        .attachment_content_response(
            Url::parse(&format!("{}/loop", api.uri())).unwrap(),
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, JiraBackendError::Protocol(message) if message.contains("redirect is invalid"))
    );
}

#[test]
fn http_backend_records_service_proxy_selection_for_test_clients() {
    let mut config = jira_config();
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: "http://jira-proxy.example:8080".to_string(),
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse("https://example.atlassian.net/rest/api/3/").unwrap(),
    );

    let audit = backend.egress_proxy_for_test(&AtlassianCredential::from_static(test_credential()));
    assert_eq!(audit["mode"], json!("service"));
    assert_eq!(audit["proxy"], json!("http://jira-proxy.example:8080"));
}

#[tokio::test]
async fn http_backend_issue_rejects_non_object_description_without_leaking_content() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-1",
            "fields": {
                "project": { "key": "PROJ" },
                "summary": "visible summary",
                "status": { "name": "Done" },
                "issuetype": { "name": "Task" },
                "description": "plain string secret"
            }
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );

    let error = backend
        .issue(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap_err();
    let provider_error = jira_backend_error(error);

    assert_eq!(
        provider_error.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert!(!provider_error.message.contains("plain string secret"));
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
}

#[tokio::test]
async fn http_backend_routes_issue_requests_through_selected_proxy() {
    let upstream = MockServer::start().await;
    let (proxy_url, request_rx) = start_recording_proxy(
        "application/json",
        r#"{"id":"10001","key":"PROJ-1","fields":{"project":{"key":"PROJ"},"summary":"via proxy","status":{"name":"Done"},"issuetype":{"name":"Task"}}}"#,
    )
    .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", upstream.uri())];
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: proxy_url,
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", upstream.uri())).unwrap(),
    );

    let response = backend
        .issue(
            "PROJ-1",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();

    assert_eq!(response.value.summary.as_deref(), Some("via proxy"));
    let request = request_rx.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET {}/rest/api/3/issue/PROJ-1?fields=project%2Csummary%2Cstatus%2Cissuetype%2Ccreated%2Cupdated%2Ccreator%2Creporter%2Cassignee%2Cpriority%2Clabels%2Cdescription HTTP/1.1",
        upstream.uri()
    )));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: basic ")
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_backend_routes_attachment_streams_through_selected_proxy() {
    let upstream = MockServer::start().await;
    let (proxy_url, request_rx) =
        start_recording_proxy("text/plain", "proxied attachment bytes").await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", upstream.uri())];
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: proxy_url,
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", upstream.uri())).unwrap(),
    );

    let response = backend
        .attachment_content(
            "10055",
            &AtlassianCredential::from_static(test_credential()),
        )
        .await
        .unwrap();
    let bytes = stream_bytes(response.value.stream).await;

    assert_eq!(bytes, b"proxied attachment bytes");
    let request = request_rx.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET {}/rest/api/3/attachment/content/10055?redirect=false HTTP/1.1",
        upstream.uri()
    )));
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

async fn start_recording_proxy(
    content_type: &'static str,
    body: &'static str,
) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0; 8192];
        let read = socket.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    (proxy_url, request_rx)
}

async fn stream_bytes(stream: ProviderResultStream) -> Vec<u8> {
    match stream.source {
        crate::ProviderResultStreamSource::Memory(bytes) => bytes,
        crate::ProviderResultStreamSource::Stream(stream) => {
            let mut stream = stream.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
    }
}

fn jira_config() -> JiraProviderConfig {
    jira_config_with_search_cap(50)
}

fn visible_issue() -> JiraIssue {
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
        description: Some(adf_text("visible description body")),
    }
}

/// One in-scope `PROJ` issue and Jira's `upstream` token for the next page.
fn page_with_upstream_token(upstream: &str) -> JiraSearchPage {
    JiraSearchPage {
        issues: vec![visible_issue()],
        max_results: 50,
        start_at: 0,
        total: None,
        next_page_token: Some(upstream.to_string()),
        is_last: Some(false),
    }
}

fn blocks_link_type() -> JiraIssueLinkType {
    JiraIssueLinkType {
        name: "Blocks".to_string(),
        outward: "blocks".to_string(),
        inward: "is blocked by".to_string(),
    }
}

fn issue_metadata(id: &str, key: &str, project: &str) -> JiraIssueMetadata {
    JiraIssueMetadata {
        id: id.to_string(),
        key: key.to_string(),
        project: project.to_string(),
    }
}

fn dependency_readback(blocking: &JiraIssueMetadata, blocked_key: &str) -> JiraIssueLinks {
    JiraIssueLinks {
        issue: blocking.clone(),
        links: vec![JiraIssueLink {
            link_type: "Blocks".to_string(),
            outward_issue: Some(blocked_key.to_string()),
            inward_issue: None,
        }],
    }
}

fn parent_readback(
    issue: &JiraIssueMetadata,
    parent: Option<&JiraIssueMetadata>,
) -> JiraIssueParentReadback {
    JiraIssueParentReadback {
        issue: issue.clone(),
        parent: parent.map(|parent| JiraIssueParent {
            id: Some(parent.id.clone()),
            key: Some(parent.key.clone()),
        }),
    }
}

fn test_comment(id: &str) -> JiraComment {
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

fn test_comment_with_body(id: &str, text: &str) -> JiraComment {
    let mut comment = test_comment(id);
    comment.body = Some(adf_text(text));
    comment
}

fn adf_text(text: &str) -> Value {
    json!({
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

fn attributed_adf_text(text: &str, broker_request_id: &str) -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": text
                }]
            },
            { "type": "rule" },
            {
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Updated via Agent Access Broker. Request ID: {broker_request_id}"
                    )
                }]
            }
        ]
    })
}

fn added_attributed_adf_text(text: &str, broker_request_id: &str) -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": text
                }]
            },
            { "type": "rule" },
            {
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Added via Agent Access Broker. Request ID: {broker_request_id}"
                    )
                }]
            }
        ]
    })
}

fn adf_table() -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "table",
            "content": [{
                "type": "tableRow",
                "content": [{
                    "type": "tableCell",
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": "cell"
                        }]
                    }]
                }]
            }]
        }]
    })
}

fn test_credential() -> ExecutionCredential {
    basic_credential("service@example.com", "token")
}

fn test_per_user_credential() -> ExecutionCredential {
    basic_credential("per-user@example.com", "per-user-token")
}

fn test_lookup_credential() -> ExecutionCredential {
    basic_credential("lookup@example.com", "lookup-token")
}

fn search_preflight<const N: usize>(projects: [&str; N]) -> SearchAuthorization {
    SearchAuthorization::new(
        "project".to_string(),
        SearchAuthorizationScope::from_exact_values(
            projects.into_iter().map(ToString::to_string).collect(),
        ),
    )
}

fn per_user_invocation(
    action: &str,
    inputs: Value,
    body_parts: Vec<BrokerBodyPart>,
) -> ProviderInvocation {
    let builder = InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .identity(crate::InvocationIdentity::new(
            "agent-one".to_string(),
            true,
        ))
        .body_parts(body_parts)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential_mode(CredentialMode::PerUser)
        .credential(test_per_user_credential())
        .lookup_credential(test_lookup_credential());
    if action == "search" {
        builder.search(search_preflight(["PROJ"]))
    } else {
        builder
    }
    .build()
}

fn issue_create_invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", "issue.create")
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(test_credential())
        .build()
}

fn issue_child_create_invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", "issue.child.create")
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .build()
}

fn seed_child_create_success(backend: &mut StubJiraBackend, child_description: Option<Value>) {
    let parent = issue_metadata("10001", "PROJ-1", "PROJ");
    backend.issues.insert("PROJ-1".to_string(), visible_issue());
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10002".to_string(),
        key: "PROJ-2".to_string(),
    });
    let mut child = visible_issue();
    child.id = "10002".to_string();
    child.key = "PROJ-2".to_string();
    child.project = "PROJ".to_string();
    child.description = child_description;
    backend
        .issue_readbacks
        .lock()
        .unwrap()
        .insert("PROJ-2".to_string(), child);
    backend.issue_parent_readbacks.lock().unwrap().insert(
        "PROJ-2".to_string(),
        parent_readback(&issue_metadata("10002", "PROJ-2", "PROJ"), Some(&parent)),
    );
}

/// Asserts the operations the stub backend served and the test credential,
/// named by its token, each one received.
fn assert_credential_observations(backend: &StubJiraBackend, expected: &[(&str, &str)]) {
    let actual = backend.credential_observations.lock().unwrap().clone();
    let expected = expected
        .iter()
        .map(|(operation, token)| CredentialObservation {
            operation: operation.to_string(),
            credential: test_credential_with_token(token),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

/// The test credential whose token is `token`.
fn test_credential_with_token(token: &str) -> ExecutionCredential {
    match token {
        "token" => test_credential(),
        "per-user-token" => test_per_user_credential(),
        "lookup-token" => test_lookup_credential(),
        other => panic!("no test credential has the token {other}"),
    }
}

#[tokio::test]
async fn credential_verification_uses_current_user_probe() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

    let verification = provider
        .verify_execution_credential(
            &test_per_user_credential(),
            &crate::CorrelationContext::for_tests(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(verification.upstream_status, 200);
    assert_eq!(verification.upstream_duration_ms, 2);
    assert_eq!(verification.audit["provider"], "jira");
    let observations = backend.credential_observations.lock().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].operation, "current_user");
    assert_eq!(observations[0].credential, test_per_user_credential());
}

#[test]
fn normalized_jira_content_contract_is_canonical_and_bounded() {
    let config = jira_config();
    let markdown = parse_issue_create_inputs(
        &json!({
            "project": "PROJ",
            "issueTypeId": "10001",
            "summary": "summary",
            "contentFormat": "markdown",
            "content": "## Heading\n\n**bold**"
        }),
        &config,
    )
    .unwrap();
    let description = markdown.description.unwrap();
    assert_eq!(description["type"], "doc");
    assert_eq!(description["content"][0]["type"], "heading");
    assert_eq!(markdown.content_audit.unwrap().requested_format, "markdown");

    let plain = prepare_jira_content("test", "plain_text", &json!("*literal*"), 1024)
        .unwrap()
        .0;
    assert_eq!(plain["content"][0]["content"][0]["text"], "*literal*");
    assert!(plain["content"][0]["content"][0].get("marks").is_none());

    let table = prepare_jira_content(
        "test",
        "markdown",
        &json!("| Name | State |\n|---|---|\n| build | green |"),
        4096,
    )
    .unwrap()
    .0;
    validate_adf_body(&table).unwrap();
    assert_eq!(table["content"][0]["type"], "table");
    assert_eq!(table["content"][0]["content"][0]["type"], "tableRow");
    assert_eq!(
        table["content"][0]["content"][0]["content"][0]["type"],
        "tableHeader"
    );

    for invalid in [
        json!({"project":"PROJ","issueTypeId":"10001","summary":"x","description":adf_text("old")}),
        json!({"project":"PROJ","issueTypeId":"10001","summary":"x","content":"missing format"}),
        json!({"project":"PROJ","issueTypeId":"10001","summary":"x","contentFormat":"markdown"}),
        json!({"project":"PROJ","issueTypeId":"10001","summary":"x","contentFormat":"adf","content":"wrong type"}),
        json!({"project":"PROJ","issueTypeId":"10001","summary":"x","contentFormat":"markdown","content":adf_text("wrong type")}),
    ] {
        assert!(
            parse_issue_create_inputs(&invalid, &config).is_err(),
            "{invalid}"
        );
    }

    let mut tiny = config;
    tiny.content.max_body_bytes = 3;
    let error = parse_issue_create_inputs(
        &json!({
            "project":"PROJ",
            "issueTypeId":"10001",
            "summary":"x",
            "contentFormat":"plain_text",
            "content":"four"
        }),
        &tiny,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
}

#[tokio::test]
async fn create_scope_resolution_reads_only_scope_fields() {
    let mut backend = StubJiraBackend::default();
    let mut parent = visible_issue();
    parent.key = "OPS-1".to_string();
    parent.project = "OPS".to_string();
    backend.issues.insert("OPS-1".to_string(), parent);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), Arc::new(backend));
    let oversized_markdown = "> ".repeat(512);
    let create = provider
        .local_scopes(
            "issue.create",
            &json!({
                "project": "PROJ",
                "issueTypeId": "10001",
                "summary": "summary",
                "contentFormat": "markdown",
                "content": oversized_markdown,
            }),
        )
        .unwrap();
    assert_eq!(create["project"], vec!["PROJ"]);

    let child = provider
        .lookup_scopes(
            "issue.child.create",
            &json!({
                "project": "PROJ",
                "parentIssue": "OPS-1",
                "contentFormat": "markdown",
                "content": "> ".repeat(512),
            }),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap();
    assert_eq!(child["project"], vec!["OPS", "PROJ"]);
    assert!(!child.contains_key("issue"));
}

#[tokio::test]
async fn issue_create_authorizes_scope_before_converting_content() {
    let backend = Arc::new(StubJiraBackend::default());
    let mut config = jira_config();
    config.content.max_body_bytes = 8;
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());

    let error = provider
        .invoke(
            InvocationBuilder::new("jira", "issue.create")
                .inputs(json!({
                    "project": "PROJ",
                    "issueTypeId": "10001",
                    "summary": "summary",
                    "contentFormat": "markdown",
                    "content": "content that exceeds the configured cap",
                }))
                .resources(BTreeMap::from([(
                    "project".to_string(),
                    vec!["OTHER".to_string()],
                )]))
                .credential(test_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.created_issues.lock().unwrap().is_empty());
}

#[test]
fn jira_write_capabilities_advertise_typed_content_and_omit_disabled_comments() {
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default(),
        Arc::new(StubJiraBackend::default()),
    );
    let capabilities = jira_descriptor(&provider.config);
    for action_name in [
        "issue.create",
        "issue.child.create",
        "issue.update",
        "comment.add",
        "comment.reply",
        "comment.update",
    ] {
        let action = capabilities
            .actions
            .iter()
            .find(|action| action.action == action_name)
            .unwrap();
        assert_eq!(
            action.input_schema["properties"]["contentFormat"]["enum"],
            json!(["adf", "markdown", "plain_text"])
        );
        assert!(action.input_schema["properties"].get("body").is_none());
        assert!(
            action.input_schema["properties"]
                .get("description")
                .is_none()
        );
    }

    let mut config = jira_config();
    config.content.comment_formats.clear();
    let disabled_provider = JiraProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(StubJiraBackend::default()),
    );
    let disabled = jira_descriptor(&disabled_provider.config);
    assert!(disabled.actions.iter().all(|action| !matches!(
        action.action.as_str(),
        "comment.add" | "comment.reply" | "comment.update"
    )));
    assert!(
        disabled
            .actions
            .iter()
            .any(|action| action.action == "issue.create")
    );
    let error = disabled_provider
        .validate_configured_comment_body_format("jira.comment.add")
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyFormatUnsupported);
}

#[test]
fn jira_descriptor_declares_adf_attribution_for_content_writes() {
    let descriptor = jira_descriptor(&jira_config());
    let attributed = descriptor
        .actions
        .iter()
        .filter_map(|action| {
            action
                .attribution
                .map(|capability| (action.action.as_str(), capability))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        attributed,
        BTreeMap::from([
            (
                "comment.add",
                AttributionCapability::required(
                    AttributionVerb::Add,
                    "body",
                    AttributionRepresentation::Adf,
                ),
            ),
            (
                "comment.reply",
                AttributionCapability::required(
                    AttributionVerb::Add,
                    "body",
                    AttributionRepresentation::Adf,
                ),
            ),
            (
                "comment.update",
                AttributionCapability::required(
                    AttributionVerb::Update,
                    "body",
                    AttributionRepresentation::Adf,
                ),
            ),
            (
                "issue.child.create",
                AttributionCapability::optional(
                    AttributionVerb::Add,
                    "description",
                    AttributionRepresentation::Adf,
                ),
            ),
            (
                "issue.create",
                AttributionCapability::optional(
                    AttributionVerb::Add,
                    "description",
                    AttributionRepresentation::Adf,
                ),
            ),
            (
                "issue.update",
                AttributionCapability::optional(
                    AttributionVerb::Update,
                    "description",
                    AttributionRepresentation::Adf,
                ),
            ),
        ])
    );
}

#[test]
fn jira_descriptor_declares_lookup_and_io_per_action() {
    let descriptor = jira_descriptor(&jira_config());
    assert_eq!(descriptor.validate(), Ok(()));
    let action = |name: &str| descriptor.action(name).unwrap();

    let upload = action("attachment.add");
    assert_eq!(upload.lookup, LookupRequirement::ScopeResolution);
    let crate::ActionIo::MultipartUpload { plan } = &upload.io else {
        panic!("attachment.add must be a multipart upload");
    };
    assert_eq!(plan.locator_inputs, vec!["issue".to_string()]);
    assert_eq!(plan.max_files, None);

    let download = action("attachment.download");
    assert_eq!(download.lookup, LookupRequirement::ScopeResolution);
    assert!(matches!(download.io, crate::ActionIo::RawDownload { .. }));

    let search = action("search");
    assert_eq!(search.lookup, LookupRequirement::None);
    assert!(search.native_search.is_some());
    assert_eq!(search.resource_scope.as_deref(), Some("project"));
    assert_eq!(search.io, crate::ActionIo::Json);

    let create = action("issue.create");
    assert_eq!(create.lookup, LookupRequirement::None);
    assert!(!create.native_search.is_some());
    assert_eq!(create.io, crate::ActionIo::Json);
}

#[test]
fn native_adf_validation_has_a_depth_bound() {
    let mut node = json!({"type":"text","text":"leaf"});
    for _ in 0..130 {
        node = json!({"type":"paragraph","content":[node]});
    }
    let body = json!({"type":"doc","version":1,"content":[node]});
    let error = validate_adf_body(&body).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);
}

fn jira_config_with_search_cap(max_results: u32) -> JiraProviderConfig {
    JiraProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
        attachments: crate::AttachmentLimitsConfig {
            media_types: vec!["text/plain".to_string()],
            ..crate::AttachmentLimitsConfig::default()
        },
        content: crate::JiraContentConfig {
            comment_formats: vec!["adf".to_string()],
            ..crate::JiraContentConfig::default()
        },
        search: SearchLimitsConfig { max_results },
        comments: crate::JiraCommentsConfig::default(),
        issue_links: crate::JiraIssueLinksConfig::default(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_upload_response_bodies_are_traced_as_timeouts() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        // Successful headers, then a body that never arrives.
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n",
            )
            .await
            .unwrap();
        let mut rest = [0; 4096];
        loop {
            if socket.read(&mut rest).await.unwrap_or(0) == 0 {
                std::future::pending::<()>().await;
            }
        }
    });
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{origin}/rest/api/3/**")];
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default().with_streaming_idle_timeout_ms(200),
        Url::parse(&format!("{origin}/rest/api/3/")).unwrap(),
    );
    let capture = agent_access_provider::test_support::install_trace_capture().start();
    let error = capture
        .run(agent_access_provider::host::with_provider_context(
            CorrelationContext::for_tests(),
            "jira".to_string(),
            "attachment.add".to_string(),
            agent_access_provider::test_support::in_invocation_hook(
                "jira",
                "attachment.add",
                backend.add_attachment(
                    "PROJ-1",
                    JiraAttachmentUpload {
                        filename: "evidence.txt".to_string(),
                        content_type: "text/plain".to_string(),
                        size: 8,
                        sha256: sha256_hex(b"evidence"),
                        bytes: b"evidence".to_vec(),
                        temp_file: None,
                    },
                    &AtlassianCredential::from_static(test_credential()),
                ),
            ),
        ))
        .await
        .unwrap_err();
    // Jira accepted the upload with a 200 before its body stalled.
    assert_eq!(
        error,
        JiraBackendError::AcceptedUnreadable(Box::new(JiraBackendError::Timeout))
    );
    let events = capture.take_upstream_requests();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["upstreamOperation"], "attachment.add");
    assert_eq!(events[0]["http.statusCode"], 200);
    assert_eq!(events[0]["reasonCode"], "upstream_timeout");
    server.abort();
}

#[test]
fn search_clause_projection_restores_exact_values_and_rejects_namespaces() {
    let scope =
        SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".into(), "HIDDEN".into()])
            .union(&SearchAuthorizationScope::from_exact_values(vec![
                "PRIVATE".into(),
            ]));
    let authorization = SearchAuthorization::new("project", scope);
    assert_eq!(
        jql::authorized_search_scope(&authorization).unwrap(),
        EffectiveSearchScope::AllExcept(std::collections::BTreeSet::from(["HIDDEN".to_string()]))
    );
    for (included, excluded) in [
        (
            vec![agent_access_provider::ResourceSelector::Namespace {
                value: "engineering".into(),
            }],
            vec![],
        ),
        (
            vec![agent_access_provider::ResourceSelector::All],
            vec![agent_access_provider::ResourceSelector::Namespace {
                value: "engineering/private".into(),
            }],
        ),
    ] {
        let authority = SearchAuthorization::new(
            "project",
            SearchAuthorizationScope::from_selectors(included, excluded),
        );
        assert_eq!(
            jql::authorized_search_scope(&authority)
                .unwrap_err()
                .reason_code(),
            ReasonCode::BrokerProviderContractFailed
        );
    }
}
