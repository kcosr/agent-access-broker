//! A Jira project whose key changed from `OLD` to `NEW`. Jira keeps `OLD-123`
//! as an alias for the issue now keyed `NEW-123` in project `NEW`: REST
//! resolves it without a redirect and returns the current key, and JQL still
//! resolves `OLD`. The Broker authorizes such issues by `NEW`, never by the
//! alias prefix, and acts on the current key once Jira confirms it.

use super::*;

const OLD_KEY: &str = "OLD-123";
const CURRENT_KEY: &str = "NEW-123";
const SECRET_SUMMARY: &str = "renamed issue summary";

/// Every issue reference a caller may still hold after the rename: the alias
/// key, and browser links whose project segment and key mix old and new keys.
fn old_locators() -> [Value; 5] {
    [
        json!({"issue": OLD_KEY}),
        json!({"url": "https://example.atlassian.net/browse/OLD-123"}),
        json!({"url": "https://example.atlassian.net/jira/software/c/projects/OLD/issues/OLD-123"}),
        json!({"url": "https://example.atlassian.net/jira/software/c/projects/OLD/issues/NEW-123"}),
        json!({"url": "https://example.atlassian.net/jira/software/c/projects/NEW/issues/OLD-123"}),
    ]
}

fn with_locator(locator: &Value, extra: Value) -> Value {
    let mut inputs = locator.clone();
    for (field, value) in extra.as_object().unwrap() {
        inputs[field] = value.clone();
    }
    inputs
}

fn renamed_issue() -> JiraIssue {
    let mut issue = visible_issue();
    issue.id = "10123".to_string();
    issue.key = CURRENT_KEY.to_string();
    issue.project = "NEW".to_string();
    issue.summary = Some(SECRET_SUMMARY.to_string());
    issue.description = Some(adf_text("renamed issue description"));
    issue
}

fn renamed_metadata() -> JiraIssueMetadata {
    issue_metadata("10123", CURRENT_KEY, "NEW")
}

fn renamed_attachment() -> JiraAttachment {
    JiraAttachment {
        id: "10300".to_string(),
        filename: "notes.txt".to_string(),
        size: 5,
        content_type: "text/plain".to_string(),
    }
}

/// A Jira site after the `OLD` to `NEW` key change. Like Jira, it resolves
/// both keys to the current issue; it records the key every call received.
#[derive(Default)]
struct RenamedJira {
    calls: Mutex<Vec<(&'static str, String)>>,
    search_page: Mutex<Option<JiraSearchPage>>,
}

impl RenamedJira {
    fn resolve(&self, operation: &'static str, key: &str) -> Result<JiraIssue, JiraBackendError> {
        self.calls
            .lock()
            .unwrap()
            .push((operation, key.to_string()));
        match key {
            OLD_KEY | CURRENT_KEY => Ok(renamed_issue()),
            _ => Err(JiraBackendError::NotFound),
        }
    }

    fn calls(&self) -> Vec<(&'static str, String)> {
        self.calls.lock().unwrap().clone()
    }

    /// Execution calls after the confirming metadata lookup.
    fn execution_keys(&self) -> Vec<(&'static str, String)> {
        self.calls()
            .into_iter()
            .filter(|(operation, _)| *operation != "issue_metadata")
            .collect()
    }
}

fn ok<T>(value: T) -> Result<JiraBackendResponse<T>, JiraBackendError> {
    Ok(JiraBackendResponse {
        value,
        status: 200,
        duration_ms: 1,
    })
}

#[async_trait]
impl JiraBackend for RenamedJira {
    async fn issue_metadata(
        &self,
        issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, JiraBackendError> {
        let issue = self.resolve("issue_metadata", issue_key)?;
        ok(issue_metadata(&issue.id, &issue.key, &issue.project))
    }

    async fn issue(
        &self,
        issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError> {
        ok(self.resolve("issue", issue_key)?)
    }

    async fn issue_view(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
        _include_issue_references: bool,
    ) -> Result<JiraBackendResponse<JiraIssueView>, JiraBackendError> {
        let response = self.issue(issue_key, credential).await?;
        ok(JiraIssueView {
            issue: response.value,
            context: JiraIssueViewContext {
                parent: Some(JiraIssueViewReference {
                    key: "OTHER-42".into(),
                    summary: Some(SECRET_SUMMARY.into()),
                    issue_type: None,
                }),
                ..Default::default()
            },
            custom_fields: Vec::new(),
            issue_links: None,
        })
    }

    async fn search(
        &self,
        request: JiraSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError> {
        self.calls.lock().unwrap().push(("search", request.jql));
        ok(self.search_page.lock().unwrap().clone().unwrap())
    }

    async fn comments(
        &self,
        issue_key: &str,
        request: JiraCommentListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPage>, JiraBackendError> {
        self.resolve("comments", issue_key)?;
        ok(JiraCommentPage {
            comments: vec![JiraCommentSummary {
                id: "10200".to_string(),
                parent_id: None,
                author: None,
                created: None,
                updated: None,
                visibility: None,
            }],
            max_results: request.max_results,
            start_at: request.start_at,
            total: Some(1),
        })
    }

    async fn comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.resolve("comment", issue_key)?;
        ok(test_comment(comment_id))
    }

    async fn add_comment(
        &self,
        issue_key: &str,
        _request: JiraCommentAddRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        self.resolve("add_comment", issue_key)?;
        ok(test_comment("10201"))
    }

    async fn add_attachment(
        &self,
        issue_key: &str,
        _attachment: JiraAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError> {
        self.resolve("add_attachment", issue_key)?;
        ok(renamed_attachment())
    }

    async fn issue_attachment_metadata(
        &self,
        issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError> {
        self.resolve("issue_attachment_metadata", issue_key)?;
        ok(vec![renamed_attachment()])
    }

    async fn issue_attachment_list(
        &self,
        issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError> {
        self.resolve("issue_attachment_list", issue_key)?;
        ok(JiraIssueAttachmentList {
            issue: renamed_metadata(),
            attachments: vec![renamed_attachment()],
        })
    }

    async fn attachment_content(
        &self,
        attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachmentContent>, JiraBackendError> {
        self.calls
            .lock()
            .unwrap()
            .push(("attachment_content", attachment_id.to_string()));
        ok(JiraAttachmentContent::from_bytes(
            "notes.txt",
            "text/plain",
            b"notes".to_vec(),
        ))
    }
}

fn renamed_provider() -> (JiraProvider, Arc<RenamedJira>) {
    let backend = Arc::new(RenamedJira::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    (provider, backend)
}

fn invocation(action: &str, inputs: Value, granted: &str) -> ProviderInvocation {
    InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec![granted.to_string()],
        )]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .build()
}

#[test]
fn modern_issue_urls_name_the_issue_by_key_whatever_their_project_segment() {
    let config = jira_config();
    for locator in old_locators() {
        let Some(url) = locator["url"].as_str() else {
            continue;
        };
        let parsed = issue_locator_from_url(url, &config).unwrap();
        assert!(url.ends_with(&format!("/{}", parsed.issue_key)), "{url}");
    }
    // The segment must still be a project key.
    for url in [
        "https://example.atlassian.net/jira/software/c/projects/old/issues/OLD-123",
        "https://example.atlassian.net/jira/software/c/projects/OLD-1/issues/OLD-123",
        "https://example.atlassian.net/jira/software/c/projects/%4FLD/issues/OLD-123",
    ] {
        assert_eq!(
            issue_locator_from_url(url, &config)
                .unwrap_err()
                .reason_code(),
            ReasonCode::LocatorInvalid,
            "{url}"
        );
    }
}

/// Scope resolution reports only the issue's current project for every
/// issue-referencing action and every old locator form, so policy never sees
/// the alias prefix. It only performs the metadata lookup.
#[tokio::test]
async fn old_issue_locators_resolve_scope_to_the_current_project() {
    let lookup = AtlassianCredential::from_static(test_lookup_credential());
    for locator in old_locators() {
        let cases = [
            ("issue.view", locator.clone()),
            (
                "issue.update",
                with_locator(&locator, json!({"summary": "Updated summary"})),
            ),
            ("comment.list", locator.clone()),
            (
                "comment.view",
                with_locator(&locator, json!({"commentId": "10200"})),
            ),
            (
                "comment.add",
                with_locator(
                    &locator,
                    json!({"contentFormat": "plain_text", "content": "hello"}),
                ),
            ),
            (
                "comment.delete",
                with_locator(&locator, json!({"commentId": "10200"})),
            ),
            (
                "comment.property.list",
                with_locator(&locator, json!({"commentId": "10200"})),
            ),
            ("attachment.list", locator.clone()),
        ];
        for (action, inputs) in cases {
            let (provider, backend) = renamed_provider();
            let scopes = provider
                .lookup_scopes(action, &inputs, Some(&lookup))
                .await
                .unwrap_or_else(|error| panic!("{action} {inputs}: {error:?}"));
            assert_eq!(
                scopes,
                ResourceScopes::from([("project".to_string(), vec!["NEW".to_string()])]),
                "{action} {inputs}"
            );
            assert_eq!(backend.execution_keys(), vec![], "{action} {inputs}");
        }
    }
    for (action, inputs) in [
        (
            "attachment.download",
            json!({"issue": OLD_KEY, "attachmentId": "10300"}),
        ),
        (
            "verify",
            json!({"issue": OLD_KEY, "expectCommentId": "10200"}),
        ),
        (
            "issue.child.create",
            json!({
                "project": "NEW",
                "issueTypeId": "10001",
                "summary": "Child issue",
                "parentUrl": "https://example.atlassian.net/jira/software/c/projects/OLD/issues/OLD-123"
            }),
        ),
    ] {
        let (provider, _) = renamed_provider();
        let scopes = provider
            .lookup_scopes(action, &inputs, Some(&lookup))
            .await
            .unwrap();
        assert_eq!(scopes["project"], vec!["NEW".to_string()], "{action}");
    }
}

#[tokio::test]
async fn issue_view_with_an_old_locator_returns_the_current_issue_when_new_is_granted() {
    for locator in old_locators() {
        let (provider, backend) = renamed_provider();
        let result = provider
            .invoke(invocation("issue.view", locator.clone(), "NEW"))
            .await
            .unwrap_or_else(|error| panic!("{locator}: {error:?}"));
        assert_eq!(result.result["key"], CURRENT_KEY, "{locator}");
        assert_eq!(result.result["project"], "NEW");
        assert_eq!(
            result.result["webUrl"],
            "https://example.atlassian.net/browse/NEW-123"
        );
        assert_eq!(result.result["summary"], SECRET_SUMMARY);
        // The confirming lookup takes the caller's locator; the read uses the
        // current key Jira returned.
        let lookups = backend
            .calls()
            .into_iter()
            .filter(|(operation, _)| *operation == "issue_metadata")
            .count();
        assert_eq!(lookups, 1, "{locator}");
        assert_eq!(
            backend.execution_keys(),
            vec![("issue", CURRENT_KEY.to_string())],
            "{locator}"
        );
    }
}

#[tokio::test]
async fn issue_view_with_an_old_locator_is_denied_when_only_the_previous_key_is_granted() {
    for locator in old_locators() {
        let (provider, backend) = renamed_provider();
        let error = provider
            .invoke(invocation("issue.view", locator.clone(), "OLD"))
            .await
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::ScopeUnresolved,
            "{locator}"
        );
        assert!(error.result.is_none());
        assert!(!format!("{error:?}").contains(SECRET_SUMMARY));
        assert_eq!(backend.execution_keys(), vec![], "{locator}");
    }
}

#[tokio::test]
async fn comment_and_attachment_actions_with_an_old_key_act_on_the_current_key() {
    let comment_url =
        json!({"url": "https://example.atlassian.net/jira/software/c/projects/OLD/issues/OLD-123"});
    let cases = [
        ("comment.list", json!({"issue": OLD_KEY}), vec!["comments"]),
        (
            "comment.view",
            with_locator(&comment_url, json!({"commentId": "10200"})),
            vec!["comment"],
        ),
        (
            "comment.add",
            json!({"issue": OLD_KEY, "contentFormat": "plain_text", "content": "hello"}),
            vec!["add_comment"],
        ),
        (
            "attachment.list",
            json!({"url": "https://example.atlassian.net/browse/OLD-123"}),
            vec!["issue_attachment_list"],
        ),
        (
            "attachment.download",
            json!({"issue": OLD_KEY, "attachmentId": "10300"}),
            vec!["issue_attachment_metadata"],
        ),
        (
            "verify",
            json!({"issue": OLD_KEY, "expectCommentId": "10200"}),
            vec!["comment"],
        ),
    ];
    for (action, inputs, operations) in cases {
        let (provider, backend) = renamed_provider();
        let result = provider
            .invoke(invocation(action, inputs.clone(), "NEW"))
            .await
            .unwrap_or_else(|error| panic!("{action} {inputs}: {error:?}"));
        // Every keyed call after the lookup names the current issue.
        let keyed = backend
            .execution_keys()
            .into_iter()
            .filter(|(operation, _)| *operation != "attachment_content")
            .collect::<Vec<_>>();
        assert_eq!(
            keyed,
            operations
                .into_iter()
                .map(|operation| (operation, CURRENT_KEY.to_string()))
                .collect::<Vec<_>>(),
            "{action}"
        );
        if action == "attachment.download" {
            assert!(result.stream.is_some());
        }
        let reported = if matches!(action, "verify" | "attachment.download") {
            &result.result["issueKey"]
        } else {
            &result.result["issue"]["key"]
        };
        assert_eq!(reported, CURRENT_KEY, "{action}");
    }
}

fn renamed_search_page() -> JiraSearchPage {
    JiraSearchPage {
        issues: vec![renamed_issue()],
        max_results: 1,
        start_at: 0,
        total: Some(1),
        next_page_token: None,
        is_last: Some(true),
    }
}

fn search_invocation(inputs: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::new("jira", "search")
        .inputs(inputs)
        .credential(test_credential())
        .search(SearchAuthorization::new("project".to_string(), scope))
        .build()
}

fn all_projects_except<const N: usize>(excluded: [&str; N]) -> SearchAuthorizationScope {
    SearchAuthorizationScope::excluding_exact_values(
        excluded.into_iter().map(ToString::to_string).collect(),
    )
}

fn finite_projects<const N: usize>(values: [&str; N]) -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_exact_values(
        values.into_iter().map(ToString::to_string).collect(),
    )
}

/// Jira resolves a previous project key or issue key inside JQL, so the
/// current issues it returns are checked against the authorized boundary,
/// not against the project names the caller wrote.
#[tokio::test]
async fn search_naming_previous_keys_returns_current_issues_inside_the_boundary() {
    for (inputs, scope, upstream_jql) in [
        (
            json!({"query": {"type": "jql", "value": "project = OLD AND status = Done"}}),
            all_projects_except([]),
            "project = OLD AND status = Done",
        ),
        (
            json!({"query": {"type": "jql", "value": "project IN (OLD, OTHER) AND status = Done"}}),
            all_projects_except(["PRIVATE"]),
            "(project IN (OLD, OTHER) AND status = Done) AND project NOT IN (PRIVATE)",
        ),
        (
            json!({"query": {"type": "jql", "value": "status = Done"}, "projects": ["OLD"]}),
            all_projects_except(["PRIVATE"]),
            "(status = Done) AND project IN (OLD)",
        ),
        (
            json!({"query": {"type": "jql", "value": "project = OLD"}}),
            finite_projects(["NEW"]),
            "(project = OLD) AND project IN (NEW)",
        ),
        (
            json!({"query": {"type": "text", "value": OLD_KEY}}),
            finite_projects(["NEW"]),
            "(key = OLD-123) AND project IN (NEW)",
        ),
    ] {
        let (provider, backend) = renamed_provider();
        *backend.search_page.lock().unwrap() = Some(renamed_search_page());
        let result = provider
            .invoke(search_invocation(inputs.clone(), scope))
            .await
            .unwrap_or_else(|error| panic!("{inputs}: {error:?}"));
        assert_eq!(result.result["issues"][0]["key"], CURRENT_KEY, "{inputs}");
        assert_eq!(result.result["issues"][0]["project"], "NEW");
        assert_eq!(
            backend.calls(),
            vec![("search", upstream_jql.to_string())],
            "{inputs}"
        );
    }
}

#[tokio::test]
async fn search_still_rejects_renamed_projects_outside_the_boundary() {
    for (inputs, scope) in [
        // A grant that still names the previous key does not cover `NEW`.
        (
            json!({"query": {"type": "jql", "value": "project = OLD"}}),
            finite_projects(["OLD"]),
        ),
        // An exclusion of the current key holds however the caller names it.
        (
            json!({"query": {"type": "jql", "value": "project = OLD AND status = Done"}}),
            all_projects_except(["NEW"]),
        ),
        (
            json!({"query": {"type": "jql", "value": "status = Done"}, "projects": ["OLD"]}),
            all_projects_except(["NEW"]),
        ),
    ] {
        let (provider, backend) = renamed_provider();
        *backend.search_page.lock().unwrap() = Some(renamed_search_page());
        let error = provider
            .invoke(search_invocation(inputs.clone(), scope))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved, "{inputs}");
        assert!(error.result.is_none());
        assert!(!format!("{error:?}").contains(SECRET_SUMMARY));
    }
    // Explicit projects outside a finite boundary are refused before Jira.
    let (provider, backend) = renamed_provider();
    let error = provider
        .invoke(search_invocation(
            json!({"query": {"type": "jql", "value": "status = Done"}, "projects": ["OLD"]}),
            finite_projects(["NEW"]),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
    assert_eq!(backend.calls(), vec![]);
}
