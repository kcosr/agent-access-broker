//! An issue that moves to an ungranted project between scope resolution and
//! invocation. Scope resolution confirms `PROJ-1` in `PROJ`, which the host
//! admits; by invocation Jira reports the same issue as `OTHER-9` in `OTHER`.
//! Every issue action confirms the issue again and denies with the concealed
//! `scope_unresolved` before any execution read or write.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct MovingJira {
    lookups: AtomicUsize,
    /// Every execution call, read or write. None may be sent.
    calls: Mutex<Vec<&'static str>>,
}

impl MovingJira {
    fn sent(&self, operation: &'static str) -> JiraBackendError {
        self.calls.lock().unwrap().push(operation);
        JiraBackendError::Protocol(format!("{operation} must not be sent"))
    }
}

#[async_trait]
impl JiraBackend for MovingJira {
    async fn project_list(
        &self,
        _request: JiraProjectListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "unexpected project listing in this fixture".to_string(),
        ))
    }

    async fn issue_metadata(
        &self,
        issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, JiraBackendError> {
        assert_eq!(issue_key, "PROJ-1");
        let value = if self.lookups.fetch_add(1, Ordering::SeqCst) == 0 {
            issue_metadata("10001", "PROJ-1", "PROJ")
        } else {
            issue_metadata("10001", "OTHER-9", "OTHER")
        };
        Ok(JiraBackendResponse {
            value,
            status: 200,
            duration_ms: 1,
        })
    }

    async fn issue(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError> {
        Err(self.sent("issue"))
    }

    async fn issue_view(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
        _include_issue_references: bool,
    ) -> Result<JiraBackendResponse<JiraIssueView>, JiraBackendError> {
        Err(self.sent("issue_view"))
    }

    async fn update_issue(
        &self,
        _issue_key: &str,
        _request: JiraIssueUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(self.sent("update_issue"))
    }

    async fn search(
        &self,
        _request: JiraSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError> {
        Err(self.sent("search"))
    }

    async fn comments(
        &self,
        _issue_key: &str,
        _request: JiraCommentListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPage>, JiraBackendError> {
        Err(self.sent("comments"))
    }

    async fn comment(
        &self,
        _issue_key: &str,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        Err(self.sent("comment"))
    }

    async fn add_comment(
        &self,
        _issue_key: &str,
        _request: JiraCommentAddRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        Err(self.sent("add_comment"))
    }

    async fn update_comment(
        &self,
        _issue_key: &str,
        _comment_id: &str,
        _request: JiraCommentUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        Err(self.sent("update_comment"))
    }

    async fn delete_comment(
        &self,
        _issue_key: &str,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(self.sent("delete_comment"))
    }

    async fn comment_property_keys(
        &self,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPropertyKeys>, JiraBackendError> {
        Err(self.sent("comment_property_keys"))
    }

    async fn comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(self.sent("comment_property"))
    }

    async fn set_comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _value: Value,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(self.sent("set_comment_property"))
    }

    async fn delete_comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(self.sent("delete_comment_property"))
    }

    async fn add_attachment(
        &self,
        _issue_key: &str,
        _attachment: JiraAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError> {
        Err(self.sent("add_attachment"))
    }

    async fn issue_attachment_metadata(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError> {
        Err(self.sent("issue_attachment_metadata"))
    }

    async fn issue_attachment_list(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError> {
        Err(self.sent("issue_attachment_list"))
    }

    async fn attachment_content(
        &self,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachmentContent>, JiraBackendError> {
        Err(self.sent("attachment_content"))
    }
}

const UPLOAD: &[u8] = b"evidence";

/// Every action that names a single issue, with inputs that pass validation.
fn single_issue_actions() -> Vec<(&'static str, Value)> {
    let issue = |extra: Value| {
        let mut inputs = json!({"issue": "PROJ-1"});
        for (field, value) in extra.as_object().unwrap() {
            inputs[field] = value.clone();
        }
        inputs
    };
    let comment = json!({"commentId": "10200"});
    let content = json!({"contentFormat": "plain_text", "content": "hello"});
    vec![
        ("issue.view", issue(json!({}))),
        ("issue.view", issue(json!({"includeComments": true}))),
        ("issue.update", issue(json!({"summary": "Updated summary"}))),
        ("comment.list", issue(json!({}))),
        ("comment.list", issue(json!({"includeBodies": true}))),
        ("comment.view", issue(comment.clone())),
        ("comment.add", issue(content.clone())),
        (
            "comment.reply",
            issue(
                json!({"parentCommentId": "10200", "contentFormat": "plain_text", "content": "hello"}),
            ),
        ),
        (
            "comment.update",
            issue(json!({"commentId": "10200", "contentFormat": "plain_text", "content": "hello"})),
        ),
        ("comment.delete", issue(comment.clone())),
        ("comment.property.list", issue(comment.clone())),
        (
            "comment.property.get",
            issue(json!({"commentId": "10200", "propertyKey": "agent-access.review"})),
        ),
        (
            "comment.property.set",
            issue(json!({
                "commentId": "10200",
                "propertyKey": "agent-access.review",
                "value": {"state": "done"}
            })),
        ),
        (
            "comment.property.delete",
            issue(json!({"commentId": "10200", "propertyKey": "agent-access.review"})),
        ),
        (
            "attachment.add",
            issue(json!({"attachments": [{
                "field": "file0",
                "filename": "evidence.txt",
                "contentType": "text/plain",
                "size": UPLOAD.len(),
                "sha256": sha256_hex(UPLOAD)
            }]})),
        ),
        (
            "attachment.download",
            issue(json!({"attachmentId": "10300"})),
        ),
        ("attachment.list", issue(json!({}))),
        ("verify", issue(json!({"expectCommentId": "10200"}))),
    ]
}

#[tokio::test]
async fn issue_moved_out_of_the_admitted_project_is_denied_before_any_upstream_call() {
    let lookup = AtlassianCredential::from_static(test_lookup_credential());
    for (action, inputs) in single_issue_actions() {
        let backend = Arc::new(MovingJira::default());
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());

        // Scope resolution confirms the issue in PROJ, and the host admits it.
        let scopes = provider
            .lookup_scopes(action, &inputs, Some(&lookup))
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        assert_eq!(scopes["project"], vec!["PROJ".to_string()], "{action}");

        // By invocation the issue has moved to OTHER, which was not admitted.
        let mut invocation = InvocationBuilder::new("jira", action)
            .inputs(inputs)
            .resources(scopes)
            .companion_reads_authorized(true)
            .credential(test_credential())
            .lookup_credential(test_lookup_credential());
        if action == "attachment.add" {
            invocation = invocation.body_parts(vec![BrokerBodyPart::in_memory(
                "file0".to_string(),
                Some("evidence.txt".to_string()),
                Some("text/plain".to_string()),
                UPLOAD.to_vec(),
            )]);
        }
        let error = provider.invoke(invocation.build()).await.unwrap_err();

        assert_eq!(
            error.reason_code(),
            ReasonCode::ScopeUnresolved,
            "{action}: {error:?}"
        );
        assert_eq!(
            error.message, "Jira issue moved outside the authorized scope",
            "{action}"
        );
        // Nothing was sent, so there is no mutation receipt or partial result,
        // and the new location is not disclosed.
        assert!(error.result.is_none(), "{action}");
        assert!(!format!("{error:?}").contains("OTHER"), "{action}");
        assert_eq!(backend.lookups.load(Ordering::SeqCst), 2, "{action}");
        assert_eq!(
            *backend.calls.lock().unwrap(),
            Vec::<&str>::new(),
            "{action}"
        );
    }
}
