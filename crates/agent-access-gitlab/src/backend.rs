//! The GitLab backend seam, its wire types, response parsing, pagination headers, and the HTTP implementation.
use super::*;

#[async_trait]
pub trait GitlabBackend: Send + Sync {
    async fn provisioning(
        &self,
        _project_id: u64,
        _operation: GitlabProvisioningOperation,
        _request: GitlabProvisioningRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab provisioning backend is unavailable".into(),
        ))
    }

    fn egress_proxy_audit(&self, _credential: &ExecutionCredential) -> Value {
        EgressProxySelection::direct().audit_value()
    }

    async fn current_user(
        &self,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabUser>, GitlabBackendError>;

    async fn project(
        &self,
        project: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProject>, GitlabBackendError>;

    async fn upload_project(
        &self,
        _project_id: u64,
        _upload: BrokerBodyPart,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProjectUpload>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project upload is unavailable".to_string(),
        ))
    }

    async fn webhooks(
        &self,
        _project_id: u64,
        _request: GitlabWebhookListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhook>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook listing is unavailable".to_string(),
        ))
    }

    async fn webhook(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook view is unavailable".to_string(),
        ))
    }

    async fn create_webhook(
        &self,
        _project_id: u64,
        _request: GitlabWebhookWriteRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook creation is unavailable".to_string(),
        ))
    }

    async fn update_webhook(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _request: GitlabWebhookWriteRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook update is unavailable".to_string(),
        ))
    }

    async fn delete_webhook(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook deletion is unavailable".to_string(),
        ))
    }

    async fn test_webhook(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _trigger: &str,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook testing is unavailable".to_string(),
        ))
    }

    async fn webhook_events(
        &self,
        _project_id: u64,
        _request: GitlabWebhookEventListRequest,
        _redacted_header_names: &BTreeSet<String>,
        _field_byte_cap: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhookDeliveryEvent>>, GitlabBackendError>
    {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook delivery listing is unavailable".to_string(),
        ))
    }

    async fn resend_webhook_event(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _webhook_event_id: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook resend is unavailable".to_string(),
        ))
    }

    async fn set_webhook_custom_header(
        &self,
        _project_id: u64,
        _request: GitlabWebhookCustomHeaderRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook custom-header update is unavailable".to_string(),
        ))
    }

    async fn delete_webhook_custom_header(
        &self,
        _project_id: u64,
        _request: GitlabWebhookCustomHeaderRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab project webhook custom-header deletion is unavailable".to_string(),
        ))
    }

    async fn issue(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError>;

    async fn issues(
        &self,
        project_id: u64,
        request: GitlabIssueSearchRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabIssue>>, GitlabBackendError>;

    async fn create_issue(
        &self,
        project_id: u64,
        request: GitlabIssueCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError>;

    async fn update_issue(
        &self,
        project_id: u64,
        request: GitlabIssueUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError>;

    async fn issue_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError>;

    async fn create_issue_note(
        &self,
        project_id: u64,
        request: GitlabIssueNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn update_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn delete_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError>;

    async fn merge_request(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError>;

    async fn merge_requests(
        &self,
        project_id: u64,
        request: GitlabMergeRequestSearchRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabMergeRequest>>, GitlabBackendError>;

    async fn create_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError>;

    async fn update_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError>;

    async fn merge_request_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError>;

    async fn create_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn update_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn delete_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError>;

    async fn merge_request_discussions_page(
        &self,
        project_id: u64,
        request: GitlabDiscussionListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiscussion>>, GitlabBackendError>;

    async fn create_merge_request_inline_discussion(
        &self,
        _project_id: u64,
        _request: GitlabPositionedDiscussionCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab inline discussion creation is unavailable".to_string(),
        ))
    }

    async fn create_merge_request_discussion_note(
        &self,
        _project_id: u64,
        _request: GitlabDiscussionReplyRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab discussion replies are unavailable".to_string(),
        ))
    }

    async fn merge_request_draft_notes(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDraftNote>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_draft_note(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteObjectRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note view is unavailable".to_string(),
        ))
    }

    async fn create_merge_request_draft_note(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note creation is unavailable".to_string(),
        ))
    }

    async fn update_merge_request_draft_note(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note update is unavailable".to_string(),
        ))
    }

    async fn delete_merge_request_draft_note(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteObjectRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note deletion is unavailable".to_string(),
        ))
    }

    async fn publish_merge_request_draft_note(
        &self,
        _project_id: u64,
        _request: GitlabDraftNoteObjectRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab draft note publication is unavailable".to_string(),
        ))
    }

    async fn bulk_publish_merge_request_draft_notes(
        &self,
        _project_id: u64,
        _request: GitlabDraftBulkPublishRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab bulk draft publication is unavailable".to_string(),
        ))
    }

    async fn create_merge_request_review_summary(
        &self,
        _project_id: u64,
        _request: GitlabReviewSummaryNoteRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab review summary creation is unavailable".to_string(),
        ))
    }

    async fn gitlab_version(
        &self,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabServerVersion>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab version discovery is unavailable".to_string(),
        ))
    }

    async fn merge_request_approval_summary(
        &self,
        _project_id: u64,
        _iid: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request approval summary is unavailable".to_string(),
        ))
    }

    async fn merge_request_approval_state(
        &self,
        _project_id: u64,
        _iid: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalState>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request approval state is unavailable".to_string(),
        ))
    }

    async fn merge_request_approval_rules(
        &self,
        _project_id: u64,
        _request: GitlabApprovalRuleListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabApprovalRule>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request approval rules are unavailable".to_string(),
        ))
    }

    async fn merge_request_approval_rule(
        &self,
        _project_id: u64,
        _iid: u64,
        _rule_id: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalRule>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request approval rule is unavailable".to_string(),
        ))
    }

    async fn set_merge_request_approval(
        &self,
        _project_id: u64,
        _request: GitlabApprovalMutationRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request approval mutation is unavailable".to_string(),
        ))
    }

    async fn apply_suggestions(
        &self,
        _request: GitlabSuggestionApplyRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabSuggestion>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab suggestion application is unavailable".to_string(),
        ))
    }

    async fn merge_request_reviewers(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabReviewer>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request reviewer listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_commits(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabCommit>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request commit listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_pipelines(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabPipeline>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request pipeline listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_diffs(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffFile>>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request diff listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_raw_diffs(
        &self,
        _project_id: u64,
        _iid: u64,
        _byte_cap: u64,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request raw diff download is unavailable".to_string(),
        ))
    }

    async fn merge_request_diff_versions(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestListRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffVersionSummary>>, GitlabBackendError>
    {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request diff version listing is unavailable".to_string(),
        ))
    }

    async fn merge_request_diff_version(
        &self,
        _project_id: u64,
        _request: GitlabMergeRequestObjectRequest,
        _credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiffVersion>, GitlabBackendError> {
        Err(GitlabBackendError::Protocol(
            "GitLab merge request diff version view is unavailable".to_string(),
        ))
    }

    async fn create_merge_request_discussion(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError>;

    async fn merge_request_discussion(
        &self,
        project_id: u64,
        iid: u64,
        discussion_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError>;

    async fn update_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError>;

    async fn delete_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError>;

    async fn set_merge_request_discussion_resolved(
        &self,
        project_id: u64,
        request: GitlabDiscussionStateChangeRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError>;

    async fn merge_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestMergeRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError>;

    async fn branches(
        &self,
        project_id: u64,
        request: GitlabBranchListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabBranch>>, GitlabBackendError>;

    async fn branch(
        &self,
        project_id: u64,
        branch: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError>;

    async fn create_branch(
        &self,
        project_id: u64,
        request: GitlabBranchCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError>;

    async fn protected_branches(
        &self,
        project_id: u64,
        request: GitlabProtectedBranchListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabProtectedBranch>>, GitlabBackendError>;

    async fn protected_branch(
        &self,
        project_id: u64,
        name: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProtectedBranch>, GitlabBackendError>;

    async fn file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFile>, GitlabBackendError>;

    async fn raw_file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError>;

    async fn create_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError>;

    async fn update_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError>;

    async fn delete_file(
        &self,
        project_id: u64,
        request: GitlabFileDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError>;

    async fn commits(
        &self,
        project_id: u64,
        request: GitlabCommitListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabCommit>>, GitlabBackendError>;

    async fn commit(
        &self,
        project_id: u64,
        sha: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError>;

    async fn create_commit(
        &self,
        project_id: u64,
        request: GitlabCommitCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError>;

    async fn pipelines(
        &self,
        project_id: u64,
        request: GitlabPipelineListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabPipeline>>, GitlabBackendError>;

    async fn pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError>;

    async fn run_pipeline(
        &self,
        project_id: u64,
        request: GitlabPipelineRunRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError>;

    async fn retry_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError>;

    async fn cancel_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError>;

    async fn jobs(
        &self,
        project_id: u64,
        request: GitlabJobListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabJob>>, GitlabBackendError>;

    async fn job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError>;

    async fn job_trace(
        &self,
        project_id: u64,
        job_id: u64,
        byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError>;

    async fn retry_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError>;

    async fn cancel_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError>;

    async fn play_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabUser {
    pub id: u64,
    pub username: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabUserSummary {
    pub id: Option<u64>,
    pub username: Option<String>,
    pub name: Option<String>,
    pub web_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabMilestoneSummary {
    pub id: Option<u64>,
    pub iid: Option<u64>,
    pub title: Option<String>,
    pub state: Option<String>,
    pub due_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabProject {
    pub id: u64,
    pub path_with_namespace: String,
    pub name: Option<String>,
    pub web_url: Option<String>,
    pub default_branch: Option<String>,
    pub visibility: Option<String>,
    pub archived: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GitlabWebhookEvent {
    Push,
    TagPush,
    Issues,
    ConfidentialIssues,
    MergeRequests,
    Notes,
    ConfidentialNotes,
    Jobs,
    Pipelines,
    WikiPages,
    Deployments,
    Releases,
    Milestones,
    FeatureFlags,
    Emoji,
    ResourceAccessTokens,
    ResourceDeployTokens,
    Vulnerabilities,
}

impl GitlabWebhookEvent {
    pub const ALL: [&'static str; 18] = [
        "push",
        "tag_push",
        "issues",
        "confidential_issues",
        "merge_requests",
        "notes",
        "confidential_notes",
        "jobs",
        "pipelines",
        "wiki_pages",
        "deployments",
        "releases",
        "milestones",
        "feature_flags",
        "emoji",
        "resource_access_tokens",
        "resource_deploy_tokens",
        "vulnerabilities",
    ];

    pub(crate) fn configuration_field(self) -> &'static str {
        match self {
            Self::Push => "push_events",
            Self::TagPush => "tag_push_events",
            Self::Issues => "issues_events",
            Self::ConfidentialIssues => "confidential_issues_events",
            Self::MergeRequests => "merge_requests_events",
            Self::Notes => "note_events",
            Self::ConfidentialNotes => "confidential_note_events",
            Self::Jobs => "job_events",
            Self::Pipelines => "pipeline_events",
            Self::WikiPages => "wiki_page_events",
            Self::Deployments => "deployment_events",
            Self::Releases => "releases_events",
            Self::Milestones => "milestone_events",
            Self::FeatureFlags => "feature_flag_events",
            Self::Emoji => "emoji_events",
            Self::ResourceAccessTokens => "resource_access_token_events",
            Self::ResourceDeployTokens => "resource_deploy_token_events",
            Self::Vulnerabilities => "vulnerability_events",
        }
    }

    pub(crate) fn test_trigger(self) -> Option<&'static str> {
        match self {
            Self::Push => Some("push_events"),
            Self::TagPush => Some("tag_push_events"),
            Self::Issues => Some("issues_events"),
            Self::ConfidentialIssues => Some("confidential_issues_events"),
            Self::MergeRequests => Some("merge_requests_events"),
            Self::Notes => Some("note_events"),
            Self::Jobs => Some("job_events"),
            Self::Pipelines => Some("pipeline_events"),
            Self::WikiPages => Some("wiki_page_events"),
            Self::Releases => Some("releases_events"),
            Self::Milestones => Some("milestone_events"),
            Self::Emoji => Some("emoji_events"),
            Self::ResourceAccessTokens => Some("resource_access_token_events"),
            Self::ResourceDeployTokens => Some("resource_deploy_token_events"),
            Self::Vulnerabilities => Some("vulnerability_events"),
            Self::ConfidentialNotes | Self::Deployments | Self::FeatureFlags => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabWebhookNamedSecret {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabWebhook {
    pub id: u64,
    pub project_id: Option<u64>,
    pub url: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub enable_ssl_verification: Option<bool>,
    pub alert_status: Option<String>,
    pub disabled_until: Option<String>,
    pub events: Vec<GitlabWebhookEvent>,
    pub branch_filter_strategy: Option<String>,
    pub push_events_branch_filter: Option<String>,
    pub custom_webhook_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_headers: Option<Vec<GitlabWebhookNamedSecret>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_variables: Option<Vec<GitlabWebhookNamedSecret>>,
    pub token_present: Option<bool>,
    pub signing_token_present: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabWebhookDeliveryEvent {
    pub id: u64,
    pub trigger: Option<String>,
    pub created_at: Option<String>,
    pub execution_duration: Option<f64>,
    pub response_status: Option<String>,
    pub request_headers: BTreeMap<String, String>,
    pub request_data: Option<Value>,
    pub request_data_truncated: bool,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<String>,
    pub response_body_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabWebhookDeliveryAttempt {
    pub message: Option<String>,
    pub response_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabIssue {
    pub id: Option<u64>,
    pub iid: u64,
    pub project_id: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub author: Option<GitlabUserSummary>,
    pub assignees: Option<Vec<GitlabUserSummary>>,
    pub labels: Option<Vec<String>>,
    pub milestone: Option<GitlabMilestoneSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

impl GitlabIssue {
    pub(crate) fn with_project(mut self, project: &GitlabProject) -> Self {
        self.project = Some(project.path_with_namespace.clone());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabMergeRequest {
    pub id: Option<u64>,
    pub iid: u64,
    pub project_id: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state: Option<String>,
    pub source_branch: Option<String>,
    pub target_branch: Option<String>,
    pub sha: Option<String>,
    pub merge_status: Option<String>,
    pub detailed_merge_status: Option<String>,
    pub merge_commit_sha: Option<String>,
    pub squash_commit_sha: Option<String>,
    pub source_project_id: Option<u64>,
    pub target_project_id: Option<u64>,
    pub diff_refs: Option<GitlabDiffRefs>,
    pub changes_count: Option<String>,
    pub user_notes_count: Option<u64>,
    pub discussion_locked: Option<bool>,
    pub blocking_discussions_resolved: Option<bool>,
    pub has_conflicts: Option<bool>,
    pub prepared_at: Option<String>,
    pub head_pipeline: Option<GitlabPipelineSummary>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub author: Option<GitlabUserSummary>,
    pub assignees: Option<Vec<GitlabUserSummary>>,
    pub reviewers: Option<Vec<GitlabUserSummary>>,
    pub labels: Option<Vec<String>>,
    pub milestone: Option<GitlabMilestoneSummary>,
    pub draft: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiffRefs {
    pub base_sha: Option<String>,
    pub start_sha: String,
    pub head_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabPipelineSummary {
    pub id: u64,
    pub sha: Option<String>,
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
    pub status: Option<String>,
    pub web_url: Option<String>,
}

impl GitlabMergeRequest {
    pub(crate) fn with_project(mut self, project: &GitlabProject) -> Self {
        self.project = Some(project.path_with_namespace.clone());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabNote {
    pub id: u64,
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noteable_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noteable_iid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noteable_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolvable: Option<bool>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub note_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<GitlabDiffPosition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<GitlabUserSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<GitlabSuggestion>,
    pub author_user_id: Option<u64>,
    pub author_username: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub system: Option<bool>,
    pub confidential: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GitlabCollectionProjection {
    #[default]
    Full,
    Summary,
}

impl GitlabCollectionProjection {
    pub(crate) fn parse(value: Option<&str>, context: &str) -> Result<Self, ProviderError> {
        match value {
            None | Some("full") => Ok(Self::Full),
            Some("summary") => Ok(Self::Summary),
            Some(_) => Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                format!("{context} projection is unsupported"),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitlabNoteSummary {
    pub(crate) id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) author_user_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) author_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) system: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) confidential: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resolved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resolvable: Option<bool>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub(crate) note_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) commit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) position: Option<GitlabDiffPosition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resolved_at: Option<String>,
}

impl From<GitlabNote> for GitlabNoteSummary {
    fn from(note: GitlabNote) -> Self {
        Self {
            id: note.id,
            author_user_id: note.author_user_id,
            author_username: note.author_username,
            created_at: note.created_at,
            updated_at: note.updated_at,
            system: note.system,
            confidential: note.confidential,
            resolved: note.resolved,
            resolvable: note.resolvable,
            note_type: note.note_type,
            commit_id: note.commit_id,
            position: note.position,
            resolved_at: note.resolved_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiffPosition {
    pub position_type: String,
    pub base_sha: Option<String>,
    pub start_sha: String,
    pub head_sha: String,
    pub old_path: String,
    pub new_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_range: Option<GitlabLineRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabLineRange {
    pub start: GitlabLineRangePoint,
    pub end: GitlabLineRangePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabLineRangePoint {
    pub line_code: String,
    #[serde(rename = "type")]
    pub line_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabPositionInput {
    pub position_type: String,
    pub old_path: String,
    pub new_path: String,
    pub old_line: Option<u64>,
    pub new_line: Option<u64>,
    pub line_range: Option<GitlabLineRangeInput>,
    pub width: Option<u64>,
    pub height: Option<u64>,
    pub x: Option<u64>,
    pub y: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabLineRangeInput {
    pub start: GitlabLineCoordinateInput,
    pub end: GitlabLineCoordinateInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabLineCoordinateInput {
    pub old_line: Option<u64>,
    pub new_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDraftNote {
    pub id: u64,
    pub body: Option<String>,
    pub author_user_id: Option<u64>,
    pub merge_request_id: Option<u64>,
    pub resolve_discussion: Option<bool>,
    pub discussion_id: Option<String>,
    pub commit_id: Option<String>,
    pub position: Option<GitlabDiffPosition>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitlabDraftNoteSummary {
    pub(crate) id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) author_user_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) merge_request_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resolve_discussion: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) discussion_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) commit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) position: Option<GitlabDiffPosition>,
}

impl From<GitlabDraftNote> for GitlabDraftNoteSummary {
    fn from(note: GitlabDraftNote) -> Self {
        Self {
            id: note.id,
            author_user_id: note.author_user_id,
            merge_request_id: note.merge_request_id,
            resolve_discussion: note.resolve_discussion,
            discussion_id: note.discussion_id,
            commit_id: note.commit_id,
            position: note.position,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabApprovalUser {
    pub user: GitlabUserSummary,
    pub approved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabApprovalSummary {
    pub approvals_required: Option<u64>,
    pub approvals_left: Option<u64>,
    pub approved: Option<bool>,
    pub approved_by: Vec<GitlabApprovalUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_has_approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_can_approve: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabApprovalState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_rules_overwritten: Option<bool>,
    pub rules: Vec<GitlabApprovalRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabApprovalRuleSource {
    pub approvals_required: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabApprovalRule {
    pub id: u64,
    pub name: String,
    pub rule_type: Option<String>,
    pub approvals_required: u64,
    pub approved: Option<bool>,
    pub eligible_approvers: Vec<GitlabUserSummary>,
    pub approved_by: Vec<GitlabUserSummary>,
    pub users: Vec<GitlabUserSummary>,
    pub groups: Vec<GitlabGroupSummary>,
    pub overridden: Option<bool>,
    pub contains_hidden_groups: Option<bool>,
    pub code_owner: Option<bool>,
    pub section: Option<String>,
    pub source_rule: Option<GitlabApprovalRuleSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGroupSummary {
    pub id: Option<u64>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub full_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabServerVersion {
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabSuggestion {
    pub id: u64,
    pub from_line: u64,
    pub to_line: u64,
    pub applicable: bool,
    pub applied: bool,
    pub from_content: String,
    pub to_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiscussion {
    pub id: String,
    pub individual_note: Option<bool>,
    pub notes: Vec<GitlabNote>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitlabDiscussionSummary {
    pub(crate) id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) individual_note: Option<bool>,
    pub(crate) note_count: usize,
    pub(crate) notes: Vec<GitlabNoteSummary>,
}

impl From<GitlabDiscussion> for GitlabDiscussionSummary {
    fn from(discussion: GitlabDiscussion) -> Self {
        let note_count = discussion.notes.len();
        Self {
            id: discussion.id,
            individual_note: discussion.individual_note,
            note_count,
            notes: discussion.notes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabReviewer {
    pub user: GitlabUserSummary,
    pub state: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiffFile {
    pub old_path: String,
    pub new_path: String,
    pub old_mode: Option<String>,
    pub new_mode: Option<String>,
    pub diff: Option<String>,
    pub new_file: Option<bool>,
    pub renamed_file: Option<bool>,
    pub deleted_file: Option<bool>,
    pub generated_file: Option<bool>,
    pub collapsed: Option<bool>,
    pub too_large: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiffVersion {
    pub id: u64,
    pub merge_request_id: u64,
    pub head_commit_sha: String,
    pub base_commit_sha: String,
    pub start_commit_sha: String,
    pub created_at: Option<String>,
    pub state: Option<String>,
    pub real_size: Option<String>,
    pub patch_id_sha: Option<String>,
    #[serde(default)]
    pub commits: Vec<GitlabCommit>,
    #[serde(default)]
    pub diffs: Vec<GitlabDiffFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabDiffVersionSummary {
    pub id: u64,
    pub merge_request_id: u64,
    pub head_commit_sha: String,
    pub base_commit_sha: String,
    pub start_commit_sha: String,
    pub created_at: Option<String>,
    pub state: Option<String>,
    pub real_size: Option<String>,
    pub patch_id_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabBranch {
    pub name: String,
    pub merged: Option<bool>,
    pub protected: Option<bool>,
    pub default: Option<bool>,
    pub web_url: Option<String>,
    pub commit: Option<GitlabCommitSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabCommitSummary {
    pub id: String,
    pub short_id: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabCommit {
    pub id: String,
    pub short_id: Option<String>,
    pub title: Option<String>,
    pub message: Option<String>,
    pub author_name: Option<String>,
    pub authored_date: Option<String>,
    pub committed_date: Option<String>,
    pub web_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabPipeline {
    pub id: u64,
    pub iid: Option<u64>,
    pub project_id: u64,
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
    pub sha: Option<String>,
    pub status: Option<String>,
    pub source: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabJob {
    pub id: u64,
    pub name: Option<String>,
    pub status: Option<String>,
    pub stage: Option<String>,
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
    pub pipeline_id: Option<u64>,
    pub project_id: Option<u64>,
    pub trace_size: Option<u64>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabIssueSearchRequest {
    pub state: Option<String>,
    pub labels: Vec<String>,
    pub milestone: Option<String>,
    pub assignee: Option<String>,
    pub author: Option<String>,
    pub search: Option<String>,
    pub created_after: Option<String>,
    pub updated_after: Option<String>,
    pub sort: Option<String>,
    pub order_by: Option<String>,
    pub max_results: u32,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabIssueCreateRequest {
    pub title: String,
    pub description: Option<String>,
    pub labels: Vec<String>,
    pub milestone: Option<String>,
    pub assignee_ids: Vec<u64>,
    pub confidential: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabIssueUpdateRequest {
    pub iid: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state_event: Option<String>,
    pub labels: Vec<String>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
    pub milestone: Option<String>,
    pub assignee_ids: Vec<u64>,
    pub confidential: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabNoteListRequest {
    pub iid: u64,
    pub max_results: u32,
    pub sort: Option<String>,
    pub order_by: Option<String>,
    pub projection: GitlabCollectionProjection,
    pub page_token: Option<String>,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDiscussionListRequest {
    pub iid: u64,
    pub max_results: u32,
    pub projection: GitlabCollectionProjection,
    pub page_token: Option<String>,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitlabDiscussionViewInputs {
    pub(crate) iid: u64,
    pub(crate) discussion_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestListRequest {
    pub iid: u64,
    pub max_results: u32,
    pub page_token: Option<String>,
    pub page: u32,
    pub unidiff: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestObjectRequest {
    pub iid: u64,
    pub object_id: u64,
    pub unidiff: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabApprovalRuleListRequest {
    pub iid: u64,
    pub max_results: u32,
    pub page_token: Option<String>,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabApprovalMutationRequest {
    pub iid: u64,
    pub head_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabSuggestionApplyRequest {
    pub suggestion_ids: Vec<u64>,
    pub commit_message: Option<String>,
    pub batch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitlabSuggestionLocator {
    pub(crate) discussion_id: String,
    pub(crate) note_id: u64,
    pub(crate) suggestion_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitlabSuggestionApplyInputs {
    pub(crate) iid: u64,
    pub(crate) expected_head_sha: String,
    pub(crate) locators: Vec<GitlabSuggestionLocator>,
    pub(crate) commit_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GitlabSuggestionScopePreflight {
    pub(crate) target_project_id: u64,
    pub(crate) source_project_id: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GitlabSuggestionProviderPreflight {
    pub(crate) gitlab_suggestion_scope: GitlabSuggestionScopePreflight,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitlabPositionedDiscussionCreateRequest {
    pub iid: u64,
    pub body: String,
    pub position: GitlabDiffPosition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDiscussionReplyRequest {
    pub iid: u64,
    pub discussion_id: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDraftNoteListRequest {
    pub iid: u64,
    pub max_results: u32,
    pub projection: GitlabCollectionProjection,
    pub page_token: Option<String>,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDraftNoteObjectRequest {
    pub iid: u64,
    pub draft_note_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitlabDraftNoteCreateRequest {
    pub iid: u64,
    pub body: String,
    pub position: Option<GitlabDiffPosition>,
    pub in_reply_to_discussion_id: Option<String>,
    pub resolve_discussion: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitlabDraftNoteUpdateRequest {
    pub iid: u64,
    pub draft_note_id: u64,
    pub body: String,
    pub position: Option<GitlabDiffPosition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDraftBulkPublishRequest {
    pub iid: u64,
    pub reviewer_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabReviewSummaryNoteRequest {
    pub iid: u64,
    pub body: String,
    pub internal: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabNoteCreateRequest {
    pub iid: u64,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabIssueNoteCreateRequest {
    pub iid: u64,
    pub body: String,
    pub confidential: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabNoteUpdateRequest {
    pub iid: u64,
    pub note_id: u64,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabNoteDeleteRequest {
    pub iid: u64,
    pub note_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDiscussionNoteUpdateRequest {
    pub iid: u64,
    pub discussion_id: String,
    pub note_id: u64,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDiscussionNoteDeleteRequest {
    pub iid: u64,
    pub discussion_id: String,
    pub note_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabDiscussionStateChangeRequest {
    pub iid: u64,
    pub discussion_id: String,
    pub change: GitlabDiscussionStateChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestSearchRequest {
    pub state: Option<String>,
    pub source_branch: Option<String>,
    pub target_branch: Option<String>,
    pub labels: Vec<String>,
    pub milestone: Option<String>,
    pub author: Option<String>,
    pub assignee: Option<String>,
    pub reviewer: Option<String>,
    pub search: Option<String>,
    pub created_after: Option<String>,
    pub updated_after: Option<String>,
    pub sort: Option<String>,
    pub order_by: Option<String>,
    pub max_results: u32,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabPage<T> {
    pub items: Vec<T>,
    pub next_page: Option<u32>,
}

pub(crate) fn issue_search_request_hash(request: &GitlabIssueSearchRequest) -> String {
    sha256_serialized(&BTreeMap::from([
        ("state", json!(request.state)),
        ("labels", json!(request.labels)),
        ("milestone", json!(request.milestone)),
        ("assignee", json!(request.assignee)),
        ("author", json!(request.author)),
        ("search", json!(request.search)),
        ("createdAfter", json!(request.created_after)),
        ("updatedAfter", json!(request.updated_after)),
        ("sort", json!(request.sort)),
        ("orderBy", json!(request.order_by)),
    ]))
}

pub(crate) fn merge_request_search_request_hash(
    request: &GitlabMergeRequestSearchRequest,
) -> String {
    sha256_serialized(&BTreeMap::from([
        ("state", json!(request.state)),
        ("sourceBranch", json!(request.source_branch)),
        ("targetBranch", json!(request.target_branch)),
        ("labels", json!(request.labels)),
        ("milestone", json!(request.milestone)),
        ("author", json!(request.author)),
        ("assignee", json!(request.assignee)),
        ("reviewer", json!(request.reviewer)),
        ("search", json!(request.search)),
        ("createdAfter", json!(request.created_after)),
        ("updatedAfter", json!(request.updated_after)),
        ("sort", json!(request.sort)),
        ("orderBy", json!(request.order_by)),
    ]))
}

pub(crate) fn note_list_request_hash(request: &GitlabNoteListRequest) -> String {
    sha256_serialized(&BTreeMap::from([
        ("iid", json!(request.iid)),
        ("sort", json!(request.sort)),
        ("orderBy", json!(request.order_by)),
        ("projection", json!(request.projection)),
    ]))
}

pub(crate) fn discussion_list_request_hash(request: &GitlabDiscussionListRequest) -> String {
    sha256_serialized(&BTreeMap::from([
        ("iid", json!(request.iid)),
        ("projection", json!(request.projection)),
    ]))
}

pub(crate) fn validate_gitlab_page_count(
    count: usize,
    max_results: u32,
) -> Result<(), ProviderError> {
    if count > max_results as usize {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab returned more paginated items than requested",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestCreateRequest {
    pub source_branch: String,
    pub target_branch: String,
    pub title: String,
    pub description: Option<String>,
    pub labels: Vec<String>,
    pub assignee_ids: Vec<u64>,
    pub reviewer_ids: Vec<u64>,
    pub remove_source_branch: Option<bool>,
    pub squash: Option<bool>,
    pub draft: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestUpdateRequest {
    pub iid: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state_event: Option<String>,
    pub labels: Vec<String>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
    pub assignee_ids: Vec<u64>,
    pub reviewer_ids: Vec<u64>,
    pub target_branch: Option<String>,
    pub remove_source_branch: Option<bool>,
    pub squash: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabMergeRequestMergeRequest {
    pub iid: u64,
    pub sha: String,
    pub squash: Option<bool>,
    pub should_remove_source_branch: Option<bool>,
    pub merge_commit_message: Option<String>,
    pub squash_commit_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabProtectedBranchListRequest {
    pub search: Option<String>,
    pub max_results: u32,
    pub fail_on_next_page: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabBranchListRequest {
    pub search: Option<String>,
    pub regex: Option<String>,
    pub max_results: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabCommitListRequest {
    pub ref_name: Option<String>,
    pub path: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub first_parent: Option<bool>,
    pub max_results: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabPipelineListRequest {
    pub ref_name: Option<String>,
    pub sha: Option<String>,
    pub status: Option<String>,
    pub source: Option<String>,
    pub updated_after: Option<String>,
    pub updated_before: Option<String>,
    pub max_results: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabPipelineRunRequest {
    pub ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabJobListRequest {
    pub pipeline_id: Option<u64>,
    pub scope: Option<String>,
    pub max_results: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabBranchCreateRequest {
    pub branch: String,
    pub ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabFileRequest {
    pub path: String,
    pub ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabFileWriteRequest {
    pub path: String,
    pub branch: String,
    pub content: String,
    pub commit_message: String,
    pub start_branch: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub encoding: Option<String>,
    pub execute_filemode: Option<bool>,
    pub last_commit_id: Option<String>,
    pub decoded_content_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabFileDeleteRequest {
    pub path: String,
    pub branch: String,
    pub commit_message: String,
    pub start_branch: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub last_commit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabCommitCreateRequest {
    pub branch: String,
    pub commit_message: String,
    pub actions: Vec<GitlabCommitActionRequest>,
    pub start_branch: Option<String>,
    pub start_sha: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabCommitActionRequest {
    pub action: String,
    pub file_path: String,
    pub previous_path: Option<String>,
    pub content: Option<String>,
    pub encoding: Option<String>,
    pub execute_filemode: Option<bool>,
    pub last_commit_id: Option<String>,
    pub decoded_content_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabWebhookListRequest {
    pub max_results: u32,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabWebhookEventListRequest {
    pub webhook_id: u64,
    pub status: Option<String>,
    pub max_results: u32,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitlabWebhookWriteRequest {
    pub url: String,
    pub events: Option<Vec<GitlabWebhookEvent>>,
    pub name: Option<Option<String>>,
    pub description: Option<Option<String>>,
    pub enable_ssl_verification: Option<bool>,
    pub branch_filter_strategy: Option<String>,
    pub push_events_branch_filter: Option<String>,
    pub custom_webhook_template: Option<Option<String>>,
    pub token: Option<String>,
    pub signing_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabWebhookCustomHeaderRequest {
    pub webhook_id: u64,
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabBackendResponse<T> {
    pub value: T,
    pub status: u16,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabFile {
    pub file_name: String,
    pub file_path: String,
    pub size: u64,
    pub encoding: Option<String>,
    pub content: Option<String>,
    pub content_sha256: Option<String>,
    pub ref_name: Option<String>,
    pub blob_id: Option<String>,
    pub commit_id: Option<String>,
    pub last_commit_id: Option<String>,
    pub execute_filemode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabFileMutation {
    pub file_path: String,
    pub branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabProtectedBranch {
    pub id: Option<u64>,
    pub name: String,
    pub allow_force_push: Option<bool>,
    pub code_owner_approval_required: Option<bool>,
    pub inherited: Option<bool>,
    pub push_access_levels: Vec<GitlabProtectedBranchAccessLevel>,
    pub merge_access_levels: Vec<GitlabProtectedBranchAccessLevel>,
    pub unprotect_access_levels: Vec<GitlabProtectedBranchAccessLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabProtectedBranchAccessLevel {
    pub access_level: Option<u64>,
    pub access_level_description: Option<String>,
    pub user_id: Option<u64>,
    pub group_id: Option<u64>,
    pub deploy_key_id: Option<u64>,
}

pub struct GitlabRawFile {
    pub size: Option<u64>,
    pub content_type: String,
    pub stream: ProviderResultStream,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum GitlabBackendError {
    #[error("GitLab returned unauthorized")]
    Unauthorized,
    #[error("GitLab returned forbidden")]
    Forbidden,
    #[error("GitLab returned not found")]
    NotFound,
    #[error("GitLab returned HTTP {0}")]
    HttpStatus(u16),
    #[error("GitLab is rate limiting requests")]
    RateLimited(Option<UpstreamRetryAfter>),
    #[error("GitLab validation failed with HTTP {status}")]
    Validation { status: u16, message: String },
    #[error("GitLab transport failed: {0}")]
    Transport(String),
    #[error("GitLab request timed out")]
    Timeout,
    #[error("GitLab response exceeded the configured byte cap")]
    ResponseTooLarge,
    #[error("GitLab draft position shape invalid")]
    DraftPositionShapeInvalid,
    #[error("GitLab response protocol error: {0}")]
    Protocol(String),
}

#[derive(Clone)]
pub(crate) struct HttpGitlabBackend {
    pub(crate) api_base: Url,
    pub(crate) client: UpstreamClient,
    pub(crate) upload_client: UpstreamClient,
    pub(crate) limits: ProviderLimits,
}

impl HttpGitlabBackend {
    pub(crate) fn new_with_egress(
        config: GitlabProviderConfig,
        limits: ProviderLimits,
        egress_proxy: &EgressProxyRuntimeConfig,
        outbound_tls: &crate::PreparedOutboundTls,
    ) -> Result<Self, HostError> {
        let api_base = normalized_api_base(&config.api_base_url).map_err(|error| {
            HostError::Config(crate::ConfigError::Invalid {
                errors: vec![format!("providers.gitlab.api_base_url is invalid: {error}")],
            })
        })?;
        let network = UpstreamNetwork {
            limits: &limits,
            egress: egress_proxy,
            outbound_tls,
        };
        let client = |profile| {
            UpstreamClient::build(
                UpstreamClientSpec {
                    label: "providers.gitlab.egress_proxy",
                    provider: "gitlab",
                    base: &api_base,
                    egress_proxy: config.egress_proxy.as_ref(),
                    allowed_upstream_hosts: &config.allowed_upstream_hosts,
                    profile,
                    status_reasons: &[],
                },
                network,
            )
        };
        let upload_client = client(ClientProfile::Upload)?;
        let client = client(ClientProfile::Request)?;
        Ok(Self {
            api_base,
            client,
            upload_client,
            limits,
        })
    }

    pub(crate) fn endpoint(&self, suffix: &str) -> Result<Url, GitlabBackendError> {
        self.api_base
            .join(suffix)
            .map_err(|error| GitlabBackendError::Protocol(error.to_string()))
    }

    pub(crate) async fn get_json(
        &self,
        operation: &'static str,
        url: Url,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::GET, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            operation,
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(GitlabBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn get_json_page(
        &self,
        operation: &'static str,
        url: Url,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<Value>>, GitlabBackendError> {
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::GET, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            operation,
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let next_page = gitlab_next_page(response.headers(), &url)?;
        let value =
            gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let items = value.as_array().cloned().ok_or_else(|| {
            GitlabBackendError::Protocol("GitLab paginated response is not an array".to_string())
        })?;
        Ok(GitlabBackendResponse {
            value: GitlabPage { items, next_page },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn post_json(
        &self,
        operation: &'static str,
        url: Url,
        body: Value,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        self.send_json_body(operation, "POST", url, body, credential)
            .await
    }

    pub(crate) async fn post_json_without_body(
        &self,
        operation: &'static str,
        url: Url,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::POST, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            operation,
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(GitlabBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn put_json(
        &self,
        operation: &'static str,
        url: Url,
        body: Value,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        self.send_json_body(operation, "PUT", url, body, credential)
            .await
    }

    pub(crate) async fn delete_json(
        &self,
        operation: &'static str,
        url: Url,
        body: Value,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        self.send_json_body(operation, "DELETE", url, body, credential)
            .await
    }

    pub(crate) async fn delete_no_content(
        &self,
        operation: &'static str,
        url: Url,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::DELETE, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            operation,
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        if status != 204 {
            return Err(GitlabBackendError::Protocol(format!(
                "GitLab {operation} returned unexpected success status {status}"
            )));
        }
        gitlab_response_empty(response).await?;
        Ok(GitlabBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn send_json_no_content(
        &self,
        operation: &'static str,
        method: &'static str,
        url: Url,
        body: Value,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let started = Instant::now();
        let builder = match method {
            "POST" => self.client.request(Method::POST, url.clone()),
            "PUT" => self.client.request(Method::PUT, url.clone()),
            _ => {
                return Err(GitlabBackendError::Protocol(
                    "unsupported GitLab no-content JSON method".to_string(),
                ));
            }
        };
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(builder, credential)?
                .header("Accept", "application/json")
                .json(&body),
            operation,
            gitlab_validation_fields(operation),
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        gitlab_response_empty(response).await?;
        Ok(GitlabBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn send_json_body(
        &self,
        operation: &'static str,
        method: &'static str,
        url: Url,
        body: Value,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        let started = Instant::now();
        let builder = match method {
            "POST" => self.client.request(Method::POST, url.clone()),
            "PUT" => self.client.request(Method::PUT, url.clone()),
            "DELETE" => self.client.request(Method::DELETE, url.clone()),
            _ => {
                return Err(GitlabBackendError::Protocol(
                    "unsupported GitLab JSON method".to_string(),
                ));
            }
        };
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(builder, credential)?
                .header("Accept", "application/json")
                .json(&body),
            operation,
            gitlab_validation_fields(operation),
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(GitlabBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    pub(crate) async fn get_raw(
        &self,
        operation: &'static str,
        url: Url,
        byte_cap: u64,
        allow_known_oversize: bool,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::GET, url.clone()),
                credential,
            )?
            .header("Accept", "application/octet-stream"),
            operation,
            None,
            byte_cap,
        )
        .await?;
        let status = response.status().as_u16();
        let size = response.content_length();
        if !allow_known_oversize && size.is_some_and(|size| size > byte_cap) {
            return Err(GitlabBackendError::ResponseTooLarge);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let stream = gitlab_response_stream(
            response,
            byte_cap,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            size,
            content_type.clone(),
        );
        Ok(GitlabBackendResponse {
            value: GitlabRawFile {
                size,
                content_type,
                stream,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }
}

#[async_trait]
impl GitlabBackend for HttpGitlabBackend {
    async fn provisioning(
        &self,
        project_id: u64,
        operation: GitlabProvisioningOperation,
        request: GitlabProvisioningRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Value>, GitlabBackendError> {
        self.provisioning_request(project_id, operation, request, credential)
            .await
    }

    fn egress_proxy_audit(&self, _credential: &ExecutionCredential) -> Value {
        self.client.egress_proxy().audit_value()
    }

    async fn current_user(
        &self,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabUser>, GitlabBackendError> {
        let response = self
            .get_json("credential.verify", self.endpoint("user")?, credential)
            .await?;
        Ok(response.map_json(user_from_value)?)
    }

    async fn project(
        &self,
        project: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProject>, GitlabBackendError> {
        let encoded = encoded_path_segment(project);
        let response = self
            .get_json(
                "project.view",
                self.endpoint(&format!("projects/{encoded}"))?,
                credential,
            )
            .await?;
        Ok(response.map_json(project_from_value)?)
    }

    async fn upload_project(
        &self,
        project_id: u64,
        upload: BrokerBodyPart,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProjectUpload>, GitlabBackendError> {
        let url = self.endpoint(&format!("projects/{project_id}/uploads"))?;
        let (part, progress) = if let Some(path) = upload.temp_file_path() {
            let (body, progress) = file_upload_body(path).await.map_err(|_| {
                GitlabBackendError::Transport("GitLab upload file could not be opened".to_string())
            })?;
            (
                reqwest::multipart::Part::stream_with_length(body, upload.size()),
                progress,
            )
        } else {
            // A body held in memory reports no progress: its closed channel
            // leaves only the response deadline.
            let (_, progress) = tokio::sync::watch::channel(tokio::time::Instant::now());
            (
                reqwest::multipart::Part::bytes(upload.bytes.clone()),
                progress,
            )
        };
        let part = part
            .file_name(upload.file_name.clone().unwrap_or_default())
            .mime_str(
                upload
                    .content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
            )
            .map_err(|_| {
                GitlabBackendError::Protocol("GitLab upload media type is invalid".to_string())
            })?;
        let started = Instant::now();
        let response = send_gitlab_upload(
            &self.upload_client,
            authenticated_gitlab_request(
                self.upload_client.request(Method::POST, url.clone()),
                credential,
            )?
            .header("Accept", "application/json")
            .multipart(reqwest::multipart::Form::new().part("file", part)),
            "project.upload",
            progress,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let value = gitlab_upload_response_value(
            response,
            self.limits.max_upstream_response_bytes,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
        )
        .await?;
        Ok(GitlabBackendResponse {
            value: project_upload_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn webhooks(
        &self,
        project_id: u64,
        request: GitlabWebhookListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhook>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/hooks"))?;
        url.query_pairs_mut()
            .append_pair("per_page", &request.max_results.to_string())
            .append_pair("page", &request.page.to_string());
        self.get_json_page("webhook.list", url, credential)
            .await?
            .map_page(webhook_from_value)
    }

    async fn webhook(
        &self,
        project_id: u64,
        webhook_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        self.get_json(
            "webhook.view",
            self.endpoint(&format!("projects/{project_id}/hooks/{webhook_id}"))?,
            credential,
        )
        .await?
        .map_json(webhook_from_value)
    }

    async fn create_webhook(
        &self,
        project_id: u64,
        request: GitlabWebhookWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        self.post_json(
            "webhook.create",
            self.endpoint(&format!("projects/{project_id}/hooks"))?,
            webhook_write_body(&request),
            credential,
        )
        .await?
        .map_json(webhook_from_value)
    }

    async fn update_webhook(
        &self,
        project_id: u64,
        webhook_id: u64,
        request: GitlabWebhookWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        self.put_json(
            "webhook.update",
            self.endpoint(&format!("projects/{project_id}/hooks/{webhook_id}"))?,
            webhook_write_body(&request),
            credential,
        )
        .await?
        .map_json(webhook_from_value)
    }

    async fn delete_webhook(
        &self,
        project_id: u64,
        webhook_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let url = self.endpoint(&format!("projects/{project_id}/hooks/{webhook_id}"))?;
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::DELETE, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            "webhook.delete",
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        if status == 204 {
            gitlab_response_empty(response).await?;
        } else {
            let value =
                gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
            let deleted = webhook_from_value(value)?;
            if deleted.id != webhook_id {
                return Err(GitlabBackendError::Protocol(
                    "GitLab deleted webhook id did not match the requested hook".to_string(),
                ));
            }
        }
        Ok(GitlabBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn test_webhook(
        &self,
        project_id: u64,
        webhook_id: u64,
        trigger: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        self.post_json_without_body(
            "webhook.test",
            self.endpoint(&format!(
                "projects/{project_id}/hooks/{webhook_id}/test/{trigger}"
            ))?,
            credential,
        )
        .await?
        .map_json(webhook_test_attempt_from_value)
    }

    async fn webhook_events(
        &self,
        project_id: u64,
        request: GitlabWebhookEventListRequest,
        redacted_header_names: &BTreeSet<String>,
        field_byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhookDeliveryEvent>>, GitlabBackendError>
    {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/hooks/{}/events",
            request.webhook_id
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("per_page", &request.max_results.to_string())
                .append_pair("page", &request.page.to_string());
            if let Some(status) = request.status.as_deref() {
                query.append_pair("status", status);
            }
        }
        let redacted_header_names = redacted_header_names.clone();
        self.get_json_page("webhook.event.list", url, credential)
            .await?
            .map_page(|value| {
                webhook_delivery_event_from_value(value, &redacted_header_names, field_byte_cap)
            })
    }

    async fn resend_webhook_event(
        &self,
        project_id: u64,
        webhook_id: u64,
        webhook_event_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        self.post_json_without_body(
            "webhook.event.resend",
            self.endpoint(&format!(
                "projects/{project_id}/hooks/{webhook_id}/events/{webhook_event_id}/resend"
            ))?,
            credential,
        )
        .await?
        .map_json(webhook_resend_attempt_from_value)
    }

    async fn set_webhook_custom_header(
        &self,
        project_id: u64,
        request: GitlabWebhookCustomHeaderRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let encoded_key = encoded_path_segment(&request.key);
        self.send_json_no_content(
            "webhook.custom_header.set",
            "PUT",
            self.endpoint(&format!(
                "projects/{project_id}/hooks/{}/custom_headers/{encoded_key}",
                request.webhook_id
            ))?,
            json!({ "value": request.value }),
            credential,
        )
        .await
    }

    async fn delete_webhook_custom_header(
        &self,
        project_id: u64,
        request: GitlabWebhookCustomHeaderRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let encoded_key = encoded_path_segment(&request.key);
        self.delete_no_content(
            "webhook.custom_header.delete",
            self.endpoint(&format!(
                "projects/{project_id}/hooks/{}/custom_headers/{encoded_key}",
                request.webhook_id
            ))?,
            credential,
        )
        .await
    }

    async fn issue(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        let response = self
            .get_json(
                "issue.view",
                self.endpoint(&format!("projects/{project_id}/issues/{iid}"))?,
                credential,
            )
            .await?;
        Ok(response.map_json(issue_from_value)?)
    }

    async fn issues(
        &self,
        project_id: u64,
        request: GitlabIssueSearchRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabIssue>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/issues"))?;
        append_issue_query(&mut url, &request);
        let response = self.get_json_page("issue.search", url, credential).await?;
        response.map_page(issue_from_value)
    }

    async fn create_issue(
        &self,
        project_id: u64,
        request: GitlabIssueCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        let response = self
            .post_json(
                "issue.create",
                self.endpoint(&format!("projects/{project_id}/issues"))?,
                issue_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(issue_from_value)?)
    }

    async fn update_issue(
        &self,
        project_id: u64,
        request: GitlabIssueUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        let response = self
            .put_json(
                "issue.update",
                self.endpoint(&format!("projects/{project_id}/issues/{}", request.iid))?,
                issue_update_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(issue_from_value)?)
    }

    async fn issue_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/issues/{}/notes",
            request.iid
        ))?;
        append_note_list_query(&mut url, &request);
        let response = self
            .get_json_page("issue.note.list", url, credential)
            .await?;
        response.map_page(note_from_value)
    }

    async fn create_issue_note(
        &self,
        project_id: u64,
        request: GitlabIssueNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .post_json(
                "issue.note.add",
                self.endpoint(&format!(
                    "projects/{project_id}/issues/{}/notes",
                    request.iid
                ))?,
                issue_note_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .get_json(
                "issue.note.get",
                self.endpoint(&format!(
                    "projects/{project_id}/issues/{}/notes/{}",
                    request.iid, request.note_id
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn update_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .put_json(
                "issue.note.update",
                self.endpoint(&format!(
                    "projects/{project_id}/issues/{}/notes/{}",
                    request.iid, request.note_id
                ))?,
                note_update_body(&request.body),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn delete_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.delete_no_content(
            "issue.note.delete",
            self.endpoint(&format!(
                "projects/{project_id}/issues/{}/notes/{}",
                request.iid, request.note_id
            ))?,
            credential,
        )
        .await
    }

    async fn merge_request(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.view",
                self.endpoint(&format!("projects/{project_id}/merge_requests/{iid}"))?,
                credential,
            )
            .await?;
        Ok(response.map_json(merge_request_from_value)?)
    }

    async fn merge_requests(
        &self,
        project_id: u64,
        request: GitlabMergeRequestSearchRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabMergeRequest>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/merge_requests"))?;
        append_merge_request_query(&mut url, &request);
        let response = self
            .get_json_page("merge_request.search", url, credential)
            .await?;
        response.map_page(merge_request_from_value)
    }

    async fn create_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.create",
                self.endpoint(&format!("projects/{project_id}/merge_requests"))?,
                merge_request_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(merge_request_from_value)?)
    }

    async fn update_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        let response = self
            .put_json(
                "merge_request.update",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}",
                    request.iid
                ))?,
                merge_request_update_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(merge_request_from_value)?)
    }

    async fn merge_request_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/notes",
            request.iid
        ))?;
        append_note_list_query(&mut url, &request);
        let response = self
            .get_json_page("merge_request.note.list", url, credential)
            .await?;
        response.map_page(note_from_value)
    }

    async fn create_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.note.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/notes",
                    request.iid
                ))?,
                note_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.note.get",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/notes/{}",
                    request.iid, request.note_id
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn update_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .put_json(
                "merge_request.note.update",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/notes/{}",
                    request.iid, request.note_id
                ))?,
                note_update_body(&request.body),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn delete_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.delete_no_content(
            "merge_request.note.delete",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{}/notes/{}",
                request.iid, request.note_id
            ))?,
            credential,
        )
        .await
    }

    async fn merge_request_discussions_page(
        &self,
        project_id: u64,
        request: GitlabDiscussionListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiscussion>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/discussions",
            request.iid
        ))?;
        append_discussion_list_query(&mut url, &request);
        let response = self
            .get_json_page("merge_request.discussion.list", url, credential)
            .await?;
        response.map_page(discussion_from_value)
    }

    async fn create_merge_request_inline_discussion(
        &self,
        project_id: u64,
        request: GitlabPositionedDiscussionCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.discussion.inline.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/discussions",
                    request.iid
                ))?,
                positioned_discussion_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(discussion_from_value)?)
    }

    async fn create_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionReplyRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.discussion.note.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/discussions/{}/notes",
                    request.iid,
                    encoded_path_segment(&request.discussion_id)
                ))?,
                json!({ "body": request.body }),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn merge_request_draft_notes(
        &self,
        project_id: u64,
        request: GitlabDraftNoteListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDraftNote>>, GitlabBackendError> {
        let url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/draft_notes",
            request.iid
        ))?;
        self.get_json_page("merge_request.draft_note.list", url, credential)
            .await?
            .map_page(draft_note_from_value)
    }

    async fn merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.draft_note.view",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/draft_notes/{}",
                    request.iid, request.draft_note_id
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(draft_note_from_value)?)
    }

    async fn create_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.draft_note.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/draft_notes",
                    request.iid
                ))?,
                draft_note_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(draft_note_from_value)?)
    }

    async fn update_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        let response = self
            .put_json(
                "merge_request.draft_note.update",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/draft_notes/{}",
                    request.iid, request.draft_note_id
                ))?,
                draft_note_update_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(draft_note_from_value)?)
    }

    async fn delete_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.delete_no_content(
            "merge_request.draft_note.delete",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{}/draft_notes/{}",
                request.iid, request.draft_note_id
            ))?,
            credential,
        )
        .await
    }

    async fn publish_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.send_json_no_content(
            "merge_request.draft_note.publish",
            "PUT",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{}/draft_notes/{}/publish",
                request.iid, request.draft_note_id
            ))?,
            json!({}),
            credential,
        )
        .await
    }

    async fn bulk_publish_merge_request_draft_notes(
        &self,
        project_id: u64,
        request: GitlabDraftBulkPublishRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        let mut body = serde_json::Map::new();
        if let Some(reviewer_state) = &request.reviewer_state {
            body.insert("reviewer_state".to_string(), json!(reviewer_state));
        }
        self.send_json_no_content(
            if request.reviewer_state.is_some() {
                "merge_request.review.submit"
            } else {
                "merge_request.draft_note.publish_all"
            },
            "POST",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{}/draft_notes/bulk_publish",
                request.iid
            ))?,
            Value::Object(body),
            credential,
        )
        .await
    }

    async fn create_merge_request_review_summary(
        &self,
        project_id: u64,
        request: GitlabReviewSummaryNoteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let mut body = serde_json::Map::from_iter([("body".to_string(), json!(request.body))]);
        if let Some(internal) = request.internal {
            body.insert("internal".to_string(), json!(internal));
        }
        let response = self
            .post_json(
                "merge_request.review.summary.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/notes",
                    request.iid
                ))?,
                Value::Object(body),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn gitlab_version(
        &self,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabServerVersion>, GitlabBackendError> {
        let response = self
            .get_json("gitlab.version", self.endpoint("version")?, credential)
            .await?;
        Ok(response.map_json(server_version_from_value)?)
    }

    async fn merge_request_approval_summary(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.approval.view",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{iid}/approvals"
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(approval_summary_from_value)?)
    }

    async fn merge_request_approval_state(
        &self,
        project_id: u64,
        iid: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalState>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.approval_state.view",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{iid}/approval_state"
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(approval_state_from_value)?)
    }

    async fn merge_request_approval_rules(
        &self,
        project_id: u64,
        request: GitlabApprovalRuleListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabApprovalRule>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/approval_rules",
            request.iid
        ))?;
        append_page_query(&mut url, request.max_results, request.page);
        self.get_json_page("merge_request.approval_rule.list", url, credential)
            .await?
            .map_page(approval_rule_from_value)
    }

    async fn merge_request_approval_rule(
        &self,
        project_id: u64,
        iid: u64,
        rule_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalRule>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.approval_rule.view",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{iid}/approval_rules/{rule_id}"
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(approval_rule_from_value)?)
    }

    async fn set_merge_request_approval(
        &self,
        project_id: u64,
        request: GitlabApprovalMutationRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        let (operation, path, body) = if let Some(head_sha) = request.head_sha {
            (
                "merge_request.approve",
                format!(
                    "projects/{project_id}/merge_requests/{}/approve",
                    request.iid
                ),
                json!({ "sha": head_sha }),
            )
        } else {
            (
                "merge_request.unapprove",
                format!(
                    "projects/{project_id}/merge_requests/{}/unapprove",
                    request.iid
                ),
                json!({}),
            )
        };
        let response = self
            .post_json(operation, self.endpoint(&path)?, body, credential)
            .await?;
        Ok(response.map_json(approval_summary_from_value)?)
    }

    async fn apply_suggestions(
        &self,
        request: GitlabSuggestionApplyRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabSuggestion>>, GitlabBackendError> {
        let single = !request.batch;
        if single && request.suggestion_ids.len() != 1 {
            return Err(GitlabBackendError::Protocol(
                "single suggestion apply requires exactly one suggestion ID".to_string(),
            ));
        }
        let single_id = request.suggestion_ids.first().copied();
        let mut body = serde_json::Map::new();
        if request.batch {
            body.insert("ids".to_string(), json!(request.suggestion_ids));
        }
        if let Some(commit_message) = request.commit_message {
            body.insert("commit_message".to_string(), json!(commit_message));
        }
        let (operation, path) = if single {
            (
                "merge_request.suggestion.apply",
                format!(
                    "suggestions/{}/apply",
                    single_id.expect("single suggestion id")
                ),
            )
        } else {
            (
                "merge_request.suggestion.batch_apply",
                "suggestions/batch_apply".to_string(),
            )
        };
        let response = self
            .put_json(
                operation,
                self.endpoint(&path)?,
                Value::Object(body),
                credential,
            )
            .await?;
        response.map_json(|value| {
            if single {
                Ok(vec![suggestion_from_value(&value)?])
            } else {
                value
                    .as_array()
                    .ok_or_else(|| {
                        GitlabBackendError::Protocol(
                            "suggestion batch response is not an array".to_string(),
                        )
                    })?
                    .iter()
                    .map(suggestion_from_value)
                    .collect()
            }
        })
    }

    async fn merge_request_reviewers(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabReviewer>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/reviewers",
            request.iid
        ))?;
        append_merge_request_list_query(&mut url, &request);
        self.get_json_page("merge_request.reviewer.list", url, credential)
            .await?
            .map_page(reviewer_from_value)
    }

    async fn merge_request_commits(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabCommit>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/commits",
            request.iid
        ))?;
        append_merge_request_list_query(&mut url, &request);
        self.get_json_page("merge_request.commit.list", url, credential)
            .await?
            .map_page(commit_from_value)
    }

    async fn merge_request_pipelines(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabPipeline>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/pipelines",
            request.iid
        ))?;
        append_merge_request_list_query(&mut url, &request);
        self.get_json_page("merge_request.pipeline.list", url, credential)
            .await?
            .map_page(pipeline_from_value)
    }

    async fn merge_request_diffs(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffFile>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/diffs",
            request.iid
        ))?;
        append_merge_request_list_query(&mut url, &request);
        self.get_json_page("merge_request.diff.list", url, credential)
            .await?
            .map_page(diff_file_from_value)
    }

    async fn merge_request_raw_diffs(
        &self,
        project_id: u64,
        iid: u64,
        byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        self.get_raw(
            "merge_request.diff.raw.download",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{iid}/raw_diffs"
            ))?,
            byte_cap,
            true,
            credential,
        )
        .await
    }

    async fn merge_request_diff_versions(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffVersionSummary>>, GitlabBackendError>
    {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/versions",
            request.iid
        ))?;
        append_merge_request_list_query(&mut url, &request);
        self.get_json_page("merge_request.diff_version.list", url, credential)
            .await?
            .map_page(diff_version_summary_from_value)
    }

    async fn merge_request_diff_version(
        &self,
        project_id: u64,
        request: GitlabMergeRequestObjectRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiffVersion>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/merge_requests/{}/versions/{}",
            request.iid, request.object_id
        ))?;
        if let Some(unidiff) = request.unidiff {
            url.query_pairs_mut()
                .append_pair("unidiff", if unidiff { "true" } else { "false" });
        }
        let response = self
            .get_json("merge_request.diff_version.view", url, credential)
            .await?;
        Ok(response.map_json(diff_version_from_value)?)
    }

    async fn create_merge_request_discussion(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        let response = self
            .post_json(
                "merge_request.discussion.add",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/discussions",
                    request.iid
                ))?,
                note_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(discussion_from_value)?)
    }

    async fn merge_request_discussion(
        &self,
        project_id: u64,
        iid: u64,
        discussion_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        let response = self
            .get_json(
                "merge_request.discussion.get",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{iid}/discussions/{}",
                    encoded_path_segment(discussion_id)
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(discussion_from_value)?)
    }

    async fn update_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        let response = self
            .put_json(
                "merge_request.discussion.note.update",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/discussions/{}/notes/{}",
                    request.iid,
                    encoded_path_segment(&request.discussion_id),
                    request.note_id
                ))?,
                note_update_body(&request.body),
                credential,
            )
            .await?;
        Ok(response.map_json(note_from_value)?)
    }

    async fn delete_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.delete_no_content(
            "merge_request.discussion.note.delete",
            self.endpoint(&format!(
                "projects/{project_id}/merge_requests/{}/discussions/{}/notes/{}",
                request.iid,
                encoded_path_segment(&request.discussion_id),
                request.note_id
            ))?,
            credential,
        )
        .await
    }

    async fn set_merge_request_discussion_resolved(
        &self,
        project_id: u64,
        request: GitlabDiscussionStateChangeRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        let response = self
            .put_json(
                request.change.operation(),
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/discussions/{}",
                    request.iid,
                    encoded_path_segment(&request.discussion_id)
                ))?,
                discussion_state_change_body(request.change),
                credential,
            )
            .await?;
        Ok(response.map_json(discussion_from_value)?)
    }

    async fn merge_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestMergeRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        let response = self
            .put_json(
                "merge_request.merge",
                self.endpoint(&format!(
                    "projects/{project_id}/merge_requests/{}/merge",
                    request.iid
                ))?,
                merge_request_merge_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(merge_request_from_value)?)
    }

    async fn branches(
        &self,
        project_id: u64,
        request: GitlabBranchListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabBranch>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/repository/branches"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("per_page", &request.max_results.to_string());
            if let Some(search) = &request.search {
                query.append_pair("search", search);
            }
            if let Some(regex) = &request.regex {
                query.append_pair("regex", regex);
            }
        }
        let response = self.get_json("branch.list", url, credential).await?;
        Ok(response.map_json(branch_list_from_value)?)
    }

    async fn branch(
        &self,
        project_id: u64,
        branch: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError> {
        let response = self
            .get_json(
                "branch.view",
                self.endpoint(&format!(
                    "projects/{project_id}/repository/branches/{}",
                    encoded_path_segment(branch)
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(branch_from_value)?)
    }

    async fn create_branch(
        &self,
        project_id: u64,
        request: GitlabBranchCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError> {
        let response = self
            .post_json(
                "branch.create",
                self.endpoint(&format!("projects/{project_id}/repository/branches"))?,
                json!({
                    "branch": request.branch,
                    "ref": request.ref_name,
                }),
                credential,
            )
            .await?;
        Ok(response.map_json(branch_from_value)?)
    }

    async fn protected_branches(
        &self,
        project_id: u64,
        request: GitlabProtectedBranchListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabProtectedBranch>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/protected_branches"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("per_page", &request.max_results.to_string());
            if let Some(search) = &request.search {
                query.append_pair("search", search);
            }
        }
        let started = Instant::now();
        let response = send_gitlab_request(
            &self.client,
            authenticated_gitlab_request(
                self.client.request(Method::GET, url.clone()),
                credential,
            )?
            .header("Accept", "application/json"),
            "protected_branch.list",
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        let status = response.status().as_u16();
        let next_page = response
            .headers()
            .get("x-next-page")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or("");
        let has_next_link = response
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(link_header_has_next_relation));
        if request.fail_on_next_page && (!next_page.is_empty() || has_next_link) {
            return Err(GitlabBackendError::Protocol(
                "GitLab protected branch rule list exceeded one page".to_string(),
            ));
        }
        let value =
            gitlab_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(GitlabBackendResponse {
            value: protected_branch_list_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn protected_branch(
        &self,
        project_id: u64,
        name: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabProtectedBranch>, GitlabBackendError> {
        let response = self
            .get_json(
                "protected_branch.view",
                self.endpoint(&format!(
                    "projects/{project_id}/protected_branches/{}",
                    encoded_path_segment(name)
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(protected_branch_from_value)?)
    }

    async fn file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFile>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/repository/files/{}",
            encoded_path_segment(&request.path)
        ))?;
        url.query_pairs_mut().append_pair("ref", &request.ref_name);
        let response = self.get_json("file.view", url, credential).await?;
        Ok(response.map_json(gitlab_file_from_value)?)
    }

    async fn raw_file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/repository/files/{}/raw",
            encoded_path_segment(&request.path)
        ))?;
        url.query_pairs_mut().append_pair("ref", &request.ref_name);
        self.get_raw("file.raw.download", url, byte_cap, false, credential)
            .await
    }

    async fn create_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        let response = self
            .post_json(
                "file.create",
                self.endpoint(&format!(
                    "projects/{project_id}/repository/files/{}",
                    encoded_path_segment(&request.path)
                ))?,
                file_write_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(gitlab_file_mutation_from_value)?)
    }

    async fn update_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        let response = self
            .put_json(
                "file.update",
                self.endpoint(&format!(
                    "projects/{project_id}/repository/files/{}",
                    encoded_path_segment(&request.path)
                ))?,
                file_write_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(gitlab_file_mutation_from_value)?)
    }

    async fn delete_file(
        &self,
        project_id: u64,
        request: GitlabFileDeleteRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        let response = self
            .delete_json(
                "file.delete",
                self.endpoint(&format!(
                    "projects/{project_id}/repository/files/{}",
                    encoded_path_segment(&request.path)
                ))?,
                file_delete_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(gitlab_file_mutation_from_value)?)
    }

    async fn commits(
        &self,
        project_id: u64,
        request: GitlabCommitListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabCommit>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/repository/commits"))?;
        append_commit_query(&mut url, &request);
        let response = self.get_json("commit.list", url, credential).await?;
        Ok(response.map_json(commit_list_from_value)?)
    }

    async fn commit(
        &self,
        project_id: u64,
        sha: &str,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError> {
        let response = self
            .get_json(
                "commit.view",
                self.endpoint(&format!(
                    "projects/{project_id}/repository/commits/{}",
                    encoded_path_segment(sha)
                ))?,
                credential,
            )
            .await?;
        Ok(response.map_json(commit_from_value)?)
    }

    async fn create_commit(
        &self,
        project_id: u64,
        request: GitlabCommitCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError> {
        let response = self
            .post_json(
                "commit.create",
                self.endpoint(&format!("projects/{project_id}/repository/commits"))?,
                commit_create_body(&request),
                credential,
            )
            .await?;
        Ok(response.map_json(commit_from_value)?)
    }

    async fn pipelines(
        &self,
        project_id: u64,
        request: GitlabPipelineListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabPipeline>>, GitlabBackendError> {
        let mut url = self.endpoint(&format!("projects/{project_id}/pipelines"))?;
        append_pipeline_query(&mut url, &request);
        let response = self.get_json("pipeline.list", url, credential).await?;
        Ok(response.map_json(pipeline_list_from_value)?)
    }

    async fn pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        let response = self
            .get_json(
                "pipeline.view",
                self.endpoint(&format!("projects/{project_id}/pipelines/{pipeline_id}"))?,
                credential,
            )
            .await?;
        Ok(response.map_json(pipeline_from_value)?)
    }

    async fn run_pipeline(
        &self,
        project_id: u64,
        request: GitlabPipelineRunRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        let response = self
            .post_json(
                "pipeline.run",
                self.endpoint(&format!("projects/{project_id}/pipeline"))?,
                json!({ "ref": request.ref_name }),
                credential,
            )
            .await?;
        Ok(response.map_json(pipeline_from_value)?)
    }

    async fn retry_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        let response = self
            .post_json(
                "pipeline.retry",
                self.endpoint(&format!(
                    "projects/{project_id}/pipelines/{pipeline_id}/retry"
                ))?,
                json!({}),
                credential,
            )
            .await?;
        Ok(response.map_json(pipeline_from_value)?)
    }

    async fn cancel_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        let response = self
            .post_json(
                "pipeline.cancel",
                self.endpoint(&format!(
                    "projects/{project_id}/pipelines/{pipeline_id}/cancel"
                ))?,
                json!({}),
                credential,
            )
            .await?;
        Ok(response.map_json(pipeline_from_value)?)
    }

    async fn jobs(
        &self,
        project_id: u64,
        request: GitlabJobListRequest,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabJob>>, GitlabBackendError> {
        let mut url = if let Some(pipeline_id) = request.pipeline_id {
            self.endpoint(&format!(
                "projects/{project_id}/pipelines/{pipeline_id}/jobs"
            ))?
        } else {
            self.endpoint(&format!("projects/{project_id}/jobs"))?
        };
        append_job_query(&mut url, &request);
        let response = self.get_json("job.list", url, credential).await?;
        Ok(response.map_json(job_list_from_value)?)
    }

    async fn job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        let response = self
            .get_json(
                "job.view",
                self.endpoint(&format!("projects/{project_id}/jobs/{job_id}"))?,
                credential,
            )
            .await?;
        Ok(response.map_json(job_from_value)?)
    }

    async fn job_trace(
        &self,
        project_id: u64,
        job_id: u64,
        byte_cap: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        self.get_raw(
            "job.trace.download",
            self.endpoint(&format!("projects/{project_id}/jobs/{job_id}/trace"))?,
            byte_cap,
            false,
            credential,
        )
        .await
    }

    async fn retry_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        let response = self
            .post_json(
                "job.retry",
                self.endpoint(&format!("projects/{project_id}/jobs/{job_id}/retry"))?,
                json!({}),
                credential,
            )
            .await?;
        Ok(response.map_json(job_from_value)?)
    }

    async fn cancel_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        let response = self
            .post_json(
                "job.cancel",
                self.endpoint(&format!("projects/{project_id}/jobs/{job_id}/cancel"))?,
                json!({}),
                credential,
            )
            .await?;
        Ok(response.map_json(job_from_value)?)
    }

    async fn play_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &ExecutionCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        let response = self
            .post_json(
                "job.play",
                self.endpoint(&format!("projects/{project_id}/jobs/{job_id}/play"))?,
                json!({}),
                credential,
            )
            .await?;
        Ok(response.map_json(job_from_value)?)
    }
}

impl GitlabBackendResponse<Value> {
    pub(crate) fn map_json<T>(
        self,
        map: impl FnOnce(Value) -> Result<T, GitlabBackendError>,
    ) -> Result<GitlabBackendResponse<T>, GitlabBackendError> {
        Ok(GitlabBackendResponse {
            value: map(self.value)?,
            status: self.status,
            duration_ms: self.duration_ms,
        })
    }
}

impl GitlabBackendResponse<GitlabPage<Value>> {
    pub(crate) fn map_page<T>(
        self,
        map: impl Fn(Value) -> Result<T, GitlabBackendError>,
    ) -> Result<GitlabBackendResponse<GitlabPage<T>>, GitlabBackendError> {
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: self
                    .value
                    .items
                    .into_iter()
                    .map(map)
                    .collect::<Result<Vec<_>, _>>()?,
                next_page: self.value.next_page,
            },
            status: self.status,
            duration_ms: self.duration_ms,
        })
    }
}

pub(crate) fn append_issue_query(url: &mut Url, request: &GitlabIssueSearchRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_page(&mut query, request.page);
    append_optional(&mut query, "state", request.state.as_deref());
    append_csv(&mut query, "labels", &request.labels);
    append_optional(&mut query, "milestone", request.milestone.as_deref());
    append_optional(&mut query, "assignee_username", request.assignee.as_deref());
    append_optional(&mut query, "author_username", request.author.as_deref());
    append_optional(&mut query, "search", request.search.as_deref());
    append_optional(
        &mut query,
        "created_after",
        request.created_after.as_deref(),
    );
    append_optional(
        &mut query,
        "updated_after",
        request.updated_after.as_deref(),
    );
    append_optional(&mut query, "sort", request.sort.as_deref());
    append_optional(&mut query, "order_by", request.order_by.as_deref());
}

pub(crate) fn append_merge_request_query(url: &mut Url, request: &GitlabMergeRequestSearchRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_page(&mut query, request.page);
    append_optional(&mut query, "state", request.state.as_deref());
    append_optional(
        &mut query,
        "source_branch",
        request.source_branch.as_deref(),
    );
    append_optional(
        &mut query,
        "target_branch",
        request.target_branch.as_deref(),
    );
    append_csv(&mut query, "labels", &request.labels);
    append_optional(&mut query, "milestone", request.milestone.as_deref());
    append_optional(&mut query, "author_username", request.author.as_deref());
    append_optional(&mut query, "assignee_username", request.assignee.as_deref());
    append_optional(&mut query, "reviewer_username", request.reviewer.as_deref());
    append_optional(&mut query, "search", request.search.as_deref());
    append_optional(
        &mut query,
        "created_after",
        request.created_after.as_deref(),
    );
    append_optional(
        &mut query,
        "updated_after",
        request.updated_after.as_deref(),
    );
    append_optional(&mut query, "sort", request.sort.as_deref());
    append_optional(&mut query, "order_by", request.order_by.as_deref());
}

pub(crate) fn append_commit_query(url: &mut Url, request: &GitlabCommitListRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_optional(&mut query, "ref_name", request.ref_name.as_deref());
    append_optional(&mut query, "path", request.path.as_deref());
    append_optional(&mut query, "since", request.since.as_deref());
    append_optional(&mut query, "until", request.until.as_deref());
    if let Some(first_parent) = request.first_parent {
        query.append_pair("first_parent", if first_parent { "true" } else { "false" });
    }
}

pub(crate) fn append_pipeline_query(url: &mut Url, request: &GitlabPipelineListRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_optional(&mut query, "ref", request.ref_name.as_deref());
    append_optional(&mut query, "sha", request.sha.as_deref());
    append_optional(&mut query, "status", request.status.as_deref());
    append_optional(&mut query, "source", request.source.as_deref());
    append_optional(
        &mut query,
        "updated_after",
        request.updated_after.as_deref(),
    );
    append_optional(
        &mut query,
        "updated_before",
        request.updated_before.as_deref(),
    );
}

pub(crate) fn append_job_query(url: &mut Url, request: &GitlabJobListRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_optional(&mut query, "scope[]", request.scope.as_deref());
}

pub(crate) fn append_note_list_query(url: &mut Url, request: &GitlabNoteListRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_page(&mut query, request.page);
    append_optional(&mut query, "sort", request.sort.as_deref());
    append_optional(&mut query, "order_by", request.order_by.as_deref());
}

pub(crate) fn append_page(
    query: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    page: u32,
) {
    if page > 1 {
        query.append_pair("page", &page.to_string());
    }
}

pub(crate) fn append_discussion_list_query(url: &mut Url, request: &GitlabDiscussionListRequest) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_page(&mut query, request.page);
}

pub(crate) fn append_page_query(url: &mut Url, max_results: u32, page: u32) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &max_results.to_string());
    append_page(&mut query, page);
}

pub(crate) fn append_merge_request_list_query(
    url: &mut Url,
    request: &GitlabMergeRequestListRequest,
) {
    let mut query = url.query_pairs_mut();
    query.append_pair("per_page", &request.max_results.to_string());
    append_page(&mut query, request.page);
    if let Some(unidiff) = request.unidiff {
        query.append_pair("unidiff", if unidiff { "true" } else { "false" });
    }
}

pub(crate) fn issue_create_body(request: &GitlabIssueCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("title".to_string(), json!(request.title));
    insert_optional_value(&mut body, "description", request.description.as_ref());
    insert_string_list_value(&mut body, "labels", &request.labels);
    // GitLab accepts `milestone` as an exact title string on issue writes.
    insert_optional_value(&mut body, "milestone", request.milestone.as_ref());
    insert_u64_list_value(&mut body, "assignee_ids", &request.assignee_ids);
    insert_optional_bool_value(&mut body, "confidential", request.confidential);
    Value::Object(body)
}

pub(crate) fn issue_update_body(request: &GitlabIssueUpdateRequest) -> Value {
    let mut body = serde_json::Map::new();
    insert_optional_value(&mut body, "title", request.title.as_ref());
    insert_optional_value(&mut body, "description", request.description.as_ref());
    insert_optional_value(&mut body, "state_event", request.state_event.as_ref());
    insert_string_list_value(&mut body, "labels", &request.labels);
    insert_string_list_value(&mut body, "add_labels", &request.add_labels);
    insert_string_list_value(&mut body, "remove_labels", &request.remove_labels);
    // GitLab accepts `milestone` as an exact title string on issue writes.
    insert_optional_value(&mut body, "milestone", request.milestone.as_ref());
    insert_u64_list_value(&mut body, "assignee_ids", &request.assignee_ids);
    insert_optional_bool_value(&mut body, "confidential", request.confidential);
    Value::Object(body)
}

pub(crate) fn issue_note_create_body(request: &GitlabIssueNoteCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("body".to_string(), json!(request.body));
    insert_optional_bool_value(&mut body, "confidential", request.confidential);
    Value::Object(body)
}

pub(crate) fn note_create_body(request: &GitlabNoteCreateRequest) -> Value {
    json!({ "body": request.body })
}

pub(crate) fn note_update_body(body: &str) -> Value {
    json!({ "body": body })
}

pub(crate) fn positioned_discussion_create_body(
    request: &GitlabPositionedDiscussionCreateRequest,
) -> Value {
    json!({
        "body": request.body,
        "position": diff_position_body(&request.position),
    })
}

pub(crate) fn draft_note_create_body(request: &GitlabDraftNoteCreateRequest) -> Value {
    let mut body = serde_json::Map::from_iter([("note".to_string(), json!(request.body))]);
    if let Some(position) = &request.position {
        body.insert("position".to_string(), diff_position_body(position));
    }
    if let Some(discussion_id) = &request.in_reply_to_discussion_id {
        body.insert(
            "in_reply_to_discussion_id".to_string(),
            json!(discussion_id),
        );
    }
    if let Some(resolve_discussion) = request.resolve_discussion {
        body.insert("resolve_discussion".to_string(), json!(resolve_discussion));
    }
    Value::Object(body)
}

pub(crate) fn draft_note_update_body(request: &GitlabDraftNoteUpdateRequest) -> Value {
    let mut body = serde_json::Map::from_iter([("note".to_string(), json!(request.body))]);
    if let Some(position) = &request.position {
        body.insert("position".to_string(), diff_position_body(position));
    }
    Value::Object(body)
}

pub(crate) fn diff_position_body(position: &GitlabDiffPosition) -> Value {
    let mut body = serde_json::Map::from_iter([
        ("position_type".to_string(), json!(position.position_type)),
        ("base_sha".to_string(), json!(position.base_sha)),
        ("start_sha".to_string(), json!(position.start_sha)),
        ("head_sha".to_string(), json!(position.head_sha)),
        ("old_path".to_string(), json!(position.old_path)),
        ("new_path".to_string(), json!(position.new_path)),
    ]);
    if let Some(old_line) = position.old_line {
        body.insert("old_line".to_string(), json!(old_line));
    }
    if let Some(new_line) = position.new_line {
        body.insert("new_line".to_string(), json!(new_line));
    }
    if let Some(line_range) = &position.line_range {
        body.insert(
            "line_range".to_string(),
            json!({
                "start": line_range_point_body(&line_range.start),
                "end": line_range_point_body(&line_range.end),
            }),
        );
    }
    for (key, value) in [("width", position.width), ("height", position.height)] {
        if let Some(value) = value {
            body.insert(key.to_string(), json!(value));
        }
    }
    for (key, value) in [("x", position.x), ("y", position.y)] {
        if let Some(value) = value {
            body.insert(key.to_string(), json!(value));
        }
    }
    Value::Object(body)
}

pub(crate) fn line_range_point_body(point: &GitlabLineRangePoint) -> Value {
    let mut body = serde_json::Map::from_iter([("line_code".to_string(), json!(point.line_code))]);
    if let Some(line_type) = &point.line_type {
        body.insert("type".to_string(), json!(line_type));
    }
    if let Some(old_line) = point.old_line {
        body.insert("old_line".to_string(), json!(old_line));
    }
    if let Some(new_line) = point.new_line {
        body.insert("new_line".to_string(), json!(new_line));
    }
    Value::Object(body)
}

pub(crate) fn discussion_state_change_body(change: GitlabDiscussionStateChange) -> Value {
    json!({ "resolved": change.resolved() })
}

pub(crate) fn webhook_write_body(request: &GitlabWebhookWriteRequest) -> Value {
    let mut body = serde_json::Map::from_iter([("url".to_string(), json!(request.url))]);
    if let Some(events) = &request.events {
        let enabled = events.iter().copied().collect::<BTreeSet<_>>();
        for event in GitlabWebhookEvent::ALL {
            let parsed: GitlabWebhookEvent =
                serde_json::from_value(json!(event)).expect("static webhook event is valid");
            body.insert(
                parsed.configuration_field().to_string(),
                json!(enabled.contains(&parsed)),
            );
        }
    }
    for (key, value) in [
        ("name", &request.name),
        ("description", &request.description),
        ("custom_webhook_template", &request.custom_webhook_template),
    ] {
        if let Some(value) = value {
            body.insert(key.to_string(), json!(value));
        }
    }
    if let Some(value) = request.enable_ssl_verification {
        body.insert("enable_ssl_verification".to_string(), json!(value));
    }
    if let Some(value) = &request.branch_filter_strategy {
        body.insert("branch_filter_strategy".to_string(), json!(value));
    }
    if let Some(value) = &request.push_events_branch_filter {
        body.insert("push_events_branch_filter".to_string(), json!(value));
    }
    if let Some(value) = &request.token {
        body.insert("token".to_string(), json!(value));
    }
    if let Some(value) = &request.signing_token {
        body.insert("signing_token".to_string(), json!(value));
    }
    Value::Object(body)
}

pub(crate) fn merge_request_create_body(request: &GitlabMergeRequestCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("source_branch".to_string(), json!(request.source_branch));
    body.insert("target_branch".to_string(), json!(request.target_branch));
    body.insert(
        "title".to_string(),
        json!(merge_request_create_title(request)),
    );
    insert_optional_value(&mut body, "description", request.description.as_ref());
    insert_string_list_value(&mut body, "labels", &request.labels);
    insert_u64_list_value(&mut body, "assignee_ids", &request.assignee_ids);
    insert_u64_list_value(&mut body, "reviewer_ids", &request.reviewer_ids);
    insert_optional_bool_value(
        &mut body,
        "remove_source_branch",
        request.remove_source_branch,
    );
    insert_optional_bool_value(&mut body, "squash", request.squash);
    Value::Object(body)
}

pub(crate) fn merge_request_create_title(request: &GitlabMergeRequestCreateRequest) -> String {
    if request.draft == Some(true) && !is_draft_title(&request.title) {
        format!("Draft: {}", request.title)
    } else {
        request.title.clone()
    }
}

pub(crate) fn is_draft_title(title: &str) -> bool {
    let title = title.trim_start();
    title.starts_with("[Draft]") || title.starts_with("Draft:") || title.starts_with("(Draft)")
}

pub(crate) fn merge_request_update_body(request: &GitlabMergeRequestUpdateRequest) -> Value {
    let mut body = serde_json::Map::new();
    insert_optional_value(&mut body, "title", request.title.as_ref());
    insert_optional_value(&mut body, "description", request.description.as_ref());
    insert_optional_value(&mut body, "state_event", request.state_event.as_ref());
    insert_string_list_value(&mut body, "labels", &request.labels);
    insert_string_list_value(&mut body, "add_labels", &request.add_labels);
    insert_string_list_value(&mut body, "remove_labels", &request.remove_labels);
    insert_u64_list_value(&mut body, "assignee_ids", &request.assignee_ids);
    insert_u64_list_value(&mut body, "reviewer_ids", &request.reviewer_ids);
    insert_optional_value(&mut body, "target_branch", request.target_branch.as_ref());
    insert_optional_bool_value(
        &mut body,
        "remove_source_branch",
        request.remove_source_branch,
    );
    insert_optional_bool_value(&mut body, "squash", request.squash);
    Value::Object(body)
}

pub(crate) fn merge_request_merge_body(request: &GitlabMergeRequestMergeRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("sha".to_string(), json!(request.sha));
    insert_optional_bool_value(&mut body, "squash", request.squash);
    insert_optional_bool_value(
        &mut body,
        "should_remove_source_branch",
        request.should_remove_source_branch,
    );
    insert_optional_value(
        &mut body,
        "merge_commit_message",
        request.merge_commit_message.as_ref(),
    );
    insert_optional_value(
        &mut body,
        "squash_commit_message",
        request.squash_commit_message.as_ref(),
    );
    Value::Object(body)
}

pub(crate) fn file_write_body(request: &GitlabFileWriteRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("branch".to_string(), json!(request.branch));
    body.insert("content".to_string(), json!(request.content));
    body.insert("commit_message".to_string(), json!(request.commit_message));
    insert_optional_value(&mut body, "start_branch", request.start_branch.as_ref());
    insert_optional_value(&mut body, "author_name", request.author_name.as_ref());
    insert_optional_value(&mut body, "author_email", request.author_email.as_ref());
    insert_optional_value(&mut body, "encoding", request.encoding.as_ref());
    insert_optional_bool_value(&mut body, "execute_filemode", request.execute_filemode);
    insert_optional_value(&mut body, "last_commit_id", request.last_commit_id.as_ref());
    Value::Object(body)
}

pub(crate) fn file_delete_body(request: &GitlabFileDeleteRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("branch".to_string(), json!(request.branch));
    body.insert("commit_message".to_string(), json!(request.commit_message));
    insert_optional_value(&mut body, "start_branch", request.start_branch.as_ref());
    insert_optional_value(&mut body, "author_name", request.author_name.as_ref());
    insert_optional_value(&mut body, "author_email", request.author_email.as_ref());
    insert_optional_value(&mut body, "last_commit_id", request.last_commit_id.as_ref());
    Value::Object(body)
}

pub(crate) fn commit_create_body(request: &GitlabCommitCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("branch".to_string(), json!(request.branch));
    body.insert("commit_message".to_string(), json!(request.commit_message));
    insert_optional_value(&mut body, "start_branch", request.start_branch.as_ref());
    insert_optional_value(&mut body, "start_sha", request.start_sha.as_ref());
    insert_optional_value(&mut body, "author_name", request.author_name.as_ref());
    insert_optional_value(&mut body, "author_email", request.author_email.as_ref());
    body.insert(
        "actions".to_string(),
        json!(
            request
                .actions
                .iter()
                .map(commit_action_body)
                .collect::<Vec<_>>()
        ),
    );
    Value::Object(body)
}

pub(crate) fn commit_action_body(action: &GitlabCommitActionRequest) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("action".to_string(), json!(action.action));
    body.insert("file_path".to_string(), json!(action.file_path));
    insert_optional_value(&mut body, "previous_path", action.previous_path.as_ref());
    insert_optional_value(&mut body, "content", action.content.as_ref());
    insert_optional_value(&mut body, "encoding", action.encoding.as_ref());
    insert_optional_bool_value(&mut body, "execute_filemode", action.execute_filemode);
    insert_optional_value(&mut body, "last_commit_id", action.last_commit_id.as_ref());
    Value::Object(body)
}

pub(crate) fn insert_optional_value(
    body: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<&String>,
) {
    if let Some(value) = value {
        body.insert(key.to_string(), json!(value));
    }
}

pub(crate) fn insert_string_list_value(
    body: &mut serde_json::Map<String, Value>,
    key: &str,
    values: &[String],
) {
    if !values.is_empty() {
        body.insert(key.to_string(), json!(values.join(",")));
    }
}

pub(crate) fn insert_u64_list_value(
    body: &mut serde_json::Map<String, Value>,
    key: &str,
    values: &[u64],
) {
    if !values.is_empty() {
        body.insert(key.to_string(), json!(values));
    }
}

pub(crate) fn insert_optional_bool_value(
    body: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        body.insert(key.to_string(), json!(value));
    }
}

pub(crate) fn append_optional(
    query: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    key: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        query.append_pair(key, value);
    }
}

pub(crate) fn append_csv(
    query: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    key: &str,
    values: &[String],
) {
    if !values.is_empty() {
        query.append_pair(key, &values.join(","));
    }
}

pub(crate) fn normalized_api_base(value: &str) -> Result<Url, url::ParseError> {
    let mut url = Url::parse(value)?;
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

pub(crate) fn authenticated_gitlab_request(
    builder: reqwest::RequestBuilder,
    credential: &ExecutionCredential,
) -> Result<reqwest::RequestBuilder, GitlabBackendError> {
    match credential.kind.as_str() {
        "bearer_token" => Ok(builder.bearer_auth(
            credential
                .token
                .as_deref()
                .ok_or_else(|| GitlabBackendError::Protocol("bearer token missing".to_string()))?,
        )),
        _ => Err(GitlabBackendError::Protocol(
            "unsupported GitLab credential kind".to_string(),
        )),
    }
}

pub(crate) async fn send_gitlab_upload(
    client: &UpstreamClient,
    request: reqwest::RequestBuilder,
    operation: &str,
    progress: UploadProgress,
    idle_timeout: Duration,
    response_byte_cap: u64,
) -> Result<reqwest::Response, GitlabBackendError> {
    // Upload responses expose no upstream validation bodies.
    let mut response = client
        .send_upload(
            request,
            Some(progress),
            idle_timeout,
            UpstreamCall::new(operation),
        )
        .await
        .map_err(gitlab_upstream_error)?;
    complete_upstream_trace(&mut response, None);
    map_gitlab_status(response, None, response_byte_cap).await
}

/// Sends through `client`, records the trace with the response status, and
/// maps error statuses.
pub(crate) async fn send_gitlab_request(
    client: &UpstreamClient,
    request: reqwest::RequestBuilder,
    operation: &str,
    validation_fields: Option<&'static [&'static str]>,
    response_byte_cap: u64,
) -> Result<reqwest::Response, GitlabBackendError> {
    let mut response = client
        .send(request, UpstreamCall::new(operation))
        .await
        .map_err(gitlab_upstream_error)?;
    complete_upstream_trace(&mut response, None);
    map_gitlab_status(response, validation_fields, response_byte_cap).await
}

pub(crate) fn gitlab_upstream_error(error: UpstreamError) -> GitlabBackendError {
    match error {
        // A request that never reached the upstream fails as it always has:
        // connect timeouts as timeouts, everything else as transport errors.
        UpstreamError::Timeout
        | UpstreamError::NotSent {
            timed_out: true, ..
        } => GitlabBackendError::Timeout,
        UpstreamError::Transport(message)
        | UpstreamError::NotSent {
            detail: message, ..
        } => GitlabBackendError::Transport(message),
        UpstreamError::NotAllowed | UpstreamError::Redirect => {
            GitlabBackendError::Protocol("GitLab upstream URL is not allowlisted".to_string())
        }
    }
}

pub(crate) async fn map_gitlab_status(
    response: reqwest::Response,
    validation_fields: Option<&[&str]>,
    response_byte_cap: u64,
) -> Result<reqwest::Response, GitlabBackendError> {
    let status = response.status().as_u16();
    match status {
        200..=299 => Ok(response),
        401 => Err(GitlabBackendError::Unauthorized),
        403 => Err(GitlabBackendError::Forbidden),
        404 => Err(GitlabBackendError::NotFound),
        429 => Err(GitlabBackendError::RateLimited(
            UpstreamRetryAfter::from_headers(response.headers()),
        )),
        400 | 422 if validation_fields.is_some() && response_has_json_content_type(&response) => {
            let message = read_validation_json(response, response_byte_cap)
                .await
                .as_ref()
                .and_then(|value| {
                    gitlab_validation_message(value, validation_fields.unwrap_or_default())
                });
            match message {
                Some(message) => Err(GitlabBackendError::Validation { status, message }),
                None => Err(GitlabBackendError::HttpStatus(status)),
            }
        }
        _ => Err(GitlabBackendError::HttpStatus(status)),
    }
}

pub(crate) fn gitlab_validation_fields(operation: &str) -> Option<&'static [&'static str]> {
    match operation {
        "issue.create" | "issue.update" => Some(GITLAB_ISSUE_VALIDATION_FIELDS),
        "issue.note.add"
        | "issue.note.update"
        | "merge_request.note.add"
        | "merge_request.note.update"
        | "merge_request.discussion.add"
        | "merge_request.discussion.note.add"
        | "merge_request.discussion.note.update"
        | "merge_request.review.summary.add" => Some(GITLAB_NOTE_VALIDATION_FIELDS),
        "merge_request.discussion.inline.add" => Some(GITLAB_POSITIONED_NOTE_VALIDATION_FIELDS),
        "merge_request.draft_note.add"
        | "merge_request.draft_note.update"
        | "merge_request.draft_note.publish"
        | "merge_request.draft_note.publish_all"
        | "merge_request.review.submit" => Some(GITLAB_DRAFT_NOTE_VALIDATION_FIELDS),
        "merge_request.create" | "merge_request.update" | "merge_request.merge" => {
            Some(GITLAB_MERGE_REQUEST_VALIDATION_FIELDS)
        }
        "file.create" | "file.update" | "file.delete" => Some(GITLAB_FILE_VALIDATION_FIELDS),
        "commit.create" => Some(GITLAB_COMMIT_VALIDATION_FIELDS),
        _ => None,
    }
}

// Uploads have no fixed request deadline: active transfers may outlast the idle
// window. Bound each response read separately after headers have arrived.
pub(crate) async fn gitlab_upload_response_value(
    mut response: reqwest::Response,
    byte_cap: u64,
    idle_timeout: Duration,
) -> Result<Value, GitlabBackendError> {
    validate_gitlab_body_response(&response, byte_cap)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(idle_timeout, response.chunk())
        .await
        .map_err(|_| GitlabBackendError::Timeout)?
        .map_err(|error| GitlabBackendError::Transport(error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) as u64 > byte_cap {
            return Err(GitlabBackendError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GitlabBackendError::Protocol("GitLab upload response is invalid".to_string()))
}

pub(crate) async fn gitlab_response_value(
    mut response: reqwest::Response,
    byte_cap: u64,
) -> Result<Value, GitlabBackendError> {
    validate_gitlab_body_response(&response, byte_cap)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| GitlabBackendError::Transport(error.to_string()))?
    {
        let next_len = bytes.len() + chunk.len();
        if next_len as u64 > byte_cap {
            return Err(GitlabBackendError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|error| GitlabBackendError::Protocol(error.to_string()))
}

pub(crate) async fn gitlab_response_empty(
    mut response: reqwest::Response,
) -> Result<(), GitlabBackendError> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|length| length.to_str().ok())
        .and_then(|length| length.parse::<u64>().ok())
        .is_some_and(|length| length > 0)
    {
        return Err(GitlabBackendError::Protocol(
            "GitLab no-content response included a body".to_string(),
        ));
    }
    if response.content_length().is_some_and(|length| length > 0) {
        return Err(GitlabBackendError::Protocol(
            "GitLab no-content response included a body".to_string(),
        ));
    }
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| GitlabBackendError::Transport(error.to_string()))?
    {
        if !chunk.is_empty() {
            return Err(GitlabBackendError::Protocol(
                "GitLab no-content response included a body".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn gitlab_response_stream(
    response: reqwest::Response,
    byte_cap: u64,
    idle_timeout: Duration,
    expected_size: Option<u64>,
    content_type: String,
) -> ProviderResultStream {
    let stream = stream::try_unfold((response, 0_u64), move |(mut response, size)| async move {
        let chunk = tokio::time::timeout(idle_timeout, response.chunk())
            .await
            .map_err(|_| {
                ProviderStreamError::new(ReasonCode::UpstreamTimeout, "GitLab download stalled")
            })?
            .map_err(|error| {
                ProviderStreamError::new(
                    ReasonCode::UpstreamConnectionFailed,
                    format!("GitLab download failed: {error}"),
                )
            })?;
        let Some(chunk) = chunk else {
            if expected_size.is_some_and(|expected_size| expected_size != size) {
                return Err(ProviderStreamError::new(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab download response size did not match Content-Length",
                ));
            }
            return Ok(None);
        };
        let next_size = size.checked_add(chunk.len() as u64).ok_or_else(|| {
            ProviderStreamError::new(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab download response exceeded the configured byte cap",
            )
        })?;
        if next_size > byte_cap {
            return Err(ProviderStreamError::new(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab download response exceeded the configured byte cap",
            ));
        }
        Ok(Some((chunk, (response, next_size))))
    });
    ProviderResultStream::from_stream(content_type, stream)
}

pub(crate) fn validate_gitlab_body_response(
    response: &reqwest::Response,
    byte_cap: u64,
) -> Result<(), GitlabBackendError> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > byte_cap)
    {
        return Err(GitlabBackendError::ResponseTooLarge);
    }
    Ok(())
}

pub(crate) fn user_from_value(value: Value) -> Result<GitlabUser, GitlabBackendError> {
    Ok(GitlabUser {
        id: required_u64(&value, "id")?,
        username: required_string(&value, "username")?,
        name: optional_string(&value, "name"),
    })
}

pub(crate) fn project_from_value(value: Value) -> Result<GitlabProject, GitlabBackendError> {
    let path_with_namespace = required_string(&value, "path_with_namespace")?;
    if !crate::is_canonical_repository_path(&path_with_namespace) {
        return Err(GitlabBackendError::Protocol(
            "GitLab project response did not include a canonical repository path".to_string(),
        ));
    }
    Ok(GitlabProject {
        id: required_u64(&value, "id")?,
        path_with_namespace,
        name: optional_string(&value, "name"),
        web_url: optional_string(&value, "web_url"),
        default_branch: optional_string(&value, "default_branch"),
        visibility: optional_string(&value, "visibility"),
        archived: value.get("archived").and_then(Value::as_bool),
    })
}

pub(crate) fn webhook_from_value(value: Value) -> Result<GitlabWebhook, GitlabBackendError> {
    let object = value.as_object().ok_or_else(|| {
        GitlabBackendError::Protocol("GitLab webhook response is not an object".to_string())
    })?;
    let mut events = Vec::new();
    let known_fields = GitlabWebhookEvent::ALL
        .into_iter()
        .map(|name| {
            let event: GitlabWebhookEvent =
                serde_json::from_value(json!(name)).expect("static webhook event is valid");
            (event.configuration_field(), event)
        })
        .collect::<BTreeMap<_, _>>();
    for (field, event) in &known_fields {
        match object.get(*field) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => events.push(*event),
            Some(_) => {
                return Err(GitlabBackendError::Protocol(format!(
                    "GitLab webhook {field} is not a boolean"
                )));
            }
        }
    }
    for (key, raw) in object {
        if key.ends_with("_events") && !known_fields.contains_key(key.as_str()) {
            if key == "repository_update_events" && matches!(raw, Value::Bool(false) | Value::Null)
            {
                continue;
            }
            return Err(GitlabBackendError::Protocol(format!(
                "GitLab webhook contains unsupported event field {key}"
            )));
        }
    }
    events.sort_unstable();
    events.dedup();
    Ok(GitlabWebhook {
        id: required_u64(&value, "id")?,
        project_id: optional_json_u64_strict(&value, "project_id")?,
        url: required_string(&value, "url")?,
        name: optional_string_strict(&value, "name")?,
        description: optional_string_strict(&value, "description")?,
        created_at: optional_string_strict(&value, "created_at")?,
        enable_ssl_verification: optional_bool_strict(&value, "enable_ssl_verification")?,
        alert_status: optional_string_strict(&value, "alert_status")?,
        disabled_until: optional_string_strict(&value, "disabled_until")?,
        events,
        branch_filter_strategy: optional_string_strict(&value, "branch_filter_strategy")?,
        push_events_branch_filter: optional_string_strict(&value, "push_events_branch_filter")?,
        custom_webhook_template: optional_string_strict(&value, "custom_webhook_template")?,
        custom_headers: optional_webhook_named_secrets(&value, "custom_headers")?,
        url_variables: optional_webhook_named_secrets(&value, "url_variables")?,
        token_present: optional_bool_strict(&value, "token_present")?,
        signing_token_present: optional_bool_strict(&value, "signing_token_present")?,
    })
}

pub(crate) fn optional_webhook_named_secrets(
    value: &Value,
    key: &str,
) -> Result<Option<Vec<GitlabWebhookNamedSecret>>, GitlabBackendError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(Some(Vec::new()));
    }
    let items = raw.as_array().ok_or_else(|| {
        GitlabBackendError::Protocol(format!("GitLab webhook {key} is not an array"))
    })?;
    let mut names = BTreeSet::new();
    for item in items {
        let name = required_string(item, "key")?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(GitlabBackendError::Protocol(format!(
                "GitLab webhook {key} includes an invalid name"
            )));
        }
        names.insert(name);
    }
    Ok(Some(
        names
            .into_iter()
            .map(|key| GitlabWebhookNamedSecret { key })
            .collect(),
    ))
}

pub(crate) fn webhook_test_attempt_from_value(
    value: Value,
) -> Result<GitlabWebhookDeliveryAttempt, GitlabBackendError> {
    let message = required_string(&value, "message")?;
    if message != "201 Created" {
        return Err(GitlabBackendError::Protocol(
            "GitLab webhook test response message was unexpected".to_string(),
        ));
    }
    Ok(GitlabWebhookDeliveryAttempt {
        message: Some(message),
        response_status: None,
    })
}

pub(crate) fn webhook_resend_attempt_from_value(
    value: Value,
) -> Result<GitlabWebhookDeliveryAttempt, GitlabBackendError> {
    Ok(GitlabWebhookDeliveryAttempt {
        message: optional_string_strict(&value, "message")?,
        response_status: optional_json_u64_strict(&value, "response_status")?
            .map(|status| {
                u16::try_from(status).map_err(|_| {
                    GitlabBackendError::Protocol(
                        "GitLab webhook response_status is out of range".to_string(),
                    )
                })
            })
            .transpose()?,
    })
}

pub(crate) fn webhook_delivery_event_from_value(
    value: Value,
    redacted_header_names: &BTreeSet<String>,
    field_byte_cap: u64,
) -> Result<GitlabWebhookDeliveryEvent, GitlabBackendError> {
    let request_data_raw = value
        .get("request_data")
        .cloned()
        .filter(|value| !value.is_null());
    let request_data_truncated = request_data_raw.as_ref().is_some_and(|value| {
        serde_json::to_vec(value)
            .map(|bytes| bytes.len() as u64 > field_byte_cap)
            .unwrap_or(true)
    });
    let request_data = (!request_data_truncated)
        .then_some(request_data_raw)
        .flatten();
    let raw_body = optional_string_strict(&value, "response_body")?;
    let (response_body, response_body_truncated) = raw_body
        .map(|body| truncate_utf8(body, field_byte_cap as usize))
        .map(|(body, truncated)| (Some(body), truncated))
        .unwrap_or((None, false));
    Ok(GitlabWebhookDeliveryEvent {
        id: required_u64(&value, "id")?,
        trigger: optional_string_strict(&value, "trigger")?,
        created_at: optional_string_strict(&value, "created_at")?,
        execution_duration: optional_f64_strict(&value, "execution_duration")?,
        response_status: optional_string_strict(&value, "response_status")?,
        request_headers: webhook_delivery_headers(
            value.get("request_headers"),
            redacted_header_names,
        )?,
        request_data,
        request_data_truncated,
        response_headers: webhook_delivery_headers(
            value.get("response_headers"),
            redacted_header_names,
        )?,
        response_body,
        response_body_truncated,
    })
}

pub(crate) fn optional_f64_strict(
    value: &Value,
    key: &str,
) -> Result<Option<f64>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not a finite number"))),
    }
}

pub(crate) fn webhook_delivery_headers(
    value: Option<&Value>,
    redacted_header_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, GitlabBackendError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or_else(|| {
        GitlabBackendError::Protocol(
            "GitLab webhook delivery headers are not an object".to_string(),
        )
    })?;
    let mut headers = BTreeMap::new();
    for (name, raw) in object {
        if name.chars().any(char::is_control) {
            return Err(GitlabBackendError::Protocol(
                "GitLab webhook delivery header name is invalid".to_string(),
            ));
        }
        let value = raw.as_str().ok_or_else(|| {
            GitlabBackendError::Protocol(
                "GitLab webhook delivery header value is not a string".to_string(),
            )
        })?;
        if value.chars().any(char::is_control) {
            return Err(GitlabBackendError::Protocol(
                "GitLab webhook delivery header value is invalid".to_string(),
            ));
        }
        let lower = name.to_ascii_lowercase();
        let sensitive = redacted_header_names.contains(&lower)
            || [
                "authorization",
                "cookie",
                "token",
                "key",
                "secret",
                "password",
                "session",
                "credential",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
        headers.insert(
            name.clone(),
            if sensitive {
                "[REDACTED]".to_string()
            } else {
                value.to_string()
            },
        );
    }
    Ok(headers)
}

pub(crate) fn truncate_utf8(mut value: String, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut end = max_bytes.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    (value, true)
}

pub(crate) fn gitlab_user_summary_from_value(value: &Value) -> Option<GitlabUserSummary> {
    if !value.is_object() {
        return None;
    }
    let summary = GitlabUserSummary {
        id: optional_u64(value, "id"),
        username: optional_string(value, "username"),
        name: optional_string(value, "name"),
        web_url: optional_string(value, "web_url"),
    };
    (summary.id.is_some()
        || summary.username.is_some()
        || summary.name.is_some()
        || summary.web_url.is_some())
    .then_some(summary)
}

pub(crate) fn optional_gitlab_user_summary(value: &Value, key: &str) -> Option<GitlabUserSummary> {
    value.get(key).and_then(gitlab_user_summary_from_value)
}

pub(crate) fn optional_gitlab_user_summary_list(
    value: &Value,
    key: &str,
) -> Option<Vec<GitlabUserSummary>> {
    let raw = value.get(key)?;
    let values = raw.as_array()?;
    let summaries = values
        .iter()
        .filter_map(gitlab_user_summary_from_value)
        .collect::<Vec<_>>();
    (values.is_empty() || !summaries.is_empty()).then_some(summaries)
}

pub(crate) fn optional_gitlab_labels(value: &Value) -> Option<Vec<String>> {
    value
        .get("labels")?
        .as_array()?
        .iter()
        .map(|label| label.as_str().map(ToString::to_string))
        .collect()
}

pub(crate) fn optional_gitlab_milestone(value: &Value) -> Option<GitlabMilestoneSummary> {
    let raw = value.get("milestone")?;
    if !raw.is_object() {
        return None;
    }
    let milestone = GitlabMilestoneSummary {
        id: optional_u64(raw, "id"),
        iid: optional_u64(raw, "iid"),
        title: optional_string(raw, "title"),
        state: optional_string(raw, "state"),
        due_date: optional_string(raw, "due_date"),
    };
    (milestone.id.is_some()
        || milestone.iid.is_some()
        || milestone.title.is_some()
        || milestone.state.is_some()
        || milestone.due_date.is_some())
    .then_some(milestone)
}

pub(crate) fn issue_from_value(value: Value) -> Result<GitlabIssue, GitlabBackendError> {
    Ok(GitlabIssue {
        id: optional_u64(&value, "id"),
        iid: required_u64(&value, "iid")?,
        project_id: required_u64(&value, "project_id")?,
        title: optional_string(&value, "title"),
        description: optional_string(&value, "description"),
        state: optional_string(&value, "state"),
        web_url: optional_string(&value, "web_url"),
        created_at: optional_string(&value, "created_at"),
        updated_at: optional_string(&value, "updated_at"),
        author: optional_gitlab_user_summary(&value, "author"),
        assignees: optional_gitlab_user_summary_list(&value, "assignees"),
        labels: optional_gitlab_labels(&value),
        milestone: optional_gitlab_milestone(&value),
        project: None,
    })
}

pub(crate) fn merge_request_from_value(
    value: Value,
) -> Result<GitlabMergeRequest, GitlabBackendError> {
    Ok(GitlabMergeRequest {
        id: optional_u64(&value, "id"),
        iid: required_u64(&value, "iid")?,
        project_id: required_u64(&value, "project_id")?,
        title: optional_string(&value, "title"),
        description: optional_string(&value, "description"),
        state: optional_string(&value, "state"),
        source_branch: optional_string(&value, "source_branch"),
        target_branch: optional_string(&value, "target_branch"),
        sha: optional_string(&value, "sha"),
        merge_status: optional_string(&value, "merge_status"),
        detailed_merge_status: optional_string(&value, "detailed_merge_status"),
        merge_commit_sha: optional_string(&value, "merge_commit_sha"),
        squash_commit_sha: optional_string(&value, "squash_commit_sha"),
        source_project_id: optional_u64(&value, "source_project_id"),
        target_project_id: optional_u64(&value, "target_project_id"),
        diff_refs: optional_diff_refs(&value)?,
        changes_count: optional_string(&value, "changes_count"),
        user_notes_count: optional_u64(&value, "user_notes_count"),
        discussion_locked: optional_bool_strict(&value, "discussion_locked")?,
        blocking_discussions_resolved: optional_bool_strict(
            &value,
            "blocking_discussions_resolved",
        )?,
        has_conflicts: optional_bool_strict(&value, "has_conflicts")?,
        prepared_at: optional_string(&value, "prepared_at"),
        head_pipeline: optional_pipeline_summary(&value)?,
        web_url: optional_string(&value, "web_url"),
        created_at: optional_string(&value, "created_at"),
        updated_at: optional_string(&value, "updated_at"),
        author: optional_gitlab_user_summary(&value, "author"),
        assignees: optional_gitlab_user_summary_list(&value, "assignees"),
        reviewers: optional_gitlab_user_summary_list(&value, "reviewers"),
        labels: optional_gitlab_labels(&value),
        milestone: optional_gitlab_milestone(&value),
        draft: value
            .get("draft")
            .or_else(|| value.get("work_in_progress"))
            .and_then(Value::as_bool),
        project: None,
    })
}

pub(crate) fn note_from_value(value: Value) -> Result<GitlabNote, GitlabBackendError> {
    let author_user_id = value
        .get("author")
        .and_then(|author| author.get("id"))
        .and_then(Value::as_u64);
    let author_username = value
        .get("author")
        .and_then(|author| author.get("username"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok(GitlabNote {
        id: required_u64(&value, "id")?,
        body: optional_string(&value, "body"),
        noteable_type: optional_string(&value, "noteable_type"),
        noteable_iid: optional_u64(&value, "noteable_iid"),
        noteable_id: optional_u64(&value, "noteable_id"),
        project_id: optional_u64(&value, "project_id"),
        resolved: value.get("resolved").and_then(Value::as_bool),
        resolvable: value.get("resolvable").and_then(Value::as_bool),
        note_type: optional_string(&value, "type"),
        commit_id: optional_string(&value, "commit_id"),
        position: optional_diff_position(&value)?,
        resolved_by: optional_user_summary_strict(&value, "resolved_by")?,
        resolved_at: optional_string(&value, "resolved_at"),
        suggestions: optional_suggestions(&value)?,
        author_user_id,
        author_username,
        created_at: optional_string(&value, "created_at"),
        updated_at: optional_string(&value, "updated_at"),
        system: value.get("system").and_then(Value::as_bool),
        confidential: value.get("confidential").and_then(Value::as_bool),
    })
}

pub(crate) fn optional_diff_refs(
    value: &Value,
) -> Result<Option<GitlabDiffRefs>, GitlabBackendError> {
    let Some(raw) = value.get("diff_refs") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if !raw.is_object() {
        return Err(GitlabBackendError::Protocol(
            "merge request diff_refs is not an object".to_string(),
        ));
    }
    Ok(Some(GitlabDiffRefs {
        base_sha: optional_string_strict(raw, "base_sha")?,
        start_sha: required_string(raw, "start_sha")?,
        head_sha: required_string(raw, "head_sha")?,
    }))
}

pub(crate) fn optional_pipeline_summary(
    value: &Value,
) -> Result<Option<GitlabPipelineSummary>, GitlabBackendError> {
    let Some(raw) = value.get("head_pipeline") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if !raw.is_object() {
        return Err(GitlabBackendError::Protocol(
            "merge request head_pipeline is not an object".to_string(),
        ));
    }
    Ok(Some(GitlabPipelineSummary {
        id: required_u64(raw, "id")?,
        sha: optional_string(raw, "sha"),
        ref_name: optional_string(raw, "ref"),
        status: optional_string(raw, "status"),
        web_url: optional_string(raw, "web_url"),
    }))
}

pub(crate) fn optional_bool_strict(
    value: &Value,
    key: &str,
) -> Result<Option<bool>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_bool()
            .map(Some)
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not a boolean"))),
    }
}

pub(crate) fn optional_user_summary_strict(
    value: &Value,
    key: &str,
) -> Result<Option<GitlabUserSummary>, GitlabBackendError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    gitlab_user_summary_from_value(raw)
        .map(Some)
        .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not a GitLab user object")))
}

pub(crate) fn optional_diff_position(
    value: &Value,
) -> Result<Option<GitlabDiffPosition>, GitlabBackendError> {
    let Some(raw) = value.get("position") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if !raw.is_object() {
        return Err(GitlabBackendError::Protocol(
            "note position is not an object".to_string(),
        ));
    }
    Ok(Some(GitlabDiffPosition {
        position_type: required_string(raw, "position_type")?,
        base_sha: optional_string_strict(raw, "base_sha")?,
        start_sha: required_string(raw, "start_sha")?,
        head_sha: required_string(raw, "head_sha")?,
        old_path: required_string(raw, "old_path")?,
        new_path: required_string(raw, "new_path")?,
        old_line: optional_u64_strict(raw, "old_line")?,
        new_line: optional_u64_strict(raw, "new_line")?,
        line_range: optional_line_range(raw)?,
        width: optional_json_u64_strict(raw, "width")?,
        height: optional_json_u64_strict(raw, "height")?,
        x: optional_json_u64_strict(raw, "x")?,
        y: optional_json_u64_strict(raw, "y")?,
    }))
}

pub(crate) fn optional_line_range(
    value: &Value,
) -> Result<Option<GitlabLineRange>, GitlabBackendError> {
    let Some(raw) = value.get("line_range") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let start = raw.get("start").ok_or_else(|| {
        GitlabBackendError::Protocol("position line_range start missing".to_string())
    })?;
    let end = raw.get("end").ok_or_else(|| {
        GitlabBackendError::Protocol("position line_range end missing".to_string())
    })?;
    if !raw.is_object() || !start.is_object() || !end.is_object() {
        return Err(GitlabBackendError::Protocol(
            "position line_range is malformed".to_string(),
        ));
    }
    Ok(Some(GitlabLineRange {
        start: line_range_point_from_value(start)?,
        end: line_range_point_from_value(end)?,
    }))
}

pub(crate) fn line_range_point_from_value(
    value: &Value,
) -> Result<GitlabLineRangePoint, GitlabBackendError> {
    Ok(GitlabLineRangePoint {
        line_code: required_string(value, "line_code")?,
        line_type: optional_string_strict(value, "type")?,
        old_line: optional_u64_strict(value, "old_line")?,
        new_line: optional_u64_strict(value, "new_line")?,
    })
}

pub(crate) fn optional_suggestions(
    value: &Value,
) -> Result<Vec<GitlabSuggestion>, GitlabBackendError> {
    let Some(raw) = value.get("suggestions") else {
        return Ok(Vec::new());
    };
    let values = raw.as_array().ok_or_else(|| {
        GitlabBackendError::Protocol("note suggestions is not an array".to_string())
    })?;
    values.iter().map(suggestion_from_value).collect()
}

pub(crate) fn suggestion_from_value(value: &Value) -> Result<GitlabSuggestion, GitlabBackendError> {
    if !value.is_object() {
        return Err(GitlabBackendError::Protocol(
            "note suggestion is not an object".to_string(),
        ));
    }
    let applicable = value
        .get("applicable")
        .or_else(|| value.get("appliable"))
        .and_then(Value::as_bool)
        .ok_or_else(|| GitlabBackendError::Protocol("suggestion applicable missing".to_string()))?;
    Ok(GitlabSuggestion {
        id: required_u64(value, "id")?,
        from_line: required_u64(value, "from_line")?,
        to_line: required_u64(value, "to_line")?,
        applicable,
        applied: value
            .get("applied")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                GitlabBackendError::Protocol("suggestion applied missing".to_string())
            })?,
        from_content: required_string(value, "from_content")?,
        to_content: required_string(value, "to_content")?,
    })
}

pub(crate) fn reviewer_from_value(value: Value) -> Result<GitlabReviewer, GitlabBackendError> {
    let user = value
        .get("user")
        .and_then(gitlab_user_summary_from_value)
        .ok_or_else(|| GitlabBackendError::Protocol("reviewer user missing".to_string()))?;
    let state = required_string(&value, "state")?;
    if state.is_empty() {
        return Err(GitlabBackendError::Protocol(
            "reviewer state is empty".to_string(),
        ));
    }
    Ok(GitlabReviewer {
        user,
        state,
        created_at: optional_string(&value, "created_at"),
    })
}

pub(crate) fn diff_file_from_value(value: Value) -> Result<GitlabDiffFile, GitlabBackendError> {
    Ok(GitlabDiffFile {
        old_path: required_string(&value, "old_path")?,
        new_path: required_string(&value, "new_path")?,
        old_mode: optional_string(&value, "a_mode"),
        new_mode: optional_string(&value, "b_mode"),
        diff: optional_string(&value, "diff"),
        new_file: optional_bool_strict(&value, "new_file")?,
        renamed_file: optional_bool_strict(&value, "renamed_file")?,
        deleted_file: optional_bool_strict(&value, "deleted_file")?,
        generated_file: optional_bool_strict(&value, "generated_file")?,
        collapsed: optional_bool_strict(&value, "collapsed")?,
        too_large: optional_bool_strict(&value, "too_large")?,
    })
}

pub(crate) fn diff_version_from_value(
    value: Value,
) -> Result<GitlabDiffVersion, GitlabBackendError> {
    let commits = optional_parsed_array(&value, "commits", commit_from_value)?;
    let diffs = optional_parsed_array(&value, "diffs", diff_file_from_value)?;
    Ok(GitlabDiffVersion {
        id: required_u64(&value, "id")?,
        merge_request_id: required_u64(&value, "merge_request_id")?,
        head_commit_sha: required_string(&value, "head_commit_sha")?,
        base_commit_sha: required_string(&value, "base_commit_sha")?,
        start_commit_sha: required_string(&value, "start_commit_sha")?,
        created_at: optional_string(&value, "created_at"),
        state: optional_string(&value, "state"),
        real_size: optional_string(&value, "real_size"),
        patch_id_sha: optional_string(&value, "patch_id_sha"),
        commits,
        diffs,
    })
}

pub(crate) fn diff_version_summary_from_value(
    value: Value,
) -> Result<GitlabDiffVersionSummary, GitlabBackendError> {
    Ok(GitlabDiffVersionSummary {
        id: required_u64(&value, "id")?,
        merge_request_id: required_u64(&value, "merge_request_id")?,
        head_commit_sha: required_string(&value, "head_commit_sha")?,
        base_commit_sha: required_string(&value, "base_commit_sha")?,
        start_commit_sha: required_string(&value, "start_commit_sha")?,
        created_at: optional_string(&value, "created_at"),
        state: optional_string(&value, "state"),
        real_size: optional_string(&value, "real_size"),
        patch_id_sha: optional_string(&value, "patch_id_sha"),
    })
}

pub(crate) fn optional_parsed_array<T>(
    value: &Value,
    key: &str,
    parse: impl Fn(Value) -> Result<T, GitlabBackendError>,
) -> Result<Vec<T>, GitlabBackendError> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not an array")))?;
    values.iter().cloned().map(parse).collect()
}

pub(crate) fn discussion_from_value(value: Value) -> Result<GitlabDiscussion, GitlabBackendError> {
    let notes = value
        .get("notes")
        .and_then(Value::as_array)
        .ok_or_else(|| GitlabBackendError::Protocol("discussion notes missing".to_string()))?
        .iter()
        .cloned()
        .map(note_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GitlabDiscussion {
        id: required_string(&value, "id")?,
        individual_note: value.get("individual_note").and_then(Value::as_bool),
        notes,
    })
}

pub(crate) fn draft_note_from_value(value: Value) -> Result<GitlabDraftNote, GitlabBackendError> {
    Ok(GitlabDraftNote {
        id: required_u64(&value, "id")?,
        body: optional_string_strict(&value, "note")?,
        author_user_id: optional_u64_strict(&value, "author_id")?,
        merge_request_id: optional_u64_strict(&value, "merge_request_id")?,
        resolve_discussion: optional_bool_strict(&value, "resolve_discussion")?,
        discussion_id: optional_string_strict(&value, "discussion_id")?,
        commit_id: optional_string_strict(&value, "commit_id")?,
        position: optional_draft_position(&value)?,
    })
}

pub(crate) fn optional_draft_position(
    value: &Value,
) -> Result<Option<GitlabDiffPosition>, GitlabBackendError> {
    // Depending on GitLab/Grape serialization, an omitted update position can
    // become either nil or `Position.new({})`. The latter renders as a default
    // text position whose locator fields are all null. Neither shape identifies
    // a diff location, so normalize both to an unpositioned draft while still
    // rejecting any known or future field carrying meaningful position data.
    if value
        .get("position")
        .and_then(Value::as_object)
        .is_some_and(draft_position_is_semantically_empty)
    {
        return Ok(None);
    }
    optional_diff_position(value).map_err(|error| match error {
        GitlabBackendError::Protocol(_) => GitlabBackendError::DraftPositionShapeInvalid,
        error => error,
    })
}

pub(crate) fn draft_position_is_semantically_empty(
    position: &serde_json::Map<String, Value>,
) -> bool {
    position.iter().all(|(key, value)| match key.as_str() {
        "position_type" => value.is_null() || value.as_str() == Some("text"),
        "ignore_whitespace_change" => value.is_null() || value.as_bool() == Some(false),
        "base_sha" | "start_sha" | "head_sha" | "old_path" | "new_path" | "old_line"
        | "new_line" | "line_range" | "width" | "height" | "x" | "y" => value.is_null(),
        _ => value.is_null(),
    })
}

pub(crate) fn server_version_from_value(
    value: Value,
) -> Result<GitlabServerVersion, GitlabBackendError> {
    Ok(GitlabServerVersion {
        version: required_string(&value, "version")?,
    })
}

pub(crate) fn approval_summary_from_value(
    value: Value,
) -> Result<GitlabApprovalSummary, GitlabBackendError> {
    let approved_by = match value.get("approved_by") {
        None | Some(Value::Null) => Vec::new(),
        Some(raw) => raw
            .as_array()
            .ok_or_else(|| GitlabBackendError::Protocol("approved_by is not an array".to_string()))?
            .iter()
            .map(|entry| {
                let user = entry
                    .get("user")
                    .and_then(gitlab_user_summary_from_value)
                    .ok_or_else(|| {
                        GitlabBackendError::Protocol("approved_by user missing".to_string())
                    })?;
                Ok(GitlabApprovalUser {
                    user,
                    approved_at: optional_string_strict(entry, "approved_at")?,
                })
            })
            .collect::<Result<Vec<_>, GitlabBackendError>>()?,
    };
    Ok(GitlabApprovalSummary {
        approvals_required: optional_u64_strict(&value, "approvals_required")?,
        approvals_left: optional_u64_strict(&value, "approvals_left")?,
        approved: optional_bool_strict(&value, "approved")?,
        approved_by,
        user_has_approved: optional_bool_strict(&value, "user_has_approved")?,
        user_can_approve: optional_bool_strict(&value, "user_can_approve")?,
    })
}

pub(crate) fn approval_state_from_value(
    value: Value,
) -> Result<GitlabApprovalState, GitlabBackendError> {
    Ok(GitlabApprovalState {
        approval_rules_overwritten: optional_bool_strict(&value, "approval_rules_overwritten")?,
        rules: value
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                GitlabBackendError::Protocol("approval state rules missing".to_string())
            })?
            .iter()
            .cloned()
            .map(approval_rule_from_value)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn optional_object_array<T>(
    value: &Value,
    key: &str,
    parse: fn(Value) -> Result<T, GitlabBackendError>,
) -> Result<Vec<T>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(items) => items
            .as_array()
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not an array")))?
            .iter()
            .cloned()
            .map(parse)
            .collect(),
    }
}

pub(crate) fn approval_rule_from_value(
    value: Value,
) -> Result<GitlabApprovalRule, GitlabBackendError> {
    let users = |key| optional_object_array(&value, key, required_user_summary_from_value);
    Ok(GitlabApprovalRule {
        id: required_u64(&value, "id")?,
        name: required_string(&value, "name")?,
        rule_type: optional_string_strict(&value, "rule_type")?,
        approvals_required: required_u64(&value, "approvals_required")?,
        approved: optional_bool_strict(&value, "approved")?,
        eligible_approvers: users("eligible_approvers")?,
        approved_by: users("approved_by")?,
        users: users("users")?,
        groups: optional_object_array(&value, "groups", group_summary_from_value)?,
        overridden: optional_bool_strict(&value, "overridden")?,
        contains_hidden_groups: optional_bool_strict(&value, "contains_hidden_groups")?,
        code_owner: optional_bool_strict(&value, "code_owner")?,
        section: optional_string_strict(&value, "section")?,
        source_rule: match value.get("source_rule") {
            None | Some(Value::Null) => None,
            Some(source) => Some(GitlabApprovalRuleSource {
                approvals_required: required_u64(source, "approvals_required")?,
            }),
        },
    })
}

pub(crate) fn required_user_summary_from_value(
    value: Value,
) -> Result<GitlabUserSummary, GitlabBackendError> {
    gitlab_user_summary_from_value(&value)
        .ok_or_else(|| GitlabBackendError::Protocol("approval rule user is malformed".to_string()))
}

pub(crate) fn group_summary_from_value(
    value: Value,
) -> Result<GitlabGroupSummary, GitlabBackendError> {
    if !value.is_object() {
        return Err(GitlabBackendError::Protocol(
            "approval rule group is malformed".to_string(),
        ));
    }
    Ok(GitlabGroupSummary {
        id: optional_u64_strict(&value, "id")?,
        name: optional_string_strict(&value, "name")?,
        path: optional_string_strict(&value, "path")?,
        full_path: optional_string_strict(&value, "full_path")?,
    })
}

pub(crate) fn branch_from_value(value: Value) -> Result<GitlabBranch, GitlabBackendError> {
    Ok(GitlabBranch {
        name: required_string(&value, "name")?,
        merged: value.get("merged").and_then(Value::as_bool),
        protected: value.get("protected").and_then(Value::as_bool),
        default: value.get("default").and_then(Value::as_bool),
        web_url: optional_string(&value, "web_url"),
        commit: value
            .get("commit")
            .cloned()
            .map(commit_summary_from_value)
            .transpose()?,
    })
}

pub(crate) fn branch_list_from_value(
    value: Value,
) -> Result<Vec<GitlabBranch>, GitlabBackendError> {
    value
        .as_array()
        .ok_or_else(|| {
            GitlabBackendError::Protocol("branches response is not an array".to_string())
        })?
        .iter()
        .cloned()
        .map(branch_from_value)
        .collect()
}

pub(crate) fn commit_summary_from_value(
    value: Value,
) -> Result<GitlabCommitSummary, GitlabBackendError> {
    Ok(GitlabCommitSummary {
        id: required_string(&value, "id")?,
        short_id: optional_string(&value, "short_id"),
        title: optional_string(&value, "title"),
    })
}

pub(crate) fn commit_from_value(value: Value) -> Result<GitlabCommit, GitlabBackendError> {
    Ok(GitlabCommit {
        id: required_string(&value, "id")?,
        short_id: optional_string(&value, "short_id"),
        title: optional_string(&value, "title"),
        message: optional_string(&value, "message"),
        author_name: optional_string(&value, "author_name"),
        authored_date: optional_string(&value, "authored_date"),
        committed_date: optional_string(&value, "committed_date"),
        web_url: optional_string(&value, "web_url"),
    })
}

pub(crate) fn commit_list_from_value(
    value: Value,
) -> Result<Vec<GitlabCommit>, GitlabBackendError> {
    value
        .as_array()
        .ok_or_else(|| {
            GitlabBackendError::Protocol("commits response is not an array".to_string())
        })?
        .iter()
        .cloned()
        .map(commit_from_value)
        .collect()
}

pub(crate) fn pipeline_from_value(value: Value) -> Result<GitlabPipeline, GitlabBackendError> {
    Ok(GitlabPipeline {
        id: required_u64(&value, "id")?,
        iid: optional_u64(&value, "iid"),
        project_id: required_u64(&value, "project_id")?,
        ref_name: optional_string(&value, "ref"),
        sha: optional_string(&value, "sha"),
        status: optional_string(&value, "status"),
        source: optional_string(&value, "source"),
        web_url: optional_string(&value, "web_url"),
        created_at: optional_string(&value, "created_at"),
        updated_at: optional_string(&value, "updated_at"),
    })
}

pub(crate) fn pipeline_list_from_value(
    value: Value,
) -> Result<Vec<GitlabPipeline>, GitlabBackendError> {
    value
        .as_array()
        .ok_or_else(|| {
            GitlabBackendError::Protocol("pipelines response is not an array".to_string())
        })?
        .iter()
        .cloned()
        .map(pipeline_from_value)
        .collect()
}

pub(crate) fn job_from_value(value: Value) -> Result<GitlabJob, GitlabBackendError> {
    let pipeline = value.get("pipeline");
    Ok(GitlabJob {
        id: required_u64(&value, "id")?,
        name: optional_string(&value, "name"),
        status: optional_string(&value, "status"),
        stage: optional_string(&value, "stage"),
        ref_name: optional_string(&value, "ref"),
        pipeline_id: pipeline.and_then(|pipeline| optional_u64(pipeline, "id")),
        project_id: pipeline.and_then(|pipeline| optional_u64(pipeline, "project_id")),
        trace_size: job_trace_size(&value),
        web_url: optional_string(&value, "web_url"),
        created_at: optional_string(&value, "created_at"),
        started_at: optional_string(&value, "started_at"),
        finished_at: optional_string(&value, "finished_at"),
    })
}

pub(crate) fn job_list_from_value(value: Value) -> Result<Vec<GitlabJob>, GitlabBackendError> {
    value
        .as_array()
        .ok_or_else(|| GitlabBackendError::Protocol("jobs response is not an array".to_string()))?
        .iter()
        .cloned()
        .map(job_from_value)
        .collect()
}

pub(crate) fn job_trace_size(value: &Value) -> Option<u64> {
    value
        .get("artifacts")
        .and_then(Value::as_array)?
        .iter()
        .find(|artifact| {
            artifact
                .get("file_type")
                .and_then(Value::as_str)
                .is_some_and(|file_type| file_type == "trace")
        })
        .and_then(|artifact| optional_u64(artifact, "size"))
}

pub(crate) fn gitlab_file_from_value(value: Value) -> Result<GitlabFile, GitlabBackendError> {
    Ok(GitlabFile {
        file_name: required_string(&value, "file_name")?,
        file_path: required_string(&value, "file_path")?,
        size: required_u64(&value, "size")?,
        encoding: optional_string(&value, "encoding"),
        content: optional_string(&value, "content"),
        content_sha256: optional_string(&value, "content_sha256"),
        ref_name: optional_string(&value, "ref"),
        blob_id: optional_string(&value, "blob_id"),
        commit_id: optional_string(&value, "commit_id"),
        last_commit_id: optional_string(&value, "last_commit_id"),
        execute_filemode: value.get("execute_filemode").and_then(Value::as_bool),
    })
}

pub(crate) fn gitlab_file_mutation_from_value(
    value: Value,
) -> Result<GitlabFileMutation, GitlabBackendError> {
    Ok(GitlabFileMutation {
        file_path: required_string(&value, "file_path")?,
        branch: required_string(&value, "branch")?,
    })
}

pub(crate) fn protected_branch_from_value(
    value: Value,
) -> Result<GitlabProtectedBranch, GitlabBackendError> {
    Ok(GitlabProtectedBranch {
        id: optional_u64(&value, "id"),
        name: required_string(&value, "name")?,
        allow_force_push: value.get("allow_force_push").and_then(Value::as_bool),
        code_owner_approval_required: value
            .get("code_owner_approval_required")
            .and_then(Value::as_bool),
        inherited: value.get("inherited").and_then(Value::as_bool),
        push_access_levels: protected_branch_access_levels_from_value(
            value.get("push_access_levels"),
        )?,
        merge_access_levels: protected_branch_access_levels_from_value(
            value.get("merge_access_levels"),
        )?,
        unprotect_access_levels: protected_branch_access_levels_from_value(
            value.get("unprotect_access_levels"),
        )?,
    })
}

pub(crate) fn protected_branch_access_levels_from_value(
    value: Option<&Value>,
) -> Result<Vec<GitlabProtectedBranchAccessLevel>, GitlabBackendError> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    value
        .as_array()
        .ok_or_else(|| {
            GitlabBackendError::Protocol(
                "protected branch access levels are not an array".to_string(),
            )
        })?
        .iter()
        .map(|value| {
            Ok(GitlabProtectedBranchAccessLevel {
                access_level: optional_u64(value, "access_level"),
                access_level_description: optional_string(value, "access_level_description"),
                user_id: optional_u64(value, "user_id"),
                group_id: optional_u64(value, "group_id"),
                deploy_key_id: optional_u64(value, "deploy_key_id"),
            })
        })
        .collect()
}

pub(crate) fn protected_branch_list_from_value(
    value: Value,
) -> Result<Vec<GitlabProtectedBranch>, GitlabBackendError> {
    value
        .as_array()
        .ok_or_else(|| {
            GitlabBackendError::Protocol("protected branches response is not an array".to_string())
        })?
        .iter()
        .cloned()
        .map(protected_branch_from_value)
        .collect()
}

pub(crate) fn required_string(value: &Value, key: &str) -> Result<String, GitlabBackendError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} missing")))
}

pub(crate) fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

pub(crate) fn optional_string_strict(
    value: &Value,
    key: &str,
) -> Result<Option<String>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_str()
            .map(ToString::to_string)
            .map(Some)
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not a string"))),
    }
}

pub(crate) fn required_u64(value: &Value, key: &str) -> Result<u64, GitlabBackendError> {
    optional_u64(value, key).ok_or_else(|| GitlabBackendError::Protocol(format!("{key} missing")))
}

pub(crate) fn optional_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
    })
}

pub(crate) fn optional_u64_strict(
    value: &Value,
    key: &str,
) -> Result<Option<u64>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_u64()
            .or_else(|| raw.as_str().and_then(|value| value.parse().ok()))
            .map(Some)
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not an integer"))),
    }
}

pub(crate) fn optional_json_u64_strict(
    value: &Value,
    key: &str,
) -> Result<Option<u64>, GitlabBackendError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_u64()
            .map(Some)
            .ok_or_else(|| GitlabBackendError::Protocol(format!("{key} is not an integer"))),
    }
}

pub(crate) fn link_header_has_next_relation(value: &str) -> bool {
    parse_gitlab_link_value(value).ok().flatten().is_some()
}

pub(crate) fn gitlab_next_page(
    headers: &reqwest::header::HeaderMap,
    requested_url: &Url,
) -> Result<Option<u32>, GitlabBackendError> {
    let current_page = query_page(requested_url)?;
    let expected_next = current_page.checked_add(1).ok_or_else(|| {
        GitlabBackendError::Protocol("GitLab pagination page overflowed".to_string())
    })?;
    let header_next = next_page_header(headers)?;
    if let Some(next_page) = header_next.next_page()
        && next_page != expected_next
    {
        return Err(GitlabBackendError::Protocol(
            "GitLab pagination header did not advance by one page".to_string(),
        ));
    }
    let validate_link_collection = !matches!(header_next, GitlabNextPageHeader::Next(_));
    let link_next = next_page_link(headers, requested_url, validate_link_collection)?;
    if let Some(next_page) = link_next
        && next_page != expected_next
    {
        return Err(GitlabBackendError::Protocol(
            "GitLab pagination link did not advance by one page".to_string(),
        ));
    }
    match (header_next, link_next) {
        (GitlabNextPageHeader::Absent, link_next) => Ok(link_next),
        (GitlabNextPageHeader::End, None) => Ok(None),
        (GitlabNextPageHeader::Next(header_next), None) => Ok(Some(header_next)),
        (GitlabNextPageHeader::Next(header_next), Some(link_next)) if header_next == link_next => {
            Ok(Some(header_next))
        }
        (GitlabNextPageHeader::End | GitlabNextPageHeader::Next(_), Some(_)) => Err(
            GitlabBackendError::Protocol("GitLab pagination headers disagree".to_string()),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitlabNextPageHeader {
    Absent,
    End,
    Next(u32),
}

impl GitlabNextPageHeader {
    pub(crate) fn next_page(self) -> Option<u32> {
        match self {
            Self::Next(page) => Some(page),
            Self::Absent | Self::End => None,
        }
    }
}

pub(crate) fn query_page(url: &Url) -> Result<u32, GitlabBackendError> {
    let pages = url
        .query_pairs()
        .filter_map(|(key, value)| (key == "page").then_some(value))
        .collect::<Vec<_>>();
    match pages.as_slice() {
        [] => Ok(1),
        [page] => page
            .parse::<u32>()
            .ok()
            .filter(|page| *page > 0)
            .ok_or_else(|| {
                GitlabBackendError::Protocol("GitLab pagination page is invalid".to_string())
            }),
        _ => Err(GitlabBackendError::Protocol(
            "GitLab pagination page is duplicated".to_string(),
        )),
    }
}

pub(crate) fn next_page_header(
    headers: &reqwest::header::HeaderMap,
) -> Result<GitlabNextPageHeader, GitlabBackendError> {
    let values = headers.get_all("x-next-page").iter().collect::<Vec<_>>();
    let value = match values.as_slice() {
        [] => return Ok(GitlabNextPageHeader::Absent),
        [value] => value.to_str().map_err(|_| {
            GitlabBackendError::Protocol("GitLab X-Next-Page header is not valid text".to_string())
        })?,
        _ => {
            return Err(GitlabBackendError::Protocol(
                "GitLab X-Next-Page header is duplicated".to_string(),
            ));
        }
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(GitlabNextPageHeader::End);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|page| *page > 0)
        .map(GitlabNextPageHeader::Next)
        .ok_or_else(|| {
            GitlabBackendError::Protocol("GitLab X-Next-Page header is invalid".to_string())
        })
}

pub(crate) fn next_page_link(
    headers: &reqwest::header::HeaderMap,
    requested_url: &Url,
    validate_collection: bool,
) -> Result<Option<u32>, GitlabBackendError> {
    let mut next_page = None;
    for header in headers.get_all(reqwest::header::LINK) {
        let header = header.to_str().map_err(|_| {
            GitlabBackendError::Protocol("GitLab Link header is not valid text".to_string())
        })?;
        for entry in split_gitlab_link_header_values(header)? {
            let Some(target) = parse_gitlab_link_value(entry)? else {
                continue;
            };
            if next_page.is_some() {
                return Err(GitlabBackendError::Protocol(
                    "GitLab Link header has multiple next relations".to_string(),
                ));
            }
            let target = Url::parse(target).map_err(|_| {
                GitlabBackendError::Protocol("GitLab next-page link is invalid".to_string())
            })?;
            if validate_collection {
                validate_next_page_link(requested_url, &target)?;
            }
            next_page = Some(query_page(&target)?);
        }
    }
    Ok(next_page)
}

pub(crate) fn split_gitlab_link_header_values(
    value: &str,
) -> Result<Vec<&str>, GitlabBackendError> {
    let mut values = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut in_target = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_quote => escaped = true,
            '"' if !in_target => in_quote = !in_quote,
            '<' if !in_quote && !in_target => in_target = true,
            '>' if !in_quote && in_target => in_target = false,
            ',' if !in_quote && !in_target => {
                let part = value[start..index].trim();
                if !part.is_empty() {
                    values.push(part);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if in_quote || in_target || escaped {
        return Err(GitlabBackendError::Protocol(
            "GitLab Link header is malformed".to_string(),
        ));
    }
    let part = value[start..].trim();
    if !part.is_empty() {
        values.push(part);
    }
    Ok(values)
}

pub(crate) fn parse_gitlab_link_value(value: &str) -> Result<Option<&str>, GitlabBackendError> {
    let value = value.trim();
    let rest = value.strip_prefix('<').ok_or_else(|| {
        GitlabBackendError::Protocol("GitLab Link header is malformed".to_string())
    })?;
    let (target, params) = rest.split_once('>').ok_or_else(|| {
        GitlabBackendError::Protocol("GitLab Link header is malformed".to_string())
    })?;
    if target.is_empty() {
        return Err(GitlabBackendError::Protocol(
            "GitLab Link header target is empty".to_string(),
        ));
    }
    let mut rel_is_next = false;
    let mut rel_seen = false;
    for param in split_gitlab_link_parameters(params)? {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("rel") {
            continue;
        }
        if rel_seen {
            return Err(GitlabBackendError::Protocol(
                "GitLab Link header has repeated rel parameters".to_string(),
            ));
        }
        rel_seen = true;
        let relation = unquote_gitlab_link_parameter(value.trim())?;
        if relation
            .split_ascii_whitespace()
            .any(|value| value.eq_ignore_ascii_case("next"))
        {
            rel_is_next = true;
        }
    }
    Ok(rel_is_next.then_some(target))
}

pub(crate) fn split_gitlab_link_parameters(value: &str) -> Result<Vec<&str>, GitlabBackendError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if !value.starts_with(';') {
        return Err(GitlabBackendError::Protocol(
            "GitLab Link header parameters are malformed".to_string(),
        ));
    }
    let mut parameters = Vec::new();
    let mut start = 1;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, character) in value.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            ';' if !in_quote => {
                let parameter = value[start..index].trim();
                if !parameter.is_empty() {
                    parameters.push(parameter);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if in_quote || escaped {
        return Err(GitlabBackendError::Protocol(
            "GitLab Link header parameters are malformed".to_string(),
        ));
    }
    let parameter = value[start..].trim();
    if !parameter.is_empty() {
        parameters.push(parameter);
    }
    Ok(parameters)
}

pub(crate) fn unquote_gitlab_link_parameter(value: &str) -> Result<String, GitlabBackendError> {
    let Some(inner) = value.strip_prefix('"') else {
        return Ok(value.to_string());
    };
    let inner = inner.strip_suffix('"').ok_or_else(|| {
        GitlabBackendError::Protocol("GitLab Link header parameter is malformed".to_string())
    })?;
    let mut result = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters.next().ok_or_else(|| {
                GitlabBackendError::Protocol(
                    "GitLab Link header parameter is malformed".to_string(),
                )
            })?;
            result.push(escaped);
        } else {
            result.push(character);
        }
    }
    Ok(result)
}

pub(crate) fn validate_next_page_link(
    requested: &Url,
    next: &Url,
) -> Result<(), GitlabBackendError> {
    if !same_origin(requested, next)
        || requested.path() != next.path()
        || !next.username().is_empty()
        || next.password().is_some()
        || next.fragment().is_some()
        || query_without_page(requested) != query_without_page(next)
    {
        return Err(GitlabBackendError::Protocol(
            "GitLab next-page link changed the requested collection".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn query_without_page(url: &Url) -> BTreeMap<String, Vec<String>> {
    let mut query = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in url.query_pairs().filter(|(key, _)| key != "page") {
        query
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    query
}
