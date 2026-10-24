//! The Jira backend seam, its wire types, and the HTTP implementation.
use super::*;
use agent_access_atlassian::{
    AtlassianAccessError, AtlassianClients, AtlassianCredential, AtlassianDownloadError,
    AtlassianProduct, AtlassianRouteUnavailable, AtlassianRoutes,
};
use agent_access_provider::host::UpstreamClientFactory;

#[cfg(test)]
#[path = "backend_issue_types_tests.rs"]
mod issue_types_tests;

#[async_trait]
pub trait JiraBackend: Send + Sync {
    /// One bounded project collection page, using the selected execution credential.
    async fn project_list(
        &self,
        request: JiraProjectListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError>;
    /// Project details read with the operation's selected execution credential.
    async fn project_details(
        &self,
        _project: &str,
        _include_issue_types: bool,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira project details are not supported by this backend".to_string(),
        ))
    }

    /// Search references restricted to a previously validated numeric project ID.
    async fn project_search_fields(
        &self,
        _project_id: u64,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira project fields are not supported by this backend".to_string(),
        ))
    }

    async fn project_statuses(
        &self,
        _project_id: u64,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira project statuses are not supported by this backend".to_string(),
        ))
    }
    fn egress_proxy_audit(&self, _credential: &AtlassianCredential) -> Value {
        EgressRoute::direct().audit_value()
    }

    async fn current_user(
        &self,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira current-user verification is not supported by this backend".to_string(),
        ))
    }

    async fn issue_metadata(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, JiraBackendError>;

    async fn issue(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError>;

    async fn issue_view(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
        include_issue_references: bool,
    ) -> Result<JiraBackendResponse<JiraIssueView>, JiraBackendError>;

    async fn issue_types(
        &self,
        _project: &str,
        _request: JiraIssueTypeListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueTypePage>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue type listing is not supported by this backend".to_string(),
        ))
    }

    async fn create_issue(
        &self,
        _request: JiraIssueCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCreatedIssue>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue create is not supported by this backend".to_string(),
        ))
    }

    async fn update_issue(
        &self,
        _issue_key: &str,
        _request: JiraIssueUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue update is not supported by this backend".to_string(),
        ))
    }

    async fn set_issue_parent(
        &self,
        _issue_key: &str,
        _request: JiraIssueParentSetRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue parent update is not supported by this backend".to_string(),
        ))
    }

    async fn issue_parent(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueParentReadback>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue parent readback is not supported by this backend".to_string(),
        ))
    }

    async fn issue_link_types(
        &self,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraIssueLinkType>>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue link type listing is not supported by this backend".to_string(),
        ))
    }

    async fn create_issue_link(
        &self,
        _request: JiraIssueLinkCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue link creation is not supported by this backend".to_string(),
        ))
    }

    async fn issue_links(
        &self,
        _issue_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueLinks>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira issue link readback is not supported by this backend".to_string(),
        ))
    }

    async fn search(
        &self,
        request: JiraSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError>;

    async fn comments(
        &self,
        _issue_key: &str,
        _request: JiraCommentListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPage>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment listing is not supported by this backend".to_string(),
        ))
    }

    async fn comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError>;

    async fn add_comment(
        &self,
        issue_key: &str,
        request: JiraCommentAddRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError>;

    async fn update_comment(
        &self,
        _issue_key: &str,
        _comment_id: &str,
        _request: JiraCommentUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment update is not supported by this backend".to_string(),
        ))
    }

    async fn delete_comment(
        &self,
        _issue_key: &str,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment delete is not supported by this backend".to_string(),
        ))
    }

    async fn comment_property_keys(
        &self,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPropertyKeys>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment property listing is not supported by this backend".to_string(),
        ))
    }

    async fn comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment property get is not supported by this backend".to_string(),
        ))
    }

    async fn set_comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _value: Value,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment property set is not supported by this backend".to_string(),
        ))
    }

    async fn delete_comment_property(
        &self,
        _comment_id: &str,
        _property_key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        Err(JiraBackendError::Protocol(
            "Jira comment property delete is not supported by this backend".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        issue_key: &str,
        attachment: JiraAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError>;

    async fn issue_attachment_metadata(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError>;

    async fn issue_attachment_list(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError>;

    async fn attachment_content(
        &self,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachmentContent>, JiraBackendError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueMetadata {
    pub id: String,
    pub key: String,
    pub project: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssue {
    pub id: String,
    pub key: String,
    pub project: String,
    pub summary: Option<String>,
    pub status: Option<String>,
    pub issue_type: Option<String>,
    pub description: Option<Value>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub creator: Option<JiraUserSummary>,
    pub reporter: Option<JiraUserSummary>,
    pub assignee: Option<JiraUserSummary>,
    pub priority: Option<JiraPrioritySummary>,
    pub labels: Option<Vec<String>>,
}

/// View-only data. Embedded references require universal same-mode authority.
#[derive(Debug, Clone, PartialEq)]
pub struct JiraIssueView {
    pub issue: JiraIssue,
    pub issue_links: Option<Vec<JiraIssueViewLink>>,
    pub custom_fields: Vec<Value>,
    pub context: JiraIssueViewContext,
}

/// Allowlisted metadata from a linked issue in the source issue's response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueViewLink {
    pub key: String,
    #[serde(rename = "type")]
    pub link_type: String,
    pub direction: JiraIssueLinkDirection,
    pub relationship: String,
    pub summary: Option<String>,
    pub issue_type: Option<String>,
}

/// The linked issue's side of the relationship relative to the viewed issue.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JiraIssueLinkDirection {
    Inward,
    Outward,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JiraSearchPage {
    pub issues: Vec<JiraIssue>,
    pub max_results: u32,
    pub start_at: u32,
    pub total: Option<u32>,
    pub next_page_token: Option<String>,
    pub is_last: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraSearchRequest {
    pub jql: String,
    pub projects: Vec<String>,
    pub max_results: u32,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueType {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub subtask: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueTypeListRequest {
    pub start_at: u32,
    pub max_results: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueTypePage {
    pub issue_types: Vec<JiraIssueType>,
    pub start_at: u32,
    pub max_results: u32,
    pub total: u32,
}

pub(crate) fn validate_issue_type_page(
    page: &JiraIssueTypePage,
    request: &JiraIssueTypeListRequest,
) -> Result<(), JiraBackendError> {
    let invalid = || JiraBackendError::Protocol("invalid issue type page".to_string());
    let count = u32::try_from(page.issue_types.len()).map_err(|_| invalid())?;
    let end = page.start_at.checked_add(count).ok_or_else(invalid)?;
    if page.start_at != request.start_at
        || page.max_results == 0
        || page.max_results > request.max_results
        || count > page.max_results
        || count > request.max_results
        || (count == 0 && page.start_at < page.total)
        || (count > 0 && end > page.total)
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    for issue_type in &page.issue_types {
        if issue_type.id.is_empty()
            || !issue_type.id.bytes().all(|byte| byte.is_ascii_digit())
            || issue_type.name.trim().is_empty()
            || !ids.insert(&issue_type.id)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct JiraIssueCreateRequest {
    pub project: String,
    pub issue_type_id: String,
    pub summary: String,
    pub parent_issue: Option<String>,
    pub description: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraCreatedIssue {
    pub id: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartialJiraCreatedIssue {
    pub(crate) id: Option<String>,
    pub(crate) key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JiraIssueUpdateRequest {
    pub summary: Option<String>,
    pub description: Option<Value>,
    pub notify_users: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueParentSetRequest {
    pub parent_issue: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueParentReadback {
    pub issue: JiraIssueMetadata,
    pub parent: Option<JiraIssueParent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueParent {
    pub id: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueLinkType {
    pub name: String,
    pub inward: String,
    pub outward: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueLinkCreateRequest {
    pub link_type: String,
    pub outward_issue: String,
    pub inward_issue: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueLinks {
    pub issue: JiraIssueMetadata,
    pub links: Vec<JiraIssueLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraIssueLink {
    pub link_type: String,
    pub outward_issue: Option<String>,
    pub inward_issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraCommentListRequest {
    pub max_results: u32,
    pub start_at: u32,
    pub order_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JiraCommentAddRequest {
    pub body: Value,
    pub visibility: Option<JiraCommentVisibility>,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JiraCommentUpdateRequest {
    pub body: Value,
    pub visibility: Option<JiraCommentVisibility>,
    pub notify_users: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraUserSummary {
    pub account_id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraPrioritySummary {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct JiraCommentVisibility {
    #[serde(rename = "type")]
    pub visibility_type: String,
    pub value: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JiraComment {
    pub id: String,
    pub parent_id: Option<String>,
    pub body: Option<Value>,
    pub author: Option<JiraUserSummary>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub visibility: Option<JiraCommentVisibility>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraCommentSummary {
    pub id: String,
    pub parent_id: Option<String>,
    pub author: Option<JiraUserSummary>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub visibility: Option<JiraCommentVisibility>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraCommentPage {
    pub comments: Vec<JiraCommentSummary>,
    pub max_results: u32,
    pub start_at: u32,
    pub total: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraCommentPropertyKeys {
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraAttachment {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueAttachmentList {
    pub issue: JiraIssueMetadata,
    pub attachments: Vec<JiraAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraAttachmentUpload {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub bytes: Vec<u8>,
    pub temp_file: Option<Arc<BrokerBodyPartFile>>,
    pub sha256: String,
}

impl JiraAttachmentUpload {
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        if let Some(file) = &self.temp_file {
            std::fs::read(file.path())
        } else {
            Ok(self.bytes.clone())
        }
    }

    pub fn temp_file_path(&self) -> Option<&std::path::Path> {
        self.temp_file.as_ref().map(|file| file.path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraAttachmentContent {
    pub filename: String,
    pub content_type: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub stream: ProviderResultStream,
}

impl JiraAttachmentContent {
    pub fn from_bytes(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let content_type = content_type.into();
        let size = bytes.len() as u64;
        let sha256 = sha256_hex(&bytes);
        Self {
            filename: filename.into(),
            content_type: content_type.clone(),
            size: Some(size),
            sha256: Some(sha256),
            stream: ProviderResultStream::from_bytes(content_type, bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraBackendResponse<T> {
    pub value: T,
    pub status: u16,
    pub duration_ms: u64,
}

/// The position and shared operation budgets of a project collection request.
#[derive(Debug, Clone)]
pub struct JiraProjectListRequest {
    pub start_at: u64,
    pub max_results: u32,
    pub requests: UpstreamRequestBudget,
    pub bytes: SharedBodyBudget,
    /// Shared by every page of this invocation, never reset per page.
    pub replay_used: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum JiraBackendError {
    #[error("Jira returned unauthorized")]
    Unauthorized,
    #[error("Jira returned forbidden")]
    Forbidden,
    #[error("Jira returned not found")]
    NotFound,
    #[error("Jira returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Jira is rate limiting requests")]
    RateLimited(Option<UpstreamRetryAfter>),
    #[error("Jira validation failed with HTTP {status}")]
    Validation {
        status: u16,
        message: String,
        body_malformed: bool,
    },
    /// The SDK proved the request never reached Jira: it could not be built,
    /// or no connection was established (`timed_out` for a connect timeout).
    /// It reports the same reason as `Timeout` or `Transport`.
    #[error("Jira request was not sent")]
    NotSent { timed_out: bool },
    /// The request may have reached Jira, but no response arrived: it timed
    /// out (`timed_out`), its connection failed after it was sent, or the SDK
    /// reported a failure Jira does not classify. It reports the same reason
    /// as `Timeout` or `Transport`.
    #[error("Jira request got no response")]
    NoResponse { timed_out: bool },
    /// Jira answered a write with a success status, but its response then
    /// failed, stalled, exceeded the byte cap or did not parse; reported like
    /// the wrapped failure.
    #[error("Jira accepted the write but its response failed: {0}")]
    AcceptedUnreadable(Box<JiraBackendError>),
    /// Jira answered with a redirect, which the Broker never follows. It
    /// reports the same reason as `Protocol`.
    #[error("Jira redirect responses are rejected")]
    Redirected,
    /// Reading a response failed, or an upload file could not be opened.
    #[error("Jira transport failed: {0}")]
    Transport(String),
    /// Reading a response stalled.
    #[error("Jira request timed out")]
    Timeout,
    #[error("Jira response exceeded the configured byte cap")]
    ResponseTooLarge,
    #[error("Jira issue create response protocol error")]
    IssueCreateResponseInvalid {
        id: Option<String>,
        key: Option<String>,
        status: Option<u16>,
        duration_ms: u64,
    },
    #[error("Jira response protocol error: {0}")]
    Protocol(String),
    /// Delegated (OAuth) access could not be presented: the lease's own
    /// failure (a refresh busy, throttled or uncertain, consent pending, a
    /// reconnect required, or an operation that already recovered), access
    /// for another site, or access Jira rejected again. Nothing was sent, or
    /// Jira's 401 applied nothing. Reported unchanged.
    #[error("Jira credential could not be presented")]
    Credential(ProviderError),
    /// The selected static credential or delegated access has no route on
    /// this site: a token profile Jira does not declare, a profile of
    /// another kind, or a gateway route without a configured cloud ID.
    /// Nothing was sent. Reported unchanged, as `credential_not_provisioned`.
    #[error("Jira has no route for the selected credential")]
    Unroutable(ProviderError),
}

impl From<AtlassianAccessError> for JiraBackendError {
    fn from(error: AtlassianAccessError) -> Self {
        match error {
            AtlassianAccessError::Credential(error) => Self::Credential(error),
            AtlassianAccessError::Unroutable(reason) => Self::Unroutable(
                AtlassianRouteUnavailable::new(JIRA_PRODUCT, reason).provider_error(),
            ),
        }
    }
}

/// Marks a failure that followed a write's success `status` as
/// [`JiraBackendError::AcceptedUnreadable`]; one after any other status is
/// returned unchanged.
pub(crate) fn accepted_if_success(
    status: u16,
) -> impl FnOnce(JiraBackendError) -> JiraBackendError {
    move |error| {
        if (200..300).contains(&status) {
            JiraBackendError::AcceptedUnreadable(Box::new(error))
        } else {
            error
        }
    }
}

pub(crate) fn jira_backend_error(error: JiraBackendError) -> ProviderError {
    match error {
        JiraBackendError::AcceptedUnreadable(error) => jira_backend_error(*error),
        JiraBackendError::Unauthorized => ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "Jira rejected the selected credential",
        ),
        JiraBackendError::Forbidden => ProviderError::error(
            ReasonCode::UpstreamForbidden,
            "Jira forbade the selected credential",
        ),
        JiraBackendError::NotFound => {
            ProviderError::deny(ReasonCode::ScopeUnresolved, "Jira object was not found")
        }
        JiraBackendError::HttpStatus(_) => {
            ProviderError::error(ReasonCode::UpstreamFailed, "Jira returned non-success")
        }
        JiraBackendError::RateLimited(retry_after) => upstream_rate_limited("jira", retry_after),
        JiraBackendError::Validation {
            status,
            message,
            body_malformed,
        } => ProviderError::deny(
            if body_malformed {
                ReasonCode::BodyMalformed
            } else {
                ReasonCode::InputInvalid
            },
            format!("Jira rejected the request: {message}"),
        )
        .with_upstream(Some(status), None),
        JiraBackendError::NotSent { timed_out: false }
        | JiraBackendError::NoResponse { timed_out: false }
        | JiraBackendError::Transport(_) => {
            ProviderError::error(ReasonCode::UpstreamConnectionFailed, "Jira request failed")
        }
        JiraBackendError::NotSent { timed_out: true }
        | JiraBackendError::NoResponse { timed_out: true }
        | JiraBackendError::Timeout => {
            ProviderError::error(ReasonCode::UpstreamTimeout, "Jira request timed out")
        }
        JiraBackendError::ResponseTooLarge => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira response exceeded the configured byte cap",
        ),
        JiraBackendError::IssueCreateResponseInvalid { .. }
        | JiraBackendError::Redirected
        | JiraBackendError::Protocol(_) => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira response protocol error",
        ),
        JiraBackendError::Credential(error) | JiraBackendError::Unroutable(error) => error,
    }
}

pub(crate) fn jira_backend_reason_code(error: &JiraBackendError) -> ReasonCode {
    match error {
        JiraBackendError::AcceptedUnreadable(error) => jira_backend_reason_code(error),
        JiraBackendError::Unauthorized => ReasonCode::UpstreamUnauthorized,
        JiraBackendError::Forbidden => ReasonCode::UpstreamForbidden,
        JiraBackendError::NotFound => ReasonCode::ScopeUnresolved,
        JiraBackendError::HttpStatus(_) => ReasonCode::UpstreamFailed,
        JiraBackendError::RateLimited(_) => ReasonCode::UpstreamRateLimited,
        JiraBackendError::Validation { body_malformed, .. } => {
            if *body_malformed {
                ReasonCode::BodyMalformed
            } else {
                ReasonCode::InputInvalid
            }
        }
        JiraBackendError::NotSent { timed_out: false }
        | JiraBackendError::NoResponse { timed_out: false }
        | JiraBackendError::Transport(_) => ReasonCode::UpstreamConnectionFailed,
        JiraBackendError::NotSent { timed_out: true }
        | JiraBackendError::NoResponse { timed_out: true }
        | JiraBackendError::Timeout => ReasonCode::UpstreamTimeout,
        JiraBackendError::ResponseTooLarge
        | JiraBackendError::IssueCreateResponseInvalid { .. }
        | JiraBackendError::Redirected
        | JiraBackendError::Protocol(_) => ReasonCode::UpstreamProtocolFailed,
        // Never the outcome of reading a response; only presenting a
        // credential reports them.
        JiraBackendError::Credential(_) => ReasonCode::CredentialInvalid,
        JiraBackendError::Unroutable(_) => ReasonCode::CredentialNotProvisioned,
    }
}

/// Jira's REST API v3 on the tenant host or the Atlassian gateway.
pub(crate) const JIRA_PRODUCT: AtlassianProduct = AtlassianProduct {
    provider: "jira",
    name: "Jira",
    api_path: "rest/api/3/",
    other_api_paths: &[],
    status_reasons: &[],
};

#[derive(Clone)]
pub(crate) struct HttpJiraBackend {
    pub(crate) routes: AtlassianRoutes,
    pub(crate) config: JiraProviderConfig,
    pub(crate) limits: ProviderLimits,
}

impl HttpJiraBackend {
    #[cfg(test)]
    pub(crate) fn for_tests(config: JiraProviderConfig, limits: ProviderLimits) -> Self {
        let host = agent_access_provider::test_support::TestHost::with_limits(limits.clone());
        Self::new(config, limits, &host).expect("Jira HTTP client configuration is valid")
    }

    pub(crate) fn new(
        config: JiraProviderConfig,
        limits: ProviderLimits,
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        Ok(Self {
            routes: AtlassianRoutes::new(JIRA_PRODUCT, &config.site(), clients)?,
            config,
            limits,
        })
    }

    /// This backend with its gateway route served below `gateway`, an
    /// origin such as a stub server's: `{gateway}/ex/jira/{cloud_id}/rest/api/3/`.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_gateway_origin(
        mut self,
        gateway: &str,
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let site = self.config.site();
        let cloud_id = site.gateway_cloud_id().ok_or_else(|| {
            ProviderBuildError::invalid("the test Jira site has no Atlassian gateway route")
        })?;
        let base = Url::parse(&format!(
            "{}/ex/jira/{cloud_id}/{}",
            gateway.trim_end_matches('/'),
            JIRA_PRODUCT.api_path
        ))
        .map_err(|error| ProviderBuildError::invalid(error.to_string()))?;
        let gateway = AtlassianClients::new(JIRA_PRODUCT, &site, base, clients)?;
        if let Some(route) = self.routes.gateway_mut() {
            *route = gateway;
        }
        Ok(self)
    }

    pub(crate) fn client_for(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&AtlassianClients, JiraBackendError> {
        self.routes
            .for_credential(credential)
            .map_err(|refusal| JiraBackendError::Unroutable(refusal.provider_error()))
    }

    /// Clients for one API base from the test host, routed through the
    /// configuration's service proxy when it sets one.
    #[cfg(test)]
    pub(crate) fn new_with_api_base(
        config: JiraProviderConfig,
        limits: ProviderLimits,
        api_base_override: Url,
    ) -> Self {
        let host = agent_access_provider::test_support::TestHost::with_limits(limits.clone());
        let clients = AtlassianClients::new(JIRA_PRODUCT, &config.site(), api_base_override, &host)
            .expect("Jira HTTP client configuration is valid");
        Self {
            routes: AtlassianRoutes::from_clients(JIRA_PRODUCT, clients.clone(), Some(clients)),
            config,
            limits,
        }
    }

    pub(crate) fn api_base(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<Url, JiraBackendError> {
        Ok(self.client_for(credential)?.api_base.clone())
    }
}

#[cfg(test)]
impl HttpJiraBackend {
    pub(crate) fn egress_proxy_for_test(&self, credential: &AtlassianCredential) -> Value {
        self.client_for(credential)
            .unwrap()
            .client
            .egress_route()
            .audit_value()
    }
}

impl HttpJiraBackend {
    pub(crate) fn request_client(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&UpstreamClient, JiraBackendError> {
        Ok(&self.client_for(credential)?.client)
    }

    pub(crate) fn stream_client(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&UpstreamClient, JiraBackendError> {
        Ok(&self.client_for(credential)?.stream_client)
    }
}

#[async_trait]
impl JiraBackend for HttpJiraBackend {
    async fn project_details(
        &self,
        project: &str,
        include_issue_types: bool,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        let project = utf8_percent_encode(project, JIRA_PATH_SEGMENT_ENCODE_SET);
        self.project_view_value(
            &format!("project/{project}"),
            Some(if include_issue_types {
                "description,issueTypes"
            } else {
                "description"
            }),
            None,
            credential,
        )
        .await
    }

    async fn project_search_fields(
        &self,
        project_id: u64,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        self.project_view_value(
            "jql/autocompletedata",
            None,
            Some(json!({"projectIds": [project_id], "includeCollapsedFields": false})),
            credential,
        )
        .await
    }

    async fn project_statuses(
        &self,
        project_id: u64,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        self.project_view_value(
            &format!("project/{project_id}/statuses"),
            None,
            None,
            credential,
        )
        .await
    }

    async fn project_list(
        &self,
        request: JiraProjectListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        self.project_list_page(request, credential).await
    }
    fn egress_proxy_audit(&self, credential: &AtlassianCredential) -> Value {
        self.client_for(credential)
            .map(|clients| clients.client.egress_route().audit_value())
            .unwrap_or_else(|_| EgressRoute::direct().audit_value())
    }

    async fn issue_types(
        &self,
        project: &str,
        request: JiraIssueTypeListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueTypePage>, JiraBackendError> {
        let project = utf8_percent_encode(project, JIRA_PATH_SEGMENT_ENCODE_SET);
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/createmeta/{project}/issuetypes"))
            .map_err(|_| JiraBackendError::Protocol("invalid issue type URL".to_string()))?;
        url.query_pairs_mut()
            .append_pair("startAt", &request.start_at.to_string())
            .append_pair("maxResults", &request.max_results.to_string());
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let mut response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url)
                .header("Accept", "application/json"),
            UpstreamCall::new("issue_type.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let trace = take_upstream_trace(&mut response);
        let page = read_jira_response_value(
            response,
            self.limits.max_upstream_response_bytes,
            trace.as_ref(),
        )
        .await
        .and_then(|value| {
            let page: JiraIssueTypePage = serde_json::from_value(value)
                .map_err(|_| JiraBackendError::Protocol("invalid issue type page".to_string()))?;
            validate_issue_type_page(&page, &request)?;
            Ok(page)
        });
        if let Some(trace) = trace {
            trace.complete(
                page.as_ref()
                    .err()
                    .map(jira_backend_reason_code)
                    .map(Into::into),
            );
        }
        Ok(JiraBackendResponse {
            value: page?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn current_user(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join("myself")
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("current_user"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_metadata(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("fields", "project");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.metadata"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_metadata_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssue>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair(
            "fields",
            "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels,description",
        );
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_view(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
        include_issue_references: bool,
    ) -> Result<JiraBackendResponse<JiraIssueView>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let fields = if include_issue_references {
            "*all,-comment,-attachment,-worklog"
        } else {
            "*all,-comment,-attachment,-worklog,-subtasks,-parent,-issuelinks"
        };
        url.query_pairs_mut()
            .append_pair("fields", fields)
            .append_pair("expand", "names,schema");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let issue_links = if include_issue_references {
            viewed_issue_links_from_value(&value)?
        } else {
            None
        };
        let custom_fields = custom_fields::custom_fields_from_value(&value)?;
        let context =
            issue_view_context::issue_view_context_from_value(&value, include_issue_references)?;
        Ok(JiraBackendResponse {
            value: JiraIssueView {
                issue: issue_from_value(value)?,
                issue_links,
                custom_fields,
                context,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_issue(
        &self,
        request: JiraIssueCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCreatedIssue>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join("issue")
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let body = issue_create_body(&request);
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let mut response = send_jira_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&body),
            UpstreamCall::new("issue.create"),
        )
        .await?;
        let status = response.status().as_u16();
        if response.status().is_success() && status != 201 {
            let trace = take_upstream_trace(&mut response);
            let partial = match jira_response_bytes_untraced(
                response,
                self.limits.max_upstream_response_bytes,
                None,
            )
            .await
            {
                Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .map(|value| partial_created_issue_from_value(&value))
                    .unwrap_or(PartialJiraCreatedIssue {
                        id: None,
                        key: None,
                    }),
                Err(_) => PartialJiraCreatedIssue {
                    id: None,
                    key: None,
                },
            };
            if let Some(trace) = trace {
                trace.complete(Some(ReasonCode::UpstreamProtocolFailed.into()));
            }
            return Err(JiraBackendError::IssueCreateResponseInvalid {
                id: partial.id,
                key: partial.key,
                status: Some(status),
                duration_ms: elapsed_ms(started),
            });
        }
        let value =
            match jira_response_value(response, self.limits.max_upstream_response_bytes).await {
                Ok(value) => value,
                Err(error)
                    if status == 201
                        && matches!(
                            error,
                            JiraBackendError::Protocol(_) | JiraBackendError::ResponseTooLarge
                        ) =>
                {
                    return Err(JiraBackendError::IssueCreateResponseInvalid {
                        id: None,
                        key: None,
                        status: Some(status),
                        duration_ms: elapsed_ms(started),
                    });
                }
                Err(error) => return Err(accepted_if_success(status)(error)),
            };
        let partial = partial_created_issue_from_value(&value);
        let created = created_issue_from_value(value).map_err(|_| {
            JiraBackendError::IssueCreateResponseInvalid {
                id: partial.id,
                key: partial.key,
                status: Some(status),
                duration_ms: elapsed_ms(started),
            }
        })?;
        Ok(JiraBackendResponse {
            value: created,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_issue(
        &self,
        issue_key: &str,
        request: JiraIssueUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        if let Some(notify_users) = request.notify_users {
            url.query_pairs_mut()
                .append_pair("notifyUsers", if notify_users { "true" } else { "false" });
        }
        let body = issue_update_body(&request);
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&body),
            UpstreamCall::new("issue.update"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn set_issue_parent(
        &self,
        issue_key: &str,
        request: JiraIssueParentSetRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let body = issue_parent_set_body(&request);
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&body),
            UpstreamCall::new("issue.parent.set"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_parent(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueParentReadback>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("fields", "project,parent");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.parent.readback"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_parent_readback_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_link_types(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraIssueLinkType>>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join("issueLinkType")
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.link_types"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_link_types_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_issue_link(
        &self,
        request: JiraIssueLinkCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join("issueLink")
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let body = issue_link_create_body(&request);
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&body),
            UpstreamCall::new("issue.link.create"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_links(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueLinks>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("fields", "project,issuelinks");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.links"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_links_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn search(
        &self,
        request: JiraSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraSearchPage>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join("search/jql")
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("jql", &request.jql)
                .append_pair("maxResults", &request.max_results.to_string())
                .append_pair(
                    "fields",
                    "project,summary,status,issuetype,created,updated,creator,reporter,assignee,priority,labels",
                );
            if let Some(token) = &request.next_page_token {
                query.append_pair("nextPageToken", token);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("search"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: search_page_from_value(value, request.max_results)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comments(
        &self,
        issue_key: &str,
        request: JiraCommentListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPage>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/comment"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("maxResults", &request.max_results.to_string())
                .append_pair("startAt", &request.start_at.to_string());
            if let Some(order_by) = &request.order_by {
                query.append_pair("orderBy", order_by);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: comment_page_from_value(value, request.max_results)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_comment(
        &self,
        issue_key: &str,
        request: JiraCommentAddRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/comment"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&comment_write_body(
                    request.body,
                    request.visibility.as_ref(),
                    request.parent_id.as_deref(),
                )),
            UpstreamCall::new("comment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: comment_from_value(value).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        request: JiraCommentUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/comment/{comment_id}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair(
            "notifyUsers",
            if request.notify_users {
                "true"
            } else {
                "false"
            },
        );
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&comment_write_body(
                    request.body,
                    request.visibility.as_ref(),
                    None,
                )),
            UpstreamCall::new("comment.update"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: comment_from_value(value).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn delete_comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/comment/{comment_id}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::DELETE, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.delete"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_attachment(
        &self,
        issue_key: &str,
        attachment: JiraAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/attachments"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.stream_client(credential)?;
        let mut response = send_jira_upload(
            client,
            credential,
            || async {
                // Each attempt reopens the spooled body.
                let upload_part = jira_upload_part(&attachment).await?;
                let form = reqwest::multipart::Form::new().part("file", upload_part.part);
                Ok((
                    client
                        .request(Method::POST, url.clone())
                        .header("Accept", "application/json")
                        .header("X-Atlassian-Token", "no-check")
                        .multipart(form),
                    upload_part.progress,
                ))
            },
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            UpstreamCall::new("attachment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        // The trace outlives the deadline, so a stalled body records a timeout.
        let trace = take_upstream_trace(&mut response);
        let value = tokio::time::timeout(
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            read_jira_response_value(
                response,
                self.limits.max_upstream_response_bytes,
                trace.as_ref(),
            ),
        )
        .await
        .unwrap_or(Err(JiraBackendError::Timeout));
        if let Some(trace) = trace {
            trace.complete(
                value
                    .as_ref()
                    .err()
                    .map(jira_backend_reason_code)
                    .map(Into::into),
            );
        }
        let value = value.map_err(accepted_if_success(status))?;
        let attachment = value
            .as_array()
            .and_then(|items| items.first())
            .cloned()
            .ok_or_else(|| JiraBackendError::Protocol("attachment response missing".to_string()))
            .and_then(attachment_from_value)
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: attachment,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_attachment_metadata(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Vec<JiraAttachment>>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("fields", "attachment");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.attachments.metadata"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_attachments_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn issue_attachment_list(
        &self,
        issue_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraIssueAttachmentList>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("fields", "project,attachment");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("issue.attachments.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: issue_attachment_list_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn attachment_content(
        &self,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraAttachmentContent>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("attachment/content/{attachment_id}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("redirect", "false");
        let started = Instant::now();
        let mut response = self.attachment_content_response(url, credential).await?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let byte_cap = self
            .config
            .attachments
            .max_download_bytes
            .min(self.limits.max_download_bytes);
        if let Err(error) = validate_jira_body_response(&response, byte_cap) {
            complete_upstream_trace(&mut response, Some(jira_backend_reason_code(&error).into()));
            return Err(error);
        }
        complete_upstream_trace(&mut response, None);
        let content_length = response.content_length();
        let stream = jira_response_stream(
            response,
            byte_cap,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            content_length,
            content_type.clone(),
        );
        Ok(JiraBackendResponse {
            value: JiraAttachmentContent {
                filename: String::new(),
                content_type,
                size: content_length,
                sha256: None,
                stream,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comment(
        &self,
        issue_key: &str,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraComment>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("issue/{issue_key}/comment/{comment_id}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: comment_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comment_property_keys(
        &self,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<JiraCommentPropertyKeys>, JiraBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("comment/{comment_id}/properties"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.property.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: comment_property_keys_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comment_property(
        &self,
        comment_id: &str,
        property_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        let property_key = jira_path_segment(property_key);
        let url = self
            .api_base(credential)?
            .join(&format!("comment/{comment_id}/properties/{property_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.property.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value: comment_property_value_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn set_comment_property(
        &self,
        comment_id: &str,
        property_key: &str,
        value: Value,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let property_key = jira_path_segment(property_key);
        let url = self
            .api_base(credential)?
            .join(&format!("comment/{comment_id}/properties/{property_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&value),
            UpstreamCall::new("comment.property.set"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn delete_comment_property(
        &self,
        comment_id: &str,
        property_key: &str,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<()>, JiraBackendError> {
        let property_key = jira_path_segment(property_key);
        let url = self
            .api_base(credential)?
            .join(&format!("comment/{comment_id}/properties/{property_key}"))
            .map_err(|error| JiraBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_jira_request(
            client,
            credential,
            client
                .request(Method::DELETE, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.property.delete"),
        )
        .await?;
        let status = response.status().as_u16();
        jira_response_unit(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(JiraBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }
}

impl HttpJiraBackend {
    /// Downloads `url`, following up to 5 of Atlassian's media redirects.
    /// The credential reaches only hops within the route's site, each with
    /// freshly revalidated delegated access, and a redirect to another site
    /// on the route's origin fails before it is sent. Delegated access that
    /// Jira itself answers with 401 recovers once and the download starts
    /// over ([`AtlassianCredential::download`]).
    pub(crate) async fn attachment_content_response(
        &self,
        url: Url,
        credential: &AtlassianCredential,
    ) -> Result<reqwest::Response, JiraBackendError> {
        credential
            .download(
                self.client_for(credential)?,
                url,
                5,
                Duration::from_millis(self.limits.request_timeout_ms),
                "attachment.download",
                "Jira",
            )
            .await
            .map_err(|error| match error {
                AtlassianDownloadError::Upstream(error) => jira_upstream_error(error),
                AtlassianDownloadError::Access(error) => error.into(),
            })
    }
}

pub(crate) fn jira_path_segment(value: &str) -> String {
    utf8_percent_encode(value, JIRA_PATH_SEGMENT_ENCODE_SET).to_string()
}

pub(crate) fn comment_write_body(
    body: Value,
    visibility: Option<&JiraCommentVisibility>,
    parent_id: Option<&str>,
) -> Value {
    let mut value = json!({ "body": body });
    if let Some(parent_id) = parent_id {
        // Live Jira Cloud validation on 2026-06-27 returned and accepted
        // threaded-comment parentId as a JSON number.
        value["parentId"] = parent_id
            .parse::<u64>()
            .map_or_else(|_| json!(parent_id), |parent_id| json!(parent_id));
    }
    if let Some(visibility) = visibility {
        value["visibility"] = jira_visibility_to_value(visibility);
    }
    value
}

pub(crate) fn issue_update_body(request: &JiraIssueUpdateRequest) -> Value {
    let mut fields = serde_json::Map::new();
    if let Some(summary) = &request.summary {
        fields.insert("summary".to_string(), json!(summary));
    }
    if let Some(description) = &request.description {
        fields.insert("description".to_string(), description.clone());
    }
    json!({ "fields": fields })
}

pub(crate) fn issue_parent_set_body(request: &JiraIssueParentSetRequest) -> Value {
    json!({
        "fields": {
            "parent": { "key": request.parent_issue },
        }
    })
}

pub(crate) fn issue_create_body(request: &JiraIssueCreateRequest) -> Value {
    let mut fields = serde_json::Map::new();
    fields.insert("project".to_string(), json!({ "key": request.project }));
    fields.insert(
        "issuetype".to_string(),
        json!({ "id": request.issue_type_id }),
    );
    fields.insert("summary".to_string(), json!(request.summary));
    if let Some(parent_issue) = &request.parent_issue {
        fields.insert("parent".to_string(), json!({ "key": parent_issue }));
    }
    if let Some(description) = &request.description {
        fields.insert("description".to_string(), description.clone());
    }
    json!({ "fields": fields })
}

pub(crate) fn issue_link_create_body(request: &JiraIssueLinkCreateRequest) -> Value {
    json!({
        "type": { "name": request.link_type },
        "outwardIssue": { "key": request.outward_issue },
        "inwardIssue": { "key": request.inward_issue },
    })
}

pub(crate) fn jira_visibility_to_value(visibility: &JiraCommentVisibility) -> Value {
    match visibility.visibility_type.as_str() {
        "group" => json!({
            "type": "group",
            "identifier": visibility.identifier.as_deref().unwrap_or_default(),
        }),
        "role" => {
            let mut value = json!({
                "type": "role",
                "value": visibility.value.as_deref().unwrap_or_default(),
            });
            if let Some(identifier) = &visibility.identifier {
                value["identifier"] = json!(identifier);
            }
            value
        }
        _ => json!({ "type": visibility.visibility_type }),
    }
}

/// Sends through `client` with `credential`'s authorization, mapping
/// transport failures to Jira errors. An unsupported credential kind fails
/// before anything is sent. Delegated access is pinned immediately before
/// each attempt. Jira answering it with 401 authenticated nothing and so
/// applied nothing: the presented version is marked rejected and, when the
/// operation's lease can still recover, the request is repeated once with the
/// renewed access ([`AtlassianCredential::rejected`]). A static token's 401
/// is never repeated.
pub(crate) async fn send_jira_request(
    client: &UpstreamClient,
    credential: &AtlassianCredential,
    request: reqwest::RequestBuilder,
    call: UpstreamCall<'_>,
) -> Result<reqwest::Response, JiraBackendError> {
    let mut request = request;
    let mut attempt = call.attempt;
    loop {
        let presented = credential.present().await?;
        // A copy for the one repeat a delegated 401 permits.
        let replay = if attempt == call.attempt && presented.is_delegated() {
            request.try_clone()
        } else {
            None
        };
        let mut response = client
            .send(
                request,
                call.with_attempt(attempt)
                    .with_authorization(presented.authorization()),
            )
            .await
            .map_err(jira_upstream_error)?;
        if response.status().as_u16() == 401 && presented.is_delegated() {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid.into()));
            request = credential.rejected(&presented, replay, "Jira").await?;
            attempt += 1;
            continue;
        }
        return Ok(response);
    }
}

pub(crate) fn jira_upstream_error(error: UpstreamError) -> JiraBackendError {
    match error {
        // Only the SDK's own not-sent classification proves Jira never
        // received the request; every other failure may have reached it.
        UpstreamError::NotSent { timed_out, .. } => JiraBackendError::NotSent { timed_out },
        UpstreamError::Timeout => JiraBackendError::NoResponse { timed_out: true },
        UpstreamError::Transport(_) => JiraBackendError::NoResponse { timed_out: false },
        UpstreamError::NotAllowed => {
            JiraBackendError::Protocol("Jira upstream URL is not allowlisted".to_string())
        }
        UpstreamError::Redirect => {
            JiraBackendError::Protocol("Jira attachment redirect is invalid".to_string())
        }
        // Any other failure produced no usable response and may have reached
        // Jira.
        _ => JiraBackendError::NoResponse { timed_out: false },
    }
}

pub(crate) async fn jira_response_value(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<Value, JiraBackendError> {
    let mut response = response;
    let trace = take_upstream_trace(&mut response);
    let value = read_jira_response_value(response, byte_cap, trace.as_ref()).await;
    if let Some(trace) = trace {
        trace.complete(
            value
                .as_ref()
                .err()
                .map(jira_backend_reason_code)
                .map(Into::into),
        );
    }
    value
}

/// Reads a JSON response whose detached trace the caller completes.
pub(crate) async fn read_jira_response_value(
    response: reqwest::Response,
    byte_cap: u64,
    trace: Option<&PendingUpstreamTrace>,
) -> Result<Value, JiraBackendError> {
    let validation_fields = trace.and_then(|trace| jira_validation_fields(trace.operation()));
    jira_response_bytes_untraced(response, byte_cap, validation_fields)
        .await
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| JiraBackendError::Protocol(error.to_string()))
        })
}

pub(crate) async fn jira_response_unit(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<(), JiraBackendError> {
    jira_response_bytes_for_body(response, byte_cap)
        .await
        .map(|_| ())
}

#[cfg(test)]
pub(crate) async fn jira_response_bytes(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<Vec<u8>, JiraBackendError> {
    jira_response_bytes_for_body(response, byte_cap).await
}

pub(crate) async fn jira_response_bytes_for_body(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<Vec<u8>, JiraBackendError> {
    let mut response = response;
    let trace = take_upstream_trace(&mut response);
    let validation_fields = trace
        .as_ref()
        .and_then(|trace| jira_validation_fields(trace.operation()));
    let bytes = jira_response_bytes_untraced(response, byte_cap, validation_fields).await;
    if let Some(trace) = trace {
        trace.complete(
            bytes
                .as_ref()
                .err()
                .map(jira_backend_reason_code)
                .map(Into::into),
        );
    }
    bytes
}

pub(crate) async fn jira_response_bytes_untraced(
    response: reqwest::Response,
    byte_cap: u64,
    validation_fields: Option<&'static [&'static str]>,
) -> Result<Vec<u8>, JiraBackendError> {
    let status = response.status().as_u16();
    if matches!(status, 400 | 422)
        && response_has_json_content_type(&response)
        && let Some(validation_fields) = validation_fields
    {
        let validation = read_validation_json(response, byte_cap)
            .await
            .and_then(|value| jira_validation_message(&value, validation_fields));
        return Err(
            validation.map_or(JiraBackendError::HttpStatus(status), |validation| {
                JiraBackendError::Validation {
                    status,
                    message: validation.message,
                    body_malformed: validation.body_malformed,
                }
            }),
        );
    }
    validate_jira_body_response(&response, byte_cap)?;
    read_bounded_body(response, byte_cap, None)
        .await
        .map_err(|error| match error {
            BodyReadError::TooLarge => JiraBackendError::ResponseTooLarge,
            BodyReadError::IdleTimeout => JiraBackendError::Timeout,
            BodyReadError::Transport { detail, .. } => JiraBackendError::Transport(detail),
            other => JiraBackendError::Transport(other.to_string()),
        })
}

pub(crate) fn jira_validation_fields(operation: &str) -> Option<&'static [&'static str]> {
    match operation {
        "issue.create" | "issue.update" => Some(&["summary", "description"]),
        "comment.add" | "comment.update" => Some(&["body"]),
        _ => None,
    }
}

pub(crate) fn jira_response_stream(
    response: reqwest::Response,
    byte_cap: u64,
    idle_timeout: Duration,
    expected_size: Option<u64>,
    content_type: String,
) -> ProviderResultStream {
    ProviderResultStream::from_bounded_response(
        content_type,
        response,
        BoundedDownload::new(
            "Jira attachment download",
            byte_cap,
            ReasonCode::UpstreamProtocolFailed,
            idle_timeout,
        )
        .with_expected_size(expected_size),
    )
}

pub(crate) struct JiraUploadPart {
    pub(crate) part: reqwest::multipart::Part,
    pub(crate) progress: Option<UploadProgress>,
}

pub(crate) async fn jira_upload_part(
    attachment: &JiraAttachmentUpload,
) -> Result<JiraUploadPart, JiraBackendError> {
    let (part, progress) = if let Some(path) = attachment.temp_file_path() {
        let (body, progress) = file_upload_body(path)
            .await
            .map_err(|error| JiraBackendError::Transport(error.to_string()))?;
        (
            reqwest::multipart::Part::stream_with_length(body, attachment.size),
            Some(progress),
        )
    } else {
        (
            reqwest::multipart::Part::bytes(attachment.bytes.clone()),
            None,
        )
    };
    part.file_name(attachment.filename.clone())
        .mime_str(&attachment.content_type)
        .map(|part| JiraUploadPart { part, progress })
        .map_err(|error| JiraBackendError::Protocol(error.to_string()))
}

/// Sends one upload through `client`. Its body is a stream that cannot be
/// repeated, so `prepare` builds the request and its progress for each
/// attempt; a delegated 401 repeats the upload at most once, as
/// [`send_jira_request`] does.
pub(crate) async fn send_jira_upload<F, Fut>(
    client: &UpstreamClient,
    credential: &AtlassianCredential,
    mut prepare: F,
    idle_timeout: Duration,
    call: UpstreamCall<'_>,
) -> Result<reqwest::Response, JiraBackendError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
            Output = Result<(reqwest::RequestBuilder, Option<UploadProgress>), JiraBackendError>,
        >,
{
    let mut attempt = call.attempt;
    loop {
        let presented = credential.present().await?;
        let (request, progress) = prepare().await?;
        let mut response = client
            .send_upload(
                request,
                progress,
                idle_timeout,
                call.with_attempt(attempt)
                    .with_authorization(presented.authorization()),
            )
            .await
            .map_err(jira_upstream_error)?;
        if response.status().as_u16() == 401 && presented.is_delegated() {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid.into()));
            credential
                .rejected(&presented, (attempt == call.attempt).then_some(()), "Jira")
                .await?;
            attempt += 1;
            continue;
        }
        return Ok(response);
    }
}

pub(crate) fn validate_jira_body_response(
    response: &reqwest::Response,
    byte_cap: u64,
) -> Result<(), JiraBackendError> {
    let status = response.status().as_u16();
    if response.status().is_redirection() {
        return Err(JiraBackendError::Redirected);
    }
    if status == 401 {
        return Err(JiraBackendError::Unauthorized);
    }
    if status == 403 {
        return Err(JiraBackendError::Forbidden);
    }
    if status == 404 {
        return Err(JiraBackendError::NotFound);
    }
    if status == 429 {
        return Err(JiraBackendError::RateLimited(
            UpstreamRetryAfter::from_headers(response.headers()),
        ));
    }
    if !response.status().is_success() {
        return Err(JiraBackendError::HttpStatus(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > byte_cap)
    {
        return Err(JiraBackendError::ResponseTooLarge);
    }
    Ok(())
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn issue_from_value(value: Value) -> Result<JiraIssue, JiraBackendError> {
    issue_from_value_with_description(value, true)
}

pub(crate) fn viewed_issue_links_from_value(
    value: &Value,
) -> Result<Option<Vec<JiraIssueViewLink>>, JiraBackendError> {
    let Some(links) = value
        .get("fields")
        .and_then(|fields| fields.get("issuelinks"))
    else {
        return Ok(None);
    };
    let links = links
        .as_array()
        .ok_or_else(|| JiraBackendError::Protocol("issue links must be an array".to_string()))?;
    links
        .iter()
        .map(|link| {
            let (linked_issue, direction, label_field) =
                match (link.get("inwardIssue"), link.get("outwardIssue")) {
                    (Some(issue), None) => (issue, JiraIssueLinkDirection::Inward, "inward"),
                    (None, Some(issue)) => (issue, JiraIssueLinkDirection::Outward, "outward"),
                    _ => {
                        return Err(JiraBackendError::Protocol(
                            "issue link must include exactly one linked issue".to_string(),
                        ));
                    }
                };
            let key = linked_issue
                .get("key")
                .and_then(Value::as_str)
                .filter(|key| is_issue_key(key))
                .ok_or_else(|| {
                    JiraBackendError::Protocol(
                        "issue link must include a valid issue key".to_string(),
                    )
                })?;
            let link_type = link
                .get("type")
                .ok_or_else(|| JiraBackendError::Protocol("issue link type missing".to_string()))?;
            let name = link_type
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .ok_or_else(|| {
                    JiraBackendError::Protocol("issue link type name missing".to_string())
                })?;
            let relationship = link_type
                .get(label_field)
                .and_then(Value::as_str)
                .filter(|label| !label.trim().is_empty())
                .ok_or_else(|| {
                    JiraBackendError::Protocol("issue link relationship label missing".to_string())
                })?;
            let fields = match linked_issue.get("fields") {
                None | Some(Value::Null) => None,
                Some(Value::Object(fields)) => Some(fields),
                Some(_) => {
                    return Err(JiraBackendError::Protocol(
                        "linked issue fields must be an object".to_string(),
                    ));
                }
            };
            let summary = match fields.and_then(|fields| fields.get("summary")) {
                None | Some(Value::Null) => None,
                Some(Value::String(summary)) => Some(summary.clone()),
                Some(_) => {
                    return Err(JiraBackendError::Protocol(
                        "linked issue summary must be a string".to_string(),
                    ));
                }
            };
            let issue_type = match fields.and_then(|fields| fields.get("issuetype")) {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            JiraBackendError::Protocol(
                                "linked issue type must include a string name".to_string(),
                            )
                        })?
                        .to_string(),
                ),
            };
            Ok(JiraIssueViewLink {
                key: key.to_string(),
                link_type: name.to_string(),
                direction,
                relationship: relationship.to_string(),
                summary,
                issue_type,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

pub(crate) fn issue_summary_from_value(value: Value) -> Result<JiraIssue, JiraBackendError> {
    issue_from_value_with_description(value, false)
}

pub(crate) fn issue_from_value_with_description(
    value: Value,
    include_description: bool,
) -> Result<JiraIssue, JiraBackendError> {
    let metadata = issue_metadata_from_ref(&value)?;
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| JiraBackendError::Protocol("issue fields missing".to_string()))?;
    let description = if include_description {
        match fields.get("description") {
            None | Some(Value::Null) => None,
            Some(description) if description.is_object() => Some(description.clone()),
            Some(_) => {
                return Err(JiraBackendError::Protocol(
                    "issue description must be an ADF object".to_string(),
                ));
            }
        }
    } else {
        None
    };
    Ok(JiraIssue {
        id: metadata.id,
        key: metadata.key,
        project: metadata.project,
        summary: fields
            .get("summary")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        status: fields
            .get("status")
            .and_then(|status| status.get("name"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        issue_type: fields
            .get("issuetype")
            .and_then(|issue_type| issue_type.get("name"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        description,
        created: fields
            .get("created")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        updated: fields
            .get("updated")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        creator: optional_issue_user_summary_from_fields(fields, "creator"),
        reporter: optional_issue_user_summary_from_fields(fields, "reporter"),
        assignee: optional_issue_user_summary_from_fields(fields, "assignee"),
        priority: optional_priority_summary_from_fields(fields),
        labels: optional_labels_from_fields(fields),
    })
}

pub(crate) fn issue_metadata_from_value(
    value: Value,
) -> Result<JiraIssueMetadata, JiraBackendError> {
    issue_metadata_from_ref(&value)
}

fn issue_metadata_from_ref(value: &Value) -> Result<JiraIssueMetadata, JiraBackendError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("issue id missing".to_string()))?;
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("issue key missing".to_string()))?;
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| JiraBackendError::Protocol("issue fields missing".to_string()))?;
    let project = fields
        .get("project")
        .and_then(|project| project.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("issue project key missing".to_string()))?;
    Ok(JiraIssueMetadata {
        id: id.to_string(),
        key: key.to_string(),
        project: project.to_string(),
    })
}

pub(crate) fn created_issue_from_value(value: Value) -> Result<JiraCreatedIssue, JiraBackendError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| JiraBackendError::Protocol("created issue id missing".to_string()))?;
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| JiraBackendError::Protocol("created issue key missing".to_string()))?;
    Ok(JiraCreatedIssue {
        id: id.to_string(),
        key: key.to_string(),
    })
}

pub(crate) fn partial_created_issue_from_value(value: &Value) -> PartialJiraCreatedIssue {
    PartialJiraCreatedIssue {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(ToString::to_string),
        key: value
            .get("key")
            .and_then(Value::as_str)
            .filter(|key| !key.is_empty())
            .map(ToString::to_string),
    }
}

pub(crate) fn issue_link_types_from_value(
    value: Value,
) -> Result<Vec<JiraIssueLinkType>, JiraBackendError> {
    value
        .get("issueLinkTypes")
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("issue link types missing".to_string()))?
        .iter()
        .map(|entry| {
            let name = entry.get("name").and_then(Value::as_str).ok_or_else(|| {
                JiraBackendError::Protocol("issue link type name missing".to_string())
            })?;
            let inward = entry.get("inward").and_then(Value::as_str).ok_or_else(|| {
                JiraBackendError::Protocol("issue link type inward description missing".to_string())
            })?;
            let outward = entry
                .get("outward")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JiraBackendError::Protocol(
                        "issue link type outward description missing".to_string(),
                    )
                })?;
            Ok(JiraIssueLinkType {
                name: name.to_string(),
                inward: inward.to_string(),
                outward: outward.to_string(),
            })
        })
        .collect()
}

pub(crate) fn issue_parent_readback_from_value(
    value: Value,
) -> Result<JiraIssueParentReadback, JiraBackendError> {
    let issue = issue_metadata_from_value(value.clone())?;
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| JiraBackendError::Protocol("issue fields missing".to_string()))?;
    let parent = match fields.get("parent") {
        None | Some(Value::Null) => None,
        Some(parent) => Some(issue_parent_from_value(parent)?),
    };
    Ok(JiraIssueParentReadback { issue, parent })
}

pub(crate) fn issue_parent_from_value(value: &Value) -> Result<JiraIssueParent, JiraBackendError> {
    if !value.is_object() {
        return Err(JiraBackendError::Protocol(
            "issue parent must be an object".to_string(),
        ));
    }
    let id = optional_string_or_number(value, "id")?;
    let key = match value.get("key") {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_str()
            .map(ToString::to_string)
            .map(Some)
            .ok_or_else(|| JiraBackendError::Protocol("issue parent key invalid".to_string())),
    }?;
    if id.is_none() && key.is_none() {
        return Err(JiraBackendError::Protocol(
            "issue parent id or key missing".to_string(),
        ));
    }
    Ok(JiraIssueParent { id, key })
}

pub(crate) fn issue_links_from_value(value: Value) -> Result<JiraIssueLinks, JiraBackendError> {
    let issue = issue_metadata_from_value(value.clone())?;
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| JiraBackendError::Protocol("issue fields missing".to_string()))?;
    let links = fields
        .get("issuelinks")
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("issue links missing".to_string()))?
        .iter()
        .map(issue_link_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JiraIssueLinks { issue, links })
}

pub(crate) fn issue_link_from_value(value: &Value) -> Result<JiraIssueLink, JiraBackendError> {
    let link_type = value
        .get("type")
        .and_then(|link_type| link_type.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("issue link type name missing".to_string()))?;
    let outward_issue = issue_link_side_key(value, "outwardIssue")?;
    let inward_issue = issue_link_side_key(value, "inwardIssue")?;
    if outward_issue.is_none() && inward_issue.is_none() {
        return Err(JiraBackendError::Protocol(
            "issue link missing linked issue".to_string(),
        ));
    }
    Ok(JiraIssueLink {
        link_type: link_type.to_string(),
        outward_issue,
        inward_issue,
    })
}

pub(crate) fn issue_link_side_key(
    value: &Value,
    field: &str,
) -> Result<Option<String>, JiraBackendError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .get("key")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .map(Some)
            .ok_or_else(|| JiraBackendError::Protocol(format!("{field} key missing"))),
    }
}

pub(crate) fn search_page_from_value(
    value: Value,
    requested_max_results: u32,
) -> Result<JiraSearchPage, JiraBackendError> {
    let issues = value
        .get("issues")
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("search issues missing".to_string()))?
        .iter()
        .cloned()
        .map(issue_summary_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    if issues.len() > requested_max_results as usize {
        return Err(JiraBackendError::Protocol(
            "search returned more issues than requested".to_string(),
        ));
    }
    Ok(JiraSearchPage {
        issues,
        max_results: value
            .get("maxResults")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(requested_max_results),
        start_at: value
            .get("startAt")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0),
        total: value
            .get("total")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        next_page_token: value
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        is_last: value.get("isLast").and_then(Value::as_bool),
    })
}

pub(crate) fn comment_from_value(value: Value) -> Result<JiraComment, JiraBackendError> {
    let body = value.get("body").cloned();
    Ok(JiraComment {
        id: string_or_number(&value, "id")?,
        parent_id: optional_string_or_number(&value, "parentId")?,
        body,
        author: optional_user_summary_from_value(&value, "author")?,
        created: value
            .get("created")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        updated: value
            .get("updated")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        visibility: optional_visibility_from_value(&value)?,
    })
}

pub(crate) fn comment_page_from_value(
    value: Value,
    requested_max_results: u32,
) -> Result<JiraCommentPage, JiraBackendError> {
    let comments = value
        .get("comments")
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("comment page comments missing".to_string()))?
        .iter()
        .cloned()
        .map(comment_summary_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    if comments.len() > requested_max_results as usize {
        return Err(JiraBackendError::Protocol(
            "comment list returned more comments than requested".to_string(),
        ));
    }
    Ok(JiraCommentPage {
        comments,
        max_results: value
            .get("maxResults")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(requested_max_results),
        start_at: value
            .get("startAt")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0),
        total: value
            .get("total")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
    })
}

pub(crate) fn comment_summary_from_value(
    value: Value,
) -> Result<JiraCommentSummary, JiraBackendError> {
    Ok(JiraCommentSummary {
        id: string_or_number(&value, "id")?,
        parent_id: optional_string_or_number(&value, "parentId")?,
        author: optional_user_summary_from_value(&value, "author")?,
        created: value
            .get("created")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        updated: value
            .get("updated")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        visibility: optional_visibility_from_value(&value)?,
    })
}

pub(crate) fn optional_user_summary_from_value(
    value: &Value,
    field: &str,
) -> Result<Option<JiraUserSummary>, JiraBackendError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    if !raw.is_object() {
        return Err(JiraBackendError::Protocol(format!(
            "{field} must be an object"
        )));
    }
    Ok(Some(JiraUserSummary {
        account_id: raw
            .get("accountId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        display_name: raw
            .get("displayName")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    }))
}

pub(crate) fn optional_issue_user_summary_from_fields(
    fields: &serde_json::Map<String, Value>,
    field: &str,
) -> Option<JiraUserSummary> {
    let raw = fields.get(field)?;
    if !raw.is_object() {
        return None;
    }
    let summary = JiraUserSummary {
        account_id: raw
            .get("accountId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        display_name: raw
            .get("displayName")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    };
    (summary.account_id.is_some() || summary.display_name.is_some()).then_some(summary)
}

pub(crate) fn optional_priority_summary_from_fields(
    fields: &serde_json::Map<String, Value>,
) -> Option<JiraPrioritySummary> {
    let raw = fields.get("priority")?;
    if !raw.is_object() {
        return None;
    }
    let priority = JiraPrioritySummary {
        id: raw.get("id").and_then(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        }),
        name: raw
            .get("name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    };
    (priority.id.is_some() || priority.name.is_some()).then_some(priority)
}

pub(crate) fn optional_labels_from_fields(
    fields: &serde_json::Map<String, Value>,
) -> Option<Vec<String>> {
    let raw = fields.get("labels")?;
    let labels = raw.as_array()?;
    labels
        .iter()
        .map(|value| value.as_str().map(ToString::to_string))
        .collect()
}

pub(crate) fn optional_visibility_from_value(
    value: &Value,
) -> Result<Option<JiraCommentVisibility>, JiraBackendError> {
    let Some(raw) = value.get("visibility") else {
        return Ok(None);
    };
    let object = raw.as_object().ok_or_else(|| {
        JiraBackendError::Protocol("comment visibility must be an object".to_string())
    })?;
    let visibility_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("comment visibility type missing".to_string()))?;
    match visibility_type {
        "group" => {
            let identifier = object
                .get("identifier")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JiraBackendError::Protocol(
                        "comment group visibility identifier missing".to_string(),
                    )
                })?;
            Ok(Some(JiraCommentVisibility {
                visibility_type: "group".to_string(),
                value: object
                    .get("value")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                identifier: Some(identifier.to_string()),
            }))
        }
        "role" => {
            let value = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                JiraBackendError::Protocol("comment role visibility value missing".to_string())
            })?;
            Ok(Some(JiraCommentVisibility {
                visibility_type: "role".to_string(),
                value: Some(value.to_string()),
                identifier: object
                    .get("identifier")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
            }))
        }
        _ => Err(JiraBackendError::Protocol(
            "comment visibility type is unsupported".to_string(),
        )),
    }
}

pub(crate) fn comment_property_keys_from_value(
    value: Value,
) -> Result<JiraCommentPropertyKeys, JiraBackendError> {
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("comment property keys missing".to_string()))?
        .iter()
        .map(|entry| {
            entry
                .get("key")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| {
                    JiraBackendError::Protocol("comment property key missing".to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JiraCommentPropertyKeys { keys })
}

pub(crate) fn comment_property_value_from_value(value: Value) -> Result<Value, JiraBackendError> {
    value
        .get("value")
        .cloned()
        .ok_or_else(|| JiraBackendError::Protocol("comment property value missing".to_string()))
}

pub(crate) fn issue_attachments_from_value(
    value: Value,
) -> Result<Vec<JiraAttachment>, JiraBackendError> {
    value
        .get("fields")
        .and_then(|fields| fields.get("attachment"))
        .and_then(Value::as_array)
        .ok_or_else(|| JiraBackendError::Protocol("issue attachments missing".to_string()))?
        .iter()
        .cloned()
        .map(attachment_from_value)
        .collect()
}

pub(crate) fn issue_attachment_list_from_value(
    value: Value,
) -> Result<JiraIssueAttachmentList, JiraBackendError> {
    Ok(JiraIssueAttachmentList {
        issue: issue_metadata_from_value(value.clone())?,
        attachments: issue_attachments_from_value(value)?,
    })
}

pub(crate) fn attachment_from_value(value: Value) -> Result<JiraAttachment, JiraBackendError> {
    let filename = value
        .get("filename")
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("attachment filename missing".to_string()))?;
    let content_type = value
        .get("mimeType")
        .or_else(|| value.get("contentType"))
        .and_then(Value::as_str)
        .ok_or_else(|| JiraBackendError::Protocol("attachment MIME type missing".to_string()))?;
    let size = value
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| JiraBackendError::Protocol("attachment size missing".to_string()))?;
    Ok(JiraAttachment {
        id: string_or_number(&value, "id")?,
        filename: filename.to_string(),
        size,
        content_type: content_type.to_string(),
    })
}

pub(crate) fn string_or_number(value: &Value, field: &str) -> Result<String, JiraBackendError> {
    value
        .get(field)
        .and_then(|raw| {
            raw.as_str()
                .map(ToString::to_string)
                .or_else(|| raw.as_u64().map(|number| number.to_string()))
        })
        .ok_or_else(|| JiraBackendError::Protocol(format!("{field} missing")))
}

pub(crate) fn optional_string_or_number(
    value: &Value,
    field: &str,
) -> Result<Option<String>, JiraBackendError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_str()
            .map(ToString::to_string)
            .or_else(|| raw.as_u64().map(|number| number.to_string()))
            .map(Some)
            .ok_or_else(|| JiraBackendError::Protocol(format!("{field} invalid"))),
    }
}
