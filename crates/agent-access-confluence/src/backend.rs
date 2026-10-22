//! The Confluence backend seam, its wire types, request bodies, and the HTTP implementation.
use super::*;
use agent_access_atlassian::{
    AtlassianAccessError, AtlassianClients, AtlassianCredential, AtlassianDownloadError,
    AtlassianProduct, AtlassianRoutes,
};
use agent_access_provider::host::UpstreamClientFactory;

#[async_trait]
pub trait ConfluenceBackend: Send + Sync {
    fn egress_proxy_audit(&self, _credential: &AtlassianCredential) -> Value {
        EgressRoute::direct().audit_value()
    }

    async fn current_user(
        &self,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Value>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence current-user verification is not supported by this backend".to_string(),
        ))
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError>;

    async fn space_by_key(
        &self,
        _space: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence space key lookup is not supported by this backend".to_string(),
        ))
    }

    async fn space_by_id(
        &self,
        _space_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence space id lookup is not supported by this backend".to_string(),
        ))
    }

    async fn blog_metadata(
        &self,
        _blog_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog metadata is not supported by this backend".to_string(),
        ))
    }

    async fn blog_scope_evidence(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogScopeEvidence>, ConfluenceBackendError>
    {
        let response = self.blog_metadata(blog_id, credential).await?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceBlogScopeEvidence {
                id: response.value.id,
                space: response.value.space,
                space_id: response.value.space_id,
                space_alias: response.value.space_alias,
            },
            status: response.status,
            duration_ms: response.duration_ms,
        })
    }

    async fn blog(
        &self,
        _blog_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog view is not supported by this backend".to_string(),
        ))
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError>;

    async fn page_hierarchy(
        &self,
        _page_id: &str,
        _get_draft: bool,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page hierarchy lookup is not supported by this backend".to_string(),
        ))
    }

    async fn page_ancestors(
        &self,
        _page_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page ancestor lookup is not supported by this backend".to_string(),
        ))
    }

    async fn page_direct_children(
        &self,
        _page_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageChild>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence direct-child lookup is not supported by this backend".to_string(),
        ))
    }

    async fn move_page(
        &self,
        _page_id: &str,
        _position: ConfluencePageMovePosition,
        _target_page_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page move is not supported by this backend".to_string(),
        ))
    }

    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError>;

    async fn search_blogs(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog search is not supported by this backend".to_string(),
        ))
    }

    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError>;

    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError>;

    async fn create_page_draft(
        &self,
        _request: ConfluenceDraftCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft create is not supported by this backend".to_string(),
        ))
    }

    async fn draft_page(
        &self,
        _page_id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft lookup is not supported by this backend".to_string(),
        ))
    }

    async fn update_page_draft(
        &self,
        _request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft update is not supported by this backend".to_string(),
        ))
    }

    async fn discard_page_draft(
        &self,
        _page_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft discard is not supported by this backend".to_string(),
        ))
    }

    async fn create_blog(
        &self,
        _request: ConfluenceBlogCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog create is not supported by this backend".to_string(),
        ))
    }

    async fn update_blog(
        &self,
        _request: ConfluenceBlogUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog update is not supported by this backend".to_string(),
        ))
    }

    async fn create_blog_draft(
        &self,
        _request: ConfluenceDraftCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft create is not supported by this backend".to_string(),
        ))
    }

    async fn draft_blog(
        &self,
        _blog_id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft lookup is not supported by this backend".to_string(),
        ))
    }

    async fn update_blog_draft(
        &self,
        _request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft update is not supported by this backend".to_string(),
        ))
    }

    async fn discard_blog_draft(
        &self,
        _blog_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft discard is not supported by this backend".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        page_id: &str,
        attachment: ConfluenceAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError>;

    async fn add_blog_attachment(
        &self,
        _blog_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment upload is not supported by this backend".to_string(),
        ))
    }

    async fn add_page_draft_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment upload is not supported by this backend".to_string(),
        ))
    }

    async fn add_blog_draft_attachment(
        &self,
        _blog_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft attachment upload is not supported by this backend".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError>;

    async fn page_attachments_page(
        &self,
        _page_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "bounded Confluence attachment listing is not supported by this backend".to_string(),
        ))
    }

    async fn blog_attachments_page(
        &self,
        _blog_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "bounded Confluence blog attachment listing is not supported by this backend"
                .to_string(),
        ))
    }

    async fn page_draft_attachments_page(
        &self,
        _page_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "bounded Confluence page draft attachment listing is not supported by this backend"
                .to_string(),
        ))
    }

    async fn blog_draft_attachments_page(
        &self,
        _blog_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "bounded Confluence blog draft attachment listing is not supported by this backend"
                .to_string(),
        ))
    }

    async fn blog_attachments(
        &self,
        _blog_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment lookup is not supported by this backend".to_string(),
        ))
    }

    async fn blog_attachment_content(
        &self,
        _blog_id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment download is not supported by this backend".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>;

    async fn page_draft_attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment download is not supported by this backend"
                .to_string(),
        ))
    }

    async fn blog_draft_attachment_content(
        &self,
        _blog_id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog draft attachment download is not supported by this backend"
                .to_string(),
        ))
    }

    async fn comment(
        &self,
        _kind: ConfluenceCommentKind,
        _comment_id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment lookup is not supported by this backend".to_string(),
        ))
    }

    async fn comments_page(
        &self,
        _request: ConfluenceCommentListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment listing is not supported by this backend".to_string(),
        ))
    }

    async fn comment_replies_page(
        &self,
        _kind: ConfluenceCommentKind,
        _comment_id: &str,
        _body_format: Option<&str>,
        _max_results: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment reply listing is not supported by this backend".to_string(),
        ))
    }

    async fn add_comment(
        &self,
        _request: ConfluenceCommentCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment creation is not supported by this backend".to_string(),
        ))
    }

    async fn update_comment(
        &self,
        _request: ConfluenceCommentUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment update is not supported by this backend".to_string(),
        ))
    }

    async fn delete_comment(
        &self,
        _kind: ConfluenceCommentKind,
        _comment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment delete is not supported by this backend".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluencePage {
    pub id: String,
    pub title: String,
    pub space: String,
    pub web_url: Option<String>,
    pub space_web_url: Option<String>,
    /// The URL alias a v2 space object reports for `space`; see
    /// [`ConfluenceSpace::alias`].
    pub space_alias: Option<String>,
    pub status: Option<String>,
    pub version: u64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub created_by: Option<ConfluenceCommentAuthor>,
    pub updated_by: Option<ConfluenceCommentAuthor>,
    pub bodies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceSpace {
    pub id: String,
    pub key: String,
    pub web_url: Option<String>,
    /// The space's URL alias (v2 `currentActiveAlias`) when an administrator
    /// changed the space's URL so that it differs from the key. It names
    /// browser links only, never a resource.
    pub alias: Option<String>,
    pub status: Option<String>,
    pub homepage_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluencePageHierarchy {
    pub id: String,
    pub space_id: String,
    pub parent_page_id: Option<String>,
    pub parent_type: Option<String>,
    pub status: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluencePageAncestor {
    pub id: String,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluencePageChild {
    pub id: String,
    pub content_type: String,
    pub status: String,
    pub child_position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceBlog {
    pub id: String,
    pub title: String,
    pub space: String,
    pub space_id: String,
    /// The URL alias its v2 space object reports for `space`; see
    /// [`ConfluenceSpace::alias`].
    pub space_alias: Option<String>,
    pub web_url: Option<String>,
    pub space_web_url: Option<String>,
    pub status: Option<String>,
    pub version: u64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub created_by: Option<ConfluenceCommentAuthor>,
    pub updated_by: Option<ConfluenceCommentAuthor>,
    pub bodies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceBlogSummary {
    pub id: String,
    pub title: String,
    pub space: String,
    pub web_url: Option<String>,
    pub space_web_url: Option<String>,
    pub status: Option<String>,
    pub version: u64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub created_by: Option<ConfluenceCommentAuthor>,
    pub updated_by: Option<ConfluenceCommentAuthor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceBlogScopeEvidence {
    pub id: String,
    pub space: String,
    pub space_id: String,
    /// The URL alias of `space`, which only checks a URL locator's space
    /// segment; see [`ConfluenceSpace::alias`].
    pub space_alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceSearchBlog {
    pub blogs: Vec<ConfluenceBlogSummary>,
    pub max_results: u32,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceSearchPage {
    pub pages: Vec<ConfluencePage>,
    pub max_results: u32,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceSearchRequest {
    pub cql: String,
    pub spaces: Vec<String>,
    pub max_results: u32,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceBlogCreateRequest {
    pub space: String,
    pub space_id: String,
    pub title: String,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceBlogUpdateRequest {
    pub blog_id: String,
    pub title: String,
    pub base_version: u64,
    pub version_message: Option<String>,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceDraftContent {
    pub id: String,
    pub title: String,
    pub content_type: String,
    pub space: String,
    pub space_id: String,
    /// The URL alias its v2 space object reports for `space`; see
    /// [`ConfluenceSpace::alias`].
    pub space_alias: Option<String>,
    pub parent_page_id: Option<String>,
    pub web_url: Option<String>,
    pub space_web_url: Option<String>,
    pub status: Option<String>,
    pub version: u64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub created_by: Option<ConfluenceCommentAuthor>,
    pub updated_by: Option<ConfluenceCommentAuthor>,
    pub bodies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceDraftCreateRequest {
    pub content_type: String,
    pub space: String,
    pub space_id: String,
    pub parent_page_id: Option<String>,
    pub title: String,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceDraftUpdateRequest {
    pub content_type: String,
    pub content_id: String,
    pub space_id: String,
    pub title: String,
    pub status: String,
    pub version_number: u64,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluencePageBody {
    pub representation: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluencePageCreateRequest {
    pub space: String,
    pub space_id: String,
    pub parent_page_id: Option<String>,
    pub title: String,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluencePageUpdateRequest {
    pub page_id: String,
    pub space: String,
    pub title: String,
    pub base_version: u64,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluencePagePreflight {
    pub(crate) page: ConfluencePage,
    pub(crate) upstream_status: u16,
    pub(crate) upstream_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluenceBlogPreflight {
    pub(crate) blog: ConfluenceBlog,
    pub(crate) upstream_status: u16,
    pub(crate) upstream_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluenceDraftContentPreflight {
    pub(crate) content: ConfluenceDraftContent,
    pub(crate) upstream_status: u16,
    pub(crate) upstream_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceAttachment {
    pub id: String,
    pub page_id: String,
    pub filename: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceAttachmentListPage {
    pub attachments: Vec<ConfluenceAttachment>,
    pub next_position: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceAttachmentUpload {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub bytes: Vec<u8>,
    pub temp_file: Option<Arc<BrokerBodyPartFile>>,
    pub sha256: String,
}

impl ConfluenceAttachmentUpload {
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
pub struct ConfluenceAttachmentContent {
    pub filename: String,
    pub content_type: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub stream: ProviderResultStream,
}

impl ConfluenceAttachmentContent {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceCommentAuthor {
    pub account_id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfluenceComment {
    pub id: String,
    pub kind: ConfluenceCommentKind,
    pub page_id: Option<String>,
    pub blog_id: Option<String>,
    pub parent_comment_id: Option<String>,
    pub status: Option<String>,
    pub resolution_status: Option<String>,
    pub version: Option<u64>,
    pub author: Option<ConfluenceCommentAuthor>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub bodies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceCommentListRequest {
    pub kind: ConfluenceCommentKind,
    pub container_type: ConfluenceCommentContainerType,
    pub container_id: String,
    pub body_format: Option<String>,
    pub resolution_status: Option<String>,
    pub sort: Option<String>,
    pub max_results: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceCommentListPage {
    pub comments: Vec<ConfluenceComment>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceCommentCreateRequest {
    pub kind: ConfluenceCommentKind,
    pub container_type: ConfluenceCommentContainerType,
    pub page_id: Option<String>,
    pub blog_id: Option<String>,
    pub parent_comment_id: Option<String>,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceCommentUpdateRequest {
    pub kind: ConfluenceCommentKind,
    pub comment_id: String,
    pub base_version: u64,
    pub body: ConfluencePageBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluenceAttachmentPage {
    pub(crate) attachments: Vec<ConfluenceAttachment>,
    pub(crate) next_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceBackendResponse<T> {
    pub value: T,
    pub status: u16,
    pub duration_ms: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfluenceBackendError {
    #[error("upstream unauthorized")]
    Unauthorized,
    #[error("upstream forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("http status {0}")]
    HttpStatus(u16),
    #[error("rate limited")]
    RateLimited(Option<UpstreamRetryAfter>),
    #[error("upstream validation failed with status {status}")]
    Validation { status: u16, message: String },
    /// The SDK proved the request never reached Confluence: it could not be
    /// built, or no connection was established (`timed_out` for a connect
    /// timeout). It reports the same reason as `Timeout` or `Transport`.
    #[error("request was not sent")]
    NotSent { timed_out: bool },
    /// The request may have reached Confluence, but no response arrived: it
    /// timed out (`timed_out`), its connection failed after it was sent, or
    /// the SDK reported a failure Confluence does not classify. It reports the
    /// same reason as `Timeout` or `Transport`.
    #[error("request got no response")]
    NoResponse { timed_out: bool },
    /// Confluence answered a write with a success status, but its response
    /// then failed, stalled, exceeded the byte cap or did not parse; reported
    /// like the wrapped failure.
    #[error("write accepted but its response failed: {0}")]
    AcceptedUnreadable(Box<ConfluenceBackendError>),
    /// Confluence answered with a redirect, which the Broker never follows. It
    /// reports the same reason as `Protocol`.
    #[error("Confluence redirect responses are rejected")]
    Redirected,
    /// Reading a response failed, or an upload file could not be opened.
    #[error("transport: {0}")]
    Transport(String),
    /// Reading a response stalled.
    #[error("request timed out")]
    Timeout,
    #[error("response too large")]
    ResponseTooLarge,
    #[error("protocol: {0}")]
    Protocol(String),
    /// Delegated (OAuth) access could not be presented: the lease's own
    /// failure (a refresh busy, throttled or uncertain, consent pending, a
    /// reconnect required, or an operation that already recovered), access
    /// for another site, or access Confluence rejected again. Nothing was
    /// sent, or Confluence's 401 applied nothing. Reported unchanged.
    #[error("Confluence credential could not be presented")]
    Credential(ProviderError),
}

impl From<AtlassianAccessError> for ConfluenceBackendError {
    fn from(error: AtlassianAccessError) -> Self {
        match error {
            AtlassianAccessError::Credential(error) => Self::Credential(error),
            _ => Self::Protocol("Confluence cannot route the selected credential".to_string()),
        }
    }
}

/// Marks a failure that followed a write's success `status` as
/// [`ConfluenceBackendError::AcceptedUnreadable`]; one after any other status
/// is returned unchanged.
pub(crate) fn accepted_if_success(
    status: u16,
) -> impl FnOnce(ConfluenceBackendError) -> ConfluenceBackendError {
    move |error| {
        if (200..300).contains(&status) {
            ConfluenceBackendError::AcceptedUnreadable(Box::new(error))
        } else {
            error
        }
    }
}

pub(crate) fn confluence_backend_error(error: ConfluenceBackendError) -> ProviderError {
    match error {
        ConfluenceBackendError::AcceptedUnreadable(error) => confluence_backend_error(*error),
        ConfluenceBackendError::Unauthorized => ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "Confluence credential was rejected",
        ),
        ConfluenceBackendError::Forbidden => ProviderError::error(
            ReasonCode::UpstreamForbidden,
            "Confluence access was forbidden",
        ),
        ConfluenceBackendError::NotFound => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence object was not found",
        ),
        ConfluenceBackendError::Conflict => ProviderError::error(
            ReasonCode::VersionConflict,
            "Confluence page version conflicted with the supplied base version",
        ),
        ConfluenceBackendError::HttpStatus(_) => ProviderError::error(
            ReasonCode::UpstreamFailed,
            "Confluence returned non-success",
        ),
        ConfluenceBackendError::RateLimited(retry_after) => {
            upstream_rate_limited("confluence", retry_after)
        }
        ConfluenceBackendError::Validation { status, message } => ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("Confluence rejected the request: {message}"),
        )
        .with_upstream(Some(status), None),
        ConfluenceBackendError::NotSent { timed_out: false }
        | ConfluenceBackendError::NoResponse { timed_out: false }
        | ConfluenceBackendError::Transport(_) => ProviderError::error(
            ReasonCode::UpstreamConnectionFailed,
            "Confluence request failed",
        ),
        ConfluenceBackendError::NotSent { timed_out: true }
        | ConfluenceBackendError::NoResponse { timed_out: true }
        | ConfluenceBackendError::Timeout => {
            ProviderError::error(ReasonCode::UpstreamTimeout, "Confluence request timed out")
        }
        ConfluenceBackendError::ResponseTooLarge => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence response exceeded the configured byte cap",
        ),
        ConfluenceBackendError::Redirected | ConfluenceBackendError::Protocol(_) => {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence response protocol error",
            )
        }
        ConfluenceBackendError::Credential(error) => error,
    }
}

pub(crate) fn map_confluence_conflict(error: ConfluenceBackendError) -> ProviderError {
    match error {
        ConfluenceBackendError::Conflict => ProviderError::error(
            ReasonCode::VersionConflict,
            "Confluence draft version conflicted with the broker-managed draft state",
        ),
        other => confluence_backend_error(other),
    }
}

pub(crate) fn confluence_backend_reason_code(error: &ConfluenceBackendError) -> ReasonCode {
    match error {
        ConfluenceBackendError::AcceptedUnreadable(error) => confluence_backend_reason_code(error),
        ConfluenceBackendError::Unauthorized => ReasonCode::UpstreamUnauthorized,
        ConfluenceBackendError::Forbidden => ReasonCode::UpstreamForbidden,
        ConfluenceBackendError::NotFound => ReasonCode::ScopeUnresolved,
        ConfluenceBackendError::Conflict => ReasonCode::VersionConflict,
        ConfluenceBackendError::HttpStatus(_) => ReasonCode::UpstreamFailed,
        ConfluenceBackendError::RateLimited(_) => ReasonCode::UpstreamRateLimited,
        ConfluenceBackendError::Validation { .. } => ReasonCode::InputInvalid,
        ConfluenceBackendError::NotSent { timed_out: false }
        | ConfluenceBackendError::NoResponse { timed_out: false }
        | ConfluenceBackendError::Transport(_) => ReasonCode::UpstreamConnectionFailed,
        ConfluenceBackendError::NotSent { timed_out: true }
        | ConfluenceBackendError::NoResponse { timed_out: true }
        | ConfluenceBackendError::Timeout => ReasonCode::UpstreamTimeout,
        ConfluenceBackendError::ResponseTooLarge
        | ConfluenceBackendError::Redirected
        | ConfluenceBackendError::Protocol(_) => ReasonCode::UpstreamProtocolFailed,
        // Never the outcome of reading a response; only presenting a
        // credential reports it.
        ConfluenceBackendError::Credential(_) => ReasonCode::CredentialInvalid,
    }
}

/// Confluence's REST API on the tenant host or the Atlassian gateway; v2
/// paths derive from it.
pub(crate) const CONFLUENCE_PRODUCT: AtlassianProduct = AtlassianProduct {
    provider: "confluence",
    name: "Confluence",
    api_path: "wiki/rest/api/",
    other_api_paths: &["wiki/api/v2/"],
    status_reasons: &[(409, ReasonCode::VersionConflict)],
};

#[derive(Clone)]
pub(crate) struct HttpConfluenceBackend {
    pub(crate) routes: AtlassianRoutes,
    pub(crate) config: ConfluenceProviderConfig,
    pub(crate) limits: ProviderLimits,
}

impl HttpConfluenceBackend {
    #[cfg(test)]
    pub(crate) fn for_tests(config: ConfluenceProviderConfig, limits: ProviderLimits) -> Self {
        let host = agent_access_provider::test_support::TestHost::with_limits(limits.clone());
        Self::new(config, limits, &host).expect("Confluence HTTP client configuration is valid")
    }

    pub(crate) fn new(
        config: ConfluenceProviderConfig,
        limits: ProviderLimits,
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        Ok(Self {
            routes: AtlassianRoutes::new(CONFLUENCE_PRODUCT, &config.site(), clients)?,
            config,
            limits,
        })
    }

    /// This backend with its gateway route served below `gateway`, an
    /// origin such as a stub server's:
    /// `{gateway}/ex/confluence/{cloud_id}/wiki/rest/api/`.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_gateway_origin(
        mut self,
        gateway: &str,
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let site = self.config.site();
        let cloud_id = site.gateway_cloud_id().ok_or_else(|| {
            ProviderBuildError::invalid("the test Confluence site has no Atlassian gateway route")
        })?;
        let base = Url::parse(&format!(
            "{}/ex/confluence/{cloud_id}/{}",
            gateway.trim_end_matches('/'),
            CONFLUENCE_PRODUCT.api_path
        ))
        .map_err(|error| ProviderBuildError::invalid(error.to_string()))?;
        let gateway = AtlassianClients::new(CONFLUENCE_PRODUCT, &site, base, clients)?;
        if let Some(route) = self.routes.gateway_mut() {
            *route = gateway;
        }
        Ok(self)
    }

    pub(crate) fn client_for(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&AtlassianClients, ConfluenceBackendError> {
        self.routes
            .for_credential(credential)
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))
    }

    /// Clients for one API base from the test host, routed through the
    /// configuration's service proxy when it sets one.
    #[cfg(test)]
    pub(crate) fn new_with_api_base(
        config: ConfluenceProviderConfig,
        limits: ProviderLimits,
        api_base_override: Url,
    ) -> Self {
        let host = agent_access_provider::test_support::TestHost::with_limits(limits.clone());
        let clients =
            AtlassianClients::new(CONFLUENCE_PRODUCT, &config.site(), api_base_override, &host)
                .expect("Confluence HTTP client configuration is valid");
        Self {
            routes: AtlassianRoutes::from_clients(
                CONFLUENCE_PRODUCT,
                clients.clone(),
                Some(clients),
            ),
            config,
            limits,
        }
    }

    pub(crate) fn api_base(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<Url, ConfluenceBackendError> {
        Ok(self.client_for(credential)?.api_base.clone())
    }

    /// The root of `credential`'s route's site, below which Confluence's
    /// path-absolute links name their resources.
    pub(crate) fn site_base(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<Url, ConfluenceBackendError> {
        Ok(self.client_for(credential)?.site_base.clone())
    }

    pub(crate) fn api_v2_base(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<Url, ConfluenceBackendError> {
        let mut base = self.api_base(credential)?;
        let path = base.path().to_string();
        let v2_path = path
            .strip_suffix("rest/api/")
            .map(|prefix| format!("{prefix}api/v2/"))
            .or_else(|| {
                path.strip_suffix("rest/api")
                    .map(|prefix| format!("{prefix}api/v2/"))
            })
            .ok_or_else(|| {
                ConfluenceBackendError::Protocol(
                    "Confluence API base cannot derive v2 base".to_string(),
                )
            })?;
        base.set_path(&v2_path);
        base.set_query(None);
        Ok(base)
    }
}

#[cfg(test)]
impl HttpConfluenceBackend {
    pub(crate) fn egress_proxy_for_test(&self, credential: &AtlassianCredential) -> Value {
        self.client_for(credential)
            .unwrap()
            .client
            .egress_route()
            .audit_value()
    }
}

impl HttpConfluenceBackend {
    pub(crate) fn request_client(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&UpstreamClient, ConfluenceBackendError> {
        Ok(&self.client_for(credential)?.client)
    }

    pub(crate) fn stream_client(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<&UpstreamClient, ConfluenceBackendError> {
        Ok(&self.client_for(credential)?.stream_client)
    }
}

#[async_trait]
impl ConfluenceBackend for HttpConfluenceBackend {
    fn egress_proxy_audit(&self, credential: &AtlassianCredential) -> Value {
        self.client_for(credential)
            .map(|clients| clients.client.egress_route().audit_value())
            .unwrap_or_else(|_| EgressRoute::direct().audit_value())
    }

    async fn current_user(
        &self,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Value>, ConfluenceBackendError> {
        let url = self
            .api_base(credential)?
            .join("user/current")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("current_user"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_blog_attachment(
        &self,
        blog_id: &str,
        attachment: ConfluenceAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("content/{blog_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.stream_client(credential)?;
        let mut response = send_confluence_upload(
            client,
            credential,
            || async {
                // Each attempt reopens the spooled body.
                let upload_part = confluence_upload_part(&attachment).await?;
                let form = reqwest::multipart::Form::new().part("file", upload_part.part);
                Ok((
                    client
                        .request(Method::POST, url.clone())
                        .header("Accept", "application/json")
                        .header("X-Atlassian-Token", "nocheck")
                        .multipart(form),
                    upload_part.progress,
                ))
            },
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            UpstreamCall::new("blog.attachment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        // The trace outlives the deadline, so a stalled body records a timeout.
        let trace = take_upstream_trace(&mut response);
        let value = tokio::time::timeout(
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            read_confluence_response_value(
                response,
                self.limits.max_upstream_response_bytes,
                trace.as_ref(),
            ),
        )
        .await
        .unwrap_or(Err(ConfluenceBackendError::Timeout));
        complete_confluence_trace(trace, &value);
        let value = value.map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: first_attachment_from_value_with_required_parent(value, blog_id)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("expand", "space,version,history");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.metadata"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: page_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page_hierarchy(
        &self,
        page_id: &str,
        get_draft: bool,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        if get_draft {
            url.query_pairs_mut().append_pair("get-draft", "true");
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.hierarchy"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: page_hierarchy_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page_ancestors(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        let site_base = self.site_base(credential)?;
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}/ancestors"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("limit", "250");
        let started = Instant::now();
        let mut ancestors = Vec::new();
        let mut last_status = 0;
        for attempt in 1..=MAX_PAGE_ANCESTOR_LOOKUP_PAGES {
            let client = self.request_client(credential)?;
            let response = send_confluence_request(
                client,
                credential,
                client
                    .request(Method::GET, url.clone())
                    .header("Accept", "application/json"),
                UpstreamCall::new("page.ancestors").with_attempt(attempt as u32),
            )
            .await?;
            last_status = response.status().as_u16();
            let value =
                confluence_response_value(response, self.limits.max_upstream_response_bytes)
                    .await?;
            let (mut page, next) = page_ancestors_from_value(value)?;
            ancestors.append(&mut page);
            let Some(next) = next else {
                return Ok(ConfluenceBackendResponse {
                    value: ancestors,
                    status: last_status,
                    duration_ms: elapsed_ms(started),
                });
            };
            let cursor = next_page_cursor(
                &url,
                &site_base,
                &next,
                &self.config.allowed_upstream_hosts,
                "ancestor",
                &["limit"],
            )?;
            url.set_query(None);
            url.query_pairs_mut()
                .append_pair("limit", "250")
                .append_pair("cursor", &cursor);
        }
        let _ = last_status;
        Err(ConfluenceBackendError::Protocol(
            "Confluence page ancestor pagination limit exceeded".to_string(),
        ))
    }

    async fn page_direct_children(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageChild>>, ConfluenceBackendError> {
        let site_base = self.site_base(credential)?;
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}/direct-children"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("limit", "250");
        let started = Instant::now();
        let mut children = Vec::new();
        let mut last_status = 0;
        for attempt in 1..=MAX_PAGE_DIRECT_CHILD_LOOKUP_PAGES {
            let client = self.request_client(credential)?;
            let response = send_confluence_request(
                client,
                credential,
                client
                    .request(Method::GET, url.clone())
                    .header("Accept", "application/json"),
                UpstreamCall::new("page.direct_children").with_attempt(attempt as u32),
            )
            .await?;
            last_status = response.status().as_u16();
            let value =
                confluence_response_value(response, self.limits.max_upstream_response_bytes)
                    .await?;
            let (mut page, next) = page_direct_children_from_value(value)?;
            children.append(&mut page);
            let Some(next) = next else {
                return Ok(ConfluenceBackendResponse {
                    value: children,
                    status: last_status,
                    duration_ms: elapsed_ms(started),
                });
            };
            let cursor = next_page_cursor(
                &url,
                &site_base,
                &next,
                &self.config.allowed_upstream_hosts,
                "direct-child",
                &["limit"],
            )?;
            url.set_query(None);
            url.query_pairs_mut()
                .append_pair("limit", "250")
                .append_pair("cursor", &cursor);
        }
        let _ = last_status;
        Err(ConfluenceBackendError::Protocol(
            "Confluence direct-child pagination limit exceeded".to_string(),
        ))
    }

    async fn move_page(
        &self,
        page_id: &str,
        position: ConfluencePageMovePosition,
        target_page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!(
                "content/{page_id}/move/{}/{target_page_id}",
                position.as_str()
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.move"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        let moved_page_id = value
            .get("pageId")
            .and_then(Value::as_str)
            .filter(|id| is_page_id(id))
            .ok_or_else(|| {
                ConfluenceBackendError::Protocol(
                    "Confluence page move response omitted pageId".to_string(),
                )
            })
            .map_err(accepted_if_success(status))?
            .to_string();
        Ok(ConfluenceBackendResponse {
            value: moved_page_id,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair(
            "expand",
            "space,version,history,body.storage,body.atlas_doc_format",
        );
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: page_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn space_by_key(
        &self,
        space: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join("spaces")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("keys", space)
            .append_pair("limit", "1");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("space.lookup.key"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: single_space_from_results(value, space)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn space_by_id(
        &self,
        space_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("spaces/{space_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("space.lookup.id"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: space_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn blog_metadata(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.metadata"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: blog_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn blog_scope_evidence(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogScopeEvidence>, ConfluenceBackendError>
    {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.scope"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: blog_scope_evidence_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn blog(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("body-format", "storage");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: blog_from_value(value)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join("content/search")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("cql", &request.cql)
                .append_pair("limit", &request.max_results.to_string())
                // Content search returns content `status` in the base item; expand only
                // requests nested objects needed for validation and output.
                .append_pair("expand", "space,version,history");
            if let Some(token) = &request.next_page_token {
                query.append_pair("cursor", token);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("search"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: search_page_from_value(value, request.max_results)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn search_blogs(
        &self,
        request: ConfluenceSearchRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join("content/search")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("cql", &request.cql)
                .append_pair("limit", &request.max_results.to_string())
                .append_pair("expand", "space,version,history");
            if let Some(token) = &request.next_page_token {
                query.append_pair("cursor", token);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.search"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: search_blog_from_value(value, request.max_results)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join("pages")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        // With root-level=false, Confluence v2 assigns the space homepage when
        // parentId is omitted. Explicit parent placement still sends parentId.
        url.query_pairs_mut().append_pair("root-level", "false");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&page_create_request_body(&request)),
            UpstreamCall::new("page.create"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: page_from_v2_value(value, &request.space, &request.space_id)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("content/{}", request.page_id))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&content_request_body(
                    request.page_id,
                    request.base_version + 1,
                    request.space,
                    request.title,
                    request.body,
                )),
            UpstreamCall::new("page.update"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: page_from_value(value).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_page_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join("pages")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        // Draft creation follows the same homepage default as current pages.
        url.query_pairs_mut().append_pair("root-level", "false");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&draft_create_request_body(&request)),
            UpstreamCall::new("page.draft.create"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Page)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn draft_page(
        &self,
        page_id: &str,
        body_format: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("get-draft", "true");
            if let Some(body_format) = body_format {
                pairs.append_pair("body-format", body_format);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.draft.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Page)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_page_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{}", request.content_id))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&draft_update_request_body(&request)),
            UpstreamCall::new(if request.status == "current" {
                "page.draft.publish"
            } else {
                "page.draft.update"
            }),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Page)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn discard_page_draft(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("draft", "true");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::DELETE, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.draft.discard"),
        )
        .await?;
        let status = response.status().as_u16();
        confluence_response_no_content(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_blog(
        &self,
        request: ConfluenceBlogCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join("blogposts")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&blog_create_request_body(&request)),
            UpstreamCall::new("blog.create"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: blog_from_value(value).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_blog(
        &self,
        request: ConfluenceBlogUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{}", request.blog_id))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&blog_update_request_body(&request)),
            UpstreamCall::new("blog.update"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: blog_from_value(value).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn create_blog_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join("blogposts")
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&draft_create_request_body(&request)),
            UpstreamCall::new("blog.draft.create"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Blog)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn draft_blog(
        &self,
        blog_id: &str,
        body_format: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("get-draft", "true");
            if let Some(body_format) = body_format {
                pairs.append_pair("body-format", body_format);
            }
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.draft.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Blog)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_blog_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{}", request.content_id))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&draft_update_request_body(&request)),
            UpstreamCall::new(if request.status == "current" {
                "blog.draft.publish"
            } else {
                "blog.draft.update"
            }),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: draft_content_from_value(value, ConfluenceDraftContentType::Blog)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn discard_blog_draft(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("draft", "true");
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::DELETE, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.draft.discard"),
        )
        .await?;
        let status = response.status().as_u16();
        confluence_response_no_content(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_attachment(
        &self,
        page_id: &str,
        attachment: ConfluenceAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        let url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.stream_client(credential)?;
        let mut response = send_confluence_upload(
            client,
            credential,
            || async {
                // Each attempt reopens the spooled body.
                let upload_part = confluence_upload_part(&attachment).await?;
                let form = reqwest::multipart::Form::new().part("file", upload_part.part);
                Ok((
                    client
                        .request(Method::POST, url.clone())
                        .header("Accept", "application/json")
                        .header("X-Atlassian-Token", "nocheck")
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
            read_confluence_response_value(
                response,
                self.limits.max_upstream_response_bytes,
                trace.as_ref(),
            ),
        )
        .await
        .unwrap_or(Err(ConfluenceBackendError::Timeout));
        complete_confluence_trace(trace, &value);
        let value = value.map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: first_attachment_from_value(value, page_id)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_page_draft_attachment(
        &self,
        page_id: &str,
        attachment: ConfluenceAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("status", "draft");
        let started = Instant::now();
        let client = self.stream_client(credential)?;
        let mut response = send_confluence_upload(
            client,
            credential,
            || async {
                // Each attempt reopens the spooled body.
                let upload_part = confluence_upload_part(&attachment).await?;
                let form = reqwest::multipart::Form::new().part("file", upload_part.part);
                Ok((
                    client
                        .request(Method::POST, url.clone())
                        .header("Accept", "application/json")
                        .header("X-Atlassian-Token", "nocheck")
                        .multipart(form),
                    upload_part.progress,
                ))
            },
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            UpstreamCall::new("page.draft.attachment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        // The trace outlives the deadline, so a stalled body records a timeout.
        let trace = take_upstream_trace(&mut response);
        let value = tokio::time::timeout(
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            read_confluence_response_value(
                response,
                self.limits.max_upstream_response_bytes,
                trace.as_ref(),
            ),
        )
        .await
        .unwrap_or(Err(ConfluenceBackendError::Timeout));
        complete_confluence_trace(trace, &value);
        let value = value.map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: first_attachment_from_value_with_required_parent(value, page_id)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_blog_draft_attachment(
        &self,
        blog_id: &str,
        attachment: ConfluenceAttachmentUpload,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{blog_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("status", "draft");
        let started = Instant::now();
        let client = self.stream_client(credential)?;
        let mut response = send_confluence_upload(
            client,
            credential,
            || async {
                // Each attempt reopens the spooled body.
                let upload_part = confluence_upload_part(&attachment).await?;
                let form = reqwest::multipart::Form::new().part("file", upload_part.part);
                Ok((
                    client
                        .request(Method::POST, url.clone())
                        .header("Accept", "application/json")
                        .header("X-Atlassian-Token", "nocheck")
                        .multipart(form),
                    upload_part.progress,
                ))
            },
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            UpstreamCall::new("blog.draft.attachment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        // The trace outlives the deadline, so a stalled body records a timeout.
        let trace = take_upstream_trace(&mut response);
        let value = tokio::time::timeout(
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            read_confluence_response_value(
                response,
                self.limits.max_upstream_response_bytes,
                trace.as_ref(),
            ),
        )
        .await
        .unwrap_or(Err(ConfluenceBackendError::Timeout));
        complete_confluence_trace(trace, &value);
        let value = value.map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: first_attachment_from_value_with_required_parent(value, blog_id)
                .map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page_attachments(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("expand", "version,metadata,extensions")
            .append_pair("limit", "200");
        let api_base = self.api_base(credential)?;
        let started = Instant::now();
        let mut attachments = Vec::new();
        for attempt in 1..=100 {
            let client = self.request_client(credential)?;
            let response = send_confluence_request(
                client,
                credential,
                client
                    .request(Method::GET, url.clone())
                    .header("Accept", "application/json"),
                UpstreamCall::new("attachment.list").with_attempt(attempt),
            )
            .await?;
            let status = response.status().as_u16();
            let value =
                confluence_response_value(response, self.limits.max_upstream_response_bytes)
                    .await?;
            let page = attachment_page_from_value(value, page_id)?;
            attachments.extend(page.attachments);
            let Some(next) = page.next_link else {
                return Ok(ConfluenceBackendResponse {
                    value: attachments,
                    status,
                    duration_ms: elapsed_ms(started),
                });
            };
            url = next_attachment_page_url(
                &url,
                &api_base,
                page_id,
                &next,
                &self.config.allowed_upstream_hosts,
            )?;
        }
        Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination limit exceeded".to_string(),
        ))
    }

    async fn page_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{page_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("expand", "version,metadata,extensions,container")
                .append_pair("limit", &max_results.to_string());
            for (key, value) in decoded_attachment_next_position(next_position, false)? {
                pairs.append_pair(&key, &value);
            }
        }
        let api_base = self.api_base(credential)?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("attachment.page"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let page = attachment_list_page_from_value(value, page_id)?;
        if page.attachments.len() > max_results as usize {
            return Err(ConfluenceBackendError::Protocol(
                "Confluence attachment list returned more attachments than requested".to_string(),
            ));
        }
        let next_position = page
            .next_link
            .as_deref()
            .map(|next| {
                next_attachment_page_position(
                    &url,
                    &api_base,
                    page_id,
                    next,
                    &self.config.allowed_upstream_hosts,
                )
            })
            .transpose()?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page.attachments,
                next_position,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn blog_attachments(
        &self,
        blog_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(&format!("content/{blog_id}/child/attachment"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("expand", "version,metadata,extensions,container")
            .append_pair("limit", "200");
        let api_base = self.api_base(credential)?;
        let started = Instant::now();
        let mut attachments = Vec::new();
        for attempt in 1..=100 {
            let client = self.request_client(credential)?;
            let response = send_confluence_request(
                client,
                credential,
                client
                    .request(Method::GET, url.clone())
                    .header("Accept", "application/json"),
                UpstreamCall::new("blog.attachment.lookup").with_attempt(attempt),
            )
            .await?;
            let status = response.status().as_u16();
            let value =
                confluence_response_value(response, self.limits.max_upstream_response_bytes)
                    .await?;
            let page = attachment_list_page_from_value(value, blog_id)?;
            attachments.extend(page.attachments);
            let Some(next) = page.next_link else {
                return Ok(ConfluenceBackendResponse {
                    value: attachments,
                    status,
                    duration_ms: elapsed_ms(started),
                });
            };
            url = next_attachment_page_url(
                &url,
                &api_base,
                blog_id,
                &next,
                &self.config.allowed_upstream_hosts,
            )?;
        }
        Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment pagination limit exceeded".to_string(),
        ))
    }

    async fn blog_attachments_page(
        &self,
        blog_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("blogposts/{blog_id}/attachments"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("limit", &max_results.to_string());
            for (key, value) in decoded_attachment_next_position(next_position, false)? {
                pairs.append_pair(&key, &value);
            }
        }
        let api_base = self.api_v2_base(credential)?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("blog.attachment.page"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let page = attachment_list_page_from_value(value, blog_id)?;
        if page.attachments.len() > max_results as usize {
            return Err(ConfluenceBackendError::Protocol(
                "Confluence blog attachment list returned more attachments than requested"
                    .to_string(),
            ));
        }
        let next_position = page
            .next_link
            .as_deref()
            .map(|next| {
                next_blog_attachment_page_position(
                    &url,
                    &api_base,
                    blog_id,
                    next,
                    &self.config.allowed_upstream_hosts,
                )
            })
            .transpose()?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page.attachments,
                next_position,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn page_draft_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("pages/{page_id}/attachments"))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("limit", &max_results.to_string());
            for (key, value) in decoded_attachment_next_position(next_position, false)? {
                pairs.append_pair(&key, &value);
            }
        }
        let api_base = self.api_v2_base(credential)?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("page.draft.attachment.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let page = attachment_list_page_from_value(value, page_id)?;
        if page.attachments.len() > max_results as usize {
            return Err(ConfluenceBackendError::Protocol(
                "Confluence page draft attachment list returned more attachments than requested"
                    .to_string(),
            ));
        }
        let next_position = page
            .next_link
            .as_deref()
            .map(|next| {
                next_draft_page_attachment_page_position(
                    &url,
                    &api_base,
                    page_id,
                    next,
                    &self.config.allowed_upstream_hosts,
                )
            })
            .transpose()?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page.attachments,
                next_position,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn blog_draft_attachments_page(
        &self,
        blog_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.blog_attachments_page(blog_id, max_results, next_position, credential)
            .await
    }

    async fn blog_attachment_content(
        &self,
        blog_id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let url = self
            .api_base(credential)?
            .join(&format!(
                "content/{blog_id}/child/attachment/{attachment_id}/download"
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
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
        if let Err(error) = validate_confluence_body_response(&response, byte_cap) {
            complete_upstream_trace(
                &mut response,
                Some(confluence_backend_reason_code(&error).into()),
            );
            return Err(error);
        }
        complete_upstream_trace(&mut response, None);
        let content_length = response.content_length();
        let stream = confluence_response_stream(
            response,
            byte_cap,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            content_length,
            content_type.clone(),
        );
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentContent {
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
        kind: ConfluenceCommentKind,
        comment_id: &str,
        body_format: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("{}/{comment_id}", kind.path_collection()))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        if let Some(body_format) = body_format {
            url.query_pairs_mut()
                .append_pair("body-format", body_format);
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.get"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(ConfluenceBackendResponse {
            value: comment_from_value(value, kind)?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comments_page(
        &self,
        request: ConfluenceCommentListRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        let container_segment = match request.container_type {
            ConfluenceCommentContainerType::Page => "pages",
            ConfluenceCommentContainerType::Blog => "blogposts",
        };
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!(
                "{}/{}/{}",
                container_segment,
                request.container_id,
                request.kind.path_collection()
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("limit", &request.max_results.to_string());
            if let Some(body_format) = &request.body_format {
                pairs.append_pair("body-format", body_format);
            }
            if let Some(resolution_status) = &request.resolution_status {
                pairs.append_pair("resolution-status", resolution_status);
            }
            if let Some(sort) = &request.sort {
                pairs.append_pair("sort", sort);
            }
            if let Some(cursor) = &request.cursor {
                pairs.append_pair("cursor", cursor);
            }
        }
        let site_base = self.site_base(credential)?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let header_next_links = comment_next_links_from_headers(response.headers())?;
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let page = comment_list_page_from_value(value, request.kind)?;
        let next_cursor = next_comment_page_cursor_from_sources(
            &url,
            &site_base,
            page.next_cursor.as_deref(),
            &header_next_links,
            &self.config.allowed_upstream_hosts,
        )?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments: page.comments,
                next_cursor,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn comment_replies_page(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        body_format: Option<&str>,
        max_results: u32,
        cursor: Option<&str>,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        let mut url = self
            .api_v2_base(credential)?
            .join(&format!("{}/{comment_id}/children", kind.path_collection()))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("limit", &max_results.to_string());
            if let Some(body_format) = body_format {
                pairs.append_pair("body-format", body_format);
            }
            if let Some(cursor) = cursor {
                pairs.append_pair("cursor", cursor);
            }
        }
        let site_base = self.site_base(credential)?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::GET, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.reply.list"),
        )
        .await?;
        let status = response.status().as_u16();
        let header_next_links = comment_next_links_from_headers(response.headers())?;
        let value =
            confluence_response_value(response, self.limits.max_upstream_response_bytes).await?;
        let page = comment_list_page_from_value(value, kind)?;
        let next_cursor = next_comment_page_cursor_from_sources(
            &url,
            &site_base,
            page.next_cursor.as_deref(),
            &header_next_links,
            &self.config.allowed_upstream_hosts,
        )?;
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments: page.comments,
                next_cursor,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn add_comment(
        &self,
        request: ConfluenceCommentCreateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(request.kind.path_collection())
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::POST, url.clone())
                .header("Accept", "application/json")
                .json(&comment_create_request_body(&request)),
            UpstreamCall::new("comment.add"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_response_value(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: comment_from_value(value, request.kind).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn update_comment(
        &self,
        request: ConfluenceCommentUpdateRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!(
                "{}/{}",
                request.kind.path_collection(),
                request.comment_id
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::PUT, url.clone())
                .header("Accept", "application/json")
                .json(&comment_update_request_body(&request)),
            UpstreamCall::new("comment.update"),
        )
        .await?;
        let status = response.status().as_u16();
        let value = confluence_comment_update_response_value(
            response,
            self.limits.max_upstream_response_bytes,
        )
        .await
        .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: comment_from_value(value, request.kind).map_err(accepted_if_success(status))?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn delete_comment(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        let url = self
            .api_v2_base(credential)?
            .join(&format!("{}/{comment_id}", kind.path_collection()))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let response = send_confluence_request(
            client,
            credential,
            client
                .request(Method::DELETE, url.clone())
                .header("Accept", "application/json"),
            UpstreamCall::new("comment.delete"),
        )
        .await?;
        let status = response.status().as_u16();
        confluence_response_no_content(response, self.limits.max_upstream_response_bytes)
            .await
            .map_err(accepted_if_success(status))?;
        Ok(ConfluenceBackendResponse {
            value: (),
            status,
            duration_ms: elapsed_ms(started),
        })
    }

    async fn attachment_content(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let url = self
            .api_base(credential)?
            .join(&format!(
                "content/{page_id}/child/attachment/{attachment_id}/download"
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
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
        if let Err(error) = validate_confluence_body_response(&response, byte_cap) {
            complete_upstream_trace(
                &mut response,
                Some(confluence_backend_reason_code(&error).into()),
            );
            return Err(error);
        }
        complete_upstream_trace(&mut response, None);
        let content_length = response.content_length();
        let stream = confluence_response_stream(
            response,
            byte_cap,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            content_length,
            content_type.clone(),
        );
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentContent {
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

    async fn page_draft_attachment_content(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let mut url = self
            .api_base(credential)?
            .join(&format!(
                "content/{page_id}/child/attachment/{attachment_id}/download"
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("status", "draft");
        self.draft_attachment_content_response(url, credential)
            .await
    }

    async fn blog_draft_attachment_content(
        &self,
        blog_id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let mut url = self
            .api_base(credential)?
            .join(&format!(
                "content/{blog_id}/child/attachment/{attachment_id}/download"
            ))
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
        url.query_pairs_mut().append_pair("status", "draft");
        self.draft_attachment_content_response(url, credential)
            .await
    }
}

impl HttpConfluenceBackend {
    pub(crate) async fn draft_attachment_content_response(
        &self,
        url: Url,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
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
        if let Err(error) = validate_confluence_body_response(&response, byte_cap) {
            complete_upstream_trace(
                &mut response,
                Some(confluence_backend_reason_code(&error).into()),
            );
            return Err(error);
        }
        complete_upstream_trace(&mut response, None);
        let content_length = response.content_length();
        let stream = confluence_response_stream(
            response,
            byte_cap,
            Duration::from_millis(self.limits.streaming_idle_timeout_ms),
            content_length,
            content_type.clone(),
        );
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentContent {
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

    /// Downloads `url`, following up to 5 of Atlassian's media redirects.
    /// The credential reaches only hops within the route's site, each with
    /// freshly revalidated delegated access, and a redirect to another site
    /// on the route's origin fails before it is sent. Delegated access that
    /// Confluence itself answers with 401 recovers once and the download starts
    /// over ([`AtlassianCredential::download`]).
    pub(crate) async fn attachment_content_response(
        &self,
        url: Url,
        credential: &AtlassianCredential,
    ) -> Result<reqwest::Response, ConfluenceBackendError> {
        credential
            .download(
                self.client_for(credential)?,
                url,
                5,
                Duration::from_millis(self.limits.request_timeout_ms),
                "attachment.download",
                "Confluence",
            )
            .await
            .map_err(|error| match error {
                AtlassianDownloadError::Upstream(error) => confluence_upstream_error(error),
                AtlassianDownloadError::Access(error) => error.into(),
            })
    }
}

/// Sends through `client` with `credential`'s authorization, mapping
/// transport failures to Confluence errors. An unsupported credential kind
/// fails before anything is sent. Delegated access is pinned immediately
/// before each attempt. Confluence answering it with 401 authenticated
/// nothing and so applied nothing: the presented version is marked rejected
/// and, when the operation's lease can still recover, the request is
/// repeated once with the renewed access ([`AtlassianCredential::rejected`]).
/// A static token's 401 is never repeated.
pub(crate) async fn send_confluence_request(
    client: &UpstreamClient,
    credential: &AtlassianCredential,
    request: reqwest::RequestBuilder,
    call: UpstreamCall<'_>,
) -> Result<reqwest::Response, ConfluenceBackendError> {
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
            .map_err(confluence_upstream_error)?;
        if response.status().as_u16() == 401 && presented.is_delegated() {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid.into()));
            request = credential
                .rejected(&presented, replay, "Confluence")
                .await?;
            attempt += 1;
            continue;
        }
        return Ok(response);
    }
}

pub(crate) fn confluence_upstream_error(error: UpstreamError) -> ConfluenceBackendError {
    match error {
        // Only the SDK's own not-sent classification proves Confluence never
        // received the request; every other failure may have reached it.
        UpstreamError::NotSent { timed_out, .. } => ConfluenceBackendError::NotSent { timed_out },
        UpstreamError::Timeout => ConfluenceBackendError::NoResponse { timed_out: true },
        UpstreamError::Transport(_) => ConfluenceBackendError::NoResponse { timed_out: false },
        UpstreamError::NotAllowed => ConfluenceBackendError::Protocol(
            "Confluence upstream URL is not allowlisted".to_string(),
        ),
        UpstreamError::Redirect => ConfluenceBackendError::Protocol(
            "Confluence attachment redirect is invalid".to_string(),
        ),
        // Any other failure produced no usable response and may have reached
        // Confluence.
        _ => ConfluenceBackendError::NoResponse { timed_out: false },
    }
}

pub(crate) fn next_attachment_page_url(
    current_url: &Url,
    api_base: &Url,
    page_id: &str,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<Url, ConfluenceBackendError> {
    let parsed = Url::parse(raw_next)
        .or_else(|_| api_base.join(raw_next))
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
    if !same_origin(&parsed, api_base) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination changed origin".to_string(),
        ));
    }
    if !attachment_list_path_matches(&parsed, page_id) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination changed resource".to_string(),
        ));
    }
    let Some(query) = parsed.query() else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination link is missing query".to_string(),
        ));
    };
    let mut next_url = current_url.clone();
    next_url.set_query(Some(query));
    ensure_url_allowed(&next_url, allowed_upstream_hosts)?;
    Ok(next_url)
}

pub(crate) fn next_attachment_page_position(
    current_url: &Url,
    api_base: &Url,
    page_id: &str,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<String, ConfluenceBackendError> {
    let next_url = next_attachment_page_url(
        current_url,
        api_base,
        page_id,
        raw_next,
        allowed_upstream_hosts,
    )?;
    let allowed = decoded_attachment_next_position(next_url.query(), true)?;
    if allowed.is_empty() {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination link is missing a continuation position".to_string(),
        ));
    }
    Ok(allowed
        .into_iter()
        .map(|(key, value)| {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.append_pair(&key, &value);
            encoded.finish()
        })
        .collect::<Vec<_>>()
        .join("&"))
}

pub(crate) fn next_blog_attachment_page_url(
    current_url: &Url,
    api_base: &Url,
    blog_id: &str,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<Url, ConfluenceBackendError> {
    let parsed = Url::parse(raw_next)
        .or_else(|_| api_base.join(raw_next))
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
    if !same_origin(&parsed, api_base) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment pagination changed origin".to_string(),
        ));
    }
    if !blog_attachment_list_path_matches(&parsed, blog_id) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment pagination changed resource".to_string(),
        ));
    }
    let Some(query) = parsed.query() else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment pagination link is missing query".to_string(),
        ));
    };
    let mut next_url = current_url.clone();
    next_url.set_query(Some(query));
    ensure_url_allowed(&next_url, allowed_upstream_hosts)?;
    Ok(next_url)
}

pub(crate) fn next_blog_attachment_page_position(
    current_url: &Url,
    api_base: &Url,
    blog_id: &str,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<String, ConfluenceBackendError> {
    let next_url = next_blog_attachment_page_url(
        current_url,
        api_base,
        blog_id,
        raw_next,
        allowed_upstream_hosts,
    )?;
    let allowed = decoded_attachment_next_position(next_url.query(), true)?;
    if allowed.is_empty() {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence blog attachment pagination link is missing a continuation position"
                .to_string(),
        ));
    }
    Ok(allowed
        .into_iter()
        .map(|(key, value)| {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.append_pair(&key, &value);
            encoded.finish()
        })
        .collect::<Vec<_>>()
        .join("&"))
}

pub(crate) fn next_draft_page_attachment_page_position(
    current_url: &Url,
    api_base: &Url,
    page_id: &str,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<String, ConfluenceBackendError> {
    let parsed = Url::parse(raw_next)
        .or_else(|_| api_base.join(raw_next))
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
    if !same_origin(&parsed, api_base) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment pagination changed origin".to_string(),
        ));
    }
    if !draft_page_attachment_list_path_matches(&parsed, page_id) {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment pagination changed resource".to_string(),
        ));
    }
    let Some(query) = parsed.query() else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment pagination link is missing query".to_string(),
        ));
    };
    let mut next_url = current_url.clone();
    next_url.set_query(Some(query));
    ensure_url_allowed(&next_url, allowed_upstream_hosts)?;
    let allowed = decoded_attachment_next_position(next_url.query(), true)?;
    if allowed.is_empty() {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence page draft attachment pagination link is missing a continuation position"
                .to_string(),
        ));
    }
    Ok(allowed
        .into_iter()
        .map(|(key, value)| {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.append_pair(&key, &value);
            encoded.finish()
        })
        .collect::<Vec<_>>()
        .join("&"))
}

pub(crate) fn decoded_attachment_next_position(
    next_position: Option<&str>,
    allow_confluence_echo_params: bool,
) -> Result<Vec<(String, String)>, ConfluenceBackendError> {
    let Some(next_position) = next_position else {
        return Ok(Vec::new());
    };
    let pairs = url::form_urlencoded::parse(next_position.as_bytes()).collect::<Vec<_>>();
    if pairs.is_empty() {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination position is empty".to_string(),
        ));
    }
    let mut allowed = Vec::new();
    for (key, value) in pairs {
        match key.as_ref() {
            "start" | "cursor" => {
                if value.is_empty() {
                    return Err(ConfluenceBackendError::Protocol(
                        "Confluence attachment pagination position is empty".to_string(),
                    ));
                }
                allowed.push((key.into_owned(), value.into_owned()));
            }
            "limit" | "expand" if allow_confluence_echo_params => {}
            _ => {
                return Err(ConfluenceBackendError::Protocol(
                    "Confluence attachment pagination position includes unsupported parameters"
                        .to_string(),
                ));
            }
        }
    }
    if allowed.len() != 1 {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence attachment pagination position is ambiguous".to_string(),
        ));
    }
    Ok(allowed)
}

/// The cursor of a comment or reply list's `next` link; see
/// [`next_page_cursor`] for the link rules.
pub(crate) fn next_comment_page_cursor(
    current_url: &Url,
    site_base: &Url,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
) -> Result<String, ConfluenceBackendError> {
    next_page_cursor(
        current_url,
        site_base,
        raw_next,
        allowed_upstream_hosts,
        "comment",
        &["limit", "body-format", "resolution-status", "sort"],
    )
}

/// The cursor of a v2 list's `next` link. The link must keep the route's
/// origin and name the collection `current_url` read, exactly:
///
/// - resolved against `current_url`, it has the same path; or
/// - it is path-absolute (`/wiki/api/v2/...`) and names that path below the
///   route's site root `site_base`. Confluence writes these links from its
///   site root, which on the Atlassian gateway is
///   `/ex/confluence/<cloud_id>/`, not the origin's root.
///
/// The URL the link names on the route must be allowlisted, and its query
/// must carry exactly one cursor and only the `allowed_echo_parameters`.
pub(crate) fn next_page_cursor(
    current_url: &Url,
    site_base: &Url,
    raw_next: &str,
    allowed_upstream_hosts: &[String],
    resource_name: &str,
    allowed_echo_parameters: &[&str],
) -> Result<String, ConfluenceBackendError> {
    let parsed = Url::parse(raw_next)
        .or_else(|_| current_url.join(raw_next))
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))?;
    if !same_origin(&parsed, site_base) {
        return Err(ConfluenceBackendError::Protocol(format!(
            "Confluence {resource_name} pagination changed origin"
        )));
    }
    let names_current_path = parsed.path() == current_url.path()
        || (is_path_absolute_reference(raw_next)
            && site_base
                .path()
                .strip_suffix('/')
                .and_then(|root| current_url.path().strip_prefix(root))
                == Some(parsed.path()));
    if !names_current_path {
        return Err(ConfluenceBackendError::Protocol(format!(
            "Confluence {resource_name} pagination changed resource"
        )));
    }
    let mut next_url = current_url.clone();
    next_url.set_query(parsed.query());
    ensure_url_allowed(&next_url, allowed_upstream_hosts)?;
    let Some(query) = parsed.query() else {
        return Err(ConfluenceBackendError::Protocol(format!(
            "Confluence {resource_name} pagination link is missing query"
        )));
    };
    let mut cursor = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "cursor" {
            if cursor.is_some() || value.is_empty() {
                return Err(ConfluenceBackendError::Protocol(format!(
                    "Confluence {resource_name} pagination cursor is ambiguous"
                )));
            }
            cursor = Some(value.into_owned());
        } else if !allowed_echo_parameters.contains(&key.as_ref()) {
            return Err(ConfluenceBackendError::Protocol(format!(
                "Confluence {resource_name} pagination link includes unsupported parameters"
            )));
        }
    }
    cursor.ok_or_else(|| {
        ConfluenceBackendError::Protocol(format!(
            "Confluence {resource_name} pagination link is missing a cursor"
        ))
    })
}

/// Whether `reference` is a path-absolute URL reference: one leading `/`,
/// not `//` or `/\`, which name another authority.
fn is_path_absolute_reference(reference: &str) -> bool {
    reference
        .strip_prefix('/')
        .is_some_and(|rest| !rest.starts_with(['/', '\\']))
}

pub(crate) fn next_comment_page_cursor_from_sources(
    current_url: &Url,
    site_base: &Url,
    body_next: Option<&str>,
    header_next_links: &[String],
    allowed_upstream_hosts: &[String],
) -> Result<Option<String>, ConfluenceBackendError> {
    let mut cursor: Option<String> = None;
    for raw_next in body_next
        .into_iter()
        .chain(header_next_links.iter().map(String::as_str))
    {
        let next_cursor =
            next_comment_page_cursor(current_url, site_base, raw_next, allowed_upstream_hosts)?;
        if cursor
            .as_ref()
            .is_some_and(|existing| existing != &next_cursor)
        {
            return Err(ConfluenceBackendError::Protocol(
                "Confluence comment pagination returned ambiguous next links".to_string(),
            ));
        }
        cursor = Some(next_cursor);
    }
    Ok(cursor)
}

pub(crate) fn comment_next_links_from_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<String>, ConfluenceBackendError> {
    let mut next_links = Vec::new();
    for value in headers.get_all(reqwest::header::LINK).iter() {
        let value = value.to_str().map_err(|_| {
            ConfluenceBackendError::Protocol(
                "Confluence comment pagination Link header is invalid".to_string(),
            )
        })?;
        for link_value in split_link_header_values(value)? {
            if let Some(next_link) = next_link_from_link_value(&link_value)? {
                next_links.push(next_link);
            }
        }
    }
    if next_links.len() > 1 {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header is ambiguous".to_string(),
        ));
    }
    Ok(next_links)
}

pub(crate) fn split_link_header_values(value: &str) -> Result<Vec<String>, ConfluenceBackendError> {
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
            '"' => in_quote = !in_quote,
            '<' if !in_quote => in_target = true,
            '>' if !in_quote => in_target = false,
            ',' if !in_quote && !in_target => {
                let part = value[start..index].trim();
                if !part.is_empty() {
                    values.push(part.to_string());
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if in_quote || in_target || escaped {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header is malformed".to_string(),
        ));
    }
    let part = value[start..].trim();
    if !part.is_empty() {
        values.push(part.to_string());
    }
    Ok(values)
}

pub(crate) fn next_link_from_link_value(
    value: &str,
) -> Result<Option<String>, ConfluenceBackendError> {
    let value = value.trim();
    let Some(rest) = value.strip_prefix('<') else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header is malformed".to_string(),
        ));
    };
    let Some((target, params)) = rest.split_once('>') else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header is malformed".to_string(),
        ));
    };
    if target.trim().is_empty() {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header target is empty".to_string(),
        ));
    }
    let mut rel_is_next = false;
    for param in params.split(';').skip(1) {
        let Some((name, value)) = param.trim().split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("rel") {
            continue;
        }
        let rel_value = unquote_link_param_value(value.trim())?;
        if rel_value
            .split_ascii_whitespace()
            .any(|rel| rel.eq_ignore_ascii_case("next"))
        {
            rel_is_next = true;
        }
    }
    Ok(rel_is_next.then(|| target.to_string()))
}

pub(crate) fn unquote_link_param_value(value: &str) -> Result<String, ConfluenceBackendError> {
    let Some(inner) = value.strip_prefix('"') else {
        return Ok(value.to_string());
    };
    let Some(inner) = inner.strip_suffix('"') else {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination Link header parameter is malformed".to_string(),
        ));
    };
    let mut result = String::new();
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            let Some(escaped) = chars.next() else {
                return Err(ConfluenceBackendError::Protocol(
                    "Confluence comment pagination Link header parameter is malformed".to_string(),
                ));
            };
            result.push(escaped);
        } else {
            result.push(character);
        }
    }
    Ok(result)
}

pub(crate) fn validate_comment_cursor(cursor: &str) -> Result<(), ConfluenceBackendError> {
    if cursor.trim().is_empty() || cursor.chars().any(char::is_control) {
        Err(ConfluenceBackendError::Protocol(
            "Confluence comment pagination cursor is invalid".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn attachment_list_path_matches(url: &Url, page_id: &str) -> bool {
    let segments = url
        .path_segments()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    segments.ends_with(&["content", page_id, "child", "attachment"])
}

pub(crate) fn blog_attachment_list_path_matches(url: &Url, blog_id: &str) -> bool {
    let segments = url
        .path_segments()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    segments.ends_with(&["blogposts", blog_id, "attachments"])
}

pub(crate) fn draft_page_attachment_list_path_matches(url: &Url, page_id: &str) -> bool {
    let segments = url
        .path_segments()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    segments.ends_with(&["pages", page_id, "attachments"])
}

pub(crate) async fn confluence_response_value(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<Value, ConfluenceBackendError> {
    let mut response = response;
    let trace = take_upstream_trace(&mut response);
    let value = read_confluence_response_value(response, byte_cap, trace.as_ref()).await;
    complete_confluence_trace(trace, &value);
    value
}

/// Reads a JSON response whose detached trace the caller completes.
pub(crate) async fn read_confluence_response_value(
    response: reqwest::Response,
    byte_cap: u64,
    trace: Option<&PendingUpstreamTrace>,
) -> Result<Value, ConfluenceBackendError> {
    let expose_validation =
        trace.is_some_and(|trace| confluence_operation_exposes_validation(trace.operation()));
    let bytes = confluence_response_bytes_untraced(response, byte_cap, expose_validation).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))
}

pub(crate) fn complete_confluence_trace<T>(
    trace: Option<PendingUpstreamTrace>,
    outcome: &Result<T, ConfluenceBackendError>,
) {
    if let Some(trace) = trace {
        trace.complete(
            outcome
                .as_ref()
                .err()
                .map(confluence_backend_reason_code)
                .map(Into::into),
        );
    }
}

pub(crate) async fn confluence_comment_update_response_value(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<Value, ConfluenceBackendError> {
    let mut response = response;
    let trace = take_upstream_trace(&mut response);
    let value = match confluence_response_bytes_untraced(response, byte_cap, false).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| ConfluenceBackendError::Protocol(error.to_string())),
        Err(ConfluenceBackendError::HttpStatus(400)) => Err(ConfluenceBackendError::Conflict),
        Err(error) => Err(error),
    };
    complete_confluence_trace(trace, &value);
    value
}

pub(crate) async fn confluence_response_no_content(
    response: reqwest::Response,
    byte_cap: u64,
) -> Result<(), ConfluenceBackendError> {
    let status = response.status().as_u16();
    let mut response = response;
    let trace = take_upstream_trace(&mut response);
    let outcome = match confluence_response_bytes_untraced(response, byte_cap, false).await {
        Err(error) => Err(error),
        Ok(_) if status != 204 => Err(ConfluenceBackendError::Protocol(
            "Confluence delete returned unexpected success status".to_string(),
        )),
        Ok(bytes) if !bytes.is_empty() => Err(ConfluenceBackendError::Protocol(
            "Confluence delete returned an unexpected response body".to_string(),
        )),
        Ok(_) => Ok(()),
    };
    complete_confluence_trace(trace, &outcome);
    outcome
}

pub(crate) async fn confluence_response_bytes_untraced(
    response: reqwest::Response,
    byte_cap: u64,
    expose_validation: bool,
) -> Result<Vec<u8>, ConfluenceBackendError> {
    let status = response.status().as_u16();
    if expose_validation && matches!(status, 400 | 422) && response_has_json_content_type(&response)
    {
        return match read_validation_json(response, byte_cap)
            .await
            .as_ref()
            .and_then(confluence_validation_message)
        {
            Some(message) => Err(ConfluenceBackendError::Validation { status, message }),
            None => Err(ConfluenceBackendError::HttpStatus(status)),
        };
    }
    validate_confluence_body_response(&response, byte_cap)?;
    read_bounded_body(response, byte_cap, None)
        .await
        .map_err(|error| match error {
            BodyReadError::TooLarge => ConfluenceBackendError::ResponseTooLarge,
            BodyReadError::IdleTimeout => ConfluenceBackendError::Timeout,
            _ => ConfluenceBackendError::Transport("response read failed".to_string()),
        })
}

pub(crate) fn confluence_operation_exposes_validation(operation: &str) -> bool {
    matches!(
        operation,
        "page.create"
            | "page.update"
            | "page.draft.create"
            | "blog.create"
            | "blog.update"
            | "blog.draft.create"
            | "attachment.add"
            | "blog.attachment.add"
            | "page.draft.attachment.add"
            | "blog.draft.attachment.add"
            | "comment.add"
    )
}

pub(crate) fn confluence_response_stream(
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
            "Confluence attachment download",
            byte_cap,
            ReasonCode::UpstreamProtocolFailed,
            idle_timeout,
        )
        .with_expected_size(expected_size),
    )
}

pub(crate) struct ConfluenceUploadPart {
    pub(crate) part: reqwest::multipart::Part,
    pub(crate) progress: Option<UploadProgress>,
}

pub(crate) async fn confluence_upload_part(
    attachment: &ConfluenceAttachmentUpload,
) -> Result<ConfluenceUploadPart, ConfluenceBackendError> {
    let (part, progress) = if let Some(path) = attachment.temp_file_path() {
        let (body, progress) = file_upload_body(path)
            .await
            .map_err(|error| ConfluenceBackendError::Transport(error.to_string()))?;
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
        .map(|part| ConfluenceUploadPart { part, progress })
        .map_err(|error| ConfluenceBackendError::Protocol(error.to_string()))
}

/// Sends one upload through `client`. Its body is a stream that cannot be
/// repeated, so `prepare` builds the request and its progress for each
/// attempt; a delegated 401 repeats the upload at most once, as
/// [`send_confluence_request`] does.
pub(crate) async fn send_confluence_upload<F, Fut>(
    client: &UpstreamClient,
    credential: &AtlassianCredential,
    mut prepare: F,
    idle_timeout: Duration,
    call: UpstreamCall<'_>,
) -> Result<reqwest::Response, ConfluenceBackendError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
            Output = Result<
                (reqwest::RequestBuilder, Option<UploadProgress>),
                ConfluenceBackendError,
            >,
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
            .map_err(confluence_upstream_error)?;
        if response.status().as_u16() == 401 && presented.is_delegated() {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid.into()));
            credential
                .rejected(
                    &presented,
                    (attempt == call.attempt).then_some(()),
                    "Confluence",
                )
                .await?;
            attempt += 1;
            continue;
        }
        return Ok(response);
    }
}

pub(crate) fn validate_confluence_body_response(
    response: &reqwest::Response,
    byte_cap: u64,
) -> Result<(), ConfluenceBackendError> {
    let status = response.status().as_u16();
    if response.status().is_redirection() {
        return Err(ConfluenceBackendError::Redirected);
    }
    if status == 401 {
        return Err(ConfluenceBackendError::Unauthorized);
    }
    if status == 403 {
        return Err(ConfluenceBackendError::Forbidden);
    }
    if status == 404 {
        return Err(ConfluenceBackendError::NotFound);
    }
    if status == 409 {
        return Err(ConfluenceBackendError::Conflict);
    }
    if status == 429 {
        return Err(ConfluenceBackendError::RateLimited(
            UpstreamRetryAfter::from_headers(response.headers()),
        ));
    }
    if !response.status().is_success() {
        return Err(ConfluenceBackendError::HttpStatus(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > byte_cap)
    {
        return Err(ConfluenceBackendError::ResponseTooLarge);
    }
    Ok(())
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn ensure_url_allowed(
    url: &Url,
    patterns: &[String],
) -> Result<(), ConfluenceBackendError> {
    if url_allowed_by_patterns(url, patterns) {
        return Ok(());
    }
    Err(ConfluenceBackendError::Protocol(
        "Confluence upstream URL is not allowlisted".to_string(),
    ))
}

pub(crate) fn page_create_request_body(request: &ConfluencePageCreateRequest) -> Value {
    let mut value = json!({
        "spaceId": request.space_id,
        "status": "current",
        "title": request.title,
        "body": {
            "representation": request.body.representation,
            "value": request.body.value,
        }
    });
    if let Some(parent_page_id) = &request.parent_page_id {
        value["parentId"] = json!(parent_page_id);
    }
    value
}

pub(crate) fn content_request_body(
    page_id: String,
    next_version: u64,
    space: String,
    title: String,
    body: ConfluencePageBody,
) -> Value {
    let mut body_map = serde_json::Map::new();
    body_map.insert(
        body.representation.clone(),
        json!({
            "value": body.value,
            "representation": body.representation,
        }),
    );
    json!({
        "id": page_id,
        "type": "page",
        "title": title,
        "space": { "key": space },
        "body": Value::Object(body_map),
        "version": { "number": next_version },
    })
}

pub(crate) fn blog_create_request_body(request: &ConfluenceBlogCreateRequest) -> Value {
    json!({
        "spaceId": request.space_id,
        "status": "current",
        "title": request.title,
        "body": {
            "representation": request.body.representation,
            "value": request.body.value,
        }
    })
}

pub(crate) fn blog_update_request_body(request: &ConfluenceBlogUpdateRequest) -> Value {
    let mut version = serde_json::Map::new();
    version.insert("number".to_string(), json!(request.base_version + 1));
    if let Some(message) = &request.version_message {
        version.insert("message".to_string(), json!(message));
    }
    json!({
        "id": request.blog_id,
        "status": "current",
        "title": request.title,
        "body": {
            "representation": request.body.representation,
            "value": request.body.value,
        },
        "version": Value::Object(version),
    })
}

pub(crate) fn draft_create_request_body(request: &ConfluenceDraftCreateRequest) -> Value {
    let mut value = json!({
        "spaceId": request.space_id,
        "status": "draft",
        "title": request.title,
        "body": {
            "representation": request.body.representation,
            "value": request.body.value,
        }
    });
    if request.content_type == "page"
        && let Some(parent_page_id) = &request.parent_page_id
    {
        value["parentId"] = json!(parent_page_id);
    }
    value
}

pub(crate) fn draft_update_request_body(request: &ConfluenceDraftUpdateRequest) -> Value {
    let mut body = serde_json::Map::from_iter([
        ("id".to_string(), json!(request.content_id)),
        ("status".to_string(), json!(request.status)),
        ("title".to_string(), json!(request.title)),
        (
            "body".to_string(),
            json!({
                "representation": request.body.representation,
                "value": request.body.value,
            }),
        ),
        (
            "version".to_string(),
            json!({ "number": request.version_number }),
        ),
    ]);
    if request.content_type == "blog" {
        body.insert("spaceId".to_string(), json!(request.space_id));
    }
    Value::Object(body)
}

pub(crate) fn comment_create_request_body(request: &ConfluenceCommentCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    if let Some(page_id) = &request.page_id {
        body.insert("pageId".to_string(), json!(page_id));
    }
    if let Some(blog_id) = &request.blog_id {
        body.insert("blogPostId".to_string(), json!(blog_id));
    }
    if let Some(parent_comment_id) = &request.parent_comment_id {
        body.insert("parentCommentId".to_string(), json!(parent_comment_id));
    }
    body.insert(
        "body".to_string(),
        json!({
            "representation": request.body.representation,
            "value": request.body.value,
        }),
    );
    Value::Object(body)
}

pub(crate) fn comment_update_request_body(request: &ConfluenceCommentUpdateRequest) -> Value {
    json!({
        "version": {
            "number": request.base_version + 1,
        },
        "body": {
            "representation": request.body.representation,
            "value": request.body.value,
        },
    })
}

pub(crate) fn optional_confluence_string_at(value: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value.pointer(path).and_then(Value::as_str))
        .map(ToString::to_string)
}

pub(crate) fn confluence_user_summary_from_object(raw: &Value) -> Option<ConfluenceCommentAuthor> {
    if !raw.is_object() {
        return None;
    }
    let summary = ConfluenceCommentAuthor {
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

pub(crate) fn confluence_account_id_summary(
    account_id: Option<&str>,
) -> Option<ConfluenceCommentAuthor> {
    account_id.map(|account_id| ConfluenceCommentAuthor {
        account_id: Some(account_id.to_string()),
        display_name: None,
    })
}

pub(crate) fn optional_confluence_user_at(
    value: &Value,
    paths: &[&str],
) -> Option<ConfluenceCommentAuthor> {
    paths.iter().find_map(|path| {
        value
            .pointer(path)
            .and_then(confluence_user_summary_from_object)
    })
}

pub(crate) fn confluence_created_at(value: &Value) -> Option<String> {
    optional_confluence_string_at(
        value,
        &["/createdAt", "/createdDate", "/history/createdDate"],
    )
}

pub(crate) fn confluence_updated_at(value: &Value) -> Option<String> {
    optional_confluence_string_at(
        value,
        &[
            "/updatedAt",
            "/modifiedAt",
            "/updated",
            "/version/when",
            "/version/createdAt",
        ],
    )
}

pub(crate) fn confluence_created_by(value: &Value) -> Option<ConfluenceCommentAuthor> {
    optional_confluence_user_at(
        value,
        &["/history/createdBy", "/createdBy", "/author", "/owner"],
    )
    .or_else(|| {
        confluence_account_id_summary(
            value
                .get("authorId")
                .or_else(|| value.get("ownerId"))
                .and_then(Value::as_str),
        )
    })
}

pub(crate) fn confluence_updated_by(value: &Value) -> Option<ConfluenceCommentAuthor> {
    optional_confluence_user_at(value, &["/version/by", "/version/author", "/updatedBy"]).or_else(
        || {
            confluence_account_id_summary(
                value.pointer("/version/authorId").and_then(Value::as_str),
            )
        },
    )
}

pub(crate) fn page_from_value(value: Value) -> Result<ConfluencePage, ConfluenceBackendError> {
    if value.get("type").and_then(Value::as_str) != Some("page") {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence content is not a page".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("page id missing".to_string()))?
        .to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfluenceBackendError::Protocol("page title missing".to_string()))?
        .to_string();
    let space = value
        .pointer("/space/key")
        .and_then(Value::as_str)
        .filter(|space| is_space_key(space))
        .ok_or_else(|| ConfluenceBackendError::Protocol("page space missing".to_string()))?
        .to_string();
    let web_url = confluence_webui_link(&value);
    let space_web_url = value
        .pointer("/space/_links/webui")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("page version missing".to_string()))?;
    let mut bodies = BTreeMap::new();
    if let Some(body) = value.get("body").and_then(Value::as_object) {
        for representation in ["storage", "atlas_doc_format"] {
            if let Some(content) = body
                .get(representation)
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
            {
                bodies.insert(representation.to_string(), content.to_string());
            }
        }
    }
    Ok(ConfluencePage {
        id,
        title,
        space,
        web_url,
        space_web_url,
        space_alias: None,
        status,
        version,
        created_at: confluence_created_at(&value),
        updated_at: confluence_updated_at(&value),
        created_by: confluence_created_by(&value),
        updated_by: confluence_updated_by(&value),
        bodies,
    })
}

pub(crate) fn page_from_v2_value(
    value: Value,
    expected_space: &str,
    expected_space_id: &str,
) -> Result<ConfluencePage, ConfluenceBackendError> {
    let hierarchy = page_hierarchy_from_value(value.clone())?;
    if hierarchy.space_id != expected_space_id {
        return Err(ConfluenceBackendError::Protocol(
            "created page space id did not match requested space".to_string(),
        ));
    }
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfluenceBackendError::Protocol("page title missing".to_string()))?
        .to_string();
    let mut bodies = BTreeMap::new();
    if let Some(body) = value.get("body").and_then(Value::as_object) {
        for representation in ["storage", "atlas_doc_format"] {
            if let Some(content) = body
                .get(representation)
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .or_else(|| {
                    (body.get("representation").and_then(Value::as_str) == Some(representation))
                        .then(|| body.get("value").and_then(Value::as_str))
                        .flatten()
                })
            {
                bodies.insert(representation.to_string(), content.to_string());
            }
        }
    }
    Ok(ConfluencePage {
        id: hierarchy.id,
        title,
        space: expected_space.to_string(),
        web_url: confluence_webui_link(&value),
        space_web_url: None,
        space_alias: None,
        status: Some(hierarchy.status),
        version: hierarchy.version,
        created_at: confluence_created_at(&value),
        updated_at: confluence_updated_at(&value),
        created_by: confluence_created_by(&value),
        updated_by: confluence_updated_by(&value),
        bodies,
    })
}

pub(crate) fn page_hierarchy_from_value(
    value: Value,
) -> Result<ConfluencePageHierarchy, ConfluenceBackendError> {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|content_type| content_type != "page")
    {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence hierarchy content is not a page".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("page id missing".to_string()))?
        .to_string();
    let space_id = value
        .get("spaceId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("page space id missing".to_string()))?
        .to_string();
    let parent_page_id = value
        .get("parentId")
        .and_then(Value::as_str)
        .filter(|id| is_confluence_content_id(id))
        .map(ToString::to_string);
    if value.get("parentId").is_some_and(|id| !id.is_null()) && parent_page_id.is_none() {
        return Err(ConfluenceBackendError::Protocol(
            "page parent id is invalid".to_string(),
        ));
    }
    let parent_type = value
        .get("parentType")
        .and_then(Value::as_str)
        .filter(|content_type| is_confluence_tree_content_type(content_type))
        .map(ToString::to_string);
    if value
        .get("parentType")
        .is_some_and(|content_type| !content_type.is_null())
        && parent_type.is_none()
    {
        return Err(ConfluenceBackendError::Protocol(
            "page parent type is unsupported".to_string(),
        ));
    }
    if parent_page_id.is_some() != parent_type.is_some() {
        return Err(ConfluenceBackendError::Protocol(
            "page parent id and type are inconsistent".to_string(),
        ));
    }
    if parent_type.as_deref() == Some("page")
        && parent_page_id.as_deref().is_some_and(|id| !is_page_id(id))
    {
        return Err(ConfluenceBackendError::Protocol(
            "page parent page id is invalid".to_string(),
        ));
    }
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "current" | "draft"))
        .ok_or_else(|| ConfluenceBackendError::Protocol("page status missing".to_string()))?
        .to_string();
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("page version missing".to_string()))?;
    Ok(ConfluencePageHierarchy {
        id,
        space_id,
        parent_page_id,
        parent_type,
        status,
        version,
    })
}

pub(crate) fn page_ancestors_from_value(
    value: Value,
) -> Result<(Vec<ConfluencePageAncestor>, Option<String>), ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceBackendError::Protocol("ancestor results missing".to_string()))?;
    if results.len() > 250 {
        return Err(ConfluenceBackendError::Protocol(
            "ancestor results exceeded requested limit".to_string(),
        ));
    }
    let ancestors = results
        .iter()
        .map(|ancestor| {
            let id = ancestor
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| is_confluence_content_id(id))
                .ok_or_else(|| ConfluenceBackendError::Protocol("ancestor id missing".to_string()))?
                .to_string();
            let content_type = ancestor
                .get("type")
                .and_then(Value::as_str)
                .filter(|content_type| is_confluence_tree_content_type(content_type))
                .ok_or_else(|| {
                    ConfluenceBackendError::Protocol("ancestor type is unsupported".to_string())
                })?
                .to_string();
            if content_type == "page" && !is_page_id(&id) {
                return Err(ConfluenceBackendError::Protocol(
                    "ancestor page id is invalid".to_string(),
                ));
            }
            Ok(ConfluencePageAncestor { id, content_type })
        })
        .collect::<Result<Vec<_>, ConfluenceBackendError>>()?;
    let next = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok((ancestors, next))
}

pub(crate) fn page_direct_children_from_value(
    value: Value,
) -> Result<(Vec<ConfluencePageChild>, Option<String>), ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ConfluenceBackendError::Protocol("direct-child results missing".to_string())
        })?;
    if results.len() > 250 {
        return Err(ConfluenceBackendError::Protocol(
            "direct-child results exceeded requested limit".to_string(),
        ));
    }
    let children = results
        .iter()
        .map(|child| {
            let id = child
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| is_confluence_content_id(id))
                .ok_or_else(|| {
                    ConfluenceBackendError::Protocol("direct-child id missing".to_string())
                })?
                .to_string();
            let content_type = child
                .get("type")
                .and_then(Value::as_str)
                .filter(|content_type| is_confluence_tree_content_type(content_type))
                .ok_or_else(|| {
                    ConfluenceBackendError::Protocol("direct-child type is unsupported".to_string())
                })?
                .to_string();
            let status = child
                .get("status")
                .and_then(Value::as_str)
                .filter(|status| *status == "current")
                .ok_or_else(|| {
                    ConfluenceBackendError::Protocol(
                        "direct-child status is not current".to_string(),
                    )
                })?
                .to_string();
            let child_position = child
                .get("childPosition")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    ConfluenceBackendError::Protocol("direct-child position missing".to_string())
                })?;
            Ok(ConfluencePageChild {
                id,
                content_type,
                status,
                child_position,
            })
        })
        .collect::<Result<Vec<_>, ConfluenceBackendError>>()?;
    let next = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok((children, next))
}

pub(crate) fn space_from_value(value: Value) -> Result<ConfluenceSpace, ConfluenceBackendError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("space id missing".to_string()))?
        .to_string();
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| is_space_key(key))
        .ok_or_else(|| ConfluenceBackendError::Protocol("space key missing".to_string()))?
        .to_string();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let web_url = confluence_webui_link(&value);
    // An unusable alias only loses the alias: links naming it are replaced.
    let alias = value
        .get("currentActiveAlias")
        .and_then(Value::as_str)
        .filter(|alias| is_space_alias(alias) && *alias != key)
        .map(ToString::to_string);
    let homepage_id = value
        .get("homepageId")
        .and_then(Value::as_str)
        .map(|id| {
            validate_page_id(id).map_err(|_| {
                ConfluenceBackendError::Protocol("space homepage id is invalid".to_string())
            })
        })
        .transpose()?;
    if status.as_deref().is_some_and(|value| value != "current") {
        return Err(ConfluenceBackendError::Protocol(
            "space status is not current".to_string(),
        ));
    }
    Ok(ConfluenceSpace {
        id,
        key,
        web_url,
        alias,
        status,
        homepage_id,
    })
}

pub(crate) fn single_space_from_results(
    value: Value,
    expected_key: &str,
) -> Result<ConfluenceSpace, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceBackendError::Protocol("space results missing".to_string()))?;
    if results.len() != 1 {
        return Err(ConfluenceBackendError::NotFound);
    }
    let space = space_from_value(results[0].clone())?;
    if space.key != expected_key {
        return Err(ConfluenceBackendError::Protocol(
            "space key did not match requested key".to_string(),
        ));
    }
    Ok(space)
}

pub(crate) fn blog_from_value(value: Value) -> Result<ConfluenceBlog, ConfluenceBackendError> {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|content_type| content_type != "blogpost")
    {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence content is not a blog post".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_blog_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog id missing".to_string()))?
        .to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog title missing".to_string()))?
        .to_string();
    let space_id = value
        .get("spaceId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog space id missing".to_string()))?
        .to_string();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let web_url = confluence_webui_link(&value);
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog version missing".to_string()))?;
    let mut bodies = BTreeMap::new();
    if let Some(content) = value
        .pointer("/body/storage/value")
        .and_then(Value::as_str)
        .or_else(|| {
            if value
                .pointer("/body/representation")
                .and_then(Value::as_str)
                == Some("storage")
            {
                value.pointer("/body/value").and_then(Value::as_str)
            } else {
                None
            }
        })
    {
        bodies.insert("storage".to_string(), content.to_string());
    }
    Ok(ConfluenceBlog {
        id,
        title,
        space: String::new(),
        space_id,
        space_alias: None,
        web_url,
        space_web_url: None,
        status,
        version,
        created_at: confluence_created_at(&value),
        updated_at: confluence_updated_at(&value),
        created_by: confluence_created_by(&value),
        updated_by: confluence_updated_by(&value),
        bodies,
    })
}

pub(crate) fn draft_content_from_value(
    value: Value,
    content_type: ConfluenceDraftContentType,
) -> Result<ConfluenceDraftContent, ConfluenceBackendError> {
    if let Some(kind) = value.get("type").and_then(Value::as_str) {
        match (content_type, kind) {
            (ConfluenceDraftContentType::Page, "page")
            | (ConfluenceDraftContentType::Blog, "blogpost") => {}
            _ => {
                return Err(ConfluenceBackendError::Protocol(
                    "Confluence draft content type mismatched".to_string(),
                ));
            }
        }
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| match content_type {
            ConfluenceDraftContentType::Page => is_page_id(id),
            ConfluenceDraftContentType::Blog => is_blog_id(id),
        })
        .ok_or_else(|| ConfluenceBackendError::Protocol("draft content id missing".to_string()))?
        .to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfluenceBackendError::Protocol("draft title missing".to_string()))?
        .to_string();
    let space_id = value
        .get("spaceId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("draft space id missing".to_string()))?
        .to_string();
    let parent_page_id = if content_type == ConfluenceDraftContentType::Page {
        value
            .get("parentId")
            .and_then(Value::as_str)
            .map(|id| {
                validate_page_id(id).map_err(|_| {
                    ConfluenceBackendError::Protocol("draft parent id is invalid".to_string())
                })
            })
            .transpose()?
    } else {
        None
    };
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("draft version missing".to_string()))?;
    let web_url = confluence_webui_link(&value);
    let mut bodies = BTreeMap::new();
    if let Some(body) = value.get("body").and_then(Value::as_object) {
        for representation in ["storage", "atlas_doc_format"] {
            if let Some(content) = body
                .get(representation)
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .or_else(|| {
                    (body.get("representation").and_then(Value::as_str) == Some(representation))
                        .then(|| body.get("value").and_then(Value::as_str))
                        .flatten()
                })
            {
                bodies.insert(representation.to_string(), content.to_string());
            }
        }
    }
    Ok(ConfluenceDraftContent {
        id,
        title,
        content_type: content_type.as_str().to_string(),
        space: String::new(),
        space_id,
        space_alias: None,
        parent_page_id,
        web_url,
        space_web_url: None,
        status,
        version,
        created_at: confluence_created_at(&value),
        updated_at: confluence_updated_at(&value),
        created_by: confluence_created_by(&value),
        updated_by: confluence_updated_by(&value),
        bodies,
    })
}

pub(crate) fn blog_scope_evidence_from_value(
    value: Value,
) -> Result<ConfluenceBlogScopeEvidence, ConfluenceBackendError> {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|content_type| content_type != "blogpost")
    {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence content is not a blog post".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_blog_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog id missing".to_string()))?
        .to_string();
    let space_id = value
        .get("spaceId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog space id missing".to_string()))?
        .to_string();
    Ok(ConfluenceBlogScopeEvidence {
        id,
        space: String::new(),
        space_id,
        space_alias: None,
    })
}

pub(crate) fn comment_from_value(
    value: Value,
    kind: ConfluenceCommentKind,
) -> Result<ConfluenceComment, ConfluenceBackendError> {
    if value.get("attachmentId").is_some() || value.get("customContentId").is_some() {
        return Err(ConfluenceBackendError::Protocol(
            "comment has an unsupported container".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("comment id missing".to_string()))?
        .to_string();
    let page_id = value
        .get("pageId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .map(ToString::to_string);
    let blog_id = value
        .get("blogPostId")
        .or_else(|| value.get("blogId"))
        .and_then(Value::as_str)
        .filter(|id| is_blog_id(id))
        .map(ToString::to_string);
    let parent_comment_id = value
        .get("parentCommentId")
        .and_then(Value::as_str)
        .filter(|id| is_page_id(id))
        .map(ToString::to_string);
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let resolution_status = value
        .get("resolutionStatus")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .or_else(|| value.get("version").and_then(Value::as_u64));
    let author_value = value
        .get("author")
        .or_else(|| value.get("createdBy"))
        .or_else(|| value.get("owner"));
    let author = author_value.map(|author| ConfluenceCommentAuthor {
        account_id: author
            .get("accountId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        display_name: author
            .get("displayName")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    });
    let created_at = value
        .get("createdAt")
        .or_else(|| value.get("createdDate"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let updated_at = value
        .get("updatedAt")
        .or_else(|| value.get("modifiedAt"))
        .or_else(|| value.get("updated"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let bodies = comment_bodies_from_value(&value)?;
    Ok(ConfluenceComment {
        id,
        kind,
        page_id,
        blog_id,
        parent_comment_id,
        status,
        resolution_status,
        version,
        author,
        created_at,
        updated_at,
        bodies,
    })
}

pub(crate) fn comment_bodies_from_value(
    value: &Value,
) -> Result<BTreeMap<String, String>, ConfluenceBackendError> {
    let mut bodies = BTreeMap::new();
    let Some(body) = value.get("body").and_then(Value::as_object) else {
        return Ok(bodies);
    };
    for format in ["storage"] {
        if let Some(format_body) = body.get(format).and_then(Value::as_object) {
            let representation = format_body
                .get("representation")
                .and_then(Value::as_str)
                .unwrap_or(format);
            if representation != format {
                return Err(ConfluenceBackendError::Protocol(
                    "comment body representation mismatched its format".to_string(),
                ));
            }
            if let Some(content) = format_body.get("value").and_then(Value::as_str) {
                bodies.insert(format.to_string(), content.to_string());
            }
        }
    }
    if body.get("representation").and_then(Value::as_str) == Some("storage") {
        if body
            .get("storage")
            .is_some_and(|nested| nested.get("value").and_then(Value::as_str).is_some())
        {
            return Ok(bodies);
        }
        if let Some(content) = body.get("value").and_then(Value::as_str) {
            bodies.insert("storage".to_string(), content.to_string());
        }
    }
    Ok(bodies)
}

pub(crate) fn comment_list_page_from_value(
    value: Value,
    kind: ConfluenceCommentKind,
) -> Result<ConfluenceCommentListPage, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceBackendError::Protocol("comment results missing".to_string()))?;
    let comments = results
        .iter()
        .cloned()
        .map(|item| comment_from_value(item, kind))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("next")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        });
    Ok(ConfluenceCommentListPage {
        comments,
        next_cursor,
    })
}

pub(crate) fn blog_summary_from_search_value(
    value: Value,
) -> Result<ConfluenceBlogSummary, ConfluenceBackendError> {
    if value.get("type").and_then(Value::as_str) != Some("blogpost") {
        return Err(ConfluenceBackendError::Protocol(
            "Confluence content is not a blog post".to_string(),
        ));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_blog_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog id missing".to_string()))?
        .to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog title missing".to_string()))?
        .to_string();
    let space = value
        .pointer("/space/key")
        .and_then(Value::as_str)
        .filter(|space| is_space_key(space))
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog space missing".to_string()))?
        .to_string();
    let web_url = confluence_webui_link(&value);
    let space_web_url = value
        .pointer("/space/_links/webui")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("blog version missing".to_string()))?;
    Ok(ConfluenceBlogSummary {
        id,
        title,
        space,
        web_url,
        space_web_url,
        status,
        version,
        created_at: confluence_created_at(&value),
        updated_at: confluence_updated_at(&value),
        created_by: confluence_created_by(&value),
        updated_by: confluence_updated_by(&value),
    })
}

pub(crate) fn confluence_webui_link(value: &Value) -> Option<String> {
    value
        .pointer("/_links/webui")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

pub(crate) fn first_attachment_from_value(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachment, ConfluenceBackendError> {
    let first = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .or_else(|| value.as_array().and_then(|items| items.first()))
        .cloned()
        .ok_or_else(|| {
            ConfluenceBackendError::Protocol("attachment response missing".to_string())
        })?;
    attachment_from_value(first, page_id)
}

pub(crate) fn first_attachment_from_value_with_required_parent(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachment, ConfluenceBackendError> {
    let first = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .or_else(|| value.as_array().and_then(|items| items.first()))
        .cloned()
        .ok_or_else(|| {
            ConfluenceBackendError::Protocol("attachment response missing".to_string())
        })?;
    attachment_from_value_with_required_parent(first, page_id)
}

pub(crate) fn attachments_from_value(
    value: Value,
    page_id: &str,
) -> Result<Vec<ConfluenceAttachment>, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ConfluenceBackendError::Protocol("attachment results missing".to_string())
        })?;
    results
        .iter()
        .cloned()
        .map(|item| attachment_from_value(item, page_id))
        .collect()
}

pub(crate) fn attachment_list_from_value(
    value: Value,
    page_id: &str,
) -> Result<Vec<ConfluenceAttachment>, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ConfluenceBackendError::Protocol("attachment results missing".to_string())
        })?;
    results
        .iter()
        .cloned()
        .map(|item| attachment_from_value_with_required_parent(item, page_id))
        .collect()
}

pub(crate) fn attachment_page_from_value(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachmentPage, ConfluenceBackendError> {
    let next_link = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok(ConfluenceAttachmentPage {
        attachments: attachments_from_value(value, page_id)?,
        next_link,
    })
}

pub(crate) fn attachment_list_page_from_value(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachmentPage, ConfluenceBackendError> {
    let next_link = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok(ConfluenceAttachmentPage {
        attachments: attachment_list_from_value(value, page_id)?,
        next_link,
    })
}

pub(crate) fn attachment_from_value(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachment, ConfluenceBackendError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_attachment_id(id))
        .ok_or_else(|| ConfluenceBackendError::Protocol("attachment id missing".to_string()))?
        .to_string();
    let filename = value
        .get("title")
        .or_else(|| value.get("filename"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ConfluenceBackendError::Protocol("attachment filename missing".to_string()))?
        .to_string();
    let content_type = value
        .pointer("/metadata/mediaType")
        .or_else(|| value.get("mediaType"))
        .and_then(Value::as_str)
        .filter(|value| media_type_essence(value).is_some())
        .unwrap_or("application/octet-stream")
        .to_string();
    let size = value
        .pointer("/extensions/fileSize")
        .or_else(|| value.get("fileSize"))
        .and_then(Value::as_u64)
        .ok_or_else(|| ConfluenceBackendError::Protocol("attachment size missing".to_string()))?;
    let response_page_id = value
        .get("pageId")
        .and_then(Value::as_str)
        .unwrap_or(page_id);
    if response_page_id != page_id || !is_page_id(response_page_id) {
        return Err(ConfluenceBackendError::Protocol(
            "attachment page id did not match requested page".to_string(),
        ));
    }
    Ok(ConfluenceAttachment {
        id,
        page_id: page_id.to_string(),
        filename,
        size,
        content_type,
    })
}

pub(crate) fn attachment_from_value_with_required_parent(
    value: Value,
    page_id: &str,
) -> Result<ConfluenceAttachment, ConfluenceBackendError> {
    let response_page_id = attachment_parent_page_id(&value).ok_or_else(|| {
        ConfluenceBackendError::Protocol(
            "attachment parent page id missing from list response".to_string(),
        )
    })?;
    if response_page_id != page_id || !is_page_id(response_page_id) {
        return Err(ConfluenceBackendError::Protocol(
            "attachment page id did not match requested page".to_string(),
        ));
    }
    attachment_from_value(value, page_id)
}

pub(crate) fn attachment_parent_page_id(value: &Value) -> Option<&str> {
    value
        .get("pageId")
        .and_then(Value::as_str)
        .or_else(|| value.get("blogPostId").and_then(Value::as_str))
        .or_else(|| value.pointer("/container/id").and_then(Value::as_str))
}

pub(crate) fn search_page_from_value(
    value: Value,
    max_results: u32,
) -> Result<ConfluenceSearchPage, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceBackendError::Protocol("search results missing".to_string()))?;
    let mut pages = Vec::with_capacity(results.len());
    for item in results {
        let content = search_content_from_value(item);
        pages.push(page_from_value(content)?);
    }
    let next_page_token = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .and_then(next_cursor_from_link);
    Ok(ConfluenceSearchPage {
        pages,
        max_results,
        next_page_token,
    })
}

pub(crate) fn search_blog_from_value(
    value: Value,
    max_results: u32,
) -> Result<ConfluenceSearchBlog, ConfluenceBackendError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceBackendError::Protocol("search results missing".to_string()))?;
    let mut blogs = Vec::with_capacity(results.len());
    for item in results {
        let content = search_content_from_value(item);
        blogs.push(blog_summary_from_search_value(content)?);
    }
    let next_page_token = value
        .pointer("/_links/next")
        .and_then(Value::as_str)
        .and_then(next_cursor_from_link);
    Ok(ConfluenceSearchBlog {
        blogs,
        max_results,
        next_page_token,
    })
}

pub(crate) fn search_content_from_value(item: &Value) -> Value {
    let mut content = item.get("content").unwrap_or(item).clone();
    if content.pointer("/_links/webui").is_none()
        && let Some(webui) = item.pointer("/_links/webui").cloned()
        && let Some(object) = content.as_object_mut()
    {
        let links = object.entry("_links").or_insert_with(|| json!({}));
        if let Some(links) = links.as_object_mut() {
            links.insert("webui".to_string(), webui);
        }
    }
    content
}

pub(crate) fn next_cursor_from_link(link: &str) -> Option<String> {
    let parsed = Url::parse(&format!("https://example.invalid{link}")).ok()?;
    parsed
        .query_pairs()
        .find_map(|(key, value)| (key == "cursor").then(|| value.into_owned()))
}
