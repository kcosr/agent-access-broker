//! Every published action executes under narrow content and ordinary space
//! authority, then repeats after its admitted target moves outside its region.
//! The matrix checks effects and release, not only the scope-resolution helpers.
use super::*;
use agent_access_provider::test_support::{ScopeRequestFixture, test_signing_key};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

const ROOT: &str = "https://example.atlassian.net/wiki/spaces/ENG/pages/200";
const BODY: &str = "<p>matrix content</p>";

struct MatrixBackend {
    outside: AtomicBool,
    writes: AtomicUsize,
    calls: Mutex<Vec<&'static str>>,
    parents: Mutex<BTreeMap<String, Option<ConfluenceParent>>>,
    drafts: Mutex<BTreeMap<String, ConfluenceDraftContent>>,
    comments: Mutex<BTreeMap<String, ConfluenceComment>>,
    attachments: Mutex<BTreeMap<String, Vec<ConfluenceAttachment>>>,
}

impl MatrixBackend {
    fn new() -> Self {
        let mut comments = BTreeMap::new();
        for (id, kind, page, blog) in [
            ("500", ConfluenceCommentKind::Footer, Some("100"), None),
            ("501", ConfluenceCommentKind::Inline, Some("100"), None),
            ("600", ConfluenceCommentKind::Footer, None, Some("700")),
            ("601", ConfluenceCommentKind::Inline, None, Some("700")),
        ] {
            comments.insert(id.into(), comment(id, kind, page, blog, None, BODY));
        }
        let result = Self {
            outside: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            calls: Mutex::new(vec![]),
            parents: Mutex::new(BTreeMap::from([
                ("100".into(), Some(parent("200"))),
                ("200".into(), None),
                ("300".into(), Some(parent("200"))),
                ("400".into(), Some(parent("200"))),
                ("999".into(), None),
            ])),
            drafts: Mutex::new(BTreeMap::new()),
            comments: Mutex::new(comments),
            attachments: Mutex::new(BTreeMap::new()),
        };
        for (id, kind) in [
            ("400", ConfluenceDraftContentType::Page),
            ("800", ConfluenceDraftContentType::Blog),
        ] {
            result
                .drafts
                .lock()
                .unwrap()
                .insert(id.into(), result.draft_value(id, kind));
        }
        result
    }

    fn record(&self, operation: &'static str) {
        self.calls.lock().unwrap().push(operation);
    }
    fn mutate(&self, operation: &'static str) {
        self.record(operation);
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
    fn key(&self) -> &'static str {
        if self.outside.load(Ordering::SeqCst) {
            "OPS"
        } else {
            "ENG"
        }
    }
    fn space(&self) -> ConfluenceSpace {
        ConfluenceSpace {
            id: "98765".into(),
            key: self.key().into(),
            web_url: None,
            alias: None,
            status: Some("current".into()),
            homepage_id: Some("200".into()),
        }
    }
    fn page_value(&self, id: &str) -> ConfluencePage {
        ConfluencePage {
            id: id.into(),
            title: "Matrix page".into(),
            space: self.key().into(),
            web_url: None,
            space_web_url: None,
            space_alias: None,
            version: 1,
            status: Some("current".into()),
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".into(), BODY.into())]),
        }
    }
    fn blog_value(&self, id: &str) -> ConfluenceBlog {
        ConfluenceBlog {
            id: id.into(),
            title: "Matrix blog".into(),
            space: self.key().into(),
            space_id: "98765".into(),
            space_alias: None,
            web_url: None,
            space_web_url: None,
            version: 1,
            status: Some("current".into()),
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".into(), BODY.into())]),
        }
    }
    fn draft_value(&self, id: &str, kind: ConfluenceDraftContentType) -> ConfluenceDraftContent {
        ConfluenceDraftContent {
            id: id.into(),
            title: "Matrix draft".into(),
            content_type: kind.as_str().into(),
            space: self.key().into(),
            space_id: "98765".into(),
            space_alias: None,
            space_web_url: None,
            web_url: None,
            parent: (kind == ConfluenceDraftContentType::Page).then(|| parent("200")),
            status: Some("draft".into()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".into(), BODY.into())]),
        }
    }
    fn get_draft(&self, id: &str) -> Result<ConfluenceDraftContent, ConfluenceBackendError> {
        let mut value = self
            .drafts
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        value.space = self.key().into();
        Ok(value)
    }
    fn update_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        kind: ConfluenceDraftContentType,
        operation: &'static str,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.mutate(operation);
        let mut value = self.draft_value(&request.content_id, kind);
        value.title = request.title;
        value.status = Some(request.status);
        value.version = request.version_number;
        value.bodies = BTreeMap::from([(request.body.representation, request.body.value)]);
        self.drafts
            .lock()
            .unwrap()
            .insert(value.id.clone(), value.clone());
        ok(value)
    }
    fn create_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        kind: ConfluenceDraftContentType,
        operation: &'static str,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.mutate(operation);
        let mut value = self.draft_value(
            if kind == ConfluenceDraftContentType::Page {
                "900"
            } else {
                "901"
            },
            kind,
        );
        value.title = request.title;
        value.parent = request.parent;
        value.bodies = BTreeMap::from([(request.body.representation, request.body.value)]);
        self.drafts
            .lock()
            .unwrap()
            .insert(value.id.clone(), value.clone());
        ok(value)
    }
    fn attachment(&self, id: &str) -> ConfluenceAttachment {
        ConfluenceAttachment {
            id: "9000".into(),
            page_id: id.into(),
            filename: "matrix.txt".into(),
            size: 1,
            content_type: "text/plain".into(),
            media_type_declaration: None,
        }
    }
    fn attachments(&self, id: &str) -> Vec<ConfluenceAttachment> {
        self.attachments
            .lock()
            .unwrap()
            .entry(id.into())
            .or_insert_with(|| vec![self.attachment(id)])
            .clone()
    }
    fn attachment_page(
        &self,
        id: &str,
        operation: &'static str,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.record(operation);
        ok(ConfluenceAttachmentListPage {
            attachments: self.attachments(id),
            next_position: None,
        })
    }
    fn upload(
        &self,
        id: &str,
        upload: ConfluenceAttachmentUpload,
        operation: &'static str,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        self.mutate(operation);
        let attachment = ConfluenceAttachment {
            id: "9001".into(),
            page_id: id.into(),
            filename: upload.filename,
            size: upload.size,
            content_type: upload.content_type,
            media_type_declaration: None,
        };
        self.attachments
            .lock()
            .unwrap()
            .entry(id.into())
            .or_default()
            .push(attachment.clone());
        ok(attachment)
    }
}
fn parent(id: &str) -> ConfluenceParent {
    ConfluenceParent {
        kind: ConfluenceNodeKind::Page,
        id: id.into(),
    }
}

#[async_trait]
impl ConfluenceBackend for MatrixBackend {
    async fn hierarchy_node(
        &self,
        kind: ConfluenceNodeKind,
        id: &str,
        status: ConfluenceContentStatus,
        _require_parent: bool,
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceNode>, ConfluenceBackendError> {
        self.record("hierarchy_node");
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        if kind != ConfluenceNodeKind::Page {
            return Err(ConfluenceBackendError::NotFound);
        }
        let parent = self
            .parents
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        let actual = if id == "400" {
            ConfluenceContentStatus::Draft
        } else {
            ConfluenceContentStatus::Current
        };
        if actual != status {
            return Err(ConfluenceBackendError::ScopeUnresolved);
        }
        ok(ConfluenceNode {
            id: id.into(),
            kind,
            space_id: "98765".into(),
            parent,
            status,
            version: Some(1),
        })
    }
    async fn regular_page_metadata(
        &self,
        id: &str,
        require_parent: bool,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceRegularPage>, ConfluenceBackendError> {
        self.record("regular_page_metadata");
        let node = self
            .hierarchy_node(
                ConfluenceNodeKind::Page,
                id,
                ConfluenceContentStatus::Current,
                require_parent,
                credential,
                budget,
            )
            .await?
            .value;
        ok(ConfluenceRegularPage {
            node,
            title: "Matrix page".into(),
        })
    }
    async fn blog_location_metadata(
        &self,
        id: &str,
        status: ConfluenceContentStatus,
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogLocation>, ConfluenceBackendError> {
        self.record("blog_location_metadata");
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        if !matches!(
            (id, status),
            ("700", ConfluenceContentStatus::Current) | ("800", ConfluenceContentStatus::Draft)
        ) {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(ConfluenceBlogLocation {
            id: id.into(),
            space_id: "98765".into(),
            status,
            version: 1,
        })
    }
    async fn space_location_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        self.record("space_location_metadata");
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        if id != "98765" {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(self.space())
    }
    async fn space_by_id(
        &self,
        _id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        self.record("space_by_id");
        ok(self.space())
    }
    async fn space_by_key(
        &self,
        _key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        self.record("space_by_key");
        ok(self.space())
    }
    async fn space_list(
        &self,
        _request: ConfluenceSpaceListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpaceListPage>, ConfluenceBackendError> {
        self.record("space_list");
        ok(ConfluenceSpaceListPage {
            value: json!({"results":[{"id":"98765","key":self.key(),"name":"Matrix space","type":"global","status":"current"}]}),
            next_cursor: None,
        })
    }
    async fn page_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.record("page_metadata");
        if !matches!(id, "100" | "200" | "300") {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(self.page_value(id))
    }
    async fn page(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.record("page");
        ok(self.page_value(id))
    }
    async fn blog_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.record("blog_metadata");
        if id != "700" {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(self.blog_value(id))
    }
    async fn blog(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.record("blog");
        ok(self.blog_value(id))
    }
    async fn page_hierarchy(
        &self,
        id: &str,
        _get_draft: bool,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        self.record("page_hierarchy");
        let parent = self
            .parents
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        ok(ConfluencePageHierarchy {
            id: id.into(),
            space_id: "98765".into(),
            parent_page_id: parent.as_ref().map(|p| p.id.clone()),
            parent_type: parent.map(|p| p.kind.as_str().into()),
            status: "current".into(),
            version: 1,
        })
    }
    async fn page_ancestors(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        self.record("page_ancestors");
        let parents = self.parents.lock().unwrap();
        let mut next = parents.get(id).cloned().flatten();
        let mut ancestors = vec![];
        while let Some(parent) = next {
            next = parents.get(&parent.id).cloned().flatten();
            ancestors.push(ConfluencePageAncestor {
                id: parent.id,
                content_type: parent.kind.as_str().into(),
            });
        }
        ok(ancestors)
    }
    async fn page_direct_children(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageChild>>, ConfluenceBackendError> {
        self.record("page_direct_children");
        let parents = self.parents.lock().unwrap();
        ok(parents
            .iter()
            .filter(|(child, parent)| {
                child.as_str() != "400" && parent.as_ref().is_some_and(|p| p.id == id)
            })
            .enumerate()
            .map(|(position, (id, _))| ConfluencePageChild {
                id: id.clone(),
                content_type: "page".into(),
                status: "current".into(),
                child_position: position as u64,
            })
            .collect())
    }
    async fn move_page(
        &self,
        id: &str,
        position: ConfluencePageMovePosition,
        target: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        self.mutate("move_page");
        assert_eq!(position, ConfluencePageMovePosition::Append);
        self.parents
            .lock()
            .unwrap()
            .insert(id.into(), Some(parent(target)));
        ok(id.into())
    }
    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        self.record("search");
        ok(ConfluenceSearchPage {
            pages: vec![self.page_value("100")],
            max_results: request.max_results,
            next_page_token: None,
        })
    }
    async fn search_blogs(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        self.record("search_blogs");
        let page = self.page_value("700");
        ok(ConfluenceSearchBlog {
            blogs: vec![ConfluenceBlogSummary {
                id: page.id,
                title: page.title,
                space: page.space,
                space_web_url: None,
                web_url: None,
                status: page.status,
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
            }],
            max_results: request.max_results,
            next_page_token: None,
        })
    }
    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.mutate("create_page");
        let mut page = self.page_value("900");
        page.title = request.title;
        ok(page)
    }
    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.mutate("update_page");
        let mut page = self.page_value(&request.page_id);
        page.version = request.base_version + 1;
        page.title = request.title;
        ok(page)
    }
    async fn create_blog(
        &self,
        request: ConfluenceBlogCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.mutate("create_blog");
        let mut blog = self.blog_value("901");
        blog.title = request.title;
        ok(blog)
    }
    async fn update_blog(
        &self,
        request: ConfluenceBlogUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.mutate("update_blog");
        let mut blog = self.blog_value(&request.blog_id);
        blog.version = request.base_version + 1;
        blog.title = request.title;
        ok(blog)
    }
    async fn create_page_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.create_draft(
            request,
            ConfluenceDraftContentType::Page,
            "create_page_draft",
        )
    }
    async fn create_blog_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.create_draft(
            request,
            ConfluenceDraftContentType::Blog,
            "create_blog_draft",
        )
    }
    async fn draft_page(
        &self,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.record("draft_page");
        ok(self.get_draft(id)?)
    }
    async fn draft_blog(
        &self,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.record("draft_blog");
        ok(self.get_draft(id)?)
    }
    async fn update_page_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.update_draft(
            request,
            ConfluenceDraftContentType::Page,
            "update_page_draft",
        )
    }
    async fn update_blog_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.update_draft(
            request,
            ConfluenceDraftContentType::Blog,
            "update_blog_draft",
        )
    }
    async fn discard_page_draft(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.mutate("discard_page_draft");
        self.drafts.lock().unwrap().remove(id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }
    async fn discard_blog_draft(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.mutate("discard_blog_draft");
        self.drafts.lock().unwrap().remove(id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }
    async fn page_attachments(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        self.record("page_attachments");
        ok(self.attachments(id))
    }
    async fn blog_attachments(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        self.record("blog_attachments");
        ok(self.attachments(id))
    }
    async fn comment(
        &self,
        kind: ConfluenceCommentKind,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.record("comment");
        let comment = self
            .comments
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        if comment.kind != kind {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(comment)
    }
    async fn comments_page(
        &self,
        request: ConfluenceCommentListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.record("comments_page");
        ok(ConfluenceCommentListPage {
            comments: self
                .comments
                .lock()
                .unwrap()
                .values()
                .filter(|c| {
                    c.kind == request.kind
                        && c.parent_comment_id.is_none()
                        && c.page_id.as_ref().or(c.blog_id.as_ref()) == Some(&request.container_id)
                })
                .cloned()
                .collect(),
            next_cursor: None,
        })
    }
    async fn comment_replies_page(
        &self,
        kind: ConfluenceCommentKind,
        id: &str,
        _body_format: Option<&str>,
        _max_results: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.record("comment_replies_page");
        ok(ConfluenceCommentListPage {
            comments: vec![comment("510", kind, None, None, Some(id), BODY)],
            next_cursor: None,
        })
    }
    async fn add_comment(
        &self,
        request: ConfluenceCommentCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.mutate("add_comment");
        let value = comment(
            "9000",
            request.kind,
            request.page_id.as_deref(),
            request.blog_id.as_deref(),
            request.parent_comment_id.as_deref(),
            &request.body.value,
        );
        self.comments
            .lock()
            .unwrap()
            .insert(value.id.clone(), value.clone());
        ok(value)
    }
    async fn update_comment(
        &self,
        request: ConfluenceCommentUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.mutate("update_comment");
        let mut comments = self.comments.lock().unwrap();
        let value = comments
            .get_mut(&request.comment_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        value.version = Some(request.base_version + 1);
        value.bodies = BTreeMap::from([(request.body.representation, request.body.value)]);
        ok(value.clone())
    }
    async fn delete_comment(
        &self,
        _kind: ConfluenceCommentKind,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.mutate("delete_comment");
        self.comments.lock().unwrap().remove(id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }
    async fn add_attachment(
        &self,
        id: &str,
        upload: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        self.upload(id, upload, "add_attachment")
    }
    async fn add_blog_attachment(
        &self,
        id: &str,
        upload: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        self.upload(id, upload, "add_blog_attachment")
    }
    async fn add_page_draft_attachment(
        &self,
        id: &str,
        upload: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        self.upload(id, upload, "add_page_draft_attachment")
    }
    async fn add_blog_draft_attachment(
        &self,
        id: &str,
        upload: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        self.upload(id, upload, "add_blog_draft_attachment")
    }
    async fn page_attachments_page(
        &self,
        id: &str,
        _maximum: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page(id, "page_attachments_page")
    }
    async fn blog_attachments_page(
        &self,
        id: &str,
        _maximum: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page(id, "blog_attachments_page")
    }
    async fn page_draft_attachments_page(
        &self,
        id: &str,
        _maximum: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page(id, "page_draft_attachments_page")
    }
    async fn blog_draft_attachments_page(
        &self,
        id: &str,
        _maximum: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page(id, "blog_draft_attachments_page")
    }
    async fn attachment_content(
        &self,
        _id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.record("attachment_content");
        ok(ConfluenceAttachmentContent::from_bytes(
            "matrix.txt",
            "text/plain",
            b"x".to_vec(),
        ))
    }
    async fn blog_attachment_content(
        &self,
        _id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.record("blog_attachment_content");
        ok(ConfluenceAttachmentContent::from_bytes(
            "matrix.txt",
            "text/plain",
            b"x".to_vec(),
        ))
    }
    async fn page_draft_attachment_content(
        &self,
        _id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.record("page_draft_attachment_content");
        ok(ConfluenceAttachmentContent::from_bytes(
            "matrix.txt",
            "text/plain",
            b"x".to_vec(),
        ))
    }
    async fn blog_draft_attachment_content(
        &self,
        _id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.record("blog_draft_attachment_content");
        ok(ConfluenceAttachmentContent::from_bytes(
            "matrix.txt",
            "text/plain",
            b"x".to_vec(),
        ))
    }
}

fn inputs(provider: &ConfluenceProvider, action: &str) -> Value {
    let blog = action.starts_with("blog.");
    let id = if blog { "700" } else { "100" };
    let id_field = if blog { "blogId" } else { "pageId" };
    let mut value = json!({id_field:id});
    if let Some(comment) = confluence_comment_action(action) {
        value = match comment.operation {
            ConfluenceCommentOperation::List | ConfluenceCommentOperation::Add => {
                json!({id_field:id})
            }
            _ => {
                json!({"commentId":match (blog,comment.kind){(false,ConfluenceCommentKind::Footer)=>"500",(false,ConfluenceCommentKind::Inline)=>"501",(true,ConfluenceCommentKind::Footer)=>"600",(true,ConfluenceCommentKind::Inline)=>"601"}})
            }
        };
    }
    if matches!(
        action,
        "page.create" | "page.draft.create" | "blog.create" | "blog.draft.create"
    ) {
        value = json!({"space":"ENG","title":"Created"});
    }
    if action == "space.list" {
        return json!({});
    }
    if matches!(action, "search" | "blog.search") {
        return json!({"query":{"type":"cql","value":""},"maxResults":1});
    }
    if action == "page.move" {
        value = json!({"pageId":"100","targetPageId":"300","position":"append"});
    }
    if (action.ends_with(".update") || action.ends_with(".stage")) && !consumes_draft_handle(action)
    {
        value["baseVersion"] = json!(1);
    }
    if action.ends_with(".update")
        || action.ends_with(".stage")
        || action.ends_with(".create")
        || action.ends_with("comment.add")
        || action.ends_with("reply.add")
    {
        value["contentFormat"] = json!("storage");
        value["content"] = json!(BODY);
    }
    if action.ends_with("attachment.add") {
        value["attachments"] = json!([{"field":"file","filename":"matrix.txt","contentType":"text/plain","size":1,"sha256":sha256_hex(b"x")}]);
    }
    if action.ends_with("attachment.download") {
        value["attachmentId"] = json!("9000");
    }
    if action == "verify" || action.ends_with(".verify") {
        value["expectVersion"] = json!(1);
    }
    if consumes_draft_handle(action) {
        let kind = if blog {
            ConfluenceDraftContentType::Blog
        } else {
            ConfluenceDraftContentType::Page
        };
        let draft_id = if blog { "800" } else { "400" };
        value[id_field] = json!(draft_id);
        if action.ends_with(".view") || action.ends_with(".publish") {
            value["bodyFormat"] = json!("storage");
        }
        let handle = ConfluenceDraftHandle {
            content_type: kind,
            content_id: draft_id.into(),
            space: "ENG".into(),
            space_id: "98765".into(),
            origin: ConfluenceDraftOrigin::New,
            parent: (!blog).then(|| parent("200")),
            base_version: None,
        };
        let request = InvocationBuilder::new("confluence", action)
            .credential(credential())
            .build();
        value["draftHandle"] = json!(
            provider
                .continuations
                .seal_draft_handle(request.context(), request.execution(), &handle)
                .unwrap()
        );
    }
    value
}

async fn admitted(
    provider: &ConfluenceProvider,
    action: &str,
    space_only: bool,
) -> ProviderInvocation {
    let input = inputs(provider, action);
    let mut builder = InvocationBuilder::new("confluence", action)
        .inputs(input.clone())
        .credential(credential())
        .lookup_credential(credential());
    if action.ends_with("attachment.add") {
        builder = builder.body_parts(vec![BrokerBodyPart::in_memory(
            "file",
            Some("matrix.txt".into()),
            Some("text/plain".into()),
            b"x".to_vec(),
        )]);
    }
    if matches!(action, "space.list" | "search" | "blog.search") {
        return provider
            .admit_fixture(builder.search(confluence_search_preflight(["ENG"])).build())
            .await
            .unwrap();
    }
    if matches!(action, "blog.create" | "blog.draft.create") {
        return builder
            .resources(ResourceScopes::from([("space".into(), vec!["ENG".into()])]))
            .build();
    }
    // Moves always need the complete current/proposed region, including under
    // space authority; the production host makes this same evidence request.
    let level = if space_only && action != "page.move" {
        ContainmentEvidenceLevel::ContainerOnly
    } else {
        ContainmentEvidenceLevel::CompleteLineage
    };
    let mut fixture = ScopeRequestFixture::new("confluence", action, input)
        .lookup_credential(credential())
        .containment_evidence_level(level);
    if let Some(state) = provider
        .validate_scope_locator(fixture.local_request())
        .unwrap()
    {
        fixture = fixture.locator_state(state);
    }
    let (ScopeEvidence::Containment(evidence), Some(state)) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap_or_else(|e| panic!("{action} initial: {e:?}"))
        .into_parts()
    else {
        panic!("{action} containment absent")
    };
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    let selection = if space_only {
        ResourceSelector::Exact {
            value: "ENG".into(),
        }
    } else if action.starts_with("blog.") {
        ResourceSelector::Exact {
            value: format!(
                "https://example.atlassian.net/wiki/spaces/ENG/blog/{}",
                if consumes_draft_handle(action) {
                    "800"
                } else {
                    "700"
                }
            ),
        }
    } else if consumes_draft_handle(action) {
        ResourceSelector::Exact {
            value: "https://example.atlassian.net/wiki/spaces/ENG/pages/400".into(),
        }
    } else {
        ResourceSelector::Subtree { value: ROOT.into() }
    };
    let boundary = ContainmentBoundary::new(
        vec![
            registry
                .typed_selector(
                    if space_only {
                        CONFLUENCE_SPACE_RESOURCE.id()
                    } else {
                        CONFLUENCE_CONTENT_RESOURCE.id()
                    },
                    &selection,
                )
                .unwrap(),
        ],
        vec![],
    );
    assert!(
        boundary.matches_evidence(&evidence).unwrap(),
        "{action} must fit selected content boundary"
    );
    let contract = confluence_resource_scopes()[confluence_scope_name(action)]
        .as_containment()
        .unwrap()
        .clone();
    let authorization = agent_access_provider::host::containment_authorization(
        "https://example.atlassian.net",
        contract,
        evidence,
        &registry,
        level,
        "a".repeat(64),
    )
    .unwrap();
    builder.containment(authorization).state(state).build()
}

async fn exercise(action: &str, operation: &str) {
    for (outside, space_only) in [(false, false), (false, true), (true, false)] {
        let backend = Arc::new(MatrixBackend::new());
        let mut config = confluence_config();
        config.attachments.upload_media_types = vec!["text/plain".into()];
        config.attachments.download_media_types.allow = vec!["text/plain".into()];
        let provider = ConfluenceProvider::with_backend_and_signing_key(
            config.clone(),
            ProviderLimits::default(),
            backend.clone(),
            test_signing_key(97),
        );
        let mut request = admitted(&provider, action, space_only).await;
        let before = backend.calls.lock().unwrap().len();
        if outside {
            backend.outside.store(true, Ordering::SeqCst);
            if matches!(action, "blog.create" | "blog.draft.create") {
                request = InvocationBuilder::from(request)
                    .input("space", json!("OPS"))
                    .build();
            }
        }
        let result = provider.invoke(request).await;
        if outside {
            assert_eq!(
                backend.writes.load(Ordering::SeqCst),
                0,
                "{action} out-of-bound write"
            );
            if matches!(action, "space.list" | "search" | "blog.search") {
                let result = result
                    .unwrap_or_else(|error| panic!("{action} filtered collection: {error:?}"));
                let field = match action {
                    "space.list" => "items",
                    "search" => "pages",
                    _ => "blogs",
                };
                assert_eq!(
                    result.result[field],
                    json!([]),
                    "{action} outside rows released"
                );
                assert!(
                    !result.result.to_string().contains("Matrix"),
                    "{action} outside metadata"
                );
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::ScopeUnresolved,
                    "{action}: {error:?}"
                );
                assert!(
                    error.result.is_none()
                        || error.result.as_deref().is_some_and(
                            |value| value.get("mutationStatus") == Some(&json!("not_applied"))
                        ),
                    "{action} leaked result: {error:?}"
                );
            }
        } else {
            let mut result = result.unwrap_or_else(|error| panic!("{action} positive: {error:?}"));
            assert!(
                backend.calls.lock().unwrap()[before..].contains(&operation),
                "{action} did not execute {operation}"
            );
            let readonly = confluence_descriptor(&config)
                .action(action)
                .unwrap()
                .read_only;
            assert_eq!(
                backend.writes.load(Ordering::SeqCst),
                usize::from(!readonly),
                "{action} mutation count"
            );
            if let Some(stream) = result.stream.take() {
                assert_eq!(stream_bytes(stream).await, b"x", "{action} bytes");
            }
        }
    }
}

macro_rules! cases {
    ($($name:ident: $action:literal => $operation:literal,)*) => {
        $(#[tokio::test] async fn $name(){exercise($action,$operation).await;})*
        #[test] fn execution_matrix_matches_all_published_actions(){
            let expected=BTreeSet::from([$($action,)*]);
            let descriptor=confluence_descriptor(&confluence_config());
            let published=descriptor.actions.iter().map(|action|action.action.as_str()).collect::<BTreeSet<_>>();
            assert_eq!(expected.len(),64);assert_eq!(expected,published);
            let documentation: Value = serde_json::from_str(include_str!("../action-documentation.json")).unwrap();
            let documented = documentation.as_object().unwrap().keys().map(String::as_str).collect::<BTreeSet<_>>();
            assert_eq!(expected, documented);
        }
    };
}

cases! {
    attachment_add: "attachment.add" => "add_attachment",
    attachment_download: "attachment.download" => "attachment_content",
    attachment_list: "attachment.list" => "page_attachments_page",
    blog_attachment_add: "blog.attachment.add" => "add_blog_attachment",
    blog_attachment_download: "blog.attachment.download" => "blog_attachment_content",
    blog_attachment_list: "blog.attachment.list" => "blog_attachments_page",
    blog_create: "blog.create" => "create_blog",
    blog_draft_attachment_add: "blog.draft.attachment.add" => "add_blog_draft_attachment",
    blog_draft_attachment_download: "blog.draft.attachment.download" => "blog_draft_attachment_content",
    blog_draft_attachment_list: "blog.draft.attachment.list" => "blog_draft_attachments_page",
    blog_draft_create: "blog.draft.create" => "create_blog_draft",
    blog_draft_discard: "blog.draft.discard" => "discard_blog_draft",
    blog_draft_publish: "blog.draft.publish" => "update_blog_draft",
    blog_draft_stage: "blog.draft.stage" => "update_blog_draft",
    blog_draft_update: "blog.draft.update" => "update_blog_draft",
    blog_draft_verify: "blog.draft.verify" => "draft_blog",
    blog_draft_view: "blog.draft.view" => "draft_blog",
    blog_footer_comment_add: "blog.footer_comment.add" => "add_comment",
    blog_footer_comment_delete: "blog.footer_comment.delete" => "delete_comment",
    blog_footer_comment_list: "blog.footer_comment.list" => "comments_page",
    blog_footer_comment_reply_add: "blog.footer_comment.reply.add" => "add_comment",
    blog_footer_comment_reply_list: "blog.footer_comment.reply.list" => "comment_replies_page",
    blog_footer_comment_update: "blog.footer_comment.update" => "update_comment",
    blog_footer_comment_view: "blog.footer_comment.view" => "comment",
    blog_inline_comment_delete: "blog.inline_comment.delete" => "delete_comment",
    blog_inline_comment_list: "blog.inline_comment.list" => "comments_page",
    blog_inline_comment_reply_add: "blog.inline_comment.reply.add" => "add_comment",
    blog_inline_comment_reply_list: "blog.inline_comment.reply.list" => "comment_replies_page",
    blog_inline_comment_update: "blog.inline_comment.update" => "update_comment",
    blog_inline_comment_view: "blog.inline_comment.view" => "comment",
    blog_search: "blog.search" => "search_blogs",
    blog_update: "blog.update" => "update_blog",
    blog_verify: "blog.verify" => "blog_metadata",
    blog_view: "blog.view" => "blog",
    page_create: "page.create" => "create_page",
    page_draft_attachment_add: "page.draft.attachment.add" => "add_page_draft_attachment",
    page_draft_attachment_download: "page.draft.attachment.download" => "page_draft_attachment_content",
    page_draft_attachment_list: "page.draft.attachment.list" => "page_draft_attachments_page",
    page_draft_create: "page.draft.create" => "create_page_draft",
    page_draft_discard: "page.draft.discard" => "discard_page_draft",
    page_draft_publish: "page.draft.publish" => "update_page_draft",
    page_draft_stage: "page.draft.stage" => "update_page_draft",
    page_draft_update: "page.draft.update" => "update_page_draft",
    page_draft_verify: "page.draft.verify" => "draft_page",
    page_draft_view: "page.draft.view" => "draft_page",
    page_footer_comment_add: "page.footer_comment.add" => "add_comment",
    page_footer_comment_delete: "page.footer_comment.delete" => "delete_comment",
    page_footer_comment_list: "page.footer_comment.list" => "comments_page",
    page_footer_comment_reply_add: "page.footer_comment.reply.add" => "add_comment",
    page_footer_comment_reply_list: "page.footer_comment.reply.list" => "comment_replies_page",
    page_footer_comment_update: "page.footer_comment.update" => "update_comment",
    page_footer_comment_view: "page.footer_comment.view" => "comment",
    page_inline_comment_delete: "page.inline_comment.delete" => "delete_comment",
    page_inline_comment_list: "page.inline_comment.list" => "comments_page",
    page_inline_comment_reply_add: "page.inline_comment.reply.add" => "add_comment",
    page_inline_comment_reply_list: "page.inline_comment.reply.list" => "comment_replies_page",
    page_inline_comment_update: "page.inline_comment.update" => "update_comment",
    page_inline_comment_view: "page.inline_comment.view" => "comment",
    page_move: "page.move" => "move_page",
    page_update: "page.update" => "update_page",
    page_view: "page.view" => "page",
    search: "search" => "search",
    space_list: "space.list" => "space_list",
    verify: "verify" => "page_metadata",
}
