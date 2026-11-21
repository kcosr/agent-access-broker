use super::*;
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, basic_credential, test_signing_key,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn ok<T>(value: T) -> Result<ConfluenceBackendResponse<T>, ConfluenceBackendError> {
    Ok(ConfluenceBackendResponse {
        value,
        status: 200,
        duration_ms: 1,
    })
}
fn token() -> ExecutionCredential {
    basic_credential("reader@example.test", "synthetic-token")
}
fn config() -> ConfluenceProviderConfig {
    serde_json::from_value(
        json!({"tenant_host":"example.atlassian.net","content":{"page_formats":["storage"]}}),
    )
    .unwrap()
}
fn parent(kind: ConfluenceNodeKind, id: &str) -> ConfluenceParent {
    ConfluenceParent {
        kind,
        id: id.into(),
    }
}
fn page(id: &str) -> ConfluencePage {
    ConfluencePage {
        id: id.into(),
        title: "Fixture".into(),
        space: "ENG".into(),
        web_url: None,
        space_web_url: None,
        space_alias: None,
        status: Some("current".into()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".into(), "<p>safe</p>".into())]),
    }
}
fn space() -> ConfluenceSpace {
    ConfluenceSpace {
        id: "98765".into(),
        key: "ENG".into(),
        web_url: None,
        alias: None,
        status: Some("current".into()),
        homepage_id: Some("200".into()),
    }
}

struct EvidenceBackend {
    nodes: Mutex<BTreeMap<(ConfluenceNodeKind, String), ConfluenceNode>>,
    hidden_nodes: Mutex<BTreeSet<String>>,
    hidden_for_credential: Mutex<Option<ExecutionCredential>>,
    hierarchy_credentials: Mutex<Vec<ExecutionCredential>>,
    space: Mutex<ConfluenceSpace>,
    page_reads: AtomicUsize,
    metadata_reads: AtomicUsize,
    move_during_metadata: bool,
    writes: AtomicUsize,
    published_current_version: AtomicUsize,
    published_current_reads: AtomicUsize,
    published_current_parent: Mutex<Option<ConfluenceParent>>,
    publish_requests: Mutex<Vec<ConfluenceDraftUpdateRequest>>,
    publish_response: Mutex<Option<ConfluenceDraftContent>>,
    emitted_bytes: Arc<AtomicUsize>,
    content_opens: AtomicUsize,
    download_fixture: bool,
    move_during_membership: bool,
    update_conflict: bool,
    draft_read_failure: Mutex<Option<ConfluenceBackendError>>,
    draft_read_budget: Mutex<Option<ConfluenceMetadataBudget>>,
    draft_read_override: Mutex<Option<ConfluenceDraftContent>>,
    move_during_body: bool,
    move_during_download: bool,
    move_after_upload: bool,
    comment_chain: AtomicUsize,
}
impl EvidenceBackend {
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        for (id, parent) in [
            ("100", Some(parent(ConfluenceNodeKind::Page, "200"))),
            ("200", None),
            ("300", None),
            ("400", Some(parent(ConfluenceNodeKind::Page, "200"))),
        ] {
            nodes.insert(
                (ConfluenceNodeKind::Page, id.into()),
                ConfluenceNode {
                    id: id.into(),
                    kind: ConfluenceNodeKind::Page,
                    space_id: "98765".into(),
                    parent,
                    status: ConfluenceContentStatus::Current,
                    version: Some(1),
                },
            );
        }
        Self {
            nodes: Mutex::new(nodes),
            hidden_nodes: Mutex::new(BTreeSet::new()),
            hidden_for_credential: Mutex::new(None),
            hierarchy_credentials: Mutex::new(Vec::new()),
            space: Mutex::new(space()),
            page_reads: AtomicUsize::new(0),
            metadata_reads: AtomicUsize::new(0),
            move_during_metadata: false,
            writes: AtomicUsize::new(0),
            published_current_version: AtomicUsize::new(7),
            published_current_reads: AtomicUsize::new(0),
            published_current_parent: Mutex::new(None),
            publish_requests: Mutex::new(Vec::new()),
            publish_response: Mutex::new(None),
            emitted_bytes: Arc::new(AtomicUsize::new(0)),
            content_opens: AtomicUsize::new(0),
            download_fixture: false,
            move_during_membership: false,
            update_conflict: false,
            draft_read_failure: Mutex::new(None),
            draft_read_budget: Mutex::new(None),
            draft_read_override: Mutex::new(None),
            move_during_body: false,
            move_during_download: false,
            move_after_upload: false,
            comment_chain: AtomicUsize::new(0),
        }
    }
    fn publish(
        &self,
        request: ConfluenceDraftUpdateRequest,
        kind: ConfluenceDraftContentType,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.publish_requests.lock().unwrap().push(request.clone());
        let mut published = self.draft(&request.content_id, kind);
        published.status = Some(request.status);
        published.version = request.version_number;
        ok(self
            .publish_response
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(published))
    }
    fn move_page(&self) {
        self.nodes
            .lock()
            .unwrap()
            .get_mut(&(ConfluenceNodeKind::Page, "100".into()))
            .unwrap()
            .parent = Some(parent(ConfluenceNodeKind::Page, "300"));
    }
    fn provider(self: &Arc<Self>) -> ConfluenceProvider {
        ConfluenceProvider::with_backend_and_signing_key(
            config(),
            ProviderLimits::default(),
            self.clone(),
            test_signing_key(41),
        )
    }
    fn draft(&self, id: &str, kind: ConfluenceDraftContentType) -> ConfluenceDraftContent {
        ConfluenceDraftContent {
            id: id.into(),
            title: "Draft".into(),
            content_type: kind.as_str().into(),
            space: "ENG".into(),
            space_id: "98765".into(),
            space_alias: None,
            parent: (kind == ConfluenceDraftContentType::Page)
                .then(|| parent(ConfluenceNodeKind::Page, "200")),
            web_url: None,
            space_web_url: None,
            status: Some("draft".into()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".into(), "<p>draft</p>".into())]),
        }
    }
}
#[async_trait]
impl ConfluenceBackend for EvidenceBackend {
    async fn hierarchy_node(
        &self,
        kind: ConfluenceNodeKind,
        id: &str,
        status: ConfluenceContentStatus,
        _require_parent: bool,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceNode>, ConfluenceBackendError> {
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        let material = credential
            .static_credential()
            .expect("fixture uses static credentials");
        self.hierarchy_credentials
            .lock()
            .unwrap()
            .push(material.clone());
        if self.hidden_nodes.lock().unwrap().contains(id)
            && self
                .hidden_for_credential
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|blocked| blocked == material)
        {
            return Err(ConfluenceBackendError::Forbidden);
        }
        let mut node = self
            .nodes
            .lock()
            .unwrap()
            .get(&(kind, id.into()))
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        if id == "400" {
            node.status = status;
            if status == ConfluenceContentStatus::Current {
                self.published_current_reads.fetch_add(1, Ordering::SeqCst);
                node.version = Some(self.published_current_version.load(Ordering::SeqCst) as u64);
                if let Some(parent) = self.published_current_parent.lock().unwrap().as_ref() {
                    node.parent = Some(parent.clone());
                }
            }
        }
        if node.status != status {
            return Err(ConfluenceBackendError::ScopeUnresolved);
        }
        ok(node)
    }
    async fn page_hierarchy(
        &self,
        id: &str,
        _get_draft: bool,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        let node = self
            .nodes
            .lock()
            .unwrap()
            .get(&(ConfluenceNodeKind::Page, id.into()))
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        ok(ConfluencePageHierarchy {
            id: node.id,
            space_id: node.space_id,
            parent_page_id: node.parent.as_ref().map(|parent| parent.id.clone()),
            parent_type: node
                .parent
                .as_ref()
                .map(|parent| parent.kind.as_str().into()),
            status: "current".into(),
            version: 1,
        })
    }
    async fn page_ancestors(
        &self,
        _id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        ok(Vec::new())
    }
    async fn move_page(
        &self,
        _id: &str,
        _position: ConfluencePageMovePosition,
        _target: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(ConfluenceBackendError::Protocol("unexpected move".into()))
    }
    async fn regular_page_metadata(
        &self,
        id: &str,
        require_parent: bool,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceRegularPage>, ConfluenceBackendError> {
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
            title: "Regular".into(),
        })
    }
    async fn blog_location_metadata(
        &self,
        id: &str,
        status: ConfluenceContentStatus,
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogLocation>, ConfluenceBackendError> {
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        if id == "800" && status == ConfluenceContentStatus::Current {
            self.published_current_reads.fetch_add(1, Ordering::SeqCst);
        }
        ok(ConfluenceBlogLocation {
            id: id.into(),
            space_id: "98765".into(),
            status,
            version: if id == "800" && status == ConfluenceContentStatus::Current {
                self.published_current_version.load(Ordering::SeqCst) as u64
            } else {
                1
            },
        })
    }
    async fn space_location_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        let s = self.space.lock().unwrap().clone();
        if s.id != id {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(s)
    }
    async fn space_by_key(
        &self,
        key: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let s = self.space.lock().unwrap().clone();
        if s.key != key {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(s)
    }
    async fn space_by_id(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let s = self.space.lock().unwrap().clone();
        if s.id != id {
            return Err(ConfluenceBackendError::NotFound);
        }
        ok(s)
    }
    async fn space_list(
        &self,
        _request: ConfluenceSpaceListRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpaceListPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }
    async fn page_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.metadata_reads.fetch_add(1, Ordering::SeqCst);
        if self.move_during_metadata {
            self.move_page();
        }
        ok(page(id))
    }
    async fn page(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_reads.fetch_add(1, Ordering::SeqCst);
        if self.move_during_body {
            self.move_page();
        }
        ok(page(id))
    }
    async fn blog_metadata(
        &self,
        id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        ok(ConfluenceBlog {
            id: id.into(),
            title: "Blog".into(),
            space: "ENG".into(),
            space_id: "98765".into(),
            space_alias: None,
            web_url: None,
            space_web_url: None,
            status: Some("current".into()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        })
    }
    async fn comment(
        &self,
        kind: ConfluenceCommentKind,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let indirect = self.comment_chain.load(Ordering::SeqCst) > 0 && id == "500";
        ok(ConfluenceComment {
            id: id.into(),
            kind,
            page_id: (id != "600" && !indirect).then(|| "100".into()),
            blog_id: (id == "600").then(|| "700".into()),
            parent_comment_id: indirect.then(|| "501".into()),
            status: Some("current".into()),
            resolution_status: None,
            version: Some(1),
            author: None,
            created_at: None,
            updated_at: None,
            bodies: BTreeMap::new(),
        })
    }
    async fn draft_page(
        &self,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        if let Some(budget) = self.draft_read_budget.lock().unwrap().as_ref() {
            budget.charge_bytes(u64::MAX)?;
        }
        if let Some(error) = self.draft_read_failure.lock().unwrap().as_ref() {
            return Err(error.clone());
        }
        ok(self
            .draft_read_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.draft(id, ConfluenceDraftContentType::Page)))
    }
    async fn draft_blog(
        &self,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        if let Some(budget) = self.draft_read_budget.lock().unwrap().as_ref() {
            budget.charge_bytes(u64::MAX)?;
        }
        if let Some(error) = self.draft_read_failure.lock().unwrap().as_ref() {
            return Err(error.clone());
        }
        ok(self
            .draft_read_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.draft(id, ConfluenceDraftContentType::Blog)))
    }
    async fn update_page_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.publish(request, ConfluenceDraftContentType::Page)
    }
    async fn update_blog_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.publish(request, ConfluenceDraftContentType::Blog)
    }
    async fn page_draft_attachments_page(
        &self,
        id: &str,
        _limit: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        ok(ConfluenceAttachmentListPage {
            attachments: if self.download_fixture {
                self.page_attachments(id, _credential).await?.value
            } else {
                Vec::new()
            },
            next_position: None,
        })
    }
    async fn blog_draft_attachments_page(
        &self,
        id: &str,
        _limit: u32,
        _cursor: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        ok(ConfluenceAttachmentListPage {
            attachments: if self.download_fixture {
                self.page_attachments(id, _credential).await?.value
            } else {
                Vec::new()
            },
            next_position: None,
        })
    }
    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }
    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        ok(page("900"))
    }
    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.update_conflict {
            return Err(ConfluenceBackendError::Conflict);
        }
        let mut value = page(&request.page_id);
        value.version = request.base_version + 1;
        ok(value)
    }
    async fn add_attachment(
        &self,
        page_id: &str,
        upload: ConfluenceAttachmentUpload,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.move_after_upload {
            self.move_page();
        }
        ok(ConfluenceAttachment {
            id: n.to_string(),
            page_id: page_id.into(),
            filename: upload.filename,
            size: upload.size,
            content_type: upload.content_type,
            media_type_declaration: None,
        })
    }
    async fn page_attachments(
        &self,
        page_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        if self.move_during_membership {
            self.space.lock().unwrap().key = "OPS".into();
        }
        ok(vec![ConfluenceAttachment {
            id: "800".into(),
            page_id: page_id.into(),
            filename: "a.txt".into(),
            size: 1,
            content_type: "text/plain".into(),
            media_type_declaration: None,
        }])
    }
    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.content_opens.fetch_add(1, Ordering::SeqCst);
        if self.move_during_download {
            self.move_page();
        }
        let observed = self.emitted_bytes.clone();
        let stream = futures_util::stream::once(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(bytes::Bytes::from_static(b"x"))
        });
        ok(ConfluenceAttachmentContent {
            filename: "a.txt".into(),
            sha256: None,
            stream: ProviderResultStream::from_stream("text/plain", stream),
            size: Some(1),
            content_type: "text/plain".into(),
            media_type_declaration: MediaTypeDeclaration::parse("text/plain"),
        })
    }
    async fn blog_attachments(
        &self,
        id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        self.page_attachments(id, credential).await
    }
    async fn blog_attachment_content(
        &self,
        id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.attachment_content(id, attachment_id, credential).await
    }
    async fn page_draft_attachment_content(
        &self,
        id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.attachment_content(id, attachment_id, credential).await
    }
    async fn blog_draft_attachment_content(
        &self,
        id: &str,
        attachment_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        self.attachment_content(id, attachment_id, credential).await
    }
}

fn action_inputs(provider: &ConfluenceProvider, action: &str) -> Value {
    let blog = action.starts_with("blog.");
    let id_field = if blog { "blogId" } else { "pageId" };
    let id = if blog { "700" } else { "100" };
    let mut input = json!({id_field:id});
    if let Some(comment) = confluence_comment_action(action) {
        input = match comment.operation {
            ConfluenceCommentOperation::List | ConfluenceCommentOperation::Add => {
                json!({id_field:id})
            }
            _ => json!({"commentId":if blog{"600"}else{"500"}}),
        };
    }
    if matches!(
        action,
        "page.create" | "page.draft.create" | "blog.create" | "blog.draft.create"
    ) {
        input = json!({"space":"ENG","title":"Created"});
    }
    if action == "space.list" {
        return json!({});
    }
    if matches!(action, "search" | "blog.search") {
        return json!({"query":{"text":"notes"}});
    }
    if action == "page.move" {
        input = json!({"pageId":"100","position":"append","targetPageId":"300"});
    }
    if (action.ends_with(".update") || action.ends_with(".stage")) && !consumes_draft_handle(action)
    {
        input["baseVersion"] = json!(1);
    }
    let content = action.ends_with(".update")
        || action.ends_with(".stage")
        || matches!(
            action,
            "page.create" | "page.draft.create" | "blog.create" | "blog.draft.create"
        )
        || action.ends_with("comment.add")
        || action.ends_with("reply.add");
    if content {
        input["contentFormat"] = json!("storage");
        input["content"] = json!("<p>new</p>");
    }
    if action.ends_with("attachment.add") {
        input["attachments"] = json!([{"field":"file","filename":"a.txt","contentType":"text/plain","size":1,"sha256":sha256_hex(b"x")}]);
    }
    if action.ends_with("attachment.download") {
        input["attachmentId"] = json!("800");
    }
    if action == "verify" || action.ends_with(".verify") {
        input["expectVersion"] = json!(1);
    }
    if consumes_draft_handle(action) {
        let kind = if blog {
            ConfluenceDraftContentType::Blog
        } else {
            ConfluenceDraftContentType::Page
        };
        let draft_id = if blog { "800" } else { "400" };
        input[id_field] = json!(draft_id);
        if action.ends_with(".view") || action.ends_with(".publish") {
            input["bodyFormat"] = json!("storage");
        }
        let handle = ConfluenceDraftHandle {
            content_type: kind,
            content_id: draft_id.into(),
            space: "ENG".into(),
            space_id: "98765".into(),
            origin: ConfluenceDraftOrigin::New,
            parent: (!blog).then(|| parent(ConfluenceNodeKind::Page, "200")),
            base_version: None,
        };
        let request = InvocationBuilder::new("confluence", action)
            .credential(token())
            .build();
        input["draftHandle"] = json!(
            provider
                .continuations
                .seal_draft_handle(request.context(), request.execution(), &handle)
                .unwrap()
        );
    }
    input
}

async fn admitted(
    provider: &ConfluenceProvider,
    action: &str,
    level: ContainmentEvidenceLevel,
) -> ProviderInvocation {
    admitted_with_roots(provider, action, level, Vec::new()).await
}

async fn admitted_with_roots(
    provider: &ConfluenceProvider,
    action: &str,
    level: ContainmentEvidenceLevel,
    roots: Vec<TypedResourceSelector>,
) -> ProviderInvocation {
    admitted_inputs(
        provider,
        action,
        level,
        roots,
        action_inputs(provider, action),
    )
    .await
}

async fn admitted_inputs(
    provider: &ConfluenceProvider,
    action: &str,
    level: ContainmentEvidenceLevel,
    roots: Vec<TypedResourceSelector>,
    inputs: Value,
) -> ProviderInvocation {
    let mut fixture = ScopeRequestFixture::new("confluence", action, inputs.clone())
        .lookup_credential(token())
        .containment_evidence_level(level)
        .containment_roots(roots);
    if let Some(state) = provider
        .validate_scope_locator(fixture.local_request())
        .unwrap()
    {
        fixture = fixture.locator_state(state);
    }
    let (ScopeEvidence::Containment(evidence), Some(state)) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap_or_else(|error| panic!("{action}: {error:?}"))
        .into_parts()
    else {
        panic!("{action}: missing containment")
    };
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    let boundary = |space: &str| {
        ContainmentBoundary::new(
            vec![
                registry
                    .typed_selector(
                        CONFLUENCE_SPACE_RESOURCE.id(),
                        &ResourceSelector::Exact {
                            value: space.into(),
                        },
                    )
                    .unwrap(),
            ],
            vec![],
        )
    };
    assert!(
        boundary("ENG").matches_evidence(&evidence).unwrap(),
        "{action}"
    );
    assert!(
        !boundary("OPS").matches_evidence(&evidence).unwrap(),
        "{action}"
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
    InvocationBuilder::new("confluence", action)
        .inputs(inputs)
        .credential(token())
        .lookup_credential(token())
        .containment(authorization)
        .state(state)
        .build()
}

#[tokio::test]
async fn every_point_action_admits_its_complete_operation_and_rechecks_current_location() {
    let descriptor = confluence_descriptor(&config());
    assert_eq!(descriptor.actions.len(), 64);
    let mut count = 0;
    let mut handles = 0;
    for action in descriptor.actions.iter().filter(|action| {
        !matches!(
            action.action.as_str(),
            "space.list" | "search" | "blog.search" | "blog.create" | "blog.draft.create"
        )
    }) {
        let backend = Arc::new(EvidenceBackend::new());
        let provider = backend.provider();
        let request = admitted(
            &provider,
            &action.action,
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .await;
        provider
            .recheck_content_location(&request)
            .await
            .unwrap_or_else(|error| panic!("{}: {error:?}", action.action));
        backend.space.lock().unwrap().key = "OPS".into();
        assert_eq!(
            provider
                .recheck_content_location(&request)
                .await
                .err()
                .unwrap()
                .reason_code(),
            ReasonCode::ScopeUnresolved,
            "{}",
            action.action
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
        handles += usize::from(consumes_draft_handle(&action.action));
        count += 1;
    }
    assert_eq!(count, 59);
    assert_eq!(handles, 16);
}

#[tokio::test]
async fn json_and_download_are_withheld_when_location_changes_after_fetch() {
    for action in ["page.view", "attachment.download"] {
        let mut raw = EvidenceBackend::new();
        raw.move_during_body = action == "page.view";
        raw.move_during_download = action == "attachment.download";
        let backend = Arc::new(raw);
        let provider = backend.provider();
        let request = admitted(&provider, action, ContainmentEvidenceLevel::CompleteLineage).await;
        let error = provider.invoke(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved, "{action}");
        assert!(error.result.is_none());
        assert_eq!(backend.emitted_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(
            error.audit.unwrap()["locationProof"]["finalCheck"],
            "changed"
        );
    }
}

#[tokio::test]
async fn update_has_no_side_effect_after_location_changes_and_never_reads_v1_metadata() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.update",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    backend.move_page();
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    assert_eq!(backend.page_reads.load(Ordering::SeqCst), 0);
    assert_eq!(backend.metadata_reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn same_comment_owner_with_a_changed_parent_chain_still_denies() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.footer_comment.view",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    backend.comment_chain.store(1, Ordering::SeqCst);
    assert_eq!(
        provider
            .recheck_content_location(&request)
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[tokio::test]
async fn initial_and_final_passes_share_one_metadata_budget() {
    let backend = Arc::new(EvidenceBackend::new());
    let mut provider = backend.provider();
    provider.config.content_access.max_metadata_requests = 4;
    let request = admitted(
        &provider,
        "page.view",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    assert_eq!(
        provider
            .recheck_content_location(&request)
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    let state = ProviderState::require::<ContentOperationState>(request.state()).unwrap();
    assert_eq!(state.budget.usage().unwrap().0, 4);
}

#[tokio::test]
async fn upload_rechecks_before_each_file_and_preserves_first_success() {
    let mut raw = EvidenceBackend::new();
    raw.move_after_upload = true;
    let backend = Arc::new(raw);
    let mut provider = backend.provider();
    provider.config.attachments.upload_media_types = vec!["text/plain".into()];
    let request = admitted(
        &provider,
        "attachment.add",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    let request=InvocationBuilder::from(request).input("attachments",json!([
        {"field":"file0","filename":"a.txt","contentType":"text/plain","size":1,"sha256":sha256_hex(b"x")},
        {"field":"file1","filename":"b.txt","contentType":"text/plain","size":1,"sha256":sha256_hex(b"y")}
    ])).body_parts(vec![
        BrokerBodyPart::in_memory("file0",Some("a.txt".into()),Some("text/plain".into()),b"x".to_vec()),
        BrokerBodyPart::in_memory("file1",Some("b.txt".into()),Some("text/plain".into()),b"y".to_vec()),
    ]).build();
    let error = provider.invoke(request).await.unwrap_err();
    let result = error.result.unwrap();
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(result["failures"][0]["reason"], "scope_unresolved");
    assert_eq!(
        error.audit.unwrap()["locationProof"]["finalCheck"],
        "changed"
    );
}

#[tokio::test]
async fn mixed_lineage_keeps_private_edges_and_detects_changes_below_public_projection() {
    let backend = Arc::new(EvidenceBackend::new());
    {
        let mut nodes = backend.nodes.lock().unwrap();
        nodes
            .get_mut(&(ConfluenceNodeKind::Page, "100".into()))
            .unwrap()
            .parent = Some(parent(ConfluenceNodeKind::Database, "500"));
        for (kind, id, edge) in [
            (
                ConfluenceNodeKind::Database,
                "500",
                Some(parent(ConfluenceNodeKind::Folder, "600")),
            ),
            (
                ConfluenceNodeKind::Folder,
                "600",
                Some(parent(ConfluenceNodeKind::Page, "200")),
            ),
        ] {
            nodes.insert(
                (kind, id.into()),
                ConfluenceNode {
                    id: id.into(),
                    kind,
                    space_id: "98765".into(),
                    parent: edge,
                    status: ConfluenceContentStatus::Current,
                    version: Some(1),
                },
            );
        }
    }
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.view",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    let evidence = request.containment_authorization().unwrap().evidence();
    let ContainmentObligation::Content(location) = &evidence.obligations()[0] else {
        panic!("point")
    };
    assert_eq!(
        location
            .ancestors
            .iter()
            .map(|id| id.content_kind.as_str())
            .collect::<Vec<_>>(),
        ["folder", "page"]
    );
    {
        let mut nodes = backend.nodes.lock().unwrap();
        nodes
            .get_mut(&(ConfluenceNodeKind::Page, "100".into()))
            .unwrap()
            .parent = Some(parent(ConfluenceNodeKind::Whiteboard, "501"));
        nodes.insert(
            (ConfluenceNodeKind::Whiteboard, "501".into()),
            ConfluenceNode {
                id: "501".into(),
                kind: ConfluenceNodeKind::Whiteboard,
                space_id: "98765".into(),
                parent: Some(parent(ConfluenceNodeKind::Folder, "600")),
                status: ConfluenceContentStatus::Current,
                version: Some(1),
            },
        );
    }
    assert_eq!(
        provider
            .recheck_content_location(&request)
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[tokio::test]
async fn draft_container_only_admission_still_checks_its_actual_typed_parent() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.draft.update",
        ContainmentEvidenceLevel::ContainerOnly,
    )
    .await;
    backend
        .nodes
        .lock()
        .unwrap()
        .get_mut(&(ConfluenceNodeKind::Page, "400".into()))
        .unwrap()
        .parent = Some(parent(ConfluenceNodeKind::Folder, "200"));
    assert_eq!(
        provider
            .recheck_content_location(&request)
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn prewrite_version_conflict_does_not_release_new_facts_after_location_changes() {
    let mut raw = EvidenceBackend::new();
    raw.move_during_metadata = true;
    let backend = Arc::new(raw);
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.draft.stage",
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .await;
    let request = InvocationBuilder::from(request)
        .input("baseVersion", json!(2))
        .build();
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.result.is_none());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

fn diagnostic_root() -> TypedResourceSelector {
    ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
        .unwrap()
        .typed_selector(
            CONFLUENCE_CONTENT_RESOURCE.id(),
            &ResourceSelector::Subtree {
                value: "https://example.atlassian.net/wiki/spaces/ENG/pages/900000000001".into(),
            },
        )
        .unwrap()
}

fn insert_diagnostic_root(backend: &EvidenceBackend, ancestor: Option<ConfluenceParent>) {
    backend.nodes.lock().unwrap().insert(
        (ConfluenceNodeKind::Page, "900000000001".into()),
        ConfluenceNode {
            id: "900000000001".into(),
            kind: ConfluenceNodeKind::Page,
            space_id: "98765".into(),
            parent: ancestor,
            status: ConfluenceContentStatus::Current,
            version: Some(1),
        },
    );
}

fn assert_private_move_diagnostic(error: &ProviderError) {
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.message,
        "Confluence content location could not be confirmed"
    );
    assert!(error.result.is_none());
    assert!(error.object_ids.is_none());
    let proof = &error.audit.as_deref().unwrap()["locationProof"];
    assert_eq!(proof["diagnostic"], "confluence_move_relation_unresolved");
    assert_eq!(proof["category"], "not_visible_or_absent");
    assert_eq!(proof["finalCheck"], "unresolved");
    let diagnostic = serde_json::to_string(&error.audit).unwrap();
    for forbidden in [
        "900000000001",
        "900000000002",
        "https://",
        "deleted",
        "title",
        "body",
    ] {
        assert!(!diagnostic.contains(forbidden), "{forbidden}: {diagnostic}");
        assert!(!error.message.contains(forbidden));
    }
}

#[tokio::test]
async fn unresolved_move_roots_and_ancestors_are_only_identified_in_protected_audit() {
    for mode in ["missing_root", "hidden_root", "missing_ancestor"] {
        let backend = Arc::new(EvidenceBackend::new());
        if mode != "missing_root" {
            insert_diagnostic_root(
                &backend,
                (mode == "missing_ancestor")
                    .then(|| parent(ConfluenceNodeKind::Folder, "900000000002")),
            );
        }
        if mode == "hidden_root" {
            backend
                .hidden_nodes
                .lock()
                .unwrap()
                .insert("900000000001".into());
        }
        let provider = backend.provider();
        let request = ScopeRequestFixture::new(
            "confluence",
            "page.move",
            action_inputs(&provider, "page.move"),
        )
        .lookup_credential(token())
        .containment_evidence_level(ContainmentEvidenceLevel::CompleteLineage)
        .containment_roots(vec![diagnostic_root()]);
        let error = provider
            .resolve_scopes(request.request())
            .await
            .unwrap_err();
        assert_private_move_diagnostic(&error);
        assert_eq!(
            error.audit.as_deref().unwrap()["locationProof"]
                .as_object()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    }
    // Missing operation targets carry no policy-root diagnostic.
    let backend = Arc::new(EvidenceBackend::new());
    backend
        .nodes
        .lock()
        .unwrap()
        .remove(&(ConfluenceNodeKind::Page, "100".into()));
    let provider = backend.provider();
    let request = ScopeRequestFixture::new(
        "confluence",
        "page.move",
        action_inputs(&provider, "page.move"),
    )
    .lookup_credential(token())
    .containment_evidence_level(ContainmentEvidenceLevel::CompleteLineage)
    .containment_roots(vec![diagnostic_root()]);
    let error = provider
        .resolve_scopes(request.request())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.audit.is_none());
}

#[tokio::test]
async fn a_move_root_lost_after_admission_preserves_diagnostic_and_blocks_the_move() {
    for hidden in [false, true] {
        let backend = Arc::new(EvidenceBackend::new());
        insert_diagnostic_root(&backend, None);
        let provider = backend.provider();
        let request = admitted_with_roots(
            &provider,
            "page.move",
            ContainmentEvidenceLevel::CompleteLineage,
            vec![diagnostic_root()],
        )
        .await;
        if hidden {
            backend
                .hidden_nodes
                .lock()
                .unwrap()
                .insert("900000000001".into());
        } else {
            backend
                .nodes
                .lock()
                .unwrap()
                .remove(&(ConfluenceNodeKind::Page, "900000000001".into()));
        }
        let error = provider.invoke(request).await.unwrap_err();
        assert_private_move_diagnostic(&error);
        assert_eq!(
            error.audit.as_deref().unwrap()["locationProof"]["space"],
            "ENG"
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn lookup_readable_intermediate_never_substitutes_for_execution_visibility() {
    let execution = basic_credential("reader@example.test", "different-execution-token");
    for action in ["page.view", "page.update"] {
        let backend = Arc::new(EvidenceBackend::new());
        backend.hidden_nodes.lock().unwrap().insert("200".into());
        *backend.hidden_for_credential.lock().unwrap() = Some(execution.clone());
        let provider = backend.provider();
        // Lookup can see the complete initial path with its own material.
        let request = admitted(&provider, action, ContainmentEvidenceLevel::CompleteLineage).await;
        assert!(
            backend
                .hierarchy_credentials
                .lock()
                .unwrap()
                .iter()
                .all(|material| material == &token())
        );
        backend.hierarchy_credentials.lock().unwrap().clear();
        let request = InvocationBuilder::from(request)
            .credential(execution.clone())
            .build();
        let error = provider.invoke(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        assert!(error.result.is_none());
        assert_eq!(
            error.audit.as_deref().unwrap()["locationProof"]["finalCheck"],
            "unresolved"
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
        let observed = backend.hierarchy_credentials.lock().unwrap();
        assert!(observed.len() >= 2);
        assert!(observed.iter().all(|material| material == &execution));
    }
}

async fn draft_origin_request(
    provider: &ConfluenceProvider,
    action: &str,
    origin: ConfluenceDraftOrigin,
) -> ProviderInvocation {
    let kind = if action.starts_with("page.") {
        ConfluenceDraftContentType::Page
    } else {
        ConfluenceDraftContentType::Blog
    };
    let handle = ConfluenceDraftHandle {
        content_type: kind,
        content_id: if kind == ConfluenceDraftContentType::Page {
            "400".into()
        } else {
            "800".into()
        },
        space: "ENG".into(),
        space_id: "98765".into(),
        origin,
        parent: (kind == ConfluenceDraftContentType::Page)
            .then(|| parent(ConfluenceNodeKind::Page, "200")),
        base_version: (origin == ConfluenceDraftOrigin::Staged).then_some(7),
    };
    let binding = InvocationBuilder::new("confluence", action)
        .credential(token())
        .build();
    let signed = provider
        .continuations
        .seal_draft_handle(binding.context(), binding.execution(), &handle)
        .unwrap();
    let mut inputs = action_inputs(provider, action);
    inputs["draftHandle"] = json!(signed);
    admitted_inputs(
        provider,
        action,
        ContainmentEvidenceLevel::CompleteLineage,
        Vec::new(),
        inputs,
    )
    .await
}

#[tokio::test]
async fn new_and_staged_drafts_publish_with_distinct_versions_and_same_identity_placement() {
    for action in ["page.draft.publish", "blog.draft.publish"] {
        for origin in [ConfluenceDraftOrigin::New, ConfluenceDraftOrigin::Staged] {
            let backend = Arc::new(EvidenceBackend::new());
            let provider = backend.provider();
            let request = draft_origin_request(&provider, action, origin).await;
            let result = provider.invoke(request).await.unwrap();
            let expected = if origin == ConfluenceDraftOrigin::New {
                1
            } else {
                8
            };
            let id_field = if action.starts_with("page.") {
                "pageId"
            } else {
                "blogId"
            };
            let expected_id = if action.starts_with("page.") {
                "400"
            } else {
                "800"
            };
            assert_eq!(result.result[id_field], expected_id);
            assert_eq!(result.result["version"], expected);
            if action.starts_with("page.") {
                assert_eq!(result.result["parent"], json!({"kind":"page","id":"200"}));
            }
            let requests = backend.publish_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].version_number, expected);
            assert_eq!(requests[0].content_id, expected_id);
            assert_eq!(requests[0].space_id, "98765");
            assert_eq!(requests[0].status, "current");
            assert_eq!(
                backend.published_current_reads.load(Ordering::SeqCst),
                usize::from(origin == ConfluenceDraftOrigin::Staged)
            );
        }
    }
}

#[tokio::test]
async fn staged_publish_rechecks_current_version_and_placement_before_any_write() {
    for action in ["page.draft.publish", "blog.draft.publish"] {
        let backend = Arc::new(EvidenceBackend::new());
        let provider = backend.provider();
        let request = draft_origin_request(&provider, action, ConfluenceDraftOrigin::Staged).await;
        backend.published_current_version.store(8, Ordering::SeqCst);
        let error = provider.invoke(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
        assert_eq!(error.result.as_deref().unwrap()["expectedBaseVersion"], 7);
        assert_eq!(error.result.as_deref().unwrap()["currentVersion"], 8);
        assert!(
            error
                .result
                .as_deref()
                .unwrap()
                .get("mutationStatus")
                .is_none()
        );
        assert_eq!(
            error.audit.as_deref().unwrap()["locationProof"]["finalCheck"],
            "matched"
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    }
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let request = draft_origin_request(
        &provider,
        "page.draft.publish",
        ConfluenceDraftOrigin::Staged,
    )
    .await;
    *backend.published_current_parent.lock().unwrap() =
        Some(parent(ConfluenceNodeKind::Page, "300"));
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.result.is_none());
    assert_eq!(
        error.audit.as_deref().unwrap()["locationProof"]["finalCheck"],
        "unresolved"
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepted_publish_mismatches_keep_applied_unverified_receipts_without_replay() {
    for action in ["page.draft.publish", "blog.draft.publish"] {
        let kind = if action.starts_with("page.") {
            ConfluenceDraftContentType::Page
        } else {
            ConfluenceDraftContentType::Blog
        };
        let id = if kind == ConfluenceDraftContentType::Page {
            "400"
        } else {
            "800"
        };
        for origin in [ConfluenceDraftOrigin::New, ConfluenceDraftOrigin::Staged] {
            for mismatch in ["version", "id", "space", "parent"] {
                let backend = Arc::new(EvidenceBackend::new());
                let provider = backend.provider();
                let request = draft_origin_request(&provider, action, origin).await;
                let mut response = backend.draft(id, kind);
                response.status = Some("current".into());
                response.version = if origin == ConfluenceDraftOrigin::New {
                    1
                } else {
                    8
                };
                match mismatch {
                    "version" => response.version += 1,
                    "id" => response.id = "900".into(),
                    "space" => response.space_id = "99999".into(),
                    "parent" => response.parent = Some(parent(ConfluenceNodeKind::Page, "300")),
                    _ => unreachable!(),
                }
                *backend.publish_response.lock().unwrap() = Some(response);
                let error = provider.invoke(request).await.unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::UpstreamProtocolFailed,
                    "{action} {origin:?} {mismatch}"
                );
                let receipt = error.result.as_deref().unwrap();
                assert_eq!(receipt["mutationStatus"], "applied_unverified");
                assert_eq!(receipt["retrySafe"], false);
                assert_eq!(receipt["verificationStage"], "mutation_response");
                assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
                assert_eq!(backend.publish_requests.lock().unwrap().len(), 1);
            }
        }
    }
}

#[tokio::test]
async fn staged_discard_and_attachment_modes_remain_explicitly_unsupported() {
    for prefix in ["page", "blog"] {
        for suffix in [
            "discard",
            "attachment.add",
            "attachment.download",
            "attachment.list",
        ] {
            let action = format!("{prefix}.draft.{suffix}");
            let backend = Arc::new(EvidenceBackend::new());
            let provider = backend.provider();
            let request =
                draft_origin_request(&provider, &action, ConfluenceDraftOrigin::Staged).await;
            let error = provider.invoke(request).await.unwrap_err();
            assert_eq!(
                error.reason_code(),
                ReasonCode::ServiceActionDenied,
                "{action}"
            );
            assert!(error.result.is_none());
            assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn all_attachment_downloads_recheck_location_before_opening_content() {
    for action in [
        "attachment.download",
        "blog.attachment.download",
        "page.draft.attachment.download",
        "blog.draft.attachment.download",
    ] {
        let mut raw = EvidenceBackend::new();
        raw.download_fixture = true;
        raw.move_during_membership = true;
        let backend = Arc::new(raw);
        let provider = backend.provider();
        let request = admitted(&provider, action, ContainmentEvidenceLevel::CompleteLineage).await;
        let error = provider.invoke(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved, "{action}");
        assert!(error.result.is_none(), "{action}");
        assert_eq!(backend.content_opens.load(Ordering::SeqCst), 0, "{action}");
        assert_eq!(backend.emitted_bytes.load(Ordering::SeqCst), 0, "{action}");
    }
}

#[tokio::test]
async fn page_update_upstream_conflict_is_distinct_from_measured_version_mismatch() {
    let mut raw = EvidenceBackend::new();
    raw.update_conflict = true;
    let backend = Arc::new(raw);
    let provider = backend.provider();
    let request = admitted(
        &provider,
        "page.update",
        ContainmentEvidenceLevel::ContainerOnly,
    )
    .await;
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code().as_str(), "confluence_update_conflict");
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(error.message, "Confluence rejected the page update");
    assert_eq!(
        error.result.as_deref().unwrap(),
        &json!({"pageId":"100","space":"ENG","expectedBaseVersion":1})
    );
    assert_eq!(error.upstream_status, Some(409));
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    let reason = CONFLUENCE_BACKEND
        .domain_reasons()
        .iter()
        .find(|reason| reason.code() == "confluence_update_conflict")
        .unwrap();
    assert_eq!(reason.status().as_u16(), 409);
    assert_eq!(reason.decision(), Decision::Error);

    let mut inputs = action_inputs(&provider, "page.update");
    inputs["baseVersion"] = json!(2);
    let request = admitted_inputs(
        &provider,
        "page.update",
        ContainmentEvidenceLevel::ContainerOnly,
        Vec::new(),
        inputs,
    )
    .await;
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    assert_eq!(error.result.as_deref().unwrap()["currentVersion"], 1);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn page_update_version_range_is_rejected_before_lookup_and_declared_in_schema() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let schema = confluence_descriptor(&config())
        .action("page.update")
        .unwrap()
        .input_schema
        .clone();
    assert_eq!(schema["properties"]["baseVersion"]["minimum"], 1);
    assert_eq!(
        schema["properties"]["baseVersion"]["maximum"],
        2147483646u64
    );
    for version in [1, 2147483646] {
        let mut inputs = action_inputs(&provider, "page.update");
        inputs["baseVersion"] = json!(version);
        assert!(parse_page_update_inputs(&inputs).is_ok());
    }
    for version in [0, 2147483647, u64::MAX] {
        let mut inputs = action_inputs(&provider, "page.update");
        inputs["baseVersion"] = json!(version);
        let fixture = ScopeRequestFixture::new("confluence", "page.update", inputs)
            .lookup_credential(token());
        let error = provider
            .resolve_scopes(fixture.request())
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(
            error.message,
            "confluence.page.update baseVersion must be between 1 and 2147483646"
        );
    }
    assert!(backend.hierarchy_credentials.lock().unwrap().is_empty());
    assert_eq!(backend.metadata_reads.load(Ordering::SeqCst), 0);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn draft_stage_proceeds_only_after_a_raw_missing_draft() {
    for action in ["page.draft.stage", "blog.draft.stage"] {
        for mode in [
            "present",
            "missing",
            "malformed",
            "budget",
            "wrong_lifecycle",
            "space_missing",
        ] {
            if mode == "malformed" && action.starts_with("blog") {
                continue;
            }
            let backend = Arc::new(EvidenceBackend::new());
            let provider = backend.provider();
            let request =
                admitted(&provider, action, ContainmentEvidenceLevel::ContainerOnly).await;
            match mode {
                "missing" => {
                    *backend.draft_read_failure.lock().unwrap() =
                        Some(ConfluenceBackendError::NotFound)
                }
                "malformed" => {
                    let kind = if action.starts_with("page") {
                        ConfluenceDraftContentType::Page
                    } else {
                        ConfluenceDraftContentType::Blog
                    };
                    // This is the strict parser's actual missing-parent failure.
                    let error = draft_content_from_value(json!({"id":"100","type":kind.as_str(),"title":"Competing","status":"draft","spaceId":"98765","version":{"number":1}}), kind).unwrap_err();
                    assert_eq!(error, ConfluenceBackendError::ScopeUnresolved);
                    *backend.draft_read_failure.lock().unwrap() = Some(error);
                }
                "wrong_lifecycle" | "space_missing" => {
                    let kind = if action.starts_with("page") {
                        ConfluenceDraftContentType::Page
                    } else {
                        ConfluenceDraftContentType::Blog
                    };
                    let mut draft = backend.draft(
                        if kind == ConfluenceDraftContentType::Page {
                            "100"
                        } else {
                            "700"
                        },
                        kind,
                    );
                    if mode == "wrong_lifecycle" {
                        draft.status = Some("current".into());
                    } else {
                        draft.space_id = "99999".into();
                    }
                    *backend.draft_read_override.lock().unwrap() = Some(draft);
                }
                "budget" => {
                    let state =
                        ProviderState::require::<ContentOperationState>(request.state()).unwrap();
                    *backend.draft_read_budget.lock().unwrap() = Some(state.budget.clone());
                }
                _ => {}
            }
            let result = provider.invoke(request).await;
            if mode == "missing" {
                assert!(result.is_ok(), "{action} {mode}: {result:?}");
                assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    if mode == "present" {
                        ReasonCode::VersionConflict
                    } else {
                        ReasonCode::ScopeUnresolved
                    },
                    "{action} {mode}"
                );
                assert_eq!(backend.writes.load(Ordering::SeqCst), 0, "{action} {mode}");
            }
        }
    }
}
