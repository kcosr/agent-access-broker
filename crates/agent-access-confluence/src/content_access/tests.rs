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
    space: Mutex<ConfluenceSpace>,
    page_reads: AtomicUsize,
    metadata_reads: AtomicUsize,
    move_during_metadata: bool,
    writes: AtomicUsize,
    emitted_bytes: Arc<AtomicUsize>,
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
            space: Mutex::new(space()),
            page_reads: AtomicUsize::new(0),
            metadata_reads: AtomicUsize::new(0),
            move_during_metadata: false,
            writes: AtomicUsize::new(0),
            emitted_bytes: Arc::new(AtomicUsize::new(0)),
            move_during_body: false,
            move_during_download: false,
            move_after_upload: false,
            comment_chain: AtomicUsize::new(0),
        }
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
        _credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceNode>, ConfluenceBackendError> {
        budget.charge_request()?;
        budget.charge_bytes(100)?;
        let mut node = self
            .nodes
            .lock()
            .unwrap()
            .get(&(kind, id.into()))
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        if id == "400" {
            node.status = ConfluenceContentStatus::Draft;
        }
        if node.status != status {
            return Err(ConfluenceBackendError::ScopeUnresolved);
        }
        ok(node)
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
        ok(self.draft(id, ConfluenceDraftContentType::Page))
    }
    async fn draft_blog(
        &self,
        id: &str,
        _body_format: Option<&str>,
        _credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        ok(self.draft(id, ConfluenceDraftContentType::Blog))
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
    let inputs = action_inputs(provider, action);
    let mut fixture = ScopeRequestFixture::new("confluence", action, inputs.clone())
        .lookup_credential(token())
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
