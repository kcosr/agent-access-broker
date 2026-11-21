//! Search admission, confidential resume and release checks under scripted upstream changes.
use super::*;
use agent_access_provider::test_support::{
    InvocationBuilder, basic_credential, bearer_credential, test_signing_key,
};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

const SITE: &str = "https://example.atlassian.net";
const CLOUD: &str = "00000000-0000-0000-0000-000000000000";

fn config() -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".into(),
        cloud_id: Some(CLOUD.into()),
        egress_proxy: None,
        allowed_upstream_hosts: vec![],
        attachments: Default::default(),
        content: Default::default(),
        search: SearchLimitsConfig { max_results: 3 },
        listing: Default::default(),
        content_access: Default::default(),
        content_search: Default::default(),
    }
}
fn provider(backend: Arc<Backend>, config: ConfluenceProviderConfig) -> ConfluenceProvider {
    ConfluenceProvider::with_backend_and_signing_key(
        config,
        ProviderLimits::default(),
        backend,
        test_signing_key(9),
    )
}
fn registry() -> ResourceTypeRegistry {
    ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE]).unwrap()
}
fn space(key: &str) -> TypedResourceSelector {
    registry()
        .typed_selector(
            CONFLUENCE_SPACE_RESOURCE.id(),
            &ResourceSelector::Exact { value: key.into() },
        )
        .unwrap()
}
fn content(kind: ConfluenceSearchContentKind, id: &str, subtree: bool) -> TypedResourceSelector {
    let segment = if kind == ConfluenceSearchContentKind::Page {
        "pages"
    } else {
        "blog"
    };
    let value = format!("{SITE}/wiki/spaces/ENG/{segment}/{id}");
    let selector = if subtree {
        ResourceSelector::Subtree { value }
    } else {
        ResourceSelector::Exact { value }
    };
    registry()
        .typed_selector(CONFLUENCE_CONTENT_RESOURCE.id(), &selector)
        .unwrap()
}
fn authority(
    kind: ConfluenceSearchContentKind,
    included: Vec<TypedResourceSelector>,
    excluded: Vec<TypedResourceSelector>,
    level: ContainmentEvidenceLevel,
    digest: char,
) -> ContainmentCollectionAuthorization {
    let scope = if kind == ConfluenceSearchContentKind::Page {
        "page_location"
    } else {
        "blog_location"
    };
    agent_access_provider::host::containment_collection_authorization(
        SITE,
        confluence_resource_scopes()[scope]
            .as_containment()
            .unwrap()
            .clone(),
        vec![ContainmentBoundary::new(included, excluded)],
        None,
        &registry(),
        level,
        digest.to_string().repeat(64),
    )
    .unwrap()
}
fn space_authority(kind: ConfluenceSearchContentKind) -> ContainmentCollectionAuthorization {
    authority(
        kind,
        vec![space("ENG")],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'a',
    )
}
fn tree_authority() -> ContainmentCollectionAuthorization {
    authority(
        ConfluenceSearchContentKind::Page,
        vec![content(ConfluenceSearchContentKind::Page, "100", true)],
        vec![],
        ContainmentEvidenceLevel::CompleteLineage,
        'a',
    )
}
fn inputs() -> Value {
    json!({"query":{"type":"cql","value":"title ~ \"runbook\""},"maxResults":3})
}
fn invocation(
    kind: ConfluenceSearchContentKind,
    authority: ContainmentCollectionAuthorization,
    inputs: Value,
) -> ProviderInvocation {
    InvocationBuilder::new(
        "confluence",
        if kind == ConfluenceSearchContentKind::Page {
            "search"
        } else {
            "blog.search"
        },
    )
    .principal("reader")
    .credential(basic_credential("reader@example.com", "test-token"))
    .containment_collection(authority)
    .inputs(inputs)
    .build()
}
fn page(id: &str, space: &str) -> ConfluencePage {
    ConfluencePage {
        id: id.into(),
        title: format!("Record {id}"),
        space: space.into(),
        web_url: None,
        space_web_url: None,
        space_alias: None,
        status: Some("current".into()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    }
}
fn response<T>(value: T) -> ConfluenceBackendResponse<T> {
    ConfluenceBackendResponse {
        value,
        status: 200,
        duration_ms: 1,
    }
}
fn results(rows: Vec<ConfluencePage>, next: Option<&str>) -> ConfluenceSearchPage {
    ConfluenceSearchPage {
        pages: rows,
        max_results: 3,
        next_page_token: next.map(str::to_owned),
    }
}
fn node(id: &str, space_id: &str, parent: Option<&str>) -> ConfluenceNode {
    ConfluenceNode {
        id: id.into(),
        kind: ConfluenceNodeKind::Page,
        space_id: space_id.into(),
        parent: parent.map(|id| ConfluenceParent {
            id: id.into(),
            kind: ConfluenceNodeKind::Page,
        }),
        status: ConfluenceContentStatus::Current,
        version: Some(1),
    }
}
#[derive(Default)]
struct Backend {
    pages: Mutex<VecDeque<ConfluenceSearchPage>>,
    requests: Mutex<Vec<ConfluenceSearchRequest>>,
    nodes: Mutex<BTreeMap<String, VecDeque<ConfluenceNode>>>,
    reads: Mutex<Vec<String>>,
}
impl Backend {
    fn new(pages: Vec<ConfluenceSearchPage>) -> Arc<Self> {
        Arc::new(Self {
            pages: Mutex::new(pages.into()),
            ..Self::default()
        })
    }
    fn set_nodes(&self, id: &str, nodes: Vec<ConfluenceNode>) {
        self.nodes.lock().unwrap().insert(id.into(), nodes.into());
    }
    fn rooted(&self, id: &str) {
        self.set_nodes(id, vec![node(id, "1", Some("100"))]);
        self.set_nodes("100", vec![node("100", "1", None)]);
    }
    fn fetch(&self, request: ConfluenceSearchRequest) -> ConfluenceSearchPage {
        self.requests.lock().unwrap().push(request);
        self.pages
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected candidate request")
    }
    fn metadata(
        &self,
        label: String,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<(), ConfluenceBackendError> {
        budget.charge_request()?;
        budget.charge_bytes(64)?;
        self.reads.lock().unwrap().push(label);
        Ok(())
    }
}
#[async_trait]
impl ConfluenceBackend for Backend {
    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Ok(response(self.fetch(request)))
    }
    async fn search_blogs(
        &self,
        request: ConfluenceSearchRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        let page = self.fetch(request);
        Ok(response(ConfluenceSearchBlog {
            blogs: page
                .pages
                .into_iter()
                .map(|page| ConfluenceBlogSummary {
                    id: page.id,
                    title: page.title,
                    space: page.space,
                    web_url: None,
                    space_web_url: None,
                    status: page.status,
                    version: page.version,
                    created_at: None,
                    updated_at: None,
                    created_by: None,
                    updated_by: None,
                })
                .collect(),
            max_results: page.max_results,
            next_page_token: page.next_page_token,
        }))
    }
    async fn hierarchy_node(
        &self,
        kind: ConfluenceNodeKind,
        id: &str,
        status: ConfluenceContentStatus,
        require_parent: bool,
        _: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceNode>, ConfluenceBackendError> {
        assert_eq!(kind, ConfluenceNodeKind::Page);
        assert_eq!(status, ConfluenceContentStatus::Current);
        assert!(require_parent);
        self.metadata(format!("node:{id}"), budget)?;
        let mut nodes = self.nodes.lock().unwrap();
        let sequence = nodes.get_mut(id).expect("unexpected location request");
        let value = if sequence.len() > 1 {
            sequence.pop_front().unwrap()
        } else {
            sequence.front().unwrap().clone()
        };
        Ok(response(value))
    }
    async fn space_location_metadata(
        &self,
        id: &str,
        _: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        self.metadata(format!("space:{id}"), budget)?;
        Ok(response(ConfluenceSpace {
            id: id.into(),
            key: if id == "1" {
                "ENG".into()
            } else {
                "OPS".into()
            },
            web_url: None,
            alias: None,
            status: Some("current".into()),
            homepage_id: None,
        }))
    }
    async fn space_list(
        &self,
        _: ConfluenceSpaceListRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpaceListPage>, ConfluenceBackendError> {
        panic!("unexpected space list")
    }
    async fn page_metadata(
        &self,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("unexpected metadata fallback")
    }
    async fn page(
        &self,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("unexpected page body")
    }
    async fn create_page(
        &self,
        _: ConfluencePageCreateRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("unexpected write")
    }
    async fn update_page(
        &self,
        _: ConfluencePageUpdateRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("unexpected write")
    }
    async fn add_attachment(
        &self,
        _: &str,
        _: ConfluenceAttachmentUpload,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        panic!("unexpected write")
    }
    async fn page_attachments(
        &self,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        panic!("unexpected attachment read")
    }
    async fn attachment_content(
        &self,
        _: &str,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        panic!("unexpected attachment read")
    }
}
fn field(kind: ConfluenceSearchContentKind) -> &'static str {
    if kind == ConfluenceSearchContentKind::Page {
        "pages"
    } else {
        "blogs"
    }
}
fn resume(mut inputs: Value, result: &ProviderResult) -> Value {
    inputs["nextPageToken"] = result.result["nextPageToken"].clone();
    inputs
}
fn assert_invalid(error: ProviderError) {
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{error:?}");
}

#[tokio::test]
async fn space_and_exact_content_fast_paths_use_one_query_and_no_metadata() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        for exact in [false, true] {
            let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
            let provider = provider(backend.clone(), config());
            let authority = if exact {
                authority(
                    kind,
                    vec![content(kind, "101", false)],
                    vec![],
                    ContainmentEvidenceLevel::ContainerOnly,
                    'a',
                )
            } else {
                space_authority(kind)
            };
            let result = provider
                .invoke_content_search(invocation(kind, authority, inputs()), kind)
                .await
                .unwrap();
            assert_eq!(result.result[field(kind)].as_array().unwrap().len(), 1);
            assert_eq!(result.result["scanStatus"], "exhausted");
            assert_eq!(
                result
                    .audit
                    .as_ref()
                    .unwrap()
                    .pointer("/locationProof/finalCheck")
                    .unwrap(),
                "matched"
            );
            assert_eq!(backend.requests.lock().unwrap().len(), 1);
            assert!(backend.reads.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn denied_rows_are_filtered_and_malformed_rows_fail_even_outside_scope() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        let backend = Backend::new(vec![results(
            vec![page("101", "OPS"), page("102", "ENG")],
            None,
        )]);
        let provider = provider(backend, config());
        let result = provider
            .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
            .await
            .unwrap();
        let rows = result.result[field(kind)].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][if kind == ConfluenceSearchContentKind::Page {
                "id"
            } else {
                "blogId"
            }],
            "102"
        );
        for variant in 0..4 {
            let mut malformed = page("101", "OPS");
            match variant {
                0 => malformed.id = "001".into(),
                1 => malformed.space = "bad/key".into(),
                2 => malformed.status = None,
                _ => malformed.version = 0,
            }
            let backend = Backend::new(vec![results(vec![malformed], None)]);
            let provider = self::provider(backend, config());
            let error = provider
                .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        }
    }
}

#[tokio::test]
async fn cursor_is_confidential_and_bound_to_authority_even_when_cql_is_identical() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![
        results(vec![page("101", "ENG")], Some("sensitive-upstream-cursor")),
        results(vec![page("102", "ENG")], None),
    ]);
    let provider = provider(backend.clone(), config());
    let first = provider
        .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert!(!token.contains("sensitive"));
    let decoded = decode_base64url(token);
    assert!(!decoded.windows(9).any(|bytes| bytes == b"sensitive"));
    let resumed = resume(inputs(), &first);
    let changed = authority(
        kind,
        vec![space("ENG")],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'b',
    );
    let query_a = build_containment_search_query(
        &parse_search_inputs(&inputs()).unwrap().query,
        &space_authority(kind),
        &BTreeSet::new(),
        &config().search,
        kind,
        SITE,
    )
    .unwrap();
    let query_b = build_containment_search_query(
        &parse_search_inputs(&inputs()).unwrap().query,
        &changed,
        &BTreeSet::new(),
        &config().search,
        kind,
        SITE,
    )
    .unwrap();
    assert_eq!(query_a.cql, query_b.cql);
    assert_invalid(
        provider
            .invoke_content_search(invocation(kind, changed, resumed.clone()), kind)
            .await
            .unwrap_err(),
    );
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
    let next = provider
        .invoke_content_search(invocation(kind, space_authority(kind), resumed), kind)
        .await
        .unwrap();
    assert_eq!(next.result["pages"][0]["id"], "102");
    assert_eq!(
        backend.requests.lock().unwrap()[1]
            .next_page_token
            .as_deref(),
        Some("sensitive-upstream-cursor")
    );
}

#[tokio::test]
async fn continuation_rejects_caller_context_mode_method_query_and_provider_changes_before_fetch() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![results(vec![page("101", "ENG")], Some("next"))]);
    let mut provider = provider(backend.clone(), config());
    let first = provider
        .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
        .await
        .unwrap();
    let resumed = resume(inputs(), &first);
    let request = invocation(kind, space_authority(kind), resumed.clone());
    let changed = vec![
        InvocationBuilder::from(request.clone())
            .principal("other")
            .build(),
        InvocationBuilder::from(request.clone())
            .execution_context("external")
            .build(),
        InvocationBuilder::from(request.clone())
            .credential_mode(CredentialMode::PerUser)
            .build(),
        InvocationBuilder::from(request.clone())
            .execution(ExecutionAccess::Static(bearer_credential("test")))
            .build(),
        InvocationBuilder::from(request.clone())
            .action("blog.search")
            .build(),
        InvocationBuilder::from(request.clone())
            .input("maxResults", json!(2))
            .build(),
        InvocationBuilder::from(request.clone())
            .input("query", json!({"type":"cql","value":"title ~ \"other\""}))
            .build(),
        InvocationBuilder::from(request.clone())
            .input("spaces", json!(["ENG"]))
            .build(),
    ];
    for request in changed {
        assert_invalid(
            provider
                .invoke_content_search(request, kind)
                .await
                .unwrap_err(),
        );
    }
    let restarted = self::provider(backend.clone(), config());
    assert_invalid(
        restarted
            .invoke_content_search(request.clone(), kind)
            .await
            .unwrap_err(),
    );
    // Keep the same signer to isolate the configuration commitment from
    // the independent generation fence exercised by the restart above.
    provider.config.content_search.max_candidates += 1;
    assert_invalid(
        provider
            .invoke_content_search(request, kind)
            .await
            .unwrap_err(),
    );
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mid_page_resume_refetches_original_page_and_commits_to_its_identity_order() {
    let kind = ConfluenceSearchContentKind::Page;
    for changed in [false, true] {
        let rows = vec![page("101", "ENG"), page("102", "ENG")];
        let mut second = rows.clone();
        if changed {
            second.swap(0, 1);
        }
        let backend = Backend::new(vec![results(rows, None), results(second, None)]);
        backend.rooted("101");
        backend.rooted("102");
        let mut config = config();
        config.content_access.max_metadata_requests = 132;
        let provider = provider(backend.clone(), config);
        let first = provider
            .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
            .await
            .unwrap();
        assert_eq!(first.result["pages"].as_array().unwrap().len(), 1);
        assert_eq!(first.result["scanStatus"], "scan_budget");
        let next = provider
            .invoke_content_search(
                invocation(kind, tree_authority(), resume(inputs(), &first)),
                kind,
            )
            .await;
        if changed {
            assert_invalid(next.unwrap_err());
        } else {
            let next = next.unwrap();
            assert_eq!(next.result["pages"][0]["id"], "102");
            assert_eq!(next.result["scanStatus"], "exhausted");
        }
        let requests = backend.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.next_page_token.is_none())
        );
        assert_eq!(requests[0].max_results, requests[1].max_results);
    }
}

#[tokio::test]
async fn repeated_upstream_cursor_is_rejected_across_invocations() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![
        results(vec![page("101", "ENG")], Some("same")),
        results(vec![page("102", "ENG")], Some("same")),
    ]);
    let provider = provider(backend, config());
    let first = provider
        .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
        .await
        .unwrap();
    let error = provider
        .invoke_content_search(
            invocation(kind, space_authority(kind), resume(inputs(), &first)),
            kind,
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn complete_lineage_filters_current_and_final_moves_before_release() {
    let kind = ConfluenceSearchContentKind::Page;
    for final_move in [false, true] {
        let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
        backend.rooted("101");
        if final_move {
            backend.set_nodes(
                "101",
                vec![node("101", "1", Some("100")), node("101", "1", None)],
            );
        } else {
            backend.set_nodes("101", vec![node("101", "2", None)]);
        }
        let provider = provider(backend.clone(), config());
        let result = provider
            .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
            .await
            .unwrap();
        assert!(result.result["pages"].as_array().unwrap().is_empty());
        assert_eq!(result.result["scanStatus"], "exhausted");
        assert_eq!(
            result
                .audit
                .as_ref()
                .unwrap()
                .pointer("/locationProof/finalCheck")
                .unwrap(),
            if final_move { "changed" } else { "not_run" }
        );
        assert_eq!(backend.requests.lock().unwrap().len(), 1);
        assert_eq!(
            backend
                .reads
                .lock()
                .unwrap()
                .iter()
                .filter(|read| read.as_str() == "node:101")
                .count(),
            if final_move { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn complete_lineage_requires_budget_for_initial_and_final_checks_before_fetch() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![]);
    let mut config = config();
    config.content_access.max_metadata_requests = 129;
    let provider = provider(backend.clone(), config);
    let error = provider
        .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.requests.lock().unwrap().is_empty());
}

#[test]
fn confidential_resume_expires_at_original_deadline_and_rejects_restart() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![]);
    let provider = provider(backend.clone(), config());
    let authority = space_authority(kind);
    let request = invocation(kind, authority.clone(), inputs());
    let query = build_containment_search_query(
        &parse_search_inputs(&inputs()).unwrap().query,
        &authority,
        &BTreeSet::new(),
        &config().search,
        kind,
        SITE,
    )
    .unwrap();
    let binding = binding(&provider, &request, &authority, &query, &BTreeSet::new(), 3).unwrap();
    let issued = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let expiry = provider
        .listing_signer
        .deadline_at(&binding, issued)
        .unwrap();
    let payload = serde_json::to_vec(&Position::first(3)).unwrap();
    let token = provider
        .listing_signer
        .seal_until_at(&binding, &payload, expiry, issued)
        .unwrap();
    let opened = provider
        .listing_signer
        .open_confidential_at(&binding, &token, issued + Duration::from_secs(899))
        .unwrap();
    let renewed = provider
        .listing_signer
        .seal_resumed_at(
            &binding,
            &payload,
            &opened,
            issued + Duration::from_secs(899),
        )
        .unwrap();
    assert_eq!(
        provider
            .listing_signer
            .open_confidential_at(&binding, &renewed, issued + Duration::from_secs(900))
            .unwrap_err(),
        ContinuationError::Expired
    );
    let restarted = self::provider(backend, config());
    assert_eq!(
        restarted
            .listing_signer
            .open_confidential_at(&binding, &token, issued)
            .unwrap_err(),
        ContinuationError::Invalid
    );
}

#[test]
fn malformed_resume_positions_fail_closed() {
    let valid = serde_json::to_value(Position::first(3)).unwrap();
    for (field, value) in [
        ("offset", json!(3)),
        ("page_limit", json!(0)),
        ("page_limit", json!(4)),
        ("cursor", json!("")),
        ("page_commitment", json!("a".repeat(64))),
        ("history", json!(["a".repeat(64)])),
        ("unrecognized", json!(true)),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(Position::open(&serde_json::to_vec(&changed).unwrap(), 3).is_err());
    }
    assert!(Position::open(&serde_json::to_vec(&valid).unwrap(), 3).is_ok());
}

#[test]
fn search_token_failures_preserve_the_provider_hook_contract() {
    for action in ["search", "blog.search"] {
        let hook = agent_access_provider::host::hook_context(
            "confluence",
            action,
            HookPhase::Invocation,
            CONFLUENCE_BACKEND.domain_reasons(),
        );
        for error in [
            ContinuationError::Invalid,
            ContinuationError::UnsupportedVersion,
            ContinuationError::Expired,
            ContinuationError::UpstreamQueryChanged,
            ContinuationError::TokenTooLarge { limit: 1 },
            ContinuationError::PayloadTooLarge { limit: 1 },
            ContinuationError::SigningUnavailable,
            ContinuationError::DurableKeyUnavailable,
        ] {
            assert_eq!(hook.check_failure(&token_error(error)), Ok(()));
        }
    }
}

struct Lease {
    binding: &'static str,
    version: &'static str,
}
#[async_trait]
impl DelegatedLease for Lease {
    fn access(&self) -> DelegatedAccess {
        DelegatedAccess::new(
            format!("test-{}", self.version),
            CLOUD,
            "api.atlassian.com",
            self.version,
            i64::MAX,
        )
    }
    fn binding_identity(&self) -> DelegatedBindingId {
        agent_access_provider::test_support::delegated_binding_id(self.binding)
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Ok(())
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "fixture does not recover",
        ))
    }
}
fn delegated(binding: &'static str, version: &'static str) -> ExecutionAccess {
    ExecutionAccess::Delegated(agent_access_provider::host::delegated_credential(Arc::new(
        Lease { binding, version },
    )))
}

#[tokio::test]
async fn oauth_refresh_preserves_resume_but_reconnection_and_principal_changes_reject_it() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![
        results(vec![page("101", "ENG")], Some("oauth-cursor")),
        results(vec![page("102", "ENG")], None),
    ]);
    let provider = provider(backend.clone(), config());
    let request = InvocationBuilder::from(invocation(kind, space_authority(kind), inputs()))
        .credential_mode(CredentialMode::PerUser)
        .execution(delegated("connection-one", "access-v1"))
        .build();
    let first = provider
        .invoke_content_search(request.clone(), kind)
        .await
        .unwrap();
    let resumed = InvocationBuilder::from(request)
        .inputs(resume(inputs(), &first))
        .build();
    for changed in [
        InvocationBuilder::from(resumed.clone())
            .execution(delegated("connection-two", "access-v1"))
            .build(),
        InvocationBuilder::from(resumed.clone())
            .principal("other")
            .build(),
        InvocationBuilder::from(resumed.clone())
            .execution(ExecutionAccess::Static(bearer_credential("test")))
            .build(),
    ] {
        assert_invalid(
            provider
                .invoke_content_search(changed, kind)
                .await
                .unwrap_err(),
        );
    }
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
    let refreshed = InvocationBuilder::from(resumed)
        .execution(delegated("connection-one", "access-v2"))
        .build();
    let result = provider
        .invoke_content_search(refreshed, kind)
        .await
        .unwrap();
    assert_eq!(result.result["pages"][0]["id"], "102");
}

#[tokio::test]
async fn text_query_resume_binds_each_operand_and_its_polarity() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        let backend = Backend::new(vec![results(vec![page("101", "ENG")], Some("text-cursor"))]);
        let provider = provider(backend.clone(), config());
        let query = json!({"query":{"type":"cql","value":"title !~ \"obsolete\" AND text !~ \"deprecated\""},"maxResults":3});
        let first = provider
            .invoke_content_search(invocation(kind, space_authority(kind), query.clone()), kind)
            .await
            .unwrap();
        for changed in [
            json!({"type":"cql","value":"title ~ \"obsolete\" AND text !~ \"deprecated\""}),
            json!({"type":"cql","value":"title !~ \"obsolete\" AND text ~ \"deprecated\""}),
            json!({"type":"cql","value":"title !~ \"other\" AND text !~ \"deprecated\""}),
            json!({"type":"cql","value":"title !~ \"obsolete\" AND text !~ \"other\""}),
        ] {
            let mut next = resume(query.clone(), &first);
            next["query"] = changed;
            assert_invalid(
                provider
                    .invoke_content_search(invocation(kind, space_authority(kind), next), kind)
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(backend.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn empty_filtered_pages_stop_at_scan_budget_and_resume_at_the_next_cursor() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![
        results(vec![page("101", "OPS")], Some("second")),
        results(vec![page("102", "ENG")], None),
    ]);
    let mut config = config();
    config.content_search.max_candidate_pages = 1;
    let provider = provider(backend.clone(), config);
    let first = provider
        .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
        .await
        .unwrap();
    assert!(first.result["pages"].as_array().unwrap().is_empty());
    assert_eq!(first.result["scanStatus"], "scan_budget");
    let second = provider
        .invoke_content_search(
            invocation(kind, space_authority(kind), resume(inputs(), &first)),
            kind,
        )
        .await
        .unwrap();
    assert_eq!(second.result["pages"][0]["id"], "102");
    assert_eq!(
        backend.requests.lock().unwrap()[1]
            .next_page_token
            .as_deref(),
        Some("second")
    );
}

#[tokio::test]
async fn duplicate_rows_and_empty_upstream_cursors_fail_closed() {
    let kind = ConfluenceSearchContentKind::Page;
    for candidate in [
        results(vec![page("101", "ENG"), page("101", "ENG")], None),
        results(vec![page("101", "ENG")], Some("")),
        results(
            (101..105).map(|id| page(&id.to_string(), "ENG")).collect(),
            None,
        ),
    ] {
        let backend = Backend::new(vec![candidate]);
        let provider = provider(backend, config());
        let error = provider
            .invoke_content_search(invocation(kind, space_authority(kind), inputs()), kind)
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }
}

#[test]
fn confidential_cursor_payload_cannot_exceed_the_response_budget() {
    let limits = ProviderLimits::default().with_max_upstream_response_bytes(512);
    let family = family(&limits);
    assert!(family.max_token_bytes() <= 512);
    let request = invocation(
        ConfluenceSearchContentKind::Page,
        space_authority(ConfluenceSearchContentKind::Page),
        inputs(),
    );
    let binding = family.bind(request.context(), [0; 32]);
    let signer = ContinuationSigner::new(None);
    let expiry = signer.deadline(&binding).unwrap();
    assert!(matches!(
        signer.seal_until(&binding, &[0; 512], expiry),
        Err(ContinuationError::PayloadTooLarge { .. })
    ));
}

// Decode the public wire envelope independently to ensure the cursor is not
// merely authenticated plaintext. This test does not inspect ciphertext internals.
fn decode_base64url(value: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut bytes = vec![];
    for byte in value.bytes() {
        accumulator = (accumulator << 6)
            | ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .expect("base64url token") as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
        }
    }
    bytes
}

#[tokio::test]
async fn final_proof_failure_records_unresolved_without_releasing_candidates() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
    backend.rooted("101");
    backend.set_nodes(
        "101",
        vec![node("101", "1", Some("100")), node("999", "1", None)],
    );
    let provider = provider(backend, config());
    let error = provider
        .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error
            .audit
            .as_ref()
            .unwrap()
            .pointer("/locationProof/finalCheck")
            .unwrap(),
        "unresolved"
    );
}
