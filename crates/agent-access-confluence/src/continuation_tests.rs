//! Confluence continuation families: bindings, lifetimes, bounds, draft
//! handle ownership at scope resolution and after admission, and search
//! continuations end to end.
use super::*;
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, basic_credential, bearer_credential, test_signing_key,
};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn config() -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: Some("00000000-0000-0000-0000-000000000000".to_string()),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/wiki/rest/api/**".to_string()],
        attachments: Default::default(),
        content: ConfluenceContentConfig::default(),
        search: SearchLimitsConfig { max_results: 2 },
    }
}

fn signers(stable: Option<Arc<dyn StableSigningKey>>) -> ConfluenceContinuations {
    ConfluenceContinuations::new(&config(), &ProviderLimits::default(), stable)
}

fn credential() -> ExecutionCredential {
    basic_credential("agent@example.com", "token")
}

fn identity(principal: &str) -> InvocationIdentity {
    InvocationIdentity::new(principal.to_string(), true)
}

fn invocation(action: &str) -> ProviderInvocation {
    InvocationBuilder::new("confluence", action)
        .identity(identity("agent-one"))
        .credential(credential())
        .build()
}

fn page() -> ConfluencePage {
    ConfluencePage {
        id: "123456".to_string(),
        title: "Runbook".to_string(),
        space: "ENG".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 7,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    }
}

fn blog() -> ConfluenceBlog {
    ConfluenceBlog {
        id: "222222".to_string(),
        title: "Weekly".to_string(),
        space: "ENG".to_string(),
        space_id: "98765".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 3,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    }
}

fn comment_list() -> ConfluenceCommentListBinding {
    ConfluenceCommentListBinding {
        kind: ConfluenceCommentKind::Footer,
        container_type: ConfluenceCommentContainerType::Page,
        container_id: "123456".to_string(),
        comment_id: None,
        space: "ENG".to_string(),
        body_format: Some("storage".to_string()),
        resolution_status: None,
        sort: None,
        max_results: 2,
    }
}

fn draft_handle(content_type: ConfluenceDraftContentType) -> ConfluenceDraftHandle {
    let id = match content_type {
        ConfluenceDraftContentType::Page => "123456",
        ConfluenceDraftContentType::Blog => "7777",
    };
    ConfluenceDraftHandle {
        content_type,
        content_id: id.to_string(),
        space: "ENG".to_string(),
        space_id: "98765".to_string(),
        origin: ConfluenceDraftOrigin::New,
        parent_page_id: (content_type == ConfluenceDraftContentType::Page)
            .then(|| "55555".to_string()),
        base_version: None,
    }
}

/// The four list families, sealed and opened through the provider's
/// methods for one fixed resource each.
#[derive(Debug, Clone, Copy)]
enum List {
    Attachment,
    BlogAttachment,
    Comment,
    DraftAttachment,
}

const LISTS: [List; 4] = [
    List::Attachment,
    List::BlogAttachment,
    List::Comment,
    List::DraftAttachment,
];

impl List {
    fn action(self) -> &'static str {
        match self {
            Self::Attachment => "attachment.list",
            Self::BlogAttachment => "blog.attachment.list",
            Self::Comment => "page.footer_comment.list",
            Self::DraftAttachment => "page.draft.attachment.list",
        }
    }

    fn position(self) -> &'static str {
        match self {
            Self::Comment => "cursor-2",
            _ => "cursor=next-2",
        }
    }

    fn seal(
        self,
        continuations: &ConfluenceContinuations,
        request: &ProviderInvocation,
        credential: &ExecutionCredential,
    ) -> Result<String, ProviderError> {
        let context = request.context();
        match self {
            Self::Attachment => continuations.seal_attachment_page(
                context,
                credential,
                &page(),
                PAGE_SIZE,
                self.position(),
            ),
            Self::BlogAttachment => continuations.seal_blog_attachment_page(
                context,
                credential,
                &blog(),
                PAGE_SIZE,
                self.position(),
            ),
            Self::Comment => continuations.seal_comment_page(
                context,
                credential,
                &comment_list(),
                self.position(),
            ),
            Self::DraftAttachment => continuations.seal_draft_attachment_page(
                context,
                credential,
                &draft_handle(ConfluenceDraftContentType::Page),
                PAGE_SIZE,
                self.position(),
            ),
        }
    }

    fn open(
        self,
        continuations: &ConfluenceContinuations,
        request: &ProviderInvocation,
        credential: &ExecutionCredential,
        token: &str,
    ) -> Result<String, ProviderError> {
        self.open_with_page_size(continuations, request, credential, PAGE_SIZE, token)
    }

    /// Opens with another effective `maxResults`; comment lists take theirs
    /// from [`comment_list`].
    fn open_with_page_size(
        self,
        continuations: &ConfluenceContinuations,
        request: &ProviderInvocation,
        credential: &ExecutionCredential,
        max_results: u32,
        token: &str,
    ) -> Result<String, ProviderError> {
        let context = request.context();
        match self {
            Self::Attachment => {
                continuations.open_attachment_page(context, credential, &page(), max_results, token)
            }
            Self::BlogAttachment => continuations.open_blog_attachment_page(
                context,
                credential,
                &blog(),
                max_results,
                token,
            ),
            Self::Comment => {
                let mut list = comment_list();
                list.max_results = max_results;
                continuations.open_comment_page(context, credential, &list, token)
            }
            Self::DraftAttachment => continuations.open_draft_attachment_page(
                context,
                credential,
                &draft_handle(ConfluenceDraftContentType::Page),
                max_results,
                token,
            ),
        }
    }

    /// A binding for this list's resource under `family`, for forging tokens
    /// of other versions and lifetimes.
    fn binding(
        self,
        continuations: &ConfluenceContinuations,
        family: &ContinuationFamily,
        request: &ProviderInvocation,
    ) -> ContinuationBinding {
        let binding = continuations.route_binding(family, request.context(), &credential());
        match self {
            Self::Attachment => binding
                .text("pageId", "123456")
                .text("space", "ENG")
                .number("maxResults", u64::from(PAGE_SIZE)),
            _ => unreachable!("only attachment lists are forged"),
        }
    }
}

/// The effective `maxResults` the list tests seal under; [`comment_list`]
/// uses the same.
const PAGE_SIZE: u32 = 2;

fn assert_list_rejection(result: Result<String, ProviderError>, list: List) {
    let error = result.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{list:?}");
    assert_eq!(error.decision(), Decision::Deny, "{list:?}");
}

#[test]
fn list_tokens_round_trip_and_reject_changed_context_tenant_caller_and_route() {
    let continuations = signers(None);
    let credential = credential();
    for list in LISTS {
        let request = invocation(list.action());
        let token = list.seal(&continuations, &request, &credential).unwrap();
        assert!(!token.contains(list.position()), "{list:?}");
        assert_eq!(
            list.open(&continuations, &request, &credential, &token)
                .unwrap(),
            list.position(),
            "{list:?}"
        );

        let mut changed_requests = vec![
            InvocationBuilder::from(request.clone())
                .execution_context("external")
                .build(),
            InvocationBuilder::from(request.clone())
                .credential_mode(CredentialMode::PerUser)
                .build(),
            InvocationBuilder::from(request.clone())
                .action("page.inline_comment.list")
                .build(),
        ];
        if !matches!(list, List::DraftAttachment) {
            // Service-mode draft attachment listings are shared like their
            // handle; every other list belongs to its caller.
            changed_requests.push(
                InvocationBuilder::from(request.clone())
                    .identity(identity("agent-two"))
                    .build(),
            );
            changed_requests.push(
                InvocationBuilder::from(request.clone())
                    .identity(InvocationIdentity::new("agent-one".to_string(), false))
                    .build(),
            );
        }
        for changed in changed_requests {
            assert_list_rejection(
                list.open(&continuations, &changed, &credential, &token),
                list,
            );
        }
        // The credential kind selects the tenant or gateway route.
        assert_list_rejection(
            list.open(
                &continuations,
                &request,
                &bearer_credential("token"),
                &token,
            ),
            list,
        );
        // Another tenant, gateway cloud ID or gateway route.
        let mut tenants = Vec::new();
        let mut other = config();
        other.tenant_host = "other.atlassian.net".to_string();
        tenants.push(other);
        let mut other = config();
        other.cloud_id = Some("11111111-1111-1111-1111-111111111111".to_string());
        tenants.push(other);
        let mut other = config();
        other
            .allowed_upstream_hosts
            .push("https://api.atlassian.com/ex/confluence/**".to_string());
        tenants.push(other);
        for tenant in tenants {
            let other = ConfluenceContinuations {
                route: tenant.site().route_fingerprint(),
                ..continuations.clone()
            };
            assert_list_rejection(list.open(&other, &request, &credential, &token), list);
        }
        // No list family opens another's tokens.
        for other_list in LISTS {
            if !matches!(
                (list, other_list),
                (List::Attachment, List::Attachment)
                    | (List::BlogAttachment, List::BlogAttachment)
                    | (List::Comment, List::Comment)
                    | (List::DraftAttachment, List::DraftAttachment)
            ) {
                assert_list_rejection(
                    other_list.open(&continuations, &request, &credential, &token),
                    other_list,
                );
            }
        }
    }
}

#[test]
fn draft_attachment_listings_are_shared_in_service_mode_and_owned_per_user() {
    let continuations = signers(Some(test_signing_key(5)));
    let credential = credential();
    let list = List::DraftAttachment;
    let request = invocation(list.action());
    let token = list.seal(&continuations, &request, &credential).unwrap();
    let other_service = InvocationBuilder::from(request.clone())
        .identity(identity("agent-two"))
        .build();
    assert_eq!(
        list.open(&continuations, &other_service, &credential, &token)
            .unwrap(),
        list.position()
    );
    let per_user = InvocationBuilder::from(request.clone())
        .credential_mode(CredentialMode::PerUser)
        .build();
    let owned = list.seal(&continuations, &per_user, &credential).unwrap();
    assert_eq!(
        list.open(&continuations, &per_user, &credential, &owned)
            .unwrap(),
        list.position()
    );
    for other in [
        InvocationBuilder::from(per_user.clone())
            .identity(identity("agent-two"))
            .build(),
        request,
    ] {
        assert_list_rejection(list.open(&continuations, &other, &credential, &owned), list);
    }
}

#[test]
fn list_tokens_bind_the_effective_page_size() {
    let continuations = signers(None);
    let credential = credential();
    for list in LISTS {
        let request = invocation(list.action());
        let token = list.seal(&continuations, &request, &credential).unwrap();
        assert_eq!(
            list.open_with_page_size(&continuations, &request, &credential, PAGE_SIZE, &token)
                .unwrap(),
            list.position()
        );
        for other in [1, 3] {
            assert_list_rejection(
                list.open_with_page_size(&continuations, &request, &credential, other, &token),
                list,
            );
        }
    }
}

#[test]
fn list_tokens_reject_obsolete_versions_and_formats() {
    let continuations = signers(None);
    let request = invocation("attachment.list");
    let list = List::Attachment;
    // The previous version, which did not bind maxResults.
    let obsolete = within_response_limit(
        ContinuationFamily::new(
            "confluence",
            "attachment-list-page",
            2,
            ContinuationLifetime::StableWhenConfigured,
            0,
        )
        .expires_after(PAGE_TOKEN_TTL)
        .clock_skew(PAGE_TOKEN_CLOCK_SKEW),
        &ProviderLimits::default(),
    );
    let forged = continuations
        .signer
        .seal_relayed(
            &list.binding(&continuations, &obsolete, &request),
            None,
            "start=1",
        )
        .unwrap();
    assert_list_rejection(
        list.open(&continuations, &request, &credential(), &forged),
        list,
    );
    // The previous `base64url(json).hmac` format never decodes.
    let previous = format!(
        "{}.{}",
        "eyJ2IjoxLCJzZXJ2aWNlIjoiY29uZmx1ZW5jZSJ9", "c2lnbmF0dXJl"
    );
    assert_list_rejection(
        list.open(&continuations, &request, &credential(), &previous),
        list,
    );
}

#[test]
fn list_tokens_expire_after_fifteen_minutes_with_a_minute_of_skew() {
    let continuations = signers(Some(test_signing_key(5)));
    let request = invocation("attachment.list");
    let list = List::Attachment;
    let binding = list.binding(&continuations, &continuations.attachment_pages, &request);
    let now = SystemTime::now();
    let seal_at = |at: SystemTime| {
        continuations
            .signer
            .seal_relayed_at(&binding, None, "start=1", at)
            .unwrap()
    };
    let open = |token: &str| list.open(&continuations, &request, &credential(), token);
    assert_eq!(
        open(&seal_at(now - Duration::from_secs(14 * 60))).unwrap(),
        "start=1"
    );
    let error = open(&seal_at(now - Duration::from_secs(15 * 60 + 1))).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        error.message,
        "Confluence attachment pagination token is expired"
    );
    // A token from an instance whose clock runs up to a minute ahead.
    assert_eq!(
        open(&seal_at(now + Duration::from_secs(50))).unwrap(),
        "start=1"
    );
    assert_list_rejection(open(&seal_at(now + Duration::from_secs(120))), list);
}

#[test]
fn list_tokens_follow_the_stable_key_and_search_tokens_the_generation() {
    let key = test_signing_key(5);
    let first = signers(Some(key.clone()));
    let second = signers(Some(key));
    let credential = credential();
    for list in LISTS {
        let request = invocation(list.action());
        let token = list.seal(&first, &request, &credential).unwrap();
        assert_eq!(
            list.open(&second, &request, &credential, &token).unwrap(),
            list.position(),
            "{list:?}"
        );
        let local = signers(None);
        let token = list.seal(&local, &request, &credential).unwrap();
        assert_list_rejection(
            list.open(&signers(None), &request, &credential, &token),
            list,
        );
    }
    let fixture = SearchFixture::new(&["ENG"]);
    let request = invocation("search");
    let token = first
        .seal_search_page(&fixture.pages(&request, &credential), "cursor-2")
        .unwrap();
    assert_eq!(
        first
            .open_search_page(&fixture.pages(&request, &credential), &token)
            .unwrap(),
        "cursor-2"
    );
    let error = second
        .open_search_page(&fixture.pages(&request, &credential), &token)
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn relayed_cursors_are_bounded_by_the_response_limit_and_never_truncated() {
    // The default response limit admits cursors far beyond any former cap.
    let generous = signers(None);
    let credential = credential();
    let request = invocation("attachment.list");
    let long = format!("cursor={}", "c".repeat(100 * 1024));
    let token = generous
        .seal_attachment_page(request.context(), &credential, &page(), PAGE_SIZE, &long)
        .unwrap();
    assert_eq!(
        generous
            .open_attachment_page(request.context(), &credential, &page(), PAGE_SIZE, &token)
            .unwrap(),
        long
    );

    let limits = ProviderLimits::default().with_max_upstream_response_bytes(512);
    let bounded = ConfluenceContinuations::new(&config(), &limits, None);
    assert!(bounded.attachment_pages.max_token_bytes() <= 512);
    let fits = format!(
        "cursor={}",
        "c".repeat(bounded.attachment_pages.max_payload_bytes() - "cursor=".len())
    );
    let token = bounded
        .seal_attachment_page(request.context(), &credential, &page(), PAGE_SIZE, &fits)
        .unwrap();
    assert_eq!(token.len(), bounded.attachment_pages.max_token_bytes());
    let error = bounded
        .seal_attachment_page(
            request.context(),
            &credential,
            &page(),
            PAGE_SIZE,
            &format!("{fits}c"),
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.decision(), Decision::Error);
    assert!(!error.message.contains("ccc"), "{}", error.message);
    let error = bounded
        .open_attachment_page(
            request.context(),
            &credential,
            &page(),
            PAGE_SIZE,
            &format!("{token}A"),
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    // Search cursors too, with their query commitment.
    let fixture = SearchFixture::new(&["ENG"]);
    let search = invocation("search");
    let error = bounded
        .seal_search_page(&fixture.pages(&search, &credential), &"c".repeat(512))
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(bounded.search_pages.max_token_bytes() <= 512);
}

/// A normalized search under a finite space boundary.
struct SearchFixture {
    query: BuiltConfluenceSearchQuery,
    requested: BTreeSet<String>,
    max_results: u32,
}

impl SearchFixture {
    fn new(boundary: &[&str]) -> Self {
        Self::with_query("title ~ \"runbook\"", boundary)
    }

    fn with_query(cql: &str, boundary: &[&str]) -> Self {
        Self {
            query: build_confluence_search_query(
                &ConfluenceSearchQueryInput::Cql {
                    value: cql.to_string(),
                },
                &EffectiveSearchScope::Finite(boundary.iter().map(ToString::to_string).collect()),
                &SearchLimitsConfig::default(),
            )
            .unwrap(),
            requested: BTreeSet::new(),
            max_results: 2,
        }
    }

    fn pages<'a>(
        &'a self,
        request: &'a ProviderInvocation,
        credential: &'a ExecutionCredential,
    ) -> SearchPageRequest<'a> {
        SearchPageRequest {
            context: request.context(),
            credential,
            query: &self.query,
            requested_spaces: &self.requested,
            max_results: self.max_results,
        }
    }
}

#[test]
fn search_continuations_bind_the_normalized_search_and_reject_recomposed_queries() {
    let continuations = signers(Some(test_signing_key(5)));
    let credential = credential();
    let request = invocation("search");
    let issued = SearchFixture::new(&["ENG"]);
    let token = continuations
        .seal_search_page(&issued.pages(&request, &credential), "cursor-2")
        .unwrap();
    assert_ne!(token, "cursor-2");
    assert_eq!(
        continuations
            .open_search_page(&issued.pages(&request, &credential), &token)
            .unwrap(),
        "cursor-2"
    );
    let invalid = |result: Result<String, ProviderError>| {
        let error = result.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), Decision::Deny);
        assert!(
            error
                .message
                .contains("nextPageToken is invalid or expired"),
            "{}",
            error.message
        );
    };
    // Another caller query, query type, requested spaces or page size.
    let other_query = SearchFixture::with_query("title ~ \"other\"", &["ENG"]);
    invalid(continuations.open_search_page(&other_query.pages(&request, &credential), &token));
    let mut text = SearchFixture::new(&["ENG"]);
    text.query.kind = "text";
    invalid(continuations.open_search_page(&text.pages(&request, &credential), &token));
    let mut narrowed = SearchFixture::new(&["ENG"]);
    narrowed.requested = BTreeSet::from(["ENG".to_string()]);
    invalid(continuations.open_search_page(&narrowed.pages(&request, &credential), &token));
    let mut smaller = SearchFixture::new(&["ENG"]);
    smaller.max_results = 1;
    invalid(continuations.open_search_page(&smaller.pages(&request, &credential), &token));
    // Another context, caller, mode, action or route.
    for changed in [
        InvocationBuilder::from(request.clone())
            .execution_context("external")
            .build(),
        InvocationBuilder::from(request.clone())
            .identity(identity("agent-two"))
            .build(),
        InvocationBuilder::from(request.clone())
            .credential_mode(CredentialMode::PerUser)
            .build(),
        InvocationBuilder::from(request.clone())
            .action("blog.search")
            .build(),
    ] {
        invalid(continuations.open_search_page(&issued.pages(&changed, &credential), &token));
    }
    invalid(
        continuations
            .open_search_page(&issued.pages(&request, &bearer_credential("token")), &token),
    );
    let mut other_tenant = config();
    other_tenant.tenant_host = "other.atlassian.net".to_string();
    let other_tenant = ConfluenceContinuations {
        route: other_tenant.site().route_fingerprint(),
        ..continuations.clone()
    };
    invalid(other_tenant.open_search_page(&issued.pages(&request, &credential), &token));

    // The same caller search under another boundary binds the same
    // continuation, but Confluence's cursor belongs to the old composed CQL.
    let recomposed = SearchFixture::new(&["ENG", "OPS"]);
    assert_eq!(
        issued.query.canonical_caller_cql,
        recomposed.query.canonical_caller_cql
    );
    assert_ne!(issued.query.cql, recomposed.query.cql);
    let error = continuations
        .open_search_page(&recomposed.pages(&request, &credential), &token)
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert!(
        error.message.contains("space scope changed"),
        "{}",
        error.message
    );
}

#[test]
fn search_continuations_expire_after_fifteen_minutes_without_skew() {
    let continuations = signers(None);
    let credential = credential();
    let request = invocation("search");
    let fixture = SearchFixture::new(&["ENG"]);
    let pages = fixture.pages(&request, &credential);
    let binding = continuations.search_binding(&pages);
    let cql = fixture.query.cql.as_bytes();
    let issued = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let token = continuations
        .signer
        .seal_relayed_at(&binding, Some(cql), "cursor-2", issued)
        .unwrap();
    let open = |at| {
        continuations
            .signer
            .open_relayed_at(&binding, Some(cql), &token, at)
    };
    assert_eq!(open(issued + Duration::from_secs(899)).unwrap(), "cursor-2");
    assert_eq!(
        open(issued + Duration::from_secs(900)),
        Err(ContinuationError::Expired)
    );
    assert_eq!(
        open(issued - Duration::from_secs(1)),
        Err(ContinuationError::Invalid)
    );
}

fn scope_fixture(
    action: &str,
    principal: &str,
    context: &str,
    inputs: Value,
) -> ScopeRequestFixture {
    ScopeRequestFixture::new("confluence", action, inputs)
        .execution_context(context)
        .identity(identity(principal))
}

fn assert_invalid_handle<T: std::fmt::Debug>(result: Result<T, ProviderError>) {
    let error = result.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InvalidDraftHandle);
    assert_eq!(error.decision(), Decision::Deny);
}

#[test]
fn draft_handles_resolve_scope_only_for_possible_owners() {
    let continuations = signers(Some(test_signing_key(7)));
    let handle = draft_handle(ConfluenceDraftContentType::Page);
    let service = invocation("page.draft.create");
    let per_user = InvocationBuilder::from(service.clone())
        .credential_mode(CredentialMode::PerUser)
        .build();
    let service_token = continuations
        .seal_draft_handle(service.context(), &handle)
        .unwrap();
    let per_user_token = continuations
        .seal_draft_handle(per_user.context(), &handle)
        .unwrap();
    let open = |continuations: &ConfluenceContinuations,
                principal: &str,
                context: &str,
                content_id: &str,
                token: &str| {
        let fixture = scope_fixture("page.draft.view", principal, context, json!({}));
        continuations.open_draft_handle_for_scope(
            &fixture.request(),
            ConfluenceDraftContentType::Page,
            content_id,
            token,
        )
    };
    // Service-mode handles resolve for any principal; per-user handles only
    // for their owner.
    for principal in ["agent-one", "agent-two"] {
        assert_eq!(
            open(
                &continuations,
                principal,
                "internal",
                "123456",
                &service_token
            )
            .unwrap(),
            handle
        );
    }
    assert_eq!(
        open(
            &continuations,
            "agent-one",
            "internal",
            "123456",
            &per_user_token
        )
        .unwrap(),
        handle
    );
    assert_invalid_handle(open(
        &continuations,
        "agent-two",
        "internal",
        "123456",
        &per_user_token,
    ));
    // Another execution context, content or tenant.
    assert_invalid_handle(open(
        &continuations,
        "agent-one",
        "external",
        "123456",
        &service_token,
    ));
    assert_invalid_handle(open(
        &continuations,
        "agent-one",
        "internal",
        "654321",
        &service_token,
    ));
    let mut other_tenant = config();
    other_tenant.tenant_host = "other.atlassian.net".to_string();
    let other_tenant = ConfluenceContinuations::new(
        &other_tenant,
        &ProviderLimits::default(),
        Some(test_signing_key(7)),
    );
    assert_invalid_handle(open(
        &other_tenant,
        "agent-one",
        "internal",
        "123456",
        &service_token,
    ));
    // A gateway route change keeps the tenant, so durable handles survive it.
    let mut gateway = config();
    gateway
        .allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/confluence/**".to_string());
    let gateway = ConfluenceContinuations::new(
        &gateway,
        &ProviderLimits::default(),
        Some(test_signing_key(7)),
    );
    assert_eq!(
        open(&gateway, "agent-one", "internal", "123456", &service_token).unwrap(),
        handle
    );
    // Without the durable key, scope resolution fails explicitly.
    let error = open(
        &signers(None),
        "agent-one",
        "internal",
        "123456",
        &service_token,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(
        error.message,
        "Confluence draft actions require broker_tokens.hash_key_ref"
    );
}

#[test]
fn draft_handles_bind_content_type_and_validate_their_facts() {
    let continuations = signers(Some(test_signing_key(7)));
    let request = invocation("blog.draft.create");
    let blog = draft_handle(ConfluenceDraftContentType::Blog);
    let token = continuations
        .seal_draft_handle(request.context(), &blog)
        .unwrap();
    assert_eq!(
        continuations
            .open_draft_handle(
                request.context(),
                ConfluenceDraftContentType::Blog,
                "7777",
                &token
            )
            .unwrap(),
        blog
    );
    assert_invalid_handle(continuations.open_draft_handle(
        request.context(),
        ConfluenceDraftContentType::Page,
        "7777",
        &token,
    ));
    // Facts that a broker never mints are rejected even when authentic.
    let mut staged_without_version = draft_handle(ConfluenceDraftContentType::Page);
    staged_without_version.origin = ConfluenceDraftOrigin::Staged;
    let mut blog_with_parent = blog.clone();
    blog_with_parent.parent_page_id = Some("55555".to_string());
    let mut new_with_version = draft_handle(ConfluenceDraftContentType::Page);
    new_with_version.base_version = Some(3);
    for invalid in [staged_without_version, blog_with_parent, new_with_version] {
        let token = continuations
            .seal_draft_handle(request.context(), &invalid)
            .unwrap();
        assert_invalid_handle(continuations.open_draft_handle(
            request.context(),
            invalid.content_type,
            &invalid.content_id,
            &token,
        ));
    }
    let mut staged = draft_handle(ConfluenceDraftContentType::Page);
    staged.origin = ConfluenceDraftOrigin::Staged;
    staged.base_version = Some(4);
    let token = continuations
        .seal_draft_handle(request.context(), &staged)
        .unwrap();
    assert_eq!(
        continuations
            .open_draft_handle(
                request.context(),
                ConfluenceDraftContentType::Page,
                "123456",
                &token
            )
            .unwrap(),
        staged
    );
}

#[tokio::test]
async fn provider_resolves_draft_scopes_from_handles_for_possible_owners() {
    let provider = ConfluenceProvider::with_backend_and_signing_key(
        config(),
        ProviderLimits::default(),
        Arc::new(SearchBackend::default()),
        test_signing_key(7),
    );
    let handle = draft_handle(ConfluenceDraftContentType::Page);
    let per_user = InvocationBuilder::from(invocation("page.draft.create"))
        .credential_mode(CredentialMode::PerUser)
        .build();
    let token = provider
        .continuations
        .seal_draft_handle(per_user.context(), &handle)
        .unwrap();
    let inputs = json!({ "pageId": "123456", "draftHandle": token, "bodyFormat": "storage" });
    let owner = scope_fixture("page.draft.view", "agent-one", "internal", inputs.clone());
    let resolution = provider.resolve_scopes(owner.request()).await.unwrap();
    assert_eq!(
        resolution.scopes().get("space"),
        Some(&vec!["ENG".to_string()])
    );
    let other = scope_fixture("page.draft.view", "agent-two", "internal", inputs);
    assert_invalid_handle(provider.resolve_scopes(other.request()).await);
}

/// Records the upstream cursor of every search and returns `next` cursors
/// in turn.
#[derive(Default)]
struct SearchBackend {
    requests: Mutex<Vec<ConfluenceSearchRequest>>,
}

impl SearchBackend {
    fn page(&self, request: ConfluenceSearchRequest) -> ConfluenceSearchPage {
        let next = match request.next_page_token.as_deref() {
            None => Some("upstream-cursor-2".to_string()),
            Some(_) => None,
        };
        self.requests.lock().unwrap().push(request);
        let mut page = page();
        page.id = "123456".to_string();
        ConfluenceSearchPage {
            pages: vec![page],
            max_results: 2,
            next_page_token: next,
        }
    }

    fn cursors(&self) -> Vec<Option<String>> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.next_page_token.clone())
            .collect()
    }
}

#[async_trait]
impl ConfluenceBackend for SearchBackend {
    async fn page_metadata(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn page(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: self.page(request),
            status: 200,
            duration_ms: 1,
        })
    }

    async fn search_blogs(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        let page = self.page(request);
        let blog = blog();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceSearchBlog {
                blogs: vec![ConfluenceBlogSummary {
                    id: blog.id,
                    title: blog.title,
                    space: blog.space,
                    web_url: None,
                    space_web_url: None,
                    status: blog.status,
                    version: blog.version,
                    created_at: None,
                    updated_at: None,
                    created_by: None,
                    updated_by: None,
                }],
                max_results: page.max_results,
                next_page_token: page.next_page_token,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::NotFound)
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::NotFound)
    }
}

fn search_invocation(
    action: &str,
    boundary: SearchAuthorizationScope,
    inputs: Value,
) -> ProviderInvocation {
    InvocationBuilder::from(invocation(action))
        .inputs(inputs)
        .search(SearchAuthorization::new("space".to_string(), boundary))
        .build()
}

fn finite(spaces: &[&str]) -> SearchAuthorizationScope {
    SearchAuthorizationScope::Finite {
        values: spaces.iter().map(ToString::to_string).collect(),
    }
}

#[tokio::test]
async fn search_pages_relay_only_confluence_cursors_and_reauthorize_every_page() {
    for action in ["search", "blog.search"] {
        let backend = Arc::new(SearchBackend::default());
        let provider =
            ConfluenceProvider::with_backend(config(), ProviderLimits::default(), backend.clone());
        let query = json!({ "query": { "type": "cql", "value": "title ~ \"runbook\"" } });
        let first = provider
            .invoke(search_invocation(action, finite(&["ENG"]), query.clone()))
            .await
            .unwrap();
        let token = first.result["nextPageToken"].as_str().unwrap().to_string();
        assert_ne!(token, "upstream-cursor-2");
        assert!(!token.contains("upstream-cursor-2"));
        let mut next = query.clone();
        next["nextPageToken"] = json!(token);
        let second = provider
            .invoke(search_invocation(action, finite(&["ENG"]), next.clone()))
            .await
            .unwrap();
        assert!(second.result["nextPageToken"].is_null());
        assert_eq!(
            backend.cursors(),
            vec![None, Some("upstream-cursor-2".to_string())],
            "{action}"
        );

        // A grant change that recomposes the query asks for a new search,
        // before Confluence sees the cursor.
        let error = provider
            .invoke(search_invocation(
                action,
                finite(&["ENG", "OPS"]),
                next.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(
            error.message.contains("space scope changed"),
            "{}",
            error.message
        );
        // Losing the space denies the page outright: each page is authorized
        // under current policy.
        let mut narrowed = next.clone();
        narrowed["spaces"] = json!(["ENG"]);
        let error = provider
            .invoke(search_invocation(action, finite(&["OPS"]), narrowed))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
        // Another action's continuation is not this one's.
        let other = if action == "search" {
            "blog.search"
        } else {
            "search"
        };
        let error = provider
            .invoke(search_invocation(other, finite(&["ENG"]), next))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(backend.cursors().len(), 2, "{action}");
    }
}
