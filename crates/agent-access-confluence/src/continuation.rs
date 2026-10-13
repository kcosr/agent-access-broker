//! Confluence continuations: list and search page tokens and durable draft
//! handles, sealed in SDK continuation envelopes.
//!
//! Every family binds the admitted service and execution context and the
//! Confluence configuration it depends on: list and search tokens bind the
//! route fingerprint (tenant host, gateway cloud ID and whether the gateway
//! is enabled) plus the credential kind that selects the tenant or gateway
//! route, because they relay Confluence's own route-relative cursors; draft
//! handles bind the tenant host, because a draft's content ID names content
//! on that tenant whichever route reaches it. No family binds the effective
//! grant boundary: the host authorizes every page and handle use again and
//! the provider re-applies its containment checks.
//!
//! List and search tokens relay Confluence's own cursor, so their size is
//! bounded by the provider's upstream response limit, which bounds both the
//! upstream response a cursor arrives in and the result its continuation
//! leaves in; the broker adds no cursor cap of its own and never truncates.
use super::*;

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;

/// How long list and search continuations stay valid after they are issued.
const PAGE_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
/// List continuations may be signed with the stable key shared by several
/// broker instances, whose clocks may differ by up to a minute.
const PAGE_TOKEN_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// `attachment.list` pages: Confluence's next attachment position. Stable
/// when `broker_tokens.hash_key_ref` is configured. Declared without a
/// payload cap; [`ConfluenceContinuations::new`] sizes it from the response
/// limit.
const ATTACHMENT_LIST_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "attachment-list-page",
    2,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// `blog.attachment.list` pages, like [`ATTACHMENT_LIST_PAGES`].
const BLOG_ATTACHMENT_LIST_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "blog-attachment-list-page",
    2,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// Page and blog footer/inline comment list and reply-list pages:
/// Confluence's next comment cursor.
const COMMENT_LIST_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "comment-list-page",
    2,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// Page and blog draft attachment list pages. Owned like the draft handle
/// they list: shared among service-mode principals, bound to the principal
/// in per-user mode.
const DRAFT_ATTACHMENT_LIST_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "draft-attachment-list-page",
    3,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.owner(ContinuationOwner::PerUserCaller)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// `search` and `blog.search` pages: Confluence's search cursor with a keyed
/// commitment to the composed upstream CQL. Signed with a key generated for
/// each provider instance, so a reload or restart also invalidates them.
/// Declared without a payload cap; [`ConfluenceContinuations::new`] sizes it
/// from the response limit.
const SEARCH_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "search-page",
    1,
    ContinuationLifetime::Generation,
    0,
)
.expires_after(PAGE_TOKEN_TTL);

/// The visible prefix of a draft handle.
pub(crate) const DRAFT_HANDLE_PREFIX: &str = "aab_confluence_draft_v3_";
/// A handle's facts: a space key of at most 255 bytes, numeric IDs and a
/// version, as compact JSON. Far beyond any real draft.
const DRAFT_HANDLE_PAYLOAD_MAX_BYTES: usize = 4096;

/// Durable draft handles: no expiry, signed only with the stable key, shared
/// across the draft actions, read during scope resolution for the space they
/// name, and owned by the per-user principal that created them (service-mode
/// handles are shared among authorized service-mode principals).
const DRAFT_HANDLES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "draft-handle",
    3,
    ContinuationLifetime::Durable,
    DRAFT_HANDLE_PAYLOAD_MAX_BYTES,
)
.owner(ContinuationOwner::PerUserCaller)
.shared_across_actions()
.opened_during_scope_resolution()
.token_prefix(DRAFT_HANDLE_PREFIX);

/// The exact size of the largest draft handle, which bounds the input.
pub(crate) const DRAFT_HANDLE_MAX_BYTES: usize = DRAFT_HANDLES.max_token_bytes();

/// The configuration a relayed Confluence cursor depends on: the tenant, the
/// gateway cloud ID and whether the gateway route is enabled.
pub(crate) fn route_fingerprint(config: &ConfluenceProviderConfig) -> [u8; 32] {
    let fields = json!({
        "tenantHost": config.tenant_host,
        "cloudId": config.cloud_id,
        "gateway": agent_access_atlassian::uses_atlassian_gateway_host(&config.allowed_upstream_hosts),
    });
    Sha256::digest(fields.to_string().as_bytes()).into()
}

/// `family` with the largest payload cap whose continuations fit the
/// provider's response limit, which bounds the upstream response a relayed
/// cursor arrives in and the result its continuation is returned in.
fn within_response_limit(
    family: ContinuationFamily,
    limits: &ProviderLimits,
) -> ContinuationFamily {
    let bound = usize::try_from(limits.max_upstream_response_bytes).unwrap_or(usize::MAX);
    family.with_max_payload_bytes(family.max_payload_bytes_within(bound))
}

/// One provider instance's continuation families and signer.
#[derive(Clone)]
pub(crate) struct ConfluenceContinuations {
    signer: ContinuationSigner,
    route: [u8; 32],
    tenant_host: String,
    attachment_pages: ContinuationFamily,
    blog_attachment_pages: ContinuationFamily,
    comment_pages: ContinuationFamily,
    draft_attachment_pages: ContinuationFamily,
    search_pages: ContinuationFamily,
}

/// The list families, for their error messages.
#[derive(Debug, Clone, Copy)]
enum ListPages {
    Attachment,
    BlogAttachment,
    Comment,
    DraftAttachment,
}

impl ListPages {
    fn label(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::BlogAttachment => "blog attachment",
            Self::Comment => "comment",
            Self::DraftAttachment => "draft attachment",
        }
    }
}

impl ConfluenceContinuations {
    pub(crate) fn new(
        config: &ConfluenceProviderConfig,
        limits: &ProviderLimits,
        stable: Option<Arc<dyn StableSigningKey>>,
    ) -> Self {
        Self {
            signer: ContinuationSigner::new(stable),
            route: route_fingerprint(config),
            tenant_host: config.tenant_host.clone(),
            attachment_pages: within_response_limit(ATTACHMENT_LIST_PAGES, limits),
            blog_attachment_pages: within_response_limit(BLOG_ATTACHMENT_LIST_PAGES, limits),
            comment_pages: within_response_limit(COMMENT_LIST_PAGES, limits),
            draft_attachment_pages: within_response_limit(DRAFT_ATTACHMENT_LIST_PAGES, limits),
            search_pages: within_response_limit(SEARCH_PAGES, limits),
        }
    }

    /// A list or search binding: the admitted context, the route
    /// fingerprint and the credential kind that selects the route.
    fn route_binding(
        &self,
        family: &ContinuationFamily,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
    ) -> ContinuationBinding {
        family
            .bind(context, self.route)
            .text("credentialKind", credential.kind().as_str())
    }

    fn attachment_binding(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        page: &ConfluencePage,
    ) -> ContinuationBinding {
        self.route_binding(&self.attachment_pages, context, credential)
            .text("pageId", &page.id)
            .text("space", &page.space)
    }

    pub(crate) fn seal_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        page: &ConfluencePage,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.attachment_binding(context, credential, page);
        self.seal_list(ListPages::Attachment, &binding, position)
    }

    pub(crate) fn open_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        page: &ConfluencePage,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.attachment_binding(context, credential, page);
        let position = self.open_list(ListPages::Attachment, &binding, token)?;
        checked_position(ListPages::Attachment, position)
    }

    fn blog_attachment_binding(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        blog: &ConfluenceBlog,
    ) -> ContinuationBinding {
        self.route_binding(&self.blog_attachment_pages, context, credential)
            .text("blogId", &blog.id)
            .text("space", &blog.space)
            .text("spaceId", &blog.space_id)
    }

    pub(crate) fn seal_blog_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        blog: &ConfluenceBlog,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.blog_attachment_binding(context, credential, blog);
        self.seal_list(ListPages::BlogAttachment, &binding, position)
    }

    pub(crate) fn open_blog_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        blog: &ConfluenceBlog,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.blog_attachment_binding(context, credential, blog);
        let position = self.open_list(ListPages::BlogAttachment, &binding, token)?;
        checked_position(ListPages::BlogAttachment, position)
    }

    fn comment_binding(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        list: &ConfluenceCommentListBinding,
    ) -> ContinuationBinding {
        self.route_binding(&self.comment_pages, context, credential)
            .text("commentKind", list.kind.as_str())
            .text("containerType", list.container_type.as_str())
            .text("containerId", &list.container_id)
            .optional_text("commentId", list.comment_id.as_deref())
            .text("space", &list.space)
            .optional_text("bodyFormat", list.body_format.as_deref())
            .optional_text("resolutionStatus", list.resolution_status.as_deref())
            .optional_text("sort", list.sort.as_deref())
            .number("maxResults", u64::from(list.max_results))
    }

    pub(crate) fn seal_comment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        list: &ConfluenceCommentListBinding,
        cursor: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.comment_binding(context, credential, list);
        self.seal_list(ListPages::Comment, &binding, cursor)
    }

    pub(crate) fn open_comment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        list: &ConfluenceCommentListBinding,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.comment_binding(context, credential, list);
        let cursor = self.open_list(ListPages::Comment, &binding, token)?;
        checked_cursor(ListPages::Comment, cursor)
    }

    fn draft_attachment_binding(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        handle: &ConfluenceDraftHandle,
    ) -> ContinuationBinding {
        self.route_binding(&self.draft_attachment_pages, context, credential)
            .text("contentType", handle.content_type.as_str())
            .text("contentId", &handle.content_id)
            .text("space", &handle.space)
            .text("spaceId", &handle.space_id)
            .text("origin", handle.origin.as_str())
            .optional_text("parentPageId", handle.parent_page_id.as_deref())
            .optional_number("baseVersion", handle.base_version)
    }

    pub(crate) fn seal_draft_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        handle: &ConfluenceDraftHandle,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.draft_attachment_binding(context, credential, handle);
        self.seal_list(ListPages::DraftAttachment, &binding, position)
    }

    pub(crate) fn open_draft_attachment_page(
        &self,
        context: &AdmittedContext,
        credential: &ExecutionCredential,
        handle: &ConfluenceDraftHandle,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.draft_attachment_binding(context, credential, handle);
        let position = self.open_list(ListPages::DraftAttachment, &binding, token)?;
        checked_position(ListPages::DraftAttachment, position)
    }

    fn seal_list(
        &self,
        pages: ListPages,
        binding: &ContinuationBinding,
        position: &str,
    ) -> Result<String, ProviderError> {
        self.signer
            .seal_relayed(binding, None, position)
            .map_err(|error| list_token_failure(pages, error))
    }

    fn open_list(
        &self,
        pages: ListPages,
        binding: &ContinuationBinding,
        token: &str,
    ) -> Result<String, ProviderError> {
        self.signer
            .open_relayed(binding, None, token)
            .map_err(|error| list_token_failure(pages, error))
    }

    fn search_binding(&self, search: &SearchPageRequest<'_>) -> ContinuationBinding {
        self.route_binding(&self.search_pages, search.context, search.credential)
            .text("queryType", search.query.kind)
            .text("query", &search.query.canonical_caller_cql)
            .texts("spaces", search.requested_spaces.iter().map(String::as_str))
            .number("maxResults", u64::from(search.max_results))
    }

    /// Seals Confluence's `upstream` search cursor for this search, with a
    /// commitment to the composed CQL it continues.
    pub(crate) fn seal_search_page(
        &self,
        search: &SearchPageRequest<'_>,
        upstream: &str,
    ) -> Result<String, ProviderError> {
        self.signer
            .seal_relayed(
                &self.search_binding(search),
                Some(search.query.cql.as_bytes()),
                upstream,
            )
            .map_err(|error| search_token_failure(search.context.action(), error))
    }

    /// Opens a continuation issued for this search and returns Confluence's
    /// cursor, provided the current composed CQL is the one it was issued
    /// for; otherwise the caller repeats the search, and Confluence never
    /// sees its cursor with a different query.
    pub(crate) fn open_search_page(
        &self,
        search: &SearchPageRequest<'_>,
        token: &str,
    ) -> Result<String, ProviderError> {
        self.signer
            .open_relayed(
                &self.search_binding(search),
                Some(search.query.cql.as_bytes()),
                token,
            )
            .map_err(|error| search_token_failure(search.context.action(), error))
    }

    /// Mints the durable handle for `handle`'s draft, owned as the admitted
    /// credential mode and principal decide.
    pub(crate) fn seal_draft_handle(
        &self,
        context: &AdmittedContext,
        handle: &ConfluenceDraftHandle,
    ) -> Result<String, ProviderError> {
        let facts =
            serde_json::to_vec(&ConfluenceDraftHandleFacts::from(handle)).map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "failed to encode Confluence draft handle",
                )
            })?;
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind(context, &self.tenant_host),
            handle.content_type,
            &handle.content_id,
        );
        self.signer
            .seal(&binding, &facts)
            .map_err(draft_handle_failure)
    }

    /// Reads the draft a handle names during scope resolution, for the
    /// content the inputs name. The owner is checked against the current
    /// principal here and against the admitted credential mode by
    /// [`Self::open_draft_handle`].
    pub(crate) fn open_draft_handle_for_scope(
        &self,
        request: &ScopeRequest<'_>,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        token: &str,
    ) -> Result<ConfluenceDraftHandle, ProviderError> {
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind_scope(request, &self.tenant_host),
            content_type,
            content_id,
        );
        let facts = self
            .signer
            .open_during_scope_resolution(&binding, token)
            .map_err(draft_handle_failure)?;
        ConfluenceDraftHandle::from_facts(content_type, content_id, &facts)
    }

    /// Opens a handle after admission: owned by the admitted principal in
    /// per-user mode, or a service-mode handle for a service-mode request.
    pub(crate) fn open_draft_handle(
        &self,
        context: &AdmittedContext,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        token: &str,
    ) -> Result<ConfluenceDraftHandle, ProviderError> {
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind(context, &self.tenant_host),
            content_type,
            content_id,
        );
        let facts = self
            .signer
            .open(&binding, token)
            .map_err(draft_handle_failure)?;
        ConfluenceDraftHandle::from_facts(content_type, content_id, &facts)
    }
}

/// The content a draft handle names, from the action's inputs: it is bound,
/// not carried.
fn draft_handle_binding<Stage: ContinuationStage>(
    binding: ContinuationBinding<Stage>,
    content_type: ConfluenceDraftContentType,
    content_id: &str,
) -> ContinuationBinding<Stage> {
    binding
        .text("contentType", content_type.as_str())
        .text("contentId", content_id)
}

/// The normalized search a continuation belongs to.
pub(crate) struct SearchPageRequest<'a> {
    pub(crate) context: &'a AdmittedContext,
    pub(crate) credential: &'a ExecutionCredential,
    pub(crate) query: &'a BuiltConfluenceSearchQuery,
    pub(crate) requested_spaces: &'a BTreeSet<String>,
    pub(crate) max_results: u32,
}

/// What a broker-issued draft handle establishes about its draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluenceDraftHandle {
    pub(crate) content_type: ConfluenceDraftContentType,
    pub(crate) content_id: String,
    pub(crate) space: String,
    pub(crate) space_id: String,
    pub(crate) origin: ConfluenceDraftOrigin,
    pub(crate) parent_page_id: Option<String>,
    pub(crate) base_version: Option<u64>,
}

impl ConfluenceDraftHandle {
    pub(crate) fn new(
        content_type: ConfluenceDraftContentType,
        content: &ConfluenceDraftContent,
        origin: ConfluenceDraftOrigin,
        base_version: Option<u64>,
    ) -> Self {
        Self {
            content_type,
            content_id: content.id.clone(),
            space: content.space.clone(),
            space_id: content.space_id.clone(),
            origin,
            parent_page_id: content.parent_page_id.clone(),
            base_version,
        }
    }

    fn from_facts(
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        facts: &[u8],
    ) -> Result<Self, ProviderError> {
        let facts: ConfluenceDraftHandleFacts =
            serde_json::from_slice(facts).map_err(|_| invalid_draft_handle_error())?;
        let handle = Self {
            content_type,
            content_id: content_id.to_string(),
            space: facts.space,
            space_id: facts.space_id,
            origin: facts.origin,
            parent_page_id: facts.parent_page_id,
            base_version: facts.base_version,
        };
        handle.validate()?;
        Ok(handle)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        let well_formed = is_space_key(&self.space)
            && is_page_id(&self.space_id)
            && self.content_type.validate_id(&self.content_id).is_ok()
            && self
                .parent_page_id
                .as_deref()
                .is_none_or(|id| validate_page_id(id).is_ok())
            && (self.content_type == ConfluenceDraftContentType::Page
                || self.parent_page_id.is_none())
            && match self.origin {
                ConfluenceDraftOrigin::New => self.base_version.is_none(),
                ConfluenceDraftOrigin::Staged => {
                    self.base_version.is_some_and(|version| version > 0)
                }
            };
        if well_formed {
            Ok(())
        } else {
            Err(invalid_draft_handle_error())
        }
    }
}

/// A draft handle's payload. The content type and ID come from the action's
/// inputs and are bound; the owner travels as the envelope's ownership
/// commitment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfluenceDraftHandleFacts {
    space: String,
    space_id: String,
    origin: ConfluenceDraftOrigin,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    parent_page_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    base_version: Option<u64>,
}

impl From<&ConfluenceDraftHandle> for ConfluenceDraftHandleFacts {
    fn from(handle: &ConfluenceDraftHandle) -> Self {
        Self {
            space: handle.space.clone(),
            space_id: handle.space_id.clone(),
            origin: handle.origin,
            parent_page_id: handle.parent_page_id.clone(),
            base_version: handle.base_version,
        }
    }
}

pub(crate) fn invalid_draft_handle_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InvalidDraftHandle,
        "Confluence draft handle is invalid",
    )
}

fn draft_handle_failure(error: ContinuationError) -> ProviderError {
    match error {
        ContinuationError::DurableKeyUnavailable => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft actions require broker_tokens.hash_key_ref",
        ),
        ContinuationError::SigningUnavailable => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft signing key is unavailable",
        ),
        error if error.is_token_rejection() => invalid_draft_handle_error(),
        _ => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "failed to encode Confluence draft handle",
        ),
    }
}

fn list_token_failure(pages: ListPages, error: ContinuationError) -> ProviderError {
    let label = pages.label();
    match error {
        ContinuationError::Expired => ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("Confluence {label} pagination token is expired"),
        ),
        error if error.is_token_rejection() => ProviderError::deny(
            ReasonCode::InputInvalid,
            format!(
                "Confluence {label} pagination token is invalid or does not match this request"
            ),
        ),
        ContinuationError::PayloadTooLarge { .. } => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            format!("Confluence {label} pagination position exceeds the provider response limit"),
        ),
        _ => pagination_signing_unavailable(),
    }
}

/// An attachment position from a token still names exactly one supported
/// Confluence position parameter.
fn checked_position(pages: ListPages, position: String) -> Result<String, ProviderError> {
    decoded_attachment_next_position(Some(&position), false).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!(
                "Confluence {} pagination token position is invalid",
                pages.label()
            ),
        )
    })?;
    Ok(position)
}

fn checked_cursor(pages: ListPages, cursor: String) -> Result<String, ProviderError> {
    validate_comment_cursor(&cursor).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!(
                "Confluence {} pagination token cursor is invalid",
                pages.label()
            ),
        )
    })?;
    Ok(cursor)
}

fn search_token_failure(action: &str, error: ContinuationError) -> ProviderError {
    match error {
        ContinuationError::UpstreamQueryChanged => ProviderError::deny(
            ReasonCode::InputInvalid,
            "the effective Confluence space scope changed since nextPageToken was issued; repeat the search without nextPageToken",
        ),
        error if error.is_token_rejection() => ProviderError::deny(
            ReasonCode::InputInvalid,
            format!(
                "confluence.{action} nextPageToken is invalid or expired; reuse it only with the same query, spaces, and maxResults"
            ),
        ),
        ContinuationError::PayloadTooLarge { .. } => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence search cursor exceeds the provider response limit",
        ),
        _ => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence search continuation signing is unavailable",
        ),
    }
}

fn pagination_signing_unavailable() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence pagination signing key is unavailable",
    )
}
