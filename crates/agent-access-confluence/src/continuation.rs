//! Confluence continuations: search, attachment list and comment list page
//! tokens, sealed in SDK continuation envelopes.
//!
//! Every family relays Confluence's own cursor and binds the admitted
//! service, action, execution context and caller, the route fingerprint
//! (tenant host, gateway cloud ID and whether the gateway is enabled) and
//! the credential kind that selects the tenant or gateway route, because
//! Confluence's cursors are route-relative, plus the request's resource and
//! normalized settings. No family binds the effective grant boundary: the
//! host authorizes every page again and the provider re-applies its
//! containment checks.
//!
//! The broker adds no cursor cap of its own and never truncates: each family
//! is bounded by the provider's upstream response limit, which bounds both
//! the upstream response a cursor arrives in and the result its continuation
//! leaves in.
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
    attachment_pages: ContinuationFamily,
    blog_attachment_pages: ContinuationFamily,
    comment_pages: ContinuationFamily,
    search_pages: ContinuationFamily,
}

/// The list families, for their error messages.
#[derive(Debug, Clone, Copy)]
enum ListPages {
    Attachment,
    BlogAttachment,
    Comment,
}

impl ListPages {
    fn label(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::BlogAttachment => "blog attachment",
            Self::Comment => "comment",
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
            attachment_pages: within_response_limit(ATTACHMENT_LIST_PAGES, limits),
            blog_attachment_pages: within_response_limit(BLOG_ATTACHMENT_LIST_PAGES, limits),
            comment_pages: within_response_limit(COMMENT_LIST_PAGES, limits),
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
}

/// The normalized search a continuation belongs to.
pub(crate) struct SearchPageRequest<'a> {
    pub(crate) context: &'a AdmittedContext,
    pub(crate) credential: &'a ExecutionCredential,
    pub(crate) query: &'a BuiltConfluenceSearchQuery,
    pub(crate) requested_spaces: &'a BTreeSet<String>,
    pub(crate) max_results: u32,
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
