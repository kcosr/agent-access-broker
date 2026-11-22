//! Confluence continuations: list page tokens and durable draft
//! handles, sealed in SDK continuation envelopes.
//!
//! Every family binds the admitted service and execution context, the
//! Confluence configuration it depends on and the execution material that
//! reaches Confluence ([`bind_atlassian_access`]: the credential method, a
//! static credential's kind or a delegated lease's binding, and the gateway
//! cloud ID on gateway routes). List tokens bind the Atlassian
//! route fingerprint (tenant host and cloud ID), because they relay
//! Confluence's own route-relative cursors;
//! draft handles bind the tenant host, because a draft's content ID names
//! content on that tenant whichever route of the same method reaches it.
//! Draft handles are read during scope resolution, before the host selects
//! execution material, so they carry a keyed commitment to it that is
//! checked once the handle is opened after admission. No family binds the
//! effective grant boundary: the host authorizes every page and handle use
//! again and the provider re-applies its containment checks. Content search has
//! its own confidential, authority-bound continuation in `content_search.rs`.
//!
//! List tokens relay Confluence's own cursor, so their size is
//! bounded by the provider's upstream response limit, which bounds both the
//! upstream response a cursor arrives in and the result its continuation
//! leaves in; the broker adds no cursor cap of its own and never truncates.
use super::*;

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;

/// How long list continuations stay valid after they are issued.
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
    3,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// `blog.attachment.list` pages, like [`ATTACHMENT_LIST_PAGES`].
const BLOG_ATTACHMENT_LIST_PAGES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "blog-attachment-list-page",
    3,
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
    5,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.owner(ContinuationOwner::PerUserCaller)
.expires_after(PAGE_TOKEN_TTL)
.clock_skew(PAGE_TOKEN_CLOCK_SKEW);

/// The visible prefix of a draft handle.
pub(crate) const DRAFT_HANDLE_PREFIX: &str = "aab_confluence_draft_v5_";
/// A handle's payload: the commitment to the execution material it was
/// minted under, then its facts (a space key of at most 255 bytes, numeric
/// IDs and a version) as compact JSON. Far beyond any real draft.
const DRAFT_HANDLE_PAYLOAD_MAX_BYTES: usize = 4096;
/// The size of a draft handle's execution-material commitment.
const DRAFT_HANDLE_ACCESS_COMMITMENT_BYTES: usize = 32;
/// The label of a draft handle's execution-material commitment.
const DRAFT_HANDLE_ACCESS_COMMITMENT: &str = "executionAccess";

/// Durable draft handles: no expiry, signed only with the stable key, shared
/// across the draft actions, read during scope resolution for the space they
/// name, and owned by the per-user principal that created them (service-mode
/// handles are shared among authorized service-mode principals) under the
/// execution material they were minted with.
const DRAFT_HANDLES: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "draft-handle",
    5,
    ContinuationLifetime::Durable,
    DRAFT_HANDLE_PAYLOAD_MAX_BYTES,
)
.owner(ContinuationOwner::PerUserCaller)
.shared_across_actions()
.opened_during_scope_resolution()
.token_prefix(DRAFT_HANDLE_PREFIX);

/// The exact size of the largest draft handle, which bounds the input.
pub(crate) const DRAFT_HANDLE_MAX_BYTES: usize = DRAFT_HANDLES.max_token_bytes();

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
    cloud_id: Option<String>,
    attachment_pages: ContinuationFamily,
    blog_attachment_pages: ContinuationFamily,
    comment_pages: ContinuationFamily,
    draft_attachment_pages: ContinuationFamily,
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
            route: config.site().route_fingerprint(),
            cloud_id: config.cloud_id.clone(),
            attachment_pages: within_response_limit(ATTACHMENT_LIST_PAGES, limits),
            blog_attachment_pages: within_response_limit(BLOG_ATTACHMENT_LIST_PAGES, limits),
            comment_pages: within_response_limit(COMMENT_LIST_PAGES, limits),
            draft_attachment_pages: within_response_limit(DRAFT_ATTACHMENT_LIST_PAGES, limits),
        }
    }

    /// A list binding: the admitted context, the route
    /// fingerprint and the execution material that selects the route.
    fn route_binding(
        &self,
        family: &ContinuationFamily,
        context: &AdmittedContext,
        access: &ExecutionAccess,
    ) -> Result<ContinuationBinding, ProviderError> {
        bind_atlassian_access(
            family.bind(context, self.route),
            access,
            self.cloud_id.as_deref(),
        )
    }

    fn attachment_binding(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        page: &ConfluencePage,
        max_results: u32,
    ) -> Result<ContinuationBinding, ProviderError> {
        Ok(self
            .route_binding(&self.attachment_pages, context, access)?
            .text("pageId", &page.id)
            .text("space", &page.space)
            .number("maxResults", u64::from(max_results)))
    }

    pub(crate) fn seal_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        page: &ConfluencePage,
        max_results: u32,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.attachment_binding(context, access, page, max_results)?;
        self.seal_list(ListPages::Attachment, &binding, position)
    }

    pub(crate) fn open_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        page: &ConfluencePage,
        max_results: u32,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.attachment_binding(context, access, page, max_results)?;
        let position = self.open_list(ListPages::Attachment, &binding, token)?;
        checked_position(ListPages::Attachment, position)
    }

    fn blog_attachment_binding(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        blog: &ConfluenceBlog,
        max_results: u32,
    ) -> Result<ContinuationBinding, ProviderError> {
        Ok(self
            .route_binding(&self.blog_attachment_pages, context, access)?
            .text("blogId", &blog.id)
            .text("space", &blog.space)
            .text("spaceId", &blog.space_id)
            .number("maxResults", u64::from(max_results)))
    }

    pub(crate) fn seal_blog_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        blog: &ConfluenceBlog,
        max_results: u32,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.blog_attachment_binding(context, access, blog, max_results)?;
        self.seal_list(ListPages::BlogAttachment, &binding, position)
    }

    pub(crate) fn open_blog_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        blog: &ConfluenceBlog,
        max_results: u32,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.blog_attachment_binding(context, access, blog, max_results)?;
        let position = self.open_list(ListPages::BlogAttachment, &binding, token)?;
        checked_position(ListPages::BlogAttachment, position)
    }

    fn comment_binding(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        list: &ConfluenceCommentListBinding,
    ) -> Result<ContinuationBinding, ProviderError> {
        Ok(self
            .route_binding(&self.comment_pages, context, access)?
            .text("commentKind", list.kind.as_str())
            .text("containerType", list.container_type.as_str())
            .text("containerId", &list.container_id)
            .optional_text("commentId", list.comment_id.as_deref())
            .text("space", &list.space)
            .optional_text("bodyFormat", list.body_format.as_deref())
            .optional_text("resolutionStatus", list.resolution_status.as_deref())
            .optional_text("sort", list.sort.as_deref())
            .number("maxResults", u64::from(list.max_results)))
    }

    pub(crate) fn seal_comment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        list: &ConfluenceCommentListBinding,
        cursor: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.comment_binding(context, access, list)?;
        self.seal_list(ListPages::Comment, &binding, cursor)
    }

    pub(crate) fn open_comment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        list: &ConfluenceCommentListBinding,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.comment_binding(context, access, list)?;
        let cursor = self.open_list(ListPages::Comment, &binding, token)?;
        checked_cursor(ListPages::Comment, cursor)
    }

    fn draft_attachment_binding(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        handle: &ConfluenceDraftHandle,
        max_results: u32,
    ) -> Result<ContinuationBinding, ProviderError> {
        Ok(self
            .route_binding(&self.draft_attachment_pages, context, access)?
            .text("contentType", handle.content_type.as_str())
            .text("contentId", &handle.content_id)
            .text("space", &handle.space)
            .text("spaceId", &handle.space_id)
            .text("origin", handle.origin.as_str())
            .optional_text(
                "parentKind",
                handle.parent.as_ref().map(|parent| parent.kind.as_str()),
            )
            .optional_text(
                "parentId",
                handle.parent.as_ref().map(|parent| parent.id.as_str()),
            )
            .optional_number("baseVersion", handle.base_version)
            .number("maxResults", u64::from(max_results)))
    }

    pub(crate) fn seal_draft_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        handle: &ConfluenceDraftHandle,
        max_results: u32,
        position: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.draft_attachment_binding(context, access, handle, max_results)?;
        self.seal_list(ListPages::DraftAttachment, &binding, position)
    }

    pub(crate) fn open_draft_attachment_page(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        handle: &ConfluenceDraftHandle,
        max_results: u32,
        token: &str,
    ) -> Result<String, ProviderError> {
        let binding = self.draft_attachment_binding(context, access, handle, max_results)?;
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

    /// Mints the durable handle for `handle`'s draft, owned as the admitted
    /// credential mode and principal decide and committed to `access`, the
    /// execution material it is minted with.
    pub(crate) fn seal_draft_handle(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        handle: &ConfluenceDraftHandle,
    ) -> Result<String, ProviderError> {
        handle.validate()?;
        let facts =
            serde_json::to_vec(&ConfluenceDraftHandleFacts::from(handle)).map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "failed to encode Confluence draft handle",
                )
            })?;
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind(context, self.route),
            handle.content_type,
            &handle.content_id,
        );
        let mut payload = self
            .signer
            .commit(
                &self.draft_handle_access_binding(&binding, access)?,
                DRAFT_HANDLE_ACCESS_COMMITMENT,
                &[],
            )
            .map_err(draft_handle_failure)?
            .to_vec();
        payload.extend_from_slice(&facts);
        self.signer
            .seal(&binding, &payload)
            .map_err(draft_handle_failure)
    }

    /// The binding a handle's keyed commitment to its execution material
    /// ([`bind_atlassian_access`]) is made under. Scope resolution runs
    /// before the host selects that material, so the handle's own binding
    /// cannot cover it; the commitment is checked when the handle is opened
    /// after admission.
    fn draft_handle_access_binding(
        &self,
        binding: &ContinuationBinding,
        access: &ExecutionAccess,
    ) -> Result<ContinuationBinding, ProviderError> {
        bind_atlassian_access(binding.clone(), access, self.cloud_id.as_deref())
    }

    /// Reads the draft a handle names during scope resolution, for the
    /// content the inputs name. The owner is checked against the current
    /// principal here, and against the admitted credential mode and the
    /// execution material by [`Self::open_draft_handle`].
    pub(crate) fn open_draft_handle_for_local_scope(
        &self,
        request: &LocalScopeRequest<'_>,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        token: &str,
    ) -> Result<ConfluenceDraftHandle, ProviderError> {
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind_local_scope(request, self.route),
            content_type,
            content_id,
        );
        let payload = self
            .signer
            .open_during_scope_resolution(&binding, token)
            .map_err(draft_handle_failure)?;
        let (_, facts) = split_draft_handle_payload(&payload)?;
        ConfluenceDraftHandle::from_facts(content_type, content_id, facts)
    }

    /// Opens a handle after admission: owned by the admitted principal in
    /// per-user mode, or a service-mode handle for a service-mode request,
    /// minted with the same execution material as `access`. Another
    /// credential method, OAuth connection (another account, or a
    /// reconnection) or gateway site rejects the handle; a routine OAuth
    /// refresh keeps it.
    pub(crate) fn open_draft_handle(
        &self,
        context: &AdmittedContext,
        access: &ExecutionAccess,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        token: &str,
    ) -> Result<ConfluenceDraftHandle, ProviderError> {
        let binding = draft_handle_binding(
            DRAFT_HANDLES.bind(context, self.route),
            content_type,
            content_id,
        );
        let payload = self
            .signer
            .open(&binding, token)
            .map_err(draft_handle_failure)?;
        let (commitment, facts) = split_draft_handle_payload(&payload)?;
        self.signer
            .verify_commitment(
                &self.draft_handle_access_binding(&binding, access)?,
                DRAFT_HANDLE_ACCESS_COMMITMENT,
                &[],
                commitment,
            )
            .map_err(draft_handle_failure)?;
        ConfluenceDraftHandle::from_facts(content_type, content_id, facts)
    }
}

/// A handle's payload: its execution-material commitment, then its facts.
fn split_draft_handle_payload(payload: &[u8]) -> Result<(&[u8], &[u8]), ProviderError> {
    if payload.len() < DRAFT_HANDLE_ACCESS_COMMITMENT_BYTES {
        return Err(invalid_draft_handle_error());
    }
    Ok(payload.split_at(DRAFT_HANDLE_ACCESS_COMMITMENT_BYTES))
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

/// What a broker-issued draft handle establishes about its draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfluenceDraftHandle {
    pub(crate) content_type: ConfluenceDraftContentType,
    pub(crate) content_id: String,
    pub(crate) space: String,
    pub(crate) space_id: String,
    pub(crate) origin: ConfluenceDraftOrigin,
    pub(crate) parent: Option<ConfluenceParent>,
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
            parent: content.parent.clone(),
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
        let (space, space_id, origin, parent, base_version) = match (content_type, facts) {
            (
                ConfluenceDraftContentType::Page,
                ConfluenceDraftHandleFacts::Page {
                    space,
                    space_id,
                    origin,
                    parent,
                    base_version,
                },
            ) => (space, space_id, origin, parent, base_version),
            (
                ConfluenceDraftContentType::Blog,
                ConfluenceDraftHandleFacts::Blog {
                    space,
                    space_id,
                    origin,
                    base_version,
                },
            ) => (space, space_id, origin, None, base_version),
            _ => return Err(invalid_draft_handle_error()),
        };
        let handle = Self {
            content_type,
            content_id: content_id.to_owned(),
            space,
            space_id,
            origin,
            parent,
            base_version,
        };
        handle.validate()?;
        Ok(handle)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        let well_formed = is_space_key(&self.space)
            && locations::is_canonical_content_id(&self.space_id)
            && locations::is_canonical_content_id(&self.content_id)
            && self.parent.as_ref().is_none_or(|parent| {
                locations::is_canonical_content_id(&parent.id) && parent.id != self.content_id
            })
            && (self.content_type == ConfluenceDraftContentType::Page || self.parent.is_none())
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
#[serde(
    tag = "contentType",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ConfluenceDraftHandleFacts {
    Page {
        space: String,
        space_id: String,
        origin: ConfluenceDraftOrigin,
        #[serde(deserialize_with = "required_parent")]
        parent: Option<ConfluenceParent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        base_version: Option<u64>,
    },
    Blog {
        space: String,
        space_id: String,
        origin: ConfluenceDraftOrigin,
        #[serde(skip_serializing_if = "Option::is_none")]
        base_version: Option<u64>,
    },
}

fn required_parent<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ConfluenceParent>, D::Error> {
    Option::<ConfluenceParent>::deserialize(deserializer)
}

impl From<&ConfluenceDraftHandle> for ConfluenceDraftHandleFacts {
    fn from(handle: &ConfluenceDraftHandle) -> Self {
        match handle.content_type {
            ConfluenceDraftContentType::Page => Self::Page {
                space: handle.space.clone(),
                space_id: handle.space_id.clone(),
                origin: handle.origin,
                parent: handle.parent.clone(),
                base_version: handle.base_version,
            },
            ConfluenceDraftContentType::Blog => Self::Blog {
                space: handle.space.clone(),
                space_id: handle.space_id.clone(),
                origin: handle.origin,
                base_version: handle.base_version,
            },
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
    ContinuationFailures::new(
        invalid_draft_handle_error(),
        |_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "failed to encode Confluence draft handle",
            )
        },
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft signing key is unavailable",
        ),
    )
    .durable_key_unavailable(ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence draft actions require broker_tokens.hash_key_ref",
    ))
    .report(error)
}

fn list_token_failure(pages: ListPages, error: ContinuationError) -> ProviderError {
    let label = pages.label();
    ContinuationFailures::new(
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!(
                "Confluence {label} pagination token is invalid or does not match this request"
            ),
        ),
        |_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                format!(
                    "Confluence {label} pagination position exceeds the provider response limit"
                ),
            )
        },
        pagination_signing_unavailable(),
    )
    .expired(ProviderError::deny(
        ReasonCode::InputInvalid,
        format!("Confluence {label} pagination token is expired"),
    ))
    .report(error)
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

fn pagination_signing_unavailable() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence pagination signing key is unavailable",
    )
}
