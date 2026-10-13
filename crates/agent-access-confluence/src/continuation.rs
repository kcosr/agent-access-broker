//! Confluence continuations: `search` and `blog.search` page tokens, sealed
//! in SDK continuation envelopes.
//!
//! Search continuations relay Confluence's own cursor. They bind the admitted
//! service, action, execution context and caller, the normalized search, the
//! route fingerprint (tenant host, gateway cloud ID and whether the gateway
//! is enabled) and the credential kind that selects the tenant or gateway
//! route, because Confluence's cursor is route-relative. They never bind the
//! effective grant boundary: the host authorizes every page again and the
//! provider composes and checks it under the current boundary.
//!
//! The broker adds no cursor cap of its own and never truncates: the family
//! is bounded by the provider's upstream response limit, which bounds both
//! the upstream response a cursor arrives in and the result its continuation
//! leaves in.
use super::*;

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;

/// How long search continuations stay valid after they are issued.
const PAGE_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

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
    search_pages: ContinuationFamily,
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
            search_pages: within_response_limit(SEARCH_PAGES, limits),
        }
    }

    /// A search binding: the admitted context, the route
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
