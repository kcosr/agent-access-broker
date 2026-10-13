//! Search continuations: Jira's upstream `nextPageToken`, sealed in an SDK
//! continuation envelope bound to the search that issued it.
//!
//! The binding covers the admitted context (service, action, execution
//! context, credential mode, principal and whether it authenticated), the
//! Jira configuration the upstream token depends on, the credential kind that
//! selects the upstream route, and the normalized caller inputs: query type,
//! canonical caller JQL, requested projects and effective `maxResults`. The
//! effective project boundary is deliberately not bound: every page is
//! authorized again and composed under the current boundary. The payload
//! carries a keyed commitment to the composed upstream JQL beside the
//! upstream token, so a token whose upstream query no longer matches the
//! current composition is rejected before Jira sees it, never replayed against
//! a different query.
use super::*;

/// The longest upstream `nextPageToken` the broker relays. Jira does not
/// document a maximum, and observed tokens are short opaque strings. The
/// broker returns the token to Jira in the query string of its
/// `GET search/jql` request, beside the composed JQL (raw caller JQL alone
/// may be [`MAX_JIRA_RAW_QUERY_BYTES`]), so a token Jira can accept back is
/// bounded by upstream request-URL limits on the order of 8 KiB. 16 KiB is
/// twice that ceiling. A longer token is an upstream protocol failure, never
/// truncated.
pub(crate) const JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES: usize = 16 * 1024;
const UPSTREAM_QUERY_COMMITMENT_BYTES: usize = 32;
const UPSTREAM_QUERY_LABEL: &str = "upstreamJql";

/// How long a search continuation stays valid after it is issued.
const JIRA_SEARCH_PAGE_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Search pages: a commitment to the composed upstream JQL followed by
/// Jira's upstream token. Tokens expire 15 minutes after they are issued and
/// are signed with a key generated for each provider instance, so a reload or
/// restart also invalidates them.
const JIRA_SEARCH_PAGES: ContinuationFamily = ContinuationFamily::new(
    "jira",
    "search-page",
    1,
    ContinuationLifetime::Generation,
    UPSTREAM_QUERY_COMMITMENT_BYTES + JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES,
)
.expires_after(JIRA_SEARCH_PAGE_TOKEN_TTL);

/// The exact encoded size of the largest search continuation, which bounds
/// the `nextPageToken` input.
pub(crate) const JIRA_SEARCH_PAGE_TOKEN_MAX_BYTES: usize = JIRA_SEARCH_PAGES.max_token_bytes();

/// The fingerprint of the configuration an upstream token depends on: the
/// tenant, the gateway cloud ID and whether the gateway route is enabled.
pub(crate) fn search_configuration_fingerprint(config: &JiraProviderConfig) -> [u8; 32] {
    let fields = json!({
        "tenantHost": config.tenant_host,
        "cloudId": config.cloud_id,
        "gateway": agent_access_atlassian::uses_atlassian_gateway_host(&config.allowed_upstream_hosts),
    });
    Sha256::digest(fields.to_string().as_bytes()).into()
}

/// The normalized search a continuation belongs to.
pub(crate) struct SearchPageRequest<'a> {
    pub(crate) request: &'a ProviderInvocation,
    pub(crate) configuration: &'a [u8; 32],
    pub(crate) credential: &'a ExecutionCredential,
    pub(crate) query: &'a BuiltJiraSearchQuery,
    pub(crate) requested_projects: &'a BTreeSet<String>,
    pub(crate) max_results: u32,
}

impl SearchPageRequest<'_> {
    fn binding(&self) -> ContinuationBinding {
        self.bind(&JIRA_SEARCH_PAGES)
    }

    fn bind(&self, family: &ContinuationFamily) -> ContinuationBinding {
        family
            .bind(self.request.context(), self.configuration)
            .text("credentialKind", self.credential.kind().as_str())
            .text("queryType", self.query.kind)
            .text("query", &self.query.canonical_caller_jql)
            .texts(
                "projects",
                self.requested_projects.iter().map(String::as_str),
            )
            .number("maxResults", u64::from(self.max_results))
    }

    /// Seals Jira's `upstream` token for this search, issued at `now`.
    pub(crate) fn seal(
        &self,
        signer: &ContinuationSigner,
        upstream: &str,
        now: SystemTime,
    ) -> Result<String, ProviderError> {
        if upstream.len() > JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                format!(
                    "Jira returned a nextPageToken longer than the broker's {JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES}-byte limit"
                ),
            ));
        }
        let binding = self.binding();
        let commitment = signer
            .commit(&binding, UPSTREAM_QUERY_LABEL, self.query.jql.as_bytes())
            .map_err(search_page_token_failure)?;
        let mut payload = Vec::with_capacity(commitment.len() + upstream.len());
        payload.extend_from_slice(&commitment);
        payload.extend_from_slice(upstream.as_bytes());
        signer
            .seal_at(&binding, &payload, now)
            .map_err(search_page_token_failure)
    }

    /// Opens a continuation issued for this search and unexpired at `now`,
    /// and returns Jira's upstream token, provided the current composed JQL
    /// is the one the upstream token was issued for.
    pub(crate) fn open(
        &self,
        signer: &ContinuationSigner,
        token: &str,
        now: SystemTime,
    ) -> Result<String, ProviderError> {
        let binding = self.binding();
        let payload = signer
            .open_at(&binding, token, now)
            .map_err(search_page_token_failure)?;
        if payload.len() < UPSTREAM_QUERY_COMMITMENT_BYTES {
            return Err(search_page_token_invalid());
        }
        let (commitment, upstream) = payload.split_at(UPSTREAM_QUERY_COMMITMENT_BYTES);
        match signer.verify_commitment(
            &binding,
            UPSTREAM_QUERY_LABEL,
            self.query.jql.as_bytes(),
            commitment,
        ) {
            Ok(()) => {}
            Err(ContinuationError::Invalid) => {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "the effective Jira project scope changed since nextPageToken was issued; repeat the search without nextPageToken",
                ));
            }
            Err(error) => return Err(search_page_token_failure(error)),
        }
        String::from_utf8(upstream.to_vec()).map_err(|_| search_page_token_invalid())
    }
}

pub(crate) fn search_page_token_invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "jira.search nextPageToken is invalid or expired; reuse it only with the same query, projects, and maxResults",
    )
}

fn search_page_token_failure(error: ContinuationError) -> ProviderError {
    if error.is_token_rejection() {
        search_page_token_invalid()
    } else {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira search continuation signing is unavailable",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{InvocationBuilder, basic_credential};
    use std::time::UNIX_EPOCH;

    fn now() -> SystemTime {
        SystemTime::now()
    }

    fn invocation() -> ProviderInvocation {
        InvocationBuilder::new("jira", "search")
            .principal("agent-one")
            .credential_mode(CredentialMode::PerUser)
            .build()
    }

    fn query(scope: &[&str]) -> BuiltJiraSearchQuery {
        build_jira_search_query(
            &JiraSearchQueryInput::Jql {
                value: "status = Done ORDER BY updated DESC".to_string(),
            },
            &EffectiveSearchScope::Finite(scope.iter().map(ToString::to_string).collect()),
            &SearchLimitsConfig::default(),
            CredentialMode::PerUser,
        )
        .unwrap()
    }

    struct Fixture {
        request: ProviderInvocation,
        configuration: [u8; 32],
        credential: ExecutionCredential,
        query: BuiltJiraSearchQuery,
        requested: BTreeSet<String>,
    }

    impl Fixture {
        fn new(scope: &[&str]) -> Self {
            let config = JiraProviderConfig {
                tenant_host: "example.atlassian.net".to_string(),
                cloud_id: None,
                egress_proxy: None,
                allowed_upstream_hosts: vec![],
                attachments: AttachmentLimitsConfig::default(),
                content: JiraContentConfig::default(),
                search: SearchLimitsConfig::default(),
                comments: JiraCommentsConfig::default(),
                issue_links: JiraIssueLinksConfig::default(),
            };
            Self {
                request: invocation(),
                configuration: search_configuration_fingerprint(&config),
                credential: basic_credential("agent@example.com", "token"),
                query: query(scope),
                requested: BTreeSet::new(),
            }
        }

        fn pages(&self) -> SearchPageRequest<'_> {
            SearchPageRequest {
                request: &self.request,
                configuration: &self.configuration,
                credential: &self.credential,
                query: &self.query,
                requested_projects: &self.requested,
                max_results: 50,
            }
        }
    }

    #[test]
    fn the_token_cap_is_the_exact_size_of_the_largest_upstream_token() {
        // 1 version byte, an 8-byte expiry, a 32-byte query commitment, the
        // 16 KiB upstream token and a 32-byte MAC, in unpadded URL-safe
        // base64.
        assert_eq!(JIRA_SEARCH_PAGES.max_payload_bytes(), 32 + 16 * 1024);
        assert_eq!(
            JIRA_SEARCH_PAGES.time_to_live(),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            JIRA_SEARCH_PAGES.lifetime(),
            ContinuationLifetime::Generation
        );
        assert_eq!(JIRA_SEARCH_PAGE_TOKEN_MAX_BYTES, 21_943);
        let fixture = Fixture::new(&["PROJ"]);
        let signer = ContinuationSigner::new(None);
        let largest = "u".repeat(JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES);
        let token = fixture.pages().seal(&signer, &largest, now()).unwrap();
        assert_eq!(token.len(), JIRA_SEARCH_PAGE_TOKEN_MAX_BYTES);
        assert_eq!(
            fixture.pages().open(&signer, &token, now()).unwrap(),
            largest
        );
        // An empty upstream token still round-trips exactly.
        let empty = fixture.pages().seal(&signer, "", now()).unwrap();
        assert_eq!(fixture.pages().open(&signer, &empty, now()).unwrap(), "");
        // 73 raw bytes (version, expiry, commitment, MAC) encode to 98
        // characters.
        assert_eq!(empty.len(), 98);
    }

    #[test]
    fn search_tokens_expire_fifteen_minutes_after_issue() {
        let fixture = Fixture::new(&["PROJ"]);
        let signer = ContinuationSigner::new(None);
        let issued = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let token = fixture.pages().seal(&signer, "upstream", issued).unwrap();
        let open = |offset: i64| {
            let at = if offset < 0 {
                issued - Duration::from_secs(offset.unsigned_abs())
            } else {
                issued + Duration::from_secs(offset.unsigned_abs())
            };
            fixture.pages().open(&signer, &token, at)
        };
        assert_eq!(open(899).unwrap(), "upstream");
        for offset in [900, 3_600, -1] {
            assert_eq!(
                open(offset).unwrap_err().message,
                search_page_token_invalid().message,
                "{offset}"
            );
        }
    }

    #[test]
    fn other_families_versions_and_instances_cannot_open_search_tokens() {
        let fixture = Fixture::new(&["PROJ"]);
        let signer = ContinuationSigner::new(None);
        let pages = fixture.pages();
        let payload_cap = JIRA_SEARCH_PAGES.max_payload_bytes();
        for family in [
            ContinuationFamily::new(
                "jira",
                "issue-page",
                1,
                ContinuationLifetime::Generation,
                payload_cap,
            ),
            ContinuationFamily::new(
                "confluence",
                "search-page",
                1,
                ContinuationLifetime::Generation,
                payload_cap,
            ),
            ContinuationFamily::new(
                "jira",
                "search-page",
                2,
                ContinuationLifetime::Generation,
                payload_cap,
            ),
        ] {
            let binding = pages.bind(&family);
            let commitment = signer
                .commit(&binding, UPSTREAM_QUERY_LABEL, fixture.query.jql.as_bytes())
                .unwrap();
            let mut payload = commitment.to_vec();
            payload.extend_from_slice(b"upstream");
            let foreign = signer.seal(&binding, &payload).unwrap();
            let error = pages.open(&signer, &foreign, now()).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{family:?}");
            assert_eq!(error.decision(), Decision::Deny);
            assert_eq!(error.message, search_page_token_invalid().message);
        }
        // Another provider instance (a reload) has another generation key.
        let token = pages.seal(&signer, "upstream", now()).unwrap();
        assert_eq!(
            pages
                .open(&ContinuationSigner::new(None), &token, now())
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
        // Tampering anywhere is rejected.
        let mut tampered = token.clone().into_bytes();
        let middle = tampered.len() / 2;
        tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(
            pages.open(&signer, &tampered, now()).unwrap_err().message,
            search_page_token_invalid().message
        );
    }

    #[test]
    fn a_recomposed_upstream_query_rejects_the_upstream_token() {
        let signer = ContinuationSigner::new(None);
        let issued = Fixture::new(&["PROJ"]);
        let token = issued.pages().seal(&signer, "upstream", now()).unwrap();
        // The same caller query composed under another boundary binds the
        // same continuation, but its upstream token belongs to the old query.
        let narrowed = Fixture::new(&["OPS_TOOLS", "PROJ"]);
        assert_eq!(
            issued.query.canonical_caller_jql,
            narrowed.query.canonical_caller_jql
        );
        assert_ne!(issued.query.jql, narrowed.query.jql);
        let error = narrowed.pages().open(&signer, &token, now()).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), Decision::Deny);
        assert!(
            error.message.contains("project scope changed"),
            "{}",
            error.message
        );
        assert_eq!(
            issued.pages().open(&signer, &token, now()).unwrap(),
            "upstream"
        );
    }

    #[test]
    fn oversized_upstream_tokens_are_upstream_failures_never_truncated() {
        let fixture = Fixture::new(&["PROJ"]);
        let signer = ContinuationSigner::new(None);
        let oversized = "u".repeat(JIRA_UPSTREAM_PAGE_TOKEN_MAX_BYTES + 1);
        let error = fixture
            .pages()
            .seal(&signer, &oversized, now())
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.decision(), Decision::Error);
        assert!(!error.message.contains("uuuu"));
    }
}
