//! Search continuations: Jira's upstream `nextPageToken`, sealed in an SDK
//! continuation envelope bound to the search that issued it.
//!
//! The binding covers the admitted context (service, action, execution
//! context, credential mode, principal and whether it authenticated), the
//! Atlassian route fingerprint of the Jira configuration the upstream token
//! depends on, the credential kind that selects the upstream route, and the normalized caller inputs: query type,
//! canonical caller JQL, requested projects and effective `maxResults`. The
//! effective project boundary is deliberately not bound: every page is
//! authorized again and composed under the current boundary. Jira's token is
//! relayed with the SDK's keyed commitment to the composed upstream JQL
//! ([`ContinuationSigner::seal_relayed`]), so a token whose upstream query no
//! longer matches the current composition is rejected before Jira sees it,
//! never replayed against a different query.
use super::*;

/// How long a search continuation stays valid after it is issued.
const JIRA_SEARCH_PAGE_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Search pages: Jira's upstream token, relayed with a commitment to the
/// composed upstream JQL. Tokens expire 15 minutes after they are issued and
/// are signed with a key generated for each provider instance, so a reload or
/// restart also invalidates them. Declared without a payload cap;
/// [`SearchPages::new`] sizes it from the response cap.
const JIRA_SEARCH_PAGES: ContinuationFamily = ContinuationFamily::new(
    "jira",
    "search-page",
    1,
    ContinuationLifetime::Generation,
    0,
)
.expires_after(JIRA_SEARCH_PAGE_TOKEN_TTL);

/// One provider instance's search continuations: the family, with its
/// payload cap derived from the configured limits, and the instance's
/// generation key.
#[derive(Debug, Clone)]
pub(crate) struct SearchPages {
    family: ContinuationFamily,
    signer: ContinuationSigner,
}

impl SearchPages {
    /// Jira documents no maximum `nextPageToken` size, so the broker adds no
    /// Jira-specific limit. The bound comes from the existing response
    /// contract: `limits.max_upstream_response_bytes` bounds the search
    /// response Jira's token arrives in and the provider result the
    /// continuation is returned in, so the largest continuation is the
    /// largest that fits within that cap. The family is
    /// [`ContinuationLifetime::Generation`], so the signer needs no host
    /// stable key.
    pub(crate) fn new(limits: &ProviderLimits) -> Self {
        let cap = usize::try_from(limits.max_upstream_response_bytes).unwrap_or(usize::MAX);
        Self {
            family: JIRA_SEARCH_PAGES
                .with_max_payload_bytes(JIRA_SEARCH_PAGES.max_payload_bytes_within(cap)),
            signer: ContinuationSigner::new(None),
        }
    }

    /// The longest upstream token a continuation carries.
    #[cfg(test)]
    pub(crate) fn max_upstream_token_bytes(&self) -> usize {
        self.family
            .max_payload_bytes()
            .saturating_sub(UPSTREAM_QUERY_COMMITMENT_BYTES)
    }

    /// The encoded size of the largest continuation.
    #[cfg(test)]
    pub(crate) fn max_token_bytes(&self) -> usize {
        self.family.max_token_bytes()
    }
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

    /// Seals Jira's `upstream` token for this search, issued at `now`,
    /// with a commitment to the composed JQL it continues.
    pub(crate) fn seal(
        &self,
        pages: &SearchPages,
        upstream: &str,
        now: SystemTime,
    ) -> Result<String, ProviderError> {
        pages
            .signer
            .seal_relayed_at(
                &self.bind(&pages.family),
                Some(self.query.jql.as_bytes()),
                upstream,
                now,
            )
            .map_err(search_page_token_failure)
    }

    /// Opens a continuation issued for this search and unexpired at `now`,
    /// and returns Jira's upstream token, provided the current composed JQL
    /// is the one the upstream token was issued for.
    pub(crate) fn open(
        &self,
        pages: &SearchPages,
        token: &str,
        now: SystemTime,
    ) -> Result<String, ProviderError> {
        pages
            .signer
            .open_relayed_at(
                &self.bind(&pages.family),
                Some(self.query.jql.as_bytes()),
                token,
                now,
            )
            .map_err(search_page_token_failure)
    }
}

pub(crate) fn search_page_token_invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "jira.search nextPageToken is invalid or expired; reuse it only with the same query, projects, and maxResults",
    )
}

fn search_page_token_failure(error: ContinuationError) -> ProviderError {
    if error == ContinuationError::UpstreamQueryChanged {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "the effective Jira project scope changed since nextPageToken was issued; repeat the search without nextPageToken",
        )
    } else if let ContinuationError::PayloadTooLarge { limit } = error {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            format!("Jira returned a nextPageToken longer than the broker's {limit}-byte limit"),
        )
    } else if error.is_token_rejection() {
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

    fn limited(max_upstream_response_bytes: u64) -> SearchPages {
        SearchPages::new(
            &ProviderLimits::default()
                .with_max_upstream_response_bytes(max_upstream_response_bytes),
        )
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
                request: InvocationBuilder::new("jira", "search")
                    .principal("agent-one")
                    .credential_mode(CredentialMode::PerUser)
                    .build(),
                configuration: config.site().route_fingerprint(),
                credential: basic_credential("agent@example.com", "token"),
                query: query(scope),
                requested: BTreeSet::new(),
            }
        }

        fn search(&self) -> SearchPageRequest<'_> {
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
    fn the_upstream_token_cap_is_the_configured_response_cap() {
        assert_eq!(
            JIRA_SEARCH_PAGES.time_to_live(),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            JIRA_SEARCH_PAGES.lifetime(),
            ContinuationLifetime::Generation
        );
        // The default response cap, 512 MiB, is far above the envelope's
        // 64 KiB ceiling for provider-built payloads; the largest
        // continuation is exactly the cap.
        let default = SearchPages::new(&ProviderLimits::default());
        assert_eq!(default.max_token_bytes(), 512 * 1024 * 1024);
        assert_eq!(
            default.max_upstream_token_bytes(),
            384 * 1024 * 1024 - 41 - UPSTREAM_QUERY_COMMITMENT_BYTES
        );
        let fixture = Fixture::new(&["PROJ"]);
        let beyond_ceiling = "u".repeat(100 * 1024);
        let token = fixture
            .search()
            .seal(&default, &beyond_ceiling, now())
            .unwrap();
        assert_eq!(
            fixture.search().open(&default, &token, now()).unwrap(),
            beyond_ceiling
        );

        // With a smaller response cap, the largest token fits exactly: 1
        // version byte, an 8-byte expiry, the 32-byte query commitment, the
        // token and a 32-byte MAC are 3072 raw bytes, which encode to 4096
        // characters of unpadded URL-safe base64.
        let pages = limited(4096);
        assert_eq!(pages.max_upstream_token_bytes(), 3072 - 41 - 32);
        assert_eq!(pages.max_token_bytes(), 4096);
        let largest = "u".repeat(pages.max_upstream_token_bytes());
        let token = fixture.search().seal(&pages, &largest, now()).unwrap();
        assert_eq!(token.len(), pages.max_token_bytes());
        assert_eq!(
            fixture.search().open(&pages, &token, now()).unwrap(),
            largest
        );
        // An empty upstream token still round-trips exactly: 73 raw bytes
        // (version, expiry, commitment, MAC) encode to 98 characters.
        let empty = fixture.search().seal(&pages, "", now()).unwrap();
        assert_eq!(empty.len(), 98);
        assert_eq!(fixture.search().open(&pages, &empty, now()).unwrap(), "");
    }

    #[test]
    fn the_largest_continuation_is_the_largest_that_fits_the_response_cap() {
        for cap in (0..=200).chain([4093, 4094, 4095, 4096, 1 << 20, u64::MAX]) {
            let pages = limited(cap);
            let cap = usize::try_from(cap).unwrap_or(usize::MAX);
            if pages.family.max_payload_bytes() == 0 {
                // Even an empty envelope is 55 characters.
                assert!(cap <= 55, "{cap}");
                continue;
            }
            assert!(pages.max_token_bytes() <= cap, "{cap}");
            if cap < usize::MAX {
                let larger = JIRA_SEARCH_PAGES
                    .with_max_payload_bytes(pages.family.max_payload_bytes() + 1)
                    .max_token_bytes();
                assert!(larger > cap, "{cap}");
            }
        }
        // A cap too small for an envelope relays no upstream token: even an
        // empty one fails explicitly.
        let tiny = limited(64);
        assert_eq!(tiny.max_upstream_token_bytes(), 0);
        let error = Fixture::new(&["PROJ"])
            .search()
            .seal(&limited(0), "", now())
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(error.message.contains("0-byte limit"), "{}", error.message);
    }

    #[test]
    fn oversized_tokens_are_rejected_and_never_truncated() {
        let fixture = Fixture::new(&["PROJ"]);
        let pages = limited(4096);
        let limit = pages.max_upstream_token_bytes();
        let error = fixture
            .search()
            .seal(&pages, &"u".repeat(limit + 1), now())
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.decision(), Decision::Error);
        assert!(
            error.message.contains(&format!("{limit}-byte limit")),
            "{}",
            error.message
        );
        assert!(!error.message.contains("uuuu"));

        // A presented continuation longer than the largest one is rejected
        // before it is decoded, including one sealed under a larger cap.
        let larger = limited(8192);
        let token = fixture
            .search()
            .seal(
                &larger,
                &"u".repeat(larger.max_upstream_token_bytes()),
                now(),
            )
            .unwrap();
        assert!(token.len() > pages.max_token_bytes());
        assert_eq!(
            fixture
                .search()
                .open(&pages, &token, now())
                .unwrap_err()
                .message,
            search_page_token_invalid().message
        );
    }

    #[test]
    fn search_tokens_expire_fifteen_minutes_after_issue() {
        let fixture = Fixture::new(&["PROJ"]);
        let pages = limited(4096);
        let issued = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let token = fixture.search().seal(&pages, "upstream", issued).unwrap();
        let open = |offset: i64| {
            let at = if offset < 0 {
                issued - Duration::from_secs(offset.unsigned_abs())
            } else {
                issued + Duration::from_secs(offset.unsigned_abs())
            };
            fixture.search().open(&pages, &token, at)
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
        let pages = limited(4096);
        let search = fixture.search();
        let payload_cap = pages.family.max_payload_bytes();
        for family in [
            ContinuationFamily::new("jira", "issue-page", 1, ContinuationLifetime::Generation, 0),
            ContinuationFamily::new(
                "confluence",
                "search-page",
                1,
                ContinuationLifetime::Generation,
                0,
            ),
            ContinuationFamily::new(
                "jira",
                "search-page",
                2,
                ContinuationLifetime::Generation,
                0,
            ),
        ] {
            let family = family
                .expires_after(JIRA_SEARCH_PAGE_TOKEN_TTL)
                .with_max_payload_bytes(payload_cap);
            let foreign = pages
                .signer
                .seal_relayed(
                    &search.bind(&family),
                    Some(fixture.query.jql.as_bytes()),
                    "upstream",
                )
                .unwrap();
            let error = search.open(&pages, &foreign, now()).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{family:?}");
            assert_eq!(error.decision(), Decision::Deny);
            assert_eq!(error.message, search_page_token_invalid().message);
        }
        // Another provider instance (a reload) has another generation key.
        let token = search.seal(&pages, "upstream", now()).unwrap();
        assert_eq!(
            search
                .open(&limited(4096), &token, now())
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
            search.open(&pages, &tampered, now()).unwrap_err().message,
            search_page_token_invalid().message
        );
    }

    #[test]
    fn a_recomposed_upstream_query_rejects_the_upstream_token() {
        let pages = limited(4096);
        let issued = Fixture::new(&["PROJ"]);
        let token = issued.search().seal(&pages, "upstream", now()).unwrap();
        // The same caller query composed under another boundary binds the
        // same continuation, but its upstream token belongs to the old query.
        let narrowed = Fixture::new(&["OPS_TOOLS", "PROJ"]);
        assert_eq!(
            issued.query.canonical_caller_jql,
            narrowed.query.canonical_caller_jql
        );
        assert_ne!(issued.query.jql, narrowed.query.jql);
        let error = narrowed.search().open(&pages, &token, now()).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), Decision::Deny);
        assert!(
            error.message.contains("project scope changed"),
            "{}",
            error.message
        );
        assert_eq!(
            issued.search().open(&pages, &token, now()).unwrap(),
            "upstream"
        );
    }
}
