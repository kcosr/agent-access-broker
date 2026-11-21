//! `[providers.confluence]` configuration, validation, and registration.
use super::*;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfluenceProviderConfig {
    pub tenant_host: String,
    pub cloud_id: Option<String>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub attachments: AttachmentLimitsConfig,
    #[serde(default)]
    pub content: ConfluenceContentConfig,
    #[serde(default)]
    pub search: SearchLimitsConfig,
    #[serde(default)]
    pub listing: ConfluenceListingConfig,
    #[serde(default)]
    pub content_access: ConfluenceContentAccessConfig,
    #[serde(default)]
    pub content_search: ConfluenceContentSearchConfig,
}

/// Operation-wide limits for current content-location evidence.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfluenceContentAccessConfig {
    pub max_metadata_requests: u32,
    pub max_metadata_bytes: u64,
}

impl Default for ConfluenceContentAccessConfig {
    fn default() -> Self {
        Self {
            max_metadata_requests: 1024,
            max_metadata_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Work limits for a page or blog search, including content-location proofs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfluenceContentSearchConfig {
    pub max_candidate_pages: u32,
    pub max_candidates: u32,
    pub max_upstream_requests: u32,
    pub max_scan_bytes: u64,
    /// Operator request-target ceiling; the HTTP client's URI cap also applies.
    pub max_encoded_request_target_bytes: u32,
}

impl Default for ConfluenceContentSearchConfig {
    fn default() -> Self {
        Self {
            max_candidate_pages: 4,
            max_candidates: 100,
            max_upstream_requests: 1024,
            max_scan_bytes: 32 * 1024 * 1024,
            max_encoded_request_target_bytes: 4096,
        }
    }
}

/// Work limits for live space enumeration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfluenceListingConfig {
    pub max_results: u32,
    pub max_candidate_pages: u32,
    pub max_upstream_requests: u32,
    pub max_scan_bytes: u64,
}

impl Default for ConfluenceListingConfig {
    fn default() -> Self {
        Self {
            max_results: 50,
            max_candidate_pages: 4,
            max_upstream_requests: 8,
            max_scan_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ConfluenceProviderConfig {
    /// The Atlassian site this configuration routes by.
    pub(crate) fn site(&self) -> agent_access_atlassian::AtlassianSite<'_> {
        agent_access_atlassian::AtlassianSite {
            tenant_host: &self.tenant_host,
            cloud_id: self.cloud_id.as_deref(),
            egress_proxy: self.egress_proxy.as_ref(),
            allowed_upstream_hosts: &self.allowed_upstream_hosts,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfluenceContentConfig {
    #[serde(default)]
    pub page_formats: Vec<String>,
    #[serde(default = "default_confluence_blog_formats")]
    pub blog_formats: Vec<String>,
    #[serde(default = "default_confluence_comment_formats")]
    pub comment_formats: Vec<String>,
    #[serde(default = "default_confluence_body_max_bytes")]
    pub max_body_bytes: u64,
}

impl Default for ConfluenceContentConfig {
    fn default() -> Self {
        Self {
            page_formats: vec![],
            blog_formats: default_confluence_blog_formats(),
            comment_formats: default_confluence_comment_formats(),
            max_body_bytes: default_confluence_body_max_bytes(),
        }
    }
}

pub(crate) fn default_confluence_blog_formats() -> Vec<String> {
    vec!["storage".to_string()]
}

pub(crate) fn default_confluence_comment_formats() -> Vec<String> {
    vec!["storage".to_string()]
}

pub(crate) fn default_confluence_body_max_bytes() -> u64 {
    2 * 1024 * 1024
}

pub static CONFLUENCE_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "confluence",
    parse_backend_config::<ConfluenceProviderConfig>,
)
.with_resource_types(&[&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
.with_domain_reasons(&[&UPDATE_CONFLICT]);

impl BackendConfig for ConfluenceProviderConfig {
    fn kind(&self) -> &'static str {
        "confluence"
    }

    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        validate_tenant_host(
            "providers.confluence.tenant_host",
            &self.tenant_host,
            errors,
        );
        validate_egress_proxy_config(
            "providers.confluence.egress_proxy",
            self.egress_proxy.as_ref(),
            errors,
        );
        validate_upstream_allowlist(
            "providers.confluence.allowed_upstream_hosts",
            &self.allowed_upstream_hosts,
            true,
            errors,
        );
        validate_atlassian_routes(
            crate::backend::CONFLUENCE_PRODUCT,
            &self.site(),
            context.credentials,
            errors,
        );
        validate_attachment_limits(
            "providers.confluence.attachments",
            &self.attachments,
            errors,
        );
        if self.content.max_body_bytes == 0 {
            errors.push("providers.confluence.content.max_body_bytes must be non-zero".to_string());
        }
        validate_formats_allow_empty(
            "providers.confluence.content.page_formats",
            &self.content.page_formats,
            &["atlas_doc_format", "storage"],
            errors,
        );
        validate_formats_allow_empty(
            "providers.confluence.content.blog_formats",
            &self.content.blog_formats,
            &["storage"],
            errors,
        );
        validate_formats_allow_empty(
            "providers.confluence.content.comment_formats",
            &self.content.comment_formats,
            &["storage"],
            errors,
        );
        if self.search.max_results == 0 {
            errors.push("providers.confluence.search.max_results must be non-zero".to_string());
        }
        validate_content_access_limits(&self.content_access, &self.content_search, errors);
        if self.listing.max_results == 0 || self.listing.max_results > 100 {
            errors.push("providers.confluence.listing.max_results must be in 1..=100".into());
        }
        if self.listing.max_candidate_pages == 0
            || self.listing.max_upstream_requests == 0
            || self.listing.max_scan_bytes == 0
        {
            errors.push(
                "providers.confluence.listing page, request, and byte limits must be non-zero"
                    .into(),
            );
        }
        validate_provider_limit_relation("confluence", &self.attachments, context.limits, errors);
    }

    fn descriptor(&self) -> ServiceDescriptor {
        confluence_descriptor(self)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| ("providers.confluence.egress_proxy".to_string(), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(ConfluenceProvider::new(self.clone(), host)?))
    }
}

fn validate_content_access_limits(
    access: &ConfluenceContentAccessConfig,
    search: &ConfluenceContentSearchConfig,
    errors: &mut Vec<String>,
) {
    if !(512..=65534).contains(&search.max_encoded_request_target_bytes) {
        errors.push("providers.confluence.content_search.max_encoded_request_target_bytes must be in 512..=65534".into());
    }
    for (name, value, maximum) in [
        (
            "content_access.max_metadata_requests",
            u64::from(access.max_metadata_requests),
            4096,
        ),
        (
            "content_access.max_metadata_bytes",
            access.max_metadata_bytes,
            256 * 1024 * 1024,
        ),
        (
            "content_search.max_candidate_pages",
            u64::from(search.max_candidate_pages),
            64,
        ),
        (
            "content_search.max_candidates",
            u64::from(search.max_candidates),
            1000,
        ),
        (
            "content_search.max_upstream_requests",
            u64::from(search.max_upstream_requests),
            4096,
        ),
        (
            "content_search.max_scan_bytes",
            search.max_scan_bytes,
            256 * 1024 * 1024,
        ),
    ] {
        if !(1..=maximum).contains(&value) {
            errors.push(format!(
                "providers.confluence.{name} must be in 1..={maximum}"
            ));
        }
    }
}

#[cfg(test)]
mod content_limit_tests {
    use super::*;

    #[test]
    fn content_proof_and_search_limits_preserve_defaults_and_reject_unknown_fields() {
        let access: ConfluenceContentAccessConfig = serde_json::from_value(json!({})).unwrap();
        let search: ConfluenceContentSearchConfig = serde_json::from_value(json!({})).unwrap();
        let mut errors = Vec::new();
        validate_content_access_limits(&access, &search, &mut errors);
        assert!(errors.is_empty());
        assert_eq!(access.max_metadata_requests, 1024);
        assert_eq!(search.max_candidates, 100);
        assert!(
            serde_json::from_value::<ConfluenceContentAccessConfig>(json!({"unknown": 1})).is_err()
        );
        assert!(
            serde_json::from_value::<ConfluenceContentSearchConfig>(json!({"unknown": 1})).is_err()
        );
    }

    #[test]
    fn content_limits_accept_low_and_high_bounds_but_reject_zero_and_overflow() {
        for (requests, bytes, pages, candidates, expected_errors) in [
            (1, 1, 1, 1, 0),
            (4096, 256 * 1024 * 1024, 64, 1000, 0),
            (0, 0, 0, 0, 6),
            (4097, 256 * 1024 * 1024 + 1, 65, 1001, 6),
        ] {
            let mut errors = Vec::new();
            validate_content_access_limits(
                &ConfluenceContentAccessConfig {
                    max_metadata_requests: requests,
                    max_metadata_bytes: bytes,
                },
                &ConfluenceContentSearchConfig {
                    max_candidate_pages: pages,
                    max_candidates: candidates,
                    max_upstream_requests: requests,
                    max_scan_bytes: bytes,
                    max_encoded_request_target_bytes: 4096,
                },
                &mut errors,
            );
            assert_eq!(errors.len(), expected_errors, "{errors:?}");
        }
    }
}
