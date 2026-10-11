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

pub static CONFLUENCE_BACKEND: BackendRegistration = BackendRegistration {
    kind: "confluence",
    resource_types: &[&CONFLUENCE_SPACE_RESOURCE],
    parse: parse_backend_config::<ConfluenceProviderConfig>,
    development_only: false,
};

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
        validate_atlassian_gateway_credential(
            "confluence",
            &self.allowed_upstream_hosts,
            self.cloud_id.as_deref(),
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

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, HostError> {
        Ok(Arc::new(
            ConfluenceProvider::new_with_egress_and_signing_key(
                self.clone(),
                host.limits.clone(),
                host.egress,
                host.stable_signing_key.clone(),
                host.attribution.clone(),
                host.outbound_tls,
            )?,
        ))
    }
}
