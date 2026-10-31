//! `[providers.jira]` configuration, validation, and registration.
use super::*;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JiraProviderConfig {
    pub tenant_host: String,
    pub cloud_id: Option<String>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub attachments: AttachmentLimitsConfig,
    #[serde(default)]
    pub content: JiraContentConfig,
    #[serde(default)]
    pub search: SearchLimitsConfig,
    #[serde(default)]
    pub listing: JiraListingConfig,
    #[serde(default)]
    pub comments: JiraCommentsConfig,
    #[serde(default)]
    pub issue_links: JiraIssueLinksConfig,
}

/// Work limits for live project enumeration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct JiraListingConfig {
    pub max_results: u32,
    pub max_candidate_pages: u32,
    pub max_upstream_requests: u32,
    pub max_scan_bytes: u64,
}

impl Default for JiraListingConfig {
    fn default() -> Self {
        Self {
            max_results: 50,
            max_candidate_pages: 4,
            max_upstream_requests: 8,
            max_scan_bytes: 16 * 1024 * 1024,
        }
    }
}

impl JiraProviderConfig {
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
pub struct JiraContentConfig {
    #[serde(default)]
    pub comment_formats: Vec<String>,
    #[serde(default = "default_jira_body_max_bytes")]
    pub max_body_bytes: u64,
}

impl Default for JiraContentConfig {
    fn default() -> Self {
        Self {
            comment_formats: vec![],
            max_body_bytes: default_jira_body_max_bytes(),
        }
    }
}

pub(crate) fn default_jira_body_max_bytes() -> u64 {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JiraCommentsConfig {
    #[serde(default = "default_comment_max_results")]
    pub max_results: u32,
    #[serde(default = "default_comment_body_max_results")]
    pub body_max_results: u32,
    /// Aggregate native ADF bytes per body page; omission inherits the per-body cap.
    pub max_page_body_bytes: Option<u64>,
    #[serde(default = "default_comment_property_value_max_bytes")]
    pub max_property_value_bytes: u64,
    #[serde(default = "default_comment_property_key_prefixes")]
    pub allowed_property_key_prefixes: Vec<String>,
    #[serde(default)]
    pub allowed_visibility: Vec<JiraCommentVisibilityConfig>,
}

impl Default for JiraCommentsConfig {
    fn default() -> Self {
        Self {
            max_results: default_comment_max_results(),
            body_max_results: default_comment_body_max_results(),
            max_page_body_bytes: None,
            max_property_value_bytes: default_comment_property_value_max_bytes(),
            allowed_property_key_prefixes: default_comment_property_key_prefixes(),
            allowed_visibility: vec![],
        }
    }
}

pub(crate) fn default_comment_max_results() -> u32 {
    50
}

pub(crate) fn default_comment_body_max_results() -> u32 {
    20
}

pub(crate) fn default_comment_property_value_max_bytes() -> u64 {
    32_768
}

pub(crate) fn default_comment_property_key_prefixes() -> Vec<String> {
    vec!["agent-access.".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JiraIssueLinksConfig {
    #[serde(default = "default_jira_dependency_link_type")]
    pub dependency_link_type: String,
    #[serde(default = "default_jira_dependency_outward")]
    pub dependency_outward: String,
    #[serde(default = "default_jira_dependency_inward")]
    pub dependency_inward: String,
}

impl Default for JiraIssueLinksConfig {
    fn default() -> Self {
        Self {
            dependency_link_type: default_jira_dependency_link_type(),
            dependency_outward: default_jira_dependency_outward(),
            dependency_inward: default_jira_dependency_inward(),
        }
    }
}

pub(crate) fn default_jira_dependency_link_type() -> String {
    "Blocks".to_string()
}

pub(crate) fn default_jira_dependency_outward() -> String {
    "blocks".to_string()
}

pub(crate) fn default_jira_dependency_inward() -> String {
    "is blocked by".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct JiraCommentVisibilityConfig {
    #[serde(rename = "type")]
    pub visibility_type: String,
    pub value: Option<String>,
    pub identifier: Option<String>,
}

pub(crate) fn validate_jira_comments_config(
    label: &str,
    config: &JiraCommentsConfig,
    errors: &mut Vec<String>,
) {
    if config.max_results == 0 {
        errors.push(format!("{label}.max_results must be non-zero"));
    }
    if config.body_max_results == 0 {
        errors.push(format!("{label}.body_max_results must be non-zero"));
    }
    if config.max_page_body_bytes == Some(0) {
        errors.push(format!("{label}.max_page_body_bytes must be non-zero"));
    }
    if config.max_property_value_bytes == 0 {
        errors.push(format!("{label}.max_property_value_bytes must be non-zero"));
    }
    if config.max_property_value_bytes > 32_768 {
        errors.push(format!(
            "{label}.max_property_value_bytes must not exceed 32768"
        ));
    }

    if config.allowed_property_key_prefixes.is_empty() {
        errors.push(format!(
            "{label}.allowed_property_key_prefixes must not be empty"
        ));
    }
    let mut prefixes = BTreeSet::new();
    for prefix in &config.allowed_property_key_prefixes {
        if !valid_jira_comment_property_prefix(prefix) {
            errors.push(format!(
                "{label}.allowed_property_key_prefixes contains invalid prefix {prefix}"
            ));
        }
        if jira_comment_property_prefix_reserved(prefix) {
            errors.push(format!(
                "{label}.allowed_property_key_prefixes contains reserved prefix {prefix}"
            ));
        }
        if !prefixes.insert(prefix) {
            errors.push(format!(
                "{label}.allowed_property_key_prefixes contains duplicate prefix {prefix}"
            ));
        }
    }

    let mut visibility_entries = BTreeSet::new();
    for visibility in &config.allowed_visibility {
        match visibility.visibility_type.as_str() {
            "group" => {
                if visibility
                    .identifier
                    .as_ref()
                    .is_none_or(|identifier| identifier.trim().is_empty())
                {
                    errors.push(format!(
                        "{label}.allowed_visibility group entries require identifier"
                    ));
                }
            }
            "role" => {
                if visibility
                    .value
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    errors.push(format!(
                        "{label}.allowed_visibility role entries require value"
                    ));
                }
            }
            _ => errors.push(format!(
                "{label}.allowed_visibility type must be role or group"
            )),
        }
        let key = match visibility.visibility_type.as_str() {
            "group" => (
                visibility.visibility_type.as_str(),
                None,
                visibility.identifier.as_deref(),
            ),
            _ => (
                visibility.visibility_type.as_str(),
                visibility.value.as_deref(),
                visibility.identifier.as_deref(),
            ),
        };
        if !visibility_entries.insert(key) {
            errors.push(format!(
                "{label}.allowed_visibility contains duplicate entry"
            ));
        }
    }
}

pub(crate) fn validate_jira_issue_links_config(
    label: &str,
    config: &JiraIssueLinksConfig,
    errors: &mut Vec<String>,
) {
    validate_non_empty_control_free_string(
        &format!("{label}.dependency_link_type"),
        &config.dependency_link_type,
        errors,
    );
    validate_non_empty_control_free_string(
        &format!("{label}.dependency_outward"),
        &config.dependency_outward,
        errors,
    );
    validate_non_empty_control_free_string(
        &format!("{label}.dependency_inward"),
        &config.dependency_inward,
        errors,
    );
}

pub(crate) fn valid_jira_comment_property_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.is_ascii()
        && !prefix.contains('/')
        && !prefix.chars().any(char::is_whitespace)
}

pub(crate) fn jira_comment_property_prefix_reserved(prefix: &str) -> bool {
    let prefix = prefix.to_ascii_lowercase();
    ["sd.", "jira.", "atlassian.", "com.atlassian."]
        .iter()
        .any(|reserved| prefix.starts_with(reserved))
}

pub static JIRA_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "jira",
    parse_backend_config::<JiraProviderConfig>,
)
.with_resource_types(&[&JIRA_PROJECT_RESOURCE]);

impl BackendConfig for JiraProviderConfig {
    fn kind(&self) -> &'static str {
        "jira"
    }

    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        validate_tenant_host("providers.jira.tenant_host", &self.tenant_host, errors);
        validate_egress_proxy_config(
            "providers.jira.egress_proxy",
            self.egress_proxy.as_ref(),
            errors,
        );
        validate_upstream_allowlist(
            "providers.jira.allowed_upstream_hosts",
            &self.allowed_upstream_hosts,
            true,
            errors,
        );
        validate_atlassian_routes(
            crate::backend::JIRA_PRODUCT,
            &self.site(),
            context.credentials,
            errors,
        );
        validate_attachment_limits("providers.jira.attachments", &self.attachments, errors);
        if self.content.max_body_bytes == 0 {
            errors.push("providers.jira.content.max_body_bytes must be non-zero".to_string());
        }
        validate_formats_allow_empty(
            "providers.jira.content.comment_formats",
            &self.content.comment_formats,
            &["adf"],
            errors,
        );
        if self.search.max_results == 0 {
            errors.push("providers.jira.search.max_results must be non-zero".to_string());
        }
        validate_jira_comments_config("providers.jira.comments", &self.comments, errors);
        if self
            .comments
            .max_page_body_bytes
            .is_some_and(|cap| cap < self.content.max_body_bytes)
        {
            errors.push("providers.jira.comments.max_page_body_bytes must be at least content.max_body_bytes".to_string());
        }
        if !(1..=100).contains(&self.listing.max_results)
            || self.listing.max_candidate_pages == 0
            || self.listing.max_upstream_requests == 0
            || self.listing.max_scan_bytes == 0
        {
            errors.push(
                "providers.jira.listing requires max_results in 1..100 and positive work limits"
                    .to_string(),
            );
        }
        validate_jira_issue_links_config("providers.jira.issue_links", &self.issue_links, errors);
        validate_provider_limit_relation("jira", &self.attachments, context.limits, errors);
    }

    fn descriptor(&self) -> ServiceDescriptor {
        jira_descriptor(self)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| ("providers.jira.egress_proxy".to_string(), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(JiraProvider::new(self.clone(), host)?))
    }
}
