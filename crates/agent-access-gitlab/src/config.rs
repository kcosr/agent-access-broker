//! `[providers.gitlab]` configuration, validation, and registration.
use super::*;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabProviderConfig {
    #[serde(default)]
    pub provisioning: GitlabProvisioningConfig,
    #[serde(default)]
    pub attachments: GitlabUploadLimitsConfig,
    pub api_base_url: String,
    pub web_base_url: String,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub webhooks: GitlabWebhooksConfig,
    #[serde(default)]
    pub content: GitlabContentConfig,
    #[serde(default)]
    pub search: SearchLimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabUploadLimitsConfig {
    #[serde(default = "default_attachment_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_attachment_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default)]
    pub media_types: Vec<String>,
}

impl Default for GitlabUploadLimitsConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_attachment_max_bytes(),
            max_total_bytes: default_attachment_max_total_bytes(),
            media_types: vec![],
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabWebhooksConfig {
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    #[serde(default)]
    pub allow_disable_ssl_verification: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabContentConfig {
    #[serde(default = "default_gitlab_body_max_bytes")]
    pub max_body_bytes: u64,
    #[serde(default = "default_gitlab_max_commit_actions")]
    pub max_commit_actions: u32,
    #[serde(default = "default_gitlab_file_max_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_gitlab_raw_download_max_bytes")]
    pub max_raw_download_bytes: u64,
}

impl Default for GitlabContentConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_gitlab_body_max_bytes(),
            max_commit_actions: default_gitlab_max_commit_actions(),
            max_file_bytes: default_gitlab_file_max_bytes(),
            max_raw_download_bytes: default_gitlab_raw_download_max_bytes(),
        }
    }
}

pub(crate) fn default_gitlab_body_max_bytes() -> u64 {
    1024 * 1024
}

pub(crate) fn default_gitlab_max_commit_actions() -> u32 {
    25
}

pub(crate) fn default_gitlab_file_max_bytes() -> u64 {
    10 * 1024 * 1024
}

pub(crate) fn default_gitlab_raw_download_max_bytes() -> u64 {
    100 * 1024 * 1024
}

pub(crate) fn validate_gitlab_webhook_destinations(patterns: &[String], errors: &mut Vec<String>) {
    let label = "providers.gitlab.webhooks.allowed_destinations";
    let mut seen = BTreeSet::new();
    for pattern in patterns {
        let Ok(mut url) = Url::parse(pattern) else {
            errors.push(format!(
                "{label} entry {pattern} must be a valid URL pattern"
            ));
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            errors.push(format!("{label} entry {pattern} must use http or https"));
        }
        match url.host_str() {
            Some(host) if host.contains('*') => {
                errors.push(format!(
                    "{label} entry {pattern} must not wildcard the host"
                ));
            }
            Some(_) => {}
            None => errors.push(format!("{label} entry {pattern} must include a host")),
        }
        if !url.username().is_empty() || url.password().is_some() {
            errors.push(format!(
                "{label} entry {pattern} must not include credentials"
            ));
        }
        if url.query().is_some() {
            errors.push(format!("{label} entry {pattern} must not include a query"));
        }
        if url.fragment().is_some() {
            errors.push(format!(
                "{label} entry {pattern} must not include a fragment"
            ));
        }
        for segment in url.path_segments().into_iter().flatten() {
            if segment.contains('*') && segment != "*" && segment != "**" {
                errors.push(format!(
                    "{label} entry {pattern} has invalid wildcard path segment {segment}"
                ));
            }
        }
        if url.port().is_some() && url.port() == url.port_or_known_default() {
            let _ = url.set_port(None);
        }
        url.set_fragment(None);
        if !seen.insert(url.to_string()) {
            errors.push(format!(
                "{label} contains duplicate normalized destination {pattern}"
            ));
        }
    }
}

pub static GITLAB_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "gitlab",
    parse_backend_config::<GitlabProviderConfig>,
);

impl BackendConfig for GitlabProviderConfig {
    fn kind(&self) -> &'static str {
        "gitlab"
    }

    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        validate_upload_limits(
            "providers.gitlab.attachments",
            self.attachments.max_bytes,
            self.attachments.max_total_bytes,
            &self.attachments.media_types,
            errors,
        );
        let api_base = validate_upstream_base_url(
            "providers.gitlab.api_base_url",
            &self.api_base_url,
            context.production(),
            errors,
        );
        if api_base
            .as_ref()
            .is_some_and(|api_base| !api_base.path().trim_end_matches('/').ends_with("/api/v4"))
        {
            errors.push(
                "providers.gitlab.api_base_url must point to the GitLab REST v4 API root"
                    .to_string(),
            );
        }
        validate_upstream_base_url(
            "providers.gitlab.web_base_url",
            &self.web_base_url,
            context.production(),
            errors,
        );
        validate_egress_proxy_config(
            "providers.gitlab.egress_proxy",
            self.egress_proxy.as_ref(),
            errors,
        );
        validate_upstream_allowlist(
            "providers.gitlab.allowed_upstream_hosts",
            &self.allowed_upstream_hosts,
            context.production(),
            errors,
        );
        validate_gitlab_webhook_destinations(&self.webhooks.allowed_destinations, errors);
        self.provisioning.validate(errors);
        if let Some(mut probe_url) = api_base {
            if !probe_url.path().ends_with('/') {
                let mut path = probe_url.path().to_string();
                path.push('/');
                probe_url.set_path(&path);
            }
            probe_url = probe_url
                .join("projects/example%2Frepo")
                .unwrap_or_else(|_| probe_url.clone());
            if !url_allowed_by_patterns(&probe_url, &self.allowed_upstream_hosts) {
                errors.push(
                        "providers.gitlab.allowed_upstream_hosts must include providers.gitlab.api_base_url path prefix"
                            .to_string(),
                    );
            }
        }
        if self.search.max_results == 0 {
            errors.push("providers.gitlab.search.max_results must be non-zero".to_string());
        } else if self.search.max_results > 100 {
            errors.push(
                "providers.gitlab.search.max_results must be less than or equal to 100".to_string(),
            );
        }
        if self.content.max_body_bytes == 0 {
            errors.push("providers.gitlab.content.max_body_bytes must be non-zero".to_string());
        } else if self.content.max_body_bytes > context.limits.max_http_body_bytes {
            errors.push(
                    "providers.gitlab.content.max_body_bytes must be less than or equal to limits.max_http_body_bytes"
                        .to_string(),
                );
        }
        if self.content.max_commit_actions == 0 {
            errors.push("providers.gitlab.content.max_commit_actions must be non-zero".to_string());
        } else if self.content.max_commit_actions > 100 {
            errors.push(
                "providers.gitlab.content.max_commit_actions must be less than or equal to 100"
                    .to_string(),
            );
        }
        if self.content.max_file_bytes == 0 {
            errors.push("providers.gitlab.content.max_file_bytes must be non-zero".to_string());
        } else if self.content.max_file_bytes > context.limits.max_http_body_bytes {
            errors.push(
                    "providers.gitlab.content.max_file_bytes must be less than or equal to limits.max_http_body_bytes"
                        .to_string(),
                );
        }
        if self.content.max_raw_download_bytes == 0 {
            errors.push(
                "providers.gitlab.content.max_raw_download_bytes must be non-zero".to_string(),
            );
        } else if self.content.max_raw_download_bytes > context.limits.max_download_bytes {
            errors.push(
                    "providers.gitlab.content.max_raw_download_bytes must be less than or equal to limits.max_download_bytes"
                        .to_string(),
                );
        }
        validate_provider_upload_limit_relation(
            "gitlab",
            self.attachments.max_bytes,
            self.attachments.max_total_bytes,
            context.limits,
            errors,
        );
    }

    fn descriptor(&self) -> ServiceDescriptor {
        gitlab_descriptor(self)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| ("providers.gitlab.egress_proxy".to_string(), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(GitlabProvider::new(self.clone(), host)?))
    }
}
