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
    pub search: GitlabSearchConfig,
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

/// Webhook destinations are http or https URL patterns without a query or
/// fragment, may be empty, and must not repeat once normalized.
pub(crate) fn validate_gitlab_webhook_destinations(patterns: &[String], errors: &mut Vec<String>) {
    validate_url_patterns(
        "providers.gitlab.webhooks.allowed_destinations",
        patterns,
        UrlPatternPolicy::new()
            .with_schemes(&["http", "https"])
            .allowing_empty()
            .without_query_or_fragment()
            .rejecting_duplicates(),
        errors,
    );
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
        self.search.validate(errors);
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

/// Operator-declared native search capabilities and whole-operation work bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitlabSearchConfig {
    pub max_results: u32,
    pub default_engine: String,
    pub max_candidate_pages: u32,
    pub max_upstream_requests: u32,
    pub max_scan_bytes: u64,
    pub engines: GitlabSearchEnginesConfig,
}

impl Default for GitlabSearchConfig {
    fn default() -> Self {
        Self {
            max_results: 50,
            default_engine: "basic".into(),
            max_candidate_pages: 4,
            max_upstream_requests: 128,
            max_scan_bytes: 16 * 1024 * 1024,
            engines: GitlabSearchEnginesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitlabSearchEnginesConfig {
    pub basic: GitlabSearchEngineConfig,
    pub advanced: GitlabSearchEngineConfig,
    pub zoekt: GitlabSearchEngineConfig,
}

impl Default for GitlabSearchEnginesConfig {
    fn default() -> Self {
        Self {
            basic: GitlabSearchEngineConfig {
                project_categories: search::CATEGORIES.iter().map(|v| (*v).into()).collect(),
                instance_categories: vec!["issues".into(), "merge_requests".into()],
            },
            advanced: GitlabSearchEngineConfig::default(),
            zoekt: GitlabSearchEngineConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitlabSearchEngineConfig {
    pub project_categories: Vec<String>,
    pub instance_categories: Vec<String>,
}

impl GitlabSearchConfig {
    pub(crate) fn engine(&self, engine: &str) -> Option<&GitlabSearchEngineConfig> {
        match engine {
            "basic" => Some(&self.engines.basic),
            "advanced" => Some(&self.engines.advanced),
            "zoekt" => Some(&self.engines.zoekt),
            _ => None,
        }
    }

    pub(crate) fn supports(&self, engine: &str, category: &str, project: bool) -> bool {
        self.engine(engine).is_some_and(|config| {
            let categories = if project {
                &config.project_categories
            } else {
                &config.instance_categories
            };
            categories.iter().any(|v| v == category)
        })
    }

    pub(crate) fn enabled_engines(&self, category: &str) -> Vec<&'static str> {
        ["basic", "advanced", "zoekt"]
            .into_iter()
            .filter(|engine| {
                self.supports(engine, category, true) || self.supports(engine, category, false)
            })
            .collect()
    }

    pub(crate) fn validate(&self, errors: &mut Vec<String>) {
        let prefix = "providers.gitlab.search";
        if self.engine(&self.default_engine).is_none() {
            errors.push(format!(
                "{prefix}.default_engine must be basic, advanced, or zoekt"
            ));
        }
        if !(1..=32).contains(&self.max_candidate_pages) {
            errors.push(format!(
                "{prefix}.max_candidate_pages must be between 1 and 32"
            ));
        }
        if !(4..=4096).contains(&self.max_upstream_requests)
            || self.max_upstream_requests < self.max_results.saturating_add(2).max(4)
        {
            errors.push(format!(
                "{prefix}.max_upstream_requests must be between max(max_results + 2, 4) and 4096"
            ));
        }
        if !(1024 * 1024..=64 * 1024 * 1024).contains(&self.max_scan_bytes) {
            errors.push(format!(
                "{prefix}.max_scan_bytes must be between 1 and 64 MiB"
            ));
        }
        for engine in ["basic", "advanced", "zoekt"] {
            let config = self.engine(engine).expect("known engine");
            for (route, categories) in [
                ("project", &config.project_categories),
                ("instance", &config.instance_categories),
            ] {
                let mut seen = BTreeSet::new();
                for category in categories {
                    if !search::CATEGORIES.contains(&category.as_str()) || !seen.insert(category) {
                        errors.push(format!("{prefix}.engines.{engine}.{route}_categories contains an unknown or repeated category"));
                    }
                    if (engine == "zoekt" && category != "code")
                        || (engine == "basic"
                            && route == "instance"
                            && !["issues", "merge_requests"].contains(&category.as_str()))
                    {
                        errors.push(format!("{prefix}.engines.{engine}.{route}_categories contains an unsupported tuple"));
                    }
                }
            }
        }
        for category in search::CATEGORIES {
            if !self.enabled_engines(category).is_empty()
                && !self.supports(&self.default_engine, category, true)
                && !self.supports(&self.default_engine, category, false)
            {
                errors.push(format!("{prefix}.default_engine must enable a route for each exposed category ({category})"));
            }
        }
    }
}
