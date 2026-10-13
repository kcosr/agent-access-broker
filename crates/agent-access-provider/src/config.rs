//! Configuration building blocks and validators shared by backends.
use crate::EgressProxyConfig;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use url::{Host, Url};

/// Broker-wide limits a backend must respect. The broker derives them from
/// its `[limits]` section.
///
/// The public fields are what a backend reads. Start from the defaults and
/// override limits with the `with_*` builders:
///
/// ```
/// use agent_access_provider::ProviderLimits;
///
/// let limits = ProviderLimits::default().with_request_timeout_ms(5_000);
/// assert_eq!(limits.request_timeout_ms, 5_000);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderLimits {
    pub max_http_body_bytes: u64,
    pub max_download_bytes: u64,
    pub max_upstream_response_bytes: u64,
    pub request_timeout_ms: u64,
    pub streaming_idle_timeout_ms: u64,
}

/// The Broker's default limits, which its `[limits]` section overrides.
impl Default for ProviderLimits {
    fn default() -> Self {
        Self {
            max_http_body_bytes: 512 * 1024 * 1024,
            max_download_bytes: default_download_max_bytes(),
            max_upstream_response_bytes: 512 * 1024 * 1024,
            request_timeout_ms: 30_000,
            streaming_idle_timeout_ms: 30_000,
        }
    }
}

impl ProviderLimits {
    pub const fn with_max_http_body_bytes(mut self, bytes: u64) -> Self {
        self.max_http_body_bytes = bytes;
        self
    }

    pub const fn with_max_download_bytes(mut self, bytes: u64) -> Self {
        self.max_download_bytes = bytes;
        self
    }

    pub const fn with_max_upstream_response_bytes(mut self, bytes: u64) -> Self {
        self.max_upstream_response_bytes = bytes;
        self
    }

    pub const fn with_request_timeout_ms(mut self, milliseconds: u64) -> Self {
        self.request_timeout_ms = milliseconds;
        self
    }

    pub const fn with_streaming_idle_timeout_ms(mut self, milliseconds: u64) -> Self {
        self.streaming_idle_timeout_ms = milliseconds;
        self
    }
}

/// A backend's `attachments` configuration table.
///
/// Configuration schema is intentionally exhaustive: its fields are the
/// documented keys of a table that rejects unknown keys, so adding one is a
/// configuration contract change that every consumer rendering or validating
/// the table must handle. Build it from [`Default`] with struct update syntax
/// or by deserializing it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentLimitsConfig {
    #[serde(default = "default_attachment_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_attachment_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "default_download_max_bytes")]
    pub max_download_bytes: u64,
    #[serde(default)]
    pub media_types: Vec<String>,
}

impl Default for AttachmentLimitsConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_attachment_max_bytes(),
            max_total_bytes: default_attachment_max_total_bytes(),
            max_download_bytes: default_download_max_bytes(),
            media_types: vec![],
        }
    }
}

pub fn default_attachment_max_bytes() -> u64 {
    10 * 1024 * 1024
}

pub fn default_attachment_max_total_bytes() -> u64 {
    50 * 1024 * 1024
}

pub fn default_download_max_bytes() -> u64 {
    100 * 1024 * 1024
}

/// A backend's `search` configuration table.
///
/// Configuration schema is intentionally exhaustive, like
/// [`AttachmentLimitsConfig`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchLimitsConfig {
    #[serde(default = "default_search_max_results")]
    pub max_results: u32,
}

impl Default for SearchLimitsConfig {
    fn default() -> Self {
        Self {
            max_results: default_search_max_results(),
        }
    }
}

fn default_search_max_results() -> u32 {
    50
}

pub fn validate_egress_proxy_config(
    label: &str,
    config: Option<&EgressProxyConfig>,
    errors: &mut Vec<String>,
) {
    let Some(config) = config else {
        return;
    };
    if config.url.trim().is_empty() {
        errors.push(format!("{label}.url must not be empty"));
    } else {
        match Url::parse(&config.url) {
            Ok(url) => {
                if !matches!(url.scheme(), "http" | "https") {
                    errors.push(format!("{label}.url must use http or https"));
                }
                if url.host_str().is_none() {
                    errors.push(format!("{label}.url must include a host"));
                }
                if !matches!(url.path(), "" | "/") {
                    errors.push(format!("{label}.url must be a proxy origin without a path"));
                }
                if !url.username().is_empty() || url.password().is_some() {
                    errors.push(format!("{label}.url must not include username or password"));
                }
                if url.query().is_some() {
                    errors.push(format!("{label}.url must not include a query"));
                }
                if url.fragment().is_some() {
                    errors.push(format!("{label}.url must not include a fragment"));
                }
                if url.scheme() == "http"
                    && (config.username_ref.is_some() || config.password_ref.is_some())
                {
                    errors.push(format!(
                        "{label}.username_ref and password_ref require an https proxy URL"
                    ));
                }
            }
            Err(_) => errors.push(format!("{label}.url must be a valid URL")),
        }
    }
    match (&config.username_ref, &config.password_ref) {
        (Some(username), Some(password)) => {
            if !is_secret_ref(username) {
                errors.push(format!(
                    "{label}.username_ref must use env:NAME or file:/absolute/path"
                ));
            }
            if !is_secret_ref(password) {
                errors.push(format!(
                    "{label}.password_ref must use env:NAME or file:/absolute/path"
                ));
            }
        }
        (Some(_), None) => errors.push(format!("{label}.password_ref is required")),
        (None, Some(_)) => errors.push(format!("{label}.username_ref is required")),
        (None, None) => {}
    }
}

pub fn validate_upstream_allowlist(
    label: &str,
    patterns: &[String],
    requires_https: bool,
    errors: &mut Vec<String>,
) {
    if patterns.is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
    for pattern in patterns {
        match Url::parse(pattern) {
            Ok(url) => {
                match url.host_str() {
                    Some(host) if host.contains('*') => {
                        errors.push(format!(
                            "{label} entry {pattern} must not wildcard the host"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        errors.push(format!("{label} entry {pattern} must include a host"));
                    }
                }
                if requires_https && url.scheme() != "https" {
                    errors.push(format!("{label} entry {pattern} must use https"));
                }
                if !url.username().is_empty() || url.password().is_some() {
                    errors.push(format!(
                        "{label} entry {pattern} must not include credentials"
                    ));
                }
                for segment in url.path_segments().into_iter().flatten() {
                    if segment.contains('*') && segment != "*" && segment != "**" {
                        errors.push(format!(
                            "{label} entry {pattern} has invalid wildcard path segment {segment}"
                        ));
                    }
                }
            }
            Err(_) => errors.push(format!(
                "{label} entry {pattern} must be a valid URL pattern"
            )),
        }
    }
}

pub fn validate_upstream_base_url(
    label: &str,
    value: &str,
    production: bool,
    errors: &mut Vec<String>,
) -> Option<Url> {
    let parsed = match Url::parse(value) {
        Ok(url) => url,
        Err(_) => {
            errors.push(format!("{label} must be a valid URL"));
            return None;
        }
    };
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        errors.push(format!(
            "{label} must include a host and must not include credentials, query, or fragment"
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if !production && is_loopback_or_localhost(parsed.host()) => {}
        _ => errors.push(format!(
            "{label} must use https, except loopback http in non-production"
        )),
    }
    Some(parsed)
}

pub fn validate_tenant_host(label: &str, value: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    let forbidden = ['/', '\\', '@', ':', '?', '#'];
    if trimmed.is_empty()
        || trimmed != value
        || value.chars().any(|ch| forbidden.contains(&ch))
        || Url::parse(&format!("https://{trimmed}/"))
            .map(|url| {
                url.host_str() != Some(trimmed)
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.port().is_some()
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
            })
            .unwrap_or(true)
    {
        errors.push(format!(
            "{label} must be a lowercase, normalized bare host name"
        ));
    }
}

pub fn validate_attachment_limits(
    label: &str,
    config: &AttachmentLimitsConfig,
    errors: &mut Vec<String>,
) {
    validate_upload_limits(
        label,
        config.max_bytes,
        config.max_total_bytes,
        &config.media_types,
        errors,
    );
    if config.max_download_bytes == 0 {
        errors.push(format!("{label}.max_download_bytes must be non-zero"));
    }
}

pub fn validate_upload_limits(
    label: &str,
    max_bytes: u64,
    max_total_bytes: u64,
    media_types: &[String],
    errors: &mut Vec<String>,
) {
    if max_bytes == 0 {
        errors.push(format!("{label}.max_bytes must be non-zero"));
    }
    if max_total_bytes == 0 {
        errors.push(format!("{label}.max_total_bytes must be non-zero"));
    }
    for media_type in media_types {
        if media_type.trim().is_empty() || !media_type.contains('/') {
            errors.push(format!(
                "{label}.media_types contains invalid media type {media_type}"
            ));
        }
    }
}

pub fn validate_provider_limit_relation(
    provider: &str,
    attachments: &AttachmentLimitsConfig,
    limits: &ProviderLimits,
    errors: &mut Vec<String>,
) {
    validate_provider_upload_limit_relation(
        provider,
        attachments.max_bytes,
        attachments.max_total_bytes,
        limits,
        errors,
    );
    if attachments.max_download_bytes > limits.max_download_bytes {
        errors.push(format!(
            "providers.{provider}.attachments.max_download_bytes must not exceed limits.max_download_bytes"
        ));
    }
}

pub fn validate_provider_upload_limit_relation(
    provider: &str,
    max_bytes: u64,
    max_total_bytes: u64,
    limits: &ProviderLimits,
    errors: &mut Vec<String>,
) {
    if max_total_bytes > limits.max_http_body_bytes {
        errors.push(format!(
            "providers.{provider}.attachments.max_total_bytes must not exceed limits.max_http_body_bytes"
        ));
    }
    if max_bytes > limits.max_http_body_bytes {
        errors.push(format!(
            "providers.{provider}.attachments.max_bytes must not exceed limits.max_http_body_bytes"
        ));
    }
    if max_bytes > max_total_bytes {
        errors.push(format!(
            "providers.{provider}.attachments.max_bytes must not exceed providers.{provider}.attachments.max_total_bytes"
        ));
    }
}

pub fn validate_formats_allow_empty(
    label: &str,
    values: &[String],
    allowed: &[&str],
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !allowed.contains(&value.as_str()) {
            errors.push(format!("{label} contains unsupported format {value}"));
        }
        let normalized = value.trim().to_ascii_lowercase();
        if !seen.insert(normalized.clone()) {
            errors.push(format!("{label} contains duplicate format {normalized}"));
        }
    }
}

pub fn validate_non_empty_control_free_string(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
    if value.chars().any(char::is_control) {
        errors.push(format!("{label} must not contain control characters"));
    }
}

pub fn is_loopback_or_localhost(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        _ => false,
    }
}

/// Whether a URL names a literal IPv4 or IPv6 loopback address. Only such URLs
/// receive the OAuth loopback exceptions (plain HTTP and the direct route).
/// Host names never qualify, including `localhost`: name resolution must not
/// grant the exception.
pub fn is_literal_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

pub fn is_secret_ref(value: &str) -> bool {
    if let Some(name) = value.strip_prefix("env:") {
        return is_env_name(name);
    }
    if let Some(path) = value.strip_prefix("file:") {
        return path.starts_with('/');
    }
    false
}

pub fn is_env_name(value: &str) -> bool {
    env_re().is_match(value)
}

fn env_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Z_][A-Z0-9_]*$").expect("env regex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_loopback_requires_an_ip_address() {
        for url in [
            "http://127.0.0.1:8787/token",
            "https://127.0.0.2/",
            "http://[::1]:8787/token",
            "https://[::1]/",
        ] {
            assert!(is_literal_loopback(&Url::parse(url).unwrap()), "{url}");
        }
        for url in [
            "http://localhost:8787/token",
            "https://localhost/",
            "http://LOCALHOST/",
            "http://localhost./",
            "http://127.0.0.1.example/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::2]/",
            "http://192.0.2.1/",
            "https://issuer.example/",
        ] {
            assert!(!is_literal_loopback(&Url::parse(url).unwrap()), "{url}");
        }
    }

    #[test]
    fn upstream_http_accepts_only_exact_local_hosts_outside_production() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let value = format!("http://{host}:8787/api");
            let mut errors = Vec::new();
            validate_upstream_base_url("upstream", &value, false, &mut errors).unwrap();
            assert!(errors.is_empty(), "{value}: {errors:?}");

            validate_upstream_base_url("upstream", &value, true, &mut errors).unwrap();
            assert!(
                errors.iter().any(|error| error.contains("must use https")),
                "production {value}: {errors:?}"
            );
        }

        for host in [
            "127.0.0.2",
            "[::ffff:127.0.0.1]",
            "[::2]",
            "[2001:db8::1]",
            "localhost.example",
            "broker.example",
        ] {
            let value = format!("http://{host}:8787/api");
            let mut errors = Vec::new();
            validate_upstream_base_url("upstream", &value, false, &mut errors).unwrap();
            assert!(
                errors.iter().any(|error| error.contains("must use https")),
                "{value}: {errors:?}"
            );
        }
    }
}
