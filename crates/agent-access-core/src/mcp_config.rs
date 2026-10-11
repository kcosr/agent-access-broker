//! Configuration for the downstream, authenticated HTTP MCP ingress.
use crate::BrokerConfig;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    pub enabled: bool,
    pub public_url: Option<String>,
    pub allowed_origins: Vec<String>,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_catalog_bytes: usize,
    pub operation_timeout_ms: u64,
    pub protocol_timeout_ms: u64,
    pub max_sessions: usize,
    pub max_sessions_per_principal: usize,
    pub session_idle_timeout_ms: u64,
    pub session_max_lifetime_ms: u64,
    pub max_control_requests: u32,
    pub max_control_requests_per_principal: u32,
}
impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_url: None,
            allowed_origins: Vec::new(),
            max_request_bytes: 16 * 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            max_catalog_bytes: 64 * 1024 * 1024,
            operation_timeout_ms: 120_000,
            protocol_timeout_ms: 30_000,
            max_sessions: 256,
            max_sessions_per_principal: 8,
            session_idle_timeout_ms: 900_000,
            session_max_lifetime_ms: 3_600_000,
            max_control_requests: 64,
            max_control_requests_per_principal: 8,
        }
    }
}

pub(crate) fn validate(config: &BrokerConfig, errors: &mut Vec<String>) {
    let mcp = &config.mcp;
    if !mcp.enabled {
        return;
    }
    let url = mcp
        .public_url
        .as_deref()
        .and_then(|value| Url::parse(value).ok());
    let valid = url.as_ref().is_some_and(|url| {
        let local = matches!(
            config.deployment.environment.as_str(),
            "development" | "test"
        ) && url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        (url.scheme() == "https" || local)
            && url.host_str().is_some()
            && url.path() == "/mcp"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
    });
    if !valid {
        errors.push("mcp.public_url must be an HTTPS /mcp URL without userinfo, query or fragment (loopback HTTP is permitted in development/test)".into());
    }
    if !config
        .identity
        .trusted_callers
        .values()
        .any(|caller| caller.allow_forwarded_identity)
        && !config.identity.sources.iter().any(|source| {
            source.header.eq_ignore_ascii_case("Authorization")
                && source.scheme == "Bearer"
                && matches!(source.kind.as_str(), "static_principals" | "broker_tokens")
        })
    {
        errors.push("mcp.enabled requires an Authorization Bearer static_principals or broker_tokens identity source with canonical scheme = \"Bearer\"".into());
    }
    for origin in &mcp.allowed_origins {
        let valid = Url::parse(origin).is_ok_and(|url| {
            matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/"
                && !origin.contains('*')
                && url.origin().ascii_serialization() == *origin
        });
        if !valid {
            errors.push("mcp.allowed_origins entries must be exact canonical HTTP(S) origins without paths or wildcards".into());
        }
    }
    if mcp.max_request_bytes == 0
        || mcp.max_request_bytes as u64 > config.limits.max_http_body_bytes
    {
        errors.push(
            "mcp.max_request_bytes must be positive and no greater than limits.max_http_body_bytes"
                .into(),
        );
    }
    if mcp.max_response_bytes < 64 * 1024 {
        errors.push("mcp.max_response_bytes must be at least 65536".into());
    }
    if mcp.max_catalog_bytes < mcp.max_response_bytes {
        errors.push("mcp.max_catalog_bytes must be at least mcp.max_response_bytes".into());
    }
    if mcp.max_sessions == 0
        || mcp.max_sessions_per_principal == 0
        || mcp.max_sessions_per_principal > mcp.max_sessions
    {
        errors
            .push("mcp session limits must be positive; per-principal cannot exceed global".into());
    }
    if mcp.max_control_requests == 0
        || mcp.max_control_requests_per_principal == 0
        || mcp.max_control_requests_per_principal > mcp.max_control_requests
    {
        errors
            .push("mcp control limits must be positive; per-principal cannot exceed global".into());
    }
    if [
        mcp.operation_timeout_ms,
        mcp.protocol_timeout_ms,
        mcp.session_idle_timeout_ms,
        mcp.session_max_lifetime_ms,
    ]
    .contains(&0)
    {
        errors.push("mcp deadlines and session timeouts must be positive".into());
    }
    if mcp.session_idle_timeout_ms > mcp.session_max_lifetime_ms {
        errors.push("mcp session idle timeout cannot exceed maximum lifetime".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> BrokerConfig {
        crate::tests::parse_test_config(
            r#"
[deployment]
environment="development"
[identity]
mode="required"
authority="toml"
[[identity.sources]]
name="mcp"
type="static_principals"
header="Authorization"
scheme="Bearer"
[[identity.sources.principals]]
principal="tester"
token_refs=["env:MCP_CONFIG_TEST_TOKEN"]
[policy]
authority="toml"
[mcp]
enabled=true
public_url="https://broker.example.com/mcp"
"#,
        )
        .unwrap()
    }
    fn errors(config: &BrokerConfig) -> Vec<String> {
        let mut errors = Vec::new();
        validate(config, &mut errors);
        errors
    }
    #[test]
    fn public_endpoint_requires_https_and_canonical_path_except_local_development() {
        let mut config = config();
        assert!(errors(&config).is_empty());
        for invalid in [
            "http://broker.example.com/mcp",
            "https://broker.example.com/mcp/",
            "https://broker.example.com/v1/mcp",
            "https://token@broker.example.com/mcp",
            "https://broker.example.com/mcp?token=value",
            "https://broker.example.com/mcp#fragment",
            "ftp://broker.example.com/mcp",
        ] {
            config.mcp.public_url = Some(invalid.into());
            assert!(
                errors(&config)
                    .iter()
                    .any(|e| e.starts_with("mcp.public_url")),
                "{invalid}"
            );
        }
        for local in [
            "http://127.0.0.1:4321/mcp",
            "http://[::1]:4321/mcp",
            "http://localhost:4321/mcp",
        ] {
            config.deployment.environment = "development".into();
            config.mcp.public_url = Some(local.into());
            assert!(errors(&config).is_empty(), "{local}");
            config.deployment.environment = "production".into();
            assert!(
                errors(&config)
                    .iter()
                    .any(|e| e.starts_with("mcp.public_url")),
                "{local}"
            );
        }
    }
    #[test]
    fn authentication_must_use_a_supported_bearer_machine_source() {
        let mut config = config();
        config.identity.sources[0].header = "X-Identity".into();
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("identity source"))
        );
        config.identity.sources[0].header = "authorization".into();
        config.identity.sources[0].scheme = "bearer".into();
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("canonical scheme"))
        );
        config.identity.sources[0].scheme = "Bearer".into();
        assert!(errors(&config).is_empty());
        config.identity.sources[0].scheme = "raw".into();
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("identity source"))
        );
        config.identity.sources[0].scheme = "Bearer".into();
        config.identity.sources[0].kind = "browser_cookie".into();
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("identity source"))
        );
        config.identity.sources[0].kind = "broker_tokens".into();
        assert!(errors(&config).is_empty());
    }
    #[test]
    fn origins_are_exact_canonical_origins_not_paths_or_patterns() {
        let mut config = config();
        for origin in ["https://client.example.com", "http://localhost:4567"] {
            config.mcp.allowed_origins = vec![origin.into()];
            assert!(errors(&config).is_empty(), "{origin}");
        }
        for origin in [
            "*",
            "null",
            "https://*.example.com",
            "https://client.example.com/",
            "https://client.example.com/path",
            "https://user@client.example.com",
            "https://client.example.com?x=y",
        ] {
            config.mcp.allowed_origins = vec![origin.into()];
            assert!(
                errors(&config)
                    .iter()
                    .any(|e| e.contains("allowed_origins")),
                "{origin}"
            );
        }
    }
    #[test]
    fn quotas_deadlines_and_wire_budgets_reject_unsafe_relationships() {
        let mut config = config();
        config.mcp.max_request_bytes = config.limits.max_http_body_bytes as usize + 1;
        config.mcp.max_response_bytes = 1;
        config.mcp.max_sessions_per_principal = config.mcp.max_sessions + 1;
        config.mcp.max_control_requests_per_principal = config.mcp.max_control_requests + 1;
        config.mcp.operation_timeout_ms = 0;
        config.mcp.session_idle_timeout_ms = config.mcp.session_max_lifetime_ms + 1;
        let failures = errors(&config);
        for description in [
            "max_request_bytes",
            "max_response_bytes",
            "session limits",
            "control limits",
            "deadlines",
            "idle timeout",
        ] {
            assert!(
                failures.iter().any(|e| e.contains(description)),
                "{description}: {failures:?}"
            );
        }
        config.mcp.max_response_bytes = 64 * 1024;
        config.mcp.max_catalog_bytes = 64 * 1024 - 1;
        assert!(
            errors(&config)
                .iter()
                .any(|e| e.contains("max_catalog_bytes"))
        );
        config.mcp.enabled = false;
        assert!(
            errors(&config).is_empty(),
            "disabled endpoint does not invalidate existing configurations"
        );
    }
    #[test]
    fn removed_transfer_and_protocol_options_are_not_accepted() {
        for unsupported in [
            "transfer_dir='/tmp/files'",
            "protocol_version='2026-07-28'",
            "url='https://broker.example.com/mcp'",
        ] {
            assert!(
                toml::from_str::<McpConfig>(unsupported).is_err(),
                "{unsupported}"
            );
        }
    }
}
