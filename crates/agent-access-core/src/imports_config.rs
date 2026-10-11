use crate::{BrokerConfig, is_service_name, url_allowed_by_patterns, validate_upstream_base_url};
use serde::Deserialize;
use std::collections::BTreeSet;
use url::Url;

/// Operator authority over database-managed integrations.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_kinds: Vec<String>,
    #[serde(default)]
    pub allowed_endpoints: Vec<String>,
    #[serde(default)]
    pub disabled_services: Vec<String>,
}

impl ImportsConfig {
    pub fn permits(&self, service: &str, kind: &str, endpoint: &str) -> bool {
        self.enabled
            && self.allowed_kinds.iter().any(|allowed| allowed == kind)
            && !self
                .disabled_services
                .iter()
                .any(|disabled| disabled == service)
            && Url::parse(endpoint)
                .is_ok_and(|url| url_allowed_by_patterns(&url, &self.allowed_endpoints))
    }
}

pub(crate) fn validate_imports(config: &BrokerConfig, errors: &mut Vec<String>) {
    let imports = &config.imports;
    if imports.enabled
        && (config.identity.authority != "managed"
            || config.policy.authority != "managed"
            || config.managed_store.is_none()
            || config.credential_encryption.is_none()
            || !config.management.enabled)
    {
        errors.push("imports.enabled requires managed identity, managed policy, managed_store, credential_encryption, and management.enabled".into());
    }
    for (label, values) in [
        ("allowed_kinds", &imports.allowed_kinds),
        ("allowed_endpoints", &imports.allowed_endpoints),
        ("disabled_services", &imports.disabled_services),
    ] {
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            errors.push(format!("imports.{label} contains duplicates"));
        }
    }
    if imports.enabled && (imports.allowed_kinds.is_empty() || imports.allowed_endpoints.is_empty())
    {
        errors.push("enabled imports require nonempty allowed_kinds and allowed_endpoints".into());
    }
    for kind in &imports.allowed_kinds {
        if imports.enabled && config.providers.registry().imported_adapter(kind).is_none() {
            errors.push(format!(
                "imports.allowed_kinds contains an unlinked adapter kind {kind}"
            ));
        }
        if kind == "conformance_import"
            && (config.deployment.environment == "production"
                || !config.deployment.enable_fake_service)
        {
            errors.push(
                "conformance_import requires non-production deployment.enable_fake_service".into(),
            );
        }
    }
    for endpoint in &imports.allowed_endpoints {
        validate_upstream_base_url(
            "imports.allowed_endpoints",
            endpoint,
            config.deployment.environment == "production",
            errors,
        );
    }
    for service in &imports.disabled_services {
        if !is_service_name(service) {
            errors.push("imports.disabled_services contains an invalid service ID".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_gate_requires_every_boundary() {
        let mut config = ImportsConfig {
            enabled: true,
            allowed_kinds: vec!["mcp_http".into()],
            allowed_endpoints: vec!["https://tools.example/mcp".into()],
            disabled_services: vec!["disabled".into()],
        };
        assert!(config.permits("tools", "mcp_http", "https://tools.example/mcp"));
        for (service, kind, endpoint) in [
            ("disabled", "mcp_http", "https://tools.example/mcp"),
            ("tools", "openapi_http", "https://tools.example/mcp"),
            ("tools", "mcp_http", "https://tools.example/other"),
            ("tools", "mcp_http", "https://other.example/mcp"),
        ] {
            assert!(!config.permits(service, kind, endpoint));
        }
        config.enabled = false;
        assert!(!config.permits("tools", "mcp_http", "https://tools.example/mcp"));
    }
}
