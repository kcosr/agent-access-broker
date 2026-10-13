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
    let development_fixtures_enabled =
        config.deployment.environment != "production" && config.deployment.enable_fake_service;
    for kind in &imports.allowed_kinds {
        let adapter = config.providers.registry().imported_adapter(kind);
        if imports.enabled && adapter.is_none() {
            errors.push(format!(
                "imports.allowed_kinds contains an unlinked adapter kind {kind}"
            ));
        }
        if adapter.is_some_and(|adapter| adapter.development_only())
            && !development_fixtures_enabled
        {
            errors.push(format!(
                "imports.allowed_kinds contains the development-only adapter kind {kind}, which requires non-production deployment.enable_fake_service"
            ));
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
    use crate::{BackendRegistry, ProvidersConfig, parse_broker_config_raw};
    use agent_access_provider::{
        BuildContext, ExecutionCredential, HostError, ImportedActionDefinition, ImportedAdapter,
        ImportedDiscovery, ImportedDiscoveryAuthentication, ImportedServiceDefinition, Provider,
        ProviderError,
    };
    use std::sync::Arc;

    /// Validation-only adapter double; configuration checks never build one.
    #[derive(Debug)]
    struct MarkedAdapter {
        kind: &'static str,
        development_only: bool,
    }
    static DEVELOPMENT_ADAPTER: MarkedAdapter = MarkedAdapter {
        kind: "fixture_import",
        development_only: true,
    };
    static PRODUCTION_ADAPTER: MarkedAdapter = MarkedAdapter {
        kind: "remote_import",
        development_only: false,
    };

    #[async_trait::async_trait]
    impl ImportedAdapter for MarkedAdapter {
        fn kind(&self) -> &'static str {
            self.kind
        }
        fn development_only(&self) -> bool {
            self.development_only
        }
        fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
            unreachable!("configuration validation never validates actions")
        }
        fn scoped_mcp_name(&self, _: &ImportedActionDefinition) -> Result<String, String> {
            unreachable!("configuration validation never names actions")
        }
        fn build(
            &self,
            _: &ImportedServiceDefinition,
            _: &[ImportedActionDefinition],
            _: Option<ExecutionCredential>,
            _: &BuildContext<'_>,
        ) -> Result<Arc<dyn Provider>, HostError> {
            unreachable!("configuration validation never builds providers")
        }
        async fn discover(
            &self,
            _: &ImportedServiceDefinition,
            _: &ImportedDiscoveryAuthentication,
            _: Option<ExecutionCredential>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedDiscovery, ProviderError> {
            unreachable!("configuration validation never discovers")
        }
    }

    fn import_errors(environment: &str, enable_fake_service: bool, kind: &str) -> Vec<String> {
        let registry = BackendRegistry::empty()
            .with_imported_adapters([
                &DEVELOPMENT_ADAPTER as &dyn ImportedAdapter,
                &PRODUCTION_ADAPTER as &dyn ImportedAdapter,
            ])
            .unwrap();
        let mut config = parse_broker_config_raw(
            "imports.toml",
            "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n",
            &Arc::new(BackendRegistry::empty()),
        )
        .unwrap();
        config.providers = ProvidersConfig::new(Arc::new(registry));
        config.deployment.environment = environment.into();
        config.deployment.enable_fake_service = enable_fake_service;
        config.imports.allowed_kinds = vec![kind.into()];
        let mut errors = Vec::new();
        validate_imports(&config, &mut errors);
        errors
    }

    #[test]
    fn development_only_adapter_kinds_require_the_fake_service_opt_in() {
        assert!(import_errors("development", true, "fixture_import").is_empty());
        for (environment, enable_fake_service) in [
            ("development", false),
            ("production", true),
            ("production", false),
        ] {
            assert_eq!(
                import_errors(environment, enable_fake_service, "fixture_import"),
                [
                    "imports.allowed_kinds contains the development-only adapter kind fixture_import, which requires non-production deployment.enable_fake_service"
                ],
                "{environment} {enable_fake_service}"
            );
        }
        for (environment, enable_fake_service) in [
            ("development", true),
            ("development", false),
            ("production", false),
        ] {
            assert!(
                import_errors(environment, enable_fake_service, "remote_import").is_empty(),
                "{environment} {enable_fake_service}"
            );
        }
    }

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
