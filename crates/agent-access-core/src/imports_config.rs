use crate::imports::{COMMAND_ENDPOINT_PREFIX, ImportEndpointForm, is_command_name};
use crate::{BrokerConfig, CommandImportsConfig};
use agent_access_provider::{is_service_name, url_allowed_by_patterns, validate_upstream_base_url};
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
    /// The operator gate for one destination of an import of `kind`, whose
    /// adapter uses endpoint `form`: imports are enabled, the kind is
    /// allowed, the service is not disabled, and the destination has the
    /// adapter's form and is approved for it. An HTTP(S) destination must
    /// match `allowed_endpoints`; a `command:<name>` destination must name a
    /// `[command_imports.<name>]` entry in `command_imports`.
    pub fn permits(
        &self,
        command_imports: &CommandImportsConfig,
        form: ImportEndpointForm,
        service: &str,
        kind: &str,
        destination: &str,
    ) -> bool {
        self.enabled
            && self.allowed_kinds.iter().any(|allowed| allowed == kind)
            && !self
                .disabled_services
                .iter()
                .any(|disabled| disabled == service)
            && match (form, destination.strip_prefix(COMMAND_ENDPOINT_PREFIX)) {
                (ImportEndpointForm::Command, Some(name)) => {
                    is_command_name(name) && command_imports.contains_key(name)
                }
                (ImportEndpointForm::Http, None) => Url::parse(destination)
                    .is_ok_and(|url| url_allowed_by_patterns(&url, &self.allowed_endpoints)),
                _ => false,
            }
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
    // Command endpoints are approved by `[command_imports]`, so an operator
    // allowing only command-form kinds needs no `allowed_endpoints`.
    let needs_endpoints = imports.allowed_kinds.iter().any(|kind| {
        config
            .providers
            .registry()
            .imported_adapter(kind)
            .is_none_or(|adapter| adapter.endpoint_form() == ImportEndpointForm::Http)
    });
    if imports.enabled
        && (imports.allowed_kinds.is_empty()
            || (needs_endpoints && imports.allowed_endpoints.is_empty()))
    {
        errors.push(
            "enabled imports require nonempty allowed_kinds, and nonempty allowed_endpoints unless every allowed kind uses command endpoints"
                .into(),
        );
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
    use crate::imports::{
        AdapterDiscoveryError, ImportedActionDefinition, ImportedAdapter, ImportedAdapterContext,
        ImportedDiscovery, ImportedDiscoveryAuthentication, ImportedProvider,
        ImportedServiceDefinition, imported_adapter_registration,
    };
    use crate::{BackendRegistry, ProvidersConfig, parse_broker_config_raw};
    use agent_access_provider::{BuildContext, ExecutionCredential, ProviderBuildError};
    use std::sync::Arc;

    /// Validation-only adapter double; configuration checks never build one.
    #[derive(Debug)]
    struct MarkedAdapter {
        kind: &'static str,
        development_only: bool,
        form: ImportEndpointForm,
    }
    static DEVELOPMENT_ADAPTER: MarkedAdapter = MarkedAdapter {
        kind: "fixture_import",
        development_only: true,
        form: ImportEndpointForm::Http,
    };
    static PRODUCTION_ADAPTER: MarkedAdapter = MarkedAdapter {
        kind: "remote_import",
        development_only: false,
        form: ImportEndpointForm::Http,
    };
    static COMMAND_ADAPTER: MarkedAdapter = MarkedAdapter {
        kind: "command",
        development_only: false,
        form: ImportEndpointForm::Command,
    };

    #[async_trait::async_trait]
    impl ImportedAdapter for MarkedAdapter {
        fn credential_contract(
            &self,
            definition: &crate::imports::ImportedServiceDefinition,
            import: &crate::imports::ImportedAdapterContext<'_>,
        ) -> Result<crate::imports::ImportedCredentialContract, String> {
            crate::imports::test_credential_contract(definition, import)
        }
        fn kind(&self) -> &'static str {
            self.kind
        }
        fn development_only(&self) -> bool {
            self.development_only
        }
        fn endpoint_form(&self) -> ImportEndpointForm {
            self.form
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
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedProvider, ProviderBuildError> {
            unreachable!("configuration validation never builds providers")
        }
        async fn discover(
            &self,
            _: &ImportedServiceDefinition,
            _: &ImportedDiscoveryAuthentication,
            _: Option<ExecutionCredential>,
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
            unreachable!("configuration validation never discovers")
        }
    }

    fn import_errors(environment: &str, enable_fake_service: bool, kind: &str) -> Vec<String> {
        let mut config = import_config(environment, enable_fake_service);
        config.imports.allowed_kinds = vec![kind.into()];
        let mut errors = Vec::new();
        validate_imports(&config, &mut errors);
        errors
    }

    fn import_config(environment: &str, enable_fake_service: bool) -> BrokerConfig {
        let registry = BackendRegistry::empty()
            .with_imported_adapters([
                imported_adapter_registration(
                    agent_access_provider::module_metadata!(),
                    &DEVELOPMENT_ADAPTER,
                    None,
                ),
                imported_adapter_registration(
                    agent_access_provider::module_metadata!(),
                    &PRODUCTION_ADAPTER,
                    None,
                ),
                imported_adapter_registration(
                    agent_access_provider::module_metadata!(),
                    &COMMAND_ADAPTER,
                    None,
                ),
            ])
            .unwrap();
        let mut config = parse_broker_config_raw(
            "imports.toml",
            "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n[limits]\nupload_spool_dir = \"upload-spool\"\n",
            &Arc::new(BackendRegistry::empty()),
        )
        .unwrap();
        config.providers = ProvidersConfig::new(Arc::new(registry));
        config.deployment.environment = environment.into();
        config.deployment.enable_fake_service = enable_fake_service;
        config
    }

    #[test]
    fn allowed_endpoints_are_optional_only_for_command_endpoint_kinds() {
        let mut config = import_config("development", false);
        config.imports.enabled = true;
        let errors = |config: &BrokerConfig| {
            let mut errors = Vec::new();
            validate_imports(config, &mut errors);
            errors
                .into_iter()
                .filter(|error| error.contains("allowed_endpoints"))
                .collect::<Vec<_>>()
        };
        config.imports.allowed_kinds = vec!["command".into()];
        assert!(errors(&config).is_empty());
        config.imports.allowed_kinds = vec!["command".into(), "remote_import".into()];
        assert_eq!(errors(&config).len(), 1);
        config.imports.allowed_endpoints = vec!["https://tools.example/**".into()];
        assert!(errors(&config).is_empty());
        config.imports.allowed_kinds.clear();
        assert_eq!(errors(&config).len(), 1);
    }

    #[test]
    fn command_destinations_need_an_approved_command_entry() {
        use ImportEndpointForm::{Command, Http};
        let config = ImportsConfig {
            enabled: true,
            allowed_kinds: vec!["command".into(), "remote_import".into()],
            allowed_endpoints: vec!["https://tools.example/**".into(), "command:*".into()],
            disabled_services: vec!["disabled".into()],
        };
        let mut commands = CommandImportsConfig::new();
        commands.insert(
            "ticketing".into(),
            toml::from_str("path = \"/opt/agent-commands/ticketing\"").unwrap(),
        );
        assert!(config.permits(
            &commands,
            Command,
            "tickets",
            "command",
            "command:ticketing"
        ));
        for (form, service, kind, destination) in [
            (Command, "tickets", "command", "command:other"),
            (Command, "tickets", "command", "command:Ticketing"),
            (Command, "tickets", "command", "command:"),
            (Command, "tickets", "mcp_http", "command:ticketing"),
            (Command, "disabled", "command", "command:ticketing"),
            // The adapter's form decides: an HTTP adapter's command-shaped
            // destination, or a command adapter's URL, is never permitted.
            (Http, "tickets", "remote_import", "command:ticketing"),
            (Command, "tools", "command", "https://tools.example/mcp"),
        ] {
            assert!(
                !config.permits(&commands, form, service, kind, destination),
                "{form:?} {service} {kind} {destination}"
            );
        }
        // An HTTP pattern never approves a command, nor a command entry a URL.
        assert!(!config.permits(
            &CommandImportsConfig::new(),
            Command,
            "tickets",
            "command",
            "command:ticketing"
        ));
        let mut http = config.clone();
        assert!(http.permits(
            &commands,
            Http,
            "tools",
            "remote_import",
            "https://tools.example/mcp"
        ));
        http.allowed_endpoints.clear();
        assert!(!http.permits(
            &commands,
            Http,
            "tools",
            "remote_import",
            "https://tools.example/mcp"
        ));
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
        let commands = CommandImportsConfig::new();
        let http = ImportEndpointForm::Http;
        assert!(config.permits(
            &commands,
            http,
            "tools",
            "mcp_http",
            "https://tools.example/mcp"
        ));
        for (service, kind, endpoint) in [
            ("disabled", "mcp_http", "https://tools.example/mcp"),
            ("tools", "openapi_http", "https://tools.example/mcp"),
            ("tools", "mcp_http", "https://tools.example/other"),
            ("tools", "mcp_http", "https://other.example/mcp"),
        ] {
            assert!(!config.permits(&commands, http, service, kind, endpoint));
        }
        config.enabled = false;
        assert!(!config.permits(
            &commands,
            http,
            "tools",
            "mcp_http",
            "https://tools.example/mcp"
        ));
    }
}
