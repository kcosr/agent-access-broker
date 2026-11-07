use crate::imports::{COMMAND_ENDPOINT_PREFIX, ImportEndpointForm, is_command_name};
use crate::{BrokerConfig, CommandImportsConfig};
use agent_access_provider::{is_service_name, url_allowed_by_patterns, validate_upstream_base_url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    #[serde(default)]
    pub gateway_bindings: BTreeMap<String, ImportedGatewayBinding>,
}

/// Operator-reserved host and destination for one managed gateway identity.
/// Protocol and execution authentication are selected by the accepted import.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedGatewayBinding {
    pub endpoint: String,
    pub broker_hosts: Vec<String>,
    pub auth_modes: Vec<String>,
    #[serde(default)]
    pub allow_forwarded_identity: bool,
    #[serde(default = "crate::gateway_config::default_basic_broker_token_username")]
    pub basic_broker_token_username: String,
    pub egress_proxy: Option<crate::EgressProxyConfig>,
    #[serde(default = "crate::gateway_config::default_gateway_redirect_policy")]
    pub redirect_policy: String,
    pub request_body_max_bytes: Option<u64>,
    pub response_body_max_bytes: Option<u64>,
    pub streaming_idle_timeout_ms: Option<u64>,
    #[serde(default = "crate::gateway_config::default_gateway_correlation_headers")]
    pub correlation_headers: bool,
}

impl ImportedGatewayBinding {
    /// Include private proxy references in the opaque fence hash, never in
    /// administrative projections or diagnostics.
    pub fn fingerprint(&self) -> String {
        let proxy = self.egress_proxy.as_ref().map(|proxy| {
            json!({
                "url":proxy.url,"usernameRef":proxy.username_ref,"passwordRef":proxy.password_ref,
            })
        });
        let value = json!({"endpoint":self.endpoint,"hosts":self.broker_hosts,
            "authModes":self.auth_modes,"allowForwardedIdentity":self.allow_forwarded_identity,
            "basicUsername":self.basic_broker_token_username,"proxy":proxy,
            "redirectPolicy":self.redirect_policy,"requestMax":self.request_body_max_bytes,
            "responseMax":self.response_body_max_bytes,"idleTimeout":self.streaming_idle_timeout_ms,
            "correlation":self.correlation_headers});
        format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
    }
}

/// Safe administrative options. Availability refers to new import creation;
/// a retained identity remains visible but cannot be assigned again.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedGatewayBindingView {
    pub service: String,
    pub endpoint: String,
    pub broker_hosts: Vec<String>,
    pub auth_modes: Vec<String>,
    pub allow_forwarded_identity: bool,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
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
    if (imports.enabled || !imports.gateway_bindings.is_empty())
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
            .is_some_and(|adapter| adapter.endpoint_form() == ImportEndpointForm::Http)
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
        if !is_service_name(kind) {
            errors.push(format!(
                "imports.allowed_kinds contains an invalid adapter kind {kind}"
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
    validate_gateway_bindings(config, errors);
}

fn validate_gateway_bindings(config: &BrokerConfig, errors: &mut Vec<String>) {
    let mut hosts = BTreeMap::<String, String>::new();
    for (service, gateway) in &config.gateways {
        for host in &gateway.broker_hosts {
            if let Ok(host) = crate::normalize_gateway_broker_host(host) {
                hosts.insert(host, service.clone());
            }
        }
    }
    let provider_services = crate::configured_provider_descriptors(config)
        .into_iter()
        .map(|descriptor| descriptor.service)
        .collect::<BTreeSet<_>>();
    for (service, binding) in &config.imports.gateway_bindings {
        let label = format!("imports.gateway_bindings.{service}");
        if service == "broker" || !is_service_name(service) {
            errors.push(format!("{label} has an invalid service identity"));
        }
        if config.providers.registry().get(service).is_some()
            || config.gateways.contains_key(service)
            || provider_services.contains(service)
            || config.credentials.connections.contains_key(service)
            || config.credentials.service.contains_key(service)
            || config.credentials.per_user.contains_key(service)
            || config.credentials.lookup.contains_key(service)
        {
            errors.push(format!(
                "{label} collides with a configured service or credential identity"
            ));
        }
        if binding.broker_hosts.is_empty() {
            errors.push(format!("{label}.broker_hosts must not be empty"));
        }
        for host in &binding.broker_hosts {
            match crate::normalize_gateway_broker_host(host) {
                Ok(host) => {
                    if hosts.insert(host, service.clone()).is_some() {
                        errors.push(format!(
                            "{label}.broker_hosts contains a reserved or duplicate host"
                        ));
                    }
                }
                Err(_) => errors.push(format!("{label}.broker_hosts contains an invalid host")),
            }
        }
        let endpoint = crate::imports::parse_import_endpoint(&binding.endpoint);
        if !matches!(&endpoint, Ok(crate::imports::ImportEndpoint::Http(_)))
            || binding.endpoint.contains(['*', '\\'])
        {
            errors.push(format!(
                "{label}.endpoint must be a fixed HTTP(S) API base URL"
            ));
        }
        if let Ok(crate::imports::ImportEndpoint::Http(url)) = endpoint {
            if config.deployment.environment == "production" && url.scheme() != "https" {
                errors.push(format!("{label}.endpoint must use HTTPS in production"));
            }
            if !url_allowed_by_patterns(&url, &config.imports.allowed_endpoints) {
                errors.push(format!(
                    "{label}.endpoint must also be approved by imports.allowed_endpoints"
                ));
            }
        }
        if binding.auth_modes.is_empty()
            || binding.auth_modes.iter().collect::<BTreeSet<_>>().len() != binding.auth_modes.len()
            || binding
                .auth_modes
                .iter()
                .any(|mode| !matches!(mode.as_str(), "bearer_broker_token" | "basic_broker_token"))
        {
            errors.push(format!(
                "{label}.auth_modes requires unique supported Broker authentication modes"
            ));
        }
        if binding.basic_broker_token_username.is_empty()
            || binding.basic_broker_token_username.contains(':')
            || binding
                .basic_broker_token_username
                .chars()
                .any(|c| !c.is_ascii() || c.is_whitespace() || c.is_control())
        {
            errors.push(format!("{label}.basic_broker_token_username is invalid"));
        }
        if binding.redirect_policy != "none" {
            errors.push(format!("{label}.redirect_policy must be none"));
        }
        for (field, value, maximum) in [
            (
                "request_body_max_bytes",
                binding.request_body_max_bytes,
                Some(config.limits.max_http_body_bytes),
            ),
            (
                "response_body_max_bytes",
                binding.response_body_max_bytes,
                Some(config.limits.max_upstream_response_bytes),
            ),
            (
                "streaming_idle_timeout_ms",
                binding.streaming_idle_timeout_ms,
                None,
            ),
        ] {
            if value
                .is_some_and(|value| value == 0 || maximum.is_some_and(|maximum| value > maximum))
            {
                errors.push(format!(
                    "{label}.{field} must be nonzero and within the host limit"
                ));
            }
        }
        agent_access_provider::validate_egress_proxy_config(
            &format!("{label}.egress_proxy"),
            binding.egress_proxy.as_ref(),
            errors,
        );
    }
}

pub(crate) fn validate_imported_gateway_bindings(
    config: &BrokerConfig,
    catalog: &crate::ImportedCatalog,
) -> Result<(), String> {
    for (service, binding) in &config.imports.gateway_bindings {
        let Some(record) = catalog.service(service) else {
            continue;
        };
        let gateway = config
            .providers
            .registry()
            .imported_adapter(&record.definition.adapter_kind)
            .map(|adapter| adapter.gateway_kind().is_some())
            .unwrap_or(record.gateway_routes.is_some());
        if !gateway {
            return Err(format!(
                "imports.gateway_bindings.{service} collides with a retained non-gateway import"
            ));
        }
        if record.definition.endpoint != binding.endpoint {
            return Err(format!(
                "imports.gateway_bindings.{service} endpoint differs from its retained import"
            ));
        }
    }
    Ok(())
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
            gateway_bindings: Default::default(),
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
            gateway_bindings: Default::default(),
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
    fn binding(endpoint: &str, host: &str) -> ImportedGatewayBinding {
        toml::from_str(&format!("endpoint = {endpoint:?}\nbroker_hosts = [{host:?}]\nauth_modes = [\"bearer_broker_token\"]\n")).unwrap()
    }

    #[test]
    fn gateway_binding_reserves_canonical_hosts_and_requires_exact_allowed_destination() {
        let mut config = import_config("development", false);
        config.imports.allowed_endpoints = vec!["https://api.example/**".into()];
        config.imports.gateway_bindings.insert(
            "inventory".into(),
            binding("https://api.example/api", "inventory.gateway.example"),
        );
        let errors = |config: &BrokerConfig| {
            let mut errors = Vec::new();
            validate_gateway_bindings(config, &mut errors);
            errors
        };
        assert!(errors(&config).is_empty());
        config.imports.gateway_bindings.insert(
            "other".into(),
            binding("https://api.example/api", "inventory.gateway.example"),
        );
        assert!(
            errors(&config)
                .iter()
                .any(|error| error.contains("reserved or duplicate host"))
        );
        config.imports.gateway_bindings.remove("other");
        let mut static_gateway =
            crate::GatewayConfig::new("git_http", "Git", "https://git.example");
        static_gateway.broker_hosts = vec!["inventory.gateway.example".into()];
        config.gateways.insert("git".into(), static_gateway);
        assert!(
            errors(&config)
                .iter()
                .any(|error| error.contains("reserved or duplicate host"))
        );
        config.gateways.clear();
        config
            .imports
            .gateway_bindings
            .get_mut("inventory")
            .unwrap()
            .endpoint = "https://unapproved.example/api".into();
        assert!(
            errors(&config)
                .iter()
                .any(|error| error.contains("allowed_endpoints"))
        );
        config
            .imports
            .gateway_bindings
            .get_mut("inventory")
            .unwrap()
            .endpoint = "https://api.example/**".into();
        assert!(
            errors(&config)
                .iter()
                .any(|error| error.contains("fixed HTTP(S)"))
        );
    }

    #[test]
    fn gateway_binding_rejects_identity_collisions_unsafe_ingress_and_oversized_caps() {
        let mut config = import_config("production", false);
        config.imports.allowed_endpoints = vec!["http://api.example/**".into()];
        config.imports.gateway_bindings.insert(
            "broker".into(),
            binding("http://api.example/api", "api.gateway.example"),
        );
        let mut errors = Vec::new();
        validate_gateway_bindings(&config, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("invalid service identity"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("HTTPS in production"))
        );
        let mut entry = config.imports.gateway_bindings.remove("broker").unwrap();
        entry.auth_modes = vec!["anonymous".into()];
        entry.redirect_policy = "same_origin".into();
        entry.request_body_max_bytes = Some(config.limits.max_http_body_bytes + 1);
        config
            .imports
            .gateway_bindings
            .insert("inventory".into(), entry);
        errors.clear();
        validate_gateway_bindings(&config, &mut errors);
        for expected in ["auth_modes", "redirect_policy", "request_body_max_bytes"] {
            assert!(errors.iter().any(|error| error.contains(expected)));
        }
    }

    #[test]
    fn unavailable_adapter_kinds_keep_syntax_admission_and_no_execution_authority() {
        assert!(import_errors("development", false, "unlinked_gateway").is_empty());
        let mut config = import_config("development", false);
        config.imports.enabled = true;
        config.imports.allowed_kinds = vec!["unlinked_gateway".into()];
        let mut errors = Vec::new();
        validate_imports(&config, &mut errors);
        assert!(
            !errors
                .iter()
                .any(|error| error.contains("allowed_endpoints"))
        );
        assert!(!import_errors("development", false, "BadAdapter").is_empty());
    }
    #[test]
    fn gateway_binding_proxy_secrets_are_preflighted_even_without_an_import() {
        let mut config = import_config("development", false);
        let mut binding = binding("https://api.example/api", "inventory.gateway.example");
        binding.egress_proxy = Some(crate::EgressProxyConfig {
            url: "https://proxy.example:8443".into(),
            username_ref: Some("env:AGENT_ACCESS_MISSING_IMPORTED_GATEWAY_PROXY_USER".into()),
            password_ref: Some("env:AGENT_ACCESS_MISSING_IMPORTED_GATEWAY_PROXY_PASSWORD".into()),
        });
        config
            .imports
            .gateway_bindings
            .insert("inventory".into(), binding);
        let error = crate::runtime::preflight_configured_egress_proxies(&config).unwrap_err();
        assert!(
            matches!(error, crate::RuntimeError::MissingEnv { label, name }
            if label == "imports.gateway_bindings.inventory.egress_proxy.username_ref"
            && name == "AGENT_ACCESS_MISSING_IMPORTED_GATEWAY_PROXY_USER")
        );
    }

    fn retained_import(
        adapter_kind: &str,
        status: crate::ImportedServiceStatus,
        gateway: bool,
    ) -> crate::ImportedServiceRecord {
        crate::ImportedServiceRecord {
            definition: ImportedServiceDefinition {
                service: "inventory".into(),
                display_name: "Inventory".into(),
                adapter_kind: adapter_kind.into(),
                endpoint: "https://api.example/api".into(),
                connection_settings: BTreeMap::new(),
                execution_bindings: vec![crate::imports::ImportedCredentialBinding::token(
                    crate::imports::ImportedCredentialMode::Service,
                    crate::imports::ImportedCredentialDelivery::Bearer,
                )],
                discovery: crate::imports::ImportedDiscoveryCredential::Anonymous,
                transport_auth: false,
                invocation_limit: None,
            },
            status,
            version: 3,
            actions: Vec::new(),
            slot_versions: BTreeMap::new(),
            accepted_metadata: None,
            document: None,
            gateway_routes: gateway.then(|| {
                crate::imports::ImportedGatewayRouteRecord::next(
                    None,
                    crate::imports::ImportedGatewayRouteCandidate::new(
                        json!({"version":1,"paths":{}}),
                    )
                    .unwrap(),
                )
                .unwrap()
            }),
            created_at: "2026-11-07T00:00:00Z".into(),
            created_by: "admin".into(),
            updated_at: "2026-11-07T00:00:00Z".into(),
            updated_by: "admin".into(),
        }
    }

    #[test]
    fn gateway_binding_rejects_retained_non_gateway_imports_in_every_status() {
        let mut config = import_config("development", false);
        config.imports.gateway_bindings.insert(
            "inventory".into(),
            binding("https://api.example/api", "inventory.gateway.example"),
        );
        for status in [
            crate::ImportedServiceStatus::Draft,
            crate::ImportedServiceStatus::Disabled,
            crate::ImportedServiceStatus::Enabled,
            crate::ImportedServiceStatus::Retired,
        ] {
            for kind in ["remote_import", "unlinked_import"] {
                let catalog = crate::ImportedCatalog {
                    revision: 4,
                    services: vec![retained_import(kind, status, false)],
                };
                assert_eq!(
                    validate_imported_gateway_bindings(&config, &catalog).unwrap_err(),
                    "imports.gateway_bindings.inventory collides with a retained non-gateway import"
                );
            }
        }
        // A known invoke adapter cannot become a gateway through an opaque
        // route row: the linked adapter's capability remains authoritative.
        let catalog = crate::ImportedCatalog {
            revision: 4,
            services: vec![retained_import(
                "remote_import",
                crate::ImportedServiceStatus::Retired,
                true,
            )],
        };
        assert!(validate_imported_gateway_bindings(&config, &catalog).is_err());
    }

    #[test]
    fn retired_gateway_binding_keeps_its_exact_destination_without_a_linked_adapter() {
        let mut config = import_config("development", false);
        config.imports.gateway_bindings.insert(
            "inventory".into(),
            binding("https://api.example/api", "inventory.gateway.example"),
        );
        let catalog = crate::ImportedCatalog {
            revision: 4,
            services: vec![retained_import(
                "unlinked_gateway",
                crate::ImportedServiceStatus::Retired,
                true,
            )],
        };
        validate_imported_gateway_bindings(&config, &catalog).unwrap();
        for endpoint in [
            "https://api.example/another-api",
            "https://other.example/api",
            "https://api.example/api/",
        ] {
            config
                .imports
                .gateway_bindings
                .get_mut("inventory")
                .unwrap()
                .endpoint = endpoint.into();
            assert_eq!(
                validate_imported_gateway_bindings(&config, &catalog).unwrap_err(),
                "imports.gateway_bindings.inventory endpoint differs from its retained import"
            );
        }
    }
}
