//! The modules an assembly links, validated once into an immutable
//! composition that every command and runtime generation shares.
use agent_access_core::imports::ImportedAdapterRegistration;
use agent_access_core::{
    BackendRegistry, ConfigError, HttpRouteSpec, http_route_specs, parse_broker_config_raw,
};
use agent_access_provider::{
    BackendRegistration, OAuthDialectRegistration, ResourceTypeRegistry, ServiceDescriptor,
};
use std::fmt;
use std::sync::Arc;

/// The native providers, OAuth dialects and import adapters an assembly
/// selects. Selecting a module makes it available to configure; it enables
/// nothing and creates no grants, resources, credentials, imports or consent.
///
/// A composition is immutable; clones share it. Configuration reload changes
/// what is configured within it, never what it links.
#[derive(Clone)]
pub struct BrokerComposition {
    registry: Arc<BackendRegistry>,
}

impl BrokerComposition {
    pub fn builder() -> BrokerCompositionBuilder {
        BrokerCompositionBuilder::default()
    }

    /// Selected native service kinds, in selection order (which is also the
    /// order their resource types are listed in).
    pub fn native_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.registry
            .registrations()
            .map(|registration| registration.kind())
    }

    /// Selected OAuth dialect IDs, including the companion dialects that
    /// import selections contribute.
    pub fn oauth_dialect_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.registry.oauth_dialect_ids()
    }

    /// Selected import kinds, in selection order.
    pub fn import_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.registry.imported_adapter_kinds()
    }

    /// Every resource type the broker and its selected natives define.
    pub fn resource_types(&self) -> &ResourceTypeRegistry {
        self.registry.resource_types()
    }

    /// The broker's HTTP route specifications for this composition.
    pub fn http_route_specs(&self) -> Vec<HttpRouteSpec> {
        http_route_specs(self.registry.resource_types())
    }

    /// Service descriptors of the selected natives that a broker
    /// configuration document configures, in selection order. It parses the
    /// document through the selected strict parsers without validating it or
    /// reading any file it references.
    pub fn configured_service_descriptors(
        &self,
        config: &str,
    ) -> Result<Vec<ServiceDescriptor>, ConfigError> {
        let config = parse_broker_config_raw("broker configuration", config, &self.registry)?;
        Ok(config
            .providers
            .iter()
            .map(|provider| provider.descriptor())
            .collect())
    }

    pub(crate) fn registry(&self) -> &Arc<BackendRegistry> {
        &self.registry
    }

    /// A composition over a registry that host tests already build.
    #[cfg(test)]
    pub(crate) fn from_registry(registry: BackendRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }
}

impl fmt::Debug for BrokerComposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerComposition")
            .field("natives", &self.native_kinds().collect::<Vec<_>>())
            .field(
                "oauth_dialects",
                &self.oauth_dialect_ids().collect::<Vec<_>>(),
            )
            .field("import_kinds", &self.import_kinds().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Collects an assembly's selections for [`BrokerComposition`].
#[derive(Debug, Default)]
#[must_use]
pub struct BrokerCompositionBuilder {
    natives: Vec<&'static BackendRegistration>,
    oauth_dialects: Vec<&'static OAuthDialectRegistration>,
    import_adapters: Vec<ImportedAdapterRegistration>,
}

impl BrokerCompositionBuilder {
    /// Selects a native provider.
    pub fn native(mut self, registration: &'static BackendRegistration) -> Self {
        self.natives.push(registration);
        self
    }

    /// Selects an OAuth dialect. A dialect that an import selection
    /// contributes as its companion must not be selected again.
    pub fn oauth(mut self, registration: &'static OAuthDialectRegistration) -> Self {
        self.oauth_dialects.push(registration);
        self
    }

    /// Selects a shipped import adapter through its `registration()`,
    /// together with the OAuth companion it contributes, if any.
    pub fn import_adapter(mut self, registration: ImportedAdapterRegistration) -> Self {
        self.import_adapters.push(registration);
        self
    }

    /// Validates the selections together: identifiers must be valid, the
    /// native kind `broker` is reserved, and service kinds, resource types,
    /// dialects (including import companions) and adapters must be unique.
    pub fn build(self) -> Result<BrokerComposition, CompositionError> {
        let registry = BackendRegistry::new(self.natives)
            .and_then(|registry| registry.with_oauth_dialects(self.oauth_dialects))
            .and_then(|registry| registry.with_imported_adapters(self.import_adapters))
            .map_err(|problems| CompositionError { problems })?;
        Ok(BrokerComposition {
            registry: Arc::new(registry),
        })
    }
}

/// Why a composition was rejected. Problems name only the conflicting module
/// identities, in a deterministic order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionError {
    problems: Vec<String>,
}

impl CompositionError {
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("broker composition is invalid")
    }
}

impl std::error::Error for CompositionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_fake::FAKE_BACKEND;
    use agent_access_gitlab::GITLAB_BACKEND;
    use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
    use agent_access_jira::JIRA_BACKEND;
    use agent_access_provider::{GIT_REPOSITORY_RESOURCE, ResourceType};

    static INVALID_KIND: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "Not A Kind",
        agent_access_provider::parse_backend_config::<agent_access_fake::FakeProviderConfig>,
    )
    .development_only();
    static SECOND_JIRA_TYPES: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "jira_mirror",
        agent_access_provider::parse_backend_config::<agent_access_jira::JiraProviderConfig>,
    )
    .with_resource_types(JIRA_BACKEND.resource_types());
    static SECOND_GOOGLE: OAuthDialectRegistration = OAuthDialectRegistration::new(
        agent_access_provider::module_metadata!(),
        "google",
        GOOGLE_OAUTH_DIALECT.dialect(),
    );

    const MINIMAL_CONFIG: &str = r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"
"#;

    fn selection() -> BrokerCompositionBuilder {
        BrokerComposition::builder()
            .native(&JIRA_BACKEND)
            .native(&GITLAB_BACKEND)
            .native(&GMAIL_BACKEND)
            .oauth(&GOOGLE_OAUTH_DIALECT)
            .import_adapter(agent_access_mcp_upstream::registration())
    }

    #[test]
    fn a_valid_selection_projects_its_metadata_and_routes() {
        let composition = selection().build().unwrap();
        assert_eq!(
            composition.native_kinds().collect::<Vec<_>>(),
            ["jira", "gitlab", "gmail"]
        );
        assert_eq!(composition.import_kinds().collect::<Vec<_>>(), ["mcp_http"]);
        // The MCP selection contributes its companion dialect.
        assert_eq!(
            composition.oauth_dialect_ids().collect::<Vec<_>>(),
            ["google", "mcp_oauth"]
        );
        assert!(
            composition
                .registry()
                .imported_adapter("mcp_http")
                .is_some()
        );
        assert!(
            composition
                .registry()
                .imported_adapter("openapi_http")
                .is_none()
        );
        let resource_types = composition.resource_types();
        assert!(resource_types.get(&GIT_REPOSITORY_RESOURCE.id).is_some());
        assert!(
            resource_types
                .get(&ResourceType::new("jira_project").unwrap())
                .is_some()
        );
        assert!(
            composition
                .http_route_specs()
                .iter()
                .any(|route| route.method == "GET" && route.route == "/v1/services/{service}")
        );
    }

    #[test]
    fn clones_share_one_immutable_composition() {
        let composition = selection().build().unwrap();
        let clone = composition.clone();
        assert!(Arc::ptr_eq(composition.registry(), clone.registry()));
    }

    #[test]
    fn an_empty_selection_keeps_the_host_resource_model() {
        let composition = BrokerComposition::builder().build().unwrap();
        assert_eq!(composition.native_kinds().count(), 0);
        assert!(
            composition
                .resource_types()
                .get(&GIT_REPOSITORY_RESOURCE.id)
                .is_some()
        );
    }

    #[test]
    fn duplicate_and_invalid_natives_are_rejected_deterministically() {
        let build = || {
            BrokerComposition::builder()
                .native(&JIRA_BACKEND)
                .native(&INVALID_KIND)
                .native(&JIRA_BACKEND)
                .build()
                .unwrap_err()
        };
        let error = build();
        assert_eq!(error, build());
        assert_eq!(error.to_string(), "broker composition is invalid");
        assert!(
            error
                .problems()
                .contains(&"backend kind Not A Kind is not a valid service name".to_string()),
            "{error:?}"
        );
        assert!(
            error
                .problems()
                .contains(&"backend kind jira is registered more than once".to_string()),
            "{error:?}"
        );
    }

    #[test]
    fn a_resource_type_defined_by_two_natives_is_rejected() {
        let error = BrokerComposition::builder()
            .native(&JIRA_BACKEND)
            .native(&SECOND_JIRA_TYPES)
            .build()
            .unwrap_err();
        assert!(
            error
                .problems()
                .iter()
                .any(|problem| problem.contains("jira_project")),
            "{error:?}"
        );
    }

    #[test]
    fn duplicate_dialects_and_adapters_are_rejected() {
        let dialects = BrokerComposition::builder()
            .oauth(&GOOGLE_OAUTH_DIALECT)
            .oauth(&SECOND_GOOGLE)
            .build()
            .unwrap_err();
        assert_eq!(
            dialects.problems(),
            ["OAuth dialect google is registered more than once"]
        );
        let adapters = BrokerComposition::builder()
            .import_adapter(agent_access_openapi_upstream::registration())
            .import_adapter(agent_access_openapi_upstream::registration())
            .build()
            .unwrap_err();
        assert_eq!(
            adapters.problems(),
            ["import adapter kind openapi_http is registered more than once"]
        );
    }

    #[test]
    fn an_import_companion_cannot_be_selected_again_as_a_dialect() {
        static SECOND_MCP_OAUTH: OAuthDialectRegistration = OAuthDialectRegistration::new(
            agent_access_provider::module_metadata!(),
            "mcp_oauth",
            GOOGLE_OAUTH_DIALECT.dialect(),
        );
        let error = BrokerComposition::builder()
            .oauth(&SECOND_MCP_OAUTH)
            .import_adapter(agent_access_mcp_upstream::registration())
            .build()
            .unwrap_err();
        assert_eq!(
            error.problems(),
            ["OAuth dialect mcp_oauth is registered more than once"]
        );
    }

    #[test]
    fn the_reserved_broker_kind_is_rejected_even_if_never_configured() {
        static BROKER_KIND: BackendRegistration = BackendRegistration::new(
            agent_access_provider::module_metadata!(),
            "broker",
            agent_access_provider::parse_backend_config::<agent_access_fake::FakeProviderConfig>,
        );
        let error = BrokerComposition::builder()
            .native(&FAKE_BACKEND)
            .native(&BROKER_KIND)
            .build()
            .unwrap_err();
        assert_eq!(
            error.problems(),
            ["backend kind broker is reserved for the Broker control-plane namespace"]
        );
    }

    #[test]
    fn configured_descriptors_follow_selection_order() {
        let composition = BrokerComposition::builder()
            .native(&JIRA_BACKEND)
            .native(&FAKE_BACKEND)
            .build()
            .unwrap();
        let descriptors = composition
            .configured_service_descriptors(&format!(
                r#"{MINIMAL_CONFIG}
[providers.fake]

[providers.jira]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/rest/api/3/**"]
"#
            ))
            .unwrap();
        assert_eq!(
            descriptors
                .iter()
                .map(|descriptor| descriptor.service.as_str())
                .collect::<Vec<_>>(),
            ["jira", "fake"]
        );
        let unknown = composition
            .configured_service_descriptors(&format!("{MINIMAL_CONFIG}\n[providers.gitlab]\n"))
            .unwrap_err();
        let message = unknown.to_string();
        assert!(
            message.starts_with("failed to parse broker configuration"),
            "{message}"
        );
        assert!(message.contains("unknown provider `gitlab`"), "{message}");
    }
}
