//! Backend registration: how the broker parses, validates, describes, and
//! builds a backend from its `[providers.<kind>]` table.
use crate::host::UpstreamClientFactory;
use crate::{
    EgressProxyConfig, ModuleMetadata, Provider, ProviderAttributionConfig, ProviderBuildError,
    ProviderLimits, ResourceTypeDescriptor, ServiceDescriptor, StableSigningKey,
};
use serde::de::DeserializeOwned;
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

/// Parses one `[providers.<kind>]` table. Parsers must reject unknown fields.
pub type BackendConfigParser =
    fn(toml::de::ValueDeserializer<'_>) -> Result<Box<dyn BackendConfig>, toml::de::Error>;

/// A backend this build links. The broker binary lists its registrations;
/// a `[providers.<kind>]` table configures one of them.
///
/// Declare it as a `static` with the `const` builder:
///
/// ```
/// # use agent_access_provider::{BackendConfig, BackendRegistration, module_metadata};
/// # fn parse(
/// #     _: toml::de::ValueDeserializer<'_>,
/// # ) -> Result<Box<dyn BackendConfig>, toml::de::Error> {
/// #     unimplemented!()
/// # }
/// pub static EXAMPLE_BACKEND: BackendRegistration =
///     BackendRegistration::new(module_metadata!(), "example", parse);
/// assert_eq!(EXAMPLE_BACKEND.kind(), "example");
/// assert!(EXAMPLE_BACKEND.resource_types().is_empty());
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub struct BackendRegistration {
    module: ModuleMetadata,
    kind: &'static str,
    resource_types: &'static [&'static ResourceTypeDescriptor],
    parse: BackendConfigParser,
    development_only: bool,
}

impl BackendRegistration {
    /// A backend from `module` serving `kind`, whose `[providers.<kind>]`
    /// table `parse` reads. It defines no resource types and is not a
    /// development fixture.
    pub const fn new(
        module: ModuleMetadata,
        kind: &'static str,
        parse: BackendConfigParser,
    ) -> Self {
        Self {
            module,
            kind,
            resource_types: &[],
            parse,
            development_only: false,
        }
    }

    /// Declares the resource types the backend defines, in listing order.
    pub const fn with_resource_types(
        mut self,
        resource_types: &'static [&'static ResourceTypeDescriptor],
    ) -> Self {
        self.resource_types = resource_types;
        self
    }

    /// Marks the backend as a development fixture: it is accepted only when
    /// the deployment enables fake services, and never in production.
    pub const fn development_only(mut self) -> Self {
        self.development_only = true;
        self
    }

    /// The package that declares this backend.
    pub const fn module(&self) -> ModuleMetadata {
        self.module
    }

    /// The `[providers.<kind>]` table name, which is also the service the
    /// backend serves.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Resource types the backend defines, in listing order.
    pub const fn resource_types(&self) -> &'static [&'static ResourceTypeDescriptor] {
        self.resource_types
    }

    pub const fn is_development_only(&self) -> bool {
        self.development_only
    }

    /// Parses this backend's `[providers.<kind>]` table with its strict
    /// parser.
    pub fn parse_config(
        &self,
        table: toml::de::ValueDeserializer<'_>,
    ) -> Result<Box<dyn BackendConfig>, toml::de::Error> {
        (self.parse)(table)
    }
}

/// Parser for a backend whose configuration deserializes directly into `T`.
pub fn parse_backend_config<T>(
    table: toml::de::ValueDeserializer<'_>,
) -> Result<Box<dyn BackendConfig>, toml::de::Error>
where
    T: BackendConfig + DeserializeOwned,
{
    Ok(Box::new(T::deserialize(table)?))
}

/// A parsed `[providers.<kind>]` table.
pub trait BackendConfig: Any + Debug + Send + Sync {
    fn kind(&self) -> &'static str;

    /// Checks this configuration against the rest of the broker
    /// configuration. Messages name fields under `providers.<kind>`.
    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>);

    /// Checks private resource values against this backend's active configuration.
    /// Diagnostics must never contain supplied values; callers may show them to admins.
    fn validate_resource_attributes(
        &self,
        _resource_type: &crate::ResourceType,
        _attributes: &crate::ResourceAttributes,
    ) -> Result<(), String> {
        Ok(())
    }

    /// The service this configuration defines. Must depend on the
    /// configuration alone: offline validation calls it before any provider
    /// exists.
    fn descriptor(&self) -> ServiceDescriptor;

    /// Configured egress proxies with their configuration labels, checked
    /// at startup even when an environment proxy takes precedence.
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)>;

    /// Builds the provider for one runtime generation. Building is
    /// synchronous and offline: it may prepare clients and capabilities, but
    /// never contacts an upstream, verifies a credential or refreshes OAuth.
    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError>;
}

/// The parts of the broker configuration a backend validates against.
#[derive(Debug, Clone, Copy)]
pub struct ValidationContext<'a> {
    /// `deployment.environment`.
    pub environment: &'a str,
    pub policy_authority: &'a str,
    pub limits: &'a ProviderLimits,
    /// Execution credentials configured for this backend's service.
    pub credentials: ServiceCredentialKinds<'a>,
}

impl ValidationContext<'_> {
    pub fn production(&self) -> bool {
        self.environment == "production"
    }
}

/// Credential kinds configured under `credentials.service.<service>` and
/// `credentials.per_user.<service>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceCredentialKinds<'a> {
    pub service: Option<&'a str>,
    pub per_user: Option<&'a str>,
}

/// Host services a backend builds its provider from for one runtime
/// generation. Only the host constructs it, through
/// [`crate::host::build_context`]; provider tests use `test_support::TestHost`.
#[derive(Clone)]
pub struct BuildContext<'a> {
    pub(crate) limits: &'a ProviderLimits,
    pub(crate) clients: &'a dyn UpstreamClientFactory,
    pub(crate) attribution: ProviderAttributionConfig,
    pub(crate) stable_signing_key: Option<Arc<dyn StableSigningKey>>,
}

impl<'a> BuildContext<'a> {
    pub fn limits(&self) -> &'a ProviderLimits {
        self.limits
    }

    /// Builds the generation's upstream clients; pass it to
    /// [`crate::UpstreamClient::build`]. The host decides each client's route.
    pub fn clients(&self) -> &'a dyn UpstreamClientFactory {
        self.clients
    }

    /// Attribution footers the configuration enables for this service.
    pub fn attribution(&self) -> &ProviderAttributionConfig {
        &self.attribution
    }

    /// Stable key, scoped to this service, for handles and cursors that must
    /// outlive a runtime generation; absent when the broker has no stable key
    /// configured.
    pub fn stable_signing_key(&self) -> Option<&Arc<dyn StableSigningKey>> {
        self.stable_signing_key.as_ref()
    }
}
