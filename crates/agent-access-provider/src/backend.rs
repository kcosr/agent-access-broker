//! Backend registration: how the broker parses, validates, describes, and
//! builds a backend from its `[providers.<kind>]` table.
use crate::{
    EgressProxyConfig, EgressProxyRuntimeConfig, HostError, PreparedOutboundTls, Provider,
    ProviderAttributionConfig, ProviderLimits, ResourceTypeDescriptor, ServiceDescriptor,
    StableSigningKey,
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
#[derive(Debug)]
pub struct BackendRegistration {
    /// The `[providers.<kind>]` table name, which is also the service the
    /// backend serves.
    pub kind: &'static str,
    /// Resource types the backend defines, in listing order.
    pub resource_types: &'static [&'static ResourceTypeDescriptor],
    pub parse: BackendConfigParser,
    /// Development fixtures are accepted only when the deployment enables
    /// fake services, and never in production.
    pub development_only: bool,
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

    /// Builds the provider for one runtime generation.
    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, HostError>;
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

/// Host services a backend uses to build its provider.
#[derive(Clone)]
pub struct BuildContext<'a> {
    pub limits: &'a ProviderLimits,
    pub egress: &'a EgressProxyRuntimeConfig,
    pub outbound_tls: &'a PreparedOutboundTls,
    /// Attribution footers the configuration enables for this service.
    pub attribution: ProviderAttributionConfig,
    /// Stable key for handles and cursors that must outlive a runtime
    /// generation; absent when the broker has no stable key configured.
    pub stable_signing_key: Option<Arc<dyn StableSigningKey>>,
}

impl BuildContext<'_> {
    /// The network settings upstream clients are built from.
    pub fn network(&self) -> crate::UpstreamNetwork<'_> {
        crate::UpstreamNetwork {
            limits: self.limits,
            egress: self.egress,
            outbound_tls: self.outbound_tls,
        }
    }
}
