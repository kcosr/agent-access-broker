use agent_access_provider::{
    BackendConfig, CredentialDescriptor, CredentialSource, Decision, EgressProxyConfig,
    OAuthScopeMode, ProviderLimits, ReasonCodeId, ResourceScopes, ResourceSelector,
    ResourceTypeRegistry, ServiceCredentialKinds, ServiceDescriptor, ValidationContext,
    default_download_max_bytes, is_action_name, is_env_name, is_loopback_or_localhost,
    is_secret_ref, is_service_name,
    presentation::{ReadContentFormat, ResponseFormat},
    validate_egress_proxy_config, validate_upstream_allowlist,
};
use attribution::validate_attribution_config;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use thiserror::Error;
use url::Url;

mod api;
mod attribution;
mod audit_query;
mod backends;
mod command_imports_config;
mod config_error;
pub mod connections;
mod fs_permissions;
mod gateway_token_auth;
mod import_names;
pub mod imports;
mod imports_config;
mod invocation_limits;
mod managed_store;
pub mod mcp;
mod mcp_config;
pub mod microsoft_oidc;
mod network;
mod node_identity;
pub mod oauth;
mod resource_policy;
mod runtime;
mod sqlite_support;
mod state_lock;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use api::*;
pub use attribution::AttributionConfig;
pub use audit_query::*;
pub use backends::{BackendRegistry, ProvidersConfig};
pub use command_imports_config::*;
pub use config_error::{ConfigError, HostConfigError, load_secret_ref_value};
pub use connections::{
    CONNECTION_CREDENTIAL_NAME, ConnectionConfig, ConnectionOAuthConfig, PersonalConnection,
    PrincipalKind, Selection, select,
};
pub use gateway_token_auth::{GatewayUpstreamTokenAuth, gateway_upstream_authorization};
pub use import_names::*;
pub use imports_config::*;
pub use invocation_limits::*;
pub use managed_store::*;
pub use mcp_config::*;
pub use network::{
    OutboundTlsConfig, OutboundTlsTrustMode, PreparedOutboundTls,
    parse_strict_certificate_pem_bundle,
};
pub use node_identity::*;
pub use oauth::*;
pub use resource_policy::*;
pub use runtime::*;
pub use state_lock::*;

pub const DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL: &str = "30d";
pub const EXECUTION_CONTEXT_HEADER: &str = "X-Agent-Access-Context";
pub const DEFAULT_EXECUTION_CONTEXT: &str = "default";
pub const EXECUTION_CONTEXT_MAX_VALUES: usize = 64;
pub const EXECUTION_CONTEXT_MAX_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionContext(String);

impl ExecutionContext {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidExecutionContext> {
        let value = value.into();
        if is_valid_execution_context_value(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidExecutionContext)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ExecutionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ExecutionContext {
    type Err = InvalidExecutionContext;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ExecutionContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExecutionContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("execution context must match [a-z][a-z0-9_-]{{0,63}}")]
pub struct InvalidExecutionContext;

pub fn is_valid_execution_context_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(first) if first.is_ascii_lowercase())
        && bytes.len() <= EXECUTION_CONTEXT_MAX_LENGTH
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentInvokeTokenCaveats {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_services: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_execution_contexts: Option<Vec<ExecutionContext>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_restrictions: Option<BTreeMap<String, AgentTokenServiceRestriction>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenServiceRestriction {
    pub actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceSelection>,
}

impl AgentInvokeTokenCaveats {
    /// Parses stored caveats using the same required context binding as issuance.
    pub fn parse_stored(scopes: &serde_json::Value) -> Result<Self, AgentInvokeTokenCaveatError> {
        Self::parse_issuance_structure(scopes)
    }

    /// Parses caveats for a newly issued `agent_invoke` token.
    ///
    /// Issuance requires one or more configured execution contexts. Management
    /// token classes do not use this structure.
    pub fn parse_issuance(
        scopes: &serde_json::Value,
        execution_context: Option<&ExecutionContextConfig>,
    ) -> Result<Self, AgentInvokeTokenCaveatError> {
        let caveats = Self::parse_issuance_structure(scopes)?;
        caveats.validate_configured_context_membership(execution_context)?;
        Ok(caveats)
    }

    /// Ensures every context caveat names a value in the active configuration.
    /// Context-neutral configuration has the single canonical `default` value.
    pub fn validate_configured_context_membership(
        &self,
        execution_context: Option<&ExecutionContextConfig>,
    ) -> Result<(), AgentInvokeTokenCaveatError> {
        let Some(contexts) = self.allowed_execution_contexts.as_ref() else {
            return Ok(());
        };
        for context in contexts {
            let configured = execution_context.map_or_else(
                || context.as_str() == DEFAULT_EXECUTION_CONTEXT,
                |config| {
                    config
                        .allowed_values
                        .iter()
                        .any(|value| value == context.as_str())
                },
            );
            if !configured {
                return Err(AgentInvokeTokenCaveatError::ExecutionContextNotConfigured {
                    context: context.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn to_scopes_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("agent invoke token caveats are JSON serializable")
    }

    pub(crate) fn parse_issuance_structure(
        scopes: &serde_json::Value,
    ) -> Result<Self, AgentInvokeTokenCaveatError> {
        let caveats = Self::parse(scopes)?;
        if caveats.allowed_execution_contexts.is_none() {
            return Err(AgentInvokeTokenCaveatError::ExecutionContextsRequired);
        }
        Ok(caveats)
    }

    fn parse(scopes: &serde_json::Value) -> Result<Self, AgentInvokeTokenCaveatError> {
        let wire = serde_json::from_value::<AgentInvokeTokenCaveatsWire>(scopes.clone())
            .map_err(|error| AgentInvokeTokenCaveatError::Malformed(error.to_string()))?;
        let mut caveats = Self {
            allowed_services: wire.allowed_services,
            allowed_execution_contexts: wire.allowed_execution_contexts,
            service_restrictions: wire.service_restrictions.map(|restrictions| {
                restrictions
                    .into_iter()
                    .map(|(service, restriction)| {
                        (
                            service,
                            AgentTokenServiceRestriction {
                                actions: restriction.actions,
                                resources: restriction.resources,
                            },
                        )
                    })
                    .collect()
            }),
        };
        caveats.normalize_and_validate_lists()?;
        Ok(caveats)
    }

    fn normalize_and_validate_lists(&mut self) -> Result<(), AgentInvokeTokenCaveatError> {
        if let Some(services) = &self.allowed_services {
            if services.is_empty() {
                return Err(AgentInvokeTokenCaveatError::AllowedServicesEmpty);
            }
            let mut unique = BTreeSet::new();
            for service in services {
                if !is_service_name(service) {
                    return Err(AgentInvokeTokenCaveatError::AllowedServiceInvalid {
                        service: service.clone(),
                    });
                }
                if !unique.insert(service) {
                    return Err(AgentInvokeTokenCaveatError::AllowedServiceDuplicate {
                        service: service.clone(),
                    });
                }
            }
        }

        if let Some(contexts) = &self.allowed_execution_contexts {
            if contexts.is_empty() {
                return Err(AgentInvokeTokenCaveatError::ExecutionContextsEmpty);
            }
            if contexts.len() > EXECUTION_CONTEXT_MAX_VALUES {
                return Err(AgentInvokeTokenCaveatError::TooManyExecutionContexts {
                    maximum: EXECUTION_CONTEXT_MAX_VALUES,
                });
            }
            let mut unique = BTreeSet::new();
            for context in contexts {
                if !unique.insert(context) {
                    return Err(AgentInvokeTokenCaveatError::ExecutionContextDuplicate {
                        context: context.to_string(),
                    });
                }
            }
        }

        if let Some(restrictions) = &mut self.service_restrictions {
            if restrictions.is_empty() {
                return Err(AgentInvokeTokenCaveatError::ServiceRestrictionsEmpty);
            }
            let Some(allowed_services) = self.allowed_services.as_ref() else {
                return Err(
                    AgentInvokeTokenCaveatError::ServiceRestrictionsAllowedServicesRequired,
                );
            };

            for (service, restriction) in restrictions {
                if !is_service_name(service) {
                    return Err(
                        AgentInvokeTokenCaveatError::ServiceRestrictionServiceInvalid {
                            service: service.clone(),
                        },
                    );
                }
                if !allowed_services.contains(service) {
                    return Err(
                        AgentInvokeTokenCaveatError::ServiceRestrictionServiceNotAllowed {
                            service: service.clone(),
                        },
                    );
                }
                if restriction.actions.is_empty() {
                    return Err(
                        AgentInvokeTokenCaveatError::ServiceRestrictionActionsEmpty {
                            service: service.clone(),
                        },
                    );
                }

                let mut unique_actions = BTreeSet::new();
                for action in &restriction.actions {
                    if !is_action_name(action) {
                        return Err(
                            AgentInvokeTokenCaveatError::ServiceRestrictionActionInvalid {
                                service: service.clone(),
                                action: action.clone(),
                            },
                        );
                    }
                    if action.starts_with(&format!("{service}.")) {
                        return Err(
                            AgentInvokeTokenCaveatError::ServiceRestrictionActionRepeatsServicePrefix {
                                service: service.clone(),
                                action: action.clone(),
                            },
                        );
                    }
                    if !unique_actions.insert(action.clone()) {
                        return Err(
                            AgentInvokeTokenCaveatError::ServiceRestrictionActionDuplicate {
                                service: service.clone(),
                                action: action.clone(),
                            },
                        );
                    }
                }
                restriction.actions.sort();

                if let Some(resources) = &restriction.resources {
                    resources.validate_structure().map_err(|errors| {
                        AgentInvokeTokenCaveatError::Malformed(errors.join("; "))
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentInvokeTokenCaveatsWire {
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    allowed_services: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    allowed_execution_contexts: Option<Vec<ExecutionContext>>,
    #[serde(default, deserialize_with = "deserialize_present_map")]
    service_restrictions: Option<BTreeMap<String, AgentTokenServiceRestrictionWire>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentTokenServiceRestrictionWire {
    actions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_present_selection")]
    resources: Option<ResourceSelection>,
}

fn deserialize_present_selection<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ResourceSelection>, D::Error> {
    ResourceSelection::deserialize(deserializer).map(Some)
}

fn deserialize_present_vec<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<T>::deserialize(deserializer).map(Some)
}

fn deserialize_present_map<'de, D, K, V>(
    deserializer: D,
) -> Result<Option<BTreeMap<K, V>>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    BTreeMap::<K, V>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AgentInvokeTokenCaveatError {
    #[error("agent invoke token caveats are malformed: {0}")]
    Malformed(String),
    #[error("allowedServices must not be empty")]
    AllowedServicesEmpty,
    #[error("allowedServices contains invalid service {service}")]
    AllowedServiceInvalid { service: String },
    #[error("allowedServices contains duplicate service {service}")]
    AllowedServiceDuplicate { service: String },
    #[error("allowedExecutionContexts is required for agent tokens")]
    ExecutionContextsRequired,
    #[error("allowedExecutionContexts must not be empty")]
    ExecutionContextsEmpty,
    #[error("allowedExecutionContexts must contain at most {maximum} entries")]
    TooManyExecutionContexts { maximum: usize },
    #[error("allowedExecutionContexts contains duplicate context {context}")]
    ExecutionContextDuplicate { context: String },
    #[error("allowedExecutionContexts references unconfigured context {context}")]
    ExecutionContextNotConfigured { context: String },
    #[error("serviceRestrictions must not be empty")]
    ServiceRestrictionsEmpty,
    #[error("serviceRestrictions requires allowedServices")]
    ServiceRestrictionsAllowedServicesRequired,
    #[error("serviceRestrictions contains invalid service {service}")]
    ServiceRestrictionServiceInvalid { service: String },
    #[error("serviceRestrictions service {service} is not present in allowedServices")]
    ServiceRestrictionServiceNotAllowed { service: String },
    #[error("serviceRestrictions service {service} actions must not be empty")]
    ServiceRestrictionActionsEmpty { service: String },
    #[error("serviceRestrictions service {service} contains invalid action {action}")]
    ServiceRestrictionActionInvalid { service: String, action: String },
    #[error(
        "serviceRestrictions service {service} action {action} must not repeat the service prefix"
    )]
    ServiceRestrictionActionRepeatsServicePrefix { service: String, action: String },
    #[error("serviceRestrictions service {service} contains duplicate action {action}")]
    ServiceRestrictionActionDuplicate { service: String, action: String },
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{label} uses '~' but the current user's home directory is unavailable")]
pub struct HomeExpansionError {
    label: String,
}

impl HomeExpansionError {
    pub fn label(&self) -> &str {
        &self.label
    }
}

pub fn expand_current_user_home(
    path: impl AsRef<Path>,
    label: impl Into<String>,
) -> Result<PathBuf, HomeExpansionError> {
    let home = current_user_home_dir();
    expand_home_with(path, home.as_deref(), label)
}

pub fn expand_home_with(
    path: impl AsRef<Path>,
    home: Option<&Path>,
    label: impl Into<String>,
) -> Result<PathBuf, HomeExpansionError> {
    let path = path.as_ref();
    let mut components = path.components();
    let Some(first) = components.next() else {
        return Ok(path.to_path_buf());
    };
    if first.as_os_str() != OsStr::new("~") {
        return Ok(path.to_path_buf());
    }

    let label = label.into();
    let home = home
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(HomeExpansionError { label })?;
    let mut expanded = home.to_path_buf();
    for component in components {
        expanded.push(component.as_os_str());
    }
    Ok(expanded)
}

fn current_user_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(profile));
        }
        match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
            (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
                let mut value = drive;
                value.push(path);
                Some(PathBuf::from(value))
            }
            _ => None,
        }
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseEnvelope<T> {
    pub agent_request_id: String,
    pub broker_request_id: String,
    pub decision: Decision,
    pub service: String,
    pub action: String,
    pub resource_scopes: ResourceScopes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub message: String,
}

/// A parsed broker configuration. Parse documents with
/// [`parse_broker_config_raw`] or [`load_broker_config`]: `[providers]` tables
/// need the backend registry, so the type deliberately does not implement
/// `Deserialize`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct BrokerConfig {
    #[serde(default)]
    pub deployment: DeploymentConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub execution_context: Option<ExecutionContextConfig>,
    pub identity: IdentityConfig,
    #[serde(default)]
    pub credentials: CredentialsConfig,
    #[serde(default)]
    pub imports: ImportsConfig,
    /// `[command_imports.<name>]`: operator-approved executables for the
    /// `command` import kind, keyed by command name.
    #[serde(default)]
    pub command_imports: CommandImportsConfig,
    #[serde(default)]
    pub oauth: OAuthConfig,
    pub managed_store: Option<ManagedStoreConfig>,
    pub credential_encryption: Option<CredentialEncryptionConfig>,
    #[serde(default)]
    pub management: ManagementConfig,
    pub broker_tokens: Option<BrokerTokensConfig>,
    #[serde(default)]
    pub browser_auth: BrowserAuthConfig,
    #[serde(default)]
    pub portal: PortalConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub attribution: AttributionConfig,
    /// `[providers.<kind>]` tables, parsed by the registered backends; see
    /// [`parse_broker_config_raw`].
    #[serde(skip)]
    pub providers: ProvidersConfig,
    #[serde(default)]
    pub gateways: BTreeMap<String, GatewayConfig>,
    /// `[limits]`, required for its `upload_spool_dir`.
    pub limits: LimitsConfig,
    /// `[audit]`; audit is disabled when the table is absent.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContextConfig {
    pub allowed_values: Vec<String>,
    pub default_context: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub allow_production_anonymous: bool,
    #[serde(default)]
    pub enable_fake_service: bool,
    /// The broker's node ID; `None` means the operating system host name.
    /// See [`resolve_node_id`].
    #[serde(default)]
    pub node_id: Option<String>,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            environment: default_environment(),
            allow_production_anonymous: false,
            enable_fake_service: false,
            node_id: None,
        }
    }
}

fn default_environment() -> String {
    "development".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub outbound_tls: OutboundTlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default)]
    pub trusted_callers: BTreeMap<String, TrustedCallerConfig>,
    pub mode: String,
    pub authority: String,
    #[serde(default)]
    pub sources: Vec<IdentitySourceConfig>,
    #[serde(default)]
    pub groups: Vec<IdentityGroupConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCallerConfig {
    pub credential_ref: String,
    #[serde(default)]
    pub credential_transport: TrustedCallerCredentialTransport,
    pub username_namespace: Option<String>,
    pub context_mode: TrustedCallerContextMode,
    pub execution_context: Option<String>,
    pub allowed_execution_contexts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_forwarded_identity: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedCallerCredentialTransport {
    #[default]
    CallerAuthorization,
    AuthorizationUser,
}

impl TrustedCallerCredentialTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerAuthorization => "caller_authorization",
            Self::AuthorizationUser => "authorization_user",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedCallerContextMode {
    Fixed,
    Asserted,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySourceConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub header: String,
    #[serde(default = "default_identity_scheme")]
    pub scheme: String,
    #[serde(default)]
    pub principals: Vec<StaticPrincipalConfig>,
}

fn default_identity_scheme() -> String {
    "raw".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticPrincipalConfig {
    pub principal: String,
    pub token_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityGroupConfig {
    pub id: String,
    #[serde(default = "default_identity_group_status")]
    pub status: String,
    #[serde(default)]
    pub members: Vec<String>,
}

fn default_identity_group_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    /// Effective DB bindings; never accepted from TOML. Runtime publication
    /// derives these from the managed imported-service catalog.
    #[serde(skip)]
    pub imported_modes: BTreeMap<String, Vec<String>>,
    /// `[credentials.connections.<id>]`; runtime publication adds one per
    /// imported service with a supported, allowed personal binding.
    #[serde(default)]
    pub connections: BTreeMap<String, ConnectionConfig>,
    #[serde(default)]
    pub service: BTreeMap<String, CredentialConfig>,
    #[serde(default)]
    pub per_user: BTreeMap<String, CredentialConfig>,
    #[serde(default)]
    pub lookup: BTreeMap<String, CredentialConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub username_ref: Option<String>,
    pub token_ref: Option<String>,
    pub provider: Option<String>,
    pub path: Option<String>,
    pub read_only: Option<bool>,
    /// The credential connection a `type = "connection"` per-user entry
    /// names.
    pub connection: Option<String>,
    /// The token profile a `credentials.service` or `credentials.lookup`
    /// static credential is lent as; it must be one the service declares
    /// with the same kind as `type`.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedStoreConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub require_registered_principal_for_invocation: bool,
    #[serde(default)]
    pub auto_migrate: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEncryptionConfig {
    pub active_key: String,
    #[serde(default)]
    pub keys: Vec<CredentialEncryptionKeyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEncryptionKeyConfig {
    pub id: String,
    pub provider: String,
    pub env: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub admin_principals: Vec<String>,
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub allow_classless_admin_identities: bool,
    #[serde(default)]
    pub allow_classless_user_management: bool,
    #[serde(default)]
    pub initial_admin: InitialAdminConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialAdminConfig {
    #[serde(default = "default_initial_admin_mode")]
    pub mode: String,
    pub principal_id: Option<String>,
    pub initial_password: Option<String>,
}

impl Default for InitialAdminConfig {
    fn default() -> Self {
        Self {
            mode: default_initial_admin_mode(),
            principal_id: None,
            initial_password: None,
        }
    }
}

fn default_initial_admin_mode() -> String {
    "disabled".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerTokensConfig {
    pub hash_key_ref: String,
    pub default_agent_invoke_ttl: Option<String>,
    pub default_user_manage_ttl: Option<String>,
    pub default_admin_ttl: Option<String>,
    pub max_self_issued_agent_invoke_ttl: Option<String>,
    #[serde(default = "default_self_agent_invoke_ttl_options")]
    pub self_agent_invoke_ttl_options: Vec<BrokerTokenTtlOption>,
    #[serde(default = "default_admin_agent_invoke_ttl_options")]
    pub admin_agent_invoke_ttl_options: Vec<BrokerTokenTtlOption>,
    #[serde(default = "default_user_manage_ttl_options")]
    pub user_manage_ttl_options: Vec<BrokerTokenTtlOption>,
    #[serde(default = "default_admin_ttl_options")]
    pub admin_ttl_options: Vec<BrokerTokenTtlOption>,
}

impl Default for BrokerTokensConfig {
    fn default() -> Self {
        Self {
            hash_key_ref: String::new(),
            default_agent_invoke_ttl: None,
            default_user_manage_ttl: None,
            default_admin_ttl: None,
            max_self_issued_agent_invoke_ttl: None,
            self_agent_invoke_ttl_options: default_self_agent_invoke_ttl_options(),
            admin_agent_invoke_ttl_options: default_admin_agent_invoke_ttl_options(),
            user_manage_ttl_options: default_user_manage_ttl_options(),
            admin_ttl_options: default_admin_ttl_options(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerTokenTtlOption {
    Ttl(String),
    Never,
}

impl BrokerTokenTtlOption {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ttl(value) => value,
            Self::Never => "never",
        }
    }

    pub fn ttl_seconds(&self) -> Option<u64> {
        match self {
            Self::Ttl(value) => parse_ttl_seconds(value),
            Self::Never => None,
        }
    }

    pub fn is_never(&self) -> bool {
        matches!(self, Self::Never)
    }
}

impl<'de> Deserialize<'de> for BrokerTokenTtlOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(if value == "never" {
            Self::Never
        } else {
            Self::Ttl(value)
        })
    }
}

impl Serialize for BrokerTokenTtlOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

pub fn default_self_agent_invoke_ttl_options() -> Vec<BrokerTokenTtlOption> {
    ttl_options(&["8h", "7d", DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL])
}

pub fn default_admin_agent_invoke_ttl_options() -> Vec<BrokerTokenTtlOption> {
    let mut options = default_self_agent_invoke_ttl_options();
    options.push(BrokerTokenTtlOption::Never);
    options
}

pub fn default_user_manage_ttl_options() -> Vec<BrokerTokenTtlOption> {
    ttl_options(&["30m", "2h", "8h", "1d"])
}

pub fn default_admin_ttl_options() -> Vec<BrokerTokenTtlOption> {
    default_user_manage_ttl_options()
}

fn ttl_options(values: &[&str]) -> Vec<BrokerTokenTtlOption> {
    values
        .iter()
        .map(|value| BrokerTokenTtlOption::Ttl((*value).to_string()))
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    pub public_origin: Option<String>,
    #[serde(default = "default_session_cookie_name")]
    pub session_cookie_name: String,
    #[serde(default = "default_csrf_header")]
    pub csrf_header: String,
    pub csrf_key_ref: Option<String>,
    #[serde(default = "default_browser_session_ttl")]
    pub session_ttl: String,
    #[serde(default = "default_allowed_return_paths")]
    pub allowed_return_paths: Vec<String>,
    #[serde(default)]
    pub local_password: LocalPasswordConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
}

impl Default for BrowserAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_origin: None,
            session_cookie_name: default_session_cookie_name(),
            csrf_header: default_csrf_header(),
            csrf_key_ref: None,
            session_ttl: default_browser_session_ttl(),
            allowed_return_paths: default_allowed_return_paths(),
            local_password: LocalPasswordConfig::default(),
            oidc: OidcConfig::default(),
        }
    }
}

fn default_session_cookie_name() -> String {
    "aab_session".to_string()
}

fn default_csrf_header() -> String {
    "x-agent-access-csrf".to_string()
}

fn default_browser_session_ttl() -> String {
    "8h".to_string()
}

fn default_allowed_return_paths() -> Vec<String> {
    vec!["/ui".to_string()]
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(default)]
    pub microsoft: MicrosoftOidcConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftOidcConfig {
    #[serde(default)]
    pub enabled: bool,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_ref: Option<String>,
    pub flow_key_ref: Option<String>,
    #[serde(default = "default_oidc_flow_ttl")]
    pub flow_ttl: String,
    #[serde(default = "default_oidc_max_pending_flows")]
    pub max_pending_flows: u32,
    #[serde(default = "default_oidc_jit_provisioning")]
    pub jit_provisioning: bool,
    #[serde(default = "default_oidc_external_membership_ttl")]
    pub external_membership_ttl: String,
    /// Sign-in also requests `offline_access`, and the Broker keeps the
    /// returned Microsoft refresh token, encrypted, per login method.
    #[serde(default)]
    pub membership_renewal: bool,
}

impl Default for MicrosoftOidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tenant_id: None,
            client_id: None,
            client_secret_ref: None,
            flow_key_ref: None,
            flow_ttl: default_oidc_flow_ttl(),
            max_pending_flows: default_oidc_max_pending_flows(),
            jit_provisioning: default_oidc_jit_provisioning(),
            external_membership_ttl: default_oidc_external_membership_ttl(),
            membership_renewal: false,
        }
    }
}

fn default_oidc_flow_ttl() -> String {
    "10m".to_string()
}

fn default_oidc_max_pending_flows() -> u32 {
    10_000
}

fn default_oidc_jit_provisioning() -> bool {
    true
}

fn default_oidc_external_membership_ttl() -> String {
    "8h".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPasswordConfig {
    #[serde(default)]
    pub enabled: bool,
    pub pepper_ref: Option<String>,
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    #[serde(default = "default_lockout_ttl")]
    pub lockout_ttl: String,
}

impl Default for LocalPasswordConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pepper_ref: None,
            min_password_length: default_min_password_length(),
            max_failed_attempts: default_max_failed_attempts(),
            lockout_ttl: default_lockout_ttl(),
        }
    }
}

fn default_min_password_length() -> usize {
    12
}

fn default_max_failed_attempts() -> u32 {
    10
}

fn default_lockout_ttl() -> String {
    "15m".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_portal_mount_path")]
    pub mount_path: String,
    pub static_dir: Option<String>,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount_path: default_portal_mount_path(),
            static_dir: None,
        }
    }
}

fn default_portal_mount_path() -> String {
    "/ui".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub authority: String,
    #[serde(default = "default_decision")]
    pub default_decision: String,
    #[serde(default)]
    pub grants: Vec<PolicyGrantConfig>,
    #[serde(default, deserialize_with = "resource_policy::deserialize_resources")]
    pub resources: Vec<ResourceDefinition>,
    #[serde(default, deserialize_with = "resource_policy::deserialize_groups")]
    pub resource_groups: Vec<ResourceGroupDefinition>,
}

fn default_decision() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantConfig {
    pub subjects: Vec<String>,
    pub service: String,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, deserialize_with = "resource_policy::deserialize_selection")]
    pub resources: ResourceSelection,
    #[serde(default)]
    pub execution_contexts: Option<Vec<String>>,
    pub credential_mode: String,
    pub priority: Option<i32>,
}

pub const POLICY_GRANT_MAX_SUBJECTS: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default)]
    pub allow_forwarded_identity: bool,
    pub kind: String,
    pub display_name: String,
    #[serde(default)]
    pub broker_hosts: Vec<String>,
    pub upstream_base_url: String,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub auth_modes: Vec<String>,
    #[serde(default = "default_basic_broker_token_username")]
    pub basic_broker_token_username: String,
    #[serde(default)]
    pub credential_modes: Vec<String>,
    /// How the gateway presents a token-kind upstream credential.
    #[serde(default)]
    pub upstream_token_auth: GatewayUpstreamTokenAuth,
    #[serde(default = "default_gateway_redirect_policy")]
    pub redirect_policy: String,
    pub request_body_max_bytes: Option<u64>,
    pub response_body_max_bytes: Option<u64>,
    pub streaming_idle_timeout_ms: Option<u64>,
    #[serde(default = "default_gateway_correlation_headers")]
    pub correlation_headers: bool,
    pub git: Option<GatewayGitConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayGitConfig {
    #[serde(default)]
    pub allow_fetch: bool,
    #[serde(default)]
    pub allow_push: bool,
    #[serde(default)]
    pub deny_ref_patterns: Vec<String>,
    #[serde(default = "default_deny_delete_refs")]
    pub deny_delete_refs: bool,
    pub receive_pack_prefix_max_bytes: Option<u64>,
}

fn default_basic_broker_token_username() -> String {
    "agent-access".to_string()
}

fn default_gateway_redirect_policy() -> String {
    "none".to_string()
}

fn default_gateway_correlation_headers() -> bool {
    true
}

fn default_deny_delete_refs() -> bool {
    true
}

/// `[limits]`. The table is required: `upload_spool_dir` has no default, and
/// every other limit has the built-in default [`LimitsConfig::new`] applies.
/// An omitted table is reported as its missing `upload_spool_dir`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct LimitsConfig {
    /// `[limits.invocations]`: per-principal, per-service invocation rate limits.
    #[serde(default)]
    pub invocations: InvocationLimitsConfig,
    #[serde(default = "default_auth_requests_per_principal")]
    pub auth_requests_per_principal_per_minute: u32,
    #[serde(default = "default_auth_requests_per_source")]
    pub auth_requests_per_source_per_minute: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: u32,
    #[serde(default = "default_max_concurrent_per_principal")]
    pub max_concurrent_requests_per_principal: u32,
    #[serde(default = "default_max_http_body_bytes")]
    pub max_http_body_bytes: u64,
    #[serde(default = "default_download_max_bytes")]
    pub max_download_bytes: u64,
    #[serde(default = "default_max_upstream_response_bytes")]
    pub max_upstream_response_bytes: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Total time allowed to receive an HTTP request body, including progressing uploads.
    #[serde(default = "default_request_body_timeout_ms")]
    pub request_body_timeout_ms: u64,
    #[serde(default = "default_streaming_idle_timeout_ms")]
    pub streaming_idle_timeout_ms: u64,
    /// Directory for spooled upload bodies and the spool state lock; a
    /// relative path resolves against the working directory.
    pub upload_spool_dir: String,
    #[serde(default = "default_upload_spool_max_bytes")]
    pub upload_spool_max_bytes: u64,
}

impl LimitsConfig {
    /// Limits that spool uploads in `upload_spool_dir`, with the built-in
    /// default for every other limit.
    pub fn new(upload_spool_dir: impl Into<String>) -> Self {
        Self {
            invocations: InvocationLimitsConfig::default(),
            auth_requests_per_principal_per_minute: default_auth_requests_per_principal(),
            auth_requests_per_source_per_minute: default_auth_requests_per_source(),
            max_concurrent_requests: default_max_concurrent(),
            max_concurrent_requests_per_principal: default_max_concurrent_per_principal(),
            max_http_body_bytes: default_max_http_body_bytes(),
            max_download_bytes: default_download_max_bytes(),
            max_upstream_response_bytes: default_max_upstream_response_bytes(),
            request_timeout_ms: default_request_timeout_ms(),
            request_body_timeout_ms: default_request_body_timeout_ms(),
            streaming_idle_timeout_ms: default_streaming_idle_timeout_ms(),
            upload_spool_dir: upload_spool_dir.into(),
            upload_spool_max_bytes: default_upload_spool_max_bytes(),
        }
    }
}

impl<'de> Deserialize<'de> for LimitsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// A present `[limits]` table, read by the derived deserializer.
        struct Table(LimitsConfig);

        impl<'de> Deserialize<'de> for Table {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                // The inherent function `remote = "Self"` derives, not this trait.
                LimitsConfig::deserialize(deserializer).map(Self)
            }
        }

        // Serde presents an omitted field to its type as an absent option, as
        // it does for every `Option` field, so an omitted table is `None` here.
        Option::<Table>::deserialize(deserializer)?
            .map(|Table(limits)| limits)
            .ok_or_else(|| {
                serde::de::Error::custom("missing field `upload_spool_dir` in table `[limits]`")
            })
    }
}

impl From<&LimitsConfig> for ProviderLimits {
    fn from(limits: &LimitsConfig) -> Self {
        Self::default()
            .with_max_http_body_bytes(limits.max_http_body_bytes)
            .with_max_download_bytes(limits.max_download_bytes)
            .with_max_upstream_response_bytes(limits.max_upstream_response_bytes)
            .with_request_timeout_ms(limits.request_timeout_ms)
            .with_streaming_idle_timeout_ms(limits.streaming_idle_timeout_ms)
    }
}

fn default_auth_requests_per_principal() -> u32 {
    100
}
fn default_auth_requests_per_source() -> u32 {
    300
}
fn default_max_concurrent() -> u32 {
    100
}
fn default_max_concurrent_per_principal() -> u32 {
    10
}
fn default_max_http_body_bytes() -> u64 {
    ProviderLimits::default().max_http_body_bytes
}
fn default_max_upstream_response_bytes() -> u64 {
    ProviderLimits::default().max_upstream_response_bytes
}
fn default_request_body_timeout_ms() -> u64 {
    300_000
}
fn default_request_timeout_ms() -> u64 {
    ProviderLimits::default().request_timeout_ms
}
fn default_streaming_idle_timeout_ms() -> u64 {
    ProviderLimits::default().streaming_idle_timeout_ms
}
fn default_upload_spool_max_bytes() -> u64 {
    default_max_http_body_bytes() * 4
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditDurability {
    #[default]
    Write,
    SyncData,
    SyncAll,
}

/// The `[audit]` storage backend.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditStoreType {
    /// A standalone SQLite audit database that supports queries.
    Sqlite,
    /// Size-rotated JSON Lines files, for log shippers.
    Jsonl,
}

impl AuditStoreType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(rename = "type")]
    pub kind: AuditStoreType,
    pub path: String,
    /// JSONL only; see [`AuditConfig::effective_rotate_bytes`].
    pub rotate_bytes: Option<u64>,
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_audit_queue_capacity")]
    pub queue_capacity: u32,
    pub terminal_queue_capacity: Option<u32>,
    #[serde(default = "default_audit_enqueue_timeout_ms")]
    pub enqueue_timeout_ms: u64,
    #[serde(default)]
    pub durability: AuditDurability,
}

impl AuditConfig {
    /// An `[audit]` table with `type` and `path` set and every other setting
    /// at its default.
    pub fn new(kind: AuditStoreType, path: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
            rotate_bytes: None,
            retention_days: default_audit_retention_days(),
            queue_capacity: default_audit_queue_capacity(),
            terminal_queue_capacity: None,
            enqueue_timeout_ms: default_audit_enqueue_timeout_ms(),
            durability: AuditDurability::default(),
        }
    }

    pub fn effective_terminal_queue_capacity(&self, limits: &LimitsConfig) -> u32 {
        self.terminal_queue_capacity
            .unwrap_or(limits.max_concurrent_requests)
    }

    /// The JSONL rotation size: `rotate_bytes`, or 100 MiB when unset.
    pub fn effective_rotate_bytes(&self) -> u64 {
        self.rotate_bytes.unwrap_or_else(default_audit_rotate_bytes)
    }
}

fn default_audit_rotate_bytes() -> u64 {
    100 * 1024 * 1024
}
fn default_audit_retention_days() -> u32 {
    30
}
fn default_audit_queue_capacity() -> u32 {
    1024
}
fn default_audit_enqueue_timeout_ms() -> u64 {
    1000
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliConfig {
    #[serde(default)]
    pub service: CliServiceConfig,
    #[serde(default)]
    pub identity: CliIdentityConfig,
    #[serde(default)]
    pub defaults: CliDefaultsConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CliDefaultsConfig {
    #[serde(default)]
    pub read_content_format: ReadContentFormat,
    #[serde(default)]
    pub output_format: ResponseFormat,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliServiceConfig {
    #[serde(default = "default_broker_url")]
    pub url: String,
    #[serde(default)]
    pub tls: CliTlsConfig,
}

impl Default for CliServiceConfig {
    fn default() -> Self {
        Self {
            url: default_broker_url(),
            tls: CliTlsConfig::default(),
        }
    }
}

fn default_broker_url() -> String {
    "http://127.0.0.1:8787".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CliTlsConfig {
    #[serde(default = "default_verify_certificates")]
    pub verify_certificates: bool,
    #[serde(default)]
    pub additional_ca_cert_files: Vec<String>,
}

impl Default for CliTlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: default_verify_certificates(),
            additional_ca_cert_files: Vec::new(),
        }
    }
}

fn default_verify_certificates() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliIdentityConfig {
    pub token_env: Option<String>,
    pub token_file: Option<String>,
    #[serde(default = "default_cli_identity_header")]
    pub header: String,
    #[serde(default = "default_identity_scheme")]
    pub scheme: String,
    #[serde(default)]
    pub disabled: bool,
}

impl Default for CliIdentityConfig {
    fn default() -> Self {
        Self {
            token_env: None,
            token_file: None,
            header: default_cli_identity_header(),
            scheme: default_identity_scheme(),
            disabled: false,
        }
    }
}

fn default_cli_identity_header() -> String {
    "X-Agent-Access-Identity-Token".to_string()
}

pub fn load_broker_config(
    path: impl AsRef<Path>,
    backends: &Arc<BackendRegistry>,
) -> Result<BrokerConfig, ConfigError> {
    load_broker_config_with_raw(path, backends).map(|(config, _raw)| config)
}

pub fn load_broker_config_with_raw(
    path: impl AsRef<Path>,
    backends: &Arc<BackendRegistry>,
) -> Result<(BrokerConfig, String), ConfigError> {
    let path_ref = path.as_ref();
    let path_label = path_ref.display().to_string();
    let raw = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
        path: path_label.clone(),
        source,
    })?;
    let config = parse_broker_config_raw(path_label, &raw, backends)?;
    Ok((config, raw))
}

/// Parses a broker configuration document. Each `[providers.<kind>]` table
/// is parsed by the registered backend of that kind; other kinds are
/// rejected.
pub fn parse_broker_config_raw(
    path: impl Into<String>,
    raw: &str,
    backends: &Arc<BackendRegistry>,
) -> Result<BrokerConfig, ConfigError> {
    let path = path.into();
    let parse_error = |source| ConfigError::Parse {
        path: path.clone(),
        source,
    };
    let mut document = toml::de::DeTable::parse(raw).map_err(parse_error)?;
    let providers = document.get_mut().remove("providers");
    let mut config = BrokerConfig::deserialize(toml::de::Deserializer::from(document)).map_err(
        |mut error| {
            error.set_input(Some(raw));
            parse_error(error)
        },
    )?;
    config.providers = match providers {
        Some(providers) => backends
            .parse_providers(providers, raw)
            .map_err(parse_error)?,
        None => ProvidersConfig::new(Arc::clone(backends)),
    };
    Ok(config)
}

pub fn load_cli_config(path: impl AsRef<Path>) -> Result<CliConfig, ConfigError> {
    let path_ref = path.as_ref();
    let path_label = path_ref.display().to_string();
    let raw = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
        path: path_label.clone(),
        source,
    })?;
    let config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
        path: path_label,
        source,
    })?;
    Ok(config)
}

pub fn validate_broker_config(config: &BrokerConfig) -> Result<(), ConfigError> {
    let mut errors = Vec::new();
    imports_config::validate_imports(config, &mut errors);
    command_imports_config::validate_command_imports(config, &mut errors);
    if let Err(error) = config.oauth.validate() {
        errors.push(format!("oauth: {error}"));
    }
    let development_fixtures_enabled =
        config.deployment.environment != "production" && config.deployment.enable_fake_service;
    let dialects = config.providers.registry();
    for (name, registration) in &config.oauth.registrations {
        let adapter = registration.adapter.as_str();
        if registration
            .permission_profiles
            .values()
            .next()
            .is_some_and(|first| {
                registration
                    .permission_profiles
                    .values()
                    .any(|profile| profile.scope_mode != first.scope_mode)
            })
        {
            errors.push(format!(
                "oauth.registrations.{name}: all permission_profiles must use the same scope_mode"
            ));
        }
        let Some(dialect) = dialects.oauth_dialect(adapter) else {
            errors.push(format!(
                "oauth.registrations.{name}.adapter `{adapter}` is not a registered OAuth dialect (expected one of: {})",
                dialects.oauth_dialect_ids().collect::<Vec<_>>().join(", ")
            ));
            continue;
        };
        if !dialect.dialect().supports_server_default_scopes()
            && registration
                .permission_profiles
                .values()
                .any(|profile| profile.scope_mode == OAuthScopeMode::ServerDefault)
        {
            errors.push(format!(
                "oauth.registrations.{name}: {adapter} does not support server_default scope mode"
            ));
        }
        if let Err(reason) = dialect.dialect().validate_registration(registration) {
            errors.push(format!(
                "oauth.registrations.{name} is not a valid {adapter} registration: {reason}"
            ));
        }
        oauth::validate_login_binding(
            name,
            registration,
            dialect.dialect(),
            &config.browser_auth.oidc.microsoft,
            &mut errors,
        );
        if dialect.is_development_only() && !development_fixtures_enabled {
            errors.push(format!(
                "oauth.registrations.{name} uses the development-only {adapter} dialect, which requires non-production deployment.enable_fake_service"
            ));
        }
    }
    if !config.oauth.registrations.is_empty()
        && (config.managed_store.is_none()
            || config.credential_encryption.is_none()
            || !config.browser_auth.enabled
            || !config.management.enabled)
    {
        errors.push(
            "OAuth requires managed_store, credential_encryption, browser_auth and management"
                .into(),
        );
    }
    for (name, registration) in &config.oauth.registrations {
        let expected = config
            .browser_auth
            .public_origin
            .as_deref()
            .map(|origin| format!("{}/v1/oauth/callback/{name}", origin.trim_end_matches('/')));
        if expected.as_deref() != Some(registration.redirect_uri.as_str()) {
            errors.push(format!("oauth.registrations.{name}.redirect_uri must be the exact browser_auth.public_origin callback /v1/oauth/callback/{name}"));
        }
    }
    validate_deployment(&config.deployment, &mut errors);
    validate_execution_context_config(config.execution_context.as_ref(), &mut errors);
    if config.managed_store.is_some() && config.credential_encryption.is_none() {
        errors.push("managed_store requires credential_encryption for automatically generated user identity tokens".into());
    }
    for (name, caller) in &config.identity.trusted_callers {
        let label = format!("identity.trusted_callers.{name}");
        if !is_safe_identifier(name) {
            errors.push(format!("{label} has an invalid caller name"));
        }
        if caller.credential_ref.trim().is_empty() {
            errors.push(format!("{label}.credential_ref is required"));
        }
        if let Some(namespace) = &caller.username_namespace {
            if !is_safe_identifier(namespace) {
                errors.push(format!(
                    "{label}.username_namespace must be a safe configuration identifier"
                ));
            }
            if config.identity.authority != "managed" || config.managed_store.is_none() {
                errors.push(format!(
                    "{label}.username_namespace requires managed identity and managed_store"
                ));
            }
        }
        if caller.credential_transport == TrustedCallerCredentialTransport::AuthorizationUser {
            if caller.username_namespace.is_none() {
                errors.push(format!(
                    "{label} authorization_user requires username_namespace"
                ));
            }
            if caller.context_mode != TrustedCallerContextMode::Fixed {
                errors.push(format!(
                    "{label} authorization_user requires fixed context_mode"
                ));
            }
            if caller.allow_forwarded_identity {
                errors.push(format!(
                    "{label} authorization_user forbids allow_forwarded_identity"
                ));
            }
        }
        if caller.allow_forwarded_identity
            && (config.identity.authority != "managed"
                || config.managed_store.is_none()
                || config.credential_encryption.is_none())
        {
            errors.push(format!("{label}.allow_forwarded_identity requires managed identity, managed_store, and credential_encryption"));
        }
        let contexts = match caller.context_mode {
            TrustedCallerContextMode::Fixed => {
                if caller.allowed_execution_contexts.is_some() || caller.execution_context.is_none()
                {
                    errors.push(format!("{label} fixed mode requires execution_context and forbids allowed_execution_contexts"));
                }
                caller.execution_context.iter().collect::<Vec<_>>()
            }
            TrustedCallerContextMode::Asserted => {
                if caller.execution_context.is_some()
                    || caller
                        .allowed_execution_contexts
                        .as_ref()
                        .is_none_or(Vec::is_empty)
                {
                    errors.push(format!("{label} asserted mode requires nonempty allowed_execution_contexts and forbids execution_context"));
                }
                caller
                    .allowed_execution_contexts
                    .iter()
                    .flatten()
                    .collect::<Vec<_>>()
            }
        };
        let mut seen = BTreeSet::new();
        for context in contexts {
            if !is_valid_execution_context_value(context)
                || !seen.insert(context)
                || !config
                    .execution_context
                    .as_ref()
                    .map_or(context == DEFAULT_EXECUTION_CONTEXT, |configured| {
                        configured.allowed_values.contains(context)
                    })
            {
                errors.push(format!(
                    "{label} has an invalid, duplicate, or unconfigured execution context"
                ));
            }
        }
    }
    if config.gateways.values().any(|g| g.allow_forwarded_identity)
        && !config
            .identity
            .trusted_callers
            .values()
            .any(|caller| caller.allow_forwarded_identity)
    {
        errors.push("gateway allow_forwarded_identity requires a trusted caller with identity forwarding capability".into());
    }

    validate_identity(&config.deployment, &config.identity, &mut errors);
    validate_network(&config.network, &mut errors);
    validate_managed_sections(config, &mut errors);
    validate_browser_auth(config, &mut errors);
    validate_portal(config, &mut errors);
    mcp_config::validate(config, &mut errors);
    // Imported types live in the managed store, and configuration cannot
    // reference them, so offline validation sees the composition's types.
    let effective_types = runtime::EffectiveResourceTypes::composition(config.providers.registry());
    let resource_types = effective_types.registry();
    let services = configured_service_descriptors(config);
    validate_service_descriptors(&services, resource_types, &mut errors);
    validate_private_resource_consumers(config, &services, &effective_types, &mut errors);
    validate_credentials(config, &services, &mut errors);
    // Backends see each connection's accepted token profiles, implicit
    // types included.
    let effective_credentials = connections::validate_connections(config, &services, &mut errors);
    validate_backends(config, &effective_credentials, &mut errors);
    validate_gateways(config, &mut errors);
    validate_policy(config, &services, resource_types, &mut errors);
    validate_attribution_config(&config.attribution, &services, &mut errors);
    validate_limits(config, &mut errors);
    validate_invocation_limits(config, &services, &mut errors);
    validate_audit(config, &mut errors);
    finish_validation(errors)
}

pub fn validate_cli_config(config: &CliConfig) -> Result<(), ConfigError> {
    let mut errors = Vec::new();
    match Url::parse(&config.service.url) {
        Ok(url) => {
            let scheme = url.scheme();
            if scheme != "http" && scheme != "https" && scheme != "unix" {
                errors.push("service.url must use http, https, or unix scheme".to_string());
            }
            if scheme == "http"
                && !is_loopback_or_localhost(url.host())
                && !config.identity.disabled
            {
                errors.push(
                    "service.url must use https for non-local broker URLs when identity is enabled"
                        .to_string(),
                );
            }
        }
        Err(_) => errors.push("service.url must be a valid URL".to_string()),
    }
    validate_cli_tls_config(&config.service.tls, &mut errors);
    validate_header_name("identity.header", &config.identity.header, &mut errors);
    if config.identity.scheme != "raw" && config.identity.scheme != "Bearer" {
        errors.push("identity.scheme must be raw or Bearer".to_string());
    }
    if let Some(path) = &config.identity.token_file
        && path.trim().is_empty()
    {
        errors.push("identity.token_file must not be empty".to_string());
    }
    if let Some(name) = &config.identity.token_env
        && !is_env_name(name)
    {
        errors.push("identity.token_env must be a valid environment variable name".to_string());
    }
    finish_validation(errors)
}

fn validate_cli_tls_config(config: &CliTlsConfig, errors: &mut Vec<String>) {
    for (index, path) in config.additional_ca_cert_files.iter().enumerate() {
        if path.trim().is_empty() {
            errors.push(format!(
                "service.tls.additional_ca_cert_files[{index}] must not be empty"
            ));
        }
    }
}

pub fn load_cli_tls_certificates(
    config: &CliTlsConfig,
) -> Result<Vec<reqwest::Certificate>, ConfigError> {
    let home = current_user_home_dir();
    load_cli_tls_certificates_with_home(config, home.as_deref())
}

fn load_cli_tls_certificates_with_home(
    config: &CliTlsConfig,
    home: Option<&Path>,
) -> Result<Vec<reqwest::Certificate>, ConfigError> {
    let mut errors = Vec::new();
    for (index, path) in config.additional_ca_cert_files.iter().enumerate() {
        if path.trim().is_empty() {
            errors.push(format!(
                "service.tls.additional_ca_cert_files[{index}] must not be empty"
            ));
        }
    }
    if !errors.is_empty() {
        return Err(ConfigError::Invalid { errors });
    }
    if !config.verify_certificates {
        return Ok(Vec::new());
    }

    let mut certificates = Vec::new();
    for (index, configured_path) in config.additional_ca_cert_files.iter().enumerate() {
        let label = format!("service.tls.additional_ca_cert_files[{index}]");
        let trimmed_path = configured_path.trim();
        let expanded_path = match expand_home_with(trimmed_path, home, label.clone()) {
            Ok(path) => path,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        let metadata = match fs::metadata(&expanded_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                errors.push(format!(
                    "{label} {} cannot be accessed: {error}",
                    expanded_path.display()
                ));
                continue;
            }
        };
        if metadata.is_dir() {
            errors.push(format!(
                "{label} {} must be a file, not a directory",
                expanded_path.display()
            ));
            continue;
        }
        let bytes = match fs::read(&expanded_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(format!(
                    "{label} {} cannot be read: {error}",
                    expanded_path.display()
                ));
                continue;
            }
        };
        let loaded = match parse_strict_certificate_pem_bundle(&bytes) {
            Ok(certificates) => certificates,
            Err(error) => {
                errors.push(format!("{label} {} {error}", expanded_path.display()));
                continue;
            }
        };
        certificates.extend(loaded);
    }

    if errors.is_empty() {
        Ok(certificates)
    } else {
        Err(ConfigError::Invalid { errors })
    }
}

/// Validates a configuration file offline. A valid configuration may still
/// carry warnings, such as an approved command whose executable is missing;
/// they are returned for the caller to report.
pub fn validate_broker_config_file(
    path: impl AsRef<Path>,
    backends: &Arc<BackendRegistry>,
) -> Result<Vec<String>, ConfigError> {
    let config = load_broker_config(path, backends)?;
    validate_broker_config(&config)?;
    PreparedOutboundTls::load(&config.network.outbound_tls)?;
    Ok(command_import_warnings(&config))
}

pub fn validate_cli_config_file(path: impl AsRef<Path>) -> Result<(), ConfigError> {
    let config = load_cli_config(path)?;
    validate_cli_config(&config)?;
    load_cli_tls_certificates(&config.service.tls).map(|_| ())
}

fn validate_deployment(config: &DeploymentConfig, errors: &mut Vec<String>) {
    if !matches!(
        config.environment.as_str(),
        "production" | "staging" | "development" | "test"
    ) {
        errors.push(
            "deployment.environment must be production, staging, development, or test".to_string(),
        );
    }
    if config.environment == "production" && config.enable_fake_service {
        errors.push("deployment.enable_fake_service is not allowed in production".to_string());
    }
    if let Some(node_id) = &config.node_id
        && !is_valid_node_id(node_id)
    {
        errors.push(format!("deployment.node_id {NODE_ID_RULE}"));
    }
}

fn validate_execution_context_config(
    config: Option<&ExecutionContextConfig>,
    errors: &mut Vec<String>,
) {
    let Some(config) = config else {
        return;
    };
    if config.allowed_values.is_empty() {
        errors.push("execution_context.allowed_values must not be empty".to_string());
    }
    if config.allowed_values.len() > EXECUTION_CONTEXT_MAX_VALUES {
        errors.push(format!(
            "execution_context.allowed_values must contain at most {EXECUTION_CONTEXT_MAX_VALUES} entries"
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, value) in config.allowed_values.iter().enumerate() {
        if !is_valid_execution_context_value(value) {
            errors.push(format!(
                "execution_context.allowed_values[{index}] must match ^[a-z][a-z0-9_-]{{0,63}}$"
            ));
        }
        if !seen.insert(value) {
            errors.push(format!(
                "execution_context.allowed_values[{index}] duplicates an earlier value"
            ));
        }
    }
    if let Some(default_context) = config.default_context.as_deref() {
        if !is_valid_execution_context_value(default_context) {
            errors.push(
                "execution_context.default_context must match ^[a-z][a-z0-9_-]{0,63}$".to_string(),
            );
        }
        if !config
            .allowed_values
            .iter()
            .any(|value| value == default_context)
        {
            errors.push(
                "execution_context.default_context must appear in execution_context.allowed_values"
                    .to_string(),
            );
        }
    }
}

fn validate_identity(
    deployment: &DeploymentConfig,
    config: &IdentityConfig,
    errors: &mut Vec<String>,
) {
    if !matches!(config.mode.as_str(), "required" | "optional" | "anonymous") {
        errors.push("identity.mode must be required, optional, or anonymous".to_string());
    }
    if !matches!(config.authority.as_str(), "toml" | "managed") {
        errors.push("identity.authority must be toml or managed".to_string());
    }
    if deployment.environment == "production"
        && config.mode == "anonymous"
        && !deployment.allow_production_anonymous
    {
        errors.push(
            "production anonymous mode requires deployment.allow_production_anonymous = true"
                .to_string(),
        );
    }
    if (config.mode == "required" || config.mode == "optional")
        && config.sources.is_empty()
        && !config
            .trusted_callers
            .values()
            .any(|caller| caller.allow_forwarded_identity || caller.username_namespace.is_some())
    {
        errors.push(format!(
            "identity.mode = {} requires at least one identity source",
            config.mode
        ));
    }

    let mut source_names = BTreeSet::new();
    let mut header_schemes = BTreeMap::new();
    let mut static_principals = BTreeSet::new();
    for source in &config.sources {
        let source_label = if source.name.trim().is_empty() {
            "<empty>"
        } else {
            source.name.as_str()
        };
        if !is_safe_identifier(&source.name) {
            errors.push(format!(
                "identity.sources.{source_label}.name must match ^[A-Za-z0-9._-]{{1,128}}$"
            ));
        }
        if !source_names.insert(source.name.clone()) {
            errors.push(format!(
                "identity.sources.{source_label}.name is duplicated"
            ));
        }
        validate_header_name(
            &format!("identity.sources.{source_label}.header"),
            &source.header,
            errors,
        );
        if source.header.eq_ignore_ascii_case(EXECUTION_CONTEXT_HEADER) {
            errors.push(format!(
                "identity.sources.{source_label}.header must not use reserved header {EXECUTION_CONTEXT_HEADER}"
            ));
        }
        for reserved in [
            "x-agent-access-caller-authorization",
            "x-aw-identity-token-sha256",
            "x-agent-access-user",
        ] {
            if source.header.eq_ignore_ascii_case(reserved) {
                errors.push(format!(
                    "identity.sources.{source_label}.header must not use reserved header {reserved}"
                ));
            }
        }
        if source.scheme != "raw" && source.scheme != "Bearer" {
            errors.push(format!(
                "identity.sources.{source_label}.scheme must be raw or Bearer"
            ));
        }
        let normalized_header = source.header.to_ascii_lowercase();
        if let Some(existing_scheme) =
            header_schemes.insert(normalized_header.clone(), source.scheme.clone())
            && existing_scheme != source.scheme
        {
            errors.push(format!(
                "identity.sources.{source_label} uses scheme {} for header {}, but the header is already configured with scheme {}",
                source.scheme, source.header, existing_scheme
            ));
        }

        match source.kind.as_str() {
            "static_principals" => {
                if config.authority == "managed" {
                    errors.push(format!(
                        "identity.sources.{source_label}.type static_principals is only valid when identity.authority = toml"
                    ));
                }
                if source.principals.is_empty() {
                    errors.push(format!(
                        "identity.sources.{source_label}.principals must not be empty"
                    ));
                }
                for principal in &source.principals {
                    if principal.principal == "anonymous"
                        || !is_safe_principal(&principal.principal)
                    {
                        errors.push(format!(
                            "identity.sources.{source_label}.principals principal {} is invalid",
                            principal.principal
                        ));
                    }
                    if !static_principals.insert(principal.principal.clone()) {
                        errors.push(format!(
                            "identity.sources.{source_label}.principals principal {} is duplicated",
                            principal.principal
                        ));
                    }
                    if principal.token_refs.is_empty() {
                        errors.push(format!(
                            "identity.sources.{source_label}.principals.{}.token_refs must not be empty",
                            principal.principal
                        ));
                    }
                    for token_ref in &principal.token_refs {
                        validate_secret_ref(
                            &format!(
                                "identity.sources.{source_label}.principals.{}.token_refs",
                                principal.principal
                            ),
                            Some(token_ref),
                            errors,
                        );
                    }
                }
            }
            "jwt_jwks" => {
                errors.push(format!(
                    "identity.sources.{source_label}.type jwt_jwks has been removed"
                ));
            }
            "broker_tokens" => {
                if config.authority == "toml" {
                    errors.push(format!(
                        "identity.sources.{source_label}.type broker_tokens is only valid when identity.authority = managed"
                    ));
                }
                if !source.principals.is_empty() {
                    errors.push(format!(
                        "identity.sources.{source_label}.principals is only valid for static_principals"
                    ));
                }
            }
            _ => errors.push(format!(
                "identity.sources.{source_label}.type must be static_principals or broker_tokens"
            )),
        }
    }

    if config.authority == "managed" && !config.groups.is_empty() {
        errors.push("identity.groups is only valid when identity.authority = toml".to_string());
    }

    let mut group_ids = BTreeSet::new();
    for group in &config.groups {
        let group_label = if group.id.trim().is_empty() {
            "<empty>"
        } else {
            group.id.as_str()
        };
        if !is_safe_identifier(&group.id) {
            errors.push(format!(
                "identity.groups.{group_label}.id must match ^[A-Za-z0-9._-]{{1,128}}$"
            ));
        }
        if group.id == "anonymous" {
            errors.push("identity.groups.anonymous is reserved".to_string());
        }
        if !group_ids.insert(group.id.clone()) {
            errors.push(format!("identity.groups.{group_label}.id is duplicated"));
        }
        if !matches!(group.status.as_str(), "active" | "disabled") {
            errors.push(format!(
                "identity.groups.{group_label}.status must be active or disabled"
            ));
        }
        let mut members = BTreeSet::new();
        for member in &group.members {
            if !is_safe_principal(member) {
                errors.push(format!(
                    "identity.groups.{group_label}.members contains invalid principal {member}"
                ));
            } else if !static_principals.contains(member) {
                errors.push(format!(
                    "identity.groups.{group_label}.members references unknown static principal {member}"
                ));
            }
            if !members.insert(member.clone()) {
                errors.push(format!(
                    "identity.groups.{group_label}.members contains duplicate principal {member}"
                ));
            }
        }
    }
}

fn validate_network(config: &NetworkConfig, errors: &mut Vec<String>) {
    config.outbound_tls.validate(errors);
    for proxy in &config.trusted_proxies {
        validate_trusted_proxy_entry(proxy, errors);
    }
    validate_egress_proxy_config("network.egress_proxy", config.egress_proxy.as_ref(), errors);
}

fn validate_trusted_proxy_entry(value: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        errors.push("network.trusted_proxies entries must not be empty".to_string());
        return;
    }
    if trimmed == "*" {
        errors.push(
            "network.trusted_proxies cannot trust all sources; list explicit proxy IPs or CIDRs"
                .to_string(),
        );
        return;
    }
    if let Some((addr, prefix)) = trimmed.split_once('/') {
        let Ok(ip) = addr.parse::<IpAddr>() else {
            errors.push(format!(
                "network.trusted_proxies entry {trimmed} is not a valid CIDR"
            ));
            return;
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            errors.push(format!(
                "network.trusted_proxies entry {trimmed} has invalid CIDR prefix"
            ));
            return;
        };
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            errors.push(format!(
                "network.trusted_proxies entry {trimmed} has invalid CIDR prefix"
            ));
        }
        if prefix == 0 {
            errors.push(
                "network.trusted_proxies cannot trust all sources; list explicit proxy IPs or CIDRs"
                    .to_string(),
            );
        }
        return;
    }
    if trimmed.parse::<IpAddr>().is_err() {
        errors.push(format!(
            "network.trusted_proxies entry {trimmed} must be an IP address or CIDR"
        ));
    }
}

fn validate_managed_sections(config: &BrokerConfig, errors: &mut Vec<String>) {
    let has_broker_tokens_source = config
        .identity
        .sources
        .iter()
        .any(|source| source.kind == "broker_tokens");
    let has_connections = !config.credentials.connections.is_empty();

    if has_broker_tokens_source && config.broker_tokens.is_none() {
        errors.push(
            "broker_tokens is required when an identity source uses broker_tokens".to_string(),
        );
    }
    if has_broker_tokens_source && config.managed_store.is_none() {
        errors.push(
            "managed_store is required when an identity source uses broker_tokens".to_string(),
        );
    }
    if config.management.enabled
        && config.managed_store.is_none()
        && !storeless_classless_admin_management(config)
    {
        errors.push(
            "management.enabled without managed_store requires management.allow_classless_admin_identities, at least one management admin principal or group, and management.initial_admin.mode disabled"
                .to_string(),
        );
    }
    if has_connections && config.managed_store.is_none() {
        errors.push("credentials.connections requires managed_store".to_string());
    }
    if has_connections && config.credential_encryption.is_none() {
        errors.push("credentials.connections requires credential_encryption".to_string());
    }

    if config.identity.authority == "managed" && config.managed_store.is_none() {
        errors.push("identity.authority managed requires managed_store".to_string());
    }
    if config.identity.authority == "managed" {
        if !config.management.admin_principals.is_empty() {
            errors.push(
                "management.admin_principals is only valid when identity.authority = toml"
                    .to_string(),
            );
        }
        if !config.management.admin_groups.is_empty() {
            errors.push(
                "management.admin_groups is only valid when identity.authority = toml".to_string(),
            );
        }
        if config.management.allow_classless_admin_identities {
            errors.push(
                "management.allow_classless_admin_identities is only valid when identity.authority = toml"
                    .to_string(),
            );
        }
        if config.management.allow_classless_user_management {
            errors.push(
                "management.allow_classless_user_management is only valid when identity.authority = toml"
                    .to_string(),
            );
        }
    }

    if let Some(managed_store) = &config.managed_store {
        if managed_store.kind != "sqlite" {
            errors.push("managed_store.type must be sqlite".to_string());
        }
        match Path::new(&managed_store.path) {
            path if path.is_absolute() => {}
            _ => errors.push("managed_store.path must be absolute".to_string()),
        }
    }

    if let Some(encryption) = &config.credential_encryption {
        if !is_safe_identifier(&encryption.active_key) {
            errors.push(
                "credential_encryption.active_key must match ^[A-Za-z0-9._-]{1,128}$".to_string(),
            );
        }
        if encryption.keys.is_empty() {
            errors.push("credential_encryption.keys must not be empty".to_string());
        }
        let mut key_ids = BTreeSet::new();
        for key in &encryption.keys {
            let label = if key.id.trim().is_empty() {
                "<empty>"
            } else {
                key.id.as_str()
            };
            if !is_safe_identifier(&key.id) {
                errors.push(format!(
                    "credential_encryption.keys.{label}.id must match ^[A-Za-z0-9._-]{{1,128}}$"
                ));
            }
            if !key_ids.insert(key.id.clone()) {
                errors.push(format!(
                    "credential_encryption.keys.{label}.id is duplicated"
                ));
            }
            match key.provider.as_str() {
                "env" => {
                    if key.path.is_some() {
                        errors.push(format!(
                            "credential_encryption.keys.{label}.path is only valid for file keys"
                        ));
                    }
                    match key.env.as_deref() {
                        Some(name) if is_env_name(name) => {}
                        _ => errors.push(format!(
                            "credential_encryption.keys.{label}.env must be a valid environment variable name"
                        )),
                    }
                }
                "file" => {
                    if key.env.is_some() {
                        errors.push(format!(
                            "credential_encryption.keys.{label}.env is only valid for env keys"
                        ));
                    }
                    match key.path.as_deref() {
                        Some(path) if Path::new(path).is_absolute() => {}
                        Some(_) => errors.push(format!(
                            "credential_encryption.keys.{label}.path must be absolute"
                        )),
                        None => errors.push(format!(
                            "credential_encryption.keys.{label}.path is required for file keys"
                        )),
                    }
                }
                _ => errors.push(format!(
                    "credential_encryption.keys.{label}.provider must be env or file"
                )),
            }
        }
        if !key_ids.contains(&encryption.active_key) {
            errors.push(
                "credential_encryption.active_key must reference a configured key".to_string(),
            );
        }
    }

    for principal in &config.management.admin_principals {
        if !is_safe_principal(principal) {
            errors.push(format!(
                "management.admin_principals contains invalid principal {principal}"
            ));
        }
    }
    for group in &config.management.admin_groups {
        if !is_safe_identifier(group) {
            errors.push(format!(
                "management.admin_groups contains invalid group {group}"
            ));
        } else if config.identity.authority == "toml"
            && !config
                .identity
                .groups
                .iter()
                .any(|candidate| candidate.id == *group)
        {
            errors.push(format!(
                "management.admin_groups references unknown TOML group {group}"
            ));
        }
    }
    validate_initial_admin_config(config, errors);

    if let Some(tokens) = &config.broker_tokens {
        validate_secret_ref(
            "broker_tokens.hash_key_ref",
            Some(&tokens.hash_key_ref),
            errors,
        );
        let mut default_agent_invoke_ttl = None;
        let mut max_self_issued_agent_invoke_ttl = None;
        for (label, value) in [
            (
                "broker_tokens.default_agent_invoke_ttl",
                tokens.default_agent_invoke_ttl.as_deref(),
            ),
            (
                "broker_tokens.default_user_manage_ttl",
                tokens.default_user_manage_ttl.as_deref(),
            ),
            (
                "broker_tokens.default_admin_ttl",
                tokens.default_admin_ttl.as_deref(),
            ),
            (
                "broker_tokens.max_self_issued_agent_invoke_ttl",
                tokens.max_self_issued_agent_invoke_ttl.as_deref(),
            ),
        ] {
            if let Some(value) = value
                && let Some(seconds) = parse_ttl_seconds(value)
            {
                if label == "broker_tokens.default_agent_invoke_ttl" {
                    default_agent_invoke_ttl = Some(seconds);
                }
                if label == "broker_tokens.max_self_issued_agent_invoke_ttl" {
                    max_self_issued_agent_invoke_ttl = Some(seconds);
                }
            } else if value.is_some() {
                errors.push(format!("{label} must use a duration like 30d, 8h, or 120m"));
            }
        }
        let max_self_issued_agent_invoke_ttl = max_self_issued_agent_invoke_ttl
            .unwrap_or(DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS);
        if let Some(default_agent_invoke_ttl) = default_agent_invoke_ttl
            && default_agent_invoke_ttl > max_self_issued_agent_invoke_ttl
        {
            errors.push(
                "broker_tokens.default_agent_invoke_ttl must not exceed broker_tokens.max_self_issued_agent_invoke_ttl".to_string(),
            );
        }
        validate_broker_token_ttl_options(
            "broker_tokens.self_agent_invoke_ttl_options",
            &tokens.self_agent_invoke_ttl_options,
            true,
            Some(max_self_issued_agent_invoke_ttl),
            errors,
        );
        validate_broker_token_ttl_options(
            "broker_tokens.admin_agent_invoke_ttl_options",
            &tokens.admin_agent_invoke_ttl_options,
            true,
            None,
            errors,
        );
        validate_broker_token_ttl_options(
            "broker_tokens.user_manage_ttl_options",
            &tokens.user_manage_ttl_options,
            false,
            None,
            errors,
        );
        validate_broker_token_ttl_options(
            "broker_tokens.admin_ttl_options",
            &tokens.admin_ttl_options,
            false,
            None,
            errors,
        );

        let effective_agent_default = tokens
            .default_agent_invoke_ttl
            .as_deref()
            .or(tokens.max_self_issued_agent_invoke_ttl.as_deref())
            .unwrap_or(DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL);
        if !broker_token_ttl_options_allow_ttl(
            &tokens.self_agent_invoke_ttl_options,
            effective_agent_default,
        ) {
            errors.push(
                "the effective broker_tokens.default_agent_invoke_ttl must appear in broker_tokens.self_agent_invoke_ttl_options"
                    .to_string(),
            );
        }
        if let Some(default_agent_invoke_ttl) = tokens.default_agent_invoke_ttl.as_deref()
            && !broker_token_ttl_options_allow_ttl(
                &tokens.admin_agent_invoke_ttl_options,
                default_agent_invoke_ttl,
            )
        {
            errors.push(
                "broker_tokens.default_agent_invoke_ttl must appear in broker_tokens.admin_agent_invoke_ttl_options"
                    .to_string(),
            );
        }
        for (label, default, options) in [
            (
                "broker_tokens.default_user_manage_ttl",
                tokens.default_user_manage_ttl.as_deref(),
                tokens.user_manage_ttl_options.as_slice(),
            ),
            (
                "broker_tokens.default_admin_ttl",
                tokens.default_admin_ttl.as_deref(),
                tokens.admin_ttl_options.as_slice(),
            ),
        ] {
            if let Some(default) = default
                && !broker_token_ttl_options_allow_ttl(options, default)
            {
                errors.push(format!(
                    "{label} must appear in the corresponding broker_tokens TTL options"
                ));
            }
        }
    }
}

fn validate_broker_token_ttl_options(
    label: &str,
    options: &[BrokerTokenTtlOption],
    allow_never: bool,
    max_ttl_seconds: Option<u64>,
    errors: &mut Vec<String>,
) {
    if options.is_empty() {
        errors.push(format!("{label} must not be empty"));
        return;
    }
    let mut seen_ttls = BTreeSet::new();
    let mut seen_never = false;
    for option in options {
        match option {
            BrokerTokenTtlOption::Never => {
                if !allow_never {
                    errors.push(format!("{label} must not contain never"));
                }
                if seen_never {
                    errors.push(format!("{label} contains duplicate option never"));
                }
                seen_never = true;
            }
            BrokerTokenTtlOption::Ttl(value) => {
                if value != value.trim() {
                    errors.push(format!(
                        "{label} option {value:?} must not have surrounding whitespace"
                    ));
                    continue;
                }
                let Some(seconds) = parse_ttl_seconds(value) else {
                    errors.push(format!(
                        "{label} option {value:?} must be never or a duration like 30d, 8h, or 120m"
                    ));
                    continue;
                };
                if !seen_ttls.insert(seconds) {
                    errors.push(format!(
                        "{label} contains duplicate duration option {value:?}"
                    ));
                }
                if let Some(max_ttl_seconds) = max_ttl_seconds
                    && seconds > max_ttl_seconds
                {
                    errors.push(format!(
                        "{label} option {value:?} exceeds broker_tokens.max_self_issued_agent_invoke_ttl"
                    ));
                }
            }
        }
    }
}

fn storeless_classless_admin_management(config: &BrokerConfig) -> bool {
    config.management.allow_classless_admin_identities
        && (!config.management.admin_principals.is_empty()
            || !config.management.admin_groups.is_empty())
        && config.management.initial_admin.mode == "disabled"
}

fn validate_initial_admin_config(config: &BrokerConfig, errors: &mut Vec<String>) {
    let initial_admin = &config.management.initial_admin;
    match initial_admin.mode.as_str() {
        "disabled" => {
            if initial_admin.principal_id.is_some() {
                errors.push(
                    "management.initial_admin.principal_id is only valid when mode is create_if_empty"
                        .to_string(),
                );
            }
            if initial_admin.initial_password.is_some() {
                errors.push(
                    "management.initial_admin.initial_password is only valid when mode is create_if_empty"
                        .to_string(),
                );
            }
        }
        "create_if_empty" => {
            if !config.management.enabled {
                errors.push("management.initial_admin.mode create_if_empty requires management.enabled".to_string());
            }
            if config.managed_store.is_none() {
                errors.push("management.initial_admin.mode create_if_empty requires managed_store".to_string());
            }
            if !config.browser_auth.enabled || !config.browser_auth.local_password.enabled {
                errors.push("management.initial_admin.mode create_if_empty requires browser_auth local password login".to_string());
            }
            let principal = initial_admin.principal_id.as_deref();
            match principal {
                Some(principal) if is_safe_principal(principal) => {}
                Some(principal) => errors.push(format!(
                    "management.initial_admin.principal_id contains invalid principal {principal}"
                )),
                None => errors.push(
                    "management.initial_admin.principal_id is required when mode is create_if_empty"
                        .to_string(),
                ),
            }
            match initial_admin.initial_password.as_deref() {
                Some("") => errors.push(
                    "management.initial_admin.initial_password must not be empty".to_string(),
                ),
                Some("change-me-on-first-login" | "<insert-a-unique-generated-password>") => {
                    errors.push(
                        "management.initial_admin.initial_password must replace the sample placeholder with a unique generated password"
                            .to_string(),
                    );
                }
                Some(password) if password.len() > 1024 => errors.push(
                    "management.initial_admin.initial_password must be at most 1024 bytes"
                        .to_string(),
                ),
                Some(password)
                    if password.len() < config.browser_auth.local_password.min_password_length =>
                {
                    errors.push(format!(
                        "management.initial_admin.initial_password must be at least {} bytes",
                        config.browser_auth.local_password.min_password_length
                    ));
                }
                Some(password)
                    if principal.is_some_and(|principal| {
                        password.eq_ignore_ascii_case(principal)
                    }) =>
                {
                    errors.push(
                        "management.initial_admin.initial_password must not equal the principal id"
                            .to_string(),
                    );
                }
                Some(_) => {}
                None => errors.push(
                    "management.initial_admin.initial_password is required when mode is create_if_empty"
                        .to_string(),
                ),
            }
        }
        other => errors.push(format!(
            "management.initial_admin.mode {other} is unsupported; expected disabled or create_if_empty"
        )),
    }
}

fn validate_browser_auth(config: &BrokerConfig, errors: &mut Vec<String>) {
    let browser_auth = &config.browser_auth;
    validate_microsoft_oidc(config, errors);
    if !browser_auth.enabled {
        return;
    }
    if config.managed_store.is_none() {
        errors.push("browser_auth.enabled requires managed_store".to_string());
    }
    if !config.management.enabled {
        errors.push("browser_auth.enabled requires management.enabled".to_string());
    }
    if config.broker_tokens.is_none() {
        errors.push("browser_auth.enabled requires broker_tokens".to_string());
    }
    validate_cookie_name(
        "browser_auth.session_cookie_name",
        &browser_auth.session_cookie_name,
        errors,
    );
    validate_header_name(
        "browser_auth.csrf_header",
        &browser_auth.csrf_header,
        errors,
    );
    for reserved in [
        EXECUTION_CONTEXT_HEADER,
        "x-agent-access-caller-authorization",
        "x-aw-identity-token-sha256",
        "x-agent-access-user",
    ] {
        if browser_auth.csrf_header.eq_ignore_ascii_case(reserved) {
            errors.push(format!(
                "browser_auth.csrf_header must not use reserved header {reserved}"
            ));
        }
    }
    match browser_auth.csrf_key_ref.as_deref() {
        Some(value) if is_secret_ref(value) => {}
        Some(_) => errors
            .push("browser_auth.csrf_key_ref must be env:NAME or file:/absolute/path".to_string()),
        None => errors.push(
            "browser_auth.csrf_key_ref is required when browser_auth.enabled is true".to_string(),
        ),
    }
    match parse_ttl_seconds(&browser_auth.session_ttl) {
        Some(_) => {}
        None => errors.push(
            "browser_auth.session_ttl must use a positive duration like 8h or 30m".to_string(),
        ),
    }
    if let Some(origin) = &browser_auth.public_origin {
        validate_public_origin("browser_auth.public_origin", origin, errors);
    } else if config.deployment.environment == "production" {
        errors.push(
            "browser_auth.public_origin is required when browser_auth.enabled is true in production"
                .to_string(),
        );
    }
    if browser_auth.allowed_return_paths.is_empty() {
        errors.push("browser_auth.allowed_return_paths must not be empty".to_string());
    }
    for path in &browser_auth.allowed_return_paths {
        validate_portal_return_path(
            "browser_auth.allowed_return_paths",
            path,
            &config.portal.mount_path,
            errors,
        );
    }

    let local_password = &browser_auth.local_password;
    if !local_password.enabled {
        errors.push(
            "browser_auth.local_password.enabled must be true when browser_auth.enabled is true"
                .to_string(),
        );
    }
    if local_password.enabled {
        match local_password.pepper_ref.as_deref() {
            Some(value) if is_secret_ref(value) => {}
            Some(_) => errors.push(
                "browser_auth.local_password.pepper_ref must be env:NAME or file:/absolute/path"
                    .to_string(),
            ),
            None => errors.push(
                "browser_auth.local_password.pepper_ref is required when local password login is enabled"
                    .to_string(),
            ),
        }
        if local_password.min_password_length < 8 || local_password.min_password_length > 1024 {
            errors.push(
                "browser_auth.local_password.min_password_length must be between 8 and 1024"
                    .to_string(),
            );
        }
        if local_password.max_failed_attempts == 0 {
            errors.push(
                "browser_auth.local_password.max_failed_attempts must be greater than zero"
                    .to_string(),
            );
        }
        if parse_ttl_seconds(&local_password.lockout_ttl).is_none() {
            errors.push(
                "browser_auth.local_password.lockout_ttl must use a positive duration like 15m"
                    .to_string(),
            );
        }
    }
}

fn validate_microsoft_oidc(config: &BrokerConfig, errors: &mut Vec<String>) {
    let microsoft = &config.browser_auth.oidc.microsoft;
    if !microsoft.enabled {
        return;
    }

    if !config.browser_auth.enabled {
        errors
            .push("browser_auth.oidc.microsoft.enabled requires browser_auth.enabled".to_string());
    }
    if config.identity.authority != "managed" {
        errors.push(
            "browser_auth.oidc.microsoft.enabled requires identity.authority = managed".to_string(),
        );
    }
    if config.managed_store.is_none() {
        errors.push("browser_auth.oidc.microsoft.enabled requires managed_store".to_string());
    }
    if config.broker_tokens.is_none() {
        errors.push("browser_auth.oidc.microsoft.enabled requires broker_tokens".to_string());
    }
    if !config.management.enabled {
        errors.push("browser_auth.oidc.microsoft.enabled requires management.enabled".to_string());
    }
    if !config.browser_auth.local_password.enabled {
        errors.push(
            "browser_auth.oidc.microsoft.enabled requires browser_auth.local_password.enabled"
                .to_string(),
        );
    }

    validate_oidc_public_origin(config, errors);
    validate_canonical_uuid(
        "browser_auth.oidc.microsoft.tenant_id",
        microsoft.tenant_id.as_deref(),
        errors,
    );
    validate_canonical_uuid(
        "browser_auth.oidc.microsoft.client_id",
        microsoft.client_id.as_deref(),
        errors,
    );
    validate_oidc_secret_ref(
        "browser_auth.oidc.microsoft.client_secret_ref",
        microsoft.client_secret_ref.as_deref(),
        errors,
    );
    validate_oidc_secret_ref(
        "browser_auth.oidc.microsoft.flow_key_ref",
        microsoft.flow_key_ref.as_deref(),
        errors,
    );
    validate_bounded_ttl(
        "browser_auth.oidc.microsoft.flow_ttl",
        &microsoft.flow_ttl,
        2 * 60,
        15 * 60,
        errors,
    );
    if !(100..=100_000).contains(&microsoft.max_pending_flows) {
        errors.push(
            "browser_auth.oidc.microsoft.max_pending_flows must be between 100 and 100000"
                .to_string(),
        );
    }
    validate_bounded_ttl(
        "browser_auth.oidc.microsoft.external_membership_ttl",
        &microsoft.external_membership_ttl,
        15 * 60,
        24 * 60 * 60,
        errors,
    );
}

fn validate_oidc_public_origin(config: &BrokerConfig, errors: &mut Vec<String>) {
    let Some(value) = config.browser_auth.public_origin.as_deref() else {
        errors.push(
            "browser_auth.public_origin is required when Microsoft OIDC is enabled".to_string(),
        );
        return;
    };
    let Ok(url) = Url::parse(value) else {
        return;
    };
    let loopback_development = matches!(
        config.deployment.environment.as_str(),
        "development" | "test"
    ) && url.scheme() == "http"
        && is_loopback_or_localhost(url.host());
    if url.scheme() != "https" && !loopback_development {
        errors.push(
            "browser_auth.public_origin must use https when Microsoft OIDC is enabled, except for loopback development or test origins"
                .to_string(),
        );
    }
}

fn validate_canonical_uuid(label: &str, value: Option<&str>, errors: &mut Vec<String>) {
    let Some(value) = value else {
        errors.push(format!(
            "{label} is required when Microsoft OIDC is enabled"
        ));
        return;
    };
    let canonical = uuid::Uuid::parse_str(value)
        .ok()
        .map(|value| value.hyphenated().to_string());
    if canonical.as_deref() != Some(value) {
        errors.push(format!(
            "{label} must be a canonical lowercase hyphenated UUID"
        ));
    }
}

fn validate_oidc_secret_ref(label: &str, value: Option<&str>, errors: &mut Vec<String>) {
    match value {
        Some(value) if is_secret_ref(value) => {}
        Some(_) => errors.push(format!("{label} must be env:NAME or file:/absolute/path")),
        None => errors.push(format!(
            "{label} is required when Microsoft OIDC is enabled"
        )),
    }
}

fn validate_bounded_ttl(
    label: &str,
    value: &str,
    minimum_seconds: u64,
    maximum_seconds: u64,
    errors: &mut Vec<String>,
) {
    let Some(seconds) = parse_ttl_seconds(value) else {
        errors.push(format!(
            "{label} must use a positive duration like 10m or 8h"
        ));
        return;
    };
    if !(minimum_seconds..=maximum_seconds).contains(&seconds) {
        errors.push(format!(
            "{label} must be between {minimum_seconds} and {maximum_seconds} seconds"
        ));
    }
}

fn validate_portal(config: &BrokerConfig, errors: &mut Vec<String>) {
    let portal = &config.portal;
    if portal.mount_path != "/ui" {
        errors.push("portal.mount_path must be /ui".to_string());
    }
    if !portal.enabled {
        return;
    }
    let Some(static_dir) = portal.static_dir.as_deref() else {
        errors.push("portal.static_dir is required when portal.enabled is true".to_string());
        return;
    };
    if static_dir.trim().is_empty() {
        errors.push("portal.static_dir must not be empty".to_string());
    } else if !Path::new(static_dir).is_absolute() {
        errors.push("portal.static_dir must be absolute".to_string());
    }
    if !config.browser_auth.enabled {
        errors.push("portal.enabled requires browser_auth.enabled".to_string());
    }
}

fn validate_public_origin(label: &str, value: &str, errors: &mut Vec<String>) {
    match Url::parse(value) {
        Ok(url) => {
            if !matches!(url.scheme(), "http" | "https") {
                errors.push(format!("{label} must use http or https scheme"));
            }
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                errors.push(format!(
                    "{label} must be an origin without path, query, or fragment"
                ));
            }
            if url.scheme() == "http" && !is_loopback_or_localhost(url.host()) {
                errors.push(format!("{label} must use https for non-local origins"));
            }
        }
        Err(_) => errors.push(format!("{label} must be a valid URL origin")),
    }
}

fn validate_cookie_name(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte <= 0x20 || byte >= 0x7f || b"()<>@,;:\\\"/[]?={}".contains(&byte))
    {
        errors.push(format!("{label} must be a valid cookie name"));
    }
    let lower_value = value.to_ascii_lowercase();
    if lower_value.starts_with("__host-") || lower_value.starts_with("__secure-") {
        errors.push(format!(
            "{label} must not use __Host- or __Secure- prefixes because browser sessions use Path=/v1 and loopback development may be non-Secure"
        ));
    }
}

fn validate_portal_return_path(
    label: &str,
    value: &str,
    mount_path: &str,
    errors: &mut Vec<String>,
) {
    if value.is_empty()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
    {
        errors.push(format!(
            "{label} entry {value:?} must be an absolute path without query or fragment"
        ));
        return;
    }
    let decoded = match percent_encoding::percent_decode_str(value).decode_utf8() {
        Ok(decoded) => decoded,
        Err(_) => {
            errors.push(format!(
                "{label} entry {value:?} must not contain malformed percent-encoding"
            ));
            return;
        }
    };
    if decoded.as_ref() != value || portal_path_has_forbidden_segments(value) {
        errors.push(format!(
            "{label} entry {value:?} must be a literal path without encoded characters, empty segments, or dot segments"
        ));
        return;
    }
    if value != mount_path && !value.starts_with(&format!("{mount_path}/")) {
        errors.push(format!(
            "{label} entry {value:?} must be under {mount_path}"
        ));
    }
}

fn portal_path_has_forbidden_segments(value: &str) -> bool {
    value
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn validate_credentials(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    errors: &mut Vec<String>,
) {
    for (mode, entries) in [
        ("credentials.service", &config.credentials.service),
        ("credentials.per_user", &config.credentials.per_user),
        ("credentials.lookup", &config.credentials.lookup),
    ] {
        for (service, credential) in entries {
            if !is_service_name(service) {
                errors.push(format!("{mode}.{service} uses an invalid service name"));
            }
            validate_credential(config, services, mode, service, credential, errors);
            if mode == "credentials.lookup" && credential.read_only != Some(true) {
                errors.push(format!(
                    "{mode}.{service}.read_only must be true for lookup credentials"
                ));
            }
        }
    }
}

fn validate_credential(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    mode: &str,
    service: &str,
    credential: &CredentialConfig,
    errors: &mut Vec<String>,
) {
    if mode == "credentials.per_user"
        && credential.kind != "secret_store"
        && credential.kind != "connection"
    {
        errors.push(format!(
            "{mode}.{service}.type must be connection or secret_store for per_user credentials"
        ));
    }
    if credential.kind != "connection" && credential.connection.is_some() {
        errors.push(format!(
            "{mode}.{service}.connection is supported only for type connection"
        ));
    }
    if let Some(profile) = credential.profile.as_deref() {
        validate_shared_credential_profile(services, mode, service, credential, profile, errors);
    }
    match credential.kind.as_str() {
        "connection" => {
            if mode != "credentials.per_user" {
                errors.push(format!(
                    "{mode}.{service}.type connection is supported only for credentials.per_user"
                ));
            }
            if credential.username_ref.is_some()
                || credential.token_ref.is_some()
                || credential.provider.is_some()
                || credential.path.is_some()
                || credential.read_only.is_some()
            {
                errors.push(format!(
                    "{mode}.{service}.type connection sets only connection"
                ));
            }
            match credential.connection.as_deref() {
                Some(connection) if config.credentials.connections.contains_key(connection) => {}
                Some(connection) => errors.push(format!(
                    "{mode}.{service}.connection {connection} must name a configured credentials.connections entry"
                )),
                None => errors.push(format!("{mode}.{service}.connection is required")),
            }
            if mode == "credentials.per_user" && !services.contains_key(service) {
                errors.push(format!(
                    "{mode}.{service} uses a credential connection, but {service} is not a configured service"
                ));
            }
        }
        "basic_api_token" => {
            reject_static_credential_extras(mode, service, credential, errors);
            validate_secret_ref(
                &format!("{mode}.{service}.username_ref"),
                credential.username_ref.as_deref(),
                errors,
            );
            validate_secret_ref(
                &format!("{mode}.{service}.token_ref"),
                credential.token_ref.as_deref(),
                errors,
            );
        }
        "bearer_token" => {
            reject_static_credential_extras(mode, service, credential, errors);
            validate_secret_ref(
                &format!("{mode}.{service}.token_ref"),
                credential.token_ref.as_deref(),
                errors,
            );
        }
        "secret_store" => {
            reject_secret_store_extras(mode, service, credential, errors);
            if mode != "credentials.per_user" {
                errors.push(format!(
                    "{mode}.{service}.type secret_store is supported only for credentials.per_user"
                ));
            }
            match credential.provider.as_deref() {
                Some("local_file") => {}
                Some(_) => errors.push(format!(
                    "{mode}.{service}.provider must be local_file for secret_store"
                )),
                None => errors.push(format!("{mode}.{service}.provider is required for secret_store")),
            }
            match credential.path.as_deref() {
                Some(path) if Path::new(path).is_absolute() => {}
                Some(_) => errors.push(format!(
                    "{mode}.{service}.path must be absolute for secret_store"
                )),
                None => errors.push(format!("{mode}.{service}.path is required for secret_store")),
            }
        }
        other => errors.push(format!(
            "{mode}.{service}.type {other} is unsupported; expected basic_api_token, bearer_token, secret_store, or connection"
        )),
    }
    if mode == "credentials.service"
        && let Some(descriptor) = services.get(service)
        && !descriptor.credentials.service_kinds.is_empty()
        && !descriptor
            .credentials
            .service_kinds
            .contains(&credential.kind.as_str())
    {
        errors.push(format!(
            "credentials.service.{service}.type must be {}",
            descriptor.credentials.service_kinds.join(" or ")
        ));
    }
}

/// A shared credential's `profile`: only `credentials.service` and
/// `credentials.lookup` entries of a static type name one, and the service
/// must declare it with that type's kind, so the credential is lent as a
/// profile the provider knows.
fn validate_shared_credential_profile(
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    mode: &str,
    service: &str,
    credential: &CredentialConfig,
    profile: &str,
    errors: &mut Vec<String>,
) {
    if !matches!(mode, "credentials.service" | "credentials.lookup")
        || !matches!(credential.kind.as_str(), "basic_api_token" | "bearer_token")
    {
        errors.push(format!(
            "{mode}.{service}.profile is supported only for credentials.service and credentials.lookup entries of type basic_api_token or bearer_token"
        ));
        return;
    }
    let Some(descriptor) = services.get(service) else {
        return;
    };
    match descriptor.credential_profile_kind(profile) {
        Some(kind) if kind == credential.kind => {}
        Some(kind) => errors.push(format!(
            "{mode}.{service}.profile {profile} stores {kind}, not {}",
            credential.kind
        )),
        None => errors.push(format!(
            "{mode}.{service}.profile {profile} is not a token profile {service} declares"
        )),
    }
}

fn reject_static_credential_extras(
    mode: &str,
    service: &str,
    credential: &CredentialConfig,
    errors: &mut Vec<String>,
) {
    if credential.provider.is_some() || credential.path.is_some() {
        errors.push(format!(
            "{mode}.{service} static credentials must not set provider or path"
        ));
    }
}

fn reject_secret_store_extras(
    mode: &str,
    service: &str,
    credential: &CredentialConfig,
    errors: &mut Vec<String>,
) {
    if credential.username_ref.is_some()
        || credential.token_ref.is_some()
        || credential.read_only.is_some()
    {
        errors.push(format!(
            "{mode}.{service}.type secret_store must not set username_ref, token_ref, or read_only"
        ));
    }
}

fn validate_secret_ref(label: &str, value: Option<&str>, errors: &mut Vec<String>) {
    match value {
        Some(raw) if is_secret_ref(raw) => {}
        Some(_) => errors.push(format!("{label} must use env:NAME or file:/absolute/path")),
        None => errors.push(format!("{label} is required")),
    }
}

fn validate_gateways(config: &BrokerConfig, errors: &mut Vec<String>) {
    let provider_services = configured_provider_descriptors(config)
        .into_iter()
        .map(|descriptor| descriptor.service)
        .collect::<BTreeSet<_>>();
    let mut broker_hosts = BTreeMap::<String, String>::new();
    for (service, gateway) in &config.gateways {
        if service == "broker" || !is_service_name(service) {
            errors.push(format!("gateways.{service} uses an invalid service name"));
        }
        // Every selected native kind stays reserved even while unconfigured,
        // so configuring its provider never renames a gateway's service.
        if config.providers.registry().get(service).is_some() {
            errors.push(format!(
                "gateways.{service} collides with the selected native provider kind {service}"
            ));
        } else if provider_services.contains(service) {
            errors.push(format!(
                "gateways.{service} collides with the configured provider service {service}"
            ));
        }
        if gateway.display_name.trim().is_empty() {
            errors.push(format!("gateways.{service}.display_name must not be empty"));
        }
        if gateway.broker_hosts.is_empty() {
            errors.push(format!("gateways.{service}.broker_hosts must not be empty"));
        }
        let mut service_hosts = BTreeSet::new();
        for host in &gateway.broker_hosts {
            match normalize_gateway_broker_host(host) {
                Ok(normalized) => {
                    if !service_hosts.insert(normalized.clone()) {
                        errors.push(format!(
                            "gateways.{service}.broker_hosts contains duplicate host {host}"
                        ));
                    } else if let Some(previous_service) =
                        broker_hosts.insert(normalized, service.clone())
                    {
                        errors.push(format!(
                            "gateways.{service}.broker_hosts host {host} is already used by gateways.{previous_service}"
                        ));
                    }
                }
                Err(message) => errors.push(format!(
                    "gateways.{service}.broker_hosts entry {host:?} {message}"
                )),
            }
        }
        validate_gateway_upstream_base_url(service, &gateway.upstream_base_url, errors);
        validate_upstream_allowlist(
            &format!("gateways.{service}.allowed_upstream_hosts"),
            &gateway.allowed_upstream_hosts,
            true,
            errors,
        );
        validate_egress_proxy_config(
            &format!("gateways.{service}.egress_proxy"),
            gateway.egress_proxy.as_ref(),
            errors,
        );
        if gateway.auth_modes.is_empty() {
            errors.push(format!("gateways.{service}.auth_modes must not be empty"));
        }
        for mode in &gateway.auth_modes {
            if mode != "basic_broker_token" {
                errors.push(format!(
                    "gateways.{service}.auth_modes contains unsupported mode {mode}"
                ));
            }
        }
        if gateway.basic_broker_token_username.trim().is_empty()
            || gateway.basic_broker_token_username.contains(':')
            || gateway
                .basic_broker_token_username
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace() || !ch.is_ascii())
        {
            errors.push(format!(
                "gateways.{service}.basic_broker_token_username must be non-empty ASCII without whitespace or colon"
            ));
        }
        if gateway.credential_modes.is_empty() {
            errors.push(format!(
                "gateways.{service}.credential_modes must not be empty"
            ));
        }
        let mut credential_modes = BTreeSet::new();
        for mode in &gateway.credential_modes {
            if !credential_modes.insert(mode.clone()) {
                errors.push(format!(
                    "gateways.{service}.credential_modes contains duplicate mode {mode}"
                ));
            }
            if mode != "service" && mode != "per_user" {
                errors.push(format!(
                    "gateways.{service}.credential_modes contains unsupported mode {mode}"
                ));
            } else if !credential_mode_configured(&config.credentials, service, mode) {
                errors.push(format!(
                    "gateways.{service}.credential_modes includes {mode} but credentials.{mode}.{service} is not configured"
                ));
            }
        }
        gateway_token_auth::validate_upstream_token_auth(
            service,
            &gateway.upstream_token_auth,
            errors,
        );
        if gateway.redirect_policy != "none" {
            errors.push(format!(
                "gateways.{service}.redirect_policy must be none in V1"
            ));
        }
        for (field, value) in [
            ("request_body_max_bytes", gateway.request_body_max_bytes),
            ("response_body_max_bytes", gateway.response_body_max_bytes),
            (
                "streaming_idle_timeout_ms",
                gateway.streaming_idle_timeout_ms,
            ),
        ] {
            if value == Some(0) {
                errors.push(format!("gateways.{service}.{field} must be non-zero"));
            }
        }
        if gateway
            .request_body_max_bytes
            .is_some_and(|value| value > config.limits.max_http_body_bytes)
        {
            errors.push(format!(
                "gateways.{service}.request_body_max_bytes must not exceed limits.max_http_body_bytes"
            ));
        }
        if gateway
            .response_body_max_bytes
            .is_some_and(|value| value > config.limits.max_upstream_response_bytes)
        {
            errors.push(format!(
                "gateways.{service}.response_body_max_bytes must not exceed limits.max_upstream_response_bytes"
            ));
        }
        match gateway.kind.as_str() {
            "git_http" => validate_git_http_gateway(service, gateway, errors),
            "http_reverse" => errors.push(format!(
                "gateways.{service}.kind http_reverse is not implemented in this slice"
            )),
            other => errors.push(format!(
                "gateways.{service}.kind {other} is unsupported; expected git_http"
            )),
        }
    }
}

fn validate_gateway_upstream_base_url(service: &str, value: &str, errors: &mut Vec<String>) {
    match Url::parse(value) {
        Ok(url) if url.scheme() == "https" => {
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                errors.push(format!(
                    "gateways.{service}.upstream_base_url must be an https URL without credentials, query, or fragment"
                ));
            }
        }
        Ok(_) => errors.push(format!(
            "gateways.{service}.upstream_base_url must use https"
        )),
        Err(_) => errors.push(format!(
            "gateways.{service}.upstream_base_url must be a valid URL"
        )),
    }
}

fn validate_git_http_gateway(service: &str, gateway: &GatewayConfig, errors: &mut Vec<String>) {
    let Some(git) = &gateway.git else {
        errors.push(format!("gateways.{service}.git is required for git_http"));
        return;
    };
    if !git.allow_fetch && !git.allow_push {
        errors.push(format!(
            "gateways.{service}.git must enable allow_fetch or allow_push"
        ));
    }
    if git.receive_pack_prefix_max_bytes == Some(0) {
        errors.push(format!(
            "gateways.{service}.git.receive_pack_prefix_max_bytes must be non-zero"
        ));
    }
    let mut patterns = BTreeSet::new();
    for pattern in &git.deny_ref_patterns {
        if !patterns.insert(pattern.clone()) {
            errors.push(format!(
                "gateways.{service}.git.deny_ref_patterns contains duplicate pattern {pattern}"
            ));
        }
        if !is_git_ref_pattern(pattern) {
            errors.push(format!(
                "gateways.{service}.git.deny_ref_patterns contains invalid pattern {pattern}"
            ));
        }
    }
}

pub fn normalize_gateway_broker_host(value: &str) -> Result<String, &'static str> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("must not be empty");
    }
    if host != value || value.ends_with('.') {
        return Err("must be lower-case without leading/trailing whitespace or trailing dot");
    }
    if host.contains('*')
        || host.contains('{')
        || host.contains('}')
        || host.contains(':')
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
    {
        return Err(
            "must be an exact DNS host without wildcard, placeholder, port, path, or userinfo",
        );
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("must be a DNS host, not an IP literal");
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("must be a valid lower-case DNS host");
    }
    Ok(host)
}

fn is_git_ref_pattern(value: &str) -> bool {
    let value = value.strip_suffix("/**").unwrap_or(value);
    if value.is_empty()
        || !value.starts_with("refs/")
        || value.contains('\\')
        || value.contains("//")
        || value.contains("..")
        || value.contains('*')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
    }
    true
}

fn validate_policy(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    resource_types: &ResourceTypeRegistry,
    errors: &mut Vec<String>,
) {
    if !matches!(config.policy.authority.as_str(), "toml" | "managed") {
        errors.push("policy.authority must be toml or managed".to_string());
    }
    if config.identity.authority == "toml" && config.policy.authority == "managed" {
        errors
            .push("policy.authority managed is invalid when identity.authority = toml".to_string());
    }
    if config.policy.default_decision != "deny" {
        errors.push("policy.default_decision must be deny".to_string());
    }
    if config.policy.authority == "managed" {
        if config.managed_store.is_none() {
            errors.push("policy.authority managed requires managed_store".to_string());
        }
        if !config.policy.resources.is_empty() || !config.policy.resource_groups.is_empty() {
            errors.push("policy.resources and policy.resource_groups must be empty when policy.authority = managed".to_string());
        }
        if !config.policy.grants.is_empty() {
            errors.push("policy.grants must be empty when policy.authority = managed".to_string());
        }
        return;
    }

    let toml_principals = configured_static_principals(&config.identity);
    let toml_groups = configured_toml_groups(&config.identity);
    for (index, grant) in config.policy.grants.iter().enumerate() {
        let grant_label = format!("policy.grants[{index}]");
        if config.execution_context.is_some() && grant.execution_contexts.is_none() {
            errors.push(format!(
                "{grant_label}.execution_contexts is required when execution_context is configured"
            ));
        }
        validate_policy_subjects(&format!("{grant_label}.subjects"), &grant.subjects, errors);
        validate_policy_subject_duplicates(&grant_label, &grant.subjects, errors);
        for (subject_index, subject) in grant.subjects.iter().enumerate() {
            validate_policy_subject_authority(
                &format!("{grant_label}.subjects[{subject_index}]"),
                subject,
                &config.identity,
                &toml_principals,
                &toml_groups,
                errors,
            );
        }
    }
    let catalog = services;
    let grants = config
        .policy
        .grants
        .iter()
        .enumerate()
        .flat_map(|(index, grant)| {
            grant
                .subjects
                .iter()
                .enumerate()
                .map(move |(subject_index, subject)| NormalizedPolicyGrant {
                    label: format!("policy.grants[{index}].subjects[{subject_index}]"),
                    service_label: format!("policy.grants[{index}].service"),
                    actions_label: format!("policy.grants[{index}].actions"),
                    credential_mode_label: format!("policy.grants[{index}].credential_mode"),
                    execution_contexts_label: format!("policy.grants[{index}].execution_contexts"),
                    subject_field: format!("policy.grants[{index}].subjects[{subject_index}]"),
                    subject,
                    service: &grant.service,
                    actions: &grant.actions,
                    resources: &grant.resources,
                    execution_contexts: grant
                        .execution_contexts
                        .clone()
                        .unwrap_or_else(|| vec![DEFAULT_EXECUTION_CONTEXT.to_string()]),
                    credential_mode: &grant.credential_mode,
                    priority: grant.priority,
                })
        })
        .collect::<Vec<_>>();
    // TOML grants never name imported services: imports require managed
    // policy.
    validate_normalized_policy_grants(
        config,
        catalog,
        &ImportedCatalog::default(),
        resource_types,
        &grants,
        errors,
    );
}

fn configured_static_principals(identity: &IdentityConfig) -> BTreeSet<String> {
    identity
        .sources
        .iter()
        .filter(|source| source.kind == "static_principals")
        .flat_map(|source| {
            source
                .principals
                .iter()
                .map(|principal| principal.principal.clone())
        })
        .collect()
}

fn configured_toml_groups(identity: &IdentityConfig) -> BTreeSet<String> {
    identity
        .groups
        .iter()
        .map(|group| group.id.clone())
        .collect()
}

pub fn validate_policy_subjects(label: &str, subjects: &[String], errors: &mut Vec<String>) {
    if subjects.is_empty() {
        errors.push(format!("{label} must not be empty"));
        return;
    }
    if subjects.len() > POLICY_GRANT_MAX_SUBJECTS {
        errors.push(format!(
            "{label} must contain at most {POLICY_GRANT_MAX_SUBJECTS} entries"
        ));
    }
    for (index, subject) in subjects.iter().enumerate() {
        validate_subject(&format!("{label}[{index}]"), subject, errors);
    }
}

pub fn validate_policy_subject_duplicates(
    grant_label: &str,
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for (index, subject) in subjects.iter().enumerate() {
        if !seen.insert(subject) {
            errors.push(format!(
                "{grant_label}.subjects[{index}] duplicates an earlier subject"
            ));
        }
    }
}

fn validate_policy_subject_authority(
    label: &str,
    subject: &str,
    identity: &IdentityConfig,
    toml_principals: &BTreeSet<String>,
    toml_groups: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if identity.authority != "toml" {
        return;
    }
    if subject == "group:anonymous" || subject == "user:anonymous" {
        return;
    }
    if let Some(principal) = subject.strip_prefix("user:") {
        if is_safe_principal(principal) && !toml_principals.contains(principal) {
            errors.push(format!(
                "{label} references unknown TOML principal {principal}"
            ));
        }
    } else if let Some(group) = subject.strip_prefix("group:")
        && is_safe_identifier(group)
        && !toml_groups.contains(group)
    {
        errors.push(format!("{label} references unknown TOML group {group}"));
    }
}

pub(crate) struct NormalizedPolicyGrant<'a> {
    pub label: String,
    pub service_label: String,
    pub actions_label: String,
    pub credential_mode_label: String,
    pub execution_contexts_label: String,
    pub subject_field: String,
    pub subject: &'a str,
    pub service: &'a str,
    pub actions: &'a [String],
    pub resources: &'a ResourceSelection,
    pub execution_contexts: Vec<String>,
    pub credential_mode: &'a str,
    pub priority: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NormalizedPolicyGrantIssueField {
    Grant,
    Subject,
    Service,
    Actions,
    CredentialMode,
    ExecutionContexts,
    Resources,
}

#[derive(Debug)]
pub(crate) struct NormalizedPolicyGrantValidationIssue {
    pub field: NormalizedPolicyGrantIssueField,
    pub subject_field: Option<String>,
    pub code: &'static str,
    pub message: String,
}

fn normalized_policy_issue(
    field: NormalizedPolicyGrantIssueField,
    code: &'static str,
    message: impl Into<String>,
) -> NormalizedPolicyGrantValidationIssue {
    NormalizedPolicyGrantValidationIssue {
        field,
        subject_field: None,
        code,
        message: message.into(),
    }
}

fn normalized_policy_subject_issue(
    subject_field: impl Into<String>,
    code: &'static str,
    message: impl Into<String>,
) -> NormalizedPolicyGrantValidationIssue {
    NormalizedPolicyGrantValidationIssue {
        field: NormalizedPolicyGrantIssueField::Subject,
        subject_field: Some(subject_field.into()),
        code,
        message: message.into(),
    }
}

#[derive(Debug)]
struct PolicyValidationContainmentGrant {
    label: String,
    subject_field: String,
    subject: String,
    service: String,
    action: String,
    scope_type: String,
    boundary: ResourceBoundary,
    execution_contexts: Vec<String>,
    credential_mode: String,
    priority: i32,
    lookup_required: bool,
    /// Overlapping modes are passed together, not ambiguous.
    command_enforced: bool,
}

#[derive(Debug)]
struct PolicyValidationStaticGrant {
    subject: String,
    service: String,
    action: String,
    scope_key: String,
    execution_contexts: Vec<String>,
    credential_mode: String,
    priority: i32,
}

pub(crate) fn validate_normalized_policy_grants(
    config: &BrokerConfig,
    catalog: &BTreeMap<String, Arc<ServiceDescriptor>>,
    imported: &ImportedCatalog,
    resource_types: &ResourceTypeRegistry,
    grants: &[NormalizedPolicyGrant<'_>],
    errors: &mut Vec<String>,
) {
    errors.extend(
        normalized_policy_grant_validation_issues(
            config,
            catalog,
            imported,
            resource_types,
            grants,
        )
        .into_iter()
        .map(|issue| issue.message),
    );
}

/// Validates normalized grants against the service catalog. Grants for a
/// command-enforced action of an `imported` command import may mix
/// credential modes in one band, since each passed grant names its own; every
/// other action rejects that as ambiguous.
pub(crate) fn normalized_policy_grant_validation_issues(
    config: &BrokerConfig,
    catalog: &BTreeMap<String, Arc<ServiceDescriptor>>,
    imported: &ImportedCatalog,
    resource_types: &ResourceTypeRegistry,
    grants: &[NormalizedPolicyGrant<'_>],
) -> Vec<NormalizedPolicyGrantValidationIssue> {
    let mut issues = Vec::new();
    let resource_catalog =
        match ResourceCatalog::new(&config.policy.resources, &config.policy.resource_groups)
            .and_then(|catalog| {
                let errors =
                    validate_resource_definition_types(resource_types, &config.policy.resources);
                if errors.is_empty() {
                    Ok(catalog)
                } else {
                    Err(errors)
                }
            }) {
            Ok(catalog) => catalog,
            Err(errors) => {
                return errors
                    .into_iter()
                    .map(|error| {
                        normalized_policy_issue(
                            NormalizedPolicyGrantIssueField::Resources,
                            "resource_catalog_invalid",
                            error,
                        )
                    })
                    .collect();
            }
        };
    let contexts = config
        .execution_context
        .as_ref()
        .map(|c| c.allowed_values.clone())
        .unwrap_or_else(|| vec![DEFAULT_EXECUTION_CONTEXT.to_string()]);
    if let Err(errors) = resource_catalog.validate_contexts(&contexts) {
        issues.extend(errors.into_iter().map(|error| {
            normalized_policy_issue(
                NormalizedPolicyGrantIssueField::Resources,
                "resource_context_invalid",
                error,
            )
        }));
    }
    let mut static_grants = Vec::new();
    let mut containment_grants = Vec::new();
    let mut services_requiring_lookup_credentials = BTreeSet::new();
    let mut stable_signing_key_actions = BTreeSet::new();

    for grant in grants {
        validate_policy_execution_contexts(config, grant, &mut issues);
        if !is_service_name(grant.service) {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::Service,
                "service_invalid",
                format!("{} is invalid", grant.service_label),
            ));
            continue;
        }
        let Some(service) = catalog.get(grant.service) else {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::Service,
                "service_unknown",
                format!(
                    "{} references unknown service {}",
                    grant.label, grant.service
                ),
            ));
            continue;
        };
        if grant.actions.is_empty() {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::Actions,
                "actions_empty",
                format!("{} must not be empty", grant.actions_label),
            ));
        }
        if grant.credential_mode != "service" && grant.credential_mode != "per_user" {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::CredentialMode,
                "credential_mode_invalid",
                format!(
                    "{} must be service or per_user",
                    grant.credential_mode_label
                ),
            ));
        } else if !credential_mode_available(
            &config.credentials,
            grant.service,
            grant.credential_mode,
            Some(&service.credentials),
        ) {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::CredentialMode,
                "credential_mode_unconfigured",
                format!(
                    "{} uses {} credentials for {} but they are not configured",
                    grant.label, grant.credential_mode, grant.service
                ),
            ));
        }

        if let Err(errors) = resource_catalog.validate_selection(grant.resources) {
            for error in errors {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Resources,
                    "resource_reference_invalid",
                    format!("{}: {error}", grant.label),
                ));
            }
        }

        for action in grant.actions {
            if !is_action_name(action) {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Actions,
                    "action_invalid",
                    format!("{} action {action} is invalid", grant.label),
                ));
            }
            if action.starts_with(&format!("{}.", grant.service)) {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Actions,
                    "action_invalid",
                    format!(
                        "{} action {action} must not repeat service prefix",
                        grant.label
                    ),
                ));
            }
            let command_enforced = crate::runtime::command_enforced_action(
                config,
                imported,
                catalog,
                grant.service,
                action,
            );
            let Some(action_spec) = service.action(action) else {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Actions,
                    "action_unknown",
                    format!(
                        "{} action {action} is unknown for service {}",
                        grant.label, grant.service
                    ),
                ));
                continue;
            };
            if action_spec.resource_scope.is_none() && !grant.resources.is_empty() {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Resources,
                    "resource_selection_unsupported",
                    format!(
                        "{} action {}.{} does not support resource selections",
                        grant.label, grant.service, action
                    ),
                ));
            }
            if let Some(scope) = &action_spec.resource_scope
                && !service.resource_scopes.contains_key(scope)
            {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::Resources,
                    "resource_type_unbound",
                    format!(
                        "{} action {}.{} has no supported resource type for scope {scope}",
                        grant.label, grant.service, action
                    ),
                ));
            }
            if action_spec.requires_stable_signing_key {
                stable_signing_key_actions.insert(format!("{}.{action}", grant.service));
            }
            if !action_spec
                .credential_modes
                .iter()
                .any(|mode| mode == grant.credential_mode)
            {
                issues.push(normalized_policy_issue(
                    NormalizedPolicyGrantIssueField::CredentialMode,
                    "credential_mode_invalid",
                    format!(
                        "{} credential mode {} is unsupported for {}.{}",
                        grant.label, grant.credential_mode, grant.service, action
                    ),
                ));
            }
            if action_spec.lookup.credential_required() && grant.credential_mode == "service" {
                services_requiring_lookup_credentials.insert(grant.service.to_string());
            }
            let mut reference_resources = grant.resources.resource_ids.clone();
            let mut reference_groups = grant.resources.resource_group_ids.clone();
            reference_resources.sort();
            reference_groups.sort();
            let scope_key = serde_json::to_string(&(reference_resources, reference_groups))
                .expect("serializable references");
            for previous in
                static_grants
                    .iter()
                    .filter(|previous: &&PolicyValidationStaticGrant| {
                        previous.subject == grant.subject
                            && previous.service == grant.service
                            && previous.action == *action
                            && previous.scope_key == scope_key
                            && previous.priority == grant.priority.unwrap_or(0)
                            && execution_context_lists_overlap(
                                &previous.execution_contexts,
                                &grant.execution_contexts,
                            )
                    })
            {
                if previous.credential_mode != grant.credential_mode {
                    // A command-enforced action passes both grants, each
                    // with its own credential.
                    if !command_enforced {
                        issues.push(normalized_policy_subject_issue(
                            grant.subject_field.clone(),
                            "credential_mode_ambiguous",
                            format!(
                                "{} has ambiguous credential mode precedence for the same subject/action/scope/priority",
                                grant.label
                            ),
                        ));
                    }
                } else {
                    issues.push(normalized_policy_subject_issue(
                        grant.subject_field.clone(),
                        "grant_duplicate",
                        format!(
                            "{} duplicates an existing grant for the same subject/action/scope/priority",
                            grant.label
                        ),
                    ));
                }
            }
            static_grants.push(PolicyValidationStaticGrant {
                subject: grant.subject.to_string(),
                service: grant.service.to_string(),
                action: action.clone(),
                scope_key,
                execution_contexts: grant.execution_contexts.clone(),
                credential_mode: grant.credential_mode.to_string(),
                priority: grant.priority.unwrap_or(0),
            });
            if let Some((scope_type, binding)) = service.action_resource_scope(action) {
                let resource_type = &binding.resource_type;
                for context in &grant.execution_contexts {
                    let boundary =
                        resource_catalog.resolve(grant.resources, resource_type, context);
                    containment_grants.push(PolicyValidationContainmentGrant {
                        label: grant.label.clone(),
                        subject_field: grant.subject_field.clone(),
                        subject: grant.subject.to_string(),
                        service: grant.service.to_string(),
                        action: action.clone(),
                        scope_type: scope_type.to_string(),
                        boundary,
                        execution_contexts: vec![context.clone()],
                        credential_mode: grant.credential_mode.to_string(),
                        priority: grant.priority.unwrap_or(0),
                        lookup_required: action_spec.lookup.credential_required(),
                        command_enforced,
                    });
                }
            }
        }
    }

    for service in services_requiring_lookup_credentials {
        if !config.credentials.lookup.contains_key(&service) {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::CredentialMode,
                "credential_mode_unconfigured",
                format!("service-mode lookup-backed policy requires credentials.lookup.{service}"),
            ));
        }
    }
    if let Some(action) = stable_signing_key_actions.first() {
        validate_stable_signing_key(config, action, &mut issues);
    }
    validate_policy_containment_overlaps(&containment_grants, &mut issues);
    issues
}

fn validate_policy_execution_contexts(
    config: &BrokerConfig,
    grant: &NormalizedPolicyGrant<'_>,
    issues: &mut Vec<NormalizedPolicyGrantValidationIssue>,
) {
    if grant.execution_contexts.is_empty() {
        issues.push(normalized_policy_issue(
            NormalizedPolicyGrantIssueField::ExecutionContexts,
            "execution_contexts_empty",
            format!("{} must not be empty", grant.execution_contexts_label),
        ));
        return;
    }
    if grant.execution_contexts.len() > EXECUTION_CONTEXT_MAX_VALUES {
        issues.push(normalized_policy_issue(
            NormalizedPolicyGrantIssueField::ExecutionContexts,
            "execution_contexts_too_many",
            format!(
                "{} must contain at most {EXECUTION_CONTEXT_MAX_VALUES} entries",
                grant.execution_contexts_label
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, value) in grant.execution_contexts.iter().enumerate() {
        if !is_valid_execution_context_value(value) {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::ExecutionContexts,
                "execution_context_invalid",
                format!(
                    "{}[{index}] must match ^[a-z][a-z0-9_-]{{0,63}}$",
                    grant.execution_contexts_label
                ),
            ));
        }
        if !seen.insert(value) {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::ExecutionContexts,
                "execution_context_duplicate",
                format!(
                    "{}[{index}] duplicates an earlier value",
                    grant.execution_contexts_label
                ),
            ));
        }
        let configured = config.execution_context.as_ref().map_or_else(
            || value == DEFAULT_EXECUTION_CONTEXT,
            |context| {
                context
                    .allowed_values
                    .iter()
                    .any(|allowed| allowed == value)
            },
        );
        if !configured {
            issues.push(normalized_policy_issue(
                NormalizedPolicyGrantIssueField::ExecutionContexts,
                "execution_context_unknown",
                format!(
                    "{}[{index}] references unconfigured execution context {value}",
                    grant.execution_contexts_label
                ),
            ));
        }
    }
}

fn execution_context_lists_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.contains(value))
}

/// Actions that issue durable signed handles need a signing key that survives
/// restarts and reloads, so grants for them require the configured key.
fn validate_stable_signing_key(
    config: &BrokerConfig,
    action: &str,
    issues: &mut Vec<NormalizedPolicyGrantValidationIssue>,
) {
    let Some(tokens) = config.broker_tokens.as_ref() else {
        issues.push(normalized_policy_issue(
            NormalizedPolicyGrantIssueField::Grant,
            "grant_invalid",
            format!(
                "policy grants for {action} issue durable handles and require broker_tokens.hash_key_ref"
            ),
        ));
        return;
    };
    if BrokerTokenHasher::load(tokens).is_err() {
        issues.push(normalized_policy_issue(
            NormalizedPolicyGrantIssueField::Grant,
            "grant_invalid",
            format!(
                "policy grants for {action} issue durable handles and require broker_tokens.hash_key_ref to resolve to a valid signing key"
            ),
        ));
    }
}

fn validate_policy_containment_overlaps(
    grants: &[PolicyValidationContainmentGrant],
    issues: &mut Vec<NormalizedPolicyGrantValidationIssue>,
) {
    for (left_index, left) in grants.iter().enumerate() {
        for right in grants.iter().skip(left_index + 1) {
            if left.subject != right.subject
                || left.service != right.service
                || left.action != right.action
                || left.scope_type != right.scope_type
                || left.priority != right.priority
                || left.credential_mode == right.credential_mode
                || left.command_enforced
                || !execution_context_lists_overlap(
                    &left.execution_contexts,
                    &right.execution_contexts,
                )
            {
                continue;
            }
            let left_is_wildcard = left.boundary.is_universe();
            let right_is_wildcard = right.boundary.is_universe();
            if left.lookup_required
                && right.lookup_required
                && left_is_wildcard != right_is_wildcard
            {
                continue;
            }
            if left.boundary.intersects(&right.boundary) {
                issues.push(normalized_policy_subject_issue(
                    right.subject_field.clone(),
                    "credential_mode_ambiguous",
                    format!(
                        "{} has ambiguous credential mode precedence for overlapping {} scope values",
                        right.label, right.scope_type
                    ),
                ));
            }
        }
    }
}

fn validate_limits(config: &BrokerConfig, errors: &mut Vec<String>) {
    let limits = &config.limits;
    if limits.auth_requests_per_principal_per_minute == 0 {
        errors.push("limits.auth_requests_per_principal_per_minute must be non-zero".to_string());
    }
    if limits.auth_requests_per_source_per_minute == 0 {
        errors.push("limits.auth_requests_per_source_per_minute must be non-zero".to_string());
    }
    if limits.max_concurrent_requests == 0 {
        errors.push("limits.max_concurrent_requests must be non-zero".to_string());
    }
    if limits.max_concurrent_requests_per_principal == 0 {
        errors.push("limits.max_concurrent_requests_per_principal must be non-zero".to_string());
    }
    if limits.max_http_body_bytes == 0 {
        errors.push("limits.max_http_body_bytes must be non-zero".to_string());
    }
    if limits.max_download_bytes == 0 {
        errors.push("limits.max_download_bytes must be non-zero".to_string());
    }
    if limits.max_upstream_response_bytes == 0 {
        errors.push("limits.max_upstream_response_bytes must be non-zero".to_string());
    }
    if limits.request_body_timeout_ms == 0 {
        errors.push("limits.request_body_timeout_ms must be non-zero".to_string());
    }
    if limits.request_timeout_ms == 0 {
        errors.push("limits.request_timeout_ms must be non-zero".to_string());
    }
    if limits.streaming_idle_timeout_ms == 0 {
        errors.push("limits.streaming_idle_timeout_ms must be non-zero".to_string());
    }
    if limits.upload_spool_dir.trim().is_empty() {
        errors.push("limits.upload_spool_dir must be non-empty".to_string());
    }
    if limits.upload_spool_max_bytes == 0 {
        errors.push("limits.upload_spool_max_bytes must be non-zero".to_string());
    }
}

fn validate_audit(config: &BrokerConfig, errors: &mut Vec<String>) {
    let Some(audit) = &config.audit else {
        return;
    };
    if audit.path.trim().is_empty() {
        errors.push("audit.path must be non-empty".to_string());
    } else if Path::new(&audit.path).file_name().is_none() {
        errors.push("audit.path must name a file".to_string());
    } else if let Some(managed_store) = &config.managed_store
        && audit_file_identity_key(Path::new(&audit.path))
            == audit_file_identity_key(Path::new(&managed_store.path))
    {
        errors.push("audit.path must not be the managed_store.path database".to_string());
    }
    match (audit.kind, audit.rotate_bytes) {
        (AuditStoreType::Sqlite, Some(_)) => {
            errors.push("audit.rotate_bytes is valid only with audit.type = \"jsonl\"".to_string());
        }
        (AuditStoreType::Jsonl, Some(0)) => {
            errors.push("audit.rotate_bytes must be non-zero".to_string());
        }
        _ => {}
    }
    if audit.retention_days == 0 {
        errors.push("audit.retention_days must be non-zero".to_string());
    }
    if audit.queue_capacity == 0 {
        errors.push("audit.queue_capacity must be non-zero".to_string());
    }
    if audit.enqueue_timeout_ms == 0 {
        errors.push("audit.enqueue_timeout_ms must be non-zero".to_string());
    }
    if matches!(audit.terminal_queue_capacity, Some(0)) {
        errors.push("audit.terminal_queue_capacity must be non-zero when set".to_string());
    }
    if let Some(terminal_queue_capacity) = audit.terminal_queue_capacity
        && terminal_queue_capacity < config.limits.max_concurrent_requests
    {
        errors.push(format!(
            "audit.terminal_queue_capacity must be at least limits.max_concurrent_requests ({})",
            config.limits.max_concurrent_requests
        ));
    }
}

fn validate_header_name(label: &str, value: &str, errors: &mut Vec<String>) {
    if !header_re().is_match(value) {
        errors.push(format!("{label} must be a valid HTTP header name"));
    }
}

fn validate_subject(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        errors.push(format!("{label} must be a non-empty non-control string"));
        return;
    }
    if value == "user:anonymous" || value == "group:anonymous" {
        return;
    }
    if let Some(user) = value.strip_prefix("user:") {
        if !is_safe_principal(user) {
            errors.push(format!("{label} has an invalid user principal"));
        }
    } else if let Some(group) = value.strip_prefix("group:") {
        if !is_safe_identifier(group) {
            errors.push(format!("{label} has an invalid group"));
        }
    } else {
        errors.push(format!("{label} must start with user: or group:"));
    }
}

fn finish_validation(errors: Vec<String>) -> Result<(), ConfigError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Invalid { errors })
    }
}

/// Descriptors for every service the configuration enables, derived from
/// the typed configuration alone so offline validation needs no providers.
pub(crate) fn configured_service_descriptors(
    config: &BrokerConfig,
) -> BTreeMap<String, Arc<ServiceDescriptor>> {
    let mut services = configured_provider_descriptors(config)
        .into_iter()
        .map(|descriptor| (descriptor.service.clone(), Arc::new(descriptor)))
        .collect::<BTreeMap<_, _>>();
    // A gateway colliding with a provider service is a validation error; keep
    // the provider's descriptor so the error is the only effect.
    for (service, gateway) in &config.gateways {
        if !services.contains_key(service)
            && let Some(descriptor) = runtime::gateway_service_descriptor(service, gateway)
        {
            services.insert(service.clone(), Arc::new(descriptor));
        }
    }
    services
}

fn configured_provider_descriptors(config: &BrokerConfig) -> Vec<ServiceDescriptor> {
    config
        .providers
        .iter()
        .map(BackendConfig::descriptor)
        .collect()
}

/// Checks each `[providers.<kind>]` table: its backend is registered, its
/// development-only status fits the deployment, and the backend accepts it
/// beside `credentials`, the configured credentials with each connection's
/// implicit type resolved.
fn validate_backends(
    config: &BrokerConfig,
    credentials: &CredentialsConfig,
    errors: &mut Vec<String>,
) {
    let limits = ProviderLimits::from(&config.limits);
    for backend in config.providers.iter() {
        let kind = backend.kind();
        let Some(registration) = config.providers.registry().get(kind) else {
            errors.push(format!(
                "providers.{kind} is not a backend this broker supports"
            ));
            continue;
        };
        if registration.is_development_only() && !config.deployment.enable_fake_service {
            errors.push(format!(
                "providers.{kind} is a development backend and requires deployment.enable_fake_service"
            ));
        }
        let descriptor = backend.descriptor();
        let credentials = BackendCredentials::new(credentials, kind, &descriptor);
        let context = ValidationContext::new(
            &config.deployment.environment,
            &config.policy.authority,
            &limits,
            credentials.kinds(),
        );
        backend.validate(&context, errors);
    }
}

/// What backend validation sees of one service's configured credentials
/// ([`ServiceCredentialKinds`]): its shared execution and lookup
/// credentials, and the token profiles (with a connection's implicit type
/// resolved), delegated access or secret store of its per-user entry.
struct BackendCredentials<'a> {
    service: Option<CredentialSource<'a>>,
    per_user_profiles: Vec<agent_access_provider::CredentialProfile>,
    per_user_delegated: bool,
    per_user_secret_store: bool,
    lookup: Option<CredentialSource<'a>>,
}

impl<'a> BackendCredentials<'a> {
    /// The sources of `service`, whose descriptor is `descriptor`. A listed
    /// token profile the service does not declare is left out, and so is a
    /// shared entry of an unsupported type; credential validation reports
    /// both.
    fn new(
        credentials: &'a CredentialsConfig,
        service: &str,
        descriptor: &ServiceDescriptor,
    ) -> Self {
        let connection = credentials.personal_connection(service);
        Self {
            service: credentials
                .service
                .get(service)
                .and_then(shared_credential_source),
            per_user_profiles: connection
                .map(|connection| {
                    connection
                        .config
                        .accepted_token_profiles()
                        .into_iter()
                        .filter_map(|profile| descriptor.credential_profile(profile).cloned())
                        .collect()
                })
                .unwrap_or_default(),
            per_user_delegated: connection
                .is_some_and(|connection| connection.config.oauth.is_some()),
            per_user_secret_store: credentials
                .per_user
                .get(service)
                .is_some_and(|credential| credential.kind == "secret_store"),
            lookup: credentials
                .lookup
                .get(service)
                .and_then(shared_credential_source),
        }
    }

    fn kinds(&self) -> ServiceCredentialKinds<'_> {
        ServiceCredentialKinds::default()
            .with_service(self.service)
            .with_per_user_profiles(&self.per_user_profiles)
            .with_per_user_delegated(self.per_user_delegated)
            .with_per_user_secret_store(self.per_user_secret_store)
            .with_lookup(self.lookup)
    }
}

/// A `credentials.service` or `credentials.lookup` entry as backend
/// validation sees it: a static kind, or a secret store. Other types are
/// rejected by credential validation and report nothing.
fn shared_credential_source(credential: &CredentialConfig) -> Option<CredentialSource<'_>> {
    match credential.kind.as_str() {
        "basic_api_token" | "bearer_token" => Some(match credential.profile.as_deref() {
            Some(profile) => CredentialSource::static_profile(&credential.kind, profile),
            None => CredentialSource::static_kind(&credential.kind),
        }),
        "secret_store" => Some(CredentialSource::SecretStore),
        _ => None,
    }
}

fn validate_service_descriptors(
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    resource_types: &ResourceTypeRegistry,
    errors: &mut Vec<String>,
) {
    for descriptor in services.values() {
        if let Err(origin_errors) = descriptor.validate_builtin_mcp_names() {
            errors.extend(origin_errors);
        }
        if let Err(descriptor_errors) = descriptor.validate() {
            errors.extend(descriptor_errors);
        }
        errors.extend(descriptor.validate_resource_types(resource_types));
    }
}

fn validate_private_resource_consumers(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    resource_types: &runtime::EffectiveResourceTypes,
    errors: &mut Vec<String>,
) {
    for service in services.values() {
        for action in service
            .actions
            .iter()
            .filter(|action| action.requires_resource_attributes)
        {
            let resource_type = action
                .resource_scope
                .as_ref()
                .and_then(|scope| service.resource_scopes.get(scope))
                .map(|scope| &scope.resource_type);
            if !resource_type.is_some_and(|resource_type| {
                resource_types.defining_service(resource_type) == Some(service.service.as_str())
                    && resource_types
                        .get(resource_type)
                        .is_some_and(|ty| !ty.attributes().is_empty())
            }) {
                errors.push(format!(
                    "{}.{} must consume private attributes of its defining backend's resource type",
                    service.service, action.action
                ));
            }
            if config.policy.authority != "managed" {
                errors.push(format!(
                    "{}.{} private resource attributes require managed policy",
                    service.service, action.action
                ));
            }
        }
    }
    if config.policy.authority == "toml"
        && config.policy.resources.iter().any(|resource| {
            resource_types
                .get(&resource.resource_type)
                .is_some_and(|ty| !ty.attributes().is_empty())
                && matches!(resource.selector, ResourceSelector::Exact { .. })
        })
    {
        errors.push("private resource attributes require the managed resource catalog".into());
    }
}

/// Whether a configured service can use an execution mode, including backends
/// whose authorized resources supply their own private execution material.
pub fn credential_mode_available(
    credentials: &CredentialsConfig,
    service: &str,
    mode: &str,
    descriptor: Option<&CredentialDescriptor>,
) -> bool {
    (mode == "service" && descriptor.is_some_and(|descriptor| !descriptor.execution_required))
        || credential_mode_configured(credentials, service, mode)
}

pub(crate) fn credential_mode_configured(
    credentials: &CredentialsConfig,
    service: &str,
    credential_mode: &str,
) -> bool {
    if let Some(modes) = credentials.imported_modes.get(service) {
        return modes.iter().any(|mode| mode == credential_mode);
    }
    match credential_mode {
        "service" => credentials.service.contains_key(service),
        "per_user" => credentials.per_user.contains_key(service),
        _ => false,
    }
}

/// The fields storing a credential connection's token takes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInputSchema {
    pub connection: String,
    pub profile: String,
    pub credential_kind: String,
    pub fields: Vec<CredentialInputField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInputField {
    pub name: String,
    pub required: bool,
    pub secret: bool,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_methods: Option<Vec<String>>,
}

/// Input fields for storing `connection`'s token of `credential_kind`,
/// prompted with the connection's display name.
pub fn credential_input_schema(
    connection: &str,
    display_name: &str,
    profile: &str,
    credential_kind: &str,
) -> Option<CredentialInputSchema> {
    let prompt_prefix = display_name;
    let fields = match credential_kind {
        "basic_api_token" => vec![
            CredentialInputField {
                name: "username".to_string(),
                required: true,
                secret: false,
                prompt: format!("{prompt_prefix} username"),
                description: None,
                input_methods: Some(vec![
                    "prompt".to_string(),
                    "literal".to_string(),
                    "env".to_string(),
                    "file".to_string(),
                ]),
            },
            CredentialInputField {
                name: "token".to_string(),
                required: true,
                secret: true,
                prompt: format!("{prompt_prefix} API token"),
                description: None,
                input_methods: Some(vec![
                    "prompt".to_string(),
                    "env".to_string(),
                    "file".to_string(),
                    "stdin".to_string(),
                ]),
            },
        ],
        "bearer_token" => vec![CredentialInputField {
            name: "token".to_string(),
            required: true,
            secret: true,
            prompt: format!("{prompt_prefix} bearer token"),
            description: None,
            input_methods: Some(vec![
                "prompt".to_string(),
                "env".to_string(),
                "file".to_string(),
                "stdin".to_string(),
            ]),
        }],
        _ => return None,
    };
    Some(CredentialInputSchema {
        connection: connection.to_string(),
        profile: profile.to_string(),
        credential_kind: credential_kind.to_string(),
        fields,
    })
}

pub fn parse_ttl_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (digits, unit) = trimmed.split_at(trimmed.find(|ch: char| !ch.is_ascii_digit())?);
    if digits.is_empty() {
        return None;
    }
    let amount = digits.parse::<u64>().ok()?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    amount
        .checked_mul(multiplier)
        .filter(|seconds| *seconds > 0)
}

pub fn broker_token_ttl_options_allow_ttl(options: &[BrokerTokenTtlOption], ttl: &str) -> bool {
    let Some(seconds) = parse_ttl_seconds(ttl) else {
        return false;
    };
    options
        .iter()
        .any(|option| option.ttl_seconds() == Some(seconds))
}

pub fn broker_token_ttl_options_allow_never(options: &[BrokerTokenTtlOption]) -> bool {
    options.iter().any(BrokerTokenTtlOption::is_never)
}

pub fn broker_token_ttl_option_for_ttl<'a>(
    options: &'a [BrokerTokenTtlOption],
    ttl: &str,
) -> Option<&'a str> {
    let seconds = parse_ttl_seconds(ttl)?;
    options
        .iter()
        .find(|option| option.ttl_seconds() == Some(seconds))
        .map(BrokerTokenTtlOption::as_str)
}

pub(crate) fn is_safe_principal(value: &str) -> bool {
    principal_re().is_match(value)
}

pub(crate) fn is_safe_identifier(value: &str) -> bool {
    identifier_re().is_match(value)
}

/// Exact, case-sensitive username carried by trusted identity assertions.
pub fn is_valid_identity_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-')
        })
}

fn header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$").expect("header regex"))
}

fn principal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9._@+\-]{1,256}$").expect("principal regex"))
}

fn identifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9._\-]{1,128}$").expect("identifier regex"))
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
