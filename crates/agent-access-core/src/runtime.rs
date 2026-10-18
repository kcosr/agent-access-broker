mod trusted_callers;
pub use trusted_callers::{
    AdmittedIdentity, CALLER_AUTHORIZATION_HEADER, CallerSecurityBinding, IngressAdmission,
    USER_HEADER, parse_assertion_bearer,
};
use trusted_callers::{ResolvedTrustedCaller, load_trusted_callers};
mod action_eligibility;
mod audit_jsonl;
mod audit_sqlite;
mod availability;
#[cfg(test)]
mod client_category_tests;
mod command_authority;
pub(crate) use command_authority::command_enforced_action;
pub use command_authority::{
    CommandAuthorization, CommandGrantAuthority, CommandResourceType, CommandSearchScope,
    ResourcesCheckedBy,
};
mod command_dispatch;
mod discovery;
mod gateway_access;
mod import_control;
#[cfg(test)]
mod inherited_network_tests;
pub use import_control::{ImportDiscoveryError, ImportPreparationError};
mod imports;
mod lookup_access;
mod mcp_views;
mod owned;
mod personal_credentials;
#[cfg(test)]
mod provider_contract_tests;
#[cfg(test)]
mod provider_fixture_tests;
#[cfg(test)]
mod provider_state_tests;
#[cfg(test)]
mod resource_attribute_tests;
#[cfg(test)]
mod resource_coverage_tests;
#[cfg(test)]
mod search_authority_tests;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use audit_sqlite::override_query_limits as override_audit_query_limits;
pub use audit_sqlite::{AuditVerifyCheck, AuditVerifyReport, verify_sqlite_audit_database};
pub use availability::{
    AvailabilityState, CredentialRequirement, DiscoveredService, ServiceAvailability,
};
pub use owned::InvocationControl;
mod resource_access;
mod resource_management;
mod resource_types;
use crate::fs_permissions;
use crate::imports::*;
use crate::microsoft_oidc::{MicrosoftOidcRuntimeConfig, MicrosoftOidcRuntimeConfigError};
use crate::network::{
    ClientCaller, EgressProxyEnvironment, HostNetwork, InheritedNetwork, PreparedOutboundTls,
    preflight_egress_proxy,
};
use crate::{
    AgentInvokeTokenCaveats, ApiServiceSpec, AuditDurability, BrokerConfig, BrokerTokenClass,
    BrokerTokenHasher, BrowserCsrfKey, CredentialConfig, CredentialKeyRing,
    DEFAULT_EXECUTION_CONTEXT, ExecutionContext, GatewayConfig, InitialAdminBootstrapRequest,
    LocalPasswordHasher, ManagedPolicyGrantCreateRequest, ManagedPolicyGrantPatchRequest,
    ManagedPolicyGrantRecord, ManagedPolicyGrantStatusRequest, ManagedPolicyGrantSubjectAddRequest,
    ManagedPolicyGrantSubjectRemoveRequest, ManagedPolicyMutationResult,
    ManagedPolicySubjectCatalog, ManagedResourceCatalog, ManagedStore, ManagedStoreError,
    ManagedStoreOpenMode, NormalizedPolicyGrant, NormalizedPolicyGrantIssueField,
    NormalizedPolicyGrantValidationIssue, PolicyGrantConfig, PolicyReadScope,
    PolicyValidationIssue, PolicyWriteScope, ResourceBoundary, ResourceCatalog, ResourceDefinition,
    ResourceGroupDefinition, ResourceSelection, ResponseEnvelope, api_service_spec,
    credential_mode_available, gateway_upstream_authorization, is_safe_identifier,
    is_safe_principal, normalized_policy_grant_validation_issues, validate_broker_config,
};
use crate::{ConfigError, HostConfigError, load_secret_ref_value};
use agent_access_provider::host::{ContractViolation, HookContext, with_provider_context};
use agent_access_provider::presentation::ActionPresentation;
use agent_access_provider::*;
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, Decision, LookupRequirement, ReasonCode,
    ResourceScopes, ResourceSelector, ResourceType, ResourceTypeDescriptor, ResourceTypeRegistry,
    ServiceDescriptor, ServiceSurface,
};
use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
pub use discovery::{
    ActionList, DiscoveredResource, ResourceCoverage, ResourceList, ResourceListQuery,
    ServiceDiscovery,
};
use futures_util::Stream;
pub use gateway_access::{GatewayUpstreamPresentation, GatewayUpstreamRejection};
use http::HeaderMap;
use lookup_access::{PreScopeLookup, PreScopeLookupPlan};
pub use resource_access::{
    EffectiveAccessClause, EffectiveAccessEntry, EffectiveAccessPreview, ResourceGroupOption,
};
pub(crate) use resource_types::EffectiveResourceTypes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

pub const REASON_CODE_HEADER: &str = "X-Agent-Access-Reason-Code";
pub const UPLOAD_SPOOL_FILE_PREFIX: &str = "agent-access-upload-";

pub fn upload_spool_file_prefix() -> String {
    format!("{}{}-", UPLOAD_SPOOL_FILE_PREFIX, std::process::id())
}
const AUDIT_RETENTION_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{label} references missing environment variable {name}")]
    MissingEnv { label: String, name: String },
    #[error("failed to read secret reference for {label}: {source}")]
    SecretFile {
        label: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to append audit record to {path}: {source}")]
    Audit {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("audit store {path} is unavailable: {message}")]
    AuditStore { path: String, message: String },
    #[error("broker node ID is unavailable: {message}")]
    NodeId { message: String },
    #[error("upload spool {path} is unavailable: {source}")]
    UploadSpool {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("credential store {label} is unavailable: {message}")]
    Credential { label: String, message: String },
    #[error("managed store is unavailable: {message}")]
    ManagedStore { message: String },
    #[error(transparent)]
    MicrosoftOidc(#[from] MicrosoftOidcRuntimeConfigError),
}

impl From<HostConfigError> for RuntimeError {
    fn from(error: HostConfigError) -> Self {
        match error {
            HostConfigError::Config(error) => Self::Config(error),
            HostConfigError::MissingEnv { label, name } => Self::MissingEnv { label, name },
            HostConfigError::SecretFile { label, source } => Self::SecretFile { label, source },
        }
    }
}

/// A provider build failure keeps the host's own cause when the host's
/// network construction failed, and otherwise reports the provider's safe
/// configuration diagnostics.
impl From<ProviderBuildError> for RuntimeError {
    fn from(error: ProviderBuildError) -> Self {
        let (mut errors, cause) = error.into_parts();
        match cause.map(|cause| cause.downcast::<HostConfigError>()) {
            Some(Ok(cause)) => (*cause).into(),
            Some(Err(cause)) => {
                errors.push(cause.to_string());
                Self::Config(ConfigError::Invalid { errors })
            }
            None => Self::Config(ConfigError::Invalid { errors }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySummary {
    pub principal: String,
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_groups: Vec<String>,
    pub authenticated: bool,
    /// Whether the admitted trusted-identity path is read-only; present only
    /// for an attested identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_access: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityContext {
    pub principal: String,
    /// The managed principal's kind, which selects its credential
    /// connections' methods: set wherever a managed principal is resolved,
    /// including a configured static principal whose ID names an active
    /// managed principal; `None` for other static principals and anonymous
    /// callers. Never defaulted; an unknown kind fails deserialization.
    pub principal_kind: Option<crate::PrincipalKind>,
    pub principal_subject: Option<String>,
    pub groups: Vec<String>,
    pub policy_groups: Vec<String>,
    pub authenticated: bool,
    pub source: Option<IdentitySourceAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_id: Option<String>,
}

impl IdentityContext {
    pub fn anonymous() -> Self {
        Self {
            principal: "anonymous".to_string(),
            principal_kind: None,
            principal_subject: None,
            groups: vec!["anonymous".to_string()],
            policy_groups: vec!["anonymous".to_string()],
            authenticated: false,
            source: None,
            caller_id: None,
        }
    }

    pub fn summary(&self) -> IdentitySummary {
        IdentitySummary {
            principal: self.principal.clone(),
            groups: self.groups.clone(),
            policy_groups: self.policy_groups.clone(),
            authenticated: self.authenticated,
            read_only_access: self.read_only_access(),
        }
    }

    /// The admitted trusted-identity path's read-only setting; `None` for
    /// every other identity source.
    pub fn read_only_access(&self) -> Option<bool> {
        self.source.as_ref()?.read_only_access
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceContext {
    pub listener: String,
    pub remote: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_request_id_generated: Option<bool>,
}

impl SourceContext {
    pub fn unknown() -> Self {
        Self {
            listener: "unknown".to_string(),
            remote: "unknown".to_string(),
            proxy_chain: Vec::new(),
            agent_request_id_generated: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OperationContext {
    pub agent_request_id: String,
    pub broker_request_id: String,
    pub identity: IdentityContext,
    pub service: String,
    pub action: String,
    pub source: SourceContext,
}

#[derive(Debug, Clone)]
pub struct GovernedOperationContext {
    pub operation: OperationContext,
    pub execution_context: ExecutionContext,
}

#[derive(Debug, Clone)]
pub struct GovernedIdentityFailureContext {
    pub agent_request_id: String,
    pub broker_request_id: String,
    pub service: String,
    pub action: String,
    pub source: SourceContext,
    pub execution_context: ExecutionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenOptions {
    pub policy_generation: u64,
    pub resources: Vec<ResourceDefinition>,
    pub resource_groups: Vec<ResourceGroupOption>,
    pub execution_contexts: Vec<ExecutionContext>,
    pub services: Vec<AgentTokenServiceOption>,
    /// Where an issued token connects MCP clients; see
    /// [`crate::agent_token_mcp_url`]. Not policy-derived.
    pub mcp: Option<AgentTokenMcpEndpoint>,
}

/// The HTTP MCP endpoint that accepts an issued token as `Authorization: Bearer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenMcpEndpoint {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenServiceOption {
    pub service: String,
    /// The configured service's display name, independent of caller grants.
    pub display_name: String,
    /// Hosts agents use to reach a gateway service; empty for invoke services.
    pub broker_hosts: Vec<String>,
    pub execution_contexts: Vec<ExecutionContext>,
    pub actions: Vec<AgentTokenActionOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenActionOption {
    pub action: String,
    pub description: String,
    /// Explicitly reviewed read operation (`ActionCapabilities::read_only`);
    /// false for actions the backend or import review has not classified.
    pub read_only: bool,
    pub required_scope_types: Vec<String>,
    /// None for an explicit action grant with no resource selector.
    pub resource_type: Option<ResourceType>,
    pub execution_contexts: Vec<ExecutionContext>,
    pub effective_access_by_execution_context:
        BTreeMap<ExecutionContext, Vec<EffectiveAccessClause>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatchedGrantAudit {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<u64>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    pub resources: ResourceSelection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_contexts: Vec<ExecutionContext>,
}

/// Broker-owned search plan: the admitted boundary plus the grants that
/// produced it. Audit records carry the whole plan; providers receive only the
/// [`SearchAuthorization`] view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SearchAuthorizationPlan {
    pub scope_type: String,
    pub scope: SearchAuthorizationScope,
    pub credential_mode: String,
    pub matched_grants: Vec<MatchedGrantAudit>,
}

fn search_scope_from_boundary(boundary: &ResourceBoundary) -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_selectors(boundary.included.clone(), boundary.excluded.clone())
}

fn search_clause_boundary(clause: &SearchAuthorizationClause) -> ResourceBoundary {
    ResourceBoundary {
        included: clause.included().to_vec(),
        excluded: clause.excluded().to_vec(),
    }
}

impl SearchAuthorizationPlan {
    /// The provider's view: the scope type and the complete normalized
    /// clause boundary. The credential mode travels in the admitted
    /// context, not here.
    pub fn authorization(&self) -> SearchAuthorization {
        SearchAuthorization::new(self.scope_type.clone(), self.scope.clone())
    }

    /// The envelope and audit `resourceScopes` summary of the boundary:
    /// sorted exact values, or `["*"]` when any surviving positive selector
    /// is all or a namespace. It is lossy and may hide exclusions; authorization
    /// always uses the complete clauses.
    pub fn resource_scope_summary(&self) -> ResourceScopes {
        let values = self.scope.resource_scope_summary();
        BTreeMap::from([(self.scope_type.clone(), values)])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySourceAudit {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub token_header: String,
    pub token_scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_class: Option<BrokerTokenClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    /// The read-only setting of an attested identity's admitted path, which
    /// limits it to actions the runtime catalog classifies as reads. `None`
    /// for every other source. Unlike `token_scopes` it is serialized, so it
    /// appears in audit and binds discovery cursors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_access: Option<bool>,
    #[serde(skip)]
    pub token_scopes: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityFailure {
    CallerAuthenticationRequired,
    CallerAuthenticationInvalid,
    CallerIdentityForwardingDenied,
    CallerUserAssertionDenied,
    AssertionInvalid,
    AssertionUnsupported,
    AssertionDenied,
    Unavailable,
    ExecutionContextRequired,
    ExecutionContextInvalid,
    ExecutionContextDenied,
    Required,
    Invalid,
    BrokerTokenNotFound,
    BrokerTokenExpired,
    BrokerTokenPaused,
    BrokerTokenRevoked,
    PrincipalRequired,
    PrincipalDisabled,
}

impl IdentityFailure {
    fn provider_error(&self) -> ProviderError {
        if *self == Self::Unavailable {
            ProviderError::error(self.reason_code(), self.message())
        } else {
            ProviderError::deny(self.reason_code(), self.message())
        }
    }

    pub fn admission_action(&self) -> &'static str {
        match self {
            Self::CallerAuthenticationRequired
            | Self::CallerAuthenticationInvalid
            | Self::CallerIdentityForwardingDenied
            | Self::CallerUserAssertionDenied
            | Self::ExecutionContextRequired
            | Self::ExecutionContextInvalid
            | Self::ExecutionContextDenied => "caller.authenticate",
            Self::Unavailable => "request.admit",
            _ => "identity.authenticate",
        }
    }

    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::CallerAuthenticationRequired => ReasonCode::CallerAuthenticationRequired,
            Self::CallerAuthenticationInvalid => ReasonCode::CallerAuthenticationInvalid,
            Self::CallerIdentityForwardingDenied => ReasonCode::CallerIdentityForwardingDenied,
            Self::CallerUserAssertionDenied => ReasonCode::CallerUserAssertionDenied,
            Self::AssertionInvalid => ReasonCode::IdentityAssertionInvalid,
            Self::AssertionUnsupported => ReasonCode::IdentityAssertionUnsupported,
            Self::AssertionDenied => ReasonCode::IdentityAssertionDenied,
            Self::Unavailable => ReasonCode::IdentityUnavailable,
            Self::ExecutionContextRequired => ReasonCode::ExecutionContextRequired,
            Self::ExecutionContextInvalid => ReasonCode::ExecutionContextInvalid,
            Self::ExecutionContextDenied => ReasonCode::ExecutionContextDenied,
            Self::Required => ReasonCode::IdentityRequired,
            Self::Invalid => ReasonCode::IdentityInvalid,
            Self::BrokerTokenNotFound => ReasonCode::BrokerTokenNotFound,
            Self::BrokerTokenExpired => ReasonCode::BrokerTokenExpired,
            Self::BrokerTokenPaused => ReasonCode::BrokerTokenPaused,
            Self::BrokerTokenRevoked => ReasonCode::BrokerTokenRevoked,
            Self::PrincipalRequired => ReasonCode::PrincipalRequired,
            Self::PrincipalDisabled => ReasonCode::PrincipalDisabled,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::CallerAuthenticationRequired => "caller authentication is required",
            Self::CallerAuthenticationInvalid => "caller authentication is invalid",
            Self::CallerIdentityForwardingDenied => "caller may not forward identity",
            Self::CallerUserAssertionDenied => "caller may not assert a user identity",
            Self::AssertionInvalid => "identity assertion is invalid",
            Self::AssertionUnsupported => "identity assertion is unsupported on this route",
            Self::AssertionDenied => "identity assertion is denied",
            Self::Unavailable => "identity admission is unavailable",
            Self::ExecutionContextRequired => "execution context is required",
            Self::ExecutionContextInvalid => "execution context is invalid",
            Self::ExecutionContextDenied => "caller may not assert this execution context",
            Self::Required => "identity token is required",
            Self::Invalid => "identity token is invalid",
            Self::BrokerTokenNotFound => "broker token was not found",
            Self::BrokerTokenExpired => "broker token is expired",
            Self::BrokerTokenPaused => "broker token is paused",
            Self::BrokerTokenRevoked => "broker token is revoked",
            Self::PrincipalRequired => "managed principal is required",
            Self::PrincipalDisabled => "managed principal is disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContextFailure {
    Required,
    Invalid,
}

impl ExecutionContextFailure {
    pub fn reason_code(self) -> ReasonCode {
        match self {
            Self::Required => ReasonCode::ExecutionContextRequired,
            Self::Invalid => ReasonCode::ExecutionContextInvalid,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Required => "execution context is required",
            Self::Invalid => "execution context is invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityBundle {
    pub identity: IdentitySummary,
    pub services: Vec<DiscoveredService>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvokeRequest {
    #[serde(default = "empty_json_object")]
    pub inputs: Value,
    #[serde(default)]
    pub read_content_format: agent_access_provider::presentation::ReadContentFormat,
    #[serde(default)]
    pub response_format: agent_access_provider::presentation::ResponseFormat,
    #[serde(skip)]
    pub body_parts: Vec<BrokerBodyPart>,
}

impl InvokeRequest {
    pub fn new(inputs: Value) -> Self {
        Self {
            inputs,
            read_content_format: agent_access_provider::presentation::ReadContentFormat::Native,
            response_format: agent_access_provider::presentation::ResponseFormat::Json,
            body_parts: Vec::new(),
        }
    }

    fn response_options(&self) -> agent_access_provider::presentation::ResponseOptions {
        agent_access_provider::presentation::ResponseOptions::new(
            self.read_content_format,
            self.response_format,
        )
    }
}

fn empty_json_object() -> Value {
    json!({})
}

/// The message of the host's own download-limit failure, worded like the
/// SDK's bounded downloads.
const DOWNLOAD_LIMIT_MESSAGE: &str = "raw download exceeded the download limit";

/// Bounds a raw download by `limits.max_download_bytes`, whatever bound the
/// provider applied itself. The chunk that would pass the limit is withheld:
/// the stream fails there with `attachment_size_denied`, the reason the SDK's
/// bounded downloads report for this limit, and ends. An in-memory body over
/// the limit fails the same way before any byte.
fn limited_download(stream: ProviderResultStream, max_bytes: u64) -> ProviderResultStream {
    let memory_over_limit = matches!(
        &stream.source,
        ProviderResultStreamSource::Memory(bytes) if bytes.len() as u64 > max_bytes
    );
    if memory_over_limit {
        return ProviderResultStream::from_stream(
            stream.content_type,
            futures_util::stream::iter([Err(download_limit_failure())]),
        );
    }
    stream.map_byte_stream(|inner| {
        Box::pin(DownloadLimitStream {
            inner: Some(inner),
            remaining: max_bytes,
        })
    })
}

fn download_limit_failure() -> ProviderStreamError {
    ProviderStreamError::new(ReasonCode::AttachmentSizeDenied, DOWNLOAD_LIMIT_MESSAGE)
}

/// A provider's raw download stream, failing at the first chunk that would
/// take it past the bytes `remaining`.
struct DownloadLimitStream {
    /// The provider's stream, dropped once the limit fails the download.
    inner: Option<ProviderByteStream>,
    remaining: u64,
}

impl Stream for DownloadLimitStream {
    type Item = Result<Bytes, ProviderStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let item = std::task::ready!(inner.as_mut().poll_next(cx));
        if let Some(Ok(chunk)) = &item {
            match this.remaining.checked_sub(chunk.len() as u64) {
                Some(remaining) => this.remaining = remaining,
                None => {
                    // Read nothing more from the provider.
                    this.inner = None;
                    return Poll::Ready(Some(Err(download_limit_failure())));
                }
            }
        }
        Poll::Ready(item)
    }
}

struct TerminalAuditStream {
    inner: ProviderByteStream,
    state: Arc<TerminalAuditState>,
}

impl TerminalAuditStream {
    fn new(
        inner: ProviderByteStream,
        permit: TerminalAuditPermit,
        base_record: AuditRecord,
        registry: Arc<AuditRuntimeRegistry>,
    ) -> Self {
        let state = Arc::new(TerminalAuditState::new(base_record, permit));
        registry.register_terminal(&state);
        Self { inner, state }
    }

    fn finish(
        &self,
        phase: &str,
        decision: Decision,
        reason_code: Option<ReasonCodeId>,
        message: Option<String>,
    ) {
        self.state.finish(phase, decision, reason_code, message);
    }
}

impl Stream for TerminalAuditStream {
    type Item = Result<Bytes, ProviderStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.state.is_canceled() {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(bytes))) => {
                this.state.observe_bytes(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.finish(
                    "failed",
                    Decision::Error,
                    Some(error.reason_code.into()),
                    Some(error.message.clone()),
                );
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.finish("completed", Decision::Allow, None, None);
                Poll::Ready(None)
            }
        }
    }
}

impl Drop for TerminalAuditStream {
    fn drop(&mut self) {
        self.finish(
            "canceled",
            Decision::Error,
            None,
            Some("download stream was canceled before completion".to_string()),
        );
    }
}

struct GatewayTerminalAuditGuard {
    state: Arc<GatewayTerminalAuditState>,
}

impl GatewayTerminalAuditGuard {
    fn new(
        base_record: AuditRecord,
        permit: TerminalAuditPermit,
        registry: Arc<AuditRuntimeRegistry>,
    ) -> Self {
        let state = Arc::new(GatewayTerminalAuditState::new(base_record, permit));
        registry.register_gateway_terminal(&state);
        Self { state }
    }

    fn finish_record(&self, record: AuditRecord) -> bool {
        self.state.finish_record(record)
    }

    fn observe_progress(&self, upstream_status: u16, audit: Value) {
        self.state.observe_progress(upstream_status, audit);
    }
}

impl Drop for GatewayTerminalAuditGuard {
    fn drop(&mut self) {
        self.state.cancel(
            "canceled",
            "gateway forwarding was canceled before completion",
        );
    }
}

fn stream_audit_value(
    provider_audit: Option<Value>,
    phase: &str,
    bytes: u64,
    sha256: String,
    duration_ms: Option<u64>,
    message: Option<String>,
) -> Value {
    let mut value = provider_audit.unwrap_or_else(|| json!({}));
    let Some(object) = value.as_object_mut() else {
        return json!({
            "providerAudit": value,
            "streamPhase": phase,
            "streamBytes": bytes,
            "streamSha256": sha256,
            "streamDurationMs": duration_ms,
            "streamMessage": message,
        });
    };
    object.insert("streamPhase".to_string(), json!(phase));
    object.insert("streamBytes".to_string(), json!(bytes));
    object.insert("streamSha256".to_string(), json!(sha256));
    if let Some(duration_ms) = duration_ms {
        object.insert("streamDurationMs".to_string(), json!(duration_ms));
    }
    if let Some(message) = message {
        object.insert("streamMessage".to_string(), json!(message));
    }
    value
}

fn stream_started_audit_value(provider_audit: Option<Value>) -> Option<Value> {
    let mut value = provider_audit?;
    let Some(object) = value.as_object_mut() else {
        return Some(json!({
            "providerAudit": value,
            "streamPhase": "started",
        }));
    };
    object.insert("streamPhase".to_string(), json!("started"));
    Some(value)
}

fn gateway_started_audit_value(mut provider_audit: Value) -> Value {
    if let Some(gateway) = provider_audit
        .get_mut("gateway")
        .and_then(serde_json::Value::as_object_mut)
    {
        gateway.insert("phase".to_string(), json!("started"));
        provider_audit
    } else {
        json!({
            "providerAudit": provider_audit,
            "gatewayPhase": "started",
        })
    }
}

fn gateway_terminal_audit_value(
    provider_audit: Option<Value>,
    phase: &str,
    message: Option<String>,
) -> Option<Value> {
    let mut value = provider_audit.unwrap_or_else(|| json!({"gateway": {}}));
    if let Some(gateway) = value.get_mut("gateway").and_then(Value::as_object_mut) {
        gateway.insert("phase".to_string(), json!(phase));
        if let Some(message) = message {
            gateway.insert("message".to_string(), json!(message));
        }
        return Some(value);
    }

    let mut wrapped = json!({
        "providerAudit": value,
        "gatewayPhase": phase,
    });
    if let Some(message) = message
        && let Some(object) = wrapped.as_object_mut()
    {
        object.insert("gatewayMessage".to_string(), json!(message));
    }
    Some(wrapped)
}

fn finalize_stream_sha256(digest: &Sha256) -> String {
    digest
        .clone()
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn record_span_from_audit(record: &AuditRecord, status: u16) {
    let span = tracing::Span::current();
    span.record("agentRequestId", record.agent_request_id.as_str());
    span.record("brokerRequestId", record.broker_request_id.as_str());
    span.record("service", record.service.as_str());
    span.record("action", record.action.as_str());
    span.record("principal", record.principal.as_str());
    span.record("decision", record.decision.as_str());
    if let Some(reason_code) = &record.reason_code {
        span.record("reasonCode", reason_code.as_str());
    }
    if let Some(config_generation) = record.config_generation {
        span.record("configGeneration", config_generation);
    }
    span.record("http.statusCode", status);
}

fn resource_scope_keys(scopes: &ResourceScopes) -> Vec<&str> {
    scopes.keys().map(String::as_str).collect()
}

fn resource_scope_keys_field(scopes: &ResourceScopes) -> String {
    serde_json::to_string(&resource_scope_keys(scopes))
        .expect("resource scope keys serialize as JSON")
}

fn credential_mode_label(credential_mode: &Option<Option<String>>) -> Option<&str> {
    credential_mode.as_ref().and_then(|mode| mode.as_deref())
}

macro_rules! emit_invoke_completed_event {
    ($level:path, $record:expr, $status:expr, $duration_ms:expr, $resource_scope_keys:expr, $reason_code:expr, $credential_mode:expr, $diagnostic_code:expr) => {{
        if let Some(credential_mode) = $credential_mode {
            $level!(
                event = "invoke_completed",
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                reasonCode = $reason_code,
                "http.statusCode" = $status,
                durationMs = $duration_ms,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                credentialMode = credential_mode,
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                diagnosticCode = $diagnostic_code,
            );
        } else {
            $level!(
                event = "invoke_completed",
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                reasonCode = $reason_code,
                "http.statusCode" = $status,
                durationMs = $duration_ms,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                diagnosticCode = $diagnostic_code,
            );
        }
    }};
}

fn emit_invoke_completed(
    record: &AuditRecord,
    status: u16,
    duration_ms: u64,
    diagnostic_code: Option<&'static str>,
) {
    let resource_scope_keys = resource_scope_keys_field(&record.resource_scopes);
    let credential_mode = credential_mode_label(&record.credential_mode);
    let reason_code = record
        .reason_code
        .as_ref()
        .map(ReasonCodeId::as_str)
        .unwrap_or("");
    match record.decision {
        Decision::Allow | Decision::Deny => emit_invoke_completed_event!(
            tracing::info,
            record,
            status,
            duration_ms,
            resource_scope_keys,
            reason_code,
            credential_mode,
            diagnostic_code
        ),
        Decision::Error
            if matches!(
                record.reason_code.as_ref().and_then(ReasonCodeId::standard),
                Some(
                    ReasonCode::RateLimited
                        | ReasonCode::UpstreamRateLimited
                        | ReasonCode::ConcurrencyLimited
                )
            ) =>
        {
            emit_invoke_completed_event!(
                tracing::warn,
                record,
                status,
                duration_ms,
                resource_scope_keys,
                reason_code,
                credential_mode,
                diagnostic_code
            );
        }
        Decision::Error => emit_invoke_completed_event!(
            tracing::error,
            record,
            status,
            duration_ms,
            resource_scope_keys,
            reason_code,
            credential_mode,
            diagnostic_code
        ),
    }
}

macro_rules! emit_invoke_stream_started_event {
    ($record:expr, $status:expr, $duration_ms:expr, $resource_scope_keys:expr, $credential_mode:expr) => {{
        if let Some(credential_mode) = $credential_mode {
            tracing::info!(
                event = "invoke_stream_started",
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                "http.statusCode" = $status,
                durationMs = $duration_ms,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                credentialMode = credential_mode,
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                streamPhase = "started",
            );
        } else {
            tracing::info!(
                event = "invoke_stream_started",
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                "http.statusCode" = $status,
                durationMs = $duration_ms,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                streamPhase = "started",
            );
        }
    }};
}

fn emit_invoke_stream_started(record: &AuditRecord, status: u16, duration_ms: u64) {
    let resource_scope_keys = resource_scope_keys_field(&record.resource_scopes);
    emit_invoke_stream_started_event!(
        record,
        status,
        duration_ms,
        resource_scope_keys,
        credential_mode_label(&record.credential_mode)
    );
}

macro_rules! emit_invoke_stream_terminal_event {
    ($level:path, $event:expr, $record:expr, $phase:expr, $stream_bytes:expr, $stream_duration_ms:expr, $resource_scope_keys:expr, $reason_code:expr, $credential_mode:expr) => {{
        if let Some(credential_mode) = $credential_mode {
            $level!(
                event = $event,
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                reasonCode = $reason_code,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                credentialMode = credential_mode,
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                streamPhase = $phase,
                streamBytes = $stream_bytes,
                streamDurationMs = $stream_duration_ms,
            );
        } else {
            $level!(
                event = $event,
                agentRequestId = $record.agent_request_id.as_str(),
                brokerRequestId = $record.broker_request_id.as_str(),
                configGeneration = $record.config_generation,
                service = $record.service.as_str(),
                action = $record.action.as_str(),
                principal = $record.principal.as_str(),
                decision = $record.decision.as_str(),
                reasonCode = $reason_code,
                resourceScopeKeys = $resource_scope_keys.as_str(),
                upstreamStatus = $record.upstream_status,
                upstreamDurationMs = $record.upstream_duration_ms,
                streamPhase = $phase,
                streamBytes = $stream_bytes,
                streamDurationMs = $stream_duration_ms,
            );
        }
    }};
}

fn emit_invoke_stream_terminal(record: &AuditRecord, phase: &str, stream_duration_ms: u64) {
    let resource_scope_keys = resource_scope_keys_field(&record.resource_scopes);
    let event = if phase == "completed" {
        "invoke_stream_completed"
    } else {
        "invoke_stream_failed"
    };
    let reason_code = record
        .reason_code
        .as_ref()
        .map(ReasonCodeId::as_str)
        .unwrap_or("");
    let stream_bytes = record
        .provider_audit
        .as_ref()
        .and_then(|audit| audit.get("streamBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match phase {
        "completed" => emit_invoke_stream_terminal_event!(
            tracing::info,
            event,
            record,
            phase,
            stream_bytes,
            stream_duration_ms,
            resource_scope_keys,
            reason_code,
            credential_mode_label(&record.credential_mode)
        ),
        _ => emit_invoke_stream_terminal_event!(
            tracing::error,
            event,
            record,
            phase,
            stream_bytes,
            stream_duration_ms,
            resource_scope_keys,
            reason_code,
            credential_mode_label(&record.credential_mode)
        ),
    }
}

fn emit_gateway_terminal(record: &AuditRecord, phase: &str, duration_ms: u64) {
    let resource_scope_keys = resource_scope_keys_field(&record.resource_scopes);
    let reason_code = record
        .reason_code
        .as_ref()
        .map(ReasonCodeId::as_str)
        .unwrap_or("");
    let gateway_bytes = record
        .provider_audit
        .as_ref()
        .and_then(|audit| audit.get("gateway"))
        .and_then(|gateway| gateway.get("responseBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let credential_mode = credential_mode_label(&record.credential_mode);
    match phase {
        "completed" => tracing::info!(
            event = "gateway_forward_completed",
            agentRequestId = record.agent_request_id.as_str(),
            brokerRequestId = record.broker_request_id.as_str(),
            configGeneration = record.config_generation,
            service = record.service.as_str(),
            action = record.action.as_str(),
            principal = record.principal.as_str(),
            decision = record.decision.as_str(),
            reasonCode = reason_code,
            resourceScopeKeys = resource_scope_keys.as_str(),
            credentialMode = credential_mode,
            upstreamStatus = record.upstream_status,
            upstreamDurationMs = record.upstream_duration_ms,
            gatewayPhase = phase,
            gatewayResponseBytes = gateway_bytes,
            gatewayDurationMs = duration_ms,
        ),
        _ => tracing::error!(
            event = "gateway_forward_failed",
            agentRequestId = record.agent_request_id.as_str(),
            brokerRequestId = record.broker_request_id.as_str(),
            configGeneration = record.config_generation,
            service = record.service.as_str(),
            action = record.action.as_str(),
            principal = record.principal.as_str(),
            decision = record.decision.as_str(),
            reasonCode = reason_code,
            resourceScopeKeys = resource_scope_keys.as_str(),
            credentialMode = credential_mode,
            upstreamStatus = record.upstream_status,
            upstreamDurationMs = record.upstream_duration_ms,
            gatewayPhase = phase,
            gatewayResponseBytes = gateway_bytes,
            gatewayDurationMs = duration_ms,
        ),
    }
}

fn emit_audit_append_failed(
    record: &AuditRecord,
    node_id: &str,
    status: u16,
    error: &RuntimeError,
    diagnostic_code: Option<&'static str>,
) {
    let audit_path = match error {
        RuntimeError::Audit { path, .. } => path.as_str(),
        _ => "",
    };
    tracing::error!(
        event = "audit_append_failed",
        nodeId = node_id,
        agentRequestId = record.agent_request_id.as_str(),
        brokerRequestId = record.broker_request_id.as_str(),
        configGeneration = record.config_generation,
        service = record.service.as_str(),
        action = record.action.as_str(),
        principal = record.principal.as_str(),
        decision = Decision::Error.as_str(),
        reasonCode = ReasonCode::AuditUnavailable.as_str(),
        "http.statusCode" = status,
        auditPath = audit_path,
        diagnosticCode = diagnostic_code,
        error = %error,
    );
}

fn emit_audit_terminal_append_failed(
    path: &str,
    node_id: &str,
    operation: &str,
    record: &AuditRecord,
    error: &std::io::Error,
) {
    tracing::error!(
        event = "audit_terminal_append_failed",
        auditPath = path,
        nodeId = node_id,
        operation = operation,
        agentRequestId = record.agent_request_id.as_str(),
        brokerRequestId = record.broker_request_id.as_str(),
        configGeneration = record.config_generation,
        service = record.service.as_str(),
        action = record.action.as_str(),
        principal = record.principal.as_str(),
        decision = record.decision.as_str(),
        reasonCode = record.reason_code.as_ref().map(ReasonCodeId::as_str).unwrap_or(""),
        error = %error,
    );
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialVerificationInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

impl CredentialVerificationInput {
    fn is_empty(&self) -> bool {
        self.repository.is_none()
    }
}

fn lookup_scope_denial() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "resource scope is not authorized or unavailable",
    )
}

fn add_upstream_resource_ownership_hint(
    error: &mut ProviderError,
    ownership: UpstreamResourceOwnership,
) {
    if error.reason_code() != ReasonCode::ScopeUnresolved {
        return;
    }
    let result = error
        .result
        .get_or_insert_with(|| Box::new(Value::Object(serde_json::Map::new())));
    if !result.is_object() {
        **result = Value::Object(serde_json::Map::new());
    }
    let result = result
        .as_object_mut()
        .expect("scope unresolved result was normalized to an object");
    let hints = result
        .entry("hints")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !hints.is_object() {
        *hints = Value::Object(serde_json::Map::new());
    }
    hints
        .as_object_mut()
        .expect("scope unresolved hints were normalized to an object")
        .insert(
            "upstreamResourceOwnership".to_string(),
            serde_json::to_value(ownership).expect("ownership enum is serializable"),
        );
}

/// The caller-facing form of a pre-authorization lookup failure: lookup
/// concealment keeps only failures that reveal nothing about the resource,
/// including the delegated lease failures that describe the caller's OAuth
/// connection.
/// A concealed failure keeps its internal diagnostic code, such as a
/// provider contract failure's, for the Broker's own records.
fn public_lookup_scope_error(error: ProviderError) -> ProviderError {
    if lookup_access::is_public_lease_failure(&error) {
        return error;
    }
    match error.reason_code().standard() {
        Some(
            ReasonCode::InputInvalid
            | ReasonCode::BodyMalformed
            | ReasonCode::BodyFormatUnsupported
            | ReasonCode::LocatorInvalid
            | ReasonCode::CredentialNotProvisioned
            | ReasonCode::CredentialInvalid
            | ReasonCode::CredentialExpired,
        ) => error,
        _ => {
            let mut denial = lookup_scope_denial();
            denial.internal_diagnostic_code = error.internal_diagnostic_code;
            denial
        }
    }
}

/// The caller-facing message of a provider contract failure; the provider's
/// own message, result and reason are never forwarded.
const PROVIDER_CONTRACT_FAILED_MESSAGE: &str =
    "the provider reported an outcome its contract does not allow";

/// Runs one provider hook future under its hook context and checks the
/// failure it returns against that hook's contract. Host work around the
/// hook, such as lease revalidation or attribute decryption, stays outside.
async fn run_provider_hook<T>(
    hook: HookContext,
    future: impl std::future::Future<Output = Result<T, ProviderError>>,
) -> Result<T, ProviderError> {
    let checked = hook.clone();
    agent_access_provider::host::with_hook_context(hook, future)
        .await
        .map_err(|error| checked_hook_failure(&checked, error))
}

/// A hook's failure if its contract allows it, or the host's contract
/// failure in its place.
fn checked_hook_failure(hook: &HookContext, error: ProviderError) -> ProviderError {
    match hook.check_failure(&error) {
        Ok(()) => error,
        Err(violation) => provider_contract_failure(hook, violation, error),
    }
}

/// The host's `broker_provider_contract_failed` (error/500) replacing a hook
/// failure its contract does not allow. It keeps the upstream status,
/// duration, audit and object IDs the provider reported, but never its
/// message, result or reason; the diagnostic code is internal. After
/// dispatch the provider may already have acted upstream, so an invocation's
/// contract failure reports an unknown, not retry-safe execution state.
fn provider_contract_failure(
    hook: &HookContext,
    violation: ContractViolation,
    error: ProviderError,
) -> ProviderError {
    record_provider_contract_failure(hook, "hook_failure", violation);
    let mut failure = ProviderError::error(
        ReasonCode::BrokerProviderContractFailed,
        PROVIDER_CONTRACT_FAILED_MESSAGE,
    )
    .with_internal_diagnostic_code(violation.diagnostic_code());
    if hook.phase() == HookPhase::Invocation {
        failure = failure.with_result(json!({"executionState": "unknown", "retrySafe": false}));
    }
    failure.audit = error.audit;
    failure.upstream_status = error.upstream_status;
    failure.upstream_duration_ms = error.upstream_duration_ms;
    failure.object_ids = error.object_ids;
    failure
}

fn record_provider_contract_failure(
    hook: &HookContext,
    emission: &'static str,
    violation: ContractViolation,
) {
    tracing::warn!(
        event = "provider_contract_failed",
        service = hook.service(),
        action = hook.action(),
        phase = hook.phase().as_str(),
        emission,
        diagnosticCode = violation.diagnostic_code(),
        "provider outcome rejected by its hook contract"
    );
}

/// Checks each late failure of the result's stream against the invocation's
/// contract. A rejected failure keeps the host's late-failure handling but
/// carries `broker_provider_contract_failed` and a fixed message.
fn checked_result_stream(mut result: ProviderResult, hook: HookContext) -> ProviderResult {
    use futures_util::StreamExt;
    result.stream = result.stream.map(|stream| {
        stream.map_byte_stream(move |inner| {
            Box::pin(inner.map(move |item| {
                item.map_err(|error| match hook.check_late_stream(error.reason_code) {
                    Ok(()) => error,
                    Err(violation) => {
                        record_provider_contract_failure(&hook, "late_stream", violation);
                        ProviderStreamError::new(
                            ReasonCode::BrokerProviderContractFailed,
                            "the provider stream failed outside its contract",
                        )
                    }
                })
            }))
        })
    });
    result
}

fn preserve_result_metadata_on_error(
    mut error: ProviderError,
    audit: Option<Value>,
    upstream_status: Option<u16>,
    upstream_duration_ms: Option<u64>,
    object_ids: Option<Value>,
) -> ProviderError {
    error.audit = audit.map(Box::new);
    error.upstream_status = upstream_status;
    error.upstream_duration_ms = upstream_duration_ms;
    error.object_ids = object_ids.map(Box::new);
    error
}

fn present_provider_outcome(
    presentation: Option<&ActionPresentation>,
    options: agent_access_provider::presentation::ResponseOptions,
    max_body_bytes: u64,
    max_result_bytes: u64,
    outcome: Result<ProviderResult, ProviderError>,
) -> Result<ProviderResult, ProviderError> {
    match outcome {
        Ok(mut provider_result) => {
            if let Err(error) = agent_access_provider::presentation::present_result(
                presentation,
                &mut provider_result.result,
                options,
                max_body_bytes,
                max_result_bytes,
            ) {
                return Err(preserve_result_metadata_on_error(
                    error,
                    provider_result.audit,
                    provider_result.upstream_status,
                    provider_result.upstream_duration_ms,
                    provider_result.object_ids,
                ));
            }
            Ok(provider_result)
        }
        Err(mut provider_error)
            if provider_error.decision() == Decision::Allow && provider_error.result.is_some() =>
        {
            let mut result = *provider_error
                .result
                .take()
                .expect("checked result presence");
            if let Err(error) = agent_access_provider::presentation::present_result(
                presentation,
                &mut result,
                options,
                max_body_bytes,
                max_result_bytes,
            ) {
                return Err(preserve_result_metadata_on_error(
                    error,
                    provider_error.audit.map(|value| *value),
                    provider_error.upstream_status,
                    provider_error.upstream_duration_ms,
                    provider_error.object_ids.map(|value| *value),
                ));
            }
            provider_error.result = Some(Box::new(result));
            Err(provider_error)
        }
        Err(provider_error) => Err(provider_error),
    }
}

/// Stand-in for a scope whose resource type is not registered: no resource
/// catalog entry uses its identifier and no target is canonical.
static UNRESOLVED_RESOURCE_TYPE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("unresolved_resource_type"),
    "Unresolved resource type",
    "Unresolved resource types",
    "",
    |_| false,
    &[],
);

#[derive(Debug, Clone)]
struct PolicySnapshot {
    authority: PolicyAuthority,
    generation: u64,
    grants: Vec<RuntimePolicyGrant>,
    resource_catalog: ManagedResourceCatalog,
    resources: ResourceCatalog,
}

impl PolicySnapshot {
    fn from_config(config: &BrokerConfig, generation: u64) -> Self {
        Self {
            authority: PolicyAuthority::Toml,
            generation,
            resource_catalog: ManagedResourceCatalog {
                attribute_bindings: Vec::new(),
                resource_fences: Default::default(),
                resources: config.policy.resources.clone(),
                resource_groups: config.policy.resource_groups.clone(),
            },
            resources: ResourceCatalog::new(
                &config.policy.resources,
                &config.policy.resource_groups,
            )
            .expect("validated resource catalog"),
            grants: config
                .policy
                .grants
                .iter()
                .enumerate()
                .flat_map(|(index, grant)| {
                    grant
                        .subjects
                        .iter()
                        .enumerate()
                        .map(move |(subject_order, subject)| {
                            RuntimePolicyGrant::from_toml(index, subject_order, subject, grant)
                        })
                })
                .collect(),
        }
    }

    fn from_managed(
        generation: u64,
        grants: Vec<ManagedPolicyGrantRecord>,
        catalog: ManagedResourceCatalog,
    ) -> Self {
        Self {
            authority: PolicyAuthority::Managed,
            generation,
            resources: ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
                .expect("validated managed resource catalog"),
            resource_catalog: catalog,
            grants: grants
                .into_iter()
                .flat_map(RuntimePolicyGrant::from_managed)
                .collect(),
        }
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn with_config_generation(&self, generation: u64) -> Self {
        Self {
            authority: self.authority,
            generation: match self.authority {
                PolicyAuthority::Toml => generation,
                PolicyAuthority::Managed => self.generation,
            },
            grants: self.grants.clone(),
            resource_catalog: self.resource_catalog.clone(),
            resources: self.resources.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAuthority {
    Toml,
    Managed,
}

#[derive(Debug, Clone)]
struct RuntimePolicyGrant {
    grant_ref: PolicyGrantRef,
    subject: String,
    service: String,
    actions: Vec<String>,
    resources: ResourceSelection,
    execution_contexts: Vec<ExecutionContext>,
    credential_mode: String,
    priority: Option<i32>,
    order: usize,
    subject_order: usize,
}

impl RuntimePolicyGrant {
    fn from_toml(
        index: usize,
        subject_order: usize,
        subject: &str,
        grant: &PolicyGrantConfig,
    ) -> Self {
        Self {
            grant_ref: PolicyGrantRef::Toml { index },
            subject: subject.to_string(),
            service: grant.service.clone(),
            actions: grant.actions.clone(),
            resources: grant.resources.clone(),
            execution_contexts: normalized_toml_execution_contexts(grant),
            credential_mode: grant.credential_mode.clone(),
            priority: grant.priority,
            order: index,
            subject_order,
        }
    }

    fn from_managed(grant: ManagedPolicyGrantRecord) -> Vec<Self> {
        let order = usize::try_from(grant.grant_order).unwrap_or(usize::MAX);
        let execution_contexts = grant
            .execution_contexts
            .iter()
            .map(|value| {
                ExecutionContext::new(value.clone()).expect("validated managed execution context")
            })
            .collect::<Vec<_>>();
        grant
            .subjects
            .into_iter()
            .enumerate()
            .map(|(subject_order, subject)| Self {
                grant_ref: PolicyGrantRef::Managed {
                    grant_id: grant.grant_id.clone(),
                    version: grant.version,
                },
                subject,
                service: grant.service.clone(),
                actions: grant.actions.clone(),
                resources: grant.resources.clone(),
                execution_contexts: execution_contexts.clone(),
                credential_mode: grant.credential_mode.clone(),
                priority: grant.priority,
                order,
                subject_order,
            })
            .collect()
    }

    fn toml_index(&self) -> Option<usize> {
        match &self.grant_ref {
            PolicyGrantRef::Toml { index } => Some(*index),
            PolicyGrantRef::Managed { .. } => None,
        }
    }

    fn managed_id(&self) -> Option<&str> {
        match &self.grant_ref {
            PolicyGrantRef::Managed { grant_id, .. } => Some(grant_id),
            PolicyGrantRef::Toml { .. } => None,
        }
    }

    fn managed_version(&self) -> Option<i64> {
        match &self.grant_ref {
            PolicyGrantRef::Managed { version, .. } => Some(*version),
            PolicyGrantRef::Toml { .. } => None,
        }
    }
}

fn normalized_toml_execution_contexts(grant: &PolicyGrantConfig) -> Vec<ExecutionContext> {
    match grant.execution_contexts.as_ref() {
        Some(values) => values
            .iter()
            .map(|value| {
                ExecutionContext::new(value.clone()).expect("validated TOML execution context")
            })
            .collect(),
        None => vec![
            ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT)
                .expect("built-in default execution context is valid"),
        ],
    }
}

#[derive(Debug, Clone)]
enum PolicyGrantRef {
    Toml { index: usize },
    Managed { grant_id: String, version: i64 },
}

#[derive(Clone)]
pub struct BrokerRuntime {
    config: Arc<BrokerConfig>,
    providers: Arc<BTreeMap<String, Arc<dyn Provider>>>,
    /// The command hooks of available command imports, keyed by service.
    /// Each is the same object as the service's entry in `providers`.
    command_providers: Arc<BTreeMap<String, Arc<dyn crate::imports::CommandProvider>>>,
    imported_catalog: Arc<crate::ImportedCatalog>,
    effective_credentials: Arc<crate::CredentialsConfig>,
    import_dispatch: Arc<BTreeMap<String, Arc<AtomicBool>>>,
    /// Command-import budgets and live process supervisors, carried from
    /// each generation to the next, as import dispatch fences are.
    command_registry: crate::imports::CommandRegistry,
    scoped_mcp: Arc<BTreeMap<String, crate::mcp::ScopedMcpReadiness>>,
    /// Validated descriptors for providers and gateways, fixed per generation.
    services: Arc<BTreeMap<String, Arc<ServiceDescriptor>>>,
    /// `[limits.invocations]` resolved for this generation.
    invocation_limits: Arc<crate::ConfiguredInvocationLimits>,
    /// This generation's resource types and their owners.
    resource_types: Arc<EffectiveResourceTypes>,
    policy_snapshot: Arc<ArcSwap<PolicySnapshot>>,
    policy_mutation_lock: Arc<Mutex<()>>,
    identity_sources: Arc<Vec<IdentitySourceResolver>>,
    managed_store: Option<ManagedStore>,
    credential_key_ring: Option<CredentialKeyRing>,
    oauth: Option<crate::OAuthManager>,
    trusted_callers: Arc<Vec<ResolvedTrustedCaller>>,
    broker_token_hasher: Option<BrokerTokenHasher>,
    local_password_hasher: Option<LocalPasswordHasher>,
    browser_csrf_key: Option<BrowserCsrfKey>,
    microsoft_oidc: Option<MicrosoftOidcRuntimeConfig>,
    /// This generation's outbound network: limits, TLS trust and egress
    /// proxy selection over the proxy environment captured at startup.
    network: HostNetwork,
    /// The network settings this generation's command imports inherit: its
    /// proxy route and its `[network.outbound_tls]` trust mode and path.
    inherited_network: Arc<InheritedNetwork>,
    audit: AuditSink,
    audit_registry: Arc<AuditRuntimeRegistry>,
    /// The effective node ID; see [`crate::resolve_node_id`].
    node_id: Arc<str>,
    config_generation: Option<u64>,
    /// Test-fixture provider instances, inherited by reload candidates.
    /// Empty, and zero-sized, outside test-support builds.
    provider_fixtures: ProviderFixtureSlot,
}

/// The provider fixtures a test-support runtime was constructed with. Each
/// generation built from it, including reload candidates, asks the same
/// fixtures again. Production builds have no fixture field at all.
#[derive(Clone, Default)]
struct ProviderFixtureSlot {
    #[cfg(any(test, feature = "test-support"))]
    fixtures: Option<crate::test_support::ProviderFixtures>,
}

#[cfg(any(test, feature = "test-support"))]
impl ProviderFixtureSlot {
    /// Rejects fixtures that name an unselected or unconfigured native kind
    /// in the startup configuration.
    fn check_startup(&self, config: &BrokerConfig) -> Result<(), RuntimeError> {
        let Some(fixtures) = &self.fixtures else {
            return Ok(());
        };
        let registry = config.providers.registry();
        let errors = fixtures
            .kinds()
            .filter_map(|kind| {
                if registry.get(kind).is_none() {
                    Some(format!(
                        "provider fixture {kind} names no selected native provider"
                    ))
                } else if config.providers.get_kind(kind).is_none() {
                    Some(format!(
                        "provider fixture {kind} has no [providers.{kind}] configuration"
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Config(ConfigError::Invalid { errors }))
        }
    }

    /// The fixture's provider for the configured registration `kind`, if
    /// the fixture supplies one. It must serve the service `kind`.
    fn build(
        &self,
        kind: &str,
        descriptor: &ServiceDescriptor,
        host: &BuildContext<'_>,
        backend: &dyn BackendConfig,
    ) -> Option<Result<ServiceProvider, RuntimeError>> {
        let provider = self.fixtures.as_ref()?.build(
            kind,
            &crate::test_support::ProviderFixtureContext::new(descriptor, host, backend),
        )?;
        Some(if provider.descriptor.service == kind {
            Ok(provider)
        } else {
            Err(RuntimeError::Config(ConfigError::Invalid {
                errors: vec![format!(
                    "provider fixture {kind} serves service {}",
                    provider.descriptor.service
                )],
            }))
        })
    }
}

/// One admitted operation awaiting dispatch. It pins the provider instance
/// that resolved and admitted it, so provider state never reaches another
/// generation's provider.
pub struct PreparedInvocation {
    resource_binding: Option<crate::ResourceAttributeBinding>,
    provider: Arc<dyn Provider>,
    /// The domain reasons the provider's backend registered, pinned with
    /// the provider for the operation's later hooks.
    domain_reasons: &'static [&'static ProviderReasonDefinition],
    request: AdmittedRequest,
    /// Body parts supplied with the invoke request itself; multipart bodies
    /// are consumed separately after admission.
    body_parts: Vec<BrokerBodyPart>,
    state: Option<ProviderState>,
    response_options: agent_access_provider::presentation::ResponseOptions,
    body_part_specs: Vec<BrokerBodyPartSpec>,
    finalize_context: FinalizeContext,
}

pub struct PreparedGatewayOperation {
    pub identity: IdentityContext,
    pub service: String,
    pub action: String,
    pub correlation: CorrelationContext,
    pub resource_scopes: ResourceScopes,
    pub credential_mode: String,
    /// What the request presents upstream, through
    /// [`Self::upstream_presentation`].
    access: gateway_access::GatewayAccess,
    pub matched_grant: MatchedGrantAudit,
    terminal_audit: Option<GatewayTerminalAuditGuard>,
    finalize_context: FinalizeContext,
}

struct PlannedGatewayOperation {
    identity: IdentityContext,
    service: String,
    action: String,
    correlation: CorrelationContext,
    resource_scopes: ResourceScopes,
    credential_mode: String,
    matched_grant: MatchedGrantAudit,
    finalize_context: FinalizeContext,
}

impl PreparedInvocation {
    pub fn body_part_specs(&self) -> &[BrokerBodyPartSpec] {
        &self.body_part_specs
    }

    /// The authority admitted for a command import's call.
    #[cfg(test)]
    fn command_authorization(&self) -> Option<&CommandAuthorization> {
        self.finalize_context
            .command
            .as_ref()
            .map(command_dispatch::AdmittedCommand::authorization)
    }
}

impl PreparedGatewayOperation {
    fn take_gateway_audit_append_mode(&mut self) -> AuditAppendMode {
        match self.terminal_audit.take() {
            Some(terminal) => AuditAppendMode::GatewayTerminal(terminal),
            None => AuditAppendMode::Normal,
        }
    }

    pub fn observe_gateway_response_progress(&self, upstream_status: u16, audit: Value) {
        if let Some(terminal) = &self.terminal_audit {
            terminal.observe_progress(upstream_status, self.with_credential_method(audit));
        }
    }
}

enum AuditAppendMode {
    Normal,
    OwnedTerminal(TerminalAuditPermit),
    GatewayTerminal(GatewayTerminalAuditGuard),
}

#[derive(Clone)]
struct FinalizeContext {
    search_authorization: Option<SearchAuthorizationPlan>,
    /// A command-import call from admission on: its authority, the resources
    /// its request names and its process facts, which finalization audits
    /// after any outcome, including a host interruption.
    command: Option<command_dispatch::AdmittedCommand>,
    agent_request_id: String,
    broker_request_id: String,
    policy_generation: u64,
    identity: IdentityContext,
    service: String,
    action: String,
    upstream_resource_ownership: Option<UpstreamResourceOwnership>,
    resource_scopes: ResourceScopes,
    credential_mode: Option<String>,
    matched_grant: Option<MatchedGrantAudit>,
    source: SourceContext,
    execution_context: Option<ExecutionContext>,
    redact_error_resource_scopes: bool,
    /// The credential connection whose material a personal lookup before
    /// policy used, which the audit names even when the call ends before a
    /// credential mode is selected.
    personal_lookup_connection: Option<String>,
    started: Instant,
}

impl BrokerRuntime {
    pub fn new(config: BrokerConfig) -> Result<Self, RuntimeError> {
        let environment = Arc::new(EgressProxyEnvironment::from_process_env()?);
        Self::new_with_identity_reuse(
            config,
            None,
            environment,
            Arc::new(AuditRuntimeRegistry::new()),
            ProviderFixtureSlot::default(),
        )
    }

    pub fn new_with_audit_registry(
        config: BrokerConfig,
        audit_registry: Arc<AuditRuntimeRegistry>,
    ) -> Result<Self, RuntimeError> {
        let environment = Arc::new(EgressProxyEnvironment::from_process_env()?);
        Self::new_with_identity_reuse(
            config,
            None,
            environment,
            audit_registry,
            ProviderFixtureSlot::default(),
        )
    }

    /// A startup runtime, as [`Self::new_with_audit_registry`] builds it,
    /// except that `fixtures` supply the providers of the configured native
    /// kinds they name, in this generation and every reload candidate built
    /// from it. Each named kind must be selected and configured here.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_provider_fixtures(
        config: BrokerConfig,
        audit_registry: Arc<AuditRuntimeRegistry>,
        fixtures: crate::test_support::ProviderFixtures,
    ) -> Result<Self, RuntimeError> {
        let environment = Arc::new(EgressProxyEnvironment::from_process_env()?);
        Self::new_with_identity_reuse(
            config,
            None,
            environment,
            audit_registry,
            ProviderFixtureSlot {
                fixtures: Some(fixtures),
            },
        )
    }

    pub fn new_for_reload(config: BrokerConfig, previous: &Self) -> Result<Self, RuntimeError> {
        Self::new_with_identity_reuse(
            config,
            Some(previous),
            Arc::clone(previous.network.environment()),
            Arc::clone(&previous.audit_registry),
            previous.provider_fixtures.clone(),
        )
    }

    #[cfg(test)]
    fn new_with_egress_environment(
        config: BrokerConfig,
        environment: EgressProxyEnvironment,
    ) -> Result<Self, RuntimeError> {
        Self::new_with_identity_reuse(
            config,
            None,
            Arc::new(environment),
            Arc::new(AuditRuntimeRegistry::new()),
            ProviderFixtureSlot::default(),
        )
    }

    fn new_with_identity_reuse(
        config: BrokerConfig,
        previous: Option<&Self>,
        egress_proxy_environment: Arc<EgressProxyEnvironment>,
        audit_registry: Arc<AuditRuntimeRegistry>,
        provider_fixtures: ProviderFixtureSlot,
    ) -> Result<Self, RuntimeError> {
        validate_broker_config(&config)?;
        #[cfg(any(test, feature = "test-support"))]
        if previous.is_none() {
            provider_fixtures.check_startup(&config)?;
        }
        preflight_configured_egress_proxies(&config)?;
        let network = HostNetwork::new(
            ProviderLimits::from(&config.limits),
            PreparedOutboundTls::load(&config.network.outbound_tls)?,
            egress_proxy_environment,
            config.network.egress_proxy.clone(),
        );
        let broker_token_hasher = config
            .broker_tokens
            .as_ref()
            .map(BrokerTokenHasher::load)
            .transpose()
            .map_err(runtime_managed_store_error)?;
        let stable_signing_key = broker_token_hasher
            .clone()
            .map(|hasher| Arc::new(hasher) as Arc<dyn StableSigningKey>);
        let mut providers = Vec::new();
        for (registration, backend) in config.providers.registered() {
            let descriptor = backend.descriptor();
            // The registration selected by the configuration's table name,
            // not anything the backend reports, decides its client category.
            let clients =
                network.client_factory(ClientCaller::native(registration, &config.deployment));
            let host = agent_access_provider::host::build_context(
                network.limits(),
                &clients,
                config.attribution.for_service(&descriptor),
                stable_signing_key.clone().map(|key| {
                    agent_access_provider::host::service_signing_key(key, &descriptor.service)
                }),
            );
            #[cfg(any(test, feature = "test-support"))]
            if let Some(provider) =
                provider_fixtures.build(registration.kind(), &descriptor, &host, backend)
            {
                providers.push(provider?);
                continue;
            }
            providers.push(ServiceProvider::new(descriptor, backend.build(&host)?));
        }
        Self::with_providers_and_identity_reuse(
            config,
            providers,
            previous,
            network,
            broker_token_hasher,
            audit_registry,
            provider_fixtures,
        )
    }

    /// A runtime serving `providers` in place of the configured backends'
    /// own, each with the descriptor it is paired with.
    pub fn with_providers<P: Into<ServiceProvider>>(
        config: BrokerConfig,
        providers: impl IntoIterator<Item = P>,
    ) -> Result<Self, RuntimeError> {
        let providers = providers.into_iter().map(Into::into).collect::<Vec<_>>();
        Self::reject_disabled_development_provider_injection(&config, &providers)?;
        let network = HostNetwork::new(
            ProviderLimits::from(&config.limits),
            PreparedOutboundTls::load(&config.network.outbound_tls)?,
            Arc::new(EgressProxyEnvironment::from_process_env()?),
            config.network.egress_proxy.clone(),
        );
        let broker_token_hasher = config
            .broker_tokens
            .as_ref()
            .map(BrokerTokenHasher::load)
            .transpose()
            .map_err(runtime_managed_store_error)?;
        Self::with_providers_and_identity_reuse(
            config,
            providers,
            None,
            network,
            broker_token_hasher,
            Arc::new(AuditRuntimeRegistry::new()),
            ProviderFixtureSlot::default(),
        )
    }

    fn with_providers_and_identity_reuse(
        mut config: BrokerConfig,
        providers: Vec<ServiceProvider>,
        previous: Option<&Self>,
        network: HostNetwork,
        broker_token_hasher: Option<BrokerTokenHasher>,
        audit_registry: Arc<AuditRuntimeRegistry>,
        provider_fixtures: ProviderFixtureSlot,
    ) -> Result<Self, RuntimeError> {
        Self::reject_disabled_development_provider_injection(&config, &providers)?;
        validate_broker_config(&config)?;
        let node_id: Arc<str> = crate::resolve_node_id(&config.deployment)
            .map_err(|error| RuntimeError::NodeId {
                message: error.to_string(),
            })?
            .into();
        preflight_configured_egress_proxies(&config)?;
        prepare_upload_spool(&config.limits)?;
        let inherited_network =
            Arc::new(network.export_inherited_network(&config.network.outbound_tls)?);
        let mut provider_map = BTreeMap::new();
        for provider in providers {
            register_service_provider(&mut provider_map, &config, provider)?;
        }
        let managed_store = load_managed_store(&config, previous.is_some())?;
        let credential_key_ring = config
            .credential_encryption
            .as_ref()
            .map(CredentialKeyRing::load)
            .transpose()
            .map_err(runtime_managed_store_error)?;
        if let Some(store) = &managed_store {
            store.configure_identity_token_encryption(credential_key_ring.clone());
        }
        let oauth = if config.oauth.registrations.is_empty() {
            None
        } else {
            let store = managed_store
                .clone()
                .ok_or_else(|| RuntimeError::ManagedStore {
                    message: "OAuth requires managed store".into(),
                })?;
            let ring = credential_key_ring
                .clone()
                .ok_or_else(|| RuntimeError::ManagedStore {
                    message: "OAuth requires credential encryption".into(),
                })?;
            Some(
                crate::OAuthManager::new_with_host(
                    store,
                    ring,
                    config.oauth.clone(),
                    config.providers.registry(),
                    &network,
                )
                .map_err(|error| RuntimeError::ManagedStore {
                    message: error.to_string(),
                })?,
            )
        };
        let trusted_callers = load_trusted_callers(&config)?;
        let local_password_hasher = config
            .browser_auth
            .local_password
            .pepper_ref
            .as_deref()
            .filter(|_| config.browser_auth.enabled && config.browser_auth.local_password.enabled)
            .map(|secret_ref| {
                LocalPasswordHasher::load("browser_auth.local_password.pepper_ref", secret_ref)
            })
            .transpose()
            .map_err(runtime_managed_store_error)?;
        let browser_csrf_key = config
            .browser_auth
            .csrf_key_ref
            .as_deref()
            .filter(|_| config.browser_auth.enabled)
            .map(|secret_ref| BrowserCsrfKey::load("browser_auth.csrf_key_ref", secret_ref))
            .transpose()
            .map_err(runtime_managed_store_error)?;
        let microsoft_oidc = MicrosoftOidcRuntimeConfig::from_config(
            &config.browser_auth.oidc.microsoft,
            config.browser_auth.public_origin.as_deref(),
        )?;
        prepare_managed_admin_roles(
            &config,
            managed_store.as_ref(),
            local_password_hasher.as_ref(),
            previous.is_none(),
        )?;
        validate_managed_policy_subjects(&config, managed_store.as_ref())?;
        let imported_catalog = managed_store
            .as_ref()
            .map(ManagedStore::imported_catalog)
            .transpose()
            .map_err(runtime_managed_store_error)?
            .unwrap_or_default();
        // Stored imported types join the registry before anything validates
        // the stored resources and descriptors that use them.
        let resource_types = EffectiveResourceTypes::composition(config.providers.registry())
            .with_imported(
                &imported_catalog,
                previous.map(|previous| &*previous.resource_types),
            )
            .map_err(|message| RuntimeError::ManagedStore { message })?;
        let mut services = build_service_descriptors(&config, &provider_map, &resource_types)?;
        for record in &imported_catalog.services {
            let name = &record.definition.service;
            if let Some(owner) = imported_service_collision(&config, &services, name) {
                return Err(RuntimeError::ManagedStore {
                    message: format!("retained imported service {name} collides with {owner}"),
                });
            }
            let descriptor = imports::descriptor(record, &config, resource_types.registry());
            // Retained metadata survives an adapter becoming unavailable. The
            // provider builder fails that service closed on semantic validation.
            services.insert(name.clone(), Arc::new(descriptor));
        }
        if config.imports.enabled
            && let (Some(store), Some(ring)) = (&managed_store, &credential_key_ring)
        {
            store
                .check_active_credential_keys(ring)
                .map_err(runtime_managed_store_error)?;
        }
        let imported_providers = imports::build_providers(
            &config,
            &imported_catalog,
            resource_types.registry(),
            managed_store.as_ref(),
            credential_key_ring.as_ref(),
            &network,
        )?;
        let mut command_providers = BTreeMap::new();
        for (service, provider) in imported_providers {
            if let Some(command) = provider.command() {
                command_providers.insert(service.clone(), command.clone());
            }
            provider_map.insert(
                service.clone(),
                ServiceProvider::new(
                    (**services.get(&service).expect("retained import descriptor")).clone(),
                    provider.provider(),
                ),
            );
        }
        let source_config = config.clone();
        imports::effective_credentials(&mut config, &imported_catalog);
        // Imports add connections offline validation cannot see.
        let connection_errors = crate::connections::effective_connection_errors(
            &config.credentials,
            &services,
            &config.oauth,
            config.providers.registry(),
        );
        if !connection_errors.is_empty() {
            return Err(RuntimeError::Config(ConfigError::Invalid {
                errors: connection_errors,
            }));
        }
        let policy_snapshot = Arc::new(ArcSwap::from_pointee(load_policy_snapshot(
            &imports::retention_config(&config, &imported_catalog),
            managed_store.as_ref(),
            &services,
            &imported_catalog,
            resource_types.registry(),
        )?));
        let audit = AuditSink::new(
            config.audit.as_ref(),
            &config.limits,
            Arc::clone(&audit_registry),
            &node_id,
            if previous.is_none() {
                AuditOpenMode::Startup
            } else {
                AuditOpenMode::Reload
            },
        )?;
        let invocation_limits = Arc::new(crate::ConfiguredInvocationLimits::from_config(&config));
        let identity_sources =
            load_identity_sources(&config, managed_store.clone(), broker_token_hasher.clone())?;
        trusted_callers::validate_caller_principal_credentials(
            &trusted_callers,
            &identity_sources,
        )?;
        let mut runtime = Self {
            identity_sources: Arc::new(identity_sources),
            audit,
            effective_credentials: Arc::new(config.credentials.clone()),
            config: Arc::new(source_config),
            providers: Arc::new(
                provider_map
                    .into_iter()
                    .map(|(service, provider)| (service, provider.provider))
                    .collect(),
            ),
            command_providers: Arc::new(command_providers),
            services: Arc::new(services),
            imported_catalog: Arc::new(imported_catalog),
            import_dispatch: Arc::new(BTreeMap::new()),
            command_registry: previous
                .map(|previous| previous.command_registry.clone())
                .unwrap_or_default(),
            scoped_mcp: Arc::new(BTreeMap::new()),
            invocation_limits,
            resource_types: Arc::new(resource_types),
            policy_snapshot,
            policy_mutation_lock: Arc::new(Mutex::new(())),
            managed_store,
            credential_key_ring,
            oauth,
            trusted_callers,
            broker_token_hasher,
            local_password_hasher,
            browser_csrf_key,
            microsoft_oidc,
            network,
            inherited_network,
            audit_registry,
            node_id,
            config_generation: None,
            provider_fixtures,
        };
        runtime.initialize_import_dispatch(previous);
        runtime.initialize_scoped_mcp_readiness(None);
        runtime
            .check_import_catalog_budgets()
            .map_err(runtime_managed_store_error)?;
        if previous.is_none() {
            runtime.activate_oauth()?;
            runtime.warn_aggregate_mcp_names();
        }
        Ok(runtime)
    }

    /// Injected providers must not bypass the deployment gate on
    /// development-only backends.
    fn reject_disabled_development_provider_injection(
        config: &BrokerConfig,
        providers: &[ServiceProvider],
    ) -> Result<(), RuntimeError> {
        if config.deployment.enable_fake_service {
            return Ok(());
        }
        let registry = config.providers.registry();
        let errors = providers
            .iter()
            .map(|provider| &provider.descriptor.service)
            .filter(|service| {
                registry
                    .get(service)
                    .is_some_and(|registration| registration.is_development_only())
            })
            .map(|service| {
                format!(
                    "deployment.enable_fake_service must be true before registering injected {service} provider"
                )
            })
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Config(ConfigError::Invalid { errors }))
        }
    }

    pub fn effective_credentials(&self) -> &crate::CredentialsConfig {
        &self.effective_credentials
    }

    pub fn config(&self) -> &BrokerConfig {
        &self.config
    }

    pub fn oauth_manager(&self) -> Option<&crate::OAuthManager> {
        self.oauth.as_ref()
    }

    /// Activate only after candidate validation succeeds. Staged reloads must
    /// not change persisted OAuth admission or invalidate a running snapshot.
    pub fn activate_oauth(&self) -> Result<(), RuntimeError> {
        let result = if let Some(manager) = &self.oauth {
            manager.activate()
        } else if let Some(store) = &self.managed_store {
            crate::OAuthManager::disable_all(store)
        } else {
            Ok(())
        };
        result.map_err(|error| RuntimeError::ManagedStore {
            message: error.to_string(),
        })
    }

    pub fn deactivate_oauth(&self) {
        if let Some(manager) = &self.oauth {
            manager.deactivate();
        }
    }

    pub fn config_generation(&self) -> Option<u64> {
        self.config_generation
    }

    /// The broker's effective node ID, stamped on every audit record.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn with_config_generation(mut self, generation: u64) -> Self {
        self.config_generation = Some(generation);
        let policy_snapshot = self.policy_snapshot();
        self.policy_snapshot
            .store(Arc::new(policy_snapshot.with_config_generation(generation)));
        self
    }

    pub fn policy_generation(&self) -> u64 {
        self.policy_snapshot.load().generation()
    }

    fn policy_snapshot(&self) -> Arc<PolicySnapshot> {
        self.policy_snapshot.load_full()
    }

    pub async fn append_audit_record(&self, record: &AuditRecord) -> Result<(), RuntimeError> {
        self.audit.append_required(record.clone()).await
    }

    /// This generation's audit store, or `None` when audit is disabled.
    pub fn audit_store(&self) -> Option<&AuditStoreInfo> {
        self.audit.store.as_ref()
    }

    pub fn audit_registry(&self) -> Arc<AuditRuntimeRegistry> {
        Arc::clone(&self.audit_registry)
    }

    /// The command-import budgets and live process supervisors this
    /// generation shares with every generation of the same Broker.
    pub fn command_registry(&self) -> &crate::imports::CommandRegistry {
        &self.command_registry
    }

    pub fn cancel_terminal_audits(&self) -> usize {
        self.audit_registry.cancel_terminal_audits()
    }

    pub async fn shutdown_audit(&self, timeout: Duration) -> Result<(), RuntimeError> {
        self.audit_registry.shutdown_and_drain(timeout).await
    }

    pub async fn shutdown_own_audit(&self, timeout: Duration) -> Result<(), RuntimeError> {
        self.audit.shutdown_and_drain(timeout).await
    }

    pub fn max_http_body_bytes(&self) -> usize {
        self.config
            .limits
            .max_http_body_bytes
            .try_into()
            .unwrap_or(usize::MAX)
    }

    pub fn limits(&self) -> &crate::LimitsConfig {
        &self.config.limits
    }

    /// `[limits.invocations]` resolved for this generation: service limits,
    /// configured default, and TOML principal overrides.
    pub fn configured_invocation_limits(&self) -> &crate::ConfiguredInvocationLimits {
        &self.invocation_limits
    }

    /// The invocation limit for one principal and configured service: the
    /// principal's override, else the service limit, else the configured
    /// default, else the built-in 100 per `1m`.
    ///
    /// Overrides come from `limits.invocations.principal_overrides` under TOML
    /// identity authority, or from the managed store (one primary-key read)
    /// under managed identity authority, so store changes apply to the next
    /// call. The caller must check that `service` is configured.
    pub async fn effective_invocation_limit(
        &self,
        principal: &str,
        service: &str,
    ) -> Result<crate::EffectiveInvocationLimit, ProviderError> {
        let principal_override = match self.managed_invocation_limit_store(principal) {
            Some(store) => {
                let principal = principal.to_string();
                let service_name = service.to_string();
                managed_store_blocking(move || {
                    store.principal_service_limit(&principal, &service_name)
                })
                .await
                .and_then(|record| record.map(|record| record.limit()).transpose())
                .map_err(provider_error_from_managed_store)?
            }
            None => self
                .invocation_limits
                .principal_override(principal, service),
        };
        Ok(self
            .invocation_limits
            .effective(service, principal_override))
    }

    /// Effective invocation limits for every configured service, ordered by
    /// service. Dormant managed overrides for unconfigured services are omitted.
    pub async fn effective_invocation_limits(
        &self,
        principal: &str,
    ) -> Result<Vec<crate::EffectiveInvocationLimit>, ProviderError> {
        let overrides = match self.managed_invocation_limit_store(principal) {
            Some(store) => {
                let principal = principal.to_string();
                managed_store_blocking(move || store.list_principal_service_limits(&principal))
                    .await
                    .and_then(|records| {
                        records
                            .into_iter()
                            .map(|record| Ok((record.service.clone(), record.limit()?)))
                            .collect::<Result<BTreeMap<_, _>, ManagedStoreError>>()
                    })
                    .map_err(provider_error_from_managed_store)?
            }
            None => self
                .services
                .keys()
                .filter_map(|service| {
                    self.invocation_limits
                        .principal_override(principal, service)
                        .map(|limit| (service.clone(), limit))
                })
                .collect(),
        };
        Ok(self
            .services
            .keys()
            .map(|service| {
                self.invocation_limits
                    .effective(service, overrides.get(service).copied())
            })
            .collect())
    }

    /// The store holding principal overrides, when identity authority is
    /// managed and the principal can own store rows.
    fn managed_invocation_limit_store(&self, principal: &str) -> Option<ManagedStore> {
        if self.config.identity.authority != "managed" || principal == "anonymous" {
            return None;
        }
        self.managed_store.clone()
    }

    pub fn streaming_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.config.limits.streaming_idle_timeout_ms)
    }

    pub fn upload_spool_dir(&self) -> &Path {
        Path::new(&self.config.limits.upload_spool_dir)
    }

    pub fn upload_spool_max_bytes(&self) -> u64 {
        self.config.limits.upload_spool_max_bytes
    }

    pub fn trusted_proxies(&self) -> &[String] {
        &self.config.network.trusted_proxies
    }

    pub fn managed_store(&self) -> Option<&ManagedStore> {
        self.managed_store.as_ref()
    }

    pub fn create_managed_policy_grant(
        &self,
        request: ManagedPolicyGrantCreateRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result =
            store.create_policy_grant(request, |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            })?;
        self.publish_managed_policy_result(result)
    }

    pub fn validate_managed_policy_grant_create(
        &self,
        request: ManagedPolicyGrantCreateRequest,
    ) -> Result<(), ManagedStoreError> {
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        store.validate_policy_grant_create(request, |grants, revision, subjects, catalog| {
            self.validate_managed_policy_candidate_for_store(
                grants, revision, subjects, catalog, &baseline,
            )
        })
    }

    pub fn patch_managed_policy_grant(
        &self,
        request: ManagedPolicyGrantPatchRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.patch_managed_policy_grant_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn patch_managed_policy_grant_authorized(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.patch_policy_grant_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    pub fn add_managed_policy_grant_subject(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.add_managed_policy_grant_subject_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn add_managed_policy_grant_subject_authorized(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.add_policy_grant_subject_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    pub fn remove_managed_policy_grant_subject(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.remove_managed_policy_grant_subject_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn remove_managed_policy_grant_subject_authorized(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.remove_policy_grant_subject_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    pub fn validate_managed_policy_grant_patch(
        &self,
        request: ManagedPolicyGrantPatchRequest,
    ) -> Result<(), ManagedStoreError> {
        self.validate_managed_policy_grant_patch_authorized(request, &PolicyReadScope::Global)
    }

    pub fn validate_managed_policy_grant_patch_authorized(
        &self,
        request: ManagedPolicyGrantPatchRequest,
        scope: &PolicyReadScope,
    ) -> Result<(), ManagedStoreError> {
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        store.validate_policy_grant_patch_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )
    }

    pub fn enable_managed_policy_grant(
        &self,
        request: ManagedPolicyGrantStatusRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.enable_managed_policy_grant_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn enable_managed_policy_grant_authorized(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.enable_policy_grant_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    pub fn disable_managed_policy_grant(
        &self,
        request: ManagedPolicyGrantStatusRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.disable_managed_policy_grant_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn disable_managed_policy_grant_authorized(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.disable_policy_grant_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    pub fn delete_managed_policy_grant(
        &self,
        request: ManagedPolicyGrantStatusRequest,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        self.delete_managed_policy_grant_authorized(request, &PolicyWriteScope::Global)
    }

    pub fn delete_managed_policy_grant_authorized(
        &self,
        request: ManagedPolicyGrantStatusRequest,
        scope: &PolicyWriteScope,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.delete_policy_grant_authorized(
            request,
            scope,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            },
        )?;
        self.publish_managed_policy_result(result)
    }

    fn managed_policy_mutation_guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ()>, ManagedStoreError> {
        self.policy_mutation_lock.lock().map_err(|_| {
            ManagedStoreError::Unavailable("managed policy mutation lock is poisoned".to_string())
        })
    }

    fn managed_policy_store(&self) -> Result<&ManagedStore, ManagedStoreError> {
        if self.config.policy.authority != "managed" {
            return Err(ManagedStoreError::PolicyAuthorityUnavailable(
                "managed policy mutations require policy.authority = managed".to_string(),
            ));
        }
        self.managed_store.as_ref().ok_or_else(|| {
            ManagedStoreError::PolicyAuthorityUnavailable(
                "managed policy mutations require managed_store".to_string(),
            )
        })
    }

    fn validate_managed_policy_candidate_for_store(
        &self,
        grants: &[ManagedPolicyGrantRecord],
        revision: &crate::ManagedPolicyRevision,
        subjects: &ManagedPolicySubjectCatalog,
        catalog: &ManagedResourceCatalog,
        baseline: &(crate::ManagedPolicyRevision, Vec<ManagedPolicyGrantRecord>),
    ) -> Result<(), ManagedStoreError> {
        if baseline.0.generation.checked_add(1) != Some(revision.generation) {
            return Err(ManagedStoreError::VersionConflict);
        }
        // Type-specific selector checks mirror the store's structural catalog
        // checks, so an invalid resource is an input error, not a policy issue.
        let resource_errors = crate::validate_resource_definition_types(
            self.resource_types.registry(),
            &catalog.resources,
        );
        if !resource_errors.is_empty() {
            return Err(ManagedStoreError::InputInvalid(resource_errors.join("; ")));
        }
        resource_management::validate_attribute_bindings(self.resource_types.registry(), catalog)?;
        self.validate_new_imported_grants(grants, &baseline.1)?;
        let issues = managed_policy_validation_issues(
            &imports::retention_config(&self.config, &self.imported_catalog),
            subjects,
            &self.services,
            &self.imported_catalog,
            self.resource_types.registry(),
            grants,
            catalog,
        );
        if !issues.is_empty() {
            return Err(ManagedStoreError::PolicyValidationIssues(issues));
        }
        Ok(())
    }

    fn publish_managed_policy_result(
        &self,
        result: ManagedPolicyMutationResult,
    ) -> Result<ManagedPolicyMutationResult, ManagedStoreError> {
        let current = self.policy_snapshot.load();
        if current.generation() > result.revision.generation {
            return Err(ManagedStoreError::VersionConflict);
        }
        drop(current);
        let snapshot = PolicySnapshot::from_managed(
            result.revision.generation,
            result.active_grants.clone(),
            result.catalog.clone(),
        );
        self.policy_snapshot.store(Arc::new(snapshot));
        Ok(result)
    }

    pub fn credential_key_ring(&self) -> Option<&CredentialKeyRing> {
        self.credential_key_ring.as_ref()
    }

    pub fn broker_token_hasher(&self) -> Option<&BrokerTokenHasher> {
        self.broker_token_hasher.as_ref()
    }

    pub fn local_password_hasher(&self) -> Option<&LocalPasswordHasher> {
        self.local_password_hasher.as_ref()
    }

    pub fn browser_csrf_key(&self) -> Option<&BrowserCsrfKey> {
        self.browser_csrf_key.as_ref()
    }

    pub fn outbound_tls(&self) -> &PreparedOutboundTls {
        self.network.outbound_tls()
    }

    /// The network settings this generation's command imports inherit.
    pub(crate) fn inherited_network(&self) -> &Arc<InheritedNetwork> {
        &self.inherited_network
    }

    pub fn microsoft_oidc(&self) -> Option<&MicrosoftOidcRuntimeConfig> {
        self.microsoft_oidc.as_ref()
    }

    pub fn has_configured_identity_header(&self, headers: &HeaderMap) -> bool {
        self.config
            .identity
            .sources
            .iter()
            .any(|source| headers.contains_key(source.header.as_str()))
    }

    pub async fn readiness(&self) -> Result<(), RuntimeError> {
        self.local_state_readiness().await?;
        let runtime = self.clone();
        tokio::task::spawn_blocking(move || {
            for source in runtime.identity_sources.iter() {
                source.check_ready()?;
            }
            runtime.check_credentials_ready()
        })
        .await
        .map_err(|source| RuntimeError::Audit {
            path: "readiness worker".to_string(),
            source: std::io::Error::other(source),
        })?
    }

    pub async fn local_state_readiness(&self) -> Result<(), RuntimeError> {
        self.audit.check_writable().await?;
        let runtime = self.clone();
        tokio::task::spawn_blocking(move || runtime.non_audit_local_state_readiness())
            .await
            .map_err(|source| RuntimeError::Audit {
                path: "readiness worker".to_string(),
                source: std::io::Error::other(source),
            })?
    }

    pub fn non_audit_local_state_readiness(&self) -> Result<(), RuntimeError> {
        check_upload_spool_writable(&self.config.limits)?;
        if let Some(store) = &self.managed_store {
            store
                .check_ready(self.credential_key_ring.as_ref())
                .map_err(runtime_managed_store_error)?;
        }
        Ok(())
    }

    fn accepts_delegated_credentials(&self, service: &str) -> bool {
        self.services
            .get(service)
            .is_some_and(|descriptor| descriptor.credentials.delegated.is_some())
    }

    fn check_credentials_ready(&self) -> Result<(), RuntimeError> {
        for (service, credential) in &self.effective_credentials.service {
            check_credential_ready(
                &format!("credentials.service.{service}"),
                service,
                "service",
                credential,
            )?;
        }
        for (service, credential) in &self.effective_credentials.per_user {
            let label = format!("credentials.per_user.{service}");
            if credential.kind == "connection" {
                self.check_connection_ready(&label, service)?;
                continue;
            }
            check_credential_ready(&label, service, "per_user", credential)?;
        }
        for (service, credential) in &self.effective_credentials.lookup {
            check_credential_ready(
                &format!("credentials.lookup.{service}"),
                service,
                "lookup",
                credential,
            )?;
        }
        Ok(())
    }

    pub fn resolve_identity(
        &self,
        headers: &HeaderMap,
    ) -> Result<IdentityContext, IdentityFailure> {
        let admission = self.admit_ingress(headers)?;
        self.resolve_admitted_identity(headers, &admission)
    }

    fn resolve_identity_with_anonymous_fallback(
        &self,
        headers: &HeaderMap,
        admission: &IngressAdmission,
        allow_anonymous_fallback: bool,
    ) -> Result<AdmittedIdentity, IdentityFailure> {
        // An explicit Authorization value must never fall back to forwarded identity.
        // Without forwarding, only configured identity sources claim their headers.
        let mut seen_identity_header = headers.contains_key(http::header::AUTHORIZATION)
            && headers.contains_key("x-aw-identity-token-sha256");
        for source in self.identity_sources.iter() {
            let token = match source.extract_token(headers)? {
                TokenExtraction::NoHeader => continue,
                TokenExtraction::Token(token) => {
                    seen_identity_header = true;
                    token
                }
            };
            let resolved = match source.resolve(&token)? {
                SourceResolution::NoMatch => continue,
                SourceResolution::Resolved(resolved) => resolved,
            };
            let source_audit = source.audit(&resolved);
            return Ok(AdmittedIdentity {
                identity: self.identity_from_principal_groups(
                    resolved.principal,
                    resolved.principal_kind,
                    resolved.subject,
                    resolved.groups,
                    Some(resolved.policy_groups),
                    Some(source_audit),
                ),
                proof: None,
            });
        }

        if seen_identity_header {
            Err(IdentityFailure::Invalid)
        } else if headers.contains_key("x-aw-identity-token-sha256") {
            self.resolve_forwarded_identity_with_proof(admission)
        } else if allow_anonymous_fallback {
            Ok(AdmittedIdentity {
                identity: IdentityContext::anonymous(),
                proof: None,
            })
        } else {
            Err(IdentityFailure::Required)
        }
    }

    pub fn identity_from_principal_groups(
        &self,
        principal: String,
        principal_kind: Option<crate::PrincipalKind>,
        principal_subject: Option<String>,
        raw_groups: Vec<String>,
        managed_policy_groups: Option<Vec<String>>,
        source: Option<IdentitySourceAudit>,
    ) -> IdentityContext {
        let (groups, policy_groups) = if self.config.identity.authority == "toml" {
            toml_identity_groups(&self.config, &principal)
        } else {
            let groups = sorted_unique(raw_groups);
            let policy_groups = managed_policy_groups
                .map(sorted_unique)
                .unwrap_or_else(|| groups.clone());
            (groups, policy_groups)
        };

        IdentityContext {
            principal,
            principal_kind,
            principal_subject,
            groups,
            policy_groups,
            authenticated: true,
            source,
            caller_id: None,
        }
    }

    pub fn identity_error_response(
        &self,
        agent_request_id: String,
        broker_request_id: String,
        failure: IdentityFailure,
    ) -> BrokerResponse<Value> {
        let reason_code = failure.reason_code();
        BrokerResponse {
            retry_after_seconds: None,
            status: reason_code.http_status(),
            envelope: ResponseEnvelope {
                agent_request_id,
                broker_request_id,
                decision: if failure == IdentityFailure::Unavailable {
                    Decision::Error
                } else {
                    Decision::Deny
                },
                service: "broker".into(),
                action: failure.admission_action().into(),
                resource_scopes: ResourceScopes::new(),
                reason_code: Some(reason_code.into()),
                reason: Some(failure.message().to_string()),
                result: None,
                error: Some(crate::ErrorBody {
                    message: failure.message().to_string(),
                }),
            },
            stream: None,
        }
    }

    pub async fn identity_error_response_for_operation(
        &self,
        context: GovernedIdentityFailureContext,
        failure: IdentityFailure,
    ) -> BrokerResponse<Value> {
        let identity = IdentityContext {
            principal: "unknown".into(),
            groups: vec![],
            policy_groups: vec![],
            ..IdentityContext::anonymous()
        };
        let stage = trusted_callers::PreDispatchFailure::for_identity_failure(&failure);
        stage.apply(
            self.governed_operation_error_response(
                GovernedOperationContext {
                    operation: OperationContext {
                        agent_request_id: context.agent_request_id,
                        broker_request_id: context.broker_request_id,
                        identity,
                        service: context.service,
                        action: context.action,
                        source: context.source,
                    },
                    execution_context: context.execution_context,
                },
                failure.provider_error(),
            )
            .await,
        )
    }

    pub async fn operation_error_response(
        &self,
        context: OperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let policy_generation = self.policy_generation();
        self.finalize(
            FinalizeContext {
                search_authorization: None,
                command: None,
                agent_request_id: context.agent_request_id,
                broker_request_id: context.broker_request_id,
                policy_generation,
                identity: context.identity,
                service: context.service,
                action: context.action,
                upstream_resource_ownership: None,
                resource_scopes: ResourceScopes::new(),
                credential_mode: None,
                matched_grant: None,
                source: context.source,
                execution_context: None,
                redact_error_resource_scopes: false,
                personal_lookup_connection: None,
                started: Instant::now(),
            },
            Err(error),
        )
        .await
    }

    pub async fn execution_context_error_response_for_operation(
        &self,
        context: OperationContext,
        failure: ExecutionContextFailure,
    ) -> BrokerResponse<Value> {
        self.ingress_error_response_for_operation(
            context,
            match failure {
                ExecutionContextFailure::Required => IdentityFailure::ExecutionContextRequired,
                ExecutionContextFailure::Invalid => IdentityFailure::ExecutionContextInvalid,
            },
        )
        .await
    }

    pub async fn governed_operation_error_response(
        &self,
        context: GovernedOperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let policy_generation = self.policy_generation();
        let GovernedOperationContext {
            operation,
            execution_context,
        } = context;
        self.finalize(
            FinalizeContext {
                search_authorization: None,
                command: None,
                agent_request_id: operation.agent_request_id,
                broker_request_id: operation.broker_request_id,
                policy_generation,
                identity: operation.identity,
                service: operation.service,
                action: operation.action,
                upstream_resource_ownership: None,
                resource_scopes: ResourceScopes::new(),
                credential_mode: None,
                matched_grant: None,
                source: operation.source,
                execution_context: Some(execution_context),
                redact_error_resource_scopes: false,
                personal_lookup_connection: None,
                started: Instant::now(),
            },
            Err(error),
        )
        .await
    }

    pub fn capabilities(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
    ) -> CapabilityBundle {
        CapabilityBundle {
            identity: identity.summary(),
            services: self.visible_services(identity, execution_context),
        }
    }

    pub fn api_services_for_identity(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
    ) -> Vec<ApiServiceSpec> {
        self.api_services_for_mcp_view(identity, execution_context, &crate::mcp::McpView::Aggregate)
    }

    /// Select a service before cloning schemas and evaluating caller action
    /// visibility. A connection view can only narrow ordinary catalog access.
    pub fn api_services_for_mcp_view(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        view: &crate::mcp::McpView,
    ) -> Vec<ApiServiceSpec> {
        if identity
            .source
            .as_ref()
            .and_then(|source| source.token_class.as_ref())
            .is_some_and(|token_class| token_class != &BrokerTokenClass::AgentInvoke)
        {
            return Vec::new();
        }
        self.available_service_descriptors(
            identity,
            execution_context,
            &self.policy_snapshot(),
            view.service(),
        )
        .iter()
        .filter_map(|service| {
            let mut spec = api_service_spec(
                &service.descriptor,
                self.scoped_mcp_ready(&service.descriptor.service),
            )?;
            spec.availability = Some(service.availability.clone());
            Some(spec)
        })
        .collect()
    }

    pub fn api_services_all(&self) -> Vec<ApiServiceSpec> {
        self.services
            .values()
            .filter_map(|descriptor| {
                let mut descriptor = (**descriptor).clone();
                descriptor.actions.retain(|action| {
                    self.imported_action_available(&descriptor.service, &action.action)
                });
                (!descriptor.actions.is_empty())
                    .then(|| {
                        api_service_spec(&descriptor, self.scoped_mcp_ready(&descriptor.service))
                    })
                    .flatten()
            })
            .collect()
    }

    pub fn visible_services(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
    ) -> Vec<DiscoveredService> {
        self.available_service_descriptors(
            identity,
            execution_context,
            &self.policy_snapshot(),
            None,
        )
        .iter()
        .map(|service| DiscoveredService {
            capabilities: service.descriptor.capabilities(),
            availability: service.availability.clone(),
        })
        .collect()
    }

    /// Policy-only metadata for management views, including services whose
    /// credentials still need to be provisioned.
    pub fn policy_visible_services(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
    ) -> Vec<ServiceCapabilities> {
        self.visible_service_descriptors(identity, execution_context, &self.policy_snapshot())
            .iter()
            .map(ServiceDescriptor::capabilities)
            .collect()
    }

    /// Configured services narrowed to the actions the caller could invoke in
    /// this execution context.
    fn visible_service_descriptors(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        policy_snapshot: &PolicySnapshot,
    ) -> Vec<ServiceDescriptor> {
        self.visible_service_descriptors_for_service(
            identity,
            execution_context,
            policy_snapshot,
            None,
        )
    }

    fn visible_service_descriptors_for_service(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        policy_snapshot: &PolicySnapshot,
        selected_service: Option<&str>,
    ) -> Vec<ServiceDescriptor> {
        if !identity.authenticated && self.config.identity.mode == "required" {
            return Vec::new();
        }
        let Ok(token_caveats) = parsed_agent_invoke_token_caveats(identity) else {
            return Vec::new();
        };
        self.services
            .values()
            .filter(|descriptor| {
                selected_service.is_none_or(|service| service == descriptor.service)
            })
            .filter_map(|descriptor| {
                let actions = descriptor
                    .actions
                    .iter()
                    .filter(|action| {
                        token_caveats.as_ref().is_none_or(|parsed| {
                            self.agent_invoke_permits_action(
                                parsed,
                                execution_context,
                                &descriptor.service,
                                &action.action,
                            )
                        }) && self.action_has_effective_access(
                            policy_snapshot,
                            identity,
                            execution_context,
                            &descriptor.service,
                            &action.action,
                            token_caveats.as_ref(),
                        )
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (!actions.is_empty())
                    .then(|| ServiceDescriptor::clone(descriptor).with_actions(actions))
            })
            .collect()
    }

    fn action_has_effective_access(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> bool {
        if self.action_resource_scope(service, action).is_none() {
            // Resource restrictions cannot authorize a scope-free action.
            // Use the same explicit grant/credential-mode selection as invocation.
            return token.is_none_or(|parsed| {
                self.token_resource_boundary(snapshot, context, &parsed.caveats, service, action)
                    .is_none()
            }) && self
                .scope_free_action_admitted(snapshot, identity, context, service, action);
        }
        !self
            .effective_resource_clauses(snapshot, identity, context, service, action, token)
            .is_empty()
    }

    pub fn visible_services_for_management(
        &self,
        identity: &IdentityContext,
    ) -> Vec<ServiceCapabilities> {
        if !identity.authenticated && self.config.identity.mode == "required" {
            return Vec::new();
        }
        let policy_snapshot = self.policy_snapshot();
        let configured_contexts = self.configured_execution_contexts();
        let Ok(token_caveats) = parsed_agent_invoke_token_caveats(identity) else {
            return Vec::new();
        };
        self.services
            .values()
            .filter_map(|descriptor| {
                let actions = descriptor
                    .actions
                    .iter()
                    .filter(|action| {
                        configured_contexts.iter().any(|execution_context| {
                            token_caveats.as_ref().is_none_or(|parsed| {
                                self.agent_invoke_permits_action(
                                    parsed,
                                    execution_context,
                                    &descriptor.service,
                                    &action.action,
                                )
                            }) && self.action_has_effective_access(
                                &policy_snapshot,
                                identity,
                                execution_context,
                                &descriptor.service,
                                &action.action,
                                token_caveats.as_ref(),
                            )
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (!actions.is_empty()).then(|| {
                    ServiceDescriptor::clone(descriptor)
                        .with_actions(actions)
                        .capabilities()
                })
            })
            .collect()
    }

    pub fn agent_token_options_for_identity(
        &self,
        identity: &IdentityContext,
    ) -> AgentTokenOptions {
        let configured_contexts = self.configured_execution_contexts();
        let policy_snapshot = self.policy_snapshot();
        let services = self
            .services
            .values()
            .filter_map(|descriptor| {
                let actions = descriptor
                    .actions
                    .iter()
                    .filter_map(|action| {
                        self.agent_token_action_option(
                            &policy_snapshot,
                            identity,
                            &configured_contexts,
                            descriptor,
                            action,
                        )
                    })
                    .collect::<Vec<_>>();
                let execution_contexts = configured_contexts
                    .iter()
                    .filter(|execution_context| {
                        actions
                            .iter()
                            .any(|action| action.execution_contexts.contains(execution_context))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (!execution_contexts.is_empty()).then(|| AgentTokenServiceOption {
                    service: descriptor.service.clone(),
                    display_name: descriptor.display_name.clone(),
                    broker_hosts: descriptor.broker_hosts(),
                    execution_contexts,
                    actions,
                })
            })
            .collect::<Vec<_>>();
        let execution_contexts = configured_contexts
            .into_iter()
            .filter(|execution_context| {
                services
                    .iter()
                    .any(|service| service.execution_contexts.contains(execution_context))
            })
            .collect();
        let (resources, resource_groups) =
            self.token_resource_picker_options(&policy_snapshot, identity, &services);
        AgentTokenOptions {
            policy_generation: policy_snapshot.generation(),
            resources,
            resource_groups,
            execution_contexts,
            services,
            mcp: crate::agent_token_mcp_url(self.config()).map(|url| AgentTokenMcpEndpoint { url }),
        }
    }

    fn agent_token_action_option(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        configured_contexts: &[ExecutionContext],
        service: &ServiceDescriptor,
        action: &ActionDescriptor,
    ) -> Option<AgentTokenActionOption> {
        let resource_type = service
            .action_resource_scope(&action.action)
            .map(|(_, binding)| binding.resource_type.clone());
        let mut effective_access_by_execution_context = BTreeMap::new();
        for execution_context in configured_contexts {
            let authored = policy_snapshot.grants.iter().any(|grant| {
                subject_rank(&grant.subject, identity).is_some()
                    && grant.service == service.service
                    && grant.actions.contains(&action.action)
                    && grant.execution_contexts.contains(execution_context)
            });
            if authored
                && (resource_type.is_some()
                    || self.scope_free_action_admitted(
                        policy_snapshot,
                        identity,
                        execution_context,
                        &service.service,
                        &action.action,
                    ))
            {
                let clauses = self.effective_resource_clauses(
                    policy_snapshot,
                    identity,
                    execution_context,
                    &service.service,
                    &action.action,
                    None,
                );
                effective_access_by_execution_context.insert(execution_context.clone(), clauses);
            }
        }
        let execution_contexts = effective_access_by_execution_context
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        (!execution_contexts.is_empty()).then(|| AgentTokenActionOption {
            action: action.action.clone(),
            description: action.description.clone(),
            read_only: action.read_only,
            required_scope_types: action.required_scope_types(),
            resource_type,
            execution_contexts,
            effective_access_by_execution_context,
        })
    }

    fn configured_execution_contexts(&self) -> Vec<ExecutionContext> {
        self.config.execution_context.as_ref().map_or_else(
            || {
                vec![
                    ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT)
                        .expect("built-in default execution context is valid"),
                ]
            },
            |config| {
                config
                    .allowed_values
                    .iter()
                    .map(|value| {
                        ExecutionContext::new(value.clone())
                            .expect("validated configured execution context")
                    })
                    .collect()
            },
        )
    }

    pub fn configured_service_capabilities(&self) -> Vec<ServiceCapabilities> {
        self.services
            .values()
            .map(|descriptor| descriptor.capabilities())
            .collect()
    }

    /// The validated descriptor for a configured provider or gateway service.
    pub fn service_descriptor(&self, service: &str) -> Option<Arc<ServiceDescriptor>> {
        self.services.get(service).cloned()
    }

    /// Resource types this broker understands, for catalogs and clients.
    pub fn resource_type_metadata(&self) -> Vec<agent_access_provider::ResourceTypeMetadata> {
        self.resource_types.metadata()
    }

    /// This generation's resource type registry.
    pub fn resource_types(&self) -> &ResourceTypeRegistry {
        self.resource_types.registry()
    }

    pub fn service_descriptors(&self) -> impl Iterator<Item = &Arc<ServiceDescriptor>> {
        self.services.values()
    }

    fn action_descriptor(&self, service: &str, action: &str) -> Option<&ActionDescriptor> {
        self.services.get(service)?.action(action)
    }

    fn action_upstream_resource_ownership(
        &self,
        service: &str,
        action: &str,
    ) -> Option<UpstreamResourceOwnership> {
        self.action_descriptor(service, action)?
            .upstream_resource_ownership
    }

    pub fn has_any_per_user_policy_for_service(
        &self,
        identity: &IdentityContext,
        service: &str,
    ) -> bool {
        let policy_snapshot = self.policy_snapshot();
        let Some(capabilities) = self.services.get(service) else {
            return false;
        };
        has_per_user_setup_grant(identity, capabilities, &policy_snapshot.grants)
    }

    /// Resolve setup authority inside an already-open managed-store transaction.
    ///
    /// The caller supplies the currently published runtime. Managed grants and
    /// effective managed group membership come from the same connection as the
    /// OAuth slot update, so withdrawal cannot race between admission and commit.
    /// TOML grants and identity groups come only from the current runtime.
    pub(crate) fn has_per_user_setup_grant_at_conn(
        &self,
        conn: &rusqlite::Connection,
        owner: &str,
        service: &str,
    ) -> Result<bool, ManagedStoreError> {
        let Some(capabilities) = self.services.get(service) else {
            return Ok(false);
        };
        let managed_policy_groups = if self.config.identity.authority == "managed" {
            Some(crate::managed_store::principal_policy_groups(conn, owner)?)
        } else {
            None
        };
        let principal_kind = crate::managed_store::principal_kind_at_conn(conn, owner)?;
        let identity = self.identity_from_principal_groups(
            owner.to_string(),
            principal_kind,
            Some(owner.to_string()),
            Vec::new(),
            managed_policy_groups,
            None,
        );
        let snapshot = self.policy_snapshot();
        let allowed = match snapshot.authority {
            PolicyAuthority::Toml => {
                has_per_user_setup_grant(&identity, capabilities, &snapshot.grants)
            }
            PolicyAuthority::Managed => {
                let grants = crate::managed_store::active_policy_grants_at_conn(conn)?
                    .into_iter()
                    .flat_map(RuntimePolicyGrant::from_managed)
                    .collect::<Vec<_>>();
                has_per_user_setup_grant(&identity, capabilities, &grants)
            }
        };
        Ok(allowed)
    }

    pub fn registered_service_names(&self) -> BTreeSet<String> {
        self.services.keys().cloned().collect()
    }

    pub fn service_capabilities(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
    ) -> Option<DiscoveredService> {
        self.available_service_descriptors(
            identity,
            execution_context,
            &self.policy_snapshot(),
            Some(service),
        )
        .into_iter()
        .next()
        .map(|service| DiscoveredService {
            capabilities: service.descriptor.capabilities(),
            availability: service.availability,
        })
    }

    pub fn resolve_gateway_basic_broker_token(
        &self,
        token: &str,
    ) -> Result<IdentityContext, IdentityFailure> {
        if token.trim().is_empty() {
            return Err(IdentityFailure::Invalid);
        }
        for source in self.identity_sources.iter() {
            let IdentitySourceResolverKind::BrokerTokens(broker_tokens) = &source.resolver else {
                continue;
            };
            let resolved = match broker_tokens.resolve(token)? {
                SourceResolution::NoMatch => continue,
                SourceResolution::Resolved(resolved) => resolved,
            };
            let source_audit = source.audit(&resolved);
            return Ok(self.identity_from_principal_groups(
                resolved.principal,
                resolved.principal_kind,
                resolved.subject,
                resolved.groups,
                Some(resolved.policy_groups),
                Some(source_audit),
            ));
        }
        Err(IdentityFailure::Invalid)
    }

    pub async fn prepare_gateway_operation(
        &self,
        context: GovernedOperationContext,
        resource_scopes: ResourceScopes,
    ) -> Result<PreparedGatewayOperation, Box<BrokerResponse<Value>>> {
        let plan = self
            .plan_gateway_operation(context, resource_scopes)
            .await?;
        let PlannedGatewayOperation {
            identity,
            service,
            action,
            correlation,
            resource_scopes,
            credential_mode,
            matched_grant,
            finalize_context,
        } = plan;

        let access = match self
            .resolve_gateway_access(&service, &action, &credential_mode, &identity, &correlation)
            .await
        {
            Ok(access) => access,
            Err(error) => {
                return Err(Box::new(self.finalize(finalize_context, Err(error)).await));
            }
        };

        Ok(PreparedGatewayOperation {
            identity,
            service,
            action,
            correlation,
            resource_scopes,
            credential_mode,
            access,
            matched_grant,
            terminal_audit: None,
            finalize_context,
        })
    }

    pub async fn reject_gateway_operation_without_credential(
        &self,
        context: GovernedOperationContext,
        resource_scopes: ResourceScopes,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        match self.plan_gateway_operation(context, resource_scopes).await {
            Ok(plan) => self.finalize(plan.finalize_context, Err(error)).await,
            Err(response) => *response,
        }
    }

    async fn plan_gateway_operation(
        &self,
        context: GovernedOperationContext,
        resource_scopes: ResourceScopes,
    ) -> Result<PlannedGatewayOperation, Box<BrokerResponse<Value>>> {
        let GovernedOperationContext {
            operation:
                OperationContext {
                    agent_request_id,
                    broker_request_id,
                    identity,
                    service,
                    action,
                    source,
                },
            execution_context,
        } = context;
        let correlation =
            CorrelationContext::new(agent_request_id.clone(), broker_request_id.clone());
        let started = Instant::now();
        let policy_snapshot = self.policy_snapshot();
        let policy_generation = policy_snapshot.generation();

        let Some(capabilities) = self.services.get(&service).cloned() else {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(ProviderError::deny(
                        ReasonCode::ServiceActionDenied,
                        "gateway service is not supported",
                    )),
                )
                .await,
            ));
        };
        let Some(action_capabilities) = capabilities.action(&action).cloned() else {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(ProviderError::deny(
                        ReasonCode::ServiceActionDenied,
                        "gateway action is not supported",
                    )),
                )
                .await,
            ));
        };

        if !identity.authenticated {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(ProviderError::deny(
                        ReasonCode::GatewayAuthRequired,
                        "gateway authenticated identity is required",
                    )),
                )
                .await,
            ));
        }

        if let Err(error) = self.enforce_invocation_identity_admission(&identity).await {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(error),
                )
                .await,
            ));
        }
        let token_caveats = match parsed_agent_invoke_token_caveats(&identity).and_then(|parsed| {
            self.enforce_agent_invoke_token_caveats_with(
                parsed.as_ref(),
                &service,
                &action,
                &execution_context,
            )?;
            Ok(parsed)
        }) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Err(Box::new(
                    self.finalize_pre_dispatch(
                        FinalizeContext {
                            search_authorization: None,
                            command: None,
                            agent_request_id,
                            broker_request_id,
                            policy_generation,
                            identity,
                            service,
                            action,
                            upstream_resource_ownership: None,
                            resource_scopes,
                            credential_mode: None,
                            matched_grant: None,
                            source,
                            execution_context: Some(execution_context.clone()),
                            redact_error_resource_scopes: false,
                            personal_lookup_connection: None,
                            started,
                        },
                        Err(error),
                    )
                    .await,
                ));
            }
        };
        if let Some(missing_scope) = action_capabilities
            .required_scope_types()
            .iter()
            .find(|scope| {
                resource_scopes
                    .get(scope.as_str())
                    .is_none_or(|values| values.is_empty())
            })
            .cloned()
        {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(ProviderError::deny(
                        ReasonCode::GatewayScopeUnresolved,
                        format!("gateway required scope {missing_scope} is unresolved"),
                    )),
                )
                .await,
            ));
        }

        if let Err(error) = self.enforce_agent_invoke_token_resource_caveats_with(
            &policy_snapshot,
            &execution_context,
            token_caveats.as_ref(),
            &service,
            &action,
            &resource_scopes,
        ) {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(error),
                )
                .await,
            ));
        }

        let policy = match self.select_policy(
            &policy_snapshot,
            &identity,
            &execution_context,
            &service,
            &action,
            &resource_scopes,
        ) {
            Ok(policy) => policy,
            Err(error) => {
                return Err(Box::new(
                    self.finalize_pre_dispatch(
                        FinalizeContext {
                            search_authorization: None,
                            command: None,
                            agent_request_id,
                            broker_request_id,
                            policy_generation,
                            identity,
                            service,
                            action,
                            upstream_resource_ownership: None,
                            resource_scopes,
                            credential_mode: None,
                            matched_grant: None,
                            source,
                            execution_context: Some(execution_context.clone()),
                            redact_error_resource_scopes: false,
                            personal_lookup_connection: None,
                            started,
                        },
                        Err(error),
                    )
                    .await,
                ));
            }
        };
        if !action_capabilities
            .credential_modes
            .iter()
            .any(|mode| mode == &policy.credential_mode)
        {
            return Err(Box::new(
                self.finalize_pre_dispatch(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes,
                        credential_mode: Some(policy.credential_mode),
                        matched_grant: Some(policy.matched_grant),
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(policy_planning_drift_error()),
                )
                .await,
            ));
        }

        Ok(PlannedGatewayOperation {
            identity: identity.clone(),
            service: service.clone(),
            action: action.clone(),
            correlation,
            resource_scopes: resource_scopes.clone(),
            credential_mode: policy.credential_mode.clone(),
            matched_grant: policy.matched_grant.clone(),
            finalize_context: FinalizeContext {
                search_authorization: None,
                command: None,
                agent_request_id,
                broker_request_id,
                policy_generation,
                identity,
                service,
                action,
                upstream_resource_ownership: None,
                resource_scopes,
                credential_mode: Some(policy.credential_mode),
                matched_grant: Some(policy.matched_grant),
                source,
                execution_context: Some(execution_context),
                redact_error_resource_scopes: false,
                personal_lookup_connection: None,
                started,
            },
        })
    }

    pub async fn fail_prepared_gateway_operation(
        &self,
        mut prepared: PreparedGatewayOperation,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let error = prepared.with_error_credential_method(error);
        let append_mode = prepared.take_gateway_audit_append_mode();
        self.finalize_with_append_mode(prepared.finalize_context, Err(error), append_mode)
            .await
    }

    pub async fn start_prepared_gateway_operation(
        &self,
        prepared: &mut PreparedGatewayOperation,
        audit: Value,
    ) -> Result<(), Box<BrokerResponse<Value>>> {
        let audit = prepared.with_credential_method(audit);
        let context = &prepared.finalize_context;
        let identity = &context.identity;
        let audit_record = AuditRecord {
            search_authorization: None,
            timestamp: Utc::now().to_rfc3339(),
            agent_request_id: context.agent_request_id.clone(),
            broker_request_id: context.broker_request_id.clone(),
            config_generation: self.config_generation,
            policy_generation: Some(context.policy_generation),
            principal_subject: identity.principal_subject.clone(),
            principal: identity.principal.clone(),
            groups: identity.groups.clone(),
            service: context.service.clone(),
            action: context.action.clone(),
            resource_scopes: context.resource_scopes.clone(),
            matched_grant: context.matched_grant.clone(),
            credential_mode: context.credential_mode.clone().map(Some),
            credential_connection: self.audit_credential_connection(
                &context.service,
                context.credential_mode.as_deref(),
                None,
                context.personal_lookup_connection.clone(),
            ),
            decision: Decision::Allow,
            reason_code: None,
            upstream_status: None,
            upstream_duration_ms: None,
            object_ids: None,
            identity_source: identity.source.clone(),
            caller_id: identity.caller_id.clone(),
            source: context.source.clone(),
            execution_context: context.execution_context.clone(),
            provider_audit: Some(gateway_started_audit_value(audit)),
        };

        let terminal_permit = match self.audit.reserve_terminal().await {
            Ok(permit) => permit,
            Err(error) => {
                emit_audit_append_failed(
                    &audit_record,
                    self.node_id(),
                    ReasonCode::AuditUnavailable.http_status(),
                    &error,
                    None,
                );
                return Err(Box::new(
                    trusted_callers::PreDispatchFailure::Admission.apply(
                        audit_unavailable_response(
                            context.agent_request_id.clone(),
                            context.broker_request_id.clone(),
                            context.service.clone(),
                            context.action.clone(),
                            context.resource_scopes.clone(),
                            error,
                        ),
                    ),
                ));
            }
        };

        if let Err(error) = self.audit.append_required(audit_record.clone()).await {
            emit_audit_append_failed(
                &audit_record,
                self.node_id(),
                ReasonCode::AuditUnavailable.http_status(),
                &error,
                None,
            );
            return Err(Box::new(
                trusted_callers::PreDispatchFailure::Admission.apply(audit_unavailable_response(
                    context.agent_request_id.clone(),
                    context.broker_request_id.clone(),
                    context.service.clone(),
                    context.action.clone(),
                    context.resource_scopes.clone(),
                    error,
                )),
            ));
        }
        prepared.terminal_audit = Some(GatewayTerminalAuditGuard::new(
            audit_record.clone(),
            terminal_permit,
            Arc::clone(&self.audit_registry),
        ));
        let duration_ms = elapsed_millis(context.started);
        record_span_from_audit(&audit_record, 200);
        emit_invoke_stream_started(&audit_record, 200, duration_ms);
        Ok(())
    }

    /// Finalizes a forwarded gateway request after its response was passed
    /// through. An upstream 429 still reaches the client unchanged, but the
    /// request is audited as `upstream_rate_limited` rather than a completed
    /// allow.
    pub async fn complete_prepared_gateway_operation(
        &self,
        mut prepared: PreparedGatewayOperation,
        upstream_status: u16,
        upstream_duration_ms: u64,
        audit: Value,
    ) -> Result<(), Box<BrokerResponse<Value>>> {
        let audit = prepared.with_credential_method(audit);
        let append_mode = prepared.take_gateway_audit_append_mode();
        let result = if upstream_status == 429 {
            Err(
                agent_access_provider::upstream_rate_limited(&prepared.service, None)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_audit(audit),
            )
        } else {
            Ok(ProviderResult::new(json!({"gateway": "completed"}))
                .with_audit(audit)
                .with_upstream(Some(upstream_status), Some(upstream_duration_ms)))
        };
        let response = self
            .finalize_with_append_mode(prepared.finalize_context, result, append_mode)
            .await;
        if response.status == 200 {
            Ok(())
        } else {
            Err(Box::new(response))
        }
    }

    pub fn gateway_http_client(
        &self,
        service: &str,
        gateway: &GatewayConfig,
    ) -> Result<(reqwest::Client, Value), RuntimeError> {
        let upstream_base = Url::parse(&gateway.upstream_base_url).map_err(|error| {
            RuntimeError::Config(ConfigError::Invalid {
                errors: vec![format!(
                    "gateways.{service}.upstream_base_url is invalid: {error}"
                )],
            })
        })?;
        let (client, route) = self.network.gateway_client(
            &format!("gateways.{service}.egress_proxy"),
            &upstream_base,
            gateway.egress_proxy.as_ref(),
        )?;
        Ok((client, route.audit_value()))
    }

    pub async fn verify_execution_credential(
        &self,
        service: &str,
        credential: &ExecutionCredential,
        identity: &IdentityContext,
        input: CredentialVerificationInput,
        correlation: CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let input = self.preflight_execution_credential_verification(service, identity, input)?;
        if let Some(provider) = self.providers.get(service) {
            return with_provider_context(
                correlation.clone(),
                service.to_string(),
                "credential.verify".to_string(),
                run_provider_hook(
                    agent_access_provider::host::hook_context(
                        service,
                        "credential.verify",
                        HookPhase::CredentialVerification,
                        self.service_domain_reasons(service),
                    ),
                    provider.verify_execution_credential(credential, &correlation),
                ),
            )
            .await;
        }
        if let Some(gateway) = self.config.gateways.get(service) {
            return self
                .verify_gateway_execution_credential(
                    service,
                    gateway,
                    credential,
                    identity,
                    input,
                    correlation,
                )
                .await;
        }
        Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "service is not supported",
        ))
    }

    pub fn preflight_execution_credential_verification(
        &self,
        service: &str,
        identity: &IdentityContext,
        input: CredentialVerificationInput,
    ) -> Result<CredentialVerificationInput, ProviderError> {
        if self.providers.contains_key(service) {
            if !input.is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "credential verification input is not supported for service",
                ));
            }
            return Ok(input);
        }
        let Some(gateway) = self.config.gateways.get(service) else {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "service is not supported",
            ));
        };
        if gateway.kind != "git_http" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "gateway credential verification is not supported",
            ));
        }
        self.preflight_git_http_gateway_credential_verification(service, gateway, identity, input)
    }

    async fn verify_gateway_execution_credential(
        &self,
        service: &str,
        gateway: &GatewayConfig,
        credential: &ExecutionCredential,
        identity: &IdentityContext,
        input: CredentialVerificationInput,
        correlation: CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        if gateway.kind != "git_http" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "gateway credential verification is not supported",
            ));
        }
        self.verify_git_http_gateway_credential(
            service,
            gateway,
            credential,
            identity,
            input,
            correlation,
        )
        .await
        .map(Some)
    }

    fn preflight_git_http_gateway_credential_verification(
        &self,
        service: &str,
        gateway: &GatewayConfig,
        identity: &IdentityContext,
        input: CredentialVerificationInput,
    ) -> Result<CredentialVerificationInput, ProviderError> {
        if !gateway.git.as_ref().is_some_and(|git| git.allow_fetch) {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "git gateway fetch is not enabled",
            ));
        }
        let repository = normalize_git_verification_repository(input.repository.as_deref())?;
        let resource_scopes =
            ResourceScopes::from([("repository".to_string(), vec![repository.clone()])]);
        let policy_snapshot = self.policy_snapshot();
        let has_per_user_policy = self
            .policy_candidates_for_action_across_contexts(
                &policy_snapshot,
                identity,
                service,
                "repo.fetch",
            )
            .into_iter()
            .any(|candidate| {
                candidate.credential_mode == "per_user"
                    && candidate_authorizes_scopes(&candidate, &resource_scopes)
            });
        if !has_per_user_policy {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "git credential verification requires a per_user repo.fetch policy",
            ));
        }
        Ok(CredentialVerificationInput {
            repository: Some(repository),
        })
    }

    async fn verify_git_http_gateway_credential(
        &self,
        service: &str,
        gateway: &GatewayConfig,
        credential: &ExecutionCredential,
        _identity: &IdentityContext,
        input: CredentialVerificationInput,
        correlation: CorrelationContext,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        let repository = input.repository.as_deref().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "git credential verification requires repository",
            )
        })?;

        let upstream_url = git_discovery_verification_url(gateway, repository)?;
        if !agent_access_provider::url_allowed_by_patterns(
            &upstream_url,
            &gateway.allowed_upstream_hosts,
        ) {
            return Err(ProviderError::error(
                ReasonCode::GatewayUpstreamDenied,
                "gateway upstream URL is not allowed",
            ));
        }
        let (client, egress_proxy_audit) =
            self.gateway_http_client(service, gateway).map_err(|_| {
                ProviderError::error(
                    ReasonCode::GatewayUpstreamDenied,
                    "gateway upstream client is unavailable",
                )
            })?;
        let mut builder = client
            .get(upstream_url.clone())
            .header(reqwest::header::ACCEPT, "*/*")
            .header(
                reqwest::header::USER_AGENT,
                "agent-access-broker/git-credential-verify",
            );
        if gateway.correlation_headers {
            builder = builder
                .header(REQUEST_ID_HEADER, correlation.agent_request_id.clone())
                .header(
                    BROKER_REQUEST_ID_HEADER,
                    correlation.broker_request_id.clone(),
                );
        }
        builder = agent_access_provider::host::authorize_host_request(
            builder,
            &gateway_upstream_authorization(&gateway.upstream_token_auth, credential)?,
        );
        let started = Instant::now();
        let verification_timeout = Duration::from_millis(
            gateway
                .streaming_idle_timeout_ms
                .unwrap_or(self.config.limits.streaming_idle_timeout_ms),
        );
        let response = match timeout(verification_timeout, builder.send()).await {
            Ok(result) => result.map_err(|error| {
                git_verify_reqwest_error_to_provider_error(
                    error,
                    &upstream_url,
                    repository,
                    egress_proxy_audit.clone(),
                )
                .with_upstream(None, Some(elapsed_millis(started)))
            })?,
            Err(_) => {
                return Err(git_verify_timeout_error_to_provider_error(
                    &upstream_url,
                    repository,
                    egress_proxy_audit,
                )
                .with_upstream(None, Some(elapsed_millis(started))));
            }
        };
        let upstream_status = response.status().as_u16();
        let audit = git_verification_audit(
            &upstream_url,
            repository,
            egress_proxy_audit,
            upstream_status,
        );
        if response.status().is_success() {
            let valid = match timeout(
                verification_timeout,
                git_upload_pack_discovery_response_is_valid(response, verification_timeout),
            )
            .await
            {
                Ok(result) => result.map_err(|error| {
                    error
                        .with_upstream(Some(upstream_status), Some(elapsed_millis(started)))
                        .with_audit(audit.clone())
                })?,
                Err(_) => {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamTimeout,
                        "git upstream discovery response timed out",
                    )
                    .with_upstream(Some(upstream_status), Some(elapsed_millis(started)))
                    .with_audit(audit));
                }
            };
            let duration_ms = elapsed_millis(started);
            if !valid {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "git upstream did not return upload-pack discovery",
                )
                .with_upstream(Some(upstream_status), Some(duration_ms))
                .with_audit(audit));
            }
            return Ok(ProviderCredentialVerification::new(
                upstream_status,
                duration_ms,
                audit,
            ));
        }
        let duration_ms = elapsed_millis(started);
        let error = if upstream_status == 429 {
            upstream_rate_limited(
                service,
                UpstreamRetryAfter::from_headers(response.headers()),
            )
        } else {
            git_verify_status_error(upstream_status)
        };
        Err(error
            .with_upstream(Some(upstream_status), Some(duration_ms))
            .with_audit(audit))
    }

    pub async fn invoke(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
    ) -> BrokerResponse<Value> {
        self.invoke_with_stream_requirement(context, request, false)
            .await
    }

    pub async fn invoke_required_stream(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
    ) -> BrokerResponse<Value> {
        self.invoke_with_stream_requirement(context, request, true)
            .await
    }

    async fn invoke_with_stream_requirement(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
        require_stream: bool,
    ) -> BrokerResponse<Value> {
        match self.begin_invoke(context, request).await {
            Ok(mut prepared) => {
                let body_parts = std::mem::take(&mut prepared.body_parts);
                self.finish_prepared_invoke_with_stream_requirement(
                    prepared,
                    body_parts,
                    require_stream,
                )
                .await
            }
            Err(response) => *response,
        }
    }

    pub async fn begin_invoke(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
    ) -> Result<PreparedInvocation, Box<BrokerResponse<Value>>> {
        match self.prepare_invoke(context, request).await {
            Ok(prepared) => Ok(prepared),
            Err(failure) => Err(Box::new(
                self.finalize_pre_dispatch(failure.context, failure.result)
                    .await,
            )),
        }
    }

    async fn prepare_invoke(
        &self,
        context: GovernedOperationContext,
        request: InvokeRequest,
    ) -> Result<PreparedInvocation, Box<owned::PreparationFailure>> {
        let GovernedOperationContext {
            operation:
                OperationContext {
                    agent_request_id,
                    broker_request_id,
                    identity,
                    service,
                    action,
                    source,
                },
            execution_context,
        } = context;
        let correlation =
            CorrelationContext::new(agent_request_id.clone(), broker_request_id.clone());
        let response_options = request.response_options();
        let started = Instant::now();
        let policy_snapshot = self.policy_snapshot();
        let policy_generation = policy_snapshot.generation();
        let domain_reasons = self.service_domain_reasons(&service);
        let Some(provider) = self.providers.get(&service).cloned() else {
            return Err(Box::new(owned::PreparationFailure::new(
                FinalizeContext {
                    search_authorization: None,
                    command: None,
                    agent_request_id,
                    broker_request_id,
                    policy_generation,
                    identity,
                    service,
                    action,
                    upstream_resource_ownership: None,
                    resource_scopes: ResourceScopes::new(),
                    credential_mode: None,
                    matched_grant: None,
                    source,
                    execution_context: Some(execution_context.clone()),
                    redact_error_resource_scopes: false,
                    personal_lookup_connection: None,
                    started,
                },
                Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "service is not supported",
                )),
            )));
        };
        if let Err(error) = self.enforce_invocation_identity_admission(&identity).await {
            return Err(Box::new(owned::PreparationFailure::new(
                FinalizeContext {
                    search_authorization: None,
                    command: None,
                    agent_request_id,
                    broker_request_id,
                    policy_generation,
                    identity,
                    service,
                    action,
                    upstream_resource_ownership: None,
                    resource_scopes: ResourceScopes::new(),
                    credential_mode: None,
                    matched_grant: None,
                    source,
                    execution_context: Some(execution_context.clone()),
                    redact_error_resource_scopes: false,
                    personal_lookup_connection: None,
                    started,
                },
                Err(error),
            )));
        }
        let token_caveats = match parsed_agent_invoke_token_caveats(&identity).and_then(|parsed| {
            self.enforce_agent_invoke_token_caveats_with(
                parsed.as_ref(),
                &service,
                &action,
                &execution_context,
            )?;
            Ok(parsed)
        }) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Err(Box::new(owned::PreparationFailure::new(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes: ResourceScopes::new(),
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: false,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(error),
                )));
            }
        };

        let service_descriptor = self.services.get(&service).cloned();
        // An action whose I/O kind this host does not serve is not admitted.
        let Some(action_descriptor) = self.served_action_descriptor(&service, &action).cloned()
        else {
            return Err(Box::new(owned::PreparationFailure::new(
                FinalizeContext {
                    search_authorization: None,
                    command: None,
                    agent_request_id,
                    broker_request_id,
                    policy_generation,
                    identity,
                    service,
                    action,
                    upstream_resource_ownership: None,
                    resource_scopes: ResourceScopes::new(),
                    credential_mode: None,
                    matched_grant: None,
                    source,
                    execution_context: Some(execution_context.clone()),
                    redact_error_resource_scopes: false,
                    personal_lookup_connection: None,
                    started,
                },
                Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "service action is not supported",
                )),
            )));
        };
        let upstream_resource_ownership = action_descriptor.upstream_resource_ownership;
        if response_options != agent_access_provider::presentation::ResponseOptions::default()
            && let Err(error) = agent_access_provider::presentation::validate_response_options(
                action_descriptor.presentation.as_ref(),
                response_options,
            )
        {
            return Err(Box::new(owned::PreparationFailure::new(
                FinalizeContext {
                    search_authorization: None,
                    command: None,
                    agent_request_id,
                    broker_request_id,
                    policy_generation,
                    identity,
                    service,
                    action,
                    upstream_resource_ownership: None,
                    resource_scopes: ResourceScopes::new(),
                    credential_mode: None,
                    matched_grant: None,
                    source,
                    execution_context: Some(execution_context.clone()),
                    redact_error_resource_scopes: false,
                    personal_lookup_connection: None,
                    started,
                },
                Err(error),
            )));
        }

        let lookup_scopes_before_policy = action_descriptor.lookup.before_policy();

        let pre_scope_lookup = match self
            .resolve_pre_scope_lookup_if_required(
                &policy_snapshot,
                action_descriptor.lookup,
                &identity,
                &execution_context,
                &service,
                &action,
                &correlation,
            )
            .await
        {
            Ok(credential) => credential,
            Err(error) => {
                return Err(Box::new(owned::PreparationFailure::new(
                    FinalizeContext {
                        search_authorization: None,
                        command: None,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes: ResourceScopes::new(),
                        credential_mode: None,
                        matched_grant: None,
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: lookup_scopes_before_policy,
                        personal_lookup_connection: None,
                        started,
                    },
                    Err(error),
                )));
            }
        };

        let personal_lookup_connection =
            self.personal_lookup_connection(&service, &pre_scope_lookup);
        let mut audit_search_authorization = None;
        let mut command_authorization = None;
        let (scopes, policy, provider_state, search_authorization) =
            if self.command_enforced(&service, &action) {
                let admission = self
                    .admit_command_enforced(command_authority::CommandAdmissionRequest {
                        snapshot: &policy_snapshot,
                        identity: &identity,
                        context: &execution_context,
                        service: &service,
                        action: &action,
                        token: token_caveats.as_ref(),
                        inputs: &request.inputs,
                        correlation: &correlation,
                        provider: &provider,
                        domain_reasons,
                    })
                    .await;
                match admission {
                    Ok(admission) => {
                        command_authorization = Some(admission.authorization);
                        (
                            admission.scopes,
                            admission.policy,
                            admission.state,
                            admission.search,
                        )
                    }
                    Err(error) => {
                        return Err(Box::new(owned::PreparationFailure::new(
                            FinalizeContext {
                                search_authorization: None,
                                command: None,
                                agent_request_id,
                                broker_request_id,
                                policy_generation,
                                identity,
                                service,
                                action,
                                upstream_resource_ownership: None,
                                resource_scopes: ResourceScopes::new(),
                                credential_mode: None,
                                matched_grant: None,
                                source,
                                execution_context: Some(execution_context.clone()),
                                redact_error_resource_scopes: false,
                                personal_lookup_connection: personal_lookup_connection.clone(),
                                started,
                            },
                            Err(error),
                        )));
                    }
                }
            } else if action_descriptor.native_search.is_some() {
                let mut search_authorization = match self.plan_search_authorization(
                    &policy_snapshot,
                    &identity,
                    &execution_context,
                    &service,
                    &action,
                ) {
                    Ok(search_authorization) => search_authorization,
                    Err(error) => {
                        return Err(Box::new(owned::PreparationFailure::new(
                            FinalizeContext {
                                search_authorization: None,
                                command: None,
                                agent_request_id,
                                broker_request_id,
                                policy_generation,
                                identity,
                                service,
                                action,
                                upstream_resource_ownership: None,
                                resource_scopes: ResourceScopes::new(),
                                credential_mode: None,
                                matched_grant: None,
                                source,
                                execution_context: Some(execution_context.clone()),
                                redact_error_resource_scopes: false,
                                personal_lookup_connection: personal_lookup_connection.clone(),
                                started,
                            },
                            Err(error),
                        )));
                    }
                };
                if let Err(error) = self.intersect_agent_invoke_token_search_authorization_with(
                    &policy_snapshot,
                    &execution_context,
                    token_caveats.as_ref(),
                    &service,
                    &action,
                    &mut search_authorization,
                ) {
                    return Err(Box::new(owned::PreparationFailure::new(
                        FinalizeContext {
                            search_authorization: None,
                            command: None,
                            agent_request_id,
                            broker_request_id,
                            policy_generation,
                            identity,
                            service,
                            action,
                            upstream_resource_ownership: None,
                            resource_scopes: ResourceScopes::new(),
                            credential_mode: None,
                            matched_grant: None,
                            source,
                            execution_context: Some(execution_context.clone()),
                            redact_error_resource_scopes: false,
                            personal_lookup_connection: personal_lookup_connection.clone(),
                            started,
                        },
                        Err(error),
                    )));
                }
                let scopes = search_authorization.resource_scope_summary();
                let matched_grant = search_authorization
                    .matched_grants
                    .first()
                    .cloned()
                    .expect("search authorization has at least one matched grant");
                let policy = PolicyDecision {
                    credential_mode: search_authorization.credential_mode.clone(),
                    matched_grant,
                };
                let provider_search_authorization = search_authorization.authorization();
                audit_search_authorization = Some(search_authorization);
                (scopes, policy, None, Some(provider_search_authorization))
            } else {
                let scope_identity =
                    InvocationIdentity::new(identity.principal.clone(), identity.authenticated);
                let scope_resolution = match with_provider_context(
                    correlation.clone(),
                    service.clone(),
                    action.clone(),
                    run_provider_hook(
                        agent_access_provider::host::hook_context(
                            &service,
                            &action,
                            HookPhase::ScopeResolution,
                            domain_reasons,
                        ),
                        provider.resolve_scopes(agent_access_provider::host::scope_request(
                            agent_access_provider::host::ScopeRequestParts {
                                service: &service,
                                action: &action,
                                inputs: &request.inputs,
                                execution_context: execution_context.as_str(),
                                identity: &scope_identity,
                                correlation: &correlation,
                                lookup_access: pre_scope_lookup.access(),
                            },
                        )),
                    ),
                )
                .await
                {
                    Ok(scopes) => scopes,
                    Err(error) => {
                        return Err(Box::new(owned::PreparationFailure::new(
                            FinalizeContext {
                                search_authorization: None,
                                command: None,
                                agent_request_id,
                                broker_request_id,
                                policy_generation,
                                identity,
                                service,
                                action,
                                upstream_resource_ownership: None,
                                resource_scopes: ResourceScopes::new(),
                                credential_mode: None,
                                matched_grant: None,
                                source,
                                execution_context: Some(execution_context.clone()),
                                redact_error_resource_scopes: lookup_scopes_before_policy,
                                personal_lookup_connection: personal_lookup_connection.clone(),
                                started,
                            },
                            Err(if lookup_scopes_before_policy {
                                public_lookup_scope_error(error)
                            } else {
                                error
                            }),
                        )));
                    }
                };
                let (scopes, provider_state) = scope_resolution.into_parts();

                if let Err(error) = self.enforce_agent_invoke_token_resource_caveats_with(
                    &policy_snapshot,
                    &execution_context,
                    token_caveats.as_ref(),
                    &service,
                    &action,
                    &scopes,
                ) {
                    let error = if lookup_scopes_before_policy {
                        let mut public = lookup_scope_denial();
                        public.audit = error.audit;
                        public
                    } else {
                        error
                    };
                    return Err(Box::new(owned::PreparationFailure::new(
                        FinalizeContext {
                            search_authorization: None,
                            command: None,
                            agent_request_id,
                            broker_request_id,
                            policy_generation,
                            identity,
                            service,
                            action,
                            upstream_resource_ownership: None,
                            resource_scopes: scopes,
                            credential_mode: None,
                            matched_grant: None,
                            source,
                            execution_context: Some(execution_context.clone()),
                            redact_error_resource_scopes: lookup_scopes_before_policy,
                            personal_lookup_connection: personal_lookup_connection.clone(),
                            started,
                        },
                        Err(error),
                    )));
                }

                let policy = match self.select_policy(
                    &policy_snapshot,
                    &identity,
                    &execution_context,
                    &service,
                    &action,
                    &scopes,
                ) {
                    Ok(policy) => policy,
                    Err(error) => {
                        return Err(Box::new(owned::PreparationFailure::new(
                            FinalizeContext {
                                search_authorization: None,
                                command: None,
                                agent_request_id,
                                broker_request_id,
                                policy_generation,
                                identity,
                                service,
                                action,
                                upstream_resource_ownership: None,
                                resource_scopes: scopes,
                                credential_mode: None,
                                matched_grant: None,
                                source,
                                execution_context: Some(execution_context.clone()),
                                redact_error_resource_scopes: lookup_scopes_before_policy,
                                personal_lookup_connection: personal_lookup_connection.clone(),
                                started,
                            },
                            Err(if lookup_scopes_before_policy {
                                lookup_scope_denial()
                            } else {
                                error
                            }),
                        )));
                    }
                };
                command_authorization =
                    self.broker_command_authorization(&service, &action, &scopes, &policy);
                (scopes, policy, provider_state, None)
            };
        // A command import's admission is recorded for every later outcome.
        // A command-enforced call may pass several grants' credentials and
        // reports one mode only when its grants share it.
        let command = command_authorization.and_then(|authorization| {
            self.admitted_command(
                &service,
                authorization,
                &policy_snapshot,
                &execution_context,
            )
        });
        let command_enforced = matches!(
            command
                .as_ref()
                .map(command_dispatch::AdmittedCommand::authorization),
            Some(CommandAuthorization::Command { .. })
        );
        let audit_credential_mode = match &command {
            Some(command) if command_enforced => command.authorization().credential_mode(),
            _ => Some(policy.credential_mode.clone()),
        };

        // The command request builder resolves a command import's credentials
        // after the concurrency permit; admission checks only that they are
        // present (the command-enforced plan already checked its grants').
        let credentials = match &command {
            Some(_) if command_enforced => Ok(ExecutionAccess::None),
            Some(_) => self
                .command_credential_admitted(&service, &policy.credential_mode, &identity)
                .await
                .map(|()| ExecutionAccess::None),
            None => {
                self.resolve_execution_credential_after_policy(
                    service_descriptor
                        .as_ref()
                        .map(|descriptor| &descriptor.credentials),
                    &service,
                    &action,
                    &policy.credential_mode,
                    &identity,
                    &correlation,
                    &pre_scope_lookup,
                )
                .await
            }
        };
        let credentials = match credentials {
            Ok(credentials) => credentials,
            Err(error) => {
                return Err(Box::new(owned::PreparationFailure::new(
                    FinalizeContext {
                        search_authorization: audit_search_authorization,
                        command,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes: scopes,
                        credential_mode: audit_credential_mode,
                        matched_grant: Some(policy.matched_grant),
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: lookup_scopes_before_policy,
                        personal_lookup_connection: personal_lookup_connection.clone(),
                        started,
                    },
                    Err(error),
                )));
            }
        };

        let (lookup_access, credential_mode, authority) = match self
            .resolve_lookup_access_if_required(
                action_descriptor.lookup,
                &service,
                &policy,
                &credentials,
                &pre_scope_lookup,
            )
            .await
            .and_then(|lookup| {
                Ok((
                    lookup,
                    admitted_credential_mode(&policy.credential_mode)?,
                    admitted_authority(
                        &action_descriptor,
                        &scopes,
                        search_authorization,
                        self.command_enforced(&service, &action),
                    )?,
                ))
            }) {
            Ok(selected) => selected,
            Err(error) => {
                return Err(Box::new(owned::PreparationFailure::new(
                    FinalizeContext {
                        search_authorization: audit_search_authorization,
                        command,
                        agent_request_id,
                        broker_request_id,
                        policy_generation,
                        identity,
                        service,
                        action,
                        upstream_resource_ownership: None,
                        resource_scopes: scopes,
                        credential_mode: audit_credential_mode,
                        matched_grant: Some(policy.matched_grant),
                        source,
                        execution_context: Some(execution_context.clone()),
                        redact_error_resource_scopes: lookup_scopes_before_policy,
                        personal_lookup_connection: personal_lookup_connection.clone(),
                        started,
                    },
                    Err(error),
                )));
            }
        };

        let resource_binding = if action_descriptor.requires_resource_attributes {
            action_descriptor.resource_scope.as_ref().and_then(|scope| {
                let resource_type = service_descriptor
                    .as_ref()?
                    .resource_scopes
                    .get(scope)?
                    .resource_type
                    .clone();
                let targets = scopes.get(scope)?;
                if targets.len() != 1 {
                    return None;
                }
                policy_snapshot
                    .resource_catalog
                    .attribute_bindings
                    .iter()
                    .find(|binding| {
                        binding.resource_type == resource_type
                            && binding.selector_value == targets[0]
                    })
                    .cloned()
            })
        } else {
            None
        };
        let admitted = agent_access_provider::host::admitted_request(
            agent_access_provider::host::AdmittedRequestParts {
                service: service.clone(),
                action: action.clone(),
                execution_context: execution_context.as_str().to_owned(),
                identity: InvocationIdentity::new(
                    identity.principal.clone(),
                    identity.authenticated,
                ),
                correlation: correlation.clone(),
                credential_mode,
                authority,
                inputs: request.inputs,
                execution: credentials,
                lookup_access,
            },
        );
        Ok(PreparedInvocation {
            resource_binding,
            provider,
            domain_reasons,
            request: admitted,
            body_parts: request.body_parts,
            state: provider_state,
            response_options,
            body_part_specs: Vec::new(),
            finalize_context: FinalizeContext {
                search_authorization: audit_search_authorization,
                command,
                agent_request_id,
                broker_request_id,
                policy_generation,
                identity,
                service,
                action,
                upstream_resource_ownership,
                resource_scopes: scopes,
                credential_mode: audit_credential_mode,
                matched_grant: Some(policy.matched_grant),
                source,
                execution_context: Some(execution_context),
                redact_error_resource_scopes: lookup_scopes_before_policy,
                personal_lookup_connection: personal_lookup_connection.clone(),
                started,
            },
        })
    }

    pub async fn authorize_body_parts(
        &self,
        mut prepared: PreparedInvocation,
    ) -> Result<PreparedInvocation, Box<BrokerResponse<Value>>> {
        let context = prepared.request.context().clone();
        let result = with_provider_context(
            context.correlation().clone(),
            context.service().to_owned(),
            context.action().to_owned(),
            run_provider_hook(
                agent_access_provider::host::hook_context(
                    context.service(),
                    context.action(),
                    HookPhase::BodyAdmission,
                    prepared.domain_reasons,
                ),
                prepared
                    .provider
                    .authorize_body_parts(&prepared.request, prepared.state.as_ref()),
            ),
        )
        .await;
        match result {
            Ok(admission) => {
                let (body_part_specs, disposition) = admission.into_parts();
                prepared.state = disposition.apply(prepared.state.take());
                prepared.body_part_specs = body_part_specs;
                Ok(prepared)
            }
            Err(error) => Err(Box::new(
                self.finalize(prepared.finalize_context, Err(error)).await,
            )),
        }
    }

    pub async fn fail_prepared_invoke(
        &self,
        prepared: PreparedInvocation,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        self.finalize(prepared.finalize_context, Err(error)).await
    }

    pub async fn finish_prepared_invoke(
        &self,
        prepared: PreparedInvocation,
        body_parts: Vec<BrokerBodyPart>,
    ) -> BrokerResponse<Value> {
        self.finish_prepared_invoke_with_stream_requirement(prepared, body_parts, false)
            .await
    }

    async fn finish_prepared_invoke_with_stream_requirement(
        &self,
        prepared: PreparedInvocation,
        body_parts: Vec<BrokerBodyPart>,
        require_stream: bool,
    ) -> BrokerResponse<Value> {
        let (context, result) = self
            .execute_prepared_invoke(prepared, body_parts, require_stream)
            .await;
        self.finalize(context, result).await
    }

    async fn execute_prepared_invoke(
        &self,
        prepared: PreparedInvocation,
        body_parts: Vec<BrokerBodyPart>,
        require_stream: bool,
    ) -> (FinalizeContext, Result<ProviderResult, ProviderError>) {
        let PreparedInvocation {
            resource_binding,
            provider,
            domain_reasons,
            request,
            body_parts: _,
            state,
            response_options,
            body_part_specs: _,
            finalize_context,
        } = prepared;
        let correlation = request.correlation().clone();
        let service = request.service().to_owned();
        let action = request.action().to_owned();
        let execution_context = finalize_context.execution_context.clone();
        // A command import runs through its command hook, and its call waits
        // for a budget permit before the final checks; until its hook is
        // called, no process has started.
        let command_call = self.command_provider(&service).is_some();
        let mut command_started = false;
        // Staging happens before the final invocation exists: the body is
        // already consumed, then the revision fences run and only the admitted
        // resource's attributes are decrypted.
        let result = with_provider_context(correlation, service.clone(), action.clone(), async {
            let command = self
                .command_dispatch(&service, finalize_context.started)
                .await?;
            let mut resource_attributes = ResourceAttributes::default();
            if self
                .action_descriptor(&service, &action)
                .is_some_and(|descriptor| descriptor.requires_resource_attributes)
            {
                let unavailable = || {
                    ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "configured resource is unavailable or changed; resolve it again",
                    )
                };
                let binding = resource_binding.as_ref().ok_or_else(unavailable)?;
                let context = execution_context.as_ref().ok_or_else(unavailable)?;
                let store = self.managed_store.as_ref().ok_or_else(unavailable)?;
                let ring = self.credential_key_ring.as_ref().ok_or_else(unavailable)?;
                let values = store
                    .resolve_resource_attributes(binding, context.as_str(), ring)
                    .map_err(|_| unavailable())?;
                self.validate_resource_attributes(
                    &binding.resource_type,
                    &ResourceSelector::Exact {
                        value: binding.selector_value.clone(),
                    },
                    &values,
                    true,
                )
                .map_err(|_| {
                    ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "resource configuration is not allowed by the current backend",
                    )
                })?;
                resource_attributes = values;
            }
            // Access lent at preparation may have been revoked, superseded, or
            // expired while the request body was admitted.
            if let Some(delegated) = request.execution().delegated() {
                delegated.revalidate().await?;
            }
            if !self.imported_action_available(&service, &action) {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "imported service changed or is unavailable; repeat discovery",
                ));
            }
            let hook = agent_access_provider::host::hook_context(
                &service,
                &action,
                HookPhase::Invocation,
                domain_reasons,
            );
            let result = match command {
                Some(command_dispatch::CommandDispatch {
                    provider: command_provider,
                    permit,
                    deadline,
                }) => {
                    let invocation = self
                        .command_invocation(permit, deadline, &request, &finalize_context)
                        .await?;
                    #[cfg(any(test, feature = "test-support"))]
                    crate::test_support::pause_command_dispatch(&service).await;
                    // Building the request awaited the store; the import must
                    // still dispatch before its credentials reach the command.
                    // Dropping the invocation zeroizes its request and returns
                    // its slot.
                    if !self.imported_action_available(&service, &action) {
                        return Err(ProviderError::deny(
                            ReasonCode::ServiceActionDenied,
                            "imported service changed or is unavailable; repeat discovery",
                        ));
                    }
                    command_started = true;
                    run_provider_hook(hook.clone(), command_provider.invoke_command(invocation))
                        .await?
                }
                None => {
                    run_provider_hook(
                        hook.clone(),
                        provider.invoke(agent_access_provider::host::invocation(
                            request,
                            body_parts,
                            resource_attributes,
                            state,
                        )),
                    )
                    .await?
                }
            };
            Ok(checked_result_stream(result, hook))
        })
        .await;
        let result = result.map_err(|error| {
            if command_call {
                self.command_failure(&service, &action, error, command_started, &finalize_context)
            } else {
                error
            }
        });
        let result = result.and_then(|result| {
            if !require_stream
                || result
                    .stream
                    .as_ref()
                    .is_some_and(ProviderResultStream::is_ready)
            {
                return Ok(result);
            }
            Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "provider result stream was not available",
            ))
        });
        let result = if require_stream {
            result
        } else {
            present_provider_outcome(
                self.action_presentation(&service, &action).as_ref(),
                response_options,
                self.presentation_body_limit(&service),
                self.config.limits.max_upstream_response_bytes,
                result,
            )
        };
        (finalize_context, result)
    }

    fn action_presentation(&self, service: &str, action: &str) -> Option<ActionPresentation> {
        self.services
            .get(service)
            .and_then(|descriptor| descriptor.action(action))
            .and_then(|action| action.presentation)
    }

    /// The domain reasons `service`'s native backend registered; none for an
    /// imported service.
    fn service_domain_reasons(
        &self,
        service: &str,
    ) -> &'static [&'static ProviderReasonDefinition] {
        self.config
            .providers
            .registry()
            .get(service)
            .map_or(&[], BackendRegistration::domain_reasons)
    }

    fn presentation_body_limit(&self, service: &str) -> u64 {
        self.services
            .get(service)
            .and_then(|descriptor| descriptor.presentation_body_limit)
            .unwrap_or(self.config.limits.max_upstream_response_bytes)
    }

    fn select_policy(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
        scopes: &ResourceScopes,
    ) -> Result<PolicyDecision, ProviderError> {
        let candidates = self
            .policy_candidates_for_action(
                policy_snapshot,
                identity,
                execution_context,
                service,
                action,
            )
            .into_iter()
            .filter(|candidate| candidate_authorizes_scopes(candidate, scopes))
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy denied service action for resolved scopes",
            ));
        }
        let top_band = top_policy_band(candidates);
        let credential_mode = single_policy_credential_mode(&top_band)?;
        if !self.action_supports_mode(service, action, &credential_mode) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not supported by this action",
            ));
        }
        self.check_action_credential_eligibility(service, action, &credential_mode, identity)?;
        if !credential_mode_available(
            &self.effective_credentials,
            service,
            &credential_mode,
            self.services
                .get(service)
                .map(|descriptor| &descriptor.credentials),
        ) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            ));
        }
        let selected = &top_band[0];
        Ok(PolicyDecision {
            credential_mode,
            matched_grant: matched_grant_audit(policy_snapshot, selected),
        })
    }

    fn plan_search_authorization(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Result<SearchAuthorizationPlan, ProviderError> {
        let scope_type = self
            .action_descriptor(service, action)
            .filter(|descriptor| {
                matches!(
                    descriptor.native_search,
                    Some(
                        NativeSearchEnforcement::UpstreamConstrained
                            | NativeSearchEnforcement::ResultFiltered
                    )
                )
            })
            .and_then(|descriptor| descriptor.resource_scope.clone())
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "search authorization is not supported for this service",
                )
            })?;
        let candidates = self.policy_candidates_for_action(
            policy_snapshot,
            identity,
            execution_context,
            service,
            action,
        );

        if candidates.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy denied search action",
            ));
        }
        let top_band = top_policy_band(candidates);
        let credential_mode = single_policy_credential_mode(&top_band)?;
        if !self.action_supports_mode(service, action, &credential_mode) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not supported by this action",
            ));
        }
        self.check_action_credential_eligibility(service, action, &credential_mode, identity)?;
        if !credential_mode_available(
            &self.effective_credentials,
            service,
            &credential_mode,
            self.services
                .get(service)
                .map(|descriptor| &descriptor.credentials),
        ) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            ));
        }

        let scope = top_band
            .iter()
            .fold(SearchAuthorizationScope::empty(), |scope, candidate| {
                scope.union(&search_scope_from_boundary(&candidate.boundary))
            });
        if scope.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy search boundary has no currently authorized resources",
            ));
        }

        let matched_grants = top_band
            .iter()
            .map(|candidate| matched_grant_audit(policy_snapshot, candidate))
            .collect::<Vec<_>>();

        Ok(SearchAuthorizationPlan {
            scope_type,
            scope,
            credential_mode,
            matched_grants,
        })
    }

    /// The resource scope an action is authorized against, with its type.
    /// Descriptor scopes are checked against the resource type registry when
    /// the generation is built. Should a scope's type ever be missing, the
    /// scope still binds a type that matches nothing, so the action stays
    /// scoped and denies instead of becoming unscoped.
    fn action_resource_scope(&self, service: &str, action: &str) -> Option<ActionResourceScope> {
        let (scope, binding) = self.services.get(service)?.action_resource_scope(action)?;
        Some(ActionResourceScope {
            scope: scope.to_string(),
            resource_type: self
                .resource_types
                .get(&binding.resource_type)
                .cloned()
                .unwrap_or_else(|| Arc::new(UNRESOLVED_RESOURCE_TYPE.clone())),
        })
    }

    fn action_resource_type(&self, service: &str, action: &str) -> Option<ResourceType> {
        self.action_resource_scope(service, action)
            .map(|scope| scope.resource_type.id().clone())
    }

    fn policy_candidates_for_action(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Vec<PolicyCandidate> {
        if !self.imported_action_available(service, action) {
            return Vec::new();
        }
        let resource_scope = self.action_resource_scope(service, action);
        policy_snapshot
            .grants
            .iter()
            .filter_map(|grant| {
                let rank = subject_rank(&grant.subject, identity)?;
                if grant.service != service
                    || !grant.actions.iter().any(|item| item == action)
                    || !grant.execution_contexts.contains(execution_context)
                    || (resource_scope.is_none() && !grant.resources.is_empty())
                {
                    return None;
                }
                let boundary = resource_scope.as_ref().map_or_else(
                    ResourceBoundary::default,
                    |resource_scope| {
                        policy_snapshot.resources.resolve(
                            &grant.resources,
                            resource_scope.resource_type.id(),
                            execution_context.as_str(),
                        )
                    },
                );
                if resource_scope.is_some() && boundary.is_empty() {
                    return None;
                }
                Some(PolicyCandidate {
                    subject: grant.subject.clone(),
                    credential_mode: grant.credential_mode.clone(),
                    explicit_priority: grant.priority,
                    priority: grant.priority.unwrap_or(0),
                    subject_rank: rank,
                    order: grant.order,
                    subject_order: grant.subject_order,
                    config_index: grant.toml_index(),
                    grant_id: grant.managed_id().map(ToString::to_string),
                    grant_version: grant.managed_version(),
                    resources: grant.resources.clone(),
                    resource_scope: resource_scope.clone(),
                    boundary,
                    execution_contexts: grant.execution_contexts.clone(),
                })
            })
            .collect()
    }

    fn policy_candidates_for_action_across_contexts(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        service: &str,
        action: &str,
    ) -> Vec<PolicyCandidate> {
        self.configured_execution_contexts()
            .iter()
            .flat_map(|context| {
                self.policy_candidates_for_action(
                    policy_snapshot,
                    identity,
                    context,
                    service,
                    action,
                )
            })
            .collect()
    }

    /// Selects the invocation's credential once policy has admitted it. A
    /// per-user delegated (OAuth) credential is acquired here, unless scope
    /// resolution already holds the caller's lease, which execution then
    /// reuses. An invocation without a candidate grant never obtains or
    /// refreshes upstream access.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_execution_credential_after_policy(
        &self,
        descriptor: Option<&CredentialDescriptor>,
        service: &str,
        action: &str,
        credential_mode: &str,
        identity: &IdentityContext,
        correlation: &CorrelationContext,
        pre_scope_lookup: &PreScopeLookup,
    ) -> Result<ExecutionAccess, ProviderError> {
        if matches!(pre_scope_lookup, PreScopeLookup::PerUser(_)) && credential_mode == "service" {
            return Err(policy_planning_drift_error());
        }
        if !descriptor.is_none_or(|descriptor| descriptor.execution_required) {
            return Ok(ExecutionAccess::None);
        }
        if credential_mode == "per_user" {
            if let Some(execution) = pre_scope_lookup.personal_execution() {
                return execution;
            }
            if let Some((_, crate::Selection::OAuth(oauth))) =
                self.personal_selection(service, identity)
            {
                let accepts_delegated =
                    descriptor.is_some_and(|descriptor| descriptor.delegated.is_some());
                return with_provider_context(
                    correlation.clone(),
                    service.to_owned(),
                    action.to_owned(),
                    self.acquire_delegated_credential(
                        service,
                        accepts_delegated,
                        oauth.binding(),
                        identity,
                    ),
                )
                .await
                .map(ExecutionAccess::Delegated);
            }
        }
        self.resolve_execution_credential(service, credential_mode, identity)
            .await
            .map(ExecutionAccess::Static)
    }

    async fn acquire_delegated_credential(
        &self,
        service: &str,
        accepts_delegated: bool,
        binding: crate::OAuthBinding,
        identity: &IdentityContext,
    ) -> Result<DelegatedCredential, ProviderError> {
        if !accepts_delegated {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "service does not accept delegated credentials",
            ));
        }
        if !identity.authenticated {
            return Err(ProviderError::deny(
                ReasonCode::IdentityRequired,
                "delegated credentials require an authenticated identity",
            ));
        }
        let Some(manager) = self.oauth.clone() else {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "delegated OAuth credential is not configured",
            ));
        };
        crate::oauth::ManagedOAuthLease::acquire(
            manager,
            service.to_owned(),
            identity.principal.clone(),
            binding,
        )
        .await
    }

    async fn enforce_invocation_identity_admission(
        &self,
        identity: &IdentityContext,
    ) -> Result<(), ProviderError> {
        if let Some(token_class) = identity
            .source
            .as_ref()
            .and_then(|source| source.token_class.as_ref())
            && token_class != &BrokerTokenClass::AgentInvoke
        {
            return Err(ProviderError::deny(
                ReasonCode::BrokerTokenClassDenied,
                "broker token class cannot invoke provider operations",
            ));
        }
        if !self
            .config
            .managed_store
            .as_ref()
            .is_some_and(|config| config.require_registered_principal_for_invocation)
        {
            return Ok(());
        }
        let store = self.managed_store.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::ManagedStoreUnavailable,
                "managed store is not configured",
            )
        })?;
        let principal = identity.principal.clone();
        managed_store_blocking(move || store.active_principal(&principal).map(|_| ()))
            .await
            .map_err(|error| match error {
                ManagedStoreError::PrincipalNotFound => ProviderError::deny(
                    ReasonCode::PrincipalRequired,
                    "managed principal is required",
                ),
                other => provider_error_from_managed_store(other),
            })
    }

    #[cfg(test)]
    fn enforce_agent_invoke_token_caveats(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        execution_context: &ExecutionContext,
    ) -> Result<(), ProviderError> {
        let parsed = parsed_agent_invoke_token_caveats(identity)?;
        self.enforce_agent_invoke_token_caveats_with(
            parsed.as_ref(),
            service,
            action,
            execution_context,
        )
    }

    /// The one rule an `agent_invoke` ceiling applies to an action, shared
    /// by invocation, Git admission, discovery and resource previews. It
    /// runs before grant selection and never removes grants, so it cannot
    /// change which grant wins for an action it permits.
    fn agent_invoke_action_refusal(
        &self,
        parsed: &ParsedAgentInvokeTokenCaveats<'_>,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Option<AgentInvokeRefusal> {
        if !parsed.permits_execution_context(execution_context) {
            return Some(AgentInvokeRefusal::ExecutionContext);
        }
        if parsed.read_only_access && !self.action_is_read_only(service, action) {
            return Some(AgentInvokeRefusal::ReadOnly);
        }
        let caveats = &parsed.caveats;
        if caveats
            .allowed_services
            .as_ref()
            .is_some_and(|services| !services.iter().any(|allowed| allowed == service))
        {
            return Some(AgentInvokeRefusal::Service);
        }
        caveats
            .service_restrictions
            .as_ref()
            .and_then(|restrictions| restrictions.get(service))
            .is_some_and(|restriction| !restriction.actions.iter().any(|allowed| allowed == action))
            .then_some(AgentInvokeRefusal::Action)
    }

    /// Whether the ceiling permits the action: [`Self::agent_invoke_action_refusal`]
    /// as a predicate.
    fn agent_invoke_permits_action(
        &self,
        parsed: &ParsedAgentInvokeTokenCaveats<'_>,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> bool {
        self.agent_invoke_action_refusal(parsed, execution_context, service, action)
            .is_none()
    }

    /// Whether the runtime catalog classifies the action as a read this host
    /// serves. A missing descriptor or an unserved I/O kind is not a read.
    fn action_is_read_only(&self, service: &str, action: &str) -> bool {
        self.served_action_descriptor(service, action)
            .is_some_and(|descriptor| descriptor.read_only)
    }

    /// The runtime catalog descriptor of an action whose I/O kind this host
    /// serves; invocation admits no other.
    fn served_action_descriptor(&self, service: &str, action: &str) -> Option<&ActionDescriptor> {
        self.action_descriptor(service, action)
            .filter(|descriptor| crate::api::supported_action_io(&descriptor.io))
    }

    fn enforce_agent_invoke_token_caveats_with(
        &self,
        parsed: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        service: &str,
        action: &str,
        execution_context: &ExecutionContext,
    ) -> Result<(), ProviderError> {
        let Some(parsed) = parsed else {
            return Ok(());
        };
        let message =
            match self.agent_invoke_action_refusal(parsed, execution_context, service, action) {
                None => return Ok(()),
                Some(AgentInvokeRefusal::ExecutionContext) => {
                    return Err(execution_context_denial(parsed, execution_context));
                }
                Some(AgentInvokeRefusal::ReadOnly) => {
                    return Err(read_only_access_denial(service, action));
                }
                Some(AgentInvokeRefusal::Service) => {
                    "broker token is not allowed to invoke this service"
                }
                Some(AgentInvokeRefusal::Action) => {
                    "broker token is not allowed to invoke this service action"
                }
            };
        Err(token_caveat_denial(
            parsed.token_id,
            service,
            action,
            message,
        ))
    }

    pub fn admit_agent_invoke_token_operation(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        execution_context: &ExecutionContext,
        resource_scopes: &ResourceScopes,
    ) -> Result<(), ProviderError> {
        let parsed = parsed_agent_invoke_token_caveats(identity)?;
        let snapshot = self.policy_snapshot();
        self.enforce_agent_invoke_token_caveats_with(
            parsed.as_ref(),
            service,
            action,
            execution_context,
        )?;
        self.enforce_agent_invoke_token_resource_caveats_with(
            &snapshot,
            execution_context,
            parsed.as_ref(),
            service,
            action,
            resource_scopes,
        )
    }

    #[cfg(test)]
    fn enforce_agent_invoke_token_resource_caveats(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        resource_scopes: &ResourceScopes,
    ) -> Result<(), ProviderError> {
        let parsed = parsed_agent_invoke_token_caveats(identity)?;
        let snapshot = self.policy_snapshot();
        self.enforce_agent_invoke_token_resource_caveats_with(
            &snapshot,
            &ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
            parsed.as_ref(),
            service,
            action,
            resource_scopes,
        )
    }

    fn token_resource_boundary(
        &self,
        policy_snapshot: &PolicySnapshot,
        execution_context: &ExecutionContext,
        caveats: &AgentInvokeTokenCaveats,
        service: &str,
        action: &str,
    ) -> Option<ResourceBoundary> {
        let selection = caveats
            .service_restrictions
            .as_ref()?
            .get(service)?
            .resources
            .as_ref()?;
        Some(self.action_resource_type(service, action).map_or_else(
            ResourceBoundary::default,
            |resource_type| {
                policy_snapshot.resources.resolve(
                    selection,
                    &resource_type,
                    execution_context.as_str(),
                )
            },
        ))
    }

    fn enforce_agent_invoke_token_resource_caveats_with(
        &self,
        policy_snapshot: &PolicySnapshot,
        execution_context: &ExecutionContext,
        parsed: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        service: &str,
        action: &str,
        resource_scopes: &ResourceScopes,
    ) -> Result<(), ProviderError> {
        let Some(parsed) = parsed else {
            return Ok(());
        };
        let Some(boundary) = self.token_resource_boundary(
            policy_snapshot,
            execution_context,
            &parsed.caveats,
            service,
            action,
        ) else {
            return Ok(());
        };
        let ActionResourceScope {
            scope,
            resource_type,
        } = self.action_resource_scope(service, action).ok_or_else(|| {
            token_caveat_denial(
                parsed.token_id,
                service,
                action,
                "token resource restriction cannot apply to this action",
            )
        })?;
        let values = resource_scopes
            .get(&scope)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "token-restricted resource scope could not be resolved",
                )
            })?;
        if values
            .iter()
            .any(|value| !resource_type.is_canonical_target(value))
        {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "resolved resource scope is not canonical",
            ));
        }
        if !values.iter().all(|value| boundary.matches(value)) {
            return Err(token_caveat_denial(
                parsed.token_id,
                service,
                action,
                "broker token is not allowed to invoke the resolved resource",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn intersect_agent_invoke_token_search_authorization(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        search_authorization: &mut SearchAuthorizationPlan,
    ) -> Result<(), ProviderError> {
        let parsed = parsed_agent_invoke_token_caveats(identity)?;
        let snapshot = self.policy_snapshot();
        self.intersect_agent_invoke_token_search_authorization_with(
            &snapshot,
            &ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
            parsed.as_ref(),
            service,
            action,
            search_authorization,
        )
    }

    fn intersect_agent_invoke_token_search_authorization_with(
        &self,
        policy_snapshot: &PolicySnapshot,
        execution_context: &ExecutionContext,
        parsed: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        service: &str,
        action: &str,
        search_authorization: &mut SearchAuthorizationPlan,
    ) -> Result<(), ProviderError> {
        let Some(parsed) = parsed else {
            return Ok(());
        };
        let Some(boundary) = self.token_resource_boundary(
            policy_snapshot,
            execution_context,
            &parsed.caveats,
            service,
            action,
        ) else {
            return Ok(());
        };
        let narrowed = search_authorization
            .scope
            .intersection(&search_scope_from_boundary(&boundary));
        if narrowed.is_empty() {
            return Err(token_caveat_denial(
                parsed.token_id,
                service,
                action,
                "broker token search boundary has no currently authorized resources",
            ));
        }
        search_authorization.scope = narrowed;
        Ok(())
    }

    pub fn admit_agent_invoke_execution_context(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
    ) -> Result<(), ProviderError> {
        let parsed = parsed_agent_invoke_token_caveats(identity).map_err(|_| {
            ProviderError::deny(
                ReasonCode::ExecutionContextDenied,
                "broker token caveats are invalid",
            )
        })?;
        self.admit_agent_invoke_execution_context_with(parsed.as_ref(), execution_context)
    }

    fn admit_agent_invoke_execution_context_with(
        &self,
        parsed: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        execution_context: &ExecutionContext,
    ) -> Result<(), ProviderError> {
        match parsed {
            Some(parsed) if !parsed.permits_execution_context(execution_context) => {
                Err(execution_context_denial(parsed, execution_context))
            }
            _ => Ok(()),
        }
    }

    async fn resolve_execution_credential(
        &self,
        service: &str,
        credential_mode: &str,
        identity: &IdentityContext,
    ) -> Result<ExecutionCredential, ProviderError> {
        if self.imported_catalog.service(service).is_some() {
            return self
                .resolve_imported_execution_credential(service, credential_mode, identity)
                .await;
        }
        let credential = match credential_mode {
            "service" => self.effective_credentials.service.get(service),
            "per_user" => self.effective_credentials.per_user.get(service),
            _ => None,
        }
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            )
        })?;
        if credential.kind == "connection" {
            return self.resolve_connection_token(service, identity).await;
        }
        load_execution_credential(service, credential_mode, credential, Some(identity))
    }

    async fn finalize(
        &self,
        context: FinalizeContext,
        result: Result<ProviderResult, ProviderError>,
    ) -> BrokerResponse<Value> {
        self.finalize_with_append_mode(context, result, AuditAppendMode::Normal)
            .await
    }

    async fn finalize_with_append_mode(
        &self,
        context: FinalizeContext,
        result: Result<ProviderResult, ProviderError>,
        append_mode: AuditAppendMode,
    ) -> BrokerResponse<Value> {
        let FinalizeContext {
            search_authorization,
            command,
            agent_request_id,
            broker_request_id,
            policy_generation,
            identity,
            service,
            action,
            upstream_resource_ownership,
            resource_scopes,
            credential_mode,
            matched_grant,
            source,
            execution_context,
            redact_error_resource_scopes,
            personal_lookup_connection,
            started,
        } = context;
        let upstream_resource_ownership = upstream_resource_ownership
            .or_else(|| self.action_upstream_resource_ownership(&service, &action));
        let internal_diagnostic_code = result
            .as_ref()
            .err()
            .and_then(|error| error.internal_diagnostic_code);
        let result = result.map_err(|mut error| {
            if let Some(ownership) = upstream_resource_ownership {
                add_upstream_resource_ownership_hint(&mut error, ownership);
            }
            error
        });
        let (
            status,
            envelope,
            provider_audit,
            upstream_status,
            upstream_duration_ms,
            object_ids,
            stream,
        ) = match result {
            Ok(result) => (
                200,
                ResponseEnvelope {
                    agent_request_id: agent_request_id.clone(),
                    broker_request_id: broker_request_id.clone(),
                    decision: Decision::Allow,
                    service: service.clone(),
                    action: action.clone(),
                    resource_scopes: resource_scopes.clone(),
                    reason_code: None,
                    reason: None,
                    result: Some(result.result),
                    error: None,
                },
                result.audit,
                result.upstream_status,
                result.upstream_duration_ms,
                result.object_ids,
                result.stream,
            ),
            Err(error) => {
                let reason_code = error.reason_code();
                let status = reason_code.http_status();
                let decision = error.decision();
                let error_body = (decision != Decision::Allow).then(|| crate::ErrorBody {
                    message: error.message.clone(),
                });
                let provider_audit = error.audit.map(|value| *value);
                let upstream_status = error.upstream_status;
                let upstream_duration_ms = error.upstream_duration_ms;
                let object_ids = error.object_ids.map(|value| *value);
                let envelope_resource_scopes = if redact_error_resource_scopes {
                    ResourceScopes::new()
                } else {
                    resource_scopes.clone()
                };
                (
                    status,
                    ResponseEnvelope {
                        agent_request_id: agent_request_id.clone(),
                        broker_request_id: broker_request_id.clone(),
                        decision,
                        service: service.clone(),
                        action: action.clone(),
                        resource_scopes: envelope_resource_scopes,
                        reason_code: Some(reason_code.into()),
                        reason: Some(error.message.clone()),
                        result: error.result.map(|value| *value),
                        error: error_body,
                    },
                    provider_audit,
                    upstream_status,
                    upstream_duration_ms,
                    object_ids,
                    None,
                )
            }
        };

        // Revisions belong to the admitted host snapshot, not upstream tool metadata
        // or a later store read. Apply them after either provider outcome, with
        // a command import's process facts and admitted authority, which a host
        // interruption must not discard either.
        let provider_audit = if let Some(imported) = self.imported_catalog.service(&service) {
            let revisions = json!({
                "catalogRevision": self.imported_catalog.revision,
                "serviceVersion": imported.version,
                "actionVersion": imported.actions.iter()
                    .find(|record| record.definition.action == action)
                    .map(|record| record.version),
            });
            let mut audit = provider_audit.unwrap_or_else(|| json!({}));
            if !audit.is_object() {
                audit = json!({"providerAudit": audit});
            }
            if let Some(fields) = audit.as_object_mut() {
                fields.insert("importedService".into(), revisions);
                if let Some(command) = &command {
                    fields.insert("command".into(), command.audit());
                    fields.insert("commandAuthorization".into(), command.authorization_audit());
                }
            }
            Some(audit)
        } else {
            provider_audit
        };
        let credential_connection = self.audit_credential_connection(
            &service,
            credential_mode.as_deref(),
            command.as_ref(),
            personal_lookup_connection,
        );
        let mut audit_record = AuditRecord {
            search_authorization,
            timestamp: Utc::now().to_rfc3339(),
            agent_request_id: agent_request_id.clone(),
            broker_request_id: broker_request_id.clone(),
            config_generation: self.config_generation,
            policy_generation: Some(policy_generation),
            principal_subject: identity.principal_subject,
            principal: identity.principal,
            groups: identity.groups,
            service,
            action,
            resource_scopes,
            matched_grant,
            credential_mode: credential_mode.map(Some),
            credential_connection,
            decision: envelope.decision.clone(),
            reason_code: envelope.reason_code.clone(),
            upstream_status,
            upstream_duration_ms,
            object_ids,
            identity_source: identity.source,
            caller_id: identity.caller_id,
            source,
            execution_context,
            provider_audit,
        };
        let stream =
            stream.map(|stream| limited_download(stream, self.config.limits.max_download_bytes));
        let mut terminal_permit = None;
        let stream_needs_terminal_audit = stream
            .as_ref()
            .is_some_and(ProviderResultStream::is_streaming);
        if stream_needs_terminal_audit {
            match self.audit.reserve_terminal().await {
                Ok(permit) => {
                    terminal_permit = Some(permit);
                    audit_record.provider_audit =
                        stream_started_audit_value(audit_record.provider_audit.take());
                }
                Err(error) => {
                    emit_audit_append_failed(
                        &audit_record,
                        self.node_id(),
                        ReasonCode::AuditUnavailable.http_status(),
                        &error,
                        internal_diagnostic_code,
                    );
                    return audit_unavailable_response(
                        agent_request_id,
                        broker_request_id,
                        envelope.service,
                        envelope.action,
                        envelope.resource_scopes,
                        error,
                    );
                }
            }
        }

        match append_mode {
            AuditAppendMode::Normal | AuditAppendMode::OwnedTerminal(_) => {
                let appended = match append_mode {
                    AuditAppendMode::OwnedTerminal(permit) => {
                        permit.append_required(audit_record.clone()).await
                    }
                    _ => self.audit.append_required(audit_record.clone()).await,
                };
                if let Err(error) = appended {
                    emit_audit_append_failed(
                        &audit_record,
                        self.node_id(),
                        ReasonCode::AuditUnavailable.http_status(),
                        &error,
                        internal_diagnostic_code,
                    );
                    return audit_unavailable_response(
                        agent_request_id,
                        broker_request_id,
                        envelope.service,
                        envelope.action,
                        envelope.resource_scopes,
                        error,
                    );
                }
            }
            AuditAppendMode::GatewayTerminal(terminal) => {
                let phase = if status == 200 && audit_record.decision == Decision::Allow {
                    "completed"
                } else {
                    "failed"
                };
                audit_record.provider_audit =
                    gateway_terminal_audit_value(audit_record.provider_audit.take(), phase, None);
                terminal.finish_record(audit_record.clone());
            }
        }
        let duration_ms = elapsed_millis(started);
        record_span_from_audit(&audit_record, status);
        if stream_needs_terminal_audit {
            emit_invoke_stream_started(&audit_record, status, duration_ms);
        } else {
            emit_invoke_completed(&audit_record, status, duration_ms, internal_diagnostic_code);
        }

        let stream = stream.map(|stream| {
            if let Some(permit) = terminal_permit {
                let registry = Arc::clone(&self.audit_registry);
                stream.map_byte_stream(|inner| {
                    Box::pin(TerminalAuditStream::new(
                        inner,
                        permit,
                        audit_record,
                        registry,
                    ))
                })
            } else {
                stream
            }
        });

        BrokerResponse {
            retry_after_seconds: None,
            status,
            envelope,
            stream,
        }
    }
}

fn git_discovery_verification_url(
    gateway: &GatewayConfig,
    repository: &str,
) -> Result<Url, ProviderError> {
    let mut url = Url::parse(&gateway.upstream_base_url).map_err(|_| {
        ProviderError::error(
            ReasonCode::GatewayUpstreamDenied,
            "gateway upstream base URL is invalid",
        )
    })?;
    let mut path_segments = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut repository_segments = repository
        .split('/')
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if let Some(last) = repository_segments.last_mut()
        && !last.ends_with(".git")
    {
        last.push_str(".git");
    }
    path_segments.extend(repository_segments);
    path_segments.push("info".to_string());
    path_segments.push("refs".to_string());
    url.set_path("");
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            ProviderError::error(
                ReasonCode::GatewayUpstreamDenied,
                "gateway upstream base URL cannot be a base",
            )
        })?;
        segments.extend(path_segments.iter().map(String::as_str));
    }
    url.set_query(Some("service=git-upload-pack"));
    Ok(url)
}

fn normalize_git_verification_repository(
    repository: Option<&str>,
) -> Result<String, ProviderError> {
    let repository = repository
        .map(str::trim)
        .filter(|repository| !repository.is_empty())
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "git credential verification requires repository",
            )
        })?;
    if !agent_access_provider::is_repository_selector_path(repository) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    let mut segments = repository
        .split('/')
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if segments[..segments.len().saturating_sub(1)]
        .iter()
        .any(|segment| segment.ends_with(".git"))
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    if let Some(last) = segments.last_mut()
        && let Some(stripped) = last.strip_suffix(".git")
    {
        *last = stripped.to_string();
    }
    let repository = segments.join("/");
    if !agent_access_provider::is_repository_selector_path(&repository) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    Ok(repository)
}

fn git_verify_reqwest_error_to_provider_error(
    error: reqwest::Error,
    upstream_url: &Url,
    repository: &str,
    egress_proxy: Value,
) -> ProviderError {
    let reason_code = if error.is_timeout() {
        ReasonCode::UpstreamTimeout
    } else if error.is_connect() {
        ReasonCode::UpstreamConnectionFailed
    } else {
        ReasonCode::UpstreamFailed
    };
    let mut audit = git_verification_audit_without_status(upstream_url, egress_proxy);
    audit["git"] = json!({
        "operation": "upload-pack-discovery",
        "repository": repository,
    });
    ProviderError::error(reason_code, "git upstream credential verification failed")
        .with_audit(audit)
}

fn git_verify_timeout_error_to_provider_error(
    upstream_url: &Url,
    repository: &str,
    egress_proxy: Value,
) -> ProviderError {
    let mut audit = git_verification_audit_without_status(upstream_url, egress_proxy);
    audit["git"] = json!({
        "operation": "upload-pack-discovery",
        "repository": repository,
    });
    ProviderError::error(
        ReasonCode::UpstreamTimeout,
        "git upstream credential verification timed out",
    )
    .with_audit(audit)
}

fn git_verify_status_error(status: u16) -> ProviderError {
    match status {
        401 => ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "git upstream rejected the selected credential",
        ),
        403 => ProviderError::error(
            ReasonCode::UpstreamForbidden,
            "git upstream forbids the selected credential",
        ),
        404 => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "git repository was not found or unavailable",
        ),
        _ => ProviderError::error(
            ReasonCode::UpstreamFailed,
            "git upstream credential verification failed",
        ),
    }
}

const GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES: usize = 1024;

async fn git_upload_pack_discovery_response_is_valid(
    mut response: reqwest::Response,
    read_timeout: Duration,
) -> Result<bool, ProviderError> {
    if !git_upload_pack_discovery_content_type_is_valid(response.headers()) {
        return Ok(false);
    }
    let mut prefix = Vec::new();
    while prefix.len() < GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES {
        let chunk = match timeout(read_timeout, response.chunk()).await {
            Ok(result) => result.map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "git upstream discovery response could not be read",
                )
            })?,
            Err(_) => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "git upstream discovery response timed out",
                ));
            }
        };
        let Some(chunk) = chunk else {
            return Ok(false);
        };
        if chunk.is_empty() {
            return Ok(false);
        }
        let remaining = GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES - prefix.len();
        prefix.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        match git_upload_pack_advertisement_prefix(&prefix) {
            GitAdvertisementPrefix::Valid => return Ok(true),
            GitAdvertisementPrefix::Invalid => return Ok(false),
            GitAdvertisementPrefix::NeedMore => {}
        }
    }
    Ok(false)
}

fn git_upload_pack_discovery_content_type_is_valid(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter()
        .any(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                .is_some_and(|value| {
                    value.eq_ignore_ascii_case("application/x-git-upload-pack-advertisement")
                })
        })
}

enum GitAdvertisementPrefix {
    NeedMore,
    Valid,
    Invalid,
}

fn git_upload_pack_advertisement_prefix(prefix: &[u8]) -> GitAdvertisementPrefix {
    if prefix.len() < 4 {
        return GitAdvertisementPrefix::NeedMore;
    }
    let Ok(length_hex) = std::str::from_utf8(&prefix[..4]) else {
        return GitAdvertisementPrefix::Invalid;
    };
    let Ok(length) = usize::from_str_radix(length_hex, 16) else {
        return GitAdvertisementPrefix::Invalid;
    };
    if length < 4 {
        return GitAdvertisementPrefix::Invalid;
    }
    if length > GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES {
        return GitAdvertisementPrefix::Invalid;
    }
    if prefix.len() < length {
        return GitAdvertisementPrefix::NeedMore;
    }
    let payload = &prefix[4..length];
    if payload == b"# service=git-upload-pack\n" {
        GitAdvertisementPrefix::Valid
    } else {
        GitAdvertisementPrefix::Invalid
    }
}

fn git_verification_audit(
    upstream_url: &Url,
    repository: &str,
    egress_proxy: Value,
    upstream_status: u16,
) -> Value {
    let mut audit = git_verification_audit_without_status(upstream_url, egress_proxy);
    audit["gateway"]["upstreamStatus"] = json!(upstream_status);
    audit["git"] = json!({
        "operation": "upload-pack-discovery",
        "repository": repository,
    });
    audit
}

fn git_verification_audit_without_status(upstream_url: &Url, egress_proxy: Value) -> Value {
    json!({
        "gateway": {
            "kind": "git_http",
            "operation": "credential.verify",
            "method": "GET",
            "upstreamOrigin": upstream_url.origin().ascii_serialization(),
            "upstreamPath": upstream_url.path(),
            "egressProxy": egress_proxy,
            "responseBytes": 0,
        },
    })
}

/// Every provider-backed service enters the runtime through this one path, so
/// a service ID can never be silently replaced or shadow a configured gateway.
fn register_service_provider(
    provider_map: &mut BTreeMap<String, ServiceProvider>,
    config: &BrokerConfig,
    provider: ServiceProvider,
) -> Result<(), RuntimeError> {
    let service = provider.descriptor.service.clone();
    let duplicate = if provider_map.contains_key(&service) {
        Some(format!(
            "service {service} is registered by more than one provider"
        ))
    } else if config.gateways.contains_key(&service) {
        Some(format!(
            "service {service} is registered by a provider and also configured as gateways.{service}"
        ))
    } else {
        None
    };
    if let Some(error) = duplicate {
        return Err(RuntimeError::Config(ConfigError::Invalid {
            errors: vec![error],
        }));
    }
    provider_map.insert(service, provider);
    Ok(())
}

/// Descriptors for every configured service in one generation: the ones
/// registered providers are paired with, plus configured gateways. Each
/// descriptor is validated once here and then shared by admission,
/// discovery, and catalog projection.
/// The other owner of an imported service identity, if any, named for a
/// diagnostic: the reserved control-plane namespace, a selected native kind
/// (configured or not), a gateway, another configured service, a configured
/// credential or a configured credential connection, whose ID shares the
/// namespace of token rows and credential rights. Every retained import is
/// checked, whatever its status or adapter availability.
pub(crate) fn imported_service_collision(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    name: &str,
) -> Option<String> {
    if name == "broker" {
        return Some("the reserved broker control-plane namespace".into());
    }
    if config.providers.registry().get(name).is_some() {
        return Some(format!("the selected native provider kind {name}"));
    }
    if config.gateways.contains_key(name) {
        return Some(format!("gateways.{name}"));
    }
    if services.contains_key(name) {
        return Some(format!("the configured service {name}"));
    }
    if config.credentials.connections.contains_key(name) {
        return Some(format!("credentials.connections.{name}"));
    }
    [
        ("credentials.service", &config.credentials.service),
        ("credentials.per_user", &config.credentials.per_user),
        ("credentials.lookup", &config.credentials.lookup),
    ]
    .into_iter()
    .find(|(_, credentials)| credentials.contains_key(name))
    .map(|(mode, _)| format!("{mode}.{name}"))
}

fn build_service_descriptors(
    config: &BrokerConfig,
    providers: &BTreeMap<String, ServiceProvider>,
    resource_types: &EffectiveResourceTypes,
) -> Result<BTreeMap<String, Arc<ServiceDescriptor>>, RuntimeError> {
    let mut services = BTreeMap::new();
    let mut errors = Vec::new();
    for (service, provider) in providers {
        if let Err(descriptor_errors) = provider.descriptor.validate() {
            errors.extend(descriptor_errors);
        }
        if let Err(descriptor_errors) = provider.descriptor.validate_builtin_mcp_names() {
            errors.extend(descriptor_errors);
        }
        services.insert(service.clone(), Arc::new(provider.descriptor.clone()));
    }
    for (service, gateway) in &config.gateways {
        if let Some(descriptor) = gateway_service_descriptor(service, gateway) {
            services.insert(service.clone(), Arc::new(descriptor));
        }
    }
    for descriptor in services.values() {
        errors.extend(descriptor.validate_resource_types(resource_types.registry()));
    }
    crate::validate_private_resource_consumers(config, &services, resource_types, &mut errors);
    if errors.is_empty() {
        Ok(services)
    } else {
        Err(RuntimeError::Config(ConfigError::Invalid { errors }))
    }
}

pub(crate) fn gateway_service_descriptor(
    service: &str,
    gateway: &GatewayConfig,
) -> Option<ServiceDescriptor> {
    if gateway.kind != "git_http" {
        return None;
    }
    let git_action = |action: &str, description: &str| {
        ActionDescriptor::new(
            action,
            description,
            json!({
                "type": "object",
                "additionalProperties": false
            }),
        )
        .scope("repository")
        .credential_modes(gateway.credential_modes.iter().cloned())
    };
    let mut actions = Vec::new();
    if gateway.git.as_ref().is_some_and(|git| git.allow_fetch) {
        actions.push(
            git_action(
                "repo.fetch",
                "Fetch from a Git repository through the broker gateway",
            )
            .read_only(),
        );
    }
    if gateway.git.as_ref().is_some_and(|git| git.allow_push) {
        actions.push(git_action(
            "repo.push",
            "Push to a Git repository through the broker gateway",
        ));
    }
    let per_user = gateway
        .credential_modes
        .iter()
        .any(|mode| mode == "per_user");
    // Verifying a Git credential reads one repository's refs. A personal
    // credential connection may also select OAuth, whose access the gateway
    // presents like a token.
    let credentials = if per_user {
        CredentialDescriptor::default()
            .verification_input("repository")
            .profile("git-basic-api-token", "basic_api_token")
            .profile("git-bearer-token", "bearer_token")
            .delegated(if gateway.git.as_ref().is_some_and(|git| git.allow_push) {
                "Lets agents fetch and push Git repositories as your account."
            } else {
                "Lets agents fetch Git repositories as your account."
            })
    } else {
        CredentialDescriptor::default().verification_input("repository")
    };
    Some(
        ServiceDescriptor::new(service, gateway.display_name.clone())
            .with_surface(ServiceSurface::Gateway {
                kind: gateway.kind.clone(),
                broker_hosts: gateway.broker_hosts.clone(),
            })
            .with_resource_scopes(BTreeMap::from([(
                "repository".to_string(),
                ResourceScopeCapabilities::new(
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
                    vec![
                        "exact".to_string(),
                        "namespace".to_string(),
                        "all".to_string(),
                    ],
                ),
            )]))
            .with_actions(actions)
            .with_credentials(credentials),
    )
    .map(
        |descriptor| match UpstreamAuthority::from_base_url(&gateway.upstream_base_url) {
            Ok(authority) => descriptor.with_upstream_authority(authority),
            Err(_) => descriptor,
        },
    )
}

fn toml_identity_groups(config: &BrokerConfig, principal: &str) -> (Vec<String>, Vec<String>) {
    let mut raw_groups = BTreeSet::new();
    let mut policy_groups = BTreeSet::new();
    for group in &config.identity.groups {
        if group.members.iter().any(|member| member == principal) {
            raw_groups.insert(group.id.clone());
            if group.status == "active" {
                policy_groups.insert(group.id.clone());
            }
        }
    }
    (
        raw_groups.into_iter().collect(),
        policy_groups.into_iter().collect(),
    )
}

fn sorted_unique(values: Vec<String>) -> Vec<String> {
    BTreeSet::from_iter(values).into_iter().collect()
}

fn prepare_upload_spool(limits: &crate::LimitsConfig) -> Result<(), RuntimeError> {
    let path = Path::new(&limits.upload_spool_dir);
    fs_permissions::ensure_private_dir(path).map_err(|source| RuntimeError::UploadSpool {
        path: path.display().to_string(),
        source,
    })?;
    for entry in fs::read_dir(path).map_err(|source| RuntimeError::UploadSpool {
        path: path.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| RuntimeError::UploadSpool {
            path: path.display().to_string(),
            source,
        })?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(stale_upload_spool_file_name)
        {
            fs::remove_file(entry.path()).map_err(|source| RuntimeError::UploadSpool {
                path: entry.path().display().to_string(),
                source,
            })?;
        }
    }
    check_upload_spool_writable(limits)
}

fn load_managed_store(
    config: &BrokerConfig,
    reload: bool,
) -> Result<Option<ManagedStore>, RuntimeError> {
    let Some(managed_store) = &config.managed_store else {
        return Ok(None);
    };
    let mode = if reload {
        ManagedStoreOpenMode::Reload
    } else {
        ManagedStoreOpenMode::Startup
    };
    ManagedStore::open(managed_store, mode)
        .map(Some)
        .map_err(runtime_managed_store_error)
}

fn prepare_managed_admin_roles(
    config: &BrokerConfig,
    store: Option<&ManagedStore>,
    local_password_hasher: Option<&LocalPasswordHasher>,
    allow_initial_bootstrap: bool,
) -> Result<(), RuntimeError> {
    if !config.management.enabled {
        return Ok(());
    }
    let Some(store) = store else {
        return Ok(());
    };
    let principal_count = store
        .principal_count()
        .map_err(runtime_managed_store_error)?;
    if config.management.initial_admin.mode == "create_if_empty" && principal_count == 0 {
        if !allow_initial_bootstrap {
            return Err(RuntimeError::ManagedStore{message:"initial administrator bootstrap requires startup; reload cannot provision an empty store".into()});
        }
        let hasher = local_password_hasher.ok_or_else(|| RuntimeError::ManagedStore {
            message: "initial admin bootstrap requires local password hasher".to_string(),
        })?;
        let principal_id = config
            .management
            .initial_admin
            .principal_id
            .clone()
            .ok_or_else(|| {
                RuntimeError::Config(ConfigError::Invalid {
                    errors: vec![
                    "management.initial_admin.principal_id is required when mode is create_if_empty"
                        .to_string(),
                ],
                })
            })?;
        let password = config
            .management
            .initial_admin
            .initial_password
            .clone()
            .ok_or_else(|| RuntimeError::Config(ConfigError::Invalid {
                errors: vec![
                    "management.initial_admin.initial_password is required when mode is create_if_empty"
                        .to_string(),
                ],
            }))?;
        store
            .bootstrap_initial_admin(
                hasher,
                InitialAdminBootstrapRequest {
                    principal_id: principal_id.clone(),
                    password,
                    min_password_length: config.browser_auth.local_password.min_password_length,
                },
            )
            .map_err(runtime_managed_store_error)?;
        tracing::info!(
            principal_id = %principal_id,
            "Initial admin principal created: {principal_id}. Open /ui and sign in with the configured temporary password. Password reset is required."
        );
        return Ok(());
    }
    if principal_count > 0
        && store
            .active_admin_principal_count()
            .map_err(runtime_managed_store_error)?
            == 0
    {
        if classless_admin_bootstrap_available(config) {
            tracing::warn!(
                "managed store has principals but no active DB admin; classless configured admin bootstrap remains enabled"
            );
        } else {
            return Err(RuntimeError::ManagedStore {
                message: "managed store has principals but no active DB admin; enable classless admin bootstrap or recover an admin role".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_managed_policy_subjects(
    config: &BrokerConfig,
    store: Option<&ManagedStore>,
) -> Result<(), RuntimeError> {
    if config.identity.authority != "managed" || config.policy.authority != "toml" {
        return Ok(());
    }
    let Some(store) = store else {
        return Err(RuntimeError::ManagedStore {
            message: "managed identity policy admission requires managed store".to_string(),
        });
    };

    let mut errors = Vec::new();
    for (grant_index, grant) in config.policy.grants.iter().enumerate() {
        for (subject_index, subject) in grant.subjects.iter().enumerate() {
            if subject == "user:anonymous" || subject == "group:anonymous" {
                continue;
            }
            let label = format!("policy.grants[{grant_index}].subjects[{subject_index}]");
            if let Some(principal) = subject.strip_prefix("user:") {
                match store.principal(principal) {
                    Ok(_) => {}
                    Err(
                        ManagedStoreError::PrincipalRequired | ManagedStoreError::PrincipalNotFound,
                    ) => {
                        errors.push(format!(
                            "{label} user:{principal} does not reference an existing managed principal"
                        ));
                    }
                    Err(error) => return Err(runtime_managed_store_error(error)),
                }
            } else if let Some(group) = subject.strip_prefix("group:") {
                match store.group(group) {
                    Ok(_) => {}
                    Err(ManagedStoreError::GroupNotFound) => {
                        errors.push(format!(
                            "{label} group:{group} does not reference an existing managed group"
                        ));
                    }
                    Err(error) => return Err(runtime_managed_store_error(error)),
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Config(ConfigError::Invalid { errors }))
    }
}

fn load_policy_snapshot(
    config: &BrokerConfig,
    store: Option<&ManagedStore>,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    imported: &crate::ImportedCatalog,
    resource_types: &ResourceTypeRegistry,
) -> Result<PolicySnapshot, RuntimeError> {
    if config.policy.authority == "toml" {
        return Ok(PolicySnapshot::from_config(config, 0));
    }

    let Some(store) = store else {
        return Err(RuntimeError::ManagedStore {
            message: "managed policy authority requires managed store".to_string(),
        });
    };
    let state = store
        .load_policy_snapshot()
        .map_err(runtime_managed_store_error)?;
    let subjects = store
        .policy_subject_catalog()
        .map_err(runtime_managed_store_error)?;
    resource_management::validate_attribute_bindings(resource_types, &state.catalog)
        .map_err(runtime_managed_store_error)?;
    validate_managed_policy_grants(
        config,
        &subjects,
        services,
        imported,
        resource_types,
        &state.active_grants,
        &state.catalog,
    )?;
    Ok(PolicySnapshot::from_managed(
        state.revision.generation,
        state.active_grants,
        state.catalog,
    ))
}

fn validate_managed_policy_grants(
    config: &BrokerConfig,
    subjects: &ManagedPolicySubjectCatalog,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    imported: &crate::ImportedCatalog,
    resource_types: &ResourceTypeRegistry,
    grants: &[ManagedPolicyGrantRecord],
    resources: &ManagedResourceCatalog,
) -> Result<(), RuntimeError> {
    let issues = managed_policy_validation_issues(
        config,
        subjects,
        services,
        imported,
        resource_types,
        grants,
        resources,
    );
    if issues.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Config(ConfigError::Invalid {
            errors: issues.into_iter().map(|issue| issue.message).collect(),
        }))
    }
}

fn managed_policy_validation_issues(
    config: &BrokerConfig,
    subjects: &ManagedPolicySubjectCatalog,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    imported: &crate::ImportedCatalog,
    resource_types: &ResourceTypeRegistry,
    grants: &[ManagedPolicyGrantRecord],
    resources: &ManagedResourceCatalog,
) -> Vec<PolicyValidationIssue> {
    let mut config_with_resources = config.clone();
    config_with_resources.policy.resources = resources.resources.clone();
    config_with_resources.policy.resource_groups = resources.resource_groups.clone();
    let config = &config_with_resources;
    let mut errors = Vec::new();

    for grant in grants {
        let label = managed_policy_grant_label(grant);
        if grant.grant_id.trim().is_empty() {
            errors.push(policy_validation_issue(
                "grantId",
                "grant_invalid",
                "managed policy grant id must not be empty",
            ));
        }
        if grant.grant_order < 0 {
            errors.push(policy_validation_issue(
                "grantOrder",
                "grant_invalid",
                format!("{label} grantOrder must be greater than or equal to 0"),
            ));
        }
        if grant.version < 1 {
            errors.push(policy_validation_issue(
                "version",
                "grant_invalid",
                format!("{label} version must be greater than or equal to 1"),
            ));
        }
        errors.extend(validate_managed_policy_grant_subjects(
            &label,
            &grant.status,
            &grant.subjects,
            subjects,
        ));
    }

    let catalog = services;
    let normalized_grants = grants
        .iter()
        .flat_map(|grant| {
            let label = managed_policy_grant_label(grant);
            let normalized_subjects = if grant.subjects.is_empty() {
                vec![(0, "__subjectless_disabled__")]
            } else {
                grant
                    .subjects
                    .iter()
                    .enumerate()
                    .map(|(subject_index, subject)| (subject_index, subject.as_str()))
                    .collect::<Vec<_>>()
            };
            normalized_subjects
                .into_iter()
                .map(move |(subject_index, subject)| NormalizedPolicyGrant {
                    service_label: format!("{label} service"),
                    actions_label: format!("{label} actions"),
                    credential_mode_label: format!("{label} credentialMode"),
                    execution_contexts_label: format!("{label} executionContexts"),
                    label: format!("{label} subjects[{subject_index}]"),
                    subject_field: format!("subjects[{subject_index}]"),
                    subject,
                    service: &grant.service,
                    actions: &grant.actions,
                    resources: &grant.resources,
                    execution_contexts: grant.execution_contexts.clone(),
                    credential_mode: &grant.credential_mode,
                    priority: grant.priority,
                })
        })
        .collect::<Vec<_>>();
    let normalized_errors = normalized_policy_grant_validation_issues(
        config,
        catalog,
        imported,
        resource_types,
        &normalized_grants,
    );
    errors.extend(
        normalized_errors
            .into_iter()
            .map(managed_policy_normalized_issue),
    );

    errors
}

fn managed_policy_grant_label(grant: &ManagedPolicyGrantRecord) -> String {
    format!("managed policy grant {}", grant.grant_id)
}

fn policy_validation_issue(
    field: impl Into<String>,
    code: impl Into<String>,
    message: impl Into<String>,
) -> PolicyValidationIssue {
    PolicyValidationIssue {
        field: field.into(),
        code: code.into(),
        message: message.into(),
    }
}

fn validate_managed_policy_grant_subjects(
    label: &str,
    grant_status: &str,
    grant_subjects: &[String],
    subjects: &ManagedPolicySubjectCatalog,
) -> Vec<PolicyValidationIssue> {
    let mut issues = Vec::new();
    if grant_subjects.is_empty() {
        if grant_status == "active" {
            issues.push(policy_validation_issue(
                "subjects",
                "empty",
                format!("{label} active grants must have at least one subject"),
            ));
        }
        return issues;
    }
    if grant_subjects.len() > crate::POLICY_GRANT_MAX_SUBJECTS {
        issues.push(policy_validation_issue(
            "subjects",
            "too_many",
            format!(
                "{label} subjects must contain at most {} entries",
                crate::POLICY_GRANT_MAX_SUBJECTS
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, subject) in grant_subjects.iter().enumerate() {
        if !seen.insert(subject) {
            issues.push(policy_validation_issue(
                format!("subjects[{index}]"),
                "subject_duplicate",
                format!("{label} subjects[{index}] duplicates an earlier subject"),
            ));
            continue;
        }
        if let Some(issue) = validate_managed_policy_grant_subject(
            &format!("{label} subjects[{index}]"),
            &format!("subjects[{index}]"),
            subject,
            subjects,
        ) {
            issues.push(issue);
        }
    }
    issues
}

fn validate_managed_policy_grant_subject(
    label: &str,
    field: &str,
    subject: &str,
    subjects: &ManagedPolicySubjectCatalog,
) -> Option<PolicyValidationIssue> {
    if subject.trim().is_empty() || subject.chars().any(char::is_control) {
        return Some(policy_validation_issue(
            field,
            "subject_invalid",
            format!("{label} must be a non-empty non-control string"),
        ));
    }
    if subject == "user:anonymous" || subject == "group:anonymous" {
        return None;
    }
    if let Some(principal) = subject.strip_prefix("user:") {
        if !is_safe_principal(principal) {
            return Some(policy_validation_issue(
                field,
                "subject_invalid",
                format!("{label} has an invalid user principal"),
            ));
        }
        if !subjects.principals.contains(principal) {
            return Some(policy_validation_issue(
                field,
                "subject_not_found",
                format!(
                    "{label} user:{principal} does not reference an existing managed principal"
                ),
            ));
        }
    } else if let Some(group) = subject.strip_prefix("group:") {
        if !is_safe_identifier(group) {
            return Some(policy_validation_issue(
                field,
                "subject_invalid",
                format!("{label} has an invalid group"),
            ));
        }
        if !subjects.groups.contains(group) {
            return Some(policy_validation_issue(
                field,
                "subject_not_found",
                format!("{label} group:{group} does not reference an existing managed group"),
            ));
        }
    } else {
        return Some(policy_validation_issue(
            field,
            "subject_invalid",
            format!("{label} must start with user: or group:"),
        ));
    }
    None
}

fn managed_policy_normalized_issue(
    issue: NormalizedPolicyGrantValidationIssue,
) -> PolicyValidationIssue {
    let field = match issue.field {
        NormalizedPolicyGrantIssueField::Grant => "grant".to_string(),
        NormalizedPolicyGrantIssueField::Subject => issue
            .subject_field
            .unwrap_or_else(|| "subjects".to_string()),
        NormalizedPolicyGrantIssueField::Service => "service".to_string(),
        NormalizedPolicyGrantIssueField::Actions => "actions".to_string(),
        NormalizedPolicyGrantIssueField::CredentialMode => "credentialMode".to_string(),
        NormalizedPolicyGrantIssueField::ExecutionContexts => "executionContexts".to_string(),
        NormalizedPolicyGrantIssueField::Resources => "resources".to_string(),
    };
    policy_validation_issue(field, issue.code, issue.message)
}

fn classless_admin_bootstrap_available(config: &BrokerConfig) -> bool {
    config.management.allow_classless_admin_identities
        && (!config.management.admin_principals.is_empty()
            || !config.management.admin_groups.is_empty())
}

fn runtime_managed_store_error(error: ManagedStoreError) -> RuntimeError {
    RuntimeError::ManagedStore {
        message: format!("{} ({:?})", error, error.reason_code()),
    }
}

async fn managed_store_blocking<T, F>(operation: F) -> Result<T, ManagedStoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ManagedStoreError> + Send + 'static,
{
    // Keep the store work in the caller's span for log correlation.
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || span.in_scope(operation))
        .await
        .map_err(|error| {
            ManagedStoreError::Unavailable(format!("managed store task failed: {error}"))
        })?
}

fn check_upload_spool_writable(limits: &crate::LimitsConfig) -> Result<(), RuntimeError> {
    let dir = Path::new(&limits.upload_spool_dir);
    fs_permissions::ensure_private_dir(dir).map_err(|source| RuntimeError::UploadSpool {
        path: dir.display().to_string(),
        source,
    })?;
    let probe = dir.join(format!(
        "{}readiness-{}-{}",
        upload_spool_file_prefix(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        Uuid::new_v4()
    ));
    fs_permissions::open_private_create_new(&probe)
        .and_then(|mut file| file.write_all(b"ok"))
        .map_err(|source| RuntimeError::UploadSpool {
            path: probe.display().to_string(),
            source,
        })?;
    fs::remove_file(&probe).map_err(|source| RuntimeError::UploadSpool {
        path: probe.display().to_string(),
        source,
    })
}

fn stale_upload_spool_file_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(UPLOAD_SPOOL_FILE_PREFIX) else {
        return false;
    };
    let Some((pid, _suffix)) = rest.split_once('-') else {
        return true;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return true;
    };
    !process_is_live(pid)
}

#[cfg(target_os = "linux")]
fn process_is_live(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_live(pid: u32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // POSIX `kill(pid, 0)` performs existence/permission checks without sending a signal.
    unsafe { kill(pid, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1) }
}

#[cfg(not(any(unix, target_os = "linux")))]
fn process_is_live(pid: u32) -> bool {
    pid == std::process::id()
}

#[derive(Debug)]
struct ResolvedTokenIdentity {
    principal: String,
    principal_kind: Option<crate::PrincipalKind>,
    subject: Option<String>,
    groups: Vec<String>,
    policy_groups: Vec<String>,
    token_class: Option<BrokerTokenClass>,
    token_id: Option<String>,
    token_scopes: Option<Value>,
}

enum TokenExtraction {
    NoHeader,
    Token(String),
}

enum SourceResolution {
    NoMatch,
    Resolved(ResolvedTokenIdentity),
}

struct IdentitySourceResolver {
    audit: IdentitySourceAudit,
    resolver: IdentitySourceResolverKind,
}

enum IdentitySourceResolverKind {
    Static(StaticPrincipalsSource),
    BrokerTokens(BrokerTokensSource),
}

impl IdentitySourceResolver {
    fn extract_token(&self, headers: &HeaderMap) -> Result<TokenExtraction, IdentityFailure> {
        let Some(raw) = headers.get(self.audit.token_header.as_str()) else {
            return Ok(TokenExtraction::NoHeader);
        };
        let raw = raw.to_str().map_err(|_| IdentityFailure::Invalid)?;
        let token = if self.audit.token_scheme == "Bearer" {
            let Some(token) = raw.strip_prefix("Bearer ") else {
                return Err(IdentityFailure::Invalid);
            };
            token.trim().to_string()
        } else {
            raw.trim().to_string()
        };
        if token.is_empty() {
            return Err(IdentityFailure::Invalid);
        }
        Ok(TokenExtraction::Token(token))
    }

    fn resolve(&self, token: &str) -> Result<SourceResolution, IdentityFailure> {
        match &self.resolver {
            IdentitySourceResolverKind::Static(source) => source.resolve(token),
            IdentitySourceResolverKind::BrokerTokens(source) => source.resolve(token),
        }
    }

    fn check_ready(&self) -> Result<(), RuntimeError> {
        match &self.resolver {
            IdentitySourceResolverKind::Static(_) => Ok(()),
            IdentitySourceResolverKind::BrokerTokens(source) => source.check_ready(),
        }
    }

    fn audit(&self, resolved: &ResolvedTokenIdentity) -> IdentitySourceAudit {
        let mut audit = self.audit.clone();
        audit.token_class = resolved.token_class.clone();
        audit.token_id = resolved.token_id.clone();
        audit.token_scopes = resolved.token_scopes.clone();
        audit
    }
}

struct StaticPrincipalsSource {
    tokens: BTreeMap<String, StaticPrincipalIdentity>,
    /// The managed store, whose principal row for a static principal's ID
    /// supplies its kind.
    store: Option<ManagedStore>,
}

impl StaticPrincipalsSource {
    /// A configured static principal carries the kind of the active managed
    /// principal with its ID, as classless management resolves it, and none
    /// without one. A store that cannot answer fails the resolution.
    fn resolve(&self, token: &str) -> Result<SourceResolution, IdentityFailure> {
        let Some(identity) = self.tokens.get(token) else {
            return Ok(SourceResolution::NoMatch);
        };
        let principal_kind = match &self.store {
            Some(store) => store
                .static_principal_kind(&identity.principal)
                .map_err(|_| IdentityFailure::Unavailable)?,
            None => None,
        };
        Ok(SourceResolution::Resolved(ResolvedTokenIdentity {
            principal: identity.principal.clone(),
            principal_kind,
            subject: Some(identity.principal.clone()),
            groups: Vec::new(),
            policy_groups: Vec::new(),
            token_class: None,
            token_id: None,
            token_scopes: None,
        }))
    }
}

struct StaticPrincipalIdentity {
    principal: String,
}

#[derive(Clone)]
struct BrokerTokensSource {
    store: ManagedStore,
    hasher: BrokerTokenHasher,
    execution_context: Option<crate::ExecutionContextConfig>,
}

impl BrokerTokensSource {
    fn resolve(&self, token: &str) -> Result<SourceResolution, IdentityFailure> {
        if !token.starts_with("aab_") {
            return Ok(SourceResolution::NoMatch);
        }
        let identity = self
            .store
            .resolve_broker_token(&self.hasher, token)
            .map_err(|error| match error {
                ManagedStoreError::BrokerTokenNotFound => IdentityFailure::BrokerTokenNotFound,
                ManagedStoreError::BrokerTokenExpired => IdentityFailure::BrokerTokenExpired,
                ManagedStoreError::BrokerTokenPaused => IdentityFailure::BrokerTokenPaused,
                ManagedStoreError::BrokerTokenRevoked => IdentityFailure::BrokerTokenRevoked,
                ManagedStoreError::PrincipalRequired | ManagedStoreError::PrincipalNotFound => {
                    IdentityFailure::PrincipalRequired
                }
                ManagedStoreError::PrincipalDisabled => IdentityFailure::PrincipalDisabled,
                _ => IdentityFailure::Invalid,
            })?;
        let token_class = identity.token_class;
        let token_scopes = if token_class == BrokerTokenClass::AgentInvoke {
            normalized_stored_agent_invoke_caveats(
                &identity.scopes,
                self.execution_context.as_ref(),
            )?
        } else {
            identity.scopes
        };
        Ok(SourceResolution::Resolved(ResolvedTokenIdentity {
            principal: identity.principal_id,
            principal_kind: identity.principal_kind,
            subject: None,
            groups: identity.groups,
            policy_groups: identity.policy_groups,
            token_class: Some(token_class),
            token_id: Some(identity.token_id),
            token_scopes: Some(token_scopes),
        }))
    }

    fn check_ready(&self) -> Result<(), RuntimeError> {
        self.store
            .check_schema_ready()
            .map_err(runtime_managed_store_error)
    }
}

fn normalized_stored_agent_invoke_caveats(
    scopes: &Value,
    execution_context: Option<&crate::ExecutionContextConfig>,
) -> Result<Value, IdentityFailure> {
    let caveats = AgentInvokeTokenCaveats::parse_stored(scopes)
        .and_then(|caveats| {
            caveats.validate_configured_context_membership(execution_context)?;
            Ok(caveats)
        })
        .map_err(|_| IdentityFailure::Invalid)?;
    Ok(caveats.to_scopes_value())
}

fn load_identity_sources(
    config: &BrokerConfig,
    managed_store: Option<ManagedStore>,
    broker_token_hasher: Option<BrokerTokenHasher>,
) -> Result<Vec<IdentitySourceResolver>, RuntimeError> {
    let mut sources = Vec::new();
    let mut loaded_static_tokens = BTreeSet::new();
    for source in &config.identity.sources {
        let audit = IdentitySourceAudit {
            read_only_access: None,
            namespace: None,
            binding_id: None,
            name: source.name.clone(),
            kind: source.kind.clone(),
            token_header: source.header.clone(),
            token_scheme: source.scheme.clone(),
            token_class: None,
            token_id: None,
            token_scopes: None,
        };
        match source.kind.as_str() {
            "static_principals" => {
                let mut tokens = BTreeMap::new();
                for principal in &source.principals {
                    for token_ref in &principal.token_refs {
                        let token = load_secret_ref_value(
                            &format!(
                                "identity.sources.{}.principals.{}.token_refs",
                                source.name, principal.principal
                            ),
                            token_ref,
                        )?;
                        if token.is_empty() {
                            return Err(RuntimeError::Config(ConfigError::Invalid {
                                errors: vec![format!(
                                    "identity.sources.{}.principals.{}.token_refs must resolve to non-empty secrets",
                                    source.name, principal.principal
                                )],
                            }));
                        }
                        if !loaded_static_tokens.insert(token.clone()) {
                            return Err(RuntimeError::Config(ConfigError::Invalid {
                                errors: vec![format!(
                                    "identity.sources.{}.principals.{}.token_refs contains a duplicate resolved token value",
                                    source.name, principal.principal
                                )],
                            }));
                        }
                        tokens.insert(
                            token,
                            StaticPrincipalIdentity {
                                principal: principal.principal.clone(),
                            },
                        );
                    }
                }
                sources.push(IdentitySourceResolver {
                    audit,
                    resolver: IdentitySourceResolverKind::Static(StaticPrincipalsSource {
                        tokens,
                        store: managed_store.clone(),
                    }),
                });
            }
            "broker_tokens" => {
                let store = managed_store.clone().ok_or_else(|| {
                    RuntimeError::Config(ConfigError::Invalid {
                        errors: vec![
                            "managed_store is required when an identity source uses broker_tokens"
                                .to_string(),
                        ],
                    })
                })?;
                let hasher = broker_token_hasher.clone().ok_or_else(|| {
                    RuntimeError::Config(ConfigError::Invalid {
                        errors: vec![
                            "broker_tokens.hash_key_ref is required when an identity source uses broker_tokens"
                                .to_string(),
                        ],
                    })
                })?;
                sources.push(IdentitySourceResolver {
                    audit,
                    resolver: IdentitySourceResolverKind::BrokerTokens(BrokerTokensSource {
                        store,
                        hasher,
                        execution_context: config.execution_context.clone(),
                    }),
                });
            }
            _ => {}
        }
    }
    Ok(sources)
}

pub(crate) fn preflight_configured_egress_proxies(
    config: &crate::BrokerConfig,
) -> Result<(), RuntimeError> {
    preflight_egress_proxy("network.egress_proxy", config.network.egress_proxy.as_ref())?;
    for backend in config.providers.iter() {
        for (label, proxy) in backend.egress_proxies() {
            preflight_egress_proxy(&label, Some(proxy))?;
        }
    }
    for (service, gateway) in &config.gateways {
        preflight_egress_proxy(
            &format!("gateways.{service}.egress_proxy"),
            gateway.egress_proxy.as_ref(),
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PolicyCandidate {
    subject: String,
    credential_mode: String,
    explicit_priority: Option<i32>,
    priority: i32,
    subject_rank: u8,
    order: usize,
    subject_order: usize,
    config_index: Option<usize>,
    grant_id: Option<String>,
    grant_version: Option<i64>,
    resources: ResourceSelection,
    execution_contexts: Vec<ExecutionContext>,
    resource_scope: Option<ActionResourceScope>,
    boundary: ResourceBoundary,
}

#[derive(Debug, Clone)]
struct ActionResourceScope {
    scope: String,
    resource_type: Arc<ResourceTypeDescriptor>,
}

#[derive(Debug, Clone)]
struct PolicyDecision {
    credential_mode: String,
    matched_grant: MatchedGrantAudit,
}

fn matched_grant_audit(
    policy_snapshot: &PolicySnapshot,
    candidate: &PolicyCandidate,
) -> MatchedGrantAudit {
    MatchedGrantAudit {
        config_index: candidate.config_index,
        grant_id: candidate.grant_id.clone(),
        grant_version: candidate.grant_version,
        policy_generation: Some(policy_snapshot.generation()),
        subject: candidate.subject.clone(),
        priority: candidate.explicit_priority,
        resources: candidate.resources.clone(),
        execution_contexts: candidate.execution_contexts.clone(),
    }
}

fn policy_planning_drift_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "policy lookup planner drifted from final policy selection",
    )
}

fn top_policy_band(mut candidates: Vec<PolicyCandidate>) -> Vec<PolicyCandidate> {
    candidates.sort_by(|left, right| {
        right
            .subject_rank
            .cmp(&left.subject_rank)
            .then_with(|| right.priority.cmp(&left.priority))
            .then_with(|| left.order.cmp(&right.order))
            .then_with(|| left.subject_order.cmp(&right.subject_order))
    });
    let best_rank = candidates[0].subject_rank;
    let best_priority = candidates[0].priority;
    candidates
        .into_iter()
        .filter(|candidate| {
            candidate.subject_rank == best_rank && candidate.priority == best_priority
        })
        .collect()
}

/// The typed credential mode of an admitted policy decision. Policy only
/// selects validated, provisioned modes, so another spelling fails closed.
fn admitted_credential_mode(mode: &str) -> Result<CredentialMode, ProviderError> {
    mode.parse().map_err(|_| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential mode is not provisioned",
        )
    })
}

/// The exact authority an admitted action receives, from its validated
/// contract: a search boundary for search actions, the resolved
/// resources for ordinary scoped actions, and nothing for action-only ones.
/// Policy already required those shapes, so any mismatch fails closed.
fn admitted_authority(
    action: &ActionDescriptor,
    scopes: &ResourceScopes,
    search: Option<SearchAuthorization>,
    command_enforced: bool,
) -> Result<InvocationAuthority, ProviderError> {
    let mismatch = || {
        ProviderError::error(
            ReasonCode::OperationFailed,
            "admitted authority does not match the action contract",
        )
    };
    if command_enforced {
        return match (
            action.native_search,
            action.resource_scope.as_deref(),
            search,
        ) {
            (None, Some(scope), Some(search))
                if search.scope_type == scope
                    && !search.scope.is_empty()
                    && search.scope.exact_projection().is_ok() =>
            {
                Ok(InvocationAuthority::Search(search))
            }
            (None, None, None) if scopes.is_empty() => Ok(InvocationAuthority::ActionOnly),
            _ => Err(mismatch()),
        };
    }
    match (
        action.native_search,
        search,
        action.resource_scope.as_deref(),
    ) {
        (
            Some(
                NativeSearchEnforcement::UpstreamConstrained
                | NativeSearchEnforcement::ResultFiltered,
            ),
            Some(search),
            Some(scope),
        ) if search.scope_type == scope && !search.scope.is_empty() => {
            Ok(InvocationAuthority::Search(search))
        }
        (None, None, Some(scope)) if scopes.get(scope).is_some_and(|values| !values.is_empty()) => {
            Ok(InvocationAuthority::Resources(scopes.clone()))
        }
        (None, None, None) if scopes.is_empty() => Ok(InvocationAuthority::ActionOnly),
        _ => Err(mismatch()),
    }
}

fn single_policy_credential_mode(candidates: &[PolicyCandidate]) -> Result<String, ProviderError> {
    let modes = candidates
        .iter()
        .map(|candidate| candidate.credential_mode.as_str())
        .collect::<BTreeSet<_>>();
    if modes.len() > 1 {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "ambiguous credential mode precedence",
        ));
    }
    Ok(candidates[0].credential_mode.clone())
}

fn subject_rank(subject: &str, identity: &IdentityContext) -> Option<u8> {
    if subject == format!("user:{}", identity.principal) {
        return Some(2);
    }
    subject.strip_prefix("group:").and_then(|group| {
        identity
            .policy_groups
            .iter()
            .any(|candidate| candidate == group)
            .then_some(1)
    })
}

/// Personal credential setup follows authored grant coverage, independently of
/// invocation precedence, resource availability and execution context.
fn has_per_user_setup_grant(
    identity: &IdentityContext,
    service: &ServiceDescriptor,
    grants: &[RuntimePolicyGrant],
) -> bool {
    grants.iter().any(|grant| {
        subject_rank(&grant.subject, identity).is_some()
            && grant.service == service.service
            && grant.credential_mode == "per_user"
            && service.actions.iter().any(|action| {
                grant.actions.contains(&action.action)
                    && action
                        .credential_modes
                        .iter()
                        .any(|mode| mode == "per_user")
            })
    })
}

fn candidate_authorizes_scopes(candidate: &PolicyCandidate, resolved: &ResourceScopes) -> bool {
    let Some(resource_scope) = &candidate.resource_scope else {
        return resolved.is_empty();
    };
    resolved.get(&resource_scope.scope).is_some_and(|values| {
        !values.is_empty()
            && values.iter().all(|value| {
                resource_scope.resource_type.is_canonical_target(value)
                    && candidate.boundary.matches(value)
            })
    })
}

/// The ceiling an `agent_invoke` identity places on its grants: an issued
/// token's caveats, or an attested identity's synthetic caveats plus its
/// path's read-only setting. [`BrokerRuntime::agent_invoke_action_refusal`]
/// is the one rule that judges an action against it.
struct ParsedAgentInvokeTokenCaveats<'a> {
    /// The issued token named in caveat denial audit; attested identities
    /// and proposed (previewed) tokens have none.
    token_id: Option<&'a str>,
    caveats: AgentInvokeTokenCaveats,
    /// Limits the identity to actions the runtime catalog classifies as reads.
    read_only_access: bool,
}

impl ParsedAgentInvokeTokenCaveats<'_> {
    fn permits_execution_context(&self, execution_context: &ExecutionContext) -> bool {
        self.caveats
            .allowed_execution_contexts
            .as_ref()
            .is_none_or(|contexts| contexts.contains(execution_context))
    }
}

fn invalid_agent_invoke_caveats() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "broker token caveats are invalid",
    )
}

fn parsed_agent_invoke_token_caveats(
    identity: &IdentityContext,
) -> Result<Option<ParsedAgentInvokeTokenCaveats<'_>>, ProviderError> {
    let Some(source) = identity.source.as_ref() else {
        return Ok(None);
    };
    if source.token_class.as_ref() != Some(&BrokerTokenClass::AgentInvoke) {
        // An attested identity always carries synthetic agent-invoke caveats;
        // one without them lists nothing and is denied rather than unlimited.
        return match source.read_only_access {
            Some(_) => Err(invalid_agent_invoke_caveats()),
            None => Ok(None),
        };
    }
    let scopes = source
        .token_scopes
        .as_ref()
        .ok_or_else(invalid_agent_invoke_caveats)?;
    AgentInvokeTokenCaveats::parse_stored(scopes)
        .map(|caveats| {
            Some(ParsedAgentInvokeTokenCaveats {
                token_id: source.token_id.as_deref(),
                caveats,
                read_only_access: source.read_only_access == Some(true),
            })
        })
        .map_err(|_| invalid_agent_invoke_caveats())
}

/// Why an `agent_invoke` ceiling refuses an action, before any grant is
/// considered.
enum AgentInvokeRefusal {
    ExecutionContext,
    ReadOnly,
    Service,
    Action,
}

fn token_caveat_denial(
    token_id: Option<&str>,
    service: &str,
    action: &str,
    message: &'static str,
) -> ProviderError {
    ProviderError::deny(ReasonCode::ServiceActionDenied, message).with_audit(json!({
        "brokerToken": {
            "tokenId": token_id,
            "requestedService": service,
            "requestedAction": action
        }
    }))
}

fn execution_context_denial(
    parsed: &ParsedAgentInvokeTokenCaveats<'_>,
    execution_context: &ExecutionContext,
) -> ProviderError {
    ProviderError::deny(
        ReasonCode::ExecutionContextDenied,
        "broker token is not allowed in this execution context",
    )
    .with_audit(json!({
        "brokerToken": {
            "tokenId": parsed.token_id,
            "requestedExecutionContext": execution_context
        }
    }))
}

/// A write refused on a read-only identity path. It names no fingerprint,
/// username or token, and is not an admission failure.
fn read_only_access_denial(service: &str, action: &str) -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "identity access is read-only",
    )
    .with_audit(json!({
        "identityAccess": {
            "readOnly": true,
            "requestedService": service,
            "requestedAction": action
        }
    }))
}

fn load_execution_credential(
    service: &str,
    credential_mode: &str,
    credential: &CredentialConfig,
    identity: Option<&IdentityContext>,
) -> Result<ExecutionCredential, ProviderError> {
    match credential.kind.as_str() {
        "basic_api_token" | "bearer_token" => load_materialized_credential(
            service,
            credential_mode,
            &credential.kind,
            credential.username_ref.as_deref(),
            credential.token_ref.as_deref(),
        ),
        "secret_store" => {
            load_secret_store_credential(service, credential_mode, credential, identity)
        }
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential kind cannot be resolved for execution",
        )),
    }
}

fn load_materialized_credential(
    service: &str,
    credential_mode: &str,
    kind: &str,
    username_ref: Option<&str>,
    token_ref: Option<&str>,
) -> Result<ExecutionCredential, ProviderError> {
    match kind {
        "basic_api_token" => {
            let username =
                load_credential_secret(service, credential_mode, "username_ref", username_ref)?;
            let token = load_credential_secret(service, credential_mode, "token_ref", token_ref)?;
            Ok(agent_access_provider::host::basic_credential(
                username, token,
            ))
        }
        "bearer_token" => Ok(agent_access_provider::host::bearer_credential(
            load_credential_secret(service, credential_mode, "token_ref", token_ref)?,
        )),
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "credential store record has unsupported credential type",
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileSecretStore {
    credentials: Vec<LocalFileSecretRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileSecretRecord {
    principal: Option<String>,
    subject: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    username_ref: Option<String>,
    token_ref: Option<String>,
}

fn load_secret_store_credential(
    service: &str,
    credential_mode: &str,
    credential: &CredentialConfig,
    identity: Option<&IdentityContext>,
) -> Result<ExecutionCredential, ProviderError> {
    if credential_mode != "per_user" {
        return Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "secret_store credentials are supported only for per_user execution",
        ));
    }
    if credential.provider.as_deref() != Some("local_file") {
        return Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "secret_store provider is unsupported",
        ));
    }
    let identity = identity
        .filter(|identity| identity.authenticated)
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "per_user credential requires authenticated identity",
            )
        })?;
    let store = read_local_file_secret_store(credential)?;
    let record = store
        .credentials
        .iter()
        .find(|record| record.principal.as_deref() == Some(identity.principal.as_str()))
        .or_else(|| {
            identity.principal_subject.as_deref().and_then(|subject| {
                store
                    .credentials
                    .iter()
                    .find(|record| record.subject.as_deref() == Some(subject))
            })
        })
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "per_user credential is not provisioned for principal",
            )
        })?;
    validate_secret_store_record(record)?;
    load_materialized_credential(
        service,
        credential_mode,
        &record.kind,
        record.username_ref.as_deref(),
        record.token_ref.as_deref(),
    )
}

fn read_local_file_secret_store(
    credential: &CredentialConfig,
) -> Result<LocalFileSecretStore, ProviderError> {
    let path = credential.path.as_deref().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "secret_store path is not configured",
        )
    })?;
    let body = fs::read_to_string(path).map_err(|_| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "credential store is unavailable",
        )
    })?;
    let store: LocalFileSecretStore = serde_json::from_str(&body).map_err(|_| {
        ProviderError::deny(ReasonCode::CredentialInvalid, "credential store is invalid")
    })?;
    if store.credentials.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "credential store has no credentials",
        ));
    }
    Ok(store)
}

fn validate_secret_store_record(record: &LocalFileSecretRecord) -> Result<(), ProviderError> {
    match (record.principal.as_deref(), record.subject.as_deref()) {
        (Some(principal), _) if !crate::is_safe_principal(principal) => {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "credential store record has invalid principal",
            ));
        }
        (_, Some(subject)) if !crate::is_safe_principal(subject) => {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "credential store record has invalid subject",
            ));
        }
        (None, None) => {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "credential store record requires principal or subject",
            ));
        }
        _ => {}
    }
    match record.kind.as_str() {
        "basic_api_token" | "bearer_token" => Ok(()),
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "credential store record has unsupported credential type",
        )),
    }
}

fn check_credential_ready(
    label: &str,
    service: &str,
    credential_mode: &str,
    credential: &CredentialConfig,
) -> Result<(), RuntimeError> {
    match credential.kind.as_str() {
        "basic_api_token" | "bearer_token" => {
            load_execution_credential(service, credential_mode, credential, None)
                .map(|_| ())
                .map_err(|error| RuntimeError::Credential {
                    label: label.to_string(),
                    message: error.message,
                })
        }
        "secret_store" => check_secret_store_ready(label, credential_mode, credential),
        _ => Err(RuntimeError::Credential {
            label: label.to_string(),
            message: "credential kind is unsupported".to_string(),
        }),
    }
}

fn provider_error_from_managed_store(error: ManagedStoreError) -> ProviderError {
    let reason_code = error.reason_code();
    let message = managed_store_failure_message(&error);
    match reason_code {
        ReasonCode::ManagedStoreUnavailable
        | ReasonCode::ManagedStoreMigrationRequired
        | ReasonCode::EncryptionKeyMissing
        | ReasonCode::EncryptionKeyInvalid
        | ReasonCode::CredentialDecryptFailed
        | ReasonCode::CredentialEncryptFailed => ProviderError::error(reason_code, message),
        _ => ProviderError::deny(reason_code, message),
    }
}

/// The public message for a managed-store failure the host reports, which
/// never carries the store's internal detail.
fn managed_store_failure_message(error: &ManagedStoreError) -> &'static str {
    match error {
        ManagedStoreError::CredentialNotFound => "managed per_user credential is not provisioned",
        ManagedStoreError::CredentialExpired => "managed per_user credential is expired",
        ManagedStoreError::CredentialDecryptFailed => "managed per_user credential cannot decrypt",
        ManagedStoreError::EncryptionKeyMissing(_) => {
            "managed credential encryption key is missing"
        }
        ManagedStoreError::EncryptionKeyInvalid(_) => {
            "managed credential encryption key is invalid"
        }
        ManagedStoreError::PrincipalRequired => "managed principal is required",
        ManagedStoreError::PrincipalNotFound => "managed principal was not found",
        ManagedStoreError::PrincipalDisabled => "managed principal is disabled",
        ManagedStoreError::IdentityBindingConflict => "managed identity binding already exists",
        ManagedStoreError::IdentityVersionConflict => "managed identity version changed",
        ManagedStoreError::IdentityBindingNotFound => "managed identity binding was not found",
        ManagedStoreError::AttestedIdentityDenied => "managed identity assertion is denied",
        ManagedStoreError::SelfServiceDisabled => "self-service is disabled",
        ManagedStoreError::GroupNotFound => "managed group was not found",
        ManagedStoreError::ResourceNotFound => "managed resource was not found",
        ManagedStoreError::ResourceConflict(_) => "managed resource already exists",
        ManagedStoreError::ResourceGroupNotFound => "managed resource group was not found",
        ManagedStoreError::ResourceInUse => "managed resource is still referenced",
        ManagedStoreError::PolicyGrantNotFound => "managed policy grant was not found",
        ManagedStoreError::PolicyAuthorityUnavailable(_) => {
            "managed policy authority is unavailable"
        }
        ManagedStoreError::PolicyManagementServiceMoveDenied => {
            "managed policy grant service move is outside the caller's management scope"
        }
        ManagedStoreError::PolicyValidationFailed(_)
        | ManagedStoreError::PolicyValidationIssues(_) => "managed policy validation failed",
        ManagedStoreError::ReloadInProgress => "managed policy mutation is already in progress",
        ManagedStoreError::PrincipalAlreadyExists => "managed principal already exists",
        ManagedStoreError::VersionConflict => "managed credential version changed",
        ManagedStoreError::Unavailable(_) => "managed credential store is unavailable",
        ManagedStoreError::MigrationRequired | ManagedStoreError::SchemaInvalid(_) => {
            "managed store schema is incompatible; a fresh database is required"
        }
        ManagedStoreError::InputInvalid(_) => "managed credential input is invalid",
        ManagedStoreError::ImportChangeBlocked(_) => "imported service change is blocked",
        ManagedStoreError::CredentialInvalid(_) => "managed per_user credential is invalid",
        ManagedStoreError::CredentialEncryptFailed => {
            "managed per_user credential encryption failed"
        }
        ManagedStoreError::OidcProviderUnavailable | ManagedStoreError::OidcFlowCapacity => {
            "managed identity provider is unavailable"
        }
        ManagedStoreError::OidcFlowInvalid
        | ManagedStoreError::OidcFlowExpired
        | ManagedStoreError::OidcCallbackStale
        | ManagedStoreError::OidcAdmissionDenied => "managed identity authentication failed",
        ManagedStoreError::OidcLoginMethodConflict
        | ManagedStoreError::ExternalGroupBindingConflict => {
            "managed identity configuration conflicts with an existing record"
        }
        ManagedStoreError::ExternalGroupBindingNotFound => {
            "managed external group binding was not found"
        }
        ManagedStoreError::BrokerTokenNotFound
        | ManagedStoreError::BrokerTokenExpired
        | ManagedStoreError::BrokerTokenPaused
        | ManagedStoreError::BrokerTokenRevoked
        | ManagedStoreError::BrokerTokenStateConflict
        | ManagedStoreError::BrokerTokenClassDenied
        | ManagedStoreError::LocalLoginFailed
        | ManagedStoreError::LocalPasswordNotEnabled
        | ManagedStoreError::LocalPasswordAlreadyEnabled
        | ManagedStoreError::LocalLoginLocked
        | ManagedStoreError::LocalPasswordBusy
        | ManagedStoreError::RightMissing => "managed credential authorization failed",
    }
}

fn check_secret_store_ready(
    label: &str,
    credential_mode: &str,
    credential: &CredentialConfig,
) -> Result<(), RuntimeError> {
    if credential_mode != "per_user" {
        return Err(RuntimeError::Credential {
            label: label.to_string(),
            message: "secret_store credentials are supported only for per_user execution"
                .to_string(),
        });
    }
    if credential.provider.as_deref() != Some("local_file") {
        return Err(RuntimeError::Credential {
            label: label.to_string(),
            message: "secret_store provider is unsupported".to_string(),
        });
    }
    let store =
        read_local_file_secret_store(credential).map_err(|error| RuntimeError::Credential {
            label: label.to_string(),
            message: error.message,
        })?;
    for (index, record) in store.credentials.iter().enumerate() {
        validate_secret_store_record(record).map_err(|error| RuntimeError::Credential {
            label: label.to_string(),
            message: error.message,
        })?;
        validate_secret_store_record_refs(label, index, record)?;
    }
    Ok(())
}

fn validate_secret_store_record_refs(
    label: &str,
    index: usize,
    record: &LocalFileSecretRecord,
) -> Result<(), RuntimeError> {
    match record.kind.as_str() {
        "basic_api_token" => {
            validate_secret_store_ref(
                label,
                index,
                "username_ref",
                record.username_ref.as_deref(),
            )?;
            validate_secret_store_ref(label, index, "token_ref", record.token_ref.as_deref())
        }
        "bearer_token" => {
            validate_secret_store_ref(label, index, "token_ref", record.token_ref.as_deref())
        }
        _ => Ok(()),
    }
}

fn validate_secret_store_ref(
    label: &str,
    index: usize,
    field: &str,
    reference: Option<&str>,
) -> Result<(), RuntimeError> {
    let Some(reference) = reference else {
        return Err(RuntimeError::Credential {
            label: label.to_string(),
            message: format!("credential store record {index} missing {field}"),
        });
    };
    if !credential_store_ref_has_supported_scheme(reference) {
        return Err(RuntimeError::Credential {
            label: label.to_string(),
            message: format!(
                "credential store record {index} {field} must use env:NAME or file:/absolute/path"
            ),
        });
    }
    Ok(())
}

fn credential_store_ref_has_supported_scheme(reference: &str) -> bool {
    reference
        .strip_prefix("env:")
        .is_some_and(|name| !name.is_empty())
        || reference
            .strip_prefix("file:")
            .is_some_and(|path| Path::new(path).is_absolute())
}

fn load_credential_secret(
    service: &str,
    credential_mode: &str,
    field: &str,
    reference: Option<&str>,
) -> Result<String, ProviderError> {
    let Some(reference) = reference else {
        return Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential is missing required material",
        ));
    };
    let label = format!("credentials.{credential_mode}.{service}.{field}");
    let value = load_secret_ref_value(&label, reference).map_err(|_| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential material is unavailable",
        )
    })?;
    if value.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential material is empty",
        ));
    }
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BrokerResponse<T> {
    pub status: u16,
    /// Internal HTTP metadata; admission envelopes intentionally contain no result.
    #[serde(skip)]
    pub retry_after_seconds: Option<u64>,
    pub envelope: ResponseEnvelope<T>,
    #[serde(skip)]
    pub stream: Option<ProviderResultStream>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_authorization: Option<SearchAuthorizationPlan>,
    pub timestamp: String,
    pub agent_request_id: String,
    pub broker_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<u64>,
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_subject: Option<String>,
    pub groups: Vec<String>,
    pub service: String,
    pub action: String,
    pub resource_scopes: ResourceScopes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_grant: Option<MatchedGrantAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_mode: Option<Option<String>>,
    /// The credential connection the call's personal credential comes from:
    /// present whenever the selected mode is `per_user`, or a command call
    /// passes a `per_user` grant, even when `credentialMode` is null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_connection: Option<String>,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ids: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<IdentitySourceAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_id: Option<String>,
    pub source: SourceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<ExecutionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_audit: Option<Value>,
}

fn audit_unavailable_response(
    agent_request_id: String,
    broker_request_id: String,
    service: String,
    action: String,
    resource_scopes: ResourceScopes,
    _error: RuntimeError,
) -> BrokerResponse<Value> {
    let reason_code = ReasonCode::AuditUnavailable;
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id,
            decision: Decision::Error,
            service,
            action,
            resource_scopes,
            reason_code: Some(reason_code.into()),
            reason: Some("audit sink unavailable".to_string()),
            result: None,
            error: Some(crate::ErrorBody {
                message: "audit sink unavailable".to_string(),
            }),
        },
        stream: None,
    }
}

#[derive(Clone, Default)]
pub struct AuditRuntimeRegistry {
    inner: Arc<AuditRuntimeRegistryInner>,
}

#[derive(Default)]
struct AuditRuntimeRegistryInner {
    writers: Mutex<Vec<Weak<AuditWriterHandle>>>,
    terminals: Mutex<Vec<Weak<TerminalAuditState>>>,
    gateway_terminals: Mutex<Vec<Weak<GatewayTerminalAuditState>>>,
}

impl AuditRuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn register_writer(&self, writer: &Arc<AuditWriterHandle>) {
        let mut writers = self.inner.writers.lock().unwrap();
        writers.retain(|writer| writer.strong_count() > 0);
        writers.push(Arc::downgrade(writer));
    }

    fn register_terminal(&self, terminal: &Arc<TerminalAuditState>) {
        let mut terminals = self.inner.terminals.lock().unwrap();
        terminals.retain(|terminal| terminal.strong_count() > 0);
        terminals.push(Arc::downgrade(terminal));
    }

    fn register_gateway_terminal(&self, terminal: &Arc<GatewayTerminalAuditState>) {
        let mut terminals = self.inner.gateway_terminals.lock().unwrap();
        terminals.retain(|terminal| terminal.strong_count() > 0);
        terminals.push(Arc::downgrade(terminal));
    }

    pub fn cancel_terminal_audits(&self) -> usize {
        let stream_terminals = {
            let mut terminals = self.inner.terminals.lock().unwrap();
            let live = terminals
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            *terminals = live.iter().map(Arc::downgrade).collect();
            live
        };
        let gateway_terminals = {
            let mut terminals = self.inner.gateway_terminals.lock().unwrap();
            let live = terminals
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            *terminals = live.iter().map(Arc::downgrade).collect();
            live
        };
        stream_terminals
            .into_iter()
            .filter(|terminal| terminal.cancel_from_shutdown())
            .count()
            + gateway_terminals
                .into_iter()
                .filter(|terminal| {
                    terminal.cancel(
                        "canceled",
                        "gateway forwarding was canceled during broker shutdown",
                    )
                })
                .count()
    }

    pub async fn shutdown_and_drain(&self, timeout: Duration) -> Result<(), RuntimeError> {
        let writers = {
            let mut writers = self.inner.writers.lock().unwrap();
            let mut live = Vec::<Arc<AuditWriterHandle>>::new();
            for writer in writers.iter().filter_map(Weak::upgrade) {
                if !live.iter().any(|existing| Arc::ptr_eq(existing, &writer)) {
                    live.push(writer);
                }
            }
            *writers = live.iter().map(Arc::downgrade).collect();
            live
        };
        let started = Instant::now();
        for writer in writers {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return Err(audit_runtime_error(
                    writer.path_label(),
                    std::io::ErrorKind::TimedOut,
                    "audit writer shutdown timed out",
                ));
            }
            match tokio::time::timeout(remaining, writer.shutdown_and_drain()).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(audit_runtime_error(
                        writer.path_label(),
                        std::io::ErrorKind::TimedOut,
                        "audit writer shutdown timed out",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AuditSink {
    writer: Option<Arc<AuditWriterHandle>>,
    store: Option<AuditStoreInfo>,
}

/// Whether audit storage is opened for startup, where SQLite databases are
/// created and migrated, or for reload admission, which never migrates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditOpenMode {
    Startup,
    Reload,
}

impl AuditSink {
    /// Opens the configured audit store and starts its writer. `None` disables
    /// audit.
    fn new(
        audit: Option<&crate::AuditConfig>,
        limits: &crate::LimitsConfig,
        registry: Arc<AuditRuntimeRegistry>,
        node_id: &str,
        mode: AuditOpenMode,
    ) -> Result<Self, RuntimeError> {
        let Some(audit) = audit else {
            return Ok(Self {
                writer: None,
                store: None,
            });
        };
        let path = PathBuf::from(&audit.path);
        let path_label = path.display().to_string();
        let (storage, store) = open_audit_storage(audit, &path, &path_label, node_id, mode)?;
        let config = AuditWriterConfig {
            path_label,
            node_id: node_id.to_string(),
            queue_capacity: audit.queue_capacity as usize,
            terminal_queue_capacity: audit.effective_terminal_queue_capacity(limits) as usize,
            enqueue_timeout: Duration::from_millis(audit.enqueue_timeout_ms),
            lock: audit_lock_for_path(&path),
        };
        let writer = AuditWriterHandle::start(config, storage);
        registry.register_writer(&writer);
        Ok(Self {
            writer: Some(writer),
            store: Some(store),
        })
    }

    async fn append_required(&self, record: AuditRecord) -> Result<(), RuntimeError> {
        let Some(writer) = &self.writer else {
            return Ok(());
        };
        writer.append_required(record).await
    }

    async fn check_writable(&self) -> Result<(), RuntimeError> {
        let Some(writer) = &self.writer else {
            return Ok(());
        };
        writer.check_writable().await
    }

    async fn reserve_terminal(&self) -> Result<TerminalAuditPermit, RuntimeError> {
        let Some(writer) = &self.writer else {
            return Ok(TerminalAuditPermit::Noop);
        };
        writer.reserve_terminal().await
    }

    async fn shutdown_and_drain(&self, timeout: Duration) -> Result<(), RuntimeError> {
        let Some(writer) = &self.writer else {
            return Ok(());
        };
        match tokio::time::timeout(timeout, writer.shutdown_and_drain()).await {
            Ok(result) => result,
            Err(_) => Err(audit_runtime_error(
                writer.path_label(),
                std::io::ErrorKind::TimedOut,
                "audit writer shutdown timed out",
            )),
        }
    }
}

/// What a runtime generation exposes about its audit store: the backend
/// type and database path, and for SQLite the database ID (which binds query
/// cursors to this database) and the most recent maintenance failure.
#[derive(Clone, Debug)]
pub struct AuditStoreInfo {
    kind: crate::AuditStoreType,
    path: PathBuf,
    sqlite: Option<SqliteAuditStoreInfo>,
}

#[derive(Clone, Debug)]
struct SqliteAuditStoreInfo {
    database_id: String,
    maintenance: AuditMaintenanceStatus,
    /// This generation's reader pool. Dropping the last clone of the
    /// generation closes it.
    readers: Arc<audit_sqlite::AuditReaderPool>,
}

impl AuditStoreInfo {
    pub fn store_type(&self) -> crate::AuditStoreType {
        self.kind
    }

    /// The configured audit path, as the writer opens it (relative paths
    /// resolve against the working directory).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The SQLite database's `database_id`: a UUID generated when the
    /// database was created and never changed. `None` for JSONL.
    pub fn database_id(&self) -> Option<&str> {
        self.sqlite
            .as_ref()
            .map(|sqlite| sqlite.database_id.as_str())
    }

    /// The most recent failure of an optional SQLite maintenance slice, kept
    /// until that slice next succeeds. Always `None` for JSONL.
    pub fn maintenance_failure(&self) -> Option<AuditMaintenanceFailure> {
        self.sqlite
            .as_ref()
            .and_then(|sqlite| sqlite.maintenance.current())
    }

    /// Whether this backend answers audit queries: only SQLite does.
    pub fn supports_queries(&self) -> bool {
        self.sqlite.is_some()
    }

    /// One page of the events visible to the query's caller, newest first,
    /// read through this generation's reader pool.
    pub async fn list_events(
        &self,
        query: crate::AuditEventsQuery,
    ) -> Result<crate::AuditEventsPage, crate::AuditQueryError> {
        let sqlite = self
            .sqlite
            .as_ref()
            .ok_or(crate::AuditQueryError::Unavailable)?;
        audit_sqlite::list_events(&sqlite.readers, query).await
    }

    /// The records of one broker request visible to the caller, oldest
    /// first, at most [`crate::AUDIT_TIMELINE_MAX_ITEMS`].
    pub async fn request_timeline(
        &self,
        broker_request_id: &str,
        visibility: crate::AuditVisibility,
    ) -> Result<Vec<Box<serde_json::value::RawValue>>, crate::AuditQueryError> {
        let sqlite = self
            .sqlite
            .as_ref()
            .ok_or(crate::AuditQueryError::Unavailable)?;
        audit_sqlite::request_timeline(&sqlite.readers, broker_request_id.to_string(), visibility)
            .await
    }
}

/// A failed optional maintenance slice, reported by admin `config.status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditMaintenanceFailure {
    /// `fts_merge`, `vacuum`, `optimize`, or `checkpoint`.
    pub slice: String,
    /// The SQLite result code name, such as `SQLITE_IOERR`.
    pub error_code: String,
    /// RFC 3339 time of the failure.
    pub at: String,
}

/// The shared slot the SQLite writer updates and the runtime reads.
#[derive(Clone, Debug, Default)]
struct AuditMaintenanceStatus(Arc<Mutex<Option<AuditMaintenanceFailure>>>);

impl AuditMaintenanceStatus {
    fn current(&self) -> Option<AuditMaintenanceFailure> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn record(&self, failure: AuditMaintenanceFailure) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(failure);
    }

    /// Clears the recorded failure if it belongs to `slice`.
    fn clear_slice(&self, slice: &str) {
        let mut current = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if current
            .as_ref()
            .is_some_and(|failure| failure.slice == slice)
        {
            *current = None;
        }
    }
}

/// Opens the storage backend for `audit.type`. Opening runs on the caller's
/// thread so that a store that cannot be opened fails runtime construction
/// (startup or reload admission) instead of the first append.
fn open_audit_storage(
    audit: &crate::AuditConfig,
    path: &Path,
    path_label: &str,
    node_id: &str,
    mode: AuditOpenMode,
) -> Result<(Box<dyn AuditStorage>, AuditStoreInfo), RuntimeError> {
    let config = AuditStorageConfig {
        path: path.to_path_buf(),
        path_label: path_label.to_string(),
        node_id: node_id.to_string(),
        retention_days: audit.retention_days,
        durability: audit.durability,
    };
    match audit.kind {
        crate::AuditStoreType::Jsonl => Ok((
            Box::new(audit_jsonl::JsonlAuditStorage::open(
                config,
                audit_jsonl::JsonlStorageConfig {
                    rotate_bytes: audit.effective_rotate_bytes(),
                },
            )),
            AuditStoreInfo {
                kind: crate::AuditStoreType::Jsonl,
                path: path.to_path_buf(),
                sqlite: None,
            },
        )),
        crate::AuditStoreType::Sqlite => {
            let maintenance = AuditMaintenanceStatus::default();
            let storage = audit_sqlite::SqliteAuditStorage::open(config, mode, maintenance.clone())
                .map_err(|message| RuntimeError::AuditStore {
                    path: path_label.to_string(),
                    message,
                })?;
            let store = AuditStoreInfo {
                kind: crate::AuditStoreType::Sqlite,
                path: path.to_path_buf(),
                sqlite: Some(SqliteAuditStoreInfo {
                    database_id: storage.database_id().to_string(),
                    maintenance,
                    readers: Arc::new(storage.reader_pool()),
                }),
            };
            Ok((Box::new(storage), store))
        }
    }
}

/// Backend-neutral writer settings.
struct AuditWriterConfig {
    path_label: String,
    /// The broker's effective node ID, stamped on every record.
    node_id: String,
    queue_capacity: usize,
    terminal_queue_capacity: usize,
    enqueue_timeout: Duration,
    /// Serializes appends, probes, and maintenance slices of every writer for
    /// the same path in this process.
    lock: Arc<Mutex<()>>,
}

/// Storage settings every backend receives. Backend-specific settings are
/// passed to the backend's own `open`.
struct AuditStorageConfig {
    path: PathBuf,
    path_label: String,
    node_id: String,
    retention_days: u32,
    durability: AuditDurability,
}

/// A record accepted for writing. The writer assigns `auditId` and `nodeId`
/// at its entry points, so every written record, including each terminal
/// record cloned from a started record, has its own `auditId`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StampedAuditRecord {
    audit_id: String,
    node_id: String,
    #[serde(flatten)]
    record: AuditRecord,
}

impl StampedAuditRecord {
    fn new(record: AuditRecord, node_id: &str) -> Self {
        Self {
            audit_id: Uuid::now_v7().to_string(),
            node_id: node_id.to_string(),
            record,
        }
    }
}

/// Whether a record was a required append (acknowledged to its request) or
/// a best-effort terminal append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditAppendKind {
    Required,
    Terminal,
}

impl AuditAppendKind {
    /// The class a failed append of this kind records.
    fn failure_class(self) -> AuditFailureClass {
        match self {
            Self::Required => AuditFailureClass::Append,
            Self::Terminal => AuditFailureClass::TerminalWrite,
        }
    }
}

struct AuditAppendEntry<'a> {
    kind: AuditAppendKind,
    record: &'a StampedAuditRecord,
}

/// The most append commands the writer drains into one batch.
const AUDIT_MAX_BATCH_RECORDS: usize = 256;

/// The storage step of an audit writer: everything that differs per
/// `audit.type`. The writer loop owns the queue, batching,
/// acknowledgements, health, and ordering; the backend reports health
/// effects as data in its outcomes and never touches writer health itself.
/// Every method runs on the writer thread; appends, probes, and maintenance
/// slices run under the per-path lock.
trait AuditStorage: Send {
    /// Writes `entries` (at most [`AUDIT_MAX_BATCH_RECORDS`], in queue
    /// order). Returns one outcome per entry, in order. `recorded` is the
    /// writer's current failure set.
    fn append_batch(
        &mut self,
        entries: &[AuditAppendEntry<'_>],
        recorded: AuditFailureSet,
    ) -> AuditAppendOutcome;

    /// Checks that the store is writable. `recorded` is the writer's current
    /// failure set.
    fn probe(&mut self, recorded: AuditFailureSet) -> AuditStorageOutcome;

    /// Runs one bounded slice of the maintenance cycle an append reported as
    /// due. The writer handles every queued command before each slice.
    fn run_maintenance_slice(&mut self) -> AuditMaintenanceOutcome;

    /// Whether a maintenance cycle still pending at shutdown runs to its end
    /// before [`AuditStorage::close`]. Otherwise it resumes after the next
    /// start.
    fn finishes_maintenance_at_shutdown(&self) -> bool;

    /// Releases the store after the writer has drained its queue at shutdown.
    fn close(&mut self) -> std::io::Result<()>;
}

struct AuditAppendOutcome {
    entries: Vec<AuditStorageOutcome>,
    /// Applied after the entries' changes and before any entry is
    /// acknowledged, for example the result of a recovery attempt the
    /// batch's commit triggered.
    health: AuditHealthChange,
    /// A maintenance cycle is due; the writer runs its slices after
    /// acknowledging the batch, whenever no command is queued.
    maintenance_due: bool,
}

struct AuditStorageOutcome {
    result: std::io::Result<()>,
    health: AuditHealthChange,
}

struct AuditMaintenanceOutcome {
    /// The operation name for failure logs, such as `prune`.
    operation: &'static str,
    /// A failure the writer logs as `audit_writer_failed`.
    result: std::io::Result<()>,
    health: AuditHealthChange,
    progress: AuditMaintenanceProgress,
}

/// Where a maintenance cycle stands after a slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditMaintenanceProgress {
    /// More slices remain.
    More,
    /// The slice was deferred (for example by `SQLITE_BUSY`); the cycle
    /// resumes at the same slice after the writer's next command.
    Deferred,
    /// The cycle is complete.
    Done,
}

/// Failure classes to record and to clear after a storage operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AuditHealthChange {
    mark: AuditFailureSet,
    clear: AuditFailureSet,
}

struct AuditWriterHandle {
    sender: mpsc::Sender<AuditCommand>,
    normal_capacity: Arc<Semaphore>,
    terminal_capacity: Arc<Semaphore>,
    config: Arc<AuditWriterConfig>,
    health: Arc<AuditWriterHealth>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
    shutting_down: AtomicBool,
    command_order: Mutex<()>,
}

enum AuditCommand {
    Append {
        record: StampedAuditRecord,
        ack: oneshot::Sender<std::io::Result<()>>,
        _permit: OwnedSemaphorePermit,
    },
    Probe {
        ack: oneshot::Sender<std::io::Result<()>>,
        _permit: OwnedSemaphorePermit,
    },
    TerminalAppend {
        record: StampedAuditRecord,
        _permit: OwnedSemaphorePermit,
    },
    Shutdown {
        ack: oneshot::Sender<std::io::Result<()>>,
    },
    #[cfg(test)]
    ExitForTest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditWriterTestEventKind {
    FileSync(AuditDurability),
    ParentDirSync(AuditDurability),
    Prune,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditWriterTestEvent {
    path: String,
    kind: AuditWriterTestEventKind,
}

#[cfg(test)]
type AuditWriterTestHook = Arc<dyn Fn(AuditWriterTestEvent) + Send + Sync + 'static>;

#[cfg(test)]
static AUDIT_WRITER_TEST_HOOK: OnceLock<Mutex<Option<AuditWriterTestHook>>> = OnceLock::new();

#[cfg(test)]
fn audit_writer_test_hook() -> &'static Mutex<Option<AuditWriterTestHook>> {
    AUDIT_WRITER_TEST_HOOK.get_or_init(|| Mutex::new(None))
}

fn emit_audit_writer_test_event(path: &str, kind: AuditWriterTestEventKind) {
    #[cfg(test)]
    if let Some(hook) = audit_writer_test_hook()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
    {
        hook(AuditWriterTestEvent {
            path: path.to_string(),
            kind,
        });
    }
    #[cfg(not(test))]
    {
        let _ = path;
        match kind {
            AuditWriterTestEventKind::FileSync(durability)
            | AuditWriterTestEventKind::ParentDirSync(durability) => {
                let _ = durability;
            }
            AuditWriterTestEventKind::Prune => {}
        }
    }
}

impl AuditWriterHandle {
    fn start(config: AuditWriterConfig, storage: Box<dyn AuditStorage>) -> Arc<Self> {
        let total_capacity = config
            .queue_capacity
            .saturating_add(config.terminal_queue_capacity);
        let (sender, receiver) = mpsc::channel(total_capacity);
        let config = Arc::new(config);
        let health = Arc::new(AuditWriterHealth::new(config.path_label.clone()));
        let normal_capacity = Arc::new(Semaphore::new(config.queue_capacity));
        let terminal_capacity = Arc::new(Semaphore::new(config.terminal_queue_capacity));
        let thread_config = Arc::clone(&config);
        let thread_health = Arc::clone(&health);
        // The writer logs to the subscriber in effect where it was started.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let join = thread::Builder::new()
            .name("agent-access-audit-writer".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    run_audit_writer(receiver, thread_config, thread_health, storage)
                })
            })
            .expect("audit writer thread starts");
        Arc::new(Self {
            sender,
            normal_capacity,
            terminal_capacity,
            config,
            health,
            join: Mutex::new(Some(join)),
            shutting_down: AtomicBool::new(false),
            command_order: Mutex::new(()),
        })
    }

    fn path_label(&self) -> String {
        self.config.path_label.clone()
    }

    async fn reserve_normal_capacity(&self) -> Result<OwnedSemaphorePermit, RuntimeError> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(audit_runtime_error(
                self.path_label(),
                std::io::ErrorKind::BrokenPipe,
                "audit writer is shutting down",
            ));
        }
        tokio::time::timeout(
            self.config.enqueue_timeout,
            self.normal_capacity.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            audit_runtime_error(
                self.path_label(),
                std::io::ErrorKind::TimedOut,
                "audit writer queue capacity timed out",
            )
        })?
        .map_err(|source| {
            audit_runtime_error(self.path_label(), std::io::ErrorKind::BrokenPipe, source)
        })
    }

    async fn append_required(&self, record: AuditRecord) -> Result<(), RuntimeError> {
        let permit = self.reserve_normal_capacity().await?;
        self.append_with_permit(record, permit).await
    }

    async fn append_with_permit(
        &self,
        record: AuditRecord,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), RuntimeError> {
        let record = StampedAuditRecord::new(record, &self.config.node_id);
        let (ack, done) = oneshot::channel();
        {
            let _order = self.command_order.lock().unwrap();
            if self.shutting_down.load(Ordering::SeqCst) {
                return Err(audit_runtime_error(
                    self.path_label(),
                    std::io::ErrorKind::BrokenPipe,
                    "audit writer is shutting down",
                ));
            }
            self.sender
                .try_send(AuditCommand::Append {
                    record,
                    ack,
                    _permit: permit,
                })
                .map_err(|error| self.command_send_error(error))?;
        }
        done.await
            .map_err(|source| {
                self.health.mark_writer_exit();
                audit_runtime_error(self.path_label(), std::io::ErrorKind::BrokenPipe, source)
            })?
            .map_err(|source| RuntimeError::Audit {
                path: self.path_label(),
                source,
            })
    }

    async fn check_writable(&self) -> Result<(), RuntimeError> {
        self.probe_storage().await?;
        self.health.check()
    }

    /// Queues a storage probe and returns the writer's result for it alone.
    /// Health checked afterwards can also reflect commands handled since.
    async fn probe_storage(&self) -> Result<(), RuntimeError> {
        let permit = self.reserve_normal_capacity().await?;
        let (ack, done) = oneshot::channel();
        {
            let _order = self.command_order.lock().unwrap();
            if self.shutting_down.load(Ordering::SeqCst) {
                return Err(audit_runtime_error(
                    self.path_label(),
                    std::io::ErrorKind::BrokenPipe,
                    "audit writer is shutting down",
                ));
            }
            self.sender
                .try_send(AuditCommand::Probe {
                    ack,
                    _permit: permit,
                })
                .map_err(|error| self.command_send_error(error))?;
        }
        done.await
            .map_err(|source| {
                self.health.mark_writer_exit();
                audit_runtime_error(self.path_label(), std::io::ErrorKind::BrokenPipe, source)
            })?
            .map_err(|source| RuntimeError::Audit {
                path: self.path_label(),
                source,
            })
    }

    fn command_send_error(&self, error: mpsc::error::TrySendError<AuditCommand>) -> RuntimeError {
        match error {
            mpsc::error::TrySendError::Full(_) => audit_runtime_error(
                self.path_label(),
                std::io::ErrorKind::WouldBlock,
                "audit writer command channel full",
            ),
            mpsc::error::TrySendError::Closed(_) => {
                self.health.mark_writer_exit();
                audit_runtime_error(
                    self.path_label(),
                    std::io::ErrorKind::BrokenPipe,
                    "audit writer command channel closed",
                )
            }
        }
    }

    async fn reserve_terminal(self: &Arc<Self>) -> Result<TerminalAuditPermit, RuntimeError> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(audit_runtime_error(
                self.path_label(),
                std::io::ErrorKind::BrokenPipe,
                "audit writer is shutting down",
            ));
        }
        let permit = tokio::time::timeout(
            self.config.enqueue_timeout,
            self.terminal_capacity.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            audit_runtime_error(
                self.path_label(),
                std::io::ErrorKind::TimedOut,
                "audit terminal queue capacity timed out",
            )
        })?
        .map_err(|source| {
            audit_runtime_error(self.path_label(), std::io::ErrorKind::BrokenPipe, source)
        })?;
        Ok(TerminalAuditPermit::Writer {
            writer: Arc::clone(self),
            permit: Some(permit),
        })
    }

    fn send_terminal(&self, record: AuditRecord, permit: OwnedSemaphorePermit) {
        let record = StampedAuditRecord::new(record, &self.config.node_id);
        let _order = self.command_order.lock().unwrap();
        if self.shutting_down.load(Ordering::SeqCst) {
            self.health.mark_failure(AuditFailureClass::TerminalWrite);
            let error = std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "audit writer is shutting down",
            );
            log_terminal_append_failure(&self.config.path_label, &record, &error);
            return;
        }
        if let Err(error) = self.sender.try_send(AuditCommand::TerminalAppend {
            record: record.clone(),
            _permit: permit,
        }) {
            self.health.mark_failure(AuditFailureClass::TerminalWrite);
            let error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, error.to_string());
            log_terminal_append_failure(&self.config.path_label, &record, &error);
        }
    }

    async fn shutdown_and_drain(&self) -> Result<(), RuntimeError> {
        let first = {
            let _order = self.command_order.lock().unwrap();
            !self.shutting_down.swap(true, Ordering::SeqCst)
        };
        if first {
            let (ack, done) = oneshot::channel();
            self.sender
                .send(AuditCommand::Shutdown { ack })
                .await
                .map_err(|_| {
                    self.health.mark_writer_exit();
                    audit_runtime_error(
                        self.path_label(),
                        std::io::ErrorKind::BrokenPipe,
                        "audit writer command channel closed",
                    )
                })?;
            done.await
                .map_err(|source| {
                    self.health.mark_writer_exit();
                    audit_runtime_error(self.path_label(), std::io::ErrorKind::BrokenPipe, source)
                })?
                .map_err(|source| RuntimeError::Audit {
                    path: self.path_label(),
                    source,
                })?;
        }
        let join = self.join.lock().unwrap().take();
        if let Some(join) = join {
            tokio::task::spawn_blocking(move || join.join())
                .await
                .map_err(|source| {
                    audit_runtime_error(
                        "audit writer".to_string(),
                        std::io::ErrorKind::Other,
                        source,
                    )
                })?
                .map_err(|_| {
                    audit_runtime_error(
                        "audit writer".to_string(),
                        std::io::ErrorKind::Other,
                        "audit writer thread panicked",
                    )
                })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditFailureClass {
    Append,
    Rotation,
    Prune,
    Probe,
    TerminalWrite,
    /// Sticky: the writer thread is gone, and nothing clears it.
    WriterExit,
}

impl AuditFailureClass {
    const ALL: [Self; 6] = [
        Self::Append,
        Self::Rotation,
        Self::Prune,
        Self::Probe,
        Self::TerminalWrite,
        Self::WriterExit,
    ];

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of [`AuditFailureClass`] values.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct AuditFailureSet(u8);

impl AuditFailureSet {
    const EMPTY: Self = Self(0);

    fn of(classes: &[AuditFailureClass]) -> Self {
        classes
            .iter()
            .fold(Self::EMPTY, |set, class| set.with(*class))
    }

    /// Every class except the sticky `WriterExit`.
    fn recoverable() -> Self {
        Self::of(&AuditFailureClass::ALL).without(AuditFailureClass::WriterExit)
    }

    fn with(self, class: AuditFailureClass) -> Self {
        Self(self.0 | class.bit())
    }

    fn without(self, class: AuditFailureClass) -> Self {
        Self(self.0 & !class.bit())
    }

    fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    fn contains(self, class: AuditFailureClass) -> bool {
        self.0 & class.bit() != 0
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn iter(self) -> impl Iterator<Item = AuditFailureClass> {
        AuditFailureClass::ALL
            .into_iter()
            .filter(move |class| self.contains(*class))
    }
}

impl std::fmt::Debug for AuditFailureSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

/// Writer health: every recorded failure class, each cleared only by the
/// evidence the backend reports for it. Readiness fails while any class is
/// recorded; `WriterExit` is never cleared.
struct AuditWriterHealth {
    path: String,
    failures: Mutex<AuditFailureSet>,
}

impl AuditWriterHealth {
    fn new(path: String) -> Self {
        Self {
            path,
            failures: Mutex::new(AuditFailureSet::EMPTY),
        }
    }

    fn mark_failure(&self, failure: AuditFailureClass) {
        let mut failures = self.failures.lock().unwrap();
        *failures = failures.with(failure);
    }

    fn mark_writer_exit(&self) {
        self.mark_failure(AuditFailureClass::WriterExit);
    }

    fn apply(&self, change: AuditHealthChange) {
        let mut failures = self.failures.lock().unwrap();
        let clear = change.clear.without(AuditFailureClass::WriterExit);
        *failures = failures.difference(clear).union(change.mark);
    }

    fn recorded(&self) -> AuditFailureSet {
        *self.failures.lock().unwrap()
    }

    fn check(&self) -> Result<(), RuntimeError> {
        let failures = self.recorded();
        if failures.contains(AuditFailureClass::WriterExit) {
            return Err(audit_runtime_error(
                self.path.clone(),
                std::io::ErrorKind::BrokenPipe,
                "audit writer exited",
            ));
        }
        if failures.is_empty() {
            return Ok(());
        }
        let classes = failures
            .iter()
            .map(|class| format!("{class:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        Err(audit_runtime_error(
            self.path.clone(),
            std::io::ErrorKind::Other,
            format!("audit writer has unrecovered failures: {classes}"),
        ))
    }
}

enum TerminalAuditPermit {
    Noop,
    Writer {
        writer: Arc<AuditWriterHandle>,
        permit: Option<OwnedSemaphorePermit>,
    },
}

impl TerminalAuditPermit {
    async fn append_required(self, record: AuditRecord) -> Result<(), RuntimeError> {
        match self {
            Self::Noop => Ok(()),
            Self::Writer { writer, mut permit } => {
                writer
                    .append_with_permit(record, permit.take().expect("reserved terminal permit"))
                    .await
            }
        }
    }

    fn send(mut self, record: AuditRecord) {
        match &mut self {
            Self::Noop => {}
            Self::Writer { writer, permit } => {
                if let Some(permit) = permit.take() {
                    writer.send_terminal(record, permit);
                }
            }
        }
    }
}

struct TerminalAuditState {
    inner: Mutex<TerminalAuditInner>,
    canceled: AtomicBool,
}

struct TerminalAuditInner {
    permit: Option<TerminalAuditPermit>,
    base_record: AuditRecord,
    started: Instant,
    bytes: u64,
    digest: Sha256,
    finished: bool,
}

impl TerminalAuditState {
    fn new(base_record: AuditRecord, permit: TerminalAuditPermit) -> Self {
        Self {
            inner: Mutex::new(TerminalAuditInner {
                permit: Some(permit),
                base_record,
                started: Instant::now(),
                bytes: 0,
                digest: Sha256::new(),
                finished: false,
            }),
            canceled: AtomicBool::new(false),
        }
    }

    fn observe_bytes(&self, bytes: &Bytes) {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished {
            return;
        }
        inner.bytes = inner.bytes.saturating_add(bytes.len() as u64);
        inner.digest.update(bytes);
    }

    fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::SeqCst)
    }

    fn cancel_from_shutdown(&self) -> bool {
        self.canceled.store(true, Ordering::SeqCst);
        self.finish(
            "canceled",
            Decision::Error,
            None,
            Some("download stream was canceled before completion".to_string()),
        )
    }

    fn finish(
        &self,
        phase: &str,
        decision: Decision,
        reason_code: Option<ReasonCodeId>,
        message: Option<String>,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished {
            return false;
        }
        inner.finished = true;
        let mut record = inner.base_record.clone();
        record.timestamp = Utc::now().to_rfc3339();
        record.decision = decision;
        record.reason_code = reason_code;
        record.provider_audit = Some(stream_audit_value(
            record.provider_audit.take(),
            phase,
            inner.bytes,
            finalize_stream_sha256(&inner.digest),
            Some(elapsed_millis(inner.started)),
            message,
        ));
        emit_invoke_stream_terminal(&record, phase, elapsed_millis(inner.started));
        if let Some(permit) = inner.permit.take() {
            permit.send(record);
        }
        true
    }
}

struct GatewayTerminalAuditState {
    inner: Mutex<GatewayTerminalAuditInner>,
}

struct GatewayTerminalAuditInner {
    permit: Option<TerminalAuditPermit>,
    base_record: AuditRecord,
    started: Instant,
    finished: bool,
}

impl GatewayTerminalAuditState {
    fn new(base_record: AuditRecord, permit: TerminalAuditPermit) -> Self {
        Self {
            inner: Mutex::new(GatewayTerminalAuditInner {
                permit: Some(permit),
                base_record,
                started: Instant::now(),
                finished: false,
            }),
        }
    }

    fn finish_record(&self, record: AuditRecord) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished {
            return false;
        }
        inner.finished = true;
        if let Some(permit) = inner.permit.take() {
            permit.send(record);
        }
        true
    }

    fn observe_progress(&self, upstream_status: u16, audit: Value) {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished {
            return;
        }
        inner.base_record.upstream_status = Some(upstream_status);
        inner.base_record.provider_audit = Some(audit);
    }

    fn cancel(&self, phase: &str, message: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.finished {
            return false;
        }
        inner.finished = true;
        let duration_ms = elapsed_millis(inner.started);
        let mut record = inner.base_record.clone();
        record.timestamp = Utc::now().to_rfc3339();
        record.decision = Decision::Error;
        record.reason_code = None;
        record.upstream_duration_ms = Some(duration_ms);
        record.provider_audit = gateway_terminal_audit_value(
            record.provider_audit.take(),
            phase,
            Some(message.to_string()),
        );
        emit_gateway_terminal(&record, phase, duration_ms);
        if let Some(permit) = inner.permit.take() {
            permit.send(record);
        }
        true
    }
}

/// The writer thread's state: the shared loop around one storage backend.
struct AuditWriterLoop {
    config: Arc<AuditWriterConfig>,
    health: Arc<AuditWriterHealth>,
    storage: Box<dyn AuditStorage>,
    /// A command taken from the queue while draining a batch that is not an
    /// append; it is handled next, so probes and shutdown keep their order.
    held: Option<AuditCommand>,
    maintenance: MaintenanceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceState {
    Idle,
    /// Run the next slice whenever no command is queued.
    Pending,
    /// The last slice was deferred; resume after the next command.
    Deferred,
}

/// An append command's parts after it is taken from the queue.
struct QueuedAppend {
    kind: AuditAppendKind,
    record: StampedAuditRecord,
    ack: Option<oneshot::Sender<std::io::Result<()>>>,
    _permit: OwnedSemaphorePermit,
}

impl QueuedAppend {
    /// Takes the parts of an append or terminal-append command.
    fn from_append(command: AuditCommand) -> Self {
        match command {
            AuditCommand::Append {
                record,
                ack,
                _permit,
            } => Self {
                kind: AuditAppendKind::Required,
                record,
                ack: Some(ack),
                _permit,
            },
            AuditCommand::TerminalAppend { record, _permit } => Self {
                kind: AuditAppendKind::Terminal,
                record,
                ack: None,
                _permit,
            },
            _ => unreachable!("only append commands are queued appends"),
        }
    }
}

impl AuditCommand {
    fn is_append(&self) -> bool {
        matches!(self, Self::Append { .. } | Self::TerminalAppend { .. })
    }
}

fn run_audit_writer(
    mut receiver: mpsc::Receiver<AuditCommand>,
    config: Arc<AuditWriterConfig>,
    health: Arc<AuditWriterHealth>,
    storage: Box<dyn AuditStorage>,
) {
    let mut writer = AuditWriterLoop {
        config,
        health,
        storage,
        held: None,
        maintenance: MaintenanceState::Idle,
    };
    while let Some(command) = writer.next_command(&mut receiver) {
        #[cfg(test)]
        if matches!(command, AuditCommand::ExitForTest) {
            break;
        }
        if let Some(shutdown_ack) = writer.handle(command, &mut receiver) {
            writer.drain_for_shutdown(&mut receiver);
            let _ = shutdown_ack.send(writer.storage.close());
            break;
        }
    }
}

impl AuditWriterLoop {
    /// The next command to handle. While maintenance is pending, runs one
    /// slice at a time whenever the queue is empty.
    fn next_command(
        &mut self,
        receiver: &mut mpsc::Receiver<AuditCommand>,
    ) -> Option<AuditCommand> {
        if let Some(command) = self.held.take() {
            return Some(command);
        }
        while self.maintenance == MaintenanceState::Pending {
            match receiver.try_recv() {
                Ok(command) => return Some(command),
                Err(mpsc::error::TryRecvError::Empty) => self.run_maintenance_slice(),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
            }
        }
        let command = receiver.blocking_recv();
        if self.maintenance == MaintenanceState::Deferred {
            self.maintenance = MaintenanceState::Pending;
        }
        command
    }

    /// Handles one command, draining queued appends into its batch. Returns
    /// the acknowledgement of a shutdown command.
    fn handle(
        &mut self,
        command: AuditCommand,
        receiver: &mut mpsc::Receiver<AuditCommand>,
    ) -> Option<oneshot::Sender<std::io::Result<()>>> {
        let first = match command {
            AuditCommand::Probe { ack, _permit } => {
                let outcome = {
                    let lock = Arc::clone(&self.config.lock);
                    let _guard = lock.lock().unwrap();
                    self.storage.probe(self.health.recorded())
                };
                self.health.apply(outcome.health);
                let _ = ack.send(outcome.result);
                return None;
            }
            AuditCommand::Shutdown { ack } => return Some(ack),
            #[cfg(test)]
            AuditCommand::ExitForTest => return None,
            append => QueuedAppend::from_append(append),
        };
        let mut batch = vec![first];
        while batch.len() < AUDIT_MAX_BATCH_RECORDS {
            match receiver.try_recv() {
                Ok(command) if command.is_append() => {
                    batch.push(QueuedAppend::from_append(command));
                }
                Ok(other) => {
                    self.held = Some(other);
                    break;
                }
                Err(_) => break,
            }
        }
        self.append_batch(batch);
        None
    }

    /// Writes a drained batch, applies its health changes, and then
    /// acknowledges each record with its own result. As with a probe, no
    /// record is acknowledged before every health change of its batch,
    /// including a recovery its commit triggered, is recorded.
    fn append_batch(&mut self, batch: Vec<QueuedAppend>) {
        let AuditAppendOutcome {
            entries,
            health,
            maintenance_due,
        } = {
            let entries = batch
                .iter()
                .map(|append| AuditAppendEntry {
                    kind: append.kind,
                    record: &append.record,
                })
                .collect::<Vec<_>>();
            let lock = Arc::clone(&self.config.lock);
            let _guard = lock.lock().unwrap();
            self.storage.append_batch(&entries, self.health.recorded())
        };
        let mut outcomes = entries.into_iter();
        let results = batch
            .iter()
            .map(|append| {
                let outcome = outcomes.next().unwrap_or_else(|| AuditStorageOutcome {
                    result: Err(std::io::Error::other(
                        "audit storage reported no append outcome",
                    )),
                    health: AuditHealthChange {
                        mark: AuditFailureSet::of(&[append.kind.failure_class()]),
                        clear: AuditFailureSet::EMPTY,
                    },
                });
                self.health.apply(outcome.health);
                outcome.result
            })
            .collect::<Vec<_>>();
        self.health.apply(health);
        for (append, result) in batch.into_iter().zip(results) {
            match append.ack {
                Some(ack) => {
                    let _ = ack.send(result);
                }
                None => {
                    if let Err(error) = &result {
                        log_terminal_append_failure(&self.config.path_label, &append.record, error);
                    }
                }
            }
        }
        if maintenance_due && self.maintenance == MaintenanceState::Idle {
            self.maintenance = MaintenanceState::Pending;
        }
    }

    fn run_maintenance_slice(&mut self) {
        let outcome = {
            let lock = Arc::clone(&self.config.lock);
            let _guard = lock.lock().unwrap();
            self.storage.run_maintenance_slice()
        };
        self.health.apply(outcome.health);
        if let Err(error) = &outcome.result {
            log_audit_writer_failure(
                &self.config.path_label,
                &self.config.node_id,
                outcome.operation,
                None,
                error,
            );
        }
        self.maintenance = match outcome.progress {
            AuditMaintenanceProgress::More => MaintenanceState::Pending,
            AuditMaintenanceProgress::Deferred => MaintenanceState::Deferred,
            AuditMaintenanceProgress::Done => MaintenanceState::Idle,
        };
    }

    /// Handles every command still queued at shutdown, then finishes a
    /// pending maintenance cycle if the backend asks for it.
    fn drain_for_shutdown(&mut self, receiver: &mut mpsc::Receiver<AuditCommand>) {
        while let Some(command) = self.held.take().or_else(|| receiver.try_recv().ok()) {
            #[cfg(test)]
            if matches!(command, AuditCommand::ExitForTest) {
                break;
            }
            if let Some(extra_shutdown_ack) = self.handle(command, receiver) {
                let _ = extra_shutdown_ack.send(Ok(()));
            }
        }
        if self.storage.finishes_maintenance_at_shutdown() {
            if self.maintenance == MaintenanceState::Deferred {
                self.maintenance = MaintenanceState::Pending;
            }
            while self.maintenance == MaintenanceState::Pending {
                self.run_maintenance_slice();
            }
        }
    }
}

fn audit_runtime_error(
    path: String,
    kind: std::io::ErrorKind,
    message: impl ToString,
) -> RuntimeError {
    RuntimeError::Audit {
        path,
        source: std::io::Error::new(kind, message.to_string()),
    }
}

fn log_audit_writer_failure(
    path: &str,
    node_id: &str,
    operation: &str,
    record: Option<&AuditRecord>,
    error: &std::io::Error,
) {
    let (agent_request_id, broker_request_id, service, action) = record
        .map(|record| {
            (
                Some(record.agent_request_id.as_str()),
                Some(record.broker_request_id.as_str()),
                Some(record.service.as_str()),
                Some(record.action.as_str()),
            )
        })
        .unwrap_or((None, None, None, None));
    tracing::error!(
        event = "audit_writer_failed",
        auditPath = path,
        nodeId = node_id,
        operation = operation,
        agentRequestId = agent_request_id.unwrap_or(""),
        brokerRequestId = broker_request_id.unwrap_or(""),
        service = service.unwrap_or(""),
        action = action.unwrap_or(""),
        error = %error,
    );
}

fn log_terminal_append_failure(path: &str, record: &StampedAuditRecord, error: &std::io::Error) {
    log_audit_writer_failure(
        path,
        &record.node_id,
        "terminal_append",
        Some(&record.record),
        error,
    );
    emit_audit_terminal_append_failed(
        path,
        &record.node_id,
        "terminal_append",
        &record.record,
        error,
    );
}

fn audit_lock_for_path(path: &Path) -> Arc<Mutex<()>> {
    static AUDIT_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

    let key = audit_file_identity_key(path);
    let locks = AUDIT_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks.lock().unwrap();
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }

    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

pub fn audit_file_identity_key(path: &Path) -> PathBuf {
    let Some(file_name) = path.file_name() else {
        return fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::canonicalize(parent)
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(file_name)
}

pub fn new_broker_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn split_service_action(value: &str) -> Result<(String, String), String> {
    let Some((service, action)) = value.split_once('.') else {
        return Err("service action must use service.action syntax".to_string());
    };
    if service.is_empty() || action.is_empty() {
        return Err("service action must include non-empty service and action".to_string());
    }
    if !agent_access_provider::is_service_name(service) {
        return Err("service action contains an invalid service name".to_string());
    }
    if !agent_access_provider::is_action_name(action) {
        return Err("service action contains an invalid action name".to_string());
    }
    Ok((service.to_string(), action.to_string()))
}

pub fn cli_exit_code_for_http_status(status: u16) -> i32 {
    match status {
        200 => 0,
        400 => 3,
        401 => 6,
        403 | 409 | 413 | 415 => 2,
        424 | 502 | 504 => 4,
        429 => 7,
        503 => 5,
        _ if status >= 500 => 5,
        _ if status >= 400 => 3,
        _ => 1,
    }
}

pub fn fake_service_credential(token_ref: impl Into<String>) -> CredentialConfig {
    CredentialConfig {
        kind: "bearer_token".to_string(),
        username_ref: None,
        token_ref: Some(token_ref.into()),
        provider: None,
        path: None,
        read_only: None,
        connection: None,
    }
}

#[cfg(test)]
mod tests;
