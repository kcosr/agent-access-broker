//! Contract between the Agent Access Broker host and its backends.
//!
//! A backend describes its services with a [`ServiceDescriptor`], serves
//! invocations through the [`Provider`] trait, and reaches upstream systems
//! through the host services defined here: upstream clients the host
//! constructs (TLS trust and egress routing stay inside the host), upstream
//! allowlists, correlation headers, trace events, stable token signing and
//! signed continuation envelopes.
//! The broker owns identity, policy, credentials, audit, limits and network
//! construction; backends see only the narrow views in this crate. The
//! [`host`] module holds the cooperation ports the broker host implements and
//! calls.

mod admitted;
mod attribution;
mod backend;
mod capabilities;
mod config;
mod continuation;
mod contract;
mod correlation;
mod credential;
mod delegated;
mod descriptor;
mod domain_reason;
mod egress_config;
mod error;
mod finalization;
pub mod host;
mod identifiers;
mod invocation;
mod module;
mod oauth_dialect;
pub mod presentation;
mod provider;
mod reason;
mod resource;
mod result;
mod scope;
mod signing;
mod state;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod trace;
mod upstream;
mod upstream_allowlist;
mod upstream_rate_limit;
mod upstream_validation;

pub use admitted::{
    AdmittedContext, AdmittedRequest, AuthorityMismatch, InvocationAuthority, ProviderInvocation,
};
pub use attribution::{
    AttributionCapability, AttributionMutation, AttributionRepresentation, AttributionVerb,
    ProviderAttributionConfig, attribution_audit_applied, attribution_skip_target_absent_audit,
    matching_attribution_capabilities, merge_attribution_audit, validate_attribution_pattern,
};
pub use backend::{
    BackendConfig, BackendConfigParser, BackendRegistration, BuildContext, ServiceCredentialKinds,
    ValidationContext, parse_backend_config,
};
pub use capabilities::{
    ActionCapabilities, ResourceScopeCapabilities, ServiceCapabilities, UpstreamResourceOwnership,
};
pub use config::{
    AttachmentLimitsConfig, ProviderLimits, SearchLimitsConfig, default_attachment_max_bytes,
    default_attachment_max_total_bytes, default_download_max_bytes, is_env_name,
    is_literal_loopback, is_loopback_or_localhost, is_secret_ref, validate_attachment_limits,
    validate_egress_proxy_config, validate_formats_allow_empty,
    validate_non_empty_control_free_string, validate_provider_limit_relation,
    validate_provider_upload_limit_relation, validate_tenant_host, validate_upload_limits,
    validate_upstream_allowlist, validate_upstream_base_url,
};
pub use continuation::{
    ContinuationBinding, ContinuationError, ContinuationFamily, ContinuationLifetime,
    ContinuationOwner, ContinuationSigner,
};
pub use correlation::{
    BROKER_REQUEST_ID_HEADER, CorrelationContext, InvocationScope, REQUEST_ID_HEADER,
    current_correlation_context, current_provider_action,
};
pub use credential::{
    CredentialMode, CredentialView, ExecutionAccess, ExecutionCredential, StaticCredentialKind,
    UnsupportedCredentialMode,
};
pub use delegated::{DelegatedAccess, DelegatedBindingId, DelegatedCredential, DelegatedLease};
pub use descriptor::{
    ActionDescriptor, ActionIo, CredentialDescriptor, CredentialProfile, DelegatedConnection,
    HeaderEncoding, LookupRequirement, MultipartUploadSpec, RESULT_METADATA_HEADER,
    ScopedMcpNameSource, ServiceDescriptor, ServiceSurface, attachment_upload_plan,
    raw_download_io,
};
pub use domain_reason::{
    ProviderFailureStatus, ProviderReason, ProviderReasonDefinition, domain_reason_prefix,
};
pub use egress_config::{EgressDeclaration, EgressProxyConfig, EgressProxySource, EgressRoute};
pub use error::ProviderBuildError;
pub use finalization::{
    ProviderFinalizationContext, ProviderFinalizationGuard, current_provider_finalization,
};
pub use identifiers::{ResourceScopes, is_action_name, is_service_name};
pub use invocation::{
    BrokerBodyPart, BrokerBodyPartFile, BrokerBodyPartSpec, InvocationIdentity,
    SearchAuthorization, SearchAuthorizationScope,
};
pub use module::{ModuleMetadata, SDK_PACKAGE};
pub use oauth_dialect::{
    AuthorizationRequest, CodeExchange, ConnectedIdentity, IssuedRefreshToken,
    OAUTH_MAX_RESPONSE_BYTES, OAuthAdapter, OAuthCallbackIssuer, OAuthClient, OAuthClientAuth,
    OAuthDialect, OAuthDialectError, OAuthDialectRegistration, OAuthHttp, OAuthPermissionProfile,
    OAuthRegistrationConfig, OAuthResponse, OAuthRotation, OAuthScopeMode, OAuthTarget,
    OAuthTokenEncoding, PreparedAuthorization, RefreshReplay, TokenGrant,
};
pub use provider::{Provider, ServiceProvider};
pub use reason::{Decision, HookPhase, InvalidReasonCodeId, ReasonCode, ReasonCodeId};
pub use resource::{
    GIT_REPOSITORY_RESOURCE, NamespaceSelectorDescriptor, NamespaceSelectorMetadata,
    ResourceActionInputs, ResourceAttributeDescriptor, ResourceAttributeMetadata,
    ResourceAttributes, ResourceSelector, ResourceType, ResourceTypeDescriptor,
    ResourceTypeMetadata, ResourceTypeRegistry, is_canonical_repository_path,
    is_repository_selector_path,
};
pub use result::{
    ProviderByteStream, ProviderCredentialVerification, ProviderError, ProviderResult,
    ProviderResultStream, ProviderResultStreamSource, ProviderStreamError,
};
pub use scope::{ScopeRequest, ScopeResolution};
pub use signing::{OpaqueTokenSigner, SigningError, StableSigningKey};
pub use state::{BodyAdmission, ProviderState, ProviderStateError, StateDisposition};
pub use trace::{UpstreamTrace, emit_upstream_request_completed};
pub use upstream::{
    ClientProfile, PendingUpstreamTrace, RedirectRules, UploadProgress, UpstreamCall,
    UpstreamClient, UpstreamClientSpec, UpstreamError, complete_upstream_trace, file_upload_body,
    take_upstream_trace,
};
pub use upstream_allowlist::{path_matches_pattern, same_origin, url_allowed_by_patterns};
pub use upstream_rate_limit::{
    UPSTREAM_RETRY_AFTER_MAX_SECONDS, UpstreamRetryAfter, mutation_unverified_after_throttling,
    mutation_unverified_after_throttling_message, upstream_rate_limited,
    upstream_rate_limited_message, upstream_retry_hint,
};
pub use upstream_validation::{
    VALIDATION_FIELD_MAX_BYTES, VALIDATION_FRAGMENT_MAX_BYTES, VALIDATION_MESSAGE_MAX_BYTES,
    VALIDATION_MESSAGE_MAX_PARTS, join_message_parts, push_message_part, read_validation_json,
    response_has_json_content_type, sanitize_field, sanitize_fragment,
};
