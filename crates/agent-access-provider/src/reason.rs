use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Error,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }
}

/// The Broker's standard reasons. Each has a fixed HTTP status and wire
/// spelling ([`Self::as_str`], which its serde form matches). Responses and
/// audit records carry the spelling as a [`ReasonCodeId`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    RequestIdMissing,
    RequestIdInvalid,
    InputInvalid,
    CallerAuthenticationRequired,
    CallerAuthenticationInvalid,
    CallerIdentityForwardingDenied,
    IdentityRequired,
    IdentityInvalid,
    CallerUserAssertionDenied,
    IdentityAssertionInvalid,
    IdentityAssertionUnsupported,
    IdentityAssertionDenied,
    IdentityUnavailable,
    IdentityBindingConflict,
    IdentityVersionConflict,
    IdentityBindingNotFound,
    ExecutionContextRequired,
    ExecutionContextInvalid,
    ExecutionContextDenied,
    PrincipalRequired,
    PrincipalNotFound,
    PrincipalDisabled,
    GroupNotFound,
    PolicyGrantNotFound,
    ResourceNotFound,
    ResourceGroupNotFound,
    ResourceInUse,
    PolicyAuthorityUnavailable,
    PolicyValidationFailed,
    BrokerTokenNotFound,
    BrokerTokenExpired,
    BrokerTokenPaused,
    BrokerTokenRevoked,
    BrokerTokenStateConflict,
    BrokerTokenClassDenied,
    ManagementDenied,
    SelfServiceDisabled,
    CsrfInvalid,
    PasswordChangeRequired,
    LocalLoginFailed,
    LocalLoginLocked,
    LocalPasswordNotEnabled,
    LocalPasswordAlreadyEnabled,
    OidcUnavailable,
    OidcFlowInvalid,
    OidcFlowExpired,
    OidcProviderDenied,
    OidcIdentityInvalid,
    OidcGroupClaimsIncomplete,
    OidcAdmissionDenied,
    OidcLoginMethodConflict,
    ExternalGroupBindingNotFound,
    ExternalGroupBindingConflict,
    RightMissing,
    ServiceActionDenied,
    WebhookDestinationDenied,
    ScopeUnresolved,
    InvalidDraftHandle,
    LocatorInvalid,
    LookupFailed,
    CredentialNotFound,
    CredentialNotProvisioned,
    CredentialInvalid,
    CredentialExpired,
    CredentialEncryptFailed,
    CredentialDecryptFailed,
    ManagedStoreUnavailable,
    ManagedStoreMigrationRequired,
    EncryptionKeyMissing,
    EncryptionKeyInvalid,
    BodyMalformed,
    BodyFormatUnsupported,
    ResponseFormatUnsupported,
    BodySizeDenied,
    ReloadInProgress,
    ConfigReadFailed,
    ConfigParseFailed,
    ConfigValidationFailed,
    ConfigAdmissionFailed,
    AttachmentSizeDenied,
    AttachmentIntegrityMismatch,
    AttachmentMediaTypeDenied,
    RateLimited,
    ConcurrencyLimited,
    VersionConflict,
    VerificationMismatch,
    MutationVerificationFailed,
    UpstreamUnauthorized,
    UpstreamForbidden,
    UpstreamFailed,
    UpstreamRateLimited,
    UpstreamConnectionFailed,
    UpstreamProtocolFailed,
    CursorSigningUnavailable,
    UpstreamTimeout,
    OperationCancelled,
    OperationTimeout,
    OperationFailed,
    /// A provider reported an outcome its contract does not allow. The Broker
    /// records a safe diagnostic and never forwards the provider's text or
    /// code. Host-only.
    BrokerProviderContractFailed,
    GatewayHostInvalid,
    GatewayHostUnmatched,
    GatewayRuleNotFound,
    GatewayMethodDenied,
    GatewayAuthRequired,
    GatewayAuthInvalid,
    GatewayScopeUnresolved,
    GatewayQueryDenied,
    GatewayHeaderDenied,
    GatewayContentTypeDenied,
    GatewayRequestBodyDenied,
    GatewayRequestCapExceeded,
    GatewayResponseCapExceeded,
    GatewayUpstreamDenied,
    GitServiceDenied,
    GitRefDenied,
    GitCapabilityDenied,
    GitPktLineMalformed,
    GitPrefixCapExceeded,
    AuditUnavailable,
    AuditQueryUnavailable,
    AuditRequestNotFound,
    AuditQueryTimeout,
}

impl ReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestIdMissing => "request_id_missing",
            Self::RequestIdInvalid => "request_id_invalid",
            Self::InputInvalid => "input_invalid",
            Self::CallerAuthenticationRequired => "caller_authentication_required",
            Self::CallerAuthenticationInvalid => "caller_authentication_invalid",
            Self::CallerIdentityForwardingDenied => "caller_identity_forwarding_denied",
            Self::IdentityRequired => "identity_required",
            Self::IdentityInvalid => "identity_invalid",
            Self::CallerUserAssertionDenied => "caller_user_assertion_denied",
            Self::IdentityAssertionInvalid => "identity_assertion_invalid",
            Self::IdentityAssertionUnsupported => "identity_assertion_unsupported",
            Self::IdentityAssertionDenied => "identity_assertion_denied",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::IdentityBindingConflict => "identity_binding_conflict",
            Self::IdentityVersionConflict => "identity_version_conflict",
            Self::IdentityBindingNotFound => "identity_binding_not_found",
            Self::ExecutionContextRequired => "execution_context_required",
            Self::ExecutionContextInvalid => "execution_context_invalid",
            Self::ExecutionContextDenied => "execution_context_denied",
            Self::PrincipalRequired => "principal_required",
            Self::PrincipalNotFound => "principal_not_found",
            Self::PrincipalDisabled => "principal_disabled",
            Self::GroupNotFound => "group_not_found",
            Self::PolicyGrantNotFound => "policy_grant_not_found",
            Self::ResourceNotFound => "resource_not_found",
            Self::ResourceGroupNotFound => "resource_group_not_found",
            Self::ResourceInUse => "resource_in_use",
            Self::PolicyAuthorityUnavailable => "policy_authority_unavailable",
            Self::PolicyValidationFailed => "policy_validation_failed",
            Self::BrokerTokenNotFound => "broker_token_not_found",
            Self::BrokerTokenExpired => "broker_token_expired",
            Self::BrokerTokenPaused => "broker_token_paused",
            Self::BrokerTokenRevoked => "broker_token_revoked",
            Self::BrokerTokenStateConflict => "broker_token_state_conflict",
            Self::BrokerTokenClassDenied => "broker_token_class_denied",
            Self::ManagementDenied => "management_denied",
            Self::SelfServiceDisabled => "self_service_disabled",
            Self::CsrfInvalid => "csrf_invalid",
            Self::PasswordChangeRequired => "password_change_required",
            Self::LocalLoginFailed => "local_login_failed",
            Self::LocalLoginLocked => "local_login_locked",
            Self::LocalPasswordNotEnabled => "local_password_not_enabled",
            Self::LocalPasswordAlreadyEnabled => "local_password_already_enabled",
            Self::OidcUnavailable => "oidc_unavailable",
            Self::OidcFlowInvalid => "oidc_flow_invalid",
            Self::OidcFlowExpired => "oidc_flow_expired",
            Self::OidcProviderDenied => "oidc_provider_denied",
            Self::OidcIdentityInvalid => "oidc_identity_invalid",
            Self::OidcGroupClaimsIncomplete => "oidc_group_claims_incomplete",
            Self::OidcAdmissionDenied => "oidc_admission_denied",
            Self::OidcLoginMethodConflict => "oidc_login_method_conflict",
            Self::ExternalGroupBindingNotFound => "external_group_binding_not_found",
            Self::ExternalGroupBindingConflict => "external_group_binding_conflict",
            Self::RightMissing => "right_missing",
            Self::ServiceActionDenied => "service_action_denied",
            Self::WebhookDestinationDenied => "webhook_destination_denied",
            Self::ScopeUnresolved => "scope_unresolved",
            Self::InvalidDraftHandle => "invalid_draft_handle",
            Self::LocatorInvalid => "locator_invalid",
            Self::LookupFailed => "lookup_failed",
            Self::CredentialNotFound => "credential_not_found",
            Self::CredentialNotProvisioned => "credential_not_provisioned",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialExpired => "credential_expired",
            Self::CredentialEncryptFailed => "credential_encrypt_failed",
            Self::CredentialDecryptFailed => "credential_decrypt_failed",
            Self::ManagedStoreUnavailable => "managed_store_unavailable",
            Self::ManagedStoreMigrationRequired => "managed_store_migration_required",
            Self::EncryptionKeyMissing => "encryption_key_missing",
            Self::EncryptionKeyInvalid => "encryption_key_invalid",
            Self::BodyMalformed => "body_malformed",
            Self::BodyFormatUnsupported => "body_format_unsupported",
            Self::ResponseFormatUnsupported => "response_format_unsupported",
            Self::BodySizeDenied => "body_size_denied",
            Self::ReloadInProgress => "reload_in_progress",
            Self::ConfigReadFailed => "config_read_failed",
            Self::ConfigParseFailed => "config_parse_failed",
            Self::ConfigValidationFailed => "config_validation_failed",
            Self::ConfigAdmissionFailed => "config_admission_failed",
            Self::AttachmentSizeDenied => "attachment_size_denied",
            Self::AttachmentIntegrityMismatch => "attachment_integrity_mismatch",
            Self::AttachmentMediaTypeDenied => "attachment_media_type_denied",
            Self::RateLimited => "rate_limited",
            Self::ConcurrencyLimited => "concurrency_limited",
            Self::VersionConflict => "version_conflict",
            Self::VerificationMismatch => "verification_mismatch",
            Self::MutationVerificationFailed => "mutation_verification_failed",
            Self::UpstreamUnauthorized => "upstream_unauthorized",
            Self::UpstreamForbidden => "upstream_forbidden",
            Self::UpstreamFailed => "upstream_failed",
            Self::UpstreamRateLimited => "upstream_rate_limited",
            Self::UpstreamConnectionFailed => "upstream_connection_failed",
            Self::UpstreamProtocolFailed => "upstream_protocol_failed",
            Self::CursorSigningUnavailable => "cursor_signing_unavailable",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::OperationCancelled => "operation_cancelled",
            Self::OperationTimeout => "operation_timeout",
            Self::OperationFailed => "operation_failed",
            Self::BrokerProviderContractFailed => "broker_provider_contract_failed",
            Self::GatewayHostInvalid => "gateway_host_invalid",
            Self::GatewayHostUnmatched => "gateway_host_unmatched",
            Self::GatewayRuleNotFound => "gateway_rule_not_found",
            Self::GatewayMethodDenied => "gateway_method_denied",
            Self::GatewayAuthRequired => "gateway_auth_required",
            Self::GatewayAuthInvalid => "gateway_auth_invalid",
            Self::GatewayScopeUnresolved => "gateway_scope_unresolved",
            Self::GatewayQueryDenied => "gateway_query_denied",
            Self::GatewayHeaderDenied => "gateway_header_denied",
            Self::GatewayContentTypeDenied => "gateway_content_type_denied",
            Self::GatewayRequestBodyDenied => "gateway_request_body_denied",
            Self::GatewayRequestCapExceeded => "gateway_request_cap_exceeded",
            Self::GatewayResponseCapExceeded => "gateway_response_cap_exceeded",
            Self::GatewayUpstreamDenied => "gateway_upstream_denied",
            Self::GitServiceDenied => "git_service_denied",
            Self::GitRefDenied => "git_ref_denied",
            Self::GitCapabilityDenied => "git_capability_denied",
            Self::GitPktLineMalformed => "git_pkt_line_malformed",
            Self::GitPrefixCapExceeded => "git_prefix_cap_exceeded",
            Self::AuditUnavailable => "audit_unavailable",
            Self::AuditQueryUnavailable => "audit_query_unavailable",
            Self::AuditRequestNotFound => "audit_request_not_found",
            Self::AuditQueryTimeout => "audit_query_timeout",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::RequestIdMissing
            | Self::RequestIdInvalid
            | Self::InputInvalid
            | Self::IdentityAssertionInvalid
            | Self::IdentityAssertionUnsupported
            | Self::InvalidDraftHandle
            | Self::PolicyAuthorityUnavailable
            | Self::PolicyValidationFailed
            | Self::BodyMalformed
            | Self::GatewayHostInvalid
            | Self::GatewayQueryDenied
            | Self::GatewayHeaderDenied
            | Self::GatewayRequestBodyDenied
            | Self::GitPktLineMalformed
            | Self::GitServiceDenied
            | Self::ConfigParseFailed
            | Self::ConfigValidationFailed => 400,
            Self::CallerAuthenticationRequired
            | Self::CallerAuthenticationInvalid
            | Self::IdentityRequired
            | Self::IdentityInvalid
            | Self::BrokerTokenNotFound
            | Self::BrokerTokenExpired
            | Self::BrokerTokenPaused
            | Self::BrokerTokenRevoked
            | Self::GatewayAuthRequired
            | Self::GatewayAuthInvalid
            | Self::LocalLoginFailed
            | Self::LocalLoginLocked
            | Self::OidcProviderDenied
            | Self::OidcIdentityInvalid => 401,
            Self::PrincipalNotFound
            | Self::IdentityBindingNotFound
            | Self::GroupNotFound
            | Self::PolicyGrantNotFound
            | Self::ResourceNotFound
            | Self::ResourceGroupNotFound
            | Self::CredentialNotFound
            | Self::ExternalGroupBindingNotFound
            | Self::GatewayHostUnmatched
            | Self::GatewayRuleNotFound
            | Self::AuditQueryUnavailable
            | Self::AuditRequestNotFound => 404,
            Self::ServiceActionDenied
            | Self::CallerUserAssertionDenied
            | Self::IdentityAssertionDenied
            | Self::WebhookDestinationDenied
            | Self::CallerIdentityForwardingDenied
            | Self::ExecutionContextRequired
            | Self::ExecutionContextInvalid
            | Self::ExecutionContextDenied
            | Self::PrincipalRequired
            | Self::PrincipalDisabled
            | Self::BrokerTokenClassDenied
            | Self::ManagementDenied
            | Self::SelfServiceDisabled
            | Self::CsrfInvalid
            | Self::PasswordChangeRequired
            | Self::OidcGroupClaimsIncomplete
            | Self::OidcAdmissionDenied
            | Self::RightMissing
            | Self::ScopeUnresolved
            | Self::GatewayScopeUnresolved
            | Self::LocatorInvalid
            | Self::LookupFailed
            | Self::CredentialNotProvisioned
            | Self::CredentialInvalid
            | Self::CredentialExpired
            | Self::GitRefDenied
            | Self::GitCapabilityDenied => 403,
            Self::LocalPasswordNotEnabled
            | Self::IdentityBindingConflict
            | Self::IdentityVersionConflict
            | Self::LocalPasswordAlreadyEnabled
            | Self::ResourceInUse
            | Self::VersionConflict
            | Self::BrokerTokenStateConflict
            | Self::VerificationMismatch
            | Self::MutationVerificationFailed
            | Self::ReloadInProgress
            | Self::OidcLoginMethodConflict
            | Self::ExternalGroupBindingConflict => 409,
            Self::GatewayMethodDenied => 405,
            Self::BodySizeDenied
            | Self::AttachmentSizeDenied
            | Self::AttachmentIntegrityMismatch => 413,
            Self::GatewayRequestCapExceeded | Self::GitPrefixCapExceeded => 413,
            Self::BodyFormatUnsupported
            | Self::ResponseFormatUnsupported
            | Self::AttachmentMediaTypeDenied
            | Self::GatewayContentTypeDenied => 415,
            Self::RateLimited | Self::ConcurrencyLimited | Self::UpstreamRateLimited => 429,
            Self::UpstreamUnauthorized | Self::UpstreamForbidden | Self::UpstreamFailed => 424,
            Self::UpstreamConnectionFailed
            | Self::UpstreamProtocolFailed
            | Self::GatewayResponseCapExceeded
            | Self::GatewayUpstreamDenied => 502,
            Self::UpstreamTimeout | Self::OperationTimeout => 504,
            Self::OperationCancelled => 408,
            Self::OperationFailed | Self::BrokerProviderContractFailed => 500,
            Self::CredentialEncryptFailed
            | Self::IdentityUnavailable
            | Self::CredentialDecryptFailed
            | Self::CursorSigningUnavailable
            | Self::ManagedStoreUnavailable
            | Self::ManagedStoreMigrationRequired
            | Self::EncryptionKeyMissing
            | Self::EncryptionKeyInvalid
            | Self::AuditUnavailable
            | Self::AuditQueryTimeout
            | Self::ConfigReadFailed
            | Self::ConfigAdmissionFailed
            | Self::OidcUnavailable => 503,
            Self::OidcFlowInvalid | Self::OidcFlowExpired => 400,
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::RequestIdMissing,
            Self::RequestIdInvalid,
            Self::InputInvalid,
            Self::CallerAuthenticationRequired,
            Self::CallerAuthenticationInvalid,
            Self::CallerIdentityForwardingDenied,
            Self::IdentityRequired,
            Self::IdentityInvalid,
            Self::CallerUserAssertionDenied,
            Self::IdentityAssertionInvalid,
            Self::IdentityAssertionUnsupported,
            Self::IdentityAssertionDenied,
            Self::IdentityUnavailable,
            Self::IdentityBindingConflict,
            Self::IdentityVersionConflict,
            Self::IdentityBindingNotFound,
            Self::ExecutionContextRequired,
            Self::ExecutionContextInvalid,
            Self::ExecutionContextDenied,
            Self::PrincipalRequired,
            Self::PrincipalNotFound,
            Self::PrincipalDisabled,
            Self::GroupNotFound,
            Self::PolicyGrantNotFound,
            Self::ResourceNotFound,
            Self::ResourceGroupNotFound,
            Self::ResourceInUse,
            Self::PolicyAuthorityUnavailable,
            Self::PolicyValidationFailed,
            Self::BrokerTokenNotFound,
            Self::BrokerTokenExpired,
            Self::BrokerTokenPaused,
            Self::BrokerTokenRevoked,
            Self::BrokerTokenStateConflict,
            Self::BrokerTokenClassDenied,
            Self::ManagementDenied,
            Self::SelfServiceDisabled,
            Self::CsrfInvalid,
            Self::PasswordChangeRequired,
            Self::LocalLoginFailed,
            Self::LocalLoginLocked,
            Self::LocalPasswordNotEnabled,
            Self::LocalPasswordAlreadyEnabled,
            Self::OidcUnavailable,
            Self::OidcFlowInvalid,
            Self::OidcFlowExpired,
            Self::OidcProviderDenied,
            Self::OidcIdentityInvalid,
            Self::OidcGroupClaimsIncomplete,
            Self::OidcAdmissionDenied,
            Self::OidcLoginMethodConflict,
            Self::ExternalGroupBindingNotFound,
            Self::ExternalGroupBindingConflict,
            Self::RightMissing,
            Self::ServiceActionDenied,
            Self::WebhookDestinationDenied,
            Self::ScopeUnresolved,
            Self::InvalidDraftHandle,
            Self::LocatorInvalid,
            Self::LookupFailed,
            Self::CredentialNotFound,
            Self::CredentialNotProvisioned,
            Self::CredentialInvalid,
            Self::CredentialExpired,
            Self::CredentialEncryptFailed,
            Self::CredentialDecryptFailed,
            Self::ManagedStoreUnavailable,
            Self::ManagedStoreMigrationRequired,
            Self::EncryptionKeyMissing,
            Self::EncryptionKeyInvalid,
            Self::BodyMalformed,
            Self::BodyFormatUnsupported,
            Self::ResponseFormatUnsupported,
            Self::BodySizeDenied,
            Self::ReloadInProgress,
            Self::ConfigReadFailed,
            Self::ConfigParseFailed,
            Self::ConfigValidationFailed,
            Self::ConfigAdmissionFailed,
            Self::AttachmentSizeDenied,
            Self::AttachmentIntegrityMismatch,
            Self::AttachmentMediaTypeDenied,
            Self::RateLimited,
            Self::ConcurrencyLimited,
            Self::VersionConflict,
            Self::VerificationMismatch,
            Self::MutationVerificationFailed,
            Self::UpstreamUnauthorized,
            Self::UpstreamForbidden,
            Self::UpstreamFailed,
            Self::UpstreamRateLimited,
            Self::UpstreamConnectionFailed,
            Self::UpstreamProtocolFailed,
            Self::CursorSigningUnavailable,
            Self::UpstreamTimeout,
            Self::OperationCancelled,
            Self::OperationTimeout,
            Self::OperationFailed,
            Self::BrokerProviderContractFailed,
            Self::GatewayHostInvalid,
            Self::GatewayHostUnmatched,
            Self::GatewayRuleNotFound,
            Self::GatewayMethodDenied,
            Self::GatewayAuthRequired,
            Self::GatewayAuthInvalid,
            Self::GatewayScopeUnresolved,
            Self::GatewayQueryDenied,
            Self::GatewayHeaderDenied,
            Self::GatewayContentTypeDenied,
            Self::GatewayRequestBodyDenied,
            Self::GatewayRequestCapExceeded,
            Self::GatewayResponseCapExceeded,
            Self::GatewayUpstreamDenied,
            Self::GitServiceDenied,
            Self::GitRefDenied,
            Self::GitCapabilityDenied,
            Self::GitPktLineMalformed,
            Self::GitPrefixCapExceeded,
            Self::AuditUnavailable,
            Self::AuditQueryUnavailable,
            Self::AuditRequestNotFound,
            Self::AuditQueryTimeout,
        ]
    }
}

/// The provider hook a failure or trace comes from. The host supplies it for
/// every hook it runs; it is never inferred from a reason.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPhase {
    /// Scope resolution (S), including any pre-authorization lookup.
    ScopeResolution,
    /// Body admission (A).
    BodyAdmission,
    /// The invocation result (I).
    Invocation,
    /// Credential verification (V).
    CredentialVerification,
}

impl HookPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScopeResolution => "scope_resolution",
            Self::BodyAdmission => "body_admission",
            Self::Invocation => "invocation",
            Self::CredentialVerification => "credential_verification",
        }
    }
}

/// Which failure decisions a provider-emittable standard reason allows.
#[derive(Clone, Copy)]
enum FailureDecisions {
    Deny,
    Error,
    DenyOrError,
}

impl FailureDecisions {
    fn permit(self, decision: &Decision) -> bool {
        matches!(
            (self, decision),
            (Self::Deny | Self::DenyOrError, Decision::Deny)
                | (Self::Error | Self::DenyOrError, Decision::Error)
        )
    }
}

const SAIV: &[HookPhase] = &[
    HookPhase::ScopeResolution,
    HookPhase::BodyAdmission,
    HookPhase::Invocation,
    HookPhase::CredentialVerification,
];
const SAI: &[HookPhase] = &[
    HookPhase::ScopeResolution,
    HookPhase::BodyAdmission,
    HookPhase::Invocation,
];
const INVOCATION: &[HookPhase] = &[HookPhase::Invocation];

impl ReasonCode {
    /// The decisions and hook phases a provider may report this standard
    /// reason in, or `None` when only the Broker host reports it.
    fn provider_rule(self) -> Option<(FailureDecisions, &'static [HookPhase])> {
        use FailureDecisions::{Deny, DenyOrError, Error};
        Some(match self {
            Self::InputInvalid | Self::BodyMalformed => (DenyOrError, SAIV),
            Self::InvalidDraftHandle => (Deny, SAI),
            Self::ServiceActionDenied
            | Self::ScopeUnresolved
            | Self::LocatorInvalid
            | Self::CredentialNotProvisioned
            | Self::GitRefDenied
            | Self::WebhookDestinationDenied => (Deny, SAIV),
            Self::CredentialInvalid | Self::ResourceNotFound => (DenyOrError, SAIV),
            Self::VerificationMismatch => (Deny, SAIV),
            Self::VersionConflict => (DenyOrError, SAIV),
            Self::MutationVerificationFailed => (Error, INVOCATION),
            Self::BodySizeDenied
            | Self::AttachmentSizeDenied
            | Self::AttachmentIntegrityMismatch
            | Self::BodyFormatUnsupported
            | Self::ResponseFormatUnsupported
            | Self::AttachmentMediaTypeDenied => (Deny, SAIV),
            Self::UpstreamUnauthorized | Self::UpstreamForbidden => (DenyOrError, SAIV),
            Self::UpstreamFailed | Self::UpstreamRateLimited | Self::UpstreamConnectionFailed => {
                (Error, SAIV)
            }
            Self::UpstreamProtocolFailed => (DenyOrError, SAIV),
            Self::CursorSigningUnavailable => (Error, SAI),
            Self::UpstreamTimeout | Self::OperationFailed | Self::OperationCancelled => {
                (Error, SAIV)
            }
            _ => return None,
        })
    }

    /// Whether a provider may report this standard reason at all. Every
    /// other standard reason belongs to the Broker host; a delegated host
    /// port may still pass one through as a host-origin failure.
    pub fn is_provider_emittable(self) -> bool {
        self.provider_rule().is_some()
    }

    /// Whether a provider hook running in `phase` may fail with this standard
    /// reason and `decision`. An allow decision is never a failure; see
    /// [`Self::permits_provider_allow`].
    pub fn permits_provider_failure(self, decision: &Decision, phase: HookPhase) -> bool {
        self.provider_rule().is_some_and(|(decisions, phases)| {
            decisions.permit(decision) && phases.contains(&phase)
        })
    }

    /// Whether an upstream trace in a hook running in `phase` may carry this
    /// standard reason. A trace confers no decision, so any decision the
    /// provider may report it with in that hook qualifies.
    pub fn permits_provider_trace(self, phase: HookPhase) -> bool {
        self.provider_rule()
            .is_some_and(|(_, phases)| phases.contains(&phase))
    }

    /// Whether a provider may report this reason with an allow decision:
    /// only `verification_mismatch` from an invocation, and only together
    /// with its verification result.
    pub fn permits_provider_allow(
        self,
        phase: HookPhase,
        carries_verification_result: bool,
    ) -> bool {
        self == Self::VerificationMismatch
            && phase == HookPhase::Invocation
            && carries_verification_result
    }

    /// Whether a result stream that fails after the response started may
    /// classify the failure with this standard reason. Late stream failures
    /// carry only a code; the host keeps its own late-failure decision.
    pub fn permits_late_stream(self) -> bool {
        matches!(
            self,
            Self::AttachmentSizeDenied
                | Self::UpstreamConnectionFailed
                | Self::UpstreamProtocolFailed
                | Self::UpstreamTimeout
        )
    }
}

/// The wire identifier of a reason: a standard [`ReasonCode`] spelling or a
/// provider's domain reason code.
///
/// Responses, audit records, filters and historical readers carry this one
/// string, so they stay readable when the module that defined the reason is
/// not linked. It is bounded data, not a classification: it has no status or
/// decision of its own. Its syntax is `^[a-z][a-z0-9_]{0,63}$`; serde reads
/// and writes the bare string and rejects anything else.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReasonCodeId(Cow<'static, str>);

impl ReasonCodeId {
    /// The longest identifier, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validates `value` as a reason identifier.
    pub fn new(value: impl Into<Cow<'static, str>>) -> Result<Self, InvalidReasonCodeId> {
        let value = value.into();
        if is_reason_code_id(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidReasonCodeId)
        }
    }

    /// An identifier already known to be valid.
    pub(crate) fn from_valid(value: Cow<'static, str>) -> Self {
        debug_assert!(is_reason_code_id(&value));
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The standard reason with this spelling, if there is one.
    pub fn standard(&self) -> Option<ReasonCode> {
        ReasonCode::all()
            .iter()
            .copied()
            .find(|code| code.as_str() == self.as_str())
    }
}

/// Whether `value` has reason identifier syntax: `^[a-z][a-z0-9_]{0,63}$`.
pub const fn is_reason_code_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > ReasonCodeId::MAX_LEN || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
            return false;
        }
        index += 1;
    }
    true
}

impl From<ReasonCode> for ReasonCodeId {
    fn from(code: ReasonCode) -> Self {
        Self(Cow::Borrowed(code.as_str()))
    }
}

impl PartialEq<ReasonCode> for ReasonCodeId {
    fn eq(&self, other: &ReasonCode) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<ReasonCodeId> for ReasonCode {
    fn eq(&self, other: &ReasonCodeId) -> bool {
        other == self
    }
}

impl fmt::Debug for ReasonCodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), formatter)
    }
}

impl fmt::Display for ReasonCodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ReasonCodeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ReasonCodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A string without reason identifier syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidReasonCodeId;

impl fmt::Display for InvalidReasonCodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a reason code must match ^[a-z][a-z0-9_]{0,63}$")
    }
}

impl std::error::Error for InvalidReasonCodeId {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_spellings_are_identifiers_and_match_serde() {
        let mut spellings = std::collections::BTreeSet::new();
        for &code in ReasonCode::all() {
            let id = ReasonCodeId::from(code);
            assert!(is_reason_code_id(code.as_str()), "{code:?}");
            assert_eq!(
                serde_json::to_value(code).unwrap(),
                serde_json::json!(code.as_str())
            );
            assert_eq!(
                serde_json::to_value(&id).unwrap(),
                serde_json::json!(code.as_str())
            );
            assert_eq!(
                serde_json::from_value::<ReasonCode>(serde_json::json!(code.as_str())).unwrap(),
                code
            );
            assert_eq!(id.standard(), Some(code));
            assert_eq!(id, code);
            assert!(spellings.insert(code.as_str()), "{code:?} is listed twice");
        }
    }

    #[test]
    fn identifiers_are_bounded_snake_case() {
        for valid in [
            "a",
            "upstream_failed",
            "cloudbees_ci_log_chunk_exceeded",
            "x9_",
        ] {
            assert!(ReasonCodeId::new(valid).is_ok(), "{valid}");
        }
        let longest = "a".repeat(ReasonCodeId::MAX_LEN);
        assert!(ReasonCodeId::new(longest.clone()).is_ok());
        for invalid in [
            String::new(),
            "_leading".into(),
            "9digit".into(),
            "Upper".into(),
            "has-hyphen".into(),
            "has space".into(),
            "caf\u{e9}".into(),
            format!("{longest}a"),
        ] {
            assert_eq!(
                ReasonCodeId::new(invalid.clone()),
                Err(InvalidReasonCodeId),
                "{invalid}"
            );
            assert!(
                serde_json::from_value::<ReasonCodeId>(serde_json::json!(invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn identifiers_outside_the_standard_vocabulary_stay_readable() {
        let id: ReasonCodeId =
            serde_json::from_value(serde_json::json!("example_module_quota_exceeded")).unwrap();
        assert_eq!(id.as_str(), "example_module_quota_exceeded");
        assert_eq!(id.standard(), None);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            "\"example_module_quota_exceeded\""
        );
    }

    #[test]
    fn provider_emittable_standard_reasons_match_the_contract() {
        use HookPhase::{BodyAdmission, CredentialVerification, Invocation, ScopeResolution};
        use ReasonCode as R;
        const ALL: &[HookPhase] = &[
            ScopeResolution,
            BodyAdmission,
            Invocation,
            CredentialVerification,
        ];
        const NO_V: &[HookPhase] = &[ScopeResolution, BodyAdmission, Invocation];
        const ONLY_I: &[HookPhase] = &[Invocation];
        /// Reasons, HTTP status, deny, error and phases, as published.
        type Row = (&'static [ReasonCode], u16, bool, bool, &'static [HookPhase]);
        let table: &[Row] = &[
            (&[R::InputInvalid, R::BodyMalformed], 400, true, true, ALL),
            (&[R::InvalidDraftHandle], 400, true, false, NO_V),
            (
                &[
                    R::ServiceActionDenied,
                    R::ScopeUnresolved,
                    R::LocatorInvalid,
                    R::CredentialNotProvisioned,
                    R::GitRefDenied,
                    R::WebhookDestinationDenied,
                ],
                403,
                true,
                false,
                ALL,
            ),
            (&[R::CredentialInvalid], 403, true, true, ALL),
            (&[R::ResourceNotFound], 404, true, true, ALL),
            (&[R::VerificationMismatch], 409, true, false, ALL),
            (&[R::VersionConflict], 409, true, true, ALL),
            (&[R::MutationVerificationFailed], 409, false, true, ONLY_I),
            (
                &[
                    R::BodySizeDenied,
                    R::AttachmentSizeDenied,
                    R::AttachmentIntegrityMismatch,
                ],
                413,
                true,
                false,
                ALL,
            ),
            (
                &[
                    R::BodyFormatUnsupported,
                    R::ResponseFormatUnsupported,
                    R::AttachmentMediaTypeDenied,
                ],
                415,
                true,
                false,
                ALL,
            ),
            (
                &[R::UpstreamUnauthorized, R::UpstreamForbidden],
                424,
                true,
                true,
                ALL,
            ),
            (&[R::UpstreamFailed], 424, false, true, ALL),
            (&[R::UpstreamRateLimited], 429, false, true, ALL),
            (&[R::UpstreamConnectionFailed], 502, false, true, ALL),
            (&[R::UpstreamProtocolFailed], 502, true, true, ALL),
            (&[R::CursorSigningUnavailable], 503, false, true, NO_V),
            (&[R::UpstreamTimeout], 504, false, true, ALL),
            (&[R::OperationFailed], 500, false, true, ALL),
            (&[R::OperationCancelled], 408, false, true, ALL),
        ];
        let mut listed = std::collections::BTreeSet::new();
        for &(reasons, status, deny, error, phases) in table {
            for &reason in reasons {
                assert!(listed.insert(reason), "{reason:?} is listed twice");
                assert_eq!(reason.http_status(), status, "{reason:?}");
                assert!(reason.is_provider_emittable(), "{reason:?}");
                for &phase in ALL {
                    let in_phase = phases.contains(&phase);
                    assert_eq!(
                        reason.permits_provider_failure(&Decision::Deny, phase),
                        deny && in_phase,
                        "{reason:?} deny {phase:?}"
                    );
                    assert_eq!(
                        reason.permits_provider_failure(&Decision::Error, phase),
                        error && in_phase,
                        "{reason:?} error {phase:?}"
                    );
                    assert!(!reason.permits_provider_failure(&Decision::Allow, phase));
                }
            }
        }
        for &reason in ReasonCode::all() {
            let host_only = !listed.contains(&reason);
            assert_eq!(reason.is_provider_emittable(), !host_only, "{reason:?}");
            for &phase in ALL {
                for decision in [Decision::Allow, Decision::Deny, Decision::Error] {
                    if host_only {
                        assert!(
                            !reason.permits_provider_failure(&decision, phase),
                            "{reason:?}"
                        );
                    }
                }
                assert_eq!(
                    reason.permits_provider_allow(phase, true),
                    reason == R::VerificationMismatch && phase == Invocation,
                    "{reason:?} allow {phase:?}"
                );
                assert!(!reason.permits_provider_allow(phase, false), "{reason:?}");
            }
            assert_eq!(
                reason.permits_late_stream(),
                matches!(
                    reason,
                    R::AttachmentSizeDenied
                        | R::UpstreamConnectionFailed
                        | R::UpstreamProtocolFailed
                        | R::UpstreamTimeout
                ),
                "{reason:?}"
            );
        }
        for host_only in [
            R::ConcurrencyLimited,
            R::RateLimited,
            R::OperationTimeout,
            R::ConfigValidationFailed,
            R::BrokerProviderContractFailed,
            R::CsrfInvalid,
            R::CallerAuthenticationRequired,
            R::ManagementDenied,
        ] {
            assert!(!host_only.is_provider_emittable(), "{host_only:?}");
        }
    }

    #[test]
    fn provider_contract_failure_is_a_host_error() {
        let code = ReasonCode::BrokerProviderContractFailed;
        assert_eq!(code.as_str(), "broker_provider_contract_failed");
        assert_eq!(code.http_status(), 500);
    }
}
