use serde::{Deserialize, Serialize};

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
    CloudbeesCiLogChunkExceeded,
    CloudbeesCiLogScanExceeded,
    CursorSigningUnavailable,
    UpstreamTimeout,
    OperationCancelled,
    OperationTimeout,
    OperationFailed,
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
            Self::CloudbeesCiLogChunkExceeded => "cloudbees_ci_log_chunk_exceeded",
            Self::CloudbeesCiLogScanExceeded => "cloudbees_ci_log_scan_exceeded",
            Self::CursorSigningUnavailable => "cursor_signing_unavailable",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::OperationCancelled => "operation_cancelled",
            Self::OperationTimeout => "operation_timeout",
            Self::OperationFailed => "operation_failed",
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
            | Self::AttachmentIntegrityMismatch
            | Self::CloudbeesCiLogChunkExceeded
            | Self::CloudbeesCiLogScanExceeded => 413,
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
            Self::OperationFailed => 500,
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
            Self::CloudbeesCiLogChunkExceeded,
            Self::CloudbeesCiLogScanExceeded,
            Self::CursorSigningUnavailable,
            Self::UpstreamTimeout,
            Self::OperationCancelled,
            Self::OperationTimeout,
            Self::OperationFailed,
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
