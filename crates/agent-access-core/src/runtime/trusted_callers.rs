//! Caller attestation is independent of principal authentication.
use super::*;
use crate::{TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport};
use subtle::ConstantTimeEq;

pub const CALLER_AUTHORIZATION_HEADER: &str = "x-agent-access-caller-authorization";
pub const USER_HEADER: &str = "x-agent-access-user";
const IDENTITY_HEADER: &str = "x-aw-identity-token-sha256";

#[derive(Clone)]
pub(super) struct ResolvedTrustedCaller {
    name: String,
    credential: Arc<str>,
    config: TrustedCallerConfig,
    binding: [u8; 32],
}

/// Opaque equality evidence for the complete loaded caller security contract.
/// Only process-local epoch comparison may use this value.
#[derive(Clone, PartialEq, Eq)]
pub struct CallerSecurityBinding(Vec<[u8; 32]>);
impl std::fmt::Debug for CallerSecurityBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerSecurityBinding([redacted])")
    }
}

#[derive(Clone)]
enum IngressIdentity {
    Ordinary,
    Fingerprint(String),
    Username {
        name: String,
        transport: TrustedCallerCredentialTransport,
    },
}

/// Authenticated caller attributes resolved against a single runtime snapshot.
/// The private binding must only be used in a keyed session-owner signature.
#[derive(Clone)]
pub struct IngressAdmission {
    caller: Option<ResolvedTrustedCaller>,
    context: Option<ExecutionContext>,
    identity: IngressIdentity,
}
impl std::fmt::Debug for IngressAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressAdmission")
            .field("caller_id", &self.caller_id())
            .field("context", &self.context)
            .field("username", &self.is_username())
            .finish_non_exhaustive()
    }
}
impl IngressAdmission {
    pub fn caller_id(&self) -> Option<&str> {
        self.caller.as_ref().map(|caller| caller.name.as_str())
    }
    pub fn caller_binding(&self) -> Option<&[u8]> {
        self.caller.as_ref().map(|caller| caller.binding.as_slice())
    }
    pub fn is_username(&self) -> bool {
        matches!(self.identity, IngressIdentity::Username { .. })
    }
    pub fn is_direct_username(&self) -> bool {
        matches!(
            self.identity,
            IngressIdentity::Username {
                transport: TrustedCallerCredentialTransport::AuthorizationUser,
                ..
            }
        )
    }
    pub fn execution_context(&self) -> Result<ExecutionContext, ExecutionContextFailure> {
        self.context
            .clone()
            .ok_or(ExecutionContextFailure::Required)
    }
}

/// Principal authority and private evidence from one managed identity transaction.
#[derive(Debug, Clone)]
pub struct AdmittedIdentity {
    pub identity: IdentityContext,
    pub proof: Option<crate::AttestedIdentityProof>,
}

/// The shared bounded single-field bearer grammar for username assertions and MCP.
pub fn parse_assertion_bearer<'a>(
    headers: &'a HeaderMap,
    header: &str,
) -> Result<Option<&'a str>, IdentityFailure> {
    let mut values = headers.get_all(header).iter();
    let Some(raw) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(IdentityFailure::AssertionInvalid);
    }
    let (scheme, token) = raw
        .to_str()
        .ok()
        .and_then(|value| value.split_once(' '))
        .ok_or(IdentityFailure::AssertionInvalid)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_assertion_token(token) {
        return Err(IdentityFailure::AssertionInvalid);
    }
    Ok(Some(token))
}

fn valid_assertion_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 8192
        && token
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
}

pub(super) fn load_trusted_callers(
    config: &BrokerConfig,
) -> Result<Arc<Vec<ResolvedTrustedCaller>>, RuntimeError> {
    let mut callers = Vec::<ResolvedTrustedCaller>::new();
    for (name, caller) in &config.identity.trusted_callers {
        let credential = load_secret_ref_value(
            &format!("identity.trusted_callers.{name}.credential_ref"),
            &caller.credential_ref,
        )?;
        if credential.len() < 16
            || !credential.bytes().all(|b| b.is_ascii_graphic())
            || (caller.username_namespace.is_some() && !valid_assertion_token(&credential))
        {
            return Err(RuntimeError::ManagedStore {
                message: format!(
                    "trusted caller {name} credential must contain at least 16 visible ASCII bytes; username credentials require at most 8192 bytes and forbid commas"
                ),
            });
        }
        if caller.credential_transport == TrustedCallerCredentialTransport::AuthorizationUser
            && credential.starts_with("aab_")
        {
            return Err(RuntimeError::ManagedStore {
                message: format!(
                    "trusted caller {name} direct credential uses the reserved managed-token namespace"
                ),
            });
        }
        if callers
            .iter()
            .any(|other| bool::from(credential.as_bytes().ct_eq(other.credential.as_bytes())))
        {
            return Err(RuntimeError::ManagedStore {
                message: "trusted caller credentials must be distinct".into(),
            });
        }
        // The secret and contract are length-delimited. Never publish or log this digest.
        let contract = json!([
            name,
            caller.credential_transport.as_str(),
            caller.username_namespace,
            caller.context_mode == TrustedCallerContextMode::Fixed,
            caller.execution_context,
            caller.allowed_execution_contexts,
            caller.allow_forwarded_identity
        ])
        .to_string();
        let mut digest = Sha256::new();
        digest.update((credential.len() as u64).to_be_bytes());
        digest.update(credential.as_bytes());
        digest.update((contract.len() as u64).to_be_bytes());
        digest.update(contract.as_bytes());
        callers.push(ResolvedTrustedCaller {
            name: name.clone(),
            credential: Arc::from(credential),
            config: caller.clone(),
            binding: digest.finalize().into(),
        });
    }
    Ok(Arc::new(callers))
}

pub(super) fn validate_caller_principal_credentials(
    callers: &[ResolvedTrustedCaller],
    sources: &[IdentitySourceResolver],
) -> Result<(), RuntimeError> {
    for caller in callers.iter().filter(|caller| {
        caller.config.credential_transport == TrustedCallerCredentialTransport::AuthorizationUser
    }) {
        for source in sources {
            if let IdentitySourceResolverKind::Static(source) = &source.resolver
                && source
                    .tokens
                    .keys()
                    .any(|token| bool::from(token.as_bytes().ct_eq(caller.credential.as_bytes())))
            {
                return Err(RuntimeError::ManagedStore {
                    message: format!(
                        "trusted caller {} direct credential collides with a static principal credential",
                        caller.name
                    ),
                });
            }
        }
    }
    Ok(())
}

impl BrokerRuntime {
    pub fn caller_security_binding(&self) -> CallerSecurityBinding {
        CallerSecurityBinding(
            self.trusted_callers
                .iter()
                .map(|caller| caller.binding)
                .collect(),
        )
    }

    /// Check hop-by-hop nominations before any middleware can strip evidence.
    pub fn validate_ingress_security_headers(
        &self,
        headers: &HeaderMap,
        reject_all_trailers: bool,
    ) -> Result<(), IdentityFailure> {
        let protected = |name: &str| {
            [
                "authorization",
                USER_HEADER,
                CALLER_AUTHORIZATION_HEADER,
                IDENTITY_HEADER,
                crate::EXECUTION_CONTEXT_HEADER,
            ]
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
                || self
                    .identity_sources
                    .iter()
                    .any(|source| name.eq_ignore_ascii_case(&source.audit.token_header))
        };
        for header in ["connection", "trailer"] {
            for raw in headers.get_all(header) {
                if header == "trailer" && reject_all_trailers {
                    return Err(IdentityFailure::AssertionInvalid);
                }
                let raw = raw
                    .to_str()
                    .map_err(|_| IdentityFailure::AssertionInvalid)?;
                for name in raw.split(',').map(str::trim) {
                    if protected(name) {
                        return Err(IdentityFailure::AssertionInvalid);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn admit_ingress(&self, headers: &HeaderMap) -> Result<IngressAdmission, IdentityFailure> {
        if headers.contains_key(USER_HEADER) {
            return Err(IdentityFailure::AssertionUnsupported);
        }
        self.validate_ingress_security_headers(headers, false)?;
        self.admit_ordinary_ingress(headers)
    }

    pub fn admit_mcp_ingress(
        &self,
        headers: &HeaderMap,
    ) -> Result<IngressAdmission, IdentityFailure> {
        self.validate_ingress_security_headers(headers, false)?;
        if !headers.contains_key(USER_HEADER) {
            return self.admit_ordinary_ingress(headers);
        }
        let mut names = headers.get_all(USER_HEADER).iter();
        let name = names
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(IdentityFailure::AssertionInvalid)?;
        if names.next().is_some() || !crate::is_valid_identity_username(name) {
            return Err(IdentityFailure::AssertionInvalid);
        }
        let direct = headers.contains_key(http::header::AUTHORIZATION);
        let relay = headers.contains_key(CALLER_AUTHORIZATION_HEADER);
        if (direct && relay)
            || headers.contains_key(IDENTITY_HEADER)
            || self.identity_sources.iter().any(|source| {
                !source
                    .audit
                    .token_header
                    .eq_ignore_ascii_case("authorization")
                    && headers.contains_key(source.audit.token_header.as_str())
            })
        {
            return Err(IdentityFailure::AssertionInvalid);
        }
        let (carrier, transport) = if direct {
            (
                "authorization",
                TrustedCallerCredentialTransport::AuthorizationUser,
            )
        } else {
            (
                CALLER_AUTHORIZATION_HEADER,
                TrustedCallerCredentialTransport::CallerAuthorization,
            )
        };
        let credential = parse_assertion_bearer(headers, carrier)?
            .ok_or(IdentityFailure::CallerAuthenticationRequired)?;
        let caller = self
            .match_caller(credential, transport)
            .ok_or(IdentityFailure::CallerAuthenticationInvalid)?;
        if caller.config.username_namespace.is_none() {
            return Err(IdentityFailure::CallerUserAssertionDenied);
        }
        let context = self.admitted_context(headers, Some(&caller))?;
        Ok(IngressAdmission {
            caller: Some(caller),
            context,
            identity: IngressIdentity::Username {
                name: name.to_owned(),
                transport,
            },
        })
    }

    fn match_caller(
        &self,
        credential: &str,
        transport: TrustedCallerCredentialTransport,
    ) -> Option<ResolvedTrustedCaller> {
        let mut matched = None;
        for caller in self.trusted_callers.iter() {
            let equal = bool::from(credential.as_bytes().ct_eq(caller.credential.as_bytes()));
            if equal && caller.config.credential_transport == transport {
                matched = Some(caller.clone());
            }
        }
        matched
    }

    fn admit_ordinary_ingress(
        &self,
        headers: &HeaderMap,
    ) -> Result<IngressAdmission, IdentityFailure> {
        // A direct caller secret alone is never a principal identity, including optional identity mode.
        if let Ok(Some(credential)) = parse_assertion_bearer(headers, "authorization")
            && self
                .match_caller(
                    credential,
                    TrustedCallerCredentialTransport::AuthorizationUser,
                )
                .is_some()
        {
            return Err(IdentityFailure::Invalid);
        }
        let mut supplied = headers.get_all(CALLER_AUTHORIZATION_HEADER).iter();
        let raw = supplied.next();
        if supplied.next().is_some() {
            return Err(IdentityFailure::CallerAuthenticationInvalid);
        }
        let caller = if let Some(raw) = raw {
            let credential = raw
                .to_str()
                .ok()
                .and_then(|value| value.strip_prefix("Bearer "))
                .ok_or(IdentityFailure::CallerAuthenticationInvalid)?;
            Some(
                self.match_caller(
                    credential,
                    TrustedCallerCredentialTransport::CallerAuthorization,
                )
                .ok_or(IdentityFailure::CallerAuthenticationInvalid)?,
            )
        } else {
            None
        };
        if caller.is_none()
            && (headers.contains_key(IDENTITY_HEADER)
                || headers.contains_key(crate::EXECUTION_CONTEXT_HEADER))
        {
            return Err(IdentityFailure::CallerAuthenticationRequired);
        }
        let identity = if headers.contains_key(IDENTITY_HEADER) {
            if !caller
                .as_ref()
                .is_some_and(|caller| caller.config.allow_forwarded_identity)
            {
                return Err(IdentityFailure::CallerIdentityForwardingDenied);
            }
            let mut values = headers.get_all(IDENTITY_HEADER).iter();
            let value = values
                .next()
                .and_then(|value| value.to_str().ok())
                .ok_or(IdentityFailure::Invalid)?;
            if values.next().is_some() {
                return Err(IdentityFailure::Invalid);
            }
            let hex = value
                .strip_prefix("sha256:")
                .ok_or(IdentityFailure::Invalid)?;
            if hex.len() != 64
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(IdentityFailure::Invalid);
            }
            IngressIdentity::Fingerprint(value.to_owned())
        } else {
            IngressIdentity::Ordinary
        };
        let context = self.admitted_context(headers, caller.as_ref())?;
        Ok(IngressAdmission {
            caller,
            context,
            identity,
        })
    }

    fn admitted_context(
        &self,
        headers: &HeaderMap,
        caller: Option<&ResolvedTrustedCaller>,
    ) -> Result<Option<ExecutionContext>, IdentityFailure> {
        let context = match caller {
            Some(caller) if caller.config.context_mode == TrustedCallerContextMode::Fixed => {
                if headers.contains_key(crate::EXECUTION_CONTEXT_HEADER) {
                    return Err(IdentityFailure::ExecutionContextInvalid);
                }
                caller.config.execution_context.clone()
            }
            Some(caller) => {
                let mut values = headers.get_all(crate::EXECUTION_CONTEXT_HEADER).iter();
                let context = values
                    .next()
                    .map(|raw| {
                        raw.to_str()
                            .map(str::to_owned)
                            .map_err(|_| IdentityFailure::ExecutionContextInvalid)
                    })
                    .transpose()?;
                if values.next().is_some() {
                    return Err(IdentityFailure::ExecutionContextInvalid);
                }
                if let Some(context) = &context {
                    if !crate::is_valid_execution_context_value(context)
                        || !self
                            .config
                            .execution_context
                            .as_ref()
                            .map_or(context == DEFAULT_EXECUTION_CONTEXT, |configured| {
                                configured.allowed_values.contains(context)
                            })
                    {
                        return Err(IdentityFailure::ExecutionContextInvalid);
                    }
                    if !caller
                        .config
                        .allowed_execution_contexts
                        .as_ref()
                        .is_some_and(|allowed| allowed.contains(context))
                    {
                        return Err(IdentityFailure::ExecutionContextDenied);
                    }
                }
                context
            }
            None => self.config.execution_context.as_ref().map_or_else(
                || Some(DEFAULT_EXECUTION_CONTEXT.into()),
                |config| config.default_context.clone(),
            ),
        };
        context
            .map(ExecutionContext::new)
            .transpose()
            .map_err(|_| IdentityFailure::ExecutionContextInvalid)
    }

    pub fn resolve_admitted_identity(
        &self,
        headers: &HeaderMap,
        admission: &IngressAdmission,
    ) -> Result<IdentityContext, IdentityFailure> {
        self.resolve_admitted_identity_with_proof(headers, admission)
            .map(|resolved| resolved.identity)
    }

    pub fn resolve_admitted_identity_with_proof(
        &self,
        headers: &HeaderMap,
        admission: &IngressAdmission,
    ) -> Result<AdmittedIdentity, IdentityFailure> {
        let mut resolved = if admission.is_username() {
            self.resolve_username_identity(admission)?
        } else {
            self.resolve_identity_with_anonymous_fallback(
                headers,
                admission,
                self.config.identity.mode != "required",
            )?
        };
        resolved.identity.caller_id = admission.caller_id().map(str::to_owned);
        Ok(resolved)
    }

    fn resolve_username_identity(
        &self,
        admission: &IngressAdmission,
    ) -> Result<AdmittedIdentity, IdentityFailure> {
        let IngressIdentity::Username { name, .. } = &admission.identity else {
            return Err(IdentityFailure::AssertionInvalid);
        };
        let namespace = admission
            .caller
            .as_ref()
            .and_then(|caller| caller.config.username_namespace.as_deref())
            .ok_or(IdentityFailure::CallerUserAssertionDenied)?;
        let resolved = self
            .managed_store
            .as_ref()
            .ok_or(IdentityFailure::Unavailable)?
            .resolve_username_identity(namespace, name)
            .map_err(username_store_failure)?;
        Ok(self.attested_identity(resolved, admission))
    }

    pub fn resolve_forwarded_identity(
        &self,
        _headers: &HeaderMap,
        admission: &IngressAdmission,
    ) -> Result<IdentityContext, IdentityFailure> {
        self.resolve_forwarded_identity_with_proof(admission)
            .map(|resolved| resolved.identity)
    }

    pub(super) fn resolve_forwarded_identity_with_proof(
        &self,
        admission: &IngressAdmission,
    ) -> Result<AdmittedIdentity, IdentityFailure> {
        let IngressIdentity::Fingerprint(fingerprint) = &admission.identity else {
            return Err(IdentityFailure::Required);
        };
        let resolved = self
            .managed_store
            .as_ref()
            .ok_or(IdentityFailure::Invalid)?
            .resolve_identity_fingerprint_with_proof(fingerprint)
            .map_err(|_| IdentityFailure::Invalid)?;
        Ok(self.attested_identity(resolved, admission))
    }

    pub fn revalidate_admitted_identity(
        &self,
        proof: &crate::AttestedIdentityProof,
        admission: &IngressAdmission,
    ) -> Result<IdentityContext, IdentityFailure> {
        let failure = if admission.is_username() {
            IdentityFailure::AssertionDenied
        } else {
            IdentityFailure::Invalid
        };
        let admitted_caller = admission.caller.as_ref().ok_or_else(|| failure.clone())?;
        if !self.trusted_callers.iter().any(|current| {
            current.name == admitted_caller.name
                && bool::from(current.binding.ct_eq(&admitted_caller.binding))
        }) {
            return Err(failure);
        }
        let subject_matches = match &admission.identity {
            IngressIdentity::Username { name, .. } => admitted_caller
                .config
                .username_namespace
                .as_deref()
                .is_some_and(|namespace| proof.matches_username(namespace, name)),
            IngressIdentity::Fingerprint(fingerprint) => proof.matches_fingerprint(fingerprint),
            IngressIdentity::Ordinary => false,
        };
        if !subject_matches {
            return Err(failure);
        }
        let store = self.managed_store.as_ref().ok_or_else(|| {
            if admission.is_username() {
                IdentityFailure::Unavailable
            } else {
                IdentityFailure::Invalid
            }
        })?;
        let resolved = store.revalidate_attested_identity(proof).map_err(|error| {
            if admission.is_username() {
                username_store_failure(error)
            } else {
                IdentityFailure::Invalid
            }
        })?;
        Ok(self.attested_identity(resolved, admission).identity)
    }

    fn attested_identity(
        &self,
        resolved: crate::ResolvedAttestedIdentity,
        admission: &IngressAdmission,
    ) -> AdmittedIdentity {
        let contexts = self
            .config
            .execution_context
            .as_ref()
            .map(|config| config.allowed_values.clone())
            .unwrap_or_else(|| vec![DEFAULT_EXECUTION_CONTEXT.to_string()]);
        let source = IdentitySourceAudit {
            name: if admission.is_username() {
                "trusted_user"
            } else {
                "forwarded_identity"
            }
            .into(),
            kind: if admission.is_username() {
                "trusted_user"
            } else {
                "forwarded_identity"
            }
            .into(),
            token_header: if admission.is_username() {
                USER_HEADER
            } else {
                IDENTITY_HEADER
            }
            .into(),
            token_scheme: if admission.is_username() {
                "asserted"
            } else {
                "sha256"
            }
            .into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: None,
            namespace: resolved.proof.namespace().map(str::to_owned),
            binding_id: resolved.proof.binding_id().map(str::to_owned),
            token_scopes: Some(json!({"allowedExecutionContexts":contexts})),
        };
        let principal_kind = resolved.principal.principal_kind();
        let mut identity = self.identity_from_principal_groups(
            resolved.principal.principal_id,
            principal_kind,
            resolved.principal.external_subject,
            resolved.principal.groups,
            Some(resolved.policy_groups),
            Some(source),
        );
        identity.caller_id = admission.caller_id().map(str::to_owned);
        AdmittedIdentity {
            identity,
            proof: Some(resolved.proof),
        }
    }
}

fn username_store_failure(error: ManagedStoreError) -> IdentityFailure {
    match error {
        ManagedStoreError::AttestedIdentityDenied => IdentityFailure::AssertionDenied,
        _ => IdentityFailure::Unavailable,
    }
}

/// These stages can only be constructed at host admission sites, before execution.
#[derive(Clone, Copy)]
pub(super) enum PreDispatchFailure {
    Caller,
    Identity,
    Context,
    Admission,
}
impl PreDispatchFailure {
    pub(super) fn for_identity_failure(failure: &IdentityFailure) -> Self {
        match failure.admission_action() {
            "caller.authenticate" => Self::Caller,
            "request.admit" => Self::Admission,
            _ => Self::Identity,
        }
    }

    pub(super) fn for_reason(reason: ReasonCode) -> Option<Self> {
        Some(match reason {
            ReasonCode::CallerAuthenticationRequired
            | ReasonCode::CallerAuthenticationInvalid
            | ReasonCode::CallerIdentityForwardingDenied
            | ReasonCode::CallerUserAssertionDenied
            | ReasonCode::ExecutionContextRequired
            | ReasonCode::ExecutionContextInvalid => Self::Caller,
            ReasonCode::IdentityRequired
            | ReasonCode::IdentityInvalid
            | ReasonCode::IdentityAssertionInvalid
            | ReasonCode::IdentityAssertionUnsupported
            | ReasonCode::IdentityAssertionDenied
            | ReasonCode::BrokerTokenNotFound
            | ReasonCode::BrokerTokenExpired
            | ReasonCode::BrokerTokenPaused
            | ReasonCode::BrokerTokenRevoked
            | ReasonCode::PrincipalRequired
            | ReasonCode::PrincipalDisabled => Self::Identity,
            ReasonCode::ExecutionContextDenied | ReasonCode::BrokerTokenClassDenied => {
                Self::Context
            }
            ReasonCode::RateLimited
            | ReasonCode::ConcurrencyLimited
            | ReasonCode::IdentityUnavailable
            | ReasonCode::AuditUnavailable => Self::Admission,
            _ => return None,
        })
    }
    pub(super) fn apply(self, mut response: BrokerResponse<Value>) -> BrokerResponse<Value> {
        // Required admission audit failure supersedes the initial denial.
        let stage = if response.envelope.reason_code == Some(ReasonCode::AuditUnavailable.into()) {
            Self::Admission
        } else {
            self
        };
        response.envelope.service = "broker".into();
        response.envelope.action = match stage {
            Self::Caller => "caller.authenticate",
            Self::Identity => "identity.authenticate",
            Self::Context => "context.authorize",
            Self::Admission => "request.admit",
        }
        .into();
        response.envelope.decision = if matches!(stage, Self::Admission) {
            Decision::Error
        } else {
            Decision::Deny
        };
        response.envelope.resource_scopes.clear();
        if response.status == 429 {
            response.retry_after_seconds =
                crate::result_retry_after_seconds(response.envelope.result.as_ref());
        }
        response.envelope.result = None;
        response.stream = None;
        response
    }
}

impl BrokerRuntime {
    /// Report a failure identified by host ingress admission, before any provider I/O.
    pub async fn ingress_error_response_for_operation(
        &self,
        mut context: OperationContext,
        failure: IdentityFailure,
    ) -> BrokerResponse<Value> {
        if !context.identity.authenticated {
            context.identity.principal = "unknown".into();
            context.identity.groups.clear();
            context.identity.policy_groups.clear();
        }
        let stage = PreDispatchFailure::for_identity_failure(&failure);
        stage.apply(
            self.operation_error_response(context, failure.provider_error())
                .await,
        )
    }

    /// Report a host rate/concurrency/audit admission failure before dispatch.
    pub async fn admission_limit_error_response(
        &self,
        context: OperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let reserved = matches!(
            error.reason_code().standard(),
            Some(
                ReasonCode::RateLimited
                    | ReasonCode::ConcurrencyLimited
                    | ReasonCode::AuditUnavailable
            )
        );
        let response = self.operation_error_response(context, error).await;
        if reserved {
            PreDispatchFailure::Admission.apply(response)
        } else {
            response
        }
    }

    /// Report a host admission limit after resolving an execution context.
    pub async fn governed_admission_limit_error_response(
        &self,
        context: GovernedOperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let reserved = matches!(
            error.reason_code().standard(),
            Some(
                ReasonCode::RateLimited
                    | ReasonCode::ConcurrencyLimited
                    | ReasonCode::AuditUnavailable
            )
        );
        let response = self.governed_operation_error_response(context, error).await;
        if reserved {
            PreDispatchFailure::Admission.apply(response)
        } else {
            response
        }
    }

    /// Report the host's context/token-class authorization decision before dispatch.
    pub async fn context_authorization_error_response(
        &self,
        context: GovernedOperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let reserved = matches!(
            error.reason_code().standard(),
            Some(ReasonCode::ExecutionContextDenied | ReasonCode::BrokerTokenClassDenied)
        );
        let response = self.governed_operation_error_response(context, error).await;
        if reserved {
            PreDispatchFailure::Context.apply(response)
        } else {
            response
        }
    }

    pub(super) async fn finalize_pre_dispatch(
        &self,
        context: FinalizeContext,
        result: Result<ProviderResult, ProviderError>,
    ) -> BrokerResponse<Value> {
        let stage = result
            .as_ref()
            .err()
            .and_then(|error| error.reason_code().standard())
            .and_then(PreDispatchFailure::for_reason);
        let response = self.finalize(context, result).await;
        let stage = if response.envelope.reason_code == Some(ReasonCode::AuditUnavailable.into()) {
            Some(PreDispatchFailure::Admission)
        } else {
            stage
        };
        match stage {
            Some(stage) => stage.apply(response),
            None => response,
        }
    }
}
