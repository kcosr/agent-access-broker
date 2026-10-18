//! Caller discovery inspects local credential material, never upstream access.
//! Results live for one discovery request; execution always resolves again.
use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    Partial,
    Unavailable,
    Unknown,
}

/// A prerequisite is either upstream credential setup or a local Broker
/// capability. Local requirements never invent an upstream credential mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AvailabilityRequirement {
    Credential {
        reason: String,
        #[serde(rename = "credentialMode")]
        credential_mode: String,
        resolution: AvailabilityResolution,
    },
    LocalRuntime {
        reason: LocalAvailabilityReason,
        resolution: AvailabilityResolution,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityResolution {
    User,
    Administrator,
    /// Use a supported invocation credential; no upstream setup link applies.
    Caller,
}

impl AvailabilityResolution {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Administrator => "administrator",
            Self::Caller => "caller",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalAvailabilityReason {
    ManagedIdentityRequired,
    ManagedPolicyRequired,
    CredentialEncryptionUnavailable,
    ReferenceIdentityUnsupported,
    TokenHashingUnavailable,
    FiniteTokenTtlRequired,
    ReferenceOutputRequired,
}

impl LocalAvailabilityReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedIdentityRequired => "managed_identity_required",
            Self::ManagedPolicyRequired => "managed_policy_required",
            Self::CredentialEncryptionUnavailable => "credential_encryption_unavailable",
            Self::ReferenceIdentityUnsupported => "reference_identity_unsupported",
            Self::TokenHashingUnavailable => "token_hashing_unavailable",
            Self::FiniteTokenTtlRequired => "finite_token_ttl_required",
            Self::ReferenceOutputRequired => "reference_output_required",
        }
    }
}

impl AvailabilityRequirement {
    pub fn reason(&self) -> &str {
        match self {
            Self::Credential { reason, .. } => reason,
            Self::LocalRuntime { reason, .. } => reason.as_str(),
        }
    }
    pub fn resolution(&self) -> &str {
        match self {
            Self::Credential { resolution, .. } | Self::LocalRuntime { resolution, .. } => {
                resolution.as_str()
            }
        }
    }
    pub fn credential_mode(&self) -> Option<&str> {
        match self {
            Self::Credential {
                credential_mode, ..
            } => Some(credential_mode),
            Self::LocalRuntime { .. } => None,
        }
    }
    fn local(reason: LocalAvailabilityReason) -> Self {
        let resolution = if reason == LocalAvailabilityReason::ReferenceIdentityUnsupported {
            AvailabilityResolution::Caller
        } else {
            AvailabilityResolution::Administrator
        };
        Self::LocalRuntime { reason, resolution }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceAvailability {
    pub state: AvailabilityState,
    pub requirements: Vec<AvailabilityRequirement>,
    pub message: String,
}

/// Caller-facing service metadata; provider and management capabilities remain
/// independent of the caller's current credential state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredService {
    #[serde(flatten)]
    pub capabilities: ServiceCapabilities,
    pub availability: ServiceAvailability,
}

impl std::ops::Deref for DiscoveredService {
    type Target = ServiceCapabilities;
    fn deref(&self) -> &Self::Target {
        &self.capabilities
    }
}

pub(super) struct AvailableService {
    pub descriptor: ServiceDescriptor,
    pub availability: ServiceAvailability,
    pub clauses: BTreeMap<String, Vec<EffectiveAccessClause>>,
}

#[derive(Clone)]
struct UnavailableCredential {
    reason: String,
    unknown: bool,
    administrator: bool,
    /// The store or key failure behind an unavailable credential, which
    /// invocation reports as itself; `None` when the credential is absent.
    failure: Option<Box<ProviderError>>,
}

impl UnavailableCredential {
    fn missing() -> Self {
        Self::from_provider(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "credential is not provisioned",
        ))
    }

    /// The credential connection selects no method for the caller's
    /// principal kind. Only an administrator's configuration can change
    /// that, and no stored material is absent.
    fn unselected() -> Self {
        Self {
            reason: ReasonCode::CredentialNotProvisioned.as_str().into(),
            unknown: false,
            administrator: true,
            failure: None,
        }
    }

    fn from_provider(error: ProviderError) -> Self {
        let unknown = error.reason_code() == ReasonCode::ManagedStoreUnavailable;
        let administrator = matches!(
            error.reason_code().standard(),
            Some(
                ReasonCode::ManagedStoreUnavailable
                    | ReasonCode::ManagedStoreMigrationRequired
                    | ReasonCode::EncryptionKeyMissing
                    | ReasonCode::EncryptionKeyInvalid
                    | ReasonCode::CredentialDecryptFailed
            )
        );
        Self {
            reason: error.reason_code().as_str().into(),
            unknown,
            administrator,
            failure: administrator.then(|| Box::new(error)),
        }
    }

    fn from_oauth(error: crate::oauth::OAuthError) -> Self {
        use crate::oauth::OAuthError;
        let unknown = matches!(
            error,
            OAuthError::Storage
                | OAuthError::Stale
                | OAuthError::RefreshBusy
                | OAuthError::Provider
                | OAuthError::RetryLater(_)
                | OAuthError::RefreshPaused { .. }
        );
        Self {
            reason: error.code().into(),
            unknown,
            failure: None,
            administrator: unknown
                || matches!(
                    error,
                    OAuthError::Configuration
                        | OAuthError::ApplicationCredential
                        | OAuthError::RequestRejected
                ),
        }
    }
}

impl BrokerRuntime {
    /// Prerequisites for an administrator inspecting a local action contract.
    /// This is metadata only: it neither evaluates grants nor reads targets or
    /// credentials, and it cannot authorize an invocation.
    pub fn local_action_requirements(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
    ) -> Option<Vec<AvailabilityRequirement>> {
        let RuntimeServiceRegistration::BrokerManagement(registration) =
            self.service_registration(service)?
        else {
            return None;
        };
        registration.descriptor().action(action)?;
        Some(self.broker_management_requirements(identity, action))
    }

    pub(super) fn available_service_descriptors(
        &self,
        identity: &IdentityContext,
        context: &ExecutionContext,
        snapshot: &PolicySnapshot,
        selected: Option<&str>,
    ) -> Vec<AvailableService> {
        let Ok(token) = parsed_agent_invoke_token_caveats(identity) else {
            return Vec::new();
        };
        self.visible_service_descriptors_for_service(identity, context, snapshot, selected)
            .into_iter()
            .map(|descriptor| {
                self.available_service_descriptor(
                    descriptor,
                    identity,
                    context,
                    snapshot,
                    token.as_ref().map(|t| &t.caveats),
                )
            })
            .collect()
    }

    fn available_service_descriptor(
        &self,
        mut descriptor: ServiceDescriptor,
        identity: &IdentityContext,
        context: &ExecutionContext,
        snapshot: &PolicySnapshot,
        token: Option<&AgentInvokeTokenCaveats>,
    ) -> AvailableService {
        let mut checks = BTreeMap::new();
        let mut clauses = BTreeMap::new();
        let mut requirements = Vec::new();
        let mut unknown = false;
        let actions = std::mem::take(&mut descriptor.actions);
        for action in actions {
            if let Some(local) =
                self.local_action_requirements(identity, &descriptor.service, &action.action)
                && !local.is_empty()
            {
                for requirement in local {
                    if !requirements.contains(&requirement) {
                        requirements.push(requirement);
                    }
                }
                continue;
            }
            if !action.secret_outputs.is_empty()
                && self.config.secret_outputs.mode == crate::SecretOutputMode::Reference
                && !self.can_hold_secret_references(identity)
            {
                continue;
            }
            let scoped = !action.resource_scopes.is_empty();
            let unscoped_modes = if scoped {
                Vec::new()
            } else {
                self.scope_free_action_modes(
                    snapshot,
                    identity,
                    context,
                    &descriptor.service,
                    &action.action,
                )
            };
            let mut available = false;
            for mode in ["service", "per_user"] {
                let regions = if scoped {
                    self.effective_resource_clauses_for_modes(
                        snapshot,
                        identity,
                        context,
                        &descriptor.service,
                        &action.action,
                        token,
                        |selected| selected == mode,
                    )
                } else {
                    Vec::new()
                };
                if (scoped && regions.is_empty())
                    || (!scoped && !unscoped_modes.iter().any(|selected| selected == mode))
                {
                    continue;
                }
                let mut needed = vec![mode];
                if action.lookup.before_policy() {
                    match self.plan_pre_scope_lookup(
                        snapshot,
                        identity,
                        context,
                        &descriptor.service,
                        &action.action,
                    ) {
                        PreScopeLookupPlan::UsePerUserCredential => needed.push("per_user"),
                        PreScopeLookupPlan::UseSharedLookupCredential => needed.push("lookup"),
                        PreScopeLookupPlan::NoCandidateGrant => continue,
                    }
                }
                if action.lookup.credential_required() && mode == "service" {
                    needed.push("lookup");
                }
                let mut usable = true;
                for needed_mode in needed {
                    let static_lookup =
                        needed_mode == "per_user" && action.lookup.credential_required();
                    let result = checks
                        .entry((needed_mode, static_lookup))
                        .or_insert_with(|| {
                            self.check_discovery_credential(
                                &descriptor.service,
                                needed_mode,
                                identity,
                                static_lookup,
                            )
                        });
                    if let Err(error) = result {
                        usable = false;
                        unknown |= error.unknown;
                        let requirement = AvailabilityRequirement::Credential {
                            reason: error.reason.clone(),
                            credential_mode: needed_mode.into(),
                            resolution: if needed_mode == "per_user" && !error.administrator {
                                AvailabilityResolution::User
                            } else {
                                AvailabilityResolution::Administrator
                            },
                        };
                        if !requirements.contains(&requirement) {
                            requirements.push(requirement);
                        }
                    }
                }
                if usable {
                    available = true;
                    clauses
                        .entry(action.action.clone())
                        .or_insert_with(Vec::new)
                        .extend(regions);
                }
            }
            if available {
                descriptor.actions.push(action);
            }
        }
        // Scope metadata is only useful for the retained actions.
        descriptor.resource_scopes.retain(|name, _| {
            descriptor
                .actions
                .iter()
                .any(|action| action.resource_scopes.contains(name))
        });
        if descriptor.actions.is_empty() {
            descriptor.credentials.verification_inputs.clear();
        }
        let state = if requirements.is_empty() {
            AvailabilityState::Available
        } else if !descriptor.actions.is_empty() {
            AvailabilityState::Partial
        } else if unknown {
            AvailabilityState::Unknown
        } else {
            AvailabilityState::Unavailable
        };
        let message = match state {
                    AvailabilityState::Available => "Required capabilities are locally available; upstream access has not been verified.",
                    AvailabilityState::Partial => "Some capabilities are hidden because required capabilities are unavailable. Resolve the requirements, then refresh discovery.",
                    AvailabilityState::Unavailable => "Capabilities are hidden because required capabilities are unavailable. Resolve the requirements, then refresh discovery.",
                    AvailabilityState::Unknown => "Capability availability could not be checked. Capabilities are hidden; retry discovery after the problem is resolved.",
                }.into();
        AvailableService {
            descriptor,
            availability: ServiceAvailability {
                state,
                requirements,
                message,
            },
            clauses,
        }
    }

    /// Inspect only loaded runtime capability and the caller's authentication
    /// category. No secret inventory, reference lookup or upstream I/O occurs.
    pub(super) fn broker_management_requirements(
        &self,
        identity: &IdentityContext,
        action: &str,
    ) -> Vec<AvailabilityRequirement> {
        use LocalAvailabilityReason::*;
        let mut reasons = Vec::new();
        if self.config.identity.authority != "managed" {
            reasons.push(ManagedIdentityRequired);
        }
        if self.config.policy.authority != "managed" {
            reasons.push(ManagedPolicyRequired);
        }
        if matches!(action, "credential.install" | "token.create") {
            if self.managed_store.is_none() || self.credential_key_ring.is_none() {
                reasons.push(CredentialEncryptionUnavailable);
            }
            if !self.can_hold_secret_references(identity) {
                reasons.push(ReferenceIdentityUnsupported);
            }
        }
        if action == "token.create" {
            if self.broker_token_hasher.is_none() {
                reasons.push(TokenHashingUnavailable);
            }
            if self.config.broker_tokens.as_ref().is_none_or(|tokens| {
                !tokens
                    .admin_agent_invoke_ttl_options
                    .iter()
                    .any(|option| option.ttl_seconds().is_some_and(|ttl| ttl > 0))
            }) {
                reasons.push(FiniteTokenTtlRequired);
            }
            if self.config.secret_outputs.mode != crate::SecretOutputMode::Reference {
                reasons.push(ReferenceOutputRequired);
            }
        }
        reasons
            .into_iter()
            .map(AvailabilityRequirement::local)
            .collect()
    }

    /// Whether the caller's execution credential for `mode` is locally
    /// usable, by the check caller discovery applies: `Err(None)` when it is
    /// absent, `Err(Some(error))` when the store or its keys failed.
    pub(super) fn execution_credential_check(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<(), Option<Box<ProviderError>>> {
        self.check_discovery_credential(service, mode, identity, false)
            .map_err(|unavailable| unavailable.failure)
    }

    /// Whether `identity`'s credential for `mode` is locally usable.
    /// `personal_lookup` marks a `per_user` credential the action's lookups
    /// also use, which is needed even when the service needs no execution
    /// credential.
    fn check_discovery_credential(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
        personal_lookup: bool,
    ) -> Result<(), UnavailableCredential> {
        if mode == "lookup" {
            return self
                .resolve_lookup_credential(service)
                .map(drop)
                .map_err(UnavailableCredential::from_provider);
        }
        // A connection that selects no method for the caller makes the
        // personal mode unavailable, whatever material the service needs.
        if mode == "per_user"
            && matches!(
                self.personal_selection(service, identity),
                Some((_, crate::Selection::Unavailable))
            )
        {
            return Err(UnavailableCredential::unselected());
        }
        if !personal_lookup
            && self
                .services
                .get(service)
                .is_some_and(|d| !d.credentials.execution_required)
        {
            return Ok(());
        }
        if mode == "service"
            && let Some(record) = self.imported_catalog.service(service)
        {
            let (Some(store), Some(ring), Some(version)) = (
                self.managed_store.as_ref(),
                self.credential_key_ring.as_ref(),
                record
                    .slot_versions
                    .get(&ImportedCredentialPurpose::Execution),
            ) else {
                return Err(UnavailableCredential::missing());
            };
            return store
                .resolve_imported_secret(
                    service,
                    ImportedCredentialPurpose::Execution,
                    version,
                    ring,
                )
                .map(drop)
                .map_err(provider_error_from_managed_store)
                .map_err(UnavailableCredential::from_provider);
        }
        let credential = match mode {
            "service" => self.effective_credentials.service.get(service),
            "per_user" => self.effective_credentials.per_user.get(service),
            _ => None,
        }
        .ok_or_else(UnavailableCredential::missing)?;
        if credential.kind == "connection" {
            return self.check_connection_credential(service, identity);
        }
        load_execution_credential(service, mode, credential, Some(identity))
            .map(drop)
            .map_err(UnavailableCredential::from_provider)
    }
}

impl BrokerRuntime {
    /// The local availability of the method `identity` selects for
    /// `service`'s credential connection: the stored token row, or the OAuth
    /// connection, which serves execution and lookups alike. An unavailable
    /// selection is reported as an administrator requirement.
    fn check_connection_credential(
        &self,
        service: &str,
        identity: &IdentityContext,
    ) -> Result<(), UnavailableCredential> {
        let (connection, selection) = self
            .personal_selection(service, identity)
            .ok_or_else(UnavailableCredential::missing)?;
        match selection {
            crate::Selection::Unavailable => Err(UnavailableCredential::unselected()),
            crate::Selection::OAuth(oauth) => {
                let (true, Some(manager)) = (identity.authenticated, self.oauth.as_ref()) else {
                    return Err(UnavailableCredential::missing());
                };
                manager
                    .check_credential(&identity.principal, &oauth.binding())
                    .map_err(UnavailableCredential::from_oauth)
            }
            crate::Selection::Token(profile) => {
                let (true, Some(store), Some(ring)) = (
                    identity.authenticated,
                    self.managed_store.as_ref(),
                    self.credential_key_ring.as_ref(),
                ) else {
                    return Err(UnavailableCredential::missing());
                };
                store
                    .check_user_credential(
                        ring,
                        &identity.principal,
                        connection.id,
                        crate::CONNECTION_CREDENTIAL_NAME,
                        profile,
                    )
                    .map_err(provider_error_from_managed_store)
                    .map_err(UnavailableCredential::from_provider)
            }
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn local_prerequisites_gate_only_the_actions_that_need_them() {
        let mut config = super::super::tests::base_fake_config();
        config.secret_outputs.mode = crate::SecretOutputMode::Raw;
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = IdentityContext::anonymous();
        let reasons = |action: &str| {
            runtime
                .broker_management_requirements(&identity, action)
                .iter()
                .map(|item| item.reason().to_owned())
                .collect::<Vec<_>>()
        };
        let ordinary = vec!["managed_identity_required", "managed_policy_required"];
        assert_eq!(reasons("principal.create"), ordinary);
        assert_eq!(reasons("credential.view"), ordinary);
        assert_eq!(reasons("token.view"), ordinary);
        assert_eq!(
            reasons("credential.install"),
            [
                "managed_identity_required",
                "managed_policy_required",
                "credential_encryption_unavailable",
                "reference_identity_unsupported",
            ]
        );
        assert_eq!(
            reasons("token.create"),
            [
                "managed_identity_required",
                "managed_policy_required",
                "credential_encryption_unavailable",
                "reference_identity_unsupported",
                "token_hashing_unavailable",
                "finite_token_ttl_required",
                "reference_output_required",
            ]
        );
        assert!(
            runtime
                .local_action_requirements(&identity, "fake", "echo")
                .is_none()
        );
        assert!(runtime.scoped_mcp_diagnostics("fake").ready);
    }

    #[test]
    fn requirements_are_tagged_and_local_entries_have_no_credential_mode() {
        let personal = AvailabilityRequirement::Credential {
            reason: "credential_not_provisioned".into(),
            credential_mode: "per_user".into(),
            resolution: AvailabilityResolution::User,
        };
        assert_eq!(
            serde_json::to_value(&personal).unwrap(),
            json!({
                "kind":"credential", "reason":"credential_not_provisioned",
                "credentialMode":"per_user", "resolution":"user"
            })
        );
        for reason in [
            LocalAvailabilityReason::ManagedIdentityRequired,
            LocalAvailabilityReason::ManagedPolicyRequired,
            LocalAvailabilityReason::CredentialEncryptionUnavailable,
            LocalAvailabilityReason::ReferenceIdentityUnsupported,
            LocalAvailabilityReason::TokenHashingUnavailable,
            LocalAvailabilityReason::FiniteTokenTtlRequired,
            LocalAvailabilityReason::ReferenceOutputRequired,
        ] {
            let requirement = AvailabilityRequirement::local(reason);
            let value = serde_json::to_value(&requirement).unwrap();
            assert_eq!(value["kind"], "local_runtime");
            assert_eq!(value["reason"], reason.as_str());
            assert!(value.get("credentialMode").is_none());
            assert_eq!(
                value["resolution"],
                if reason == LocalAvailabilityReason::ReferenceIdentityUnsupported {
                    "caller"
                } else {
                    "administrator"
                }
            );
            assert_eq!(
                serde_json::from_value::<AvailabilityRequirement>(value).unwrap(),
                requirement
            );
        }
        assert!(serde_json::from_value::<AvailabilityRequirement>(json!({
            "reason":"credential_not_provisioned", "credentialMode":"per_user", "resolution":"user"
        })).is_err());
        assert!(serde_json::from_value::<AvailabilityRequirement>(json!({
            "kind":"local_runtime", "reason":"managed_policy_required", "resolution":"administrator", "credentialMode":"service"
        })).is_err());
    }
}
