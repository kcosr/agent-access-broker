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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRequirement {
    pub reason: String,
    pub credential_mode: String,
    /// `user` for personal setup, `administrator` for broker configuration.
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceAvailability {
    pub state: AvailabilityState,
    pub requirements: Vec<CredentialRequirement>,
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
}

impl UnavailableCredential {
    fn missing() -> Self {
        Self::from_provider(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "credential is not provisioned",
        ))
    }

    fn from_provider(error: ProviderError) -> Self {
        let unknown = matches!(error.reason_code, ReasonCode::ManagedStoreUnavailable);
        let administrator = matches!(
            error.reason_code,
            ReasonCode::ManagedStoreUnavailable
                | ReasonCode::ManagedStoreMigrationRequired
                | ReasonCode::EncryptionKeyMissing
                | ReasonCode::EncryptionKeyInvalid
                | ReasonCode::CredentialDecryptFailed
        );
        Self {
            reason: error.reason_code.as_str().into(),
            unknown,
            administrator,
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
            let scoped = action.resource_scope.is_some();
            let unscoped_mode = (!scoped)
                .then(|| {
                    self.select_policy(
                        snapshot,
                        identity,
                        context,
                        &descriptor.service,
                        &action.action,
                        &ResourceScopes::new(),
                    )
                    .ok()
                    .map(|p| p.credential_mode)
                })
                .flatten();
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
                    || (!scoped && unscoped_mode.as_deref() != Some(mode))
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
                        let requirement = CredentialRequirement {
                            reason: error.reason.clone(),
                            credential_mode: needed_mode.into(),
                            resolution: if needed_mode == "per_user" && !error.administrator {
                                "user"
                            } else {
                                "administrator"
                            }
                            .into(),
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
                .any(|action| action.resource_scope.as_ref() == Some(name))
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
                    AvailabilityState::Available => "Required credentials are locally available; upstream access has not been verified.",
                    AvailabilityState::Partial => "Some capabilities are hidden because required credentials are unavailable. Resolve the requirements, then refresh discovery.",
                    AvailabilityState::Unavailable => "Capabilities are hidden because required credentials are unavailable. Resolve the requirements, then refresh discovery.",
                    AvailabilityState::Unknown => "Credential availability could not be checked. Capabilities are hidden; retry discovery after the problem is resolved.",
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

    fn check_discovery_credential(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
        static_lookup: bool,
    ) -> Result<(), UnavailableCredential> {
        if mode == "lookup" {
            return self
                .resolve_lookup_credential(service)
                .map(drop)
                .map_err(UnavailableCredential::from_provider);
        }
        if !static_lookup
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
        if credential.kind == "oauth" {
            if static_lookup {
                return Err(UnavailableCredential::missing());
            }
            let (true, Some(manager), Some(registration), Some(permission_profile)) = (
                identity.authenticated,
                self.oauth.as_ref(),
                credential.provider.as_ref(),
                credential.profile.as_ref(),
            ) else {
                return Err(UnavailableCredential::missing());
            };
            return manager
                .check_credential(
                    &identity.principal,
                    &crate::OAuthBinding {
                        registration: registration.clone(),
                        permission_profile: permission_profile.clone(),
                    },
                )
                .map_err(UnavailableCredential::from_oauth);
        }
        if credential.kind == "managed_store" {
            let (true, Some(store), Some(ring), Some(profile)) = (
                identity.authenticated,
                self.managed_store.as_ref(),
                self.credential_key_ring.as_ref(),
                credential.profile.as_ref(),
            ) else {
                return Err(UnavailableCredential::missing());
            };
            return store
                .check_user_credential(
                    ring,
                    &identity.principal,
                    service,
                    credential.credential_name.as_deref().unwrap_or("default"),
                    profile,
                )
                .map_err(provider_error_from_managed_store)
                .map_err(UnavailableCredential::from_provider);
        }
        load_execution_credential(service, mode, credential, Some(identity))
            .map(drop)
            .map_err(UnavailableCredential::from_provider)
    }
}
