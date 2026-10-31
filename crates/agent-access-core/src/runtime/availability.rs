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
                    token.as_ref(),
                )
            })
            .collect()
    }

    /// Whether caller discovery lists `action` for `identity` in `context`:
    /// [`Self::available_service_descriptors`] on `snapshot`, with the
    /// catalog's own policy, token and local credential checks. Like
    /// discovery, it contacts no upstream, refreshes no OAuth connection and
    /// records no credential use; its store reads run off the async executor.
    /// A failed check counts as not listed.
    pub(super) async fn caller_discovers_action(
        &self,
        snapshot: &Arc<PolicySnapshot>,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> bool {
        let runtime = self.clone();
        let snapshot = Arc::clone(snapshot);
        let (identity, context) = (identity.clone(), context.clone());
        let (service, action) = (service.to_owned(), action.to_owned());
        managed_store_blocking(move || {
            Ok(runtime
                .available_service_descriptors(&identity, &context, &snapshot, Some(&service))
                .iter()
                .any(|available| available.descriptor.action(&action).is_some()))
        })
        .await
        .unwrap_or(false)
    }

    fn available_service_descriptor(
        &self,
        mut descriptor: ServiceDescriptor,
        identity: &IdentityContext,
        context: &ExecutionContext,
        snapshot: &PolicySnapshot,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> AvailableService {
        let mut checks = BTreeMap::new();
        let mut clauses = BTreeMap::new();
        let mut requirements = Vec::new();
        let mut unknown = false;
        let actions = std::mem::take(&mut descriptor.actions);
        for action in actions {
            let scoped = action.resource_scope.is_some();
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
                    self.imported_credential_contracts
                        .get(service)
                        .ok_or_else(UnavailableCredential::missing)?
                        .requirement(ImportedCredentialPurpose::Execution)
                        .ok_or_else(UnavailableCredential::missing)?,
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
            crate::Selection::Token(profiles) => {
                let (true, Some(store), Some(ring)) = (
                    identity.authenticated,
                    self.managed_store.as_ref(),
                    self.credential_key_ring.as_ref(),
                ) else {
                    return Err(UnavailableCredential::missing());
                };
                store
                    .check_user_credential_with_imported_contract(
                        ring,
                        &identity.principal,
                        connection.id,
                        crate::CONNECTION_CREDENTIAL_NAME,
                        profiles,
                        self.imported_connection_requirement(connection.id)
                            .map_err(provider_error_from_managed_store)
                            .map_err(UnavailableCredential::from_provider)?
                            .as_ref(),
                    )
                    .map_err(provider_error_from_managed_store)
                    .map_err(UnavailableCredential::from_provider)
            }
        }
    }
}
