//! The command authority planner: the grants a command import's action
//! passes to its command, computed by one planner for invocation and caller
//! discovery.
//!
//! A command import's action is **Broker-enforced** when it names its
//! resources in typed inputs: core resolves them and selects one grant by
//! the native rules before dispatch. Every other action of a command import
//! is **command-enforced**: core checks the action, and the command receives
//! the caller's top precedence band of grants, each with its own credential
//! and boundary, and constrains its work to them. Unlike native search, the
//! band may mix credential modes; no lower band is ever consulted.
use super::*;
use crate::ImportedCatalog;

/// The authority core admitted for one call to a command import's action:
/// what the command's request `authorization` block and the invocation
/// audit's `commandAuthorization` are built from.
///
/// It is captured at admission from one policy snapshot and never holds
/// credentials or resource attributes; the request builder resolves those
/// after the concurrency permit. A command without a credential receives no
/// credentials, so its request omits every `credential` member; the modes
/// here are still the grants' own.
///
/// The serialized form is the audit record of the plan: grant IDs, versions
/// and subjects, credential modes and boundaries.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CommandAuthorization {
    /// Broker-enforced: core resolved `values` from the action's input
    /// pointers, and `grant`, selected from the top band by the native
    /// rules, covers every one of them. Only that grant's credential is
    /// passed (`{"mode": "broker", "credential", "resourceType",
    /// "resources"}` on the wire).
    Broker {
        resource_type: CommandResourceType,
        credential_mode: String,
        /// Canonical resource values, in input order without duplicates.
        values: Vec<String>,
        grant: MatchedGrantAudit,
    },
    /// Command-enforced: the caller's top-band grants that remain after
    /// token restrictions and credential availability, in precedence order
    /// (`{"mode": "command", "resourceType"?, "grants"}` on the wire). An
    /// action without a resource type has no `resource_type`, and each of
    /// its grants reaches every value.
    Command {
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_type: Option<CommandResourceType>,
        grants: Vec<CommandGrantAuthority>,
    },
}

/// An action's resource type: the manifest's type id, which is the action's
/// resource scope name and the request's `resourceType`, and the Broker type
/// the import accepted it under, which resource entries and attribute
/// bindings use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommandResourceType {
    pub id: String,
    pub broker_type: ResourceType,
}

/// One grant passed to a command-enforced action.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommandGrantAuthority {
    /// The grant's credential mode, `service` or `per_user` (`"service"`
    /// or `"user"` on the wire): the command reaches this grant's resources
    /// only with that credential.
    pub credential_mode: String,
    /// The grant's boundary after the agent token's restriction: finite
    /// exact values (`"resources": [...]` on the wire), or every value
    /// except `excludedValues` (`"resources": "any"` with `except`). The
    /// exceptions include excluded entries that are disabled or not eligible
    /// in the execution context. An untyped action's grants reach every
    /// value with no exceptions.
    pub scope: SearchAuthorizationScope,
    pub grant: MatchedGrantAudit,
}

impl CommandAuthorization {
    /// The credential modes whose credentials the request carries: exactly
    /// those its grants use.
    pub fn credential_modes(&self) -> BTreeSet<&str> {
        match self {
            Self::Broker {
                credential_mode, ..
            } => BTreeSet::from([credential_mode.as_str()]),
            Self::Command { grants, .. } => grants
                .iter()
                .map(|grant| grant.credential_mode.as_str())
                .collect(),
        }
    }

    /// The single credential mode the call uses, for the audit record's
    /// `credentialMode`; `None` when the passed grants mix modes.
    pub fn credential_mode(&self) -> Option<String> {
        let mut modes = self.credential_modes().into_iter();
        match (modes.next(), modes.next()) {
            (Some(mode), None) => Some(mode.to_owned()),
            _ => None,
        }
    }

    /// The envelope and audit `resourceScopes` summary: the resolved values,
    /// or the union of the passed boundaries as finite values or `["*"]`.
    /// Like the search summary, it is lossy and never authorizes anything.
    fn resource_scope_summary(&self) -> ResourceScopes {
        match self {
            Self::Broker {
                resource_type,
                values,
                ..
            } => BTreeMap::from([(resource_type.id.clone(), values.clone())]),
            Self::Command {
                resource_type: Some(resource_type),
                ..
            } => {
                let values = match self.union_scope() {
                    SearchAuthorizationScope::Finite { values } => values,
                    SearchAuthorizationScope::AllExcept { .. } => vec!["*".to_owned()],
                };
                BTreeMap::from([(resource_type.id.clone(), values)])
            }
            Self::Command { .. } => ResourceScopes::new(),
        }
    }

    fn union_scope(&self) -> SearchAuthorizationScope {
        match self {
            Self::Command { grants, .. } => grants.iter().fold(
                SearchAuthorizationScope::Finite { values: Vec::new() },
                |scope, grant| scope.union(&grant.scope),
            ),
            Self::Broker { values, .. } => SearchAuthorizationScope::Finite {
                values: values.clone(),
            },
        }
    }
}

/// Who checks a command import action's resources, as policy editors show
/// it: the Broker before dispatch, or the command from the grants it is
/// passed (also for an action without a resource type).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourcesCheckedBy {
    Broker,
    Command,
}

/// Why a command-enforced action has no grants to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandDenial {
    /// No grant of the caller covers the action in this context, or the top
    /// band's boundaries hold no resources.
    Policy,
    /// The agent token's resource restriction applies to an untyped action.
    TokenInapplicable,
    /// The agent token's resource restriction leaves no resources.
    TokenEmpty,
    /// Every remaining grant's credential is unavailable, or its mode is
    /// not one the action supports; these modes were omitted.
    Credentials(BTreeSet<String>),
}

/// Whether `service` is a command import of `imported`.
fn command_import(imported: &ImportedCatalog, service: &str) -> bool {
    imported.service(service).is_some_and(|record| {
        record
            .definition
            .endpoint()
            .is_ok_and(|endpoint| endpoint.form() == ImportEndpointForm::Command)
    })
}

/// Whether `action` of `service` is command-enforced: an action of a
/// command import that does not name its resources in typed inputs. Its
/// top band may mix credential modes, since every passed grant names its
/// own. The planner and policy validation both classify actions here.
pub(crate) fn command_enforced_action(
    imported: &ImportedCatalog,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    service: &str,
    action: &str,
) -> bool {
    command_import(imported, service)
        && services
            .get(service)
            .and_then(|descriptor| descriptor.action(action))
            .is_some_and(|descriptor| {
                descriptor.search_contained || descriptor.resource_scope.is_none()
            })
}

impl BrokerRuntime {
    /// Whether `service` is a command import.
    fn is_command_import(&self, service: &str) -> bool {
        command_import(&self.imported_catalog, service)
    }

    /// Whether `action` of `service` is command-enforced; see
    /// [`command_enforced_action`].
    pub(super) fn command_enforced(&self, service: &str, action: &str) -> bool {
        command_enforced_action(&self.imported_catalog, &self.services, service, action)
    }

    /// Who checks the resources of `action` of a command import, by the
    /// classification the planner and policy validation use; `None` for
    /// every other service's actions.
    pub fn resources_checked_by(&self, service: &str, action: &str) -> Option<ResourcesCheckedBy> {
        if !self.is_command_import(service) || self.action_descriptor(service, action).is_none() {
            return None;
        }
        Some(if self.command_enforced(service, action) {
            ResourcesCheckedBy::Command
        } else {
            ResourcesCheckedBy::Broker
        })
    }

    /// Whether `action` of `service` supports credential `mode`. Policy
    /// validation keeps grants within an action's modes, but a refresh can
    /// narrow them under a retained grant; selection never uses such a grant.
    pub(super) fn action_supports_mode(&self, service: &str, action: &str, mode: &str) -> bool {
        self.action_descriptor(service, action)
            .is_some_and(|descriptor| descriptor.credential_modes.iter().any(|m| m == mode))
    }

    /// The command resource type of a scoped action of a command import.
    fn command_resource_type(&self, service: &str, action: &str) -> Option<CommandResourceType> {
        let (scope, binding) = self.services.get(service)?.action_resource_scope(action)?;
        Some(CommandResourceType {
            id: scope.to_owned(),
            broker_type: binding.resource_type.clone(),
        })
    }

    /// The caller's top precedence band for the action in `context`; empty
    /// without a candidate grant.
    fn command_band(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Vec<PolicyCandidate> {
        let candidates =
            self.policy_candidates_for_action(snapshot, identity, context, service, action);
        if candidates.is_empty() {
            return candidates;
        }
        top_policy_band(candidates)
    }

    /// Plans a command-enforced action from its top band: each grant's
    /// boundary as finite values or all-except, intersected with the agent
    /// token's resource restriction; grants that end up empty, then grants
    /// whose credential mode the action does not support or cannot use for
    /// `identity`, or that `mode_available` rejects, are omitted. The same
    /// grant matched through several subjects is passed once.
    #[allow(clippy::too_many_arguments)]
    fn plan_command_grants(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        band: &[PolicyCandidate],
        token: Option<&AgentInvokeTokenCaveats>,
        mode_available: impl Fn(&str) -> bool,
    ) -> Result<CommandAuthorization, CommandDenial> {
        if band.is_empty() {
            return Err(CommandDenial::Policy);
        }
        let resource_type = self.command_resource_type(service, action);
        let token_scope = match token.and_then(|caveats| {
            self.token_resource_boundary(snapshot, context, caveats, service, action)
        }) {
            None => None,
            Some(_) if resource_type.is_none() => return Err(CommandDenial::TokenInapplicable),
            Some(boundary) => Some(search_scope_from_boundary(&boundary)),
        };
        let mut grants = Vec::<CommandGrantAuthority>::new();
        let mut token_emptied = false;
        let mut omitted_modes = BTreeSet::new();
        for candidate in band {
            let granted = if resource_type.is_some() {
                search_scope_from_boundary(&candidate.boundary)
            } else {
                SearchAuthorizationScope::AllExcept {
                    excluded_values: Vec::new(),
                }
            };
            let scope = token_scope
                .as_ref()
                .map_or_else(|| granted.clone(), |token| granted.intersection(token));
            if scope.is_empty() {
                token_emptied |= !granted.is_empty();
                continue;
            }
            if !self.action_supports_mode(service, action, &candidate.credential_mode)
                || !self.action_credential_eligible(
                    service,
                    action,
                    &candidate.credential_mode,
                    identity,
                )
                || !mode_available(&candidate.credential_mode)
            {
                omitted_modes.insert(candidate.credential_mode.as_str());
                continue;
            }
            let grant = matched_grant_audit(snapshot, candidate);
            if grants.iter().any(|passed| {
                passed.grant.grant_id == grant.grant_id
                    && passed.grant.config_index == grant.config_index
            }) {
                continue;
            }
            grants.push(CommandGrantAuthority {
                credential_mode: candidate.credential_mode.clone(),
                scope,
                grant,
            });
        }
        if grants.is_empty() {
            return Err(if !omitted_modes.is_empty() {
                CommandDenial::Credentials(omitted_modes.into_iter().map(str::to_owned).collect())
            } else if token_emptied {
                CommandDenial::TokenEmpty
            } else {
                CommandDenial::Policy
            });
        }
        Ok(CommandAuthorization::Command {
            resource_type,
            grants,
        })
    }

    /// The configured availability of `mode` for `service`: an imported
    /// execution slot or binding, or service mode without a credential.
    fn command_mode_configured(&self, service: &str, mode: &str) -> bool {
        credential_mode_available(
            &self.effective_credentials,
            service,
            mode,
            self.services
                .get(service)
                .map(|descriptor| &descriptor.credentials),
        )
    }

    /// The command-enforced plan caller discovery uses, with discovery's
    /// configured availability narrowed by `mode_available`; `None` when the
    /// caller has no grants to pass.
    #[allow(clippy::too_many_arguments)]
    fn discovered_command_authorization(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&AgentInvokeTokenCaveats>,
        mode_available: impl Fn(&str) -> bool,
    ) -> Option<CommandAuthorization> {
        let band = self.command_band(snapshot, identity, context, service, action);
        self.plan_command_grants(
            snapshot,
            identity,
            context,
            service,
            action,
            &band,
            token,
            |mode| mode_available(mode) && self.command_mode_configured(service, mode),
        )
        .ok()
    }

    /// The effective resource clauses of a typed command-enforced action:
    /// the union of the passed grants' boundaries.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn command_effective_clauses(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&AgentInvokeTokenCaveats>,
        mode_available: impl Fn(&str) -> bool,
    ) -> Vec<EffectiveAccessClause> {
        match self.discovered_command_authorization(
            snapshot,
            identity,
            context,
            service,
            action,
            token,
            mode_available,
        ) {
            Some(CommandAuthorization::Command {
                resource_type: Some(_),
                grants,
            }) => grants
                .iter()
                .map(|grant| {
                    EffectiveAccessClause::from_boundary(search_scope_boundary(&grant.scope))
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Whether the caller may invoke a scope-free action in `context` with
    /// a configured credential: one native selection, or command grants to
    /// pass for a command-enforced action.
    pub(super) fn scope_free_action_admitted(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> bool {
        if self.command_enforced(service, action) {
            return self
                .discovered_command_authorization(
                    snapshot,
                    identity,
                    context,
                    service,
                    action,
                    None,
                    |_| true,
                )
                .is_some();
        }
        self.select_policy(
            snapshot,
            identity,
            context,
            service,
            action,
            &ResourceScopes::new(),
        )
        .is_ok()
    }

    /// The credential modes a scope-free action admits the caller with in
    /// `context`, before checking local credential material.
    pub(super) fn scope_free_action_modes(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Vec<String> {
        if self.command_enforced(service, action) {
            return self
                .discovered_command_authorization(
                    snapshot,
                    identity,
                    context,
                    service,
                    action,
                    None,
                    |_| true,
                )
                .map(|plan| {
                    plan.credential_modes()
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
        }
        self.select_policy(
            snapshot,
            identity,
            context,
            service,
            action,
            &ResourceScopes::new(),
        )
        .map(|policy| vec![policy.credential_mode])
        .unwrap_or_default()
    }

    /// Plans an admitted call to a command-enforced action. A grant's
    /// credential is available when its mode is configured and the
    /// caller's credential material is present locally, as caller discovery
    /// checks it, without contacting upstream; the request builder resolves
    /// the credentials themselves after the concurrency permit.
    async fn plan_command_invocation(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> Result<CommandAuthorization, ProviderError> {
        let band = self.command_band(snapshot, identity, context, service, action);
        let mut available = BTreeSet::new();
        let mut failures = BTreeMap::new();
        for mode in band
            .iter()
            .map(|candidate| candidate.credential_mode.clone())
            .collect::<BTreeSet<_>>()
        {
            if !self.command_mode_configured(service, &mode) {
                continue;
            }
            match self
                .command_credential_check(service, &mode, identity)
                .await
            {
                Ok(()) => {
                    available.insert(mode);
                }
                Err(Some(failure)) => {
                    failures.insert(mode, *failure);
                }
                Err(None) => {}
            }
        }
        self.plan_command_grants(
            snapshot,
            identity,
            context,
            service,
            action,
            &band,
            token.map(|parsed| &parsed.caveats),
            |mode| available.contains(mode),
        )
        .map_err(|denial| match (denial, token) {
            // A store or key failure behind an omitted credential is reported
            // as itself, as credential resolution would report it.
            (CommandDenial::Credentials(omitted), _) => omitted
                .iter()
                .find_map(|mode| failures.remove(mode))
                .unwrap_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::CredentialNotProvisioned,
                        "no credential of the caller's command grants is provisioned",
                    )
                }),
            (CommandDenial::TokenInapplicable, Some(parsed)) => token_caveat_denial(
                parsed.source,
                service,
                action,
                "token resource restriction cannot apply to this action",
            ),
            (CommandDenial::TokenEmpty, Some(parsed)) => token_caveat_denial(
                parsed.source,
                service,
                action,
                "broker token command boundary has no currently authorized resources",
            ),
            _ => ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy denied command action",
            ),
        })
    }

    /// Admits a call to a command-enforced action: the adapter checks its
    /// inputs in its scope hook, then the planner selects the grants. Such
    /// an action names no resources in its inputs, so an adapter that
    /// resolved some fails closed.
    pub(super) async fn admit_command_enforced(
        &self,
        request: CommandAdmissionRequest<'_>,
    ) -> Result<CommandAdmission, ProviderError> {
        let CommandAdmissionRequest {
            snapshot,
            identity,
            context,
            service,
            action,
            token,
            inputs,
            correlation,
            provider,
            domain_reasons,
        } = request;
        let scope_identity =
            InvocationIdentity::new(identity.principal.clone(), identity.authenticated);
        let (resolved, state) = with_provider_context(
            correlation.clone(),
            service.to_owned(),
            action.to_owned(),
            run_provider_hook(
                agent_access_provider::host::hook_context(
                    service,
                    action,
                    HookPhase::ScopeResolution,
                    domain_reasons,
                ),
                provider.resolve_scopes(agent_access_provider::host::scope_request(
                    agent_access_provider::host::ScopeRequestParts {
                        service,
                        action,
                        inputs,
                        execution_context: context.as_str(),
                        identity: &scope_identity,
                        correlation,
                        // Command actions declare no lookups.
                        lookup_access: None,
                    },
                )),
            ),
        )
        .await?
        .into_parts();
        let mismatch = || {
            ProviderError::error(
                ReasonCode::OperationFailed,
                "admitted authority does not match the action contract",
            )
        };
        if !resolved.is_empty() {
            return Err(mismatch());
        }
        let plan = self
            .plan_command_invocation(snapshot, identity, context, service, action, token)
            .await?;
        CommandAdmission::new(plan, state).ok_or_else(mismatch)
    }

    /// Whether the caller's credential for `mode` is present locally,
    /// checked off the async executor like other managed-store reads.
    /// `Err(None)` when the credential is absent, `Err(Some(error))` when the
    /// store or its keys failed to answer.
    async fn command_credential_check(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<(), Option<Box<ProviderError>>> {
        let runtime = self.clone();
        let (service, mode, identity) = (service.to_owned(), mode.to_owned(), identity.clone());
        managed_store_blocking(move || {
            Ok(runtime.execution_credential_check(&service, &mode, &identity))
        })
        .await
        .unwrap_or_else(|error| Err(Some(Box::new(provider_error_from_managed_store(error)))))
    }

    /// The Broker-enforced authority of a command import's scoped action,
    /// from its native policy decision; `None` for every other action.
    pub(super) fn broker_command_authorization(
        &self,
        service: &str,
        action: &str,
        scopes: &ResourceScopes,
        policy: &PolicyDecision,
    ) -> Option<CommandAuthorization> {
        if !self.is_command_import(service) || self.command_enforced(service, action) {
            return None;
        }
        let resource_type = self.command_resource_type(service, action)?;
        Some(CommandAuthorization::Broker {
            values: scopes.get(&resource_type.id).cloned().unwrap_or_default(),
            resource_type,
            credential_mode: policy.credential_mode.clone(),
            grant: policy.matched_grant.clone(),
        })
    }
}

/// What preparation needs to admit a call to a command-enforced action.
pub(super) struct CommandAdmissionRequest<'a> {
    pub snapshot: &'a PolicySnapshot,
    pub identity: &'a IdentityContext,
    pub context: &'a ExecutionContext,
    pub service: &'a str,
    pub action: &'a str,
    pub token: Option<&'a ParsedAgentInvokeTokenCaveats<'a>>,
    pub inputs: &'a Value,
    pub correlation: &'a CorrelationContext,
    pub provider: &'a Arc<dyn Provider>,
    pub domain_reasons: &'static [&'static ProviderReasonDefinition],
}

/// The admission of a command-enforced call: its plan and the native
/// shapes the rest of preparation expects. The policy decision names the
/// first passed grant and its mode, as a search plan names its first
/// matched grant; the audit's credential mode is the plan's single mode.
pub(super) struct CommandAdmission {
    pub scopes: ResourceScopes,
    pub policy: PolicyDecision,
    pub state: Option<ProviderState>,
    pub search: Option<SearchAuthorization>,
    pub authorization: CommandAuthorization,
}

impl CommandAdmission {
    fn new(authorization: CommandAuthorization, state: Option<ProviderState>) -> Option<Self> {
        let CommandAuthorization::Command {
            resource_type,
            grants,
        } = &authorization
        else {
            return None;
        };
        let first = grants.first()?;
        Some(Self {
            scopes: authorization.resource_scope_summary(),
            policy: PolicyDecision {
                credential_mode: first.credential_mode.clone(),
                matched_grant: first.grant.clone(),
            },
            state,
            search: resource_type.as_ref().map(|resource_type| {
                SearchAuthorization::new(resource_type.id.clone(), authorization.union_scope())
            }),
            authorization,
        })
    }
}

#[cfg(test)]
#[path = "command_authority_tests.rs"]
mod tests;
