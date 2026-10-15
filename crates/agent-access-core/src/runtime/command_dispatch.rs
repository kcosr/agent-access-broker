//! Command-import dispatch: what admission records for a call, the budget
//! permit the call waits for before its final checks, the request built after
//! them, the outcome of a call whose process never started, the audit facts
//! finalization adds, and credential verification through `<path> verify`.
//!
//! An admitted call of a command import waits, until its command deadline,
//! for a permit from the budget of the approved command its endpoint names.
//! Only then do the final checks run: the import dispatch fence (which also
//! compares the `[command_imports.<name>]` entry), the resource entries the
//! request names, revalidated and decrypted, and the credentials. A call
//! queued behind a quarantine, a slot rotation, a resource replacement or a
//! reload that changed the command entry fails without starting a process.
//! Core then builds the request: the caller, the admitted authority with its
//! resources, the credentials its grants use (a service slot at its admitted
//! version, a personal credential as it is now) and, for `network =
//! "inherit"`, the egress settings. The permit moves into the invocation and
//! on to the supervisor of the process the hook starts.
use super::*;
use crate::imports::{
    CommandAcquireError, CommandCaller, CommandCallerToken, CommandCallerUsername,
    CommandCredential, CommandInvocation, CommandPermit, CommandProcessFacts, CommandVerification,
    InvokeRequest, RequestAuthorization, RequestBoundary, RequestCredentials, RequestGrant,
    RequestResource, VerifyRequest, wire_deadline, wire_mode,
};
use crate::{
    AdmittedResourceEntry, CommandImportConfig, CommandNetwork, CommandResourceAttributes,
    CredentialVerificationTarget, ResourceFence,
};

/// An admitted command-import call holding its budget permit.
pub(super) struct CommandDispatch {
    pub(super) provider: Arc<dyn crate::imports::CommandProvider>,
    pub(super) permit: CommandPermit,
    /// The command deadline: the earlier of admission plus the command's
    /// `timeout` and the host operation deadline.
    pub(super) deadline: tokio::time::Instant,
}

/// What admission records for a command-import call, held in its
/// finalization context so that every outcome from admission on, including
/// a host interruption, audits it: the approved command, the authority
/// admitted for the call, the resource entries its request names, and the
/// process facts its supervisor records.
#[derive(Clone)]
pub(super) struct AdmittedCommand {
    /// The approved command name the import's endpoint names.
    name: String,
    authorization: CommandAuthorization,
    /// The enabled exact entries, by value, of the resources the request
    /// names, as the admission snapshot published them. A value without one
    /// is passed as its value alone.
    resources: BTreeMap<String, AdmittedResourceEntry>,
    facts: CommandProcessFacts,
}

impl AdmittedCommand {
    pub(super) fn authorization(&self) -> &CommandAuthorization {
        &self.authorization
    }

    /// The audit's `command` facts: the command name, whether its process
    /// was spawned, how the leader ended, how long it ran, whether it broke
    /// the contract, and whether the operation was dispatched. Facts not yet
    /// known are `null`.
    pub(super) fn audit(&self) -> Value {
        let facts = self.facts.snapshot();
        json!({
            "name": self.name,
            "spawned": facts.spawned,
            "exitCode": facts.exit_code,
            "signal": facts.signal,
            "durationMs": facts.duration_ms,
            "contractViolation": facts.contract_violation,
            "operationDispatched": facts.spawned,
        })
    }

    /// The audit's `commandAuthorization`: the admitted grant IDs, versions,
    /// subjects, credential modes and boundaries, never attributes.
    pub(super) fn authorization_audit(&self) -> Value {
        serde_json::to_value(&self.authorization).unwrap_or(Value::Null)
    }
}

fn imported_service_changed() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "imported service changed or is unavailable; repeat discovery",
    )
}

fn resource_changed() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "configured resource is unavailable or changed; resolve it again",
    )
}

fn admission_mismatch() -> ProviderError {
    ProviderError::error(
        ReasonCode::OperationFailed,
        "admitted authority does not match the action contract",
    )
}

fn credential_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "imported execution credential is unavailable",
    )
}

/// A resource store failure after the permit: a changed or missing entry is
/// `scope_unresolved`; the store's own failures keep their reasons.
fn resource_store_error(error: ManagedStoreError) -> ProviderError {
    match error {
        ManagedStoreError::VersionConflict
        | ManagedStoreError::ResourceNotFound
        | ManagedStoreError::InputInvalid(_) => resource_changed(),
        other => provider_error_from_managed_store(other),
    }
}

impl BrokerRuntime {
    /// The approved command name and this generation's
    /// `[command_imports.<name>]` entry of the command import `service`.
    fn command_import_entry(&self, service: &str) -> Option<(&str, &CommandImportConfig)> {
        let record = self.imported_catalog.service(service)?;
        let endpoint = record.definition.endpoint().ok()?;
        let (name, command) = self
            .config
            .command_imports
            .get_key_value(endpoint.command_name()?)?;
        Some((name.as_str(), command))
    }

    /// The deadline of a call of the command import `service` admitted at
    /// `admitted`: the earlier of admission plus the command's `timeout` and
    /// the host operation deadline, if the host set one.
    pub(crate) fn command_deadline(
        &self,
        service: &str,
        admitted: Instant,
    ) -> Result<tokio::time::Instant, ProviderError> {
        let timeout = self
            .command_import_entry(service)
            .and_then(|(_, command)| command.timeout())
            .ok_or_else(imported_service_changed)?;
        let deadline = tokio::time::Instant::from_std(admitted + timeout);
        Ok(agent_access_provider::current_provider_finalization()
            .and_then(|finalization| finalization.deadline())
            .map_or(deadline, |host| deadline.min(host)))
    }

    /// Waits until `deadline` for a permit from the budget of the command
    /// the import `service` names, under this generation's `max_concurrent`.
    /// Every `describe`, `invoke` and `verify` run of the command draws from
    /// the same budget, whichever import or generation admitted it. No permit
    /// by the deadline fails `upstream_timeout`; a Broker shutting down fails
    /// `operation_cancelled`. Nothing has started either way.
    pub(crate) async fn command_permit(
        &self,
        service: &str,
        deadline: tokio::time::Instant,
    ) -> Result<CommandPermit, ProviderError> {
        let (name, command) = self
            .command_import_entry(service)
            .ok_or_else(imported_service_changed)?;
        let limit = usize::try_from(command.max_concurrent).unwrap_or(usize::MAX);
        self.command_registry
            .acquire(name, limit, deadline)
            .await
            .map_err(|error| match error {
                CommandAcquireError::Closed => ProviderError::error(
                    ReasonCode::OperationCancelled,
                    "operation stopped during broker shutdown",
                ),
                CommandAcquireError::DeadlineExceeded => ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "The tool did not start in time.",
                ),
            })
    }

    /// For a command import, the hook and a budget permit, waited for until
    /// the call's command deadline; `None` for every other service.
    pub(super) async fn command_dispatch(
        &self,
        service: &str,
        admitted: Instant,
    ) -> Result<Option<CommandDispatch>, ProviderError> {
        let Some(provider) = self.command_provider(service).cloned() else {
            return Ok(None);
        };
        let deadline = self.command_deadline(service, admitted)?;
        let permit = self.command_permit(service, deadline).await?;
        Ok(Some(CommandDispatch {
            provider,
            permit,
            deadline,
        }))
    }

    /// What admission records for a call of the command import `service`
    /// planned as `authorization` from `snapshot`: the resource entries of
    /// the values it names, with their attribute bindings, from the same
    /// snapshot, and a fresh facts cell.
    pub(super) fn admitted_command(
        &self,
        service: &str,
        authorization: CommandAuthorization,
        snapshot: &PolicySnapshot,
        context: &ExecutionContext,
    ) -> Option<AdmittedCommand> {
        let record = self.imported_catalog.service(service)?;
        let name = record
            .definition
            .endpoint()
            .ok()?
            .command_name()?
            .to_owned();
        let (resource_type, values) = match &authorization {
            CommandAuthorization::Broker {
                resource_type,
                values,
                ..
            } => (Some(resource_type), values.iter().collect::<Vec<_>>()),
            CommandAuthorization::Command {
                resource_type,
                grants,
            } => (
                resource_type.as_ref(),
                grants
                    .iter()
                    .flat_map(|grant| match &grant.scope {
                        SearchAuthorizationScope::Finite { values } => values.as_slice(),
                        _ => &[],
                    })
                    .collect(),
            ),
        };
        let catalog = &snapshot.resource_catalog;
        let resources = resource_type
            .map(|resource_type| {
                values
                    .into_iter()
                    .filter_map(|value| {
                        let definition = catalog.resources.iter().find(|definition| {
                            definition.resource_type == resource_type.broker_type
                                && definition.selector
                                    == (ResourceSelector::Exact {
                                        value: value.clone(),
                                    })
                                && definition.enabled
                                && definition
                                    .allowed_execution_contexts
                                    .iter()
                                    .any(|allowed| allowed == context.as_str())
                        })?;
                        // Only a stored entry has an identity fence; a
                        // value without one is passed as its value alone.
                        let fence: &ResourceFence = catalog.resource_fences.get(&definition.id)?;
                        let binding = catalog
                            .attribute_bindings
                            .iter()
                            .find(|binding| binding.resource_id == definition.id)
                            .cloned();
                        Some((
                            value.clone(),
                            AdmittedResourceEntry {
                                resource_id: definition.id.clone(),
                                resource_type: definition.resource_type.clone(),
                                selector_value: value.clone(),
                                display_name: definition.display_name.clone(),
                                fence: fence.clone(),
                                binding,
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(AdmittedCommand {
            name,
            authorization,
            resources,
            facts: CommandProcessFacts::new(),
        })
    }

    /// Admission's check of a Broker-enforced call's credential: present
    /// locally in `mode`, as caller discovery checks it, without recording a
    /// use. The request builder resolves it after the permit.
    pub(super) async fn command_credential_admitted(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<(), ProviderError> {
        if !self.imported_mode_available(service, mode) {
            return Err(credential_unavailable());
        }
        let runtime = self.clone();
        let (service, mode, identity) = (service.to_owned(), mode.to_owned(), identity.clone());
        managed_store_blocking(move || {
            Ok(runtime.execution_credential_check(&service, &mode, &identity))
        })
        .await
        .map_err(provider_error_from_managed_store)?
        .map_err(|failure| failure.map_or_else(credential_unavailable, |error| *error))
    }

    /// The invocation the command hook receives, built after the permit and
    /// the final checks from the admitted request and what admission recorded
    /// in `context`. Its request carries the caller, the admitted
    /// authorization with each named resource's identity and decrypted
    /// attributes, the credentials its grants use and, for `network =
    /// "inherit"`, the egress settings, which also become the invocation's
    /// network variables. It shares the call's process facts with
    /// finalization. A failure starts no process.
    pub(super) async fn command_invocation(
        &self,
        permit: CommandPermit,
        deadline: tokio::time::Instant,
        request: &AdmittedRequest,
        context: &FinalizeContext,
    ) -> Result<CommandInvocation, ProviderError> {
        let service = request.service();
        let action = request.action();
        let admitted = context.command.as_ref().ok_or_else(admission_mismatch)?;
        let (_, entry) = self
            .command_import_entry(service)
            .ok_or_else(imported_service_changed)?;
        let record = self
            .imported_catalog
            .service(service)
            .ok_or_else(imported_service_changed)?;
        let source = record
            .actions
            .iter()
            .find(|candidate| candidate.definition.action == action)
            .and_then(|candidate| candidate.definition.source.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(imported_service_changed)?;
        let read_only = self
            .action_descriptor(service, action)
            .ok_or_else(imported_service_changed)?
            .read_only;
        let resources = self
            .command_resources(admitted, request.execution_context())
            .await?;
        let credentials = self
            .command_credentials(service, &admitted.authorization, &context.identity)
            .await?;
        let caller = self.command_caller(&context.identity).await?;
        let authorization = request_authorization(
            &admitted.authorization,
            &admitted.resources,
            resources,
            credentials.is_none(),
        )?;
        let network =
            (entry.network == CommandNetwork::Inherit).then(|| self.inherited_network().as_ref());
        let (encoded, secrets) = InvokeRequest {
            action: source,
            context: request.execution_context(),
            request_id: &context.broker_request_id,
            deadline: &wire_deadline(deadline),
            caller: &caller,
            inputs: request.inputs(),
            authorization,
            credentials,
            network,
        }
        .encode()?;
        let invocation =
            CommandInvocation::new(action.to_owned(), read_only, encoded, deadline, permit)
                .with_facts(admitted.facts.clone())
                .with_secrets(secrets);
        Ok(match network {
            Some(network) => invocation.with_environment(network.environment()),
            None => invocation,
        })
    }

    /// Revalidates and decrypts, after the permit, the resource entries
    /// admission recorded: each must still be the same stored row and the
    /// same enabled exact entry in `context` with the admitted attribute
    /// versions, and its attributes must satisfy the type's current
    /// declaration. A replaced, recreated or changed entry fails
    /// `scope_unresolved`.
    async fn command_resources(
        &self,
        admitted: &AdmittedCommand,
        context: &str,
    ) -> Result<BTreeMap<String, CommandResourceAttributes>, ProviderError> {
        if admitted.resources.is_empty() {
            return Ok(BTreeMap::new());
        }
        let store = self.managed_store.clone().ok_or_else(resource_changed)?;
        let ring = self
            .credential_key_ring
            .clone()
            .ok_or_else(resource_changed)?;
        let entries = admitted.resources.values().cloned().collect::<Vec<_>>();
        let context = context.to_owned();
        let values = managed_store_blocking({
            let entries = entries.clone();
            move || store.resolve_command_resources(&entries, &context, &ring)
        })
        .await
        .map_err(resource_store_error)?;
        entries
            .into_iter()
            .zip(values)
            .map(|(entry, attributes)| {
                if !self.command_attributes_valid(&entry.resource_type, &attributes) {
                    return Err(resource_changed());
                }
                Ok((entry.selector_value, attributes))
            })
            .collect()
    }

    /// Whether decrypted attribute `values` satisfy the current declaration
    /// of `resource_type`: known names, non-empty values within 8 KiB that
    /// pass their patterns, and every required attribute present. Checked
    /// in place, so the plaintext is never copied out of zeroizing storage.
    fn command_attributes_valid(
        &self,
        resource_type: &ResourceType,
        values: &CommandResourceAttributes,
    ) -> bool {
        const MAX_ATTRIBUTE_BYTES: usize = 8 * 1024;
        let Some(descriptor) = self.resource_types.get(resource_type) else {
            return values.is_empty();
        };
        let fields = descriptor.attributes();
        values.iter().all(|(name, value)| {
            fields.iter().any(|field| {
                field.name() == name
                    && !value.is_empty()
                    && value.len() <= MAX_ATTRIBUTE_BYTES
                    && field.is_valid(value)
            })
        }) && fields
            .iter()
            .all(|field| !field.is_required() || values.contains_key(field.name()))
    }

    /// The credentials a request carries, resolved after the permit: one
    /// for each credential mode its grants use, keyed by wire mode. `None`
    /// for a command without a credential.
    async fn command_credentials(
        &self,
        service: &str,
        authorization: &CommandAuthorization,
        identity: &IdentityContext,
    ) -> Result<Option<RequestCredentials>, ProviderError> {
        let record = self
            .imported_catalog
            .service(service)
            .ok_or_else(imported_service_changed)?;
        if imports::credential_free(&record.definition) {
            return Ok(None);
        }
        let mut credentials = RequestCredentials::default();
        for mode in authorization.credential_modes() {
            let wire = wire_mode(mode).ok_or_else(admission_mismatch)?;
            let credential = self.command_credential(service, mode, identity).await?;
            credentials.insert(wire, credential);
        }
        if credentials.is_empty() {
            return Err(admission_mismatch());
        }
        Ok(Some(credentials))
    }

    /// The credential of `mode` for a command import: the execution slot at
    /// the version this generation admitted, or the caller's personal
    /// credential as it is now. A personal credential never falls back to
    /// the service slot. A slot rotated since admission fails
    /// `service_action_denied`; a missing credential fails
    /// `credential_not_provisioned`.
    async fn command_credential(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<CommandCredential, ProviderError> {
        let record = self
            .imported_catalog
            .service(service)
            .ok_or_else(imported_service_changed)?;
        if !self.imported_mode_available(service, mode) {
            return Err(credential_unavailable());
        }
        let store = self
            .managed_store
            .clone()
            .ok_or_else(credential_unavailable)?;
        let ring = self.credential_key_ring.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::EncryptionKeyMissing,
                "credential encryption key ring is not configured",
            )
        })?;
        let credential = match mode {
            "service" => {
                let version = record
                    .slot_versions
                    .get(&ImportedCredentialPurpose::Execution)
                    .cloned()
                    .ok_or_else(credential_unavailable)?;
                let service = service.to_owned();
                managed_store_blocking(move || {
                    store.resolve_imported_command_credential(
                        &service,
                        ImportedCredentialPurpose::Execution,
                        &version,
                        &ring,
                    )
                })
                .await
                .map_err(|error| match error {
                    ManagedStoreError::VersionConflict => imported_service_changed(),
                    other => provider_error_from_managed_store(other),
                })?
            }
            "per_user" => {
                let (name, profile) = self.personal_command_credential(service)?;
                if !identity.authenticated {
                    return Err(credential_unavailable());
                }
                let (principal, service) = (identity.principal.clone(), service.to_owned());
                managed_store_blocking(move || {
                    store.resolve_user_command_credential(
                        &ring, &principal, &service, &name, &profile,
                    )
                })
                .await
                .map_err(|error| match error {
                    ManagedStoreError::CredentialNotFound => credential_unavailable(),
                    other => provider_error_from_managed_store(other),
                })?
            }
            _ => return Err(admission_mismatch()),
        };
        if credential.kind() != imports::execution_credential_kind(record) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "stored credential kind does not match the command's credential",
            ));
        }
        Ok(credential)
    }

    /// The name and profile of the personal credential a command import
    /// reads in `per_user` mode.
    fn personal_command_credential(
        &self,
        service: &str,
    ) -> Result<(String, String), ProviderError> {
        let credential = self
            .effective_credentials
            .per_user
            .get(service)
            .filter(|credential| credential.kind == "managed_store")
            .ok_or_else(credential_unavailable)?;
        Ok((
            credential
                .credential_name
                .clone()
                .unwrap_or_else(|| "default".into()),
            credential
                .profile
                .clone()
                .ok_or_else(credential_unavailable)?,
        ))
    }

    /// The request's `caller`, read from the managed store: the principal's
    /// kind, display name and email, the asserted username binding, the
    /// agent token and its label, and the caller's policy groups.
    async fn command_caller(
        &self,
        identity: &IdentityContext,
    ) -> Result<CommandCaller, ProviderError> {
        let store = self.managed_store.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::ManagedStoreUnavailable,
                "managed store is not configured",
            )
        })?;
        let source = identity.source.as_ref();
        let token_id = source.and_then(|source| source.token_id.clone());
        let binding_id = source
            .filter(|source| source.kind == "trusted_user")
            .and_then(|source| source.binding_id.clone());
        let principal = identity.principal.clone();
        let record = managed_store_blocking({
            let token_id = token_id.clone();
            move || store.command_caller(&principal, token_id.as_deref(), binding_id.as_deref())
        })
        .await
        .map_err(provider_error_from_managed_store)?;
        Ok(CommandCaller {
            principal: identity.principal.clone(),
            kind: record.kind,
            display_name: record.display_name,
            email: record.email,
            username: record
                .username
                .map(|(namespace, name)| CommandCallerUsername { namespace, name }),
            token: token_id
                .zip(record.token_label)
                .map(|(id, label)| CommandCallerToken { id, label }),
            groups: identity.policy_groups.clone(),
        })
    }

    /// `error` of a command-import call, with what a write-capable action
    /// reports about its process: nothing was applied when no process
    /// started (`started` is false when the hook was never called), and
    /// `operationDispatched` beside any receipt.
    pub(super) fn command_failure(
        &self,
        service: &str,
        action: &str,
        error: ProviderError,
        started: bool,
        context: &FinalizeContext,
    ) -> ProviderError {
        if self
            .action_descriptor(service, action)
            .is_none_or(|descriptor| descriptor.read_only)
        {
            return error;
        }
        let mut error = if started {
            error
        } else {
            error.with_mutation_receipt(MutationReceipt::not_applied())
        };
        let spawned = context
            .command
            .as_ref()
            .is_some_and(|admitted| admitted.facts.snapshot().spawned);
        if let Some(result) = error
            .result
            .as_deref_mut()
            .and_then(Value::as_object_mut)
            .filter(|result| result.contains_key("mutationStatus"))
        {
            result.insert("operationDispatched".into(), json!(spawned));
        }
        error
    }

    /// Verifies the personal credential `target` names, which `owner` holds
    /// as `name` for the command import `service`, by running `<path>
    /// verify` under the command's budget. `None` when the command does not
    /// declare `verify`, so verification is unsupported. The import must
    /// still dispatch under this generation when the verification is
    /// admitted, after its slot, and immediately before the process starts;
    /// a reload or change that retired it fails `service_action_denied`
    /// without supplying the credential. The verification audit, or the
    /// failure's, records the process facts.
    pub async fn verify_command_credential(
        &self,
        service: &str,
        owner: &IdentityContext,
        name: &str,
        target: &CredentialVerificationTarget,
        correlation: CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let provider = self.command_provider(service).cloned().ok_or_else(|| {
            ProviderError::deny(ReasonCode::ServiceActionDenied, "service is not supported")
        })?;
        let verify = self
            .imported_catalog
            .service(service)
            .and_then(|record| record.accepted_metadata.as_ref())
            .is_some_and(|metadata| metadata.verify);
        if !verify {
            return Ok(None);
        }
        self.command_import_fenced(service)?;
        let (_, profile) = self.personal_command_credential(service)?;
        let deadline = self.command_deadline(service, Instant::now())?;
        let permit = self.command_permit(service, deadline).await?;
        self.command_import_fenced(service)?;
        let store = self
            .managed_store
            .clone()
            .ok_or_else(credential_unavailable)?;
        let ring = self.credential_key_ring.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::EncryptionKeyMissing,
                "credential encryption key ring is not configured",
            )
        })?;
        let credential = managed_store_blocking({
            let (principal, service, name, target) = (
                owner.principal.clone(),
                service.to_owned(),
                name.to_owned(),
                target.clone(),
            );
            move || {
                store.resolve_user_command_credential_for_verification(
                    &ring, &principal, &service, &name, &profile, &target,
                )
            }
        })
        .await
        .map_err(provider_error_from_managed_store)?;
        self.run_command_verification(
            service,
            provider,
            &credential,
            deadline,
            permit,
            correlation,
        )
        .await
        .map(Some)
    }

    /// `Ok` while the command import `service` still dispatches under this
    /// generation; `service_action_denied` once a change retired it.
    fn command_import_fenced(&self, service: &str) -> Result<(), ProviderError> {
        if self.imported_service_dispatchable(service) {
            Ok(())
        } else {
            Err(imported_service_changed())
        }
    }

    /// Runs `<path> verify` for the personal `credential` under `permit`
    /// until `deadline`, in the credential-verification hook, once the
    /// import's fence holds immediately before the process starts.
    async fn run_command_verification(
        &self,
        service: &str,
        provider: Arc<dyn crate::imports::CommandProvider>,
        credential: &CommandCredential,
        deadline: tokio::time::Instant,
        permit: CommandPermit,
        correlation: CorrelationContext,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        let (name, entry) = self
            .command_import_entry(service)
            .ok_or_else(imported_service_changed)?;
        let network =
            (entry.network == CommandNetwork::Inherit).then(|| self.inherited_network().as_ref());
        let (request, secrets) = VerifyRequest {
            request_id: &correlation.broker_request_id,
            deadline: &wire_deadline(deadline),
            credential,
            network,
        }
        .encode()?;
        let facts = CommandProcessFacts::new();
        let mut verification = CommandVerification::new(request, deadline, permit)
            .with_facts(facts.clone())
            .with_secrets(secrets);
        if let Some(network) = network {
            verification = verification.with_environment(network.environment());
        }
        self.command_import_fenced(service)?;
        let admitted = AdmittedCommand {
            name: name.to_owned(),
            authorization: CommandAuthorization::Command {
                resource_type: None,
                grants: Vec::new(),
            },
            resources: BTreeMap::new(),
            facts,
        };
        let result = with_provider_context(
            correlation,
            service.to_owned(),
            "credential.verify".to_owned(),
            run_provider_hook(
                agent_access_provider::host::hook_context(
                    service,
                    "credential.verify",
                    HookPhase::CredentialVerification,
                    &[],
                ),
                provider.verify_command(verification),
            ),
        )
        .await;
        let audit = json!({"command": admitted.audit()});
        match result {
            Ok(mut verification) => {
                verification.audit = audit;
                Ok(verification)
            }
            Err(error) => Err(error.with_audit(audit)),
        }
    }
}

/// The request's `authorization` block from the admitted plan, with each
/// resource that has an admitted entry passed with its ID, display name and
/// the attributes `resolved` after the permit, and every `credential` member
/// omitted for a command without a credential.
fn request_authorization(
    authorization: &CommandAuthorization,
    entries: &BTreeMap<String, AdmittedResourceEntry>,
    resolved: BTreeMap<String, CommandResourceAttributes>,
    credential_free: bool,
) -> Result<RequestAuthorization, ProviderError> {
    let credential = |mode: &str| -> Result<Option<&'static str>, ProviderError> {
        if credential_free {
            Ok(None)
        } else {
            wire_mode(mode).map(Some).ok_or_else(admission_mismatch)
        }
    };
    let resource = |value: &String| match entries.get(value) {
        Some(entry) => RequestResource::entry(
            value.clone(),
            entry.resource_id.clone(),
            entry.display_name.clone(),
            resolved.get(value).cloned().unwrap_or_default(),
        ),
        None => RequestResource::value(value.clone()),
    };
    Ok(match authorization {
        CommandAuthorization::Broker {
            resource_type,
            credential_mode,
            values,
            ..
        } => RequestAuthorization::Broker {
            credential: credential(credential_mode)?,
            resource_type: resource_type.id.clone(),
            resources: values.iter().map(resource).collect(),
        },
        CommandAuthorization::Command {
            resource_type,
            grants,
        } => RequestAuthorization::Command {
            resource_type: resource_type
                .as_ref()
                .map(|resource_type| resource_type.id.clone()),
            grants: grants
                .iter()
                .map(|grant| {
                    Ok(RequestGrant {
                        credential: credential(&grant.credential_mode)?,
                        boundary: match &grant.scope {
                            SearchAuthorizationScope::Finite { values } => {
                                RequestBoundary::Resources(values.iter().map(resource).collect())
                            }
                            SearchAuthorizationScope::AllExcept { excluded_values } => {
                                RequestBoundary::Any {
                                    except: excluded_values.clone(),
                                }
                            }
                        },
                    })
                })
                .collect::<Result<_, ProviderError>>()?,
        },
    })
}
