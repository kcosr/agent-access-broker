//! Command imports: operator-approved local executables imported as Broker
//! services through the `command` import kind.
//!
//! An operator approves an executable as `[command_imports.<name>]`; an
//! import names it by its `command:<name>` endpoint. Discovery runs
//! `<path> describe` and maps its `agent-access-command/1` manifest onto
//! imported actions, the service-level metadata acceptance stores, and the
//! unsupported reasons of invalid actions. Building never runs the command,
//! so startup and reload stay offline.
//!
//! Each accepted action declares how its resources are checked: through
//! input pointers the Broker resolves and checks before dispatch, or by the
//! command from the grants it is passed (see
//! [`ImportedActionAuthority`]).
//!
//! The adapter builds a [`CommandProvider`]: core calls its command hook
//! instead of `Provider::invoke` with a request it assembles after the
//! budget permit and final checks. Every run, `describe` included, starts one
//! process under a supervisor that holds a permit from the command's budget
//! until the process group is killed and reaped (`process.rs`,
//! `supervisor.rs`, `run.rs`). Commands run on Unix only.
mod download;
mod manifest;
mod mapping;
mod response;
mod scopes;

use agent_access_core::CommandImportConfig;
use agent_access_core::imports::{
    AdapterDiscoveryError, CommandAcquireError, CommandInvocation, CommandProcessFacts,
    CommandProvider, CommandSecrets, CommandVerification, ImportEndpointForm,
    ImportedActionAuthority, ImportedActionDefinition, ImportedAdapter, ImportedAdapterContext,
    ImportedAdapterRegistration, ImportedAuthMechanism, ImportedBindingStatus, ImportedDiscovery,
    ImportedDiscoveryAuthentication, ImportedDiscoveryCredential, ImportedProvider,
    ImportedServiceDefinition, ImportedServiceMetadata, imported_adapter_registration,
};
use agent_access_provider::{
    BuildContext, ExecutionCredential, MutationReceipt, Provider, ProviderBuildError,
    ProviderCredentialVerification, ProviderError, ProviderInvocation, ProviderResult, ReasonCode,
    ScopeRequest, ScopeResolution,
};
use async_trait::async_trait;
use mapping::CompiledAction;
use run::{CommandOperation, RunFailure};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
mod process;
mod run;
#[cfg(unix)]
mod supervisor;

/// The import kind this adapter serves, `adapterKind` in imported definitions.
const KIND: &str = "command";
/// The shared administrative discovery deadline.
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(60);

/// The `command` import selection. Command imports use static credentials
/// only, so it declares no OAuth companion.
pub fn registration() -> ImportedAdapterRegistration {
    imported_adapter_registration(
        agent_access_provider::module_metadata!(),
        &CommandAdapter,
        None,
    )
}

#[derive(Debug)]
struct CommandAdapter;

fn discovery_failure(reason: ReasonCode, message: &str) -> AdapterDiscoveryError {
    AdapterDiscoveryError::Failed(ProviderError::error(reason, message))
}

fn describe_timeout() -> AdapterDiscoveryError {
    discovery_failure(
        ReasonCode::UpstreamTimeout,
        "the command did not finish describe in time",
    )
}

#[async_trait]
impl ImportedAdapter for CommandAdapter {
    fn kind(&self) -> &'static str {
        KIND
    }
    fn development_only(&self) -> bool {
        false
    }
    fn endpoint_form(&self) -> ImportEndpointForm {
        ImportEndpointForm::Command
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()?;
        if definition.endpoint()?.form() != ImportEndpointForm::Command {
            return Err("command imports use a command:<name> endpoint".into());
        }
        if definition.discovery != ImportedDiscoveryCredential::Anonymous {
            return Err("command imports discover without a credential".into());
        }
        if definition.execution_bindings.iter().any(|binding| {
            binding.mechanism != ImportedAuthMechanism::StaticToken
                || binding.status != ImportedBindingStatus::Configured
        }) {
            return Err("command imports use static credentials".into());
        }
        Ok(())
    }
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamCommand"]
    }
    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
        let compiled = CompiledAction::new(action)?;
        if compiled.authority.listing_of.is_some() && !action.read_only {
            return Err(
                "listingOf requires the action to be classified as reviewed read-only".into(),
            );
        }
        Ok(())
    }
    fn action_authority(
        &self,
        action: &ImportedActionDefinition,
    ) -> Result<ImportedActionAuthority, String> {
        CompiledAction::new(action).map(|compiled| compiled.authority)
    }
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        mapping::source_name(action).map(str::to_owned)
    }
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport_credential: Option<ExecutionCredential>,
        import: &ImportedAdapterContext<'_>,
        _host: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        self.validate_definition(definition)
            .map_err(ProviderBuildError::invalid)?;
        if transport_credential.is_some() {
            return Err(ProviderBuildError::invalid(
                "command imports have no transport credential",
            ));
        }
        let command = import.command.ok_or_else(|| {
            ProviderBuildError::invalid("the command is not approved in [command_imports]")
        })?;
        let metadata = import.accepted_metadata.ok_or_else(|| {
            ProviderBuildError::invalid("the command's manifest has not been accepted")
        })?;
        let mut compiled = BTreeMap::new();
        for action in actions {
            if action.download && command.max_download_bytes.is_none() {
                return Err(ProviderBuildError::invalid(
                    "command downloads require max_download_bytes",
                ));
            }
            let value = CompiledAction::new(action).map_err(ProviderBuildError::invalid)?;
            if compiled
                .insert(action.action.clone(), Arc::new(value))
                .is_some()
            {
                return Err(ProviderBuildError::invalid("duplicate imported action"));
            }
        }
        Ok(ImportedProvider::Command(Arc::new(CommandImportProvider {
            service: definition.service.clone(),
            actions: compiled,
            command: command.clone(),
            metadata: metadata.clone(),
        })))
    }
    async fn discover(
        &self,
        definition: &ImportedServiceDefinition,
        authentication: &ImportedDiscoveryAuthentication,
        transport_credential: Option<ExecutionCredential>,
        import: &ImportedAdapterContext<'_>,
        _host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
        self.validate_definition(definition)
            .map_err(AdapterDiscoveryError::Configuration)?;
        let name = definition
            .endpoint()
            .ok()
            .and_then(|endpoint| endpoint.command_name().map(str::to_owned))
            .ok_or_else(|| {
                AdapterDiscoveryError::Configuration(
                    "command imports use a command:<name> endpoint".into(),
                )
            })?;
        let command = import.command.cloned().ok_or_else(|| {
            AdapterDiscoveryError::Configuration(
                "the command is not approved in [command_imports]".into(),
            )
        })?;
        // `describe` never receives credentials.
        if !matches!(authentication, ImportedDiscoveryAuthentication::Anonymous)
            || transport_credential.is_some()
        {
            return Err(AdapterDiscoveryError::Configuration(
                "command imports discover without a credential".into(),
            ));
        }
        let registry = import.command_registry.ok_or_else(|| {
            AdapterDiscoveryError::Configuration("the command's budget is unavailable".into())
        })?;
        // `describe` runs within the command's timeout and the discovery
        // deadline, permit wait included, under the command's shared budget.
        let deadline = tokio::time::Instant::now()
            + command
                .timeout()
                .unwrap_or(DISCOVERY_DEADLINE)
                .min(DISCOVERY_DEADLINE);
        let limit = usize::try_from(command.max_concurrent).unwrap_or(usize::MAX);
        let permit =
            registry
                .acquire(&name, limit, deadline)
                .await
                .map_err(|error| match error {
                    CommandAcquireError::Closed => discovery_failure(
                        ReasonCode::OperationCancelled,
                        "the Broker is shutting down",
                    ),
                    CommandAcquireError::DeadlineExceeded => describe_timeout(),
                })?;
        let output = run::execute(run::Run {
            service: &definition.service,
            command: &command,
            operation: CommandOperation::Describe,
            permit,
            request: None,
            deadline,
            max_output_bytes: manifest::MAX_DESCRIBE_BYTES,
            environment: Vec::new(),
            facts: CommandProcessFacts::new(),
        })
        .await
        .map_err(|failure| match failure {
            RunFailure::Spawn => discovery_failure(
                ReasonCode::OperationFailed,
                "the command could not be started",
            ),
            RunFailure::Cancelled | RunFailure::Stopped => discovery_failure(
                ReasonCode::OperationCancelled,
                "the Broker is shutting down",
            ),
            RunFailure::DeadlineBeforeStart | RunFailure::TimedOut => describe_timeout(),
            RunFailure::OutputLimit => discovery_failure(
                ReasonCode::OperationFailed,
                "the command's describe output exceeds 16 MiB",
            ),
            RunFailure::PipesHeldOpen => discovery_failure(
                ReasonCode::OperationFailed,
                "a process the command started kept its output open",
            ),
            RunFailure::ExitStatus | RunFailure::Signal | RunFailure::Unobserved => {
                discovery_failure(ReasonCode::OperationFailed, "the command's describe failed")
            }
        })?
        .stdout;
        let manifest = manifest::parse(&output).map_err(|reason| {
            AdapterDiscoveryError::Failed(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                format!(
                    "the command's manifest is invalid: {}",
                    reason.chars().take(512).collect::<String>()
                ),
            ))
        })?;
        mapping::check_credential(definition, &manifest, import.accepted_metadata)
            .map_err(AdapterDiscoveryError::Configuration)?;
        mapping::discovery(
            definition,
            &name,
            &manifest,
            import.accepted_metadata,
            command.max_download_bytes.is_some(),
        )
        .map_err(|reason| {
            AdapterDiscoveryError::Failed(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                reason,
            ))
        })
    }
}

/// One enabled command import. It resolves a Broker-enforced action's
/// resources at admission. Each call runs one supervised process of the
/// approved command; core never calls [`Provider::invoke`] on it.
struct CommandImportProvider {
    service: String,
    actions: BTreeMap<String, Arc<CompiledAction>>,
    command: CommandImportConfig,
    metadata: ImportedServiceMetadata,
}

impl CommandImportProvider {
    fn action(&self, action: &str) -> Result<&Arc<CompiledAction>, ProviderError> {
        self.actions.get(action).ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "unknown command import action")
        })
    }

    /// The result of the document an `invoke` process printed before
    /// exiting 0 (see [`response`]). A document that breaks the command
    /// contract is recorded and logged as a violation and fails
    /// `operation_failed`: the process ran, so a write's outcome is unknown.
    fn invoke_response(
        &self,
        action: &CompiledAction,
        read_only: bool,
        completed: run::Completed,
        facts: &CommandProcessFacts,
        secrets: &CommandSecrets,
    ) -> Result<ProviderResult, ProviderError> {
        match response::invoke(&self.service, action, read_only, &completed.stdout, secrets) {
            Ok(outcome) => {
                facts.record_contract_kept();
                outcome
            }
            Err(violation) => Err(self.violation(
                &completed,
                facts,
                CommandOperation::Invoke,
                violation,
                read_only,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_response(
        &self,
        action: Arc<CompiledAction>,
        read_only: bool,
        mut completed: run::Completed,
        facts: &CommandProcessFacts,
        secrets: CommandSecrets,
        cap: usize,
        deadline: tokio::time::Instant,
        lease: agent_access_core::imports::CommandBudgetLease,
    ) -> Result<ProviderResult, ProviderError> {
        let stdout = std::mem::take(&mut completed.stdout);
        let service = self.service.clone();
        let result = download::run_worker(lease, deadline, move |control| {
            let result = download::invoke(
                &service, &action, read_only, &stdout, &secrets, cap, control,
            );
            // Encoded bytes and supplied secrets never accompany the result
            // or its delivery stream out of the blocking worker.
            drop(stdout);
            drop(secrets);
            result
        })
        .await;
        match result {
            Ok(outcome) => {
                facts.record_contract_kept();
                outcome
            }
            Err(download::Error::Violation(violation)) => Err(self.violation(
                &completed,
                facts,
                CommandOperation::Invoke,
                violation,
                read_only,
            )),
            Err(error) => {
                let failure = match error {
                    download::Error::Stopped => RunFailure::TimedOut,
                    _ => RunFailure::Unobserved,
                };
                completed.log_violation(
                    &self.service,
                    &self.command,
                    CommandOperation::Invoke,
                    failure.category(),
                );
                Err(failure.invocation_error(read_only))
            }
        }
    }

    /// The verification result of the document a `verify` process printed
    /// before exiting 0: verified for `{"ok": true}`, the command's mapped
    /// error otherwise. Commands have no upstream status; core records the
    /// process facts in the verification audit.
    fn verify_response(
        &self,
        completed: run::Completed,
        facts: &CommandProcessFacts,
        secrets: &CommandSecrets,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        match response::verify(&self.service, &completed.stdout, secrets) {
            Ok(Ok(())) => {
                facts.record_contract_kept();
                Ok(ProviderCredentialVerification::new(
                    0,
                    facts.snapshot().duration_ms.unwrap_or(0),
                    serde_json::json!({}),
                ))
            }
            Ok(Err(error)) => {
                facts.record_contract_kept();
                Err(error)
            }
            Err(violation) => {
                Err(self.violation(&completed, facts, CommandOperation::Verify, violation, true))
            }
        }
    }

    /// Records and logs a response that broke the command contract; callers
    /// see only `operation_failed`, with an `unknown` write receipt.
    fn violation(
        &self,
        completed: &run::Completed,
        facts: &CommandProcessFacts,
        operation: CommandOperation,
        violation: response::Violation,
        read_only: bool,
    ) -> ProviderError {
        facts.record_contract_violation();
        completed.log_violation(
            &self.service,
            &self.command,
            operation,
            violation.category(),
        );
        let error = ProviderError::error(ReasonCode::OperationFailed, "The tool failed.");
        if read_only {
            error
        } else {
            error.with_mutation_receipt(MutationReceipt::unknown())
        }
    }
}

/// A call that ends before any process starts: nothing was applied.
fn not_started(error: ProviderError, read_only: bool) -> ProviderError {
    if read_only {
        error
    } else {
        error.with_mutation_receipt(MutationReceipt::not_applied())
    }
}

#[async_trait]
impl Provider for CommandImportProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        scopes::resolve(self.action(request.action())?, request.inputs())
            .map(ScopeResolution::resources)
    }

    /// Core runs command imports through the command hook; a direct call
    /// fails closed.
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Err(not_started(
            ProviderError::error(
                ReasonCode::OperationFailed,
                "command imports run only through the command hook",
            ),
            self.action(request.action())?.read_only,
        ))
    }
}

#[async_trait]
impl CommandProvider for CommandImportProvider {
    async fn invoke_command(
        &self,
        invocation: CommandInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let read_only = invocation.read_only();
        let action = self
            .action(invocation.action())
            .map_err(|error| not_started(error, read_only))?;
        let read_only = read_only && action.read_only;
        let agent_access_core::imports::CommandRun {
            request,
            deadline,
            permit,
            environment,
            facts,
            secrets,
        } = invocation.into_run();
        let download_limits = if action.download {
            let cap = self
                .command
                .max_download_bytes
                .and_then(|cap| usize::try_from(cap).ok());
            let output = self
                .command
                .download_output_bytes()
                .and_then(|cap| usize::try_from(cap).ok());
            Some(cap.zip(output).ok_or_else(|| {
                not_started(
                    ProviderError::error(
                        ReasonCode::OperationFailed,
                        "command downloads require valid max_download_bytes",
                    ),
                    read_only,
                )
            })?)
        } else {
            None
        };
        // This retains the same counted unit, but cannot register another
        // process. Capture it before the supervisor takes the unique permit.
        let lease = download_limits.map(|_| permit.retain_budget());
        let completed = run::execute(run::Run {
            service: &self.service,
            command: &self.command,
            operation: CommandOperation::Invoke,
            permit,
            request: Some(request),
            deadline,
            max_output_bytes: download_limits
                .map_or_else(|| run::output_limit(&self.command), |(_, output)| output),
            environment,
            facts: facts.clone(),
        })
        .await
        .map_err(|failure| failure.invocation_error(read_only))?;
        match download_limits {
            Some((cap, _)) => {
                self.download_response(
                    action.clone(),
                    read_only,
                    completed,
                    &facts,
                    secrets,
                    cap,
                    deadline,
                    lease.expect("download retained its budget"),
                )
                .await
            }
            None => self.invoke_response(action, read_only, completed, &facts, &secrets),
        }
    }

    async fn verify_command(
        &self,
        verification: CommandVerification,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        // Core verifies only through commands whose accepted manifest
        // declares `verify`; anything else fails before a process starts.
        if !self.metadata.verify {
            return Err(ProviderError::error(
                ReasonCode::OperationFailed,
                "this command does not verify credentials",
            ));
        }
        let agent_access_core::imports::CommandRun {
            request,
            deadline,
            permit,
            environment,
            facts,
            secrets,
        } = verification.into_run();
        let completed = run::execute(run::Run {
            service: &self.service,
            command: &self.command,
            operation: CommandOperation::Verify,
            permit,
            request: Some(request),
            deadline,
            max_output_bytes: run::output_limit(&self.command),
            environment,
            facts: facts.clone(),
        })
        .await
        .map_err(RunFailure::error)?;
        self.verify_response(completed, &facts, &secrets)
    }
}

#[cfg(test)]
mod tests;
