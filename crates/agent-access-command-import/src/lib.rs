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
//! budget permit and final checks. Until the process supervisor lands, the
//! hook fails closed before any process starts.
mod describe;
mod manifest;
mod mapping;
mod scopes;

use agent_access_core::CommandImportConfig;
use agent_access_core::imports::{
    AdapterDiscoveryError, CommandInvocation, CommandProvider, CommandVerification,
    ImportEndpointForm, ImportedActionAuthority, ImportedActionDefinition, ImportedAdapter,
    ImportedAdapterContext, ImportedAdapterRegistration, ImportedAuthMechanism,
    ImportedBindingStatus, ImportedDiscovery, ImportedDiscoveryAuthentication,
    ImportedDiscoveryCredential, ImportedProvider, ImportedServiceDefinition,
    ImportedServiceMetadata, imported_adapter_registration,
};
use agent_access_provider::{
    BuildContext, ExecutionCredential, MutationReceipt, Provider, ProviderBuildError,
    ProviderCredentialVerification, ProviderError, ProviderInvocation, ProviderResult, ReasonCode,
    ScopeRequest, ScopeResolution,
};
use async_trait::async_trait;
use mapping::CompiledAction;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the command hook starts processes after the foundation lands"
    )
)]
mod process;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the command hook starts processes after the foundation lands"
    )
)]
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
        CompiledAction::new(action).map(|_| ())
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
            let value = CompiledAction::new(action).map_err(ProviderBuildError::invalid)?;
            if compiled.insert(action.action.clone(), value).is_some() {
                return Err(ProviderBuildError::invalid("duplicate imported action"));
            }
        }
        Ok(ImportedProvider::Command(Arc::new(CommandImportProvider {
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
        let timeout = command
            .timeout()
            .unwrap_or(DISCOVERY_DEADLINE)
            .min(DISCOVERY_DEADLINE);
        let output = tokio::task::spawn_blocking(move || {
            describe::run(&command, manifest::MAX_DESCRIBE_BYTES, timeout)
        })
        .await
        .map_err(|_| {
            discovery_failure(
                ReasonCode::OperationFailed,
                "the command's describe did not complete",
            )
        })?
        .map_err(|failure| match failure {
            describe::DescribeFailure::Timeout => discovery_failure(
                ReasonCode::UpstreamTimeout,
                "the command did not finish describe in time",
            ),
            describe::DescribeFailure::Spawn => discovery_failure(
                ReasonCode::OperationFailed,
                "the command could not be started",
            ),
            describe::DescribeFailure::OutputTooLarge => discovery_failure(
                ReasonCode::OperationFailed,
                "the command's describe output exceeds 16 MiB",
            ),
            describe::DescribeFailure::Failed => {
                discovery_failure(ReasonCode::OperationFailed, "the command's describe failed")
            }
            describe::DescribeFailure::PipesOpen => discovery_failure(
                ReasonCode::OperationFailed,
                "a process the command started kept its output open",
            ),
        })?;
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
        mapping::discovery(definition, &name, &manifest, import.accepted_metadata).map_err(
            |reason| {
                AdapterDiscoveryError::Failed(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    reason,
                ))
            },
        )
    }
}

/// One enabled command import. It resolves a Broker-enforced action's
/// resources at admission and fails every call closed before a process
/// starts.
struct CommandImportProvider {
    actions: BTreeMap<String, CompiledAction>,
    #[expect(dead_code, reason = "the process supervisor spawns from it")]
    command: CommandImportConfig,
    #[expect(dead_code, reason = "the request contract reads its declarations")]
    metadata: ImportedServiceMetadata,
}

impl CommandImportProvider {
    fn action(&self, action: &str) -> Result<&CompiledAction, ProviderError> {
        self.actions.get(action).ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "unknown command import action")
        })
    }
}

/// A call that ends before any process starts: nothing was applied.
fn not_dispatched(read_only: bool) -> ProviderError {
    let error = ProviderError::error(
        ReasonCode::OperationFailed,
        "command imports cannot run commands in this broker yet",
    );
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
        Err(not_dispatched(self.action(request.action())?.read_only))
    }
}

#[async_trait]
impl CommandProvider for CommandImportProvider {
    async fn invoke_command(
        &self,
        invocation: CommandInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let action = self.action(invocation.action())?;
        Err(not_dispatched(action.read_only && invocation.read_only()))
    }

    async fn verify_command(
        &self,
        _verification: CommandVerification,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        Err(not_dispatched(true))
    }
}

#[cfg(test)]
mod tests;
