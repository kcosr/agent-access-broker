//! Command-import dispatch: the budget permit an admitted call waits for
//! before its final checks, the invocation its command hook receives, and the
//! `not_applied` receipt of a call whose process never started.
//!
//! An admitted call of a command import waits, until its command deadline,
//! for a permit from the budget of the approved command its endpoint names.
//! Only then do the final checks run (the import dispatch fence, resource
//! attribute bindings and credentials), so a call queued behind a quarantine,
//! a slot rotation or a reload that changed the command entry fails without
//! starting a process. The permit moves into the invocation and on to the
//! supervisor of the process the hook starts.
use super::*;
use crate::CommandImportConfig;
use crate::imports::{CommandAcquireError, CommandInvocation, CommandPermit};

/// An admitted command-import call holding its budget permit.
pub(super) struct CommandDispatch {
    pub(super) provider: Arc<dyn crate::imports::CommandProvider>,
    pub(super) permit: CommandPermit,
    /// The command deadline: the earlier of admission plus the command's
    /// `timeout` and the host operation deadline.
    pub(super) deadline: tokio::time::Instant,
}

fn imported_service_changed() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "imported service changed or is unavailable; repeat discovery",
    )
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

    /// The invocation the command hook receives, built after the permit and
    /// the final checks, from the admitted request, its context, the
    /// authority admission planned for it and the decrypted attributes of its
    /// resources. Its request carries the caller, the resolved authorization,
    /// the credentials it uses (a service slot
    /// at its admitted version, a personal credential as it is now) and, for
    /// `network = "inherit"`, the egress settings, which also become the
    /// invocation's network variables. It shares the call's process facts
    /// with finalization.
    ///
    /// This Broker does not assemble command requests, so every call fails
    /// closed here, before any process starts.
    pub(super) async fn command_invocation(
        &self,
        permit: CommandPermit,
        deadline: tokio::time::Instant,
        request: &AdmittedRequest,
        authorization: Option<CommandAuthorization>,
        resource_attributes: ResourceAttributes,
        context: &FinalizeContext,
    ) -> Result<CommandInvocation, ProviderError> {
        let _ = (
            permit,
            deadline,
            request,
            authorization,
            resource_attributes,
            context,
        );
        Err(ProviderError::error(
            ReasonCode::OperationFailed,
            "command import requests are not supported by this broker",
        ))
    }

    /// `error` of a command-import call whose process never started: a
    /// write-capable action reports that nothing was applied.
    pub(super) fn command_not_started(
        &self,
        service: &str,
        action: &str,
        error: ProviderError,
    ) -> ProviderError {
        if self
            .action_descriptor(service, action)
            .is_some_and(|descriptor| descriptor.read_only)
        {
            error
        } else {
            error.with_mutation_receipt(MutationReceipt::not_applied())
        }
    }
}
