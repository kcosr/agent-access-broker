//! Command imports: operator-approved local executables imported as Broker
//! services through the `command` import kind.
//!
//! This is the adapter's selection skeleton. Every adapter operation fails
//! closed, so selecting it grants nothing until the command contract is
//! implemented.
use agent_access_core::imports::{
    AdapterDiscoveryError, ImportEndpointForm, ImportedActionDefinition, ImportedAdapter,
    ImportedAdapterRegistration, ImportedDiscovery, ImportedDiscoveryAuthentication,
    ImportedServiceDefinition, imported_adapter_registration,
};
use agent_access_provider::{BuildContext, ExecutionCredential, Provider, ProviderBuildError};
use async_trait::async_trait;
use std::sync::Arc;

/// The import kind this adapter serves, `adapterKind` in imported definitions.
const KIND: &str = "command";
const UNAVAILABLE: &str = "command imports are not available in this broker";

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
    fn validate_definition(&self, _definition: &ImportedServiceDefinition) -> Result<(), String> {
        Err(UNAVAILABLE.into())
    }
    fn validate_action(&self, _action: &ImportedActionDefinition) -> Result<(), String> {
        Err(UNAVAILABLE.into())
    }
    fn scoped_mcp_name(&self, _action: &ImportedActionDefinition) -> Result<String, String> {
        Err(UNAVAILABLE.into())
    }
    fn build(
        &self,
        _definition: &ImportedServiceDefinition,
        _actions: &[ImportedActionDefinition],
        _transport_credential: Option<ExecutionCredential>,
        _host: &BuildContext<'_>,
    ) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Err(ProviderBuildError::invalid(UNAVAILABLE))
    }
    async fn discover(
        &self,
        _definition: &ImportedServiceDefinition,
        _authentication: &ImportedDiscoveryAuthentication,
        _transport_credential: Option<ExecutionCredential>,
        _host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
        Err(AdapterDiscoveryError::Configuration(UNAVAILABLE.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skeleton_selection_fails_closed() {
        let registration = registration();
        assert_eq!(registration.kind(), "command");
        assert_eq!(
            registration.module().crate_name(),
            "agent-access-command-import"
        );
        let adapter = CommandAdapter;
        assert!(!adapter.development_only());
        let action = ImportedActionDefinition {
            action: "issue.view".into(),
            source: Default::default(),
            label: None,
            description: String::new(),
            input_schema: Default::default(),
            output_schema: None,
            annotations: Default::default(),
            read_only: true,
        };
        assert!(adapter.validate_action(&action).is_err());
        assert!(adapter.scoped_mcp_name(&action).is_err());
    }
}
