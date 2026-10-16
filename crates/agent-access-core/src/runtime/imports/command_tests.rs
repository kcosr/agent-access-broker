//! Command import descriptors and credential availability.
use super::*;
use crate::ImportedActionRecord;
use crate::imports::{
    ImportedCredentialBinding, ImportedCredentialDeclaration, ImportedCredentialDelivery,
    ImportedCredentialMode, ImportedDiscoveryCredential, ImportedServiceMetadata,
};

fn command_record(
    modes: &[ImportedCredentialMode],
    kind: Option<ImportedCredentialKind>,
) -> ImportedServiceRecord {
    ImportedServiceRecord {
        definition: ImportedServiceDefinition {
            service: "ticketing".into(),
            display_name: "Ticketing".into(),
            adapter_kind: "command".into(),
            endpoint: "command:ticketing".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: modes
                .iter()
                .map(|mode| {
                    ImportedCredentialBinding::token(*mode, ImportedCredentialDelivery::Stdin)
                })
                .collect(),
            discovery: ImportedDiscoveryCredential::Anonymous,
            transport_auth: false,
            invocation_limit: None,
        },
        status: ImportedServiceStatus::Enabled,
        version: 1,
        actions: vec![ImportedActionRecord {
            definition: ImportedActionDefinition {
                action: "issue.view".into(),
                source: json!({"name":"issue.view"}),
                label: None,
                description: "Show one issue.".into(),
                input_schema: json!({"type":"object"}),
                output_schema: None,
                annotations: json!({"command":{}}),
                read_only: true,
            },
            status: ImportedActionStatus::Enabled,
            version: 1,
            definition_hash: String::new(),
        }],
        slot_versions: BTreeMap::new(),
        accepted_metadata: Some(ImportedServiceMetadata {
            format: "agent-access-command/1".into(),
            version: "1.0.0".into(),
            credential: kind.map(|kind| ImportedCredentialDeclaration {
                kind,
                modes: modes.to_vec(),
            }),
            verify: false,
            resource_types: Vec::new(),
        }),
        created_at: String::new(),
        created_by: String::new(),
        updated_at: String::new(),
        updated_by: String::new(),
    }
}

/// A descriptor-only double of the command adapter.
#[derive(Debug)]
struct CommandForm;
static COMMAND_FORM: CommandForm = CommandForm;

#[async_trait::async_trait]
impl crate::imports::ImportedAdapter for CommandForm {
    fn kind(&self) -> &'static str {
        "command"
    }
    fn development_only(&self) -> bool {
        false
    }
    fn endpoint_form(&self) -> ImportEndpointForm {
        ImportEndpointForm::Command
    }
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamCommand"]
    }
    fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
        Ok(())
    }
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        Ok(action.action.replace('.', "_"))
    }
    fn build(
        &self,
        _: &ImportedServiceDefinition,
        _: &[ImportedActionDefinition],
        _: Option<ExecutionCredential>,
        _: &ImportedAdapterContext<'_>,
        _: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        unreachable!("descriptor tests never build providers")
    }
    async fn discover(
        &self,
        _: &ImportedServiceDefinition,
        _: &crate::imports::ImportedDiscoveryAuthentication,
        _: Option<ExecutionCredential>,
        _: &ImportedAdapterContext<'_>,
        _: &BuildContext<'_>,
    ) -> Result<crate::imports::ImportedDiscovery, crate::imports::AdapterDiscoveryError> {
        unreachable!("descriptor tests never discover")
    }
}

fn config() -> BrokerConfig {
    let mut config = crate::runtime::tests::base_fake_config();
    config.providers = crate::ProvidersConfig::new(Arc::new(
        crate::BackendRegistry::empty()
            .with_imported_adapters([crate::imports::imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                &COMMAND_FORM,
                None,
            )])
            .unwrap(),
    ));
    config
}

fn catalog(record: ImportedServiceRecord) -> ImportedCatalog {
    ImportedCatalog {
        revision: 1,
        services: vec![record],
    }
}

#[test]
fn credential_free_command_imports_use_service_mode_without_a_slot() {
    let config = config();
    let record = command_record(&[], None);
    assert!(credential_free(&record.definition));
    let descriptor = descriptor(&record, &config);
    descriptor.validate().unwrap();
    assert_eq!(
        descriptor.actions[0].sensitive_output_pointers,
        ["/result/upstreamCommand"]
    );
    assert!(!descriptor.credentials.execution_required);
    assert!(descriptor.credentials.profiles.is_empty());
    assert_eq!(descriptor.actions[0].credential_modes, ["service"]);
    let catalog = catalog(record);
    let mut effective = config.clone();
    effective_credentials(&mut effective, &catalog);
    assert_eq!(
        effective.credentials.imported_modes["ticketing"],
        ["service"]
    );
    assert!(!effective.credentials.per_user.contains_key("ticketing"));
    assert!(crate::credential_mode_available(
        &effective.credentials,
        "ticketing",
        "service",
        Some(&descriptor.credentials)
    ));
    assert!(!crate::credential_mode_available(
        &effective.credentials,
        "ticketing",
        "per_user",
        Some(&descriptor.credentials)
    ));
    let retained = retention_config(&config, &catalog);
    assert_eq!(
        retained.credentials.imported_modes["ticketing"],
        ["service"]
    );
}

#[test]
fn credentialed_command_imports_need_their_slot_and_declare_their_profile() {
    let config = config();
    let modes = [
        ImportedCredentialMode::Service,
        ImportedCredentialMode::PerUser,
    ];
    for (kind, profile, credential_kind) in [
        (ImportedCredentialKind::Token, "token", "bearer_token"),
        (
            ImportedCredentialKind::UsernameToken,
            "username-token",
            "basic_api_token",
        ),
    ] {
        let mut record = command_record(&modes, Some(kind));
        assert!(!credential_free(&record.definition));
        let descriptor = descriptor(&record, &config);
        descriptor.validate().unwrap();
        assert!(descriptor.credentials.execution_required);
        assert_eq!(descriptor.credentials.profiles.len(), 1);
        assert_eq!(descriptor.credentials.profiles[0].name, profile);
        assert_eq!(descriptor.credentials.profiles[0].kind, credential_kind);
        assert_eq!(
            descriptor.actions[0].credential_modes,
            ["service", "per_user"]
        );
        let mut effective = config.clone();
        effective_credentials(&mut effective, &catalog(record.clone()));
        // The service slot is not provisioned yet; personal mode is.
        assert_eq!(
            effective.credentials.imported_modes["ticketing"],
            ["per_user"]
        );
        assert_eq!(
            effective.credentials.per_user["ticketing"]
                .profile
                .as_deref(),
            Some(profile)
        );
        record
            .slot_versions
            .insert(ImportedCredentialPurpose::Execution, "slot-version".into());
        let mut effective = config.clone();
        effective_credentials(&mut effective, &catalog(record));
        assert_eq!(
            effective.credentials.imported_modes["ticketing"],
            ["service", "per_user"]
        );
    }
}
