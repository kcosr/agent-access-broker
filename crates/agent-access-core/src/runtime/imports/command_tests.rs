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
        document: None,
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
                download: false,
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
struct CommandForm(ImportEndpointForm);
static COMMAND_FORM: CommandForm = CommandForm(ImportEndpointForm::Command);
static HTTP_FORM: CommandForm = CommandForm(ImportEndpointForm::Http);

#[async_trait::async_trait]
impl crate::imports::ImportedAdapter for CommandForm {
    fn credential_contract(
        &self,
        definition: &crate::imports::ImportedServiceDefinition,
        import: &crate::imports::ImportedAdapterContext<'_>,
    ) -> Result<crate::imports::ImportedCredentialContract, String> {
        crate::imports::test_credential_contract(definition, import)
    }
    fn kind(&self) -> &'static str {
        "command"
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()
    }
    fn development_only(&self) -> bool {
        false
    }
    fn endpoint_form(&self) -> ImportEndpointForm {
        self.0
    }
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamCommand"]
    }
    fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
        Ok(())
    }
    fn action_audit_inputs(
        &self,
        action: &ImportedActionDefinition,
    ) -> Result<Option<agent_access_provider::AuditInputProjection>, String> {
        match action.annotations.get("fixtureAudit") {
            None => Ok(None),
            Some(Value::String(_)) => Err("fixture audit contract rejected".into()),
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|_| "fixture audit contract invalid".into()),
        }
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
    config_with_adapter(&COMMAND_FORM)
}

fn config_with_adapter(adapter: &'static CommandForm) -> BrokerConfig {
    let mut config = crate::runtime::tests::base_fake_config();
    config.providers = crate::ProvidersConfig::new(Arc::new(
        crate::BackendRegistry::empty()
            .with_imported_adapters([crate::imports::imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                adapter,
                None,
            )])
            .unwrap(),
    ));
    config
}

fn audit_declaration() -> Value {
    json!([{"key":"issue","pointer":"/issue","capture":"value","shape":"scalar","label":"Issue",
        "display":"primary","role":"target","kind":"identifier","maxBytes":1024,"overflow":"omit"}])
}

#[test]
fn audit_hook_is_independent_of_adapter_validate_action_and_is_never_silently_accepted() {
    let config = config();
    let mut record = command_record(&[], None);
    record.actions[0].definition.input_schema = json!({"properties":{"issue":{"type":"string"}}});
    record.actions[0].definition.annotations["fixtureAudit"] = audit_declaration();
    let resolved = resolve_audit_inputs(&config, &record).unwrap();
    assert_eq!(resolved.len(), 1);
    let published = descriptor(
        &record,
        &config,
        config.providers.registry().resource_types(),
    );
    assert!(published.actions[0].audit_inputs.is_some());
    // The adapter claims validate_action succeeded, but the separate hook fails.
    record.actions[0].definition.annotations["fixtureAudit"] = json!("reject");
    assert!(
        crate::imports::ImportedAdapter::validate_action(
            &COMMAND_FORM,
            &record.actions[0].definition
        )
        .is_ok()
    );
    assert!(resolve_audit_inputs(&config, &record).is_err());
    let retained = descriptor(
        &record,
        &config,
        config.providers.registry().resource_types(),
    );
    assert_eq!(retained.actions[0].action, "issue.view");
    assert!(retained.actions[0].audit_inputs.is_none());
    // Structurally valid declarations still cannot capture sensitive values.
    record.actions[0].definition.annotations["fixtureAudit"] = audit_declaration();
    record.actions[0].definition.input_schema["properties"]["issue"]["x-agent-access-sensitive"] =
        json!(true);
    assert!(resolve_audit_inputs(&config, &record).is_err());
}

#[test]
fn http_adapter_cannot_approve_audit_capture_even_with_command_shaped_metadata() {
    let config = config_with_adapter(&HTTP_FORM);
    let mut record = command_record(&[], None);
    record.definition.endpoint = "https://api.example.test/tools".into();
    record.actions[0].definition.input_schema = json!({"properties":{"issue":{"type":"string"}}});
    record.actions[0].definition.annotations["fixtureAudit"] = audit_declaration();
    assert!(resolve_audit_inputs(&config, &record).is_err());
    // A typed command adapter also cannot attach capture to an HTTP definition.
    assert!(resolve_audit_inputs(&config_with_adapter(&COMMAND_FORM), &record).is_err());
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
    let descriptor = descriptor(
        &record,
        &config,
        config.providers.registry().resource_types(),
    );
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
    // A credential-free import publishes no credential connection.
    assert!(!effective.credentials.connections.contains_key("ticketing"));
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
        let descriptor = descriptor(
            &record,
            &config,
            config.providers.registry().resource_types(),
        );
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
        // The personal binding publishes a single-consumer connection under
        // the import's ID with the declared profile and no OAuth.
        assert_eq!(
            effective.credentials.connections["ticketing"],
            crate::ConnectionConfig {
                display_name: Some("Ticketing".into()),
                token_profiles: Some(vec![profile.into()]),
                service_account_token_profiles: None,
                oauth: None,
            }
        );
        let connection = effective
            .credentials
            .personal_connection("ticketing")
            .unwrap();
        assert_eq!(connection.id, "ticketing");
        for principal_kind in [
            crate::PrincipalKind::User,
            crate::PrincipalKind::ServiceAccount,
            crate::PrincipalKind::System,
        ] {
            assert_eq!(
                connection.select(Some(principal_kind)),
                crate::Selection::Token(&[profile.to_string()])
            );
        }
        assert_eq!(connection.select(None), crate::Selection::Unavailable);
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

#[test]
fn only_a_supported_personal_binding_publishes_a_connection() {
    let config = config();
    // Service mode alone: no personal setup target or selection.
    let mut service_only = command_record(
        &[ImportedCredentialMode::Service],
        Some(ImportedCredentialKind::Token),
    );
    service_only
        .slot_versions
        .insert(ImportedCredentialPurpose::Execution, "slot-version".into());
    let mut effective = config.clone();
    effective_credentials(&mut effective, &catalog(service_only));
    assert_eq!(
        effective.credentials.imported_modes["ticketing"],
        ["service"]
    );
    assert!(effective.credentials.connections.is_empty());
    assert!(effective.credentials.per_user.is_empty());

    // Personal mode added after acceptance publishes the connection on the
    // next publication, from configuration alone.
    let personal = command_record(
        &[
            ImportedCredentialMode::Service,
            ImportedCredentialMode::PerUser,
        ],
        Some(ImportedCredentialKind::Token),
    );
    effective_credentials(&mut effective, &catalog(personal));
    assert!(effective.credentials.connections.contains_key("ticketing"));
    assert_eq!(
        effective
            .credentials
            .connection_consumers("ticketing")
            .collect::<Vec<_>>(),
        ["ticketing"]
    );
}

#[test]
fn managed_import_rate_preserves_service_wait_policy_and_default_inheritance() {
    for service_wait in [None, Some("7s")] {
        let mut config = config();
        config.limits.invocations.default = Some(crate::InvocationLimitConfig {
            requests: 100,
            window: "1m".into(),
            max_wait: Some("11s".into()),
        });
        config.limits.invocations.services.insert(
            "ticketing".into(),
            crate::InvocationLimitConfig {
                requests: 9,
                window: "30s".into(),
                max_wait: service_wait.map(str::to_string),
            },
        );
        let mut record = command_record(&[], None);
        record.definition.invocation_limit = Some(crate::imports::ImportedInvocationLimit {
            requests: 2,
            window_seconds: 10,
        });
        effective_credentials(&mut config, &catalog(record));
        let effective = crate::ConfiguredInvocationLimits::from_config(&config);
        assert_eq!(effective.service_limit("ticketing").requests(), 2);
        assert_eq!(effective.service_limit("ticketing").window_seconds(), 10);
        assert_eq!(
            effective.max_wait("ticketing"),
            Duration::from_secs(if service_wait.is_some() { 7 } else { 11 })
        );
    }
}
