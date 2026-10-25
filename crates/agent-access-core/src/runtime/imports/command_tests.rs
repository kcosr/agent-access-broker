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

/// A command adapter double that deliberately does not validate action inputs.
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
        Ok(ImportedProvider::Command(Arc::new(CommandFixture)))
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

struct CommandFixture;

#[async_trait::async_trait]
impl Provider for CommandFixture {
    async fn resolve_scopes(
        &self,
        _: agent_access_provider::ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::resources(BTreeMap::new()))
    }
    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        unreachable!("command invocation uses its dedicated hook")
    }
}

#[async_trait::async_trait]
impl crate::imports::CommandProvider for CommandFixture {
    async fn invoke_command(
        &self,
        _: crate::imports::CommandInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({"dispatched":true})))
    }
    async fn verify_command(
        &self,
        _: crate::imports::CommandVerification,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        unreachable!("audit contract tests do not verify credentials")
    }
}

fn config() -> BrokerConfig {
    config_with_adapter(&COMMAND_FORM)
}

fn config_with_adapter(adapter: &'static CommandForm) -> BrokerConfig {
    let mut config = crate::runtime::tests::base_fake_config();
    config.providers = crate::ProvidersConfig::new(Arc::new(
        crate::BackendRegistry::new([&agent_access_fake::FAKE_BACKEND])
            .unwrap()
            .with_imported_adapters([crate::imports::imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                adapter,
                None,
            )])
            .unwrap(),
    ))
    .with(agent_access_fake::FakeProviderConfig::default());
    config.policy.resources.retain(|resource| {
        resource.resource_type == *agent_access_fake::FAKE_PROJECT_RESOURCE.id()
    });
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

fn audited_action(name: &str, valid: bool, status: ImportedActionStatus) -> ImportedActionRecord {
    let mut action = command_record(&[], None).actions.remove(0);
    action.definition.action = name.into();
    action.definition.source = json!({"name":name});
    action.definition.input_schema =
        json!({"type":"object", "properties":{"issue":{"type":"string"}}});
    action.definition.annotations["fixtureAudit"] = if valid {
        audit_declaration()
    } else {
        json!("reject")
    };
    action.status = status;
    action
}

fn change_request(
    catalog: &ImportedCatalog,
    record: &ImportedServiceRecord,
) -> crate::ImportedServiceUpdateRequest {
    crate::ImportedServiceUpdateRequest {
        discovery_source: crate::imports::ImportedDiscoverySource::Remote,
        definition: record.definition.clone(),
        status: record.status,
        actions: record
            .actions
            .iter()
            .map(|action| crate::ImportedActionWrite {
                definition: action.definition.clone(),
                status: action.status,
            })
            .collect(),
        expected_version: record.version,
        expected_catalog_revision: catalog.revision,
        accepted_preview: None,
        actor: "admin".into(),
    }
}

/// Seed accepted records independently of this binary's runtime compiler, as a
/// prior version can leave definitions that the current audit hook rejects.
fn stored_command(record: ImportedServiceRecord) -> (tempfile::TempDir, BrokerConfig) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.management.enabled = true;
    config.managed_store = Some(crate::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory
            .path()
            .join("store/store.sqlite")
            .display()
            .to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
    config.imports.enabled = true;
    config.imports.allowed_kinds = vec!["command".into()];
    config.command_imports.insert(
        "ticketing".into(),
        crate::CommandImportConfig {
            path: "/usr/bin/true".into(),
            timeout: "10s".into(),
            max_output_bytes: 1024,
            max_download_bytes: None,
            max_concurrent: 1,
            working_dir: "/".into(),
            network: Default::default(),
            log_stderr: false,
            env: BTreeMap::new(),
        },
    );
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    let store = initial.managed_store().unwrap();
    store
        .create_principal(crate::PrincipalWriteRequest {
            principal_id: "admin".into(),
            kind: "user".into(),
            role: crate::PrincipalRole::Admin,
            self_service_enabled: None,
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "fixture".into(),
        })
        .unwrap();
    let mut draft_definition = record.definition.clone();
    draft_definition.discovery = ImportedDiscoveryCredential::Anonymous;
    let draft = store
        .create_imported_service(draft_definition, "admin", |_| Ok(()))
        .unwrap()
        .catalog;
    let observed = store
        .write_imported_preview(
            crate::ImportedPreviewWriteRequest {
                service: "ticketing".into(),
                expected_version: draft.services[0].version,
                expected_catalog_revision: draft.revision,
                config_revision: "fixture".into(),
                credential_versions: BTreeMap::new(),
                manifest: json!({"tools":[]}),
                quarantine_actions: vec![],
                actor: "admin".into(),
            },
            |_| Ok(()),
        )
        .unwrap()
        .catalog;
    let preview = store.imported_preview("ticketing").unwrap().unwrap();
    let mut accepted = record;
    accepted.version = observed.services[0].version;
    let mut request = change_request(&observed, &accepted);
    request.accepted_preview = Some(crate::ImportedPreviewAcceptance {
        manifest_hash: preview.manifest_hash,
        config_revision: preview.config_revision,
        credential_versions: preview.credential_versions,
        accepted_metadata: accepted.accepted_metadata,
    });
    store.update_imported_service(request, |_| Ok(())).unwrap();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    runtime
        .create_managed_resource(crate::CreateResourceRequest {
            id: Some("fake-project-TEST".into()),
            display_name: None,
            resource_type: agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
            selector: crate::ResourceSelector::Exact {
                value: "TEST".into(),
            },
            allowed_execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    for (service, action, resources) in [
        ("fake", "echo", vec!["fake-project-TEST".into()]),
        ("ticketing", "issue.view", vec![]),
    ] {
        // These grants predate this binary's stricter audit contract too.
        store
            .create_policy_grant(
                crate::ManagedPolicyGrantCreateRequest {
                    grant_id: Some(format!("grant-{service}")),
                    subjects: vec!["user:admin".into()],
                    service: service.into(),
                    actions: vec![action.into()],
                    resources: ResourceSelection {
                        resource_ids: resources,
                        resource_group_ids: vec![],
                    },
                    execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.into()],
                    credential_mode: "service".into(),
                    priority: None,
                    status: None,
                    description: None,
                    created_by: "admin".into(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap();
    }
    (directory, config)
}

async fn invoke_fixture(
    runtime: &BrokerRuntime,
    service: &str,
    action: &str,
) -> BrokerResponse<Value> {
    let mut identity = IdentityContext::anonymous();
    identity.principal = "admin".into();
    identity.principal_subject = Some("admin".into());
    identity.principal_kind = Some(crate::PrincipalKind::User);
    identity.authenticated = true;
    let inputs = if service == "fake" {
        json!({"project":"TEST", "message":"fixture"})
    } else {
        json!({"issue":"OPS-1"})
    };
    runtime
        .invoke(
            GovernedOperationContext {
                admission: None,
                operation: OperationContext {
                    agent_request_id: "audit-gate-test".into(),
                    broker_request_id: "audit-gate-test-broker".into(),
                    identity,
                    service: service.into(),
                    action: action.into(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
            },
            InvokeRequest::new(inputs),
        )
        .await
}

async fn assert_invocable(runtime: &BrokerRuntime, service: &str, action: &str) {
    let response = invoke_fixture(runtime, service, action).await;
    assert_eq!(
        response.envelope.decision,
        Decision::Allow,
        "{:?}",
        response.envelope
    );
    assert!(response.envelope.error.is_none());
    assert!(response.envelope.result.is_some());
}

#[tokio::test]
async fn inactive_invalid_actions_do_not_block_enabled_actions_or_hide_valid_metadata() {
    for status in [
        ImportedActionStatus::Disabled,
        ImportedActionStatus::Quarantined,
        ImportedActionStatus::Retired,
    ] {
        let mut record = command_record(&[], None);
        record.actions = vec![
            audited_action("issue.view", true, ImportedActionStatus::Enabled),
            audited_action("issue.old", false, status),
            audited_action("issue.disabled", true, ImportedActionStatus::Disabled),
        ];
        let (_directory, config) = stored_command(record);
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        assert!(runtime.command_providers.contains_key("ticketing"));
        let descriptor = &runtime.services["ticketing"];
        assert!(
            descriptor
                .actions
                .iter()
                .find(|a| a.action == "issue.view")
                .unwrap()
                .audit_inputs
                .is_some()
        );
        assert!(
            descriptor
                .actions
                .iter()
                .find(|a| a.action == "issue.old")
                .unwrap()
                .audit_inputs
                .is_none()
        );
        assert!(
            descriptor
                .actions
                .iter()
                .find(|a| a.action == "issue.disabled")
                .unwrap()
                .audit_inputs
                .is_some()
        );
        assert_invocable(&runtime, "ticketing", "issue.view").await;
        let reloaded = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
        assert_invocable(&reloaded, "ticketing", "issue.view").await;
        let retained = reloaded.imported_catalog.service("ticketing").unwrap();
        let prepared = reloaded
            .prepare_imported_service_change(retained, None)
            .unwrap();
        assert!(prepared.providers.contains_key("ticketing"));
    }
}

#[tokio::test]
async fn invalid_enabled_contract_is_unavailable_at_startup_reload_and_managed_publication() {
    let mut record = command_record(&[], None);
    record.actions = vec![audited_action(
        "issue.view",
        false,
        ImportedActionStatus::Enabled,
    )];
    let (_directory, config) = stored_command(record);
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let before = runtime.imported_catalog.clone();
    assert!(!runtime.providers.contains_key("ticketing"));
    assert!(
        runtime
            .imported_service_unavailable_reason("ticketing")
            .is_some()
    );
    assert_eq!(
        runtime.services["ticketing"].actions[0].action,
        "issue.view"
    );
    assert_eq!(
        before.services[0].actions[0].definition.annotations["fixtureAudit"],
        "reject"
    );
    assert!(
        runtime
            .policy_snapshot()
            .grants
            .iter()
            .any(|grant| grant.service == "ticketing")
    );
    assert_eq!(
        invoke_fixture(&runtime, "ticketing", "issue.view")
            .await
            .envelope
            .reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_invocable(&runtime, "fake", "echo").await;
    let reloaded = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert!(!reloaded.providers.contains_key("ticketing"));
    assert_invocable(&reloaded, "fake", "echo").await;
    assert!(matches!(
        reloaded.prepare_imported_service_change(&before.services[0], None),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    // A preparation for a repaired action cannot publish the invalid definition.
    let mut repaired = before.services[0].clone();
    repaired.actions[0].definition.annotations["fixtureAudit"] = audit_declaration();
    let prepared = reloaded
        .prepare_imported_service_change(&repaired, None)
        .unwrap();
    let store = reloaded.managed_store().unwrap();
    let result = store
        .update_imported_service(change_request(&before, &before.services[0]), |catalog| {
            reloaded.with_imported_catalog(catalog.clone(), prepared)
        });
    assert!(matches!(result, Err(ManagedStoreError::InputInvalid(_))));
    assert_eq!(store.imported_catalog().unwrap(), *before);
    assert_eq!(*reloaded.imported_catalog, *before);
    assert_invocable(&reloaded, "fake", "echo").await;
}

#[tokio::test]
async fn invalid_retained_contract_can_be_disabled_or_retired_with_metadata_preserved() {
    for status in [
        ImportedServiceStatus::Disabled,
        ImportedServiceStatus::Retired,
    ] {
        let mut record = command_record(&[], None);
        record.actions = vec![
            audited_action("issue.view", false, ImportedActionStatus::Enabled),
            audited_action("issue.detail", true, ImportedActionStatus::Disabled),
        ];
        let (_directory, config) = stored_command(record);
        let runtime = BrokerRuntime::new(config).unwrap();
        let catalog = runtime.imported_catalog();
        let mut candidate = catalog.services[0].clone();
        candidate.status = status;
        let prepared = runtime
            .prepare_imported_service_change(&candidate, None)
            .unwrap();
        let next = runtime
            .managed_store()
            .unwrap()
            .update_imported_service(change_request(catalog, &candidate), |catalog| {
                runtime.with_imported_catalog(catalog.clone(), prepared)
            })
            .unwrap()
            .value;
        assert_eq!(next.imported_catalog.services[0].status, status);
        assert!(!next.providers.contains_key("ticketing"));
        assert!(
            next.services["ticketing"]
                .actions
                .iter()
                .find(|a| a.action == "issue.detail")
                .unwrap()
                .audit_inputs
                .is_some()
        );
        assert_invocable(&next, "fake", "echo").await;
        candidate.status = ImportedServiceStatus::Enabled;
        assert!(matches!(
            next.prepare_imported_service_change(&candidate, None),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
}

#[test]
fn operator_disabled_destination_does_not_validate_an_unexecutable_audit_contract() {
    let mut record = command_record(&[], None);
    record.actions = vec![audited_action(
        "issue.view",
        false,
        ImportedActionStatus::Enabled,
    )];
    let (_directory, mut config) = stored_command(record);
    config.imports.disabled_services.push("ticketing".into());
    let runtime = BrokerRuntime::new(config).unwrap();
    let prepared = runtime
        .prepare_imported_service_change(&runtime.imported_catalog.services[0], None)
        .unwrap();
    assert!(!prepared.providers.contains_key("ticketing"));
}

#[tokio::test]
async fn invalid_unavailable_contract_allows_only_pure_credential_removal() {
    let mut record = command_record(
        &[ImportedCredentialMode::Service],
        Some(ImportedCredentialKind::Token),
    );
    record.definition.discovery = ImportedDiscoveryCredential::Slot;
    record.actions = vec![audited_action(
        "issue.view",
        false,
        ImportedActionStatus::Enabled,
    )];
    let (_directory, config) = stored_command(record);
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    let store = initial.managed_store().unwrap();
    for purpose in [
        ImportedCredentialPurpose::Execution,
        ImportedCredentialPurpose::Discovery,
    ] {
        let catalog = store.imported_catalog().unwrap();
        store
            .write_imported_secret(
                crate::ImportedSecretWriteRequest {
                    service: "ticketing".into(),
                    purpose,
                    expected_version: catalog.services[0].version,
                    expected_catalog_revision: catalog.revision,
                    token: "fixture-credential".into(),
                    username: None,
                    actor: "admin".into(),
                },
                initial.credential_key_ring().unwrap(),
                &crate::PreparedImportedCredentialContract::for_test(
                    catalog,
                    "ticketing",
                    purpose,
                    false,
                )
                .unwrap(),
                |_, _| Ok(()),
            )
            .unwrap();
    }
    let mut runtime = BrokerRuntime::new_for_reload(config, &initial).unwrap();
    for purpose in [
        ImportedCredentialPurpose::Execution,
        ImportedCredentialPurpose::Discovery,
    ] {
        let before = runtime.imported_catalog.clone();
        let mut candidate = before.services[0].clone();
        candidate.slot_versions.remove(&purpose);
        // Even an identical retained definition cannot use this exception if
        // the admitted generation still has an executable provider for it.
        let mut available = runtime.clone();
        Arc::make_mut(&mut available.providers)
            .insert("ticketing".into(), Arc::new(CommandFixture));
        assert!(matches!(
            available.prepare_imported_service_change(&candidate, None),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut changed = candidate.clone();
        changed.actions[0]
            .definition
            .description
            .push_str(" changed");
        assert!(matches!(
            runtime.prepare_imported_service_change(&changed, None),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut changed = candidate.clone();
        changed.accepted_metadata.as_mut().unwrap().version = "2.0.0".into();
        assert!(matches!(
            runtime.prepare_imported_service_change(&changed, None),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut changed = candidate.clone();
        changed
            .slot_versions
            .insert(purpose, "replacement-version".into());
        assert!(matches!(
            runtime.prepare_imported_service_change(&changed, None),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let prepared = runtime
            .prepare_imported_service_change(&candidate, None)
            .unwrap();
        assert!(!prepared.providers.contains_key("ticketing"));
        runtime = runtime
            .managed_store()
            .unwrap()
            .delete_imported_secret(
                crate::ImportedSecretDeleteRequest {
                    service: "ticketing".into(),
                    purpose,
                    expected_version: before.services[0].version,
                    expected_catalog_revision: before.revision,
                    actor: "admin".into(),
                },
                |catalog| runtime.with_imported_catalog(catalog.clone(), prepared),
            )
            .unwrap()
            .value;
        assert!(!runtime.providers.contains_key("ticketing"));
        assert!(
            !runtime.imported_catalog.services[0]
                .slot_versions
                .contains_key(&purpose)
        );
        assert_eq!(
            runtime.imported_catalog.services[0].actions,
            before.services[0].actions
        );
        assert_invocable(&runtime, "fake", "echo").await;
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
