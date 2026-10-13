use super::*;
use agent_access_core::{ImportedActionRecord, ImportedServiceRecord};

fn request(record: &ImportedServiceRecord, revision: u64) -> ImportedServiceUpdateRequest {
    ImportedServiceUpdateRequest {
        definition: record.definition.clone(),
        status: record.status,
        actions: record
            .actions
            .iter()
            .map(|action| ImportedActionWrite {
                definition: action.definition.clone(),
                status: action.status,
            })
            .collect(),
        expected_version: record.version,
        expected_catalog_revision: revision,
        accepted_preview: None,
        actor: "admin".into(),
    }
}

fn commit(
    runtime: &BrokerRuntime,
    record: ImportedServiceRecord,
) -> Result<BrokerRuntime, ManagedStoreError> {
    let prepared = runtime.prepare_imported_service_change(&record, None)?;
    runtime
        .managed_store()
        .unwrap()
        .update_imported_service(
            request(&record, runtime.import_catalog_revision()),
            |catalog| runtime.with_imported_catalog(catalog.clone(), prepared),
        )
        .map(|result| result.value)
}

fn create(runtime: &BrokerRuntime, service: &str) -> BrokerRuntime {
    let mut record = runtime.imported_catalog().services[0].clone();
    record.definition.service = service.into();
    record.status = ImportedServiceStatus::Draft;
    record.actions.clear();
    record.slot_versions.clear();
    let prepared = runtime
        .prepare_imported_service_change(&record, None)
        .unwrap();
    runtime
        .managed_store()
        .unwrap()
        .create_imported_service(record.definition, "admin", |catalog| {
            runtime.with_imported_catalog(catalog.clone(), prepared)
        })
        .unwrap()
        .value
}

fn accept(runtime: &BrokerRuntime, service: &str, name: &str) -> ImportedServiceRecord {
    let mut record = runtime.imported_catalog().service(service).unwrap().clone();
    record.status = ImportedServiceStatus::Enabled;
    record.actions.push(ImportedActionRecord {
        definition: agent_access_provider::ImportedActionDefinition {
            action: name.into(),
            ..conformance_import_action()
        },
        status: ImportedActionStatus::Enabled,
        version: 1,
        definition_hash: String::new(),
    });
    record
}

#[test]
fn aggregate_name_collision_rejects_acceptance_without_committing_catalog() {
    let fixture = fixture();
    let runtime = create(&fixture.runtime, "test-one");
    let runtime = commit(&runtime, accept(&runtime, "test-one", "inspect")).unwrap();
    let runtime = create(&runtime, "test_one");
    let before = runtime.managed_store().unwrap().imported_catalog().unwrap();
    let error = match commit(&runtime, accept(&runtime, "test_one", "inspect")) {
        Ok(_) => panic!("conflicting import must not be committed"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("test-one/inspect"), "{error}");
    assert!(error.contains("test_one/inspect"), "{error}");
    assert!(error.contains("name_conflict"), "{error}");
    assert_eq!(
        runtime.managed_store().unwrap().imported_catalog().unwrap(),
        before
    );
    assert_eq!(*runtime.imported_catalog(), before);
    // The rejected proposal remains editable and can be accepted with a useful name.
    let runtime = commit(&runtime, accept(&runtime, "test_one", "read")).unwrap();
    assert_eq!(
        runtime
            .imported_catalog()
            .service("test_one")
            .unwrap()
            .actions[0]
            .definition
            .action,
        "read"
    );
}

#[test]
fn aggregate_name_length_rejects_acceptance_without_committing_catalog() {
    let fixture = fixture();
    let runtime = create(&fixture.runtime, "new_import");
    let before = runtime.managed_store().unwrap().imported_catalog().unwrap();
    let error = match commit(&runtime, accept(&runtime, "new_import", &"a".repeat(128))) {
        Ok(_) => panic!("overlength import must not be committed"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("name_too_long"), "{error}");
    assert_eq!(
        runtime.managed_store().unwrap().imported_catalog().unwrap(),
        before
    );
}

#[test]
fn retained_overlength_import_survives_restart_and_supports_recovery() {
    let fixture = fixture();
    let runtime = create(&fixture.runtime, "legacy_import");
    let legacy = accept(&runtime, "legacy_import", &"a".repeat(128));
    // Seed an accepted identity from an earlier Broker version. Its canonical
    // identity and source mapping remain valid even though aggregate MCP omits it.
    runtime
        .managed_store()
        .unwrap()
        .update_imported_service(request(&legacy, runtime.import_catalog_revision()), |_| {
            Ok(())
        })
        .unwrap();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert!(runtime.imported_action_available("legacy_import", &"a".repeat(128)));
    let mut catalog = agent_access_core::empty_catalog(json!({}));
    catalog.services = runtime.api_services_all();
    let tools = agent_access_core::mcp::project_catalog(
        &catalog,
        agent_access_core::mcp::ProjectionMode::Stdio,
    )
    .unwrap();
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "observability_inspect")
    );
    assert!(!tools.iter().any(|tool| {
        tool["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("legacy_import_"))
    }));

    let mut record = runtime
        .imported_catalog()
        .service("legacy_import")
        .unwrap()
        .clone();
    record.definition.display_name = "Reviewed legacy import".into();
    let runtime = commit(&runtime, record).unwrap();
    let mut record = runtime
        .imported_catalog()
        .service("legacy_import")
        .unwrap()
        .clone();
    record.status = ImportedServiceStatus::Disabled;
    let runtime = commit(&runtime, record).unwrap();
    let before = runtime.managed_store().unwrap().imported_catalog().unwrap();
    let mut record = runtime
        .imported_catalog()
        .service("legacy_import")
        .unwrap()
        .clone();
    record.status = ImportedServiceStatus::Enabled;
    let error = match commit(&runtime, record) {
        Ok(_) => panic!("incompatible legacy import must not be reenabled"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("name_too_long"), "{error}");
    assert_eq!(
        runtime.managed_store().unwrap().imported_catalog().unwrap(),
        before
    );

    let mut record = runtime
        .imported_catalog()
        .service("legacy_import")
        .unwrap()
        .clone();
    record.actions[0].status = ImportedActionStatus::Retired;
    record.status = ImportedServiceStatus::Enabled;
    record.actions.push(ImportedActionRecord {
        definition: conformance_import_action(),
        status: ImportedActionStatus::Enabled,
        version: 1,
        definition_hash: String::new(),
    });
    let runtime = commit(&runtime, record).unwrap();
    assert!(runtime.imported_action_available("legacy_import", "inspect"));
    assert_eq!(
        runtime
            .imported_catalog()
            .service("legacy_import")
            .unwrap()
            .actions
            .len(),
        2
    );
}
