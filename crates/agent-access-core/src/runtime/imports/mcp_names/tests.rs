use super::*;
use crate::{
    ImportedActionRecord, ImportedCredentialBinding, ImportedCredentialDelivery,
    ImportedCredentialMode, ImportedDiscoveryCredential,
};

fn record(service: &str, names: &[&str]) -> ImportedServiceRecord {
    ImportedServiceRecord {
        definition: ImportedServiceDefinition {
            service: service.into(),
            display_name: service.into(),
            adapter_kind: "mcp_http".into(),
            endpoint: "https://tools.example/mcp".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: vec![ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            )],
            discovery: ImportedDiscoveryCredential::Execution,
            transport_auth: false,
            invocation_limit: None,
        },
        status: ImportedServiceStatus::Enabled,
        version: 1,
        actions: names
            .iter()
            .map(|name| ImportedActionRecord {
                definition: ImportedActionDefinition {
                    action: (*name).into(),
                    source: json!({"toolName":name}),
                    label: None,
                    description: String::new(),
                    input_schema: json!({"type":"object"}),
                    output_schema: None,
                    annotations: json!({}),
                    read_only: false,
                },
                status: ImportedActionStatus::Enabled,
                version: 1,
                definition_hash: String::new(),
            })
            .collect(),
        slot_versions: BTreeMap::new(),
        created_at: String::new(),
        created_by: String::new(),
        updated_at: String::new(),
        updated_by: String::new(),
    }
}

fn runtime(catalog: ImportedCatalog) -> BrokerRuntime {
    let mut runtime = BrokerRuntime::new(crate::runtime::tests::base_fake_config()).unwrap();
    runtime.imported_catalog = Arc::new(catalog);
    runtime
}

fn catalog(services: Vec<ImportedServiceRecord>) -> ImportedCatalog {
    ImportedCatalog {
        revision: 1,
        services,
    }
}

#[test]
fn admission_includes_disabled_and_quarantined_but_releases_retired_names() {
    let mut previous = record("search", &["find-record"]);
    previous.status = ImportedServiceStatus::Disabled;
    previous.actions[0].status = ImportedActionStatus::Quarantined;
    let runtime = runtime(catalog(vec![previous.clone()]));
    let mut proposed = previous;
    proposed
        .actions
        .extend(record("search", &["find_record"]).actions);
    let mut candidate = catalog(vec![proposed]);
    let error = runtime
        .validate_import_mcp_names(&candidate)
        .unwrap_err()
        .to_string();
    assert!(error.contains("search/find-record"), "{error}");
    assert!(error.contains("search/find_record"), "{error}");
    assert!(error.contains("name_conflict"), "{error}");
    candidate.services[0].actions[0].status = ImportedActionStatus::Retired;
    runtime.validate_import_mcp_names(&candidate).unwrap();
}

#[test]
fn admission_checks_helpers_builtin_boundaries_and_exact_length() {
    let mut runtime = runtime(ImportedCatalog::default());
    let fake = Arc::make_mut(&mut runtime.services)
        .get_mut("fake")
        .unwrap();
    Arc::make_mut(fake).actions = vec![ActionDescriptor::new(
        "foo_bar",
        "",
        json!({"type":"object"}),
    )];
    let collision = catalog(vec![record("fake_foo", &["bar"])]);
    let error = runtime
        .validate_import_mcp_names(&collision)
        .unwrap_err()
        .to_string();
    assert!(error.contains("fake/foo_bar"), "{error}");
    assert!(error.contains("fake_foo/bar"), "{error}");
    let reserved = catalog(vec![record("services", &["list"])]);
    assert!(
        runtime
            .validate_import_mcp_names(&reserved)
            .unwrap_err()
            .to_string()
            .contains("reserved_name")
    );
    let accepted = "a".repeat(121); // search + underscore + action = 128 bytes.
    runtime
        .validate_import_mcp_names(&catalog(vec![record("search", &[&accepted])]))
        .unwrap();
    let rejected = "a".repeat(122);
    let error = runtime
        .validate_import_mcp_names(&catalog(vec![record("search", &[&rejected])]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("name_too_long"), "{error}");
}

#[test]
fn retained_issues_allow_maintenance_and_recovery_but_not_new_colliders() {
    let previous = record("search", &["find-record", "find_record"]);
    let runtime = runtime(catalog(vec![previous.clone()]));
    let mut candidate = catalog(vec![previous]);
    candidate.services[0].definition.display_name = "New label".into();
    candidate.services[0]
        .slot_versions
        .insert(ImportedCredentialPurpose::Execution, "replacement".into());
    runtime.validate_import_mcp_names(&candidate).unwrap();
    candidate.services[0]
        .actions
        .extend(record("search", &["find.record"]).actions);
    assert!(runtime.validate_import_mcp_names(&candidate).is_err());
    candidate.services[0].actions.pop();
    candidate.services[0].status = ImportedServiceStatus::Disabled;
    runtime.validate_import_mcp_names(&candidate).unwrap();
    candidate.services[0].status = ImportedServiceStatus::Retired;
    candidate.services.push(record("search_find", &["record"]));
    runtime.validate_import_mcp_names(&candidate).unwrap();
}

#[test]
fn legacy_incompatible_service_and_action_cannot_be_reactivated() {
    let mut previous = record("search", &["find-record", "find_record"]);
    previous.status = ImportedServiceStatus::Disabled;
    let disabled_runtime = runtime(catalog(vec![previous.clone()]));
    previous.status = ImportedServiceStatus::Enabled;
    let error = disabled_runtime
        .validate_import_mcp_names(&catalog(vec![previous.clone()]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("enable unavailable"), "{error}");
    previous.actions[0].status = ImportedActionStatus::Disabled;
    let enabled_runtime = runtime(catalog(vec![previous.clone()]));
    previous.actions[0].status = ImportedActionStatus::Enabled;
    assert!(
        enabled_runtime
            .validate_import_mcp_names(&catalog(vec![previous]))
            .is_err()
    );
}

#[test]
fn malformed_catalog_does_not_masquerade_as_budget_failure() {
    let mut runtime = runtime(catalog(vec![record("search", &[])]));
    let fake = Arc::make_mut(&mut runtime.services)
        .get_mut("fake")
        .unwrap();
    let fake = Arc::make_mut(fake);
    fake.actions.push(fake.actions[0].clone());
    let error = runtime
        .check_import_catalog_budgets()
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate action identities"), "{error}");
    assert!(!error.contains("exceed"), "{error}");
}
