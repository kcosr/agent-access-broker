//! Source TOML wait policy survives stored import loading and publication.
use super::*;
use crate::imports::{
    ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
    ImportedDiscoveryCredential, ImportedInvocationLimit,
};
use crate::{InvocationLimitConfig, ManagedStoreConfig, PrincipalRole, PrincipalWriteRequest};

struct Fixture {
    _directory: tempfile::TempDir,
    config: BrokerConfig,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::runtime::tests::base_fake_config();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory
            .path()
            .join("store")
            .join("store.sqlite")
            .display()
            .to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    let store = initial.managed_store().unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            principal_id: "admin".into(),
            kind: "user".into(),
            role: PrincipalRole::Admin,
            self_service_enabled: None,
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "fixture".into(),
        })
        .unwrap();
    // Retained imports load even when their adapter and operator gate are no
    // longer available. No provider build or upstream connection is needed.
    for service in ["records", "other_import"] {
        store
            .create_imported_service(
                ImportedServiceDefinition {
                    service: service.into(),
                    display_name: service.into(),
                    adapter_kind: "fixture_import".into(),
                    endpoint: "https://tools.example.test/mcp".into(),
                    connection_settings: BTreeMap::new(),
                    execution_bindings: vec![ImportedCredentialBinding::token(
                        ImportedCredentialMode::Service,
                        ImportedCredentialDelivery::Bearer,
                    )],
                    discovery: ImportedDiscoveryCredential::Anonymous,
                    transport_auth: false,
                    invocation_limit: Some(ImportedInvocationLimit {
                        requests: 2,
                        window_seconds: 10,
                    }),
                },
                "admin",
                |_| Ok(()),
            )
            .unwrap();
    }
    drop(initial);
    config.limits.invocations.default = Some(InvocationLimitConfig {
        requests: 100,
        window: "1m".into(),
        max_wait: Some("11s".into()),
    });
    config.limits.invocations.services.insert(
        "records".into(),
        InvocationLimitConfig {
            requests: 9,
            window: "30s".into(),
            max_wait: Some("7s".into()),
        },
    );
    Fixture {
        _directory: directory,
        config,
    }
}

fn assert_limits(runtime: &BrokerRuntime, service: &str, requests: u32, window: u32, wait: u64) {
    let configured = runtime.configured_invocation_limits();
    let limit = configured.service_limit(service);
    assert_eq!(limit.requests(), requests);
    assert_eq!(limit.window_seconds(), window);
    assert_eq!(configured.max_wait(service), Duration::from_secs(wait));
}

fn update(
    runtime: &BrokerRuntime,
    service: &str,
    change: impl FnOnce(&mut ImportedServiceRecord),
) -> BrokerRuntime {
    let mut record = runtime.imported_catalog().service(service).unwrap().clone();
    change(&mut record);
    let prepared = runtime
        .prepare_imported_service_change(&record, None)
        .unwrap();
    runtime
        .managed_store()
        .unwrap()
        .update_imported_service(
            crate::ImportedServiceUpdateRequest {
                discovery_source: crate::imports::ImportedDiscoverySource::Remote,
                definition: record.definition,
                status: record.status,
                actions: vec![],
                expected_version: record.version,
                expected_catalog_revision: runtime.import_catalog_revision(),
                accepted_preview: None,
                actor: "admin".into(),
            },
            |catalog| runtime.with_imported_catalog(catalog.clone(), prepared),
        )
        .unwrap()
        .value
}

fn failure(result: Result<BrokerRuntime, RuntimeError>) -> String {
    match result {
        Ok(_) => panic!("unknown service unexpectedly published"),
        Err(RuntimeError::Config(error)) => config_errors(error),
        Err(error) => panic!("unexpected startup failure: {error:?}"),
    }
}

fn config_errors(error: ConfigError) -> String {
    match error {
        ConfigError::Invalid { errors } => errors.join("; "),
        error => panic!("unexpected configuration failure: {error:?}"),
    }
}

#[tokio::test]
async fn imported_limits_startup_and_reload_resolve_toml_wait_and_stored_rate_independently() {
    let fixture = fixture();
    crate::validate_broker_config(&fixture.config).unwrap();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert_limits(&runtime, "records", 2, 10, 7);
    assert_limits(&runtime, "other_import", 2, 10, 11);
    assert_eq!(
        runtime.config().limits.invocations.services["records"].requests,
        9
    );
    runtime
        .managed_store()
        .unwrap()
        .upsert_principal_service_limit(crate::PrincipalServiceLimitWriteRequest {
            principal_id: "admin".into(),
            service: "records".into(),
            limit: crate::InvocationLimit::new(3, 15).unwrap(),
            actor: "admin".into(),
        })
        .unwrap();
    let personal = runtime
        .effective_invocation_limit("admin", "records")
        .await
        .unwrap();
    assert_eq!((personal.requests, personal.window_seconds), (3, 15));
    assert!(personal.overridden);
    let other = runtime
        .effective_invocation_limit("admin", "other_import")
        .await
        .unwrap();
    assert_eq!((other.requests, other.window_seconds), (2, 10));
    assert!(!other.overridden);
    assert_limits(&runtime, "records", 2, 10, 7);
    assert_limits(&runtime, "other_import", 2, 10, 11);

    let mut config = fixture.config.clone();
    config
        .limits
        .invocations
        .services
        .get_mut("records")
        .unwrap()
        .max_wait = None;
    let reloaded = BrokerRuntime::new_for_reload(config.clone(), &runtime).unwrap();
    assert_limits(&reloaded, "records", 2, 10, 11);

    // Catalog loading follows managed_store, not imports.enabled or either
    // authority. Retained limits still work after an operator disables imports
    // and changes identity/policy back to TOML.
    config.identity.authority = "toml".into();
    config.policy.authority = "toml".into();
    let restarted = BrokerRuntime::new(config).unwrap();
    assert_limits(&restarted, "records", 2, 10, 11);
}

#[test]
fn imported_limit_publications_preserve_wait_and_restore_source_rate_fallback() {
    let fixture = fixture();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let runtime = update(&runtime, "other_import", |record| {
        record.definition.display_name = "Other records".into();
    });
    assert_limits(&runtime, "records", 2, 10, 7);
    let runtime = update(&runtime, "records", |record| {
        record.definition.invocation_limit = Some(ImportedInvocationLimit {
            requests: 4,
            window_seconds: 20,
        });
    });
    assert_limits(&runtime, "records", 4, 20, 7);
    let runtime = update(&runtime, "records", |record| {
        record.definition.invocation_limit = None;
    });
    assert_limits(&runtime, "records", 9, 30, 7);
    let mut runtime = update(&runtime, "other_import", |record| {
        record.definition.invocation_limit = None;
    });
    assert_limits(&runtime, "other_import", 100, 60, 11);

    for status in [
        ImportedServiceStatus::Disabled,
        ImportedServiceStatus::Retired,
    ] {
        runtime = update(&runtime, "records", |record| record.status = status);
        assert_limits(&runtime, "records", 9, 30, 7);
        let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
        assert_eq!(
            restarted
                .imported_catalog()
                .service("records")
                .unwrap()
                .status,
            status
        );
        assert_limits(&restarted, "records", 9, 30, 7);
    }
}

#[test]
fn imported_limit_unknown_names_fail_startup_and_reload_after_catalog_loading() {
    let fixture = fixture();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let mut config = fixture.config.clone();
    let limit = config
        .limits
        .invocations
        .services
        .remove("records")
        .unwrap();
    config
        .limits
        .invocations
        .services
        .insert("reocrds".into(), limit);
    crate::validate_broker_config(&config).unwrap();
    for error in [
        failure(BrokerRuntime::new(config.clone())),
        failure(BrokerRuntime::new_for_reload(config, &runtime)),
    ] {
        assert!(
            error
                .contains("limits.invocations.services.reocrds references unknown service reocrds"),
            "{error}"
        );
    }
    assert_limits(&runtime, "records", 2, 10, 7);
}

#[test]
fn imported_limit_offline_deferral_keeps_name_syntax_and_limit_validation() {
    let fixture = fixture();
    for service in ["records/invalid", "missing"] {
        let mut config = fixture.config.clone();
        config.limits.invocations.services.insert(
            service.into(),
            InvocationLimitConfig {
                requests: 0,
                window: "1m".into(),
                max_wait: Some("-1s".into()),
            },
        );
        let error = config_errors(crate::validate_broker_config(&config).unwrap_err());
        assert!(
            error.contains("requests must be an integer from 1"),
            "{error}"
        );
        assert!(error.contains("max_wait must be"), "{error}");
        if service.contains('/') {
            assert!(
                error.contains("references unknown service records/invalid"),
                "{error}"
            );
        }
    }
    let mut config = crate::runtime::tests::base_fake_config();
    config.limits.invocations.services = fixture.config.limits.invocations.services;
    let error = config_errors(crate::validate_broker_config(&config).unwrap_err());
    assert!(
        error.contains("references unknown service records"),
        "{error}"
    );
}
