fn gateway_definition() -> ImportedServiceDefinition {
    let mut definition = definition();
    definition.adapter_kind = "gateway_fixture".into();
    definition.discovery = crate::imports::ImportedDiscoveryCredential::Anonymous;
    definition.execution_bindings.clear();
    definition
}

fn gateway_pending(catalog: &ImportedCatalog) -> ImportedPreviewWriteRequest {
    ImportedPreviewWriteRequest {
        gateway_routes: None,
        service: "observability".into(),
        expected_version: catalog.services[0].version,
        expected_catalog_revision: catalog.revision,
        config_revision: "config-one".into(),
        credential_versions: BTreeMap::new(),
        manifest: json!({"tools":[]}),
        quarantine_actions: Vec::new(),
        actor: "admin".into(),
    }
}

fn gateway_route_candidate(path: &str) -> crate::imports::ImportedGatewayRouteCandidate {
    crate::imports::ImportedGatewayRouteCandidate::new(
        json!({"version":1,"paths":{path:{"methods":{}}}}),
    )
    .unwrap()
}

#[test]
fn gateway_routes_are_durable_beyond_previews_and_private_to_runtime() {
    let (_temp, config, store, _) = fixture();
    let initial = gateway_route_candidate("/reserved-initial");
    let created = store
        .create_imported_service_with_routes(
            gateway_definition(),
            Some(initial.clone()),
            "admin",
            accept,
        )
        .unwrap()
        .catalog;
    let routes = created.services[0].gateway_routes.as_ref().unwrap();
    assert_eq!(routes.generation, 1);
    assert_eq!(routes.content_hash, initial.content_hash().unwrap());
    assert!(
        !serde_json::to_string(&created)
            .unwrap()
            .contains("reserved-initial")
    );
    assert!(!format!("{created:?}").contains("reserved-initial"));
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/reserved-refresh"));
    let saved = store
        .write_imported_preview(refresh, accept)
        .unwrap()
        .catalog;
    assert_eq!(
        saved.services[0]
            .gateway_routes
            .as_ref()
            .unwrap()
            .generation,
        2
    );
    store
        .connection
        .lock()
        .unwrap()
        .execute("DELETE FROM imported_previews", [])
        .unwrap();
    assert!(store.imported_preview("observability").unwrap().is_none());
    drop(store);
    let reopened = ManagedStore::open(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), saved);
    assert!(
        reopened
            .imported_preview("observability")
            .unwrap()
            .is_none()
    );
}

#[test]
fn gateway_routes_failed_publication_preserves_prior_generation_and_preview() {
    let (_temp, _config, store, _) = fixture();
    let created = store
        .create_imported_service_with_routes(
            gateway_definition(),
            Some(gateway_route_candidate("/old")),
            "admin",
            accept,
        )
        .unwrap()
        .catalog;
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/new"));
    assert!(store.write_imported_preview(refresh, reject).is_err());
    assert_eq!(store.imported_catalog().unwrap(), created);
    assert!(store.imported_preview("observability").unwrap().is_none());
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/new"));
    let saved = store
        .write_imported_preview(refresh, accept)
        .unwrap()
        .catalog;
    let mut stale = gateway_pending(&created);
    stale.gateway_routes = Some(gateway_route_candidate("/stale"));
    assert!(matches!(
        store.write_imported_preview(stale, accept),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert_eq!(store.imported_catalog().unwrap(), saved);
}

#[test]
fn gateway_routes_hash_corruption_is_rejected_and_unknown_envelope_is_retained_unavailable() {
    let (_temp, config, store, _) = fixture();
    let mut future = gateway_route_candidate("/future");
    future.version = 2;
    let created = store
        .create_imported_service_with_routes(gateway_definition(), Some(future), "admin", accept)
        .unwrap()
        .catalog;
    assert!(
        !created.services[0]
            .gateway_routes
            .as_ref()
            .unwrap()
            .manifest
            .is_supported()
    );
    drop(store);
    let reopened = ManagedStore::open(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), created);
    reopened
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE imported_gateway_routes SET content_hash=?1",
            ["0".repeat(64)],
        )
        .unwrap();
    assert!(matches!(
        reopened.imported_catalog(),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
    drop(reopened);
    assert!(matches!(
        ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        ),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
}

#[test]
fn gateway_route_first_release_envelope_and_hash_are_frozen() {
    const ENVELOPE: &str = r#"{"version":1,"data":{"paths":{"/items/admin":{"methods":{"DELETE":{"current":false,"source":{"operationId":"delete_admin"},"supported":true}}}},"version":1}}"#;
    const HASH: &str = "c88e988a7a637f69efe57a9039894ca1cffd9186431f0e9738033f97648ae64f";
    let candidate: crate::imports::ImportedGatewayRouteCandidate =
        serde_json::from_str(ENVELOPE).unwrap();
    assert_eq!(candidate.encoded().unwrap(), ENVELOPE.as_bytes());
    assert_eq!(candidate.content_hash().unwrap(), HASH);
    let (_temp, _config, store, _) = fixture();
    let saved = store
        .create_imported_service_with_routes(gateway_definition(), Some(candidate), "admin", accept)
        .unwrap()
        .catalog;
    assert_eq!(
        saved.services[0]
            .gateway_routes
            .as_ref()
            .unwrap()
            .content_hash,
        HASH
    );
}

#[test]
fn gateway_routes_migration_is_additive_requires_admission_and_supports_backup_restore() {
    let temp = tempfile::TempDir::new().unwrap();
    let config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    };
    let through_contexts = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| {
            migration.version == MANAGED_STORE_AGENT_TOKEN_ISSUANCE_CONTEXTS_VERSION
        })
        .unwrap();
    let store = ManagedStore::open_with_catalog(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..=through_contexts],
        },
    )
    .unwrap();
    let original = {
        let conn = store.connection.lock().unwrap();
        // A deterministic row in the actual pre-gateway schema. Current mutation
        // methods intentionally require the current schema and are not used here.
        conn.execute(
            "INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by) VALUES(?1,?2,'draft',1,'2026-01-01T00:00:00Z','admin','2026-01-01T00:00:00Z','admin')",
            params!["observability", serde_json::to_string(&definition()).unwrap()],
        )
        .unwrap();
        conn.execute(
            "UPDATE imported_catalog_revision SET revision=1 WHERE singleton=1",
            [],
        )
        .unwrap();
        assert!(
            !sqlite_support::sqlite_object_exists(&conn, "table", "imported_gateway_routes")
                .unwrap()
        );
        let original = catalog_at(&conn, ImportSchema::SourceDocuments).unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        original
    };
    drop(store);
    let backup = fs::read(&config.path).unwrap();
    let mut read_only = config.clone();
    read_only.auto_migrate = false;
    assert!(matches!(
        ManagedStore::open(
            &read_only,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup
        ),
        Err(ManagedStoreError::MigrationRequired)
    ));
    let migrated = ManagedStore::open(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert_eq!(migrated.imported_catalog().unwrap(), original);
    migrated
        .create_imported_service_with_routes(
            {
                let mut value = definition();
                value.service = "gateway".into();
                value
            },
            Some(gateway_route_candidate("/reserved")),
            "admin",
            accept,
        )
        .unwrap();
    drop(migrated);
    // Restore the matching source snapshot at a fresh path, independently of
    // the upgraded database and its retained service reservations.
    let restored_path = std::path::Path::new(&config.path).with_file_name("restored.sqlite");
    fs::write(&restored_path, backup).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&restored_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut restored_config = config.clone();
    restored_config.path = restored_path.display().to_string();
    let restored = ManagedStore::open(
        &restored_config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert_eq!(restored.imported_catalog().unwrap(), original);
}
