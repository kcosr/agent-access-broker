fn gateway_pending(catalog: &ImportedCatalog) -> ImportedPreviewWriteRequest {
    ImportedPreviewWriteRequest {
        gateway_routes: None, service: "observability".into(),
        expected_version: catalog.services[0].version,
        expected_catalog_revision: catalog.revision,
        config_revision: "config-one".into(), credential_versions: BTreeMap::new(),
        manifest: json!({"tools":[]}), quarantine_actions: Vec::new(), actor: "admin".into(),
    }
}

fn gateway_route_candidate(path: &str) -> crate::imports::ImportedGatewayRouteCandidate {
    crate::imports::ImportedGatewayRouteCandidate::new(json!({"version":1,"paths":{path:{"methods":{}}}})).unwrap()
}

#[test]
fn gateway_routes_are_durable_beyond_previews_and_private_to_runtime() {
    let (_temp, config, store, _) = fixture();
    let initial = gateway_route_candidate("/reserved-initial");
    let created = store.create_imported_service_with_routes(definition(), Some(initial.clone()), "admin", accept).unwrap().catalog;
    let routes = created.services[0].gateway_routes.as_ref().unwrap();
    assert_eq!(routes.generation, 1);
    assert_eq!(routes.content_hash, initial.content_hash().unwrap());
    assert!(!serde_json::to_string(&created).unwrap().contains("reserved-initial"));
    assert!(!format!("{created:?}").contains("reserved-initial"));
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/reserved-refresh"));
    let saved = store.write_imported_preview(refresh, accept).unwrap().catalog;
    assert_eq!(saved.services[0].gateway_routes.as_ref().unwrap().generation, 2);
    store.connection.lock().unwrap().execute("DELETE FROM imported_previews", []).unwrap();
    assert!(store.imported_preview("observability").unwrap().is_none());
    drop(store);
    let reopened = ManagedStore::open(&config, &test_execution_contexts(), ManagedStoreOpenMode::Startup).unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), saved);
    assert!(reopened.imported_preview("observability").unwrap().is_none());
}

#[test]
fn gateway_routes_failed_publication_preserves_prior_generation_and_preview() {
    let (_temp, _config, store, _) = fixture();
    let created = store.create_imported_service_with_routes(definition(), Some(gateway_route_candidate("/old")), "admin", accept).unwrap().catalog;
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/new"));
    assert!(store.write_imported_preview(refresh, reject).is_err());
    assert_eq!(store.imported_catalog().unwrap(), created);
    assert!(store.imported_preview("observability").unwrap().is_none());
    let mut refresh = gateway_pending(&created);
    refresh.gateway_routes = Some(gateway_route_candidate("/new"));
    let saved = store.write_imported_preview(refresh, accept).unwrap().catalog;
    let mut stale = gateway_pending(&created);
    stale.gateway_routes = Some(gateway_route_candidate("/stale"));
    assert!(matches!(store.write_imported_preview(stale, accept), Err(ManagedStoreError::VersionConflict)));
    assert_eq!(store.imported_catalog().unwrap(), saved);
}

#[test]
fn gateway_routes_hash_corruption_is_rejected_and_unknown_envelope_is_retained_unavailable() {
    let (_temp, config, store, _) = fixture();
    let mut future = gateway_route_candidate("/future");
    future.version = 2;
    let created = store.create_imported_service_with_routes(definition(), Some(future), "admin", accept).unwrap().catalog;
    assert!(!created.services[0].gateway_routes.as_ref().unwrap().manifest.is_supported());
    drop(store);
    let reopened = ManagedStore::open(&config, &test_execution_contexts(), ManagedStoreOpenMode::Startup).unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), created);
    reopened.connection.lock().unwrap().execute("UPDATE imported_gateway_routes SET content_hash=?1", ["0".repeat(64)]).unwrap();
    assert!(matches!(reopened.imported_catalog(), Err(ManagedStoreError::SchemaInvalid(_))));
}
