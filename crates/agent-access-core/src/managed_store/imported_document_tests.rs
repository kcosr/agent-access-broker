// Retained raw source shares the existing preview/version publication boundary.
fn upload_definition() -> ImportedServiceDefinition {
    let mut definition = definition();
    definition.adapter_kind = "openapi_http".into();
    definition.discovery = ImportedDiscoveryCredential::Anonymous;
    definition
        .connection_settings
        .insert("definitionSource".into(), "upload".into());
    definition
}

fn document_preview(catalog: &ImportedCatalog) -> ImportedPreviewWriteRequest {
    ImportedPreviewWriteRequest {
        service: "observability".into(),
        expected_version: catalog.services[0].version,
        expected_catalog_revision: catalog.revision,
        config_revision: "config-one".into(),
        credential_versions: BTreeMap::new(),
        manifest: json!({"tools":[]}),
        quarantine_actions: vec![],
        actor: "admin".into(),
    }
}

fn prepared_document(
    catalog: &ImportedCatalog,
    bytes: &[u8],
) -> crate::PreparedImportedDocumentUpload {
    crate::PreparedImportedDocumentUpload::for_test(
        catalog.clone(),
        "observability",
        Some("spec.json".into()),
        bytes.to_vec(),
    )
    .unwrap()
}

#[test]
fn uploaded_document_atomic_preview_and_exact_bytes_survive_restart() {
    let (_temp, config, store, _) = fixture();
    let draft = store
        .create_imported_service(upload_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let bytes = b"{ \"marker\": \"source-only-private-content\", \"paths\": {} }\n";
    let prepared = prepared_document(&draft, bytes);
    assert!(!format!("{prepared:?}").contains("source-only-private-content"));
    let saved = store
        .write_imported_document_preview(document_preview(&draft), &prepared, accept)
        .unwrap()
        .catalog;
    assert_eq!(saved.revision, draft.revision + 1);
    assert_eq!(saved.services[0].version, draft.services[0].version + 1);
    assert_eq!(
        saved.services[0].document.as_ref(),
        Some(prepared.metadata())
    );
    assert_eq!(prepared.metadata().byte_length, bytes.len() as u64);
    assert_eq!(prepared.metadata().sha256, sha256_hex(bytes));
    assert_eq!(store.imported_document(&saved.services[0]).unwrap(), bytes);
    assert!(
        !serde_json::to_string(&saved)
            .unwrap()
            .contains("source-only-private-content")
    );
    assert!(!format!("{saved:?}").contains("source-only-private-content"));
    let preview = store.imported_preview("observability").unwrap().unwrap();
    assert_eq!(preview.service_version, saved.services[0].version);
    assert_eq!(preview.catalog_revision, saved.revision);
    drop(store);
    let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), saved);
    assert_eq!(
        reopened.imported_document(&saved.services[0]).unwrap(),
        bytes
    );
    assert_eq!(
        reopened.imported_preview("observability").unwrap(),
        Some(preview)
    );
}

#[test]
fn uploaded_document_failed_candidate_and_stale_proof_preserve_source_preview_and_versions() {
    let (_temp, _config, store, _) = fixture();
    let draft = store
        .create_imported_service(upload_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let first = prepared_document(&draft, br#"{"old":true}"#);
    let saved = store
        .write_imported_document_preview(document_preview(&draft), &first, accept)
        .unwrap()
        .catalog;
    let preview = store.imported_preview("observability").unwrap();
    let next = prepared_document(&saved, br#"{"replacement":true}"#);
    assert!(
        store
            .write_imported_document_preview(document_preview(&saved), &next, reject)
            .is_err()
    );
    assert!(matches!(
        store.write_imported_document_preview(document_preview(&saved), &first, accept),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert_eq!(store.imported_catalog().unwrap(), saved);
    assert_eq!(store.imported_preview("observability").unwrap(), preview);
    assert_eq!(
        store.imported_document(&saved.services[0]).unwrap(),
        first.bytes()
    );
    assert!(matches!(
        store.imported_document(&draft.services[0]),
        Err(ManagedStoreError::VersionConflict)
    ));
    let mut mismatched = saved.services[0].clone();
    mismatched.document = None;
    assert!(matches!(
        store.imported_document(&mismatched),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        next.validate(&saved.services[0], saved.revision + 1),
        Err(ManagedStoreError::VersionConflict)
    ));
}

#[test]
fn uploaded_document_draft_settings_retain_source_and_remote_switch_deletes_atomically() {
    use crate::imports::ImportedDiscoverySource;
    let (_temp, _config, store, _) = fixture();
    let draft = store
        .create_imported_service(upload_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let source = prepared_document(&draft, b"{}");
    let saved = store
        .write_imported_document_preview(document_preview(&draft), &source, accept)
        .unwrap()
        .catalog;
    let mut edit = update(&saved);
    edit.status = ImportedServiceStatus::Draft;
    edit.discovery_source = ImportedDiscoverySource::StoredDocument;
    edit.definition
        .connection_settings
        .insert("securityScheme".into(), "basic".into());
    edit.definition.execution_bindings[0].delivery = ImportedCredentialDelivery::Basic;
    let saved = store.update_imported_service(edit, accept).unwrap().catalog;
    assert_eq!(store.imported_document(&saved.services[0]).unwrap(), b"{}");
    let mut remote = update(&saved);
    remote.status = ImportedServiceStatus::Draft;
    remote
        .definition
        .connection_settings
        .remove("definitionSource");
    remote.definition.connection_settings.insert(
        "definitionUrl".into(),
        "https://tools.example/spec.json".into(),
    );
    assert!(
        store
            .update_imported_service(remote.clone(), reject)
            .is_err()
    );
    assert_eq!(store.imported_catalog().unwrap(), saved);
    assert_eq!(store.imported_document(&saved.services[0]).unwrap(), b"{}");
    let changed = store
        .update_imported_service(remote, accept)
        .unwrap()
        .catalog;
    assert!(changed.services[0].document.is_none());
    let conn = store.connection.lock().unwrap();
    assert_eq!(count_table(&conn, "imported_source_documents").unwrap(), 0);
}

#[test]
fn uploaded_document_bounds_and_filename_validation_do_not_echo_content() {
    use super::super::imported_documents::{validate_document_bytes, validate_document_filename};
    assert!(
        validate_document_bytes(&vec![b' '; crate::imports::IMPORT_MAX_DOCUMENT_BYTES]).is_ok()
    );
    for bytes in [
        vec![],
        vec![0xff],
        vec![b'X'; crate::imports::IMPORT_MAX_DOCUMENT_BYTES + 1],
    ] {
        assert!(validate_document_bytes(&bytes).is_err());
    }
    for filename in [
        "",
        ".",
        "..",
        "...",
        "/tmp/spec.json",
        "x\\spec.json",
        "bad\0name",
        "bad\u{85}name",
    ] {
        let error = validate_document_filename(Some(filename)).unwrap_err();
        assert!(!error.to_string().contains(filename) || filename.is_empty());
    }
    assert!(validate_document_filename(Some(&"é".repeat(128))).is_err());
    assert!(validate_document_filename(Some(&"a".repeat(255))).is_ok());
    assert!(validate_document_filename(Some(".spec é.json")).is_ok());
    assert!(validate_document_filename(None).is_ok());
}

#[test]
fn uploaded_document_corrupt_content_is_rejected_on_load_and_reopen() {
    let (_temp, config, store, _) = fixture();
    let draft = store
        .create_imported_service(upload_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let source = prepared_document(&draft, b"{}");
    let saved = store
        .write_imported_document_preview(document_preview(&draft), &source, accept)
        .unwrap()
        .catalog;
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE imported_source_documents SET content=?1 WHERE service='observability'",
            [b"[]".as_slice()],
        )
        .unwrap();
    assert!(store.imported_document(&saved.services[0]).is_err());
    drop(store);
    assert!(ManagedStore::open(&config, ManagedStoreOpenMode::Startup).is_err());
}

#[test]
fn uploaded_document_schema_031_upgrade_preserves_durable_rows() {
    let (temp, _, store, _) = fixture();
    drop(store);
    let config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp.path().join("prior.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    };
    let previous = ManagedStoreMigrationCatalog {
        migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS.len() - 1],
    };
    let old =
        ManagedStore::open_with_catalog(&config, ManagedStoreOpenMode::Startup, previous).unwrap();
    let bytes = GOLDEN_SERVICE_ROWS[2].1;
    {
        let conn = old.connection.lock().unwrap();
        conn.execute("INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by) VALUES('golden-openapi',?1,'draft',1,'2026-01-01T00:00:00Z','admin','2026-01-01T00:00:00Z','admin')", [bytes]).unwrap();
        assert!(
            catalog_at(&conn, ImportSchema::CommandImports)
                .unwrap()
                .services[0]
                .document
                .is_none()
        );
    }
    drop(old);
    let upgraded = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    assert!(upgraded.migration_applied_this_open(MANAGED_STORE_IMPORTED_SOURCE_DOCUMENTS_VERSION));
    let catalog = upgraded.imported_catalog().unwrap();
    assert!(catalog.services[0].document.is_none());
    assert!(
        !serde_json::to_string(&catalog)
            .unwrap()
            .contains("document")
    );
    let conn = upgraded.connection.lock().unwrap();
    let retained: String = conn
        .query_row(
            "SELECT definition_json FROM imported_services WHERE service='golden-openapi'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, bytes);
    assert_eq!(count_table(&conn, "imported_source_documents").unwrap(), 0);
}
