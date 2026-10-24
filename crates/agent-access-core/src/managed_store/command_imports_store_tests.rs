// Command import storage: migration `027_command_imports` from a schema-026
// store, accepted metadata, and `basic_api_token` execution slots. Rows that
// existed before the migration must stay byte-for-byte valid; see the golden
// vectors above, which these tests reuse and never change.

fn command_definition(modes: &[ImportedCredentialMode]) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "ticketing".into(),
        display_name: "Ticketing".into(),
        adapter_kind: "command".into(),
        endpoint: "command:ticketing".into(),
        connection_settings: BTreeMap::new(),
        execution_bindings: modes
            .iter()
            .map(|mode| ImportedCredentialBinding::token(*mode, ImportedCredentialDelivery::Stdin))
            .collect(),
        discovery: ImportedDiscoveryCredential::Anonymous,
        transport_auth: false,
        invocation_limit: None,
    }
}

fn command_metadata(kind: Option<ImportedCredentialKind>) -> ImportedServiceMetadata {
    ImportedServiceMetadata {
        format: "agent-access-command/1".into(),
        version: "1.4.0".into(),
        credential: kind.map(|kind| crate::imports::ImportedCredentialDeclaration {
            kind,
            modes: vec![ImportedCredentialMode::Service, ImportedCredentialMode::PerUser],
        }),
        verify: true,
        resource_types: Vec::new(),
    }
}

fn command_action() -> ImportedActionWrite {
    ImportedActionWrite {
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
    }
}

/// Discovers and accepts `issue.view` with `metadata`, as the host does.
fn accept_command(
    store: &ManagedStore,
    metadata: Option<ImportedServiceMetadata>,
) -> Result<ImportedCatalog, ManagedStoreError> {
    let catalog = store.imported_catalog().unwrap();
    let record = catalog.service("ticketing").unwrap();
    let observed = store
        .write_imported_preview(
            ImportedPreviewWriteRequest {
                service: "ticketing".into(),
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                config_revision: "config-command".into(),
                credential_versions: BTreeMap::new(),
                manifest: json!({"tools":[]}),
                quarantine_actions: Vec::new(),
                actor: "admin".into(),
            },
            accept,
        )
        .unwrap()
        .catalog;
    let pending = store.imported_preview("ticketing").unwrap().unwrap();
    let record = observed.service("ticketing").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: record.definition.clone(),
                status: ImportedServiceStatus::Disabled,
                actions: vec![command_action()],
                expected_version: record.version,
                expected_catalog_revision: observed.revision,
                accepted_preview: Some(ImportedPreviewAcceptance {
                    manifest_hash: pending.manifest_hash,
                    config_revision: pending.config_revision,
                    credential_versions: pending.credential_versions,
                    accepted_metadata: metadata,
                }),
                actor: "admin".into(),
            },
            accept,
        )
        .map(|mutation| mutation.catalog)
}

fn command_slot(
    store: &ManagedStore,
    ring: &CredentialKeyRing,
    token: &str,
    username: Option<&str>,
) -> Result<ImportedCatalog, ManagedStoreError> {
    let catalog = store.imported_catalog().unwrap();
    let record = catalog.service("ticketing").unwrap();
    store
        .write_imported_secret(
            ImportedSecretWriteRequest {
                service: "ticketing".into(),
                purpose: ImportedCredentialPurpose::Execution,
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                token: token.into(),
                username: username.map(str::to_owned),
                actor: "admin".into(),
            },
            ring,
            |_, _| Ok(()),
        )
        .map(|mutation| mutation.catalog)
}

/// Every stored column of every slot row, BLOBs as hex with their storage
/// class, so a comparison is byte-for-byte.
fn slot_rows(conn: &Connection) -> Vec<Vec<String>> {
    conn.prepare(
        "SELECT service, purpose, credential_kind, material_version, key_id,
                typeof(nonce), hex(nonce), typeof(ciphertext), hex(ciphertext)
         FROM imported_secret_material ORDER BY service, purpose",
    )
    .unwrap()
    .query_map([], |row| (0..9).map(|index| row.get(index)).collect())
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn service_rows(conn: &Connection) -> Vec<Vec<String>> {
    conn.prepare(
        "SELECT service, definition_json, status, CAST(version AS TEXT), created_at, created_by,
                updated_at, updated_by
         FROM imported_services ORDER BY service",
    )
    .unwrap()
    .query_map([], |row| (0..8).map(|index| row.get(index)).collect())
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[test]
fn migration_027_copies_schema_026_slot_rows_byte_for_byte() {
    upgrade_preserves_import_rows("026_trusted_user_identity");
}

#[test]
fn upgrades_from_schema_025_keep_import_rows_byte_for_byte() {
    upgrade_preserves_import_rows("025_principal_access");
}

// Each pending migration first validates the previous schema, so the 023 and
// 024 validators run on stores without the 027 column.
#[test]
fn upgrades_from_schema_024_keep_import_rows_byte_for_byte() {
    upgrade_preserves_import_rows("024_oauth_discovery_revision");
}

#[test]
fn upgrades_from_schema_023_keep_import_rows_byte_for_byte() {
    upgrade_preserves_import_rows("023_imported_services");
}

/// A store at schema `from` holding import rows and every kind of slot
/// upgrades to the current schema with its rows byte-for-byte unchanged.
fn upgrade_preserves_import_rows(from: &str) {
    let (_temp, _config, latest, ring) = fixture();
    drop(latest);
    let temp = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp.path().join(format!("schema-{from}.sqlite")).display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    };
    let through = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| migration.version == from)
        .unwrap()
        + 1;
    let previous = ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..through],
        },
    )
    .unwrap();
    let (slots_before, services_before) = {
        let conn = previous.connection.lock().unwrap();
        for (service, json) in GOLDEN_SERVICE_ROWS {
            conn.execute(
                "INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by)
                 VALUES(?1,?2,'disabled',3,'2026-10-13T00:00:00Z','admin','2026-10-14T00:00:00Z','admin')",
                params![service, json],
            )
            .unwrap();
        }
        // The execution slot an earlier release wrote, plus bearer slots of
        // every purpose under both keys, encrypted as the bearer encoding
        // has always been.
        let (version, nonce, ciphertext, _) = GOLDEN_IMPORTED_SLOT;
        conn.execute(
            "INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext)
             VALUES('observability','execution','bearer_token',?1,'old',?2,?3)",
            params![version, golden_hex(nonce), golden_hex(ciphertext)],
        )
        .unwrap();
        for (service, purpose, key_id, token) in [
            ("golden-header", "execution", "old", "header-execution-token"),
            ("golden-header", "discovery", "new", "header-discovery-token"),
            ("golden-header", "transport", "old", "header-transport-token"),
            ("golden-oauth", "discovery", "new", "oauth-discovery-token"),
            ("golden-openapi", "execution", "new", "openapi-execution-token"),
        ] {
            let mut row = SecretRow {
                service: service.into(),
                purpose: purpose.into(),
                credential_kind: "bearer_token".into(),
                material_version: format!("{service}-{purpose}-version"),
                key_id: key_id.into(),
                nonce: Vec::new(),
                ciphertext: Vec::new(),
            };
            let encrypted = encrypt(&ring, &row, token).unwrap();
            row.nonce = encrypted.nonce;
            row.ciphertext = encrypted.ciphertext;
            conn.execute(
                "INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![row.service, row.purpose, row.credential_kind, row.material_version, row.key_id, row.nonce, row.ciphertext],
            )
            .unwrap();
        }
        let schema: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='imported_secret_material'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(schema.contains("CHECK(credential_kind = 'bearer_token')"));
        (slot_rows(&conn), service_rows(&conn))
    };
    drop(previous);

    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    let conn = store.connection.lock().unwrap();
    assert_eq!(slot_rows(&conn), slots_before);
    assert_eq!(slots_before.len(), 6);
    assert_eq!(service_rows(&conn), services_before);
    let metadata_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM imported_services WHERE accepted_metadata_json IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(metadata_rows, 0);
    let ledger: Vec<String> = conn
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(ledger.iter().any(|version| version == "027_command_imports"));
    assert_eq!(
        ledger.last().map(String::as_str),
        Some(MANAGED_STORE_SCHEMA_VERSION)
    );
    let row = secret_row(&conn, "observability", "execution")
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(aad(&row).unwrap()).unwrap(),
        r#"["aab-imported-service-credential:v1","observability","execution","bearer_token","3e3467b6-f61b-41d4-8b08-8b7a699c7eda","old"]"#
    );
    drop(conn);

    // Every migrated record reads back and every slot decrypts unchanged.
    let catalog = store.imported_catalog().unwrap();
    for definition in golden_definitions() {
        let record = catalog.service(&definition.service).unwrap();
        assert_eq!(record.definition, definition);
        assert_eq!(record.accepted_metadata, None);
    }
    store.check_ready(Some(&ring)).unwrap();
    assert_eq!(
        store
            .resolve_imported_secret(
                "observability",
                ImportedCredentialPurpose::Execution,
                GOLDEN_IMPORTED_SLOT.0,
                &ring,
            )
            .unwrap(),
        bearer_credential(GOLDEN_IMPORTED_SLOT.3)
    );
    assert_eq!(
        store
            .resolve_imported_secret(
                "golden-header",
                ImportedCredentialPurpose::Transport,
                "golden-header-transport-version",
                &ring,
            )
            .unwrap(),
        bearer_credential("header-transport-token")
    );
    // The widened CHECK admits both kinds and nothing else.
    let conn = store.connection.lock().unwrap();
    let error = conn.execute(
        "UPDATE imported_secret_material SET credential_kind='oauth' WHERE service='observability'",
        [],
    );
    assert!(error.is_err());
}

#[test]
fn username_token_slots_encrypt_the_managed_encoding_and_round_trip() {
    let (_temp, _config, store, ring) = fixture();
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::Service, ImportedCredentialMode::PerUser]),
            "admin",
            accept,
        )
        .unwrap();
    // The kind is unknown until the manifest's declaration is accepted.
    assert!(matches!(
        command_slot(&store, &ring, "svc-example", Some("svc-tickets")),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("accept the command's manifest")
    ));
    let metadata = command_metadata(Some(ImportedCredentialKind::UsernameToken));
    let catalog = accept_command(&store, Some(metadata.clone())).unwrap();
    assert_eq!(
        catalog.service("ticketing").unwrap().accepted_metadata,
        Some(metadata)
    );
    for username in [None, Some(""), Some("bad\nname")] {
        assert!(command_slot(&store, &ring, "svc-example", username).is_err());
    }
    let long = "u".repeat(257);
    assert!(command_slot(&store, &ring, "svc-example", Some(&long)).is_err());
    let catalog = command_slot(&store, &ring, "svc-example", Some("svc-tickets")).unwrap();
    let version = catalog.service("ticketing").unwrap().slot_versions
        [&ImportedCredentialPurpose::Execution]
        .clone();
    {
        let conn = store.connection.lock().unwrap();
        let row = secret_row(&conn, "ticketing", "execution").unwrap().unwrap();
        assert_eq!(row.credential_kind, "basic_api_token");
        assert_eq!(
            String::from_utf8(aad(&row).unwrap()).unwrap(),
            format!(
                r#"["aab-imported-service-credential:v1","ticketing","execution","basic_api_token","{version}","old"]"#
            )
        );
        // The managed `basic_api_token` secret encoding.
        assert_eq!(
            decrypt(&ring, &row).unwrap(),
            r#"{"token":"svc-example","username":"svc-tickets"}"#
        );
    }
    let resolve = |ring: &CredentialKeyRing| {
        store.resolve_imported_secret(
            "ticketing",
            ImportedCredentialPurpose::Execution,
            &version,
            ring,
        )
    };
    let credential = resolve(&ring).unwrap();
    assert_eq!(credential.kind().as_str(), "basic_api_token");
    assert_eq!(
        credential,
        agent_access_provider::test_support::basic_credential("svc-tickets", "svc-example")
    );
    store.check_ready(Some(&ring)).unwrap();
    // Rewrap preserves the plaintext encoding and the material version.
    let ring = CredentialKeyRing {
        active_key: "new".into(),
        ..ring
    };
    let rewrapped = rewrap(&mut store.connection.lock().unwrap(), &ring, "old", "new").unwrap();
    assert_eq!(rewrapped, 1);
    let row = secret_row(&store.connection.lock().unwrap(), "ticketing", "execution")
        .unwrap()
        .unwrap();
    assert_eq!((row.key_id.as_str(), row.material_version.as_str()), ("new", version.as_str()));
    assert_eq!(resolve(&ring).unwrap(), credential);
}

#[test]
fn command_slots_follow_the_accepted_credential_declaration() {
    let (_temp, _config, store, ring) = fixture();
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::Service]),
            "admin",
            accept,
        )
        .unwrap();
    accept_command(&store, Some(command_metadata(Some(ImportedCredentialKind::Token)))).unwrap();
    assert!(command_slot(&store, &ring, "svc-example", Some("svc-tickets")).is_err());
    let catalog = command_slot(&store, &ring, "svc-example", None).unwrap();
    let version = &catalog.service("ticketing").unwrap().slot_versions
        [&ImportedCredentialPurpose::Execution];
    let row = secret_row(&store.connection.lock().unwrap(), "ticketing", "execution")
        .unwrap()
        .unwrap();
    assert_eq!(row.credential_kind, "bearer_token");
    assert_eq!(decrypt(&ring, &row).unwrap(), "svc-example");
    assert_eq!(
        store
            .resolve_imported_secret("ticketing", ImportedCredentialPurpose::Execution, version, &ring)
            .unwrap(),
        bearer_credential("svc-example")
    );

    // A credential-free command has no execution slot at all.
    let (_temp, _config, store, ring) = fixture();
    store
        .create_imported_service(command_definition(&[]), "admin", accept)
        .unwrap();
    accept_command(&store, Some(command_metadata(None))).unwrap();
    assert!(matches!(
        command_slot(&store, &ring, "svc-example", None),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("declares no execution credential")
    ));
}

#[test]
fn accepted_metadata_is_written_with_acceptance_and_its_credential_is_fixed() {
    let (_temp, _config, store, _ring) = fixture();
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::Service]),
            "admin",
            accept,
        )
        .unwrap();
    let mut metadata = command_metadata(Some(ImportedCredentialKind::Token));
    accept_command(&store, Some(metadata.clone())).unwrap();
    let stored: String = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT accepted_metadata_json FROM imported_services WHERE service='ticketing'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored).unwrap(),
        serde_json::to_value(&metadata).unwrap()
    );
    // Later acceptances replace display data, never the credential.
    metadata.version = "1.5.0".into();
    let catalog = accept_command(&store, Some(metadata.clone())).unwrap();
    assert_eq!(
        catalog.service("ticketing").unwrap().accepted_metadata,
        Some(metadata.clone())
    );
    for credential in [
        None,
        Some(ImportedCredentialKind::UsernameToken),
    ] {
        let changed = ImportedServiceMetadata {
            credential: command_metadata(credential).credential,
            ..metadata.clone()
        };
        assert!(matches!(
            accept_command(&store, Some(changed)),
            Err(ManagedStoreError::InputInvalid(message)) if message.contains("cannot change")
        ));
    }
    assert!(accept_command(&store, None).is_err());
    let mut invalid = metadata;
    invalid.format = String::new();
    assert!(accept_command(&store, Some(invalid)).is_err());
    // A corrupted column makes the catalog unreadable rather than silently
    // dropping the declaration.
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE imported_services SET accepted_metadata_json='{}' WHERE service='ticketing'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.imported_catalog(),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
}

#[test]
fn updates_keep_credential_modes_within_the_accepted_declaration() {
    let update = |store: &ManagedStore, modes: &[ImportedCredentialMode]| {
        let catalog = store.imported_catalog().unwrap();
        let mut request = update(&catalog);
        request.definition = command_definition(modes);
        request.status = catalog.services[0].status;
        store.update_imported_service(request, accept)
    };
    let mut service_only = command_metadata(Some(ImportedCredentialKind::Token));
    service_only.credential.as_mut().unwrap().modes = vec![ImportedCredentialMode::Service];
    let (_temp, _config, store, _ring) = fixture();
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::Service]),
            "admin",
            accept,
        )
        .unwrap();
    accept_command(&store, Some(service_only)).unwrap();
    assert!(matches!(
        update(&store, &[ImportedCredentialMode::Service, ImportedCredentialMode::PerUser]),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("only the credential modes service")
    ));
    update(&store, &[ImportedCredentialMode::Service]).unwrap();

    // A command without a credential takes no credential modes at all.
    let (_temp, _config, store, _ring) = fixture();
    store
        .create_imported_service(command_definition(&[]), "admin", accept)
        .unwrap();
    accept_command(&store, Some(command_metadata(None))).unwrap();
    assert!(matches!(
        update(&store, &[ImportedCredentialMode::Service]),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    let (_temp, _config, store, _ring) = fixture();
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::Service]),
            "admin",
            accept,
        )
        .unwrap();
    assert!(matches!(
        accept_command(&store, Some(command_metadata(None))),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("declares no credential")
    ));

    // Acceptance checks the declaration it stores.
    let (_temp, _config, store, _ring) = fixture();
    store
        .create_imported_service(command_definition(&[]), "admin", accept)
        .unwrap();
    assert!(matches!(
        accept_command(&store, Some(command_metadata(Some(ImportedCredentialKind::Token)))),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("declares a credential")
    ));
}
