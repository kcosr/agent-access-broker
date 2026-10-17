// Receiver overlays migrate independently of accepted source JSON and ciphertext.
#[test]
fn migration_030_preserves_029_source_rows_hashes_versions_and_slots() {
    let (temp, mut config, latest, ring) = fixture();
    drop(latest);
    config.path = temp.path().join("schema-029.sqlite").display().to_string();
    let through = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| migration.version == "029_secret_references")
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
    let before_slots = {
        let conn = previous.connection.lock().unwrap();
        for (service, raw) in GOLDEN_SERVICE_ROWS {
            conn.execute("INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by) VALUES(?1,?2,'disabled',3,'2026-10-13T00:00:00Z','admin','2026-10-13T00:00:00Z','admin')",params![service,raw]).unwrap();
        }
        for (action, source, definition, hash, status, version) in GOLDEN_ACTION_ROWS {
            conn.execute("INSERT INTO imported_actions(service,action,source_json,definition_json,definition_hash,status,version) VALUES('golden-openapi',?1,?2,?3,?4,?5,?6)",params![action,source,definition,hash,status,version]).unwrap();
        }
        let (version, nonce, ciphertext, _) = GOLDEN_IMPORTED_SLOT;
        conn.execute("INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext) VALUES('observability','execution','bearer_token',?1,'old',?2,?3)",params![version,golden_hex(nonce),golden_hex(ciphertext)]).unwrap();
        slot_rows(&conn)
    };
    drop(previous);
    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    {
        let conn = store.connection.lock().unwrap();
        assert_eq!(slot_rows(&conn), before_slots);
        for (action, source, definition, hash, status, version) in GOLDEN_ACTION_ROWS {
            let row: (String,String,String,String,i64,String) = conn.query_row("SELECT source_json,definition_json,definition_hash,status,version,secret_inputs_json FROM imported_actions WHERE service='golden-openapi' AND action=?1",[action],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
            assert_eq!(
                row,
                (
                    source.into(),
                    definition.into(),
                    hash.into(),
                    status.into(),
                    version,
                    "[]".into()
                )
            );
        }
    }
    let catalog = store.imported_catalog().unwrap();
    assert!(
        catalog
            .services
            .iter()
            .flat_map(|service| &service.actions)
            .all(|action| action.secret_inputs.is_empty())
    );
    store.check_ready(Some(&ring)).unwrap();
    drop(store);
    assert!(
        ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..through]
            }
        )
        .is_err()
    );
}

#[test]
fn receiver_overlay_persists_versions_without_changing_source_hash_and_rejects_corruption() {
    let (_temp, config, store, _) = fixture();
    let draft = store
        .create_imported_service(definition(), "admin", accept)
        .unwrap()
        .catalog;
    let mut initial = update(&draft);
    initial.actions = vec![action()];
    let accepted = store
        .update_imported_service(initial, accept)
        .unwrap()
        .catalog;
    let mut edited = update(&accepted);
    edited.actions[0].secret_inputs = vec![agent_access_provider::SecretInputDescriptor::new(
        "/inputs/query",
    )];
    let changed = store
        .update_imported_service(edited, accept)
        .unwrap()
        .catalog;
    assert_eq!(
        changed.services[0].actions[0].definition,
        accepted.services[0].actions[0].definition
    );
    assert_eq!(
        changed.services[0].actions[0].definition_hash,
        accepted.services[0].actions[0].definition_hash
    );
    assert_eq!(
        changed.services[0].actions[0].version,
        accepted.services[0].actions[0].version + 1
    );
    assert_eq!(
        changed.services[0].version,
        accepted.services[0].version + 1
    );
    assert_eq!(changed.revision, accepted.revision + 1);
    drop(store);
    let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
    assert_eq!(reopened.imported_catalog().unwrap(), changed);
    // Well-formed unsupported retained contracts remain readable for administration.
    reopened.connection.lock().unwrap().execute("UPDATE imported_actions SET secret_inputs_json='[{\"pointer\":\"/inputs/no_longer_present\"}]'",[]).unwrap();
    assert!(reopened.imported_catalog().is_ok());
    for corrupt in [
        "{}",
        r#"[{"pointer":"/inputs/query","unknown":true}]"#,
        r#"[{"pointer":"/inputs/query"},{"pointer":"/inputs/query"}]"#,
        r#"[{"pointer":"/inputs/query~bad"}]"#,
    ] {
        reopened
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE imported_actions SET secret_inputs_json=?1",
                [corrupt],
            )
            .unwrap();
        assert!(reopened.imported_catalog().is_err(), "{corrupt}");
    }
}
