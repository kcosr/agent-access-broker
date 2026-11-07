#[test]
fn gateway_static_service_and_personal_credentials_survive_retirement_and_rewrap() {
    use agent_access_provider::test_support::{basic_credential, credential_with_profile};

    for delivery in [
        ImportedCredentialDelivery::Basic,
        ImportedCredentialDelivery::Bearer,
        ImportedCredentialDelivery::RawHeader {
            name: "X-Api-Key".into(),
        },
    ] {
        let (_temp, config, store, ring) = fixture();
        let mut definition = gateway_definition();
        definition.adapter_kind = "openapi_gateway".into();
        definition.endpoint = "https://api.example/api".into();
        definition.connection_settings = BTreeMap::from([
            ("definitionSource".into(), "upload".into()),
            ("executionAuthentication".into(), "static".into()),
            ("securityScheme".into(), "access".into()),
        ]);
        definition.execution_bindings = vec![
            ImportedCredentialBinding::token(ImportedCredentialMode::Service, delivery.clone()),
            ImportedCredentialBinding::token(ImportedCredentialMode::PerUser, delivery.clone()),
        ];
        let catalog = store
            .create_imported_service_with_routes(
                definition.clone(),
                Some(gateway_route_candidate("/items/admin")),
                "admin",
                accept,
            )
            .unwrap()
            .catalog;
        let mut service_write = slot(&catalog, "synthetic-service-token");
        let (kind, profile, personal_secret, requirement, service_expected, personal_expected) =
            if delivery == ImportedCredentialDelivery::Basic {
                service_write.username = Some("service-account".into());
                (
                    "basic_api_token",
                    "username-token",
                    json!({"username":"personal-account","token":"synthetic-personal-token"}),
                    crate::imports::ImportedCredentialRequirement::http_basic(),
                    basic_credential("service-account", "synthetic-service-token"),
                    basic_credential("personal-account", "synthetic-personal-token"),
                )
            } else {
                (
                    "bearer_token",
                    "token",
                    json!({"token":"synthetic-personal-token"}),
                    crate::imports::ImportedCredentialRequirement::token_header(),
                    bearer_credential("synthetic-service-token"),
                    bearer_credential("synthetic-personal-token"),
                )
            };
        let catalog = store
            .write_imported_secret_for_test(service_write, &ring, |catalog, _| accept(catalog))
            .unwrap()
            .catalog;
        let personal = store
            .upsert_user_credential_for_test(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "admin".into(),
                    service: "observability".into(),
                    name: crate::CONNECTION_CREDENTIAL_NAME.into(),
                    profile: profile.into(),
                    credential_kind: kind.into(),
                    secret: personal_secret,
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let new_only = CredentialKeyRing {
            active_key: "new".into(),
            keys: Arc::new(BTreeMap::from([("new".into(), [8; 32])])),
        };
        let mut retained = catalog;
        for status in [
            ImportedServiceStatus::Disabled,
            ImportedServiceStatus::Retired,
        ] {
            let mut change = update(&retained);
            change.discovery_source = crate::imports::ImportedDiscoverySource::StoredDocument;
            change.status = status;
            retained = store
                .update_imported_service(change, accept)
                .unwrap()
                .catalog;
            assert_eq!(store.active_credential_key_ids().unwrap(), vec!["old"]);
            assert_eq!(store.active_credential_count().unwrap(), 1);
            assert!(store.active_credentials_need_key_ring().unwrap());
            assert!(matches!(
                store.check_ready(Some(&new_only)),
                Err(ManagedStoreError::EncryptionKeyMissing(key)) if key == "old"
            ));
            store.check_ready(Some(&ring)).unwrap();
        }
        assert!(
            store
                .create_imported_service_with_routes(
                    definition.clone(),
                    Some(gateway_route_candidate("/replacement")),
                    "admin",
                    accept,
                )
                .is_err()
        );
        assert_eq!(store.imported_catalog().unwrap(), retained);
        drop(store);
        let store = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert_eq!(store.imported_catalog().unwrap(), retained);
        assert!(store.check_ready(None).is_err());
        let summary = store
            .rewrap_credentials(&ring, "old", "new", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 2);
        assert_eq!(summary.conflicts, 0);
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["new"]);
        store.check_ready(Some(&new_only)).unwrap();
        // Rewrap changes encryption only: both material identities, catalog
        // versions and the retained route generation/hash remain unchanged.
        assert_eq!(store.imported_catalog().unwrap(), retained);
        assert_eq!(
            store.credential_by_id(&personal.credential_id).unwrap(),
            personal
        );
        assert_eq!(
            store
                .resolve_imported_secret(
                    "observability",
                    ImportedCredentialPurpose::Execution,
                    &retained.services[0].slot_versions[&ImportedCredentialPurpose::Execution],
                    &new_only,
                    &requirement,
                )
                .unwrap(),
            service_expected
        );
        assert_eq!(
            store
                .resolve_user_credential_with_imported_contract(
                    &new_only,
                    "admin",
                    "observability",
                    crate::CONNECTION_CREDENTIAL_NAME,
                    &[profile.into()],
                    Some(&requirement),
                )
                .unwrap(),
            credential_with_profile(personal_expected, profile)
        );
        store
            .delete_imported_secret(
                ImportedSecretDeleteRequest {
                    service: "observability".into(),
                    purpose: ImportedCredentialPurpose::Execution,
                    expected_version: retained.services[0].version,
                    expected_catalog_revision: retained.revision,
                    actor: "admin".into(),
                },
                accept,
            )
            .unwrap();
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["new"]);
        store
            .delete_retained_user_credential(
                &personal.credential_id,
                "admin",
                &BTreeSet::new(),
                CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert!(store.active_credential_key_ids().unwrap().is_empty());
        assert!(!store.active_credentials_need_key_ring().unwrap());
        store.check_ready(None).unwrap();
        let after_delete = store.imported_catalog().unwrap();
        definition.endpoint = "https://replacement.example/api".into();
        assert!(matches!(
            store.create_imported_service_with_routes(
                definition,
                Some(gateway_route_candidate("/replacement")),
                "admin",
                accept,
            ),
            Err(ManagedStoreError::InputInvalid(message))
                if message == "imported service identity already exists and cannot be recycled"
        ));
        assert_eq!(store.imported_catalog().unwrap(), after_delete);
        assert_eq!(
            count_table(&store.connection.lock().unwrap(), "principals").unwrap(),
            1
        );
    }
}
