// Legacy/corrupt plaintext must be checked after authenticated decryption and
// before constructing opaque credentials. Keep ciphertext/AAD goldens unchanged.

fn basic_definition() -> ImportedServiceDefinition {
    let mut definition = definition();
    definition.adapter_kind = "openapi_http".into();
    definition.execution_bindings = vec![
        ImportedCredentialBinding::token(
            ImportedCredentialMode::Service,
            ImportedCredentialDelivery::Basic,
        ),
        ImportedCredentialBinding::token(
            ImportedCredentialMode::PerUser,
            ImportedCredentialDelivery::Basic,
        ),
    ];
    definition
}

#[test]
fn imported_basic_slots_reject_decryptable_wrong_kind_and_invalid_material() {
    let (_temp, _config, store, ring) = fixture();
    let catalog = store
        .create_imported_service(basic_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let mut write = slot(&catalog, " secret: é ");
    write.username = Some(" Ålice ".into());
    let catalog = store
        .write_imported_secret_for_test(write, &ring, |catalog, _| accept(catalog))
        .unwrap()
        .catalog;
    let version = &catalog.services[0].slot_versions[&ImportedCredentialPurpose::Execution];
    let requirement = crate::imports::ImportedCredentialRequirement::http_basic();
    let original = store
        .resolve_imported_secret(
            "observability",
            ImportedCredentialPurpose::Execution,
            version,
            &ring,
            &requirement,
        )
        .unwrap();
    assert_eq!(
        original,
        agent_access_provider::test_support::basic_credential(" Ålice ", " secret: é ")
    );
    for (kind, plaintext) in [
        (
            "basic_api_token",
            json!({"username":"bad:name","token":"token"}).to_string(),
        ),
        (
            "basic_api_token",
            json!({"username":"alice","token":"bad\u{85}token"}).to_string(),
        ),
        (
            "basic_api_token",
            json!({"username":"alice\n","token":"token"}).to_string(),
        ),
        ("bearer_token", "decryptable-wrong-kind".to_string()),
    ] {
        {
            let conn = store.connection.lock().unwrap();
            let mut row = secret_row(&conn, "observability", "execution")
                .unwrap()
                .unwrap();
            row.credential_kind = kind.into();
            let encrypted = encrypt(&ring, &row, &plaintext).unwrap();
            conn.execute("UPDATE imported_secret_material SET credential_kind=?1,nonce=?2,ciphertext=?3 WHERE service='observability' AND purpose='execution'",params![kind,encrypted.nonce,encrypted.ciphertext]).unwrap();
            assert_eq!(
                decrypt(
                    &ring,
                    &secret_row(&conn, "observability", "execution")
                        .unwrap()
                        .unwrap()
                )
                .unwrap(),
                plaintext
            );
        }
        assert!(matches!(
            store.resolve_imported_secret(
                "observability",
                ImportedCredentialPurpose::Execution,
                version,
                &ring,
                &requirement
            ),
            Err(ManagedStoreError::CredentialInvalid(_))
        ));
    }
}

#[test]
fn imported_personal_basic_invalid_plaintext_fails_availability_execution_and_verification() {
    let (_temp, _config, store, ring) = fixture();
    store
        .create_imported_service(basic_definition(), "admin", accept)
        .unwrap();
    let request = CredentialWriteRequest {
        owner_principal_id: "admin".into(),
        service: "observability".into(),
        name: "default".into(),
        profile: "username-token".into(),
        credential_kind: "basic_api_token".into(),
        secret: json!({"username":"alice","token":" secret: é "}),
        metadata: json!({}),
        actor: "admin".into(),
    };
    assert!(matches!(
        store.upsert_user_credential(
            &ring,
            request.clone(),
            CredentialManagementPurpose::Administrative
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    store
        .upsert_user_credential_for_test(
            &ring,
            request,
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let requirement = crate::imports::ImportedCredentialRequirement::http_basic();
    let profiles = vec!["username-token".into()];
    store
        .check_user_credential_with_imported_contract(
            &ring,
            "admin",
            "observability",
            "default",
            &profiles,
            Some(&requirement),
        )
        .unwrap();
    assert!(
        store
            .resolve_user_credential(&ring, "admin", "observability", "default", &profiles)
            .is_err()
    );
    for secret in [
        json!({"username":"alice:admin","token":"token"}),
        json!({"username":"alice","token":"control\u{85}"}),
    ] {
        {
            let conn = store.connection.lock().unwrap();
            let row =
                encrypted_credential_by_tuple(&conn, "admin", "observability", "default").unwrap();
            let encrypted = ring.encrypt(&secret, &credential_aad(&row)).unwrap();
            conn.execute("UPDATE credential_secret_material SET secret_nonce=?1,secret_ciphertext=?2 WHERE secret_ref=?3",params![encrypted.nonce,encrypted.ciphertext,row.secret_ref]).unwrap();
        }
        assert!(matches!(
            store.check_user_credential_with_imported_contract(
                &ring,
                "admin",
                "observability",
                "default",
                &profiles,
                Some(&requirement)
            ),
            Err(ManagedStoreError::CredentialInvalid(_))
        ));
        assert!(matches!(
            store.resolve_user_credential_with_imported_contract(
                &ring,
                "admin",
                "observability",
                "default",
                &profiles,
                Some(&requirement)
            ),
            Err(ManagedStoreError::CredentialInvalid(_))
        ));
        assert!(matches!(
            store.resolve_user_credential_for_verification_with_imported_contract(
                &ring,
                "admin",
                "observability",
                "default",
                &profiles,
                CredentialManagementPurpose::Administrative,
                Some(&requirement)
            ),
            Err(ManagedStoreError::CredentialInvalid(_))
        ));
        let conn = store.connection.lock().unwrap();
        let metadata =
            credential_metadata_by_tuple(&conn, "admin", "observability", "default").unwrap();
        assert!(metadata.last_used_at.is_none());
        assert!(metadata.last_verified_at.is_none());
    }
}

#[test]
fn imported_basic_does_not_narrow_native_or_command_personal_plaintext() {
    let (_temp, _config, store, ring) = fixture();
    let username = "  alice:region\u{85} ";
    let token = " opaque\nü ";
    let request = |service: &str| CredentialWriteRequest {
        owner_principal_id: "admin".into(),
        service: service.into(),
        name: "default".into(),
        profile: "username-token".into(),
        credential_kind: "basic_api_token".into(),
        secret: json!({"username":username,"token":token}),
        metadata: json!({}),
        actor: "admin".into(),
    };
    let profiles = vec!["username-token".into()];
    let expected = agent_access_provider::test_support::credential_with_profile(
        agent_access_provider::test_support::basic_credential(username, token),
        "username-token",
    );
    store
        .upsert_user_credential(
            &ring,
            request("jira"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert_eq!(
        store
            .resolve_user_credential(&ring, "admin", "jira", "default", &profiles)
            .unwrap(),
        expected
    );
    store
        .create_imported_service(
            command_definition(&[ImportedCredentialMode::PerUser]),
            "admin",
            accept,
        )
        .unwrap();
    accept_command(
        &store,
        Some(command_metadata(Some(
            ImportedCredentialKind::UsernameToken,
        ))),
    )
    .unwrap();
    store
        .upsert_user_credential_for_test(
            &ring,
            request("ticketing"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let requirement = crate::imports::ImportedCredentialRequirement::command_stdin(
        ImportedCredentialKind::UsernameToken,
    );
    assert_eq!(
        store
            .resolve_user_credential_with_imported_contract(
                &ring,
                "admin",
                "ticketing",
                "default",
                &profiles,
                Some(&requirement),
            )
            .unwrap(),
        expected
    );
}

#[test]
fn imported_prepared_contract_rejects_changed_definition_metadata_purpose_and_revision() {
    let (_temp, _config, store, ring) = fixture();
    let catalog = store
        .create_imported_service(basic_definition(), "admin", accept)
        .unwrap()
        .catalog;
    let proof = crate::PreparedImportedCredentialContract::for_test(
        catalog.clone(),
        "observability",
        ImportedCredentialPurpose::Execution,
        false,
    )
    .unwrap();
    let record = &catalog.services[0];
    assert!(
        proof
            .validate(
                catalog.revision,
                record,
                ImportedCredentialPurpose::Execution,
                false
            )
            .is_ok()
    );
    assert!(matches!(
        proof.validate(
            catalog.revision,
            record,
            ImportedCredentialPurpose::Discovery,
            false
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        proof.validate(
            catalog.revision,
            record,
            ImportedCredentialPurpose::Execution,
            true
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        proof.validate(
            catalog.revision + 1,
            record,
            ImportedCredentialPurpose::Execution,
            false
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    let mut altered = record.clone();
    altered.definition.execution_bindings[0].delivery = ImportedCredentialDelivery::Bearer;
    assert!(matches!(
        proof.validate(
            catalog.revision,
            &altered,
            ImportedCredentialPurpose::Execution,
            false
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    altered = record.clone();
    altered.accepted_metadata = Some(command_metadata(Some(ImportedCredentialKind::Token)));
    assert!(matches!(
        proof.validate(
            catalog.revision,
            &altered,
            ImportedCredentialPurpose::Execution,
            false
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    let changed = store
        .update_imported_service(update(&catalog), accept)
        .unwrap()
        .catalog;
    let mut request = slot(&changed, "token");
    request.username = Some("alice".into());
    assert!(matches!(
        store.write_imported_secret(request, &ring, &proof, |catalog, _| accept(catalog)),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(store.active_credential_key_ids().unwrap().is_empty());
}
