fn material_fence_request(token: &str) -> CredentialWriteRequest {
    CredentialWriteRequest {
        owner_principal_id: "alice".into(),
        service: "inventory".into(),
        name: "default".into(),
        profile: "token".into(),
        credential_kind: "bearer_token".into(),
        secret: json!({"token":token}),
        metadata: json!({}),
        actor: "admin".into(),
    }
}

fn material_fence_fixture() -> (
    TempDir,
    ManagedStore,
    CredentialKeyRing,
    CredentialMetadata,
    CredentialMaterialFence,
) {
    let (temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"), &test_execution_contexts())
        .unwrap();
    let ring = key_ring_with_keys("old", &[("old", 7), ("new", 8)]);
    let metadata = store
        .upsert_user_credential(
            &ring,
            material_fence_request("first"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let (_, fence) = store
        .resolve_user_credential_with_material_fence(
            &ring,
            "alice",
            "inventory",
            "default",
            &["token".into()],
            None,
        )
        .unwrap();
    (temp, store, ring, metadata, fence)
}

#[test]
fn material_fence_survives_rewrap_and_verification_but_same_path_rotation_retires_it() {
    let (_temp, store, ring, metadata, fence) = material_fence_fixture();
    let other = ManagedStore::open(
        &store_config(store.path()),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Reload,
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        &store.credential_material_proofs,
        &other.credential_material_proofs
    ));
    other
        .rewrap_credentials(&ring, "old", "new", "admin")
        .unwrap();
    other
        .mark_user_credential_verified_if_current(
            &CredentialVerificationTarget {
                credential_id: metadata.credential_id,
                material_version: metadata.material_version,
            },
            "local_verified",
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    fence.validate_current().unwrap();
    store.validate_credential_material_fence(&fence).unwrap();
    other
        .upsert_user_credential(
            &ring,
            material_fence_request("second"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(matches!(
        fence.validate_current(),
        Err(ManagedStoreError::CredentialInvalid(_))
    ));
    let (_, replacement) = store
        .resolve_user_credential_with_material_fence(
            &ring,
            "alice",
            "inventory",
            "default",
            &["token".into()],
            None,
        )
        .unwrap();
    replacement.validate_current().unwrap();
    assert!(!Arc::ptr_eq(&fence.current, &replacement.current));
    // A later replacement with the original bytes cannot revive the old proof.
    other
        .upsert_user_credential(
            &ring,
            material_fence_request("first"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(fence.validate_current().is_err());
    assert!(replacement.validate_current().is_err());
}

#[test]
fn material_fence_all_personal_credential_delete_paths_retire_selected_material() {
    for path in ["tuple", "id", "connection", "retained"] {
        let (_temp, store, _ring, metadata, fence) = material_fence_fixture();
        let other = ManagedStore::open(
            &store_config(store.path()),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Reload,
        )
        .unwrap();
        match path {
            "tuple" => other.delete_user_credential(
                "alice",
                "inventory",
                "default",
                CredentialManagementPurpose::Administrative,
            ),
            "id" => other.delete_user_credential_by_id(
                &metadata.credential_id,
                CredentialManagementPurpose::Administrative,
            ),
            "connection" => other.delete_connection_credential(
                "alice",
                "inventory",
                &["token".into()],
                CredentialManagementPurpose::Administrative,
            ),
            "retained" => other.delete_retained_user_credential(
                &metadata.credential_id,
                "alice",
                &BTreeSet::new(),
                CredentialManagementPurpose::Administrative,
            ),
            _ => unreachable!(),
        }
        .unwrap();
        assert!(
            matches!(
                fence.validate_current(),
                Err(ManagedStoreError::CredentialInvalid(_))
            ),
            "{path}"
        );
    }
}

#[test]
fn material_fence_failed_commit_restores_current_proof_and_original_material() {
    let (_temp, store, ring, metadata, fence) = material_fence_fixture();
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_material_commit AFTER UPDATE OF material_version ON credentials
         BEGIN INSERT INTO principal_groups(principal_id,group_id,created_at,created_by)
           VALUES('alice','missing-group','2026-01-01T00:00:00Z','test'); END;
         PRAGMA defer_foreign_keys=ON;",
        )
        .unwrap();
    assert!(matches!(
        store.upsert_user_credential(
            &ring,
            material_fence_request("replacement"),
            CredentialManagementPurpose::Administrative
        ),
        Err(ManagedStoreError::Unavailable(_))
    ));
    fence.validate_current().unwrap();
    store.validate_credential_material_fence(&fence).unwrap();
    assert_eq!(
        store
            .credential_by_id(&metadata.credential_id)
            .unwrap()
            .material_version,
        metadata.material_version
    );
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_material_commit")
        .unwrap();
}

#[test]
fn material_fence_final_check_enforces_expiry_without_locking_the_store() {
    let (_temp, store, _ring, _metadata, mut fence) = material_fence_fixture();
    let _locked = store.connection.lock().unwrap();
    fence.validate_current().unwrap();
    fence.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    assert!(matches!(
        fence.validate_current(),
        Err(ManagedStoreError::CredentialExpired)
    ));
}

#[test]
fn material_fence_weak_registry_drops_completed_material_versions() {
    let (_temp, store, ring, _metadata, fence) = material_fence_fixture();
    drop(fence);
    for index in 0..20 {
        store
            .upsert_user_credential(
                &ring,
                material_fence_request(&format!("token-{index}")),
                CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let (_, fence) = store
            .resolve_user_credential_with_material_fence(
                &ring,
                "alice",
                "inventory",
                "default",
                &["token".into()],
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .credential_material_proofs
                .lock()
                .unwrap()
                .current
                .len(),
            1
        );
        drop(fence);
    }
}
