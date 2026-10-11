fn identity_user_request(id: &str) -> PrincipalWriteRequest {
    PrincipalWriteRequest {
        role: PrincipalRole::User,
        self_service_enabled: None,
        principal_id: id.into(),
        kind: "user".into(),
        display_name: None,
        email: None,
        external_subject: None,
        created_by: "admin".into(),
    }
}

fn identity_test_store() -> (TempDir, ManagedStore) {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    (temp, store)
}

fn identity_test_pause(
    store: &ManagedStore,
    principal: &str,
    paused: bool,
) -> IdentityAccessRecord {
    let version = store.identity_access(principal).unwrap().version;
    store
        .set_identity_access_paused(principal, paused, version, "admin")
        .unwrap()
}

#[test]
fn identity_username_enrollment_is_exact_scoped_and_inventory_independent() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store
        .create_principal(identity_user_request("bob"))
        .unwrap();
    let gate = store.identity_access("alice").unwrap();
    assert!(!gate.paused);
    assert_eq!(gate.version, 1);
    assert_eq!(gate.updated_by, "admin");
    assert_eq!(
        store.identity_token_metadata("alice").unwrap().revision,
        None
    );
    for name in ["alice", "Alice", "1000", "anonymous"] {
        assert!(matches!(
            store.resolve_username_identity("linux", name),
            Err(ManagedStoreError::AttestedIdentityDenied)
        ));
    }
    let binding = store
        .create_username_binding("alice", "linux", "1000", "admin")
        .unwrap();
    store
        .create_username_binding("bob", "other-linux", "1000", "admin")
        .unwrap();
    let resolved = store.resolve_username_identity("linux", "1000").unwrap();
    assert_eq!(resolved.principal.principal_id, "alice");
    assert_eq!(
        resolved.proof.binding_id(),
        Some(binding.binding_id.as_str())
    );
    assert_eq!(resolved.proof.namespace(), Some("linux"));
    assert!(resolved.proof.matches_username("linux", "1000"));
    assert!(!resolved.proof.matches_username("other-linux", "1000"));
    assert!(!resolved.proof.matches_fingerprint("1000"));
    assert!(resolved.proof.is_username());
    assert_eq!(
        store
            .resolve_username_identity("other-linux", "1000")
            .unwrap()
            .principal
            .principal_id,
        "bob"
    );
    for name in ["1000 ", " 1000", "1000,alice", "%31%30%30%30", "álîce"] {
        assert!(
            store
                .create_username_binding("alice", "linux", name, "admin")
                .is_err()
        );
        assert!(store.resolve_username_identity("linux", name).is_err());
    }
    assert!(
        store
            .create_username_binding("alice", "bad namespace", "alice", "admin")
            .is_err()
    );
    assert!(
        store
            .create_username_binding("alice", "linux", &"x".repeat(129), "admin")
            .is_err()
    );
    store
        .create_username_binding("alice", "linux", &"x".repeat(128), "admin")
        .unwrap();
    store
        .create_username_binding("alice", "linux", "Alice", "admin")
        .unwrap();
    assert!(store.resolve_username_identity("linux", "alice").is_err());
    assert_eq!(
        format!("{:?}", resolved.proof),
        "AttestedIdentityProof([redacted])"
    );
}

#[test]
fn identity_binding_uniqueness_ownership_and_versions_are_atomic() {
    let (_temp, store) = identity_test_store();
    for principal in ["alice", "bob"] {
        store
            .create_principal(identity_user_request(principal))
            .unwrap();
    }
    let binding = store
        .create_username_binding("alice", "linux", "alice", "admin")
        .unwrap();
    assert_eq!(binding.version, 1);
    for principal in ["alice", "bob"] {
        assert!(matches!(
            store.create_username_binding(principal, "linux", "alice", "admin"),
            Err(ManagedStoreError::IdentityBindingConflict)
        ));
    }
    assert!(matches!(
        store.set_username_binding_enabled("bob", &binding.binding_id, false, 1, "admin"),
        Err(ManagedStoreError::IdentityBindingNotFound)
    ));
    assert!(matches!(
        store.delete_username_binding("bob", &binding.binding_id, 1),
        Err(ManagedStoreError::IdentityBindingNotFound)
    ));
    let same = store
        .set_username_binding_enabled("alice", &binding.binding_id, true, 1, "admin")
        .unwrap();
    assert_eq!(same, binding);
    let disabled = store
        .set_username_binding_enabled("alice", &binding.binding_id, false, 1, "admin")
        .unwrap();
    assert_eq!(disabled.version, 2);
    assert!(!disabled.enabled);
    assert!(matches!(
        store.create_username_binding("bob", "linux", "alice", "admin"),
        Err(ManagedStoreError::IdentityBindingConflict)
    ));
    for result in [
        store.set_username_binding_enabled("alice", &binding.binding_id, true, 1, "admin"),
        store.delete_username_binding("alice", &binding.binding_id, 1),
    ] {
        assert!(matches!(
            result,
            Err(ManagedStoreError::IdentityVersionConflict)
        ));
    }
    assert_eq!(
        store.list_username_bindings("alice").unwrap(),
        vec![disabled.clone()]
    );
    assert_eq!(
        store
            .delete_username_binding("alice", &binding.binding_id, 2)
            .unwrap(),
        disabled
    );
    let replacement = store
        .create_username_binding("bob", "linux", "alice", "admin")
        .unwrap();
    assert_ne!(replacement.binding_id, binding.binding_id);
    assert_eq!(replacement.version, 1);
    assert_eq!(
        store
            .resolve_username_identity("linux", "alice")
            .unwrap()
            .principal
            .principal_id,
        "bob"
    );
}

#[test]
fn identity_shared_pause_and_inventory_revision_have_separate_lifetimes() {
    let (_temp, store) = identity_test_store();
    let ring = key_ring("k1");
    store.configure_identity_token_encryption(Some(ring.clone()));
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store
        .create_username_binding("alice", "linux", "alice", "admin")
        .unwrap();
    let token = store.reveal_identity_token("alice", &ring).unwrap();
    let fingerprint = format!("sha256:{}", sha256_hex(token.as_bytes()));
    let username = store
        .resolve_username_identity("linux", "alice")
        .unwrap()
        .proof;
    let old_fingerprint = store
        .resolve_identity_fingerprint_with_proof(&fingerprint)
        .unwrap()
        .proof;
    assert!(!old_fingerprint.is_username());
    assert!(old_fingerprint.matches_fingerprint(&fingerprint));
    assert_eq!(
        store.identity_token_metadata("alice").unwrap().revision,
        Some(1)
    );
    assert_eq!(
        store.remove_identity_token("alice").unwrap().revision,
        Some(2)
    );
    assert_eq!(
        store.revalidate_attested_identity(&username).unwrap().proof,
        username
    );
    assert!(
        store
            .revalidate_attested_identity(&old_fingerprint)
            .is_err()
    );
    assert_eq!(
        store
            .set_identity_token("alice", &token, &ring)
            .unwrap()
            .revision,
        Some(3)
    );
    assert!(
        store
            .revalidate_attested_identity(&old_fingerprint)
            .is_err(),
        "A-B-A inventory cannot restore proof"
    );
    assert!(store.revalidate_attested_identity(&username).is_ok());
    let new_fingerprint = store
        .resolve_identity_fingerprint_with_proof(&fingerprint)
        .unwrap()
        .proof;
    assert_ne!(
        old_fingerprint.session_binding(),
        new_fingerprint.session_binding()
    );
    let pause = identity_test_pause(&store, "alice", true);
    assert_eq!(pause.version, 2);
    assert!(store.resolve_username_identity("linux", "alice").is_err());
    assert!(store.resolve_identity_fingerprint(&fingerprint).is_err());
    store.remove_identity_token("alice").unwrap();
    store.set_identity_token("alice", &token, &ring).unwrap();
    assert!(store.identity_access("alice").unwrap().paused);
    identity_test_pause(&store, "alice", false);
    assert!(store.resolve_username_identity("linux", "alice").is_ok());
    assert!(store.resolve_identity_fingerprint(&fingerprint).is_ok());
    assert_eq!(
        store
            .batch_proof_current(&[username, old_fingerprint, new_fingerprint])
            .unwrap(),
        vec![false, false, false]
    );
    let metadata = serde_json::to_value(store.identity_token_metadata("alice").unwrap()).unwrap();
    assert!(metadata.get("paused").is_none());
    assert!(metadata.get("fingerprint").is_none());
}

#[test]
fn identity_pause_does_not_pause_issued_broker_tokens_and_reverse() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store
        .create_username_binding("alice", "linux", "alice", "admin")
        .unwrap();
    let hasher = broker_token_hasher_for_test(51);
    let token = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "independent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts":["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    identity_test_pause(&store, "alice", true);
    assert!(store.resolve_broker_token(&hasher, &token.token).is_ok());
    identity_test_pause(&store, "alice", false);
    store
        .pause_broker_token(&token.record.token_id, "admin")
        .unwrap();
    assert!(matches!(
        store.resolve_broker_token(&hasher, &token.token),
        Err(ManagedStoreError::BrokerTokenPaused)
    ));
    assert!(store.resolve_username_identity("linux", "alice").is_ok());
    store.set_principal_enabled("alice", false).unwrap();
    assert!(store.resolve_username_identity("linux", "alice").is_err());
    assert!(store.resolve_broker_token(&hasher, &token.token).is_err());
}

#[test]
fn identity_proofs_reject_every_status_aba_and_reassignment() {
    for transition in [
        "set",
        "patch",
        "upsert",
        "pause",
        "binding",
        "recreate",
        "remap",
        "principal-reuse",
    ] {
        let (_temp, store) = identity_test_store();
        for principal in ["alice", "bob"] {
            store
                .create_principal(identity_user_request(principal))
                .unwrap();
        }
        let binding = store
            .create_username_binding("alice", "linux", "alice", "admin")
            .unwrap();
        let old = store
            .resolve_username_identity("linux", "alice")
            .unwrap()
            .proof;
        match transition {
            "set" => {
                store.set_principal_enabled("alice", false).unwrap();
                store.set_principal_enabled("alice", true).unwrap();
            }
            "patch" => {
                for status in ["disabled", "active"] {
                    store
                        .patch_principal(PrincipalPatchRequest {
                            principal_id: "alice".into(),
                            display_name: None,
                            email: None,
                            status: Some(status.into()),
                        })
                        .unwrap();
                }
            }
            "upsert" => {
                store.set_principal_enabled("alice", false).unwrap();
                store
                    .create_or_update_principal(identity_user_request("alice"))
                    .unwrap();
            }
            "pause" => {
                identity_test_pause(&store, "alice", true);
                identity_test_pause(&store, "alice", false);
            }
            "binding" => {
                store
                    .set_username_binding_enabled("alice", &binding.binding_id, false, 1, "admin")
                    .unwrap();
                store
                    .set_username_binding_enabled("alice", &binding.binding_id, true, 2, "admin")
                    .unwrap();
            }
            "recreate" => {
                store
                    .delete_username_binding("alice", &binding.binding_id, 1)
                    .unwrap();
                store
                    .create_username_binding("alice", "linux", "alice", "admin")
                    .unwrap();
            }
            "remap" => {
                store
                    .delete_username_binding("alice", &binding.binding_id, 1)
                    .unwrap();
                let bob = store
                    .create_username_binding("bob", "linux", "alice", "admin")
                    .unwrap();
                assert!(matches!(
                    store.revalidate_attested_identity(&old),
                    Err(ManagedStoreError::AttestedIdentityDenied)
                ));
                store
                    .delete_username_binding("bob", &bob.binding_id, 1)
                    .unwrap();
                store
                    .create_username_binding("alice", "linux", "alice", "admin")
                    .unwrap();
            }
            "principal-reuse" => {
                let incarnation = store.identity_access("alice").unwrap().incarnation;
                store
                    .connection
                    .lock()
                    .unwrap()
                    .execute("DELETE FROM principals WHERE principal_id='alice'", [])
                    .unwrap();
                store
                    .create_principal(identity_user_request("alice"))
                    .unwrap();
                store
                    .create_username_binding("alice", "linux", "alice", "admin")
                    .unwrap();
                assert_ne!(
                    store.identity_access("alice").unwrap().incarnation,
                    incarnation
                );
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                store.revalidate_attested_identity(&old),
                Err(ManagedStoreError::AttestedIdentityDenied)
            ),
            "{transition}"
        );
        let new = store
            .resolve_username_identity("linux", "alice")
            .unwrap()
            .proof;
        assert_ne!(old, new, "{transition}");
        assert_ne!(old.session_binding(), new.session_binding(), "{transition}");
        assert_eq!(
            store.batch_proof_current(&[old, new]).unwrap(),
            vec![false, true],
            "{transition}"
        );
    }
}

#[test]
fn identity_noop_and_profile_updates_preserve_proof_but_missing_gate_is_unavailable() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store
        .create_username_binding("alice", "linux", "alice", "admin")
        .unwrap();
    let proof = store
        .resolve_username_identity("linux", "alice")
        .unwrap()
        .proof;
    identity_test_pause(&store, "alice", false);
    store.set_principal_enabled("alice", true).unwrap();
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".into(),
            display_name: Some(Some("Alice Updated".into())),
            email: None,
            status: Some("active".into()),
        })
        .unwrap();
    store
        .create_or_update_principal(identity_user_request("alice"))
        .unwrap();
    assert!(store.revalidate_attested_identity(&proof).is_ok());
    assert!(matches!(
        store.set_identity_access_paused("alice", true, 0, "admin"),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    identity_test_pause(&store, "alice", true);
    assert!(matches!(
        store.set_identity_access_paused("alice", false, 1, "admin"),
        Err(ManagedStoreError::IdentityVersionConflict)
    ));
    identity_test_pause(&store, "alice", false);
    let proof = store
        .resolve_username_identity("linux", "alice")
        .unwrap()
        .proof;
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM principal_identity_access WHERE principal_id='alice'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.resolve_username_identity("linux", "alice"),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
    assert!(matches!(
        store.revalidate_attested_identity(&proof),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
    assert!(matches!(
        store.batch_proof_current(&[proof]),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
    assert!(store.check_ready(None).is_err());
    assert!(store.set_principal_enabled("alice", false).is_err());
    assert_eq!(
        store.principal("alice").unwrap().status,
        "active",
        "status mutation rolls back when gate is missing"
    );
}

#[test]
fn identity_human_kind_and_creation_invariants_are_transactional() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    for kind in ["system", "service_account"] {
        let mut request = identity_user_request(kind);
        request.kind = kind.into();
        request.self_service_enabled = Some(false);
        store.create_principal(request).unwrap();
        assert!(store.identity_access(kind).is_err());
        assert!(
            store
                .create_username_binding(kind, "linux", kind, "admin")
                .is_err()
        );
        assert!(
            store
                .create_or_update_principal(identity_user_request(kind))
                .is_err()
        );
        assert_eq!(store.principal(kind).unwrap().kind, kind);
        let mut request = identity_user_request("alice");
        request.kind = kind.into();
        request.self_service_enabled = Some(false);
        assert!(store.create_or_update_principal(request).is_err());
        assert_eq!(store.principal("alice").unwrap().kind, "user");
    }
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_identity_gate BEFORE INSERT ON principal_identity_access WHEN NEW.principal_id='rejected' BEGIN SELECT RAISE(ABORT, 'test gate failure'); END;").unwrap();
    assert!(
        store
            .create_principal(identity_user_request("rejected"))
            .is_err()
    );
    assert!(matches!(
        store.principal("rejected"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    assert!(
        store
            .create_or_update_principal(identity_user_request("rejected"))
            .is_err()
    );
    assert!(matches!(
        store.principal("rejected"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[test]
fn identity_revalidation_refreshes_membership_without_rebinding_identity() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store
        .create_username_binding("alice", "linux", "alice", "admin")
        .unwrap();
    let initial = store.resolve_username_identity("linux", "alice").unwrap();
    assert!(initial.policy_groups.is_empty());
    create_test_group(&store, "engineering");
    store.add_group("alice", "engineering", "admin").unwrap();
    let admitted = store.revalidate_attested_identity(&initial.proof).unwrap();
    assert_eq!(admitted.proof, initial.proof);
    assert_eq!(admitted.principal.groups, vec!["engineering"]);
    assert_eq!(admitted.policy_groups, vec!["engineering"]);
    store.remove_group("alice", "engineering").unwrap();
    assert!(
        store
            .revalidate_attested_identity(&initial.proof)
            .unwrap()
            .policy_groups
            .is_empty()
    );
}

#[test]
fn identity_paused_gate_survives_oidc_profile_upsert_and_allows_browser_login() {
    let (_temp, store) = identity_test_store();
    let provider = reconcile_test_oidc_provider(&store, true, 3_600, "identity-gate-oidc");
    create_test_group(&store, "engineering");
    store
        .create_external_group_binding(ExternalGroupBindingCreateRequest {
            external_group_id: TEST_EXTERNAL_GROUP_A.into(),
            group_id: "engineering".into(),
            actor: "admin".into(),
        })
        .unwrap();
    let hasher = broker_token_hasher_for_test(61);
    let first = store
        .complete_oidc_login(
            &hasher,
            test_oidc_completion_request(
                1,
                provider.config_generation,
                TEST_OIDC_USER,
                "oidc-identity-user",
                &[TEST_EXTERNAL_GROUP_A],
                &normalized_now_string(),
            ),
        )
        .unwrap();
    assert!(matches!(
        first,
        OidcCompletionOutcome::Succeeded {
            jit_created: true,
            ..
        }
    ));
    let gate = identity_test_pause(&store, "oidc-identity-user", true);
    assert_eq!(gate.version, 2);
    let second = store
        .complete_oidc_login(
            &hasher,
            test_oidc_completion_request(
                2,
                provider.config_generation,
                TEST_OIDC_USER,
                "unused-new-user",
                &[TEST_EXTERNAL_GROUP_A],
                &normalized_now_string(),
            ),
        )
        .unwrap();
    let OidcCompletionOutcome::Succeeded {
        result,
        jit_created,
    } = second
    else {
        panic!("paused attested identity must not disable independent browser sign-in");
    };
    assert!(!jit_created);
    assert_eq!(result.principal.principal_id, "oidc-identity-user");
    assert_eq!(store.identity_access("oidc-identity-user").unwrap(), gate);
    assert!(
        store
            .resolve_browser_session(&hasher, &result.session.token)
            .is_ok()
    );
    assert!(matches!(
        store.principal("unused-new-user"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[test]
fn identity_migration_preserves_encrypted_inventory_and_missing_or_removed_pause_state() {
    let (_fixture_dir, fixture) = identity_test_store();
    let ring = key_ring("k1");
    fixture.configure_identity_token_encryption(Some(ring.clone()));
    fixture
        .create_principal(identity_user_request("retained"))
        .unwrap();
    let token = fixture.reveal_identity_token("retained", &ring).unwrap();
    let inventory: (String, String, Vec<u8>, Vec<u8>, String) = fixture.connection.lock().unwrap().query_row(
        "SELECT fingerprint,key_id,nonce,ciphertext,updated_at FROM principal_identity_tokens WHERE principal_id='retained'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).unwrap();
    let temp = TempDir::new().unwrap();
    let config = store_config(&temp.path().join("previous.sqlite"));
    let previous = ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS
                .iter()
                .position(|m| m.version == MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION)
                .unwrap()],
        },
    )
    .unwrap();
    {
        let conn = previous.connection.lock().unwrap();
        for id in ["retained", "removed", "absent"] {
            conn.execute("INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled) VALUES(?1,'user','active',?2,?2,'admin','user',1)", params![id,normalized_now_string()]).unwrap();
        }
        conn.execute("INSERT INTO principal_identity_tokens(principal_id,fingerprint,key_id,nonce,ciphertext,paused,updated_at) VALUES('retained',?1,?2,?3,?4,1,?5)", params![inventory.0,inventory.1,inventory.2,inventory.3,inventory.4]).unwrap();
        conn.execute("INSERT INTO principal_identity_tokens(principal_id,paused,updated_at) VALUES('removed',1,?1)", [normalized_now_string()]).unwrap();
    }
    drop(previous);
    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    for (principal, paused) in [("retained", true), ("removed", true), ("absent", false)] {
        let access = store.identity_access(principal).unwrap();
        assert_eq!(access.paused, paused);
        assert_eq!(access.version, 1);
        assert_eq!(access.updated_by, "system:identity_access_migration");
        assert!(store.list_username_bindings(principal).unwrap().is_empty());
    }
    assert_eq!(
        store.reveal_identity_token("retained", &ring).unwrap(),
        token
    );
    let after: (String, String, Vec<u8>, Vec<u8>, String) = store.connection.lock().unwrap().query_row(
        "SELECT fingerprint,key_id,nonce,ciphertext,updated_at FROM principal_identity_tokens WHERE principal_id='retained'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).unwrap();
    assert_eq!(inventory, after);
    assert_eq!(
        store.identity_token_metadata("retained").unwrap().revision,
        Some(1)
    );
    assert_eq!(
        store.identity_token_metadata("removed").unwrap().revision,
        Some(1)
    );
    assert_eq!(
        store.identity_token_metadata("absent").unwrap().revision,
        None
    );
    assert!(
        !table_columns(
            &store.connection.lock().unwrap(),
            "principal_identity_tokens"
        )
        .contains(&"paused".to_string())
    );
    store.check_ready(Some(&ring)).unwrap();
    let incarnations: BTreeSet<_> = ["retained", "removed", "absent"]
        .iter()
        .map(|id| store.identity_access(id).unwrap().incarnation)
        .collect();
    assert_eq!(incarnations.len(), 3);
}

#[test]
fn identity_migration_rejects_prior_schema_drift_without_modification() {
    let schema = |conn: &Connection| {
        let mut statement = conn
            .prepare("SELECT type || ':' || name || ':' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let inventory = |conn: &Connection| {
        let mut statement = conn
            .prepare("SELECT * FROM principal_identity_tokens ORDER BY principal_id")
            .unwrap();
        let column_count = statement.column_count();
        statement
            .query_map([], |row| {
                (0..column_count)
                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    for (name, drift) in [
        (
            "extra-column",
            "ALTER TABLE principal_identity_tokens ADD COLUMN recovery_note TEXT;
             UPDATE principal_identity_tokens SET recovery_note='preserve this data';",
        ),
        (
            "extra-index",
            "CREATE INDEX unexpected_inventory_index ON principal_identity_tokens(updated_at);",
        ),
        (
            "extra-trigger",
            "CREATE TRIGGER unexpected_inventory_trigger AFTER UPDATE ON principal_identity_tokens BEGIN SELECT 1; END;",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(format!("{name}.sqlite"));
        let config = store_config(&path);
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS
                    .iter()
                    .position(|migration| {
                        migration.version == MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION
                    })
                    .unwrap()],
            },
        )
        .unwrap();
        let (before_schema, before_inventory) = {
            let conn = previous.connection.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
                 VALUES('retained','user','active','2026-01-01','2026-01-01','admin','user',1);
                 INSERT INTO principal_identity_tokens(principal_id,paused,updated_at)
                 VALUES('retained',1,'2026-01-01');",
            )
            .unwrap();
            conn.execute_batch(drift).unwrap();
            (schema(&conn), inventory(&conn))
        };
        drop(previous);
        let before_ledger = migration_rows(&path);
        let before_file = fs::read(&path).unwrap();

        let error = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap_err();
        assert!(
            matches!(error, ManagedStoreError::SchemaInvalid(_)),
            "{name}: {error}"
        );
        assert_eq!(fs::read(&path).unwrap(), before_file, "{name}");
        assert_eq!(migration_rows(&path), before_ledger, "{name}");
        let conn = Connection::open(&path).unwrap();
        assert_eq!(schema(&conn), before_schema, "{name}");
        assert_eq!(inventory(&conn), before_inventory, "{name}");
        assert!(!sqlite_object_exists(&conn, "table", "principal_identity_access").unwrap());
    }
}

#[test]
fn identity_failed_migration_restores_the_old_schema_and_ledger() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("previous.sqlite");
    let config = store_config(&path);
    let previous = ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS
                .iter()
                .position(|m| m.version == MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION)
                .unwrap()],
        },
    )
    .unwrap();
    previous.connection.lock().unwrap().execute_batch("INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled) VALUES('robot','service_account','active','2026-01-01','2026-01-01','admin','user',0);
        INSERT INTO principal_identity_tokens(principal_id,paused,updated_at) VALUES('robot',1,'2026-01-01');").unwrap();
    drop(previous);
    let ledger = migration_rows(&path);
    assert!(matches!(
        ManagedStore::open(&config, ManagedStoreOpenMode::Startup),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
    assert_eq!(migration_rows(&path), ledger);
    let conn = Connection::open(&path).unwrap();
    assert!(table_columns(&conn, "principal_identity_tokens").contains(&"paused".to_string()));
    assert!(!sqlite_object_exists(&conn, "table", "principal_identity_access").unwrap());
    assert!(
        conn.query_row(
            "SELECT paused FROM principal_identity_tokens WHERE principal_id='robot'",
            [],
            |row| row.get::<_, bool>(0)
        )
        .unwrap()
    );
}
