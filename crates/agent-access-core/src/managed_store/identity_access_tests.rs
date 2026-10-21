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

fn identity_test_enabled(enabled: bool) -> UsernameBindingUpdate {
    UsernameBindingUpdate {
        enabled: Some(enabled),
        read_only: None,
    }
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
    let inventory = store.identity_token_metadata("alice").unwrap();
    assert!(!inventory.configured);
    assert_eq!(inventory.revision, 1);
    for name in ["alice", "Alice", "1000", "anonymous"] {
        assert!(matches!(
            store.resolve_username_identity("linux", name),
            Err(ManagedStoreError::AttestedIdentityDenied)
        ));
    }
    let binding = store
        .create_username_binding("alice", "linux", "1000", false, "admin")
        .unwrap();
    store
        .create_username_binding("bob", "other-linux", "1000", false, "admin")
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
                .create_username_binding("alice", "linux", name, false, "admin")
                .is_err()
        );
        assert!(store.resolve_username_identity("linux", name).is_err());
    }
    assert!(
        store
            .create_username_binding("alice", "bad namespace", "alice", false, "admin")
            .is_err()
    );
    assert!(
        store
            .create_username_binding("alice", "linux", &"x".repeat(129), false, "admin")
            .is_err()
    );
    store
        .create_username_binding("alice", "linux", &"x".repeat(128), false, "admin")
        .unwrap();
    store
        .create_username_binding("alice", "linux", "Alice", false, "admin")
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
        .create_username_binding("alice", "linux", "alice", false, "admin")
        .unwrap();
    assert_eq!(binding.version, 1);
    for principal in ["alice", "bob"] {
        assert!(matches!(
            store.create_username_binding(principal, "linux", "alice", false, "admin"),
            Err(ManagedStoreError::IdentityBindingConflict)
        ));
    }
    assert!(matches!(
        store.update_username_binding(
            "bob",
            &binding.binding_id,
            identity_test_enabled(false),
            1,
            "admin"
        ),
        Err(ManagedStoreError::IdentityBindingNotFound)
    ));
    assert!(matches!(
        store.delete_username_binding("bob", &binding.binding_id, 1),
        Err(ManagedStoreError::IdentityBindingNotFound)
    ));
    let (_, same) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_enabled(true),
            1,
            "admin",
        )
        .unwrap();
    assert_eq!(same, binding);
    let (_, disabled) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_enabled(false),
            1,
            "admin",
        )
        .unwrap();
    assert_eq!(disabled.version, 2);
    assert!(!disabled.enabled);
    assert!(matches!(
        store.create_username_binding("bob", "linux", "alice", false, "admin"),
        Err(ManagedStoreError::IdentityBindingConflict)
    ));
    for result in [
        store
            .update_username_binding(
                "alice",
                &binding.binding_id,
                identity_test_enabled(true),
                1,
                "admin",
            )
            .map(|(_, after)| after),
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
        .create_username_binding("bob", "linux", "alice", false, "admin")
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
        .create_username_binding("alice", "linux", "alice", false, "admin")
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
    // Creation wrote the generated secret into the row the trigger made.
    assert_eq!(store.identity_token_metadata("alice").unwrap().revision, 2);
    assert_eq!(store.remove_identity_token("alice").unwrap().revision, 3);
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
        4
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
        .create_username_binding("alice", "linux", "alice", false, "admin")
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
        "read-only",
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
            .create_username_binding("alice", "linux", "alice", false, "admin")
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
                    .update_username_binding(
                        "alice",
                        &binding.binding_id,
                        identity_test_enabled(false),
                        1,
                        "admin",
                    )
                    .unwrap();
                store
                    .update_username_binding(
                        "alice",
                        &binding.binding_id,
                        identity_test_enabled(true),
                        2,
                        "admin",
                    )
                    .unwrap();
            }
            "read-only" => {
                for (read_only, version) in [(true, 1), (false, 2)] {
                    store
                        .update_username_binding(
                            "alice",
                            &binding.binding_id,
                            UsernameBindingUpdate {
                                enabled: None,
                                read_only: Some(read_only),
                            },
                            version,
                            "admin",
                        )
                        .unwrap();
                }
            }
            "recreate" => {
                store
                    .delete_username_binding("alice", &binding.binding_id, 1)
                    .unwrap();
                store
                    .create_username_binding("alice", "linux", "alice", false, "admin")
                    .unwrap();
            }
            "remap" => {
                store
                    .delete_username_binding("alice", &binding.binding_id, 1)
                    .unwrap();
                let bob = store
                    .create_username_binding("bob", "linux", "alice", false, "admin")
                    .unwrap();
                assert!(matches!(
                    store.revalidate_attested_identity(&old),
                    Err(ManagedStoreError::AttestedIdentityDenied)
                ));
                store
                    .delete_username_binding("bob", &bob.binding_id, 1)
                    .unwrap();
                store
                    .create_username_binding("alice", "linux", "alice", false, "admin")
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
                    .create_username_binding("alice", "linux", "alice", false, "admin")
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
        .create_username_binding("alice", "linux", "alice", false, "admin")
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
                .create_username_binding(kind, "linux", kind, false, "admin")
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
        .create_username_binding("alice", "linux", "alice", false, "admin")
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
    for principal in ["retained", "removed", "absent"] {
        assert_eq!(
            store.identity_token_metadata(principal).unwrap().revision,
            1
        );
    }
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

fn identity_test_catalog_through(version: &str) -> ManagedStoreMigrationCatalog<'static> {
    let end = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| migration.version == version)
        .unwrap();
    ManagedStoreMigrationCatalog {
        migrations: &MANAGED_STORE_MIGRATIONS[..=end],
    }
}

fn identity_test_read_only(read_only: bool) -> UsernameBindingUpdate {
    UsernameBindingUpdate {
        enabled: None,
        read_only: Some(read_only),
    }
}

fn identity_test_token_settings(
    enabled: Option<bool>,
    read_only: Option<bool>,
) -> IdentityTokenSettingsUpdate {
    IdentityTokenSettingsUpdate { enabled, read_only }
}

type IdentityTestSecret = (
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn identity_test_secret(conn: &Connection, principal: &str) -> IdentityTestSecret {
    conn.query_row(
        "SELECT fingerprint, key_id, nonce, ciphertext FROM principal_identity_tokens
         WHERE principal_id=?1",
        [principal],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .unwrap()
}

fn identity_test_token_rows(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare("SELECT principal_id FROM principal_identity_tokens ORDER BY principal_id")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn identity_test_missing_row<T>(result: Result<T, ManagedStoreError>) -> bool {
    matches!(result, Err(ManagedStoreError::SchemaInvalid(ref message)) if message == "human identity token inventory is missing")
}

/// Stores at 026, 027 and 028 admit humans without identity-token rows.
/// Migration 029 gives each exactly one, keeping existing secrets and
/// revisions, with the path settings defaulting to enabled and not read-only.
#[test]
fn identity_path_controls_migration_backfills_one_token_row_per_human() {
    let (_fixture_dir, fixture) = identity_test_store();
    let ring = key_ring("k1");
    fixture.configure_identity_token_encryption(Some(ring.clone()));
    fixture
        .create_principal(identity_user_request("configured"))
        .unwrap();
    let token = fixture.reveal_identity_token("configured", &ring).unwrap();
    let fingerprint = format!("sha256:{}", sha256_hex(token.as_bytes()));
    let secret = identity_test_secret(&fixture.connection.lock().unwrap(), "configured");
    for version in [
        MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION,
        MANAGED_STORE_COMMAND_IMPORTS_VERSION,
        MANAGED_STORE_OAUTH_REVOCATIONS_VERSION,
    ] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("previous.sqlite");
        let config = store_config(&path);
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            identity_test_catalog_through(version),
        )
        .unwrap();
        let binding_id = Uuid::new_v4().to_string();
        {
            let conn = previous.connection.lock().unwrap();
            for (principal, kind, updated_at) in [
                ("configured", "user", "2026-01-01T00:00:00Z"),
                ("removed", "user", "2026-01-02T00:00:00Z"),
                ("absent", "user", "2026-01-03T00:00:00Z"),
                ("robot", "service_account", "2026-01-04T00:00:00Z"),
            ] {
                conn.execute(
                    "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
                     VALUES(?1,?2,'active',?3,?3,'admin','user',?4)",
                    params![principal, kind, updated_at, kind == "user"],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO principal_identity_tokens(principal_id,fingerprint,key_id,nonce,ciphertext,revision,updated_at)
                 VALUES('configured',?1,?2,?3,?4,3,'2026-01-05T00:00:00Z')",
                params![secret.0, secret.1, secret.2, secret.3],
            )
            .unwrap();
            conn.execute_batch(
                "INSERT INTO principal_identity_tokens(principal_id,revision,updated_at)
                 VALUES('removed',2,'2026-01-06T00:00:00Z');",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO principal_username_bindings
                 (binding_id,principal_id,namespace,username,enabled,version,created_at,created_by,updated_at,updated_by)
                 VALUES(?1,'absent','linux','absent',0,4,'2026-01-03T00:00:00Z','admin','2026-01-03T00:00:00Z','admin')",
                [&binding_id],
            )
            .unwrap();
            // The historical validator accepts humans without rows; only the
            // new invariant rejects them.
            let migration = MANAGED_STORE_MIGRATIONS
                .iter()
                .find(|migration| migration.version == version)
                .unwrap();
            (migration.structural_validation)(&conn).unwrap();
            identity_access::check_integrity(&conn).unwrap();
            assert!(identity_test_missing_row(
                identity_access::check_identity_token_rows(&conn)
            ));
        }
        drop(previous);
        drop(
            ManagedStore::open_with_catalog(
                &config,
                ManagedStoreOpenMode::Reload,
                identity_test_catalog_through(version),
            )
            .unwrap(),
        );
        let ledger = migration_rows(&path);

        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(
            store.migration_applied_this_open(MANAGED_STORE_IDENTITY_ACCESS_PATH_CONTROLS_VERSION),
            "{version}"
        );
        let upgraded = migration_rows(&path);
        assert_eq!(upgraded[..ledger.len()], ledger[..], "{version}");
        assert_eq!(upgraded.len(), MANAGED_STORE_MIGRATIONS.len(), "{version}");
        let identity_path_migration = upgraded.iter().find(|row|
            row.0 == MANAGED_STORE_IDENTITY_ACCESS_PATH_CONTROLS_VERSION).unwrap();
        assert_eq!(
            (
                identity_path_migration.0.as_str(),
                identity_path_migration.1.as_str()
            ),
            (
                MANAGED_STORE_IDENTITY_ACCESS_PATH_CONTROLS_VERSION,
                sha256_hex(include_str!("identity_access_path_controls.sql").as_bytes()).as_str()
            ),
            "{version}"
        );
        assert_eq!(
            identity_test_token_rows(&store.connection.lock().unwrap()),
            ["absent", "configured", "removed"],
            "{version}"
        );
        for (principal, configured, revision, updated_at) in [
            ("configured", true, 3, "2026-01-05T00:00:00Z"),
            ("removed", false, 2, "2026-01-06T00:00:00Z"),
            ("absent", false, 1, "2026-01-03T00:00:00Z"),
        ] {
            assert_eq!(
                store.identity_token_metadata(principal).unwrap(),
                IdentityTokenMetadata {
                    principal_id: principal.into(),
                    configured,
                    enabled: true,
                    read_only: false,
                    revision,
                    updated_at: updated_at.into(),
                },
                "{version}"
            );
        }
        assert_eq!(
            identity_test_secret(&store.connection.lock().unwrap(), "configured"),
            secret,
            "{version}"
        );
        assert_eq!(
            store.reveal_identity_token("configured", &ring).unwrap(),
            token
        );
        let binding = store
            .list_username_bindings("absent")
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(binding.binding_id, binding_id);
        assert!(!binding.enabled && !binding.read_only, "{version}");
        assert_eq!(binding.version, 4, "{version}");
        store.check_ready(Some(&ring)).unwrap();
        let resolved = store
            .resolve_identity_fingerprint_with_proof(&fingerprint)
            .unwrap();
        assert_eq!(resolved.principal.principal_id, "configured");
        assert!(!resolved.read_only());
        drop(store);
        drop(ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap());
    }
}

#[test]
fn identity_latest_readiness_and_admission_reject_a_missing_token_row() {
    let (temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    store.check_ready(None).unwrap();
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM principal_identity_tokens WHERE principal_id='alice'",
            [],
        )
        .unwrap();
    assert!(identity_test_missing_row(store.check_ready(None)));
    {
        let conn = store.connection.lock().unwrap();
        identity_access::check_integrity(&conn).unwrap();
        let validate_latest = production_migration_catalog().latest().unwrap().structural_validation;
        assert!(identity_test_missing_row(validate_latest(&conn)));
    }
    drop(store);
    let config = store_config(&temp.path().join("store.sqlite"));
    for mode in [ManagedStoreOpenMode::Startup, ManagedStoreOpenMode::Reload] {
        assert!(identity_test_missing_row(ManagedStore::open(&config, mode)));
    }
}

/// Every operation needs the row; none of them recreates or repairs it.
#[test]
fn identity_token_operations_fail_on_a_missing_row_without_recreating_it() {
    let (_temp, store) = identity_test_store();
    let ring = key_ring("k1");
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    let rows = |store: &ManagedStore| identity_test_token_rows(&store.connection.lock().unwrap());
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM principal_identity_tokens WHERE principal_id='alice'",
            [],
        )
        .unwrap();
    let token = Uuid::new_v4().to_string();
    assert!(identity_test_missing_row(
        store.identity_token_metadata("alice")
    ));
    assert!(identity_test_missing_row(
        store.set_identity_token("alice", &token, &ring)
    ));
    assert!(identity_test_missing_row(store.set_identity_token(
        "alice",
        &Uuid::new_v4().to_string(),
        &ring
    )));
    assert!(identity_test_missing_row(
        store.remove_identity_token("alice")
    ));
    for update in [
        identity_test_token_settings(Some(false), None),
        identity_test_token_settings(None, Some(true)),
        identity_test_token_settings(Some(true), Some(false)),
    ] {
        assert!(identity_test_missing_row(
            store.update_identity_token_settings("alice", update, 1)
        ));
    }
    assert!(matches!(
        store.resolve_identity_fingerprint_with_proof(&format!(
            "sha256:{}",
            sha256_hex(token.as_bytes())
        )),
        Err(ManagedStoreError::AttestedIdentityDenied)
    ));
    assert!(rows(&store).is_empty());

    // Initialization completes the trigger-created row and never inserts one.
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER principal_identity_tokens_on_user_create;")
        .unwrap();
    for configured_ring in [None, Some(ring.clone())] {
        store.configure_identity_token_encryption(configured_ring);
        assert!(identity_test_missing_row(
            store.create_principal(identity_user_request("bob"))
        ));
        assert!(identity_test_missing_row(
            store.create_or_update_principal(identity_user_request("bob"))
        ));
        assert!(matches!(
            store.principal("bob"),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
        assert!(rows(&store).is_empty());
    }
}

/// Every human creation path gets its row in the creating transaction: a
/// not-configured one without a key ring, and with one the generated secret
/// written into it.
#[test]
fn identity_token_rows_follow_every_human_creation_path() {
    for with_ring in [false, true] {
        let (_temp, store) = identity_test_store();
        let ring = key_ring("k1");
        if with_ring {
            store.configure_identity_token_encryption(Some(ring.clone()));
        }
        // Bootstrap admits only an empty store.
        store
            .bootstrap_initial_admin(
                &local_password_hasher_for_test(71),
                InitialAdminBootstrapRequest {
                    principal_id: "bootstrap".into(),
                    password: "initial-admin-password".into(),
                    min_password_length: 8,
                },
            )
            .unwrap();
        store
            .create_principal(identity_user_request("created"))
            .unwrap();
        store
            .create_or_update_principal(identity_user_request("upserted"))
            .unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3_600, "identity-token-oidc");
        create_test_group(&store, "engineering");
        store
            .create_external_group_binding(ExternalGroupBindingCreateRequest {
                external_group_id: TEST_EXTERNAL_GROUP_A.into(),
                group_id: "engineering".into(),
                actor: "admin".into(),
            })
            .unwrap();
        assert!(matches!(
            store
                .complete_oidc_login(
                    &broker_token_hasher_for_test(72),
                    test_oidc_completion_request(
                        1,
                        provider.config_generation,
                        TEST_OIDC_USER,
                        "oidc-user",
                        &[TEST_EXTERNAL_GROUP_A],
                        &normalized_now_string(),
                    ),
                )
                .unwrap(),
            OidcCompletionOutcome::Succeeded {
                jit_created: true,
                ..
            }
        ));
        // A direct insert, as by any future path, gets its row from the trigger.
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
                 VALUES('direct','user','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','user',1);",
            )
            .unwrap();
        let mut robot = identity_user_request("robot");
        robot.kind = "service_account".into();
        robot.self_service_enabled = Some(false);
        store.create_principal(robot).unwrap();
        let humans = ["bootstrap", "created", "direct", "oidc-user", "upserted"];
        assert_eq!(
            identity_test_token_rows(&store.connection.lock().unwrap()),
            humans
        );
        for principal in humans {
            let metadata = store.identity_token_metadata(principal).unwrap();
            let generated = with_ring && principal != "direct";
            assert_eq!(metadata.configured, generated, "{principal}");
            assert!(metadata.enabled && !metadata.read_only, "{principal}");
            // Initialization writes the secret with the same checked update as
            // every secret write, so it advances the trigger's first revision.
            assert_eq!(
                metadata.revision,
                if generated { 2 } else { 1 },
                "{principal}"
            );
            if generated {
                let token = store.reveal_identity_token(principal, &ring).unwrap();
                assert_eq!(
                    store
                        .resolve_identity_fingerprint(&format!(
                            "sha256:{}",
                            sha256_hex(token.as_bytes())
                        ))
                        .unwrap()
                        .0
                        .principal_id,
                    principal
                );
            }
        }
        assert!(store.identity_token_metadata("robot").is_err());
        let conn = store.connection.lock().unwrap();
        assert!(
            conn.execute(
                "INSERT INTO principal_identity_tokens(principal_id,revision,updated_at)
                 VALUES('robot',1,'2026-01-01T00:00:00Z')",
                [],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO principal_identity_tokens(principal_id,revision,updated_at)
                 VALUES('direct',1,'2026-01-01T00:00:00Z')",
                [],
            )
            .is_err(),
            "one row per human"
        );
        identity_access::check_identity_token_rows(&conn).unwrap();
    }
}

#[test]
fn identity_token_settings_survive_secret_writes_and_advance_one_revision() {
    let (_temp, store) = identity_test_store();
    let ring = key_ring("k1");
    store.configure_identity_token_encryption(Some(ring.clone()));
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    let initial = store.identity_token_metadata("alice").unwrap();
    assert!(initial.configured && initial.enabled && !initial.read_only);
    for (update, revision) in [
        (IdentityTokenSettingsUpdate::default(), initial.revision),
        (identity_test_token_settings(Some(false), None), 0),
    ] {
        assert!(matches!(
            store.update_identity_token_settings("alice", update, revision),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
    assert!(matches!(
        store.update_identity_token_settings(
            "alice",
            identity_test_token_settings(None, Some(true)),
            initial.revision + 1
        ),
        Err(ManagedStoreError::IdentityVersionConflict)
    ));
    let mut robot = identity_user_request("robot");
    robot.kind = "service_account".into();
    robot.self_service_enabled = Some(false);
    store.create_principal(robot).unwrap();
    assert!(
        store
            .update_identity_token_settings(
                "robot",
                identity_test_token_settings(Some(false), None),
                1
            )
            .is_err()
    );

    // A no-op writes nothing.
    assert_eq!(
        store
            .update_identity_token_settings(
                "alice",
                identity_test_token_settings(Some(true), Some(false)),
                initial.revision
            )
            .unwrap(),
        (initial.clone(), initial.clone())
    );
    assert_eq!(store.identity_token_metadata("alice").unwrap(), initial);

    let (before, read_only) = store
        .update_identity_token_settings(
            "alice",
            identity_test_token_settings(None, Some(true)),
            initial.revision,
        )
        .unwrap();
    assert_eq!(before, initial);
    assert!(read_only.enabled && read_only.read_only && read_only.configured);
    assert_eq!(read_only.revision, initial.revision + 1);
    let (before, disabled) = store
        .update_identity_token_settings(
            "alice",
            identity_test_token_settings(Some(false), None),
            read_only.revision,
        )
        .unwrap();
    assert_eq!(before, read_only);
    assert!(!disabled.enabled && disabled.read_only);
    assert_eq!(disabled.revision, read_only.revision + 1);
    let (before, both) = store
        .update_identity_token_settings(
            "alice",
            identity_test_token_settings(Some(true), Some(false)),
            disabled.revision,
        )
        .unwrap();
    assert_eq!(before, disabled);
    assert!(both.enabled && !both.read_only);
    assert_eq!(
        both.revision,
        disabled.revision + 1,
        "one revision per change"
    );
    let (_, settings) = store
        .update_identity_token_settings(
            "alice",
            identity_test_token_settings(Some(false), Some(true)),
            both.revision,
        )
        .unwrap();

    // Secret writes keep both settings and keep the revision monotonic, and
    // they work while the token is disabled.
    let mut revision = settings.revision;
    let replacement = Uuid::new_v4().to_string();
    for step in ["set", "generate", "remove", "remove", "set"] {
        let metadata = match step {
            "set" => store.set_identity_token("alice", &replacement, &ring),
            "generate" => store.set_identity_token("alice", &Uuid::new_v4().to_string(), &ring),
            _ => store.remove_identity_token("alice"),
        }
        .unwrap();
        assert_eq!(metadata.configured, step != "remove", "{step}");
        assert!(!metadata.enabled && metadata.read_only, "{step}");
        assert_eq!(metadata.revision, revision + 1, "{step}");
        revision = metadata.revision;
    }
    assert_eq!(
        store.reveal_identity_token("alice", &ring).unwrap(),
        replacement
    );
    assert!(matches!(
        store.update_identity_token_settings(
            "alice",
            identity_test_token_settings(Some(true), None),
            settings.revision
        ),
        Err(ManagedStoreError::IdentityVersionConflict)
    ));
    let value = serde_json::to_value(store.identity_token_metadata("alice").unwrap()).unwrap();
    assert_eq!(
        value,
        json!({"principalId":"alice","configured":true,"enabled":false,"readOnly":true,
            "revision":revision,"updatedAt":value["updatedAt"]})
    );
    assert!(value["updatedAt"].is_string());
}

#[test]
fn identity_binding_update_applies_settings_with_one_version() {
    let (_temp, store) = identity_test_store();
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    let binding = store
        .create_username_binding("alice", "linux", "alice", false, "admin")
        .unwrap();
    assert!(binding.enabled && !binding.read_only);
    let reader = store
        .create_username_binding("alice", "linux", "reader", true, "admin")
        .unwrap();
    assert!(reader.enabled && reader.read_only);
    assert_eq!(reader.version, 1);
    let resolved = store.resolve_username_identity("linux", "reader").unwrap();
    assert!(resolved.read_only() && resolved.proof.read_only());
    assert!(
        !store
            .resolve_username_identity("linux", "alice")
            .unwrap()
            .read_only()
    );

    assert!(matches!(
        store.update_username_binding(
            "alice",
            &binding.binding_id,
            UsernameBindingUpdate::default(),
            1,
            "admin"
        ),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    assert!(matches!(
        store.update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_read_only(true),
            2,
            "admin"
        ),
        Err(ManagedStoreError::IdentityVersionConflict)
    ));
    let both = |enabled, read_only| UsernameBindingUpdate {
        enabled: Some(enabled),
        read_only: Some(read_only),
    };
    assert_eq!(
        store
            .update_username_binding("alice", &binding.binding_id, both(true, false), 1, "other")
            .unwrap(),
        (binding.clone(), binding.clone()),
        "a no-op writes nothing"
    );

    let (before, read_only) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_read_only(true),
            1,
            "second-admin",
        )
        .unwrap();
    assert_eq!(before, binding);
    assert!(read_only.enabled && read_only.read_only);
    assert_eq!(read_only.version, 2);
    assert_eq!(read_only.updated_by, "second-admin");
    let (before, disabled) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_enabled(false),
            2,
            "admin",
        )
        .unwrap();
    assert_eq!(before, read_only);
    assert!(!disabled.enabled && disabled.read_only);
    assert_eq!(disabled.version, 3);
    let (before, restored) = store
        .update_username_binding("alice", &binding.binding_id, both(true, false), 3, "admin")
        .unwrap();
    assert_eq!(before, disabled);
    assert!(restored.enabled && !restored.read_only);
    assert_eq!(restored.version, 4, "one version per change");
    assert_eq!(
        store.list_username_bindings("alice").unwrap(),
        vec![restored.clone(), reader]
    );
    let value = serde_json::to_value(&restored).unwrap();
    assert_eq!(value["readOnly"], false);
    assert!(value.get("read_only").is_none());
}

/// A setting change on one path ends that path's proofs, even when the value
/// is later restored, and leaves the other path's proofs current.
#[test]
fn identity_path_settings_fence_only_their_own_path_proofs() {
    let (_temp, store) = identity_test_store();
    let ring = key_ring("k1");
    store.configure_identity_token_encryption(Some(ring.clone()));
    store
        .create_principal(identity_user_request("alice"))
        .unwrap();
    let binding = store
        .create_username_binding("alice", "linux", "alice", false, "admin")
        .unwrap();
    let token = store.reveal_identity_token("alice", &ring).unwrap();
    let fingerprint = format!("sha256:{}", sha256_hex(token.as_bytes()));
    let username = || {
        store
            .resolve_username_identity("linux", "alice")
            .unwrap()
            .proof
    };
    let fingerprint_proof = || {
        store
            .resolve_identity_fingerprint_with_proof(&fingerprint)
            .unwrap()
            .proof
    };
    let settings = |enabled, read_only| {
        let revision = store.identity_token_metadata("alice").unwrap().revision;
        store
            .update_identity_token_settings(
                "alice",
                identity_test_token_settings(enabled, read_only),
                revision,
            )
            .unwrap()
            .1
    };
    let current = |proofs: &[&AttestedIdentityProof]| {
        store
            .batch_proof_current(
                &proofs
                    .iter()
                    .map(|proof| (*proof).clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap()
    };

    // Token read-only, then back (A-B-A).
    let user = username();
    let full = fingerprint_proof();
    assert!(!full.read_only() && !user.read_only());
    settings(None, Some(true));
    let read_only = fingerprint_proof();
    assert!(read_only.read_only());
    assert_ne!(read_only, full);
    assert_ne!(read_only.session_binding(), full.session_binding());
    assert!(matches!(
        store.revalidate_attested_identity(&full),
        Err(ManagedStoreError::AttestedIdentityDenied)
    ));
    assert_eq!(
        store.revalidate_attested_identity(&user).unwrap().proof,
        user
    );
    settings(None, Some(false));
    let restored = fingerprint_proof();
    assert!(!restored.read_only());
    assert_eq!(
        current(&[&full, &read_only, &restored, &user]),
        [false, false, true, true],
        "A-B-A token settings cannot restore a proof"
    );
    settings(Some(true), Some(false));
    assert_eq!(
        current(&[&restored, &user]),
        [true, true],
        "a no-op ends nothing"
    );

    // A disabled token resolves like an unknown fingerprint and keeps its
    // secret; re-enabling restores resolution with the same secret.
    let disabled = settings(Some(false), None);
    assert!(!disabled.enabled && disabled.configured);
    assert!(matches!(
        store.resolve_identity_fingerprint_with_proof(&fingerprint),
        Err(ManagedStoreError::AttestedIdentityDenied)
    ));
    assert!(matches!(
        store.revalidate_attested_identity(&restored),
        Err(ManagedStoreError::AttestedIdentityDenied)
    ));
    assert_eq!(current(&[&restored, &user]), [false, true]);
    assert_eq!(store.reveal_identity_token("alice", &ring).unwrap(), token);
    settings(Some(true), None);
    let reenabled = fingerprint_proof();
    assert!(reenabled.matches_fingerprint(&fingerprint));
    assert!(store.revalidate_attested_identity(&restored).is_err());
    assert_eq!(
        store
            .revalidate_attested_identity(&reenabled)
            .unwrap()
            .proof,
        reenabled
    );
    assert_eq!(
        current(&[&user]),
        [true],
        "token settings leave username proofs"
    );

    // Binding read-only, then back (A-B-A).
    let (_, read_only_binding) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_read_only(true),
            binding.version,
            "admin",
        )
        .unwrap();
    let read_only_user = store.resolve_username_identity("linux", "alice").unwrap();
    assert!(read_only_user.read_only());
    assert_ne!(
        read_only_user.proof.session_binding(),
        user.session_binding()
    );
    assert!(matches!(
        store.revalidate_attested_identity(&user),
        Err(ManagedStoreError::AttestedIdentityDenied)
    ));
    assert_eq!(
        store
            .revalidate_attested_identity(&reenabled)
            .unwrap()
            .proof,
        reenabled,
        "binding settings leave fingerprint proofs"
    );
    let (_, restored_binding) = store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            identity_test_read_only(false),
            read_only_binding.version,
            "admin",
        )
        .unwrap();
    let restored_user = username();
    assert!(!restored_user.read_only());
    assert_eq!(
        current(&[&user, &read_only_user.proof, &restored_user, &reenabled]),
        [false, false, true, true],
        "A-B-A binding settings cannot restore a proof"
    );
    store
        .update_username_binding(
            "alice",
            &binding.binding_id,
            UsernameBindingUpdate {
                enabled: Some(true),
                read_only: Some(false),
            },
            restored_binding.version,
            "admin",
        )
        .unwrap();
    assert_eq!(
        current(&[&restored_user, &reenabled]),
        [true, true],
        "a no-op ends nothing"
    );
}

#[test]
fn identity_path_controls_migration_rejects_prior_schema_drift_without_modification() {
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
    for (name, drift) in [
        (
            "binding-column",
            "ALTER TABLE principal_username_bindings ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0;",
        ),
        (
            "inventory-column",
            "ALTER TABLE principal_identity_tokens ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;",
        ),
        (
            "inventory-trigger",
            "CREATE TRIGGER principal_identity_tokens_require_human BEFORE INSERT ON principal_identity_tokens BEGIN SELECT 1; END;",
        ),
        (
            "non-human-inventory",
            "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
             VALUES('robot','service_account','active','2026-01-01','2026-01-01','admin','user',0);
             INSERT INTO principal_identity_tokens(principal_id,revision,updated_at) VALUES('robot',1,'2026-01-01');",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(format!("{name}.sqlite"));
        let config = store_config(&path);
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            identity_test_catalog_through(MANAGED_STORE_OAUTH_REVOCATIONS_VERSION),
        )
        .unwrap();
        let before_schema = {
            let conn = previous.connection.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
                 VALUES('absent','user','active','2026-01-01','2026-01-01','admin','user',1);",
            )
            .unwrap();
            conn.execute_batch(drift).unwrap();
            schema(&conn)
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
        assert!(
            !identity_test_token_rows(&conn).contains(&"absent".to_string()),
            "{name}"
        );
    }
}

fn identity_test_rejected_validation(_: &Connection) -> Result<(), ManagedStoreError> {
    Err(ManagedStoreError::SchemaInvalid(
        "injected validation failure".into(),
    ))
}

/// A failed migration leaves the 028 store as it was; once migrated, an older
/// binary refuses the newer ledger, so rollback needs the pre-migration backup.
#[test]
fn identity_path_controls_failed_migration_restores_the_old_schema_and_ledger() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("previous.sqlite");
    let config = store_config(&path);
    let previous = ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(MANAGED_STORE_OAUTH_REVOCATIONS_VERSION),
    )
    .unwrap();
    previous
        .connection
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
             VALUES('absent','user','active','2026-01-01','2026-01-01','admin','user',1);",
        )
        .unwrap();
    drop(previous);
    let ledger = migration_rows(&path);
    let mut failing = identity_test_catalog_through(MANAGED_STORE_IDENTITY_ACCESS_PATH_CONTROLS_VERSION)
        .migrations
        .to_vec();
    failing.last_mut().unwrap().structural_validation = identity_test_rejected_validation;
    assert!(matches!(
        ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &failing,
            },
        ),
        Err(ManagedStoreError::SchemaInvalid(ref message)) if message == "injected validation failure"
    ));
    assert_eq!(migration_rows(&path), ledger);
    {
        let conn = Connection::open(&path).unwrap();
        assert!(!table_columns(&conn, "principal_username_bindings").contains(&"read_only".into()));
        assert!(!table_columns(&conn, "principal_identity_tokens").contains(&"enabled".into()));
        assert!(
            !sqlite_object_exists(&conn, "trigger", "principal_identity_tokens_on_user_create")
                .unwrap()
        );
        assert!(identity_test_token_rows(&conn).is_empty());
    }

    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    assert_eq!(
        identity_test_token_rows(&store.connection.lock().unwrap()),
        ["absent"]
    );
    drop(store);
    let migrated = fs::read(&path).unwrap();
    let error = ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(MANAGED_STORE_OAUTH_REVOCATIONS_VERSION),
    )
    .unwrap_err();
    assert!(
        matches!(error, ManagedStoreError::SchemaInvalid(ref message) if message.contains("newer than this broker supports")),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), migrated);
}
