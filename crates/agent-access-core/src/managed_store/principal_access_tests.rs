fn access_principal(
    store: &ManagedStore,
    id: &str,
    kind: &str,
    role: PrincipalRole,
    self_service_enabled: Option<bool>,
) -> Result<PrincipalRecord, ManagedStoreError> {
    store.create_principal(PrincipalWriteRequest {
        principal_id: id.into(),
        kind: kind.into(),
        role,
        self_service_enabled,
        display_name: None,
        email: None,
        external_subject: None,
        created_by: "test".into(),
    })
}
fn access_patch(
    store: &ManagedStore,
    id: &str,
    role: Option<PrincipalRole>,
    enabled: Option<bool>,
) -> Result<PrincipalAccessChange, ManagedStoreError> {
    store.patch_principal_access(PrincipalAccessPatchRequest {
        principal_id: id.into(),
        role,
        self_service_enabled: enabled,
        actor: "test".into(),
    })
}
fn access_token(
    store: &ManagedStore,
    id: &str,
    class: BrokerTokenClass,
) -> Result<IssuedBrokerToken, ManagedStoreError> {
    let scopes = if class == BrokerTokenClass::AgentInvoke {
        json!({"allowedExecutionContexts":["default"]})
    } else {
        json!({})
    };
    store.issue_broker_token(
        &broker_token_hasher_for_test(9),
        BrokerTokenIssueRequest {
            principal_id: id.into(),
            name: "test".into(),
            token_class: class,
            scopes,
            expires_at: None,
            created_by: "test".into(),
        },
    )
}
#[test]
fn principal_access_roles_and_personal_permission_are_independent() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for role in [
        PrincipalRole::User,
        PrincipalRole::Auditor,
        PrincipalRole::ServicePolicyManager,
        PrincipalRole::Admin,
    ] {
        for enabled in [false, true] {
            let id = format!("{}-{enabled}", role.as_str());
            access_principal(&store, &id, "user", role, Some(enabled)).unwrap();
            if role == PrincipalRole::ServicePolicyManager {
                for service in ["jira", "confluence"] {
                    store
                        .put_service_policy_management_assignment(
                            ServicePolicyManagementAssignmentPutRequest {
                                service: service.into(),
                                principal_id: id.clone(),
                                created_by: "test".into(),
                            },
                        )
                        .unwrap();
                }
            }
            let authority = store.management_authority(&id).unwrap();
            assert_eq!(authority.principal.role, role);
            assert_eq!(authority.principal.self_service_enabled, enabled);
            assert_eq!(
                matches!(authority.policy_read_scope, PolicyReadScope::Global),
                role.can_read_admin()
            );
            assert_eq!(
                matches!(authority.policy_write_scope, PolicyWriteScope::Global),
                role == PrincipalRole::Admin
            );
            assert_eq!(
                authority.policy_write_scope.authorizes_service("jira"),
                matches!(
                    role,
                    PrincipalRole::Admin | PrincipalRole::ServicePolicyManager
                )
            );
            assert_eq!(
                authority.policy_write_scope.authorizes_service("other"),
                role == PrincipalRole::Admin
            );
            let value = serde_json::to_value(&authority.principal).unwrap();
            assert_eq!(value["role"], role.as_str());
            assert_eq!(value["selfServiceEnabled"], enabled);
            assert!(value.get("roles").is_none());
            assert!(value.get("isAdmin").is_none());
        }
    }
    assert!(
        access_principal(
            &store,
            "system",
            "system",
            PrincipalRole::ServicePolicyManager,
            None
        )
        .unwrap()
        .self_service_enabled
    );
    assert!(
        !access_principal(
            &store,
            "service",
            "service_account",
            PrincipalRole::User,
            None
        )
        .unwrap()
        .self_service_enabled
    );
    for kind in ["system", "service_account"] {
        assert!(matches!(
            access_principal(
                &store,
                &format!("invalid-{kind}"),
                kind,
                PrincipalRole::Auditor,
                None
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
    assert!(matches!(
        access_patch(&store, "service", None, Some(true)),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    access_patch(&store, "system", None, Some(false)).unwrap();
    assert!(access_token(&store, "system", BrokerTokenClass::UserManage).is_ok());
    assert!(access_token(&store, "system", BrokerTokenClass::Admin).is_err());
}
#[test]
fn principal_access_role_changes_revoke_admin_tokens_and_remove_direct_scope_only_on_change() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    access_principal(&store, "root", "user", PrincipalRole::Admin, None).unwrap();
    access_principal(&store, "alice", "user", PrincipalRole::Auditor, None).unwrap();
    let token = access_token(&store, "alice", BrokerTokenClass::Admin).unwrap();
    let personal = access_token(&store, "alice", BrokerTokenClass::UserManage).unwrap();
    let agent = access_token(&store, "alice", BrokerTokenClass::AgentInvoke).unwrap();
    for change in [
        access_patch(&store, "alice", Some(PrincipalRole::Auditor), None).unwrap(),
        access_patch(&store, "alice", None, Some(false)).unwrap(),
    ] {
        assert!(change.revoked_admin_token_ids.is_empty());
        assert!(
            store
                .resolve_broker_token(&broker_token_hasher_for_test(9), &token.token)
                .is_ok()
        );
    }
    let promoted = access_patch(&store, "alice", Some(PrincipalRole::Admin), None).unwrap();
    assert_eq!(
        promoted.revoked_admin_token_ids,
        vec![token.record.token_id]
    );
    assert!(matches!(
        store.resolve_broker_token(&broker_token_hasher_for_test(9), &token.token),
        Err(ManagedStoreError::BrokerTokenRevoked)
    ));
    for token in [personal, agent] {
        assert!(
            store
                .resolve_broker_token(&broker_token_hasher_for_test(9), &token.token)
                .is_ok()
        );
    }
    access_patch(
        &store,
        "alice",
        Some(PrincipalRole::ServicePolicyManager),
        None,
    )
    .unwrap();
    for service in ["jira", "confluence"] {
        store
            .put_service_policy_management_assignment(ServicePolicyManagementAssignmentPutRequest {
                service: service.into(),
                principal_id: "alice".into(),
                created_by: "test".into(),
            })
            .unwrap();
    }
    store.set_principal_enabled("alice", false).unwrap();
    assert_eq!(
        store
            .service_policy_management_assignments(None)
            .unwrap()
            .len(),
        2
    );
    store.set_principal_enabled("alice", true).unwrap();
    assert!(
        access_patch(
            &store,
            "alice",
            Some(PrincipalRole::ServicePolicyManager),
            None
        )
        .unwrap()
        .removed_services
        .is_empty()
    );
    let changed = access_patch(&store, "alice", Some(PrincipalRole::Auditor), None).unwrap();
    assert_eq!(changed.removed_services, vec!["confluence", "jira"]);
    access_patch(
        &store,
        "alice",
        Some(PrincipalRole::ServicePolicyManager),
        None,
    )
    .unwrap();
    assert!(
        store
            .management_authority("alice")
            .unwrap()
            .policy_write_scope
            .is_empty()
    );
    assert!(matches!(
        access_patch(&store, "root", Some(PrincipalRole::User), None),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    assert!(matches!(
        store.set_principal_enabled("root", false),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    access_patch(&store, "root", None, Some(false)).unwrap();
    assert_eq!(store.active_admin_principal_count().unwrap(), 1);
}
#[test]
fn self_service_disablement_blocks_transactional_writes_without_changing_invocation_material() {
    let temp = TempDir::new().unwrap();
    let config = store_config(&temp.path().join("store.sqlite"));
    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    create_alice(&store);
    let ring = key_ring("k1");
    let credential = || CredentialWriteRequest {
        owner_principal_id: "alice".into(),
        service: "jira".into(),
        name: "default".into(),
        profile: "jira-cloud-api-token".into(),
        credential_kind: "basic_api_token".into(),
        secret: json!({"username":"alice@example.com","token":"synthetic"}),
        metadata: json!({}),
        actor: "alice".into(),
    };
    store
        .upsert_user_credential(&ring, credential(), CredentialManagementPurpose::Personal)
        .unwrap();
    let token = access_token(&store, "alice", BrokerTokenClass::AgentInvoke).unwrap();
    store
        .pause_principal_agent_token(
            "alice",
            &token.record.token_id,
            "alice",
            AgentTokenManagementPurpose::Personal,
        )
        .unwrap();
    access_patch(&store, "alice", None, Some(false)).unwrap();
    let self_issue = || SelfAgentTokenIssueRequest {
        principal_id: "alice".into(),
        name: "self".into(),
        scopes: json!({"allowedExecutionContexts":["default"]}),
        expires_at: None,
        created_by: "alice".into(),
    };
    assert!(matches!(
        store.issue_self_agent_token(&broker_token_hasher_for_test(9), self_issue()),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    assert!(matches!(
        store.resume_principal_agent_token(
            "alice",
            &token.record.token_id,
            "alice",
            AgentTokenManagementPurpose::Personal
        ),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    assert!(matches!(
        store.upsert_user_credential(&ring, credential(), CredentialManagementPurpose::Personal),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    assert!(matches!(
        store.delete_user_credential(
            "alice",
            "jira",
            "default",
            CredentialManagementPurpose::Personal
        ),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    store
        .upsert_user_credential(
            &ring,
            credential(),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    store
        .resume_broker_token_with_catalog(&token.record.token_id, "test", None)
        .unwrap();
    assert!(
        store
            .resolve_broker_token(&broker_token_hasher_for_test(9), &token.token)
            .is_ok()
    );
    assert!(
        store
            .resolve_user_credential(&ring, "alice", "jira", "default", "jira-cloud-api-token")
            .is_ok()
    );
    create_alice(&store); // profile synchronization does not reset disabled self-service
    assert!(!store.principal("alice").unwrap().self_service_enabled);
}
#[test]
fn principal_access_upgrade_preserves_admins_and_dependents_and_rejects_existing_assignments() {
    for has_assignment in [false, true] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("store.sqlite");
        let config = store_config(&path);
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS
                    .iter()
                    .position(|migration| {
                        migration.version == MANAGED_STORE_PRINCIPAL_ACCESS_VERSION
                    })
                    .unwrap()],
            },
        )
        .unwrap();
        previous.connection.lock().unwrap().execute_batch("INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by) VALUES ('admin','user','active','2026-01-01','2026-01-01','test'),('alice','user','active','2026-01-01','2026-01-01','test'),('system','system','active','2026-01-01','2026-01-01','test'),('service','service_account','active','2026-01-01','2026-01-01','test'); INSERT INTO principal_roles VALUES('admin','admin','2026-01-01','test'); INSERT INTO broker_tokens(token_id,token_hash,principal_id,name,token_class,scopes_json,created_at,created_by) VALUES('11111111-1111-4111-8111-111111111111','hash','alice','retained','user_manage','{}','2026-01-01','test'); INSERT INTO groups(group_id,status,created_at,created_by,updated_at,updated_by) VALUES('team','active','2026-01-01','test','2026-01-01','test'); INSERT INTO principal_groups(principal_id,group_id,created_at,created_by) VALUES('alice','team','2026-01-01','test');").unwrap();
        let token_hasher = broker_token_hasher_for_test(9);
        let stale_admin_id = "22222222-2222-4222-8222-222222222222";
        let stale_admin_secret = "synthetic-legacy-admin-token";
        previous.connection.lock().unwrap().execute(
            "INSERT INTO broker_tokens(token_id,token_hash,principal_id,name,token_class,scopes_json,created_at,created_by) VALUES(?1,?2,'alice','legacy admin','admin','{}','2026-01-01','test')",
            params![stale_admin_id, token_hasher.hash(stale_admin_secret).unwrap()],
        ).unwrap();
        if has_assignment {
            previous.connection.lock().unwrap().execute("INSERT INTO service_policy_management_assignments(assignment_id,service,principal_id,created_at,created_by) VALUES('assignment','jira','alice','2026-01-01','test')",[]).unwrap();
        }
        drop(previous);
        let before = migration_rows(&path);
        let result = ManagedStore::open(&config, ManagedStoreOpenMode::Startup);
        if has_assignment {
            assert!(result.is_err());
            assert_eq!(migration_rows(&path), before);
            let conn = Connection::open(&path).unwrap();
            assert!(sqlite_object_exists(&conn, "table", "principal_roles").unwrap());
            assert!(!table_columns(&conn, "principals").contains(&"role".to_string()));
            continue;
        }
        let store = result.unwrap();
        assert_eq!(store.principal("admin").unwrap().role, PrincipalRole::Admin);
        assert_eq!(store.principal("alice").unwrap().groups, vec!["team"]);
        assert_eq!(store.list_broker_tokens().unwrap().len(), 2);
        for id in ["admin", "alice", "system"] {
            assert!(store.principal(id).unwrap().self_service_enabled);
        }
        assert!(!store.principal("service").unwrap().self_service_enabled);
        assert!(
            store
                .broker_token("11111111-1111-4111-8111-111111111111")
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert!(
            store
                .broker_token(stale_admin_id)
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert!(matches!(
            store.resolve_broker_token(&token_hasher, stale_admin_secret),
            Err(ManagedStoreError::BrokerTokenClassDenied)
        ));
        let promoted = access_patch(&store, "alice", Some(PrincipalRole::Auditor), None).unwrap();
        assert_eq!(promoted.revoked_admin_token_ids, vec![stale_admin_id]);
        assert!(matches!(
            store.resolve_broker_token(&token_hasher, stale_admin_secret),
            Err(ManagedStoreError::BrokerTokenRevoked)
        ));
        run_foreign_key_check(&store.connection.lock().unwrap()).unwrap();
        drop(store);
        let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(!reopened.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert_eq!(&migration_rows(&path)[..before.len()], before.as_slice());
    }
}

#[test]
fn principal_access_administrative_token_and_credential_cleanup_remain_available() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    create_alice(&store);
    access_principal(&store, "bob", "user", PrincipalRole::User, Some(false)).unwrap();
    let ring = key_ring("k1");
    let request = |name: &str| CredentialWriteRequest {
        owner_principal_id: "alice".into(),
        service: "jira".into(),
        name: name.into(),
        profile: "jira-cloud-api-token".into(),
        credential_kind: "basic_api_token".into(),
        secret: json!({"username":"alice@example.com","token":"synthetic"}),
        metadata: json!({}),
        actor: "admin".into(),
    };
    store
        .upsert_user_credential(
            &ring,
            request("tuple"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let by_id = store
        .upsert_user_credential(
            &ring,
            request("id"),
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let token = access_token(&store, "alice", BrokerTokenClass::AgentInvoke).unwrap();
    access_patch(&store, "alice", None, Some(false)).unwrap();
    assert!(matches!(
        store.pause_principal_agent_token(
            "alice",
            &token.record.token_id,
            "alice",
            AgentTokenManagementPurpose::Personal
        ),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    store
        .pause_principal_agent_token(
            "alice",
            &token.record.token_id,
            "admin",
            AgentTokenManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(matches!(
        store.resume_principal_agent_token(
            "alice",
            &token.record.token_id,
            "alice",
            AgentTokenManagementPurpose::Personal
        ),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    assert!(
        store
            .broker_token(&token.record.token_id)
            .unwrap()
            .paused_at
            .is_some()
    );
    store
        .resume_principal_agent_token(
            "alice",
            &token.record.token_id,
            "admin",
            AgentTokenManagementPurpose::Administrative,
        )
        .unwrap();
    for purpose in [
        AgentTokenManagementPurpose::Personal,
        AgentTokenManagementPurpose::Administrative,
    ] {
        assert!(matches!(
            store.pause_principal_agent_token("bob", &token.record.token_id, "admin", purpose),
            Err(ManagedStoreError::BrokerTokenNotFound)
        ));
    }
    let verification = store
        .resolve_user_credential_for_verification(
            &ring,
            "alice",
            "jira",
            "tuple",
            "jira-cloud-api-token",
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    store.set_principal_enabled("alice", false).unwrap();
    assert!(matches!(
        store.mark_user_credential_verified_if_current(
            &verification.target,
            "local_verified",
            CredentialManagementPurpose::Personal
        ),
        Err(ManagedStoreError::PrincipalDisabled)
    ));
    let completed = store
        .mark_user_credential_verified_if_current(
            &verification.target,
            "local_verified",
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert_eq!(
        completed.verification_status.as_deref(),
        Some("local_verified")
    );
    let failed = store
        .mark_user_credential_verification_failed_if_current(
            &verification.target,
            "upstream_unauthorized",
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert_eq!(
        failed.last_verification_error_code.as_deref(),
        Some("upstream_unauthorized")
    );
    let stale = CredentialVerificationTarget {
        credential_id: verification.target.credential_id.clone(),
        material_version: Uuid::new_v4().to_string(),
    };
    assert!(matches!(
        store.mark_user_credential_verified_if_current(
            &stale,
            "local_verified",
            CredentialManagementPurpose::Administrative
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    store
        .pause_principal_agent_token(
            "alice",
            &token.record.token_id,
            "admin",
            AgentTokenManagementPurpose::Administrative,
        )
        .unwrap();
    store
        .resume_principal_agent_token(
            "alice",
            &token.record.token_id,
            "admin",
            AgentTokenManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(matches!(
        store.upsert_user_credential(
            &ring,
            request("new"),
            CredentialManagementPurpose::Administrative
        ),
        Err(ManagedStoreError::PrincipalDisabled)
    ));
    assert!(matches!(
        store.resolve_user_credential_for_verification(
            &ring,
            "alice",
            "jira",
            "tuple",
            "jira-cloud-api-token",
            CredentialManagementPurpose::Administrative
        ),
        Err(ManagedStoreError::PrincipalDisabled)
    ));
    assert!(matches!(
        store.delete_user_credential(
            "alice",
            "jira",
            "tuple",
            CredentialManagementPurpose::Personal
        ),
        Err(ManagedStoreError::PrincipalDisabled)
    ));
    store
        .delete_user_credential(
            "alice",
            "jira",
            "tuple",
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    store
        .delete_user_credential_by_id(
            &by_id.credential_id,
            CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(store.list_credentials(Some("alice")).unwrap().is_empty());
}
