fn issuance_access_patch(
    id: &str,
    setting: PrincipalAgentTokenIssuance,
) -> PrincipalAccessPatchRequest {
    PrincipalAccessPatchRequest {
        principal_id: id.into(),
        role: None,
        self_service_enabled: None,
        agent_token_issuance: Some(test_principal_issuance(setting)),
        actor: "admin".into(),
    }
}

fn issuance_group_request(id: &str, mode: AgentTokenIssuanceMode) -> GroupWriteRequest {
    GroupWriteRequest {
        group_id: id.into(),
        display_name: None,
        description: None,
        auto_enroll_new_microsoft_users: false,
        agent_token_issuance: test_group_issuance(mode),
        created_by: "admin".into(),
    }
}

fn issuance_group_patch(id: &str, mode: AgentTokenIssuanceMode) -> GroupPatchRequest {
    GroupPatchRequest {
        group_id: id.into(),
        display_name: None,
        description: None,
        status: None,
        auto_enroll_new_microsoft_users: None,
        agent_token_issuance: Some(test_group_issuance(mode)),
        updated_by: "policy-admin".into(),
    }
}

fn issuance_request(id: &str, read_only: bool) -> SelfAgentTokenIssueRequest {
    SelfAgentTokenIssueRequest {
        principal_id: id.into(),
        name: "agent".into(),
        scopes: json!({"allowedExecutionContexts": ["default"], "readOnly": read_only}),
        expires_at: None,
        created_by: id.into(),
    }
}

#[test]
fn agent_token_issuance_resolution_covers_all_modes_overrides_and_group_provenance() {
    use AgentTokenIssuanceMode::{Disabled, ReadOnly, WriteCapable};
    use AgentTokenIssuanceSource::{Default, Groups, User};
    for first in [Disabled, ReadOnly, WriteCapable] {
        for second in [Disabled, ReadOnly, WriteCapable] {
            let contributions = vec![
                ("z".into(), test_group_issuance(first)),
                ("a".into(), test_group_issuance(second)),
                ("z".into(), test_group_issuance(first)),
            ];
            let mode = first.max(second);
            let expected_ids = [("a", second), ("z", first)]
                .into_iter()
                .filter(|(_, value)| *value == mode && mode != Disabled)
                .map(|(id, _)| id.to_string())
                .collect::<Vec<_>>();
            for (setting, override_mode) in [
                (PrincipalAgentTokenIssuance::Inherit, None),
                (PrincipalAgentTokenIssuance::Disabled, Some(Disabled)),
                (PrincipalAgentTokenIssuance::ReadOnly, Some(ReadOnly)),
                (
                    PrincipalAgentTokenIssuance::WriteCapable,
                    Some(WriteCapable),
                ),
            ] {
                let resolved = agent_token_issuance::resolve_policy(
                    &test_principal_issuance(setting),
                    contributions.clone(),
                    &test_execution_contexts(),
                );
                let expected_mode = override_mode.unwrap_or(mode);
                assert_eq!(
                    resolved.contexts,
                    if expected_mode == Disabled {
                        vec![]
                    } else {
                        vec![AgentTokenIssuanceContextPolicy {
                            execution_context: "default".into(),
                            mode: expected_mode,
                            group_ids: if override_mode.is_some() {
                                vec![]
                            } else {
                                expected_ids.clone()
                            },
                        }]
                    }
                );
                assert_eq!(
                    resolved.source,
                    if override_mode.is_some() {
                        User
                    } else if mode == Disabled {
                        Default
                    } else {
                        Groups
                    }
                );
            }
        }
    }
    let empty = agent_token_issuance::resolve_policy(
        &PrincipalAgentTokenIssuanceSetting::default(),
        [],
        &test_execution_contexts(),
    );
    assert!(empty.contexts.is_empty());
    assert_eq!(empty.source, Default);
}

#[test]
fn agent_token_issuance_settings_are_strict_and_default_to_no_permission() {
    for value in [
        json!(null),
        json!(true),
        json!(1),
        json!("readOnly"),
        json!("READ_ONLY"),
        json!("unknown"),
    ] {
        assert!(serde_json::from_value::<PrincipalAgentTokenIssuance>(value.clone()).is_err());
        assert!(serde_json::from_value::<AgentTokenIssuanceMode>(value).is_err());
    }
    assert!(serde_json::from_value::<AgentTokenIssuanceMode>(json!("inherit")).is_err());
    let body = json!({"principalId":"alice","kind":"user","createdBy":"admin"});
    let request: PrincipalWriteRequest = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(
        request.agent_token_issuance,
        test_principal_issuance(PrincipalAgentTokenIssuance::Inherit)
    );
    let mut invalid = body;
    invalid["agentTokenIssuance"] = Value::Null;
    assert!(serde_json::from_value::<PrincipalWriteRequest>(invalid).is_err());
    let (_temp, store) = identity_test_store();
    let principal = store
        .create_principal(request, &test_execution_contexts())
        .unwrap();
    assert_eq!(
        principal.agent_token_issuance,
        test_principal_issuance(PrincipalAgentTokenIssuance::Inherit)
    );
    let group = store
        .create_group(
            issuance_group_request("default", AgentTokenIssuanceMode::Disabled),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(group).unwrap()["agentTokenIssuance"],
        json!({"mode":"disabled","allowedExecutionContexts":[]})
    );
    let conn = store.connection.lock().unwrap();
    for value in ["NULL", "'unknown'", "1", "'READ_ONLY'"] {
        assert!(
            conn.execute(
                &format!(
                    "UPDATE principals SET agent_token_issuance={value} WHERE principal_id='alice'"
                ),
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                &format!("UPDATE groups SET agent_token_issuance={value} WHERE group_id='default'"),
                []
            )
            .is_err()
        );
    }
    assert!(
        conn.execute(
            "UPDATE groups SET agent_token_issuance='inherit' WHERE group_id='default'",
            []
        )
        .is_err()
    );
}

#[test]
fn agent_token_issuance_policy_writes_preserve_profile_role_memberships_and_noop_timestamps() {
    let (_temp, store) = identity_test_store();
    let mut request = identity_user_request("alice");
    request.role = PrincipalRole::Admin;
    request.agent_token_issuance = test_principal_issuance(PrincipalAgentTokenIssuance::ReadOnly);
    let original = store
        .create_principal(request.clone(), &test_execution_contexts())
        .unwrap();
    let admin_token = access_token(&store, "alice", BrokerTokenClass::Admin).unwrap();
    request.agent_token_issuance =
        test_principal_issuance(PrincipalAgentTokenIssuance::WriteCapable);
    assert_eq!(
        store
            .create_or_update_principal(request, &test_execution_contexts())
            .unwrap()
            .agent_token_issuance,
        test_principal_issuance(PrincipalAgentTokenIssuance::ReadOnly)
    );
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".into(),
            display_name: Some(Some("Updated".into())),
            email: None,
            status: None,
        })
        .unwrap();
    assert_eq!(
        store.principal("alice").unwrap().agent_token_issuance,
        original.agent_token_issuance
    );
    let changed = store
        .patch_principal_access(
            issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(
        changed.previous_agent_token_issuance,
        test_principal_issuance(PrincipalAgentTokenIssuance::ReadOnly)
    );
    assert_eq!(changed.principal.role, PrincipalRole::Admin);
    assert!(changed.revoked_admin_token_ids.is_empty());
    assert!(changed.removed_services.is_empty());
    assert!(
        store
            .resolve_broker_token(&broker_token_hasher_for_test(9), &admin_token.token)
            .is_ok()
    );
    let manager = access_principal(
        &store,
        "manager",
        "user",
        PrincipalRole::ServicePolicyManager,
        None,
    )
    .unwrap();
    store
        .put_service_policy_management_assignment(ServicePolicyManagementAssignmentPutRequest {
            principal_id: manager.principal_id,
            service: "jira".into(),
            created_by: "admin".into(),
        })
        .unwrap();
    let manager_change = store
        .patch_principal_access(
            issuance_access_patch("manager", PrincipalAgentTokenIssuance::WriteCapable),
            &test_execution_contexts(),
        )
        .unwrap();
    assert!(manager_change.removed_services.is_empty());
    assert_eq!(
        store
            .effective_service_policy_management_services("manager")
            .unwrap(),
        ["jira"]
    );
    let mut group_request = issuance_group_request("readers", AgentTokenIssuanceMode::ReadOnly);
    group_request.auto_enroll_new_microsoft_users = true;
    let created = store
        .create_group_with_effect(group_request, &test_execution_contexts())
        .unwrap();
    assert_eq!(
        created.agent_token_issuance_change,
        Some(GroupAgentTokenIssuanceChange {
            previous: test_group_issuance(AgentTokenIssuanceMode::Disabled),
            current: test_group_issuance(AgentTokenIssuanceMode::ReadOnly)
        })
    );
    store.add_group("alice", "readers", "admin").unwrap();
    let changed_group = store
        .patch_group_with_effect(
            issuance_group_patch("readers", AgentTokenIssuanceMode::WriteCapable),
            &test_execution_contexts(),
        )
        .unwrap();
    assert!(changed_group.group.auto_enroll_new_microsoft_users);
    assert!(changed_group.auto_enrollment_change.is_none());
    assert_eq!(
        changed_group.agent_token_issuance_change,
        Some(GroupAgentTokenIssuanceChange {
            previous: test_group_issuance(AgentTokenIssuanceMode::ReadOnly),
            current: test_group_issuance(AgentTokenIssuanceMode::WriteCapable)
        })
    );
    assert_eq!(store.groups("alice").unwrap(), ["readers"]);
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER forbid_principal_policy_noop BEFORE UPDATE ON principals WHEN OLD.principal_id='alice' BEGIN SELECT RAISE(ABORT,'unexpected write'); END;
         CREATE TEMP TRIGGER forbid_group_policy_noop BEFORE UPDATE ON groups WHEN OLD.group_id='readers' BEGIN SELECT RAISE(ABORT,'unexpected write'); END;"
    ).unwrap();
    let same = store
        .patch_principal_access(
            issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(same.principal.updated_at, changed.principal.updated_at);
    let same_group = store
        .patch_group_with_effect(
            issuance_group_patch("readers", AgentTokenIssuanceMode::WriteCapable),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(same_group.group, changed_group.group);
    assert!(same_group.agent_token_issuance_change.is_none());
}

#[test]
fn agent_token_issuance_membership_is_active_deduplicated_and_managed_only() {
    let (_temp, store) = identity_test_store();
    let provider = enrollment_fixture(&store);
    store
        .patch_group(
            issuance_group_patch("mapped", AgentTokenIssuanceMode::WriteCapable),
            &test_execution_contexts(),
        )
        .unwrap();
    store
        .create_group(
            issuance_group_request("readers", AgentTokenIssuanceMode::ReadOnly),
            &test_execution_contexts(),
        )
        .unwrap();
    let now = normalized_now_string();
    enrollment_succeeded(
        store
            .complete_oidc_login(
                &broker_token_hasher_for_test(91),
                test_oidc_completion_request(
                    1,
                    provider.config_generation,
                    TEST_OIDC_USER,
                    "alice",
                    &[TEST_EXTERNAL_GROUP_A],
                    &now,
                ),
            )
            .unwrap(),
        true,
    );
    store.add_group("alice", "readers", "admin").unwrap();
    store.add_group("alice", "mapped", "admin").unwrap();
    let policy = store
        .agent_token_issuance_policy(
            "alice",
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
        )
        .unwrap();
    assert_eq!(
        policy
            .contexts
            .first()
            .map(|row| row.mode)
            .unwrap_or(AgentTokenIssuanceMode::Disabled),
        AgentTokenIssuanceMode::WriteCapable
    );
    assert_eq!(
        policy
            .contexts
            .iter()
            .flat_map(|row| row.group_ids.iter())
            .collect::<Vec<_>>(),
        ["mapped"]
    );
    assert_eq!(
        store
            .agent_token_issuance_policy(
                "alice",
                &test_issuance_environment(AgentTokenIssuanceAuthority::Toml)
            )
            .unwrap()
            .contexts
            .first()
            .map(|row| row.mode)
            .unwrap_or(AgentTokenIssuanceMode::Disabled),
        AgentTokenIssuanceMode::Disabled
    );
    let later = normalized_timestamp(
        DateTime::parse_from_rfc3339(&now)
            .unwrap()
            .with_timezone(&Utc)
            + Duration::seconds(3_601),
    );
    let at = |timestamp: &str| {
        let mut conn = store.connection.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let principal = principal_by_id_without_groups(&tx, "alice").unwrap();
        agent_token_issuance::policy_at_conn(
            &tx,
            &principal,
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
            timestamp,
        )
        .unwrap()
    };
    assert_eq!(at(&later).contexts[0].group_ids, ["mapped"]); // Local contribution survives external expiry.
    store.remove_group("alice", "mapped").unwrap();
    assert_eq!(
        at(&now).contexts[0].mode,
        AgentTokenIssuanceMode::WriteCapable
    );
    assert_eq!(at(&later).contexts[0].group_ids, ["readers"]);
    let mut patch = issuance_group_patch("mapped", AgentTokenIssuanceMode::WriteCapable);
    patch.status = Some("disabled".into());
    store
        .patch_group(patch, &test_execution_contexts())
        .unwrap();
    assert_eq!(at(&now).contexts[0].group_ids, ["readers"]);
    for (setting, mode) in [
        (
            PrincipalAgentTokenIssuance::Disabled,
            AgentTokenIssuanceMode::Disabled,
        ),
        (
            PrincipalAgentTokenIssuance::WriteCapable,
            AgentTokenIssuanceMode::WriteCapable,
        ),
    ] {
        store
            .patch_principal_access(
                issuance_access_patch("alice", setting),
                &test_execution_contexts(),
            )
            .unwrap();
        for authority in [
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Toml),
        ] {
            let policy = store
                .agent_token_issuance_policy("alice", authority)
                .unwrap();
            assert_eq!(
                policy
                    .contexts
                    .first()
                    .map(|row| row.mode)
                    .unwrap_or(AgentTokenIssuanceMode::Disabled),
                mode
            );
            assert_eq!(policy.source, AgentTokenIssuanceSource::User);
            assert!(
                policy
                    .contexts
                    .iter()
                    .flat_map(|row| row.group_ids.iter())
                    .collect::<Vec<_>>()
                    .is_empty()
            );
        }
    }
}

#[test]
fn agent_token_issuance_enforces_personal_modes_and_keeps_administrative_and_existing_tokens_independent()
 {
    let (_temp, store) = identity_test_store();
    create_alice(&store);
    let hasher = broker_token_hasher_for_test(92);
    for (setting, mode) in [
        (
            PrincipalAgentTokenIssuance::Inherit,
            AgentTokenIssuanceMode::Disabled,
        ),
        (
            PrincipalAgentTokenIssuance::Disabled,
            AgentTokenIssuanceMode::Disabled,
        ),
        (
            PrincipalAgentTokenIssuance::ReadOnly,
            AgentTokenIssuanceMode::ReadOnly,
        ),
        (
            PrincipalAgentTokenIssuance::WriteCapable,
            AgentTokenIssuanceMode::WriteCapable,
        ),
    ] {
        store
            .patch_principal_access(
                issuance_access_patch("alice", setting),
                &test_execution_contexts(),
            )
            .unwrap();
        for read_only in [true, false] {
            let result = store.issue_self_agent_token(
                &hasher,
                issuance_request("alice", read_only),
                &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
            );
            match (mode, read_only) {
                (AgentTokenIssuanceMode::Disabled, _) => assert!(matches!(
                    result,
                    Err(ManagedStoreError::TokenIssuanceDenied {
                        category: TokenIssuanceDenial::Disabled
                    })
                )),
                (AgentTokenIssuanceMode::ReadOnly, false) => assert!(matches!(
                    result,
                    Err(ManagedStoreError::TokenIssuanceDenied {
                        category: TokenIssuanceDenial::ReadOnlyRequired
                    })
                )),
                _ => {
                    let issued = result.unwrap();
                    assert_eq!(issued.record.scopes["readOnly"], read_only);
                    assert_eq!(
                        issued.issuance_policy.as_ref().unwrap().contexts[0].mode,
                        mode
                    );
                    assert!(
                        serde_json::to_value(&issued)
                            .unwrap()
                            .get("issuancePolicy")
                            .is_none()
                    );
                }
            }
        }
    }
    let issued = store
        .issue_self_agent_token(
            &hasher,
            issuance_request("alice", false),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
        )
        .unwrap();
    store
        .patch_principal_access(
            issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(
        issued.issuance_policy.unwrap().contexts[0].mode,
        AgentTokenIssuanceMode::WriteCapable
    );
    assert_eq!(
        store
            .resolve_broker_token(&hasher, &issued.token)
            .unwrap()
            .scopes["readOnly"],
        false
    );
    access_patch(&store, "alice", None, Some(false)).unwrap();
    // Equal creator and owner must not turn the admitted administrative route into personal issuance.
    let administrative = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "admin issued".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: issuance_request("alice", false).scopes,
                expires_at: None,
                created_by: "alice".into(),
            },
        )
        .unwrap();
    assert!(administrative.issuance_policy.is_none());
    assert!(matches!(
        store.issue_self_agent_token(
            &hasher,
            issuance_request("alice", true),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed)
        ),
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
    store.set_principal_enabled("alice", false).unwrap();
    assert!(matches!(
        store.issue_self_agent_token(
            &hasher,
            issuance_request("alice", true),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed)
        ),
        Err(ManagedStoreError::PrincipalDisabled)
    ));
    for kind in ["system", "service_account"] {
        access_principal(&store, kind, kind, PrincipalRole::User, None).unwrap();
        store
            .patch_principal_access(
                issuance_access_patch(kind, PrincipalAgentTokenIssuance::WriteCapable),
                &test_execution_contexts(),
            )
            .unwrap();
        let result = store.issue_self_agent_token(
            &hasher,
            issuance_request(kind, true),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Toml),
        );
        if kind == "system" {
            assert_eq!(
                result.unwrap().issuance_policy.unwrap().source,
                AgentTokenIssuanceSource::User
            );
        } else {
            assert!(matches!(
                result,
                Err(ManagedStoreError::SelfServiceDisabled)
            ));
        }
    }
}

#[test]
fn agent_token_issuance_waits_for_current_policy_and_membership_before_inserting() {
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    thread_local! {
        static ISSUANCE_WRITE_WAIT: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
    }
    for mutation in ["principal", "group", "membership"] {
        let (temp, store) = identity_test_store();
        create_alice(&store);
        store
            .create_group(
                issuance_group_request("writers", AgentTokenIssuanceMode::WriteCapable),
                &test_execution_contexts(),
            )
            .unwrap();
        store.add_group("alice", "writers", "admin").unwrap();
        let other = ManagedStore::open(
            &store_config(&temp.path().join("store.sqlite")),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Reload,
        )
        .unwrap();
        let mut conn = store.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        match mutation {
            "principal" => tx.execute_batch(
                "UPDATE principals SET agent_token_issuance='disabled' WHERE principal_id='alice'; DELETE FROM principal_agent_token_issuance_contexts WHERE principal_id='alice'"
            ),
            "group" => tx.execute_batch(
                "UPDATE groups SET agent_token_issuance='disabled' WHERE group_id='writers'; DELETE FROM group_agent_token_issuance_contexts WHERE group_id='writers'"
            ),
            "membership" => tx.execute_batch(
                "DELETE FROM principal_groups WHERE principal_id='alice'"
            ),
            _ => unreachable!(),
        }
        .unwrap();
        let (blocked, ready) = channel();
        let (resume, released) = channel();
        let task = thread::spawn(move || {
            ISSUANCE_WRITE_WAIT.with(|slot| *slot.borrow_mut() = Some((blocked, released)));
            other
                .connection
                .lock()
                .unwrap()
                .busy_handler(Some(|_| {
                    ISSUANCE_WRITE_WAIT.with(|slot| {
                        let Some((blocked, released)) = slot.borrow_mut().take() else {
                            return false;
                        };
                        blocked.send(()).is_ok() && released.recv().is_ok()
                    })
                }))
                .unwrap();
            other.issue_self_agent_token(
                &broker_token_hasher_for_test(93),
                issuance_request("alice", false),
                &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
            )
        });
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        tx.commit().unwrap();
        drop(conn);
        resume.send(()).unwrap();
        assert!(
            matches!(
                task.join().unwrap(),
                Err(ManagedStoreError::TokenIssuanceDenied {
                    category: TokenIssuanceDenial::Disabled
                })
            ),
            "{mutation}"
        );
        assert!(
            store
                .list_self_agent_tokens("alice", true, true)
                .unwrap()
                .is_empty()
        );
    }
}

fn issuance_previous_schema(path: &Path) -> ManagedStore {
    let store = ManagedStore::open_with_catalog(
        &store_config(path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(MANAGED_STORE_IMPORTED_SOURCE_DOCUMENTS_VERSION),
    )
    .unwrap();
    store.connection.lock().unwrap().execute_batch(
        "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
         VALUES('alice','user','active','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','admin',1);
         INSERT INTO groups(group_id,status,created_at,created_by,updated_at,updated_by,auto_enroll_new_microsoft_users)
         VALUES('existing','active','2026-01-01T00:00:00Z','admin','2026-01-02T00:00:00Z','admin',1);
         INSERT INTO principal_groups(principal_id,group_id,created_at,created_by)
         VALUES('alice','existing','2026-01-03T00:00:00Z','admin');"
    ).unwrap();
    store
}

fn issuance_old_token(
    store: &ManagedStore,
    class: BrokerTokenClass,
    scopes: &str,
    state: &str,
) -> (String, String) {
    let id = Uuid::new_v4().to_string();
    let raw = generate_broker_token(&class);
    let hash = broker_token_hasher_for_test(94).hash(&raw).unwrap();
    store.connection.lock().unwrap().execute(
        "INSERT INTO broker_tokens(token_id,token_hash,principal_id,name,token_class,scopes_json,created_at,expires_at,revoked_at,revoked_by,last_used_at,created_by,paused_at,paused_by)
         VALUES(?1,?2,'alice','existing token',?3,?4,'2026-01-01T00:00:00Z',?5,?6,?7,'2026-01-02T00:00:00Z','creator',?8,?9)",
        params![id, hash, class.as_str(), scopes,
            if state == "expired" { Some("2000-01-01T00:00:00Z") } else { Some("2099-01-01T00:00:00Z") },
            (state == "revoked").then_some("2026-01-03T00:00:00Z"), (state == "revoked").then_some("revoker"),
            (state == "paused").then_some("2026-01-04T00:00:00Z"), (state == "paused").then_some("pauser")],
    ).unwrap();
    (id, raw)
}

fn issuance_table_columns(conn: &Connection, table: &str) -> String {
    let statement = conn.prepare(&format!("SELECT * FROM {table} LIMIT 0")).unwrap();
    statement.column_names().into_iter().map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
        .collect::<Vec<_>>().join(", ")
}

fn issuance_table_rows(conn: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    issuance_projected_rows(conn, table, "*")
}

fn issuance_projected_rows(conn: &Connection, table: &str, columns: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = conn
        .prepare(&format!("SELECT {columns} FROM {table} ORDER BY 1"))
        .unwrap();
    let count = statement.column_count();
    statement
        .query_map([], |row| (0..count).map(|column| row.get(column)).collect())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn agent_token_issuance_migration_preserves_tokens_and_credentials_and_rewrites_only_once() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("prior.sqlite");
    let old = issuance_previous_schema(&path);
    let valid_scopes = r#"{ "allowedExecutionContexts": ["default"], "allowedServices":["jira"], "serviceRestrictions":{"jira":{"actions":["issue.view"]}} }"#;
    let mut active = None;
    for state in ["active", "paused", "expired", "revoked"] {
        let token = issuance_old_token(&old, BrokerTokenClass::AgentInvoke, valid_scopes, state);
        if state == "active" {
            active = Some(token);
        }
    }
    for scopes in [
        "not-json-sensitive-marker",
        "[]",
        "true",
        "null",
        "{}",
        r#"{"allowedExecutionContexts":[]}"#,
        r#"{"allowedExecutionContexts":["default"],"unknown":true}"#,
        r#"{ "unknownNumber":9.123456789123456789e+99, "allowedExecutionContexts":["default"] } "#,
        r#"{"allowedExecutionContexts":["default"],"serviceRestrictions":{"jira":{"actions":"invalid"}}}"#,
    ] {
        issuance_old_token(&old, BrokerTokenClass::AgentInvoke, scopes, "active");
    }
    let revoked_collision = issuance_old_token(
        &old,
        BrokerTokenClass::AgentInvoke,
        r#"{ "allowedExecutionContexts":["default"], "readOnly": "sensitive-marker" }"#,
        "revoked",
    );
    for class in [BrokerTokenClass::Admin, BrokerTokenClass::UserManage] {
        issuance_old_token(
            &old,
            class,
            r#"{ "existingManagementSemantics":null, "readOnly":"untouched" }"#,
            "active",
        );
    }
    // Reuse the durable golden ciphertext; migration must not alter or re-encrypt it.
    let golden = &GOLDEN_STORED_CREDENTIALS[0];
    {
        let conn = old.connection.lock().unwrap();
        conn.execute("INSERT INTO credentials(credential_id,owner_principal_id,owner_kind,service,name,profile,credential_kind,metadata_json,secret_backend,secret_ref,material_version,status,created_at,updated_at,created_by,updated_by) VALUES(?1,'alice','user',?2,'default',?3,?4,?5,'sqlite_encrypted',?6,?7,'active','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','admin')",
            params![golden.credential_id,golden.service,golden.profile,golden.credential_kind,golden.metadata_json,golden.secret_ref,golden.material_version]).unwrap();
        conn.execute("INSERT INTO credential_secret_material(secret_ref,credential_id,backend,secret_ciphertext,secret_nonce,key_id,created_at,updated_at) VALUES(?1,?2,'sqlite_encrypted',?3,?4,'k1','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')",
            params![golden.secret_ref,golden.credential_id,golden_hex(golden.ciphertext_hex),golden_hex(golden.nonce_hex)]).unwrap();
    }
    let preserved_tables = [
        "principals",
        "groups",
        "principal_groups",
        "credentials",
        "credential_secret_material",
    ];
    let (before, prior_columns) = {
        let conn = old.connection.lock().unwrap();
        (preserved_tables.map(|table| issuance_table_rows(&conn, table)),
         preserved_tables.map(|table| issuance_table_columns(&conn, table)))
    };
    let tokens_before = issuance_table_rows(&old.connection.lock().unwrap(), "broker_tokens");
    let ledger_before = migration_rows(&path);
    drop(old);
    assert!(matches!(
        ManagedStore::open(
            &store_config(&path),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Reload
        ),
        Err(ManagedStoreError::MigrationRequired)
    ));
    let upgraded = ManagedStore::open(
        &store_config(&path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(upgraded.migration_applied_this_open(MANAGED_STORE_AGENT_TOKEN_ISSUANCE_VERSION));
    let ledger_after = migration_rows(&path);
    assert_eq!(&ledger_after[..ledger_before.len()], ledger_before);
    assert_eq!(ledger_after.last().unwrap().0, MANAGED_STORE_SCHEMA_VERSION);
    assert_eq!(
        upgraded.principal("alice").unwrap().agent_token_issuance,
        test_principal_issuance(PrincipalAgentTokenIssuance::Inherit)
    );
    assert_eq!(
        upgraded.group("existing").unwrap().agent_token_issuance,
        test_group_issuance(AgentTokenIssuanceMode::Disabled)
    );
    assert_eq!(
        upgraded
            .agent_token_issuance_policy(
                "alice",
                &test_issuance_environment(AgentTokenIssuanceAuthority::Managed)
            )
            .unwrap()
            .contexts
            .first()
            .map(|row| row.mode)
            .unwrap_or(AgentTokenIssuanceMode::Disabled),
        AgentTokenIssuanceMode::Disabled
    );
    {
        let conn = upgraded.connection.lock().unwrap();
        for (index, table) in preserved_tables.into_iter().enumerate() {
            // Compare every pre-migration value, independently of later additive columns.
            let after = issuance_projected_rows(&conn, table, &prior_columns[index]);
            assert_eq!(after, before[index], "{table}");
        }
        let tokens_after = issuance_table_rows(&conn, "broker_tokens");
        assert_eq!(tokens_before.len(), tokens_after.len());
        for (before, after) in tokens_before.iter().zip(&tokens_after) {
            let mut expected = before.clone();
            let rusqlite::types::Value::Text(scopes) = &before[5] else {
                panic!("scopes must be text")
            };
            if before[4] == rusqlite::types::Value::Text("agent_invoke".into())
                && let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(scopes)
                && !object.contains_key("readOnly")
            {
                let valid_before = object.get("allowedServices").is_some();
                object.insert("readOnly".into(), Value::Bool(false));
                let upgraded_scopes = Value::Object(object);
                assert_eq!(
                    AgentInvokeTokenCaveats::parse_stored(&upgraded_scopes).is_ok(),
                    valid_before
                );
                let rusqlite::types::Value::Text(actual_scopes) = &after[5] else {
                    panic!("upgraded scopes must remain text")
                };
                assert_eq!(
                    serde_json::from_str::<Value>(actual_scopes).unwrap(),
                    upgraded_scopes
                );
                let closing_brace = scopes.rfind('}').unwrap();
                assert!(actual_scopes.starts_with(&scopes[..closing_brace]));
                assert!(actual_scopes.ends_with(&scopes[closing_brace..]));
                expected[5] = after[5].clone();
            }
            assert_eq!(&expected, after);
        }
    }
    assert!(matches!(
        upgraded.resolve_broker_token(&broker_token_hasher_for_test(94), &revoked_collision.1),
        Err(ManagedStoreError::BrokerTokenRevoked)
    ));
    let (id, raw) = active.unwrap();
    assert_eq!(
        upgraded
            .resolve_broker_token(&broker_token_hasher_for_test(94), &raw)
            .unwrap()
            .scopes["readOnly"],
        false
    );
    // A current-schema invalid old shape is never repaired on reload or restart.
    upgraded
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE broker_tokens SET scopes_json=?2 WHERE token_id=?1",
            params![id, valid_scopes],
        )
        .unwrap();
    drop(upgraded);
    let reopened = ManagedStore::open(
        &store_config(&path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(!reopened.migration_applied_this_open(MANAGED_STORE_AGENT_TOKEN_ISSUANCE_VERSION));
    assert!(
        AgentInvokeTokenCaveats::parse_stored(&reopened.broker_token(&id).unwrap().scopes).is_err()
    );
    assert_eq!(migration_rows(&path), ledger_after);
    assert!(matches!(
        ManagedStore::open_with_catalog(
            &store_config(&path),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Reload,
            identity_test_catalog_through(MANAGED_STORE_IMPORTED_SOURCE_DOCUMENTS_VERSION)
        ),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
}

#[test]
fn agent_token_issuance_migration_collision_rolls_back_and_supports_revoke_then_retry() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("prior.sqlite");
    let old = issuance_previous_schema(&path);
    issuance_old_token(
        &old,
        BrokerTokenClass::AgentInvoke,
        r#"{"allowedExecutionContexts":["default"]}"#,
        "active",
    );
    let mut collisions = Vec::new();
    for state in ["active", "paused", "expired"] {
        collisions.push(issuance_old_token(
            &old,
            BrokerTokenClass::AgentInvoke,
            r#"{"allowedExecutionContexts":["default"],"readOnly":"private-collision-material"}"#,
            state,
        ));
    }
    let revoked = issuance_old_token(
        &old,
        BrokerTokenClass::AgentInvoke,
        r#"{ "allowedExecutionContexts":["default"], "readOnly": false }"#,
        "revoked",
    );
    let before = issuance_table_rows(&old.connection.lock().unwrap(), "broker_tokens");
    let ledger = migration_rows(&path);
    drop(old);
    let error = ManagedStore::open(
        &store_config(&path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap_err()
    .to_string();
    for (id, raw) in &collisions {
        assert!(error.contains(id));
        assert!(!error.contains(raw));
    }
    assert!(!error.contains(&revoked.0));
    assert!(!error.contains("private-collision-material"));
    assert!(!error.contains("allowedExecutionContexts"));
    assert_eq!(migration_rows(&path), ledger);
    let original = ManagedStore::open_with_catalog(
        &store_config(&path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Reload,
        identity_test_catalog_through(MANAGED_STORE_IMPORTED_SOURCE_DOCUMENTS_VERSION),
    )
    .unwrap();
    {
        let conn = original.connection.lock().unwrap();
        assert_eq!(issuance_table_rows(&conn, "broker_tokens"), before);
        assert!(
            !table_columns(&conn, "principals")
                .iter()
                .any(|column| column == "agent_token_issuance")
        );
        assert!(
            !table_columns(&conn, "groups")
                .iter()
                .any(|column| column == "agent_token_issuance")
        );
    }
    // Supported recovery needs only the token IDs diagnosed above, using the old schema.
    for (id, _) in &collisions {
        original.revoke_broker_token(id, "admin").unwrap();
    }
    let revoked_rows = issuance_table_rows(&original.connection.lock().unwrap(), "broker_tokens");
    drop(original);
    let upgraded = ManagedStore::open(
        &store_config(&path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let after = issuance_table_rows(&upgraded.connection.lock().unwrap(), "broker_tokens");
    for (id, raw) in collisions.into_iter().chain([revoked]) {
        let id_value = rusqlite::types::Value::Text(id);
        assert_eq!(
            after.iter().find(|row| row[0] == id_value),
            revoked_rows.iter().find(|row| row[0] == id_value)
        );
        assert!(matches!(
            upgraded.resolve_broker_token(&broker_token_hasher_for_test(94), &raw),
            Err(ManagedStoreError::BrokerTokenRevoked)
        ));
    }
}

#[test]
fn agent_token_issuance_latest_schema_validates_both_permission_columns() {
    for table in ["principals", "groups"] {
        let (temp, store) = identity_test_store();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(&format!(
                "ALTER TABLE {table} DROP COLUMN agent_token_issuance"
            ))
            .unwrap();
        drop(store);
        assert!(matches!(
            ManagedStore::open(
                &store_config(&temp.path().join("store.sqlite")),
                &test_execution_contexts(),
                ManagedStoreOpenMode::Reload
            ),
            Err(ManagedStoreError::SchemaInvalid(_))
        ));
    }
}

#[test]
fn agent_token_issuance_uses_post_wait_time_for_external_membership_expiry() {
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    thread_local! {
        static ISSUANCE_EXPIRY_WAIT: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
    }
    let (temp, store) = identity_test_store();
    let provider = enrollment_fixture(&store);
    store
        .patch_group(
            issuance_group_patch("mapped", AgentTokenIssuanceMode::ReadOnly),
            &test_execution_contexts(),
        )
        .unwrap();
    enrollment_succeeded(
        store
            .complete_oidc_login(
                &broker_token_hasher_for_test(95),
                test_oidc_completion_request(
                    1,
                    provider.config_generation,
                    TEST_OIDC_USER,
                    "alice",
                    &[TEST_EXTERNAL_GROUP_A],
                    &normalized_now_string(),
                ),
            )
            .unwrap(),
        true,
    );
    assert_eq!(
        store
            .agent_token_issuance_policy(
                "alice",
                &test_issuance_environment(AgentTokenIssuanceAuthority::Managed)
            )
            .unwrap()
            .contexts
            .first()
            .map(|row| row.mode)
            .unwrap_or(AgentTokenIssuanceMode::Disabled),
        AgentTokenIssuanceMode::ReadOnly
    );
    let other = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Reload,
    )
    .unwrap();
    let mut conn = store.connection.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let (blocked, ready) = channel();
    let (resume, released) = channel();
    let task = thread::spawn(move || {
        ISSUANCE_EXPIRY_WAIT.with(|slot| *slot.borrow_mut() = Some((blocked, released)));
        other
            .connection
            .lock()
            .unwrap()
            .busy_handler(Some(|_| {
                ISSUANCE_EXPIRY_WAIT.with(|slot| {
                    let Some((blocked, released)) = slot.borrow_mut().take() else {
                        return false;
                    };
                    blocked.send(()).is_ok() && released.recv().is_ok()
                })
            }))
            .unwrap();
        other.issue_self_agent_token(
            &broker_token_hasher_for_test(95),
            issuance_request("alice", true),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
        )
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // Choose expiry after the request is blocked: a timestamp captured before
    // acquiring its transaction would still accept this evidence after release.
    let expires_at = normalized_timestamp(Utc::now() + Duration::seconds(1));
    tx.execute(
        "UPDATE external_principal_groups SET valid_until=?1",
        [&expires_at],
    )
    .unwrap();
    tx.execute(
        "UPDATE oidc_membership_refresh_state SET valid_until=?1",
        [&expires_at],
    )
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while normalized_now_string() <= expires_at {
        assert!(
            std::time::Instant::now() < deadline,
            "clock failed to advance to the explicit evidence expiry"
        );
        thread::sleep(std::time::Duration::from_millis(10));
    }
    tx.commit().unwrap();
    drop(conn);
    resume.send(()).unwrap();
    assert!(matches!(
        task.join().unwrap(),
        Err(ManagedStoreError::TokenIssuanceDenied {
            category: TokenIssuanceDenial::Disabled
        })
    ));
    assert!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn agent_token_issuance_strict_boolean_and_management_class_rejection_are_transactional_inputs() {
    let (_temp, store) = identity_test_store();
    create_alice(&store);
    let hasher = broker_token_hasher_for_test(96);
    for value in [
        None,
        Some(Value::Null),
        Some(json!(0)),
        Some(json!("false")),
    ] {
        let mut request = issuance_request("alice", true);
        match value {
            None => {
                request.scopes.as_object_mut().unwrap().remove("readOnly");
            }
            Some(value) => {
                request.scopes["readOnly"] = value;
            }
        }
        assert!(matches!(
            store.issue_self_agent_token(
                &hasher,
                request,
                &test_issuance_environment(AgentTokenIssuanceAuthority::Managed)
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
    for class in [BrokerTokenClass::Admin, BrokerTokenClass::UserManage] {
        assert!(matches!(
            store.issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: "invalid management token".into(),
                    token_class: class,
                    scopes: json!({"readOnly":false}),
                    expires_at: None,
                    created_by: "admin".into(),
                }
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
    assert!(store.list_broker_tokens().unwrap().is_empty());
}

#[test]
fn agent_token_issuance_preserves_created_at_precision_and_fractional_list_order() {
    let (_temp, store) = identity_test_store();
    create_alice(&store);
    store
        .patch_principal_access(
            PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: Some(PrincipalRole::Admin),
                self_service_enabled: None,
                agent_token_issuance: Some(test_principal_issuance(
                    PrincipalAgentTokenIssuance::WriteCapable,
                )),
                actor: "admin".into(),
            },
            &test_execution_contexts(),
        )
        .unwrap();
    let hasher = broker_token_hasher_for_test(97);
    let assert_created_at = |record: &BrokerTokenRecord| {
        let created_at = DateTime::parse_from_rfc3339(&record.created_at)
            .unwrap()
            .with_timezone(&Utc);
        // Creation metadata keeps the pre-existing precise UTC representation;
        // the whole-second Z timestamp used for policy resolution is separate.
        assert!(
            record.created_at.ends_with("+00:00"),
            "{}",
            record.created_at
        );
        assert_eq!(record.created_at, created_at.to_rfc3339());
        assert_eq!(
            store.broker_token(&record.token_id).unwrap().created_at,
            record.created_at
        );
    };

    let personal = store
        .issue_self_agent_token(
            &hasher,
            issuance_request("alice", true),
            &test_issuance_environment(AgentTokenIssuanceAuthority::Managed),
        )
        .unwrap();
    assert_created_at(&personal.record);
    let mut agent_token_ids = vec![personal.record.token_id];
    for class in [
        BrokerTokenClass::AgentInvoke,
        BrokerTokenClass::UserManage,
        BrokerTokenClass::Admin,
    ] {
        let agent = class == BrokerTokenClass::AgentInvoke;
        let issued = store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: "administrative issuance".into(),
                    token_class: class,
                    scopes: if agent {
                        issuance_request("alice", false).scopes
                    } else {
                        json!({})
                    },
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap();
        assert_created_at(&issued.record);
        if agent {
            agent_token_ids.push(issued.record.token_id);
        }
    }

    // Make chronological and token-ID ordering disagree deterministically.
    // Both fixtures occupy the same second, so dropping fractional precision
    // would incorrectly order the earlier token first on the UUID tie-break.
    agent_token_ids.sort();
    let timestamps = [
        "2026-01-01T00:00:00.100000001+00:00",
        "2026-01-01T00:00:00.900000009+00:00",
    ];
    {
        let conn = store.connection.lock().unwrap();
        for (token_id, timestamp) in agent_token_ids.iter().zip(timestamps) {
            conn.execute(
                "UPDATE broker_tokens SET created_at=?2 WHERE token_id=?1",
                params![token_id, timestamp],
            )
            .unwrap();
        }
    }
    let expected_ids = agent_token_ids.into_iter().rev().collect::<Vec<_>>();
    for records in [
        store.list_self_agent_tokens("alice", false, false).unwrap(),
        store.list_broker_tokens_for_principal("alice").unwrap(),
        store.list_broker_tokens().unwrap(),
    ] {
        let agent_tokens = records
            .into_iter()
            .filter(|token| token.token_class == BrokerTokenClass::AgentInvoke)
            .collect::<Vec<_>>();
        assert_eq!(
            agent_tokens
                .iter()
                .map(|token| token.token_id.clone())
                .collect::<Vec<_>>(),
            expected_ids
        );
        assert_eq!(
            agent_tokens
                .iter()
                .map(|token| token.created_at.as_str())
                .collect::<Vec<_>>(),
            timestamps.into_iter().rev().collect::<Vec<_>>()
        );
    }
}
