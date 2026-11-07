fn context_registry(names: &[&str]) -> ConfiguredExecutionContexts {
    ConfiguredExecutionContexts::from_config(Some(&crate::ExecutionContextConfig {
        allowed_values: names.iter().map(|name| (*name).into()).collect(),
        default_context: names.first().map(|name| (*name).into()),
    }))
    .unwrap()
}

fn context_principal(
    mode: PrincipalAgentTokenIssuance,
    names: &[&str],
) -> PrincipalAgentTokenIssuanceSetting {
    PrincipalAgentTokenIssuanceSetting::new(mode, names.iter().map(|name| (*name).into()).collect())
        .unwrap()
}

fn context_group(mode: AgentTokenIssuanceMode, names: &[&str]) -> GroupAgentTokenIssuanceSetting {
    GroupAgentTokenIssuanceSetting::new(mode, names.iter().map(|name| (*name).into()).collect())
        .unwrap()
}

#[test]
fn issuance_context_settings_reject_noncanonical_contracts_and_sort_sets() {
    for value in [
        json!("read_only"),
        json!(null),
        json!({}),
        json!({"mode":"inherit"}),
        json!({"allowedExecutionContexts":[]}),
        json!({"mode":"inherit","allowedExecutionContexts":[],"extra":true}),
        json!({"mode":"inherit","allowedExecutionContexts":["internal"]}),
        json!({"mode":"disabled","allowedExecutionContexts":["internal"]}),
        json!({"mode":"read_only","allowedExecutionContexts":[]}),
        json!({"mode":"write_capable","allowedExecutionContexts":null}),
        json!({"mode":"write_capable","allowedExecutionContexts":["Internal"]}),
        json!({"mode":"write_capable","allowedExecutionContexts":["internal","internal"]}),
        json!({"mode":"write_capable","allowedExecutionContexts":[1]}),
    ] {
        assert!(
            serde_json::from_value::<PrincipalAgentTokenIssuanceSetting>(value.clone()).is_err(),
            "{value}"
        );
        assert!(
            serde_json::from_value::<GroupAgentTokenIssuanceSetting>(value.clone()).is_err(),
            "{value}"
        );
    }
    assert!(
        serde_json::from_value::<GroupAgentTokenIssuanceSetting>(
            json!({"mode":"inherit","allowedExecutionContexts":[]})
        )
        .is_err()
    );
    let setting: PrincipalAgentTokenIssuanceSetting = serde_json::from_value(
        json!({"mode":"write_capable","allowedExecutionContexts":["internal","external"]}),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&setting).unwrap(),
        json!({"mode":"write_capable","allowedExecutionContexts":["external","internal"]})
    );
    assert!(setting.validate(&context_registry(&["internal"])).is_err());
    assert!(
        PrincipalAgentTokenIssuanceSetting::new(
            PrincipalAgentTokenIssuance::ReadOnly,
            (0..65).map(|i| format!("ctx{i}")).collect()
        )
        .is_err()
    );
}

#[test]
fn issuance_context_resolution_keeps_per_context_winners_and_explicit_overrides() {
    let registry = context_registry(&["internal", "external", "future"]);
    let contributions = vec![
        (
            "internal-writers".into(),
            context_group(AgentTokenIssuanceMode::WriteCapable, &["internal"]),
        ),
        (
            "external-readers".into(),
            context_group(AgentTokenIssuanceMode::ReadOnly, &["external", "internal"]),
        ),
        (
            "a-writers".into(),
            context_group(AgentTokenIssuanceMode::WriteCapable, &["internal"]),
        ),
        (
            "a-writers".into(),
            context_group(AgentTokenIssuanceMode::WriteCapable, &["internal"]),
        ),
        ("disabled".into(), GroupAgentTokenIssuanceSetting::default()),
    ];
    let policy = agent_token_issuance::resolve_policy(
        &PrincipalAgentTokenIssuanceSetting::default(),
        contributions.clone(),
        &registry,
    );
    assert_eq!(
        serde_json::to_value(&policy).unwrap(),
        json!({"source":"groups","contexts":[
            {"executionContext":"internal","mode":"write_capable","groupIds":["a-writers","internal-writers"]},
            {"executionContext":"external","mode":"read_only","groupIds":["external-readers"]}
        ]})
    );
    let override_policy = agent_token_issuance::resolve_policy(
        &context_principal(PrincipalAgentTokenIssuance::ReadOnly, &["external"]),
        contributions.clone(),
        &registry,
    );
    assert_eq!(
        serde_json::to_value(override_policy).unwrap(),
        json!({"source":"user","contexts":[{"executionContext":"external","mode":"read_only","groupIds":[]}]})
    );
    let disabled = agent_token_issuance::resolve_policy(
        &context_principal(PrincipalAgentTokenIssuance::Disabled, &[]),
        contributions,
        &registry,
    );
    assert_eq!(
        serde_json::to_value(disabled).unwrap(),
        json!({"source":"user","contexts":[]})
    );
}

#[test]
fn issuance_context_writes_validate_atomically_and_reordering_is_a_true_noop() {
    let (_temp, store) = identity_test_store();
    let registry = context_registry(&["internal", "external"]);
    let mut request = identity_user_request("alice");
    request.role = PrincipalRole::Admin;
    request.agent_token_issuance = context_principal(
        PrincipalAgentTokenIssuance::WriteCapable,
        &["internal", "external"],
    );
    let original = store.create_principal(request.clone(), &registry).unwrap();
    let admin_token = access_token(&store, "alice", BrokerTokenClass::Admin).unwrap();
    let mut group_request = issuance_group_request("writers", AgentTokenIssuanceMode::Disabled);
    group_request.agent_token_issuance =
        context_group(AgentTokenIssuanceMode::ReadOnly, &["internal", "external"]);
    let group = store.create_group(group_request, &registry).unwrap();
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER reject_principal_context_delete BEFORE DELETE ON principal_agent_token_issuance_contexts BEGIN SELECT RAISE(ABORT,'unexpected context write'); END;
         CREATE TEMP TRIGGER reject_group_context_delete BEFORE DELETE ON group_agent_token_issuance_contexts BEGIN SELECT RAISE(ABORT,'unexpected context write'); END;
         CREATE TEMP TRIGGER reject_principal_context_noop BEFORE UPDATE ON principals BEGIN SELECT RAISE(ABORT,'unexpected owner write'); END;
         CREATE TEMP TRIGGER reject_group_context_noop BEFORE UPDATE ON groups BEGIN SELECT RAISE(ABORT,'unexpected owner write'); END;"
    ).unwrap();
    let mut policy = original.agent_token_issuance.clone();
    policy.allowed_execution_contexts.reverse();
    let mut patch = issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled);
    patch.agent_token_issuance = Some(policy);
    let unchanged = store.patch_principal_access(patch, &registry).unwrap();
    assert_eq!(unchanged.principal, original);
    let mut policy = group.agent_token_issuance.clone();
    policy.allowed_execution_contexts.reverse();
    let mut patch = issuance_group_patch("writers", AgentTokenIssuanceMode::Disabled);
    patch.agent_token_issuance = Some(policy);
    let unchanged = store.patch_group_with_effect(patch, &registry).unwrap();
    assert_eq!(unchanged.group, group);
    assert!(unchanged.agent_token_issuance_change.is_none());
    // Registry validation precedes every write, including an otherwise valid role edit.
    let mut patch = issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled);
    patch.role = Some(PrincipalRole::Auditor);
    patch.agent_token_issuance = Some(context_principal(
        PrincipalAgentTokenIssuance::ReadOnly,
        &["unknown"],
    ));
    assert!(matches!(
        store.patch_principal_access(patch, &registry),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    assert_eq!(store.principal("alice").unwrap(), original);
    request.principal_id = "new-user".into();
    request.agent_token_issuance =
        context_principal(PrincipalAgentTokenIssuance::ReadOnly, &["unknown"]);
    assert!(
        store
            .create_or_update_principal(request, &registry)
            .is_err()
    );
    assert!(matches!(
        store.principal("new-user"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    store.connection.lock().unwrap().execute_batch(
        "DROP TRIGGER reject_principal_context_delete; DROP TRIGGER reject_group_context_delete;
         DROP TRIGGER reject_principal_context_noop; DROP TRIGGER reject_group_context_noop;"
    ).unwrap();
    let mut patch = issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled);
    patch.agent_token_issuance = Some(context_principal(
        PrincipalAgentTokenIssuance::WriteCapable,
        &["external"],
    ));
    let changed = store.patch_principal_access(patch, &registry).unwrap();
    assert_eq!(
        changed.previous_agent_token_issuance,
        original.agent_token_issuance
    );
    assert_eq!(
        changed
            .principal
            .agent_token_issuance
            .allowed_execution_contexts,
        ["external"]
    );
    assert_eq!(changed.principal.role, PrincipalRole::Admin);
    assert!(changed.revoked_admin_token_ids.is_empty());
    assert!(changed.removed_services.is_empty());
    assert!(
        store
            .broker_token(&admin_token.record.token_id)
            .unwrap()
            .revoked_at
            .is_none()
    );
    let mut patch = issuance_group_patch("writers", AgentTokenIssuanceMode::Disabled);
    patch.agent_token_issuance = Some(context_group(
        AgentTokenIssuanceMode::ReadOnly,
        &["internal"],
    ));
    let changed = store.patch_group_with_effect(patch, &registry).unwrap();
    let change = changed.agent_token_issuance_change.unwrap();
    assert_eq!(change.previous, group.agent_token_issuance);
    assert_eq!(change.current.allowed_execution_contexts, ["internal"]);
    assert_eq!(change.current.mode, change.previous.mode);
}

#[test]
fn issuance_context_transactions_reject_whole_requests_and_preserve_issued_tokens() {
    let (_temp, store) = identity_test_store();
    let registry = context_registry(&["internal", "external", "future"]);
    let environment =
        AgentTokenIssuanceEnvironment::new(AgentTokenIssuanceAuthority::Managed, registry.clone());
    store
        .create_principal(identity_user_request("alice"), &registry)
        .unwrap();
    for (id, mode, contexts) in [
        (
            "writers",
            AgentTokenIssuanceMode::WriteCapable,
            &["internal"][..],
        ),
        (
            "readers",
            AgentTokenIssuanceMode::ReadOnly,
            &["external"][..],
        ),
    ] {
        let mut request = issuance_group_request(id, AgentTokenIssuanceMode::Disabled);
        request.agent_token_issuance = context_group(mode, contexts);
        store.create_group(request, &registry).unwrap();
        store.add_group("alice", id, "admin").unwrap();
    }
    let hasher = broker_token_hasher_for_test(76);
    let issue = |contexts: &[&str], read_only| {
        let mut request = issuance_request("alice", read_only);
        request.scopes["allowedExecutionContexts"] = json!(contexts);
        store.issue_self_agent_token(&hasher, request, &environment)
    };
    let internal = issue(&["internal"], false).unwrap();
    let mixed = issue(&["internal", "external"], true).unwrap();
    assert_eq!(
        mixed.issuance_policy.as_ref().unwrap(),
        &store
            .agent_token_issuance_policy("alice", &environment)
            .unwrap()
    );
    for (contexts, read_only, category) in [
        (
            &["external"][..],
            false,
            TokenIssuanceDenial::ReadOnlyRequired,
        ),
        (
            &["internal", "external"][..],
            false,
            TokenIssuanceDenial::ReadOnlyRequired,
        ),
        (
            &["external", "future"][..],
            false,
            TokenIssuanceDenial::ContextNotAllowed,
        ),
        (
            &["future"][..],
            true,
            TokenIssuanceDenial::ContextNotAllowed,
        ),
    ] {
        assert!(
            matches!(issue(contexts, read_only), Err(ManagedStoreError::TokenIssuanceDenied { category: actual }) if actual == category)
        );
    }
    assert_eq!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .len(),
        2
    );
    let saved = store.broker_token(&internal.record.token_id).unwrap();
    store
        .patch_principal_access(
            issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled),
            &registry,
        )
        .unwrap();
    assert!(matches!(
        issue(&["future"], false),
        Err(ManagedStoreError::TokenIssuanceDenied {
            category: TokenIssuanceDenial::Disabled
        })
    ));
    assert_eq!(
        serde_json::to_value(store.broker_token(&internal.record.token_id).unwrap()).unwrap(),
        serde_json::to_value(saved).unwrap()
    );
    let mut admin_request = BrokerTokenIssueRequest {
        principal_id: "alice".into(),
        name: "admin-issued".into(),
        token_class: BrokerTokenClass::AgentInvoke,
        scopes: json!({"readOnly":false,"allowedExecutionContexts":["external"]}),
        expires_at: None,
        created_by: "admin".into(),
    };
    assert!(
        store
            .issue_broker_token(&hasher, admin_request.clone())
            .unwrap()
            .issuance_policy
            .is_none()
    );
    admin_request.name = "second-admin-issued".into();
    assert!(store.issue_broker_token(&hasher, admin_request).is_ok());
}

fn contexts_previous_schema(path: &Path) -> ManagedStore {
    let store = ManagedStore::open_with_catalog(
        &store_config(path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(MANAGED_STORE_AGENT_TOKEN_ISSUANCE_VERSION),
    )
    .unwrap();
    store.connection.lock().unwrap().execute_batch(
        "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled,agent_token_issuance)
         VALUES('alice','system','disabled','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','user',1,'write_capable'),
               ('reader','system','active','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','user',1,'read_only'),
               ('inheritor','system','active','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','user',1,'inherit'),
               ('denied','system','active','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','admin','user',1,'disabled');
         INSERT INTO groups(group_id,status,created_at,created_by,updated_at,updated_by,agent_token_issuance)
         VALUES('writers','disabled','2026-01-01T00:00:00Z','admin','2026-01-02T00:00:00Z','admin','write_capable'),
               ('readers','active','2026-01-01T00:00:00Z','admin','2026-01-02T00:00:00Z','admin','read_only'),
               ('denied','active','2026-01-01T00:00:00Z','admin','2026-01-02T00:00:00Z','admin','disabled');"
    ).unwrap();
    store
}

#[test]
fn issuance_context_migration_seeds_once_from_registry_without_touching_owner_or_token_bytes() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("contexts.sqlite");
    let old = contexts_previous_schema(&path);
    for state in ["active", "paused", "expired", "revoked"] {
        issuance_old_token(
            &old,
            BrokerTokenClass::AgentInvoke,
            r#"{ "readOnly": false, "allowedExecutionContexts":["default"] }"#,
            state,
        );
    }
    let tables = ["principals", "groups", "broker_tokens", "principal_groups"];
    let before: Vec<_> = {
        let conn = old.connection.lock().unwrap();
        tables
            .iter()
            .map(|table| issuance_table_rows(&conn, table))
            .collect()
    };
    drop(old);
    let registry = context_registry(&["internal", "external"]);
    let previous_ledger = migration_rows(&path);
    for (mode, auto_migrate) in [
        (ManagedStoreOpenMode::Reload, true),
        (ManagedStoreOpenMode::Startup, false),
    ] {
        let mut config = store_config(&path);
        config.auto_migrate = auto_migrate;
        assert!(matches!(
            ManagedStore::open(&config, &registry, mode),
            Err(ManagedStoreError::MigrationRequired)
        ));
        assert_eq!(migration_rows(&path), previous_ledger);
    }

    let store = ManagedStore::open(
        &store_config(&path),
        &registry,
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(
        store
            .applied_migrations_this_open
            .contains(MANAGED_STORE_AGENT_TOKEN_ISSUANCE_CONTEXTS_VERSION)
    );
    let conn = store.connection.lock().unwrap();
    for (table, before) in tables.into_iter().zip(before) {
        assert_eq!(issuance_table_rows(&conn, table), before, "{table}");
    }
    for (is_principal, owner, expected) in [
        (true, "alice", vec!["external", "internal"]),
        (true, "reader", vec!["external", "internal"]),
        (true, "inheritor", vec![]),
        (true, "denied", vec![]),
        (false, "writers", vec!["external", "internal"]),
        (false, "readers", vec!["external", "internal"]),
        (false, "denied", vec![]),
    ] {
        assert_eq!(
            agent_token_issuance::load_contexts(&conn, is_principal, owner).unwrap(),
            expected
        );
    }
    drop(conn);
    drop(store);
    let reopened = ManagedStore::open(
        &store_config(&path),
        &context_registry(&["future", "external", "internal"]),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(reopened.applied_migrations_this_open.is_empty());
    assert_eq!(
        reopened
            .principal("alice")
            .unwrap()
            .agent_token_issuance
            .allowed_execution_contexts,
        ["external", "internal"]
    );
    assert!(
        reopened
            .create_principal(identity_user_request("fresh"), &registry)
            .unwrap()
            .agent_token_issuance
            .allowed_execution_contexts
            .is_empty()
    );
}

#[test]
fn issuance_context_migration_failure_rolls_back_tables_seed_and_ledger() {
    fn failed_seed(
        conn: &Connection,
        registry: &ConfiguredExecutionContexts,
    ) -> Result<(), ManagedStoreError> {
        agent_token_issuance::seed_contexts(conn, registry)?;
        Err(ManagedStoreError::SchemaInvalid(
            "injected after context seed".into(),
        ))
    }
    fn failed_ledger(
        conn: &Connection,
        registry: &ConfiguredExecutionContexts,
    ) -> Result<(), ManagedStoreError> {
        agent_token_issuance::seed_contexts(conn, registry)?;
        // TEMP leaves the supported schema unchanged while rejecting the final ledger step.
        conn.execute_batch(
            "CREATE TEMP TRIGGER reject_context_ledger BEFORE INSERT ON main.schema_migrations
            WHEN NEW.version='034_agent_token_issuance_contexts'
            BEGIN SELECT RAISE(ABORT,'injected context ledger failure'); END;",
        )
        .map_err(sql_unavailable)
    }
    type TestSeed = fn(&Connection, &ConfiguredExecutionContexts) -> Result<(), ManagedStoreError>;
    for (stage, seed) in [
        ("seed", failed_seed as TestSeed),
        ("ledger", failed_ledger as TestSeed),
    ] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("rollback.sqlite");
        drop(contexts_previous_schema(&path));
        let before = migration_rows(&path);
        let mut migrations = MANAGED_STORE_MIGRATIONS.to_vec();
        migrations
            .iter_mut()
            .find(|migration| {
                migration.version == MANAGED_STORE_AGENT_TOKEN_ISSUANCE_CONTEXTS_VERSION
            })
            .expect("issuance-context migration is present")
            .seed = Some(seed);
        let error = ManagedStore::open_with_catalog(
            &store_config(&path),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &migrations,
            },
        )
        .unwrap_err();
        if stage == "ledger" {
            assert!(
                matches!(error, ManagedStoreError::Unavailable(message) if message.contains("failed to record managed store migration 034_agent_token_issuance_contexts"))
            );
        } else {
            assert!(
                matches!(error, ManagedStoreError::SchemaInvalid(message) if message == "injected after context seed")
            );
        }
        assert_eq!(migration_rows(&path), before, "{stage}");
        let conn = Connection::open(&path).unwrap();
        assert!(
            !sqlite_support::sqlite_object_exists(
                &conn,
                "table",
                "principal_agent_token_issuance_contexts"
            )
            .unwrap(),
            "{stage}"
        );
        assert!(
            !sqlite_support::sqlite_object_exists(
                &conn,
                "table",
                "group_agent_token_issuance_contexts"
            )
            .unwrap(),
            "{stage}"
        );
        drop(conn);
        let upgraded = ManagedStore::open(
            &store_config(&path),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert_eq!(
            upgraded
                .principal("alice")
                .unwrap()
                .agent_token_issuance
                .allowed_execution_contexts,
            ["default"]
        );
    }
}

#[test]
fn issuance_context_migration_concurrent_openers_seed_exactly_one_snapshot() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("concurrent.sqlite");
    drop(contexts_previous_schema(&path));
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = ["alpha", "beta"]
        .into_iter()
        .map(|context| {
            let path = path.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                ManagedStore::open(
                    &store_config(&path),
                    &context_registry(&[context]),
                    ManagedStoreOpenMode::Startup,
                )
                .unwrap()
            })
        })
        .collect();
    let stores: Vec<_> = threads
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect();
    assert_eq!(
        stores
            .iter()
            .filter(|store| store
                .applied_migrations_this_open
                .contains(MANAGED_STORE_AGENT_TOKEN_ISSUANCE_CONTEXTS_VERSION))
            .count(),
        1
    );
    let first = &stores[0];
    let values = first
        .principal("alice")
        .unwrap()
        .agent_token_issuance
        .allowed_execution_contexts;
    assert!(values == ["alpha"] || values == ["beta"]);
    assert_eq!(
        first
            .group("writers")
            .unwrap()
            .agent_token_issuance
            .allowed_execution_contexts,
        values
    );
}

#[test]
fn issuance_context_structural_validation_rejects_invalid_lists_and_foreign_keys() {
    for sql in [
        "UPDATE principals SET agent_token_issuance='write_capable' WHERE principal_id='alice'",
        "INSERT INTO principal_agent_token_issuance_contexts VALUES('alice','internal')",
        "UPDATE principals SET agent_token_issuance='read_only' WHERE principal_id='alice'; INSERT INTO principal_agent_token_issuance_contexts VALUES('alice','Invalid')",
        "INSERT INTO group_agent_token_issuance_contexts VALUES('missing','internal')",
        "UPDATE groups SET agent_token_issuance='read_only' WHERE group_id='readers'",
        "DROP TABLE group_agent_token_issuance_contexts",
    ] {
        let (temp, store) = identity_test_store();
        store
            .create_principal(identity_user_request("alice"), &test_execution_contexts())
            .unwrap();
        store
            .create_group(
                issuance_group_request("readers", AgentTokenIssuanceMode::Disabled),
                &test_execution_contexts(),
            )
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(&format!("PRAGMA foreign_keys=OFF; {sql};"))
            .unwrap();
        drop(store);
        assert!(
            matches!(
                ManagedStore::open(
                    &store_config(&temp.path().join("store.sqlite")),
                    &test_execution_contexts(),
                    ManagedStoreOpenMode::Reload
                ),
                Err(ManagedStoreError::SchemaInvalid(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn issuance_context_retirement_always_checks_principals_but_only_active_authority_groups() {
    let (_temp, store) = identity_test_store();
    let registry = context_registry(&["principal-context", "group-context"]);
    let mut request = identity_user_request("alice");
    request.agent_token_issuance = context_principal(
        PrincipalAgentTokenIssuance::ReadOnly,
        &["principal-context"],
    );
    store.create_principal(request, &registry).unwrap();
    store.set_principal_enabled("alice", false).unwrap();
    let mut group_request = issuance_group_request("dormant", AgentTokenIssuanceMode::Disabled);
    group_request.agent_token_issuance =
        context_group(AgentTokenIssuanceMode::ReadOnly, &["group-context"]);
    store.create_group(group_request, &registry).unwrap();
    let mut patch = issuance_group_patch("dormant", AgentTokenIssuanceMode::Disabled);
    patch.agent_token_issuance = None;
    patch.status = Some("disabled".into());
    store.patch_group(patch, &registry).unwrap();
    let retained_principal = context_registry(&["principal-context"]);
    assert!(
        store
            .validate_agent_token_issuance_context_references(&AgentTokenIssuanceEnvironment::new(
                AgentTokenIssuanceAuthority::Toml,
                retained_principal.clone()
            ))
            .is_ok()
    );
    assert!(
        store
            .validate_agent_token_issuance_context_references(&AgentTokenIssuanceEnvironment::new(
                AgentTokenIssuanceAuthority::Managed,
                retained_principal
            ))
            .is_err()
    );
    for authority in [
        AgentTokenIssuanceAuthority::Toml,
        AgentTokenIssuanceAuthority::Managed,
    ] {
        assert!(
            store
                .validate_agent_token_issuance_context_references(
                    &AgentTokenIssuanceEnvironment::new(
                        authority,
                        context_registry(&["group-context"])
                    )
                )
                .is_err()
        );
    }
}

#[test]
fn issuance_context_current_schema_validation_uses_one_snapshot_during_policy_write() {
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    thread_local! {
        static VALIDATION_WAIT: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
    }
    let (temp, reader) = identity_test_store();
    let mut request = identity_user_request("alice");
    request.agent_token_issuance = test_principal_issuance(PrincipalAgentTokenIssuance::ReadOnly);
    reader
        .create_principal(request, &test_execution_contexts())
        .unwrap();
    let writer = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Reload,
    )
    .unwrap();
    let (blocked, ready) = channel();
    let (resume, released) = channel();
    let validate_current_schema = production_migration_catalog()
        .latest()
        .unwrap()
        .structural_validation;
    let task = thread::spawn(move || {
        VALIDATION_WAIT.with(|slot| *slot.borrow_mut() = Some((blocked, released)));
        let conn = reader.connection.lock().unwrap();
        conn.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| {
                if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event
                    && sql.starts_with(
                        "SELECT execution_context FROM principal_agent_token_issuance_contexts",
                    )
                {
                    VALIDATION_WAIT.with(|slot| {
                        if let Some((blocked, released)) = slot.borrow_mut().take() {
                            blocked.send(()).unwrap();
                            released
                                .recv_timeout(std::time::Duration::from_secs(10))
                                .unwrap();
                        }
                    });
                }
            }),
        );
        validate_current_schema(&conn)
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    writer
        .patch_principal_access(
            issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled),
            &test_execution_contexts(),
        )
        .unwrap();
    resume.send(()).unwrap();
    task.join().unwrap().unwrap();
    assert_eq!(
        writer.principal("alice").unwrap().agent_token_issuance,
        PrincipalAgentTokenIssuanceSetting::new(PrincipalAgentTokenIssuance::Disabled, vec![])
            .unwrap()
    );
}

#[test]
fn issuance_context_stale_projection_conflicts_without_relabeling_writes_or_corruption() {
    for inherited in [false, true] {
        let (_temp, store) = identity_test_store();
        let previous_registry = test_execution_contexts();
        let registry = context_registry(&["default", "new-context"]);
        let previous_environment = AgentTokenIssuanceEnvironment::new(
            AgentTokenIssuanceAuthority::Managed,
            previous_registry.clone(),
        );
        let environment = AgentTokenIssuanceEnvironment::new(
            AgentTokenIssuanceAuthority::Managed,
            registry.clone(),
        );
        store
            .create_principal(identity_user_request("alice"), &previous_registry)
            .unwrap();
        if inherited {
            let mut request = issuance_group_request("issuers", AgentTokenIssuanceMode::Disabled);
            request.agent_token_issuance = context_group(
                AgentTokenIssuanceMode::ReadOnly,
                &["default", "new-context"],
            );
            // Submitted contexts remain a request error under the older registry.
            assert!(matches!(
                store.create_group(request.clone(), &previous_registry),
                Err(ManagedStoreError::InputInvalid(_))
            ));
            store.create_group(request, &registry).unwrap();
            store.add_group("alice", "issuers", "admin").unwrap();
        } else {
            let mut patch = issuance_access_patch("alice", PrincipalAgentTokenIssuance::Disabled);
            patch.agent_token_issuance = Some(context_principal(
                PrincipalAgentTokenIssuance::ReadOnly,
                &["default", "new-context"],
            ));
            assert!(matches!(
                store.patch_principal_access(patch.clone(), &previous_registry),
                Err(ManagedStoreError::InputInvalid(_))
            ));
            store.patch_principal_access(patch, &registry).unwrap();
        }
        assert!(matches!(
            store.agent_token_issuance_policy("alice", &previous_environment),
            Err(ManagedStoreError::VersionConflict)
        ));
        let fresh = store
            .agent_token_issuance_policy("alice", &environment)
            .unwrap();
        assert_eq!(
            fresh
                .contexts
                .iter()
                .map(|row| row.execution_context.as_str())
                .collect::<Vec<_>>(),
            ["default", "new-context"]
        );
        let hasher = broker_token_hasher_for_test(79);
        assert!(matches!(
            store.issue_self_agent_token(
                &hasher,
                issuance_request("alice", true),
                &previous_environment
            ),
            Err(ManagedStoreError::VersionConflict)
        ));
        assert!(
            store
                .list_self_agent_tokens("alice", true, true)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .issue_self_agent_token(&hasher, issuance_request("alice", true), &environment)
                .is_ok()
        );
        // Malformed stored data is corruption, even when the snapshot is stale.
        let table = if inherited {
            "group_agent_token_issuance_contexts"
        } else {
            "principal_agent_token_issuance_contexts"
        };
        store.connection.lock().unwrap().execute(&format!("UPDATE {table} SET execution_context='Invalid' WHERE execution_context='new-context'"), []).unwrap();
        assert!(matches!(
            store.agent_token_issuance_policy("alice", &previous_environment),
            Err(ManagedStoreError::SchemaInvalid(_))
        ));
    }
}
