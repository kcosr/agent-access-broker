fn enrollment_group_request(group_id: &str, enabled: bool) -> GroupWriteRequest {
    GroupWriteRequest {
        group_id: group_id.into(),
        display_name: None,
        description: None,
        auto_enroll_new_microsoft_users: enabled,
        created_by: "admin".into(),
    }
}

fn enrollment_group_patch(group_id: &str, enabled: Option<bool>) -> GroupPatchRequest {
    GroupPatchRequest {
        group_id: group_id.into(),
        display_name: None,
        description: None,
        status: None,
        auto_enroll_new_microsoft_users: enabled,
        updated_by: "enrollment-admin".into(),
    }
}

fn enrollment_fixture(store: &ManagedStore) -> OidcProviderStateRecord {
    let provider = reconcile_test_oidc_provider(store, true, 3_600, "auto-enrollment");
    store.create_group(enrollment_group_request("mapped", false)).unwrap();
    store.create_external_group_binding(ExternalGroupBindingCreateRequest {
        external_group_id: TEST_EXTERNAL_GROUP_A.into(),
        group_id: "mapped".into(),
        actor: "admin".into(),
    }).unwrap();
    provider
}

fn enrollment_succeeded(outcome: OidcCompletionOutcome, expected_jit: bool) -> OidcCompleteLoginResult {
    let OidcCompletionOutcome::Succeeded { result, jit_created } = outcome else {
        panic!("expected successful enrollment")
    };
    assert_eq!(jit_created, expected_jit);
    *result
}

#[test]
fn group_auto_enrollment_settings_capture_changes_and_noop_writes_nothing() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let off = store.create_group_with_effect(enrollment_group_request("off", false)).unwrap();
    assert!(!off.group.auto_enroll_new_microsoft_users);
    assert!(off.auto_enrollment_change.is_none());
    let on = store.create_group_with_effect(enrollment_group_request("on", true)).unwrap();
    assert_eq!(on.auto_enrollment_change, Some(GroupAutoEnrollmentChange { previous: false, current: true }));
    assert_eq!(serde_json::to_value(&on.group).unwrap()["autoEnrollNewMicrosoftUsers"], true);
    assert!(store.list_groups().unwrap().iter().find(|g| g.group_id == "on").unwrap().auto_enroll_new_microsoft_users);

    // An update trigger catches even a same-value UPDATE, independently of
    // filesystem timestamps and the precision of updated_at.
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER reject_enrollment_noop BEFORE UPDATE ON groups
         WHEN OLD.group_id = 'on' BEGIN SELECT RAISE(ABORT, 'no writes expected'); END;"
    ).unwrap();
    let unchanged = store.patch_group_with_effect(enrollment_group_patch("on", Some(true))).unwrap();
    assert_eq!(unchanged.group, on.group);
    assert!(unchanged.auto_enrollment_change.is_none());
    store.connection.lock().unwrap().execute_batch("DROP TRIGGER reject_enrollment_noop;").unwrap();

    let changed = store.patch_group_with_effect(enrollment_group_patch("on", Some(false))).unwrap();
    assert_eq!(changed.auto_enrollment_change, Some(GroupAutoEnrollmentChange { previous: true, current: false }));
    assert_eq!(changed.group.updated_by.as_deref(), Some("enrollment-admin"));
    assert!(!changed.group.auto_enroll_new_microsoft_users);
    assert!(matches!(store.patch_group(enrollment_group_patch("on", None)), Err(ManagedStoreError::InputInvalid(_))));
}

#[test]
fn group_auto_enrollment_is_once_only_local_and_resumes_for_future_accounts() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let provider = enrollment_fixture(&store);
    for name in ["z-baseline", "a-baseline", "paused"] {
        store.create_group(enrollment_group_request(name, true)).unwrap();
    }
    store.patch_group(enrollment_group_patch("mapped", Some(true))).unwrap();
    let mut pause = enrollment_group_patch("paused", None);
    pause.status = Some("disabled".into());
    assert!(store.patch_group(pause).unwrap().auto_enroll_new_microsoft_users);
    let now = normalized_now_string();
    let hasher = broker_token_hasher_for_test(74);
    let first = enrollment_succeeded(store.complete_oidc_login(&hasher, test_oidc_completion_request(
        1, provider.config_generation, TEST_OIDC_USER, "first", &[TEST_EXTERNAL_GROUP_A], &now,
    )).unwrap(), true);
    assert_eq!(first.auto_enrolled_group_ids, ["a-baseline", "mapped", "z-baseline"]);
    assert_eq!(first.membership.groups, first.auto_enrolled_group_ids);
    assert_eq!(first.principal.role, crate::PrincipalRole::User);
    let mapped = first.membership.details.iter().find(|d| d.group_id == "mapped").unwrap();
    assert_eq!(mapped.source, "local_and_microsoft");
    for group in &first.auto_enrolled_group_ids {
        let member = store.group_members(group).unwrap().remove(0);
        assert_eq!(member.created_at.as_deref(), Some(now.as_str()));
        assert_eq!(member.created_by.as_deref(), Some("oidc-microsoft"));
    }
    let expired_at = normalized_timestamp(DateTime::parse_from_rfc3339(&now).unwrap().with_timezone(&Utc) + Duration::seconds(3_601));
    let expired = store.effective_membership_at("first", &expired_at).unwrap();
    assert_eq!(expired.groups, first.auto_enrolled_group_ids);
    assert!(expired.details.iter().all(|d| d.source == "local"));

    store.patch_group(enrollment_group_patch("a-baseline", Some(false))).unwrap();
    store.remove_group("first", "z-baseline").unwrap();
    let mut resume = enrollment_group_patch("paused", None);
    resume.status = Some("active".into());
    store.patch_group(resume).unwrap();
    let returning = enrollment_succeeded(store.complete_oidc_login(&hasher, test_oidc_completion_request(
        2, provider.config_generation, TEST_OIDC_USER, "unused", &[], &now,
    )).unwrap(), false);
    assert!(returning.auto_enrolled_group_ids.is_empty());
    assert_eq!(returning.membership.groups, ["a-baseline", "mapped"]);
    assert!(returning.membership.details.iter().all(|d| d.source == "local"));
    let second = enrollment_succeeded(store.complete_oidc_login(&hasher, test_oidc_completion_request(
        3, provider.config_generation, TEST_OIDC_USER_TWO, "second", &[TEST_EXTERNAL_GROUP_A], &now,
    )).unwrap(), true);
    assert_eq!(second.auto_enrolled_group_ids, ["mapped", "paused", "z-baseline"]);
    assert_eq!(store.groups("first").unwrap(), ["a-baseline", "mapped"]);
}

#[test]
fn group_auto_enrollment_never_bypasses_admission_and_zero_defaults_work() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let provider = enrollment_fixture(&store);
    store.create_group(enrollment_group_request("default", true)).unwrap();
    let hasher = broker_token_hasher_for_test(75);
    let now = normalized_now_string();
    let request = test_oidc_completion_request(1, provider.config_generation, TEST_OIDC_USER, "first", &[], &now);
    assert!(matches!(store.complete_oidc_login(&hasher, request).unwrap(), OidcCompletionOutcome::Denied { reason } if reason == "no_mapped_group"));
    let mut request = test_oidc_completion_request(2, provider.config_generation, TEST_OIDC_USER, "first", &[TEST_EXTERNAL_GROUP_A], &now);
    request.jit_provisioning = false;
    assert!(matches!(store.complete_oidc_login(&hasher, request).unwrap(), OidcCompletionOutcome::Denied { reason } if reason == "jit_disabled"));
    assert!(store.list_principals().unwrap().is_empty());
    assert!(store.group_members("default").unwrap().is_empty());
    store.patch_group(enrollment_group_patch("default", Some(false))).unwrap();
    let created = enrollment_succeeded(store.complete_oidc_login(&hasher, test_oidc_completion_request(
        3, provider.config_generation, TEST_OIDC_USER, "first", &[TEST_EXTERNAL_GROUP_A], &now,
    )).unwrap(), true);
    assert!(created.auto_enrolled_group_ids.is_empty());
    assert_eq!(created.membership.groups, ["mapped"]);
    assert_eq!(created.membership.details[0].source, "microsoft");
}

#[test]
fn group_auto_enrollment_excludes_local_login_and_admin_linked_accounts() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let provider = enrollment_fixture(&store);
    store.create_group(enrollment_group_request("default", true)).unwrap();
    create_alice(&store);
    let passwords = local_password_hasher_for_test(76);
    let hasher = broker_token_hasher_for_test(77);
    store.enable_local_password(&passwords, local_write("first-password")).unwrap();
    store.authenticate_local_password_session(&passwords, &hasher, local_change("first-password", false).verification, 3600).unwrap();
    assert!(store.groups("alice").unwrap().is_empty());
    store.link_oidc_login_method(OidcLoginMethodLinkRequest { principal_id: "alice".into(), user_object_id: TEST_OIDC_USER.into(), actor: "admin".into() }).unwrap();
    let result = enrollment_succeeded(store.complete_oidc_login(&hasher, test_oidc_completion_request(
        1, provider.config_generation, TEST_OIDC_USER, "unused", &[TEST_EXTERNAL_GROUP_A], &normalized_now_string(),
    )).unwrap(), false);
    assert!(result.auto_enrolled_group_ids.is_empty());
    assert_eq!(result.membership.groups, ["mapped"]);
    assert!(store.group_members("default").unwrap().is_empty());
}

#[test]
fn group_auto_enrollment_unlinked_profile_match_creates_a_distinct_account() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let provider = enrollment_fixture(&store);
    store.create_group(enrollment_group_request("default", true)).unwrap();
    create_alice(&store);
    store.patch_principal(PrincipalPatchRequest { principal_id: "alice".into(), display_name: None, email: Some(Some("oidc@example.com".into())), status: None }).unwrap();
    let result = enrollment_succeeded(store.complete_oidc_login(&broker_token_hasher_for_test(78), test_oidc_completion_request(
        1, provider.config_generation, TEST_OIDC_USER, "new-user", &[TEST_EXTERNAL_GROUP_A], &normalized_now_string(),
    )).unwrap(), true);
    assert_eq!(result.principal.principal_id, "new-user");
    assert_eq!(result.auto_enrolled_group_ids, ["default"]);
    assert!(store.groups("alice").unwrap().is_empty());
}

#[test]
fn group_auto_enrollment_insert_failure_rolls_back_entire_new_account() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(&store_config(&temp.path().join("store.sqlite")), ManagedStoreOpenMode::Startup).unwrap();
    let provider = enrollment_fixture(&store);
    for name in ["a-default", "z-default"] {
        store.create_group(enrollment_group_request(name, true)).unwrap();
    }
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER reject_enrollment_insert BEFORE INSERT ON principal_groups
         WHEN NEW.group_id = 'z-default' BEGIN SELECT RAISE(ABORT, 'enrollment failure'); END;"
    ).unwrap();
    let request = test_oidc_completion_request(1, provider.config_generation, TEST_OIDC_USER, "new-user", &[TEST_EXTERNAL_GROUP_A], &normalized_now_string());
    let hasher = broker_token_hasher_for_test(79);
    assert!(matches!(store.complete_oidc_login(&hasher, request.clone()), Err(ManagedStoreError::Unavailable(_))));
    {
        let conn = store.connection.lock().unwrap();
        for table in ["principals", "principal_identity_access", "principal_identity_tokens", "principal_login_methods", "principal_groups", "external_principal_groups", "oidc_membership_refresh_state", "broker_tokens"] {
            let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap();
            assert_eq!(count, 0, "{table} must roll back");
        }
        conn.execute_batch("DROP TRIGGER reject_enrollment_insert;").unwrap();
    }
    // The flow watermark also rolled back, allowing the same request to commit.
    let created = enrollment_succeeded(store.complete_oidc_login(&hasher, request).unwrap(), true);
    assert_eq!(created.auto_enrolled_group_ids, ["a-default", "z-default"]);
}

#[test]
fn group_auto_enrollment_serializes_with_a_pending_admin_setting_change() {
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    thread_local! {
        static ENROLLMENT_WRITE_WAIT: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
    }
    for enable in [false, true] {
        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        let provider = enrollment_fixture(&store);
        store.create_group(enrollment_group_request("default", !enable)).unwrap();
        let other = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        let mut conn = store.connection.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
        tx.execute("UPDATE groups SET auto_enroll_new_microsoft_users = ?1 WHERE group_id = 'default'", [enable]).unwrap();
        let (blocked, ready) = channel();
        let (resume, released) = channel();
        let task = thread::spawn(move || {
            ENROLLMENT_WRITE_WAIT.with(|slot| *slot.borrow_mut() = Some((blocked, released)));
            other.connection.lock().unwrap().busy_handler(Some(|_| {
                ENROLLMENT_WRITE_WAIT.with(|slot| {
                    let Some((blocked, released)) = slot.borrow_mut().take() else { return false; };
                    blocked.send(()).is_ok() && released.recv().is_ok()
                })
            })).unwrap();
            other.complete_oidc_login(&broker_token_hasher_for_test(80), test_oidc_completion_request(
                1, provider.config_generation, TEST_OIDC_USER, "new-user", &[TEST_EXTERNAL_GROUP_A], &normalized_now_string(),
            ))
        });
        ready.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        tx.commit().unwrap();
        drop(conn);
        resume.send(()).unwrap();
        let result = enrollment_succeeded(task.join().unwrap().unwrap(), true);
        let expected: Vec<&str> = if enable { vec!["default"] } else { vec![] };
        assert_eq!(result.auto_enrolled_group_ids, expected);
    }
}

#[test]
fn group_auto_enrollment_migration_defaults_existing_groups_to_false_and_preserves_state() {
    for version in [MANAGED_STORE_COMMAND_IMPORTS_VERSION, MANAGED_STORE_OAUTH_REVOCATIONS_VERSION,
        MANAGED_STORE_IDENTITY_ACCESS_PATH_CONTROLS_VERSION] {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("previous.sqlite");
    let config = store_config(&path);
    let previous = ManagedStore::open_with_catalog(&config, ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(version)).unwrap();
    previous.connection.lock().unwrap().execute_batch(
        "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)
         VALUES ('alice','user','active','2026-01-01','2026-01-01','admin','user',1);
         INSERT INTO groups (group_id, status, created_at, created_by, updated_at, updated_by)
         VALUES ('existing', 'active', '2026-01-01', 'admin', '2026-01-02', 'updater');
         INSERT INTO principal_groups (principal_id, group_id, created_at, created_by)
         VALUES ('alice', 'existing', '2026-01-03', 'admin');"
    ).unwrap();
    drop(previous);
    let ledger = migration_rows(&path);
    let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
    assert!(store.migration_applied_this_open(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION));
    let group = store.group("existing").unwrap();
    assert!(!group.auto_enroll_new_microsoft_users);
    assert_eq!(group.updated_at.as_deref(), Some("2026-01-02"));
    assert_eq!(group.updated_by.as_deref(), Some("updater"));
    assert_eq!(store.groups("alice").unwrap(), ["existing"]);
    let upgraded = migration_rows(&path);
    assert_eq!(&upgraded[..ledger.len()], ledger.as_slice());
    assert_eq!(upgraded.len(), MANAGED_STORE_MIGRATIONS.len());
    assert!(!store.identity_token_metadata("alice").unwrap().configured);
    let conn = store.connection.lock().unwrap();
    for value in ["NULL", "-1", "2", "'enabled'"] {
        assert!(conn.execute(&format!("UPDATE groups SET auto_enroll_new_microsoft_users = {value} WHERE group_id = 'existing'"), []).is_err(), "{value}");
    }
    }
}

#[test]
fn group_auto_enrollment_latest_validation_keeps_prior_identity_and_schema_invariants() {
    for corruption in [
        "ALTER TABLE groups DROP COLUMN auto_enroll_new_microsoft_users;",
        "DELETE FROM principal_identity_tokens WHERE principal_id = 'alice';",
    ] {
        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        create_alice(&store);
        store.connection.lock().unwrap().execute_batch(corruption).unwrap();
        drop(store);
        assert!(matches!(ManagedStore::open(&config, ManagedStoreOpenMode::Reload), Err(ManagedStoreError::SchemaInvalid(_))), "{corruption}");
    }
}
