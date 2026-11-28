use super::*;
use crate::AccessKeyType;
use serde_json::json;
use tempfile::TempDir;

fn access_key_type(id: &str, self_service: bool) -> AccessKeyType {
    AccessKeyType {
        id: id.into(),
        display_name: id.into(),
        description: None,
        lifetime_options: vec!["600s".into(), "1h".into()],
        default_lifetime: "1h".into(),
        self_service,
    }
}

/// `inference` and `packages` are open to self-service; `batch` is not.
fn configured() -> AccessKeyTypes {
    AccessKeyTypes::for_test([
        access_key_type("inference", true),
        access_key_type("packages", true),
        access_key_type("batch", false),
    ])
}

fn store() -> (TempDir, ManagedStore) {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (id, kind) in [
        ("usr-alice", "user"),
        ("usr-bob", "user"),
        ("robot", "service_account"),
    ] {
        store
            .create_principal(
                PrincipalWriteRequest {
                    principal_id: id.into(),
                    kind: kind.into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                    role: crate::PrincipalRole::User,
                    self_service_enabled: Some(false),
                    agent_token_issuance: test_principal_issuance(
                        PrincipalAgentTokenIssuance::Disabled,
                    ),
                },
                &test_execution_contexts(),
            )
            .unwrap();
    }
    (temp, store)
}

fn group(store: &ManagedStore, id: &str, members: &[&str]) {
    store
        .create_group(
            GroupWriteRequest {
                group_id: id.into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: test_group_issuance(AgentTokenIssuanceMode::Disabled),
                created_by: "admin".into(),
            },
            &test_execution_contexts(),
        )
        .unwrap();
    for member in members {
        store.add_group(member, id, "admin").unwrap();
    }
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

/// Each configured access key type's decision for `principal`: whether it is
/// allowed, where that comes from and the contributing groups.
fn decisions(
    store: &ManagedStore,
    configured: &AccessKeyTypes,
    principal: &str,
) -> Vec<(String, bool, AccessKeyTypeSource, Vec<String>)> {
    store
        .access_key_type_policy(configured, principal)
        .unwrap()
        .access_key_types
        .into_iter()
        .map(|decision| {
            (
                decision.access_key_type,
                decision.allowed,
                decision.source,
                decision.group_ids,
            )
        })
        .collect()
}

fn row(
    access_key_type: &str,
    allowed: bool,
    source: AccessKeyTypeSource,
    groups: &[&str],
) -> (String, bool, AccessKeyTypeSource, Vec<String>) {
    (access_key_type.to_string(), allowed, source, ids(groups))
}

fn patch_principal(
    store: &ManagedStore,
    principal: &str,
    setting: &PrincipalAccessKeyTypes,
    configured: &AccessKeyTypes,
) -> Result<PrincipalAccessChange, ManagedStoreError> {
    store.patch_principal_access_with_access_key_types(
        PrincipalAccessPatchRequest {
            principal_id: principal.into(),
            role: None,
            self_service_enabled: None,
            agent_token_issuance: None,
            actor: "admin".into(),
        },
        Some(AccessKeyTypesWrite {
            setting,
            configured,
        }),
        &test_execution_contexts(),
    )
}

fn patch_group(
    store: &ManagedStore,
    group: &str,
    setting: &GroupAccessKeyTypes,
    configured: &AccessKeyTypes,
) -> Result<GroupMutationResult, ManagedStoreError> {
    store.patch_group_with_access(
        GroupPatchRequest {
            group_id: group.into(),
            display_name: None,
            description: None,
            status: None,
            auto_enroll_new_microsoft_users: None,
            agent_token_issuance: None,
            updated_by: "admin".into(),
        },
        Some(AccessKeyTypesWrite {
            setting,
            configured,
        }),
        &test_execution_contexts(),
    )
}

use AccessKeyTypeSource::{Account, Groups, None as Nowhere};

#[test]
fn each_access_key_type_is_decided_alone_by_the_account_or_else_by_its_groups() {
    let (_temp, store) = store();
    let configured = configured();
    // A new account says nothing and a new group allows nothing: no
    // access key type switches itself on.
    assert_eq!(
        store.principal_access_key_types("usr-alice").unwrap(),
        PrincipalAccessKeyTypes::default()
    );
    assert_eq!(
        decisions(&store, &configured, "usr-alice"),
        [
            row("batch", false, Nowhere, &[]),
            row("inference", false, Nowhere, &[]),
            row("packages", false, Nowhere, &[]),
        ]
    );
    group(&store, "platform", &["usr-alice"]);
    group(&store, "research", &["usr-alice", "usr-bob"]);
    assert!(store.group_access_key_types().unwrap().is_empty());
    assert!(
        decisions(&store, &configured, "usr-alice")
            .iter()
            .all(|decision| !decision.1)
    );

    // A group allows an access key type for its local members that inherit it.
    let change = patch_group(
        &store,
        "platform",
        &GroupAccessKeyTypes::new(ids(&["packages", "inference"])).unwrap(),
        &configured,
    )
    .unwrap();
    assert_eq!(
        change.access_key_types,
        Some(AccessKeyTypesChange {
            previous: GroupAccessKeyTypes::default(),
            current: GroupAccessKeyTypes::new(ids(&["inference", "packages"])).unwrap(),
        })
    );
    assert_eq!(
        store.group_access_key_types().unwrap()["platform"].allow,
        ["inference", "packages"]
    );
    assert_eq!(
        decisions(&store, &configured, "usr-alice"),
        [
            row("batch", false, Nowhere, &[]),
            row("inference", true, Groups, &["platform"]),
            row("packages", true, Groups, &["platform"]),
        ]
    );
    // Bob is not in that group.
    assert!(
        decisions(&store, &configured, "usr-bob")
            .iter()
            .all(|decision| !decision.1)
    );
    // Every group that allows an access key type is reported for it.
    patch_group(
        &store,
        "research",
        &GroupAccessKeyTypes::new(ids(&["inference"])).unwrap(),
        &configured,
    )
    .unwrap();
    assert_eq!(
        decisions(&store, &configured, "usr-alice")[1],
        row("inference", true, Groups, &["platform", "research"])
    );
    assert_eq!(
        decisions(&store, &configured, "usr-bob")[1],
        row("inference", true, Groups, &["research"])
    );

    // The account overrides one access key type at a time: a denial and an
    // allowance of its own, with the third still inherited.
    let setting = PrincipalAccessKeyTypes::new(ids(&["batch"]), ids(&["packages"])).unwrap();
    let change = patch_principal(&store, "usr-alice", &setting, &configured).unwrap();
    assert_eq!(
        change.access_key_types,
        Some(AccessKeyTypesChange {
            previous: PrincipalAccessKeyTypes::default(),
            current: setting.clone(),
        })
    );
    assert_eq!(
        store.principal_access_key_types("usr-alice").unwrap(),
        setting
    );
    assert_eq!(
        decisions(&store, &configured, "usr-alice"),
        [
            row("batch", true, Account, &[]),
            row("inference", true, Groups, &["platform", "research"]),
            row("packages", false, Account, &[]),
        ]
    );
    // The same setting again writes nothing.
    let before = store.principal("usr-alice").unwrap();
    let unchanged = patch_principal(&store, "usr-alice", &setting, &configured).unwrap();
    assert_eq!(
        unchanged.access_key_types,
        Some(AccessKeyTypesChange {
            previous: setting.clone(),
            current: setting.clone(),
        })
    );
    assert_eq!(unchanged.principal.updated_at, before.updated_at);

    // A disabled group contributes nothing and vetoes nothing; neither does
    // a membership that ended.
    store
        .patch_group(
            GroupPatchRequest {
                group_id: "platform".into(),
                display_name: None,
                description: None,
                status: Some("disabled".into()),
                auto_enroll_new_microsoft_users: None,
                agent_token_issuance: None,
                updated_by: "admin".into(),
            },
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(
        decisions(&store, &configured, "usr-alice")[1],
        row("inference", true, Groups, &["research"])
    );
    store.remove_group("usr-alice", "research").unwrap();
    assert_eq!(
        decisions(&store, &configured, "usr-alice"),
        [
            row("batch", true, Account, &[]),
            row("inference", false, Nowhere, &[]),
            row("packages", false, Account, &[]),
        ]
    );
    store.add_group("usr-alice", "research", "admin").unwrap();

    // A service account has the same setting.
    patch_principal(
        &store,
        "robot",
        &PrincipalAccessKeyTypes::new(ids(&["batch"]), Vec::new()).unwrap(),
        &configured,
    )
    .unwrap();
    assert_eq!(
        decisions(&store, &configured, "robot")[0],
        row("batch", true, Account, &[])
    );
    // An access key type the configuration no longer defines has no decision.
    let fewer = AccessKeyTypes::for_test([access_key_type("inference", true)]);
    assert_eq!(
        decisions(&store, &fewer, "usr-alice"),
        [row("inference", true, Groups, &["research"])]
    );
    assert!(matches!(
        store.access_key_type_policy(&configured, "missing"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[test]
fn a_setting_is_a_complete_object_of_configured_access_key_types() {
    let (_temp, store) = store();
    let configured = configured();
    group(&store, "platform", &[]);
    // The two lists are disjoint, hold each ID once and only valid IDs.
    for (allow, deny) in [
        (vec!["inference"], vec!["inference"]),
        (vec!["inference", "inference"], vec![]),
        (vec![], vec!["Batch"]),
        (vec![""], vec![]),
    ] {
        assert!(
            matches!(
                PrincipalAccessKeyTypes::new(ids(&allow), ids(&deny)),
                Err(ManagedStoreError::InputInvalid(_))
            ),
            "{allow:?} {deny:?}"
        );
    }
    assert!(GroupAccessKeyTypes::new(ids(&["inference", "inference"])).is_err());
    let many: Vec<String> = (0..=ACCESS_KEY_TYPES_MAX_ENTRIES)
        .map(|index| format!("e{index}"))
        .collect();
    assert!(GroupAccessKeyTypes::new(many).is_err());
    // On the wire both of an account's lists are required, a group has one,
    // and no other member is accepted.
    let account = |value: Value| serde_json::from_value::<PrincipalAccessKeyTypes>(value);
    assert_eq!(
        account(json!({"allow": ["packages", "inference"], "deny": []})).unwrap(),
        PrincipalAccessKeyTypes::new(ids(&["inference", "packages"]), Vec::new()).unwrap()
    );
    for invalid in [
        json!({"allow": ["inference"]}),
        json!({"deny": []}),
        json!({"allow": [], "deny": [], "mode": "inherit"}),
        json!({"allow": ["inference"], "deny": ["inference"]}),
        json!(["inference"]),
        // The setting is an object: its members in order are not one.
        json!([["inference"], []]),
        json!([["inference"]]),
        json!([[], ["inference"]]),
        json!([]),
        json!(null),
    ] {
        assert!(account(invalid.clone()).is_err(), "{invalid}");
        // A request body is read from text, a stored value from a tree.
        assert!(
            serde_json::from_str::<PrincipalAccessKeyTypes>(&invalid.to_string()).is_err(),
            "{invalid}"
        );
    }
    let of_group = |value: Value| serde_json::from_value::<GroupAccessKeyTypes>(value);
    assert!(of_group(json!({"allow": ["inference"]})).is_ok());
    for invalid in [
        json!({}),
        json!({"allow": [], "deny": []}),
        json!({"allow": "inference"}),
        json!([["inference"]]),
        json!(["inference"]),
        json!([]),
        json!(null),
    ] {
        assert!(of_group(invalid.clone()).is_err(), "{invalid}");
        assert!(
            serde_json::from_str::<GroupAccessKeyTypes>(&invalid.to_string()).is_err(),
            "{invalid}"
        );
    }
    assert_eq!(
        serde_json::to_value(
            PrincipalAccessKeyTypes::new(ids(&["inference"]), ids(&["batch"])).unwrap()
        )
        .unwrap(),
        json!({"allow": ["inference"], "deny": ["batch"]})
    );

    // A write names configured access key types only, in either list, and a
    // refused write changes nothing.
    for setting in [
        PrincipalAccessKeyTypes::new(ids(&["telemetry"]), Vec::new()).unwrap(),
        PrincipalAccessKeyTypes::new(ids(&["inference"]), ids(&["telemetry"])).unwrap(),
    ] {
        assert!(matches!(
            patch_principal(&store, "usr-alice", &setting, &configured),
            Err(ManagedStoreError::InputInvalid(message)) if message.contains("not configured")
        ));
    }
    assert!(matches!(
        patch_group(
            &store,
            "platform",
            &GroupAccessKeyTypes::new(ids(&["telemetry"])).unwrap(),
            &configured
        ),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("not configured")
    ));
    assert_eq!(
        store.principal_access_key_types("usr-alice").unwrap(),
        PrincipalAccessKeyTypes::default()
    );
    // A group can be created with its setting; without one it allows nothing.
    let created = store
        .create_group_with_access(
            GroupWriteRequest {
                group_id: "builders".into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: test_group_issuance(AgentTokenIssuanceMode::Disabled),
                created_by: "admin".into(),
            },
            Some(AccessKeyTypesWrite {
                setting: &GroupAccessKeyTypes::new(ids(&["batch"])).unwrap(),
                configured: &configured,
            }),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(created.access_key_types.unwrap().current.allow, ["batch"]);
    assert_eq!(
        store.group_access_key_types().unwrap()["builders"].allow,
        ["batch"]
    );
    // An access change alone is a complete patch.
    assert!(
        store
            .patch_principal_access(
                PrincipalAccessPatchRequest {
                    principal_id: "usr-alice".into(),
                    role: None,
                    self_service_enabled: None,
                    agent_token_issuance: None,
                    actor: "admin".into(),
                },
                &test_execution_contexts(),
            )
            .is_err()
    );
}

#[test]
fn startup_refuses_a_saved_reference_to_an_access_key_type_that_is_not_configured() {
    let (_temp, store) = store();
    let configured = configured();
    group(&store, "platform", &[]);
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference"],
        &["batch"],
        &configured,
    );
    store.set_group_access_key_types_for_test("platform", &["packages"], &configured);
    assert_eq!(
        store
            .access_key_types_still_referenced(&configured)
            .unwrap(),
        []
    );

    // A configuration without an access key type a saved setting names is
    // refused, for an account's allowance, an account's denial and a
    // group's allowance alike: the type is named, with how many settings
    // of each kind still name it and whose.
    for (remaining, missing, accounts, groups) in [
        (
            vec!["batch", "packages"],
            "inference",
            vec!["usr-alice"],
            vec![],
        ),
        (
            vec!["inference", "packages"],
            "batch",
            vec!["usr-alice"],
            vec![],
        ),
        (
            vec!["inference", "batch"],
            "packages",
            vec![],
            vec!["platform"],
        ),
    ] {
        let fewer = AccessKeyTypes::for_test(remaining.iter().map(|id| access_key_type(id, true)));
        let referenced = store.access_key_types_still_referenced(&fewer).unwrap();
        assert_eq!(
            referenced,
            [AccessKeyTypeStillReferenced {
                access_key_type: missing.into(),
                account_settings: accounts.len() as u64,
                accounts: accounts.iter().map(|id| (*id).to_string()).collect(),
                group_settings: groups.len() as u64,
                groups: groups.iter().map(|id| (*id).to_string()).collect(),
                unexpired_keys: 0,
            }],
            "{remaining:?}"
        );
        let message = referenced[0].message();
        assert!(
            message.starts_with(&format!(
                "access key type {missing} is not in [access_key_types] and is still named by"
            )),
            "{message}"
        );
        for owner in accounts.iter().chain(&groups) {
            assert!(message.contains(owner), "{message}");
        }
    }
    // Several types at once are each reported, by ID, and every owner is
    // counted while only some are named.
    for index in 0..11 {
        let id = format!("usr-extra-{index:02}");
        store
            .create_principal(
                PrincipalWriteRequest {
                    principal_id: id.clone(),
                    kind: "user".into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                    role: crate::PrincipalRole::User,
                    self_service_enabled: Some(false),
                    agent_token_issuance: test_principal_issuance(
                        PrincipalAgentTokenIssuance::Disabled,
                    ),
                },
                &test_execution_contexts(),
            )
            .unwrap();
        store.set_principal_access_key_types_for_test(&id, &["inference"], &[], &configured);
    }
    let only_packages = AccessKeyTypes::for_test([access_key_type("packages", true)]);
    let referenced = store
        .access_key_types_still_referenced(&only_packages)
        .unwrap();
    assert_eq!(
        referenced
            .iter()
            .map(|entry| (
                entry.access_key_type.as_str(),
                entry.account_settings,
                entry.accounts.len(),
                entry.group_settings
            ))
            .collect::<Vec<_>>(),
        [("batch", 1, 1, 0), ("inference", 12, 10, 0)]
    );
    assert_eq!(
        referenced[1].message(),
        "access key type inference is not in [access_key_types] and is still named by \
         12 account settings (usr-alice, usr-extra-00, usr-extra-01, usr-extra-02, usr-extra-03, \
         usr-extra-04, usr-extra-05, usr-extra-06, usr-extra-07, usr-extra-08 and 2 more) \
         and no group settings; 0 unexpired access keys carry it. Take it out of those settings, or \
         keep its table, then reload or start again: see \"Retire an access key type\" in the \
         administrator guide"
    );
    for index in 0..11 {
        store.set_principal_access_key_types_for_test(
            &format!("usr-extra-{index:02}"),
            &[],
            &[],
            &configured,
        );
    }
    // A disabled group's references are checked too.
    store
        .patch_group(
            GroupPatchRequest {
                group_id: "platform".into(),
                display_name: None,
                description: None,
                status: Some("disabled".into()),
                auto_enroll_new_microsoft_users: None,
                agent_token_issuance: None,
                updated_by: "admin".into(),
            },
            &test_execution_contexts(),
        )
        .unwrap();
    let without_packages = AccessKeyTypes::for_test([
        access_key_type("inference", true),
        access_key_type("batch", false),
    ]);
    assert_eq!(
        store
            .access_key_types_still_referenced(&without_packages)
            .unwrap()[0]
            .group_settings,
        1
    );
    // Removing the references first lets the access key type go.
    store.set_group_access_key_types_for_test("platform", &[], &configured);
    assert_eq!(
        store
            .access_key_types_still_referenced(&without_packages)
            .unwrap(),
        []
    );
    // The rows go with their owner.
    store.set_group_access_key_types_for_test("platform", &["packages"], &configured);
    let count = |table: &str| -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    assert_eq!(count("principal_access_key_types"), 2);
    assert_eq!(count("group_access_key_types"), 1);
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(
            "DELETE FROM principals WHERE principal_id = 'usr-alice';
             DELETE FROM groups WHERE group_id = 'platform';",
        )
        .unwrap();
    assert_eq!(count("principal_access_key_types"), 0);
    assert_eq!(count("group_access_key_types"), 0);
}
