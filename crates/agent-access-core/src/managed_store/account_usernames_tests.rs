use super::*;
use tempfile::TempDir;

fn temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn config_at(path: &Path, auto_migrate: bool) -> ManagedStoreConfig {
    ManagedStoreConfig {
        kind: "sqlite".into(),
        path: path.display().to_string(),
        auto_migrate,
        require_registered_principal_for_invocation: false,
    }
}

fn policy() -> AccountUsernamePolicy {
    AccountUsernamePolicy::for_test(&["example.com"], &["root", "operator"], &["carol", "dave"])
}

fn fixture() -> (TempDir, ManagedStore) {
    let temp = temp();
    let store = ManagedStore::open(
        &config_at(&temp.path().join("store.sqlite"), true),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store.configure_account_usernames(policy());
    (temp, store)
}

fn write_request(id: &str, kind: &str, email: Option<&str>) -> PrincipalWriteRequest {
    PrincipalWriteRequest {
        principal_id: id.into(),
        kind: kind.into(),
        display_name: None,
        email: email.map(str::to_string),
        external_subject: None,
        created_by: "admin".into(),
        role: crate::PrincipalRole::User,
        self_service_enabled: Some(false),
        agent_token_issuance: test_principal_issuance(PrincipalAgentTokenIssuance::Disabled),
    }
}

fn create(store: &ManagedStore, id: &str, kind: &str, email: Option<&str>) -> PrincipalCreation {
    store
        .create_principal_with_effect(
            write_request(id, kind, email),
            None,
            None,
            &test_execution_contexts(),
        )
        .unwrap()
}

fn name(store: &ManagedStore, id: &str) -> Option<AccountUsernameRecord> {
    store.principal_account_username(id).unwrap().name
}

/// The mode, state and reason of an account's name.
fn status(
    store: &ManagedStore,
    id: &str,
) -> (
    Option<AccountUsernameMode>,
    PrincipalAccountUsernameState,
    Option<AccountUsernameReason>,
) {
    let view = store.principal_account_username(id).unwrap();
    (view.mode, view.state, view.reason)
}

fn setting(
    store: &ManagedStore,
    id: &str,
    setting: AccountUsernameSetting,
) -> AccountUsernameChange {
    store
        .set_account_username_setting(id, &setting, "admin")
        .unwrap()
        .unwrap()
}

/// An administrator leaves the person without a name.
fn clear(store: &ManagedStore, id: &str) -> AccountUsernameChange {
    setting(store, id, AccountUsernameSetting::ManualNone)
}

/// An administrator changes the account's profile email.
fn patch_email(
    store: &ManagedStore,
    id: &str,
    email: Option<&str>,
) -> Option<AccountUsernameChange> {
    store
        .patch_principal_with_account_username(
            PrincipalPatchRequest {
                principal_id: id.into(),
                display_name: None,
                email: Some(email.map(str::to_string)),
                status: None,
            },
            "admin",
        )
        .unwrap()
        .account_username_change
}

fn sign_in(store: &ManagedStore, id: &str) -> AuthenticatedLocalPassword {
    let passwords = LocalPasswordHasher {
        verification_hook: None,
        key: Arc::new([23; 32]),
    };
    let tokens = BrokerTokenHasher {
        key: Arc::new([24; 32]),
    };
    if !store
        .list_login_methods(id)
        .unwrap()
        .iter()
        .any(|method| method.method == "local_password")
    {
        store
            .enable_local_password(
                &passwords,
                LocalPasswordWriteRequest {
                    principal_id: id.into(),
                    password: "first-password".into(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".into(),
                },
            )
            .unwrap();
    }
    store
        .authenticate_local_password_session(
            &passwords,
            &tokens,
            LocalPasswordVerifyRequest {
                principal_id: id.into(),
                password: "first-password".into(),
                source: "203.0.113.10".into(),
                max_failed_attempts: 3,
                lockout_ttl_seconds: 60,
            },
            3600,
            None,
        )
        .unwrap()
}

/// Writes the email column alone, as a row that predates names holds one.
fn set_email(store: &ManagedStore, id: &str, email: &str) {
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE principals SET email = ?2 WHERE principal_id = ?1",
            params![id, email],
        )
        .unwrap();
}

#[test]
fn account_creation_names_a_person_from_the_lower_cased_local_part_of_their_email() {
    let (_temp, store) = fixture();
    let created = create(&store, "usr-1", "user", Some("Alice@Example.com"));
    let derived = created.derived_account_username.unwrap();
    assert_eq!(derived.account_username, "alice");
    assert_eq!(derived.origin, AccountUsernameOrigin::Derived);
    assert_eq!(derived.holder_kind, AccountUsernameHolderKind::User);
    assert_eq!(derived.assigned_by, "admin");
    assert_eq!(derived.state, AccountUsernameState::Usable);
    assert_eq!(derived.incarnation.len(), 32);
    assert_eq!(name(&store, "usr-1"), Some(derived.clone()));
    // Every person starts by following their email.
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Usable,
            None
        )
    );

    // An account the email names nobody for holds none, and says why.
    for (id, email, reason) in [
        ("usr-2", None, AccountUsernameReason::NoEmail),
        (
            "usr-3",
            Some("erin@example.org"),
            AccountUsernameReason::DomainNotListed,
        ),
        (
            "usr-6",
            Some("root@example.com"),
            AccountUsernameReason::NameReserved,
        ),
    ] {
        assert!(
            create(&store, id, "user", email)
                .derived_account_username
                .is_none()
        );
        assert_eq!(name(&store, id), None);
        assert_eq!(
            status(&store, id),
            (
                Some(AccountUsernameMode::FromEmail),
                PrincipalAccountUsernameState::None,
                Some(reason)
            ),
            "{id}"
        );
    }
    // The profile email is free text an older row may hold in any form.
    for (email, reason) in [
        ("not an address", AccountUsernameReason::EmailUnusable),
        ("fr ank@example.com", AccountUsernameReason::NameInvalid),
    ] {
        set_email(&store, "usr-2", email);
        assert!(sign_in(&store, "usr-2").derived_account_username.is_none());
        assert_eq!(status(&store, "usr-2").2, Some(reason), "{email}");
    }
    // A service account is named by its ID, never by an email, and has no
    // mode.
    assert!(
        create(&store, "robot", "service_account", Some("zed@example.com"))
            .derived_account_username
            .is_none()
    );
    let robot = store.principal_account_username("robot").unwrap();
    assert_eq!(
        (robot.mode, robot.state, robot.reason),
        (None, PrincipalAccountUsernameState::Usable, None)
    );
    let robot = robot.name.unwrap();
    assert_eq!(
        (
            robot.account_username.as_str(),
            robot.origin,
            robot.holder_kind,
            robot.state
        ),
        (
            "robot",
            AccountUsernameOrigin::ServiceAccount,
            AccountUsernameHolderKind::ServiceAccount,
            AccountUsernameState::Usable
        )
    );
}

#[test]
fn the_name_of_a_person_who_follows_their_email_follows_an_email_change() {
    let (_temp, store) = fixture();
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com", "example.net"],
        &["root"],
        &[],
    ));
    let first = create(&store, "usr-1", "user", Some("alice@example.com"))
        .derived_account_username
        .unwrap();

    // A new address renames: the old name is released and the new one
    // allocated in the same change, under a new incarnation.
    let renamed = patch_email(&store, "usr-1", Some("Alicia@example.com")).unwrap();
    assert!(renamed.changed() && renamed.renamed());
    assert_eq!(renamed.before, Some(first.clone()));
    let alicia = renamed.after.clone().unwrap();
    assert_eq!(alicia.account_username, "alicia");
    assert_eq!(alicia.origin, AccountUsernameOrigin::Derived);
    assert_eq!(alicia.assigned_by, "admin");
    assert_ne!(alicia.incarnation, first.incarnation);
    assert_eq!(renamed.view.name, Some(alicia.clone()));
    assert_eq!(
        renamed.audit_details()["before"]["accountUsername"],
        serde_json::json!("alice")
    );
    assert_eq!(
        renamed.audit_details()["after"]["accountUsername"],
        serde_json::json!("alicia")
    );
    // The released name is free for the next account.
    assert_eq!(
        create(&store, "usr-2", "user", Some("alice@example.com"))
            .derived_account_username
            .unwrap()
            .account_username,
        "alice"
    );

    // The same address again, and an address that derives the same name,
    // change nothing: the allocation and its incarnation stay.
    assert_eq!(
        patch_email(&store, "usr-1", Some("Alicia@example.com")),
        None
    );
    let same = patch_email(&store, "usr-1", Some("alicia@example.net")).unwrap();
    assert!(!same.changed() && !same.renamed());
    assert_eq!(same.after, Some(alicia.clone()));
    assert_eq!(same.ended_keys, 0);

    // An address that derives a name someone else holds leaves the person
    // without one, in conflict; the holder keeps theirs.
    let conflict = patch_email(&store, "usr-1", Some("alice@example.net")).unwrap();
    assert_eq!(conflict.before, Some(alicia));
    assert_eq!(conflict.after, None);
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Conflict,
            Some(AccountUsernameReason::NameTaken)
        )
    );
    assert_eq!(
        store.principal_account_username("usr-1").unwrap().conflict,
        Some(AccountUsernameConflict {
            account_username: "alice".into(),
            held_by: "usr-2".into()
        })
    );
    assert_eq!(name(&store, "usr-2").unwrap().account_username, "alice");

    // An address that derives nothing leaves the person without a name.
    for (email, reason) in [
        (
            Some("alicia@example.org"),
            AccountUsernameReason::DomainNotListed,
        ),
        (None, AccountUsernameReason::NoEmail),
        (
            Some("root@example.com"),
            AccountUsernameReason::NameReserved,
        ),
    ] {
        patch_email(&store, "usr-1", Some("alicia@example.com")).unwrap();
        assert!(name(&store, "usr-1").is_some());
        let released = patch_email(&store, "usr-1", email).unwrap();
        assert!(released.renamed());
        assert_eq!(released.after, None);
        assert_eq!(
            status(&store, "usr-1"),
            (
                Some(AccountUsernameMode::FromEmail),
                PrincipalAccountUsernameState::None,
                Some(reason)
            )
        );
    }

    // A change of another profile field renames nobody.
    patch_email(&store, "usr-1", Some("alicia@example.com")).unwrap();
    let before = name(&store, "usr-1");
    let patch = store
        .patch_principal_with_account_username(
            PrincipalPatchRequest {
                principal_id: "usr-1".into(),
                display_name: Some(Some("Alicia Example".into())),
                email: None,
                status: None,
            },
            "admin",
        )
        .unwrap();
    assert!(patch.account_username_change.is_none());
    assert_eq!(name(&store, "usr-1"), before);

    // Delisting a domain takes no name away: nothing changed for the
    // account, so nothing is recomputed.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&["example.net"], &[], &[]));
    assert_eq!(name(&store, "usr-1"), before);
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Usable,
            None
        )
    );
    assert!(sign_in(&store, "usr-1").derived_account_username.is_none());
    assert_eq!(name(&store, "usr-1"), before);

    // A person whose name is set by hand keeps it whatever their email.
    let manual = setting(&store, "usr-2", AccountUsernameSetting::Manual)
        .after
        .unwrap();
    let kept = patch_email(&store, "usr-2", Some("zoe@example.net")).unwrap();
    assert!(!kept.changed() && !kept.renamed());
    assert_eq!(kept.previous_mode, AccountUsernameMode::Manual);
    assert_eq!(kept.before, Some(manual.clone()));
    assert_eq!(kept.after, Some(manual.clone()));
    assert_eq!(kept.ended_keys, 0);
    assert_eq!(name(&store, "usr-2"), Some(manual));
    // An account that is not a person has no name to follow an email.
    create(&store, "robot", "service_account", None);
    assert_eq!(
        patch_email(&store, "robot", Some("robot@example.com")),
        None
    );
    // The internal upsert of an existing account follows the same rule.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com", "example.net"],
        &[],
        &[],
    ));
    store
        .create_or_update_principal(
            write_request("usr-1", "user", Some("amy@example.com")),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_eq!(name(&store, "usr-1").unwrap().account_username, "amy");
}

/// What following the email gives `id` for the email saved on the account.
fn from_email(store: &ManagedStore, id: &str) -> AccountUsernameFromEmail {
    store
        .principal_account_username(id)
        .unwrap()
        .from_email
        .unwrap()
}

fn gives(name: &str) -> AccountUsernameFromEmail {
    AccountUsernameFromEmail {
        account_username: Some(name.into()),
        reason: None,
        conflict: None,
    }
}

fn gives_none(reason: AccountUsernameReason) -> AccountUsernameFromEmail {
    AccountUsernameFromEmail {
        account_username: None,
        reason: Some(reason),
        conflict: None,
    }
}

#[test]
fn an_account_s_view_says_what_its_saved_email_gives_whatever_its_mode() {
    let (_temp, store) = fixture();
    // A person who follows their email: the name they hold.
    create(&store, "usr-1", "user", Some("Alice@example.com"));
    assert_eq!(from_email(&store, "usr-1"), gives("alice"));
    assert_eq!(name(&store, "usr-1").unwrap().account_username, "alice");

    // A person whose name is set by hand: what switching would give, which
    // is then what switching gives.
    store
        .set_account_username("usr-1", "a.example", "admin")
        .unwrap()
        .unwrap();
    assert_eq!(name(&store, "usr-1").unwrap().account_username, "a.example");
    assert_eq!(from_email(&store, "usr-1"), gives("alice"));
    let switched = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert_eq!(switched.after.unwrap().account_username, "alice");

    // Each reason the saved email gives none, for a person in either mode.
    for (id, email, reason) in [
        ("usr-none", None, AccountUsernameReason::NoEmail),
        (
            "usr-unlisted",
            Some("bob@example.org"),
            AccountUsernameReason::DomainNotListed,
        ),
        (
            "usr-invalid",
            Some("b%b@example.com"),
            AccountUsernameReason::NameInvalid,
        ),
        (
            "usr-reserved",
            Some("root@example.com"),
            AccountUsernameReason::NameReserved,
        ),
    ] {
        create(&store, id, "user", email);
        assert_eq!(from_email(&store, id), gives_none(reason), "{id}");
        assert_eq!(status(&store, id).2, Some(reason), "{id}");
        clear(&store, id);
        assert_eq!(from_email(&store, id), gives_none(reason), "{id} by hand");
        assert_eq!(
            setting(&store, id, AccountUsernameSetting::FromEmail).after,
            None,
            "{id}"
        );
    }

    // A name someone else holds is not given, and the view says who holds
    // it: a person, or the service account whose ID it is.
    create(&store, "usr-2", "user", Some("alice@example.com"));
    create(&store, "robot", "service_account", None);
    create(&store, "usr-3", "user", Some("robot@example.com"));
    for (id, taken, held_by) in [("usr-2", "alice", "usr-1"), ("usr-3", "robot", "robot")] {
        let expected = AccountUsernameFromEmail {
            account_username: None,
            reason: Some(AccountUsernameReason::NameTaken),
            conflict: Some(AccountUsernameConflict {
                account_username: taken.into(),
                held_by: held_by.into(),
            }),
        };
        assert_eq!(from_email(&store, id), expected, "{id}");
        // Set by hand, the same account still reads what its email gives.
        store
            .set_account_username(id, &format!("{id}.manual"), "admin")
            .unwrap()
            .unwrap();
        assert_eq!(from_email(&store, id), expected, "{id} by hand");
    }

    // A name on the operator's list is given like any other; holding it
    // then awaits confirmation.
    create(&store, "usr-4", "user", Some("carol@example.com"));
    assert_eq!(from_email(&store, "usr-4"), gives("carol"));
    assert_eq!(
        status(&store, "usr-4").1,
        PrincipalAccountUsernameState::AwaitingConfirmation
    );

    // The answer follows the saved email and the current settings, and
    // takes no held name away.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&["example.net"], &[], &[]));
    assert_eq!(
        from_email(&store, "usr-1"),
        gives_none(AccountUsernameReason::DomainNotListed)
    );
    assert_eq!(name(&store, "usr-1").unwrap().account_username, "alice");

    // A service account's name is its ID: no email gives it one.
    assert_eq!(
        store
            .principal_account_username("robot")
            .unwrap()
            .from_email,
        None
    );
    assert_eq!(
        serde_json::to_value(store.principal_account_username("usr-2").unwrap()).unwrap()["fromEmail"],
        serde_json::json!({"accountUsername": null, "reason": "domain_not_listed",
            "conflict": null})
    );
}

#[test]
fn first_holder_keeps_a_name_and_email_never_finds_or_merges_accounts() {
    let (_temp, store) = fixture();
    let first = create(&store, "usr-1", "user", Some("alice@example.com"))
        .derived_account_username
        .unwrap();
    // A second account with the same email is a second account without a
    // name; the first is neither found, merged nor displaced.
    let second = create(&store, "usr-2", "user", Some("ALICE@example.com"));
    assert_eq!(second.principal.principal_id, "usr-2");
    assert!(second.derived_account_username.is_none());
    assert_eq!(
        status(&store, "usr-2"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Conflict,
            Some(AccountUsernameReason::NameTaken)
        )
    );
    assert_eq!(
        store.principal_account_username("usr-2").unwrap().conflict,
        Some(AccountUsernameConflict {
            account_username: "alice".into(),
            held_by: "usr-1".into()
        })
    );
    assert_eq!(store.principal_count().unwrap(), 2);
    assert_eq!(name(&store, "usr-1"), Some(first.clone()));
    assert_eq!(name(&store, "usr-2"), None);

    // An administrator cannot move the name either, and neither a sign-in
    // nor the fill gives it to the second account.
    assert_eq!(
        store
            .set_account_username("usr-2", "alice", "admin")
            .unwrap(),
        Err(AccountUsernameRefusal::NameTaken)
    );
    assert!(sign_in(&store, "usr-2").derived_account_username.is_none());
    assert!(
        store
            .fill_missing_account_usernames(None, 10, "system:reload")
            .unwrap()
            .assigned
            .is_empty()
    );
    assert_eq!(name(&store, "usr-1"), Some(first.clone()));

    // When the holder's name is taken away, the name is free: the second
    // account is not yet named, and its next sign-in names it.
    let cleared = clear(&store, "usr-1");
    assert_eq!(cleared.before, Some(first.clone()));
    assert_eq!(cleared.after, None);
    assert_eq!(cleared.view.name, None);
    assert_eq!(
        status(&store, "usr-2"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::NotYetAssigned)
        )
    );
    let reused = sign_in(&store, "usr-2").derived_account_username.unwrap();
    assert_eq!(reused.account_username, "alice");
    assert_ne!(reused.incarnation, first.incarnation);
    // The account an administrator left without a name is not named again
    // by a sign-in or by the fill.
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::Manual),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::NotSet)
        )
    );
    assert!(sign_in(&store, "usr-1").derived_account_username.is_none());
    assert_eq!(
        store
            .fill_missing_account_usernames(None, 10, "system:reload")
            .unwrap()
            .examined,
        0
    );
    assert_eq!(name(&store, "usr-1"), None);
}

#[test]
fn a_sign_in_names_a_person_who_follows_their_email_and_holds_no_name() {
    let (_temp, store) = fixture();
    create(&store, "usr-1", "user", None);
    set_email(&store, "usr-1", "Bob@example.com");
    assert_eq!(
        status(&store, "usr-1").2,
        Some(AccountUsernameReason::NotYetAssigned)
    );
    let derived = sign_in(&store, "usr-1").derived_account_username.unwrap();
    assert_eq!(derived.account_username, "bob");
    assert_eq!(derived.assigned_by, "system:sign_in");
    assert_eq!(derived.origin, AccountUsernameOrigin::Derived);
    // A sign-in of a person who holds a name changes nothing.
    assert!(sign_in(&store, "usr-1").derived_account_username.is_none());
    assert_eq!(name(&store, "usr-1"), Some(derived));

    // Any sign-in names, not only the first: one that could name nobody
    // leaves the next one free to.
    create(&store, "usr-2", "user", None);
    assert!(sign_in(&store, "usr-2").derived_account_username.is_none());
    assert_eq!(
        status(&store, "usr-2").2,
        Some(AccountUsernameReason::NoEmail)
    );
    set_email(&store, "usr-2", "eve@example.com");
    assert_eq!(
        sign_in(&store, "usr-2")
            .derived_account_username
            .unwrap()
            .account_username,
        "eve"
    );

    // A person whose name is set by hand is never named by a sign-in.
    create(&store, "usr-3", "user", None);
    set_email(&store, "usr-3", "finn@example.com");
    clear(&store, "usr-3");
    assert!(sign_in(&store, "usr-3").derived_account_username.is_none());
    assert_eq!(name(&store, "usr-3"), None);
    let set = store
        .set_account_username("usr-3", "finn", "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        set.after.unwrap().origin,
        AccountUsernameOrigin::Administrator
    );
}

#[test]
fn switching_modes_keeps_the_name_or_derives_it_and_a_manual_name_stays() {
    let (_temp, store) = fixture();
    let derived = create(&store, "usr-1", "user", Some("bob@example.com"))
        .derived_account_username
        .unwrap();

    // To manual: the name held now becomes the one set by hand, unchanged.
    let manual = setting(&store, "usr-1", AccountUsernameSetting::Manual);
    assert!(manual.changed() && !manual.renamed());
    assert_eq!(manual.previous_mode, AccountUsernameMode::FromEmail);
    assert_eq!(manual.view.mode, Some(AccountUsernameMode::Manual));
    assert_eq!(manual.after, Some(derived.clone()));
    assert_eq!(manual.ended_keys, 0);
    assert_eq!(
        manual.audit_details()["previousMode"],
        serde_json::json!("from_email")
    );
    assert_eq!(manual.audit_details()["mode"], serde_json::json!("manual"));
    // Asking again changes nothing.
    assert!(!setting(&store, "usr-1", AccountUsernameSetting::Manual).changed());

    // Back to the email: it derives at once. The name it derives is the
    // one held, so the allocation stays.
    let followed = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(followed.changed() && !followed.renamed());
    assert_eq!(followed.after, Some(derived.clone()));

    // A name set by hand is another allocation, and switching to the email
    // replaces it with the derived one at once.
    let typed = setting(
        &store,
        "usr-1",
        AccountUsernameSetting::ManualName("b.smith".into()),
    );
    assert!(typed.renamed());
    let typed = typed.after.unwrap();
    assert_eq!(typed.origin, AccountUsernameOrigin::Administrator);
    assert_ne!(typed.incarnation, derived.incarnation);
    let followed = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(followed.renamed());
    assert_eq!(followed.before, Some(typed.clone()));
    let again = followed.after.unwrap();
    assert_eq!(again.account_username, "bob");
    assert_eq!(again.origin, AccountUsernameOrigin::Derived);
    assert_ne!(again.incarnation, derived.incarnation);
    assert_ne!(again.incarnation, typed.incarnation);

    // Following an email that derives nothing leaves no name.
    create(&store, "usr-2", "user", Some("gail@example.org"));
    store
        .set_account_username("usr-2", "gail", "admin")
        .unwrap()
        .unwrap();
    let followed = setting(&store, "usr-2", AccountUsernameSetting::FromEmail);
    assert_eq!(followed.after, None);
    assert_eq!(
        status(&store, "usr-2"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::DomainNotListed)
        )
    );
    // No value in manual mode is no name.
    let none = clear(&store, "usr-1");
    assert!(none.renamed());
    assert_eq!(none.after, None);
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::Manual),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::NotSet)
        )
    );
    assert!(!clear(&store, "usr-1").changed());

    // Only a person has a mode.
    create(&store, "robot", "service_account", None);
    for requested in [
        AccountUsernameSetting::FromEmail,
        AccountUsernameSetting::Manual,
        AccountUsernameSetting::ManualNone,
    ] {
        assert_eq!(
            store
                .set_account_username_setting("robot", &requested, "admin")
                .unwrap(),
            Err(AccountUsernameRefusal::NotHuman)
        );
    }
}

#[test]
fn asking_for_the_mode_a_person_already_follows_takes_no_name_away() {
    let (_temp, store) = fixture();
    let derived = create(&store, "usr-1", "user", Some("bob@example.com"))
        .derived_account_username
        .unwrap();
    // The operator delists the domain. The name stays usable, although the
    // email would derive nothing now.
    let delisted = || AccountUsernamePolicy::for_test(&["example.net"], &["root", "operator"], &[]);
    store.configure_account_usernames(delisted());
    assert_eq!(name(&store, "usr-1"), Some(derived.clone()));

    // Asking for the mode the person is in changes neither their email nor
    // their mode: the name and its incarnation stay, and no token ends.
    let same = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(!same.changed() && !same.renamed());
    assert_eq!(same.previous_mode, AccountUsernameMode::FromEmail);
    assert_eq!(same.before, Some(derived.clone()));
    assert_eq!(same.after, Some(derived.clone()));
    assert_eq!(same.ended_keys, 0);
    assert_eq!(name(&store, "usr-1"), Some(derived.clone()));
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Usable,
            None
        )
    );

    // Only a transition to following the email derives at once, and under
    // these settings the email derives nothing.
    let manual = setting(&store, "usr-1", AccountUsernameSetting::Manual);
    assert_eq!(manual.after, Some(derived.clone()));
    let followed = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(followed.renamed());
    assert_eq!(followed.before, Some(derived.clone()));
    assert_eq!(followed.after, None);
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::DomainNotListed)
        )
    );

    // The same request for a person who holds no name fills in what their
    // email derives, as a sign-in would: nothing while the domain is not
    // listed, the name once it is.
    let nothing = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(!nothing.changed());
    assert_eq!(nothing.after, None);
    store.configure_account_usernames(policy());
    let filled = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(filled.renamed());
    assert_eq!(filled.before, None);
    let filled = filled.after.unwrap();
    assert_eq!(filled.account_username, "bob");
    assert_eq!(filled.origin, AccountUsernameOrigin::Derived);
    assert_eq!(filled.assigned_by, "admin");
    assert_ne!(filled.incarnation, derived.incarnation);
    // It never replaces a name: a name another account took meanwhile is
    // the holder's, and a held name that the email no longer derives stays.
    create(&store, "usr-2", "user", Some("zed@example.com"));
    store.configure_account_usernames(delisted());
    patch_email(&store, "usr-2", Some("bob@example.net"));
    assert_eq!(name(&store, "usr-2"), None);
    let kept = setting(&store, "usr-1", AccountUsernameSetting::FromEmail);
    assert!(!kept.changed());
    assert_eq!(kept.after, Some(filled));
    let conflict = setting(&store, "usr-2", AccountUsernameSetting::FromEmail);
    assert!(!conflict.changed());
    assert_eq!(conflict.view.state, PrincipalAccountUsernameState::Conflict);
}

#[test]
fn manual_set_changes_the_incarnation_and_refuses_reserved_invalid_and_taken_names() {
    let (_temp, store) = fixture();
    create(&store, "usr-1", "user", Some("alice@example.com"));
    create(&store, "usr-2", "user", None);
    create(&store, "robot", "service_account", None);
    create(&store, "sys", "system", None);
    let derived = name(&store, "usr-1").unwrap();

    // The name held, set by hand: the person stops following their email
    // and the allocation stays.
    let same = store
        .set_account_username("usr-1", "alice", "admin")
        .unwrap()
        .unwrap();
    assert!(same.changed() && !same.renamed());
    assert_eq!(same.view.mode, Some(AccountUsernameMode::Manual));
    assert_eq!(name(&store, "usr-1"), Some(derived.clone()));

    let changed = store
        .set_account_username("usr-1", "Alice.Admin", "admin")
        .unwrap()
        .unwrap();
    assert!(changed.changed());
    assert_eq!(changed.before, Some(derived.clone()));
    let after = changed.after.clone().unwrap();
    assert_eq!(after.account_username, "Alice.Admin");
    assert_eq!(after.origin, AccountUsernameOrigin::Administrator);
    assert_eq!(after.assigned_by, "admin");
    assert_ne!(after.incarnation, derived.incarnation);
    assert_eq!(
        changed.audit_details()["after"]["accountUsername"],
        serde_json::json!("Alice.Admin")
    );

    // Setting the first name again is a third incarnation, never the first.
    let back = store
        .set_account_username("usr-1", "alice", "admin")
        .unwrap()
        .unwrap()
        .after
        .unwrap();
    assert_ne!(back.incarnation, derived.incarnation);
    assert_ne!(back.incarnation, after.incarnation);

    for (principal, account_username, refusal) in [
        ("usr-2", "alice", AccountUsernameRefusal::NameTaken),
        ("usr-2", "robot", AccountUsernameRefusal::NameTaken),
        ("usr-2", "root", AccountUsernameRefusal::NameReserved),
        ("usr-2", "anonymous", AccountUsernameRefusal::NameInvalid),
        ("usr-2", "has/slash", AccountUsernameRefusal::NameInvalid),
        ("usr-2", "", AccountUsernameRefusal::NameInvalid),
        ("robot", "other", AccountUsernameRefusal::NotHuman),
        ("sys", "other", AccountUsernameRefusal::NotHuman),
    ] {
        assert_eq!(
            store
                .set_account_username(principal, account_username, "admin")
                .unwrap(),
            Err(refusal),
            "{principal} {account_username}"
        );
    }
    assert_eq!(name(&store, "usr-2"), None);
    assert!(matches!(
        store.set_account_username("missing", "name", "admin"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    // A disabled person keeps their name until an administrator changes it.
    store.set_principal_enabled("usr-1", false).unwrap();
    assert_eq!(name(&store, "usr-1"), Some(back));
    assert_eq!(
        store
            .set_account_username("usr-2", "alice", "admin")
            .unwrap(),
        Err(AccountUsernameRefusal::NameTaken)
    );
}

#[test]
fn a_listed_existing_username_is_unusable_until_an_administrator_confirms_it() {
    let (_temp, store) = fixture();
    // Derived at creation: allocated, so nobody else gets it, but not usable.
    let derived = create(&store, "usr-1", "user", Some("carol@example.com"))
        .derived_account_username
        .unwrap();
    assert_eq!(derived.state, AccountUsernameState::AwaitingConfirmation);
    assert!(!derived.is_usable());
    assert!(
        create(&store, "usr-2", "user", Some("carol@example.com"))
            .derived_account_username
            .is_none()
    );
    // Manual assignment of a listed name awaits confirmation too.
    let manual = store
        .set_account_username("usr-2", "dave", "admin")
        .unwrap()
        .unwrap()
        .after
        .unwrap();
    assert_eq!(manual.state, AccountUsernameState::AwaitingConfirmation);
    create(&store, "usr-3", "user", Some("gina@example.com"));

    let confirm = |principal: &str, account_username: &str| {
        store
            .confirm_account_username(principal, account_username, "admin")
            .unwrap()
    };
    // A confirmation names the name the account holds, and only a listed
    // name is confirmed.
    for (principal, account_username, refusal) in [
        ("usr-2", "carol", AccountUsernameRefusal::NameChanged),
        (
            "usr-3",
            "gina",
            AccountUsernameRefusal::ConfirmationNotRequired,
        ),
    ] {
        assert_eq!(
            confirm(principal, account_username),
            Err(refusal),
            "{principal}"
        );
    }
    assert_eq!(
        name(&store, "usr-2").unwrap().state,
        AccountUsernameState::AwaitingConfirmation
    );

    for (principal, account_username) in [("usr-1", "carol"), ("usr-2", "dave")] {
        let change = confirm(principal, account_username).unwrap();
        let after = change.after.as_ref().unwrap();
        assert_eq!(after.state, AccountUsernameState::Usable);
        assert_eq!(after.confirmed_by.as_deref(), Some("admin"));
        assert_eq!(change.view.state, PrincipalAccountUsernameState::Usable);
        // Confirmation is not a change of name or of mode.
        assert!(!change.renamed());
        assert_eq!(Some(change.previous_mode), change.view.mode);
        assert_eq!(
            after.incarnation,
            change.before.as_ref().unwrap().incarnation
        );
    }
    // Confirming again writes nothing.
    let again = confirm("usr-1", "carol").unwrap();
    assert_eq!(again.before, again.after);

    // A name that is taken away and given again awaits confirmation again.
    clear(&store, "usr-1");
    let reused = store
        .set_account_username("usr-3", "carol", "admin")
        .unwrap()
        .unwrap()
        .after
        .unwrap();
    assert_eq!(reused.state, AccountUsernameState::AwaitingConfirmation);
    assert_eq!(reused.confirmed_at, None);

    // The lists are read from the current settings: a name the operator
    // lists or reserves later stops being usable without any write.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &["dave"],
        &["carol", "gina"],
    ));
    assert_eq!(
        name(&store, "usr-2").unwrap().state,
        AccountUsernameState::Reserved
    );
    store.configure_account_usernames(AccountUsernamePolicy::default());
    assert_eq!(
        name(&store, "usr-3").unwrap().state,
        AccountUsernameState::Usable
    );
    let listed = store.list_principal_account_usernames().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|entry| (
                entry.principal_id.as_str(),
                entry
                    .name
                    .as_ref()
                    .map(|name| name.account_username.as_str())
            ))
            .collect::<Vec<_>>(),
        [
            ("usr-1", None),
            ("usr-2", Some("dave")),
            ("usr-3", Some("carol"))
        ]
    );
}

#[test]
fn a_person_s_name_and_a_service_account_id_never_collide_in_either_order() {
    let (_temp, store) = fixture();
    create(&store, "robot", "service_account", None);
    // A person cannot take a service account's ID.
    assert!(
        create(&store, "usr-1", "user", Some("robot@example.com"))
            .derived_account_username
            .is_none()
    );
    assert_eq!(
        status(&store, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::Conflict,
            Some(AccountUsernameReason::NameTaken)
        )
    );
    assert_eq!(
        store
            .principal_account_username("usr-1")
            .unwrap()
            .conflict
            .unwrap()
            .held_by,
        "robot"
    );
    assert_eq!(
        store
            .set_account_username("usr-1", "robot", "admin")
            .unwrap(),
        Err(AccountUsernameRefusal::NameTaken)
    );
    // A service account cannot be created under a person's name, by the
    // store's API or by any other path.
    store
        .set_account_username("usr-1", "nightly", "admin")
        .unwrap()
        .unwrap();
    for request in [
        write_request("nightly", "service_account", None),
        write_request("nightly", "system", None),
    ] {
        let kind = request.kind.clone();
        let created =
            store.create_principal_with_effect(request, None, None, &test_execution_contexts());
        if kind == "service_account" {
            assert!(
                matches!(created, Err(ManagedStoreError::InputInvalid(message)) if message.contains("username"))
            );
        } else {
            created.unwrap();
        }
    }
    // The system principal cannot become a service account while a person
    // holds its ID as a name.
    assert!(matches!(
        store.create_or_update_principal(
            write_request("nightly", "service_account", None),
            &test_execution_contexts()
        ),
        Err(ManagedStoreError::InputInvalid(message)) if message.contains("username")
    ));
    {
        let conn = store.connection.lock().unwrap();
        for sql in [
            "INSERT INTO principals (principal_id, kind, status, created_at, updated_at, created_by, role, self_service_enabled)
             VALUES ('nightly2', 'service_account', 'active', '2026-01-01', '2026-01-01', 'test', 'user', 0)",
            "UPDATE principals SET kind = 'service_account', self_service_enabled = 0 WHERE principal_id = 'nightly'",
        ] {
            let outcome = conn.execute(sql, []);
            if sql.contains("nightly2") {
                outcome.unwrap();
            } else {
                assert!(
                    outcome
                        .unwrap_err()
                        .to_string()
                        .contains("service account ID is held as a username")
                );
            }
        }
        assert!(
            conn.execute(
                "INSERT INTO account_usernames (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
                 VALUES ('nightly2', 'usr-1', 'user', 'x1', 'administrator', '2026-01-01', 'test')",
                [],
            )
            .is_err()
        );
    }
    // After the person's name is taken away the ID can be a service
    // account, whose name is a new incarnation each time it becomes one.
    clear(&store, "usr-1");
    store
        .create_or_update_principal(
            write_request("nightly", "service_account", None),
            &test_execution_contexts(),
        )
        .unwrap();
    let first = name(&store, "nightly").unwrap();
    assert_eq!(first.account_username, "nightly");
    store
        .create_or_update_principal(
            write_request("nightly", "system", None),
            &test_execution_contexts(),
        )
        .unwrap();
    assert!(matches!(
        store.principal_account_username("nightly"),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    store
        .create_or_update_principal(
            write_request("nightly", "service_account", None),
            &test_execution_contexts(),
        )
        .unwrap();
    assert_ne!(
        name(&store, "nightly").unwrap().incarnation,
        first.incarnation
    );
    store.check_ready(None).unwrap();
}

#[test]
fn both_reservation_lists_apply_to_service_accounts_at_creation_and_at_every_use() {
    let (_temp, store) = fixture();
    // `fixture` reserves root and operator and lists carol and dave.
    for id in ["root", "carol"] {
        assert!(matches!(
            store.create_principal_with_effect(
                write_request(id, "service_account", None),
                None,
                None,
                &test_execution_contexts()
            ),
            Err(ManagedStoreError::InputInvalid(message)) if message.contains("reserved username")
        ));
        // The same ID is refused when an existing principal changes kind.
        create(&store, id, "system", None);
        assert!(matches!(
            store.create_or_update_principal(
                write_request(id, "service_account", None),
                &test_execution_contexts()
            ),
            Err(ManagedStoreError::InputInvalid(message)) if message.contains("reserved username")
        ));
        assert_eq!(store.principal(id).unwrap().kind, "system");
    }

    // A service account that already exists under a name the operator
    // lists later, or that another path created, holds an unusable name.
    create(&store, "robot", "service_account", None);
    create(&store, "nightly", "service_account", None);
    assert!(name(&store, "robot").unwrap().is_usable());
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &["robot"],
        &["nightly"],
    ));
    for id in ["robot", "nightly"] {
        assert_eq!(
            name(&store, id).unwrap().state,
            AccountUsernameState::Reserved
        );
    }
    // A listed existing username belongs to a person: it cannot be confirmed
    // for a service account.
    assert_eq!(
        store
            .confirm_account_username("nightly", "nightly", "admin")
            .unwrap(),
        Err(AccountUsernameRefusal::NotHuman)
    );
    assert_eq!(
        name(&store, "nightly").unwrap().state,
        AccountUsernameState::Reserved
    );
    // Removing the entries makes the names usable again.
    store.configure_account_usernames(policy());
    for id in ["robot", "nightly"] {
        assert!(name(&store, id).unwrap().is_usable());
    }
}

#[test]
fn concurrent_creation_allocates_one_name_to_one_account() {
    let (_temp, store) = fixture();
    let handles = (0..8)
        .map(|index| {
            let store = store.clone();
            std::thread::spawn(move || {
                create(
                    &store,
                    &format!("usr-{index}"),
                    "user",
                    Some("alice@example.com"),
                )
                .derived_account_username
                .is_some()
            })
        })
        .collect::<Vec<_>>();
    let named = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|named| *named)
        .count();
    assert_eq!(named, 1);
    let holders = store
        .list_principal_account_usernames()
        .unwrap()
        .into_iter()
        .filter(|entry| entry.name.is_some())
        .count();
    assert_eq!(holders, 1);

    // A second connection to the same file sees the same single allocation.
    let other = ManagedStore::open(
        &config_at(store.path(), false),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    other.configure_account_usernames(policy());
    assert_eq!(
        other
            .set_account_username("usr-0", "alice", "admin")
            .unwrap()
            .err(),
        name(&store, "usr-0")
            .is_none()
            .then_some(AccountUsernameRefusal::NameTaken)
    );
}

/// Two stores on one file. Each has a connection of its own, so what they
/// do at the same time contends in SQLite, not on a lock of this process.
fn two_stores() -> (TempDir, [ManagedStore; 2]) {
    let (temp, first) = fixture();
    let second = ManagedStore::open(
        &config_at(first.path(), false),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    second.configure_account_usernames(policy());
    (temp, [first, second])
}

/// Runs `first` and `second` at the same moment, each on a thread of its
/// own, and returns what each did.
fn race<A: Send + 'static, B: Send + 'static>(
    first: impl FnOnce() -> A + Send + 'static,
    second: impl FnOnce() -> B + Send + 'static,
) -> (A, B) {
    let start = Arc::new(std::sync::Barrier::new(2));
    let (first_start, second_start) = (start.clone(), start);
    let first = std::thread::spawn(move || {
        first_start.wait();
        first()
    });
    let second = std::thread::spawn(move || {
        second_start.wait();
        second()
    });
    (first.join().unwrap(), second.join().unwrap())
}

#[test]
fn two_connections_racing_for_one_name_give_it_to_exactly_one_holder() {
    const ROUNDS: usize = 24;
    let (_temp, stores) = two_stores();
    // The two connections take turns at being the one that asks first.
    let sides = |round: usize| {
        let [first, second] = stores.clone();
        if round.is_multiple_of(2) {
            (first, second)
        } else {
            (second, first)
        }
    };
    // Who holds `wanted`, as each connection sees it: the same single
    // principal on both, or nobody.
    let holders = |wanted: &str| {
        let seen = stores.clone().map(|store| {
            store
                .list_principal_account_usernames()
                .unwrap()
                .into_iter()
                .filter(|entry| {
                    entry
                        .name
                        .as_ref()
                        .is_some_and(|name| name.account_username == wanted)
                })
                .map(|entry| entry.principal_id)
                .collect::<Vec<_>>()
        });
        assert_eq!(seen[0], seen[1], "{wanted}");
        seen[0].clone()
    };

    for round in 0..ROUNDS {
        // People against people, at creation: two accounts whose emails
        // give the same name are created at once. One is named; the other
        // is created without a name.
        let wanted = format!("created{round}");
        let email = format!("{wanted}@example.com");
        let (left, right) = sides(round);
        let (ids, emails) = (
            [format!("usr-ca-{round}"), format!("usr-cb-{round}")],
            [
                email.clone(),
                email.to_uppercase().replace("EXAMPLE.COM", "example.com"),
            ],
        );
        let (a, b) = {
            let [id_a, id_b] = ids.clone();
            let [email_a, email_b] = emails;
            race(
                move || create(&left, &id_a, "user", Some(&email_a)).derived_account_username,
                move || create(&right, &id_b, "user", Some(&email_b)).derived_account_username,
            )
        };
        let named = [&a, &b].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(named.len(), 1, "round {round}: {a:?} {b:?}");
        assert_eq!(named[0].account_username, wanted);
        assert_eq!(holders(&wanted), [named[0].principal_id.clone()]);
        let loser = ids.iter().find(|id| **id != named[0].principal_id).unwrap();
        assert_eq!(
            status(&stores[round % 2], loser),
            (
                Some(AccountUsernameMode::FromEmail),
                PrincipalAccountUsernameState::Conflict,
                Some(AccountUsernameReason::NameTaken)
            ),
            "round {round}"
        );

        // People against people, by hand: two people who hold no name are
        // both given the same one at once. One holds it; the other is
        // refused and holds none.
        let wanted = format!("typed{round}");
        let ids = [format!("usr-ta-{round}"), format!("usr-tb-{round}")];
        for id in &ids {
            create(&stores[0], id, "user", None);
        }
        let (left, right) = sides(round);
        let (a, b) = {
            let [id_a, id_b] = ids.clone();
            let (name_a, name_b) = (wanted.clone(), wanted.clone());
            race(
                move || left.set_account_username(&id_a, &name_a, "admin").unwrap(),
                move || right.set_account_username(&id_b, &name_b, "admin").unwrap(),
            )
        };
        let refusals = [&a, &b]
            .into_iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .collect::<Vec<_>>();
        assert_eq!(
            refusals,
            [&AccountUsernameRefusal::NameTaken],
            "round {round}"
        );
        assert_eq!(holders(&wanted).len(), 1, "round {round}");

        // A person against a service account's ID, by hand: a person is
        // given a name at the moment a service account is created under it.
        // Either the person holds the name and the account is refused, or
        // the account exists and the person is refused: never both.
        let wanted = format!("svc-typed{round}");
        let person = format!("usr-sa-{round}");
        create(&stores[0], &person, "user", None);
        let (left, right) = sides(round);
        let (set, created) = {
            let (person, name, id) = (person.clone(), wanted.clone(), wanted.clone());
            race(
                move || left.set_account_username(&person, &name, "admin").unwrap(),
                move || {
                    right.create_principal_with_effect(
                        write_request(&id, "service_account", None),
                        None,
                        None,
                        &test_execution_contexts(),
                    )
                },
            )
        };
        assert_ne!(
            set.is_ok(),
            created.is_ok(),
            "round {round}: {set:?} {:?}",
            created
                .as_ref()
                .map(|creation| &creation.principal.principal_id)
        );
        assert_eq!(
            holders(&wanted),
            [if set.is_ok() {
                person.clone()
            } else {
                wanted.clone()
            }],
            "round {round}"
        );
        if let Err(refusal) = &set {
            assert_eq!(*refusal, AccountUsernameRefusal::NameTaken);
        }

        // A person against a service account's ID, at creation: a person
        // whose email gives the ID is created at the moment the service
        // account is. Either the person is named and the account refused,
        // or the account exists and the person has no name.
        let wanted = format!("svc-derived{round}");
        let person = format!("usr-sd-{round}");
        let (left, right) = sides(round);
        let (derived, created) = {
            let (person, email, id) = (
                person.clone(),
                format!("{wanted}@example.com"),
                wanted.clone(),
            );
            race(
                move || create(&left, &person, "user", Some(&email)).derived_account_username,
                move || {
                    right.create_principal_with_effect(
                        write_request(&id, "service_account", None),
                        None,
                        None,
                        &test_execution_contexts(),
                    )
                },
            )
        };
        assert_ne!(derived.is_some(), created.is_ok(), "round {round}");
        assert_eq!(
            holders(&wanted),
            [if derived.is_some() {
                person
            } else {
                wanted.clone()
            }],
            "round {round}"
        );
    }

    // Over every round no name has two holders, on either connection.
    for store in &stores {
        let mut names = store
            .list_principal_account_usernames()
            .unwrap()
            .into_iter()
            .filter_map(|entry| entry.name.map(|name| name.account_username))
            .collect::<Vec<_>>();
        let held = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), held);
        assert_eq!(held, 4 * ROUNDS);
    }
}

#[test]
fn migration_names_existing_service_accounts_and_people_are_named_afterwards() {
    let temp = temp();
    let path = temp.path().join("store.sqlite");
    let previous_end = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| migration.version == MANAGED_STORE_RESOURCE_BROWSER_URLS_VERSION)
        .unwrap();
    let previous = ManagedStoreMigrationCatalog {
        migrations: &MANAGED_STORE_MIGRATIONS[..=previous_end],
    };
    assert_eq!(MANAGED_STORE_ACCESS_KEYS_VERSION, "040_access_keys");
    let old = ManagedStore::open_with_catalog(
        &config_at(&path, true),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        previous,
    )
    .unwrap();
    old.connection
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO principals (principal_id, kind, email, status, created_at, updated_at, created_by, role, self_service_enabled) VALUES
             ('usr-1', 'user', 'alice@example.com', 'active', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'admin', 'user', 1),
             ('robot', 'service_account', NULL, 'active', '2026-01-03T00:00:00Z', '2026-01-03T00:00:00Z', 'admin', 'user', 0),
             ('sys', 'system', NULL, 'active', '2026-01-04T00:00:00Z', '2026-01-04T00:00:00Z', 'admin', 'user', 1);",
        )
        .unwrap();
    let ledger = |path: &Path| {
        let conn = Connection::open(path).unwrap();
        let mut statement = conn
            .prepare("SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version")
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let before = ledger(&path);
    drop(old);
    assert!(matches!(
        ManagedStore::open(
            &config_at(&path, false),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup
        ),
        Err(ManagedStoreError::MigrationRequired)
    ));
    assert_eq!(ledger(&path), before);

    let current = ManagedStore::open(
        &config_at(&path, true),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(current.migration_applied_this_open(MANAGED_STORE_ACCESS_KEYS_VERSION));
    let after = ledger(&path);
    assert_eq!(&after[..before.len()], before.as_slice());
    assert_eq!(after.len(), MANAGED_STORE_MIGRATIONS.len());
    assert_eq!(after[before.len()].0, MANAGED_STORE_ACCESS_KEYS_VERSION);
    assert_eq!(
        after[before.len()].1,
        sha256_hex(include_str!("access_keys.sql").as_bytes())
    );
    current.configure_account_usernames(policy());
    assert_eq!(
        current.principal("usr-1").unwrap().updated_at,
        "2026-01-02T00:00:00Z"
    );

    // A migrated service account whose ID the operator reserves holds an
    // unusable name; without the reservation it is usable.
    current.configure_account_usernames(AccountUsernamePolicy::for_test(&[], &[], &["robot"]));
    assert_eq!(
        name(&current, "robot").unwrap().state,
        AccountUsernameState::Reserved
    );
    current.configure_account_usernames(policy());

    // The service account holds its ID. The migration itself names no
    // person: every existing account follows its email and waits for the
    // fill after startup, or for its next sign-in.
    let robot = name(&current, "robot").unwrap();
    assert_eq!(robot.account_username, "robot");
    assert_eq!(robot.assigned_at, "2026-01-03T00:00:00Z");
    assert_eq!(robot.assigned_by, "system:access_keys_migration");
    assert_eq!(
        status(&current, "usr-1"),
        (
            Some(AccountUsernameMode::FromEmail),
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::NotYetAssigned)
        )
    );
    assert_eq!(name(&current, "usr-1"), None);
    assert!(
        current
            .list_access_key_views(
                &crate::AccessKeyTypes::default(),
                &AccessKeyListFilter {
                    include_revoked: true,
                    include_expired: true,
                    ..Default::default()
                },
            )
            .unwrap()
            .is_empty()
    );
    // The fill that runs after startup names it.
    let fill = current
        .fill_missing_account_usernames(None, 10, "system:startup")
        .unwrap();
    assert_eq!((fill.examined, fill.next.clone()), (1, None));
    assert_eq!(fill.assigned.len(), 1);
    assert_eq!(fill.assigned[0].account_username, "alice");
    assert_eq!(fill.assigned[0].assigned_by, "system:startup");
    assert_eq!(name(&current, "usr-1"), Some(fill.assigned[0].clone()));
    current.check_ready(None).unwrap();
    drop(current);

    assert!(
        ManagedStore::open_with_catalog(
            &config_at(&path, false),
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
            previous
        )
        .is_err()
    );
    let reopened = ManagedStore::open(
        &config_at(&path, false),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(!reopened.migration_applied_this_open(MANAGED_STORE_ACCESS_KEYS_VERSION));
    assert_eq!(ledger(&path), after);
    assert_eq!(name(&reopened, "robot"), Some(robot));
}

/// Accounts created while no domain is listed, so that none is named: the
/// people who exist when the feature is first configured.
fn unnamed(store: &ManagedStore, accounts: &[(&str, Option<&str>)]) {
    store.configure_account_usernames(AccountUsernamePolicy::default());
    for (id, email) in accounts {
        assert!(
            create(store, id, "user", *email)
                .derived_account_username
                .is_none()
        );
    }
    store.configure_account_usernames(policy());
}

fn fill(store: &ManagedStore, after: Option<&str>, limit: usize) -> AccountUsernameFillBatch {
    store
        .fill_missing_account_usernames(after, limit, "system:startup")
        .unwrap()
}

#[test]
fn the_fill_names_people_who_follow_their_email_and_hold_no_name() {
    let (_temp, store) = fixture();
    let held = create(&store, "usr-0", "user", Some("alice@example.com"))
        .derived_account_username
        .unwrap();
    unnamed(
        &store,
        &[
            ("usr-a", Some("Ann@example.com")),
            // The email of the first holder: a conflict, never a move.
            ("usr-b", Some("alice@example.com")),
            ("usr-c", None),
            ("usr-d", Some("dora@example.org")),
            // A listed existing ID: named, awaiting confirmation.
            ("usr-e", Some("carol@example.com")),
            ("usr-f", Some("fay@example.com")),
            ("usr-g", Some("root@example.com")),
        ],
    );
    // A person an administrator left without a name is not the fill's.
    clear(&store, "usr-f");
    create(&store, "robot", "service_account", None);

    let batch = fill(&store, None, 100);
    // Everyone who follows their email and holds no name was examined.
    assert_eq!((batch.examined, batch.next.clone()), (6, None));
    assert_eq!(
        batch
            .assigned
            .iter()
            .map(|name| (
                name.principal_id.as_str(),
                name.account_username.as_str(),
                name.state,
                name.assigned_by.as_str()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "usr-a",
                "ann",
                AccountUsernameState::Usable,
                "system:startup"
            ),
            (
                "usr-e",
                "carol",
                AccountUsernameState::AwaitingConfirmation,
                "system:startup"
            ),
        ]
    );
    for name in &batch.assigned {
        assert_eq!(name.origin, AccountUsernameOrigin::Derived);
    }
    // It moved no name and changed no account that held one.
    assert_eq!(name(&store, "usr-0"), Some(held));
    assert_eq!(name(&store, "usr-f"), None);
    for (id, state, reason) in [
        (
            "usr-b",
            PrincipalAccountUsernameState::Conflict,
            AccountUsernameReason::NameTaken,
        ),
        (
            "usr-c",
            PrincipalAccountUsernameState::None,
            AccountUsernameReason::NoEmail,
        ),
        (
            "usr-d",
            PrincipalAccountUsernameState::None,
            AccountUsernameReason::DomainNotListed,
        ),
        (
            "usr-g",
            PrincipalAccountUsernameState::None,
            AccountUsernameReason::NameReserved,
        ),
    ] {
        assert_eq!(
            status(&store, id),
            (Some(AccountUsernameMode::FromEmail), state, Some(reason)),
            "{id}"
        );
    }

    // It only fills in what is missing: the next one finds the four it
    // could not name and names nobody.
    let again = fill(&store, None, 100);
    assert_eq!((again.examined, again.assigned.len()), (4, 0));
    // A domain added later names its people at the next fill.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com", "example.org"],
        &["root"],
        &[],
    ));
    let added = fill(&store, None, 100);
    assert_eq!(added.examined, 4);
    assert_eq!(
        added
            .assigned
            .iter()
            .map(|name| (name.principal_id.as_str(), name.account_username.as_str()))
            .collect::<Vec<_>>(),
        [("usr-d", "dora")]
    );
    // Delisting it takes the name away from nobody.
    store.configure_account_usernames(policy());
    assert_eq!(fill(&store, None, 100).assigned.len(), 0);
    assert_eq!(name(&store, "usr-d").unwrap().account_username, "dora");
    assert!(matches!(
        store.fill_missing_account_usernames(None, 0, "system:startup"),
        Err(ManagedStoreError::InputInvalid(_))
    ));
}

#[test]
fn the_fill_walks_a_population_nobody_in_which_can_be_named_in_bounded_batches() {
    let (_temp, store) = fixture();
    // Seven people without an email: none of them can be named.
    let ids: Vec<String> = (0..7).map(|index| format!("usr-{index}")).collect();
    for id in &ids {
        create(&store, id, "user", None);
    }
    let mut after = None;
    let mut batches = Vec::new();
    loop {
        let batch = fill(&store, after.as_deref(), 3);
        // A batch never examines more than its limit, named or not.
        assert!(batch.examined <= 3);
        assert!(batch.assigned.is_empty());
        batches.push((batch.examined, batch.next.clone()));
        match batch.next {
            Some(next) => after = Some(next),
            None => break,
        }
        assert!(batches.len() < 10, "the walk ends");
    }
    assert_eq!(
        batches,
        [
            (3, Some("usr-2".to_string())),
            (3, Some("usr-5".to_string())),
            (1, None),
        ]
    );
    assert!(ids.iter().all(|id| name(&store, id).is_none()));

    // The walk gets past the accounts it cannot name: people behind them,
    // in principal-ID order, are reached and named.
    unnamed(
        &store,
        &[
            ("usr-7", Some("gus@example.com")),
            ("usr-8", Some("hal@example.com")),
        ],
    );
    let mut after = None;
    let (mut examined, mut named) = (0, Vec::new());
    loop {
        let batch = fill(&store, after.as_deref(), 3);
        examined += batch.examined;
        named.extend(batch.assigned.into_iter().map(|name| name.account_username));
        match batch.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(examined, 9);
    assert_eq!(named, ["gus", "hal"]);
    // A batch that ends exactly at the last account reports that more may
    // remain, and the next one is empty and final.
    let exact = fill(&store, None, 7);
    assert_eq!((exact.examined, exact.next.as_deref()), (7, Some("usr-6")));
    let last = fill(&store, exact.next.as_deref(), 7);
    assert_eq!((last.examined, last.next), (0, None));
}

#[test]
fn broker_secrets_cannot_be_assigned_derived_or_confirmed_as_usernames() {
    let (_temp, store) = fixture();
    create(&store, "alice", "user", Some("alice@example.com"));
    for (i, prefix) in [
        "aab_",
        "aab_ak_",
        "aab_ai_",
        "aab_um_",
        "aab_ad_",
        "aab_future_",
    ]
    .into_iter()
    .enumerate()
    {
        let secret = format!("{prefix}{}", "A".repeat(43));
        assert_eq!(
            store
                .set_account_username_setting(
                    "alice",
                    &AccountUsernameSetting::ManualName(secret.clone()),
                    "admin"
                )
                .unwrap()
                .unwrap_err(),
            AccountUsernameRefusal::NameInvalid
        );
        assert_eq!(
            store
                .confirm_account_username("alice", &secret, "admin")
                .unwrap()
                .unwrap_err(),
            AccountUsernameRefusal::NameInvalid
        );
        assert_eq!(name(&store, "alice").unwrap().account_username, "alice");
        let derived = format!("derived-{i}");
        create(
            &store,
            &derived,
            "user",
            Some(&format!("{secret}@example.com")),
        );
        assert!(name(&store, &derived).is_none());
        assert!(
            store
                .create_principal(
                    write_request(&secret, "service_account", None),
                    &test_execution_contexts()
                )
                .is_err()
        );
        assert!(
            store
                .list_principal_account_usernames()
                .unwrap()
                .iter()
                .all(|view| view
                    .name
                    .as_ref()
                    .is_none_or(|name| !name.account_username.starts_with("aab_")))
        );
    }
}
