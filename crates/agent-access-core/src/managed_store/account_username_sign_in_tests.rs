#[test]
fn microsoft_sign_in_names_a_person_at_creation_and_whenever_they_hold_no_name() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store.configure_account_usernames(crate::AccountUsernamePolicy::for_test(&["example.com"], &[], &[]));
    let provider = enrollment_fixture(&store);
    let now = normalized_now_string();
    let hasher = broker_token_hasher_for_test(75);
    let sign_in = |flow: u64, user: &str, principal: &str, email: &str| {
        let mut request = test_oidc_completion_request(
            flow,
            provider.config_generation,
            user,
            principal,
            &[TEST_EXTERNAL_GROUP_A],
            &now,
        );
        request.email = Some(email.to_string());
        let outcome = store.complete_oidc_login(&hasher, request).unwrap();
        let OidcCompletionOutcome::Succeeded { result, .. } = outcome else {
            panic!("expected a successful sign-in")
        };
        *result
    };

    // A person created by their first Microsoft sign-in is named in the
    // transaction that creates them, from the profile email it stores.
    let created = sign_in(1, TEST_OIDC_USER, "usr-dana", "Dana@example.com");
    let derived = created.derived_account_username.unwrap();
    assert_eq!(derived.account_username, "dana");
    assert_eq!(derived.assigned_by, "oidc-microsoft");
    assert_eq!(
        store.principal_account_username("usr-dana").unwrap().name,
        Some(derived.clone())
    );
    assert_eq!(
        store.principal_account_username("usr-dana").unwrap().mode,
        Some(AccountUsernameMode::FromEmail)
    );
    // A later sign-in of a person who holds a name derives nothing, and
    // neither does one of a person an administrator left without a name.
    assert!(
        sign_in(2, TEST_OIDC_USER, "unused", "Dana@example.com")
            .derived_account_username
            .is_none()
    );
    store
        .set_account_username_setting("usr-dana", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert!(
        sign_in(5, TEST_OIDC_USER, "unused", "Dana@example.com")
            .derived_account_username
            .is_none()
    );
    assert_eq!(store.principal_account_username("usr-dana").unwrap().name, None);

    // An account that follows its email and holds no name, here because it
    // was created before the domain was listed, is named at its Microsoft
    // sign-in, from its profile email and not the token's.
    store.configure_account_usernames(crate::AccountUsernamePolicy::default());
    store
        .create_principal(
            PrincipalWriteRequest {
                principal_id: "usr-erin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                agent_token_issuance: test_principal_issuance(
                    PrincipalAgentTokenIssuance::Disabled,
                ),
            },
            &test_execution_contexts(),
        )
        .unwrap();
    store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "usr-erin".into(),
            user_object_id: TEST_OIDC_USER_TWO.into(),
            actor: "admin".into(),
        })
        .unwrap();
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "usr-erin".into(),
            display_name: None,
            email: Some(Some("erin@example.com".into())),
            status: None,
        })
        .unwrap();
    assert_eq!(store.principal_account_username("usr-erin").unwrap().name, None);
    store.configure_account_usernames(crate::AccountUsernamePolicy::for_test(&["example.com"], &[], &[]));
    let first = sign_in(3, TEST_OIDC_USER_TWO, "unused", "someone.else@example.com");
    assert_eq!(first.principal.principal_id, "usr-erin");
    let derived = first.derived_account_username.unwrap();
    assert_eq!(derived.account_username, "erin");
    assert_eq!(derived.assigned_by, "system:sign_in");
    assert!(
        sign_in(4, TEST_OIDC_USER_TWO, "unused", "someone.else@example.com")
            .derived_account_username
            .is_none()
    );
    // No sign-in found or merged an account by email.
    assert_eq!(store.principal_count().unwrap(), 2);
}

/// A group a person holds only by Microsoft group evidence is not a group of
/// their access keys: it is not returned by a resolution and what the
/// group allows is not allowed to them. The same group held by local
/// membership is returned and counts.
#[test]
fn directory_evidence_membership_is_neither_returned_nor_counted_for_access_key_types() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store.configure_account_usernames(crate::AccountUsernamePolicy::for_test(&["example.com"], &[], &[]));
    // The local group `mapped` is bound to a Microsoft group.
    let provider = enrollment_fixture(&store);
    let hasher = broker_token_hasher_for_test(76);
    let mut request = test_oidc_completion_request(
        1,
        provider.config_generation,
        TEST_OIDC_USER,
        "usr-dana",
        &[TEST_EXTERNAL_GROUP_A],
        &normalized_now_string(),
    );
    request.email = Some("dana@example.com".to_string());
    let OidcCompletionOutcome::Succeeded { result, .. } =
        store.complete_oidc_login(&hasher, request).unwrap()
    else {
        panic!("expected a successful sign-in")
    };
    // Dana is in `mapped` for the Broker's own policy, by evidence alone.
    assert!(result.membership.groups.contains(&"mapped".to_string()));
    let mapped = result
        .membership
        .details
        .iter()
        .find(|detail| detail.group_id == "mapped")
        .unwrap();
    assert!(mapped.effective && mapped.local.is_none() && !mapped.microsoft.is_empty());

    let access_key_type = |id: &str| crate::AccessKeyType {
        id: id.into(),
        display_name: id.into(),
        description: None,
        lifetime_options: vec!["600s".into(), "1h".into()],
        default_lifetime: "1h".into(),
        self_service: true,
    };
    let access_key_types = crate::AccessKeyTypes::for_test([access_key_type("own"), access_key_type("members")]);
    // Dana's account allows `own`; `members` is allowed only by `mapped`.
    store.set_principal_access_key_types_for_test("usr-dana", &["own"], &[], &access_key_types);
    store.set_group_access_key_types_for_test("mapped", &["members"], &access_key_types);
    let mint = |ids: &[&str]| {
        store
            .mint_portal_access_key(
                &hasher,
                &access_key_types,
                &PortalAccessKeyRequest {
                    principal_id: "usr-dana".into(),
                    session_token_id: result.session.record.token_id.clone(),
                    name: "laptop".into(),
                    access_key_types: ids.iter().map(|id| (*id).to_string()).collect(),
                    lifetime: "600s".into(),
                },
            )
            .unwrap()
    };
    let options = |store: &ManagedStore| {
        store
            .portal_access_key_options(&access_key_types, "usr-dana")
            .unwrap()
            .access_key_types
            .into_iter()
            .map(|access_key_type| access_key_type.id)
            .collect::<Vec<_>>()
    };
    let resolve = |token: &str| {
        match store
            .resolve_access_key(&hasher, &access_key_types, token)
            .unwrap()
        {
            AccessKeyResolution::Active(facts) => *facts,
            AccessKeyResolution::Inactive(inactive) => panic!("inactive: {:?}", inactive.reason),
        }
    };

    // What the group allows is not allowed to her by evidence.
    let refused = mint(&["members"]).unwrap_err();
    assert_eq!(refused.refusal, AccessKeyRefusal::AccessKeyTypeNotEligible);
    assert_eq!(refused.access_key_type.as_deref(), Some("members"));
    assert_eq!(options(&store), ["own"]);
    assert_eq!(
        store
            .access_key_type_policy(&access_key_types, "usr-dana")
            .unwrap()
            .access_key_types
            .iter()
            .map(|decision| (decision.access_key_type.as_str(), decision.source))
            .collect::<Vec<_>>(),
        [
            ("members", crate::AccessKeyTypeSource::None),
            ("own", crate::AccessKeyTypeSource::Account),
        ]
    );
    // Her token carries no group she holds by evidence only.
    let token = mint(&["own"]).unwrap();
    let facts = resolve(&token.key);
    assert_eq!(facts.subject.id, "dana");
    assert_eq!(facts.groups, Vec::<String>::new());

    // Local membership of the same group is returned and counts.
    store.add_group("usr-dana", "mapped", "admin").unwrap();
    assert_eq!(resolve(&token.key).groups, ["mapped"]);
    assert_eq!(options(&store), ["members", "own"]);
    let member = mint(&["members"]).unwrap();
    assert_eq!(
        resolve(&member.key)
            .access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.as_str())
            .collect::<Vec<_>>(),
        ["members"]
    );
    // Without it the access key type is gone again, evidence or not.
    store.remove_group("usr-dana", "mapped").unwrap();
    assert!(matches!(
        store
            .resolve_access_key(&hasher, &access_key_types, &member.key)
            .unwrap(),
        AccessKeyResolution::Inactive(inactive)
            if inactive.reason == AccessKeyInactiveReason::NoAccessKeyType
    ));
}
