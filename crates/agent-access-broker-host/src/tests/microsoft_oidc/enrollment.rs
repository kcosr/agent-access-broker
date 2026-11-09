//! Full callback validation and transaction outcomes for explicit email enrollment.
use super::*;
use agent_access_core::{
    ConfiguredExecutionContexts, MicrosoftEnrollmentCancelRequest, MicrosoftEnrollmentCreate,
    MicrosoftEnrollmentUpdateRequest, OidcLoginMethodLinkRequest, PrincipalPatchRequest,
    PrincipalRole, PrincipalWriteRequest,
};

async fn fixture_without_jit() -> OidcBrowserFixture {
    oidc_browser_fixture_custom(
        false,
        false,
        temp_path("microsoft-precreation.audit.jsonl"),
        |config| {
            config.browser_auth.oidc.microsoft.jit_provisioning = false;
        },
    )
    .await
}

fn prepare(
    fixture: &OidcBrowserFixture,
    id: &str,
    enrollment: Option<&str>,
) -> agent_access_core::PrincipalRecord {
    fixture
        .store
        .create_principal_with_microsoft_enrollment(
            PrincipalWriteRequest {
                principal_id: id.into(),
                kind: "user".into(),
                display_name: Some("Prepared display name".into()),
                email: Some("profile@example.test".into()),
                external_subject: None,
                role: PrincipalRole::User,
                self_service_enabled: Some(false),
                agent_token_issuance: Default::default(),
                created_by: "administrator".into(),
            },
            enrollment.map(|email| MicrosoftEnrollmentCreate {
                email: email.into(),
            }),
            enrollment.map(|_| {
                fixture
                    .store
                    .oidc_provider_state()
                    .unwrap()
                    .unwrap()
                    .config_generation
            }),
            &ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap()
}

fn default_group(fixture: &OidcBrowserFixture, id: &str) {
    fixture
        .store
        .create_group(
            GroupWriteRequest {
                group_id: id.into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: true,
                agent_token_issuance: Default::default(),
                created_by: "administrator".into(),
            },
            &ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
}

fn status(fixture: &OidcBrowserFixture, principal: &str, value: &str) {
    fixture
        .store
        .patch_principal(PrincipalPatchRequest {
            principal_id: principal.into(),
            display_name: None,
            email: None,
            status: Some(value.into()),
        })
        .unwrap();
}

#[tokio::test]
async fn pending_binding_bypasses_jit_and_group_gate_preserves_account_and_inventory() {
    let fixture = fixture_without_jit().await;
    let principal = prepare(&fixture, "prepared", Some("  ADA@Example.Test  "));
    let enrollment = principal.microsoft_enrollment.unwrap();
    let inventory = fixture.store.identity_token_metadata("prepared").unwrap();
    let identity_gate = fixture.store.identity_access("prepared").unwrap();
    default_group(&fixture, "prepared-group");
    default_group(&fixture, "initial-group");
    fixture
        .store
        .add_group("prepared", "prepared-group", "administrator")
        .unwrap();
    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.groups = FakeGroupClaims::Empty;
    fixture.provider.set_next_claims(claims);
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-first").await;
    assert!(session_cookie(&response).is_some());
    assert_eq!(fixture.store.list_principals().unwrap().len(), 1);
    let principal = fixture.store.principal("prepared").unwrap();
    assert_eq!(principal.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(principal.email.as_deref(), Some("profile@example.test"));
    assert!(!principal.self_service_enabled);
    assert_eq!(principal.role, PrincipalRole::User);
    assert!(principal.microsoft_enrollment.is_none());
    assert_eq!(
        fixture.store.identity_token_metadata("prepared").unwrap(),
        inventory
    );
    assert_eq!(
        fixture.store.identity_access("prepared").unwrap(),
        identity_gate
    );
    let membership = fixture
        .store
        .effective_membership_at("prepared", &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["initial-group", "prepared-group"]);
    assert_eq!(
        membership
            .details
            .iter()
            .find(|g| g.group_id == "prepared-group")
            .unwrap()
            .local
            .as_ref()
            .unwrap()
            .added_by,
        "administrator"
    );
    let audit = login_success_audit(&fixture, "precreated-first");
    assert_eq!(audit["jitCreated"], false);
    assert_eq!(audit["enrollmentId"], enrollment.enrollment_id);
    assert_eq!(audit["tenantId"], TENANT_ID);
    assert_eq!(audit["displayNameUpdated"], true);
    assert_eq!(audit["autoEnrolledGroupIds"], json!(["initial-group"]));
    assert!(!audit.to_string().contains("example.test"));
    assert!(!audit.to_string().contains("Ada"));

    // The email is irrelevant after binding, and manually removed defaults stay removed.
    fixture
        .store
        .remove_group("prepared", "initial-group")
        .unwrap();
    fixture.clock.advance_seconds(1);
    let mut claims = FakeTokenClaims::valid(fixture.clock.now().timestamp());
    claims.email = Some("different@example.test".into());
    claims.groups = FakeGroupClaims::Empty;
    fixture.provider.set_next_claims(claims);
    let flow = start_browser_login(&fixture, Some(&flow.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-return").await;
    assert!(session_cookie(&response).is_some());
    let audit = login_success_audit(&fixture, "precreated-return");
    assert!(audit.get("enrollmentId").is_none());
    assert_eq!(audit["displayNameUpdated"], false);
    assert_eq!(audit["autoEnrolledGroupIds"], json!([]));
    assert!(
        fixture
            .store
            .group_members("initial-group")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn display_name_refresh_uses_sanitized_fallbacks_and_preserves_profile_email() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    let cases = [
        (
            Some(" First name "),
            Some("username@example.test"),
            Some("ada@example.test"),
            "First name",
            true,
        ),
        (
            None,
            Some(" Fallback username "),
            Some("changed@example.test"),
            "Fallback username",
            true,
        ),
        (
            Some("bad\nname"),
            Some("\t"),
            Some(" Capital@Example.Test "),
            "Capital@Example.Test",
            true,
        ),
        (None, None, None, "Capital@Example.Test", false),
        (
            Some("Capital@Example.Test"),
            None,
            None,
            "Capital@Example.Test",
            false,
        ),
    ];
    let mut cookie = None;
    for (index, (name, username, email, expected, changed)) in cases.into_iter().enumerate() {
        fixture.clock.advance_seconds(1);
        let mut claims = FakeTokenClaims::valid(fixture.clock.now().timestamp());
        claims.name = name.map(str::to_string);
        claims.preferred_username = username.map(str::to_string);
        claims.email = email.map(str::to_string);
        fixture.provider.set_next_claims(claims);
        let flow = start_browser_login(&fixture, cookie.as_deref()).await;
        let request = format!("precreated-name-{index}");
        let response = finish_browser_login(&fixture, &flow, &request).await;
        assert!(session_cookie(&response).is_some(), "{index}");
        let principal = fixture.store.principal("prepared").unwrap();
        assert_eq!(principal.display_name.as_deref(), Some(expected));
        assert_eq!(principal.email.as_deref(), Some("profile@example.test"));
        assert_eq!(
            login_success_audit(&fixture, &request)["displayNameUpdated"],
            changed
        );
        cookie = Some(flow.binding_cookie);
    }
    fixture
        .store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "prepared".into(),
            display_name: Some(Some("Administrator edit".into())),
            email: None,
            status: None,
        })
        .unwrap();
    fixture.clock.advance_seconds(1);
    fixture
        .provider
        .set_next_claims(FakeTokenClaims::valid(fixture.clock.now().timestamp()));
    let flow = start_browser_login(&fixture, cookie.as_deref()).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-name-admin-edit").await;
    assert!(session_cookie(&response).is_some());
    assert_eq!(
        fixture
            .store
            .principal("prepared")
            .unwrap()
            .display_name
            .as_deref(),
        Some("Ada Lovelace")
    );
    assert_eq!(
        login_success_audit(&fixture, "precreated-name-admin-edit")["displayNameUpdated"],
        true
    );
}

#[tokio::test]
async fn unusable_email_has_no_username_fallback_and_profile_email_is_not_enrollment() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    for (index, email) in [
        None,
        Some("different@example.test".to_string()),
        Some("invalid".to_string()),
        Some(format!("{}@example.test", "x".repeat(321))),
    ]
    .into_iter()
    .enumerate()
    {
        let mut claims = FakeTokenClaims::valid(FIXED_NOW);
        claims.email = email;
        claims.preferred_username = Some("ada@example.test".into());
        fixture.provider.set_next_claims(claims);
        let flow = start_browser_login(&fixture, None).await;
        let request = format!("precreated-no-match-{index}");
        let response = finish_browser_login(&fixture, &flow, &request).await;
        assert_callback_error(&response, "oidc_admission_denied", &request);
        assert!(
            fixture
                .store
                .microsoft_enrollment("prepared")
                .unwrap()
                .is_some()
        );
    }
    let enrollment = fixture
        .store
        .microsoft_enrollment("prepared")
        .unwrap()
        .unwrap();
    fixture
        .store
        .cancel_microsoft_enrollment(MicrosoftEnrollmentCancelRequest {
            principal_id: "prepared".into(),
            enrollment_id: enrollment.enrollment_id,
            expected_revision: enrollment.revision,
            actor: "administrator".into(),
        })
        .unwrap();
    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.email = Some("profile@example.test".into());
    fixture.provider.set_next_claims(claims);
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-profile-is-not-match").await;
    assert_callback_error(
        &response,
        "oidc_admission_denied",
        "precreated-profile-is-not-match",
    );
    assert!(
        fixture
            .store
            .list_login_methods("prepared")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn unmatched_email_follows_ordinary_jit_without_consuming_prepared_account() {
    let fixture = oidc_browser_fixture(false).await;
    prepare(&fixture, "prepared", Some("another@example.test"));
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-unmatched-jit").await;
    assert!(session_cookie(&response).is_some());
    assert_eq!(fixture.store.list_principals().unwrap().len(), 2);
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    let audit = login_success_audit(&fixture, "precreated-unmatched-jit");
    assert_eq!(audit["jitCreated"], true);
    assert_eq!(audit["displayNameUpdated"], false);
    assert!(audit.get("enrollmentId").is_none());
}

#[tokio::test]
async fn disabled_match_and_incomplete_groups_do_not_bind_or_fall_back_to_jit() {
    let fixture = oidc_browser_fixture(false).await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    status(&fixture, "prepared", "disabled");
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-disabled").await;
    assert_callback_error(&response, "oidc_admission_denied", "precreated-disabled");
    status(&fixture, "prepared", "active");
    for (index, groups) in [FakeGroupClaims::Overage, FakeGroupClaims::Malformed]
        .into_iter()
        .enumerate()
    {
        let mut claims = FakeTokenClaims::valid(FIXED_NOW);
        claims.groups = groups;
        fixture.provider.set_next_claims(claims);
        let flow = start_browser_login(&fixture, None).await;
        let request = format!("precreated-incomplete-{index}");
        let response = finish_browser_login(&fixture, &flow, &request).await;
        assert_callback_error(&response, "oidc_group_claims_incomplete", &request);
    }
    assert_eq!(fixture.store.list_principals().unwrap().len(), 1);
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .store
            .list_login_methods("prepared")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .store
            .principal("prepared")
            .unwrap()
            .display_name
            .as_deref(),
        Some("Prepared display name")
    );
}

#[tokio::test]
async fn immutable_subject_precedes_pending_email_including_disabled_identity_refusal() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    prepare(&fixture, "established", None);
    fixture
        .store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "established".into(),
            user_object_id: USER_OBJECT_ID.into(),
            actor: "administrator".into(),
        })
        .unwrap();
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-established").await;
    assert!(session_cookie(&response).is_some());
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .store
            .principal("established")
            .unwrap()
            .display_name
            .as_deref(),
        Some("Ada Lovelace")
    );
    status(&fixture, "established", "disabled");
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-established-disabled").await;
    assert_callback_error(
        &response,
        "oidc_admission_denied",
        "precreated-established-disabled",
    );
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .store
            .list_login_methods("prepared")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn concurrent_identities_only_bind_one_prepared_account() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    default_group(&fixture, "initial-group");
    let first = start_browser_login(&fixture, None).await;
    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.user_object_id = "cccccccc-cccc-4ccc-8ccc-ccccccccccc4".into();
    fixture.provider.set_next_claims(claims);
    let second = start_browser_login(&fixture, None).await;
    let (first, second) = tokio::join!(
        finish_browser_login(&fixture, &first, "precreated-race-one"),
        finish_browser_login(&fixture, &second, "precreated-race-two"),
    );
    assert_eq!(
        [&first, &second]
            .iter()
            .filter(|r| session_cookie(r).is_some())
            .count(),
        1
    );
    assert_eq!(
        fixture.store.list_login_methods("prepared").unwrap().len(),
        1
    );
    assert_eq!(fixture.store.list_principals().unwrap().len(), 1);
    assert_eq!(
        fixture.store.group_members("initial-group").unwrap().len(),
        1
    );
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_callbacks_for_one_identity_consume_pending_and_defaults_once() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    default_group(&fixture, "initial-group");
    let first = start_browser_login(&fixture, None).await;
    let second = start_browser_login(&fixture, None).await;
    let (first, second) = tokio::join!(
        finish_browser_login(&fixture, &first, "precreated-same-one"),
        finish_browser_login(&fixture, &second, "precreated-same-two"),
    );
    assert!(
        [&first, &second]
            .iter()
            .any(|r| session_cookie(r).is_some())
    );
    let records = super::super::read_audit_records(&fixture.audit_path);
    let successes: Vec<_> = records
        .iter()
        .filter(|r| r["action"] == "oidc.login.succeeded")
        .map(|r| &r["providerAudit"]["oidc"])
        .collect();
    assert_eq!(
        successes
            .iter()
            .filter(|r| r.get("enrollmentId").is_some())
            .count(),
        1
    );
    assert_eq!(
        successes
            .iter()
            .filter(|r| r["autoEnrolledGroupIds"] == json!(["initial-group"]))
            .count(),
        1
    );
    assert_eq!(
        fixture.store.list_login_methods("prepared").unwrap().len(),
        1
    );
}

#[tokio::test]
async fn administrator_edit_and_cancel_during_flow_preserve_current_reservation() {
    for cancel in [false, true] {
        let fixture = fixture_without_jit().await;
        let enrollment = prepare(&fixture, "prepared", Some("ada@example.test"))
            .microsoft_enrollment
            .unwrap();
        let flow = start_browser_login(&fixture, None).await;
        if cancel {
            fixture
                .store
                .cancel_microsoft_enrollment(MicrosoftEnrollmentCancelRequest {
                    principal_id: "prepared".into(),
                    enrollment_id: enrollment.enrollment_id,
                    expected_revision: enrollment.revision,
                    actor: "administrator".into(),
                })
                .unwrap();
        } else {
            fixture
                .store
                .update_microsoft_enrollment(MicrosoftEnrollmentUpdateRequest {
                    principal_id: "prepared".into(),
                    enrollment_id: enrollment.enrollment_id,
                    expected_revision: enrollment.revision,
                    email: "replacement@example.test".into(),
                    provider_generation: fixture
                        .store
                        .oidc_provider_state()
                        .unwrap()
                        .unwrap()
                        .config_generation,
                    actor: "administrator".into(),
                })
                .unwrap();
        }
        let response = finish_browser_login(&fixture, &flow, "precreated-edited-flow").await;
        assert_callback_error(&response, "oidc_admission_denied", "precreated-edited-flow");
        assert!(
            fixture
                .store
                .list_login_methods("prepared")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fixture
                .store
                .microsoft_enrollment("prepared")
                .unwrap()
                .is_some(),
            !cancel
        );
    }
}

#[tokio::test]
async fn browser_session_failure_rolls_back_binding_name_and_first_groups() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    default_group(&fixture, "initial-group");
    let connection =
        rusqlite::Connection::open(&fixture.config.managed_store.as_ref().unwrap().path).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_precreated_session BEFORE INSERT ON browser_sessions BEGIN SELECT RAISE(ABORT, 'injected-session-failure'); END;").unwrap();
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-session-failure").await;
    assert_callback_error(&response, "oidc_unavailable", "precreated-session-failure");
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .store
            .list_login_methods("prepared")
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .store
            .group_members("initial-group")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .store
            .principal("prepared")
            .unwrap()
            .display_name
            .as_deref(),
        Some("Prepared display name")
    );
    connection
        .execute_batch("DROP TRIGGER reject_precreated_session;")
        .unwrap();
    let flow = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-session-retry").await;
    assert!(session_cookie(&response).is_some());
    assert_eq!(
        login_success_audit(&fixture, "precreated-session-retry")["autoEnrolledGroupIds"],
        json!(["initial-group"])
    );
}

#[tokio::test]
async fn provider_reload_invalidates_pending_flow_without_consuming_enrollment() {
    let fixture = fixture_without_jit().await;
    prepare(&fixture, "prepared", Some("ada@example.test"));
    fixture
        .store
        .patch_principal_access(
            agent_access_core::PrincipalAccessPatchRequest {
                principal_id: "prepared".into(),
                role: Some(PrincipalRole::Admin),
                self_service_enabled: None,
                agent_token_issuance: None,
                actor: "administrator".into(),
            },
            &ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let flow = start_browser_login(&fixture, None).await;
    let mut config = fixture.config.clone();
    config.browser_auth.oidc.microsoft.jit_provisioning = true;
    fixture.broker.reload_config(&config).await;
    let response = finish_browser_login(&fixture, &flow, "precreated-reloaded-flow").await;
    assert!(session_cookie(&response).is_none());
    assert!(
        fixture
            .store
            .microsoft_enrollment("prepared")
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .store
            .list_login_methods("prepared")
            .unwrap()
            .is_empty()
    );
}
