fn microsoft_precreation_request(principal: &str) -> PrincipalWriteRequest {
    PrincipalWriteRequest {
        principal_id: principal.into(),
        kind: "user".into(),
        display_name: Some("Prepared name".into()),
        email: Some("profile@example.com".into()),
        external_subject: None,
        created_by: "preparing-admin".into(),
        role: PrincipalRole::Auditor,
        self_service_enabled: Some(false),
        agent_token_issuance: test_principal_issuance(PrincipalAgentTokenIssuance::Disabled),
    }
}

fn microsoft_prepare(
    store: &ManagedStore,
    principal: &str,
    email: &str,
    generation: u64,
) -> MicrosoftEnrollmentRecord {
    store
        .create_principal_with_microsoft_enrollment(
            microsoft_precreation_request(principal),
            Some(MicrosoftEnrollmentCreate {
                email: email.into(),
            }),
            Some(generation),
            &test_execution_contexts(),
        )
        .unwrap()
        .microsoft_enrollment
        .unwrap()
}

fn microsoft_cancel_request(
    record: &MicrosoftEnrollmentRecord,
) -> MicrosoftEnrollmentCancelRequest {
    MicrosoftEnrollmentCancelRequest {
        principal_id: record.principal_id.clone(),
        enrollment_id: record.enrollment_id.clone(),
        expected_revision: record.revision,
        actor: "admin".into(),
    }
}

fn microsoft_edit_request(
    record: &MicrosoftEnrollmentRecord,
    email: &str,
    generation: u64,
) -> MicrosoftEnrollmentUpdateRequest {
    MicrosoftEnrollmentUpdateRequest {
        principal_id: record.principal_id.clone(),
        enrollment_id: record.enrollment_id.clone(),
        expected_revision: record.revision,
        email: email.into(),
        provider_generation: generation,
        actor: "editing-admin".into(),
    }
}

fn microsoft_first_request(
    generation: u64,
    object: &str,
    sequence: u64,
) -> OidcCompleteLoginRequest {
    let mut request = test_oidc_completion_request(
        sequence,
        generation,
        object,
        "unused-jit",
        &[],
        &normalized_now_string(),
    );
    request.jit_provisioning = false;
    request.email = Some("  Person@Example.COM  ".into());
    request
}

#[test]
fn microsoft_enrollment_email_is_bounded_and_canonical_without_claim_fallbacks() {
    assert_eq!(
        canonical_microsoft_enrollment_email("  Person@EXAMPLE.COM \t"),
        Some("person@example.com".into())
    );
    assert_eq!(
        canonical_microsoft_enrollment_email("ÄBC@Example.com"),
        Some("Äbc@example.com".into())
    );
    for value in [
        "",
        "person",
        "@example.com",
        "person@example",
        "person@.example.com",
        "person@example.com.",
        "person@@example.com",
        "person\n@example.com",
        "person@example.\0com",
    ] {
        assert!(
            canonical_microsoft_enrollment_email(value).is_none(),
            "{value:?}"
        );
    }
    assert!(
        canonical_microsoft_enrollment_email(&format!("{}@example.com", "a".repeat(309))).is_none()
    );
    assert!(
        canonical_microsoft_enrollment_email(&format!("{}@example.com", "a".repeat(308))).is_some()
    );
}

#[test]
fn microsoft_enrollment_create_edit_cancel_are_explicit_versioned_and_atomic() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, false, 3600, "paused");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        " Person@Example.COM ",
        provider.config_generation,
    );
    assert_eq!(pending.match_email, "person@example.com");
    assert_eq!(pending.tenant_id, TEST_OIDC_TENANT);
    assert_eq!(pending.revision, 1);
    assert_eq!(
        store.list_principals().unwrap()[0].microsoft_enrollment,
        Some(pending.clone())
    );
    assert_eq!(
        store
            .update_microsoft_enrollment(microsoft_edit_request(
                &pending,
                "PERSON@EXAMPLE.COM",
                provider.config_generation
            ))
            .unwrap(),
        pending
    );
    store.set_principal_enabled("prepared", false).unwrap();
    for (principal, email, generation) in [
        (
            "duplicate",
            "person@example.com",
            provider.config_generation,
        ),
        ("invalid", "not-email", provider.config_generation),
        ("stale", "other@example.com", provider.config_generation + 1),
    ] {
        assert!(
            store
                .create_principal_with_microsoft_enrollment(
                    microsoft_precreation_request(principal),
                    Some(MicrosoftEnrollmentCreate {
                        email: email.into()
                    }),
                    Some(generation),
                    &test_execution_contexts()
                )
                .is_err()
        );
        assert!(matches!(
            store.principal(principal),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
    }
    let mut nonhuman = microsoft_precreation_request("robot");
    nonhuman.kind = "service_account".into();
    nonhuman.role = PrincipalRole::User;
    assert!(
        store
            .create_principal_with_microsoft_enrollment(
                nonhuman,
                Some(MicrosoftEnrollmentCreate {
                    email: "robot@example.com".into()
                }),
                Some(provider.config_generation),
                &test_execution_contexts()
            )
            .is_err()
    );
    assert!(matches!(
        store.principal("robot"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    assert!(matches!(
        store.link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "prepared".into(),
            user_object_id: TEST_OIDC_USER.into(),
            actor: "admin".into()
        }),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    let changed = store
        .update_microsoft_enrollment(microsoft_edit_request(
            &pending,
            "new@example.com",
            provider.config_generation,
        ))
        .unwrap();
    assert_eq!(changed.revision, 2);
    assert_eq!(changed.enrollment_id, pending.enrollment_id);
    assert_eq!(changed.created_by, pending.created_by);
    assert_eq!(changed.updated_by, "editing-admin");
    assert!(matches!(
        store.cancel_microsoft_enrollment(microsoft_cancel_request(&pending)),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    assert!(matches!(
        store.update_microsoft_enrollment(microsoft_edit_request(
            &pending,
            "stale@example.com",
            provider.config_generation
        )),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    assert_eq!(
        store
            .cancel_microsoft_enrollment(microsoft_cancel_request(&changed))
            .unwrap(),
        changed
    );
    assert!(store.microsoft_enrollment("prepared").unwrap().is_none());
    let replacement = store
        .create_microsoft_enrollment(MicrosoftEnrollmentCreateRequest {
            principal_id: "prepared".into(),
            email: "person@example.com".into(),
            provider_generation: provider.config_generation,
            actor: "admin".into(),
        })
        .unwrap();
    assert_ne!(replacement.enrollment_id, pending.enrollment_id);
    assert_eq!(replacement.revision, 1);
    assert!(matches!(
        store.cancel_microsoft_enrollment(microsoft_cancel_request(&changed)),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    assert_eq!(
        store.principal("prepared").unwrap().email.as_deref(),
        Some("profile@example.com")
    );
}

#[test]
fn microsoft_enrollment_binding_preserves_preparation_refreshes_names_and_assigns_once() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    for group in ["existing", "new", "paused"] {
        store
            .create_group(
                enrollment_group_request(group, true),
                &test_execution_contexts(),
            )
            .unwrap();
    }
    let mut disabled = enrollment_group_patch("paused", None);
    disabled.status = Some("disabled".into());
    store
        .patch_group(disabled, &test_execution_contexts())
        .unwrap();
    store
        .add_group("prepared", "existing", "preparing-admin")
        .unwrap();
    let original_membership = store.group_members("existing").unwrap()[0].clone();
    let inventory = store.identity_token_metadata("prepared").unwrap();
    let hasher = broker_token_hasher_for_test(83);
    let request = microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 1);
    let bound = enrollment_succeeded(
        store.complete_oidc_login(&hasher, request.clone()).unwrap(),
        false,
    );
    assert_eq!(
        bound.enrollment_id.as_deref(),
        Some(pending.enrollment_id.as_str())
    );
    assert!(bound.display_name_updated);
    assert_eq!(bound.auto_enrolled_group_ids, ["new"]);
    assert_eq!(bound.principal.principal_id, "prepared");
    assert_eq!(
        bound.principal.email.as_deref(),
        Some("profile@example.com")
    );
    assert_eq!(bound.principal.role, PrincipalRole::Auditor);
    assert!(!bound.principal.self_service_enabled);
    assert_eq!(
        bound.principal.agent_token_issuance.mode,
        PrincipalAgentTokenIssuance::Disabled
    );
    assert_eq!(
        store.identity_token_metadata("prepared").unwrap(),
        inventory
    );
    assert!(bound.principal.microsoft_enrollment.is_none());
    let kept = store.group_members("existing").unwrap().remove(0);
    assert_eq!(kept.created_at, original_membership.created_at);
    assert_eq!(kept.created_by, original_membership.created_by);
    assert!(matches!(
        store.update_microsoft_enrollment(microsoft_edit_request(
            &pending,
            "other@example.com",
            provider.config_generation
        )),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    assert!(matches!(
        store.cancel_microsoft_enrollment(microsoft_cancel_request(&pending)),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    store.remove_group("prepared", "new").unwrap();
    let mut later = request.clone();
    later.flow_sequence = 2;
    later.email = Some("changed@example.com".into());
    later.display_name = Some("New Microsoft name".into());
    let returning = enrollment_succeeded(
        store.complete_oidc_login(&hasher, later.clone()).unwrap(),
        false,
    );
    assert!(returning.enrollment_id.is_none());
    assert!(returning.auto_enrolled_group_ids.is_empty());
    assert!(returning.display_name_updated);
    assert_eq!(
        returning.principal.display_name.as_deref(),
        Some("New Microsoft name")
    );
    later.flow_sequence = 3;
    assert!(
        !enrollment_succeeded(
            store.complete_oidc_login(&hasher, later.clone()).unwrap(),
            false
        )
        .display_name_updated
    );
    later.flow_sequence = 4;
    later.display_name = None;
    assert!(
        !enrollment_succeeded(store.complete_oidc_login(&hasher, later).unwrap(), false)
            .display_name_updated
    );
    assert!(matches!(
        store.complete_oidc_login(&hasher, request).unwrap(),
        OidcCompletionOutcome::Superseded
    ));
    assert_eq!(
        store.principal("prepared").unwrap().display_name.as_deref(),
        Some("New Microsoft name")
    );
    store.unlink_oidc_login_method("prepared", "admin").unwrap();
    let reenrollment = store
        .create_microsoft_enrollment(MicrosoftEnrollmentCreateRequest {
            principal_id: "prepared".into(),
            email: "person@example.com".into(),
            provider_generation: provider.config_generation,
            actor: "admin".into(),
        })
        .unwrap();
    let rebound = enrollment_succeeded(
        store
            .complete_oidc_login(
                &hasher,
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER_TWO, 5),
            )
            .unwrap(),
        false,
    );
    assert_eq!(rebound.enrollment_id, Some(reenrollment.enrollment_id));
    assert!(rebound.auto_enrolled_group_ids.is_empty());
    assert_eq!(store.groups("prepared").unwrap(), ["existing"]);
}

#[test]
fn microsoft_enrollment_missing_email_disabled_owner_and_existing_identity_never_redirect() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    let hasher = broker_token_hasher_for_test(84);
    for (i, email) in [None, Some("not-email"), Some("different@example.com")]
        .into_iter()
        .enumerate()
    {
        let mut request =
            microsoft_first_request(provider.config_generation, TEST_OIDC_USER, i as u64 + 1);
        request.email = email.map(str::to_string);
        assert!(
            matches!(store.complete_oidc_login(&hasher, request).unwrap(), OidcCompletionOutcome::Denied { reason } if reason == "jit_disabled")
        );
    }
    store.set_principal_enabled("prepared", false).unwrap();
    let mut request = microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 4);
    request.jit_provisioning = true;
    assert!(
        matches!(store.complete_oidc_login(&hasher, request).unwrap(), OidcCompletionOutcome::Denied { reason } if reason == "login_method_disabled")
    );
    store
        .create_principal(
            microsoft_precreation_request("already-linked"),
            &test_execution_contexts(),
        )
        .unwrap();
    store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "already-linked".into(),
            user_object_id: TEST_OIDC_USER.into(),
            actor: "admin".into(),
        })
        .unwrap();
    let linked = enrollment_succeeded(
        store
            .complete_oidc_login(
                &hasher,
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 5),
            )
            .unwrap(),
        false,
    );
    assert_eq!(linked.principal.principal_id, "already-linked");
    assert!(linked.enrollment_id.is_none());
    assert_eq!(
        store.microsoft_enrollment("prepared").unwrap(),
        Some(pending.clone())
    );
    store
        .set_principal_enabled("already-linked", false)
        .unwrap();
    store.set_principal_enabled("prepared", true).unwrap();
    assert!(matches!(store.complete_oidc_login(&hasher,
        microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 6)).unwrap(), OidcCompletionOutcome::Denied { reason } if reason == "login_method_disabled"));
    assert_eq!(
        store.microsoft_enrollment("prepared").unwrap(),
        Some(pending)
    );
}

#[test]
fn microsoft_enrollment_session_failure_rolls_back_binding_name_groups_and_watermark() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    store
        .create_group(
            enrollment_group_request("initial", true),
            &test_execution_contexts(),
        )
        .unwrap();
    let before = store.principal("prepared").unwrap();
    let inventory = store.identity_token_metadata("prepared").unwrap();
    let hasher = broker_token_hasher_for_test(85);
    let request = microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 1);
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER reject_precreated_session BEFORE INSERT ON broker_tokens
         BEGIN SELECT RAISE(ABORT, 'session failed'); END;",
        )
        .unwrap();
    assert!(store.complete_oidc_login(&hasher, request.clone()).is_err());
    assert_eq!(store.principal("prepared").unwrap(), before);
    assert_eq!(
        store.identity_token_metadata("prepared").unwrap(),
        inventory
    );
    assert_eq!(
        store.microsoft_enrollment("prepared").unwrap(),
        Some(pending)
    );
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_precreated_session;")
        .unwrap();
    let bound = enrollment_succeeded(store.complete_oidc_login(&hasher, request).unwrap(), false);
    assert_eq!(bound.auto_enrolled_group_ids, ["initial"]);
    assert!(bound.display_name_updated);
}

#[test]
fn microsoft_enrollment_pending_reservation_guards_tenant_even_when_disabled() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, false, 3600, "paused");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    store.set_principal_enabled("prepared", false).unwrap();
    let change = OidcProviderStateReconcileRequest {
        tenant_id: TEST_OIDC_USER_TWO.into(),
        client_id: TEST_OIDC_CLIENT.into(),
        enabled: false,
        config_fingerprint: "different-tenant".into(),
        external_membership_ttl_seconds: 3600,
        membership_renewal: false,
        invalidate_existing_evidence: false,
        actor: "admin".into(),
    };
    assert!(matches!(
        store.reconcile_oidc_provider_state(change.clone()),
        Err(ManagedStoreError::OidcLoginMethodConflict)
    ));
    store
        .cancel_microsoft_enrollment(microsoft_cancel_request(&pending))
        .unwrap();
    assert_eq!(
        store
            .reconcile_oidc_provider_state(change)
            .unwrap()
            .tenant_id,
        TEST_OIDC_USER_TWO
    );
}

#[test]
fn microsoft_enrollment_sql_excludes_pending_and_disabled_bound_methods_in_both_directions() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    let pending = microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    store
        .create_principal(
            microsoft_precreation_request("bound"),
            &test_execution_contexts(),
        )
        .unwrap();
    store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "bound".into(),
            user_object_id: TEST_OIDC_USER.into(),
            actor: "admin".into(),
        })
        .unwrap();
    let conn = store.connection.lock().unwrap();
    conn.execute(
        "UPDATE principal_login_methods SET status = 'disabled' WHERE principal_id = 'bound'",
        [],
    )
    .unwrap();
    assert!(conn.execute("UPDATE principal_login_methods SET principal_id = 'prepared' WHERE principal_id = 'bound'", []).is_err());
    assert!(conn.execute("INSERT INTO principal_login_methods (login_method_id,principal_id,method,external_provider,external_subject,status,must_change_password,created_at,updated_at,created_by,updated_by)
        VALUES ('another','prepared','oidc','microsoft',?1,'disabled',0,?2,?2,'admin','admin')", params![test_oidc_subject(TEST_OIDC_USER_TWO), normalized_now_string()]).is_err());
    assert!(conn.execute("INSERT INTO pending_microsoft_enrollments SELECT 'another','bound',tenant_id,'bound@example.com',1,created_at,updated_at,created_by,updated_by FROM pending_microsoft_enrollments", []).is_err());
    assert!(
        conn.execute(
            "UPDATE pending_microsoft_enrollments SET tenant_id = ?1 WHERE enrollment_id = ?2",
            params![TEST_OIDC_USER_TWO, pending.enrollment_id]
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE principals SET kind = 'service_account' WHERE principal_id = 'prepared'",
            []
        )
        .is_err()
    );
}

#[test]
fn microsoft_enrollment_competing_identities_consume_exactly_once_and_same_identity_reuses_binding()
{
    for same_identity in [false, true] {
        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
        microsoft_prepare(
            &store,
            "prepared",
            "person@example.com",
            provider.config_generation,
        );
        store
            .create_group(
                enrollment_group_request("initial", true),
                &test_execution_contexts(),
            )
            .unwrap();
        let other = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Reload,
        )
        .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for (index, connection) in [store.clone(), other].into_iter().enumerate() {
            let barrier = barrier.clone();
            let object = if same_identity || index == 0 {
                TEST_OIDC_USER
            } else {
                TEST_OIDC_USER_TWO
            };
            let request =
                microsoft_first_request(provider.config_generation, object, index as u64 + 1);
            threads.push(thread::spawn(move || {
                barrier.wait();
                connection
                    .complete_oidc_login(&broker_token_hasher_for_test(86), request)
                    .unwrap()
            }));
        }
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect();
        let successful: Vec<_> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                OidcCompletionOutcome::Succeeded {
                    result,
                    jit_created,
                } => {
                    assert!(!jit_created);
                    Some(result)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            successful
                .iter()
                .filter(|result| result.enrollment_id.is_some())
                .count(),
            1
        );
        assert_eq!(
            successful
                .iter()
                .map(|result| result.auto_enrolled_group_ids.len())
                .sum::<usize>(),
            1
        );
        if !same_identity {
            assert_eq!(successful.len(), 1);
        }
        assert!(store.microsoft_enrollment("prepared").unwrap().is_none());
        assert_eq!(store.list_principals().unwrap().len(), 1);
        assert_eq!(store.group_members("initial").unwrap().len(), 1);
    }
}

#[test]
fn microsoft_enrollment_migration_preserves_existing_accounts_without_backfill() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("store.sqlite");
    let config = store_config(&path);
    let previous = ManagedStore::open_with_catalog(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        identity_test_catalog_through(MANAGED_STORE_IMPORTED_GATEWAY_ROUTES_VERSION),
    )
    .unwrap();
    previous.connection.lock().unwrap().execute_batch(
        "INSERT INTO principals(principal_id,kind,display_name,email,status,created_at,updated_at,created_by,role,self_service_enabled)
         VALUES ('existing','user','Existing','person@example.com','active','2026-01-01','2026-01-01','admin','user',1);"
    ).unwrap();
    reconcile_test_oidc_provider(&previous, true, 3600, "active");
    previous.connection.lock().unwrap().execute(
        "INSERT INTO principal_login_methods(login_method_id,principal_id,method,external_provider,external_subject,status,must_change_password,created_at,updated_at,created_by,updated_by)
         VALUES ('11111111-1111-4111-8111-111111111111','existing','oidc','microsoft',?1,'active',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','admin')",
        [test_oidc_subject(TEST_OIDC_USER)],
    ).unwrap();
    drop(previous);
    let old_ledger = migration_rows(&path);
    let store = ManagedStore::open(
        &config,
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    assert!(store.migration_applied_this_open(MANAGED_STORE_MICROSOFT_ENROLLMENTS_VERSION));
    assert_eq!(
        &migration_rows(&path)[..old_ledger.len()],
        old_ledger.as_slice()
    );
    let principal = store.principal("existing").unwrap();
    assert_eq!(principal.display_name.as_deref(), Some("Existing"));
    assert_eq!(principal.email.as_deref(), Some("person@example.com"));
    assert!(principal.microsoft_enrollment.is_none());
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    store
        .create_group(
            enrollment_group_request("initial", true),
            &test_execution_contexts(),
        )
        .unwrap();
    let login = enrollment_succeeded(
        store
            .complete_oidc_login(
                &broker_token_hasher_for_test(87),
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 1),
            )
            .unwrap(),
        false,
    );
    assert!(login.auto_enrolled_group_ids.is_empty());
    assert_eq!(login.login_method.login_method_id, "11111111-1111-4111-8111-111111111111");
    assert!(store.group_members("initial").unwrap().is_empty());
    microsoft_prepare(
        &store,
        "new",
        "person@example.com",
        provider.config_generation,
    );
    let login = enrollment_succeeded(
        store
            .complete_oidc_login(
                &broker_token_hasher_for_test(87),
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER_TWO, 2),
            )
            .unwrap(),
        false,
    );
    assert_eq!(login.auto_enrolled_group_ids, ["initial"]);
}

#[test]
fn microsoft_enrollment_zero_defaults_are_processed_and_later_settings_do_not_backfill() {
    let temp = TempDir::new().unwrap();
    let store = ManagedStore::open(
        &store_config(&temp.path().join("store.sqlite")),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
    microsoft_prepare(
        &store,
        "prepared",
        "person@example.com",
        provider.config_generation,
    );
    store
        .create_group(
            enrollment_group_request("initial", false),
            &test_execution_contexts(),
        )
        .unwrap();
    let hasher = broker_token_hasher_for_test(88);
    let first = enrollment_succeeded(
        store
            .complete_oidc_login(
                &hasher,
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 1),
            )
            .unwrap(),
        false,
    );
    assert!(first.auto_enrolled_group_ids.is_empty());
    store
        .patch_group(
            enrollment_group_patch("initial", Some(true)),
            &test_execution_contexts(),
        )
        .unwrap();
    let later = enrollment_succeeded(
        store
            .complete_oidc_login(
                &hasher,
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 2),
            )
            .unwrap(),
        false,
    );
    assert!(later.auto_enrolled_group_ids.is_empty());
    store.unlink_oidc_login_method("prepared", "admin").unwrap();
    store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "prepared".into(),
            user_object_id: TEST_OIDC_USER.into(),
            actor: "admin".into(),
        })
        .unwrap();
    let relinked = enrollment_succeeded(
        store
            .complete_oidc_login(
                &hasher,
                microsoft_first_request(provider.config_generation, TEST_OIDC_USER, 3),
            )
            .unwrap(),
        false,
    );
    assert!(relinked.auto_enrolled_group_ids.is_empty());
    assert!(store.group_members("initial").unwrap().is_empty());
}

#[test]
fn microsoft_enrollment_reload_rejects_noncanonical_rows_and_missing_constraints() {
    for corruption in [
        "UPDATE pending_microsoft_enrollments SET match_email = 'Person@example.com';",
        "UPDATE pending_microsoft_enrollments SET match_email = 'not-email';",
        "UPDATE oidc_provider_state SET tenant_id = 'dddddddd-dddd-4ddd-8ddd-ddddddddddd4';",
        "DROP TRIGGER microsoft_login_method_pending_insert;",
        "DELETE FROM principal_identity_tokens WHERE principal_id = 'prepared';",
    ] {
        let temp = TempDir::new().unwrap();
        let config = store_config(&temp.path().join("store.sqlite"));
        let store = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        let provider = reconcile_test_oidc_provider(&store, true, 3600, "active");
        microsoft_prepare(
            &store,
            "prepared",
            "person@example.com",
            provider.config_generation,
        );
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(corruption)
            .unwrap();
        drop(store);
        assert!(
            matches!(
                ManagedStore::open(
                    &config,
                    &test_execution_contexts(),
                    ManagedStoreOpenMode::Reload
                ),
                Err(ManagedStoreError::SchemaInvalid(_))
            ),
            "{corruption}"
        );
    }
}
