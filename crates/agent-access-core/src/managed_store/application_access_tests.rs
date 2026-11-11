use super::*;
use serde_json::json;
use tempfile::TempDir;

const APP: &str = "example-runner";
const REDIRECT: &str = "https://runner.example.test/auth/broker/callback";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier-0123";

fn hasher() -> BrokerTokenHasher {
    BrokerTokenHasher {
        key: Arc::new([9; 32]),
    }
}

fn config_at(path: &Path) -> ManagedStoreConfig {
    ManagedStoreConfig {
        kind: "sqlite".into(),
        path: path.display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    }
}

fn temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn store_at(path: &Path, through: Option<&str>) -> ManagedStore {
    let catalog = match through {
        Some(version) => {
            let end = MANAGED_STORE_MIGRATIONS
                .iter()
                .position(|migration| migration.version == version)
                .unwrap();
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..=end],
            }
        }
        None => production_migration_catalog(),
    };
    ManagedStore::open_with_catalog(
        &config_at(path),
        &test_execution_contexts(),
        ManagedStoreOpenMode::Startup,
        catalog,
    )
    .unwrap()
}

fn principal(store: &ManagedStore, id: &str, kind: &str) {
    store
        .create_principal(
            PrincipalWriteRequest {
                principal_id: id.into(),
                kind: kind.into(),
                display_name: (id == "alice").then(|| "Alex Example".into()),
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

fn fixture() -> (TempDir, ManagedStore) {
    let temp = temp();
    let store = store_at(&temp.path().join("store.sqlite"), None);
    principal(&store, "alice", "user");
    principal(&store, "bob", "user");
    (temp, store)
}

fn terms(read_only: bool) -> ApplicationAccessTerms {
    ApplicationAccessTerms {
        application_id: APP.into(),
        read_only,
        allowed_execution_contexts: vec!["default".into()],
        allowed_services: Some(vec!["jira".into()]),
        access_token_ttl_seconds: 8 * 60 * 60,
        refresh_idle_ttl_seconds: 90 * 24 * 60 * 60,
    }
}

fn parameters() -> ApplicationAuthorizationParameters {
    ApplicationAuthorizationParameters {
        redirect_uri: REDIRECT.into(),
        state: "client-state".into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
    }
}

fn request(store: &ManagedStore) -> String {
    store
        .create_application_authorization_request(&hasher(), APP, &parameters())
        .unwrap()
}

fn approve(store: &ManagedStore, who: &str) -> ApplicationAuthorizationDecision {
    store
        .decide_application_authorization(
            &hasher(),
            &request(store),
            who,
            Some(&terms(false)),
            true,
        )
        .unwrap()
}

fn code_grant(code: &str) -> ApplicationGrant<'_> {
    ApplicationGrant::AuthorizationCode {
        code,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
    }
}

fn mint(
    store: &ManagedStore,
    terms: Option<&ApplicationAccessTerms>,
    grant: ApplicationGrant<'_>,
) -> Result<ApplicationTokenMint, ApplicationGrantRefused> {
    store
        .mint_application_token(&hasher(), APP, terms, grant)
        .unwrap()
}

/// Connects `who` and returns the first mint, which carries the refresh token.
fn connect(store: &ManagedStore, who: &str) -> ApplicationTokenMint {
    let decision = approve(store, who);
    mint(
        store,
        Some(&terms(false)),
        code_grant(decision.code.as_deref().unwrap()),
    )
    .unwrap()
}

fn refresh(
    store: &ManagedStore,
    terms: Option<&ApplicationAccessTerms>,
    refresh_token: &str,
) -> Result<ApplicationTokenMint, ApplicationGrantRefused> {
    mint(
        store,
        terms,
        ApplicationGrant::RefreshToken { refresh_token },
    )
}

fn refusal(
    result: Result<ApplicationTokenMint, ApplicationGrantRefused>,
) -> ApplicationGrantRefusal {
    result.unwrap_err().refusal
}

fn sql(store: &ManagedStore, statement: &str) {
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(statement)
        .unwrap();
}

fn resolves(store: &ManagedStore, token: &str) -> Result<BrokerTokenIdentity, ManagedStoreError> {
    store.resolve_broker_token(&hasher(), token)
}

#[test]
fn code_exchange_and_refresh_mint_independent_agent_tokens_hidden_from_token_lists() {
    let (_temp, store) = fixture();
    let request_id = request(&store);
    let pending = store
        .application_authorization_request(&hasher(), &request_id)
        .unwrap();
    assert_eq!(pending.application_id, APP);
    assert_eq!(pending.parameters, parameters());
    assert_eq!(
        store
            .application_connect_denial("alice", APP, true)
            .unwrap(),
        None
    );
    let decision = store
        .decide_application_authorization(
            &hasher(),
            &request_id,
            "alice",
            Some(&terms(false)),
            true,
        )
        .unwrap();
    let code = decision.code.clone().unwrap();
    assert!(code.starts_with("aac_") && !code.starts_with("aab_"));
    let access = decision.access.clone().unwrap();
    assert!(access.enabled && !access.read_only && !access.connected);
    assert_eq!((access.version, access.live_token_count), (1, 0));
    // The request is one use.
    assert!(matches!(
        store.application_authorization_request(&hasher(), &request_id),
        Err(ManagedStoreError::ApplicationAuthorizationInvalid)
    ));

    let first = mint(&store, Some(&terms(false)), code_grant(&code)).unwrap();
    let refresh_token = first.refresh_token.clone().unwrap();
    assert!(refresh_token.starts_with("aar_"));
    assert!(first.token.starts_with("aab_ai_"));
    assert_eq!(first.principal_name, "Alex Example");
    assert_eq!(first.expires_in_seconds, 8 * 60 * 60);
    assert!(!first.read_only && first.access.connected);
    assert_eq!(first.record.token_class, BrokerTokenClass::AgentInvoke);
    assert_eq!(first.record.principal_id, "alice");
    assert_eq!(
        first.record.scopes,
        json!({"readOnly": false, "allowedExecutionContexts": ["default"], "allowedServices": ["jira"]})
    );
    let identity = resolves(&store, &first.token).unwrap();
    assert_eq!(identity.principal_id, "alice");
    assert_eq!(identity.token_class, BrokerTokenClass::AgentInvoke);

    let second = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    assert!(
        second.refresh_token.is_none(),
        "the refresh token does not rotate"
    );
    assert_ne!(second.token, first.token);
    assert!(resolves(&store, &first.token).is_ok());
    assert!(resolves(&store, &second.token).is_ok());
    assert_eq!(second.access.live_token_count, 2);
    assert!(second.access.last_used_at.is_some());

    // Neither a code nor a refresh token is a caller token.
    for secret in [code.as_str(), refresh_token.as_str()] {
        assert!(matches!(
            resolves(&store, secret),
            Err(ManagedStoreError::BrokerTokenNotFound)
        ));
    }
    // The tokens stay out of every individual token list.
    assert!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_broker_tokens_for_principal("alice")
            .unwrap()
            .is_empty()
    );
    assert!(store.list_broker_tokens().unwrap().is_empty());
    let listed = store.list_application_access("alice").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].live_token_count, 2);
    assert!(store.list_application_access("bob").unwrap().is_empty());
}

#[test]
fn a_code_is_consumed_by_its_first_presentation_whatever_the_outcome() {
    let (_temp, store) = fixture();
    for (redirect_uri, code_verifier, application) in [
        (
            REDIRECT,
            "wrong-verifier-wrong-verifier-wrong-verifier-01",
            APP,
        ),
        ("https://runner.example.test/other", VERIFIER, APP),
        (REDIRECT, VERIFIER, "another-application"),
    ] {
        let decision = approve(&store, "alice");
        let code = decision.code.unwrap();
        let wrong = store
            .mint_application_token(
                &hasher(),
                application,
                Some(&ApplicationAccessTerms {
                    application_id: application.into(),
                    ..terms(false)
                }),
                ApplicationGrant::AuthorizationCode {
                    code: &code,
                    redirect_uri,
                    code_verifier,
                },
            )
            .unwrap();
        assert_eq!(refusal(wrong), ApplicationGrantRefusal::GrantInvalid);
        // The correct presentation no longer works either.
        assert_eq!(
            refusal(mint(&store, Some(&terms(false)), code_grant(&code))),
            ApplicationGrantRefusal::GrantInvalid
        );
    }
    let decision = approve(&store, "alice");
    let code = decision.code.unwrap();
    assert!(mint(&store, Some(&terms(false)), code_grant(&code)).is_ok());
    assert_eq!(
        refusal(mint(&store, Some(&terms(false)), code_grant(&code))),
        ApplicationGrantRefusal::GrantInvalid,
        "a replayed code mints nothing"
    );
    for malformed in ["", "aac_short", "aab_ai_notacode", &"x".repeat(47)] {
        assert_eq!(
            refusal(mint(&store, Some(&terms(false)), code_grant(malformed))),
            ApplicationGrantRefusal::GrantInvalid
        );
    }
}

#[test]
fn expired_requests_and_codes_are_refused() {
    let (_temp, store) = fixture();
    let request_id = request(&store);
    sql(
        &store,
        "UPDATE application_authorization_requests SET created_at = '2000-01-01T00:00:00Z',
         expires_at = '2000-01-01T00:10:00Z'",
    );
    assert!(matches!(
        store.application_authorization_request(&hasher(), &request_id),
        Err(ManagedStoreError::ApplicationAuthorizationInvalid)
    ));
    assert!(matches!(
        store.decide_application_authorization(
            &hasher(),
            &request_id,
            "alice",
            Some(&terms(false)),
            true
        ),
        Err(ManagedStoreError::ApplicationAuthorizationInvalid)
    ));
    assert!(matches!(
        store.application_authorization_request(&hasher(), "not-a-request"),
        Err(ManagedStoreError::ApplicationAuthorizationInvalid)
    ));

    let code = approve(&store, "alice").code.unwrap();
    sql(
        &store,
        "UPDATE application_authorization_codes SET created_at = '2000-01-01T00:00:00Z',
         expires_at = '2000-01-01T00:01:00Z'",
    );
    assert_eq!(
        refusal(mint(&store, Some(&terms(false)), code_grant(&code))),
        ApplicationGrantRefusal::GrantInvalid
    );
}

#[test]
fn a_person_who_may_not_connect_is_refused_and_can_still_return() {
    let (_temp, store) = fixture();
    principal(&store, "robot", "service_account");
    let request_id = request(&store);
    // Level `none`: there are no terms.
    assert_eq!(
        store
            .application_connect_denial("alice", APP, false)
            .unwrap(),
        Some(ApplicationConnectDenial::ConnectingDisabled)
    );
    assert!(matches!(
        store.decide_application_authorization(&hasher(), &request_id, "alice", None, true),
        Err(ManagedStoreError::ApplicationAccessDenied(
            ApplicationConnectDenial::ConnectingDisabled
        ))
    ));
    assert!(matches!(
        store.decide_application_authorization(
            &hasher(),
            &request_id,
            "robot",
            Some(&terms(false)),
            true
        ),
        Err(ManagedStoreError::ApplicationAccessDenied(
            ApplicationConnectDenial::NotHuman
        ))
    ));
    // Another application's terms never connect this request.
    let other = ApplicationAccessTerms {
        application_id: "another-application".into(),
        ..terms(false)
    };
    assert!(matches!(
        store.decide_application_authorization(&hasher(), &request_id, "alice", Some(&other), true),
        Err(ManagedStoreError::ApplicationAccessDenied(_))
    ));
    assert!(store.list_application_access("alice").unwrap().is_empty());
    // A refused approval leaves the request for the return to the application.
    let cancelled = store
        .decide_application_authorization(&hasher(), &request_id, "alice", None, false)
        .unwrap();
    assert!(cancelled.code.is_none() && cancelled.access.is_none());
    assert_eq!(cancelled.parameters, parameters());
    assert!(matches!(
        store.decide_application_authorization(&hasher(), &request_id, "alice", None, false),
        Err(ManagedStoreError::ApplicationAuthorizationInvalid)
    ));

    // An access an administrator disabled cannot be reconnected.
    let minted = connect(&store, "alice");
    store
        .update_application_access(
            "alice",
            &minted.access.access_id,
            ApplicationAccessUpdate {
                enabled: Some(false),
                read_only: None,
            },
            1,
            "admin",
        )
        .unwrap();
    assert_eq!(
        store
            .application_connect_denial("alice", APP, true)
            .unwrap(),
        Some(ApplicationConnectDenial::AccessDisabled)
    );
    assert!(matches!(
        store.decide_application_authorization(
            &hasher(),
            &request(&store),
            "alice",
            Some(&terms(false)),
            true
        ),
        Err(ManagedStoreError::ApplicationAccessDenied(
            ApplicationConnectDenial::AccessDisabled
        ))
    ));
}

#[test]
fn settings_changes_advance_the_version_once_and_end_live_tokens() {
    let (_temp, store) = fixture();
    let minted = connect(&store, "alice");
    let refresh_token = minted.refresh_token.clone().unwrap();
    let access_id = minted.access.access_id.clone();
    let update = |enabled, read_only, version| {
        store.update_application_access(
            "alice",
            &access_id,
            ApplicationAccessUpdate { enabled, read_only },
            version,
            "admin",
        )
    };
    // A no-op writes nothing and ends nothing.
    let (before, after) = update(Some(true), Some(false), 1).unwrap();
    assert_eq!(before, after);
    assert!(resolves(&store, &minted.token).is_ok());
    assert!(matches!(
        update(Some(false), None, 2),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        store.update_application_access(
            "bob",
            &access_id,
            ApplicationAccessUpdate {
                enabled: Some(false),
                read_only: None
            },
            1,
            "admin"
        ),
        Err(ManagedStoreError::ApplicationAccessNotFound)
    ));

    // Read-only: the live token ends, and the next one carries the ceiling
    // although the application's level is read and write.
    let (_, after) = update(None, Some(true), 1).unwrap();
    assert_eq!(
        (after.version, after.read_only, after.live_token_count),
        (2, true, 0)
    );
    assert_eq!(after.updated_by, "admin");
    assert!(matches!(
        resolves(&store, &minted.token),
        Err(ManagedStoreError::BrokerTokenRevoked)
    ));
    let narrowed = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    assert!(narrowed.read_only);
    assert_eq!(narrowed.record.scopes["readOnly"], true);

    // Disabled: the token ends and the same refresh token mints nothing
    // until an administrator enables the access again.
    let (_, after) = update(Some(false), None, 2).unwrap();
    assert_eq!((after.version, after.enabled), (3, false));
    assert!(resolves(&store, &narrowed.token).is_err());
    assert_eq!(
        refusal(refresh(&store, Some(&terms(false)), &refresh_token)),
        ApplicationGrantRefusal::AccessDisabled
    );
    update(Some(true), Some(false), 3).unwrap();
    let restored = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    assert!(!restored.read_only);
    // The application's own level also narrows.
    assert!(
        refresh(&store, Some(&terms(true)), &refresh_token)
            .unwrap()
            .read_only
    );
}

#[test]
fn removal_reconnect_and_revocation_end_the_access_tokens() {
    let (_temp, store) = fixture();
    let first = connect(&store, "alice");
    let old_refresh = first.refresh_token.clone().unwrap();

    // Connecting again keeps the access and its settings, ends its tokens
    // and replaces the refresh token.
    let decision = approve(&store, "alice");
    assert_eq!(decision.revoked_tokens, 1);
    assert_eq!(
        decision.access.as_ref().unwrap().access_id,
        first.access.access_id
    );
    assert!(resolves(&store, &first.token).is_err());
    assert_eq!(
        refusal(refresh(&store, Some(&terms(false)), &old_refresh)),
        ApplicationGrantRefusal::GrantInvalid
    );
    let second = mint(
        &store,
        Some(&terms(false)),
        code_grant(decision.code.as_deref().unwrap()),
    )
    .unwrap();
    let refresh_token = second.refresh_token.clone().unwrap();

    // Another application cannot revoke these.
    for token in [second.token.as_str(), refresh_token.as_str()] {
        assert_eq!(
            store
                .revoke_application_token(&hasher(), "another-application", token)
                .unwrap(),
            ApplicationRevocation::Unknown
        );
    }
    assert_eq!(
        store
            .revoke_application_token(&hasher(), APP, "unknown-token")
            .unwrap(),
        ApplicationRevocation::Unknown
    );
    // An access token: only that token ends.
    let third = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    assert!(matches!(
        store
            .revoke_application_token(&hasher(), APP, &second.token)
            .unwrap(),
        ApplicationRevocation::AccessToken { .. }
    ));
    assert!(matches!(
        resolves(&store, &second.token),
        Err(ManagedStoreError::BrokerTokenRevoked)
    ));
    assert!(resolves(&store, &third.token).is_ok());
    // The refresh token: the access goes with every live token.
    let ApplicationRevocation::Access { revoked_tokens, .. } = store
        .revoke_application_token(&hasher(), APP, &refresh_token)
        .unwrap()
    else {
        panic!("the refresh token names the access");
    };
    assert_eq!(revoked_tokens, 1);
    assert!(resolves(&store, &third.token).is_err());
    assert!(store.list_application_access("alice").unwrap().is_empty());
    assert_eq!(
        refusal(refresh(&store, Some(&terms(false)), &refresh_token)),
        ApplicationGrantRefusal::GrantInvalid
    );
    // Ended tokens of a removed access stay out of token lists.
    assert!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .is_empty()
    );

    // Removal by the person or a version-checked administrator.
    let again = connect(&store, "alice");
    assert!(matches!(
        store.remove_application_access("alice", &again.access.access_id, Some(7), "admin"),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        store.remove_application_access("bob", &again.access.access_id, None, "bob"),
        Err(ManagedStoreError::ApplicationAccessNotFound)
    ));
    store
        .remove_application_access("alice", &again.access.access_id, None, "alice")
        .unwrap();
    assert!(resolves(&store, &again.token).is_err());
    assert!(store.list_application_access("alice").unwrap().is_empty());
}

#[test]
fn mint_rechecks_the_application_the_person_idleness_and_the_live_bound() {
    let (_temp, store) = fixture();
    let minted = connect(&store, "alice");
    let refresh_token = minted.refresh_token.clone().unwrap();
    // The application was removed, or its level became `none`.
    assert_eq!(
        refusal(refresh(&store, None, &refresh_token)),
        ApplicationGrantRefusal::ApplicationUnavailable
    );
    // The same refresh token works again once the application returns.
    assert!(refresh(&store, Some(&terms(false)), &refresh_token).is_ok());

    // Disabling the person ends the tokens at once; re-enabling does not
    // restore them, and the refresh token works again.
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".into(),
            display_name: None,
            email: None,
            status: Some("disabled".into()),
        })
        .unwrap();
    assert_eq!(
        refusal(refresh(&store, Some(&terms(false)), &refresh_token)),
        ApplicationGrantRefusal::PrincipalUnavailable
    );
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".into(),
            display_name: None,
            email: None,
            status: Some("active".into()),
        })
        .unwrap();
    assert!(matches!(
        resolves(&store, &minted.token),
        Err(ManagedStoreError::BrokerTokenRevoked)
    ));
    assert_eq!(
        store.list_application_access("alice").unwrap()[0].live_token_count,
        0
    );
    assert!(refresh(&store, Some(&terms(false)), &refresh_token).is_ok());

    // Idle expiry counts from the last use.
    sql(
        &store,
        "UPDATE application_access SET last_used_at = '2000-01-01T00:00:00Z'",
    );
    assert_eq!(
        refusal(refresh(&store, Some(&terms(false)), &refresh_token)),
        ApplicationGrantRefusal::RefreshTokenIdle
    );
    sql(&store, "UPDATE application_access SET last_used_at = NULL");
    assert!(refresh(&store, Some(&terms(false)), &refresh_token).is_ok());

    // The live-token bound.
    let live = store.list_application_access("alice").unwrap()[0].live_token_count;
    for _ in live..APPLICATION_ACCESS_MAX_LIVE_TOKENS {
        assert!(refresh(&store, Some(&terms(false)), &refresh_token).is_ok());
    }
    let limited = refresh(&store, Some(&terms(false)), &refresh_token).unwrap_err();
    assert_eq!(limited.refusal, ApplicationGrantRefusal::TokenLimit);
    assert_eq!(limited.principal_id.as_deref(), Some("alice"));
}

#[test]
fn ended_tokens_are_deleted_after_the_retention_time() {
    let (_temp, store) = fixture();
    let minted = connect(&store, "alice");
    let refresh_token = minted.refresh_token.clone().unwrap();
    let kept = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    let recent = refresh(&store, Some(&terms(false)), &refresh_token).unwrap();
    let count = |store: &ManagedStore| -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(1) FROM broker_tokens WHERE application_access_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    sql(
        &store,
        &format!(
            "UPDATE broker_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE token_id = '{}';
             UPDATE broker_tokens SET revoked_at = '2000-01-01T00:00:00+00:00', revoked_by = 'alice'
               WHERE token_id = '{}';
             UPDATE broker_tokens SET revoked_at = '{}', revoked_by = 'alice' WHERE token_id = '{}';",
            minted.record.token_id,
            kept.record.token_id,
            now_string(),
            recent.record.token_id
        ),
    );
    assert_eq!(count(&store), 3);
    // The next token request runs retention; a recently ended token stays.
    assert!(refresh(&store, Some(&terms(false)), &refresh_token).is_ok());
    assert_eq!(count(&store), 2);
    assert!(store.broker_token(&recent.record.token_id).is_ok());
    assert!(matches!(
        store.broker_token(&minted.record.token_id),
        Err(ManagedStoreError::BrokerTokenNotFound)
    ));
}

#[test]
fn the_principal_name_is_never_empty_and_is_bounded() {
    assert_eq!(
        application_principal_name(Some(" Alex Example "), "alice"),
        "Alex Example"
    );
    for absent in [None, Some(""), Some("   ")] {
        assert_eq!(application_principal_name(absent, "alice"), "alice");
    }
    let long = "é".repeat(300);
    assert_eq!(
        application_principal_name(Some(&long), "alice")
            .chars()
            .count(),
        256
    );
    // A person without a display name is named by their principal ID.
    let (_temp, store) = fixture();
    let minted = connect(&store, "bob");
    assert_eq!(minted.principal_name, "bob");
    let refreshed = refresh(
        &store,
        Some(&terms(false)),
        minted.refresh_token.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(refreshed.principal_name, "bob");
}

#[test]
fn pending_requests_are_bounded() {
    let (_temp, store) = fixture();
    request(&store);
    {
        let conn = store.connection.lock().unwrap();
        for index in 1..APPLICATION_AUTHORIZATION_MAX_PENDING {
            let mut hash = [0_u8; 32];
            hash[..8].copy_from_slice(&index.to_be_bytes());
            conn.execute(
                "INSERT INTO application_authorization_requests
                 (request_hash, application_id, encrypted_payload, encryption_nonce, created_at,
                  expires_at) VALUES (?1, 'example-runner', x'00', x'000000000000000000000000',
                  '2000-01-01T00:00:00Z', '2999-01-01T00:00:00Z')",
                params![hash.as_slice()],
            )
            .unwrap();
        }
    }
    assert!(matches!(
        store.create_application_authorization_request(&hasher(), APP, &parameters()),
        Err(ManagedStoreError::ApplicationAuthorizationCapacity)
    ));
    // Expired requests make room.
    sql(
        &store,
        "UPDATE application_authorization_requests SET created_at = '2000-01-01T00:00:00Z',
         expires_at = '2000-01-01T00:10:00Z' WHERE encrypted_payload = x'00'",
    );
    request(&store);
}

#[test]
fn secrets_stay_out_of_debug_output_and_the_database() {
    let (temp, store) = fixture();
    let request_id = request(&store);
    let pending = store
        .application_authorization_request(&hasher(), &request_id)
        .unwrap();
    let decision = store
        .decide_application_authorization(
            &hasher(),
            &request_id,
            "alice",
            Some(&terms(false)),
            true,
        )
        .unwrap();
    let code = decision.code.clone().unwrap();
    let minted = mint(&store, Some(&terms(false)), code_grant(&code)).unwrap();
    let refresh_token = minted.refresh_token.clone().unwrap();
    let debug = format!(
        "{pending:?} {decision:?} {minted:?} {:?}",
        pending.parameters
    );
    for secret in [
        request_id.as_str(),
        code.as_str(),
        refresh_token.as_str(),
        minted.token.as_str(),
        "client-state",
        &parameters().code_challenge,
    ] {
        assert!(!debug.contains(secret), "{debug}");
    }
    drop(store);
    let mut stored = fs::read(temp.path().join("store.sqlite")).unwrap();
    if let Ok(bytes) = fs::read(temp.path().join("store.sqlite-wal")) {
        stored.extend(bytes);
    }
    let contains = |needle: &str| stored.windows(needle.len()).any(|w| w == needle.as_bytes());
    for secret in [
        request_id.as_str(),
        code.as_str(),
        refresh_token.as_str(),
        minted.token.as_str(),
        "client-state",
    ] {
        assert!(!contains(secret), "a raw secret reached the database");
    }
}

#[test]
fn migration_037_adds_application_access_and_preserves_existing_tokens() {
    let temp = temp();
    let path = temp.path().join("store.sqlite");
    let old = store_at(&path, Some(MANAGED_STORE_MICROSOFT_ENROLLMENTS_VERSION));
    principal(&old, "alice", "user");
    let issued = old
        .issue_broker_token(
            &hasher(),
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "existing".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"readOnly": true, "allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    drop(old);
    let store = store_at(&path, None);
    assert_eq!(
        store.schema_version,
        MANAGED_STORE_APPLICATION_ACCESS_VERSION
    );
    assert_eq!(MANAGED_STORE_SCHEMA_VERSION, "037_application_access");
    let kept = store.broker_token(&issued.record.token_id).unwrap();
    assert_eq!(kept, issued.record);
    assert!(resolves(&store, &issued.token).is_ok());
    assert_eq!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .len(),
        1
    );
    let minted = connect(&store, "alice");
    assert!(resolves(&store, &minted.token).is_ok());
    {
        let conn = store.connection.lock().unwrap();
        validate_structure(&conn).unwrap();
        // Only humans hold application access.
        principal_insert_robot(&conn);
        assert!(
            conn.execute(
                "INSERT INTO application_access (access_id, principal_id, application_id, enabled,
                 read_only, version, created_at, connected_at, updated_at, updated_by)
                 VALUES ('00000000-0000-4000-8000-000000000001', 'robot', 'example-runner', 1, 0, 1,
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'admin')",
                [],
            )
            .is_err()
        );
        assert!(
            conn.execute("UPDATE application_access SET application_id = 'other'", [])
                .is_err()
        );
    }
    // Deleting the person removes the access, its codes and its tokens.
    sql(
        &store,
        "DELETE FROM principals WHERE principal_id = 'alice'",
    );
    let conn = store.connection.lock().unwrap();
    for table in [
        "application_access",
        "application_authorization_codes",
        "broker_tokens",
    ] {
        assert_eq!(count_table(&conn, table).unwrap(), 0, "{table}");
    }
    validate_structure(&conn).unwrap();
}

fn principal_insert_robot(conn: &Connection) {
    conn.execute(
        "INSERT INTO principals (principal_id, kind, status, created_at, updated_at, created_by,
         role, self_service_enabled, agent_token_issuance)
         VALUES ('robot', 'service_account', 'active', '2026-01-01T00:00:00Z',
         '2026-01-01T00:00:00Z', 'admin', 'user', 0, 'disabled')",
        [],
    )
    .unwrap();
}
