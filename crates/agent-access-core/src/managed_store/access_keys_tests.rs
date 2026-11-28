use super::*;
use crate::AccessKeyType;
use serde_json::json;
use tempfile::TempDir;

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

fn hasher() -> BrokerTokenHasher {
    test_token_hasher()
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

fn policy() -> AccountUsernamePolicy {
    AccountUsernamePolicy::for_test(&["example.com"], &[], &[])
}

fn access_key_type(id: &str, max: u64) -> AccessKeyType {
    AccessKeyType {
        id: id.into(),
        display_name: id.into(),
        description: None,
        lifetime_options: [60, HOUR, DAY, 7 * DAY, max]
            .into_iter()
            .filter(|value| *value <= max)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|value| format!("{value}s"))
            .collect(),
        default_lifetime: format!("{max}s"),
        self_service: true,
    }
}

/// `inference` (7 days) and `packages` (1 day) are open to self-service and
/// every account of the fixture may hold them; `research` is held through
/// the `research` group, which allows it; `batch` is not self-service.
fn access_key_types() -> AccessKeyTypes {
    AccessKeyTypes::for_test([
        access_key_type("inference", 7 * DAY),
        access_key_type("packages", DAY),
        access_key_type("research", 7 * DAY),
        AccessKeyType {
            self_service: false,
            ..access_key_type("batch", 30 * DAY)
        },
    ])
}

/// What the fixture's accounts may hold by their own setting.
const ACCOUNT_ACCESS_KEY_TYPES: [&str; 3] = ["inference", "packages", "batch"];

fn principal(store: &ManagedStore, id: &str, kind: &str, email: Option<&str>) {
    store
        .create_principal(
            PrincipalWriteRequest {
                principal_id: id.into(),
                kind: kind.into(),
                display_name: None,
                email: email.map(str::to_string),
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
    // A group named after an access key type allows it to its members.
    if access_key_types().get(id).is_some() {
        store.set_group_access_key_types_for_test(id, &[id], &access_key_types());
    }
}

/// Alice (named `alice`) and Bob (named `bob`), and the service account
/// `robot`. Each may hold `inference`, `packages` and `batch` by its own
/// setting.
fn fixture() -> (TempDir, ManagedStore) {
    let temp = temp();
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
    store.configure_account_usernames(policy());
    principal(&store, "usr-alice", "user", Some("alice@example.com"));
    principal(&store, "usr-bob", "user", Some("bob@example.com"));
    principal(&store, "robot", "service_account", None);
    for id in ["usr-alice", "usr-bob", "robot"] {
        store.set_principal_access_key_types_for_test(
            id,
            &ACCOUNT_ACCESS_KEY_TYPES,
            &[],
            &access_key_types(),
        );
    }
    (temp, store)
}

/// Signs `id` in with a local password and returns the session's token ID.
fn session(store: &ManagedStore, id: &str) -> String {
    let passwords = LocalPasswordHasher {
        verification_hook: None,
        key: Arc::new([23; 32]),
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
            &hasher(),
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
        .session
        .record
        .token_id
}

fn portal_request(
    principal: &str,
    session: &str,
    access_key_types: &[&str],
    lifetime_seconds: u64,
) -> PortalAccessKeyRequest {
    PortalAccessKeyRequest {
        principal_id: principal.into(),
        session_token_id: session.into(),
        name: "laptop".into(),
        access_key_types: access_key_types.iter().map(|id| (*id).into()).collect(),
        lifetime: format!("{lifetime_seconds}s"),
    }
}

fn mint_portal(
    store: &ManagedStore,
    principal: &str,
    session: &str,
    access_key_types_requested: &[&str],
    lifetime_seconds: u64,
) -> Result<IssuedAccessKey, AccessKeyRefused> {
    store
        .mint_portal_access_key(
            &hasher(),
            &access_key_types(),
            &portal_request(
                principal,
                session,
                access_key_types_requested,
                lifetime_seconds,
            ),
        )
        .unwrap()
}

fn admin_request(
    principal: &str,
    access_key_types: &[&str],
    lifetime_seconds: u64,
) -> AdministratorAccessKeyRequest {
    AdministratorAccessKeyRequest {
        principal_id: principal.into(),
        name: "nightly job".into(),
        access_key_types: access_key_types.iter().map(|id| (*id).into()).collect(),
        lifetime: format!("{lifetime_seconds}s"),
        created_by: "admin".into(),
    }
}

fn mint_admin(
    store: &ManagedStore,
    principal: &str,
    access_key_types_requested: &[&str],
    lifetime_seconds: u64,
) -> Result<IssuedAccessKey, AccessKeyRefused> {
    store
        .mint_administrator_access_key(
            &hasher(),
            &access_key_types(),
            &admin_request(principal, access_key_types_requested, lifetime_seconds),
        )
        .unwrap()
}

fn refusal(outcome: Result<IssuedAccessKey, AccessKeyRefused>) -> AccessKeyRefusal {
    outcome.unwrap_err().refusal
}

/// The listed tokens of one principal, or of everyone.
fn views_of(
    store: &ManagedStore,
    principal: Option<&str>,
    include_revoked: bool,
    include_expired: bool,
) -> Vec<AccessKeyView> {
    store
        .list_access_key_views(
            &access_key_types(),
            &AccessKeyListFilter {
                principal_id: principal.map(str::to_string),
                include_revoked,
                include_expired,
            },
        )
        .unwrap()
}

fn resolve_at(
    store: &ManagedStore,
    access_key_types: &AccessKeyTypes,
    token: &str,
    now: DateTime<Utc>,
) -> AccessKeyResolution {
    store
        .resolve_access_key_at(&hasher(), access_key_types, token, now)
        .unwrap()
}

fn active(resolution: AccessKeyResolution) -> AccessKeyFacts {
    match resolution {
        AccessKeyResolution::Active(facts) => *facts,
        AccessKeyResolution::Inactive(inactive) => panic!("inactive: {:?}", inactive.reason),
    }
}

fn reason(resolution: AccessKeyResolution) -> AccessKeyInactiveReason {
    match resolution {
        AccessKeyResolution::Inactive(inactive) => inactive.reason,
        AccessKeyResolution::Active(facts) => panic!("active: {}", facts.key_id),
    }
}

fn time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

/// The fields of the log events emitted while it is the thread's subscriber.
#[derive(Clone, Default)]
struct LoggedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LoggedEvents {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_string(), value.to_string());
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

fn sql(store: &ManagedStore, statement: &str) {
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(statement)
        .unwrap();
}

#[test]
fn token_has_the_access_key_shape_and_only_its_keyed_hash_is_stored() {
    let (_temp, store) = fixture();
    let session = session(&store, "usr-alice");
    let issued = mint_portal(
        &store,
        "usr-alice",
        &session,
        &["packages", "inference"],
        HOUR,
    )
    .unwrap();
    let secret = issued.key.strip_prefix("aab_ak_").unwrap();
    assert_eq!(issued.key.len(), 50);
    assert_eq!(URL_SAFE_NO_PAD.decode(secret).unwrap().len(), 32);
    assert!(is_access_key(&issued.key));
    assert!(!format!("{issued:?}").contains(secret));

    let record = &issued.record;
    let id = record.key_id.strip_prefix("ak_").unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(record.principal_id, "usr-alice");
    assert_eq!(record.name, "laptop");
    assert_eq!(record.origin, AccessKeyOrigin::Portal);
    assert_eq!(record.access_key_types, ["packages", "inference"]);
    assert_eq!(record.created_by, "usr-alice");
    assert_eq!(
        time(record.expires_at.as_deref().unwrap()) - time(&record.created_at),
        Duration::hours(1)
    );
    assert_eq!((&record.revoked_at, &record.last_used_at), (&None, &None));
    assert_eq!(
        record.username_incarnation,
        store
            .principal_account_username("usr-alice")
            .unwrap()
            .name
            .unwrap()
            .incarnation
    );
    assert!(!record.audit_details().to_string().contains(secret));

    let conn = store.connection.lock().unwrap();
    let stored: String = conn
        .query_row(
            "SELECT key_hash FROM access_keys WHERE key_id = ?1",
            [&record.key_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, hasher().hash(&issued.key).unwrap());
    let dump: String = conn
        .query_row(
            "SELECT group_concat(key_id || key_hash || name || created_by, '|') FROM access_keys",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!dump.contains(secret));
    // Nothing reaches the Broker token table.
    let broker_rows: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM broker_tokens WHERE token_hash = ?1 OR token_class NOT IN ('user_manage')",
            [&stored],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(broker_rows, 0);
    drop(conn);

    // The shared grammar: the prefix and 43 characters of [A-Za-z0-9_-].
    assert!(is_access_key(
        "aab_ak_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v"
    ));
    for malformed in [
        "aab_ak_short",
        "aab_ai_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
        "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        " aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "",
    ] {
        assert!(!is_access_key(malformed), "{malformed}");
        assert_eq!(
            reason(resolve_at(
                &store,
                &access_key_types(),
                malformed,
                Utc::now()
            )),
            AccessKeyInactiveReason::Malformed
        );
    }
}

#[test]
fn portal_mint_requires_a_live_session_a_usable_name_and_eligible_self_service_access_key_types() {
    let (_temp, store) = fixture();
    group(&store, "research", &["usr-bob"]);
    principal(&store, "usr-carol", "user", None);
    let alice = session(&store, "usr-alice");
    let bob = session(&store, "usr-bob");
    let carol = session(&store, "usr-carol");

    // The session must be the person's own and still live.
    assert_eq!(
        refusal(mint_portal(&store, "usr-alice", &bob, &["inference"], HOUR)),
        AccessKeyRefusal::SessionRequired
    );
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &Uuid::new_v4().to_string(),
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::SessionRequired
    );
    // An issued agent token of the person is not a browser session.
    let agent = store
        .issue_broker_token(
            &hasher(),
            BrokerTokenIssueRequest {
                principal_id: "usr-alice".into(),
                name: "agent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"readOnly": true, "allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &agent.record.token_id,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::SessionRequired
    );
    let ended = session(&store, "usr-alice");
    store.revoke_browser_session(&ended, "usr-alice").unwrap();
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &ended,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::SessionRequired
    );

    // No name, no token.
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-carol",
            &carol,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::NoAccountUsername
    );
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&[], &[], &["alice"]));
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::AccountUsernameAwaitingConfirmation
    );
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&[], &["alice"], &[]));
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::AccountUsernameReserved
    );
    store.configure_account_usernames(policy());

    // Every requested access key type must be one the person may hold and
    // self-service; nothing is trimmed. A type that is not configured is
    // refused like one the person may not hold.
    for (who, session, requested, expected, named) in [
        (
            "usr-alice",
            &alice,
            vec!["inference", "missing"],
            AccessKeyRefusal::AccessKeyTypeNotEligible,
            "missing",
        ),
        (
            "usr-alice",
            &alice,
            vec!["batch"],
            AccessKeyRefusal::AccessKeyTypeNotSelfService,
            "batch",
        ),
        (
            "usr-alice",
            &alice,
            vec!["inference", "research"],
            AccessKeyRefusal::AccessKeyTypeNotEligible,
            "research",
        ),
    ] {
        let refused = mint_portal(&store, who, session, &requested, HOUR).unwrap_err();
        assert_eq!(refused.refusal, expected);
        assert_eq!(refused.access_key_type.as_deref(), Some(named));
        assert_eq!(
            refused.audit_details(),
            json!({"refusal": expected.as_str(), "accessKeyType": named})
        );
    }
    assert_eq!(
        mint_portal(&store, "usr-bob", &bob, &["research"], HOUR)
            .unwrap()
            .record
            .access_key_types,
        ["research"]
    );

    // An unoffered lifetime is refused by the first type that lacks it.
    let too_long = mint_portal(
        &store,
        "usr-alice",
        &alice,
        &["inference", "packages"],
        DAY + 1,
    )
    .unwrap_err();
    assert_eq!(too_long.refusal, AccessKeyRefusal::LifetimeNotOffered);
    assert_eq!(too_long.access_key_type.as_deref(), Some("inference"));
    mint_portal(&store, "usr-alice", &alice, &["inference", "packages"], DAY).unwrap();
    mint_portal(&store, "usr-alice", &alice, &["inference"], 7 * DAY).unwrap();

    // A person's own request never names a service account or a disabled
    // account.
    assert_eq!(
        refusal(mint_portal(&store, "robot", &alice, &["inference"], HOUR)),
        AccessKeyRefusal::OwnerKind
    );
    store.set_principal_enabled("usr-bob", false).unwrap();
    assert_eq!(
        refusal(mint_portal(&store, "usr-bob", &bob, &["inference"], HOUR)),
        AccessKeyRefusal::PrincipalDisabled
    );

    for (name, requested, lifetime) in [
        ("", vec!["inference"], HOUR),
        (" padded ", vec!["inference"], HOUR),
        ("laptop", vec![], HOUR),
        ("laptop", vec!["inference", "inference"], HOUR),
        ("laptop", vec!["Inference"], HOUR),
        ("laptop", vec!["inference"], 0),
        ("laptop", vec!["e"; 17], HOUR),
    ] {
        let mut request = portal_request("usr-alice", &alice, &requested, lifetime);
        request.name = name.into();
        assert!(matches!(
            store.mint_portal_access_key(&hasher(), &access_key_types(), &request),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }
    assert_eq!(views_of(&store, Some("usr-alice"), false, false).len(), 2);
}

#[test]
fn a_person_cannot_tell_a_type_they_may_not_hold_from_one_that_does_not_exist() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    // Alice may hold nothing: no type is offered to her.
    store.set_principal_access_key_types_for_test("usr-alice", &[], &[], &access_key_types());
    assert!(
        store
            .portal_access_key_options(&access_key_types(), "usr-alice")
            .unwrap()
            .access_key_types
            .is_empty()
    );
    // A guessed ID is refused the same way whether it is not configured,
    // configured for administrators to issue, or configured for people to
    // create: the refusal and its message say nothing of which.
    let refused = |id: &str| mint_portal(&store, "usr-alice", &alice, &[id], HOUR).unwrap_err();
    let answers = ["telemetry", "batch", "research", "inference"].map(|id| {
        let refused = refused(id);
        assert_eq!(refused.access_key_type.as_deref(), Some(id));
        (refused.refusal, refused.message())
    });
    assert_eq!(answers[0].0, AccessKeyRefusal::AccessKeyTypeNotEligible);
    assert!(
        answers.iter().all(|answer| *answer == answers[0]),
        "{answers:?}"
    );
    // Beside a type she may hold, the same.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference", "batch"],
        &[],
        &access_key_types(),
    );
    for id in ["telemetry", "research"] {
        let refused =
            mint_portal(&store, "usr-alice", &alice, &["inference", id], HOUR).unwrap_err();
        assert_eq!(refused.refusal, AccessKeyRefusal::AccessKeyTypeNotEligible);
        assert_eq!(refused.access_key_type.as_deref(), Some(id));
    }
    // What she is told apart is only what her options already show her: a
    // type she may hold that people do not create themselves.
    assert_eq!(
        refused("batch").refusal,
        AccessKeyRefusal::AccessKeyTypeNotSelfService
    );
    // An administrator, who can list the types, is told which it is.
    assert_eq!(
        refusal(mint_admin(&store, "usr-alice", &["telemetry"], HOUR)),
        AccessKeyRefusal::AccessKeyTypeUnknown
    );
    assert_eq!(
        refusal(mint_admin(&store, "usr-alice", &["research"], HOUR)),
        AccessKeyRefusal::AccessKeyTypeNotEligible
    );
}

#[test]
fn a_portal_mint_refuses_a_session_the_portal_does_not_treat_as_signed_in() {
    let (_temp, store) = fixture();
    let minted = |principal: &str, session: &str| {
        mint_portal(&store, principal, session, &["inference"], HOUR).map(|issued| issued.record)
    };
    let refused = |principal: &str, session: &str| {
        assert_eq!(
            minted(principal, session).unwrap_err().refusal,
            AccessKeyRefusal::SessionRequired
        );
    };
    // A session that must change its password first is not signed in.
    let passwords = LocalPasswordHasher {
        verification_hook: None,
        key: Arc::new([23; 32]),
    };
    store
        .enable_local_password(
            &passwords,
            LocalPasswordWriteRequest {
                principal_id: "usr-bob".into(),
                password: "first-password".into(),
                min_password_length: 8,
                password_change_required: true,
                actor: "admin".into(),
            },
        )
        .unwrap();
    let bob = store
        .authenticate_local_password_session(
            &passwords,
            &hasher(),
            LocalPasswordVerifyRequest {
                principal_id: "usr-bob".into(),
                password: "first-password".into(),
                source: "203.0.113.10".into(),
                max_failed_attempts: 3,
                lockout_ttl_seconds: 60,
            },
            3600,
            None,
        )
        .unwrap()
        .session;
    assert!(bob.record.revoked_at.is_none());
    refused("usr-bob", &bob.record.token_id);

    // Each state the session resolver refuses is refused by the mint's own
    // check too, without relying on the session having been revoked.
    let alice = session(&store, "usr-alice");
    minted("usr-alice", &alice).unwrap();
    for (name, enter, leave) in [
        (
            "the session's token is paused",
            "UPDATE broker_tokens SET paused_at = '2026-01-01T00:00:00Z', paused_by = 'admin'
             WHERE token_id = (SELECT token_id FROM browser_sessions WHERE principal_id = 'usr-alice')",
            "UPDATE broker_tokens SET paused_at = NULL, paused_by = NULL
             WHERE token_id = (SELECT token_id FROM browser_sessions WHERE principal_id = 'usr-alice')",
        ),
        (
            "the session must change its password",
            "UPDATE browser_sessions SET password_change_required = 1 WHERE principal_id = 'usr-alice'",
            "UPDATE browser_sessions SET password_change_required = 0 WHERE principal_id = 'usr-alice'",
        ),
        (
            "the sign-in method must change its password",
            "UPDATE principal_login_methods SET must_change_password = 1 WHERE principal_id = 'usr-alice'",
            "UPDATE principal_login_methods SET must_change_password = 0 WHERE principal_id = 'usr-alice'",
        ),
        (
            "the password was set after the sign-in",
            "UPDATE principal_login_methods SET password_set_at = '9999-01-01T00:00:00Z'
             WHERE principal_id = 'usr-alice'",
            "UPDATE principal_login_methods SET password_set_at = '2000-01-01T00:00:00Z'
             WHERE principal_id = 'usr-alice'",
        ),
        (
            "the sign-in method is disabled",
            "UPDATE principal_login_methods SET status = 'disabled' WHERE principal_id = 'usr-alice'",
            "UPDATE principal_login_methods SET status = 'active' WHERE principal_id = 'usr-alice'",
        ),
    ] {
        sql(&store, enter);
        assert_eq!(
            minted("usr-alice", &alice).map_err(|refused| refused.refusal),
            Err(AccessKeyRefusal::SessionRequired),
            "{name}"
        );
        sql(&store, leave);
        minted("usr-alice", &alice).unwrap_or_else(|refused| panic!("{name}: {refused:?}"));
    }
}

#[test]
fn administrator_token_for_a_service_account_resolves_as_that_service_account() {
    let (_temp, store) = fixture();
    group(&store, "automation", &["robot"]);
    // An administrator's token does not need the self-service switch.
    let issued = mint_admin(&store, "robot", &["batch", "inference"], 7 * DAY).unwrap();
    assert_eq!(issued.record.origin, AccessKeyOrigin::Administrator);
    assert_eq!(issued.record.created_by, "admin");
    let facts = active(resolve_at(
        &store,
        &access_key_types(),
        &issued.key,
        Utc::now(),
    ));
    assert_eq!(
        facts.subject,
        AccessKeySubject {
            kind: AccessKeySubjectKind::ServiceAccount,
            id: "robot".into()
        }
    );
    assert_eq!(facts.principal_id, "robot");
    assert_eq!(facts.origin, AccessKeyOrigin::Administrator);
    assert_eq!(facts.application, None);
    assert_eq!(facts.groups, ["automation"]);
    assert_eq!(
        facts
            .access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.as_str())
            .collect::<Vec<_>>(),
        ["batch", "inference"]
    );

    // Only a person or a service account owns a token.
    principal(&store, "sys", "system", None);
    assert_eq!(
        refusal(mint_admin(&store, "sys", &["inference"], HOUR)),
        AccessKeyRefusal::OwnerKind
    );
    assert_eq!(
        refusal(mint_admin(&store, "robot", &["research"], HOUR)),
        AccessKeyRefusal::AccessKeyTypeNotEligible
    );
    assert_eq!(
        refusal(mint_admin(&store, "robot", &["inference"], 7 * DAY + 1)),
        AccessKeyRefusal::LifetimeNotOffered
    );
    assert!(matches!(
        store.mint_administrator_access_key(
            &hasher(),
            &access_key_types(),
            &admin_request("missing", &["inference"], HOUR)
        ),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    // A reservation the operator adds later applies to the service account:
    // it neither mints nor resolves until the entry is removed.
    for reserving in [
        AccountUsernamePolicy::for_test(&[], &["robot"], &[]),
        AccountUsernamePolicy::for_test(&[], &[], &["robot"]),
    ] {
        store.configure_account_usernames(reserving);
        assert_eq!(
            refusal(mint_admin(&store, "robot", &["inference"], HOUR)),
            AccessKeyRefusal::AccountUsernameReserved
        );
        assert_eq!(
            reason(resolve_at(
                &store,
                &access_key_types(),
                &issued.key,
                Utc::now()
            )),
            AccessKeyInactiveReason::AccountUsernameReserved
        );
    }
    store.configure_account_usernames(policy());
    assert!(resolve_at(&store, &access_key_types(), &issued.key, Utc::now()).is_active());

    // The token ends with the service account's kind and state.
    store.set_principal_enabled("robot", false).unwrap();
    assert_eq!(
        refusal(mint_admin(&store, "robot", &["inference"], HOUR)),
        AccessKeyRefusal::PrincipalDisabled
    );
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            Utc::now()
        )),
        AccessKeyInactiveReason::PrincipalDisabled
    );
    store.set_principal_enabled("robot", true).unwrap();
    sql(
        &store,
        "UPDATE principals SET kind = 'system' WHERE principal_id = 'robot';
         UPDATE principals SET kind = 'service_account' WHERE principal_id = 'robot';",
    );
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            Utc::now()
        )),
        AccessKeyInactiveReason::UsernameIncarnationChanged
    );
}

#[test]
fn an_administrator_issues_a_token_for_a_person_and_it_is_the_person_s_own() {
    let (_temp, store) = fixture();
    let owned = |id: &str| {
        store
            .portal_access_key_options(&access_key_types(), id)
            .unwrap()
            .has_keys
    };
    assert!(!owned("usr-alice"));

    // No session of hers is needed, and `batch` is a type people cannot
    // create themselves: only an administrator hands it out.
    let issued = mint_admin(&store, "usr-alice", &["batch", "inference"], HOUR).unwrap();
    assert_eq!(issued.record.principal_id, "usr-alice");
    assert_eq!(issued.record.origin, AccessKeyOrigin::Administrator);
    assert_eq!(issued.record.created_by, "admin");
    let now = Utc::now();
    let facts = active(resolve_at(&store, &access_key_types(), &issued.key, now));
    assert_eq!(
        facts.subject,
        AccessKeySubject {
            kind: AccessKeySubjectKind::User,
            id: "alice".into()
        }
    );
    assert_eq!(facts.origin, AccessKeyOrigin::Administrator);
    assert_eq!(facts.application, None);
    assert_eq!(
        facts
            .access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.as_str())
            .collect::<Vec<_>>(),
        ["batch", "inference"]
    );
    let alice = session(&store, "usr-alice");
    assert_eq!(
        refusal(mint_portal(&store, "usr-alice", &alice, &["batch"], HOUR)),
        AccessKeyRefusal::AccessKeyTypeNotSelfService
    );

    // The token is hers: it is in her list beside one she created, and she
    // revokes it herself.
    let own = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    assert!(owned("usr-alice") && !owned("usr-bob"));
    let listed = store
        .list_access_key_views(
            &access_key_types(),
            &AccessKeyListFilter {
                principal_id: Some("usr-alice".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let entry = |key_id: &str| {
        let view = listed
            .iter()
            .find(|view| view.record.key_id == key_id)
            .unwrap();
        (
            view.record.origin,
            view.record.created_by.clone(),
            view.status,
        )
    };
    assert_eq!(listed.len(), 2);
    assert_eq!(
        entry(&issued.record.key_id),
        (
            AccessKeyOrigin::Administrator,
            "admin".to_string(),
            AccessKeyStatus::Active
        )
    );
    assert_eq!(
        entry(&own.record.key_id),
        (
            AccessKeyOrigin::Portal,
            "usr-alice".to_string(),
            AccessKeyStatus::Active
        )
    );

    // The same checks as her own mint, apart from the session and the
    // self-service switch, inside the mint's transaction; nothing is
    // trimmed.
    for (requested, lifetime, expected) in [
        (
            &["inference", "research"][..],
            HOUR,
            AccessKeyRefusal::AccessKeyTypeNotEligible,
        ),
        (
            &["inference", "telemetry"][..],
            HOUR,
            AccessKeyRefusal::AccessKeyTypeUnknown,
        ),
        (
            &["batch", "inference"][..],
            7 * DAY + 1,
            AccessKeyRefusal::LifetimeNotOffered,
        ),
    ] {
        assert_eq!(
            refusal(mint_admin(&store, "usr-alice", requested, lifetime)),
            expected,
            "{requested:?}"
        );
    }
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", true, version, "admin")
        .unwrap();
    assert_eq!(
        refusal(mint_admin(&store, "usr-alice", &["inference"], HOUR)),
        AccessKeyRefusal::IdentityAccessPaused
    );
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", false, version, "admin")
        .unwrap();
    store.set_principal_enabled("usr-alice", false).unwrap();
    assert_eq!(
        refusal(mint_admin(&store, "usr-alice", &["inference"], HOUR)),
        AccessKeyRefusal::PrincipalDisabled
    );
    store.set_principal_enabled("usr-alice", true).unwrap();

    // It stops working by the rules of a token she created: her access to
    // a type withdrawn, then her name changed.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference", "packages"],
        &["batch"],
        &access_key_types(),
    );
    assert_eq!(
        active(resolve_at(&store, &access_key_types(), &issued.key, now))
            .access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.as_str())
            .collect::<Vec<_>>(),
        ["inference"]
    );
    store
        .set_account_username("usr-alice", "alice.renamed", "admin")
        .unwrap()
        .unwrap();
    for token in [&issued.key, &own.key] {
        assert_eq!(
            reason(resolve_at(&store, &access_key_types(), token, now)),
            AccessKeyInactiveReason::UsernameIncarnationChanged
        );
    }
    // Without a usable name nothing is issued for her either.
    store
        .set_account_username_setting("usr-alice", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        refusal(mint_admin(&store, "usr-alice", &["inference"], HOUR)),
        AccessKeyRefusal::NoAccountUsername
    );
    // She revokes the administrator's token like her own.
    let revoked = store
        .revoke_access_key(&issued.record.key_id, Some("usr-alice"), "usr-alice")
        .unwrap()
        .unwrap();
    assert!(revoked.newly_revoked);
    assert_eq!(revoked.record.revoked_by.as_deref(), Some("usr-alice"));
    assert_eq!(
        reason(resolve_at(&store, &access_key_types(), &issued.key, now)),
        AccessKeyInactiveReason::Revoked
    );
}

/// The vendored copy of the fixtures shared with the resolving service.
fn shared_fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/access-key-resolution")
            .join(name),
    )
    .unwrap()
}

/// The store produces exactly the active portal and administrator answers,
/// for a service account and for a person, and the inactive answer of the
/// shared fixtures.
#[test]
fn resolution_answers_are_exactly_the_shared_wire_answers() {
    let index: Value = serde_json::from_str(&shared_fixture("index.json")).unwrap();
    let names = |list: &Value| {
        list.as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    // The application answer is not one this store produces: no operation
    // issues or resolves that origin.
    assert_eq!(
        names(&index["answers"]["callerAcceptsAsSubject"]),
        [
            "answer.active.portal.json",
            "answer.active.application.json",
            "answer.active.administrator.json",
            "answer.active.administrator-user.json",
            "answer.active.never.json",
            "answer.active.never-finite-type.json"
        ]
    );
    let unmatched_fixture = index["answers"]["endpointInactiveForms"]["unknownOrMalformedKey"]
        .as_str()
        .unwrap();
    let shared = |name: &str| serde_json::from_str::<Value>(&shared_fixture(name)).unwrap();
    let request: Value = shared(&names(&index["requests"]["valid"])[0]);
    let portal_token = request["key"].as_str().unwrap().to_string();
    assert!(is_access_key(&portal_token));

    let (_temp, store) = fixture();
    principal(&store, "nightly-evals", "service_account", None);
    store.set_principal_access_key_types_for_test(
        "nightly-evals",
        &["inference"],
        &[],
        &access_key_types(),
    );
    principal(&store, "usr-dana", "user", None);
    store.set_principal_access_key_types_for_test(
        "usr-dana",
        &["inference"],
        &[],
        &access_key_types(),
    );
    group(&store, "platform", &["usr-alice", "usr-dana"]);
    let administrator_token = "aab_ak_B1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
    let person_token = "aab_ak_D1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(&format!(
            "DELETE FROM account_usernames WHERE principal_id IN ('usr-alice', 'nightly-evals', 'usr-dana');
             INSERT INTO account_usernames
               (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
             VALUES ('alice', 'usr-alice', 'user', 'n1-7b0c2f', 'derived', '2026-11-01T00:00:00Z', 'admin'),
                    ('nightly-evals', 'nightly-evals', 'service_account', 'n1-0001', 'service_account',
                     '2026-11-01T00:00:00Z', 'admin'),
                    ('dana', 'usr-dana', 'user', 'n1-44d0', 'administrator', '2026-11-01T00:00:00Z',
                     'admin');
             INSERT INTO access_keys
               (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at,
                created_by, expires_at)
             VALUES ('ak_01HZXK3Q8', '{}', 'usr-alice', 'laptop', 'portal', 'n1-7b0c2f',
                     '2026-11-24T02:00:00Z', 'usr-alice', '2026-12-01T02:00:00Z'),
                    ('ak_01HZXK5BB', '{}', 'nightly-evals', 'nightly job', 'administrator', 'n1-0001',
                     '2026-11-20T00:00:00Z', 'admin', '2026-12-20T00:00:00Z'),
                    ('ak_01HZXK6CC', '{}', 'usr-dana', 'workstation', 'administrator', 'n1-44d0',
                     '2026-11-24T02:00:00Z', 'admin', '2026-12-01T02:00:00Z');
             INSERT INTO access_key_type_links (key_id, access_key_type, access_key_type_order)
             VALUES ('ak_01HZXK3Q8', 'inference', 0), ('ak_01HZXK5BB', 'inference', 0),
                    ('ak_01HZXK6CC', 'inference', 0);",
            hasher().hash(&portal_token).unwrap(),
            hasher().hash(administrator_token).unwrap(),
            hasher().hash(person_token).unwrap(),
        ))
        .unwrap();
    let access_key_types = AccessKeyTypes::for_test([access_key_type("inference", 30 * DAY)]);
    let now = time("2026-11-26T12:00:00Z");

    let portal = resolve_at(&store, &access_key_types, &portal_token, now);
    assert_eq!(
        serde_json::to_value(&portal).unwrap(),
        shared("answer.active.portal.json")
    );
    // The members are written in the contract's order.
    assert_eq!(
        serde_json::to_string(&portal).unwrap(),
        r#"{"active":true,"subject":{"kind":"user","id":"alice"},"usernameIncarnation":"n1-7b0c2f","groups":["platform"],"types":[{"name":"inference","validUntil":"2026-12-01T02:00:00Z"}],"origin":"portal","application":null,"keyId":"ak_01HZXK3Q8","expiresAt":"2026-12-01T02:00:00Z"}"#
    );
    assert_eq!(
        serde_json::to_value(resolve_at(
            &store,
            &access_key_types,
            administrator_token,
            now
        ))
        .unwrap(),
        shared("answer.active.administrator.json")
    );
    // An administrator's key for a person resolves as that person.
    assert_eq!(
        serde_json::to_value(resolve_at(&store, &access_key_types, person_token, now)).unwrap(),
        shared("answer.active.administrator-user.json")
    );
    // Unmatched values disclose no identity or reason.
    for (token, at) in [
        ("aab_ak_C1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v", now),
        ("aab_ak_short", now),
    ] {
        let inactive = resolve_at(&store, &access_key_types, token, at);
        assert!(!inactive.is_active());
        assert_eq!(
            serde_json::to_value(&inactive).unwrap(),
            shared(unmatched_fixture)
        );
        assert_eq!(
            serde_json::to_string(&inactive).unwrap(),
            r#"{"active":false}"#
        );
    }
    assert_eq!(
        serde_json::to_value(resolve_at(
            &store,
            &access_key_types,
            &portal_token,
            time("2026-12-01T02:00:00Z")
        ))
        .unwrap(),
        json!({"active": false, "keyId": "ak_01HZXK3Q8",
            "owner": {"kind": "user", "id": "alice"}, "reason": "expired"})
    );
    // The requests the endpoint answers 400 are not an object whose one
    // member is a well-formed access key: a positional array of the same
    // token is among them.
    for entry in index["requests"]["endpointMustAnswer400"]
        .as_array()
        .unwrap()
    {
        let request = shared(entry["file"].as_str().unwrap());
        let well_formed = request.as_object().is_some_and(|object| object.len() == 1)
            && request["key"].as_str().is_some_and(is_access_key);
        assert!(!well_formed, "{}", entry["why"]);
    }
}

#[test]
fn inactive_resolutions_carry_the_reason_and_stored_identity() {
    let (_temp, store) = fixture();
    let session = session(&store, "usr-alice");
    let config = access_key_types();
    let mint =
        |requested: &[&str]| mint_portal(&store, "usr-alice", &session, requested, HOUR).unwrap();
    let now = Utc::now();
    let check = |token: &str, at: DateTime<Utc>| resolve_at(&store, &config, token, at);

    let unknown = check("aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now);
    assert_eq!(
        unknown,
        AccessKeyResolution::Inactive(AccessKeyInactive {
            reason: AccessKeyInactiveReason::Unknown,
            key_id: None,
            owner: None,
        })
    );

    let issued = mint(&["inference"]);
    assert!(check(&issued.key, now).is_active());
    // At its expiry a token is no longer active.
    let expiry = time(issued.record.expires_at.as_deref().unwrap());
    assert!(check(&issued.key, expiry - Duration::seconds(1)).is_active());
    let expired = check(&issued.key, expiry);
    assert_eq!(
        expired,
        AccessKeyResolution::Inactive(AccessKeyInactive {
            reason: AccessKeyInactiveReason::Expired,
            key_id: Some(issued.record.key_id.clone()),
            owner: Some(AccessKeySubject {
                kind: AccessKeySubjectKind::User,
                id: "alice".into()
            }),
        })
    );

    // A name on the operator's lists stops resolving without any write.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&[], &[], &["alice"]));
    assert_eq!(
        reason(check(&issued.key, now)),
        AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation
    );
    store
        .confirm_account_username("usr-alice", "alice", "admin")
        .unwrap()
        .unwrap();
    assert!(check(&issued.key, now).is_active());
    store.configure_account_usernames(AccountUsernamePolicy::for_test(&[], &["alice"], &[]));
    assert_eq!(
        reason(check(&issued.key, now)),
        AccessKeyInactiveReason::AccountUsernameReserved
    );
    store.configure_account_usernames(policy());

    store.set_principal_enabled("usr-alice", false).unwrap();
    assert_eq!(
        reason(check(&issued.key, now)),
        AccessKeyInactiveReason::PrincipalDisabled
    );
    store.set_principal_enabled("usr-alice", true).unwrap();
    assert!(check(&issued.key, now).is_active());

    // A changed name ends the tokens of the earlier incarnation, and so
    // does setting the earlier name again.
    let changed = store
        .set_account_username("usr-alice", "asmith", "admin")
        .unwrap()
        .unwrap();
    assert_eq!(changed.ended_keys, 1);
    assert_eq!(
        reason(check(&issued.key, now)),
        AccessKeyInactiveReason::UsernameIncarnationChanged
    );
    store
        .set_account_username("usr-alice", "alice", "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        reason(check(&issued.key, now)),
        AccessKeyInactiveReason::UsernameIncarnationChanged
    );
    let renamed = mint(&["inference"]);
    assert_eq!(active(check(&renamed.key, now)).subject.id, "alice");
    let released = store
        .set_account_username_setting("usr-alice", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(released.ended_keys, 1);
    for token in [&issued.key, &renamed.key] {
        assert_eq!(
            reason(check(token, now)),
            AccessKeyInactiveReason::NoAccountUsername
        );
    }

    // Revocation wins over every later state.
    store
        .set_account_username("usr-alice", "alice", "admin")
        .unwrap()
        .unwrap();
    let revoked = mint(&["inference"]);
    store
        .revoke_access_key(&revoked.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        reason(check(&revoked.key, now)),
        AccessKeyInactiveReason::Revoked
    );
    assert_eq!(
        reason(check(&revoked.key, expiry + Duration::days(1))),
        AccessKeyInactiveReason::Revoked
    );

    // More groups than an answer may hold is not answered with fewer.
    let many = mint(&["inference"]);
    for index in 0..64 {
        group(&store, &format!("g{index}"), &["usr-alice"]);
    }
    assert_eq!(active(check(&many.key, now)).groups.len(), 64);
    group(&store, "g64", &["usr-alice"]);
    assert_eq!(
        reason(check(&many.key, now)),
        AccessKeyInactiveReason::GroupLimitExceeded
    );
}

#[test]
fn a_key_of_an_origin_no_operation_resolves_yet_is_inactive_and_listed_as_such() {
    let (_temp, store) = fixture();
    // Nothing mints an application's key yet: the row is written as a
    // later version would write it, under the person's current username.
    let raw = format!("{ACCESS_KEY_PREFIX}{}", "B".repeat(43));
    let incarnation = store
        .principal_account_username("usr-alice")
        .unwrap()
        .name
        .unwrap()
        .incarnation;
    let now = Utc::now();
    let insert = |key_id: &str, owner: &str, raw: &str| {
        let conn = store.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO access_keys
             (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at,
              created_by, expires_at, revoked_at, revoked_by, last_used_at)
             VALUES (?1, ?2, ?3, 'from an application', 'application', ?4, ?5, ?3, ?6,
                     NULL, NULL, NULL)",
            params![
                key_id,
                hasher().hash(raw).unwrap(),
                owner,
                incarnation,
                normalized_timestamp(now),
                normalized_timestamp(now + Duration::hours(1)),
            ],
        )?;
        conn.execute(
            "INSERT INTO access_key_type_links (key_id, access_key_type, access_key_type_order)
             VALUES (?1, 'inference', 0)",
            [key_id],
        )
    };
    insert("ak_application", "usr-alice", &raw).unwrap();
    let later = now + Duration::minutes(1);
    // It resolves as not active, with a reason of its own, whatever else
    // is in order: the owner, her username and her type are.
    assert_eq!(
        resolve_at(&store, &access_key_types(), &raw, later),
        AccessKeyResolution::Inactive(AccessKeyInactive {
            reason: AccessKeyInactiveReason::OriginUnsupported,
            key_id: Some("ak_application".into()),
            owner: Some(AccessKeySubject {
                kind: AccessKeySubjectKind::User,
                id: "alice".into()
            }),
        })
    );
    assert_eq!(
        serde_json::to_value(resolve_at(&store, &access_key_types(), &raw, later)).unwrap(),
        json!({"active": false, "keyId": "ak_application",
            "owner": {"kind": "user", "id": "alice"}, "reason": "origin_unsupported"})
    );
    let view = store
        .list_access_key_views_at(
            &access_key_types(),
            &AccessKeyListFilter {
                principal_id: Some("usr-alice".into()),
                ..Default::default()
            },
            later,
        )
        .unwrap()
        .remove(0);
    assert_eq!(view.record.origin, AccessKeyOrigin::Application);
    assert_eq!(view.status.as_str(), "origin_unsupported");
    assert_eq!(view.access, AccessKeyAccess::None);
    assert!(view.usable_access_key_types.is_empty());
    // No use is recorded for it.
    assert_eq!(view.record.last_used_at, None);
    // A service account never holds a key of that origin: the store
    // refuses the row.
    let refused = insert(
        "ak_application_robot",
        "robot",
        &format!("{ACCESS_KEY_PREFIX}{}", "C".repeat(43)),
    )
    .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("access key origin does not match its owner"),
        "{refused}"
    );
}

#[test]
fn pausing_a_person_s_identity_access_pauses_their_access_keys_until_resumed() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let issued = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let robot = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    let config = access_key_types();
    let check = |token: &str| resolve_at(&store, &config, token, Utc::now());
    let set_paused = |paused: bool| {
        let version = store.identity_access("usr-alice").unwrap().version;
        store
            .set_identity_access_paused("usr-alice", paused, version, "admin")
            .unwrap();
    };
    assert!(check(&issued.key).is_active());

    set_paused(true);
    let paused = check(&issued.key);
    assert_eq!(
        paused,
        AccessKeyResolution::Inactive(AccessKeyInactive {
            reason: AccessKeyInactiveReason::IdentityAccessPaused,
            key_id: Some(issued.record.key_id.clone()),
            owner: Some(AccessKeySubject {
                kind: AccessKeySubjectKind::User,
                id: "alice".into()
            }),
        })
    );
    assert_eq!(
        serde_json::to_value(&paused).unwrap(),
        json!({"active": false, "keyId": issued.record.key_id,
            "owner": {"kind": "user", "id": "alice"}, "reason": "identity_access_paused"})
    );
    // A paused person cannot mint either; nobody else is affected.
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::IdentityAccessPaused
    );
    assert!(check(&robot.key).is_active());
    // The pause changes no token row.
    let stored = store.access_key(&issued.record.key_id).unwrap().unwrap();
    assert_eq!(
        (&stored.revoked_at, &stored.expires_at),
        (&None, &issued.record.expires_at)
    );

    set_paused(false);
    assert!(check(&issued.key).is_active());
    mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();

    // A person without a gate row never resolves or mints: the mint is
    // refused with the reason a resolution records.
    sql(
        &store,
        "DELETE FROM principal_identity_access WHERE principal_id = 'usr-alice'",
    );
    assert_eq!(
        reason(check(&issued.key)),
        AccessKeyInactiveReason::IdentityAccessMissing
    );
    assert_eq!(
        refusal(
            store
                .mint_portal_access_key(
                    &hasher(),
                    &config,
                    &portal_request("usr-alice", &alice, &["inference"], HOUR)
                )
                .unwrap()
        ),
        AccessKeyRefusal::IdentityAccessMissing
    );
    assert!(check(&robot.key).is_active());
}

#[test]
fn access_key_type_lifetime_and_eligibility_are_read_at_resolution() {
    let (_temp, store) = fixture();
    group(&store, "research", &["usr-alice"]);
    group(&store, "retired", &["usr-alice"]);
    sql(
        &store,
        "UPDATE groups SET status = 'disabled' WHERE group_id = 'retired'",
    );
    let session = session(&store, "usr-alice");
    let issued = mint_portal(
        &store,
        "usr-alice",
        &session,
        &["research", "packages", "inference"],
        DAY,
    )
    .unwrap();
    let created = time(&issued.record.created_at);
    let expires = time(issued.record.expires_at.as_deref().unwrap());
    let names = |facts: &AccessKeyFacts| {
        facts
            .access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.clone())
            .collect::<Vec<_>>()
    };

    let facts = active(resolve_at(
        &store,
        &access_key_types(),
        &issued.key,
        created,
    ));
    assert_eq!(names(&facts), ["research", "packages", "inference"]);
    // Only active local groups are returned.
    assert_eq!(facts.groups, ["research"]);
    assert_eq!(facts.expires_at, issued.record.expires_at);
    for access_key_type in &facts.access_key_types {
        // Never later than the token's expiry, even under a longer maximum.
        assert_eq!(access_key_type.valid_until, issued.record.expires_at);
    }

    // Lowering a maximum shortens that access key type for an existing token.
    let lowered = AccessKeyTypes::for_test([
        access_key_type("inference", 7 * DAY),
        access_key_type("packages", 2 * HOUR),
        access_key_type("research", 6 * HOUR),
    ]);
    let facts = active(resolve_at(
        &store,
        &lowered,
        &issued.key,
        created + Duration::hours(1),
    ));
    assert_eq!(names(&facts), ["research", "packages", "inference"]);
    assert_eq!(
        facts
            .access_key_types
            .iter()
            .map(|access_key_type| time(access_key_type.valid_until.as_deref().unwrap()) - created)
            .collect::<Vec<_>>(),
        [Duration::hours(6), Duration::hours(2), Duration::days(1)]
    );
    // An access key type is not returned from its `validUntil` on.
    let facts = active(resolve_at(
        &store,
        &lowered,
        &issued.key,
        created + Duration::hours(2),
    ));
    assert_eq!(names(&facts), ["research", "inference"]);
    let facts = active(resolve_at(
        &store,
        &lowered,
        &issued.key,
        created + Duration::hours(6),
    ));
    assert_eq!(names(&facts), ["inference"]);
    // Raising a maximum never extends a token past its expiry.
    assert_eq!(
        reason(resolve_at(&store, &lowered, &issued.key, expires)),
        AccessKeyInactiveReason::Expired
    );

    // What a group allows follows current local membership.
    store.remove_group("usr-alice", "research").unwrap();
    let facts = active(resolve_at(
        &store,
        &access_key_types(),
        &issued.key,
        created,
    ));
    assert_eq!(names(&facts), ["packages", "inference"]);
    assert!(facts.groups.is_empty());
    // Access withdrawn after the mint stops the access key type for a token
    // minted before, one access key type at a time, and restoring it brings the
    // access key type back.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["packages"],
        &["inference"],
        &access_key_types(),
    );
    assert_eq!(
        names(&active(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            created
        ))),
        ["packages"]
    );
    // A group's allowance does not lift the account's own denial.
    group(&store, "inference", &["usr-alice"]);
    assert_eq!(
        names(&active(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            created
        ))),
        ["packages"]
    );
    // With nothing said by the account, the group's allowance is enough.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["packages"],
        &[],
        &access_key_types(),
    );
    assert_eq!(
        names(&active(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            created
        ))),
        ["packages", "inference"]
    );

    // A token whose every access key type was removed or expired is inactive.
    for remaining in [
        AccessKeyTypes::default(),
        AccessKeyTypes::for_test([access_key_type("other", DAY)]),
    ] {
        assert_eq!(
            reason(resolve_at(&store, &remaining, &issued.key, created)),
            AccessKeyInactiveReason::NoAccessKeyType
        );
    }
    // So is one whose subject may hold none of them any more.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &[],
        &["inference", "packages"],
        &access_key_types(),
    );
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &issued.key,
            created
        )),
        AccessKeyInactiveReason::NoAccessKeyType
    );
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &ACCOUNT_ACCESS_KEY_TYPES,
        &[],
        &access_key_types(),
    );
    assert!(resolve_at(&store, &access_key_types(), &issued.key, created).is_active());
    assert_eq!(
        reason(resolve_at(
            &store,
            &AccessKeyTypes::for_test([access_key_type("packages", HOUR)]),
            &issued.key,
            created + Duration::hours(1)
        )),
        AccessKeyInactiveReason::NoAccessKeyType
    );
}

#[test]
fn last_used_is_written_at_most_once_in_five_minutes_and_never_fails_a_resolution() {
    let (_temp, store) = fixture();
    let session = session(&store, "usr-alice");
    let issued = mint_portal(&store, "usr-alice", &session, &["inference"], DAY).unwrap();
    let config = access_key_types();
    let created = time(&issued.record.created_at);
    let last_used = || {
        store
            .access_key(&issued.record.key_id)
            .unwrap()
            .unwrap()
            .last_used_at
            .map(|value| time(&value))
    };
    let at = |seconds: i64| created + Duration::seconds(seconds);

    // An inspection without a use records nothing.
    assert!(
        store
            .access_key_resolution(&config, &issued.record.key_id)
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(last_used(), None);

    assert!(resolve_at(&store, &config, &issued.key, at(10)).is_active());
    assert_eq!(last_used(), Some(at(10)));
    for seconds in [11, 150, 309] {
        assert!(resolve_at(&store, &config, &issued.key, at(seconds)).is_active());
        assert_eq!(last_used(), Some(at(10)), "{seconds}");
    }
    assert!(resolve_at(&store, &config, &issued.key, at(310)).is_active());
    assert_eq!(last_used(), Some(at(310)));

    // An inactive resolution is not a use.
    store.set_principal_enabled("usr-alice", false).unwrap();
    assert!(!resolve_at(&store, &config, &issued.key, at(1000)).is_active());
    store.set_principal_enabled("usr-alice", true).unwrap();
    assert_eq!(last_used(), Some(at(310)));

    // A write that fails leaves the answer as it is.
    sql(
        &store,
        "CREATE TEMP TRIGGER refuse_last_used BEFORE UPDATE OF last_used_at ON access_keys
         BEGIN SELECT RAISE(ABORT, 'last-used write refused'); END;",
    );
    let logged = LoggedEvents::default();
    let resolved = {
        use tracing_subscriber::layer::SubscriberExt;
        let _capture =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(logged.clone()));
        active(resolve_at(&store, &config, &issued.key, at(2000)))
    };
    assert_eq!(resolved.key_id, issued.record.key_id);
    assert_eq!(last_used(), Some(at(310)));
    // The failure is logged under the key's ID, in the member name the
    // records and audit details use, and never with the key itself.
    let events = logged.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0].get("event").map(String::as_str),
        Some("access_key_last_used_write_failed")
    );
    assert_eq!(events[0].get("keyId"), Some(&issued.record.key_id));
    assert!(!events[0].contains_key("tokenId"), "{events:?}");
    assert!(
        events[0].values().all(|value| !value.contains("aab_ak_")),
        "{events:?}"
    );
    sql(&store, "DROP TRIGGER refuse_last_used");
    assert!(resolve_at(&store, &config, &issued.key, at(2001)).is_active());
    assert_eq!(last_used(), Some(at(2001)));
}

#[test]
fn a_key_no_store_holds_costs_one_indexed_read_and_no_write() {
    let (_temp, store) = fixture();
    let issued = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    let now = time(&issued.record.created_at) + Duration::minutes(1);
    // Trace the statements the production resolver actually executes. Explain
    // that captured lookup, rather than a second hand-written query.
    use std::cell::RefCell;
    thread_local! { static QUERIES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) }; }
    QUERIES.with(|queries| queries.borrow_mut().clear());
    store.connection.lock().unwrap().trace_v2(
        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
        Some(|event| {
            if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
                QUERIES.with(|queries| queries.borrow_mut().push(sql.to_string()));
            }
        }),
    );
    // Resolving a well-formed key that no store holds changes nothing in
    // the store, however often it is asked for.
    let unknown = format!("{ACCESS_KEY_PREFIX}{}", "A".repeat(43));
    let changes = || store.connection.lock().unwrap().total_changes();
    let before = changes();
    for _ in 0..3 {
        let start = QUERIES.with(|queries| queries.borrow().len());
        let resolution = resolve_at(&store, &access_key_types(), &unknown, now);
        QUERIES.with(|queries| {
            assert_eq!(
                queries.borrow()[start..]
                    .iter()
                    .filter(|sql| sql.trim_start().starts_with("SELECT"))
                    .count(),
                1
            )
        });
        assert_eq!(
            resolution,
            AccessKeyResolution::Inactive(AccessKeyInactive {
                reason: AccessKeyInactiveReason::Unknown,
                key_id: None,
                owner: None,
            })
        );
    }
    assert_eq!(changes(), before);
    store
        .connection
        .lock()
        .unwrap()
        .trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
    let queries = QUERIES.with(|queries| std::mem::take(&mut *queries.borrow_mut()));
    let selects: Vec<_> = queries
        .iter()
        .filter(|sql| sql.trim_start().starts_with("SELECT"))
        .collect();
    assert_eq!(selects.len(), 3, "one lookup per resolution: {queries:?}");
    assert!(selects.windows(2).all(|pair| pair[0] == pair[1]));
    let plan: Vec<String> = {
        let conn = store.connection.lock().unwrap();
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", selects[0]))
            .unwrap();
        statement
            .query_map(["x"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(plan.len(), 1, "{plan:?}");
    assert!(
        plan[0].starts_with("SEARCH access_keys USING INDEX") && plan[0].contains("key_hash=?"),
        "{plan:?}"
    );

    // Nor does a stored key that is not active: only an active answer
    // records a use.
    store
        .revoke_access_key(&issued.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    let before = changes();
    assert_eq!(
        reason(resolve_at(&store, &access_key_types(), &issued.key, now)),
        AccessKeyInactiveReason::Revoked
    );
    assert_eq!(changes(), before);
}

#[test]
fn tokens_are_listed_and_revoked_by_their_owner_or_an_administrator() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let bob = session(&store, "usr-bob");
    let first = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let second = mint_portal(&store, "usr-alice", &alice, &["packages"], HOUR).unwrap();
    let other = mint_portal(&store, "usr-bob", &bob, &["inference"], HOUR).unwrap();
    let robot = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();

    let ids = |views: Vec<AccessKeyView>| {
        views
            .into_iter()
            .map(|view| view.record.key_id)
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        ids(views_of(&store, Some("usr-alice"), false, false)),
        BTreeSet::from([first.record.key_id.clone(), second.record.key_id.clone()])
    );
    assert_eq!(ids(views_of(&store, None, false, false)).len(), 4);
    assert_eq!(
        store.access_key(&robot.record.key_id).unwrap(),
        Some(robot.record.clone())
    );
    assert_eq!(store.access_key("ak_missing").unwrap(), None);
    assert_eq!(store.access_key("not an id").unwrap(), None);
    assert!(matches!(
        store.list_access_key_views(
            &access_key_types(),
            &AccessKeyListFilter {
                principal_id: Some("missing".into()),
                ..Default::default()
            }
        ),
        Err(ManagedStoreError::PrincipalNotFound)
    ));

    // A person revokes only their own tokens.
    assert_eq!(
        store
            .revoke_access_key(&other.record.key_id, Some("usr-alice"), "usr-alice")
            .unwrap(),
        None
    );
    assert!(resolve_at(&store, &access_key_types(), &other.key, Utc::now()).is_active());
    let revoked = store
        .revoke_access_key(&first.record.key_id, Some("usr-alice"), "usr-alice")
        .unwrap()
        .unwrap();
    assert!(revoked.newly_revoked);
    assert_eq!(revoked.record.revoked_by.as_deref(), Some("usr-alice"));
    assert!(revoked.record.revoked_at.is_some());
    // Revocation is final: a second request, by anyone, writes nothing.
    let again = store
        .revoke_access_key(&first.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    assert!(!again.newly_revoked);
    assert_eq!(again.record, revoked.record);
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &first.key,
            Utc::now()
        )),
        AccessKeyInactiveReason::Revoked
    );
    assert!(resolve_at(&store, &access_key_types(), &second.key, Utc::now()).is_active());
    assert_eq!(
        store
            .revoke_access_key("ak_missing", None, "admin")
            .unwrap(),
        None
    );

    // The schema keeps a token's identity, expiry and revocation fixed.
    let conn = store.connection.lock().unwrap();
    for statement in [
        "UPDATE access_keys SET expires_at = '2099-01-01T00:00:00Z'",
        "UPDATE access_keys SET principal_id = 'usr-bob'",
        "UPDATE access_keys SET username_incarnation = 'other'",
        "UPDATE access_keys SET revoked_at = NULL, revoked_by = NULL WHERE revoked_at IS NOT NULL",
        "INSERT INTO access_keys (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at, created_by, expires_at)
         VALUES ('ak_x', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'robot', 'n', 'portal', 'i', '2026-01-01T00:00:00Z', 'admin', '2026-01-02T00:00:00Z')",
        "INSERT INTO access_keys (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at, created_by, expires_at)
         VALUES ('token-1', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'usr-alice', 'n', 'portal', 'i', '2026-01-01T00:00:00Z', 'admin', '2026-01-02T00:00:00Z')",
        "INSERT INTO access_keys (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at, created_by, expires_at)
         VALUES ('ak_y', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'usr-alice', 'n', 'portal', 'i', '2026-01-02T00:00:00Z', 'admin', '2026-01-02T00:00:00Z')",
    ] {
        assert!(conn.execute(statement, []).is_err(), "{statement}");
    }
    // A token without an access key type is refused at admission.
    validate_structure(&conn).unwrap();
    conn.execute(
        "DELETE FROM access_key_type_links WHERE key_id = ?1",
        [&second.record.key_id],
    )
    .unwrap();
    assert!(matches!(
        validate_structure(&conn),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
}

#[test]
fn a_listing_shows_what_each_token_would_resolve_as_and_hides_ended_tokens_unless_asked() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let live = mint_portal(
        &store,
        "usr-alice",
        &alice,
        &["inference", "packages"],
        HOUR,
    )
    .unwrap();
    let short = mint_portal(&store, "usr-alice", &alice, &["inference"], 60).unwrap();
    let revoked = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let both = mint_portal(&store, "usr-alice", &alice, &["inference"], 60).unwrap();
    let robot = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    for token in [&revoked, &both] {
        store
            .revoke_access_key(&token.record.key_id, None, "admin")
            .unwrap()
            .unwrap();
    }
    // Ten minutes on, the two one-minute tokens have expired.
    let later = time(&live.record.created_at) + Duration::minutes(10);
    let listed = |principal: Option<&str>, include_revoked: bool, include_expired: bool| {
        store
            .list_access_key_views_at(
                &access_key_types(),
                &AccessKeyListFilter {
                    principal_id: principal.map(str::to_string),
                    include_revoked,
                    include_expired,
                },
                later,
            )
            .unwrap()
            .into_iter()
            .map(|view| (view.record.key_id.clone(), view.status.as_str()))
            .collect::<BTreeMap<_, _>>()
    };
    let id = |token: &IssuedAccessKey| token.record.key_id.clone();

    // By default only tokens that have neither expired nor been revoked.
    assert_eq!(
        listed(Some("usr-alice"), false, false),
        BTreeMap::from([(id(&live), "active")])
    );
    assert_eq!(
        listed(None, false, false),
        BTreeMap::from([(id(&live), "active"), (id(&robot), "active")])
    );
    // An expired token is listed on request; a revoked one, expired or not,
    // only when revoked tokens are asked for.
    assert_eq!(
        listed(Some("usr-alice"), false, true),
        BTreeMap::from([(id(&live), "active"), (id(&short), "expired")])
    );
    assert_eq!(
        listed(Some("usr-alice"), true, false),
        BTreeMap::from([
            (id(&live), "active"),
            (id(&revoked), "revoked"),
            (id(&both), "revoked"),
        ])
    );
    assert_eq!(listed(Some("usr-alice"), true, true).len(), 4);
    assert_eq!(listed(None, true, true).len(), 5);

    // An active token lists the access key types it may use now, as a
    // resolution would return them; reading it records no use.
    let views = store
        .list_access_key_views_at(
            &access_key_types(),
            &AccessKeyListFilter {
                principal_id: Some("usr-alice".into()),
                ..Default::default()
            },
            later,
        )
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].record, live.record);
    assert_eq!(views[0].record.last_used_at, None);
    assert_eq!(
        views[0]
            .usable_access_key_types
            .iter()
            .map(|access_key_type| access_key_type.name.as_str())
            .collect::<Vec<_>>(),
        ["inference", "packages"]
    );
    assert_eq!(
        serde_json::to_value(&views[0]).unwrap()["status"],
        json!("active")
    );
    assert_eq!(
        serde_json::to_value(&views[0]).unwrap()["keyId"],
        json!(live.record.key_id)
    );

    // Every other state is the reason a resolution would record: the
    // listing and the resolution route never disagree.
    store
        .set_account_username("usr-alice", "alice.renamed", "admin")
        .unwrap()
        .unwrap();
    let after_rename = listed(Some("usr-alice"), false, false);
    assert_eq!(
        after_rename,
        BTreeMap::from([(id(&live), "username_incarnation_changed")])
    );
    assert_eq!(
        reason(resolve_at(&store, &access_key_types(), &live.key, later)).as_str(),
        "username_incarnation_changed"
    );
    assert!(
        store
            .list_access_key_views_at(
                &access_key_types(),
                &AccessKeyListFilter {
                    principal_id: Some("usr-alice".into()),
                    ..Default::default()
                },
                later,
            )
            .unwrap()[0]
            .usable_access_key_types
            .is_empty()
    );
}

/// The fixture's types with names people read, `inference` lasting
/// `inference_max` seconds; `packages` is left out on request.
fn named_types(inference_max: u64, with_packages: bool) -> AccessKeyTypes {
    let mut types = vec![AccessKeyType {
        display_name: "Model inference".into(),
        ..access_key_type("inference", inference_max)
    }];
    if with_packages {
        types.push(AccessKeyType {
            display_name: "Package downloads".into(),
            ..access_key_type("packages", DAY)
        });
    }
    AccessKeyTypes::for_test(types)
}

#[test]
fn a_listing_names_each_type_a_key_carries_and_says_whether_the_key_still_holds_it() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let both = mint_portal(
        &store,
        "usr-alice",
        &alice,
        &["inference", "packages"],
        HOUR,
    )
    .unwrap();
    let single = mint_portal(&store, "usr-alice", &alice, &["packages"], HOUR).unwrap();
    let short = mint_portal(&store, "usr-alice", &alice, &["inference"], 60).unwrap();
    let revoked = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    store
        .revoke_access_key(&revoked.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    // Ten minutes on, the one-minute key has expired.
    let later = time(&both.record.created_at) + Duration::minutes(10);
    // A key's status, how much it resolves with, and each type it carries
    // as (ID, display name, held).
    let listed = |types: &AccessKeyTypes, token: &IssuedAccessKey| {
        let view = store
            .list_access_key_views_at(
                types,
                &AccessKeyListFilter {
                    principal_id: Some("usr-alice".into()),
                    include_revoked: true,
                    include_expired: true,
                },
                later,
            )
            .unwrap()
            .into_iter()
            .find(|view| view.record.key_id == token.record.key_id)
            .unwrap();
        // The listing and a resolution never disagree: an active key
        // resolves with exactly the types the listing says it holds.
        let held: Vec<&str> = view
            .access_key_type_states
            .iter()
            .filter(|state| state.held)
            .map(|state| state.id.as_str())
            .collect();
        match resolve_at(&store, types, &token.key, later) {
            AccessKeyResolution::Active(facts) => {
                assert_eq!(view.status, AccessKeyStatus::Active);
                assert_eq!(
                    facts
                        .access_key_types
                        .iter()
                        .map(|resolved| resolved.name.as_str())
                        .collect::<Vec<_>>(),
                    held
                );
            }
            AccessKeyResolution::Inactive(inactive) => {
                assert_eq!(view.status, AccessKeyStatus::Inactive(inactive.reason));
                assert_eq!(view.access, AccessKeyAccess::None);
            }
        }
        assert_eq!(
            view.access_key_type_states
                .iter()
                .map(|state| &state.id)
                .collect::<Vec<_>>(),
            view.record.access_key_types.iter().collect::<Vec<_>>()
        );
        (
            view.status.as_str(),
            view.access,
            view.access_key_type_states
                .into_iter()
                .map(|state| (state.id, state.display_name, state.held))
                .collect::<Vec<_>>(),
        )
    };
    let state = |id: &str, display_name: Option<&str>, held: bool| {
        (id.to_string(), display_name.map(str::to_string), held)
    };
    let inference = |held| state("inference", Some("Model inference"), held);
    let packages = |held| state("packages", Some("Package downloads"), held);
    let configured = named_types(7 * DAY, true);

    // Every type held: the display names are the configured ones.
    assert_eq!(
        listed(&configured, &both),
        (
            "active",
            AccessKeyAccess::Full,
            vec![inference(true), packages(true)]
        )
    );
    assert_eq!(
        serde_json::to_value(
            store
                .list_access_key_views_at(
                    &configured,
                    &AccessKeyListFilter {
                        principal_id: Some("usr-alice".into()),
                        ..Default::default()
                    },
                    later,
                )
                .unwrap()
                .into_iter()
                .find(|view| view.record.key_id == both.record.key_id)
                .unwrap()
        )
        .unwrap()["accessKeyTypeStates"],
        json!([
            {"id": "inference", "displayName": "Model inference", "held": true},
            {"id": "packages", "displayName": "Package downloads", "held": true},
        ])
    );

    // A type withdrawn from the owner: the key that has another works with
    // the rest, and the key that has none resolves with nothing.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference", "batch"],
        &[],
        &access_key_types(),
    );
    assert_eq!(
        listed(&configured, &both),
        (
            "active",
            AccessKeyAccess::Partial,
            vec![inference(true), packages(false)]
        )
    );
    assert_eq!(
        listed(&configured, &single),
        (
            "no_access_key_type",
            AccessKeyAccess::None,
            vec![packages(false)]
        )
    );
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &ACCOUNT_ACCESS_KEY_TYPES,
        &[],
        &access_key_types(),
    );
    assert_eq!(listed(&configured, &single).1, AccessKeyAccess::Full);

    // A type the configuration no longer defines has no name to show.
    let without_packages = named_types(7 * DAY, false);
    assert_eq!(
        listed(&without_packages, &both),
        (
            "active",
            AccessKeyAccess::Partial,
            vec![inference(true), state("packages", None, false)]
        )
    );
    assert_eq!(
        listed(&without_packages, &single),
        (
            "no_access_key_type",
            AccessKeyAccess::None,
            vec![state("packages", None, false)]
        )
    );

    // A type whose maximum lifetime was lowered below the key's age is no
    // longer held, while the key works with the other.
    let shortened = named_types(5 * 60, true);
    assert_eq!(
        listed(&shortened, &both),
        (
            "active",
            AccessKeyAccess::Partial,
            vec![inference(false), packages(true)]
        )
    );

    // A key that ended for a reason of its own says so in its status. Its
    // types are still its own: nothing was taken from an expired or a
    // revoked key.
    assert_eq!(
        listed(&configured, &short),
        ("expired", AccessKeyAccess::None, vec![inference(true)])
    );
    assert_eq!(
        listed(&configured, &revoked),
        ("revoked", AccessKeyAccess::None, vec![inference(true)])
    );
    // Unless the type itself was: removed, withdrawn, or cut shorter than
    // the key lasted.
    assert_eq!(
        listed(&named_types(30, true), &short).2,
        vec![inference(false)]
    );
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["packages"],
        &[],
        &access_key_types(),
    );
    assert_eq!(listed(&configured, &short).2, vec![inference(false)]);
    assert_eq!(listed(&configured, &revoked).2, vec![inference(false)]);
}

#[test]
fn a_person_s_options_name_the_problem_only_an_administrator_can_remove() {
    let (_temp, store) = fixture();
    let problem = |id: &str| {
        store
            .portal_access_key_options(&access_key_types(), id)
            .unwrap()
            .problem
    };
    let alice = session(&store, "usr-alice");
    let issued = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let now = time(&issued.record.created_at) + Duration::minutes(1);
    assert_eq!(problem("usr-alice"), None);

    // In as many groups as a resolution returns, her keys work.
    for index in 0..ACCESS_KEY_RESOLUTION_MAX_GROUPS {
        group(&store, &format!("team-{index:02}"), &["usr-alice"]);
    }
    assert_eq!(problem("usr-alice"), None);
    assert!(resolve_at(&store, &access_key_types(), &issued.key, now).is_active());

    // One more local group and no key of hers resolves: the options name
    // the reason, which is the status her keys list, and a mint is refused
    // for it, since the key could not work.
    group(&store, "team-64", &["usr-alice"]);
    assert_eq!(
        problem("usr-alice"),
        Some(AccessKeyInactiveReason::GroupLimitExceeded)
    );
    assert_eq!(
        reason(resolve_at(&store, &access_key_types(), &issued.key, now)),
        AccessKeyInactiveReason::GroupLimitExceeded
    );
    assert_eq!(
        views_of(&store, Some("usr-alice"), false, false)[0].status,
        AccessKeyStatus::Inactive(AccessKeyInactiveReason::GroupLimitExceeded)
    );
    let options = store
        .portal_access_key_options(&access_key_types(), "usr-alice")
        .unwrap();
    assert_eq!(options.refusal, Some(AccessKeyRefusal::GroupLimitExceeded));
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::GroupLimitExceeded
    );
    assert!(options.has_keys);
    // A disabled group is not a group she holds.
    let set_status = |status: &str| {
        store
            .patch_group(
                GroupPatchRequest {
                    group_id: "team-64".into(),
                    display_name: None,
                    description: None,
                    status: Some(status.into()),
                    auto_enroll_new_microsoft_users: None,
                    agent_token_issuance: None,
                    updated_by: "admin".into(),
                },
                &test_execution_contexts(),
            )
            .unwrap();
    };
    set_status("disabled");
    assert_eq!(problem("usr-alice"), None);
    set_status("active");

    // A name that cannot be used is reported first: it is what a mint
    // refuses, and what a resolution finds first.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &[],
        &["alice", "bob"],
    ));
    assert_eq!(
        problem("usr-alice"),
        Some(AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation)
    );
    assert_eq!(
        problem("usr-bob"),
        Some(AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation)
    );
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &["bob"],
        &[],
    ));
    assert_eq!(
        problem("usr-bob"),
        Some(AccessKeyInactiveReason::AccountUsernameReserved)
    );
    store.configure_account_usernames(policy());
    store
        .set_account_username_setting("usr-bob", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        problem("usr-bob"),
        Some(AccessKeyInactiveReason::NoAccountUsername)
    );
    assert_eq!(
        serde_json::to_value(problem("usr-bob")).unwrap(),
        json!("no_account_username")
    );

    // A person who may hold no type and owns no key has nothing to be told,
    // whatever their name and groups.
    store.set_principal_access_key_types_for_test("usr-bob", &[], &[], &access_key_types());
    assert_eq!(problem("usr-bob"), None);
    // One who owns a key is told why it does not work, as the key lists it.
    store.set_principal_access_key_types_for_test("usr-alice", &[], &[], &access_key_types());
    assert_eq!(
        problem("usr-alice"),
        Some(AccessKeyInactiveReason::GroupLimitExceeded)
    );
    assert_eq!(
        views_of(&store, Some("usr-alice"), false, false)[0].status,
        AccessKeyStatus::Inactive(AccessKeyInactiveReason::GroupLimitExceeded)
    );
}

#[test]
fn a_person_s_options_never_name_a_problem_a_resolution_would_not_find_first() {
    let (_temp, store) = fixture();
    let options = |id: &str| {
        store
            .portal_access_key_options(&access_key_types(), id)
            .unwrap()
    };
    // What the page tells the person: the problem, or else why no key can be
    // created. It must be the status every key of theirs lists.
    let told = |id: &str| {
        let options = options(id);
        let told = options
            .problem
            .map(|problem| serde_json::to_value(problem).unwrap())
            .or_else(|| options.refusal.map(|refusal| json!(refusal.as_str())));
        for view in views_of(&store, Some(id), false, false) {
            let status = match view.status {
                AccessKeyStatus::Inactive(reason) => Some(serde_json::to_value(reason).unwrap()),
                _ => None,
            };
            assert_eq!(status, told, "{id}");
        }
        told
    };
    let pause = |id: &str, paused: bool| {
        let version = store.identity_access(id).unwrap().version;
        store
            .set_identity_access_paused(id, paused, version, "admin")
            .unwrap();
    };
    let alice = session(&store, "usr-alice");
    mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    assert_eq!(told("usr-alice"), None);

    // Paused and with a name that cannot be used: a resolution finds the
    // pause first, so the options do not name the username over it.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &["alice"],
        &[],
    ));
    assert_eq!(told("usr-alice"), Some(json!("account_username_reserved")));
    pause("usr-alice", true);
    let paused = options("usr-alice");
    assert_eq!(paused.refusal, Some(AccessKeyRefusal::IdentityAccessPaused));
    assert_eq!(paused.problem, None);
    assert_eq!(told("usr-alice"), Some(json!("identity_access_paused")));
    // Disabled comes before both.
    store.set_principal_enabled("usr-alice", false).unwrap();
    let disabled = options("usr-alice");
    assert_eq!(disabled.refusal, Some(AccessKeyRefusal::PrincipalDisabled));
    assert_eq!(disabled.problem, None);
    assert_eq!(told("usr-alice"), Some(json!("principal_disabled")));
    store.set_principal_enabled("usr-alice", true).unwrap();
    // Paused and in too many groups, with a usable name.
    store.configure_account_usernames(policy());
    for index in 0..=ACCESS_KEY_RESOLUTION_MAX_GROUPS {
        group(&store, &format!("team-{index:02}"), &["usr-alice"]);
    }
    assert_eq!(options("usr-alice").problem, None);
    assert_eq!(told("usr-alice"), Some(json!("identity_access_paused")));
    pause("usr-alice", false);
    assert_eq!(
        options("usr-alice").problem,
        Some(AccessKeyInactiveReason::GroupLimitExceeded)
    );
    assert_eq!(told("usr-alice"), Some(json!("group_limit_exceeded")));

    // Bob may hold only a type an administrator issues, and owns no key:
    // nothing of his can be stopped, so there is no problem to name, though
    // a mint of his own is still refused for the name.
    store.set_principal_access_key_types_for_test("usr-bob", &["batch"], &[], &access_key_types());
    store
        .set_account_username_setting("usr-bob", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    let bob = options("usr-bob");
    assert_eq!(bob.access_key_types.len(), 1);
    assert!(!bob.access_key_types[0].self_service);
    assert!(!bob.has_keys);
    assert_eq!(bob.refusal, Some(AccessKeyRefusal::NoAccountUsername));
    assert_eq!(bob.problem, None);
    // Nor do too many groups make one.
    store
        .set_account_username_setting("usr-bob", &AccountUsernameSetting::FromEmail, "admin")
        .unwrap()
        .unwrap();
    for index in 0..=ACCESS_KEY_RESOLUTION_MAX_GROUPS {
        store
            .add_group("usr-bob", &format!("team-{index:02}"), "admin")
            .unwrap();
    }
    let bob = options("usr-bob");
    assert_eq!(bob.refusal, Some(AccessKeyRefusal::GroupLimitExceeded));
    assert_eq!(bob.problem, None);
    // Once he owns a key, which an administrator can issue only while he
    // is in few enough groups, the problem stops something of his and he
    // is told.
    assert_eq!(
        refusal(mint_admin(&store, "usr-bob", &["batch"], HOUR)),
        AccessKeyRefusal::GroupLimitExceeded
    );
    store.remove_group("usr-bob", "team-00").unwrap();
    mint_admin(&store, "usr-bob", &["batch"], HOUR).unwrap();
    store.add_group("usr-bob", "team-00", "admin").unwrap();
    let bob = options("usr-bob");
    assert!(bob.has_keys);
    assert_eq!(
        bob.problem,
        Some(AccessKeyInactiveReason::GroupLimitExceeded)
    );
    assert_eq!(told("usr-bob"), Some(json!("group_limit_exceeded")));
}

#[test]
fn no_key_is_issued_for_an_account_whose_keys_could_not_resolve() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    // A key each account already holds: it must be left as it is, saying
    // why it does not resolve.
    let held = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let robot_held = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    let keys = |id: &str| views_of(&store, Some(id), true, true).len();

    // Both ways of issuing refuse with the account's problem, as its code,
    // and the keys already held list that problem and are otherwise
    // untouched. A person's own request is refused for it before any type
    // is judged: a type they may not hold is not said.
    let refused = |id: &str, expected: AccessKeyInactiveReason| {
        let problem = store.access_key_account_problem(id).unwrap();
        assert_eq!(problem, Some(expected), "{id}");
        let before = keys(id);
        let by_administrator = mint_admin(&store, id, &["inference"], HOUR).unwrap_err();
        assert_eq!(by_administrator.refusal.as_str(), expected.as_str(), "{id}");
        assert_eq!(by_administrator.access_key_type, None);
        if id == "usr-alice" {
            for requested in [&["inference"][..], &["research"], &["batch"], &["nonesuch"]] {
                let own = mint_portal(&store, id, &alice, requested, HOUR).unwrap_err();
                assert_eq!(own.refusal.as_str(), expected.as_str(), "{requested:?}");
                assert_eq!(own.access_key_type, None, "{requested:?}");
            }
            // Her options say the same of a request of her own.
            let options = store
                .portal_access_key_options(&access_key_types(), id)
                .unwrap();
            assert_eq!(
                options.refusal.map(AccessKeyRefusal::as_str),
                Some(expected.as_str())
            );
        }
        assert_eq!(keys(id), before, "{id}");
        for view in views_of(&store, Some(id), false, false) {
            assert_eq!(view.status, AccessKeyStatus::Inactive(expected), "{id}");
            assert_eq!(view.record.revoked_at, None);
        }
    };
    // Once the problem is gone, both ways issue again and the keys held
    // resolve again.
    let issues = |id: &str| {
        assert_eq!(store.access_key_account_problem(id).unwrap(), None, "{id}");
        mint_admin(&store, id, &["inference"], HOUR).unwrap();
        if id == "usr-alice" {
            mint_portal(&store, id, &alice, &["inference"], HOUR).unwrap();
        }
        for view in views_of(&store, Some(id), false, false) {
            assert_eq!(view.status, AccessKeyStatus::Active, "{id}");
        }
    };
    let now = || Utc::now() + Duration::seconds(1);
    for id in ["usr-alice", "robot"] {
        issues(id);

        // More local groups than a resolution returns.
        for index in 0..=ACCESS_KEY_RESOLUTION_MAX_GROUPS {
            let group_id = format!("crowd-{index:02}");
            if id == "usr-alice" {
                group(&store, &group_id, &[id]);
            } else {
                store.add_group(id, &group_id, "admin").unwrap();
            }
        }
        refused(id, AccessKeyInactiveReason::GroupLimitExceeded);
        store.remove_group(id, "crowd-00").unwrap();
        issues(id);

        // Disabled.
        store.set_principal_enabled(id, false).unwrap();
        refused(id, AccessKeyInactiveReason::PrincipalDisabled);
        store.set_principal_enabled(id, true).unwrap();
        issues(id);

        // A reserved name, which also bars a service account's ID.
        store.configure_account_usernames(AccountUsernamePolicy::for_test(
            &["example.com"],
            &["alice", "robot"],
            &[],
        ));
        refused(id, AccessKeyInactiveReason::AccountUsernameReserved);
        store.configure_account_usernames(policy());
        issues(id);
    }

    // What only a person can be in: a name that awaits confirmation, no
    // name, and identity access that is paused or has no record.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &[],
        &["alice"],
    ));
    refused(
        "usr-alice",
        AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation,
    );
    store.configure_account_usernames(policy());
    issues("usr-alice");
    let pause = |paused: bool| {
        let version = store.identity_access("usr-alice").unwrap().version;
        store
            .set_identity_access_paused("usr-alice", paused, version, "admin")
            .unwrap();
    };
    pause(true);
    refused("usr-alice", AccessKeyInactiveReason::IdentityAccessPaused);
    pause(false);
    issues("usr-alice");
    // Bob, who holds no key: no name, and then no gate.
    store
        .set_account_username_setting("usr-bob", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        refusal(mint_admin(&store, "usr-bob", &["inference"], HOUR)),
        AccessKeyRefusal::NoAccountUsername
    );
    store
        .set_account_username_setting("usr-bob", &AccountUsernameSetting::FromEmail, "admin")
        .unwrap()
        .unwrap();
    mint_admin(&store, "usr-bob", &["inference"], HOUR).unwrap();
    sql(
        &store,
        "DELETE FROM principal_identity_access WHERE principal_id = 'usr-alice'",
    );
    refused("usr-alice", AccessKeyInactiveReason::IdentityAccessMissing);
    // Nothing above ended a key: every one of them is as it was issued.
    for key in [&held, &robot_held] {
        let stored = store.access_key(&key.record.key_id).unwrap().unwrap();
        assert_eq!(
            (&stored.revoked_at, &stored.expires_at),
            (&None, &key.record.expires_at)
        );
    }
    assert!(resolve_at(&store, &access_key_types(), &robot_held.key, now()).is_active());
}

#[test]
fn an_account_s_problem_is_the_status_every_key_of_it_lists() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    mint_admin(&store, "usr-alice", &["batch"], HOUR).unwrap();
    mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    // The problem of an account, which must be the status of each of its
    // keys: both are what a resolution finds first in the account.
    let problem = |id: &str| {
        let problem = store.access_key_account_problem(id).unwrap();
        let listed = views_of(&store, Some(id), false, false);
        assert!(!listed.is_empty(), "{id}");
        for view in listed {
            assert_eq!(
                view.status,
                problem.map_or(AccessKeyStatus::Active, AccessKeyStatus::Inactive),
                "{id}"
            );
        }
        problem
    };
    for id in ["usr-alice", "robot"] {
        assert_eq!(problem(id), None, "{id}");
        // Disabled.
        store.set_principal_enabled(id, false).unwrap();
        assert_eq!(
            problem(id),
            Some(AccessKeyInactiveReason::PrincipalDisabled),
            "{id}"
        );
        store.set_principal_enabled(id, true).unwrap();
        // More local groups than a resolution returns.
        for index in 0..=ACCESS_KEY_RESOLUTION_MAX_GROUPS {
            let group_id = format!("crowd-{index:02}");
            if id == "usr-alice" {
                group(&store, &group_id, &[id]);
            } else {
                store.add_group(id, &group_id, "admin").unwrap();
            }
        }
        assert_eq!(
            problem(id),
            Some(AccessKeyInactiveReason::GroupLimitExceeded),
            "{id}"
        );
        store.remove_group(id, "crowd-00").unwrap();
        assert_eq!(problem(id), None, "{id}");
    }

    // A person's identity access paused; a service account has no gate.
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", true, version, "admin")
        .unwrap();
    assert_eq!(
        problem("usr-alice"),
        Some(AccessKeyInactiveReason::IdentityAccessPaused)
    );
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", false, version, "admin")
        .unwrap();

    // A name that cannot be used: awaiting confirmation, reserved, none.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &[],
        &["alice"],
    ));
    assert_eq!(
        problem("usr-alice"),
        Some(AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation)
    );
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &["alice", "robot"],
        &[],
    ));
    for id in ["usr-alice", "robot"] {
        assert_eq!(
            problem(id),
            Some(AccessKeyInactiveReason::AccountUsernameReserved),
            "{id}"
        );
    }
    store.configure_account_usernames(policy());
    assert_eq!(problem("usr-alice"), None);
    // Released, her keys are of an earlier name: that is each key's own
    // status, and the account's problem is that it has no name.
    store
        .set_account_username_setting("usr-alice", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        store.access_key_account_problem("usr-alice").unwrap(),
        Some(AccessKeyInactiveReason::NoAccountUsername)
    );
    assert_eq!(
        views_of(&store, Some("usr-alice"), false, false)[0].status,
        AccessKeyStatus::Inactive(AccessKeyInactiveReason::NoAccountUsername)
    );
    // The first cause a resolution finds is the one reported.
    store.set_principal_enabled("usr-alice", false).unwrap();
    assert_eq!(
        store.access_key_account_problem("usr-alice").unwrap(),
        Some(AccessKeyInactiveReason::PrincipalDisabled)
    );
    assert!(matches!(
        store.access_key_account_problem("missing"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[test]
fn a_name_s_view_counts_the_live_keys_a_change_of_the_name_would_end() {
    let (_temp, store) = fixture();
    let live_keys = |id: &str| store.principal_account_username(id).unwrap().live_keys;
    assert_eq!(live_keys("usr-alice"), 0);
    let alice = session(&store, "usr-alice");
    let kept = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    let revoked = mint_portal(&store, "usr-alice", &alice, &["inference"], HOUR).unwrap();
    mint_admin(&store, "usr-alice", &["batch"], HOUR).unwrap();
    mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    assert_eq!(live_keys("usr-alice"), 3);
    assert_eq!(live_keys("robot"), 1);
    assert_eq!(live_keys("usr-bob"), 0);
    // A revoked key is not one a rename would end.
    store
        .revoke_access_key(&revoked.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(live_keys("usr-alice"), 2);
    // The count is what the change then reports, and the keys of the name
    // held afterwards start from none.
    let renamed = store
        .set_account_username("usr-alice", "alice.renamed", "admin")
        .unwrap()
        .unwrap();
    assert_eq!(renamed.ended_keys, 2);
    assert_eq!(renamed.view.live_keys, 0);
    assert_eq!(live_keys("usr-alice"), 0);
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &kept.key,
            time(&kept.record.created_at) + Duration::minutes(1)
        )),
        AccessKeyInactiveReason::UsernameIncarnationChanged
    );
    let outcome = renamed.outcome();
    assert_eq!(outcome["renamed"], json!(true));
    assert_eq!(outcome["endedKeys"], json!(2));
    assert_eq!(outcome["before"]["accountUsername"], json!("alice"));
    assert_eq!(outcome["after"]["accountUsername"], json!("alice.renamed"));
    assert_eq!(outcome["previousMode"], json!("from_email"));
    assert_eq!(outcome["mode"], json!("manual"));
    assert_eq!(outcome["reason"], json!(null));
    // Released: no name afterwards, and the reason.
    mint_admin(&store, "usr-alice", &["batch"], HOUR).unwrap();
    let released = store
        .set_account_username_setting("usr-alice", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        released.outcome(),
        json!({
            "previousMode": "manual",
            "mode": "manual",
            "before": released.before,
            "after": null,
            "renamed": true,
            "endedKeys": 1,
            "reason": "not_set",
            "conflict": null,
        })
    );
}

#[test]
fn a_person_s_options_are_the_types_they_may_hold_now_and_why_they_can_create_none() {
    let (_temp, store) = fixture();
    let options = |id: &str| {
        let options = store
            .portal_access_key_options(&access_key_types(), id)
            .unwrap();
        (
            options
                .account_username
                .and_then(|view| view.name)
                .map(|name| (name.account_username, name.state)),
            options.refusal,
            options
                .access_key_types
                .into_iter()
                .map(|access_key_type| access_key_type.id)
                .collect::<Vec<_>>(),
        )
    };
    let ids = |ids: &[&str]| ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
    // The types her access allows, `batch` included although only an
    // administrator issues it; not `research`, which only its group allows.
    assert_eq!(
        options("usr-alice"),
        (
            Some(("alice".to_string(), AccountUsernameState::Usable)),
            None,
            ids(&["batch", "inference", "packages"]),
        )
    );
    assert_eq!(
        store
            .portal_access_key_options(&access_key_types(), "usr-alice")
            .unwrap()
            .access_key_types
            .into_iter()
            .map(|access_key_type| (access_key_type.id, access_key_type.self_service))
            .collect::<Vec<_>>(),
        [
            ("batch".to_string(), false),
            ("inference".to_string(), true),
            ("packages".to_string(), true),
        ]
    );
    group(&store, "research", &["usr-alice"]);
    assert_eq!(
        options("usr-alice").2,
        ids(&["batch", "inference", "packages", "research"])
    );
    assert_eq!(
        options("usr-bob").2,
        ids(&["batch", "inference", "packages"])
    );
    // Her account's deny removes a type, whatever her group allows.
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference", "packages"],
        &["research"],
        &access_key_types(),
    );
    assert_eq!(options("usr-alice").2, ids(&["inference", "packages"]));
    store.set_principal_access_key_types_for_test(
        "usr-alice",
        &["inference", "packages"],
        &[],
        &access_key_types(),
    );

    // What the options say is what a mint decides.
    let alice = session(&store, "usr-alice");
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", true, version, "admin")
        .unwrap();
    assert_eq!(
        options("usr-alice").1,
        Some(AccessKeyRefusal::IdentityAccessPaused)
    );
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::IdentityAccessPaused
    );
    let version = store.identity_access("usr-alice").unwrap().version;
    store
        .set_identity_access_paused("usr-alice", false, version, "admin")
        .unwrap();

    store
        .set_account_username_setting("usr-alice", &AccountUsernameSetting::ManualNone, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        options("usr-alice"),
        (
            None,
            Some(AccessKeyRefusal::NoAccountUsername),
            vec![
                "inference".to_string(),
                "packages".to_string(),
                "research".to_string()
            ],
        )
    );
    assert_eq!(
        refusal(mint_portal(
            &store,
            "usr-alice",
            &alice,
            &["inference"],
            HOUR
        )),
        AccessKeyRefusal::NoAccountUsername
    );
    // A name that awaits confirmation is shown with its state.
    store.configure_account_usernames(AccountUsernamePolicy::for_test(
        &["example.com"],
        &[],
        &["bob"],
    ));
    assert_eq!(
        options("usr-bob"),
        (
            Some((
                "bob".to_string(),
                AccountUsernameState::AwaitingConfirmation
            )),
            Some(AccessKeyRefusal::AccountUsernameAwaitingConfirmation),
            ids(&["batch", "inference", "packages"]),
        )
    );
    // A service account creates nothing for itself.
    assert_eq!(options("robot").1, Some(AccessKeyRefusal::OwnerKind));
    assert!(matches!(
        store.portal_access_key_options(&access_key_types(), "missing"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[test]
fn no_broker_token_path_accepts_an_access_key() {
    let (_temp, store) = fixture();
    let issued = mint_admin(&store, "robot", &["inference"], HOUR).unwrap();
    assert!(issued.key.starts_with("aab_"));
    assert!(matches!(
        store.resolve_broker_token(&hasher(), &issued.key),
        Err(ManagedStoreError::BrokerTokenNotFound)
    ));
    assert!(matches!(
        store.resolve_browser_session(&hasher(), &issued.key),
        Err(ManagedStoreError::BrokerTokenNotFound)
    ));
    assert_eq!(
        store
            .revoke_application_token(&hasher(), "example-runner", &issued.key)
            .unwrap(),
        ApplicationRevocation::Unknown
    );
    // Neither does resolution accept a Broker token.
    let agent = store
        .issue_broker_token(
            &hasher(),
            BrokerTokenIssueRequest {
                principal_id: "robot".into(),
                name: "agent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"readOnly": true, "allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    assert_eq!(
        reason(resolve_at(
            &store,
            &access_key_types(),
            &agent.token,
            Utc::now()
        )),
        AccessKeyInactiveReason::Malformed
    );
    assert!(resolve_at(&store, &access_key_types(), &issued.key, Utc::now()).is_active());
}

const INACTIVE_WIRE_REASONS: [AccessKeyInactiveReason; 12] = [
    AccessKeyInactiveReason::Revoked,
    AccessKeyInactiveReason::Expired,
    AccessKeyInactiveReason::PrincipalDisabled,
    AccessKeyInactiveReason::IdentityAccessPaused,
    AccessKeyInactiveReason::IdentityAccessMissing,
    AccessKeyInactiveReason::OriginUnsupported,
    AccessKeyInactiveReason::NoAccountUsername,
    AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation,
    AccessKeyInactiveReason::AccountUsernameReserved,
    AccessKeyInactiveReason::UsernameIncarnationChanged,
    AccessKeyInactiveReason::GroupLimitExceeded,
    AccessKeyInactiveReason::NoAccessKeyType,
];

fn assert_stored_inactive_wire(
    resolution: AccessKeyResolution,
    key_id: &str,
    reason: AccessKeyInactiveReason,
    owner: Option<(AccessKeySubjectKind, &str)>,
) {
    let owner = owner.map(|(kind, id)| AccessKeySubject {
        kind,
        id: id.into(),
    });
    assert_eq!(
        serde_json::to_value(&resolution).unwrap(),
        json!({"active": false, "keyId": key_id, "owner": owner, "reason": reason})
    );
}

#[test]
fn stored_inactive_answers_identify_the_current_usable_owner_for_every_reason() {
    use AccessKeyInactiveReason::*;
    for expected in INACTIVE_WIRE_REASONS {
        let (_temp, store) = fixture();
        let config = access_key_types();
        let mut issued = match expected {
            Revoked => mint_portal(
                &store,
                "usr-alice",
                &session(&store, "usr-alice"),
                &["inference"],
                HOUR,
            ),
            Expired => mint_admin(&store, "robot", &["inference"], HOUR),
            _ => mint_admin(&store, "usr-alice", &["inference"], HOUR),
        }
        .unwrap();
        let mut at = time(&issued.record.created_at) + Duration::seconds(1);
        match expected {
            Revoked => {
                store
                    .revoke_access_key(&issued.record.key_id, None, "admin")
                    .unwrap()
                    .unwrap();
                store
                    .set_account_username("usr-alice", "alice.current", "admin")
                    .unwrap()
                    .unwrap();
            }
            Expired => {
                at = time(issued.record.expires_at.as_deref().unwrap());
            }
            PrincipalDisabled => {
                store.set_principal_enabled("usr-alice", false).unwrap();
            }
            IdentityAccessPaused => {
                let version = store.identity_access("usr-alice").unwrap().version;
                store
                    .set_identity_access_paused("usr-alice", true, version, "admin")
                    .unwrap();
            }
            IdentityAccessMissing => {
                sql(
                    &store,
                    "DELETE FROM principal_identity_access WHERE principal_id = 'usr-alice'",
                );
            }
            OriginUnsupported => {
                // Seed a later-origin row without changing an immutable existing identity.
                let raw = format!("{ACCESS_KEY_PREFIX}{}", "Z".repeat(43));
                let conn = store.connection.lock().unwrap();
                conn.execute(
                    "INSERT INTO access_keys
                     (key_id, key_hash, principal_id, name, origin, username_incarnation,
                      created_at, created_by, expires_at)
                     SELECT 'ak_wire_application', ?1, principal_id, name, 'application',
                            username_incarnation, created_at, created_by, expires_at
                     FROM access_keys WHERE key_id = ?2",
                    params![hasher().hash(&raw).unwrap(), issued.record.key_id],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO access_key_type_links (key_id, access_key_type, access_key_type_order)
                     VALUES ('ak_wire_application', 'inference', 0)", [],
                ).unwrap();
                issued.key = raw;
                issued.record.key_id = "ak_wire_application".into();
            }
            NoAccountUsername => {
                store
                    .set_account_username_setting(
                        "usr-alice",
                        &AccountUsernameSetting::ManualNone,
                        "admin",
                    )
                    .unwrap()
                    .unwrap();
            }
            AccountUsernameAwaitingConfirmation => {
                store.configure_account_usernames(AccountUsernamePolicy::for_test(
                    &["example.com"],
                    &[],
                    &["alice"],
                ));
            }
            AccountUsernameReserved => {
                store.configure_account_usernames(AccountUsernamePolicy::for_test(
                    &["example.com"],
                    &["alice"],
                    &[],
                ));
            }
            UsernameIncarnationChanged => {
                store
                    .set_account_username("usr-alice", "alice.renamed", "admin")
                    .unwrap()
                    .unwrap();
            }
            GroupLimitExceeded => {
                for index in 0..=ACCESS_KEY_RESOLUTION_MAX_GROUPS {
                    group(&store, &format!("wire-{index}"), &["usr-alice"]);
                }
            }
            NoAccessKeyType => {
                store.set_principal_access_key_types_for_test("usr-alice", &[], &[], &config);
            }
            Malformed | Unknown => unreachable!(),
        }
        let owner = match expected {
            NoAccountUsername | AccountUsernameAwaitingConfirmation | AccountUsernameReserved => {
                None
            }
            Revoked => Some((AccessKeySubjectKind::User, "alice.current")),
            Expired => Some((AccessKeySubjectKind::ServiceAccount, "robot")),
            UsernameIncarnationChanged => Some((AccessKeySubjectKind::User, "alice.renamed")),
            _ => Some((AccessKeySubjectKind::User, "alice")),
        };
        assert_stored_inactive_wire(
            resolve_at(&store, &config, &issued.key, at),
            &issued.record.key_id,
            expected,
            owner,
        );
        if expected == Expired {
            // Reuse the service-account key before expiry for both unusable-name policies.
            for policy in [
                AccountUsernamePolicy::for_test(&[], &["robot"], &[]),
                AccountUsernamePolicy::for_test(&[], &[], &["robot"]),
            ] {
                store.configure_account_usernames(policy);
                assert_stored_inactive_wire(
                    resolve_at(
                        &store,
                        &config,
                        &issued.key,
                        time(&issued.record.created_at),
                    ),
                    &issued.record.key_id,
                    AccountUsernameReserved,
                    None,
                );
            }
        }
    }
}

#[test]
fn unmatched_keys_never_disclose_owner_id_or_reason() {
    let (_temp, store) = fixture();
    for raw in [
        "aab_ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aab_ak_short",
        "another-kind",
    ] {
        let resolution = resolve_at(&store, &access_key_types(), raw, Utc::now());
        assert_eq!(
            serde_json::to_string(&resolution).unwrap(),
            r#"{"active":false}"#
        );
        assert_eq!(
            resolution,
            AccessKeyResolution::Inactive(AccessKeyInactive {
                reason: if is_access_key(raw) {
                    AccessKeyInactiveReason::Unknown
                } else {
                    AccessKeyInactiveReason::Malformed
                },
                key_id: None,
                owner: None,
            })
        );
    }
}

#[test]
fn longest_stored_inactive_answers_fit_the_existing_answer_bound() {
    let key_id = format!("ak_{}", "x".repeat(60));
    let id = "x".repeat(256);
    for reason in INACTIVE_WIRE_REASONS {
        for owner in [
            None,
            Some(AccessKeySubject {
                kind: AccessKeySubjectKind::User,
                id: id.clone(),
            }),
            Some(AccessKeySubject {
                kind: AccessKeySubjectKind::ServiceAccount,
                id: id.clone(),
            }),
        ] {
            let expected =
                json!({"active": false, "keyId": key_id, "owner": owner, "reason": reason});
            let answer = AccessKeyResolution::Inactive(AccessKeyInactive {
                reason,
                key_id: Some(key_id.clone()),
                owner,
            });
            let bytes = serde_json::to_vec(&answer).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                expected
            );
            assert!(bytes.len() <= largest_access_key_resolution_answer_bytes());
            assert!(bytes.len() <= ACCESS_KEY_RESOLUTION_MAX_ANSWER_BYTES);
        }
    }
}

#[test]
fn stored_inactive_answers_match_the_shared_endpoint_fixtures() {
    let index: Value = serde_json::from_str(&shared_fixture("index.json")).unwrap();
    let stored = index["answers"]["endpointInactiveForms"]["storedKey"]
        .as_array()
        .unwrap();
    assert_eq!(stored.len(), 3);
    for name in stored {
        let name = name.as_str().unwrap();
        let mut expected: Value = serde_json::from_str(&shared_fixture(name)).unwrap();
        let (_temp, store) = fixture();
        let config = access_key_types();
        let issued = if expected["owner"].is_null() || expected["owner"]["kind"] == json!("user") {
            if !expected["owner"].is_null() {
                assert_eq!(expected["owner"]["id"], "alice", "{name}");
            }
            mint_portal(
                &store,
                "usr-alice",
                &session(&store, "usr-alice"),
                &["inference"],
                HOUR,
            )
            .unwrap()
        } else {
            assert_eq!(expected["owner"]["kind"], "service_account", "{name}");
            let id = expected["owner"]["id"].as_str().unwrap();
            principal(&store, id, "service_account", None);
            store.set_principal_access_key_types_for_test(id, &["inference"], &[], &config);
            mint_admin(&store, id, &["inference"], HOUR).unwrap()
        };
        let mut at = time(&issued.record.created_at) + Duration::seconds(1);
        match expected["reason"].as_str().unwrap() {
            "revoked" => {
                store
                    .revoke_access_key(&issued.record.key_id, None, "admin")
                    .unwrap()
                    .unwrap();
            }
            "no_account_username" => {
                store
                    .set_account_username_setting(
                        "usr-alice",
                        &AccountUsernameSetting::ManualNone,
                        "admin",
                    )
                    .unwrap()
                    .unwrap();
            }
            "expired" => at = time(issued.record.expires_at.as_deref().unwrap()),
            reason => panic!("unsupported stored fixture reason {reason}: {name}"),
        }
        // The fixture's owner and reason remain authoritative. Only the
        // freshly generated key ID differs from its representative value.
        expected["keyId"] = json!(issued.record.key_id);
        assert_eq!(
            serde_json::to_value(resolve_at(&store, &config, &issued.key, at)).unwrap(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn stored_inactive_wire_reasons_match_the_shared_index() {
    let index: Value = serde_json::from_str(&shared_fixture("index.json")).unwrap();
    assert_eq!(
        serde_json::to_value(INACTIVE_WIRE_REASONS).unwrap(),
        index["inactiveReasons"]
    );
}

#[test]
fn access_key_id_grammar_excludes_broker_secrets() {
    for id in [
        "ak_a".to_string(),
        "ak_Az09_-".to_string(),
        format!("ak_{}", "a".repeat(60)),
    ] {
        assert!(is_access_key_id(&id));
    }
    for id in [
        "ak_".to_string(),
        "AK_a".to_string(),
        "ak_a.b".to_string(),
        "ak_a/b".to_string(),
        "ak_é".to_string(),
        "ak_a\n".to_string(),
        format!("ak_{}", "a".repeat(61)),
    ] {
        assert!(!is_access_key_id(&id));
    }
    for prefix in [
        "aab_",
        "aab_ak_",
        "aab_ai_",
        "aab_um_",
        "aab_ad_",
        "aab_future_",
    ] {
        assert!(!is_access_key_id(&format!("ak_{prefix}{}", "A".repeat(43))));
    }
}

fn lifetime_type(id: &str, choices: &[&str]) -> AccessKeyType {
    AccessKeyType {
        lifetime_options: choices.iter().map(|value| (*value).into()).collect(),
        default_lifetime: choices[0].into(),
        ..access_key_type(id, HOUR)
    }
}

#[test]
fn issuance_matches_every_types_offered_lifetime_after_account_and_type_checks() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let types = AccessKeyTypes::for_test([
        lifetime_type("inference", &["2h", "60m", "never"]),
        lifetime_type("packages", &["1h", "never"]),
    ]);
    for administrator in [false, true] {
        let issue = |requested: &[&str], lifetime: &str| {
            if administrator {
                let mut request = admin_request("usr-alice", requested, HOUR);
                request.lifetime = lifetime.into();
                store
                    .mint_administrator_access_key(&hasher(), &types, &request)
                    .unwrap()
            } else {
                let mut request = portal_request("usr-alice", &alice, requested, HOUR);
                request.lifetime = lifetime.into();
                store
                    .mint_portal_access_key(&hasher(), &types, &request)
                    .unwrap()
            }
        };
        for lifetime in ["3600s", "60m", "01h", "never"] {
            let issued = issue(&["inference", "packages"], lifetime).unwrap();
            if lifetime == "never" {
                assert_eq!(issued.record.expires_at, None);
            } else {
                assert_eq!(
                    time(issued.record.expires_at.as_deref().unwrap())
                        - time(&issued.record.created_at),
                    Duration::hours(1)
                );
            }
        }
        for (requested, lifetime, first) in [
            (vec!["inference", "packages"], "2h", "packages"),
            (vec!["inference", "packages"], "30m", "inference"),
            (vec!["packages", "inference"], "30m", "packages"),
        ] {
            let refused = issue(&requested, lifetime).unwrap_err();
            assert_eq!(refused.refusal, AccessKeyRefusal::LifetimeNotOffered);
            assert_eq!(refused.access_key_type.as_deref(), Some(first));
            assert_eq!(
                refused.audit_details(),
                json!({"refusal": "lifetime_not_offered", "accessKeyType": first})
            );
        }
        let refused = issue(&["inference", "missing"], "30m").unwrap_err();
        assert_eq!(
            refused.refusal,
            if administrator {
                AccessKeyRefusal::AccessKeyTypeUnknown
            } else {
                AccessKeyRefusal::AccessKeyTypeNotEligible
            }
        );
        store.set_principal_enabled("usr-alice", false).unwrap();
        assert_eq!(
            issue(&["missing"], "30m").unwrap_err().refusal,
            AccessKeyRefusal::PrincipalDisabled
        );
        store.set_principal_enabled("usr-alice", true).unwrap();
    }
}

#[test]
fn never_expiry_is_stored_listed_counted_and_immutable_in_both_null_directions() {
    let (_temp, store) = fixture();
    let types = AccessKeyTypes::for_test([lifetime_type("inference", &["1h", "never"])]);
    let mut request = admin_request("usr-alice", &["inference"], HOUR);
    request.lifetime = "never".into();
    let never = store
        .mint_administrator_access_key(&hasher(), &types, &request)
        .unwrap()
        .unwrap();
    request.lifetime = "1h".into();
    let finite = store
        .mint_administrator_access_key(&hasher(), &types, &request)
        .unwrap()
        .unwrap();
    let later = time(&never.record.created_at) + Duration::days(4000);
    let views = store
        .list_access_key_views_at(&types, &AccessKeyListFilter::default(), later)
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].record.key_id, never.record.key_id);
    assert_eq!(views[0].record.expires_at, None);
    assert_eq!(views[0].status, AccessKeyStatus::Active);
    assert_eq!(views[0].usable_access_key_types[0].valid_until, None);
    let serialized = serde_json::to_value(&views[0]).unwrap();
    assert!(serialized.as_object().unwrap().contains_key("expiresAt"));
    assert_eq!(serialized["expiresAt"], Value::Null);
    assert_eq!(
        store
            .principal_account_username("usr-alice")
            .unwrap()
            .live_keys,
        2
    );
    let refs = store
        .access_key_types_still_referenced(&AccessKeyTypes::default())
        .unwrap();
    assert_eq!(
        refs.iter()
            .find(|item| item.access_key_type == "inference")
            .unwrap()
            .unexpired_keys,
        2
    );
    {
        let conn = store.connection.lock().unwrap();
        assert!(
            conn.execute(
                "UPDATE access_keys SET expires_at = '2099-01-01T00:00:00Z' WHERE key_id = ?1",
                [&never.record.key_id]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE access_keys SET expires_at = NULL WHERE key_id = ?1",
                [&finite.record.key_id]
            )
            .is_err()
        );
        assert_eq!(
            conn.execute(
                "UPDATE access_keys SET expires_at = NULL WHERE key_id = ?1",
                [&never.record.key_id]
            )
            .unwrap(),
            1
        );
        validate_structure(&conn).unwrap();
    }
    assert_eq!(
        store
            .set_account_username("usr-alice", "renamed-alice", "admin")
            .unwrap()
            .unwrap()
            .ended_keys,
        2
    );
    assert_eq!(
        reason(resolve_at(&store, &types, &never.key, later)),
        AccessKeyInactiveReason::UsernameIncarnationChanged
    );
    store
        .revoke_access_key(&never.record.key_id, None, "admin")
        .unwrap()
        .unwrap();
    assert_eq!(
        reason(resolve_at(&store, &types, &never.key, later)),
        AccessKeyInactiveReason::Revoked
    );
}

#[test]
fn current_type_options_bound_old_keys_without_changing_their_stored_expiry() {
    let (_temp, store) = fixture();
    let unlimited = AccessKeyTypes::for_test([lifetime_type("inference", &["1h", "never"])]);
    let mut request = admin_request("usr-alice", &["inference"], HOUR);
    request.lifetime = "never".into();
    let never = store
        .mint_administrator_access_key(&hasher(), &unlimited, &request)
        .unwrap()
        .unwrap();
    request.lifetime = "1h".into();
    let finite = store
        .mint_administrator_access_key(&hasher(), &unlimited, &request)
        .unwrap()
        .unwrap();
    let created = time(&never.record.created_at);
    let shorter = AccessKeyTypes::for_test([lifetime_type("inference", &["30m"])]);
    let finite_type = AccessKeyTypes::for_test([lifetime_type("inference", &["1h"])]);
    let before = created + Duration::minutes(10);
    let never_facts = active(resolve_at(&store, &unlimited, &never.key, before));
    assert_eq!(never_facts.expires_at, None);
    assert_eq!(never_facts.access_key_types[0].valid_until, None);
    let limited = active(resolve_at(&store, &finite_type, &never.key, before));
    assert_eq!(limited.expires_at, None);
    assert_eq!(
        limited.access_key_types[0].valid_until,
        Some(normalized_timestamp(created + Duration::hours(1)))
    );
    for key in [&never, &finite] {
        let facts = active(resolve_at(&store, &shorter, &key.key, before));
        assert_eq!(
            facts.access_key_types[0].valid_until,
            Some(normalized_timestamp(
                time(&key.record.created_at) + Duration::minutes(30)
            ))
        );
        assert_eq!(
            reason(resolve_at(
                &store,
                &shorter,
                &key.key,
                created + Duration::minutes(31)
            )),
            AccessKeyInactiveReason::NoAccessKeyType
        );
    }
    let finite_facts = active(resolve_at(&store, &unlimited, &finite.key, before));
    assert_eq!(finite_facts.expires_at, finite.record.expires_at);
    assert_eq!(
        finite_facts.access_key_types[0].valid_until,
        finite.record.expires_at
    );
    let after = created + Duration::hours(2);
    assert_eq!(
        reason(resolve_at(&store, &unlimited, &finite.key, after)),
        AccessKeyInactiveReason::Expired
    );
    assert!(resolve_at(&store, &unlimited, &never.key, after).is_active());
    assert_eq!(
        reason(resolve_at(&store, &finite_type, &never.key, after)),
        AccessKeyInactiveReason::NoAccessKeyType
    );
}

#[test]
fn never_expiring_store_answers_match_the_shared_fixtures() {
    let (_temp, store) = fixture();
    group(&store, "platform", &["usr-alice"]);
    let request: Value = serde_json::from_str(&shared_fixture("request.valid.json")).unwrap();
    let key = request["key"].as_str().unwrap();
    {
        let conn = store.connection.lock().unwrap();
        conn.execute(
            "DELETE FROM account_usernames WHERE principal_id = 'usr-alice'",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO account_usernames (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by) VALUES ('alice', 'usr-alice', 'user', 'n1-7b0c2f', 'derived', '2026-11-01T00:00:00Z', 'admin')", []).unwrap();
        conn.execute("INSERT INTO access_keys (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at, created_by, expires_at) VALUES ('ak_01HZXK3Q8', ?1, 'usr-alice', 'laptop', 'portal', 'n1-7b0c2f', '2026-11-24T02:00:00Z', 'usr-alice', NULL)", [hasher().hash(key).unwrap()]).unwrap();
        conn.execute("INSERT INTO access_key_type_links (key_id, access_key_type, access_key_type_order) VALUES ('ak_01HZXK3Q8', 'inference', 0)", []).unwrap();
    }
    for (choices, fixture) in [
        (vec!["never"], "answer.active.never.json"),
        (vec!["7d"], "answer.active.never-finite-type.json"),
    ] {
        let types = AccessKeyTypes::for_test([lifetime_type("inference", &choices)]);
        let answer = resolve_at(&store, &types, key, time("2026-11-26T12:00:00Z"));
        let expected: Value = serde_json::from_str(&shared_fixture(fixture)).unwrap();
        assert_eq!(
            serde_json::to_value(&answer).unwrap(),
            expected,
            "{fixture}"
        );
    }
}

#[test]
fn malformed_lifetimes_are_input_errors_before_issuance_policy_without_echoing_values() {
    let (_temp, store) = fixture();
    let alice = session(&store, "usr-alice");
    let types = access_key_types();
    store.set_principal_enabled("usr-alice", false).unwrap();
    for value in [
        "",
        "0s",
        "-1h",
        "1 h",
        "Never",
        "never ",
        "3651d",
        "18446744073709551615d",
        "aab_ak_must_not_echo",
    ] {
        let mut own = portal_request("usr-alice", &alice, &["missing"], HOUR);
        own.lifetime = value.into();
        let mut admin = admin_request("usr-alice", &["missing"], HOUR);
        admin.lifetime = value.into();
        for error in [
            store
                .mint_portal_access_key(&hasher(), &types, &own)
                .unwrap_err(),
            store
                .mint_administrator_access_key(&hasher(), &types, &admin)
                .unwrap_err(),
        ] {
            let ManagedStoreError::InputInvalid(message) = error else {
                panic!("expected malformed-input error")
            };
            assert_eq!(
                message,
                "access key lifetime must be a positive duration of at most 3650d or never"
            );
        }
    }
}
