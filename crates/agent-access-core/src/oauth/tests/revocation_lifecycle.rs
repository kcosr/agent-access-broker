//! Remote revocation through the manager's lifecycle, with a fixture
//! dialect that speaks the `stub` wire and revokes through `/oauth/revoke`
//! as GitLab does: the local fence first, the encrypted pending revocation
//! kept in the same transaction, bounded retries, refreshes racing a fence,
//! uncertain refreshes, crash recovery and the reported states.
use super::*;
use crate::oauth::revocation::RemoteRevocation;
use agent_access_provider::{RevocationOutcome, TokenRevocation};
use std::time::Duration;

/// The `stub` dialect's wire with GitLab-style revocation: `POST
/// /oauth/revoke` with the token and its type hint; 2xx revokes, an
/// `invalid_token` error reports an already invalid token, 429 and 5xx are
/// retryable and anything else is final.
struct RevokingDialect;
pub(in crate::oauth::tests) static REVOKING_DIALECT:
    agent_access_provider::OAuthDialectRegistration =
    agent_access_provider::OAuthDialectRegistration::new(
        agent_access_provider::module_metadata!(),
        "revoking_fixture",
        &RevokingDialect,
    )
    .development_only();

fn stub() -> &'static dyn OAuthDialect {
    STUB_OAUTH_DIALECT.dialect()
}

#[async_trait::async_trait]
impl OAuthDialect for RevokingDialect {
    fn supports_revocation(&self) -> bool {
        true
    }
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
        stub().validate_registration(config)
    }
    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
        stub().upstream_allowlist(config)
    }
    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        stub().authorization_url(client, profile, request)
    }
    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        stub().callback_issuer(config)
    }
    fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay {
        stub().refresh_replay(config)
    }
    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        stub().exchange_code(http, client, exchange).await
    }
    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        stub()
            .refresh(http, client, profile, refresh_token, granted_scopes)
            .await
    }
    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<agent_access_provider::ConnectedIdentity, OAuthDialectError> {
        stub().identity(http, client, access_token).await
    }
    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        stub()
            .discover_targets(http, client, access_token, granted_scopes)
            .await
    }
    async fn revoke(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        revocation: TokenRevocation<'_>,
    ) -> Result<RevocationOutcome, OAuthDialectError> {
        let url = Url::parse(&client.config.base_url)
            .and_then(|base| base.join("oauth/revoke"))
            .map_err(|_| OAuthDialectError::Configuration)?;
        let request = http.request(reqwest::Method::POST, url).form(&[
            ("token", revocation.token),
            ("token_type_hint", revocation.token_type.hint()),
        ]);
        let response = http.send(request, "oauth.revoke").await?;
        match response.status() {
            200..=299 => Ok(RevocationOutcome::Revoked),
            429 => Err(OAuthDialectError::RetryAfter(1)),
            status if status >= 500 => Err(OAuthDialectError::Failed),
            _ => match response
                .json()
                .await
                .ok()
                .as_ref()
                .and_then(|body| body["error"].as_str())
            {
                Some("invalid_token") => Ok(RevocationOutcome::AlreadyInvalid),
                _ => Err(OAuthDialectError::RequestRejected),
            },
        }
    }
}

/// The lifecycle tests' `stub` registration, speaking the revoking fixture
/// dialect.
fn revoking_config(server: &MockServer, secret_file: &std::path::Path) -> OAuthConfig {
    let mut config = config(server, secret_file);
    config.registrations.get_mut("stub").unwrap().adapter = OAuthAdapter::new("revoking_fixture");
    config
}

async fn revoking_fixture() -> (
    tempfile::TempDir,
    ManagedStore,
    CredentialKeyRing,
    OAuthManager,
    MockServer,
) {
    let (dir, store, ring) = test_fixture();
    let server = MockServer::start().await;
    let secret_file = dir.path().join("client-secret");
    std::fs::write(&secret_file, "application-secret").unwrap();
    let manager = stub_manager(
        store.clone(),
        ring.clone(),
        revoking_config(&server, &secret_file),
    )
    .unwrap();
    manager.activate().unwrap();
    (dir, store, ring, manager, server)
}

async fn revoke_responds(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(response)
        .mount(server)
        .await;
}

/// Each revocation request's token and type hint, in order.
async fn revoked(server: &MockServer) -> Vec<(String, String)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/oauth/revoke")
        .map(|request| {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            (form["token"].clone(), form["token_type_hint"].clone())
        })
        .collect()
}

fn family(number: usize) -> BTreeSet<(String, String)> {
    BTreeSet::from([
        (
            format!("protected-refresh-{number}"),
            "refresh_token".to_owned(),
        ),
        (
            format!("protected-access-{number}"),
            "access_token".to_owned(),
        ),
    ])
}

/// A read-only connection to `store`'s database.
fn database(store: &ManagedStore) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(store.path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
}

/// `(cause, state, holds tokens)` of every stored revocation, oldest first.
fn stored(store: &ManagedStore) -> Vec<(String, String, bool)> {
    let conn = database(store);
    let mut statement = conn
        .prepare("SELECT cause,state,ciphertext IS NOT NULL FROM oauth_revocations ORDER BY created_at,revocation_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn revocation_ids(store: &ManagedStore) -> Vec<String> {
    let conn = database(store);
    let mut statement = conn
        .prepare("SELECT revocation_id FROM oauth_revocations ORDER BY created_at,revocation_id")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// How many stored revocations hold an encrypted payload.
fn revocation_keys(store: &ManagedStore) -> i64 {
    database(store)
        .query_row(
            "SELECT COUNT(*) FROM oauth_revocations WHERE key_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// Makes every stored revocation due now, as if its retry wait ended.
fn make_due(store: &ManagedStore) {
    test_sql(
        store,
        "UPDATE oauth_revocations SET due_at=0 WHERE ciphertext IS NOT NULL",
    );
}

fn due_in(store: &ManagedStore) -> i64 {
    let due: i64 = database(store)
        .query_row("SELECT MIN(due_at) FROM oauth_revocations", [], |row| {
            row.get(0)
        })
        .unwrap();
    due - now()
}

fn no_plaintext(dir: &tempfile::TempDir, tokens: &[&str]) {
    for name in ["oauth.sqlite", "oauth.sqlite-wal"] {
        if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
            for token in tokens {
                assert!(
                    !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                    "{token} in {name}"
                );
            }
        }
    }
}

/// Waits until the refresh attempt in flight is persisted.
async fn attempt_persisted(manager: &OAuthManager) {
    let started = std::time::Instant::now();
    while manager
        .read("user", "stub")
        .ok()
        .and_then(|slot| slot.connection)
        .is_none_or(|connection| connection.family.attempt.is_none())
    {
        assert!(started.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn disconnect_fences_first_then_revokes_every_known_family_member() {
    let (dir, store, ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    let lease = manager.acquire("user", &binding()).await.unwrap();
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::NotRequested
    );
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Revoked
    );
    assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::ReconnectRequired
    );
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0)
    );
    // A finished revocation keeps no token, only its answer.
    assert_eq!(
        stored(&store),
        [("disconnect".into(), "revoked".into(), false)]
    );
    assert_eq!(revocation_keys(&store), 0);
    store.check_ready(Some(&ring)).unwrap();
    no_plaintext(&dir, &["protected-refresh-0", "protected-access-0"]);
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Revoked
    );
    // Disconnecting again requests nothing more and still answers.
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Revoked
    );
    assert_eq!(revoked(&server).await.len(), 2);
    assert!(due_in(&store) > RETENTION_SECONDS_FOR_TESTS - 60);
}

const RETENTION_SECONDS_FOR_TESTS: i64 = crate::oauth::revocation::RETENTION_SECONDS;

/// Retryable failures are retried on a growing schedule, a bounded number
/// of times, from the stored record; local access never returns.
#[tokio::test]
async fn retryable_failures_are_bounded_and_never_restore_access() {
    let (dir, store, ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(503)).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::ReconnectRequired
    );
    // Encrypted while pending: the tokens appear nowhere in the database.
    no_plaintext(&dir, &["protected-refresh-0", "protected-access-0"]);
    assert_eq!(revocation_keys(&store), 1);
    assert_eq!(store.active_credential_key_ids().unwrap(), ["one"]);
    test_sql(&store, "DELETE FROM oauth_slots");
    assert!(store.check_ready(None).is_err());
    store.check_ready(Some(&ring)).unwrap();
    // Not due again until the first wait ends.
    assert!((25..=31).contains(&due_in(&store)));
    assert!((25..=30).contains(&manager.revoke_due().await.unwrap().unwrap().as_secs()));
    assert_eq!(revoked(&server).await.len(), 2);
    for (pass, wait) in [(2, 120), (3, 600), (4, 3600)] {
        make_due(&store);
        manager.revoke_due().await.unwrap();
        assert_eq!(revoked(&server).await.len(), 2 * pass);
        assert!((wait - 5..=wait + 1).contains(&due_in(&store)), "{pass}");
        assert_eq!(
            manager.remote_revocation("user", "stub").unwrap(),
            RemoteRevocation::Pending
        );
    }
    make_due(&store);
    assert_eq!(manager.revoke_due().await.unwrap(), None);
    assert_eq!(revoked(&server).await.len(), 10);
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Failed
    );
    assert_eq!(
        stored(&store),
        [("disconnect".into(), "failed".into(), false)]
    );
    assert_eq!(revocation_keys(&store), 0);
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::ReconnectRequired
    );
}

#[tokio::test]
async fn already_invalid_tokens_are_revoked_and_final_rejections_fail_at_once() {
    for (response, expected) in [
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error":"invalid_token"})),
            RemoteRevocation::Revoked,
        ),
        (
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"error":"unsupported_token_type"})),
            RemoteRevocation::Failed,
        ),
    ] {
        let (_dir, store, _ring, manager, server) = revoking_fixture().await;
        connected(&manager, &server).await;
        revoke_responds(&server, response).await;
        assert_eq!(manager.disconnect("user", "stub").await.unwrap(), expected);
        assert_eq!(revoked(&server).await.len(), 2);
        assert!(!stored(&store)[0].2);
    }
}

/// A process that dies with revocations pending resumes them from the
/// store: a restarted manager's pass completes them.
#[tokio::test]
async fn restart_resumes_pending_revocations_from_the_store() {
    let (_dir, store, ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    let config = manager.config().clone();
    drop(manager);
    let restarted = stub_manager(store.clone(), ring, config).unwrap();
    // A deactivated or unactivated manager makes no pass.
    assert_eq!(restarted.revoke_due().await.unwrap_err(), OAuthError::Stale);
    restarted.activate().unwrap();
    make_due(&store);
    assert_eq!(restarted.revoke_due().await.unwrap(), None);
    assert_eq!(
        restarted.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Revoked
    );
    assert_eq!(revoked(&server).await.len(), 4);
}

/// A consuming refresh whose response is lost keeps its predecessor for
/// revocation before clearing it; the successor may exist unknown to the
/// Broker, so the family is only ever unconfirmed.
#[tokio::test]
async fn lost_refresh_response_keeps_the_predecessor_and_is_unconfirmed() {
    let (_dir, store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    expire(&manager);
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{truncated"))
        .expect(1)
        .mount(&server)
        .await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::RefreshUncertain
    );
    assert_eq!(
        stored(&store),
        [("refresh_uncertain".into(), "unconfirmed".into(), true)]
    );
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Unconfirmed
    );
    manager.revoke_due().await.unwrap();
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0)
    );
    // Every known member is revoked, and it stays unconfirmed.
    assert_eq!(
        stored(&store),
        [("refresh_uncertain".into(), "unconfirmed".into(), false)]
    );
    // Disconnecting the fenced connection keeps nothing new and reports it.
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Unconfirmed
    );
    assert_eq!(stored(&store).len(), 1);
}

/// A refresh in flight when the owner disconnects is recorded with the
/// revocation. Its successful response is never installed: the successor
/// joins the revocation, and the family is revoked once both are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_refresh_success_after_disconnect_is_never_installed_and_is_revoked() {
    let (_dir, _store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    expire(&manager);
    server.reset().await;
    identity(&server).await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(token(1))
                .set_delay(Duration::from_millis(1500)),
        )
        .expect(1)
        .mount(&server)
        .await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    let refreshing = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.acquire("user", &binding()).await })
    };
    attempt_persisted(&manager).await;
    // The predecessor is revoked at once; the family waits for the refresh.
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0)
    );
    assert_eq!(refreshing.await.unwrap().unwrap_err(), OAuthError::Stale);
    assert_eq!(
        manager.status("user", "stub").unwrap().status,
        OAuthConnectionStatus::Disconnected
    );
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::ReconnectRequired
    );
    assert_eq!(manager.revoke_due().await.unwrap(), None);
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0).into_iter().chain(family(1)).collect()
    );
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Revoked
    );
}

/// A refresh in flight at the fence whose outcome is lost leaves an
/// unknown successor; one the provider rejects proves nothing was issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_refresh_failure_after_disconnect_settles_the_family() {
    for (response, expected) in [
        (
            ResponseTemplate::new(200).set_body_string("{truncated"),
            RemoteRevocation::Unconfirmed,
        ),
        (
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error":"invalid_grant"})),
            RemoteRevocation::Revoked,
        ),
    ] {
        let (_dir, _store, _ring, manager, server) = revoking_fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(response.set_delay(Duration::from_millis(1500)))
            .expect(1)
            .mount(&server)
            .await;
        revoke_responds(&server, ResponseTemplate::new(200)).await;
        let refreshing = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.acquire("user", &binding()).await })
        };
        attempt_persisted(&manager).await;
        assert_eq!(
            manager.disconnect("user", "stub").await.unwrap(),
            RemoteRevocation::Pending
        );
        assert!(refreshing.await.unwrap().is_err());
        assert_eq!(manager.remote_revocation("user", "stub").unwrap(), expected);
        assert_eq!(revoked(&server).await.len(), 2);
    }
}

/// Principal disablement in flight with a refresh: the late successor is
/// kept for revocation although its owner is disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_refresh_success_after_principal_disable_is_revoked() {
    let (_dir, store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    expire(&manager);
    server.reset().await;
    identity(&server).await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(token(1))
                .set_delay(Duration::from_millis(1500)),
        )
        .expect(1)
        .mount(&server)
        .await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    let refreshing = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.acquire("user", &binding()).await })
    };
    attempt_persisted(&manager).await;
    store.set_principal_enabled("user", false).unwrap();
    assert_eq!(
        stored(&store),
        [("principal_disabled".into(), "pending".into(), true)]
    );
    assert!(refreshing.await.unwrap().is_err());
    assert_eq!(manager.revoke_due().await.unwrap(), None);
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0).into_iter().chain(family(1)).collect()
    );
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Revoked
    );
    // Re-enabling restores nothing.
    store.set_principal_enabled("user", true).unwrap();
    assert_eq!(
        manager.status("user", "stub").unwrap().status,
        OAuthConnectionStatus::Disconnected
    );
}

/// A refresh attempt persisted by a process that died, or by another
/// process, is waited for until it expires: then its outcome is unknown.
#[tokio::test]
async fn refresh_attempt_of_a_dead_process_is_unconfirmed_once_it_expires() {
    let (_dir, store, ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    manager
        .update("user", "stub", |_, current| {
            let mut current = current.unwrap();
            let family = &mut current.connection.as_mut().unwrap().family;
            family.attempt = Some(RefreshAttempt {
                id: "dead-process-attempt".into(),
                material_version: family.material_version.clone(),
                expires_at: now() + ATTEMPT_TTL,
            });
            Ok((current, ()))
        })
        .unwrap();
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    assert_eq!(revoked(&server).await.len(), 2);
    // Due again just after the attempt expires.
    assert!((ATTEMPT_TTL - 5..=ATTEMPT_TTL + 1).contains(&due_in(&store)));
    let id = revocation_ids(&store).remove(0);
    store
        .oauth_revocation_update(&ring, &id, |row| {
            row.material
                .as_mut()
                .unwrap()
                .refresh_attempt
                .as_mut()
                .unwrap()
                .expires_at = now() - 1;
            row.due_at = 0;
        })
        .unwrap();
    // A restarted process finds it expired and not its own.
    let restarted = stub_manager(store.clone(), ring, manager.config().clone()).unwrap();
    restarted.activate().unwrap();
    assert_eq!(restarted.revoke_due().await.unwrap(), None);
    assert_eq!(
        restarted.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Unconfirmed
    );
    assert_eq!(revoked(&server).await.len(), 2);
}

/// A reconnect or an account replacement keeps the superseded family for
/// revocation in the install transaction; the new connection is unaffected.
#[tokio::test]
async fn replacing_consent_revokes_the_superseded_family() {
    for intent in [
        OAuthConnectIntent::Reconnect,
        OAuthConnectIntent::ReplaceAccount,
    ] {
        let (_dir, store, _ring, manager, server) = revoking_fixture().await;
        connected(&manager, &server).await;
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .mount(&server)
            .await;
        revoke_responds(&server, ResponseTemplate::new(200)).await;
        let state = start(&manager, intent).await;
        manager
            .complete(
                "user",
                "session",
                "stub",
                &state,
                "second-code",
                runtime(&manager),
            )
            .await
            .unwrap();
        assert_eq!(
            stored(&store),
            [("superseded".into(), "pending".into(), true)]
        );
        assert_eq!(manager.revoke_due().await.unwrap(), None);
        assert_eq!(
            revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
            family(0)
        );
        assert_eq!(
            manager.remote_revocation("user", "stub").unwrap(),
            RemoteRevocation::Revoked
        );
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap().token(),
            "protected-access-1"
        );
    }
}

/// Disablement ends the owner's connections and keeps their families in
/// its transaction; re-enabling restores nothing.
#[tokio::test]
async fn principal_disable_keeps_and_revokes_the_family() {
    let (_dir, store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    let lease = manager.acquire("user", &binding()).await.unwrap();
    store
        .patch_principal(crate::PrincipalPatchRequest {
            principal_id: "user".into(),
            display_name: None,
            email: None,
            status: Some("disabled".into()),
        })
        .unwrap();
    assert!(manager.validate_lease(&lease).is_err());
    assert_eq!(
        stored(&store),
        [("principal_disabled".into(), "pending".into(), true)]
    );
    assert_eq!(manager.revoke_due().await.unwrap(), None);
    assert_eq!(
        revoked(&server).await.into_iter().collect::<BTreeSet<_>>(),
        family(0)
    );
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Revoked
    );
    store.set_principal_enabled("user", true).unwrap();
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::ReconnectRequired
    );
}

/// A dialect that does not revoke keeps nothing: every end reports
/// `not_requested`.
#[tokio::test]
async fn non_revoking_dialects_keep_nothing_and_report_not_requested() {
    let (_dir, store, _ring, manager, server) = fixture().await;
    connected(&manager, &server).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::NotRequested
    );
    connected(&manager, &server).await;
    expire(&manager);
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{truncated"))
        .mount(&server)
        .await;
    assert_eq!(
        manager.acquire("user", &binding()).await.unwrap_err(),
        OAuthError::RefreshUncertain
    );
    store.set_principal_enabled("user", false).unwrap();
    assert!(stored(&store).is_empty());
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == "/oauth/revoke")
    );
    assert_eq!(
        manager.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::NotRequested
    );
}

/// A changed registration may have no client the provider accepts a
/// revocation from: pending revocations fail without a request, and so do
/// they when OAuth is disabled.
#[tokio::test]
async fn changed_or_disabled_registrations_fail_pending_revocations_without_requests() {
    let (_dir, store, ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(503)).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    let mut changed = manager.config().clone();
    changed.registrations.get_mut("stub").unwrap().client_id = "other-application".into();
    let changed = stub_manager(store.clone(), ring.clone(), changed).unwrap();
    changed.activate().unwrap();
    make_due(&store);
    assert_eq!(changed.revoke_due().await.unwrap(), None);
    assert_eq!(revoked(&server).await.len(), 2);
    assert_eq!(
        changed.remote_revocation("user", "stub").unwrap(),
        RemoteRevocation::Failed
    );
    // Disabling OAuth gives pending revocations a final outcome too.
    let (_dir, store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(503)).await;
    manager.disconnect("user", "stub").await.unwrap();
    OAuthManager::disable_all(&store).unwrap();
    assert_eq!(
        stored(&store),
        [("disconnect".into(), "failed".into(), false)]
    );
    assert_eq!(revocation_keys(&store), 0);
}

/// Fenced records of several ends of one registration report the most
/// severe state.
#[tokio::test]
async fn several_revocations_report_the_most_severe_state() {
    let (_dir, store, _ring, manager, server) = revoking_fixture().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(200)).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Revoked
    );
    server.reset().await;
    connected(&manager, &server).await;
    revoke_responds(&server, ResponseTemplate::new(503)).await;
    assert_eq!(
        manager.disconnect("user", "stub").await.unwrap(),
        RemoteRevocation::Pending
    );
    assert_eq!(stored(&store).len(), 2);
    // Finished revocations are pruned once their answering period ends.
    test_sql(
        &store,
        "UPDATE oauth_revocations SET due_at=0 WHERE ciphertext IS NULL",
    );
    manager.revoke_due().await.unwrap();
    assert_eq!(stored(&store).len(), 1);
}
