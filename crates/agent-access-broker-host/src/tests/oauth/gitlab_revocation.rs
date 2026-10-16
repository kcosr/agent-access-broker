//! GitLab remote revocation end to end through the management API, against
//! a stubbed GitLab `POST /oauth/revoke`: the states disconnect reports and
//! the connection rows show, a remote failure that never restores access,
//! the serving broker's revocation worker, principal disablement, and a
//! restart that resumes a pending revocation.
use super::*;

/// Mounts GitLab's revocation endpoint answering `response`.
async fn mount_revoke(gitlab: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(response)
        .mount(gitlab)
        .await;
}

/// The form of each revocation GitLab received, in order.
async fn revocations(gitlab: &MockServer) -> Vec<BTreeMap<String, String>> {
    gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == "/oauth/revoke")
        .map(|request| {
            url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect()
        })
        .collect()
}

/// `(token, token_type_hint)` of each revocation GitLab received.
async fn revoked_tokens(gitlab: &MockServer) -> BTreeSet<(String, String)> {
    revocations(gitlab)
        .await
        .into_iter()
        .map(|form| (form["token"].clone(), form["token_type_hint"].clone()))
        .collect()
}

fn first_family() -> BTreeSet<(String, String)> {
    BTreeSet::from([
        ("gitlab-refresh-1".to_owned(), "refresh_token".to_owned()),
        ("gitlab-access-1".to_owned(), "access_token".to_owned()),
    ])
}

impl OAuthFixture {
    async fn gitlab_rows(&self, request_id: &str) -> Vec<Value> {
        let response = self
            .browser(Method::GET, "/v1/oauth/connections", request_id, None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await["result"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn disconnect_gitlab(&self, request_id: &str) -> Value {
        let response = self
            .browser(
                Method::DELETE,
                "/v1/oauth/connections/gitlab",
                request_id,
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await["result"].clone()
    }

    /// The `remoteRevocation` of alice's `gitlab` row once it is `expected`,
    /// waiting for the serving broker's revocation worker.
    async fn await_remote_revocation(&self, expected: &str) {
        let started = std::time::Instant::now();
        loop {
            let rows = self.gitlab_rows("gitlab-revocation-poll").await;
            let state = rows
                .iter()
                .find(|row| row["registration"] == "gitlab")
                .map(|row| row["remoteRevocation"].clone());
            if state == Some(json!(expected)) {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "still {state:?}, expected {expected}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn store_path(&self) -> PathBuf {
        PathBuf::from(&self.config.managed_store.as_ref().unwrap().path)
    }

    /// `(cause, state, holds tokens)` of every stored revocation.
    fn revocation_rows(&self) -> Vec<(String, String, bool)> {
        let conn = rusqlite::Connection::open_with_flags(
            self.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut statement = conn
            .prepare("SELECT cause,state,ciphertext IS NOT NULL FROM oauth_revocations ORDER BY created_at")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Makes every pending revocation due now and wakes the worker.
    fn revocations_due_now(&self) {
        rusqlite::Connection::open(self.store_path())
            .unwrap()
            .execute(
                "UPDATE oauth_revocations SET due_at=0 WHERE ciphertext IS NOT NULL",
                [],
            )
            .unwrap();
        agent_access_core::oauth_revocation_signal().notify_waiters();
    }
}

async fn connected_gitlab() -> (MockServer, Arc<InstanceConsumer>, OAuthFixture) {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = gitlab_fixture(&gitlab, &consumer).await;
    mount_exchange(&gitlab, token_info_scopes()).await;
    let (state, callback) = fixture.gitlab_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    let (code, body) = fixture
        .invoke("account.view", "gitlab-before-disconnect", json!({}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    (gitlab, consumer, fixture)
}

/// Disconnect ends the connection locally first, then revokes the refresh
/// and access tokens at GitLab with the application's `client_secret_post`
/// credentials; the result, the connection row and the credentials list
/// all report `revoked`.
#[tokio::test]
async fn disconnect_revokes_the_gitlab_family_and_reports_revoked() {
    let (gitlab, _consumer, fixture) = connected_gitlab().await;
    mount_revoke(&gitlab, ResponseTemplate::new(200).set_body_json(json!({}))).await;
    let rows = fixture.gitlab_rows("gitlab-rows-connected").await;
    assert_eq!(rows[0]["remoteRevocation"], "not_requested");

    assert_eq!(
        fixture.disconnect_gitlab("gitlab-disconnect").await,
        json!({"disconnected": true, "remoteRevocation": "revoked"})
    );
    assert_eq!(revoked_tokens(&gitlab).await, first_family());
    for form in revocations(&gitlab).await {
        assert_eq!(form["client_id"], "broker-app");
        assert_eq!(form["client_secret"], "stub-client-secret");
    }
    let (code, body) = fixture
        .invoke("account.view", "gitlab-after-disconnect", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");

    let rows = fixture.gitlab_rows("gitlab-rows-disconnected").await;
    assert_eq!(rows[0]["remoteRevocation"], "revoked");
    assert_eq!(rows[0]["canDisconnect"], false);
    assert_eq!(rows[0]["connection"]["status"], "disconnected");
    let response = fixture
        .browser(Method::GET, "/v1/credentials", "gitlab-credentials", None)
        .await;
    let list = response_json(response).await;
    let row = list["result"]["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["connection"] == "oauth_stub")
        .unwrap()
        .clone();
    assert_eq!(row["method"], "oauth");
    assert_eq!(row["registration"], "gitlab");
    assert_eq!(row["remoteRevocation"], "revoked");
    assert_eq!(
        fixture.revocation_rows(),
        [("disconnect".into(), "revoked".into(), false)]
    );
    // Disconnecting again revokes nothing more and still answers.
    assert_eq!(
        fixture.disconnect_gitlab("gitlab-disconnect-again").await,
        json!({"disconnected": true, "remoteRevocation": "revoked"})
    );
    assert_eq!(revocations(&gitlab).await.len(), 2);
}

/// Losing the last grant on the connection's consumers revokes nothing: the
/// connection stays listed for its owner's cleanup, and that cleanup
/// disconnect revokes the family.
#[tokio::test]
async fn grant_loss_revokes_nothing_until_the_owner_cleans_up() {
    let (gitlab, _consumer, fixture) = connected_gitlab().await;
    mount_revoke(&gitlab, ResponseTemplate::new(200)).await;
    fixture
        .runtime
        .disable_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
            grant_id: "personal-oauth".into(),
            expected_version: 1,
            updated_by: "admin".into(),
        })
        .unwrap();
    let rows = fixture.gitlab_rows("gitlab-rows-grant-loss").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["consumers"], json!([]));
    assert_eq!(rows[0]["canConnect"], false);
    assert_eq!(rows[0]["canDisconnect"], true);
    assert_eq!(rows[0]["remoteRevocation"], "not_requested");
    assert!(fixture.revocation_rows().is_empty());
    assert!(revocations(&gitlab).await.is_empty());

    assert_eq!(
        fixture.disconnect_gitlab("gitlab-cleanup-disconnect").await,
        json!({"disconnected": true, "remoteRevocation": "revoked"})
    );
    assert_eq!(revoked_tokens(&gitlab).await, first_family());
    assert_eq!(
        fixture.revocation_rows(),
        [("disconnect".into(), "revoked".into(), false)]
    );
}

/// A token GitLab refuses to revoke fails the revocation; local access
/// never returns.
#[tokio::test]
async fn a_gitlab_rejection_reports_failed_and_never_restores_access() {
    let (gitlab, _consumer, fixture) = connected_gitlab().await;
    mount_revoke(
        &gitlab,
        ResponseTemplate::new(400).set_body_json(json!({"error": "unsupported_token_type"})),
    )
    .await;
    assert_eq!(
        fixture.disconnect_gitlab("gitlab-disconnect-failed").await,
        json!({"disconnected": true, "remoteRevocation": "failed"})
    );
    assert_eq!(revocations(&gitlab).await.len(), 2);
    let (code, body) = fixture
        .invoke("account.view", "gitlab-after-failed", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
    let rows = fixture.gitlab_rows("gitlab-rows-failed").await;
    assert_eq!(rows[0]["remoteRevocation"], "failed");
}

/// GitLab unavailable at disconnect leaves the revocation pending; the
/// serving broker's worker completes it once it is due.
#[tokio::test]
async fn the_revocation_worker_completes_a_pending_revocation() {
    let (gitlab, _consumer, fixture) = connected_gitlab().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&gitlab)
        .await;
    mount_revoke(&gitlab, ResponseTemplate::new(200)).await;
    assert_eq!(
        fixture.disconnect_gitlab("gitlab-disconnect-pending").await,
        json!({"disconnected": true, "remoteRevocation": "pending"})
    );
    let rows = fixture.gitlab_rows("gitlab-rows-pending").await;
    assert_eq!(rows[0]["remoteRevocation"], "pending");
    let (code, body) = fixture
        .invoke("account.view", "gitlab-while-pending", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
    fixture.revocations_due_now();
    fixture.await_remote_revocation("revoked").await;
    assert_eq!(revocations(&gitlab).await.len(), 4);
    assert_eq!(revoked_tokens(&gitlab).await, first_family());
}

/// Disabling alice ends her GitLab connection at once and keeps its family
/// for the worker to revoke; re-enabling her restores nothing.
#[tokio::test]
async fn disabling_the_owner_revokes_the_gitlab_family() {
    let (gitlab, _consumer, fixture) = connected_gitlab().await;
    mount_revoke(&gitlab, ResponseTemplate::new(200)).await;
    // The broker's own store performs disablement, as the administrator
    // API does.
    let store = fixture.runtime.managed_store().unwrap();
    store
        .patch_principal(agent_access_core::PrincipalPatchRequest {
            principal_id: "alice".into(),
            display_name: None,
            email: None,
            status: Some("disabled".into()),
        })
        .unwrap();
    let (code, body) = fixture
        .invoke("account.view", "gitlab-disabled", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
    let started = std::time::Instant::now();
    while revoked_tokens(&gitlab).await != first_family() {
        assert!(started.elapsed() < Duration::from_secs(20));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let started = std::time::Instant::now();
    while fixture.revocation_rows() != [("principal_disabled".into(), "revoked".into(), false)] {
        assert!(started.elapsed() < Duration::from_secs(20));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    store.set_principal_enabled("alice", true).unwrap();
    let (code, body) = fixture
        .invoke("account.view", "gitlab-reenabled", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
}

/// A broker that stops with a revocation pending leaves it in the store;
/// the next broker's startup pass completes it.
#[tokio::test]
async fn a_restarted_broker_resumes_a_pending_revocation() {
    let (gitlab, consumer, fixture) = connected_gitlab().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&gitlab)
        .await;
    mount_revoke(&gitlab, ResponseTemplate::new(200)).await;
    assert_eq!(
        fixture
            .disconnect_gitlab("gitlab-disconnect-before-restart")
            .await,
        json!({"disconnected": true, "remoteRevocation": "pending"})
    );
    let OAuthFixture {
        _dir: dir,
        broker,
        config,
        runtime,
        app,
        ..
    } = fixture;
    drop((runtime, app));
    broker.stop().await;
    assert_eq!(
        revocation_rows_at(&config),
        [("disconnect".into(), "pending".into(), true)]
    );
    rusqlite::Connection::open(&config.managed_store.as_ref().unwrap().path)
        .unwrap()
        .execute("UPDATE oauth_revocations SET due_at=0", [])
        .unwrap();
    let restarted =
        start_oauth_broker(&config, vec![ServiceProvider::from(Arc::clone(&consumer))]).await;
    let started = std::time::Instant::now();
    while revocation_rows_at(&config) != [("disconnect".into(), "revoked".into(), false)] {
        assert!(started.elapsed() < Duration::from_secs(20));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(revoked_tokens(&gitlab).await, first_family());
    assert_eq!(revocations(&gitlab).await.len(), 4);
    restarted.stop().await;
    drop(dir);
}

fn revocation_rows_at(config: &BrokerConfig) -> Vec<(String, String, bool)> {
    let conn = rusqlite::Connection::open_with_flags(
        &config.managed_store.as_ref().unwrap().path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut statement = conn
        .prepare("SELECT cause,state,ciphertext IS NOT NULL FROM oauth_revocations")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
