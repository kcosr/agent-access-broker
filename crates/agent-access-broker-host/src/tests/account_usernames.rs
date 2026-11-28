//! A username derived when an account is created, when its email changes
//! or when its person signs in without one is recorded on the audit record
//! of the operation that derived it.

use super::*;

async fn admin(fixture: &BrowserRateFixture, method: Method, uri: &str, body: Value) -> Value {
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "account-username-admin",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some(&body.to_string()),
    )
    .await;
    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn sign_in(fixture: &BrowserRateFixture, principal: &str, request_id: &str) {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:43101".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, request_id)
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"principalId": principal, "password": "carol-password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

fn records_of(fixture: &BrowserRateFixture, action: &str, request_id: &str) -> Vec<Value> {
    read_audit_records(&fixture.audit_path)
        .into_iter()
        .filter(|record| record["action"] == action && record["agentRequestId"] == request_id)
        .collect()
}

/// Leaves `usr-carol` (Carol@example.com) following her email without a
/// name while the name her email derives is free: another account held it
/// when she was created, and an administrator then took it away there. Her
/// next sign-in names her.
async fn unnamed_carol(fixture: &BrowserRateFixture) {
    admin(
        fixture,
        Method::POST,
        "/v1/admin/principals",
        json!({"principalId": "usr-holder", "kind": "user", "email": "carol@example.com"}),
    )
    .await;
    admin(
        fixture,
        Method::POST,
        "/v1/admin/principals",
        json!({"principalId": "usr-carol", "kind": "user", "email": "Carol@example.com"}),
    )
    .await;
    admin(
        fixture,
        Method::PUT,
        "/v1/admin/principals/usr-holder/account-username",
        json!({"mode": "manual", "accountUsername": null}),
    )
    .await;
}

#[tokio::test]
async fn derivation_is_recorded_by_the_creation_the_email_change_and_the_sign_in_that_performed_it()
{
    let fixture = browser_rate_fixture_with(test_limits(), |config| {
        config.usernames.email_domains = vec!["example.com".to_string()];
        config.usernames.existing_usernames = vec!["bob".to_string()];
    })
    .await;
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();

    // An administrator creates a person whose email derives a listed name.
    admin(
        &fixture,
        Method::POST,
        "/v1/admin/principals",
        json!({"principalId": "usr-bob", "kind": "user", "email": "Bob@example.com"}),
    )
    .await;
    let name = store
        .principal_account_username("usr-bob")
        .unwrap()
        .name
        .unwrap();
    assert_eq!(name.account_username, "bob");
    assert_eq!(name.assigned_by, "admin");
    let created = records_of(
        &fixture,
        "admin.principals.create",
        "account-username-admin",
    );
    let derived = created
        .iter()
        .find_map(|record| {
            // The completion record's target carries the transaction's facts.
            let target = &record["providerAudit"]["management"]["target"];
            (!target["derivedAccountUsername"].is_null())
                .then(|| target["derivedAccountUsername"].clone())
        })
        .unwrap_or_else(|| panic!("{created:?}"));
    assert_eq!(
        derived,
        json!({
            "accountUsername": "bob",
            "usernameIncarnation": name.incarnation,
            "origin": "derived",
            "state": "awaiting_confirmation",
        })
    );

    // A person created without an email holds no name. Giving them an
    // email of a listed domain names them in that change, which records it.
    admin(
        &fixture,
        Method::POST,
        "/v1/admin/principals",
        json!({"principalId": "usr-erin", "kind": "user"}),
    )
    .await;
    assert_eq!(
        store.principal_account_username("usr-erin").unwrap().name,
        None
    );
    let patched = admin(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/usr-erin",
        json!({"email": "erin@example.com"}),
    )
    .await;
    let name = store
        .principal_account_username("usr-erin")
        .unwrap()
        .name
        .unwrap();
    assert_eq!(name.account_username, "erin");
    assert_eq!(name.assigned_by, "admin");
    assert_eq!(
        patched["result"]["accountUsernameChange"]["after"]["incarnation"],
        json!(name.incarnation)
    );
    let renamed = records_of(&fixture, "admin.principals.patch", "account-username-admin")
        .into_iter()
        .find_map(|record| {
            let target = &record["providerAudit"]["management"]["target"];
            (!target["accountUsername"].is_null()).then(|| target["accountUsername"].clone())
        })
        .expect("the email change's completion record carries the name");
    assert_eq!(renamed["principal"], "usr-erin");
    assert!(renamed["before"].is_null());
    assert_eq!(
        renamed["after"],
        json!({
            "accountUsername": "erin",
            "usernameIncarnation": name.incarnation,
            "origin": "derived",
            "state": "usable",
        })
    );

    // A person who follows their email and holds no name is named by their
    // next sign-in, which records it; a later sign-in derives nothing.
    unnamed_carol(&fixture).await;
    assert_eq!(
        store.principal_account_username("usr-carol").unwrap().name,
        None
    );
    store
        .enable_local_password(
            fixture
                .state
                .current()
                .runtime
                .local_password_hasher()
                .unwrap(),
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "usr-carol".to_string(),
                password: "carol-password".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".to_string(),
            },
        )
        .unwrap();
    sign_in(&fixture, "usr-carol", "account-username-first-sign-in").await;
    let name = store
        .principal_account_username("usr-carol")
        .unwrap()
        .name
        .unwrap();
    assert_eq!(name.account_username, "carol");
    assert_eq!(name.assigned_by, "system:sign_in");
    let first = records_of(
        &fixture,
        "auth.local.login",
        "account-username-first-sign-in",
    );
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(
        first[0]["providerAudit"]["auth"]["derivedAccountUsername"],
        json!({
            "accountUsername": "carol",
            "usernameIncarnation": name.incarnation,
            "origin": "derived",
            "state": "usable",
        })
    );
    sign_in(&fixture, "usr-carol", "account-username-second-sign-in").await;
    let second = records_of(
        &fixture,
        "auth.local.login",
        "account-username-second-sign-in",
    );
    assert_eq!(second.len(), 1, "{second:?}");
    assert!(second[0]["providerAudit"]["auth"]["derivedAccountUsername"].is_null());
    assert_eq!(
        store.principal_account_username("usr-carol").unwrap().name,
        Some(name)
    );
}

fn login_request(principal: &str, request_id: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/local/login")
        .extension(ConnectInfo(
            "127.0.0.1:43101".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header("Host", "localhost")
        .header("Origin", "http://localhost")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"principalId": principal, "password": "carol-password"}).to_string(),
        ))
        .unwrap()
}

/// A fixture whose only listed email domain is `example.com`, with the
/// person `usr-carol` (Carol@example.com) who has a password, follows her
/// email and holds no name yet. Returns the fixture, its configuration and
/// its store.
async fn unsigned_person() -> (
    BrowserRateFixture,
    BrokerConfig,
    agent_access_core::ManagedStore,
) {
    // A file reference, so a reload can load the provider credential again.
    let provider_token = temp_path("account-username-fake-token");
    std::fs::write(&provider_token, "synthetic-fake-service-token").unwrap();
    let mut captured = None;
    let fixture = browser_rate_fixture_with(test_limits(), |config| {
        config.usernames.email_domains = vec!["example.com".to_string()];
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", provider_token.display()));
        captured = Some(config.clone());
    })
    .await;
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    unnamed_carol(&fixture).await;
    store
        .enable_local_password(
            fixture
                .state
                .current()
                .runtime
                .local_password_hasher()
                .unwrap(),
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "usr-carol".to_string(),
                password: "carol-password".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".to_string(),
            },
        )
        .unwrap();
    (fixture, captured.unwrap(), store)
}

/// Holds the next sign-in's owner after its password work and before its
/// fenced store completion.
fn hold_sign_in(state: &crate::state::ReloadableState) -> Arc<crate::state::McpBlockingBarrier> {
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    *state.sign_in_completion_barrier.lock().unwrap() = Some(barrier.clone());
    barrier
}

#[tokio::test]
async fn a_cancelled_sign_in_still_audits_the_name_it_allocated() {
    let (fixture, _config, store) = unsigned_person().await;
    let barrier = hold_sign_in(&fixture.state);
    let app = fixture.app.clone();
    let waiter = tokio::spawn(async move {
        app.oneshot(login_request(
            "usr-carol",
            "account-username-cancelled-sign-in",
        ))
        .await
    });
    // The password is verified; the transaction that derives has not begun.
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .expect("the sign-in owner reaches its store completion");
    assert_eq!(
        store.principal_account_username("usr-carol").unwrap().name,
        None
    );
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    barrier.release();
    tokio::time::timeout(Duration::from_secs(10), barrier.completed.notified())
        .await
        .expect("the sign-in owner finishes without its waiter");
    *fixture.state.sign_in_completion_barrier.lock().unwrap() = None;

    let name = store
        .principal_account_username("usr-carol")
        .unwrap()
        .name
        .unwrap();
    assert_eq!(name.account_username, "carol");
    let records = records_of(
        &fixture,
        "auth.local.login",
        "account-username-cancelled-sign-in",
    );
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(
        records[0]["providerAudit"]["auth"]["derivedAccountUsername"]["usernameIncarnation"],
        json!(name.incarnation)
    );
}

#[tokio::test]
async fn a_sign_in_that_began_before_a_reload_allocates_nothing_under_the_retired_settings() {
    let (fixture, config, store) = unsigned_person().await;
    let barrier = hold_sign_in(&fixture.state);
    let app = fixture.app.clone();
    let waiter = tokio::spawn(async move {
        app.oneshot(login_request("usr-carol", "account-username-stale-sign-in"))
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(10), barrier.reached.notified())
        .await
        .expect("the sign-in owner reaches its store completion");
    // While the password work is done and the transaction has not begun,
    // the operator stops deriving names for the domain.
    *fixture.state.sign_in_completion_barrier.lock().unwrap() = None;
    let mut retired = config.clone();
    retired.usernames.email_domains.clear();
    let generation = fixture.state.current().generation;
    fixture._broker.reload_config(&retired).await;
    assert_eq!(fixture.state.current().generation, generation + 1);
    barrier.release();
    let response = waiter.await.unwrap();

    // The stale request is refused before its transaction: no session and
    // no name.
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .is_none()
    );
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "version_conflict", "{body}");
    let current = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    let carol = current.principal_account_username("usr-carol").unwrap();
    assert_eq!(carol.name, None);
    assert_eq!(
        store.principal_account_username("usr-carol").unwrap().name,
        None
    );

    // A sign-in under the current settings succeeds and derives nothing:
    // the domain is no longer listed.
    sign_in(&fixture, "usr-carol", "account-username-current-sign-in").await;
    let carol = current.principal_account_username("usr-carol").unwrap();
    assert_eq!(carol.name, None);
    assert_eq!(
        carol.reason,
        Some(agent_access_core::AccountUsernameReason::DomainNotListed)
    );
}
