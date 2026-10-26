//! A browser session is a request its portal sign-in cookie authenticated,
//! never an identity source that resembles one. Only a session administers
//! with its `user_manage` class and reaches the browser-only OAuth connection
//! routes, and only a session is held to the cookie CSRF check and the forced
//! password change.
use super::*;

const ADMIN_READ: &str = "/v1/admin/principals";
const ADMIN_WRITE: &str = "/v1/admin/groups";
const GROUP: &str = r#"{"groupId":"reviewers"}"#;

/// A `user_manage` or `agent_invoke` broker token issued to the admin.
fn admin_token(
    fixture: &OAuthFixture,
    token_class: BrokerTokenClass,
) -> agent_access_core::IssuedBrokerToken {
    let scopes = if token_class == BrokerTokenClass::AgentInvoke {
        json!({"allowedExecutionContexts": ["default"]})
    } else {
        json!({})
    };
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            fixture.runtime.broker_token_hasher().unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "admin self-service".into(),
                token_class,
                scopes,
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
}

/// Sets the admin's local password and signs it in, returning the session
/// cookie and CSRF token.
async fn admin_session(fixture: &OAuthFixture, change_required: bool) -> (String, String) {
    let store = fixture.runtime.managed_store().unwrap();
    let hasher = fixture.runtime.local_password_hasher().unwrap();
    let password = || LocalPasswordWriteRequest {
        principal_id: "admin".into(),
        password: "admin-password".into(),
        min_password_length: 8,
        password_change_required: change_required,
        actor: "test".into(),
    };
    match store.enable_local_password(hasher, password()) {
        Err(agent_access_core::ManagedStoreError::LocalPasswordAlreadyEnabled) => {
            store.reset_local_password(hasher, password()).unwrap();
        }
        enabled => {
            enabled.unwrap();
        }
    }
    let login = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "browser-identity-login")
                .header("Host", "127.0.0.1")
                .header("Origin", "http://127.0.0.1")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"principalId":"admin","password":"admin-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body = response_json(login).await;
    assert_eq!(body["result"]["passwordChangeRequired"], change_required);
    (cookie, body["result"]["csrfToken"].as_str().unwrap().into())
}

async fn bearer(
    fixture: &OAuthFixture,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "browser-identity-bearer",
        "Authorization",
        format!("Bearer {token}"),
        body,
    )
    .await;
    (response.status(), response_json(response).await)
}

async fn cookie(
    fixture: &OAuthFixture,
    (cookie, csrf): (&str, Option<&str>),
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, "browser-identity-cookie")
        .header("Cookie", cookie)
        .header("Host", "127.0.0.1")
        .header("Origin", "http://127.0.0.1")
        .header(CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        request = request.header("X-Agent-Access-CSRF", csrf);
    }
    let response = fixture
        .app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), response_json(response).await)
}

/// Whether the catalog lists the admin and browser-only OAuth routes.
fn catalog_routes(catalog: &Value) -> (bool, bool) {
    (
        catalog_has_route(catalog, "GET", ADMIN_READ),
        catalog_has_route(catalog, "POST", "/v1/oauth/connect"),
    )
}

#[tokio::test]
async fn admin_user_manage_bearer_token_is_not_a_browser_session() {
    let fixture = oauth_fixture().await;
    let token = admin_token(&fixture, BrokerTokenClass::UserManage).token;

    // No administration with the `user_manage` class, and no browser-only
    // OAuth connection routes, in admission or in the catalog.
    for (method, uri, body) in [
        (Method::GET, ADMIN_READ, None),
        (Method::POST, ADMIN_WRITE, Some(GROUP)),
    ] {
        let (status, response) = bearer(&fixture, &token, method, uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {response}");
        assert_eq!(response["reasonCode"], "broker_token_class_denied");
    }
    for (method, uri, body) in [
        (Method::GET, "/v1/oauth/connections", None),
        (
            Method::POST,
            "/v1/oauth/connect",
            Some(r#"{"registration":"stub","intent":"connect"}"#),
        ),
    ] {
        let (status, response) = bearer(&fixture, &token, method, uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {response}");
        assert_eq!(response["reasonCode"], "management_denied", "{uri}");
    }
    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "browser-identity-catalog",
        Some(&token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog = response_json(catalog).await;
    assert!(catalog_has_route(&catalog, "GET", "/v1/tokens"));
    assert_eq!(catalog_routes(&catalog), (false, false));

    // Nor is it held to the session's CSRF check or forced password change.
    let agent_token = admin_token(&fixture, BrokerTokenClass::AgentInvoke).record;
    let (status, paused) = bearer(
        &fixture,
        &token,
        Method::POST,
        &format!("/v1/tokens/{}/pause", agent_token.token_id),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paused}");
    admin_session(&fixture, true).await;
    let (status, response) = bearer(&fixture, &token, Method::GET, "/v1/tokens", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn admin_browser_session_administers_with_csrf_and_password_change() {
    let fixture = oauth_fixture().await;
    let (session, csrf) = admin_session(&fixture, false).await;

    let (status, response) =
        cookie(&fixture, (&session, None), Method::GET, ADMIN_READ, None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = cookie(
        &fixture,
        (&session, None),
        Method::GET,
        "/v1/oauth/connections",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, catalog) = cookie(
        &fixture,
        (&session, None),
        Method::GET,
        "/v1/spec/catalog",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert_eq!(catalog_routes(&catalog), (true, true));

    // Writes need the session's CSRF token.
    for csrf in [None, Some("not-the-csrf-token")] {
        let (status, response) = cookie(
            &fixture,
            (&session, csrf),
            Method::POST,
            ADMIN_WRITE,
            Some(GROUP),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
        assert_eq!(response["reasonCode"], "csrf_invalid");
    }
    let (status, response) = cookie(
        &fixture,
        (&session, Some(&csrf)),
        Method::POST,
        ADMIN_WRITE,
        Some(GROUP),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // A session whose password must change cannot administer.
    let (changing, _) = admin_session(&fixture, true).await;
    let (status, response) =
        cookie(&fixture, (&changing, None), Method::GET, ADMIN_READ, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(response["reasonCode"], "password_change_required");
}

#[tokio::test]
async fn identity_sources_cannot_take_the_browser_session_name() {
    let fixture = oauth_fixture().await;
    let generation = fixture.broker.state().current().generation;
    for name in ["browser-session", "Browser-Session"] {
        let mut config = fixture.config.clone();
        config.identity.sources[0].name = name.into();
        let running = fixture.broker.running();
        running
            .rewrite_config(ConfigDoc::from_config(&config).render())
            .unwrap();
        let outcome = running.reload().await.unwrap();
        assert!(!outcome.is_success(), "{name}: {outcome:?}");
        assert!(
            outcome.message().is_some_and(|message| message.contains(
                &format!("identity.sources.{name}.name browser-session is reserved for portal browser sessions")
            )),
            "{name}: {outcome:?}"
        );
        assert_eq!(fixture.broker.state().current().generation, generation);
    }
    let token = admin_token(&fixture, BrokerTokenClass::UserManage).token;
    let (status, response) = bearer(&fixture, &token, Method::GET, ADMIN_READ, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(response["reasonCode"], "broker_token_class_denied");
}
