//! Admin service-limit routes and the `/v1/me` `serviceLimits` view: global
//! admin authorization, CSRF, audit, validation, managed-authority-only
//! availability, and overrides changing the next admission.
use super::invocation_limits::{ALICE, BOB, assert_limited, limit, limit_fixture, set_fake_limit};
use super::*;
use agent_access_core::{InvocationLimitsConfig, LocalPasswordWriteRequest};

const LIMITS: &str = "/v1/admin/principals/alice/service-limits";
const FAKE_LIMIT: &str = "/v1/admin/principals/alice/service-limits/fake";

fn fake_limit_of_two() -> LimitsConfig {
    LimitsConfig {
        invocations: InvocationLimitsConfig {
            services: BTreeMap::from([("fake".to_string(), limit(2, "1m"))]),
            ..Default::default()
        },
        ..test_limits()
    }
}

/// Admin broker-token request against the managed fixture.
async fn admin_request(
    fixture: &BrowserRateFixture,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let body = body.map(|value| value.to_string());
    authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "service-limits-admin",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        body.as_deref(),
    )
    .await
}

async fn admin_put(fixture: &BrowserRateFixture, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = admin_request(fixture, Method::PUT, uri, Some(body)).await;
    (response.status(), response_json(response).await)
}

fn fake_item(items: &Value) -> &Value {
    items
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["service"] == "fake")
        .unwrap()
}

/// Signs `admin` in through local-password login and returns the session
/// cookie and CSRF token.
async fn admin_browser_session(fixture: &BrowserRateFixture) -> (String, String) {
    let runtime = fixture.state.current().runtime.clone();
    runtime
        .managed_store()
        .unwrap()
        .enable_local_password(
            runtime.local_password_hasher().unwrap(),
            LocalPasswordWriteRequest {
                principal_id: "admin".to_string(),
                password: "admin-password-123".to_string(),
                min_password_length: 8,
                password_change_required: false,
                actor: "test".to_string(),
            },
        )
        .unwrap();
    let login = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "service-limits-admin-login")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"principalId":"admin","password":"admin-password-123"}"#,
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
    let csrf = response_json(login).await["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    (cookie, csrf)
}

async fn cookie_request(
    fixture: &BrowserRateFixture,
    cookie: &str,
    csrf: Option<&str>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(
            "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, "service-limits-browser")
        .header("Cookie", cookie)
        .header("Host", "localhost")
        .header("Origin", "http://localhost")
        .header(CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        builder = builder.header("X-Agent-Access-CSRF", csrf);
    }
    fixture
        .app
        .clone()
        .oneshot(
            builder
                .body(
                    body.map(|value| Body::from(value.to_string()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn assert_denied(response: axum::response::Response, status: StatusCode, reason: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response_json(response).await["reasonCode"], reason);
}

fn management_audit<'a>(records: &'a [Value], operation: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["providerAudit"]["management"]["operation"] == operation)
        .collect()
}

#[tokio::test]
async fn service_limit_routes_require_a_global_admin_and_browser_csrf_for_writes() {
    let fixture = browser_rate_fixture(fake_limit_of_two()).await;
    let body = json!({"requests": 5, "windowSeconds": 60});

    // Non-admin browser session, user-manage token, and agent token.
    assert_denied(
        fixture.browser_request(Method::GET, LIMITS, None).await,
        StatusCode::FORBIDDEN,
        "management_denied",
    )
    .await;
    assert_denied(
        fixture
            .browser_request(Method::PUT, FAKE_LIMIT, Some(body.clone()))
            .await,
        StatusCode::FORBIDDEN,
        "management_denied",
    )
    .await;
    for token in [&fixture.management_token, &fixture.agent_tokens[0]] {
        for (method, uri) in [
            (Method::GET, LIMITS),
            (Method::PUT, FAKE_LIMIT),
            (Method::DELETE, FAKE_LIMIT),
        ] {
            let response = authed_json_request(
                fixture.app.clone(),
                method,
                uri,
                "service-limits-token-class",
                "X-Agent-Token",
                format!("Bearer {token}"),
                Some(&body.to_string()),
            )
            .await;
            assert_denied(response, StatusCode::FORBIDDEN, "broker_token_class_denied").await;
        }
    }
    let anonymous = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(LIMITS)
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "service-limits-anonymous")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_denied(anonymous, StatusCode::UNAUTHORIZED, "identity_required").await;
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .list_principal_service_limits("alice")
            .unwrap()
            .is_empty()
    );

    // An admin browser session reads without CSRF but writes only with it.
    let (cookie, csrf) = admin_browser_session(&fixture).await;
    let listed = cookie_request(&fixture, &cookie, None, Method::GET, LIMITS, None).await;
    assert_eq!(listed.status(), StatusCode::OK);
    for method in [Method::PUT, Method::DELETE] {
        assert_denied(
            cookie_request(
                &fixture,
                &cookie,
                None,
                method.clone(),
                FAKE_LIMIT,
                Some(body.clone()),
            )
            .await,
            StatusCode::FORBIDDEN,
            "csrf_invalid",
        )
        .await;
        assert_denied(
            cookie_request(
                &fixture,
                &cookie,
                Some("not-the-csrf-token"),
                method,
                FAKE_LIMIT,
                Some(body.clone()),
            )
            .await,
            StatusCode::FORBIDDEN,
            "csrf_invalid",
        )
        .await;
    }
    let set = cookie_request(
        &fixture,
        &cookie,
        Some(&csrf),
        Method::PUT,
        FAKE_LIMIT,
        Some(body),
    )
    .await;
    assert_eq!(set.status(), StatusCode::OK);
    assert_eq!(
        response_json(set).await["result"],
        json!({"service":"fake","requests":5,"windowSeconds":60,"overridden":true})
    );
    let cleared = cookie_request(
        &fixture,
        &cookie,
        Some(&csrf),
        Method::DELETE,
        FAKE_LIMIT,
        None,
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(response_json(cleared).await["result"]["overridden"], false);
}

#[tokio::test]
async fn service_limit_override_changes_the_next_admission_and_is_audited() {
    let fixture = browser_rate_fixture(fake_limit_of_two()).await;
    let token = fixture.agent_tokens[0].clone();

    let listed = admin_request(&fixture, Method::GET, LIMITS, None).await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed["operation"], "admin.principals.service_limits.list");
    assert_eq!(
        fake_item(&listed["result"]),
        &json!({"service":"fake","requests":2,"windowSeconds":60,"overridden":false})
    );

    assert_eq!(
        fixture.token_invoke("sil-0", &token).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture.token_invoke("sil-1", &token).await.status(),
        StatusCode::OK
    );
    assert_limited(fixture.token_invoke("sil-service-limit", &token).await, 2).await;

    // Raising the limit through the admin API admits the next request.
    let (status, set) = admin_put(
        &fixture,
        FAKE_LIMIT,
        json!({"requests": 4, "windowSeconds": 60}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["operation"], "admin.principals.service_limits.set");
    assert_eq!(
        set["result"],
        json!({"service":"fake","requests":4,"windowSeconds":60,"overridden":true})
    );
    assert_eq!(
        fixture
            .token_invoke("sil-override-0", &token)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .token_invoke("sil-override-1", &token)
            .await
            .status(),
        StatusCode::OK
    );
    assert_limited(
        fixture.token_invoke("sil-override-limited", &token).await,
        4,
    )
    .await;
    let listed = response_json(admin_request(&fixture, Method::GET, LIMITS, None).await).await;
    assert_eq!(fake_item(&listed["result"])["overridden"], true);

    // Lowering it applies immediately as well.
    let (status, _) = admin_put(
        &fixture,
        FAKE_LIMIT,
        json!({"requests": 1, "windowSeconds": 60}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_limited(fixture.token_invoke("sil-lowered", &token).await, 1).await;

    // Reset returns the effective default and restores the service limit.
    let cleared = admin_request(&fixture, Method::DELETE, FAKE_LIMIT, None).await;
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared = response_json(cleared).await;
    assert_eq!(
        cleared["operation"],
        "admin.principals.service_limits.clear"
    );
    assert_eq!(
        cleared["result"],
        json!({"service":"fake","requests":2,"windowSeconds":60,"overridden":false})
    );
    assert_limited(fixture.token_invoke("sil-cleared", &token).await, 2).await;
    // Clearing again is idempotent.
    let again = admin_request(&fixture, Method::DELETE, FAKE_LIMIT, None).await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(response_json(again).await["result"]["overridden"], false);

    let records = read_audit_records(&fixture.audit_path);
    let sets = management_audit(&records, "admin.principals.service_limits.set");
    assert_eq!(sets.len(), 2);
    let first = sets[0];
    assert_eq!(first["principal"], "admin");
    assert_eq!(first["action"], "admin.principals.service_limits.set");
    assert_eq!(first["decision"], "allow");
    assert_eq!(first["providerAudit"]["management"]["phase"], "preflight");
    assert_eq!(
        first["providerAudit"]["management"]["target"],
        json!({"principal":"alice","service":"fake","requests":4,"windowSeconds":60})
    );
    let clears = management_audit(&records, "admin.principals.service_limits.clear");
    assert_eq!(clears.len(), 2);
    assert_eq!(
        clears[0]["providerAudit"]["management"]["target"],
        json!({"principal":"alice","service":"fake"})
    );
    // The two successful lists are unaudited reads.
    assert!(management_audit(&records, "admin.principals.service_limits.list").is_empty());
    let stored = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .list_principal_service_limits("alice")
        .unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn service_limit_writes_validate_bounds_bodies_services_and_principals() {
    let fixture = browser_rate_fixture(fake_limit_of_two()).await;
    for body in [
        json!({"requests": 0, "windowSeconds": 60}),
        json!({"requests": 1_000_001, "windowSeconds": 60}),
        json!({"requests": 10, "windowSeconds": 0}),
        json!({"requests": 10, "windowSeconds": 86_401}),
        json!({"requests": -1, "windowSeconds": 60}),
        json!({"requests": 1.5, "windowSeconds": 60}),
        json!({"requests": "10", "windowSeconds": 60}),
        json!({"requests": 10}),
        json!({"windowSeconds": 60}),
        json!({"requests": 10, "window": "1m"}),
        json!({"requests": 10, "windowSeconds": 60, "overridden": true}),
        json!([10, 60]),
    ] {
        let (status, value) = admin_put(&fixture, FAKE_LIMIT, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {value}");
        assert_eq!(value["reasonCode"], "input_invalid", "{body}");
    }
    let (_, value) = admin_put(
        &fixture,
        FAKE_LIMIT,
        json!({"requests": 0, "windowSeconds": 60}),
    )
    .await;
    assert_eq!(
        value["error"]["message"],
        "requests must be an integer from 1 to 1000000"
    );
    let (_, value) = admin_put(
        &fixture,
        FAKE_LIMIT,
        json!({"requests": 1, "windowSeconds": 86_401}),
    )
    .await;
    assert_eq!(
        value["error"]["message"],
        "windowSeconds must be an integer from 1 to 86400"
    );
    let malformed = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        FAKE_LIMIT,
        "service-limits-malformed",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some("{"),
    )
    .await;
    assert_denied(malformed, StatusCode::BAD_REQUEST, "input_invalid").await;
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .list_principal_service_limits("alice")
            .unwrap()
            .is_empty()
    );

    // Both bounds are inclusive.
    for (requests, window_seconds) in [(1, 1), (1_000_000, 86_400)] {
        let (status, value) = admin_put(
            &fixture,
            FAKE_LIMIT,
            json!({"requests": requests, "windowSeconds": window_seconds}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["result"]["requests"], requests);
        assert_eq!(value["result"]["windowSeconds"], window_seconds);
    }

    // Unknown or malformed services are rejected before the store.
    let body = json!({"requests": 5, "windowSeconds": 60});
    for (uri, message) in [
        (
            "/v1/admin/principals/alice/service-limits/missing",
            "service is not configured",
        ),
        (
            "/v1/admin/principals/alice/service-limits/Not-A-Service",
            "service name is invalid",
        ),
    ] {
        let (status, value) = admin_put(&fixture, uri, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(value["reasonCode"], "input_invalid");
        assert_eq!(value["error"]["message"], message);
        let cleared = admin_request(&fixture, Method::DELETE, uri, None).await;
        assert_denied(cleared, StatusCode::BAD_REQUEST, "input_invalid").await;
    }

    // Unknown principals are not found on every route.
    let (status, value) = admin_put(
        &fixture,
        "/v1/admin/principals/ghost/service-limits/fake",
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(value["reasonCode"], "principal_not_found");
    for (method, uri) in [
        (Method::GET, "/v1/admin/principals/ghost/service-limits"),
        (
            Method::DELETE,
            "/v1/admin/principals/ghost/service-limits/fake",
        ),
    ] {
        assert_denied(
            admin_request(&fixture, method, uri, None).await,
            StatusCode::NOT_FOUND,
            "principal_not_found",
        )
        .await;
    }
}

#[tokio::test]
async fn service_limits_cover_gateway_services_and_every_principal_kind() {
    let fixture = browser_rate_fixture_with(fake_limit_of_two(), |config| {
        let token_path = temp_path("service-limits-gateway-token");
        std::fs::write(&token_path, "git-service-token").unwrap();
        config.credentials.service.insert(
            "gitlab_git".to_string(),
            CredentialConfig {
                kind: "bearer_token".to_string(),
                username_ref: None,
                token_ref: Some(format!("file:{}", token_path.display())),
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
                connection: None,
            },
        );
        config
            .gateways
            .insert("gitlab_git".to_string(), test_git_gateway_config());
    })
    .await;
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "build-bot".to_string(),
            kind: "service_account".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "alice".to_string(),
            display_name: None,
            email: None,
            status: Some("disabled".to_string()),
        })
        .unwrap();

    let listed = response_json(admin_request(&fixture, Method::GET, LIMITS, None).await).await;
    let services = listed["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["service"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(services.contains(&"fake"), "{listed}");
    assert!(services.contains(&"gitlab_git"), "{listed}");
    let mut sorted = services.clone();
    sorted.sort_unstable();
    assert_eq!(services, sorted);

    // Gateway service names are configured services; so are disabled users
    // and service accounts.
    for principal in ["alice", "build-bot"] {
        let (status, value) = admin_put(
            &fixture,
            &format!("/v1/admin/principals/{principal}/service-limits/gitlab_git"),
            json!({"requests": 7, "windowSeconds": 3600}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{principal}: {value}");
        assert_eq!(
            value["result"],
            json!({"service":"gitlab_git","requests":7,"windowSeconds":3600,"overridden":true})
        );
    }
    let bot = response_json(
        admin_request(
            &fixture,
            Method::GET,
            "/v1/admin/principals/build-bot/service-limits",
            None,
        )
        .await,
    )
    .await;
    let gateway = bot["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["service"] == "gitlab_git")
        .unwrap();
    assert_eq!(gateway["overridden"], true);
    assert_eq!(fake_item(&bot["result"])["overridden"], false);
}

#[tokio::test]
async fn service_limit_routes_are_unavailable_under_toml_identity_authority() {
    let store_path = temp_path("service-limits-toml-store.sqlite");
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 2, "1m");
        config.managed_store = Some(agent_access_core::ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        });
        config.management = agent_access_core::ManagementConfig {
            enabled: true,
            admin_principals: vec!["alice".to_string()],
            allow_classless_admin_identities: true,
            initial_admin: agent_access_core::InitialAdminConfig::default(),
            ..agent_access_core::ManagementConfig::default()
        };
    })
    .await;
    for (method, uri) in [
        (Method::GET, "/v1/admin/principals/bob/service-limits"),
        (Method::PUT, "/v1/admin/principals/bob/service-limits/fake"),
        (
            Method::DELETE,
            "/v1/admin/principals/bob/service-limits/fake",
        ),
    ] {
        let response = authed_json_request(
            fixture.app.clone(),
            method.clone(),
            uri,
            "service-limits-toml",
            "Authorization",
            format!("Bearer {ALICE}"),
            Some(r#"{"requests":5,"windowSeconds":60}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let value = response_json(response).await;
        assert_eq!(value["reasonCode"], "input_invalid");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("limits.invocations.principal_overrides"),
            "{value}"
        );
    }
    // A non-admin static principal is still denied first.
    let denied = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/admin/principals/alice/service-limits",
        "service-limits-toml-denied",
        "Authorization",
        format!("Bearer {BOB}"),
        None,
    )
    .await;
    assert_denied(denied, StatusCode::FORBIDDEN, "management_denied").await;
}

async fn me(app: &Router, token: &str, context: Option<&str>) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/v1/me")
        .extension(ConnectInfo(
            "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, "service-limits-me")
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(context) = context {
        builder = builder
            .header(EXECUTION_CONTEXT_HEADER, context)
            .header(CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn me_lists_visible_service_limits_under_toml_authority_without_override_marker() {
    let fixture = limit_fixture(|config| {
        config.limits.invocations.default = Some(limit(50, "1h"));
        set_fake_limit(config, 2, "1m");
        config.limits.invocations.principal_overrides =
            vec![agent_access_core::PrincipalInvocationLimitConfig {
                principal: "alice".into(),
                service: "fake".into(),
                requests: 3,
                window: "90s".into(),
            }];
    })
    .await;
    let alice = me(&fixture.app, ALICE, None).await;
    assert_eq!(alice.status(), StatusCode::OK);
    let alice = response_json(alice).await;
    assert_eq!(alice["principal"], "alice");
    assert_eq!(alice["authenticated"], true);
    assert_eq!(
        alice["serviceLimits"],
        json!([{"service":"fake","requests":3,"windowSeconds":90}])
    );
    let bob = response_json(me(&fixture.app, BOB, None).await).await;
    assert_eq!(
        bob["serviceLimits"],
        json!([{"service":"fake","requests":2,"windowSeconds":60}])
    );

    // Services the caller cannot see are omitted, like /v1/services.
    fixture
        .publish(2, |config| {
            config.policy.grants[0].subjects = vec!["user:alice".to_string()];
        })
        .await;
    let bob = response_json(me(&fixture.app, BOB, None).await).await;
    assert_eq!(bob["principal"], "bob");
    assert_eq!(bob["serviceLimits"], json!([]));
    let services = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services",
        "service-limits-services",
        "Authorization",
        format!("Bearer {BOB}"),
        None,
    )
    .await;
    assert_eq!(response_json(services).await, json!([]));
}

#[tokio::test]
async fn me_service_limits_follow_the_request_execution_context_without_requiring_one() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 2, "1m");
        config.execution_context = Some(ExecutionContextConfig {
            allowed_values: vec!["internal".to_string(), "external".to_string()],
            default_context: None,
        });
        install_context_caller(config);
        config.policy.resources = fixture_resources(&["internal", "external"]);
        config.policy.grants[0].execution_contexts = Some(vec!["internal".to_string()]);
    })
    .await;
    let expected = json!([{"service":"fake","requests":2,"windowSeconds":60}]);
    let internal = response_json(me(&fixture.app, ALICE, Some("internal")).await).await;
    assert_eq!(internal["serviceLimits"], expected);
    for context in [None, Some("external")] {
        let response = me(&fixture.app, ALICE, context).await;
        assert_eq!(response.status(), StatusCode::OK, "{context:?}");
        let value = response_json(response).await;
        assert_eq!(value["principal"], "alice");
        assert_eq!(value["serviceLimits"], json!([]), "{context:?}");
    }
    let invalid = me(&fixture.app, ALICE, Some("unknown-context")).await;
    assert_denied(invalid, StatusCode::FORBIDDEN, "execution_context_invalid").await;
    let services = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services",
        "service-limits-services-no-context",
        "Authorization",
        format!("Bearer {ALICE}"),
        None,
    )
    .await;
    assert_denied(
        services,
        StatusCode::FORBIDDEN,
        "execution_context_required",
    )
    .await;
}

#[tokio::test]
async fn me_reflects_managed_overrides_for_sessions_and_tokens() {
    let fixture = browser_rate_fixture(fake_limit_of_two()).await;
    let default = json!([{"service":"fake","requests":2,"windowSeconds":60}]);
    let session = response_json(fixture.browser_request(Method::GET, "/v1/me", None).await).await;
    assert_eq!(session["principal"], "alice");
    assert_eq!(session["serviceLimits"], default);

    let (status, _) = admin_put(
        &fixture,
        FAKE_LIMIT,
        json!({"requests": 9, "windowSeconds": 120}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let overridden = json!([{"service":"fake","requests":9,"windowSeconds":120}]);
    let session = response_json(fixture.browser_request(Method::GET, "/v1/me", None).await).await;
    assert_eq!(session["serviceLimits"], overridden);
    for token in [&fixture.agent_tokens[0], &fixture.management_token] {
        let response = fixture.token_request(token, "/v1/me").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["serviceLimits"], overridden);
    }
    // /v1/me is not an invocation and never counts against the window.
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);

    // The admin has no grant for the fake service, so it sees no limits.
    let admin = response_json(fixture.token_request(&fixture.admin_token, "/v1/me").await).await;
    assert_eq!(admin["principal"], "admin");
    assert_eq!(admin["serviceLimits"], json!([]));
}
