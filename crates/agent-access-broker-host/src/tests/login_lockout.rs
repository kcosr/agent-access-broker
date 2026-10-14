//! Local-password rate budgets and lockouts are keyed by `(principal, source)`.

use super::*;
use crate::ingress::source::auth_source_key;
use agent_access_core::SourceContext;

async fn local_login(
    fixture: &BrowserRateFixture,
    remote: &str,
    principal: &str,
    password: &str,
) -> axum::response::Response {
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "local-login-lockout")
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"principalId": principal, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn assert_login_rejected(response: axum::response::Response, reason_code: &str) -> Value {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], reason_code, "{body}");
    assert_eq!(body["error"]["message"], "login failed");
    body
}

async fn admin_request(
    fixture: &BrowserRateFixture,
    method: Method,
    uri: &str,
) -> axum::response::Response {
    authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "local-login-lockout-admin",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await
}

fn object_keys(value: &Value) -> Vec<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

#[tokio::test]
async fn another_source_cannot_lock_out_the_user_and_admin_unlock_clears_every_source() {
    let fixture = browser_rate_fixture(test_limits()).await;
    let attacker = "198.51.100.7:5000";
    let failed = assert_login_rejected(
        local_login(&fixture, attacker, "alice", "wrong-password").await,
        "local_login_failed",
    )
    .await;
    assert_login_rejected(
        local_login(&fixture, attacker, "alice", "wrong-password").await,
        "local_login_failed",
    )
    .await;
    let locked = assert_login_rejected(
        local_login(&fixture, attacker, "alice", "wrong-password").await,
        "local_login_locked",
    )
    .await;
    // Lockout responses keep the failure shape and do not name sources.
    assert_eq!(object_keys(&failed), object_keys(&locked));
    assert!(!locked.to_string().contains("198.51.100.7"));
    assert_login_rejected(
        local_login(&fixture, attacker, "alice", "alice-password").await,
        "local_login_locked",
    )
    .await;
    assert_eq!(
        local_login(&fixture, "127.0.0.1:43101", "alice", "alice-password")
            .await
            .status(),
        StatusCode::OK
    );

    // IPv6 sources are grouped by /64.
    for _ in 0..3 {
        local_login(
            &fixture,
            "[2001:db8:1:2::10]:5000",
            "alice",
            "wrong-password",
        )
        .await;
    }
    assert_login_rejected(
        local_login(
            &fixture,
            "[2001:db8:1:2::99]:5001",
            "alice",
            "alice-password",
        )
        .await,
        "local_login_locked",
    )
    .await;
    assert_eq!(
        local_login(
            &fixture,
            "[2001:db8:1:3::10]:5000",
            "alice",
            "alice-password"
        )
        .await
        .status(),
        StatusCode::OK
    );

    let listing = admin_request(
        &fixture,
        Method::GET,
        "/v1/admin/principals/alice/login-methods",
    )
    .await;
    assert_eq!(listing.status(), StatusCode::OK);
    let listing = response_json(listing).await;
    let method = &listing["result"][0];
    assert_eq!(method["method"], "local_password");
    assert_eq!(method["status"], "active");
    assert_eq!(method["locked"], true);
    assert!(method["lockedUntil"].is_string());
    assert!(method.get("failedAttempts").is_none());
    assert!(!listing.to_string().contains("198.51.100.7"));
    assert!(!listing.to_string().contains("2001:db8"));

    let unlocked = admin_request(
        &fixture,
        Method::POST,
        "/v1/admin/principals/alice/login-methods/local-password/unlock",
    )
    .await;
    assert_eq!(unlocked.status(), StatusCode::OK);
    let unlocked = response_json(unlocked).await;
    assert_eq!(unlocked["result"]["locked"], false);
    assert!(unlocked["result"]["lockedUntil"].is_null());
    for source in [attacker, "[2001:db8:1:2::10]:5000"] {
        assert_eq!(
            local_login(&fixture, source, "alice", "alice-password")
                .await
                .status(),
            StatusCode::OK,
            "{source}"
        );
    }
}

#[tokio::test]
async fn login_principal_budget_and_concurrency_are_keyed_by_source() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_principal_per_minute: 3,
        max_concurrent_requests_per_principal: 1,
        ..test_limits()
    })
    .await;
    // The fixture login spent one of 127.0.0.1's three attempts. Alice's
    // own in-flight requests do not block her login, and login attempts
    // from elsewhere cannot hold her in-flight slots.
    let alice_in_flight = fixture
        .ingress
        .try_principal_concurrency("alice", 1)
        .unwrap();
    assert_eq!(
        local_login(&fixture, "127.0.0.1:43101", "alice", "alice-password")
            .await
            .status(),
        StatusCode::OK
    );
    drop(alice_in_flight);

    let attacker = "198.51.100.7:5000";
    for _ in 0..3 {
        local_login(&fixture, attacker, "alice", "wrong-password").await;
    }
    let limited = local_login(&fixture, attacker, "alice", "wrong-password").await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(limited).await["reasonCode"], "rate_limited");
    assert_eq!(
        local_login(&fixture, "127.0.0.1:43102", "alice", "alice-password")
            .await
            .status(),
        StatusCode::OK
    );
    let own_budget_spent =
        local_login(&fixture, "127.0.0.1:43103", "alice", "alice-password").await;
    assert_eq!(own_budget_spent.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn password_change_failures_count_against_the_callers_source() {
    let fixture = browser_rate_fixture(test_limits()).await;
    // Repeated attempts after the source locks retain the generic change error.
    for _ in 0..4 {
        let response = fixture
            .browser_request(
                Method::POST,
                "/v1/auth/local/password/change",
                Some(json!({"currentPassword": "wrong-password", "newPassword": "alice-new-password"})),
            )
            .await;
        assert_login_rejected(response, "local_login_failed").await;
    }
    // The fixture session uses 127.0.0.1, which is now locked; other sources are not.
    assert_login_rejected(
        local_login(&fixture, "127.0.0.1:43101", "alice", "alice-password").await,
        "local_login_locked",
    )
    .await;
    assert_eq!(
        local_login(&fixture, "198.51.100.7:5000", "alice", "alice-password")
            .await
            .status(),
        StatusCode::OK
    );
}

#[test]
fn login_source_groups_ipv6_by_64_and_keeps_full_ipv4() {
    let source = |remote: &str| SourceContext {
        listener: "http".to_string(),
        remote: remote.to_string(),
        proxy_chain: Vec::new(),
        agent_request_id_generated: None,
    };
    assert_eq!(auth_source_key(&source("203.0.113.10:443")), "203.0.113.10");
    assert_eq!(auth_source_key(&source("203.0.113.10")), "203.0.113.10");
    assert_eq!(
        auth_source_key(&source("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:443")),
        "2001:db8:1:2::/64"
    );
    // Trusted-proxy resolution yields bare addresses.
    assert_eq!(
        auth_source_key(&source("2001:db8:1:2::ffff")),
        "2001:db8:1:2::/64"
    );
    assert_eq!(
        auth_source_key(&source("[::ffff:198.51.100.7]:443")),
        "198.51.100.7"
    );
    // Bare IPv4-mapped and well-known NAT64 addresses use the embedded IPv4 address.
    assert_eq!(
        auth_source_key(&source("::ffff:198.51.100.7")),
        "198.51.100.7"
    );
    assert_eq!(
        auth_source_key(&source("[64:ff9b::c633:6407]:443")),
        "198.51.100.7"
    );
    assert_eq!(
        auth_source_key(&source("64:ff9b::198.51.100.7")),
        "198.51.100.7"
    );
    // Only the well-known /96 is translated; other prefixes group by /64.
    assert_eq!(
        auth_source_key(&source("[64:ff9b:1::c633:6407]:443")),
        "64:ff9b:1::/64"
    );
    assert_eq!(
        auth_source_key(&source("64:ff9b::1:c633:6407")),
        "64:ff9b::/64"
    );
    assert_eq!(auth_source_key(&SourceContext::unknown()), "unknown");
}

async fn invalid_token_discovery(fixture: &BrowserRateFixture, remote: &str) -> StatusCode {
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/services")
                .extension(ConnectInfo(remote.parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "auth-source-grouping")
                .header("X-Agent-Token", "Bearer not-a-broker-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn auth_source_budget_uses_the_grouped_login_source() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_source_per_minute: 2,
        auth_requests_per_principal_per_minute: 100,
        ..test_limits()
    })
    .await;
    // Login from rotating addresses within one IPv6 /64 shares one budget.
    for remote in ["[2001:db8:1:2::10]:5000", "[2001:db8:1:2::99]:5001"] {
        assert_login_rejected(
            local_login(&fixture, remote, "ghost", "wrong-password").await,
            "local_login_failed",
        )
        .await;
    }
    let limited = local_login(
        &fixture,
        "[2001:db8:1:2:ffff::1]:5002",
        "ghost",
        "wrong-password",
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(limited).await["reasonCode"], "rate_limited");
    assert_login_rejected(
        local_login(
            &fixture,
            "[2001:db8:1:3::10]:5000",
            "ghost",
            "wrong-password",
        )
        .await,
        "local_login_failed",
    )
    .await;

    // Failed token authentication from an IPv4 address and its IPv4-mapped
    // and NAT64 forms shares that address's budget.
    for remote in ["[::ffff:203.0.113.5]:1000", "[64:ff9b::cb00:7105]:1001"] {
        assert_eq!(
            invalid_token_discovery(&fixture, remote).await,
            StatusCode::UNAUTHORIZED,
            "{remote}"
        );
    }
    assert_eq!(
        invalid_token_discovery(&fixture, "203.0.113.5:1002").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        invalid_token_discovery(&fixture, "203.0.113.6:1000").await,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn trusted_proxy_client_address_is_the_login_source() {
    let resolver = crate::ingress::source::SourceResolver::new(&["127.0.0.1".to_string()]);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Forwarded-For", "2001:db8:9:9::42".parse().unwrap());
    let source = resolver.source_context("127.0.0.1:40000".parse().unwrap(), &headers);
    assert_eq!(auth_source_key(&source), "2001:db8:9:9::/64");
}

#[tokio::test]
async fn failed_login_audits_only_a_valid_claimed_principal() {
    let fixture = browser_rate_fixture(test_limits()).await;
    let invalid = "bad principal <script>";
    let too_long = "a".repeat(257);
    for principal in [invalid, too_long.as_str()] {
        let response = local_login(&fixture, "127.0.0.1:43201", principal, "wrong-password").await;
        let body = assert_login_rejected(response, "local_login_failed").await;
        assert!(body.get("principal").is_none(), "{body}");
    }
    let response = local_login(&fixture, "127.0.0.1:43201", "ghost", "wrong-password").await;
    let body = assert_login_rejected(response, "local_login_failed").await;
    assert_eq!(body["principal"], "ghost");

    let records = read_audit_records(&fixture.audit_path)
        .into_iter()
        .filter(|record| record["action"] == "auth.local.login" && record["decision"] == "deny")
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3, "{records:#?}");
    for record in &records[..2] {
        assert_eq!(record["principal"], "anonymous", "{record}");
        assert_eq!(
            record["providerAudit"]["auth"]["claimedPrincipalInvalid"],
            true
        );
    }
    assert_eq!(records[2]["principal"], "ghost");
    assert!(
        records[2]["providerAudit"]["auth"]
            .get("claimedPrincipalInvalid")
            .is_none()
    );
    let raw = read_audit_text(&fixture.audit_path);
    assert!(!raw.contains("bad principal"));
    assert!(!raw.contains(&too_long));
}
