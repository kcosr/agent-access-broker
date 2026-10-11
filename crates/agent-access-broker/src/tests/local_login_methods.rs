//! Explicit local enrollment and independent Microsoft/local session lifecycles.
use super::*;
use agent_access_core::{
    BrowserSessionIssueRequest, OidcLoginMethodLinkRequest, OidcProviderStateReconcileRequest,
};

async fn admin(
    fixture: &BrowserRateFixture,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let body = body.map(|value| value.to_string());
    authed_json_request(
        fixture.app.clone(),
        method,
        path,
        "local-method-admin",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        body.as_deref(),
    )
    .await
}

async fn browser(
    fixture: &BrowserRateFixture,
    method: Method,
    path: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: Option<Value>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .extension(ConnectInfo(
            "127.0.0.1:43109".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, "local-method-browser")
        .header("Host", "localhost")
        .header("Origin", "http://localhost")
        .header("Cookie", cookie)
        .header(CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        request = request.header("X-Agent-Access-CSRF", csrf);
    }
    fixture
        .app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    body.map(|value| value.to_string()).unwrap_or_default(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn session(fixture: &BrowserRateFixture, cookie: &str) -> Value {
    let response = browser(fixture, Method::GET, "/v1/auth/session", cookie, None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await["result"].clone()
}

fn link_microsoft(fixture: &BrowserRateFixture) -> String {
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
            tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            client_id: "11111111-2222-3333-4444-555555555555".into(),
            enabled: true,
            config_fingerprint: "local-method-test".into(),
            external_membership_ttl_seconds: 3600,
            invalidate_existing_evidence: false,
            actor: "test".into(),
        })
        .unwrap();
    let method = store
        .link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: "alice".into(),
            user_object_id: "12345678-1234-1234-1234-123456789abc".into(),
            actor: "test".into(),
        })
        .unwrap();
    let issued = store
        .issue_browser_session(
            snapshot.runtime.broker_token_hasher().unwrap(),
            BrowserSessionIssueRequest {
                principal_id: "alice".into(),
                login_method: "oidc".into(),
                login_method_id: Some(method.login_method_id),
                ttl_seconds: 3600,
                password_change_required: false,
                created_by: "alice".into(),
            },
        )
        .unwrap();
    format!("aab_session={}", issued.token)
}

#[tokio::test]
async fn local_password_admin_requires_explicit_enrollment_and_audits_previous_state() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "bob".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    let path = "/v1/admin/principals/bob/login-methods/local-password";
    let enable = format!("{path}/enable");
    let password = json!({"password":"temporary-password"});
    let reset = admin(&fixture, Method::PUT, path, Some(password.clone())).await;
    assert_eq!(reset.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(reset).await["reasonCode"],
        "local_password_not_enabled"
    );
    for ack in [None, Some(false)] {
        let mut body = password.clone();
        if let Some(ack) = ack {
            body["acknowledgeSeparateSignIn"] = json!(ack);
        }
        let rejected = admin(&fixture, Method::POST, &enable, Some(body)).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(rejected).await["reasonCode"], "input_invalid");
    }
    assert!(store.list_login_methods("bob").unwrap().is_empty());
    let accepted = json!({"password":"temporary-password", "acknowledgeSeparateSignIn":true});
    let non_admin = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        &enable,
        "local-method-not-admin",
        "X-Agent-Token",
        format!("Bearer {}", fixture.management_token),
        Some(&accepted.to_string()),
    )
    .await;
    assert_eq!(non_admin.status(), StatusCode::FORBIDDEN);
    for previous in ["absent", "disabled"] {
        let enabled = admin(&fixture, Method::POST, &enable, Some(accepted.clone())).await;
        assert_eq!(enabled.status(), StatusCode::OK);
        let enabled = response_json(enabled).await;
        assert_eq!(enabled["result"]["previousStatus"], previous);
        assert_eq!(enabled["result"]["method"], "local_password");
        assert_eq!(enabled["result"]["mustChangePassword"], true);
        assert!(enabled["result"].get("passwordHashPhc").is_none());
        let duplicate = admin(&fixture, Method::POST, &enable, Some(accepted.clone())).await;
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(duplicate).await["reasonCode"],
            "local_password_already_enabled"
        );
        let reset = admin(&fixture, Method::PUT, path, Some(password.clone())).await;
        assert_eq!(reset.status(), StatusCode::OK);
        let disabled = admin(&fixture, Method::DELETE, path, None).await;
        assert_eq!(disabled.status(), StatusCode::OK);
        let reset = admin(&fixture, Method::PUT, path, Some(password.clone())).await;
        assert_eq!(reset.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(reset).await["reasonCode"],
            "local_password_not_enabled"
        );
    }
    store.set_principal_enabled("bob", false).unwrap();
    assert_eq!(
        admin(&fixture, Method::POST, &enable, Some(accepted))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(store.principal("bob").unwrap().status, "disabled");
    let listing =
        response_json(admin(&fixture, Method::GET, "/v1/admin/principals", None).await).await;
    let bob = listing["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["principalId"] == "bob")
        .unwrap();
    assert_eq!(
        bob["signInMethods"],
        json!({"localPassword":"active","microsoft":"absent"})
    );
    let records = read_audit_records(&fixture.audit_path);
    for previous in ["absent", "disabled"] {
        assert!(
            records.iter().any(
                |record| record["providerAudit"]["management"]["target"]["previousStatus"]
                    == previous
            ),
            "missing {previous} audit: {records:?}"
        );
    }
    let audit = serde_json::to_string(&records).unwrap();
    assert!(!audit.contains("temporary-password"));
    assert!(!audit.contains("passwordHashPhc"));
}

#[tokio::test]
async fn hybrid_password_change_preserves_microsoft_session_and_revokes_only_local_sessions() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let oidc_cookie = link_microsoft(&fixture);
    let local_before = session(&fixture, &fixture.cookie).await;
    let oidc_before = session(&fixture, &oidc_cookie).await;
    for view in [&local_before, &oidc_before] {
        assert_eq!(view["authenticated"], true);
        assert_eq!(
            view["signInMethods"],
            json!({"localPassword":"active","microsoft":"active"})
        );
    }
    assert_eq!(local_before["loginMethod"], "local_password");
    assert_eq!(oidc_before["loginMethod"], "oidc");
    let changed = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/password/change",
        &oidc_cookie,
        oidc_before["csrfToken"].as_str(),
        Some(json!({"currentPassword":"alice-password","newPassword":"alice-new-password"})),
    )
    .await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert!(changed.headers().get("set-cookie").is_none());
    let changed = response_json(changed).await;
    assert_eq!(changed["result"]["loginMethod"], "oidc");
    assert_eq!(changed["result"]["csrfToken"], oidc_before["csrfToken"]);
    assert_eq!(changed["result"]["expiresAt"], oidc_before["expiresAt"]);
    assert_eq!(
        session(&fixture, &fixture.cookie).await["authenticated"],
        false
    );
    assert_eq!(session(&fixture, &oidc_cookie).await["authenticated"], true);
    let login = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/login",
        "",
        None,
        Some(json!({"principalId":"alice","password":"alice-new-password"})),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let local_cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        response_json(login).await["result"]["loginMethod"],
        "local_password"
    );
    let unlink = admin(
        &fixture,
        Method::DELETE,
        "/v1/admin/principals/alice/login-methods/oidc/microsoft",
        None,
    )
    .await;
    assert_eq!(unlink.status(), StatusCode::OK);
    assert_eq!(
        session(&fixture, &oidc_cookie).await["authenticated"],
        false
    );
    assert_eq!(
        session(&fixture, &local_cookie).await["authenticated"],
        true
    );
    let oidc_cookie = link_microsoft(&fixture);
    let disabled = admin(
        &fixture,
        Method::DELETE,
        "/v1/admin/principals/alice/login-methods/local-password",
        None,
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(
        session(&fixture, &local_cookie).await["authenticated"],
        false
    );
    let oidc = session(&fixture, &oidc_cookie).await;
    assert_eq!(oidc["authenticated"], true);
    assert_eq!(
        oidc["signInMethods"],
        json!({"localPassword":"disabled","microsoft":"active"})
    );
    let denied = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/password/change",
        &oidc_cookie,
        oidc["csrfToken"].as_str(),
        Some(json!({"currentPassword":"alice-new-password","newPassword":"must-not-enable"})),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(denied).await["reasonCode"],
        "local_login_failed"
    );
    assert_eq!(
        session(&fixture, &oidc_cookie).await["signInMethods"]["localPassword"],
        "disabled"
    );
}

#[tokio::test]
async fn password_change_sanitizes_store_failures_without_losing_validation_messages() {
    for malformed_hash in [true, false] {
        let fixture = browser_rate_fixture(LimitsConfig::default()).await;
        let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
        if malformed_hash {
            conn.execute(
                "UPDATE principal_login_methods SET password_hash_phc = ?1 WHERE principal_id = 'alice' AND method = 'local_password'",
                ["private-malformed-password-hash"],
            ).unwrap();
        } else {
            conn.execute_batch(
                "CREATE TRIGGER fail_password_write BEFORE UPDATE OF password_hash_phc ON principal_login_methods BEGIN SELECT RAISE(ABORT, 'private-password-store-failure'); END;",
            ).unwrap();
        }
        let response = browser(
            &fixture,
            Method::POST,
            "/v1/auth/local/password/change",
            &fixture.cookie,
            Some(&fixture.csrf),
            Some(json!({"currentPassword":"alice-password","newPassword":"new-secret-password"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_json(response).await;
        assert_eq!(
            body["reasonCode"],
            if malformed_hash {
                "managed_store_migration_required"
            } else {
                "managed_store_unavailable"
            }
        );
        assert_eq!(body["error"]["message"], "password change is unavailable");
        let serialized = body.to_string();
        for forbidden in [
            "private-malformed",
            "private-password-store",
            "new-secret-password",
            "password_hash_phc",
            "local password hash is malformed",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "unexpected store detail: {body}"
            );
        }
        assert!(
            response_json(
                browser(
                    &fixture,
                    Method::GET,
                    "/v1/auth/session",
                    &fixture.cookie,
                    None,
                    None
                )
                .await
            )
            .await["result"]["authenticated"]
                .as_bool()
                .unwrap()
        );
    }
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/password/change",
        &fixture.cookie,
        Some(&fixture.csrf),
        Some(json!({"currentPassword":"alice-password","newPassword":"short"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "input_invalid");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("at least")
    );
}

#[tokio::test]
async fn local_password_enable_keeps_committed_success_if_completion_audit_fails() {
    for failing_phase in ["preflight", "success"] {
        let fixture = browser_rate_fixture(LimitsConfig::default()).await;
        let snapshot = fixture.state.current();
        let store = snapshot.runtime.managed_store().unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        let conn = rusqlite::Connection::open(&fixture.audit_path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER fail_selected_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{failing_phase}' AND json_extract(NEW.record_json, '$.providerAudit.management.operation') = 'admin.principals.local_password.enable' BEGIN SELECT RAISE(ABORT, 'injected-completion-audit-failure'); END;"
        )).unwrap();
        let response = admin(
            &fixture,
            Method::POST,
            "/v1/admin/principals/bob/login-methods/local-password/enable",
            Some(json!({"password":"new-temporary-password", "acknowledgeSeparateSignIn":true})),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        if failing_phase == "preflight" {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["reasonCode"], "audit_unavailable");
            assert!(store.list_login_methods("bob").unwrap().is_empty());
        } else {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["ok"], true);
            assert_eq!(body["result"]["previousStatus"], "absent");
            assert_eq!(body["result"]["status"], "active");
            assert!(
                store
                    .verify_local_password(
                        snapshot.runtime.local_password_hasher().unwrap(),
                        agent_access_core::LocalPasswordVerifyRequest {
                            principal_id: "bob".into(),
                            password: "new-temporary-password".into(),
                            source: "127.0.0.1".into(),
                            max_failed_attempts: 3,
                            lockout_ttl_seconds: 900,
                        }
                    )
                    .is_ok()
            );
            let recorded_preflight: i64 = conn.query_row(
                "SELECT count(*) FROM audit_events WHERE phase = 'preflight' AND json_extract(record_json, '$.providerAudit.management.operation') = 'admin.principals.local_password.enable'", [], |row| row.get(0),
            ).unwrap();
            assert_eq!(recorded_preflight, 1);
            let recorded_completion: i64 = conn
                .query_row(
                    "SELECT count(*) FROM audit_events WHERE phase = 'success'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(recorded_completion, 0);
        }
        assert!(
            !body
                .to_string()
                .contains("injected-completion-audit-failure")
        );
        assert!(!body.to_string().contains("new-temporary-password"));
    }
}

#[tokio::test]
async fn password_change_requires_preflight_and_preserves_committed_success() {
    for failing_phase in ["preflight", "success"] {
        let fixture = browser_rate_fixture(LimitsConfig::default()).await;
        let conn = rusqlite::Connection::open(&fixture.audit_path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER fail_auth_audit BEFORE INSERT ON audit_events WHEN json_extract(NEW.record_json, '$.providerAudit.auth.phase') = '{failing_phase}' AND NEW.action = 'auth.local.password.change' BEGIN SELECT RAISE(ABORT, 'private-auth-audit-failure'); END;"
        )).unwrap();
        let response = browser(
            &fixture,
            Method::POST,
            "/v1/auth/local/password/change",
            &fixture.cookie,
            Some(&fixture.csrf),
            Some(json!({"currentPassword":"alice-password","newPassword":"new-secret-password"})),
        )
        .await;
        let status = response.status();
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let replacement_cookie = response.headers().get("set-cookie").map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        });
        let body = response_json(response).await;
        let snapshot = fixture.state.current();
        let store = snapshot.runtime.managed_store().unwrap();
        let password = if failing_phase == "preflight" {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            assert_eq!(body["reasonCode"], "audit_unavailable");
            assert!(replacement_cookie.is_none());
            assert_eq!(
                session(&fixture, &fixture.cookie).await["authenticated"],
                true
            );
            "alice-password"
        } else {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["ok"], true);
            assert_eq!(
                session(&fixture, &fixture.cookie).await["authenticated"],
                false
            );
            assert_eq!(
                session(&fixture, replacement_cookie.as_deref().unwrap()).await["authenticated"],
                true
            );
            "new-secret-password"
        };
        store
            .verify_local_password(
                snapshot.runtime.local_password_hasher().unwrap(),
                agent_access_core::LocalPasswordVerifyRequest {
                    principal_id: "alice".into(),
                    password: password.into(),
                    source: "127.0.0.1".into(),
                    max_failed_attempts: 3,
                    lockout_ttl_seconds: 900,
                },
            )
            .unwrap();
        let phases: Vec<String> = conn
            .prepare("SELECT phase FROM audit_events WHERE action = 'auth.local.password.change' ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            phases,
            if failing_phase == "preflight" {
                vec![]
            } else {
                vec!["preflight".to_string()]
            }
        );
        let serialized = body.to_string();
        assert!(!serialized.contains("private-auth-audit-failure"));
        assert!(!serialized.contains("new-secret-password"));
    }
}

#[tokio::test]
async fn logout_reports_failed_session_lookup_and_allows_retry_after_recovery() {
    for fail_schema_read in [false, true] {
        let fixture = browser_rate_fixture(LimitsConfig::default()).await;
        let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
        let (fail, recover) = if fail_schema_read {
            (
                "ALTER TABLE browser_sessions RENAME TO private_unavailable_sessions;",
                "ALTER TABLE private_unavailable_sessions RENAME TO browser_sessions;",
            )
        } else {
            (
                "CREATE TRIGGER fail_session_lookup BEFORE UPDATE OF last_used_at ON broker_tokens BEGIN SELECT RAISE(ABORT, 'private-session-lookup-failure'); END;",
                "DROP TRIGGER fail_session_lookup;",
            )
        };
        conn.execute_batch(fail).unwrap();
        let response = browser(
            &fixture,
            Method::POST,
            "/v1/auth/logout",
            &fixture.cookie,
            Some(&fixture.csrf),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert!(response.headers().get("set-cookie").is_none());
        let body = response_json(response).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["reasonCode"], "managed_store_unavailable");
        assert_eq!(
            body["error"]["message"],
            "browser session could not be revoked"
        );
        assert!(!body.to_string().contains("private"));
        let audit = rusqlite::Connection::open(&fixture.audit_path).unwrap();
        let failures: i64 = audit.query_row(
            "SELECT count(*) FROM audit_events WHERE action = 'auth.logout' AND decision = 'deny' AND reason_code = 'managed_store_unavailable'", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(failures, 1);

        conn.execute_batch(recover).unwrap();
        assert_eq!(
            session(&fixture, &fixture.cookie).await["authenticated"],
            true
        );
        let response = browser(
            &fixture,
            Method::POST,
            "/v1/auth/logout",
            &fixture.cookie,
            Some(&fixture.csrf),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(
            session(&fixture, &fixture.cookie).await["authenticated"],
            false
        );
    }
}

#[tokio::test]
async fn logout_reports_failed_revocation_and_keeps_session_cookie() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_session_revoke BEFORE UPDATE OF revoked_at ON broker_tokens WHEN NEW.revoked_at IS NOT NULL AND OLD.token_id IN (SELECT token_id FROM browser_sessions) BEGIN SELECT RAISE(ABORT, 'private-session-revoke-failure'); END;",
    ).unwrap();
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/logout",
        &fixture.cookie,
        Some(&fixture.csrf),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert!(response.headers().get("set-cookie").is_none());
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "managed_store_unavailable");
    assert_eq!(
        body["error"]["message"],
        "browser session could not be revoked"
    );
    assert!(!body.to_string().contains("private-session-revoke-failure"));
    assert_eq!(
        session(&fixture, &fixture.cookie).await["authenticated"],
        true
    );
    let audit = rusqlite::Connection::open(&fixture.audit_path).unwrap();
    let failures: i64 = audit.query_row(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.logout' AND decision = 'deny' AND reason_code = 'managed_store_unavailable'", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(failures, 1);
    conn.execute_batch("DROP TRIGGER fail_session_revoke;")
        .unwrap();
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/logout",
        &fixture.cookie,
        Some(&fixture.csrf),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        session(&fixture, &fixture.cookie).await["authenticated"],
        false
    );
}

#[tokio::test]
async fn logout_requires_preflight_and_preserves_committed_success() {
    for failing_phase in ["preflight", "success"] {
        let fixture = browser_rate_fixture(LimitsConfig::default()).await;
        let conn = rusqlite::Connection::open(&fixture.audit_path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER fail_logout_audit BEFORE INSERT ON audit_events WHEN json_extract(NEW.record_json, '$.providerAudit.auth.phase') = '{failing_phase}' AND NEW.action = 'auth.logout' BEGIN SELECT RAISE(ABORT, 'private-logout-audit-failure'); END;"
        )).unwrap();
        let response = browser(
            &fixture,
            Method::POST,
            "/v1/auth/logout",
            &fixture.cookie,
            Some(&fixture.csrf),
            None,
        )
        .await;
        if failing_phase == "preflight" {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get("set-cookie").is_none());
            assert_eq!(
                response_json(response).await["reasonCode"],
                "audit_unavailable"
            );
            assert_eq!(
                session(&fixture, &fixture.cookie).await["authenticated"],
                true
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers()["set-cookie"]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=0")
            );
            assert_eq!(
                response_json(response).await["result"]["authenticated"],
                false
            );
            assert_eq!(
                session(&fixture, &fixture.cookie).await["authenticated"],
                false
            );
            let preflights: i64 = conn.query_row(
                "SELECT count(*) FROM audit_events WHERE action = 'auth.logout' AND phase = 'preflight'", [], |row| row.get(0),
            ).unwrap();
            assert_eq!(preflights, 1);
        }
    }
}

#[tokio::test]
async fn auth_session_and_errors_are_not_cacheable() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    for cookie in [&fixture.cookie, "", "aab_session=invalid"] {
        let response = browser(
            &fixture,
            Method::GET,
            "/v1/auth/session",
            cookie,
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/logout",
        &fixture.cookie,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let invalid_id = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/session")
                .extension(ConnectInfo(
                    "127.0.0.1:43109".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "invalid request id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_id.headers()[CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn local_login_reports_infrastructure_failure_without_exposing_store_details() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
    let before: i64 = conn
        .query_row("SELECT count(*) FROM browser_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_session_issue BEFORE INSERT ON browser_sessions BEGIN SELECT RAISE(ABORT, 'private-session-issue-failure'); END;",
    ).unwrap();
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/login",
        "",
        None,
        Some(json!({"principalId":"alice","password":"alice-password"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert!(response.headers().get("set-cookie").is_none());
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "managed_store_unavailable");
    assert_eq!(body["error"]["message"], "login is unavailable");
    assert!(!body.to_string().contains("private-session-issue-failure"));
    assert!(!body.to_string().contains("alice-password"));
    let after: i64 = conn
        .query_row("SELECT count(*) FROM browser_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(
        session(&fixture, &fixture.cookie).await["authenticated"],
        true
    );
}

#[tokio::test]
async fn browser_session_cookie_security_uses_the_parsed_origin_scheme() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    for (origin, secure) in [
        ("http://localhost", false),
        ("https://localhost", true),
        ("HTTPS://localhost", true),
    ] {
        let mut config = fixture.state.current().runtime.config().clone();
        config.browser_auth.public_origin = Some(origin.into());
        let runtime = BrokerRuntime::new(config).unwrap();
        let snapshot = RuntimeSnapshot::new(
            1,
            "sha256:cookie-origin-test".into(),
            runtime,
            StateLockSet::empty(),
        );
        let mut headers = axum::http::HeaderMap::new();
        crate::handlers::auth::set_session_cookie(
            &snapshot,
            "synthetic-session-token",
            60,
            &mut headers,
        );
        let cookie = headers["set-cookie"].to_str().unwrap();
        assert_eq!(cookie.contains("; Secure"), secure, "{origin}: {cookie}");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }
}

#[tokio::test]
async fn local_password_capacity_rejects_login_without_blocking_token_management() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    let first = store.try_admit_local_password_request().unwrap();
    let second = store.try_admit_local_password_request().unwrap();
    let response = browser(
        &fixture,
        Method::POST,
        "/v1/auth/local/login",
        "",
        None,
        Some(json!({"principalId":"unknown-capacity-test", "password":"wrong-password"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );
    let management = admin(&fixture, Method::GET, "/v1/admin/principals", None).await;
    assert_eq!(management.status(), StatusCode::OK);
    drop(first);
    drop(second);
}
