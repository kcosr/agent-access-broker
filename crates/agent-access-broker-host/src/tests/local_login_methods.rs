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
            membership_renewal: false,
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
    let fixture = browser_rate_fixture(test_limits()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .create_principal(
            PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
async fn login_admitted_before_registry_reload_reports_conflict_without_mutating_auth_state() {
    use axum::Json;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::response::IntoResponse;

    for group_policy in [false, true] {
        let fixture = browser_rate_fixture(test_limits()).await;
        if group_policy {
            let created = admin(
                &fixture,
                Method::POST,
                "/v1/admin/groups",
                Some(json!({"groupId":"issuers"})),
            )
            .await;
            assert_eq!(created.status(), StatusCode::OK);
            let joined = admin(
                &fixture,
                Method::PUT,
                "/v1/admin/groups/issuers/members/alice",
                None,
            )
            .await;
            assert_eq!(joined.status(), StatusCode::OK);
        }
        let failed = browser(
            &fixture,
            Method::POST,
            "/v1/auth/local/login",
            "",
            None,
            Some(json!({"principalId":"alice","password":"incorrect-password"})),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::UNAUTHORIZED);

        let old_snapshot = fixture.state.current();
        let old_store = old_snapshot.runtime.managed_store().unwrap().clone();
        let before_tokens = old_store
            .list_broker_tokens_for_principal("alice")
            .unwrap()
            .into_iter()
            .map(|token| token.token_id)
            .collect::<Vec<_>>();
        let db = rusqlite::Connection::open(&fixture.store_path).unwrap();
        let auth_state = || {
            let password: String = db.query_row(
                "SELECT password_hash_phc FROM principal_login_methods WHERE principal_id = 'alice' AND method = 'local_password'",
                [], |row| row.get(0),
            ).unwrap();
            let failures = db.prepare("SELECT source, failed_attempts, last_failed_at, locked_until FROM local_password_failures WHERE principal_id = 'alice' ORDER BY source").unwrap()
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?))).unwrap()
                .collect::<Result<Vec<_>, _>>().unwrap();
            (password, failures)
        };
        let before_auth = auth_state();
        assert_eq!(before_auth.1.len(), 1);

        // This existing validation API holds the old connection mutex in a
        // read-only transaction. New runtime connections can still write WAL.
        // No timing assumption or production test hook is needed to hold the
        // admitted login before its first store read.
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocked_store = old_store.clone();
        let blocker = tokio::task::spawn_blocking(move || {
            let mut held_tx = Some(held_tx);
            blocked_store.validate_policy_grant_create(
                agent_access_core::ManagedPolicyGrantCreateRequest {
                    grant_id: None,
                    subjects: vec!["user:alice".into()],
                    execution_contexts: vec!["default".into()],
                    service: "fake".into(),
                    actions: vec!["echo".into()],
                    resources: ResourceSelection::default(),
                    credential_mode: "service".into(),
                    priority: None,
                    status: None,
                    description: None,
                    created_by: "test".into(),
                },
                |_, _, _, _| {
                    held_tx.take().unwrap().send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                    Ok(())
                },
            )
        });
        held_rx.await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("stale-registry-login"),
        );
        headers.insert("Host", HeaderValue::from_static("localhost"));
        headers.insert("Origin", HeaderValue::from_static("http://localhost"));
        let body =
            serde_json::from_value(json!({"principalId":"alice","password":"alice-password"}))
                .unwrap();
        let mut login = Box::pin(crate::handlers::auth::auth_local_login(
            State(crate::state::AppState {
                reloadable: fixture.state.clone(),
            }),
            ConnectInfo("127.0.0.1:43109".parse().unwrap()),
            headers,
            Json(body),
        ));
        assert!(futures_util::poll!(&mut login).is_pending());

        let mut config = old_snapshot.runtime.config().clone();
        config.execution_context = Some(ExecutionContextConfig {
            allowed_values: vec!["default".into(), "new-context".into()],
            default_context: Some("default".into()),
        });
        let token_path = fixture
            ._broker
            .running()
            .directory()
            .secret_file("stale-registry-fake.token", "synthetic-fake-credential")
            .unwrap();
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", token_path.display()));
        fixture._broker.reload_config(&config).await;
        assert!(!Arc::ptr_eq(&old_snapshot, &fixture.state.current()));
        let path = if group_policy {
            "/v1/admin/groups/issuers"
        } else {
            "/v1/admin/principals/alice/access"
        };
        let updated = admin(&fixture, Method::PATCH, path, Some(json!({
            "agentTokenIssuance":{"mode":"read_only","allowedExecutionContexts":["new-context"]},
        }))).await;
        assert_eq!(updated.status(), StatusCode::OK);
        release_tx.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        let response = login.await.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get("set-cookie").is_none());
        let response = response_json(response).await;
        assert_eq!(response["reasonCode"], "version_conflict");
        assert_eq!(auth_state(), before_auth);
        assert_eq!(
            old_store
                .list_broker_tokens_for_principal("alice")
                .unwrap()
                .into_iter()
                .map(|token| token.token_id)
                .collect::<Vec<_>>(),
            before_tokens
        );

        let expected = json!({"source":if group_policy {"groups"} else {"user"},"contexts":[{
            "executionContext":"new-context", "mode":"read_only", "groupIds":if group_policy {vec!["issuers"]} else {vec![]},
        }]});
        let current_session = session(&fixture, &fixture.cookie).await;
        assert_eq!(
            current_session["tokenIssuancePolicy"]["selfAgentInvoke"]["access"],
            expected
        );
        let fresh_login = browser(
            &fixture,
            Method::POST,
            "/v1/auth/local/login",
            "",
            None,
            Some(json!({"principalId":"alice","password":"alice-password"})),
        )
        .await;
        assert_eq!(fresh_login.status(), StatusCode::OK);
        assert_eq!(
            response_json(fresh_login).await["result"]["tokenIssuancePolicy"]["selfAgentInvoke"]["access"],
            expected
        );
    }
}

#[tokio::test]
async fn auth_policy_projection_failure_preserves_password_and_existing_sessions() {
    for operation in ["login", "local_change", "oidc_change"] {
        let fixture = browser_rate_fixture(test_limits()).await;
        let oidc_cookie = link_microsoft(&fixture);
        let oidc_before = session(&fixture, &oidc_cookie).await;
        let snapshot = fixture.state.current();
        let store = snapshot.runtime.managed_store().unwrap();
        store
            .create_group(
                agent_access_core::GroupWriteRequest {
                    group_id: "issuers".into(),
                    display_name: None,
                    description: None,
                    auto_enroll_new_microsoft_users: false,
                    agent_token_issuance: agent_access_core::GroupAgentTokenIssuanceSetting::new(
                        agent_access_core::AgentTokenIssuanceMode::ReadOnly,
                        vec!["default".into()],
                    )
                    .unwrap(),
                    created_by: "admin".into(),
                },
                &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
            )
            .unwrap();
        store.add_group("alice", "issuers", "admin").unwrap();
        let before_tokens = store
            .list_broker_tokens_for_principal("alice")
            .unwrap()
            .len();
        let conn = rusqlite::Connection::open(&fixture.store_path).unwrap();
        let before_hash: String = conn.query_row(
            "SELECT password_hash_phc FROM principal_login_methods WHERE principal_id = 'alice' AND method = 'local_password'",
            [], |row| row.get(0),
        ).unwrap();
        let failed_login = browser(
            &fixture,
            Method::POST,
            "/v1/auth/local/login",
            "",
            None,
            Some(json!({"principalId":"alice","password":"incorrect-password"})),
        )
        .await;
        assert_eq!(failed_login.status(), StatusCode::UNAUTHORIZED);
        let failure_counters = || {
            conn.prepare("SELECT source, failed_attempts, last_failed_at, locked_until FROM local_password_failures WHERE principal_id = 'alice' ORDER BY source").unwrap()
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?))).unwrap()
                .collect::<Result<Vec<_>, _>>().unwrap()
        };
        let before_failures = failure_counters();
        assert_eq!(before_failures.len(), 1);
        conn.execute_batch(
            "UPDATE group_agent_token_issuance_contexts SET execution_context = 'private-invalid-policy!' WHERE group_id = 'issuers';",
        ).unwrap();
        // Ordinary session reads must still fail closed when current policy is
        // unavailable, while a failed mutation must leave durable auth intact.
        let session_error = browser(
            &fixture,
            Method::GET,
            "/v1/auth/session",
            &fixture.cookie,
            None,
            None,
        )
        .await;
        assert_eq!(session_error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_json(session_error).await["reasonCode"],
            "managed_store_migration_required"
        );
        let response = if operation == "login" {
            browser(
                &fixture,
                Method::POST,
                "/v1/auth/local/login",
                "",
                None,
                Some(json!({"principalId":"alice","password":"alice-password"})),
            )
            .await
        } else {
            let (cookie, csrf) = if operation == "local_change" {
                (fixture.cookie.as_str(), fixture.csrf.as_str())
            } else {
                (
                    oidc_cookie.as_str(),
                    oidc_before["csrfToken"].as_str().unwrap(),
                )
            };
            browser(
                &fixture,
                Method::POST,
                "/v1/auth/local/password/change",
                cookie,
                Some(csrf),
                Some(
                    json!({"currentPassword":"alice-password","newPassword":"new-secret-password"}),
                ),
            )
            .await
        };
        assert!(!response.status().is_success(), "{operation}");
        assert!(
            response.headers().get("set-cookie").is_none(),
            "{operation}"
        );
        let body = response_json(response).await;
        assert!(!body.to_string().contains("private-invalid-policy"));
        assert!(!body.to_string().contains("new-secret-password"));
        assert_eq!(
            store
                .list_broker_tokens_for_principal("alice")
                .unwrap()
                .len(),
            before_tokens,
            "{operation}"
        );
        let after_hash: String = conn.query_row(
            "SELECT password_hash_phc FROM principal_login_methods WHERE principal_id = 'alice' AND method = 'local_password'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(
            after_hash == before_hash,
            "password changed after {operation} failed"
        );
        assert_eq!(
            failure_counters(),
            before_failures,
            "projection failure cleared failed-password accounting for {operation}"
        );
        for cookie in [&fixture.cookie, &oidc_cookie] {
            store
                .resolve_browser_session(
                    snapshot.runtime.broker_token_hasher().unwrap(),
                    cookie.strip_prefix("aab_session=").unwrap(),
                )
                .unwrap();
        }
        conn.execute(
            "UPDATE group_agent_token_issuance_contexts SET execution_context = 'default' WHERE group_id = 'issuers'",
            [],
        )
        .unwrap();
        for cookie in [&fixture.cookie, &oidc_cookie] {
            let current = session(&fixture, cookie).await;
            assert_eq!(current["authenticated"], true, "{operation}");
            assert_eq!(
                current["tokenIssuancePolicy"]["selfAgentInvoke"]["access"],
                json!({"source":"groups","contexts":[{"executionContext":"default","mode":"read_only","groupIds":["issuers"]}]})
            );
        }
    }
}

#[tokio::test]
async fn password_change_sanitizes_store_failures_without_losing_validation_messages() {
    for malformed_hash in [true, false] {
        let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
        let fixture = browser_rate_fixture(test_limits()).await;
        let snapshot = fixture.state.current();
        let store = snapshot.runtime.managed_store().unwrap();
        store
            .create_principal(
                PrincipalWriteRequest {
                    agent_token_issuance: Default::default(),
                    role: agent_access_core::PrincipalRole::User,
                    self_service_enabled: None,
                    principal_id: "bob".into(),
                    kind: "user".into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "test".into(),
                },
                &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
            )
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
        let fixture = browser_rate_fixture(test_limits()).await;
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
        let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
        let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
    let fixture = browser_rate_fixture(test_limits()).await;
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
