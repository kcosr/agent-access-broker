//! Trusted-identity administration exercises real routing, authority and storage.
use super::audit_query::{AuditFixture, Backend, audit_fixture_with};
use super::*;
use agent_access_core::{
    BrokerTokenClass, PrincipalAccessPatchRequest, PrincipalRole, TrustedCallerConfig,
    TrustedCallerContextMode, TrustedCallerCredentialTransport,
};

const GATE: &str = "/v1/admin/principals/alice/identity-access";
const BINDINGS: &str = "/v1/admin/principals/alice/identity-bindings";
const TOKEN: &str = "/v1/admin/principals/alice/identity-token";
const CREATE: &str = r#"{"namespace":"Managed.Linux","username":"Alice+team@example.test"}"#;
const TOKEN_PATCH: &str = "admin.principals.identity_token.patch";
const BINDING_PATCH: &str = "admin.principals.identity_bindings.patch";

/// A path's `(enabled, readOnly, fence)` as a response or audit reports it.
fn path_settings(value: &Value, fence: &str) -> (bool, bool, i64) {
    (
        value["enabled"].as_bool().unwrap(),
        value["readOnly"].as_bool().unwrap(),
        value[fence].as_i64().unwrap(),
    )
}

/// The management records of `operation` in `phase`, in append order.
fn phase_records(fixture: &AuditFixture, operation: &str, phase: &str) -> Vec<Value> {
    fixture
        .records()
        .into_iter()
        .filter(|record| {
            record["action"] == operation && record["providerAudit"]["management"]["phase"] == phase
        })
        .collect()
}

fn targets(records: &[Value]) -> Vec<Value> {
    records
        .iter()
        .map(|record| record["providerAudit"]["management"]["target"].clone())
        .collect()
}

async fn fixture() -> AuditFixture {
    audit_fixture_with(Backend::Sqlite, |config, _| {
        // Reloading the caller configuration checks credential readiness.
        let token = temp_path("identity-management-fake-token");
        std::fs::write(&token, "synthetic-fake-service-token").unwrap();
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", token.display()));
        for (id, transport) in [
            (
                "direct",
                TrustedCallerCredentialTransport::AuthorizationUser,
            ),
            (
                "relay",
                TrustedCallerCredentialTransport::CallerAuthorization,
            ),
        ] {
            let path = temp_path(&format!("identity-management-{id}.secret"));
            std::fs::write(&path, format!("synthetic-caller-secret-{id}-0123456789")).unwrap();
            config.identity.trusted_callers.insert(
                id.into(),
                TrustedCallerConfig {
                    credential_ref: format!("file:{}", path.display()),
                    credential_transport: transport,
                    username_namespace: Some("Managed.Linux".into()),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: false,
                },
            );
        }
    })
    .await
}

async fn admin(
    fixture: &AuditFixture,
    method: Method,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    fixture
        .request(
            method,
            &fixture.admin,
            path,
            body,
            "identity-management-test",
        )
        .await
}

fn auditor(fixture: &AuditFixture) -> String {
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "carol".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: None,
            actor: "admin".into(),
        })
        .unwrap();
    store
        .issue_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "carol".into(),
                name: "identity audit".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}

#[tokio::test]
async fn identity_management_gate_is_independent_and_version_checked() {
    let fixture = fixture().await;
    let (status, gate) = admin(&fixture, Method::GET, GATE, None).await;
    assert_eq!(status, StatusCode::OK, "{gate}");
    assert_eq!(gate["result"]["paused"], false);
    assert_eq!(gate["result"]["version"], 1);
    assert!(gate["result"]["incarnation"].as_str().is_some());
    assert!(
        !fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .identity_token_metadata("alice")
            .unwrap()
            .configured
    );

    let (status, paused) = admin(
        &fixture,
        Method::PATCH,
        GATE,
        Some(r#"{"paused":true,"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paused}");
    assert_eq!(paused["result"]["paused"], true);
    assert_eq!(paused["result"]["version"], 2);
    assert_eq!(
        paused["result"]["incarnation"],
        gate["result"]["incarnation"]
    );
    let (status, stale) = admin(
        &fixture,
        Method::PATCH,
        GATE,
        Some(r#"{"paused":false,"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(stale["reasonCode"], "identity_version_conflict");
    let (status, same) = admin(
        &fixture,
        Method::PATCH,
        GATE,
        Some(r#"{"paused":true,"expectedVersion":2}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{same}");
    assert_eq!(same["result"]["version"], 2);

    // Independent issued credentials and inventory deletion do not resume the gate.
    let (status, result) = fixture
        .request(
            Method::GET,
            &fixture.alice,
            "/v1/tokens",
            None,
            "paused-user-token",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (status, metadata) = admin(
        &fixture,
        Method::DELETE,
        "/v1/admin/principals/alice/identity-token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert!(metadata["result"].get("paused").is_none());
    let (_, gate) = admin(&fixture, Method::GET, GATE, None).await;
    assert_eq!(gate["result"]["paused"], true);
    assert_eq!(gate["result"]["version"], 2);
    for old_route in ["pause", "resume"] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            &format!("/v1/admin/principals/alice/identity-token/{old_route}"),
            "removed-identity-route",
            "Authorization",
            format!("Bearer {}", fixture.admin),
            None,
        )
        .await;
        // Unregistered routes use the router's empty 404 response.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let records = fixture.records();
    let completed = records
        .iter()
        .filter(|record| {
            record["action"] == "admin.principals.identity_access.patch"
                && record["providerAudit"]["management"]["phase"] == "success"
        })
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record["action"] != "admin.principals.identity_access.inspect")
    );
}

#[tokio::test]
async fn identity_management_binding_cas_ownership_and_namespace_availability() {
    let fixture = fixture().await;
    let (status, created) = admin(&fixture, Method::POST, BINDINGS, Some(CREATE)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let binding = created["result"]["bindingId"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(binding).is_ok());
    assert_eq!(created["result"]["version"], 1);
    assert_eq!(created["result"]["namespaceAvailable"], true);
    assert_eq!(created["result"]["username"], "Alice+team@example.test");
    let path = format!("{BINDINGS}/{binding}");
    let (status, _) = admin(
        &fixture,
        Method::PATCH,
        &path,
        Some(r#"{"enabled":false,"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, duplicate) = admin(
        &fixture,
        Method::POST,
        "/v1/admin/principals/bob/identity-bindings",
        Some(CREATE),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{duplicate}");
    assert_eq!(duplicate["reasonCode"], "identity_binding_conflict");
    assert!(!duplicate.to_string().contains("Alice+team"));
    for method in [Method::PATCH, Method::DELETE] {
        let wrong_owner = format!(
            "/v1/admin/principals/bob/identity-bindings/{binding}{}",
            if method == Method::DELETE {
                "?expectedVersion=2"
            } else {
                ""
            }
        );
        let body = (method == Method::PATCH).then_some(r#"{"enabled":true,"expectedVersion":2}"#);
        let (status, denied) = admin(&fixture, method, &wrong_owner, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
        assert_eq!(denied["reasonCode"], "identity_binding_not_found");
    }
    let (status, stale) = admin(
        &fixture,
        Method::DELETE,
        &format!("{path}?expectedVersion=1"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(stale["reasonCode"], "identity_version_conflict");
    let (_, listed) = admin(&fixture, Method::GET, BINDINGS, None).await;
    assert_eq!(
        listed["result"]["configuredNamespaces"],
        json!([{"namespace":"Managed.Linux","credentialTransports":["authorization_user","caller_authorization"]}])
    );
    assert_eq!(listed["result"]["bindings"][0]["enabled"], false);

    // Removing caller configuration retains the binding but makes it unavailable.
    let configured = fixture.state.current().runtime.config().clone();
    let mut config = configured.clone();
    config.identity.trusted_callers.clear();
    fixture.broker.reload_config(&config).await;
    let response = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        BINDINGS,
        "namespace-unavailable",
        "Authorization",
        format!("Bearer {}", fixture.admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let unavailable = response_json(response).await;
    assert_eq!(unavailable["result"]["configuredNamespaces"], json!([]));
    assert_eq!(
        unavailable["result"]["bindings"][0]["namespaceAvailable"],
        false
    );
    fixture.broker.reload_config(&configured).await;

    let (status, deleted) = admin(
        &fixture,
        Method::DELETE,
        &format!("{path}?expectedVersion=2"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["result"]["deleted"], true);
    let (_, replacement) = admin(&fixture, Method::POST, BINDINGS, Some(CREATE)).await;
    assert_ne!(replacement["result"]["bindingId"], binding);
    assert_eq!(replacement["result"]["version"], 1);
    // The binding creations carried the username.
    require_audit_action(
        fixture.audit_path.as_deref().unwrap(),
        "broker",
        "admin.principals.identity_bindings.create",
    );
    let audits = serde_json::to_string(&fixture.records()).unwrap();
    assert!(!audits.contains("Alice+team@example.test"));
    assert!(!audits.contains("synthetic-caller-secret"));
}

#[tokio::test]
async fn identity_management_admin_read_allows_auditors_and_rejects_invalid_writes() {
    let fixture = fixture().await;
    let token = auditor(&fixture);
    for path in [GATE, BINDINGS] {
        let (status, body) = fixture
            .request(Method::GET, &token, path, None, "auditor-identity-read")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.to_string().contains("synthetic-caller-secret"));
        assert!(!body.to_string().contains("credentialRef"));
    }
    let (_, binding) = admin(&fixture, Method::POST, BINDINGS, Some(CREATE)).await;
    let binding = format!(
        "{BINDINGS}/{}",
        binding["result"]["bindingId"].as_str().unwrap()
    );
    let (status, inventory) = fixture
        .request(Method::GET, &token, TOKEN, None, "auditor-token-read")
        .await;
    assert_eq!(status, StatusCode::OK, "{inventory}");
    for (method, path, body) in [
        (
            Method::PATCH,
            GATE,
            r#"{"paused":true,"expectedVersion":1}"#,
        ),
        (Method::POST, BINDINGS, CREATE),
        (
            Method::PATCH,
            binding.as_str(),
            r#"{"readOnly":true,"expectedVersion":1}"#,
        ),
        (
            Method::PATCH,
            TOKEN,
            r#"{"readOnly":true,"expectedRevision":1}"#,
        ),
    ] {
        for (token, reason) in [
            (&token, "management_denied"),
            (&fixture.alice, "broker_token_class_denied"),
        ] {
            let (status, denied) = fixture
                .request(
                    method.clone(),
                    token,
                    path,
                    Some(body),
                    "identity-write-denied",
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
            assert_eq!(denied["reasonCode"], reason);
        }
    }
    for body in [
        r#"{"paused":true}"#,
        r#"{"paused":true,"expectedVersion":0}"#,
        r#"{"paused":true,"expectedVersion":1,"principalId":"admin"}"#,
        r#"{"paused":true,"expectedVersion":1,"expectedVersion":2}"#,
        r#"[true,1]"#,
    ] {
        let (status, error) = admin(&fixture, Method::PATCH, GATE, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    }
    for body in [
        r#"{"namespace":"absent","username":"valid"}"#,
        r#"{"namespace":"Managed.Linux","username":"bad,subject"}"#,
        r#"{"namespace":"Managed.Linux","username":" valid"}"#,
        r#"{"namespace":"Managed.Linux","username":"valid","bindingId":"chosen"}"#,
        r#"["Managed.Linux","valid"]"#,
    ] {
        let (status, error) = admin(&fixture, Method::POST, BINDINGS, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert!(!error.to_string().contains("bad,subject"));
    }
    for path in ["identity-access", "identity-bindings"] {
        let (status, _) = admin(
            &fixture,
            Method::GET,
            &format!("/v1/admin/principals/unknown/{path}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let path = binding;
    for query in [
        "",
        "?expectedVersion=0",
        "?expectedVersion=1&expectedVersion=1",
        "?expectedVersion=1&extra=x",
    ] {
        let (status, error) =
            admin(&fixture, Method::DELETE, &format!("{path}{query}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    }
    let (_, listed) = admin(&fixture, Method::GET, BINDINGS, None).await;
    assert_eq!(listed["result"]["bindings"].as_array().unwrap().len(), 1);
    // Neither refused PATCH changed a setting.
    assert_eq!(
        path_settings(&listed["result"]["bindings"][0], "version"),
        (true, false, 1)
    );
    let (_, inventory) = admin(&fixture, Method::GET, TOKEN, None).await;
    assert_eq!(
        path_settings(&inventory["result"], "revision"),
        (true, false, 1)
    );
}

#[tokio::test]
async fn identity_management_audit_preflight_failure_prevents_mutation() {
    let fixture = fixture().await;
    let blocker = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (status, read) = admin(&fixture, Method::GET, GATE, None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    let (status, failed) = admin(
        &fixture,
        Method::PATCH,
        GATE,
        Some(r#"{"paused":true,"expectedVersion":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
    assert_eq!(failed["reasonCode"], "audit_unavailable");
    let gate = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .identity_access("alice")
        .unwrap();
    assert!(!gate.paused);
    assert_eq!(gate.version, 1);
    let (status, failed) = admin(
        &fixture,
        Method::PATCH,
        TOKEN,
        Some(r#"{"readOnly":true,"expectedRevision":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
    assert_eq!(failed["reasonCode"], "audit_unavailable");
    let inventory = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .identity_token_metadata("alice")
        .unwrap();
    assert!(!inventory.read_only);
    assert_eq!(inventory.revision, 1);
    blocker.execute_batch("ROLLBACK").unwrap();
}

#[tokio::test]
async fn identity_management_browser_mutations_require_csrf_and_preserve_sign_in() {
    let fixture = browser_rate_fixture(test_limits()).await;
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "admin".into(),
        })
        .unwrap();
    let inventory = || {
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .identity_token_metadata("alice")
            .unwrap()
    };
    let revision = inventory().revision;
    let token_body = json!({"readOnly":true,"expectedRevision":revision}).to_string();
    for ((uri, body), (csrf, expected)) in [
        (GATE, r#"{"paused":true,"expectedVersion":1}"#.to_owned()),
        (TOKEN, token_body),
    ]
    .into_iter()
    .flat_map(|route| {
        [
            (route.clone(), (None, StatusCode::FORBIDDEN)),
            (route, (Some(fixture.csrf.as_str()), StatusCode::OK)),
        ]
    }) {
        let mut request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .extension(ConnectInfo(
                "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "identity-browser-csrf")
            .header("Cookie", &fixture.cookie)
            .header("Host", "localhost")
            .header("Origin", "http://localhost")
            .header("Content-Type", "application/json");
        if let Some(csrf) = csrf {
            request = request.header("X-Agent-Access-CSRF", csrf);
        }
        let response = fixture
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, expected, "{uri}: {body}");
        if csrf.is_none() {
            assert_eq!(body["reasonCode"], "csrf_invalid");
        }
    }
    let inventory = inventory();
    assert!(inventory.read_only);
    assert_eq!(inventory.revision, revision + 1);
    let (status, session) = super::management_read_audit::cookie_get(
        fixture.app.clone(),
        fixture.cookie,
        fixture.csrf,
        "/v1/auth/session",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["result"]["authenticated"], true);
}

#[tokio::test]
async fn identity_management_committed_write_keeps_success_when_completion_audit_fails() {
    let fixture = fixture().await;
    let mutation_guard = fixture.state.policy_mutation_lock.lock().await;
    let app = fixture.app.clone();
    let token = fixture.admin.clone();
    let writer = tokio::spawn(async move {
        authed_json_request(
            app,
            Method::PATCH,
            GATE,
            "completion-failure",
            "Authorization",
            format!("Bearer {token}"),
            Some(r#"{"paused":true,"expectedVersion":1}"#),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture.records().iter().any(|record| {
                record["agentRequestId"] == "completion-failure"
                    && record["providerAudit"]["management"]["phase"] == "preflight"
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mandatory audit preflight should precede blocked write");
    let audit_blocker = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
    audit_blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    drop(mutation_guard);
    let response = writer.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["result"]["paused"], true);
    audit_blocker.execute_batch("ROLLBACK").unwrap();
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .identity_access("alice")
            .unwrap()
            .paused
    );
}

#[tokio::test]
async fn identity_management_binding_settings_patch_is_partial_and_audits_transaction_state() {
    let fixture = fixture().await;
    let (status, created) = admin(
        &fixture,
        Method::POST,
        BINDINGS,
        Some(
            r#"{"namespace":"Managed.Linux","username":"Alice+team@example.test","readOnly":true}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        path_settings(&created["result"], "version"),
        (true, true, 1)
    );
    let binding = created["result"]["bindingId"].as_str().unwrap().to_owned();
    let path = format!("{BINDINGS}/{binding}");
    for (body, expected) in [
        (
            r#"{"readOnly":false,"expectedVersion":1}"#,
            (true, false, 2),
        ),
        (
            r#"{"enabled":false,"expectedVersion":2}"#,
            (false, false, 3),
        ),
        (
            r#"{"enabled":true,"readOnly":true,"expectedVersion":3}"#,
            (true, true, 4),
        ),
        // Repeating current values writes nothing and keeps the version.
        (
            r#"{"enabled":true,"readOnly":true,"expectedVersion":4}"#,
            (true, true, 4),
        ),
        (r#"{"readOnly":true,"expectedVersion":4}"#, (true, true, 4)),
    ] {
        let (status, patched) = admin(&fixture, Method::PATCH, &path, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{body}: {patched}");
        let result = &patched["result"];
        assert_eq!(path_settings(result, "version"), expected, "{body}");
        assert_eq!(result["bindingId"], binding.as_str());
        assert_eq!(result["username"], "Alice+team@example.test");
        assert_eq!(result["namespaceAvailable"], true);
        assert_eq!(result["updatedBy"], "admin");
    }
    let (_, listed) = admin(&fixture, Method::GET, BINDINGS, None).await;
    assert_eq!(
        path_settings(&listed["result"]["bindings"][0], "version"),
        (true, true, 4)
    );
    // An omitted readOnly creates a full-access binding.
    let (status, second) = admin(
        &fixture,
        Method::POST,
        BINDINGS,
        Some(r#"{"namespace":"Managed.Linux","username":"second"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        path_settings(&second["result"], "version"),
        (true, false, 1)
    );
    let (status, _) = admin(
        &fixture,
        Method::DELETE,
        &format!("{path}?expectedVersion=4"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let settings = |enabled, read_only, version| json!({"enabled": enabled, "readOnly": read_only, "version": version});
    let preflights = targets(&phase_records(&fixture, BINDING_PATCH, "preflight"));
    assert_eq!(preflights.len(), 5);
    assert!(
        preflights
            .iter()
            .all(|target| *target == json!({"principal":"alice","bindingId":binding}))
    );
    let completed = targets(&phase_records(&fixture, BINDING_PATCH, "success"));
    let transitions = [
        ((true, true, 1), (true, false, 2)),
        ((true, false, 2), (false, false, 3)),
        ((false, false, 3), (true, true, 4)),
        ((true, true, 4), (true, true, 4)),
        ((true, true, 4), (true, true, 4)),
    ];
    assert_eq!(completed.len(), transitions.len());
    for (target, (before, after)) in completed.iter().zip(transitions) {
        assert_eq!(
            *target,
            json!({"principal":"alice","bindingId":binding,"namespace":"Managed.Linux",
                "before":settings(before.0, before.1, before.2),
                "after":settings(after.0, after.1, after.2)})
        );
    }
    let created = targets(&phase_records(
        &fixture,
        "admin.principals.identity_bindings.create",
        "success",
    ));
    assert_eq!(created[0]["before"], Value::Null);
    assert_eq!(created[0]["after"], settings(true, true, 1));
    assert_eq!(created[1]["after"], settings(true, false, 1));
    let deleted = targets(&phase_records(
        &fixture,
        "admin.principals.identity_bindings.delete",
        "success",
    ));
    assert_eq!(deleted[0]["before"], settings(true, true, 4));
    assert_eq!(deleted[0]["after"], Value::Null);
    let audits = serde_json::to_string(&fixture.records()).unwrap();
    assert!(!audits.contains("Alice+team@example.test"));
}

#[tokio::test]
async fn identity_management_settings_patches_reject_invalid_and_stale_requests() {
    let fixture = fixture().await;
    let (_, created) = admin(&fixture, Method::POST, BINDINGS, Some(CREATE)).await;
    let binding = format!(
        "{BINDINGS}/{}",
        created["result"]["bindingId"].as_str().unwrap()
    );
    for (path, fence, other) in [
        (binding.as_str(), "expectedVersion", "expectedRevision"),
        (TOKEN, "expectedRevision", "expectedVersion"),
    ] {
        for body in [
            String::new(),
            "{}".to_owned(),
            "[true,1]".to_owned(),
            format!(r#"{{"{fence}":1}}"#),
            format!(r#"{{"enabled":null,"{fence}":1}}"#),
            format!(r#"{{"readOnly":null,"{fence}":1}}"#),
            format!(r#"{{"readOnly":"true","{fence}":1}}"#),
            r#"{"enabled":true}"#.to_owned(),
            format!(r#"{{"enabled":true,"{fence}":0}}"#),
            format!(r#"{{"readOnly":true,"{fence}":-1}}"#),
            format!(r#"{{"enabled":true,"{other}":1}}"#),
            format!(r#"{{"enabled":true,"{fence}":1,"username":"replacement"}}"#),
            format!(r#"{{"readOnly":true,"readOnly":false,"{fence}":1}}"#),
        ] {
            let (status, error) = admin(&fixture, Method::PATCH, path, Some(&body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {body}: {error}");
            assert_eq!(error["reasonCode"], "input_invalid", "{path} {body}");
        }
        let (status, stale) = admin(
            &fixture,
            Method::PATCH,
            path,
            Some(&format!(r#"{{"readOnly":true,"{fence}":2}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {stale}");
        assert_eq!(stale["reasonCode"], "identity_version_conflict");
    }
    // Unknown principals and non-human principals are refused.
    let (status, missing) = admin(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/unknown/identity-token",
        Some(r#"{"readOnly":true,"expectedRevision":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    assert_eq!(missing["reasonCode"], "principal_not_found");
    let (status, created) = admin(
        &fixture,
        Method::POST,
        "/v1/admin/principals",
        Some(r#"{"principalId":"robot","kind":"service_account"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (status, refused) = admin(
        &fixture,
        Method::PATCH,
        "/v1/admin/principals/robot/identity-token",
        Some(r#"{"enabled":false,"expectedRevision":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["reasonCode"], "input_invalid");
    // Nothing changed: no completion was audited and both fences stand.
    for operation in [BINDING_PATCH, TOKEN_PATCH] {
        assert!(phase_records(&fixture, operation, "success").is_empty());
    }
    let (_, listed) = admin(&fixture, Method::GET, BINDINGS, None).await;
    assert_eq!(
        path_settings(&listed["result"]["bindings"][0], "version"),
        (true, false, 1)
    );
    let (_, inventory) = admin(&fixture, Method::GET, TOKEN, None).await;
    assert_eq!(
        path_settings(&inventory["result"], "revision"),
        (true, false, 1)
    );
}

#[tokio::test]
async fn identity_management_token_settings_patch_keeps_the_secret_lifecycle_independent() {
    let fixture = fixture().await;
    let (status, inventory) = admin(&fixture, Method::GET, TOKEN, None).await;
    assert_eq!(status, StatusCode::OK, "{inventory}");
    assert_eq!(inventory["result"]["configured"], false);
    assert_eq!(
        path_settings(&inventory["result"], "revision"),
        (true, false, 1)
    );
    // Settings apply to the not-configured row before any secret exists.
    for (body, expected) in [
        (r#"{"readOnly":true,"expectedRevision":1}"#, (true, true, 2)),
        (r#"{"readOnly":true,"expectedRevision":2}"#, (true, true, 2)),
        (
            r#"{"enabled":false,"expectedRevision":2}"#,
            (false, true, 3),
        ),
    ] {
        let (status, patched) = admin(&fixture, Method::PATCH, TOKEN, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{body}: {patched}");
        assert_eq!(path_settings(&patched["result"], "revision"), expected);
        assert_eq!(patched["result"]["configured"], false);
        assert_eq!(patched["result"]["principalId"], "alice");
        assert!(patched["result"].get("token").is_none());
        assert!(patched["result"].get("fingerprint").is_none());
    }
    // Generating, replacing and removing the secret keep both settings.
    let (status, generated) =
        admin(&fixture, Method::POST, &format!("{TOKEN}/generate"), None).await;
    assert_eq!(status, StatusCode::OK, "{generated}");
    assert_eq!(generated["result"]["configured"], true);
    assert_eq!(
        path_settings(&generated["result"], "revision"),
        (false, true, 4)
    );
    let (status, patched) = admin(
        &fixture,
        Method::PATCH,
        TOKEN,
        Some(r#"{"enabled":true,"readOnly":false,"expectedRevision":4}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["result"]["configured"], true);
    assert_eq!(
        path_settings(&patched["result"], "revision"),
        (true, false, 5)
    );
    let secret = "00000000-0000-4000-8000-00000000c0de";
    let (status, set) = admin(
        &fixture,
        Method::PUT,
        TOKEN,
        Some(&json!({"token": secret}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(path_settings(&set["result"], "revision"), (true, false, 6));
    let (status, revealed) = admin(&fixture, Method::POST, &format!("{TOKEN}/reveal"), None).await;
    assert_eq!(status, StatusCode::OK, "{revealed}");
    assert_eq!(revealed["result"]["token"], secret);
    let (status, _) = admin(
        &fixture,
        Method::PATCH,
        TOKEN,
        Some(r#"{"readOnly":true,"expectedRevision":6}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A settings change never touches the secret.
    let (_, revealed) = admin(&fixture, Method::POST, &format!("{TOKEN}/reveal"), None).await;
    assert_eq!(revealed["result"]["token"], secret);
    let (status, removed) = admin(&fixture, Method::DELETE, TOKEN, None).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["result"]["configured"], false);
    assert_eq!(
        path_settings(&removed["result"], "revision"),
        (true, true, 8)
    );

    let settings = |enabled, read_only, revision| json!({"enabled": enabled, "readOnly": read_only, "revision": revision});
    let preflights = targets(&phase_records(&fixture, TOKEN_PATCH, "preflight"));
    assert_eq!(preflights.len(), 5);
    assert!(
        preflights
            .iter()
            .all(|target| *target == json!({"principal":"alice"}))
    );
    let completed = targets(&phase_records(&fixture, TOKEN_PATCH, "success"));
    let transitions = [
        ((true, false, 1), (true, true, 2)),
        ((true, true, 2), (true, true, 2)),
        ((true, true, 2), (false, true, 3)),
        ((false, true, 4), (true, false, 5)),
        ((true, false, 6), (true, true, 7)),
    ];
    assert_eq!(completed.len(), transitions.len());
    for (target, (before, after)) in completed.iter().zip(transitions) {
        assert_eq!(
            *target,
            json!({"principal":"alice",
                "before":settings(before.0, before.1, before.2),
                "after":settings(after.0, after.1, after.2)})
        );
    }
    for (operation, configured, after) in [
        ("generate", true, (false, true, 4)),
        ("set", true, (true, false, 6)),
        ("remove", false, (true, true, 8)),
    ] {
        let completed = targets(&phase_records(
            &fixture,
            &format!("admin.principals.identity_token.{operation}"),
            "success",
        ));
        assert_eq!(completed.len(), 1, "{operation}");
        assert_eq!(
            completed[0]["after"],
            json!({"configured": configured, "enabled": after.0, "readOnly": after.1, "revision": after.2}),
            "{operation}"
        );
    }
    let audits = serde_json::to_string(&fixture.records()).unwrap();
    assert!(!audits.contains(secret));
}
