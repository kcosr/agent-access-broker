//! Administrator enrollment through the HTTP authorization, CSRF and audit boundaries.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::*;
use agent_access_core::{ManagedStore, OidcProviderStateReconcileRequest};

const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const ENROLLMENT: &str = "/v1/admin/principals/alice/login-methods/oidc/microsoft/enrollment";

fn paused_provider(store: &ManagedStore) {
    store
        .reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
            tenant_id: TENANT.into(),
            client_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2".into(),
            enabled: false,
            config_fingerprint: "enrollment-test".into(),
            external_membership_ttl_seconds: 3600,
            membership_renewal: false,
            invalidate_existing_evidence: false,
            actor: "test".into(),
        })
        .unwrap();
}

fn store(fixture: &AuditFixture) -> ManagedStore {
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn microsoft_enrollment_crud_paused_provider_versions_and_safe_audit() {
    for backend in [Backend::Sqlite, Backend::Jsonl] {
        let fixture = audit_fixture(backend).await;
        let store = store(&fixture);
        paused_provider(&store);
        let (status, config) = fixture
            .request(
                Method::GET,
                &fixture.admin,
                "/v1/admin/config/status",
                None,
                "enrollment-status",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{config}");
        assert_eq!(
            config["result"]["microsoftEnrollment"],
            json!({"available":true,"tenantId":TENANT})
        );
        let (status, empty) = fixture
            .request(
                Method::GET,
                &fixture.admin,
                ENROLLMENT,
                None,
                "enrollment-empty",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{empty}");
        assert_eq!(empty["result"], Value::Null);
        let (status, created) = fixture
            .request(
                Method::POST,
                &fixture.admin,
                ENROLLMENT,
                Some(r#"{"email":"  ADA@Example.Test  "}"#),
                "ms-enrollment-create",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let record = &created["result"];
        assert_eq!(record["matchEmail"], "ada@example.test");
        assert_eq!(record["tenantId"], TENANT);
        assert_eq!(record["revision"], 1);
        let original = json!({"enrollmentId":record["enrollmentId"],"expectedRevision":1});
        let (status, duplicate) = fixture
            .request(
                Method::POST,
                &fixture.admin,
                ENROLLMENT,
                Some(r#"{"email":"different@example.test"}"#),
                "ms-enrollment-duplicate",
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{duplicate}");
        let (status, inspected) = fixture
            .request(
                Method::GET,
                &fixture.admin,
                "/v1/admin/principals/alice",
                None,
                "ms-enrollment-principal",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{inspected}");
        assert_eq!(inspected["result"]["microsoftEnrollment"], *record);
        let (status, profile) = fixture
            .request(
                Method::PATCH,
                &fixture.admin,
                "/v1/admin/principals/alice",
                Some(r#"{"email":"profile@example.test","status":"disabled"}"#),
                "ms-enrollment-profile",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{profile}");
        assert_eq!(
            store
                .microsoft_enrollment("alice")
                .unwrap()
                .unwrap()
                .match_email,
            "ada@example.test"
        );
        let (status, conflict) = fixture.request(Method::POST, &fixture.admin, "/v1/admin/principals", Some(r#"{"principalId":"duplicate","microsoftEnrollment":{"email":"ada@example.test"}}"#), "ms-enrollment-reserved").await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
        assert!(
            store.principal("duplicate").is_err(),
            "creation rolls back with reservation conflict"
        );
        let mut edit = original.clone();
        edit["email"] = json!("new@example.test");
        let (status, updated) = fixture
            .request(
                Method::PATCH,
                &fixture.admin,
                ENROLLMENT,
                Some(&edit.to_string()),
                "ms-enrollment-update",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["result"]["revision"], 2);
        assert_eq!(updated["result"]["enrollmentId"], record["enrollmentId"]);
        let (status, stale) = fixture
            .request(
                Method::DELETE,
                &fixture.admin,
                ENROLLMENT,
                Some(&original.to_string()),
                "ms-enrollment-stale",
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{stale}");
        let (status, linked) = fixture
            .request(
                Method::PUT,
                &fixture.admin,
                "/v1/admin/principals/alice/login-methods/oidc/microsoft",
                Some(r#"{"userObjectId":"cccccccc-cccc-4ccc-8ccc-ccccccccccc3"}"#),
                "ms-enrollment-link-conflict",
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{linked}");
        let current = json!({"enrollmentId":record["enrollmentId"],"expectedRevision":2});
        let (status, cancelled) = fixture
            .request(
                Method::DELETE,
                &fixture.admin,
                ENROLLMENT,
                Some(&current.to_string()),
                "ms-enrollment-cancel",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{cancelled}");
        assert_eq!(cancelled["result"], json!({"cancelled":true}));
        assert!(store.microsoft_enrollment("alice").unwrap().is_none());
        assert_eq!(
            store.principal("alice").unwrap().email.as_deref(),
            Some("profile@example.test")
        );
        let events = fixture.records();
        for request in [
            "ms-enrollment-create",
            "ms-enrollment-update",
            "ms-enrollment-cancel",
        ] {
            let audit: Vec<_> = events
                .iter()
                .filter(|event| event["agentRequestId"] == request)
                .collect();
            assert_eq!(audit.len(), 2, "{audit:?}");
            let target = &audit[1]["providerAudit"]["management"]["target"];
            assert_eq!(target["enrollmentId"], record["enrollmentId"]);
            assert_eq!(target["tenantId"], TENANT);
            let encoded = serde_json::to_string(&audit).unwrap();
            assert!(
                !encoded.contains("example.test"),
                "email leaked in {encoded}"
            );
        }
    }
}

#[tokio::test]
async fn microsoft_enrollment_creation_is_atomic_and_requires_provider() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let store = store(&fixture);
    let body = r#"{"principalId":"prepared","email":"profile@example.test","microsoftEnrollment":{"email":"ada@example.test"}}"#;
    let (status, unavailable) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/principals",
            Some(body),
            "ms-create-unavailable",
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unavailable}");
    assert!(store.principal("prepared").is_err());
    paused_provider(&store);
    let (status, created) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/principals",
            Some(body),
            "ms-create-atomic",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["result"]["email"], "profile@example.test");
    assert_eq!(
        created["result"]["microsoftEnrollment"]["matchEmail"],
        "ada@example.test"
    );
    assert!(store.list_login_methods("prepared").unwrap().is_empty());
    for (id, kind, email) in [
        ("invalid", "user", "bad"),
        ("system", "system", "system@example.test"),
    ] {
        let body = json!({"principalId":id,"kind":kind,"microsoftEnrollment":{"email":email}});
        let (status, result) = fixture
            .request(
                Method::POST,
                &fixture.admin,
                "/v1/admin/principals",
                Some(&body.to_string()),
                "ms-create-invalid",
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        assert!(store.principal(id).is_err());
    }
}

#[tokio::test]
async fn microsoft_enrollment_admin_cookie_mutations_require_csrf() {
    let fixture = browser_rate_fixture(test_limits()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    paused_provider(store);
    store
        .patch_principal_access(
            agent_access_core::PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: Some(agent_access_core::PrincipalRole::Admin),
                self_service_enabled: None,
                agent_token_issuance: None,
                actor: "test".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let inspected = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        ENROLLMENT,
        "ms-cookie-inspect",
        "Cookie",
        fixture.cookie.clone(),
        None,
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    assert_eq!(response_json(inspected).await["result"], Value::Null);
    for (method, body) in [
        (Method::POST, json!({"email":"ada@example.test"})),
        (
            Method::PATCH,
            json!({"enrollmentId":"00000000-0000-4000-8000-000000000001","expectedRevision":1,"email":"ada@example.test"}),
        ),
        (
            Method::DELETE,
            json!({"enrollmentId":"00000000-0000-4000-8000-000000000001","expectedRevision":1}),
        ),
    ] {
        let response = authed_json_request(
            fixture.app.clone(),
            method,
            ENROLLMENT,
            "ms-csrf-denied",
            "Cookie",
            fixture.cookie.clone(),
            Some(&body.to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_json(response).await["reasonCode"], "csrf_invalid");
    }
    let response = fixture
        .browser_request(
            Method::POST,
            ENROLLMENT,
            Some(json!({"email":"ada@example.test"})),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response_json(response).await
    );
}

#[tokio::test]
async fn microsoft_enrollment_preflight_failure_prevents_mutation_completion_failure_retains_it() {
    for phase in ["preflight", "success"] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let store = store(&fixture);
        paused_provider(&store);
        let db = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER fail_ms_enrollment_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{phase}' AND NEW.action = 'admin.principals.login_methods.oidc.microsoft.enrollment.create' BEGIN SELECT RAISE(ABORT, 'injected-failure'); END;")).unwrap();
        let (status, result) = fixture
            .request(
                Method::POST,
                &fixture.admin,
                ENROLLMENT,
                Some(r#"{"email":"ada@example.test"}"#),
                "ms-audit-failure",
            )
            .await;
        assert_eq!(
            status,
            if phase == "preflight" {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            "{result}"
        );
        assert_eq!(
            store.microsoft_enrollment("alice").unwrap().is_some(),
            phase == "success"
        );
    }
}

async fn admitted_create_context(
    fixture: &AuditFixture,
    request_id: &'static str,
) -> crate::handlers::management::common::ManagementContext {
    use crate::handlers::management::common::{
        ManagementAccess, management_context, management_write_audit_preflight,
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "Authorization",
        axum::http::HeaderValue::from_str(&format!("Bearer {}", fixture.admin)).unwrap(),
    );
    headers.insert(
        REQUEST_ID_HEADER,
        axum::http::HeaderValue::from_static(request_id),
    );
    let context = management_context(
        &crate::state::AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        "admin.principals.login_methods.oidc.microsoft.enrollment.create",
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(
        &context,
        "admin.principals.login_methods.oidc.microsoft.enrollment.create",
        Some(json!({"principal":"alice","provider":"microsoft"})),
    )
    .await
    .unwrap();
    context
}

#[tokio::test]
async fn microsoft_enrollment_mutation_owner_audits_captured_commit_after_disconnect() {
    use crate::handlers::management::microsoft_enrollments::committed_mutation;
    let fixture = audit_fixture(Backend::Sqlite).await;
    let store = store(&fixture);
    paused_provider(&store);
    let context = admitted_create_context(&fixture, "ms-disconnected").await;
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(committed_mutation(
        crate::state::AppState {
            reloadable: fixture.state.clone(),
        },
        context,
        "admin.principals.login_methods.oidc.microsoft.enrollment.create",
        Some(json!({"principal":"alice","provider":"microsoft"})),
        false,
        move |runtime| {
            let store = runtime.managed_store().unwrap();
            let result = store.create_microsoft_enrollment(
                agent_access_core::MicrosoftEnrollmentCreateRequest {
                    principal_id: "alice".into(),
                    email: "ada@example.test".into(),
                    provider_generation: store.oidc_provider_state()?.unwrap().config_generation,
                    actor: "admin".into(),
                },
            )?;
            committed_tx.send(result.clone()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(result)
        },
    ));
    let record = committed_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    // A later administrative edit cannot rewrite the first operation's receipt.
    store
        .update_microsoft_enrollment(agent_access_core::MicrosoftEnrollmentUpdateRequest {
            principal_id: "alice".into(),
            enrollment_id: record.enrollment_id.clone(),
            expected_revision: record.revision,
            email: "replacement@example.test".into(),
            provider_generation: store
                .oidc_provider_state()
                .unwrap()
                .unwrap()
                .config_generation,
            actor: "admin".into(),
        })
        .unwrap();
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if fixture.records().iter().any(|event| {
                event["agentRequestId"] == "ms-disconnected"
                    && event["providerAudit"]["management"]["phase"] == "success"
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let records = fixture.records();
    let audit = records
        .iter()
        .find(|event| {
            event["agentRequestId"] == "ms-disconnected"
                && event["providerAudit"]["management"]["phase"] == "success"
        })
        .unwrap();
    assert_eq!(
        audit["providerAudit"]["management"]["target"]["revision"],
        1
    );
    assert_eq!(
        audit["providerAudit"]["management"]["target"]["enrollmentId"],
        record.enrollment_id
    );
    assert_eq!(
        store
            .microsoft_enrollment("alice")
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn microsoft_enrollment_mutation_rejects_superseded_snapshot_before_write() {
    use crate::handlers::management::microsoft_enrollments::committed_mutation;
    let fixture = audit_fixture(Backend::Sqlite).await;
    paused_provider(&store(&fixture));
    let context = admitted_create_context(&fixture, "ms-stale-snapshot").await;
    let old = fixture.state.current();
    fixture
        .state
        .active
        .store(Arc::new(crate::state::RuntimeSnapshot {
            generation: old.generation + 1,
            ..(*old).clone()
        }));
    let response = committed_mutation(
        crate::state::AppState {
            reloadable: fixture.state.clone(),
        },
        context,
        "admin.principals.login_methods.oidc.microsoft.enrollment.create",
        Some(json!({"principal":"alice","provider":"microsoft"})),
        false,
        |_| panic!("stale snapshot must be refused before mutation"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        store(&fixture)
            .microsoft_enrollment("alice")
            .unwrap()
            .is_none()
    );
}
