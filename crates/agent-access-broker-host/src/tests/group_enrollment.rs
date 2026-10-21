//! Managed group enrollment settings use normal admin authority and captured audit changes.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::*;
use agent_access_core::{GroupWriteRequest, PrincipalAccessPatchRequest, PrincipalRole};
use axum::http::{HeaderMap, HeaderValue};

fn events(fixture: &AuditFixture, request_id: &str) -> Vec<Value> {
    fixture
        .records()
        .into_iter()
        .filter(|record| record["agentRequestId"] == request_id)
        .collect()
}

fn assert_change(fixture: &AuditFixture, request_id: &str, previous: bool, current: bool) {
    let events = events(fixture, request_id);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["brokerRequestId"], events[1]["brokerRequestId"]);
    assert_eq!(
        events[0]["providerAudit"]["management"]["phase"],
        "preflight"
    );
    assert_eq!(
        events[0]["providerAudit"]["management"]["target"],
        json!({
            "group":"onboarding", "autoEnrollNewMicrosoftUsers":current,
        })
    );
    assert_eq!(events[1]["providerAudit"]["management"]["phase"], "success");
    assert_eq!(
        events[1]["providerAudit"]["management"]["target"],
        json!({
            "group":"onboarding", "autoEnrollNewMicrosoftUsers":{"previous":previous,"current":current},
        })
    );
}

#[tokio::test]
async fn group_enrollment_http_crud_and_captured_audit_round_trip() {
    for backend in [Backend::Sqlite, Backend::Jsonl] {
        let fixture = audit_fixture(backend).await;
        let (status, created) = fixture.request(Method::POST, &fixture.admin, "/v1/admin/groups",
            Some(r#"{"groupId":"onboarding","displayName":"Private label","description":"Private description","autoEnrollNewMicrosoftUsers":true}"#), "enrollment-create").await;
        assert_eq!(status, StatusCode::OK, "{created}");
        assert_eq!(created["result"]["autoEnrollNewMicrosoftUsers"], true);
        assert_change(&fixture, "enrollment-create", false, true);

        let (status, listed) = fixture
            .request(
                Method::GET,
                &fixture.admin,
                "/v1/admin/groups",
                None,
                "enrollment-list",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["result"][0]["autoEnrollNewMicrosoftUsers"], true);
        let (status, inspected) = fixture
            .request(
                Method::GET,
                &fixture.admin,
                "/v1/admin/groups/onboarding",
                None,
                "enrollment-inspect",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{inspected}");
        assert_eq!(inspected["result"]["autoEnrollNewMicrosoftUsers"], true);

        let (status, no_op) = fixture
            .request(
                Method::PATCH,
                &fixture.admin,
                "/v1/admin/groups/onboarding",
                Some(r#"{"autoEnrollNewMicrosoftUsers":true}"#),
                "enrollment-no-op",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{no_op}");
        assert_eq!(no_op["result"]["updatedAt"], created["result"]["updatedAt"]);
        assert_eq!(events(&fixture, "enrollment-no-op").len(), 1);

        let (status, changed) = fixture
            .request(
                Method::PATCH,
                &fixture.admin,
                "/v1/admin/groups/onboarding",
                Some(r#"{"autoEnrollNewMicrosoftUsers":false}"#),
                "enrollment-clear",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["result"]["autoEnrollNewMicrosoftUsers"], false);
        assert_change(&fixture, "enrollment-clear", true, false);

        let (status, metadata) = fixture
            .request(
                Method::PATCH,
                &fixture.admin,
                "/v1/admin/groups/onboarding",
                Some(r#"{"description":"A different private description"}"#),
                "enrollment-metadata",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{metadata}");
        assert_eq!(metadata["result"]["autoEnrollNewMicrosoftUsers"], false);
        let metadata_events = events(&fixture, "enrollment-metadata");
        assert_eq!(metadata_events.len(), 1);
        assert_eq!(
            metadata_events[0]["providerAudit"]["management"]["target"],
            json!({"group":"onboarding"})
        );

        for (group, supplied) in [
            ("omitted", ""),
            ("explicit-false", ",\"autoEnrollNewMicrosoftUsers\":false"),
        ] {
            let request_id = format!("enrollment-create-{group}");
            let body = format!("{{\"groupId\":\"{group}\"{supplied}}}");
            let (status, result) = fixture
                .request(
                    Method::POST,
                    &fixture.admin,
                    "/v1/admin/groups",
                    Some(&body),
                    &request_id,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{result}");
            assert_eq!(result["result"]["autoEnrollNewMicrosoftUsers"], false);
            assert_eq!(events(&fixture, &request_id).len(), 1);
        }
        for request_id in [
            "enrollment-create",
            "enrollment-clear",
            "enrollment-metadata",
        ] {
            let serialized = serde_json::to_string(&events(&fixture, request_id)).unwrap();
            assert!(!serialized.contains("Private label"));
            assert!(!serialized.contains("Private description"));
            assert!(!serialized.contains("A different private description"));
        }
    }
}

#[tokio::test]
async fn group_enrollment_rejects_null_and_non_boolean_settings() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .create_group(GroupWriteRequest {
            group_id: "onboarding".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: false,
            created_by: "test".into(),
        })
        .unwrap();
    for value in [Value::Null, json!("true"), json!(1), json!([]), json!({})] {
        for method in [Method::POST, Method::PATCH] {
            let mut body = json!({"autoEnrollNewMicrosoftUsers":value});
            let path = if method == Method::POST {
                body["groupId"] = json!("invalid");
                "/v1/admin/groups"
            } else {
                "/v1/admin/groups/onboarding"
            };
            let response = authed_json_request(
                fixture.app.clone(),
                method,
                path,
                "enrollment-invalid",
                "Authorization",
                format!("Bearer {}", fixture.admin),
                Some(&body.to_string()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    assert!(store.group("invalid").is_err());
    assert!(
        !store
            .group("onboarding")
            .unwrap()
            .auto_enroll_new_microsoft_users
    );
}

#[tokio::test]
async fn group_enrollment_requires_admin_write_authority() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .create_group(GroupWriteRequest {
            group_id: "onboarding".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: false,
            created_by: "test".into(),
        })
        .unwrap();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "carol".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let auditor = store
        .issue_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "carol".into(),
                name: "auditor".into(),
                token_class: agent_access_core::BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token;
    for token in [&fixture.alice, &fixture.bob, &auditor] {
        for (method, path, body) in [
            (
                Method::POST,
                "/v1/admin/groups",
                r#"{"groupId":"denied","autoEnrollNewMicrosoftUsers":true}"#,
            ),
            (
                Method::PATCH,
                "/v1/admin/groups/onboarding",
                r#"{"autoEnrollNewMicrosoftUsers":true}"#,
            ),
        ] {
            let (status, result) = fixture
                .request(method, token, path, Some(body), "enrollment-denied")
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{result}");
        }
    }
    assert!(store.group("denied").is_err());
    assert!(
        !store
            .group("onboarding")
            .unwrap()
            .auto_enroll_new_microsoft_users
    );
}

#[tokio::test]
async fn group_enrollment_browser_edits_require_csrf() {
    let fixture = browser_rate_fixture(test_limits()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    for (method, path, body) in [
        (
            Method::POST,
            "/v1/admin/groups",
            r#"{"groupId":"onboarding","autoEnrollNewMicrosoftUsers":true}"#,
        ),
        (
            Method::PATCH,
            "/v1/admin/groups/onboarding",
            r#"{"autoEnrollNewMicrosoftUsers":false}"#,
        ),
    ] {
        for csrf in [None, Some(fixture.csrf.as_str())] {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(path)
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "enrollment-browser-csrf")
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
            let result = response_json(response).await;
            assert_eq!(
                status,
                if csrf.is_some() {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                },
                "{result}"
            );
            if csrf.is_none() {
                assert_eq!(result["reasonCode"], "csrf_invalid");
            }
        }
    }
    assert!(
        !store
            .group("onboarding")
            .unwrap()
            .auto_enroll_new_microsoft_users
    );
}

#[tokio::test]
async fn group_enrollment_preflight_failure_prevents_write_and_completion_failure_preserves_commit()
{
    for operation in ["admin.groups.create", "admin.groups.patch"] {
        for phase in ["preflight", "success"] {
            let fixture = audit_fixture(Backend::Sqlite).await;
            let store = fixture
                .state
                .current()
                .runtime
                .managed_store()
                .unwrap()
                .clone();
            let is_create = operation == "admin.groups.create";
            if !is_create {
                store
                    .create_group(GroupWriteRequest {
                        group_id: "onboarding".into(),
                        display_name: None,
                        description: None,
                        auto_enroll_new_microsoft_users: false,
                        created_by: "test".into(),
                    })
                    .unwrap();
            }
            let connection =
                rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
            connection.execute_batch(&format!("CREATE TRIGGER fail_enrollment_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{phase}' AND NEW.action = '{operation}' BEGIN SELECT RAISE(ABORT, 'private-audit-failure'); END;")).unwrap();
            let (method, path, body) = if is_create {
                (
                    Method::POST,
                    "/v1/admin/groups",
                    r#"{"groupId":"onboarding","autoEnrollNewMicrosoftUsers":true}"#,
                )
            } else {
                (
                    Method::PATCH,
                    "/v1/admin/groups/onboarding",
                    r#"{"autoEnrollNewMicrosoftUsers":true}"#,
                )
            };
            let (status, result) = fixture
                .request(
                    method,
                    &fixture.admin,
                    path,
                    Some(body),
                    "enrollment-audit-failure",
                )
                .await;
            if phase == "preflight" {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
                assert_eq!(result["reasonCode"], "audit_unavailable");
                if is_create {
                    assert!(store.group("onboarding").is_err());
                } else {
                    assert!(
                        !store
                            .group("onboarding")
                            .unwrap()
                            .auto_enroll_new_microsoft_users
                    );
                }
            } else {
                assert_eq!(status, StatusCode::OK, "{result}");
                assert_eq!(result["result"]["autoEnrollNewMicrosoftUsers"], true);
                assert!(
                    store
                        .group("onboarding")
                        .unwrap()
                        .auto_enroll_new_microsoft_users
                );
                let audit = events(&fixture, "enrollment-audit-failure");
                assert_eq!(audit.len(), 1);
                assert_eq!(
                    audit[0]["providerAudit"]["management"]["phase"],
                    "preflight"
                );
            }
            assert!(!result.to_string().contains("private-audit-failure"));
        }
    }
}

#[tokio::test]
async fn group_enrollment_mutation_owner_completes_audit_after_waiter_cancellation() {
    use crate::handlers::management::admin::committed_group_mutation;
    use crate::handlers::management::common::{
        ManagementAccess, management_context, management_write_audit_preflight,
    };
    let fixture = audit_fixture(Backend::Sqlite).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", fixture.admin)).unwrap(),
    );
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("enrollment-cancelled"),
    );
    let operation = "admin.groups.create";
    let context = management_context(
        &crate::state::AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    let target = Some(json!({"group":"onboarding","autoEnrollNewMicrosoftUsers":true}));
    management_write_audit_preflight(&context, operation, target.clone())
        .await
        .unwrap();
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(committed_group_mutation(
        context,
        operation,
        target,
        move |store| {
            let result = store.create_group_with_effect(GroupWriteRequest {
                group_id: "onboarding".into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: true,
                created_by: "admin".into(),
            })?;
            committed_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(result)
        },
    ));
    committed_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if events(&fixture, "enrollment-cancelled").len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_change(&fixture, "enrollment-cancelled", false, true);
}
