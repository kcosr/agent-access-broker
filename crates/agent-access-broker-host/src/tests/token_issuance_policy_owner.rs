//! Policy writes retain the registry fence and own their transaction-captured
//! receipts independently of an HTTP response waiter.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::*;
use crate::handlers::management::admin::{committed_group_mutation, committed_principal_mutation};
use crate::handlers::management::common::{
    ManagementAccess, ManagementContext, management_context, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    GroupAgentTokenIssuanceSetting, GroupWriteRequest, PrincipalAgentTokenIssuance,
    PrincipalAgentTokenIssuanceSetting,
};
use axum::http::{HeaderMap, HeaderValue};

async fn context(
    fixture: &AuditFixture,
    operation: &'static str,
    request: &'static str,
) -> ManagementContext {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", fixture.admin)).unwrap(),
    );
    headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static(request));
    let context = management_context(
        &AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(&context, operation, None)
        .await
        .unwrap();
    context
}

fn events(fixture: &AuditFixture, request: &str) -> Vec<Value> {
    fixture
        .records()
        .into_iter()
        .filter(|event| event["agentRequestId"] == request)
        .collect()
}

fn config_for_reload(fixture: &AuditFixture) -> BrokerConfig {
    let mut config = fixture.broker.runtime().config().clone();
    let credential = fixture
        .broker
        .running()
        .directory()
        .secret_file("policy-reload.token", "synthetic-policy-reload-token")
        .unwrap();
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", credential.display()));
    config
}

async fn completion(fixture: &AuditFixture, request: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(event) = events(fixture, request)
                .into_iter()
                .find(|event| event["providerAudit"]["management"]["phase"] == "success")
            {
                return event;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn principal_creation_and_access_receipts_survive_cancellation_and_capture_the_committed_pair()
 {
    for (create, explicit) in [(true, false), (true, true), (false, true)] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let operation = if create {
            "admin.principals.create"
        } else {
            "admin.principals.access.patch"
        };
        let principal_id = if create { "created-user" } else { "alice" };
        let setting = if explicit {
            PrincipalAgentTokenIssuanceSetting::new(
                PrincipalAgentTokenIssuance::ReadOnly,
                vec!["default".into()],
            )
            .unwrap()
        } else {
            PrincipalAgentTokenIssuanceSetting::default()
        };
        let expected = serde_json::to_value(&setting).unwrap();
        let context = context(&fixture, operation, "policy-owner-cancelled").await;
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(committed_principal_mutation(
            AppState {
                reloadable: fixture.state.clone(),
            },
            context,
            operation,
            None,
            move |store, environment| {
                let principal = if create {
                    store.create_principal(
                        PrincipalWriteRequest {
                            principal_id: principal_id.into(),
                            kind: "user".into(),
                            display_name: None,
                            email: None,
                            external_subject: None,
                            role: Default::default(),
                            self_service_enabled: None,
                            agent_token_issuance: setting,
                            created_by: "admin".into(),
                        },
                        environment.contexts(),
                    )?
                } else {
                    store
                        .patch_principal_access(
                            agent_access_core::PrincipalAccessPatchRequest {
                                principal_id: principal_id.into(),
                                role: None,
                                self_service_enabled: None,
                                agent_token_issuance: Some(setting),
                                actor: "admin".into(),
                            },
                            environment.contexts(),
                        )?
                        .principal
                };
                let receipt = json!({"principal":principal.principal_id, "agentTokenIssuance":principal.agent_token_issuance});
                committed_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok((principal, receipt))
            },
        ));
        committed_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(fixture.state.policy_mutation_lock.try_lock().is_err());
        let runtime = fixture.broker.runtime();
        runtime
            .managed_store()
            .unwrap()
            .patch_principal_access(
                agent_access_core::PrincipalAccessPatchRequest {
                    principal_id: principal_id.into(),
                    role: None,
                    self_service_enabled: None,
                    agent_token_issuance: Some(
                        PrincipalAgentTokenIssuanceSetting::new(
                            PrincipalAgentTokenIssuance::Disabled,
                            vec![],
                        )
                        .unwrap(),
                    ),
                    actor: "admin".into(),
                },
                runtime.execution_context_registry(),
            )
            .unwrap();
        release_tx.send(()).unwrap();
        let receipt = completion(&fixture, "policy-owner-cancelled").await;
        assert_eq!(
            receipt["providerAudit"]["management"]["target"]["agentTokenIssuance"],
            expected
        );
        assert_eq!(events(&fixture, "policy-owner-cancelled").len(), 2);
    }
}

#[tokio::test]
async fn actual_principal_routes_capture_creation_defaults_and_keep_commits_after_completion_failure()
 {
    for (path, method, body, principal_id, expected) in [
        (
            "/v1/admin/principals",
            Method::POST,
            json!({"principalId":"default-user"}),
            "default-user",
            json!({"mode":"inherit","allowedExecutionContexts":[]}),
        ),
        (
            "/v1/admin/principals",
            Method::POST,
            json!({"principalId":"explicit-user","agentTokenIssuance":{"mode":"read_only","allowedExecutionContexts":["default"]}}),
            "explicit-user",
            json!({"mode":"read_only","allowedExecutionContexts":["default"]}),
        ),
        (
            "/v1/admin/principals/alice/access",
            Method::PATCH,
            json!({"agentTokenIssuance":{"mode":"write_capable","allowedExecutionContexts":["default"]}}),
            "alice",
            json!({"mode":"write_capable","allowedExecutionContexts":["default"]}),
        ),
    ] {
        for fail_completion in [false, true] {
            let fixture = audit_fixture(Backend::Sqlite).await;
            if fail_completion {
                let db = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
                db.execute_batch("CREATE TRIGGER fail_policy_receipt BEFORE INSERT ON audit_events WHEN NEW.phase = 'success' BEGIN SELECT RAISE(ABORT, 'private-policy-receipt'); END;").unwrap();
            }
            let captured = install_trace_capture().start();
            let (status, result) = captured
                .run(fixture.request(
                    method.clone(),
                    &fixture.admin,
                    path,
                    Some(&body.to_string()),
                    "actual-policy-receipt",
                ))
                .await;
            assert_eq!(status, StatusCode::OK, "{result}");
            assert_eq!(result["result"]["agentTokenIssuance"], expected);
            assert_eq!(
                serde_json::to_value(
                    fixture
                        .broker
                        .runtime()
                        .managed_store()
                        .unwrap()
                        .principal(principal_id)
                        .unwrap()
                        .agent_token_issuance
                )
                .unwrap(),
                expected
            );
            if !fail_completion {
                let receipt = completion(&fixture, "actual-policy-receipt").await;
                assert_eq!(
                    receipt["providerAudit"]["management"]["target"]["agentTokenIssuance"],
                    expected
                );
            } else {
                assert!(
                    captured.take_events().iter().any(|event| event["event"]
                        == "management_committed_write_audit_append_failed"
                        && event["agentRequestId"] == "actual-policy-receipt"),
                    "the mutation owner must preserve the request's diagnostic subscriber"
                );
            }
            if method == Method::POST {
                let (status, _) = fixture
                    .request(
                        Method::POST,
                        &fixture.admin,
                        path,
                        Some(&body.to_string()),
                        "duplicate-policy-create",
                    )
                    .await;
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(
                    !events(&fixture, "duplicate-policy-create")
                        .iter()
                        .any(|event| event["providerAudit"]["management"]["phase"] == "success")
                );
            }
        }
    }
}

#[tokio::test]
async fn group_mutation_holds_registry_fence_through_commit_and_retirement_requires_cleanup() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let mut config = config_for_reload(&fixture);
    config.execution_context = Some(agent_access_core::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "retired".into()],
        default_context: Some("default".into()),
    });
    fixture.broker.reload_config(&config).await;
    let context = context(&fixture, "admin.groups.create", "group-registry-fence").await;
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(committed_group_mutation(
        AppState {
            reloadable: fixture.state.clone(),
        },
        context,
        "admin.groups.create",
        None,
        move |store, environment| {
            let result = store.create_group_with_effect(
                GroupWriteRequest {
                    group_id: "retirement-blocker".into(),
                    display_name: None,
                    description: None,
                    auto_enroll_new_microsoft_users: false,
                    agent_token_issuance: GroupAgentTokenIssuanceSetting::new(
                        agent_access_core::AgentTokenIssuanceMode::ReadOnly,
                        vec!["retired".into()],
                    )
                    .unwrap(),
                    created_by: "admin".into(),
                },
                environment.contexts(),
            )?;
            committed_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(result)
        },
    ));
    committed_rx.await.unwrap();
    let current = fixture.state.current();
    config.execution_context.as_mut().unwrap().allowed_values = vec!["default".into()];
    fixture
        .broker
        .running()
        .rewrite_config(super::broker::ConfigDoc::from_config(&config).render())
        .unwrap();
    assert!(
        !fixture
            .broker
            .running()
            .reload()
            .await
            .unwrap()
            .is_success()
    );
    assert!(Arc::ptr_eq(&current, &fixture.state.current()));
    release_tx.send(()).unwrap();
    assert_eq!(waiter.await.unwrap().status(), StatusCode::OK);
    let receipt = completion(&fixture, "group-registry-fence").await;
    assert_eq!(
        receipt["providerAudit"]["management"]["target"]["agentTokenIssuance"],
        json!({
            "previous":{"mode":"disabled","allowedExecutionContexts":[]},
            "current":{"mode":"read_only","allowedExecutionContexts":["retired"]},
        })
    );
    assert!(
        !fixture
            .broker
            .running()
            .reload()
            .await
            .unwrap()
            .is_success()
    );
    assert!(Arc::ptr_eq(&current, &fixture.state.current()));
    let (status, body) = fixture
        .request(
            Method::PATCH,
            &fixture.admin,
            "/v1/admin/groups/retirement-blocker",
            Some(r#"{"agentTokenIssuance":{"mode":"disabled","allowedExecutionContexts":[]}}"#),
            "retirement-cleanup",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        fixture
            .broker
            .running()
            .reload()
            .await
            .unwrap()
            .is_success()
    );
}

#[tokio::test]
async fn policy_writers_reject_old_snapshot_after_actual_registry_reload() {
    for group in [false, true] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let operation = if group {
            "admin.groups.create"
        } else {
            "admin.principals.create"
        };
        let context = context(&fixture, operation, "stale-policy-write").await;
        let mut config = config_for_reload(&fixture);
        config.execution_context = Some(agent_access_core::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "new-context".into()],
            default_context: Some("default".into()),
        });
        fixture.broker.reload_config(&config).await;
        let state = AppState {
            reloadable: fixture.state.clone(),
        };
        let response = if group {
            committed_group_mutation(state, context, operation, None, |_, _| {
                panic!("stale group write entered store")
            })
            .await
        } else {
            committed_principal_mutation(state, context, operation, None, |_, _| {
                panic!("stale principal write entered store")
            })
            .await
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(response).await["reasonCode"],
            "version_conflict"
        );
    }
}
