//! Sealed management authority and retained HTTP completion ownership.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::*;
use crate::handlers::management::common::{
    ManagementAccess, ManagementContext, management_authorized_write, management_context,
    management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    ManagedStoreError, ManagementOperation, PrincipalAccessPatchRequest, PrincipalRole,
};
use axum::http::{HeaderMap, HeaderValue};
use std::future::Future;
use std::task::Poll;

fn headers(token: &str, request: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers.insert(REQUEST_ID_HEADER, HeaderValue::from_str(request).unwrap());
    headers
}
fn create_request(id: &str) -> PrincipalWriteRequest {
    PrincipalWriteRequest {
        principal_id: id.into(),
        kind: "service_account".into(),
        display_name: None,
        email: None,
        external_subject: None,
        role: PrincipalRole::User,
        self_service_enabled: Some(false),
        created_by: "admin".into(),
    }
}
async fn context(fixture: &AuditFixture, request: &str) -> ManagementContext {
    let context = management_context(
        &AppState {
            reloadable: fixture.state.clone(),
        },
        "127.0.0.1:1234".parse().unwrap(),
        &headers(&fixture.admin, request),
        "admin.principals.create",
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    management_write_audit_preflight(&context, "admin.principals.create", None)
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

#[tokio::test]
async fn management_local_read_does_not_wait_for_the_policy_mutation_lock() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    runtime
        .managed_store()
        .unwrap()
        .create_principal(create_request("read-target"))
        .unwrap();
    runtime
        .create_managed_resource(agent_access_core::CreateResourceRequest {
            id: Some("read-target-scope".into()),
            display_name: None,
            resource_type: ResourceType::from_static("broker_principal"),
            selector: ResourceSelector::Exact {
                value: "read-target".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    runtime
        .create_managed_policy_grant(agent_access_core::ManagedPolicyGrantCreateRequest {
            grant_id: Some("local-read".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "broker_management".into(),
            actions: vec!["principal.view".into()],
            resources: ResourceSelection {
                resource_ids: vec!["read-target-scope".into()],
                resource_group_ids: vec![],
            },
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();

    // Hold the write fence for the entire request. The timeout is only a
    // deadlock watchdog: a successful read must finish before we release it.
    let guard = fixture.state.policy_mutation_lock.lock().await;
    let (status, response) = tokio::time::timeout(
        Duration::from_secs(10),
        fixture.request(
            Method::POST,
            &fixture.alice_agent,
            "/v1/invoke/broker_management/principal.view",
            Some(r#"{"inputs":{"principalId":"read-target"}}"#),
            "local-read-with-write-fence",
        ),
    )
    .await
    .expect("read-only local command waited for the policy mutation lock");
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["principalId"], "read-target");
    drop(guard);
}

#[tokio::test]
async fn management_write_releases_publication_fence_before_rendering_completion() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "release-before-completion").await;
    let mutation_state = fixture.state.clone();
    let rendering_state = fixture.state.clone();
    let response = management_authorized_write(
        &state,
        context,
        "admin.principals.create",
        None,
        move |runtime, authority| {
            assert!(
                mutation_state.policy_mutation_lock.try_lock().is_err(),
                "the transaction must retain the publication fence"
            );
            runtime
                .managed_store()
                .unwrap()
                .create_principal_with_management_authority(
                    create_request("release-before-completion"),
                    authority,
                )
        },
        move |context, operation, target, record| {
            assert!(
                rendering_state.policy_mutation_lock.try_lock().is_ok(),
                "rendering and completion audit must run outside the publication fence"
            );
            crate::handlers::management::common::management_success_envelope(
                context,
                operation,
                target,
                json!(record),
            )
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let records = events(&fixture, "release-before-completion");
    assert_eq!(records.len(), 2, "preflight and one completion audit");
    assert_eq!(
        records[1]["providerAudit"]["management"]["phase"],
        "success"
    );
}

#[tokio::test]
async fn management_write_preserves_request_span_and_task_subscriber() {
    use tracing::Instrument;
    use tracing::instrument::WithSubscriber;

    #[derive(Clone, Default)]
    struct OwnerEvents(Arc<std::sync::Mutex<Vec<(String, bool)>>>);
    impl<S> tracing_subscriber::Layer<S> for OwnerEvents
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, ctx: TracingLayerContext<'_, S>) {
            let mut fields = BTreeMap::new();
            event.record(&mut JsonVisitor(&mut fields));
            if let Some(stage) = fields.get("management_stage").and_then(Value::as_str) {
                let correlated = ctx.event_scope(event).is_some_and(|scope| {
                    scope
                        .from_root()
                        .any(|span| span.metadata().name() == "management-owner-correlation")
                });
                self.0.lock().unwrap().push((stage.into(), correlated));
            }
        }
    }

    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "management-owner-correlation").await;
    let events = OwnerEvents::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let response = async {
        management_authorized_write(
            &state,
            context,
            "admin.principals.create",
            None,
            |runtime, authority| {
                tracing::info!(management_stage = "blocking", "management store work");
                runtime
                    .managed_store()
                    .unwrap()
                    .create_principal_with_management_authority(
                        create_request("management-owner-correlation"),
                        authority,
                    )
            },
            |context, operation, target, record| {
                tracing::info!(
                    management_stage = "completion",
                    "management completion work"
                );
                crate::handlers::management::common::management_success_envelope(
                    context,
                    operation,
                    target,
                    json!(record),
                )
            },
        )
        .instrument(tracing::info_span!("management-owner-correlation"))
        .await
    }
    .with_subscriber(subscriber)
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![("blocking".into(), true), ("completion".into(), true)]
    );
}

#[tokio::test]
async fn management_authority_rechecks_original_token_and_current_role_inside_transaction() {
    for change in ["revoke", "downgrade", "disable", "replace_hash", "actor"] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let snapshot = fixture.state.current();
        let runtime = &snapshot.runtime;
        let store = runtime.managed_store().unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: "keeper".into(),
                kind: "user".into(),
                role: PrincipalRole::Admin,
                self_service_enabled: None,
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        let authority = runtime
            .admit_management_authority(
                &headers(&fixture.admin, "sealed-authority"),
                ManagementOperation::PrincipalCreate,
            )
            .unwrap();
        let token = store
            .resolve_broker_token(runtime.broker_token_hasher().unwrap(), &fixture.admin)
            .unwrap();
        match change {
            "revoke" => {
                store.revoke_broker_token(&token.token_id, "admin").unwrap();
            }
            "downgrade" => {
                store
                    .patch_principal_access(PrincipalAccessPatchRequest {
                        principal_id: "admin".into(),
                        role: Some(PrincipalRole::User),
                        self_service_enabled: None,
                        actor: "test".into(),
                    })
                    .unwrap();
            }
            "disable" => {
                store
                    .patch_principal(PrincipalPatchRequest {
                        principal_id: "admin".into(),
                        display_name: None,
                        email: None,
                        status: Some("disabled".into()),
                    })
                    .unwrap();
            }
            "replace_hash" => {
                let conn = rusqlite::Connection::open(
                    &runtime.config().managed_store.as_ref().unwrap().path,
                )
                .unwrap();
                conn.execute("UPDATE broker_tokens SET token_hash = 'changed-original-credential' WHERE token_id=?1",[&token.token_id]).unwrap();
            }
            "actor" => {}
            _ => unreachable!(),
        }
        let mut request = create_request("must-not-exist");
        if change == "actor" {
            request.created_by = "alice".into();
        }
        let result = store.create_principal_with_management_authority(request, authority);
        assert!(result.is_err(), "{change} must invalidate the sealed write");
        assert!(matches!(
            store.principal("must-not-exist"),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
    }
}

#[tokio::test]
async fn management_authority_personal_tokens_recheck_self_service_and_class() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let store = runtime.managed_store().unwrap();
    assert!(
        runtime
            .admit_management_authority(
                &headers(&fixture.alice_agent, "wrong-class"),
                ManagementOperation::PersonalTokenIssue
            )
            .is_err()
    );
    let authority = runtime
        .admit_management_authority(
            &headers(&fixture.alice, "self-service"),
            ManagementOperation::PersonalTokenIssue,
        )
        .unwrap();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: None,
            self_service_enabled: Some(false),
            actor: "admin".into(),
        })
        .unwrap();
    let result = store.issue_self_agent_token_with_management_authority(
        runtime.broker_token_hasher().unwrap(),
        agent_access_core::SelfAgentTokenIssueRequest {
            principal_id: "alice".into(),
            name: "must-not-mint".into(),
            scopes: json!({"allowedExecutionContexts":["default"]}),
            expires_at: Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
            created_by: "alice".into(),
        },
        None,
        authority,
    );
    assert!(matches!(
        result,
        Err(ManagedStoreError::SelfServiceDisabled)
    ));
}

#[tokio::test]
async fn management_write_cancel_before_commit_prevents_mutation() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "cancel-before").await;
    let guard = fixture.state.policy_mutation_lock.lock().await;
    let mut waiter = Box::pin(management_authorized_write(
        &state,
        context,
        "admin.principals.create",
        None,
        |runtime, authority| {
            runtime
                .managed_store()
                .unwrap()
                .create_principal_with_management_authority(
                    create_request("cancel-before"),
                    authority,
                )
        },
        |context, operation, target, record| {
            crate::handlers::management::common::management_success_envelope(
                context,
                operation,
                target,
                json!(record),
            )
        },
    ));
    // Poll through synchronous owner registration, stopping at the response wait.
    std::future::poll_fn(|cx| {
        assert!(waiter.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(waiter);
    drop(guard);
    assert_eq!(
        fixture
            .state
            .shutdown_operations(Duration::from_secs(10))
            .await,
        0
    );
    assert!(matches!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .principal("cancel-before"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
    let records = events(&fixture, "cancel-before");
    assert_eq!(records.len(), 2, "preflight and one cancellation audit");
    assert_eq!(records[1]["reasonCode"], "operation_cancelled");
}

#[tokio::test]
async fn management_write_owner_drains_commit_and_audit_after_waiter_disconnect() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "cancel-after").await;
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let waiter = tokio::spawn(async move {
        management_authorized_write(
            &state,
            context,
            "admin.principals.create",
            None,
            move |runtime, authority| {
                let mutation = runtime
                    .managed_store()
                    .unwrap()
                    .create_principal_with_management_authority(
                        create_request("cancel-after"),
                        authority,
                    )?;
                committed_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(mutation)
            },
            |context, operation, target, record| {
                crate::handlers::management::common::management_success_envelope(
                    context,
                    operation,
                    target,
                    json!(record),
                )
            },
        )
        .await
    });
    committed_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let mut drain = Box::pin(fixture.state.shutdown_operations(Duration::from_secs(10)));
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release_tx.send(()).unwrap();
    assert_eq!(drain.await, 0);
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .principal("cancel-after")
            .is_ok()
    );
    let records = events(&fixture, "cancel-after");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1]["providerAudit"]["management"]["phase"],
        "success"
    );
    assert_eq!(
        records[1]["providerAudit"]["management"]["change"]["changed"],
        true
    );
}

#[tokio::test]
async fn management_write_preflight_required_and_postcommit_audit_failure_preserves_success() {
    for phase in ["preflight", "success"] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let conn = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
        conn.execute_batch(&format!("CREATE TRIGGER fail_management_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{phase}' AND NEW.action = 'admin.principals.create' BEGIN SELECT RAISE(ABORT,'private-audit-failure'); END;")).unwrap();
        let (status, response) = fixture
            .request(
                Method::POST,
                &fixture.admin,
                "/v1/admin/principals",
                Some(r#"{"principalId":"audit-failure","kind":"service_account"}"#),
                "management-audit-failure",
            )
            .await;
        let snapshot = fixture.state.current();
        let exists = snapshot
            .runtime
            .managed_store()
            .unwrap()
            .principal("audit-failure")
            .is_ok();
        if phase == "preflight" {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
            assert!(!exists);
        } else {
            assert_eq!(status, StatusCode::OK, "{response}");
            assert!(exists);
        }
        assert!(!response.to_string().contains("private-audit-failure"));
    }
}

#[tokio::test]
async fn management_write_rejects_a_replaced_runtime_before_commit() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "runtime-replaced").await;
    let snapshot = fixture.state.current();
    let guard = fixture.state.policy_mutation_lock.lock().await;
    let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempted_write = attempted.clone();
    let mut waiter = Box::pin(management_authorized_write(
        &state,
        context,
        "admin.principals.create",
        None,
        move |runtime, authority| {
            attempted_write.store(true, Ordering::SeqCst);
            runtime
                .managed_store()
                .unwrap()
                .create_principal_with_management_authority(
                    create_request("runtime-replaced"),
                    authority,
                )
        },
        |context, operation, target, record| {
            crate::handlers::management::common::management_success_envelope(
                context,
                operation,
                target,
                json!(record),
            )
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(waiter.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        snapshot.generation + 1,
        "replacement".into(),
        snapshot.runtime.clone(),
        snapshot.state_locks.clone(),
    ));
    drop(guard);
    let response = waiter.await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!attempted.load(Ordering::SeqCst));
    assert!(matches!(
        snapshot
            .runtime
            .managed_store()
            .unwrap()
            .principal("runtime-replaced"),
        Err(ManagedStoreError::PrincipalNotFound)
    ));
}

#[tokio::test]
async fn management_grant_subjects_recheck_scoped_authority_without_pinning_unrelated_generation() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let store = runtime.managed_store().unwrap();
    let create = |id: &str| agent_access_core::ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec!["user:alice".into()],
        execution_contexts: vec!["default".into()],
        service: "fake".into(),
        actions: vec!["echo".into()],
        resources: ResourceSelection {
            resource_ids: vec![resource_id("project", "TEST")],
            ..Default::default()
        },
        credential_mode: "service".into(),
        priority: None,
        status: None,
        description: None,
        created_by: "admin".into(),
    };
    let grant = runtime
        .create_managed_policy_grant(create("managed-grant"))
        .unwrap()
        .grant;
    let authority = runtime
        .admit_management_authority(
            &headers(&fixture.bob, "scoped-management"),
            ManagementOperation::GrantSubjectAdd,
        )
        .unwrap();
    let mut unrelated = create("unrelated-grant");
    unrelated.resources.resource_ids = vec![resource_id("project", "OPS")];
    runtime.create_managed_policy_grant(unrelated).unwrap();
    let mutation = runtime
        .add_managed_policy_grant_subject_with_management_authority(
            agent_access_core::ManagedPolicyGrantSubjectAddRequest {
                grant_id: grant.grant_id,
                expected_version: grant.version,
                subject: "user:carol".into(),
                updated_by: "bob".into(),
            },
            authority,
        )
        .unwrap();
    assert!(mutation.value.grant.subjects.contains(&"user:carol".into()));
    assert_eq!(
        runtime.policy_generation(),
        mutation.value.revision.generation
    );
    let authority = runtime
        .admit_management_authority(
            &headers(&fixture.bob, "scoped-management-loss"),
            ManagementOperation::GrantSubjectRemove,
        )
        .unwrap();
    assert!(
        store
            .delete_service_policy_management_assignment("fake", "bob")
            .unwrap()
    );
    let result = runtime.remove_managed_policy_grant_subject_with_management_authority(
        agent_access_core::ManagedPolicyGrantSubjectRemoveRequest {
            grant_id: mutation.value.grant.grant_id.clone(),
            expected_version: mutation.value.grant.version,
            subject: "user:carol".into(),
            last_subject_behavior: "reject".into(),
            updated_by: "bob".into(),
        },
        authority,
    );
    assert!(matches!(result, Err(ManagedStoreError::ManagementDenied)));
    assert!(
        store
            .policy_grant(&mutation.value.grant.grant_id)
            .unwrap()
            .subjects
            .contains(&"user:carol".into())
    );
}

#[tokio::test]
async fn management_write_uncertain_commit_reports_one_unknown_terminal_outcome() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = AppState {
        reloadable: fixture.state.clone(),
    };
    let context = context(&fixture, "commit-unknown").await;
    let response = management_authorized_write(
        &state,
        context,
        "admin.principals.create",
        None,
        |runtime, authority| {
            runtime
                .managed_store()
                .unwrap()
                .create_principal_with_management_authority(
                    create_request("commit-unknown"),
                    authority,
                )?;
            // Model loss of the commit acknowledgement after persistence. The
            // owner must retain uncertainty and never report a safe retry.
            Err::<agent_access_core::ManagementMutation<()>, _>(ManagedStoreError::CommitUnknown)
        },
        |_, _, _, _| panic!("uncertain write must not render success"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let response = response_json(response).await;
    assert_eq!(response["result"]["executionState"], "unknown");
    assert_eq!(response["result"]["retrySafe"], false);
    assert!(
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .principal("commit-unknown")
            .is_ok()
    );
    let records = events(&fixture, "commit-unknown");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["providerAudit"]["management"]["phase"], "error");
    assert_eq!(
        records[1]["providerAudit"]["management"]["change"]["executionState"],
        "unknown"
    );
}

fn patch_test_grant(id: &str) -> agent_access_core::ManagedPolicyGrantCreateRequest {
    agent_access_core::ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec!["user:alice".into()],
        execution_contexts: vec!["default".into()],
        service: "fake".into(),
        actions: vec!["echo".into()],
        resources: ResourceSelection {
            resource_ids: vec![resource_id("project", "TEST")],
            ..Default::default()
        },
        credential_mode: "service".into(),
        priority: None,
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}

async fn patch_after_admission(
    fixture: &AuditFixture,
    token: &str,
    body: &str,
    request_id: &str,
    change: impl FnOnce(),
) -> (StatusCode, Value) {
    let guard = fixture.state.policy_mutation_lock.lock().await;
    let request = fixture.request(
        Method::PATCH,
        token,
        "/v1/admin/policy/grants/patch-target",
        Some(body),
        request_id,
    );
    tokio::pin!(request);
    // The persisted preflight event establishes that admission completed.
    // Hold the publication fence until the authority change is committed;
    // the timeout is only a deadlock watchdog, never the ordering signal.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                response = &mut request => panic!("patch escaped the write fence: {response:?}"),
                _ = tokio::task::yield_now() => {}
            }
            if events(fixture, request_id)
                .iter()
                .any(|event| event["providerAudit"]["management"]["phase"] == "preflight")
            {
                break;
            }
        }
    })
    .await
    .expect("patch did not reach admission while queued");
    change();
    drop(guard);
    tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("patch did not finish after the write fence was released")
}

#[tokio::test]
async fn management_grant_patch_rechecks_token_role_and_service_assignment_before_commit() {
    for change in [
        "revoke_token",
        "remove_role",
        "remove_assignment",
        "demote_admin",
    ] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        let snapshot = fixture.state.current();
        let runtime = &snapshot.runtime;
        let store = runtime.managed_store().unwrap();
        let raw_token = if change == "demote_admin" {
            store
                .create_principal(PrincipalWriteRequest {
                    principal_id: "keeper".into(),
                    kind: "user".into(),
                    role: PrincipalRole::Admin,
                    self_service_enabled: None,
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                })
                .unwrap();
            &fixture.admin
        } else {
            &fixture.bob
        };
        let before = runtime
            .create_managed_policy_grant(patch_test_grant("patch-target"))
            .unwrap();
        let original = serde_json::to_value(&before.grant).unwrap();
        let revision = serde_json::to_value(store.policy_revision().unwrap()).unwrap();
        let generation = runtime.policy_generation();
        let body = json!({
            "expectedVersion": before.grant.version,
            "subjects": ["user:alice", "user:carol"],
        })
        .to_string();
        let token = store
            .resolve_broker_token(runtime.broker_token_hasher().unwrap(), raw_token)
            .unwrap();
        let (status, response) =
            patch_after_admission(&fixture, raw_token, &body, change, || match change {
                "revoke_token" => {
                    store.revoke_broker_token(&token.token_id, "admin").unwrap();
                }
                "remove_role" | "demote_admin" => {
                    store
                        .patch_principal_access(PrincipalAccessPatchRequest {
                            principal_id: if change == "demote_admin" {
                                "admin"
                            } else {
                                "bob"
                            }
                            .into(),
                            role: Some(PrincipalRole::User),
                            self_service_enabled: None,
                            actor: "admin".into(),
                        })
                        .unwrap();
                }
                "remove_assignment" => {
                    assert!(
                        store
                            .delete_service_policy_management_assignment("fake", "bob")
                            .unwrap()
                    );
                }
                _ => unreachable!(),
            })
            .await;
        assert!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "{change}: {response}"
        );
        assert_eq!(
            serde_json::to_value(store.policy_grant("patch-target").unwrap()).unwrap(),
            original,
            "{change} changed the grant"
        );
        assert_eq!(
            serde_json::to_value(store.policy_revision().unwrap()).unwrap(),
            revision,
            "{change} changed the stored revision"
        );
        assert_eq!(runtime.policy_generation(), generation);
        let records = events(&fixture, change);
        assert_eq!(records.len(), 2, "preflight and one denial: {records:?}");
        assert_eq!(
            records[0]["providerAudit"]["management"]["phase"],
            "preflight"
        );
        assert_ne!(
            records[1]["providerAudit"]["management"]["phase"],
            "success"
        );
        assert_eq!(records[1]["decision"], "deny");
    }
}

#[tokio::test]
async fn management_grant_patch_keeps_live_authority_cas_and_active_snapshot_publication() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let store = runtime.managed_store().unwrap();
    let before = runtime
        .create_managed_policy_grant(patch_test_grant("patch-target"))
        .unwrap();
    let body = json!({
        "expectedVersion": before.grant.version,
        "subjects": ["user:alice", "user:carol"],
    })
    .to_string();
    let (status, response) = patch_after_admission(
        &fixture,
        &fixture.bob,
        &body,
        "patch-live-authority",
        || {
            let mut unrelated = patch_test_grant("unrelated-patch-grant");
            unrelated.resources.resource_ids = vec![resource_id("project", "OPS")];
            runtime.create_managed_policy_grant(unrelated).unwrap();
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let updated = store.policy_grant("patch-target").unwrap();
    assert_eq!(updated.subjects, vec!["user:alice", "user:carol"]);
    assert_eq!(updated.version, before.grant.version + 1);
    assert_eq!(
        runtime.policy_generation(),
        store.policy_revision().unwrap().generation
    );
    assert_eq!(response["result"]["grant"]["version"], updated.version);
    let records = events(&fixture, "patch-live-authority");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1]["providerAudit"]["management"]["phase"],
        "success"
    );

    let revision = serde_json::to_value(store.policy_revision().unwrap()).unwrap();
    let (status, response) = fixture
        .request(
            Method::PATCH,
            &fixture.bob,
            "/v1/admin/policy/grants/patch-target",
            Some(&body),
            "patch-stale-version",
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(
        serde_json::to_value(store.policy_grant("patch-target").unwrap()).unwrap(),
        serde_json::to_value(&updated).unwrap()
    );
    assert_eq!(
        serde_json::to_value(store.policy_revision().unwrap()).unwrap(),
        revision
    );

    // Editing and disabling together validates an inactive candidate after
    // the active snapshot. Only the active grants may be published.
    let body = json!({
        "expectedVersion": updated.version,
        "subjects": ["user:alice"],
        "status": "disabled",
    })
    .to_string();
    let (status, response) = fixture
        .request(
            Method::PATCH,
            &fixture.bob,
            "/v1/admin/policy/grants/patch-target",
            Some(&body),
            "patch-disabled-subjects",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        store.policy_grant("patch-target").unwrap().status,
        "disabled"
    );
    let identity = runtime
        .resolve_identity(&headers(&fixture.alice_agent, "patch-snapshot-discovery"))
        .unwrap();
    let execution_context = agent_access_core::ExecutionContext::new("default").unwrap();
    let discovery = runtime
        .service_discovery(&identity, &execution_context, "fake")
        .expect("the unrelated active grant remains visible");
    assert!(
        discovery
            .actions(Some("TEST"), None, None, None)
            .unwrap()
            .actions
            .is_empty()
    );
    assert_eq!(
        discovery
            .actions(Some("OPS"), None, None, None)
            .unwrap()
            .actions,
        vec!["echo"]
    );
    assert_eq!(
        runtime.policy_generation(),
        store.policy_revision().unwrap().generation
    );
}

async fn assert_subject_mutation_keeps_only_unrelated_grant_active(
    fixture: &AuditFixture,
    generation: u64,
) {
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    assert_eq!(runtime.policy_generation(), generation);
    assert_eq!(
        runtime
            .managed_store()
            .unwrap()
            .policy_revision()
            .unwrap()
            .generation,
        generation
    );
    let identity = runtime
        .resolve_identity(&headers(&fixture.alice_agent, "subject-snapshot-discovery"))
        .unwrap();
    let execution_context = agent_access_core::ExecutionContext::new("default").unwrap();
    let discovery = runtime
        .service_discovery(&identity, &execution_context, "fake")
        .expect("the unrelated active grant remains visible");
    assert!(
        discovery
            .actions(Some("TEST"), None, None, None)
            .unwrap()
            .actions
            .is_empty()
    );
    assert_eq!(
        discovery
            .actions(Some("OPS"), None, None, None)
            .unwrap()
            .actions,
        vec!["echo"]
    );
    for (project, expected_status) in [("TEST", StatusCode::FORBIDDEN), ("OPS", StatusCode::OK)] {
        let body =
            json!({"inputs": {"project": project, "message": "subject snapshot"}}).to_string();
        let (status, response) = fixture
            .request(
                Method::POST,
                &fixture.alice_agent,
                "/v1/invoke/fake/echo",
                Some(&body),
                &format!("subject-snapshot-invoke-{project}"),
            )
            .await;
        assert_eq!(status, expected_status, "{project}: {response}");
    }
}

#[tokio::test]
async fn management_grant_subject_add_to_disabled_grant_preserves_active_snapshot() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let mut inactive = patch_test_grant("subject-target");
    inactive.subjects = vec!["user:carol".into()];
    inactive.status = Some("disabled".into());
    let target = runtime.create_managed_policy_grant(inactive).unwrap().grant;
    let mut unrelated = patch_test_grant("subject-unrelated");
    unrelated.resources.resource_ids = vec![resource_id("project", "OPS")];
    let unrelated = runtime
        .create_managed_policy_grant(unrelated)
        .unwrap()
        .grant;
    let body = json!({"expectedVersion": target.version, "subject": "user:alice"}).to_string();
    let (status, response) = fixture
        .request(
            Method::POST,
            &fixture.bob,
            "/v1/admin/policy/grants/subject-target/subjects",
            Some(&body),
            "subject-add-disabled",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let store = runtime.managed_store().unwrap();
    let updated = store.policy_grant("subject-target").unwrap();
    assert_eq!(updated.status, "disabled");
    assert_eq!(updated.subjects, vec!["user:carol", "user:alice"]);
    assert_eq!(updated.version, target.version + 1);
    assert_eq!(store.policy_grant("subject-unrelated").unwrap(), unrelated);
    assert_subject_mutation_keeps_only_unrelated_grant_active(
        &fixture,
        response["result"]["revision"]["generation"]
            .as_u64()
            .unwrap(),
    )
    .await;
}

#[tokio::test]
async fn management_grant_subject_remove_last_and_disable_preserves_active_snapshot() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let target = runtime
        .create_managed_policy_grant(patch_test_grant("subject-target"))
        .unwrap()
        .grant;
    let mut unrelated = patch_test_grant("subject-unrelated");
    unrelated.resources.resource_ids = vec![resource_id("project", "OPS")];
    let unrelated = runtime
        .create_managed_policy_grant(unrelated)
        .unwrap()
        .grant;
    let body = json!({
        "expectedVersion": target.version,
        "subject": "user:alice",
        "lastSubjectBehavior": "disable_grant",
    })
    .to_string();
    let (status, response) = fixture
        .request(
            Method::POST,
            &fixture.bob,
            "/v1/admin/policy/grants/subject-target/subjects/remove",
            Some(&body),
            "subject-remove-disable",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let store = runtime.managed_store().unwrap();
    let updated = store.policy_grant("subject-target").unwrap();
    assert_eq!(updated.status, "disabled");
    assert!(updated.subjects.is_empty());
    assert_eq!(updated.version, target.version + 1);
    assert_eq!(store.policy_grant("subject-unrelated").unwrap(), unrelated);
    assert_subject_mutation_keeps_only_unrelated_grant_active(
        &fixture,
        response["result"]["revision"]["generation"]
            .as_u64()
            .unwrap(),
    )
    .await;
}
