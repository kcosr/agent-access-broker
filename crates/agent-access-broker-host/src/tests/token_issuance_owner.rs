//! A response waiter cannot cancel token insertion's completion audit, and an
//! audit failure never exposes the newly committed one-time secret.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::*;
use crate::handlers::management::common::{
    ManagementAccess, committed_token_issuance, management_context,
    management_write_audit_preflight,
};
use agent_access_core::{
    AgentTokenIssuanceAuthority, BrokerTokenClass, BrokerTokenIssueRequest,
    PrincipalAccessPatchRequest, PrincipalAgentTokenIssuance, SelfAgentTokenIssueRequest,
};
use axum::http::{HeaderMap, HeaderValue};

async fn permit_personal_issuance(fixture: &AuditFixture) {
    let store = fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .clone();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: None,
            self_service_enabled: None,
            agent_token_issuance: Some(PrincipalAgentTokenIssuance::WriteCapable),
            actor: "admin".into(),
        })
        .unwrap();
    let (status, body) = fixture.request(Method::POST, &fixture.admin,
        "/v1/admin/policy/grants",
        Some(r#"{"subjects":["user:alice"],"executionContexts":["default"],"service":"fake","actions":["echo"],"resources":{"resourceIds":["project-test"]},"credentialMode":"service"}"#),
        "owner-grant").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn issuance_events(fixture: &AuditFixture, request: &str) -> Vec<Value> {
    fixture
        .records()
        .into_iter()
        .filter(|event| event["agentRequestId"] == request)
        .collect()
}

#[tokio::test]
async fn token_issuance_owner_completes_once_after_waiter_cancellation() {
    for operation in [
        "tokens.issue",
        "admin.tokens.issue",
        "admin.tokens.issue_principal_agent",
    ] {
        let fixture = audit_fixture(Backend::Sqlite).await;
        permit_personal_issuance(&fixture).await;
        let personal = operation == "tokens.issue";
        let state = crate::state::AppState {
            reloadable: fixture.state.clone(),
        };
        let mut headers = HeaderMap::new();
        let bearer = if personal {
            &fixture.alice
        } else {
            &fixture.admin
        };
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
        );
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("token-owner-cancelled"),
        );
        let context = management_context(
            &state,
            "127.0.0.1:43210".parse().unwrap(),
            &headers,
            operation,
            if personal {
                ManagementAccess::UserManageToken
            } else {
                ManagementAccess::AdminWrite
            },
        )
        .await
        .unwrap();
        let hasher = context
            .snapshot
            .runtime
            .broker_token_hasher()
            .unwrap()
            .clone();
        let target = Some(json!({"principal":"alice","readOnly":true}));
        management_write_audit_preflight(&context, operation, target.clone())
            .await
            .unwrap();
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(committed_token_issuance(
            state,
            context,
            operation,
            target,
            personal,
            move |store, catalog| {
                let scopes = json!({"allowedExecutionContexts":["default"],"readOnly":true});
                let token = if personal {
                    store.issue_self_agent_token_with_catalog(
                        &hasher,
                        SelfAgentTokenIssueRequest {
                            principal_id: "alice".into(),
                            name: "cancelled-owner".into(),
                            scopes,
                            expires_at: None,
                            created_by: "alice".into(),
                        },
                        AgentTokenIssuanceAuthority::Managed,
                        catalog.as_ref(),
                    )?
                } else {
                    store.issue_broker_token_with_catalog(
                        &hasher,
                        BrokerTokenIssueRequest {
                            principal_id: "alice".into(),
                            name: "cancelled-owner".into(),
                            scopes,
                            token_class: BrokerTokenClass::AgentInvoke,
                            expires_at: None,
                            created_by: "admin".into(),
                        },
                        catalog.as_ref(),
                    )?
                };
                committed_tx
                    .send((token.record.token_id.clone(), token.token.clone()))
                    .unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(token)
            },
            |token| json!(token),
        ));
        let (token_id, secret) = committed_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        // A later account-policy edit must not rewrite captured issuance provenance.
        fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .patch_principal_access(PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: None,
                self_service_enabled: None,
                agent_token_issuance: Some(PrincipalAgentTokenIssuance::Disabled),
                actor: "admin".into(),
            })
            .unwrap();
        release_tx.send(()).unwrap();
        let events = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let events = issuance_events(&fixture, "token-owner-cancelled");
                if events.len() == 2 {
                    break events;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let success = events
            .iter()
            .find(|event| event["providerAudit"]["management"]["phase"] == "success")
            .unwrap();
        let captured = &success["providerAudit"]["management"]["target"];
        assert_eq!(captured["tokenId"], token_id);
        assert_eq!(captured["boundary"]["readOnly"], true);
        assert_eq!(
            captured["issuanceAuthority"],
            if personal {
                "personal"
            } else {
                "administrative"
            }
        );
        if personal {
            assert_eq!(
                captured["agentTokenIssuancePolicy"],
                json!({"mode":"write_capable","source":"user","groupIds":[]})
            );
        } else {
            assert!(captured.get("agentTokenIssuancePolicy").is_none());
        }
        assert!(!serde_json::to_string(&events).unwrap().contains(&secret));
        let store = fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .clone();
        let tokens = store.list_self_agent_tokens("alice", true, true).unwrap();
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.name == "cancelled-owner")
                .count(),
            1
        );
        assert!(
            store
                .resolve_broker_token(
                    fixture
                        .state
                        .current()
                        .runtime
                        .broker_token_hasher()
                        .unwrap(),
                    &secret
                )
                .is_ok()
        );
    }
}

#[tokio::test]
async fn token_issuance_audit_failures_preserve_commit_and_withhold_secret_on_every_route() {
    for (operation, path, generic, personal) in [
        ("tokens.issue", "/v1/tokens", false, true),
        (
            "admin.tokens.issue",
            "/v1/admin/principals/alice/tokens",
            true,
            false,
        ),
        (
            "admin.tokens.issue_principal_agent",
            "/v1/admin/principals/alice/agent-tokens",
            false,
            false,
        ),
    ] {
        for phase in ["preflight", "success"] {
            let fixture = audit_fixture(Backend::Sqlite).await;
            permit_personal_issuance(&fixture).await;
            let db = rusqlite::Connection::open(fixture.audit_path.as_ref().unwrap()).unwrap();
            db.execute_batch(&format!("CREATE TRIGGER fail_token_audit BEFORE INSERT ON audit_events WHEN NEW.phase = '{phase}' AND NEW.action = '{operation}' BEGIN SELECT RAISE(ABORT, 'private-token-audit-failure'); END;")).unwrap();
            let body = if generic {
                json!({"name":"completion-failure","tokenClass":"agent_invoke","ttl":"8h","scopes":{"allowedExecutionContexts":["default"],"readOnly":true}})
            } else {
                json!({"name":"completion-failure","ttl":"8h","allowedExecutionContexts":["default"],"readOnly":true})
            }.to_string();
            let bearer = if personal {
                &fixture.alice
            } else {
                &fixture.admin
            };
            let (status, response) = fixture
                .request(
                    Method::POST,
                    bearer,
                    path,
                    Some(&body),
                    "token-audit-failure",
                )
                .await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{operation}/{phase}: {response}"
            );
            assert_eq!(response["reasonCode"], "audit_unavailable");
            assert!(response.get("result").is_none());
            assert!(!response.to_string().contains("private-token-audit-failure"));
            let store = fixture
                .state
                .current()
                .runtime
                .managed_store()
                .unwrap()
                .clone();
            let tokens = store.list_self_agent_tokens("alice", true, true).unwrap();
            assert_eq!(
                tokens
                    .iter()
                    .filter(|token| token.name == "completion-failure")
                    .count(),
                usize::from(phase == "success")
            );
            let events = issuance_events(&fixture, "token-audit-failure");
            assert_eq!(events.len(), usize::from(phase == "success"));
        }
    }
}

#[tokio::test]
async fn token_issuance_owner_rejects_a_stale_snapshot_before_insertion() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let state = crate::state::AppState {
        reloadable: fixture.state.clone(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", fixture.admin)).unwrap(),
    );
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("token-owner-stale"),
    );
    let context = management_context(
        &state,
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        "admin.tokens.issue",
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    let snapshot = context.snapshot.clone();
    management_write_audit_preflight(&context, "admin.tokens.issue", None)
        .await
        .unwrap();
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entered_owner = entered.clone();
    fixture
        .state
        .publish_snapshot(Arc::new((*snapshot).clone()));
    let response = committed_token_issuance(
        state,
        context,
        "admin.tokens.issue",
        None,
        false,
        move |_, _| {
            entered_owner.store(true, Ordering::SeqCst);
            panic!("stale token issuance must not enter its store write")
        },
        |token| json!(token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "version_conflict"
    );
    assert!(!entered.load(Ordering::SeqCst));
    assert_eq!(issuance_events(&fixture, "token-owner-stale").len(), 2);
}

#[tokio::test]
async fn browser_token_issuance_under_toml_ignores_dormant_groups_and_honors_account_override() {
    let directory = tempfile::tempdir().unwrap();
    let static_token = directory.path().join("static-token");
    std::fs::write(&static_token, "synthetic-toml-browser-fixture-token").unwrap();
    let fixture = browser_rate_fixture_with(test_limits(), |config| {
        config.identity.authority = "toml".into();
        config.identity.sources = vec![IdentitySourceConfig {
            name: "static".into(),
            kind: "static_principals".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![StaticPrincipalConfig {
                principal: "alice".into(),
                token_refs: vec![format!("file:{}", static_token.display())],
            }],
        }];
        config.identity.groups = vec![IdentityGroupConfig {
            id: "dormant-writers".into(),
            status: "active".into(),
            members: vec!["alice".into()],
        }];
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
        .create_group(agent_access_core::GroupWriteRequest {
            group_id: "dormant-writers".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: false,
            agent_token_issuance: agent_access_core::AgentTokenIssuanceMode::WriteCapable,
            created_by: "admin".into(),
        })
        .unwrap();
    store
        .add_group("alice", "dormant-writers", "admin")
        .unwrap();
    let session = fixture
        .browser_request(Method::GET, "/v1/auth/session", None)
        .await;
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(
        response_json(session).await["result"]["tokenIssuancePolicy"]["selfAgentInvoke"]["access"],
        json!({"mode":"disabled","source":"default","groupIds":[]})
    );
    let options = fixture
        .browser_request(Method::GET, "/v1/tokens/options", None)
        .await;
    assert_eq!(options.status(), StatusCode::OK);
    let options = response_json(options).await;
    assert_eq!(
        options["result"]["agentTokenIssuancePolicy"],
        json!({"mode":"disabled","source":"default","groupIds":[]})
    );
    assert!(!options["result"]["services"].as_array().unwrap().is_empty());
    for read_only in [true, false] {
        let denied = fixture.browser_request(Method::POST, "/v1/tokens", Some(json!({
            "name":"toml-inherit-denied", "allowedExecutionContexts":["default"], "readOnly":read_only,
        }))).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let denied = response_json(denied).await;
        assert_eq!(denied["reasonCode"], "token_issuance_denied");
        assert_eq!(denied["details"]["category"], "disabled");
    }
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: None,
            self_service_enabled: None,
            agent_token_issuance: Some(PrincipalAgentTokenIssuance::ReadOnly),
            actor: "admin".into(),
        })
        .unwrap();
    let session = fixture
        .browser_request(Method::GET, "/v1/auth/session", None)
        .await;
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(
        response_json(session).await["result"]["tokenIssuancePolicy"]["selfAgentInvoke"]["access"],
        json!({"mode":"read_only","source":"user","groupIds":[]})
    );
    for read_only in [false, true] {
        let issued = fixture.browser_request(Method::POST, "/v1/tokens", Some(json!({
            "name":"toml-account-override", "allowedExecutionContexts":["default"], "readOnly":read_only,
        }))).await;
        assert_eq!(
            issued.status(),
            if read_only {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        let issued = response_json(issued).await;
        if read_only {
            assert_eq!(issued["result"]["record"]["scopes"]["readOnly"], true);
        } else {
            assert_eq!(issued["reasonCode"], "token_issuance_denied");
            assert_eq!(issued["details"]["category"], "read_only_required");
        }
    }
    assert_eq!(
        store
            .list_self_agent_tokens("alice", true, true)
            .unwrap()
            .iter()
            .filter(|token| token.name.starts_with("toml-"))
            .count(),
        1
    );
}
