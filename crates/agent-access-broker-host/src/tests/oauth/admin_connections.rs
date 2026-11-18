//! Administrator OAuth oversight reuses owner metadata and disconnect semantics,
//! with separate actor authority and target identity.
use super::browser_session_identity::{admin_session, admin_token, cookie};
use super::*;
use agent_access_core::{OAuthBinding, OAuthError, PrincipalAccessPatchRequest, PrincipalRole};

const LIST: &str = "/v1/admin/principals/alice/oauth/connections";
const DELETE: &str = "/v1/admin/principals/alice/oauth/connections/stub";

pub(super) async fn admin_request(
    fixture: &OAuthFixture,
    method: Method,
    uri: &str,
    request_id: &str,
) -> (StatusCode, Value) {
    let token = admin_token(fixture, BrokerTokenClass::Admin).token;
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        request_id,
        "Authorization",
        format!("Bearer {token}"),
        None,
    )
    .await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    (response.status(), response_json(response).await)
}

fn role(
    fixture: &OAuthFixture,
    principal: &str,
    role: Option<PrincipalRole>,
    self_service: Option<bool>,
) {
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(
            PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: principal.into(),
                role,
                self_service_enabled: self_service,
                actor: "test".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(
                fixture.config.execution_context.as_ref(),
            )
            .unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn administration_lists_target_metadata_without_contacting_provider_or_auditing_reads() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    let own = fixture
        .browser(Method::GET, "/v1/oauth/connections", "owner-metadata", None)
        .await;
    let mut expected = response_json(own).await["result"].clone();
    for row in expected.as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("canConnect");
        row.as_object_mut()
            .unwrap()
            .remove("connectUnavailableReason");
    }
    let (status, response) = admin_request(&fixture, Method::GET, LIST, "admin-oauth-list").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["principal"], "admin");
    assert_eq!(response["target"], json!({"principal": "alice"}));
    assert_eq!(response["result"], expected);
    assert_eq!(response["result"][0]["connection"]["status"], "ready");
    assert!(fixture.requests_after_consent().await.is_empty());
    assert!(
        read_audit_records(&fixture.audit_path)
            .iter()
            .all(|record| { record["action"] != "admin.principals.oauth_connections.list" })
    );
}

#[tokio::test]
async fn admin_oauth_role_gates_preserve_connection_on_denied_disconnect() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    // Keep another active administrator while exercising the signed-in
    // actor's roles; the last-administrator invariant still applies.
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .create_principal(
            PrincipalWriteRequest {
                principal_id: "remaining-admin".into(),
                kind: "user".into(),
                role: PrincipalRole::Admin,
                self_service_enabled: None,
                agent_token_issuance: Default::default(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(
                fixture.config.execution_context.as_ref(),
            )
            .unwrap(),
        )
        .unwrap();
    let (session, csrf) = admin_session(&fixture, false).await;
    for (assigned, can_read) in [
        (PrincipalRole::Auditor, true),
        (PrincipalRole::User, false),
        (PrincipalRole::ServicePolicyManager, false),
    ] {
        role(&fixture, "admin", Some(assigned), None);
        let (status, body) = cookie(&fixture, (&session, None), Method::GET, LIST, None).await;
        assert_eq!(
            status,
            if can_read {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            },
            "{body}"
        );
        let (status, body) = cookie(
            &fixture,
            (&session, Some(&csrf)),
            Method::DELETE,
            DELETE,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            fixture
                .runtime
                .oauth_manager()
                .unwrap()
                .status("alice", "stub")
                .unwrap()
                .connection_id
                .is_some()
        );
    }
    role(&fixture, "admin", Some(PrincipalRole::Admin), None);
    for class in [BrokerTokenClass::UserManage, BrokerTokenClass::AgentInvoke] {
        let token = admin_token(&fixture, class).token;
        for (method, path) in [(Method::GET, LIST), (Method::DELETE, DELETE)] {
            let response = authed_json_request(
                fixture.app.clone(),
                method,
                path,
                "denied-class",
                "Authorization",
                format!("Bearer {token}"),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                response_json(response).await["reasonCode"],
                "broker_token_class_denied"
            );
        }
    }
    let (status, body) = cookie(&fixture, (&session, None), Method::DELETE, DELETE, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "csrf_invalid");
    assert!(
        fixture
            .runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_some()
    );
    let (status, body) = cookie(
        &fixture,
        (&session, Some(&csrf)),
        Method::DELETE,
        DELETE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn administrator_disconnect_works_without_target_self_service_and_invalidates_leases() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    let manager = fixture.runtime.oauth_manager().unwrap();
    let lease = manager
        .acquire(
            "alice",
            &OAuthBinding {
                registration: "stub".into(),
                permission_profile: "read".into(),
            },
        )
        .await
        .unwrap();
    role(&fixture, "alice", None, Some(false));
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "self-service-disabled",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "self_service_disabled"
    );
    let (status, response) = admin_request(
        &fixture,
        Method::GET,
        LIST,
        "admin-disabled-self-service-list",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"][0]["canDisconnect"], true);
    let (status, response) = admin_request(
        &fixture,
        Method::DELETE,
        DELETE,
        "admin-disabled-self-service-delete",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["result"],
        json!({"disconnected": true, "remoteRevocation": "not_requested"})
    );
    assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
    assert_eq!(
        manager.status("alice", "stub").unwrap().status,
        agent_access_core::OAuthConnectionStatus::Disconnected
    );
    assert_eq!(
        admin_request(&fixture, Method::DELETE, DELETE, "admin-repeat")
            .await
            .0,
        StatusCode::OK
    );
    let records = read_audit_records(&fixture.audit_path);
    let records = records
        .iter()
        .filter(|record| record["agentRequestId"] == "admin-disabled-self-service-delete")
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["principal"], "admin");
    assert_eq!(
        records[0]["action"],
        "admin.principals.oauth_connections.disconnect"
    );
    assert_eq!(
        records[0]["providerAudit"]["management"]["phase"],
        "preflight"
    );
    assert_eq!(
        records[0]["providerAudit"]["management"]["target"],
        json!({"principal":"alice","registration":"stub"})
    );
    let serialized = serde_json::to_string(&records).unwrap();
    assert!(!serialized.contains("Alice"));
    assert!(!serialized.contains("stub-access"));
    assert!(!serialized.contains("stub-refresh"));
}

#[tokio::test]
async fn admin_delete_without_a_connection_preserves_pending_initial_consent() {
    let fixture = oauth_fixture().await;
    fixture
        .mock_consent("records.read offline_access", 3600)
        .await;
    let state = fixture.begin_consent("admin-empty-start").await;
    let (status, response) =
        admin_request(&fixture, Method::DELETE, DELETE, "admin-empty-delete").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["disconnected"], true);
    let response = fixture.finish_consent(&state, "admin-empty-callback").await;
    assert_completion_page(response, "Authorized", &[&state, "one-use-code"]).await;
    assert!(
        fixture
            .runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_some()
    );
}

#[tokio::test]
async fn admin_list_keeps_connected_registrations_after_grant_and_consumer_loss() {
    for remove_consumer in [false, true] {
        let fixture = oauth_fixture().await;
        fixture.connect("").await;
        fixture
            .runtime
            .delete_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
                grant_id: "personal-oauth".into(),
                expected_version: 1,
                updated_by: "admin".into(),
            })
            .unwrap();
        if remove_consumer {
            let mut changed = fixture.config.clone();
            changed.credentials.service.remove("fake");
            changed.credentials.per_user.remove("oauth_stub");
            changed.credentials.connections.remove("oauth_stub");
            fixture.broker.reload_config(&changed).await;
        }
        let (status, response) =
            admin_request(&fixture, Method::GET, LIST, "admin-retained-list").await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let rows = response["result"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["registration"], "stub");
        assert_eq!(rows[0]["canDisconnect"], true);
        assert_eq!(rows[0]["consumers"], json!([]));
        assert_eq!(rows[0]["connection"]["status"], "ready");
        if remove_consumer {
            assert!(rows[0]["permissionProfile"].is_null());
        }
        assert_eq!(
            admin_request(&fixture, Method::DELETE, DELETE, "admin-retained-delete")
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            admin_request(&fixture, Method::GET, LIST, "admin-retained-gone")
                .await
                .1["result"],
            json!([])
        );
    }
}

#[tokio::test]
async fn admin_disconnect_targets_an_owner_without_changing_other_owners() {
    let mut fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture
        .runtime
        .create_managed_policy_grant(agent_access_core::ManagedPolicyGrantCreateRequest {
            grant_id: Some("admin-personal".into()),
            subjects: vec!["user:admin".into()],
            service: "oauth_stub".into(),
            actions: vec!["account.view".into()],
            resources: ResourceSelection::default(),
            execution_contexts: vec!["default".into()],
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "test".into(),
        })
        .unwrap();
    (fixture.cookie, fixture.csrf) = admin_session(&fixture, false).await;
    fixture.connect("second-owner-consent").await;
    let manager = fixture.runtime.oauth_manager().unwrap();
    let other = manager
        .status("admin", "stub")
        .unwrap()
        .connection_id
        .unwrap();
    assert_eq!(
        admin_request(&fixture, Method::DELETE, DELETE, "isolated-disconnect")
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        manager
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_none()
    );
    assert_eq!(
        manager
            .status("admin", "stub")
            .unwrap()
            .connection_id
            .as_deref(),
        Some(other.as_str())
    );
}

#[tokio::test]
async fn admin_oauth_reports_unknown_targets_and_corrupt_status_without_hiding_failures() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    for method in [Method::GET, Method::DELETE] {
        let path = if method == Method::GET {
            "/v1/admin/principals/nobody/oauth/connections"
        } else {
            "/v1/admin/principals/nobody/oauth/connections/stub"
        };
        let (status, response) =
            admin_request(&fixture, method.clone(), path, "unknown-target").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
        assert_eq!(response["target"]["principal"], "nobody");
        if method == Method::DELETE {
            assert_eq!(response["target"]["registration"], "stub");
        }
    }
    let (status, response) = admin_request(
        &fixture,
        Method::DELETE,
        "/v1/admin/principals/alice/oauth/connections/unknown",
        "unknown-registration",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        response["target"],
        json!({"principal":"alice","registration":"unknown"})
    );
    let conn =
        rusqlite::Connection::open(&fixture.config.managed_store.as_ref().unwrap().path).unwrap();
    conn.execute("UPDATE oauth_slots SET ciphertext = zeroblob(length(ciphertext)) WHERE owner_principal_id = 'alice'", []).unwrap();
    let (status, response) = admin_request(&fixture, Method::GET, LIST, "corrupt-status").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["message"], "oauth_storage_unavailable");
    assert_eq!(response["target"], json!({"principal":"alice"}));
}
