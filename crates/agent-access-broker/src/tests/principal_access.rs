//! Exercise role, credential-class and personal access boundaries through real routes.
use super::audit_query::{AuditFixture, Backend, audit_fixture};
use super::management_read_audit::{concrete_route, cookie_get, read_post_body};
use super::*;
use agent_access_core::{
    BrokerTokenClass, PrincipalAccessPatchRequest, PrincipalRole, RouteAccess, http_route_specs,
};

async fn sweep_request(
    fixture: &AuditFixture,
    method: Method,
    token: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        uri,
        "access-route-sweep",
        "Authorization",
        format!("Bearer {token}"),
        body,
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"rawBody":String::from_utf8_lossy(&bytes)}));
    (status, result)
}

// Valid extractor inputs ensure denials exercise authorization, not JSON parsing.
fn write_body(operation: &str) -> &'static str {
    match operation {
        "admin.groups.create" => r#"{"groupId":"audit-test-group"}"#,
        "admin.groups.external_group_bindings.create" => {
            r#"{"externalGroupId":"00000000-0000-4000-8000-000000000001"}"#
        }
        "admin.groups.external_group_bindings.patch" => r#"{"status":"disabled"}"#,
        "admin.principals.create" => r#"{"principalId":"new-user"}"#,
        "admin.principals.access.patch" => r#"{"role":"admin"}"#,
        "admin.principals.identity_token.set" => {
            r#"{"token":"00000000-0000-4000-8000-000000000001"}"#
        }
        "admin.principals.login_methods.oidc.microsoft.link" => {
            r#"{"userObjectId":"00000000-0000-4000-8000-000000000001"}"#
        }
        "admin.principals.local_password.reset" | "admin.principals.local_password.enable" => {
            r#"{"password":"synthetic-password"}"#
        }
        "admin.rights.grant" => r#"{"principalId":"alice","right":"credentials.write"}"#,
        "admin.principals.tokens.issue" => r#"{"name":"test","tokenClass":"user_manage"}"#,
        "credentials.put" | "admin.credentials.put" | "admin.principals.credentials.put" => {
            r#"{"secret":{"token":"synthetic"}}"#
        }
        "admin.credentials.rewrap" => r#"{"fromKey":"k1","toKey":"k2"}"#,
        _ => "{}",
    }
}

fn issue(fixture: &AuditFixture, principal: &str, class: BrokerTokenClass) -> String {
    let snapshot = fixture.state.current();
    snapshot
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: principal.into(),
                name: "access test".into(),
                token_class: class.clone(),
                scopes: if class == BrokerTokenClass::AgentInvoke {
                    json!({"allowedExecutionContexts":["default"]})
                } else {
                    json!({})
                },
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}

fn auditor(fixture: &AuditFixture) -> String {
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "carol".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: None,
            actor: "admin".into(),
        })
        .unwrap();
    issue(fixture, "carol", BrokerTokenClass::Admin)
}

#[tokio::test]
async fn auditor_all_admin_reads_and_safe_previews_are_admitted_but_every_write_is_denied() {
    let fixture = audit_fixture(Backend::Sqlite);
    let token = auditor(&fixture);
    let routes = http_route_specs(fixture.state.current().runtime.resource_types());
    let ids = BTreeMap::from([(
        "brokerRequestId",
        "0b5d4a4e-2b4e-4d67-9d5b-0a0f3f1c2d3e".into(),
    )]);
    let mut successes = BTreeSet::new();
    let mut denials = BTreeSet::new();
    for route in routes.iter().filter(|route| {
        matches!(
            route.access,
            RouteAccess::AdminRead
                | RouteAccess::PolicyRead
                | RouteAccess::AdminWrite
                | RouteAccess::PolicyWrite
        )
    }) {
        let uri = concrete_route(&route.route, &ids);
        let method = Method::from_bytes(route.method.as_bytes()).unwrap();
        let write = matches!(
            route.access,
            RouteAccess::AdminWrite | RouteAccess::PolicyWrite
        );
        let body = read_post_body(&route.operation).or(
            if method == Method::GET || method == Method::DELETE {
                None
            } else {
                Some(write_body(&route.operation))
            },
        );
        let (status, result) = sweep_request(&fixture, method.clone(), &token, &uri, body).await;
        if write {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{} {uri}: {result}",
                route.method
            );
            assert_eq!(result["reasonCode"], "management_denied", "{uri}: {result}");
            denials.insert(route.operation.as_str());
        } else {
            let (admin_status, admin_result) = fixture
                .request(method, &fixture.admin, &uri, body, "admin-read-baseline")
                .await;
            assert_eq!(
                status, admin_status,
                "{} {uri}: auditor {result}; admin {admin_result}",
                route.method
            );
            if status == StatusCode::OK {
                successes.insert(route.operation.as_str());
            }
        }
    }
    for operation in [
        "admin.config.status",
        "admin.principals.list",
        "admin.groups.list",
        "admin.tokens.list",
        "admin.credentials.list",
        "admin.policy.grants.validate",
        "admin.policy.effective_access",
        "admin.audit.events.list",
    ] {
        assert!(
            successes.contains(operation),
            "missing successful {operation}: {successes:?}"
        );
    }
    for operation in [
        "admin.config.reload",
        "admin.principals.access.patch",
        "admin.principals.identity_token.reveal",
        "admin.policy.resources.attribute.reveal",
        "admin.credentials.verify",
    ] {
        assert!(
            denials.contains(operation),
            "missing denial {operation}: {denials:?}"
        );
    }
    let denial = fixture
        .records()
        .into_iter()
        .find(|record| record["action"] == "config.reload")
        .unwrap();
    assert_eq!(denial["principal"], "carol");
}

#[tokio::test]
async fn auditor_credentials_and_catalog_keep_their_distinct_boundaries() {
    let fixture = audit_fixture(Backend::Sqlite);
    auditor(&fixture);
    let issue_body = json!({
        "name": "auditor API token",
        "tokenClass": "admin",
        "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
    })
    .to_string();
    let (status, issued) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/principals/carol/tokens",
            Some(&issue_body),
            "issue-auditor-api-token",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let admin_class = issued["result"]["token"].as_str().unwrap().to_string();
    let agent = issue(&fixture, "carol", BrokerTokenClass::AgentInvoke);
    for (token, metadata, policy, personal) in [
        (&admin_class, true, true, false),
        (&fixture.carol, false, true, true),
        (&agent, false, false, false),
    ] {
        for (uri, allowed) in [
            ("/v1/admin/principals", metadata),
            ("/v1/admin/policy/grants", policy),
            ("/v1/admin/audit/events", policy),
            ("/v1/tokens", personal),
        ] {
            let (status, body) = fixture
                .request(Method::GET, token, uri, None, "auditor-class-matrix")
                .await;
            assert_eq!(
                status,
                if allowed {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                },
                "{uri}: {body}"
            );
        }
    }
    for query in ["", "?visibility=all"] {
        let (status, catalog) = fixture
            .request(
                Method::GET,
                &admin_class,
                &format!("/v1/spec/catalog{query}"),
                None,
                "auditor-spec",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{catalog}");
        assert!(catalog_has_route(&catalog, "GET", "/v1/admin/principals"));
        assert!(catalog_has_route(
            &catalog,
            "POST",
            "/v1/admin/policy/grants/validate"
        ));
        for route in http_route_specs(fixture.state.current().runtime.resource_types())
            .iter()
            .filter(|route| {
                matches!(
                    route.access,
                    RouteAccess::AdminWrite | RouteAccess::PolicyWrite
                ) || (query.is_empty()
                    && matches!(
                        route.access,
                        RouteAccess::UserManagement | RouteAccess::UserTokenManagement
                    ))
            })
        {
            assert!(
                !catalog_has_route(&catalog, &route.method, &route.route),
                "{} {} leaked into {query}",
                route.method,
                route.route
            );
        }
        if !query.is_empty() {
            assert!(catalog_has_service(&catalog, "fake"));
        }
    }
    let (status, catalog) = fixture
        .request(
            Method::GET,
            &fixture.carol,
            "/v1/spec/catalog",
            None,
            "auditor-personal-spec",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert!(!catalog_has_route(&catalog, "GET", "/v1/admin/principals"));
    assert!(catalog_has_route(
        &catalog,
        "GET",
        "/v1/admin/policy/grants"
    ));
    assert!(catalog_has_route(&catalog, "GET", "/v1/tokens"));
}

#[tokio::test]
async fn browser_auditor_keeps_authentication_when_personal_access_is_disabled() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: Some(false),
            actor: "admin".into(),
        })
        .unwrap();
    for (uri, allowed) in [
        ("/v1/auth/session", true),
        ("/v1/admin/principals", true),
        ("/v1/admin/config/status", true),
        ("/v1/tokens", false),
        ("/v1/credentials", false),
        ("/v1/audit/events", false),
    ] {
        let (status, body) = cookie_get(
            fixture.app.clone(),
            fixture.cookie.clone(),
            fixture.csrf.clone(),
            uri,
        )
        .await;
        assert_eq!(
            status,
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            },
            "{uri}: {body}"
        );
        if !allowed {
            assert_eq!(body["reasonCode"], "self_service_disabled", "{body}");
        }
        if uri == "/v1/auth/session" {
            assert_eq!(body["result"]["authenticated"], true);
            assert_eq!(body["result"]["role"], "auditor");
            assert_eq!(body["result"]["selfServiceEnabled"], false);
            assert!(body["result"].get("roles").is_none());
            assert!(body["result"].get("isAdmin").is_none());
        }
    }
    let before = store
        .resolve_broker_token(
            snapshot.runtime.broker_token_hasher().unwrap(),
            &fixture.agent_tokens[0],
        )
        .unwrap();
    assert_eq!(
        before.principal_id, "alice",
        "invocation credentials survive personal disablement"
    );
}

#[tokio::test]
async fn disabled_self_service_is_enforced_on_direct_personal_routes_and_hidden_from_catalog() {
    let fixture = audit_fixture(Backend::Sqlite);
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: None,
            self_service_enabled: Some(false),
            actor: "admin".into(),
        })
        .unwrap();
    let ids = BTreeMap::new();
    for route in http_route_specs(fixture.state.current().runtime.resource_types())
        .iter()
        .filter(|route| {
            matches!(
                route.access,
                RouteAccess::UserManagement | RouteAccess::UserTokenManagement
            )
        })
    {
        let uri = concrete_route(&route.route, &ids);
        let method = Method::from_bytes(route.method.as_bytes()).unwrap();
        let body = if method == Method::GET || method == Method::DELETE {
            None
        } else {
            Some(write_body(&route.operation))
        };
        let (status, result) = sweep_request(&fixture, method, &fixture.bob, &uri, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{} {uri}: {result}",
            route.method
        );
        assert_eq!(
            result["reasonCode"], "self_service_disabled",
            "{uri}: {result}"
        );
    }
    let (status, body) = fixture
        .request(
            Method::GET,
            &fixture.bob,
            "/v1/admin/policy/grants",
            None,
            "disabled-manager-still-manages",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, catalog) = fixture
        .request(
            Method::GET,
            &fixture.bob,
            "/v1/spec/catalog",
            None,
            "disabled-personal-spec",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert!(!catalog_has_route(&catalog, "GET", "/v1/tokens"));
    assert!(catalog_has_route(
        &catalog,
        "POST",
        "/v1/admin/policy/grants"
    ));
}

#[tokio::test]
async fn access_patch_guards_last_admin_revokes_old_admin_tokens_and_audits_committed_facts() {
    let fixture = audit_fixture(Backend::Sqlite);
    let auditor_token = auditor(&fixture);
    let patch = |body: &'static str| {
        fixture.request(
            Method::PATCH,
            &fixture.admin,
            "/v1/admin/principals/carol/access",
            Some(body),
            "access-patch-test",
        )
    };
    for body in [r#"{"role":"auditor"}"#, r#"{"selfServiceEnabled":false}"#] {
        let (status, result) = patch(body).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let (status, result) = fixture
            .request(
                Method::GET,
                &auditor_token,
                "/v1/admin/principals",
                None,
                "retained-admin-token",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{result}");
    }
    let (status, result) = fixture
        .request(
            Method::PATCH,
            &fixture.admin,
            "/v1/admin/principals/admin/access",
            Some(r#"{"role":"user"}"#),
            "last-admin-guard",
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    let (status, result) = patch(r#"{"role":"admin"}"#).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["result"]["role"], "admin");
    assert_eq!(result["result"]["selfServiceEnabled"], false);
    let request_id = result["brokerRequestId"].clone();
    let (status, result) = fixture
        .request(
            Method::POST,
            &auditor_token,
            "/v1/admin/config/reload",
            None,
            "old-auditor-cannot-become-writer",
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{result}");
    assert_eq!(result["reasonCode"], "broker_token_revoked");
    let records = fixture.records();
    let completion = records
        .iter()
        .find(|record| {
            record["brokerRequestId"] == request_id
                && record["providerAudit"]["management"]["target"]["previousRole"] == "auditor"
        })
        .expect("committed access audit");
    assert_eq!(
        completion["providerAudit"]["management"]["target"]["role"],
        "admin"
    );
    assert_eq!(
        completion["providerAudit"]["management"]["target"]["revokedAdminTokenIds"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        completion["providerAudit"]["management"]["target"]["selfServiceEnabled"],
        false
    );
}

#[tokio::test]
async fn administrator_token_transitions_ignore_owner_personal_access_but_keep_owner_scope() {
    let fixture = audit_fixture(Backend::Sqlite);
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    for owner in ["alice", "admin"] {
        let personal = issue(&fixture, owner, BrokerTokenClass::UserManage);
        let raw_agent = issue(&fixture, owner, BrokerTokenClass::AgentInvoke);
        let token_id = store
            .resolve_broker_token(snapshot.runtime.broker_token_hasher().unwrap(), &raw_agent)
            .unwrap()
            .token_id;
        store
            .patch_principal_access(PrincipalAccessPatchRequest {
                principal_id: owner.into(),
                role: None,
                self_service_enabled: Some(false),
                actor: "admin".into(),
            })
            .unwrap();
        for action in ["pause", "resume"] {
            let (status, denied) = fixture
                .request(
                    Method::POST,
                    &personal,
                    &format!("/v1/tokens/{token_id}/{action}"),
                    None,
                    "personal-token-transition-disabled",
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{owner}/{action}: {denied}");
            assert_eq!(denied["reasonCode"], "self_service_disabled");
            assert_eq!(
                store.broker_token(&token_id).unwrap().paused_at.is_some(),
                action == "resume",
                "denied personal transition must leave state unchanged"
            );
            let (status, wrong_owner) = fixture
                .request(
                    Method::POST,
                    &fixture.admin,
                    &format!("/v1/admin/principals/carol/agent-tokens/{token_id}/{action}"),
                    None,
                    "admin-token-transition-wrong-owner",
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong_owner}");
            assert_eq!(wrong_owner["reasonCode"], "broker_token_not_found");
            let (status, changed) = fixture
                .request(
                    Method::POST,
                    &fixture.admin,
                    &format!("/v1/admin/principals/{owner}/agent-tokens/{token_id}/{action}"),
                    None,
                    "admin-token-transition-disabled-personal",
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{owner}/{action}: {changed}");
            assert_eq!(changed["result"]["pausedAt"].is_string(), action == "pause");
        }
    }
}

#[tokio::test]
async fn administrator_can_delete_credentials_after_disabling_the_owner() {
    let fixture = audit_fixture(Backend::Sqlite);
    let snapshot = fixture.state.current();
    let store = snapshot.runtime.managed_store().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("credential-key");
    std::fs::write(
        &key_path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([37_u8; 32]),
    )
    .unwrap();
    let ring = agent_access_core::CredentialKeyRing::load(
        &agent_access_core::CredentialEncryptionConfig {
            active_key: "test".into(),
            keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
                id: "test".into(),
                provider: "file".into(),
                env: None,
                path: Some(key_path.display().to_string()),
            }],
        },
    )
    .unwrap();
    let mut credential_ids = Vec::new();
    for name in ["tuple", "id"] {
        let credential = store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "alice".into(),
                    service: "jira".into(),
                    name: name.into(),
                    profile: "jira-cloud-api-token".into(),
                    credential_kind: "basic_api_token".into(),
                    secret: json!({"username":"alice@example.com","token":"synthetic"}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                agent_access_core::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        credential_ids.push(credential.credential_id);
    }
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: None,
            self_service_enabled: Some(false),
            actor: "admin".into(),
        })
        .unwrap();
    store.set_principal_enabled("alice", false).unwrap();
    for uri in [
        "/v1/admin/principals/alice/credentials/jira/tuple".to_string(),
        format!("/v1/admin/credentials/{}", credential_ids[1]),
    ] {
        let (status, deleted) = fixture
            .request(
                Method::DELETE,
                &fixture.admin,
                &uri,
                None,
                "admin-disabled-owner-credential-cleanup",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {deleted}");
    }
    assert!(store.list_credentials(Some("alice")).unwrap().is_empty());
}
