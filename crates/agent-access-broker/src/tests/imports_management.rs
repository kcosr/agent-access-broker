//! Exercise the administrator workflow through the real router and store.
use super::imports_foundation::{Fixture, definition, fixture, update};
use super::*;
use agent_access_core::*;

fn admin_token(fixture: &Fixture) -> String {
    admin_token_for(fixture, "admin")
}
fn admin_token_for(fixture: &Fixture, principal: &str) -> String {
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            &BrokerTokenHasher::load(fixture.config.broker_tokens.as_ref().unwrap()).unwrap(),
            BrokerTokenIssueRequest {
                principal_id: principal.into(),
                name: "imports administration".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}
async fn request(
    app: &Router,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map(|body| body.to_string());
    let response = authed_json_request(
        app.clone(),
        method,
        path,
        "imports-management",
        "Authorization",
        format!("Bearer {token}"),
        body.as_deref(),
    )
    .await;
    (response.status(), response_json(response).await)
}
fn versions(result: &Value) -> Value {
    json!({"expectedVersion":result["service"]["version"],"expectedCatalogRevision":result["catalogRevision"]})
}
async fn detail(app: &Router, token: &str, service: &str) -> Value {
    let (status, body) = request(
        app,
        token,
        Method::GET,
        &format!("/v1/admin/imports/{service}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["result"].clone()
}
fn selection(preview: &Value, read_only: bool) -> Value {
    let definition = &preview["preview"]["manifest"]["tools"][0]["definition"];
    json!({"source":definition["source"],"action":definition["action"],"readOnly":read_only})
}
async fn accept_preview(
    app: &Router,
    token: &str,
    service: &str,
    preview: &Value,
    confirm: bool,
) -> (StatusCode, Value) {
    let mut body = versions(preview);
    body["manifestHash"] = preview["preview"]["manifestHash"].clone();
    body["selections"] = json!([selection(preview, true)]);
    body["confirmAffectedGrants"] = json!(confirm);
    request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/accept"),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn admin_import_flow_is_versioned_explicit_and_persistent() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    let app = build_router(fixture.runtime.clone());
    let mut definition = definition();
    definition.service = "toolbox".into();
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(json!(definition)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["result"]["service"]["status"], "draft");
    assert_eq!(created["result"]["scopedMcp"]["ready"], false);
    let mut secret = versions(&created["result"]);
    secret["token"] = json!("import-service-token");
    let (status, put) = request(
        &app,
        &token,
        Method::PUT,
        "/v1/admin/imports/toolbox/credentials/execution",
        Some(secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    assert!(!put.to_string().contains("import-service-token"));
    assert_eq!(put["result"]["scopedMcp"]["ready"], false);
    let (status, stale) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/toolbox/discover",
        Some(versions(&created["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/toolbox/discover",
        Some(versions(&put["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    assert_eq!(
        discovered["result"]["preview"]["manifest"]["tools"][0]["definition"]["action"],
        "inspect"
    );
    assert_eq!(discovered["result"]["service"]["actions"], json!([]));
    assert_eq!(discovered["result"]["scopedMcpWarnings"], json!([]));
    assert_eq!(discovered["result"]["scopedMcp"]["ready"], false);
    let (status, accepted) =
        accept_preview(&app, &token, "toolbox", &discovered["result"], false).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(accepted["result"]["service"]["status"], "disabled");
    assert_eq!(accepted["result"]["scopedMcp"]["ready"], false);
    assert_eq!(
        accepted["result"]["service"]["actions"][0]["definition"]["readOnly"],
        true
    );
    let mut enable = versions(&accepted["result"]);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/toolbox/status",
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_eq!(
        enabled["result"]["scopedMcp"],
        json!({"ready":true,"issues":[],"truncated":false})
    );
    let (status, denied) = request(
        &app,
        &fixture.tokens["alice"],
        Method::POST,
        "/v1/invoke/toolbox/inspect",
        Some(json!({"inputs":{"message":"read"}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    let mut moved = versions(&enabled["result"]);
    definition.endpoint = "https://synthetic.invalid/other".into();
    moved["definition"] = json!(definition);
    assert_eq!(
        request(
            &app,
            &token,
            Method::PATCH,
            "/v1/admin/imports/toolbox",
            Some(moved)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let record = restarted.imported_catalog().service("toolbox").unwrap();
    assert_eq!(record.status, ImportedServiceStatus::Enabled);
    assert_eq!(record.actions.len(), 1);
    let mut retired = versions(&enabled["result"]);
    retired["status"] = json!("retired");
    retired["confirm"] = json!(true);
    assert_eq!(
        request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/toolbox/status",
            Some(retired)
        )
        .await
        .0,
        StatusCode::OK
    );
    let current = detail(&app, &token, "toolbox").await;
    assert_eq!(current["scopedMcp"]["ready"], false);
    let mut enable = versions(&current);
    enable["status"] = json!("enabled");
    assert_eq!(
        request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/toolbox/status",
            Some(enable)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn refresh_quarantines_changed_tools_and_accept_requires_grant_confirmation() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    let record = fixture
        .runtime
        .imported_catalog()
        .service("observability")
        .unwrap();
    let mut actions = record
        .actions
        .iter()
        .map(|a| ImportedActionWrite {
            definition: a.definition.clone(),
            status: a.status,
        })
        .collect::<Vec<_>>();
    actions[0].definition.input_schema["properties"]["oldFlag"] = json!({"type":"boolean"});
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: record.definition.clone(),
                status: record.status,
                actions,
                expected_version: record.version,
                expected_catalog_revision: fixture.runtime.import_catalog_revision(),
                accepted_preview: None,
                actor: "admin".into(),
            },
            |_| Ok(()),
        )
        .unwrap();
    let app = build_router(BrokerRuntime::new(fixture.config.clone()).unwrap());
    let current = detail(&app, &token, "observability").await;
    let (status, body) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/discover",
        Some(versions(&current)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let preview = &body["result"];
    assert_eq!(preview["service"]["actions"][0]["status"], "quarantined");
    let audit = std::fs::read_to_string(&fixture.config.audit.as_ref().unwrap().path).unwrap();
    let completed = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|record| {
            record["providerAudit"]["management"]["operation"] == "admin.imports.discover"
                && record["providerAudit"]["management"]["phase"] == "success"
        })
        .unwrap();
    assert_eq!(
        completed["providerAudit"]["management"]["target"]["manifestHash"],
        preview["preview"]["manifestHash"]
    );
    assert_eq!(
        completed["providerAudit"]["management"]["target"]["quarantinedActions"],
        json!(["inspect"])
    );
    assert!(!completed.to_string().contains("inputSchema"));
    assert!(!completed.to_string().contains("import-service-token"));
    assert_eq!(preview["affectedGrants"].as_array().unwrap().len(), 3);
    assert_eq!(
        preview["affectedGrantsByAction"]["inspect"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let (status, denied) = request(
        &app,
        &fixture.tokens["alice"],
        Method::POST,
        "/v1/invoke/observability/inspect",
        Some(json!({"inputs":{"message":"read"}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    let mut status_body = versions(preview);
    status_body["status"] = json!("enabled");
    assert_eq!(
        request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/observability/actions/inspect/status",
            Some(status_body)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        accept_preview(&app, &token, "observability", preview, false)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, accepted) = accept_preview(&app, &token, "observability", preview, true).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(
        request(
            &app,
            &fixture.tokens["alice"],
            Method::POST,
            "/v1/invoke/observability/inspect",
            Some(json!({"inputs":{"message":"read"}}))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn import_restoration_requires_confirmation_and_retired_tools_get_new_identity() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    let app = build_router(fixture.runtime.clone());
    for suffix in ["actions/inspect/status", "status"] {
        let current = detail(&app, &token, "observability").await;
        let path = format!("/v1/admin/imports/observability/{suffix}");
        let mut body = versions(&current);
        body["status"] = json!("disabled");
        let (status, disabled) = request(&app, &token, Method::POST, &path, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{disabled}");
        let mut enable = versions(&disabled["result"]);
        enable["status"] = json!("enabled");
        assert_eq!(
            request(&app, &token, Method::POST, &path, Some(enable.clone()))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        enable["confirm"] = json!(true);
        let (status, enabled) = request(&app, &token, Method::POST, &path, Some(enable)).await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        assert_eq!(enabled["target"]["status"], "enabled");
        if suffix.starts_with("actions") {
            assert_eq!(enabled["target"]["action"], "inspect");
        }
    }
    let current = detail(&app, &token, "observability").await;
    let mut retire = versions(&current);
    retire["status"] = json!("retired");
    retire["confirm"] = json!(true);
    let (status, retired) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/actions/inspect/status",
        Some(retire),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retired}");
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/discover",
        Some(versions(&retired["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let preview = &discovered["result"];
    let next_name = selection(preview, true)["action"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(next_name, "inspect");
    let (status, accepted) = accept_preview(&app, &token, "observability", preview, false).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(
        accepted["result"]["service"]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        accepted["target"]["manifestHash"],
        preview["preview"]["manifestHash"]
    );
    assert_eq!(
        accepted["target"]["actions"],
        json!([{"action":next_name,"readOnly":true}])
    );
    for action in ["inspect", next_name.as_str()] {
        assert_eq!(
            request(
                &app,
                &fixture.tokens["alice"],
                Method::POST,
                &format!("/v1/invoke/observability/{action}"),
                Some(json!({"inputs":{"message":"read"}}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let audit = std::fs::read_to_string(&fixture.config.audit.as_ref().unwrap().path).unwrap();
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let serialized = serde_json::to_string(&records).unwrap();
    assert!(serialized.contains("manifestHash"));
    assert!(serialized.contains(&next_name));
    assert!(!serialized.contains("import-service-token"));
    assert!(!serialized.contains("inputSchema"));
}

#[tokio::test]
async fn deleted_grants_do_not_block_restoration_or_appear_in_import_preview() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    for grant in fixture
        .runtime
        .managed_store()
        .unwrap()
        .policy_grants()
        .unwrap()
    {
        fixture
            .runtime
            .delete_managed_policy_grant(ManagedPolicyGrantStatusRequest {
                grant_id: grant.grant_id,
                expected_version: grant.version,
                updated_by: "admin".into(),
            })
            .unwrap();
    }
    let app = build_router(fixture.runtime.clone());
    for suffix in ["actions/inspect/status", "status"] {
        for status in ["disabled", "enabled"] {
            let current = detail(&app, &token, "observability").await;
            let mut body = versions(&current);
            body["status"] = json!(status);
            let (status, result) = request(
                &app,
                &token,
                Method::POST,
                &format!("/v1/admin/imports/observability/{suffix}"),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{result}");
        }
    }
    let current = detail(&app, &token, "observability").await;
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/discover",
        Some(versions(&current)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    assert_eq!(discovered["result"]["affectedGrants"], json!([]));
    assert_eq!(discovered["result"]["affectedGrantsByAction"], json!({}));
    let (status, preview) = request(
        &app,
        &token,
        Method::GET,
        "/v1/admin/imports/observability/preview",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["result"]["affectedGrants"], json!([]));
    assert_eq!(preview["result"]["affectedGrantsByAction"], json!({}));
}

#[tokio::test]
async fn import_management_requires_admin_and_gate_off_preserves_cleanup() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    let mut config = fixture.config.clone();
    config.imports.enabled = false;
    let app = build_router(BrokerRuntime::new(config).unwrap());
    assert_eq!(
        request(
            &app,
            &fixture.tokens["alice"],
            Method::GET,
            "/v1/admin/imports",
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, list) = request(&app, &token, Method::GET, "/v1/admin/imports", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["result"]["operatorEnabled"], false);
    let current = detail(&app, &token, "observability").await;
    assert_eq!(current["operatorAllowed"], false);
    assert_eq!(
        request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports/observability/discover",
            Some(versions(&current))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut disable = versions(&current);
    disable["status"] = json!("disabled");
    let (status, disabled) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/status",
        Some(disable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{disabled}");
    let (status, deleted) = request(
        &app,
        &token,
        Method::DELETE,
        "/v1/admin/imports/observability/credentials/execution",
        Some(versions(&disabled["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert!(
        deleted["result"]["service"]["slotVersions"]
            .get("execution")
            .is_none()
    );
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .policy_grants()
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn personal_discovery_rotation_invalidates_preview_without_service_edit() {
    let fixture = fixture();
    let token = admin_token(&fixture);
    let app = build_router(fixture.runtime.clone());
    let current = detail(&app, &token, "observability").await;
    let mut definition = definition();
    definition.discovery = ImportedDiscoveryCredential::PerUser {
        principal: "admin".into(),
    };
    let mut update = versions(&current);
    update["definition"] = json!(definition);
    let (status, changed) = request(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/imports/observability",
        Some(update),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let put = |token: &str| {
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .upsert_user_credential(
                fixture.runtime.credential_key_ring().unwrap(),
                CredentialWriteRequest {
                    owner_principal_id: "admin".into(),
                    service: "observability".into(),
                    name: "default".into(),
                    profile: "token".into(),
                    credential_kind: "bearer_token".into(),
                    secret: json!({"token":token}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                agent_access_core::CredentialManagementPurpose::Administrative,
            )
            .unwrap()
    };
    put("admin-discovery-one");
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/observability/discover",
        Some(versions(&changed["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    put("admin-discovery-two");
    assert_eq!(
        accept_preview(&app, &token, "observability", &discovered["result"], true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (status, preview) = request(
        &app,
        &token,
        Method::GET,
        "/v1/admin/imports/observability/preview",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview["result"]["preview"].is_null());
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("alice").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("admin").into(),
        })
        .unwrap();
    let other_admin = admin_token_for(&fixture, "alice");
    let current = detail(&app, &other_admin, "observability").await;
    let mut edit = versions(&current);
    edit["definition"] = current["service"]["definition"].clone();
    edit["definition"]["displayName"] = json!("Updated by another administrator");
    let (status, updated) = request(
        &app,
        &other_admin,
        Method::PATCH,
        "/v1/admin/imports/observability",
        Some(edit),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        request(
            &app,
            &other_admin,
            Method::POST,
            "/v1/admin/imports/observability/discover",
            Some(versions(&updated["result"]))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn imported_service_metadata_follows_the_reviewed_definition() {
    let fixture = fixture();
    let user_manage_token = |runtime: &BrokerRuntime, principal: &str| {
        runtime
            .managed_store()
            .unwrap()
            .issue_broker_token(
                &BrokerTokenHasher::load(fixture.config.broker_tokens.as_ref().unwrap()).unwrap(),
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "imports metadata".into(),
                    token_class: BrokerTokenClass::UserManage,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap()
            .token
    };
    let metadata = |runtime: BrokerRuntime| {
        let alice = user_manage_token(&runtime, "alice");
        let bob = user_manage_token(&runtime, "bob");
        async move {
            let app = build_router(runtime);
            let (status, options) =
                request(&app, &alice, Method::GET, "/v1/tokens/options", None).await;
            assert_eq!(status, StatusCode::OK, "{options}");
            let (status, targets) =
                request(&app, &bob, Method::GET, "/v1/credentials/targets", None).await;
            assert_eq!(status, StatusCode::OK, "{targets}");
            (options["result"].clone(), targets["result"].clone())
        }
    };

    let (options, targets) = metadata(fixture.runtime.clone()).await;
    let service = &options["services"][0];
    assert_eq!(options["services"].as_array().unwrap().len(), 1);
    assert_eq!(service["service"], "observability");
    assert_eq!(service["displayName"], "Imported observations");
    assert_eq!(service["brokerHosts"], json!([]));
    assert_eq!(service["actions"][0]["action"], "inspect");
    assert_eq!(service["actions"][0]["readOnly"], true);
    assert_eq!(targets.as_array().unwrap().len(), 1, "{targets}");
    assert_eq!(targets[0]["service"], "observability");
    assert_eq!(targets[0]["displayName"], "Imported observations");
    assert_eq!(targets[0]["credentialVerificationInputs"], json!([]));

    // An administrator's reviewed classification and name replace the old ones.
    let mut reviewed = update(
        fixture.runtime.imported_catalog(),
        ImportedServiceStatus::Enabled,
    );
    reviewed.definition.display_name = "Reviewed observations".into();
    reviewed.actions[0].definition.read_only = false;
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .update_imported_service(reviewed, |_| Ok(()))
        .unwrap();
    let (options, targets) = metadata(BrokerRuntime::new(fixture.config.clone()).unwrap()).await;
    let service = &options["services"][0];
    assert_eq!(service["displayName"], "Reviewed observations");
    assert_eq!(service["actions"][0]["readOnly"], false);
    assert_eq!(targets[0]["displayName"], "Reviewed observations");
}
