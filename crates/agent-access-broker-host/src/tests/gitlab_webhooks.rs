use super::*;
use agent_access_provider::{ScopeRequest, ScopeResolution};
use axum::extract::State;
use axum::response::IntoResponse;
use std::sync::atomic::AtomicBool;

const WEBHOOK_ACTIONS: &[&str] = &[
    "webhook.list",
    "webhook.view",
    "webhook.create",
    "webhook.update",
    "webhook.delete",
    "webhook.test",
    "webhook.event.list",
    "webhook.event.resend",
    "webhook.custom_header.set",
    "webhook.custom_header.delete",
];

const WEBHOOK_SECRET_SENTINEL: &str = "gitlab-webhook-secret-sentinel-c6f8a1";

#[tokio::test]
async fn webhook_actions_have_caller_filtered_catalog_openapi_and_send_parity() {
    let fixture = spec_agent_fixture(&["gitlab"], false);
    let catalog = response_json(
        spec_get(
            fixture.app.clone(),
            "/v1/spec/catalog",
            "gitlab-webhook-catalog",
            Some(&fixture.agent_token),
        )
        .await,
    )
    .await;
    let openapi = response_json(
        spec_get(
            fixture.app.clone(),
            "/v1/spec/openapi.json",
            "gitlab-webhook-openapi",
            Some(&fixture.agent_token),
        )
        .await,
    )
    .await;
    let send_schema = response_json(
        spec_get(
            fixture.app,
            "/v1/spec/send-schema.json",
            "gitlab-webhook-send-schema",
            Some(&fixture.agent_token),
        )
        .await,
    )
    .await;

    for action in WEBHOOK_ACTIONS {
        let catalog_action = catalog_action(&catalog, "gitlab", action);
        let route = format!("/v1/invoke/gitlab/{action}");
        let openapi_action = &openapi["paths"][&route]["post"];
        let send_action = send_action_variant(&send_schema, "gitlab", action);
        assert_eq!(
            openapi_action["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"],
            catalog_action["inputSchema"],
            "catalog and OpenAPI diverged for gitlab.{action}"
        );
        assert_eq!(
            send_action["properties"]["inputs"], catalog_action["inputSchema"],
            "catalog and send schema diverged for gitlab.{action}"
        );
        assert_eq!(catalog_action["requiredScopeTypes"], json!(["repository"]));
        assert!(catalog_action.get("upstreamResourceOwnership").is_none());
    }

    assert_eq!(
        catalog_action(&catalog, "gitlab", "webhook.create")["sensitiveInputPointers"],
        json!(["/inputs/signingToken", "/inputs/token"])
    );
    assert_eq!(
        catalog_action(&catalog, "gitlab", "webhook.update")["sensitiveInputPointers"],
        json!(["/inputs/signingToken", "/inputs/token"])
    );
    assert_eq!(
        catalog_action(&catalog, "gitlab", "webhook.custom_header.set")["sensitiveInputPointers"],
        json!(["/inputs/value"])
    );
    for action in WEBHOOK_ACTIONS.iter().copied().filter(|action| {
        !matches!(
            *action,
            "webhook.create" | "webhook.update" | "webhook.custom_header.set"
        )
    }) {
        assert!(
            catalog_action(&catalog, "gitlab", action)
                .get("sensitiveInputPointers")
                .is_none(),
            "gitlab.{action} unexpectedly advertises sensitive inputs"
        );
    }
    for unsupported in [
        "webhook.event.view",
        "webhook.url_variable.set",
        "webhook.url_variable.delete",
    ] {
        assert!(!catalog_has_action(&catalog, "gitlab", unsupported));
        assert!(
            openapi["paths"]
                .get(format!("/v1/invoke/gitlab/{unsupported}"))
                .is_none()
        );
        assert!(!send_schema_has_action(&send_schema, "gitlab", unsupported));
    }
    for action in [
        "webhook.create",
        "webhook.update",
        "webhook.custom_header.set",
    ] {
        let route = format!("/v1/invoke/gitlab/{action}");
        assert!(
            openapi["paths"][&route]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["properties"]
                .get("secretSources")
                .is_none(),
            "direct HTTP must carry canonical inputs, not local secretSources for gitlab.{action}"
        );
        assert!(
            send_action_variant(&send_schema, "gitlab", action)["properties"]
                .get("secretSources")
                .is_some(),
            "send schema omitted secretSources for gitlab.{action}"
        );
    }

    let restricted = spec_agent_fixture_with_restrictions(
        &["gitlab"],
        json!({
            "gitlab": {
                "actions": ["webhook.view", "webhook.test"],
                "resources":{"resourceIds":["repository-sip-service"],"resourceGroupIds":[]}
            }
        }),
    );
    let restricted_catalog = response_json(
        spec_get(
            restricted.app.clone(),
            "/v1/spec/catalog",
            "gitlab-webhook-filtered-catalog",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;
    let restricted_openapi = response_json(
        spec_get(
            restricted.app.clone(),
            "/v1/spec/openapi.json",
            "gitlab-webhook-filtered-openapi",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;
    let restricted_send = response_json(
        spec_get(
            restricted.app,
            "/v1/spec/send-schema.json",
            "gitlab-webhook-filtered-send",
            Some(&restricted.agent_token),
        )
        .await,
    )
    .await;

    for action in ["webhook.view", "webhook.test"] {
        assert!(catalog_has_action(&restricted_catalog, "gitlab", action));
        assert!(
            restricted_openapi["paths"]
                .get(format!("/v1/invoke/gitlab/{action}"))
                .is_some()
        );
        assert!(send_schema_has_action(&restricted_send, "gitlab", action));
    }
    for action in ["webhook.create", "webhook.update", "webhook.event.resend"] {
        assert!(!catalog_has_action(&restricted_catalog, "gitlab", action));
        assert!(
            restricted_openapi["paths"]
                .get(format!("/v1/invoke/gitlab/{action}"))
                .is_none()
        );
        assert!(!send_schema_has_action(&restricted_send, "gitlab", action));
    }
}

#[derive(Debug)]
struct BrokerWebhookContractProvider;

impl agent_access_provider::test_support::DescribedProvider for BrokerWebhookContractProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let schema = |required: &[&str]| {
            let mut properties = serde_json::Map::from_iter([
                ("project".to_string(), json!({ "type": "string" })),
                ("url".to_string(), json!({ "type": "string" })),
                (
                    "token".to_string(),
                    json!({
                        "type": "string",
                        "x-agent-access-sensitive": true
                    }),
                ),
                (
                    "webhookId".to_string(),
                    json!({ "type": "integer", "minimum": 1 }),
                ),
            ]);
            if !required.contains(&"url") {
                properties.remove("url");
                properties.remove("token");
            }
            json!({
                "type": "object",
                "required": required,
                "properties": properties,
                "additionalProperties": false
            })
        };
        ServiceDescriptor {
            service: "gitlab".to_string(),
            display_name: "GitLab Webhook Broker Contract Test Provider".to_string(),
            surface: ServiceSurface::Invoke,
            resource_scopes: fixture_scope_capabilities("repository"),
            actions: vec![
                ActionDescriptor::new(
                    "webhook.create",
                    "Create a webhook",
                    schema(&["project", "url", "token"]),
                )
                .scope("repository")
                .credential_modes(["service"]),
                ActionDescriptor::new(
                    "webhook.update",
                    "Update a webhook",
                    schema(&["project", "webhookId"]),
                )
                .scope("repository")
                .credential_modes(["service"]),
            ],
            credentials: CredentialDescriptor::default(),
            presentation_body_limit: None,
        }
    }
}

impl BrokerWebhookContractProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if !matches!(action, "webhook.create" | "webhook.update") {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab webhook test action is unsupported",
            ));
        }
        let project = inputs["project"]
            .as_str()
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "repository".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for BrokerWebhookContractProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert_eq!(
            request
                .credential
                .as_ref()
                .and_then(|credential| credential.token.as_deref()),
            Some("broker-webhook-service-token")
        );
        match request.action.as_str() {
            "webhook.create" => {
                assert_eq!(request.inputs["token"], WEBHOOK_SECRET_SENTINEL);
                Ok(ProviderResult {
                    result: json!({
                        "mutationStatus": "applied",
                        "retrySafe": false,
                        "webhookId": 42
                    }),
                    stream: None,
                    audit: Some(json!({
                        "provider": "gitlab",
                        "operation": "webhook.create",
                        "repository": "sip/service",
                        "webhookId": 42,
                        "urlChanged": true
                    })),
                    upstream_status: Some(201),
                    upstream_duration_ms: Some(8),
                    object_ids: Some(json!({ "webhookId": 42 })),
                })
            }
            "webhook.update" => Err(ProviderError::error(
                ReasonCode::MutationVerificationFailed,
                "upstream mutation could not be fully verified",
            )
            .with_result(json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "mutation_readback",
                "safeLocators": { "webhookIds": [42] }
            }))),
            action => panic!("unexpected GitLab webhook action: {action}"),
        }
    }
}

#[tokio::test]
async fn webhook_direct_http_invoke_preserves_safe_mutation_envelopes_without_secret_leaks() {
    let audit_path = temp_path("gitlab-webhook-http.audit.jsonl");
    let credential_path = temp_path("gitlab-webhook-http.service-token");
    std::fs::write(&credential_path, "broker-webhook-service-token").unwrap();
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.credentials.service.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", credential_path.display())),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some(format!("file:{}", credential_path.display())),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
            attachments: Default::default(),
            api_base_url: "https://gitlab.example.com/api/v4".to_string(),
            web_base_url: "https://gitlab.example.com".to_string(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
            webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
            content: agent_access_gitlab::GitlabContentConfig::default(),
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["webhook.create".to_string(), "webhook.update".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    let app = build_router(
        BrokerRuntime::with_providers(config, vec![Arc::new(BrokerWebhookContractProvider)])
            .unwrap(),
        broker_build_status(),
    );

    let create = webhook_invoke_request(
        app.clone(),
        "webhook.create",
        "gitlab-webhook-http-create",
        json!({
            "inputs": {
                "project": "sip/service",
                "url": "https://hooks.example.com/gitlab/events",
                "token": WEBHOOK_SECRET_SENTINEL
            }
        }),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let create = response_json(create).await;
    assert_eq!(create["decision"], "allow");
    assert_eq!(create["result"]["mutationStatus"], "applied");
    assert_eq!(create["result"]["retrySafe"], false);
    assert_eq!(create["result"]["webhookId"], 42);
    assert!(!create.to_string().contains(WEBHOOK_SECRET_SENTINEL));

    let update = webhook_invoke_request(
        app,
        "webhook.update",
        "gitlab-webhook-http-update-ambiguous",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42
            }
        }),
    )
    .await;
    assert_eq!(update.status(), StatusCode::CONFLICT);
    let update = response_json(update).await;
    assert_eq!(update["decision"], "error");
    assert_eq!(update["reasonCode"], "mutation_verification_failed");
    assert_eq!(
        update["result"],
        json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": "mutation_readback",
            "safeLocators": { "webhookIds": [42] }
        })
    );
    assert!(!update.to_string().contains(WEBHOOK_SECRET_SENTINEL));

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains(WEBHOOK_SECRET_SENTINEL));
    assert!(audit.contains("\"action\":\"webhook.create\""));
    assert!(audit.contains("\"action\":\"webhook.update\""));
}

async fn webhook_invoke_request(
    app: Router,
    action: &str,
    request_id: &str,
    body: Value,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/invoke/gitlab/{action}"))
            .extension(ConnectInfo(
                "127.0.0.1:43220".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[derive(Clone)]
struct GitlabWebhookStubState {
    create_requests: Arc<AtomicUsize>,
    update_requests: Arc<AtomicUsize>,
    test_requests: Arc<AtomicUsize>,
    resend_requests: Arc<AtomicUsize>,
    delete_requests: Arc<AtomicUsize>,
    deleted: Arc<AtomicBool>,
}

async fn gitlab_webhook_stub(
    State(state): State<GitlabWebhookStubState>,
    method: Method,
    uri: Uri,
) -> axum::response::Response {
    let path = uri.path();
    let project = json!({
        "id": 1,
        "path_with_namespace": "sip/service",
        "name": "service",
        "web_url": "https://gitlab.example.com/sip/service",
        "default_branch": "main",
        "visibility": "private",
        "archived": false
    });
    let hook = json!({
        "id": 42,
        "project_id": 1,
        "url": "https://hooks.example.com/gitlab/events",
        "name": "updated",
        "description": "reload boundary test",
        "enable_ssl_verification": true,
        "push_events": true,
        "repository_update_events": false,
        "custom_headers": [],
        "url_variables": [],
        "token_present": true,
        "signing_token_present": false
    });

    if method == Method::GET && path.ends_with("/hooks/42") {
        if state.deleted.load(Ordering::SeqCst) {
            return (StatusCode::NOT_FOUND, axum::Json(json!({}))).into_response();
        }
        return (StatusCode::OK, axum::Json(hook)).into_response();
    }
    if method == Method::POST && path.ends_with("/hooks") {
        state.create_requests.fetch_add(1, Ordering::SeqCst);
        return (StatusCode::CREATED, axum::Json(hook)).into_response();
    }
    if method == Method::PUT && path.ends_with("/hooks/42") {
        state.update_requests.fetch_add(1, Ordering::SeqCst);
        return (StatusCode::OK, axum::Json(hook)).into_response();
    }
    if method == Method::POST && path.ends_with("/hooks/42/test/push_events") {
        state.test_requests.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::CREATED,
            axum::Json(json!({ "message": "201 Created" })),
        )
            .into_response();
    }
    if method == Method::POST && path.ends_with("/hooks/42/events/9001/resend") {
        state.resend_requests.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::CREATED,
            axum::Json(json!({
                "message": "Hook event resent",
                "response_status": 200
            })),
        )
            .into_response();
    }
    if method == Method::DELETE && path.ends_with("/hooks/42") {
        state.delete_requests.fetch_add(1, Ordering::SeqCst);
        state.deleted.store(true, Ordering::SeqCst);
        return StatusCode::NO_CONTENT.into_response();
    }
    if method == Method::GET && path.contains("/projects/") {
        return (StatusCode::OK, axum::Json(project)).into_response();
    }
    (StatusCode::NOT_FOUND, axum::Json(json!({}))).into_response()
}

#[tokio::test]
async fn webhook_destination_reload_denies_introduction_but_preserves_existing_management() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream_state = GitlabWebhookStubState {
        create_requests: Arc::new(AtomicUsize::new(0)),
        update_requests: Arc::new(AtomicUsize::new(0)),
        test_requests: Arc::new(AtomicUsize::new(0)),
        resend_requests: Arc::new(AtomicUsize::new(0)),
        delete_requests: Arc::new(AtomicUsize::new(0)),
        deleted: Arc::new(AtomicBool::new(false)),
    };
    let upstream_app = Router::new()
        .fallback(gitlab_webhook_stub)
        .with_state(upstream_state.clone());
    let upstream = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let config_path = temp_path("gitlab-webhook-reload.toml");
    let audit_path = temp_path("gitlab-webhook-reload.audit.jsonl");
    let spool_dir = temp_path("gitlab-webhook-reload-spool");
    let service_token = temp_path("gitlab-webhook-reload-service-token");
    let lookup_token = temp_path("gitlab-webhook-reload-lookup-token");
    let admin_token = temp_path("gitlab-webhook-reload-admin-token");
    std::fs::write(&service_token, "service-token").unwrap();
    std::fs::write(&lookup_token, "lookup-token").unwrap();
    std::fs::write(&admin_token, "admin-token").unwrap();
    write_gitlab_webhook_reload_config(
        &config_path,
        &audit_path,
        &spool_dir,
        &service_token,
        &lookup_token,
        &admin_token,
        upstream_addr,
        &["https://hooks.example.com/gitlab/**"],
    );

    let state = build_reloadable_state(
        config_path.clone(),
        std::sync::Arc::new(crate::backend_registry()),
        broker_build_status(),
        Some(10_485_760),
        // This tests policy after reload, not reload latency. Candidate
        // admission uses real filesystem and worker threads on a shared host.
        Duration::from_secs(10),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let app = build_public_router(state);

    let allowed_create = webhook_invoke_request(
        app.clone(),
        "webhook.create",
        "gitlab-webhook-create-before-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "url": "https://hooks.example.com/gitlab/events",
                "events": ["push"],
                "token": "reload-secret"
            }
        }),
    )
    .await;
    assert_eq!(allowed_create.status(), StatusCode::OK);
    assert_eq!(
        upstream_state.create_requests.load(Ordering::SeqCst),
        1,
        "allowed create reached GitLab"
    );

    write_gitlab_webhook_reload_config(
        &config_path,
        &audit_path,
        &spool_dir,
        &service_token,
        &lookup_token,
        &admin_token,
        upstream_addr,
        &[],
    );
    let reload = admin_request(
        app.clone(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("gitlab-webhook-empty-allowlist-reload"),
        Some("admin-token"),
    )
    .await;
    let reload_status = reload.status();
    let reload_body = response_json(reload).await;
    assert_eq!(reload_status, StatusCode::OK, "{reload_body}");
    assert_eq!(reload_body["result"]["generation"], 2);

    let denied_create = webhook_invoke_request(
        app.clone(),
        "webhook.create",
        "gitlab-webhook-create-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "url": "https://hooks.example.com/gitlab/new",
                "events": ["push"]
            }
        }),
    )
    .await;
    assert_eq!(denied_create.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(denied_create).await["reasonCode"],
        "webhook_destination_denied"
    );
    assert_eq!(
        upstream_state.create_requests.load(Ordering::SeqCst),
        1,
        "denied create did not reach GitLab"
    );

    let existing_view = webhook_invoke_request(
        app.clone(),
        "webhook.view",
        "gitlab-webhook-view-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42
            }
        }),
    )
    .await;
    assert_eq!(existing_view.status(), StatusCode::OK);
    assert_eq!(
        response_json(existing_view).await["result"]["webhook"]["id"],
        42
    );

    let denied_url_change = webhook_invoke_request(
        app.clone(),
        "webhook.update",
        "gitlab-webhook-url-change-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42,
                "url": "https://hooks.example.com/gitlab/new",
                "clearToken": true,
                "confirmDestinationReset": true
            }
        }),
    )
    .await;
    assert_eq!(denied_url_change.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(denied_url_change).await["reasonCode"],
        "webhook_destination_denied"
    );
    assert_eq!(upstream_state.update_requests.load(Ordering::SeqCst), 0);

    let preserving_update = webhook_invoke_request(
        app.clone(),
        "webhook.update",
        "gitlab-webhook-preserving-update-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42,
                "name": "updated"
            }
        }),
    )
    .await;
    assert_eq!(preserving_update.status(), StatusCode::OK);
    assert_eq!(upstream_state.update_requests.load(Ordering::SeqCst), 1);

    let test_delivery = webhook_invoke_request(
        app.clone(),
        "webhook.test",
        "gitlab-webhook-test-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42,
                "event": "push"
            }
        }),
    )
    .await;
    assert_eq!(test_delivery.status(), StatusCode::OK);
    assert_eq!(upstream_state.test_requests.load(Ordering::SeqCst), 1);

    let resend = webhook_invoke_request(
        app.clone(),
        "webhook.event.resend",
        "gitlab-webhook-resend-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42,
                "webhookEventId": 9001
            }
        }),
    )
    .await;
    assert_eq!(resend.status(), StatusCode::OK);
    assert_eq!(upstream_state.resend_requests.load(Ordering::SeqCst), 1);

    let delete = webhook_invoke_request(
        app.clone(),
        "webhook.delete",
        "gitlab-webhook-delete-after-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "webhookId": 42
            }
        }),
    )
    .await;
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(upstream_state.delete_requests.load(Ordering::SeqCst), 1);

    std::fs::write(&config_path, "[deployment\nenvironment = \"test\"\n").unwrap();
    let invalid_reload = admin_request(
        app.clone(),
        Method::POST,
        "/v1/admin/config/reload",
        Some("gitlab-webhook-invalid-reload"),
        Some("admin-token"),
    )
    .await;
    assert_eq!(invalid_reload.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid_reload).await["reasonCode"],
        "config_parse_failed"
    );

    let still_denied = webhook_invoke_request(
        app,
        "webhook.create",
        "gitlab-webhook-create-after-invalid-reload",
        json!({
            "inputs": {
                "project": "sip/service",
                "url": "https://hooks.example.com/gitlab/newer",
                "events": ["push"]
            }
        }),
    )
    .await;
    assert_eq!(still_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(still_denied).await["reasonCode"],
        "webhook_destination_denied"
    );
    assert_eq!(upstream_state.create_requests.load(Ordering::SeqCst), 1);

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains("reload-secret"));
    assert!(!audit.contains("https://hooks.example.com/gitlab/events"));

    upstream.abort();
}

#[allow(clippy::too_many_arguments)]
fn write_gitlab_webhook_reload_config(
    config_path: &Path,
    audit_path: &Path,
    spool_dir: &Path,
    service_token: &Path,
    lookup_token: &Path,
    admin_token: &Path,
    upstream_addr: SocketAddr,
    allowed_destinations: &[&str],
) {
    let destinations = allowed_destinations
        .iter()
        .map(|destination| format!("\"{destination}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(
        r#"[deployment]
environment = "test"

[identity]
mode = "optional"
authority = "toml"

[[identity.sources]]
name = "reload-admin"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "admin"
token_refs = ["file:{admin_token}"]

[[identity.groups]]
id = "broker-admins"
status = "active"
members = ["admin"]

[management]
enabled = true
admin_principals = ["admin"]
admin_groups = ["broker-admins"]
allow_classless_admin_identities = true

[credentials.service.gitlab]
type = "bearer_token"
token_ref = "file:{service_token}"

[credentials.lookup.gitlab]
type = "bearer_token"
token_ref = "file:{lookup_token}"
read_only = true

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "repository-sip-service"
resource_type = "git_repository"
selector = {{ kind = "exact", value = "sip/service" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:anonymous"]
service = "gitlab"
actions = ["webhook.view", "webhook.create", "webhook.update", "webhook.delete", "webhook.test", "webhook.event.resend"]
resources = {{ resource_ids = ["repository-sip-service"] }}
credential_mode = "service"

[limits]
max_http_body_bytes = 10485760
upload_spool_dir = "{spool_dir}"

[audit]
type = "jsonl"
path = "{audit_path}"

[providers.gitlab]
api_base_url = "http://{upstream_addr}/api/v4"
web_base_url = "http://{upstream_addr}"
allowed_upstream_hosts = ["http://{upstream_addr}/api/v4/**"]

[providers.gitlab.attachments]
max_bytes = 10485760
max_total_bytes = 10485760

[providers.gitlab.webhooks]
allowed_destinations = [{destinations}]
allow_disable_ssl_verification = false
"#,
        admin_token = admin_token.display(),
        service_token = service_token.display(),
        lookup_token = lookup_token.display(),
        spool_dir = spool_dir.display(),
        audit_path = audit_path.display(),
    );
    std::fs::write(config_path, config).unwrap();
}
