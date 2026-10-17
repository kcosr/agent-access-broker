use super::*;

#[tokio::test]
async fn project_upload_catalog_and_transport_are_filtered_by_token_actions() {
    for (actions, included) in [
        (json!(["project.upload"]), true),
        (json!(["project.view"]), false),
    ] {
        let fixture = spec_agent_fixture_with_restrictions(
            &["gitlab"],
            json!({
                "gitlab": {"actions": actions, "resources":{"resourceIds":["repository-sip-service"],"resourceGroupIds":[]}}
            }),
        ).await;
        let catalog = response_json(
            spec_get(
                fixture.app.clone(),
                "/v1/spec/catalog",
                "upload-catalog",
                Some(&fixture.agent_token),
            )
            .await,
        )
        .await;
        assert_eq!(
            catalog_has_action(&catalog, "gitlab", "project.upload"),
            included
        );
        let openapi = response_json(
            spec_get(
                fixture.app.clone(),
                "/v1/spec/openapi.json",
                "upload-openapi",
                Some(&fixture.agent_token),
            )
            .await,
        )
        .await;
        let send = response_json(
            spec_get(
                fixture.app.clone(),
                "/v1/spec/send-schema.json",
                "upload-send",
                Some(&fixture.agent_token),
            )
            .await,
        )
        .await;
        assert_eq!(
            openapi["paths"]
                .get("/v1/invoke/gitlab/project.upload")
                .is_some(),
            included
        );
        assert_eq!(
            send_schema_has_action(&send, "gitlab", "project.upload"),
            included
        );
        if included {
            let action = catalog_action(&catalog, "gitlab", "project.upload");
            assert_eq!(
                action["requiredScopes"],
                json!({"repository":{"resourceType":"git_repository"}})
            );
            assert_eq!(action["io"]["type"], "multipart_upload");
            assert_eq!(action["io"]["plan"]["maxFiles"], 1);
            assert!(openapi["paths"]["/v1/invoke/gitlab/project.upload"]["post"]["requestBody"]["content"].get("multipart/form-data").is_some());
            assert_eq!(
                send_action_variant(&send, "gitlab", "project.upload")["properties"]["files"]["maxItems"],
                1
            );
        } else {
            let response = denied_upload(fixture.app, &fixture.agent_token, "sip/service").await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let response = response_json(response).await;
            assert_eq!(response["reasonCode"], "service_action_denied");
            assert!(
                response["reason"]
                    .as_str()
                    .unwrap()
                    .contains("broker token")
            );
        }
    }
}

async fn denied_upload(app: Router, token: &str, project: &str) -> axum::response::Response {
    let boundary = "gitlab-upload-denial";
    let metadata = json!({"inputs": {"project": project, "attachments": [{
        "field": "file0", "filename": "session.html", "contentType": "text/html",
        "size": 1, "sha256": "0".repeat(64)
    }]}});
    // The file part deliberately has no field name: policy/token rejection must
    // precede inspecting it and must never become a multipart validation error.
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Disposition: form-data; filename=\"session.html\"\r\nContent-Type: text/html\r\n\r\nx\r\n--{boundary}--\r\n"
    );
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/invoke/gitlab/project.upload")
            .extension(ConnectInfo(
                "127.0.0.1:40201".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "upload-token-denied")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn project_upload_token_repository_denial_precedes_upload_and_file_validation() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let uploads = Arc::new(AtomicUsize::new(0));
    let lookups = Arc::new(AtomicUsize::new(0));
    let upload_count = uploads.clone();
    let lookup_count = lookups.clone();
    let upstream_app = Router::new().fallback(move |method: Method, uri: Uri| {
        let uploads = upload_count.clone();
        let lookups = lookup_count.clone();
        async move {
            if method == Method::POST {
                uploads.fetch_add(1, Ordering::SeqCst);
                return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({})));
            }
            assert!(uri.path().starts_with("/api/v4/projects/"));
            lookups.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::OK,
                axum::Json(json!({"id": 1, "path_with_namespace": "sip/service"})),
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move { axum::serve(listener, upstream_app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let hash_key = temp.path().join("hash-key");
    let credential_file = temp.path().join("credential");
    std::fs::write(&hash_key, URL_SAFE_NO_PAD.encode([41_u8; 32])).unwrap();
    std::fs::write(&credential_file, "upload-test-upstream-credential").unwrap();
    let mut config = fake_config("");
    config.limits.upload_spool_dir = temp.path().join("spool").display().to_string();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: temp.path().join("store.sqlite").display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    let credential = CredentialConfig {
        kind: "bearer_token".to_string(),
        username_ref: None,
        token_ref: Some(format!("file:{}", credential_file.display())),
        provider: None,
        path: None,
        read_only: None,
        connection: None,
    };
    config
        .credentials
        .service
        .insert("gitlab".to_string(), credential.clone());
    config.credentials.lookup.insert(
        "gitlab".to_string(),
        CredentialConfig {
            read_only: Some(true),
            ..credential
        },
    );
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
            api_base_url: format!("{upstream_url}/api/v4"),
            web_base_url: upstream_url.clone(),
            allowed_upstream_hosts: vec![format!("{upstream_url}/api/v4/**")],
            egress_proxy: None,
            attachments: Default::default(),
            content: Default::default(),
            search: Default::default(),
            webhooks: Default::default(),
        });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["user:upload-user".to_string()],
        execution_contexts: None,
        service: "gitlab".to_string(),
        actions: vec!["project.upload".to_string()],
        resources: selected_resources(&[("repository", &["sip/service"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let store = agent_access_core::ManagedStore::open(
        &store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "upload-user".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".to_string(),
        })
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store.issue_broker_token_with_catalog(&hasher, agent_access_core::BrokerTokenIssueRequest {
        principal_id: "upload-user".to_string(), name: "restricted upload".to_string(),
        token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
        scopes: json!({"allowedServices": ["gitlab"], "allowedExecutionContexts": ["default"],
            "serviceRestrictions": {"gitlab": {"actions": ["project.upload"], "resources":{"resourceIds":["repository-other-project"],"resourceGroupIds":[]}}}}),
        expires_at: None, created_by: "test".to_string(),
    }, Some(&agent_access_core::ManagedResourceCatalog { attribute_bindings: Vec::new(), resource_fences: Default::default(), resources: config.policy.resources.clone(), resource_groups: config.policy.resource_groups.clone() })).unwrap();
    let allowed = store.issue_broker_token_with_catalog(&hasher, agent_access_core::BrokerTokenIssueRequest {
        principal_id: "upload-user".to_string(), name: "allowed upload".to_string(),
        token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
        scopes: json!({"allowedServices": ["gitlab"], "allowedExecutionContexts": ["default"],
            "serviceRestrictions": {"gitlab": {"actions": ["project.upload"], "resources":{"resourceIds":["repository-sip-service"],"resourceGroupIds":[]}}}}),
        expires_at: None, created_by: "test".to_string(),
    }, Some(&agent_access_core::ManagedResourceCatalog { attribute_bindings: Vec::new(), resource_fences: Default::default(), resources: config.policy.resources.clone(), resource_groups: config.policy.resource_groups.clone() })).unwrap();
    drop(store);
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let response = denied_upload(app.clone(), &issued.token, "sip/service").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = response_json(response).await;
    assert_eq!(response["reasonCode"], "scope_unresolved");
    assert_eq!(
        response["reason"],
        "resource scope is not authorized or unavailable"
    );
    assert_eq!(response["resourceScopes"], json!({}));
    assert!(lookups.load(Ordering::SeqCst) > 0);
    // With only the token repository restriction changed, the same grant and
    // request authorize successfully and reach malformed file-part validation.
    let control = denied_upload(app, &allowed.token, "sip/service").await;
    assert_eq!(control.status(), StatusCode::BAD_REQUEST);
    let control = response_json(control).await;
    assert_eq!(control["reasonCode"], "input_invalid");
    assert_eq!(control["reason"], "multipart file part name is required");
    assert_eq!(uploads.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read_dir(temp.path().join("spool"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(&agent_access_core::upload_spool_file_prefix()))
            .count(),
        0
    );
    upstream.abort();
}
