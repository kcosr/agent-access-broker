//! Managed identities must retain token-class and revocation boundaries over MCP.
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ManagedResourceCatalog, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

async fn send(app: &Router, request: Request<Body>) -> axum::response::Response {
    tokio::time::timeout(Duration::from_secs(10), app.clone().oneshot(request))
        .await
        .expect("managed MCP HTTP request timed out")
        .unwrap()
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"managed-token-test","version":"1"}
    }})
}

#[tokio::test]
async fn managed_mcp_checks_token_class_and_revocation_on_existing_sessions() {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let hash_key = directory.path().join("token-hash-key");
    let upstream_token = directory.path().join("fake-upstream-token");
    let audit_path = directory.path().join("audit.jsonl");
    std::fs::write(&hash_key, URL_SAFE_NO_PAD.encode([71_u8; 32])).unwrap();
    std::fs::write(&upstream_token, "synthetic-managed-mcp-upstream").unwrap();
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".into(),
        authority: "managed".into(),
        sources: vec![IdentitySourceConfig {
            name: "broker".into(),
            kind: "broker_tokens".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let store_config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory
            .path()
            .join("managed.sqlite")
            .display()
            .to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    config.policy.grants[0].subjects = vec!["user:mcp-managed-user".into()];
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", upstream_token.display()));
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    let store = ManagedStore::open(&store_config, ManagedStoreOpenMode::Startup).unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "mcp-managed-user".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    // Even an administrator's valid management tokens must not become invoke tokens.
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("mcp-managed-user").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let catalog = ManagedResourceCatalog {
        attribute_bindings: Vec::new(),
        resources: config.policy.resources.clone(),
        resource_groups: config.policy.resource_groups.clone(),
    };
    let issue = |token_class: BrokerTokenClass| {
        let scopes = if token_class == BrokerTokenClass::AgentInvoke {
            json!({"allowedServices":["fake"],"allowedExecutionContexts":["default"]})
        } else {
            json!({})
        };
        store
            .issue_broker_token_with_catalog(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "mcp-managed-user".into(),
                    name: "managed MCP fixture".into(),
                    token_class,
                    scopes,
                    expires_at: None,
                    created_by: "test".into(),
                },
                Some(&catalog),
            )
            .unwrap()
    };
    let agent = issue(BrokerTokenClass::AgentInvoke);
    let management = [
        issue(BrokerTokenClass::UserManage),
        issue(BrokerTokenClass::Admin),
    ];
    let broker = TestBroker::start_config(&config).await;
    let runtime = broker.runtime();
    let app = broker.app();

    for token in &management {
        let headers = mcp::request(Method::POST, Some(&token.token), None, None)
            .headers()
            .clone();
        let identity = runtime.resolve_identity(&headers).unwrap();
        assert!(identity.authenticated, "management token itself is valid");
        assert_eq!(
            identity.source.unwrap().token_class,
            Some(token.record.token_class.clone())
        );
        let response = send(
            &app,
            mcp::request(Method::POST, Some(&token.token), None, Some(initialize())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("mcp-session-id").is_none());
    }

    let response = send(
        &app,
        mcp::request(Method::POST, Some(&agent.token), None, Some(initialize())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp::rpc_body(response).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    let response = send(
        &app,
        mcp::request(
            Method::POST,
            Some(&agent.token),
            Some(&session),
            Some(json!({
                "jsonrpc":"2.0","method":"notifications/initialized"
            })),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":agent_access_core::mcp::tool_name("fake","echo"),
        "arguments":{"inputs":{"project":"TEST","message":"managed token allowed"}}
    }});
    let response = send(
        &app,
        mcp::request(
            Method::POST,
            Some(&agent.token),
            Some(&session),
            Some(call.clone()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = mcp::rpc_body(response).await;
    assert_eq!(
        result["result"]["structuredContent"]["decision"], "allow",
        "{result}"
    );
    assert_ne!(result["result"]["isError"], true, "{result}");

    store
        .revoke_broker_token(&agent.record.token_id, "test")
        .unwrap();
    for message in [
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        call,
    ] {
        let response = send(
            &app,
            mcp::request(
                Method::POST,
                Some(&agent.token),
                Some(&session),
                Some(message),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "existing session must not cache authority"
        );
    }
    let records = std::fs::read_to_string(audit_path).unwrap();
    let provider_calls = records
        .lines()
        .filter(|line| {
            let value: Value = serde_json::from_str(line).unwrap();
            value["service"] == "fake" && value["action"] == "echo" && value["decision"] == "allow"
        })
        .count();
    assert_eq!(
        provider_calls, 1,
        "revocation must prevent a second provider call"
    );
}
