//! Real imported HTTP MCP providers use ordinary broker policy and credentials.
use super::*;
use agent_access_core::imports::{
    ImportedActionDefinition, ImportedCredentialBinding, ImportedCredentialDelivery,
    ImportedCredentialMode, ImportedCredentialPurpose, ImportedDiscoveryCredential,
    ImportedInvocationLimit, ImportedServiceDefinition,
};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    CredentialEncryptionConfig, CredentialEncryptionKeyConfig, ImportedActionStatus,
    ImportedActionWrite, ImportedSecretWriteRequest, ImportedServiceStatus,
    ImportedServiceUpdateRequest, ImportsConfig, ManagedPolicyGrantCreateRequest, ProvidersConfig,
};
use axum::{Json, extract::State, http::HeaderMap, routing::post};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
struct Upstream {
    requests: Arc<Mutex<Vec<(String, HeaderMap, Value)>>>,
    fail_calls: Arc<AtomicBool>,
    discovery_tools: Arc<Mutex<Option<Vec<Value>>>>,
}
async fn upstream(
    State(state): State<Upstream>,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Json<Value> {
    assert_eq!(
        headers["mcp-protocol-version"],
        agent_access_mcp_upstream::PROTOCOL_VERSION
    );
    assert_eq!(headers["mcp-method"], request["method"].as_str().unwrap());
    let method = request["method"].as_str().unwrap();
    let result = match method {
        "server/discover" => {
            json!({"supportedVersions":[agent_access_mcp_upstream::PROTOCOL_VERSION],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})
        }
        "tools/call" => {
            assert_eq!(
                headers["mcp-name"],
                request["params"]["name"].as_str().unwrap()
            );
            json!({"content":[{"type":"text","text":"synthetic-sensitive-upstream-body"}],"structuredContent":{"ok":true},"isError":state.fail_calls.load(Ordering::Relaxed)})
        }
        "tools/list" => json!({"tools": state.discovery_tools.lock().unwrap().as_ref()
            .expect("unexpected discovery during execution").clone()}),
        // Execution must use the accepted registry, never fetch a fresh tool catalog.
        _ => panic!("unexpected imported request: {method}"),
    };
    state
        .requests
        .lock()
        .unwrap()
        .push((uri.path().into(), headers, request.clone()));
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
}
struct Fixture {
    _directory: tempfile::TempDir,
    audit_path: PathBuf,
    runtime: BrokerRuntime,
    app: Router,
    tokens: BTreeMap<String, String>,
    upstream: Upstream,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
fn action(read_only: bool) -> ImportedActionDefinition {
    ImportedActionDefinition {
        action: if read_only { "inspect" } else { "update" }.into(),
        source: json!({"toolName":if read_only {"read_item"} else {"update_item"}}),
        label: None,
        description: "Synthetic imported action".into(),
        input_schema: json!({"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}),
        output_schema: Some(
            json!({"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}),
        ),
        annotations: json!({}),
        read_only,
    }
}
async fn fixture(limit: Option<u32>) -> Fixture {
    let upstream_state = Upstream::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let upstream_app = Router::new()
        .route("/{service}", post(upstream))
        .with_state(upstream_state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, upstream_app).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let audit_path = directory.path().join("audit.jsonl");
    let key = directory.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([72u8; 32])).unwrap();
    let hash = directory.path().join("hash");
    std::fs::write(&hash, URL_SAFE_NO_PAD.encode([73u8; 32])).unwrap();
    let mut config = context_aware_fake_config(audit_path.to_str().unwrap());
    config.providers = ProvidersConfig::new(Arc::new(crate::backend_registry()));
    config.credentials = CredentialsConfig::default();
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
    install_context_caller(&mut config);
    config.policy = PolicyConfig {
        authority: "managed".into(),
        default_decision: "deny".into(),
        grants: vec![],
        resources: vec![],
        resource_groups: vec![],
    };
    config.management.enabled = true;
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash.display()),
        ..Default::default()
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            env: None,
            path: Some(key.display().to_string()),
        }],
    });
    config.imports = ImportsConfig {
        enabled: true,
        allowed_kinds: vec!["mcp_http".into()],
        allowed_endpoints: vec![format!("{base}/one"), format!("{base}/two")],
        disabled_services: vec![],
    };
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    let store = initial.managed_store().unwrap();
    let ring = initial.credential_key_ring().unwrap();
    for principal in ["admin", "alice", "bob", "charlie"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    for service in ["one", "two"] {
        let definition = ImportedServiceDefinition {
            service: service.into(),
            display_name: format!("Imported {service}"),
            adapter_kind: "mcp_http".into(),
            endpoint: format!("{base}/{service}"),
            connection_settings: Default::default(),
            execution_bindings: vec![
                ImportedCredentialBinding::token(
                    ImportedCredentialMode::Service,
                    ImportedCredentialDelivery::Bearer,
                ),
                ImportedCredentialBinding::token(
                    ImportedCredentialMode::PerUser,
                    ImportedCredentialDelivery::Bearer,
                ),
            ],
            discovery: ImportedDiscoveryCredential::Execution,
            transport_auth: false,
            invocation_limit: limit.map(|requests| ImportedInvocationLimit {
                requests,
                window_seconds: 60,
            }),
        };
        let draft = store
            .create_imported_service(definition, "admin", |_| Ok(()))
            .unwrap()
            .catalog;
        let record = draft
            .services
            .iter()
            .find(|record| record.definition.service == service)
            .unwrap();
        let configured = store
            .write_imported_secret(
                ImportedSecretWriteRequest {
                    service: service.into(),
                    purpose: ImportedCredentialPurpose::Execution,
                    expected_version: record.version,
                    expected_catalog_revision: draft.revision,
                    token: format!("service-{service}-secret"),
                    actor: "admin".into(),
                },
                ring,
                |_, _| Ok(()),
            )
            .unwrap()
            .catalog;
        let record = configured
            .services
            .iter()
            .find(|record| record.definition.service == service)
            .unwrap();
        store
            .update_imported_service(
                ImportedServiceUpdateRequest {
                    definition: record.definition.clone(),
                    status: ImportedServiceStatus::Enabled,
                    actions: vec![true, false]
                        .into_iter()
                        .map(|read| ImportedActionWrite {
                            definition: action(read),
                            status: ImportedActionStatus::Enabled,
                        })
                        .collect(),
                    expected_version: record.version,
                    expected_catalog_revision: configured.revision,
                    accepted_preview: None,
                    actor: "admin".into(),
                },
                |_| Ok(()),
            )
            .unwrap();
        store
            .upsert_user_credential(
                ring,
                CredentialWriteRequest {
                    owner_principal_id: "bob".into(),
                    service: service.into(),
                    name: "default".into(),
                    profile: "token".into(),
                    credential_kind: "bearer_token".into(),
                    secret: json!({"token":format!("bob-{service}-secret")}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                agent_access_core::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
    }
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let tokens=["alice","bob","charlie"].into_iter().map(|principal|{
        let issued=store.issue_broker_token(&hasher,BrokerTokenIssueRequest{principal_id:principal.into(),name:"MCP fixture".into(),token_class:BrokerTokenClass::AgentInvoke,scopes:json!({"allowedServices":["one","two"],"allowedExecutionContexts":["internal","external"]}),expires_at:None,created_by:"admin".into()}).unwrap();
        (principal.into(),issued.token)
    }).collect();
    drop(initial);
    let runtime = BrokerRuntime::new(config).unwrap();
    for service in ["one", "two"] {
        for (principal, mode) in [
            ("alice", "service"),
            ("bob", "per_user"),
            ("charlie", "per_user"),
        ] {
            runtime
                .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                    grant_id: Some(format!("{service}-{principal}")),
                    subjects: vec![format!("user:{principal}")],
                    execution_contexts: vec!["internal".into()],
                    service: service.into(),
                    actions: if principal == "alice" {
                        vec!["inspect".into(), "update".into()]
                    } else {
                        vec!["inspect".into()]
                    },
                    resources: ResourceSelection::default(),
                    credential_mode: mode.into(),
                    priority: None,
                    status: None,
                    description: None,
                    created_by: "admin".into(),
                })
                .unwrap();
        }
    }
    assert!(
        upstream_state.requests.lock().unwrap().is_empty(),
        "startup must be offline"
    );
    Fixture {
        _directory: directory,
        audit_path,
        app: build_router(runtime.clone(), broker_build_status()),
        runtime,
        tokens,
        upstream: upstream_state,
        server,
    }
}
impl Fixture {
    async fn invoke(
        &self,
        principal: &str,
        service: &str,
        action: &str,
        context: &str,
        id: &str,
    ) -> (StatusCode, Value) {
        let response = authed_context_json_request(
            self.app.clone(),
            Method::POST,
            &format!("/v1/invoke/{service}/{action}"),
            id,
            &self.tokens[principal],
            context,
            Some(r#"{"inputs":{"message":"private-agent-input"}}"#),
        )
        .await;
        (response.status(), response_json(response).await)
    }
}

#[tokio::test]
async fn imports_mcp_credentials_policy_context_and_audit_use_real_host_boundary() {
    let fixture = fixture(None).await;
    for (principal, service, action) in [
        ("alice", "one", "inspect"),
        ("alice", "two", "update"),
        ("bob", "one", "inspect"),
        ("bob", "two", "inspect"),
    ] {
        let (status, body) = fixture
            .invoke(
                principal,
                service,
                action,
                "internal",
                &format!("mcp-{principal}-{service}"),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["upstreamMcp"]["structuredContent"]["ok"],
            true
        );
        if action == "update" {
            assert_eq!(body["result"]["mutationStatus"], "applied_unverified");
            assert_eq!(body["result"]["retrySafe"], false);
        }
    }
    let expected = [
        ("/one", "Bearer service-one-secret", "read_item"),
        ("/two", "Bearer service-two-secret", "update_item"),
        ("/one", "Bearer bob-one-secret", "read_item"),
        ("/two", "Bearer bob-two-secret", "read_item"),
    ];
    {
        let requests = fixture.upstream.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            8,
            "each call gets one discovery and one call; no retry/list"
        );
        for ((path, headers, request), (endpoint, token, tool)) in requests
            .iter()
            .filter(|(_, _, r)| r["method"] == "tools/call")
            .zip(expected)
        {
            assert_eq!(path, endpoint);
            assert_eq!(headers[AUTHORIZATION], token);
            assert_eq!(request["params"]["name"], tool);
        }
    }
    for (principal, action, context, id) in [
        ("bob", "update", "internal", "mcp-action-deny"),
        ("alice", "inspect", "external", "mcp-context-deny"),
        ("charlie", "inspect", "internal", "mcp-no-user-token"),
    ] {
        let (status, body) = fixture.invoke(principal, "one", action, context, id).await;
        assert!(!status.is_success(), "{body}");
        assert_eq!(
            fixture.upstream.requests.lock().unwrap().len(),
            8,
            "denied request must not reach upstream"
        );
    }
    fixture
        .runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = read_audit_records(&fixture.audit_path);
    let read = records
        .iter()
        .find(|r| r["agentRequestId"] == "mcp-bob-one")
        .unwrap();
    assert_eq!(read["principal"], "bob");
    assert_eq!(read["service"], "one");
    assert_eq!(read["executionContext"], "internal");
    assert_eq!(read["providerAudit"]["credentialMode"], "per_user");
    let write = records
        .iter()
        .find(|r| r["agentRequestId"] == "mcp-alice-two")
        .unwrap();
    assert_eq!(write["providerAudit"]["toolDispatched"], true);
    for id in ["mcp-action-deny", "mcp-context-deny", "mcp-no-user-token"] {
        let denied = records.iter().find(|r| r["agentRequestId"] == id).unwrap();
        assert_ne!(denied["decision"], "allow");
    }
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    for secret in [
        "service-one-secret",
        "service-two-secret",
        "bob-one-secret",
        "bob-two-secret",
        "synthetic-sensitive-upstream-body",
        "private-agent-input",
    ] {
        assert!(!audit.contains(secret), "audit leaked {secret}");
    }
}

#[tokio::test]
async fn imports_mcp_service_limit_rejects_before_upstream_dispatch() {
    let fixture = fixture(Some(1)).await;
    let (status, body) = fixture
        .invoke("alice", "one", "inspect", "internal", "mcp-rate-first")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fixture
        .invoke("alice", "one", "update", "internal", "mcp-rate-denied")
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reasonCode"], "rate_limited");
    assert_eq!(fixture.upstream.requests.lock().unwrap().len(), 2);
    // The other imported service has its own counter and token.
    let (status, body) = fixture
        .invoke("alice", "two", "inspect", "internal", "mcp-other-service")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    fixture
        .runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = read_audit_records(&fixture.audit_path);
    let limited = records
        .iter()
        .find(|r| r["agentRequestId"] == "mcp-rate-denied")
        .unwrap();
    assert_eq!(limited["reasonCode"], "rate_limited");
    assert_eq!(limited["principal"], "alice");
}

#[tokio::test]
async fn imports_mcp_audits_admitted_revisions_on_success_and_provider_error() {
    let fixture = fixture(None).await;
    for (action, id) in [("inspect", "revision-read"), ("update", "revision-write")] {
        let (status, body) = fixture.invoke("alice", "one", action, "internal", id).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    fixture.upstream.fail_calls.store(true, Ordering::Relaxed);
    let (status, body) = fixture
        .invoke("alice", "one", "update", "internal", "revision-error")
        .await;
    assert_eq!(status, StatusCode::FAILED_DEPENDENCY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_failed");
    assert_eq!(body["result"]["mutationStatus"], "unknown");
    assert_eq!(body["result"]["retrySafe"], false);
    assert_eq!(
        fixture.upstream.requests.lock().unwrap().len(),
        6,
        "the failed write must be dispatched exactly once"
    );
    fixture
        .runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = read_audit_records(&fixture.audit_path);
    let catalog = fixture.runtime.imported_catalog();
    let service = catalog.service("one").unwrap();
    for (action, id) in [
        ("inspect", "revision-read"),
        ("update", "revision-write"),
        ("update", "revision-error"),
    ] {
        let record = records.iter().find(|r| r["agentRequestId"] == id).unwrap();
        let action_version = service
            .actions
            .iter()
            .find(|r| r.definition.action == action)
            .unwrap()
            .version;
        assert_eq!(
            record["providerAudit"]["importedService"],
            json!({"catalogRevision":catalog.revision,"serviceVersion":service.version,"actionVersion":action_version})
        );
        assert_eq!(record["providerAudit"]["adapterKind"], "mcp_http");
        assert_eq!(record["providerAudit"]["toolDispatched"], true);
    }
    let error = records
        .iter()
        .find(|r| r["agentRequestId"] == "revision-error")
        .unwrap();
    assert_eq!(error["reasonCode"], "upstream_failed");
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    for private in [
        "service-one-secret",
        "synthetic-sensitive-upstream-body",
        "private-agent-input",
    ] {
        assert!(!audit.contains(private), "audit leaked {private}");
    }
}

#[tokio::test]
async fn scoped_mcp_admin_warnings_do_not_block_aggregate_and_follow_publication() {
    use sha2::{Digest, Sha256};
    let fixture = fixture(None).await;
    let admin = fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            &BrokerTokenHasher::load(fixture.runtime.config().broker_tokens.as_ref().unwrap())
                .unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "Scoped MCP administration".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    async fn management(
        app: &Router,
        token: &str,
        method: Method,
        suffix: &str,
        body: Option<Value>,
    ) -> Value {
        let serialized = body.map(|value| value.to_string());
        let response = authed_json_request(
            app.clone(),
            method,
            &format!("/v1/admin/imports/one{suffix}"),
            "scoped-admin",
            "Authorization",
            format!("Bearer {token}"),
            serialized.as_deref(),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["result"].clone()
    }
    fn versions(value: &Value) -> Value {
        json!({"expectedVersion":value["service"]["version"],"expectedCatalogRevision":value["catalogRevision"]})
    }
    let tools: Vec<_> = ["read_item", "update_item", "bad/name", "resources_list"].into_iter().map(|name| {
        json!({"name":name,"description":"Synthetic action","inputSchema":action(true).input_schema,"outputSchema":action(true).output_schema})
    }).collect();
    *fixture.upstream.discovery_tools.lock().unwrap() = Some(tools.clone());
    let initial = management(&fixture.app, &admin, Method::GET, "", None).await;
    assert_eq!(initial["scopedMcp"]["ready"], true);
    let preview = management(
        &fixture.app,
        &admin,
        Method::POST,
        "/discover",
        Some(versions(&initial)),
    )
    .await;
    assert_eq!(preview["scopedMcpWarnings"].as_array().unwrap().len(), 2);
    assert_eq!(
        preview["scopedMcpWarnings"][0]["codes"],
        json!(["invalid_name"])
    );
    assert_eq!(
        preview["scopedMcpWarnings"][1]["codes"],
        json!(["reserved_name"])
    );
    assert!(
        preview["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["unsupportedReason"].is_null())
    );
    assert_eq!(
        preview["preview"]["manifestHash"],
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&preview["preview"]["manifest"]).unwrap())
        )
    );
    assert!(
        preview["preview"]["manifest"]
            .get("scopedMcpWarnings")
            .is_none()
    );
    let mut accept = versions(&preview);
    accept["manifestHash"] = preview["preview"]["manifestHash"].clone();
    accept["confirmAffectedGrants"] = json!(true);
    accept["selections"] = json!([
        {"source":{"toolName":"read_item"},"action":"inspect","readOnly":true},
        {"source":{"toolName":"update_item"},"action":"update","readOnly":false},
        {"source":{"toolName":"bad/name"},"action":"bad.name","readOnly":true},
        {"source":{"toolName":"resources_list"},"action":"reserved","readOnly":true},
    ]);
    let accepted = management(&fixture.app, &admin, Method::POST, "/accept", Some(accept)).await;
    assert_eq!(accepted["scopedMcp"]["ready"], false);
    assert_eq!(accepted["service"]["actions"].as_array().unwrap().len(), 4);
    assert!(!accepted["scopedMcp"].to_string().contains("bad/name"));
    let response = authed_context_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/spec/catalog",
        "scoped-hidden",
        &fixture.tokens["bob"],
        "internal",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let catalog = response_json(response).await;
    let one = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "one")
        .unwrap();
    assert_eq!(one["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        one["scopedMcpReady"], false,
        "hidden invalid actions must affect all callers"
    );
    assert!(one.get("scopedMcp").is_none());
    assert_eq!(
        fixture
            .invoke("bob", "one", "inspect", "internal", "aggregate-still-works")
            .await
            .0,
        StatusCode::OK
    );
    let mut current = accepted;
    for (action, status, ready) in [
        ("bad.name", "disabled", false),
        ("reserved", "retired", true),
        ("bad.name", "enabled", false),
    ] {
        let mut body = versions(&current);
        body["status"] = json!(status);
        body["confirm"] = json!(true);
        current = management(
            &fixture.app,
            &admin,
            Method::POST,
            &format!("/actions/{action}/status"),
            Some(body),
        )
        .await;
        assert_eq!(current["scopedMcp"]["ready"], ready);
    }
    *fixture.upstream.discovery_tools.lock().unwrap() = Some(tools[..2].to_vec());
    let refreshed = management(
        &fixture.app,
        &admin,
        Method::POST,
        "/discover",
        Some(versions(&current)),
    )
    .await;
    assert_eq!(
        refreshed["scopedMcp"]["ready"], true,
        "quarantined and retired names do not participate"
    );
    assert_eq!(refreshed["scopedMcpWarnings"], json!([]));
    let readback = management(&fixture.app, &admin, Method::GET, "/preview", None).await;
    assert_eq!(readback["scopedMcp"], refreshed["scopedMcp"]);
    assert_eq!(readback["scopedMcpWarnings"], json!([]));
}

#[path = "imports_mcp/scoped.rs"]
mod scoped;
