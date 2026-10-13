use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    CredentialEncryptionConfig, CredentialEncryptionKeyConfig, ManagedStore, ManagedStoreConfig,
    TrustedCallerConfig, TrustedCallerContextMode,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

struct Fixture {
    runtime: BrokerRuntime,
    _dir: tempfile::TempDir,
    app: Router,
    store: ManagedStore,
    hash: String,
    admin_token: String,
    agent_token: String,
}
fn fixture() -> Fixture {
    fixture_with_config(|_| {})
}

fn fixture_with_config(configure: impl FnOnce(&mut BrokerConfig)) -> Fixture {
    let dir = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = dir.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([9u8; 32])).unwrap();
    let proxy = dir.path().join("proxy");
    std::fs::write(&proxy, "trusted-proxy-credential-0123456789").unwrap();
    let mut config = fake_config("");
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.trusted_callers.insert(
        "identity_ingress".into(),
        TrustedCallerConfig {
            credential_transport: Default::default(),
            username_namespace: None,
            credential_ref: format!("file:{}", proxy.display()),
            context_mode: TrustedCallerContextMode::Fixed,
            execution_context: Some("default".into()),
            allowed_execution_contexts: None,
            allow_forwarded_identity: true,
        },
    );
    config.identity.sources = vec![IdentitySourceConfig {
        name: "tokens".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: dir.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            path: Some(key.display().to_string()),
            env: None,
        }],
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    });
    config.management.enabled = true;
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    config.policy.grants.clear();
    configure(&mut config);
    // Managed grant subjects must exist before the final runtime validates them.
    let mut bootstrap_config = config.clone();
    bootstrap_config.policy.grants.clear();
    let runtime = BrokerRuntime::new(bootstrap_config).unwrap();
    let store = runtime.managed_store().unwrap().clone();
    for principal in ["alice", "admin"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
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
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let raw = store
        .reveal_identity_token("alice", runtime.credential_key_ring().unwrap())
        .unwrap();
    let hash = format!("sha256:{:x}", Sha256::digest(raw.as_bytes()));
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let admin_token = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "admin".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    let contexts = config.execution_context.as_ref().map_or_else(
        || vec!["default".to_owned()],
        |context| context.allowed_values.clone(),
    );
    let agent_token = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "invocation".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": contexts, "allowedServices": ["fake", "gitlab_git"]}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token;
    Fixture {
        _dir: dir,
        app: build_router(runtime.clone()),
        runtime,
        store,
        hash,
        admin_token,
        agent_token,
    }
}
async fn request(
    f: &Fixture,
    path: &str,
    method: Method,
    proxy: Option<&str>,
    hash: Option<&str>,
    authorization: Option<&str>,
    body: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, "managed-identity-test");
    if let Some(p) = proxy {
        builder = builder.header("x-agent-access-caller-authorization", p);
    }
    if let Some(h) = hash {
        builder = builder.header("x-aw-identity-token-sha256", h);
    }
    if let Some(a) = authorization {
        builder = builder.header(AUTHORIZATION, a);
    }
    let body = if let Some(b) = body {
        builder = builder.header(CONTENT_TYPE, "application/json");
        Body::from(b.to_string())
    } else {
        Body::empty()
    };
    f.app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}
const PROXY: &str = "Bearer trusted-proxy-credential-0123456789";
#[tokio::test]
async fn managed_identity_ingress_rejects_spoofing_and_management_escalation() {
    let f = fixture();
    for p in [None, Some("Bearer wrong")] {
        assert_eq!(
            request(&f, "/v1/me", Method::GET, p, Some(&f.hash), None, None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let me = request(
        &f,
        "/v1/me",
        Method::GET,
        Some(PROXY),
        Some(&f.hash),
        None,
        None,
    )
    .await;
    assert_eq!(me.status(), StatusCode::OK);
    assert!(response_json(me).await.to_string().contains("alice"));
    // Even a real administrator's managed identity is invocation-only.
    f.store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("alice").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    for path in ["/v1/admin/principals", "/v1/tokens", "/v1/credentials"] {
        assert_eq!(
            request(
                &f,
                path,
                Method::GET,
                Some(PROXY),
                Some(&f.hash),
                None,
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(
            &f,
            "/v1/me",
            Method::GET,
            Some(PROXY),
            Some(&f.hash),
            Some("Bearer invalid"),
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    for hash in [
        "sha256:abc".to_string(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "0".repeat(64)),
    ] {
        assert_eq!(
            request(
                &f,
                "/v1/me",
                Method::GET,
                Some(PROXY),
                Some(&hash),
                None,
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
#[tokio::test]
async fn managed_identity_pause_and_remove_are_live_and_explicit_token_remains_authoritative() {
    let f = fixture();
    f.store
        .set_identity_access_paused(
            "alice",
            true,
            f.store.identity_access("alice").unwrap().version,
            "test",
        )
        .unwrap();
    assert_eq!(
        request(
            &f,
            "/v1/me",
            Method::GET,
            Some(PROXY),
            Some(&f.hash),
            None,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let auth = format!("Bearer {}", f.admin_token);
    assert_eq!(
        request(
            &f,
            "/v1/admin/principals",
            Method::GET,
            Some(PROXY),
            Some(&f.hash),
            Some(&auth),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    f.store
        .set_identity_access_paused(
            "alice",
            false,
            f.store.identity_access("alice").unwrap().version,
            "test",
        )
        .unwrap();
    assert_eq!(
        request(
            &f,
            "/v1/me",
            Method::GET,
            Some(PROXY),
            Some(&f.hash),
            None,
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    f.store.remove_identity_token("alice").unwrap();
    assert_eq!(
        request(
            &f,
            "/v1/me",
            Method::GET,
            Some(PROXY),
            Some(&f.hash),
            None,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn managed_identity_admin_inventory_reveal_is_explicit_and_no_store() {
    let mut f = fixture();
    let audit_path = f._dir.path().join("inventory-audit.jsonl");
    let mut config = f.runtime.config().clone();
    config.audit = Some(agent_access_core::AuditConfig::new(
        agent_access_core::AuditStoreType::Jsonl,
        audit_path.display().to_string(),
    ));
    f.app = build_router(BrokerRuntime::new(config).unwrap());
    let auth = format!("Bearer {}", f.admin_token);
    let path = "/v1/admin/principals/alice/identity-token";
    let metadata = request(&f, path, Method::GET, Some(PROXY), None, Some(&auth), None).await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let body = response_json(metadata).await;
    assert!(body["result"].get("token").is_none());
    assert!(body["result"].get("fingerprint").is_none());
    let reveal = request(
        &f,
        &format!("{path}/reveal"),
        Method::POST,
        Some(PROXY),
        None,
        Some(&auth),
        None,
    )
    .await;
    assert_eq!(reveal.status(), StatusCode::OK);
    assert_eq!(reveal.headers()[CACHE_CONTROL], "no-store");
    let token = response_json(reveal).await["result"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(uuid::Uuid::parse_str(&token).unwrap().get_version_num(), 4);
    // The metadata read is unaudited; the plaintext reveal is audited
    // before decryption, and its record never holds the token.
    let records = read_audit_records(&audit_path);
    assert!(
        records
            .iter()
            .all(|record| record["action"] != "admin.principals.identity_token.inspect")
    );
    assert!(records.iter().any(|record| {
        record["action"] == "admin.principals.identity_token.reveal"
            && record["providerAudit"]["management"]["phase"] == "preflight"
            && record["callerId"] == "identity_ingress"
            && record["identitySource"]["type"] == "broker_tokens"
    }));
    assert!(
        !std::fs::read_to_string(&audit_path)
            .unwrap()
            .contains(&token)
    );
}

#[tokio::test]
async fn managed_identity_duplicate_headers_fail_closed() {
    let f = fixture();
    for name in [
        "x-agent-access-caller-authorization",
        "x-aw-identity-token-sha256",
    ] {
        let value = if name == "x-agent-access-caller-authorization" {
            PROXY
        } else {
            &f.hash
        };
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/me")
                    .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                    .header(REQUEST_ID_HEADER, "duplicate-identity")
                    .header("x-agent-access-caller-authorization", PROXY)
                    .header("x-aw-identity-token-sha256", &f.hash)
                    .header(name, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn managed_identity_http_mcp_authenticates_without_bearer_and_rechecks_pause() {
    for path in ["/mcp", "/mcp/fake"] {
        let f = fixture_with_config(|config| {
            config.policy.grants.push(PolicyGrantConfig {
                subjects: vec!["user:alice".into()],
                execution_contexts: None,
                service: "fake".into(),
                actions: vec!["echo".into()],
                resources: selected_resources(&[("project", &["TEST"])]),
                credential_mode: "service".into(),
                priority: None,
            });
        });
        let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"managed-identity-test","version":"1"}}});
        let make = |message: Value, session: Option<&str>| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(path)
                .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                .header("host", "broker.example.test")
                .header("accept", "application/json, text/event-stream")
                .header(CONTENT_TYPE, "application/json")
                .header("x-agent-access-caller-authorization", PROXY)
                .header("x-aw-identity-token-sha256", &f.hash);
            if let Some(session) = session {
                builder = builder
                    .header("mcp-session-id", session)
                    .header("mcp-protocol-version", "2025-11-25");
            }
            builder.body(Body::from(message.to_string())).unwrap()
        };
        let response = f.app.clone().oneshot(make(initialize, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            super::mcp::rpc_body(response).await["result"]["protocolVersion"],
            "2025-11-25"
        );
        let response = f
            .app
            .clone()
            .oneshot(make(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                Some(&session),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        f.store
            .set_identity_access_paused(
                "alice",
                true,
                f.store.identity_access("alice").unwrap().version,
                "test",
            )
            .unwrap();
        let response = f
            .app
            .clone()
            .oneshot(make(
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                Some(&session),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn managed_identity_queued_rotation_rejects_retired_runtime_generation() {
    let f = fixture();
    let ring = f.runtime.credential_key_ring().unwrap().clone();
    let original = f.store.reveal_identity_token("alice", &ring).unwrap();
    let snapshot = RuntimeSnapshot::new(
        1,
        "generation-one".into(),
        f.runtime.clone(),
        StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        std::sync::Arc::new(crate::backend_registry()),
        snapshot.clone(),
        f.runtime.max_http_body_bytes(),
        Duration::from_secs(1),
        Duration::from_secs(1),
        f.runtime.audit_registry(),
    ));
    let guard = state.policy_mutation_lock.lock().await;
    let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempted_write = attempted.clone();
    let queued = state.token_store_call_from_snapshot(snapshot, move |runtime| {
        attempted_write.store(true, Ordering::SeqCst);
        runtime.managed_store().unwrap().set_identity_token(
            "alice",
            &uuid::Uuid::new_v4().to_string(),
            runtime.credential_key_ring().unwrap(),
        )
    });
    tokio::pin!(queued);
    assert!(matches!(
        futures_util::poll!(&mut queued),
        std::task::Poll::Pending
    ));
    // Publish exactly while the mutation is queued, as a coordinated reload does.
    state.publish_snapshot(RuntimeSnapshot::new(
        2,
        "generation-two".into(),
        f.runtime.clone(),
        StateLockSet::empty(),
    ));
    drop(guard);
    assert!(matches!(
        queued.await,
        Err(agent_access_core::ManagedStoreError::VersionConflict)
    ));
    assert!(!attempted.load(Ordering::SeqCst));
    assert_eq!(
        f.store.reveal_identity_token("alice", &ring).unwrap(),
        original
    );
}

#[tokio::test]
async fn managed_identity_cancelled_waiter_keeps_reload_fence_until_write_finishes() {
    let f = fixture();
    let snapshot = RuntimeSnapshot::new(
        1,
        "generation-one".into(),
        f.runtime.clone(),
        StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        std::sync::Arc::new(crate::backend_registry()),
        snapshot.clone(),
        f.runtime.max_http_body_bytes(),
        Duration::from_secs(1),
        Duration::from_secs(1),
        f.runtime.audit_registry(),
    ));
    let (started, started_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let expected = uuid::Uuid::new_v4().to_string();
    let replacement = expected.clone();
    let owner = state.clone();
    let waiter = tokio::spawn(async move {
        owner
            .token_store_call_from_snapshot(snapshot, move |runtime| {
                let _ = started.send(());
                release_rx.recv().unwrap();
                runtime.managed_store().unwrap().set_identity_token(
                    "alice",
                    &replacement,
                    runtime.credential_key_ring().unwrap(),
                )
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(state.policy_mutation_lock.try_lock().is_err());
    release.send(()).unwrap();
    let guard = tokio::time::timeout(Duration::from_secs(2), state.policy_mutation_lock.lock())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .reveal_identity_token("alice", f.runtime.credential_key_ring().unwrap())
            .unwrap(),
        expected
    );
    drop(guard);
}

#[tokio::test(flavor = "current_thread")]
async fn trusted_caller_rejection_is_traced_correlated_and_audited_on_all_routes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing::instrument::WithSubscriber;
    struct RequestSpan(Arc<AtomicBool>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RequestSpan {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == "http.request" {
                self.0.store(true, Ordering::Relaxed);
            }
        }
    }
    let _capture_guard = event_capture_lock().await;
    let mut f = fixture();
    let audit_path = f._dir.path().join("proxy-audit.jsonl");
    let mut config = f.runtime.config().clone();
    config.audit = Some(agent_access_core::AuditConfig::new(
        agent_access_core::AuditStoreType::Jsonl,
        audit_path.display().to_string(),
    ));
    f.app = build_router(BrokerRuntime::new(config).unwrap());
    let traced = Arc::new(AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(RequestSpan(traced.clone()));
    let _registration_guard = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing_core::callsite::rebuild_interest_cache();
    for path in ["/v1/me", "/v1/healthz", "/ui", "/mcp"] {
        traced.store(false, Ordering::Relaxed);
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                    .header("x-agent-access-caller-authorization", "Bearer incorrect")
                    .header("x-aw-identity-token-sha256", &f.hash)
                    .header(EXECUTION_CONTEXT_HEADER, "forged-context")
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response_json(response).await;
        assert_eq!(body["reasonCode"], "caller_authentication_invalid");
        assert!(!body["agentRequestId"].as_str().unwrap().is_empty());
        assert!(!body["brokerRequestId"].as_str().unwrap().is_empty());
        assert!(traced.load(Ordering::Relaxed), "missing trace for {path}");
    }
    let records = read_audit_records(&audit_path);
    assert_eq!(records.len(), 4);
    for record in records {
        assert_eq!(record["principal"], "unknown");
        assert_eq!(record["groups"], json!([]));
        assert_eq!(record["action"], "caller.authenticate");
        assert_eq!(record["reasonCode"], "caller_authentication_invalid");
        assert!(!record.to_string().contains("forged-context"));
        assert!(!record.to_string().contains(&f.hash));
        assert!(!record.to_string().contains("incorrect"));
    }
}

#[tokio::test]
async fn trusted_caller_rejection_uses_existing_source_rate_guard() {
    let mut f = fixture();
    let mut config = f.runtime.config().clone();
    config.limits.auth_requests_per_source_per_minute = 1;
    f.app = build_router(BrokerRuntime::new(config).unwrap());
    let first = request(
        &f,
        "/v1/healthz",
        Method::GET,
        None,
        Some(&f.hash),
        None,
        None,
    )
    .await;
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(first).await["reasonCode"],
        "caller_authentication_required"
    );
    let second = request(&f, "/ui", Method::GET, None, Some(&f.hash), None, None).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(second).await["reasonCode"], "rate_limited");
}

#[tokio::test]
async fn trusted_caller_gateway_rejection_is_audited_and_rate_limited_without_challenge() {
    let dir = tempfile::TempDir::new().unwrap();
    let proxy = dir.path().join("proxy");
    std::fs::write(&proxy, "trusted-proxy-credential-0123456789").unwrap();
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.identity.trusted_callers.insert(
            "identity_ingress".into(),
            TrustedCallerConfig {
                credential_transport: Default::default(),
                username_namespace: None,
                credential_ref: format!("file:{}", proxy.display()),
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: true,
            },
        );
        config
            .gateways
            .get_mut("gitlab_git")
            .unwrap()
            .allow_forwarded_identity = true;
        config.limits.auth_requests_per_source_per_minute = 1;
    });
    for (id, status, reason) in [
        (
            "proxy-git-first",
            StatusCode::UNAUTHORIZED,
            "caller_authentication_required",
        ),
        (
            "proxy-git-second",
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        ),
    ] {
        let response = gateway_request(GatewayRequestSpec {
            app: fixture.app.clone(),
            method: Method::GET,
            uri: "/sip/service.git/info/refs?service=git-upload-pack"
                .parse()
                .unwrap(),
            host: Some("git.example.test"),
            request_id: Some(id),
            authorization: None,
            headers: &[(EXECUTION_CONTEXT_HEADER, "forged-context")],
            body: Body::empty(),
        })
        .await;
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[REASON_CODE_HEADER], reason);
        assert!(!response.headers()[BROKER_REQUEST_ID_HEADER].is_empty());
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    }
    let records = read_audit_records(&fixture.audit_path);
    assert!(
        records
            .iter()
            .any(|record| record["agentRequestId"] == "proxy-git-first"
                && record["principal"] == "unknown"
                && record["groups"] == json!([])
                && record["action"] == "caller.authenticate"
                && record["reasonCode"] == "caller_authentication_required")
    );
    assert!(
        records
            .iter()
            .any(|record| record["agentRequestId"] == "proxy-git-second"
                && record["reasonCode"] == "rate_limited")
    );
}

fn external_default(config: &mut BrokerConfig) {
    let caller = config
        .identity
        .trusted_callers
        .get_mut("identity_ingress")
        .unwrap();
    caller.context_mode = TrustedCallerContextMode::Asserted;
    caller.execution_context = None;
    caller.allowed_execution_contexts = Some(vec!["external".into(), "internal".into()]);
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["external".into(), "internal".into()],
        default_context: Some("external".into()),
    });
    config.policy.resources = fixture_resources(&["external", "internal"]);
}

type HandoffCase<'a> = (&'static str, Vec<(&'static str, &'a str)>, bool);

fn handoff_cases<'a>(authorization: &'a str, fingerprint: &'a str) -> Vec<HandoffCase<'a>> {
    let auth = ("authorization", authorization);
    let context = (EXECUTION_CONTEXT_HEADER, "internal");
    let proxy = ("x-agent-access-caller-authorization", PROXY);
    let fingerprint = ("x-aw-identity-token-sha256", fingerprint);
    vec![
        ("no credentials", vec![], false),
        ("direct ordinary token", vec![auth], true),
        (
            "context needs proxy even with token",
            vec![auth, context],
            false,
        ),
        ("fingerprint needs proxy", vec![fingerprint], false),
        (
            "wrong proxy credential alone",
            vec![("x-agent-access-caller-authorization", "Bearer wrong")],
            false,
        ),
        (
            "malformed proxy credential alone",
            vec![("x-agent-access-caller-authorization", "Basic wrong")],
            false,
        ),
        (
            "duplicate proxy credential alone",
            vec![proxy, proxy],
            false,
        ),
        (
            "valid proxy credential is not user identity",
            vec![proxy],
            false,
        ),
        (
            "ordinary token through proxy",
            vec![auth, proxy, context],
            true,
        ),
        (
            "managed identity through proxy",
            vec![proxy, fingerprint, context],
            true,
        ),
        (
            "asserted caller cannot use direct default context",
            vec![proxy, fingerprint],
            false,
        ),
        (
            "invalid explicit token never falls back",
            vec![
                ("authorization", "Bearer invalid"),
                proxy,
                fingerprint,
                context,
            ],
            false,
        ),
        (
            "invalid proxy cannot accompany ordinary token",
            vec![
                auth,
                ("x-agent-access-caller-authorization", "Bearer wrong"),
            ],
            false,
        ),
    ]
}

async fn handoff_request(
    app: Router,
    path: &str,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mcp = path == "/mcp" || path.starts_with("/mcp/");
    let mut request = Request::builder()
        .method(if mcp { Method::POST } else { Method::GET })
        .uri(path)
        .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
        .header(REQUEST_ID_HEADER, "handoff-test")
        .header("host", "broker.example.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = if mcp {
        request = request
            .header("accept", "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json");
        Body::from(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"handoff-test","version":"1"}}}).to_string())
    } else {
        Body::empty()
    };
    app.oneshot(request.body(body).unwrap()).await.unwrap()
}

#[tokio::test]
async fn trusted_caller_http_and_mcp_handoff_matrix_preserves_direct_token_access() {
    let f = fixture_with_config(|config| {
        external_default(config);
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:alice".into()],
            execution_contexts: Some(vec!["internal".into(), "external".into()]),
            service: "fake".into(),
            actions: vec!["echo".into()],
            resources: selected_resources(&[("project", &["TEST"])]),
            credential_mode: "service".into(),
            priority: None,
        });
    });
    let authorization = format!("Bearer {}", f.agent_token);
    for path in ["/v1/capabilities", "/mcp", "/mcp/fake"] {
        for (case, headers, authenticated) in handoff_cases(&authorization, &f.hash) {
            let response = handoff_request(f.app.clone(), path, &headers).await;
            let expected = if authenticated {
                StatusCode::OK
            } else if headers.iter().any(|(name, value)| {
                *name == "x-agent-access-caller-authorization" && *value == PROXY
            }) && !headers
                .iter()
                .any(|(name, _)| *name == EXECUTION_CONTEXT_HEADER)
                && !case.starts_with("duplicate")
            {
                if path.starts_with("/mcp") {
                    if case == "valid proxy credential is not user identity" {
                        StatusCode::UNAUTHORIZED
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                } else {
                    StatusCode::FORBIDDEN
                }
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(response.status(), expected, "{path}: {case}");
            if authenticated && path.starts_with("/mcp") {
                assert!(response.headers().contains_key("mcp-session-id"), "{case}");
            }
        }
    }
}

#[tokio::test]
async fn trusted_caller_health_accepts_direct_requests_but_checks_any_proxy_credential() {
    let f = fixture();
    for headers in [vec![], vec![("x-agent-access-caller-authorization", PROXY)]] {
        let response = handoff_request(f.app.clone(), "/v1/healthz", &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Header presence, including empty and duplicate values, invokes the trust check.
    for headers in [
        vec![("x-agent-access-caller-authorization", "")],
        vec![("x-agent-access-caller-authorization", "Bearer wrong")],
        vec![
            ("x-agent-access-caller-authorization", PROXY),
            ("x-agent-access-caller-authorization", PROXY),
        ],
        vec![("x-aw-identity-token-sha256", "")],
        vec![(EXECUTION_CONTEXT_HEADER, "")],
    ] {
        let response = handoff_request(f.app.clone(), "/v1/healthz", &headers).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn trusted_caller_direct_default_is_conservative_and_absent_default_fails_closed() {
    let mut f = fixture_with_config(|config| {
        external_default(config);
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:alice".into()],
            execution_contexts: Some(vec!["internal".into()]),
            service: "fake".into(),
            actions: vec!["echo".into()],
            resources: selected_resources(&[("project", &["TEST"])]),
            credential_mode: "service".into(),
            priority: None,
        });
    });
    let authorization = format!("Bearer {}", f.agent_token);
    for (headers, sees_internal_service) in [
        (vec![("authorization", authorization.as_str())], false),
        (
            vec![
                ("authorization", authorization.as_str()),
                ("x-agent-access-caller-authorization", PROXY),
                (EXECUTION_CONTEXT_HEADER, "internal"),
            ],
            true,
        ),
    ] {
        let response = handoff_request(f.app.clone(), "/v1/capabilities", &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(
            body["services"]
                .as_array()
                .unwrap()
                .iter()
                .any(|service| service["service"] == "fake"),
            sees_internal_service
        );
        let scoped = handoff_request(f.app.clone(), "/mcp/fake", &headers).await;
        assert_eq!(
            scoped.status(),
            if sees_internal_service {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        );
    }
    let mut config = f.runtime.config().clone();
    config.execution_context.as_mut().unwrap().default_context = None;
    f.app = build_router(BrokerRuntime::new(config).unwrap());
    for (path, status) in [
        ("/v1/capabilities", StatusCode::FORBIDDEN),
        ("/mcp", StatusCode::BAD_REQUEST),
        ("/mcp/fake", StatusCode::BAD_REQUEST),
    ] {
        for headers in [
            vec![("authorization", authorization.as_str())],
            vec![
                ("x-agent-access-caller-authorization", PROXY),
                ("x-aw-identity-token-sha256", f.hash.as_str()),
            ],
        ] {
            let response = handoff_request(f.app.clone(), path, &headers).await;
            assert_eq!(response.status(), status, "{path}");
        }
    }
}

#[tokio::test]
async fn trusted_caller_browser_login_and_session_work_without_proxy_headers() {
    let dir = tempfile::tempdir().unwrap();
    let csrf = dir.path().join("csrf");
    let pepper = dir.path().join("pepper");
    std::fs::write(&csrf, URL_SAFE_NO_PAD.encode([18_u8; 32])).unwrap();
    std::fs::write(&pepper, URL_SAFE_NO_PAD.encode([19_u8; 32])).unwrap();
    let f = fixture_with_config(|config| {
        external_default(config);
        config.browser_auth = agent_access_core::BrowserAuthConfig {
            enabled: true,
            public_origin: Some("http://localhost".into()),
            csrf_key_ref: Some(format!("file:{}", csrf.display())),
            local_password: agent_access_core::LocalPasswordConfig {
                enabled: true,
                pepper_ref: Some(format!("file:{}", pepper.display())),
                min_password_length: 8,
                ..Default::default()
            },
            ..Default::default()
        };
    });
    f.store
        .enable_local_password(
            f.runtime.local_password_hasher().unwrap(),
            agent_access_core::LocalPasswordWriteRequest {
                principal_id: "alice".into(),
                password: "alice-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "admin".into(),
            },
        )
        .unwrap();
    let login = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                .header("host", "localhost")
                .header("origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"principalId":"alice","password":"alice-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    for path in ["/v1/auth/session", "/v1/me", "/v1/tokens"] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
                    .header(REQUEST_ID_HEADER, "browser-handoff-test")
                    .header("host", "localhost")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

fn managed_git_fixture(token_free: bool, default_context: bool) -> Fixture {
    let mut f = fixture_with_config(|config| {
        external_default(config);
        if !default_context {
            config.execution_context.as_mut().unwrap().default_context = None;
        }
        let mut gateway = test_git_gateway_config();
        gateway.allow_forwarded_identity = token_free;
        config.gateways.insert("gitlab_git".into(), gateway);
        let upstream_token = PathBuf::from(&config.managed_store.as_ref().unwrap().path)
            .with_file_name("git-upstream-token");
        std::fs::write(&upstream_token, "synthetic-git-upstream-token").unwrap();
        config.credentials.service.insert(
            "gitlab_git".into(),
            CredentialConfig {
                kind: "bearer_token".into(),
                token_ref: Some(format!("file:{}", upstream_token.display())),
                username_ref: None,
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:alice".into()],
            execution_contexts: Some(vec!["external".into(), "internal".into()]),
            service: "gitlab_git".into(),
            actions: vec!["repo.fetch".into()],
            resources: selected_resources(&[("repository", &["sip/service"])]),
            credential_mode: "service".into(),
            priority: None,
        });
    });
    let runtime = f.runtime.clone();
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        std::sync::Arc::new(crate::backend_registry()),
        RuntimeSnapshot::new(
            1,
            "managed-git-handoff".into(),
            runtime.clone(),
            StateLockSet::empty(),
        ),
        runtime.max_http_body_bytes(),
        Duration::from_secs(30),
        Duration::from_secs(30),
        runtime.audit_registry(),
    ));
    f.app = build_gateway_router(state);
    f
}

async fn git_handoff(f: &Fixture, headers: &[(&str, &str)]) -> axum::response::Response {
    gateway_request(GatewayRequestSpec {
        app: f.app.clone(),
        method: Method::GET,
        uri: "/sip/service.git/info/refs?service=git-upload-pack"
            .parse()
            .unwrap(),
        host: Some("git.example.test"),
        request_id: Some("git-handoff"),
        authorization: None,
        headers,
        body: Body::empty(),
    })
    .await
}

#[tokio::test]
async fn trusted_caller_git_handoff_matrix_preserves_basic_and_managed_identity() {
    let f = managed_git_fixture(true, true);
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", f.agent_token))
    );
    for (case, headers, authenticated) in handoff_cases(&basic, &f.hash) {
        let response = git_handoff(&f, &headers).await;
        // The fixture deliberately blocks its upstream. This proves successful
        // authentication and grant evaluation without making a network request.
        let expected = if authenticated {
            StatusCode::BAD_GATEWAY
        } else if headers
            .iter()
            .any(|(name, value)| *name == "x-agent-access-caller-authorization" && *value == PROXY)
            && !headers
                .iter()
                .any(|(name, _)| *name == EXECUTION_CONTEXT_HEADER)
            && !case.starts_with("duplicate")
        {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(
            response.status(),
            expected,
            "{case}: {:?}",
            response.headers()
        );
        if authenticated {
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                ReasonCode::GatewayUpstreamDenied.as_str(),
                "{case}"
            );
        }
    }
}

#[tokio::test]
async fn trusted_caller_git_opt_out_still_protects_context_and_proxy_headers() {
    let f = managed_git_fixture(false, true);
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", f.agent_token))
    );
    for headers in [
        vec![
            ("authorization", basic.as_str()),
            (EXECUTION_CONTEXT_HEADER, "internal"),
        ],
        vec![
            ("authorization", basic.as_str()),
            ("x-aw-identity-token-sha256", f.hash.as_str()),
        ],
        vec![
            ("authorization", basic.as_str()),
            ("x-agent-access-caller-authorization", "Bearer wrong"),
        ],
        vec![
            ("x-agent-access-caller-authorization", PROXY),
            ("x-aw-identity-token-sha256", f.hash.as_str()),
            (EXECUTION_CONTEXT_HEADER, "internal"),
        ],
    ] {
        assert_eq!(
            git_handoff(&f, &headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for headers in [
        vec![("authorization", basic.as_str())],
        vec![
            ("authorization", basic.as_str()),
            ("x-agent-access-caller-authorization", PROXY),
            (EXECUTION_CONTEXT_HEADER, "internal"),
        ],
    ] {
        let response = git_handoff(&f, &headers).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "{:?}",
            response.headers()
        );
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            ReasonCode::GatewayUpstreamDenied.as_str()
        );
    }
}

#[tokio::test]
async fn trusted_caller_git_without_default_context_does_not_invent_one() {
    let f = managed_git_fixture(true, false);
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", f.agent_token))
    );
    for headers in [
        vec![("authorization", basic.as_str())],
        vec![
            ("x-agent-access-caller-authorization", PROXY),
            ("x-aw-identity-token-sha256", f.hash.as_str()),
        ],
    ] {
        let response = git_handoff(&f, &headers).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "execution_context_required"
        );
    }
}

#[tokio::test]
async fn trusted_dispatch_caller_enforces_assertions_without_granting_identity() {
    let f = fixture_with_config(|config| {
        external_default(config);
        config
            .identity
            .trusted_callers
            .get_mut("identity_ingress")
            .unwrap()
            .allow_forwarded_identity = false;
        config
            .identity
            .trusted_callers
            .get_mut("identity_ingress")
            .unwrap()
            .allowed_execution_contexts = Some(vec!["external".into()]);
    });
    let token = format!("Bearer {}", f.agent_token);
    let caller = ("x-agent-access-caller-authorization", PROXY);
    let auth = ("authorization", token.as_str());
    for (headers, status, reason) in [
        (
            vec![caller, auth],
            StatusCode::FORBIDDEN,
            "execution_context_required",
        ),
        (
            vec![caller, auth, (EXECUTION_CONTEXT_HEADER, "internal")],
            StatusCode::FORBIDDEN,
            "execution_context_denied",
        ),
        (
            vec![caller, auth, (EXECUTION_CONTEXT_HEADER, "External")],
            StatusCode::FORBIDDEN,
            "execution_context_invalid",
        ),
        (
            vec![
                caller,
                auth,
                (EXECUTION_CONTEXT_HEADER, "external"),
                ("x-aw-identity-token-sha256", f.hash.as_str()),
            ],
            StatusCode::FORBIDDEN,
            "caller_identity_forwarding_denied",
        ),
        (
            vec![caller, (EXECUTION_CONTEXT_HEADER, "external")],
            StatusCode::UNAUTHORIZED,
            "identity_required",
        ),
    ] {
        let response = handoff_request(f.app.clone(), "/v1/capabilities", &headers).await;
        assert_eq!(response.status(), status);
        let body = response_json(response).await;
        assert_eq!(body["service"], "broker");
        assert_eq!(body["reasonCode"], reason);
        assert_eq!(body["decision"], "deny");
        assert_eq!(body["agentRequestId"], "handoff-test");
        assert_eq!(body["resourceScopes"], json!({}));
        assert!(body.get("result").is_none_or(Value::is_null));
    }
    let response = handoff_request(
        f.app.clone(),
        "/v1/capabilities",
        &[caller, auth, (EXECUTION_CONTEXT_HEADER, "external")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // Assertions must be validated even on health and non-governed identity routes.
    for path in ["/v1/healthz", "/v1/me", "/v1/admin/principals"] {
        let response = handoff_request(
            f.app.clone(),
            path,
            &[caller, auth, (EXECUTION_CONTEXT_HEADER, "internal")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn fixed_caller_rejects_even_matching_context_assertions() {
    let f = fixture();
    let authorization = format!("Bearer {}", f.agent_token);
    for path in ["/v1/healthz", "/v1/me", "/v1/capabilities", "/mcp"] {
        let response = handoff_request(
            f.app.clone(),
            path,
            &[
                ("x-agent-access-caller-authorization", PROXY),
                ("authorization", authorization.as_str()),
                (EXECUTION_CONTEXT_HEADER, "default"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        let body = response_json(response).await;
        assert_eq!(body["reasonCode"], "execution_context_invalid");
    }
}

#[tokio::test]
async fn trusted_caller_git_capabilities_apply_even_with_valid_basic_identity() {
    let mut f = managed_git_fixture(true, true);
    let mut config = f.runtime.config().clone();
    let mut dispatch = config.identity.trusted_callers["identity_ingress"].clone();
    dispatch.allow_forwarded_identity = false;
    dispatch.allowed_execution_contexts = Some(vec!["external".into()]);
    let secret_path = f._dir.path().join("dispatch");
    std::fs::write(&secret_path, "dispatch-git-secret-0123456789").unwrap();
    dispatch.credential_ref = format!("file:{}", secret_path.display());
    config
        .identity
        .trusted_callers
        .insert("agent_dispatch".into(), dispatch);
    let runtime = BrokerRuntime::new(config).unwrap();
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        Arc::new(crate::backend_registry()),
        RuntimeSnapshot::new(
            1,
            "git-caller-capabilities".into(),
            runtime.clone(),
            StateLockSet::empty(),
        ),
        runtime.max_http_body_bytes(),
        Duration::from_secs(30),
        Duration::from_secs(30),
        runtime.audit_registry(),
    ));
    f.app = build_gateway_router(state);
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", f.agent_token))
    );
    let auth = ("authorization", basic.as_str());
    let caller = (
        "x-agent-access-caller-authorization",
        "Bearer dispatch-git-secret-0123456789",
    );
    for (headers, reason) in [
        (
            vec![auth, caller, (EXECUTION_CONTEXT_HEADER, "internal")],
            "execution_context_denied",
        ),
        (
            vec![
                auth,
                caller,
                (EXECUTION_CONTEXT_HEADER, "external"),
                ("x-aw-identity-token-sha256", f.hash.as_str()),
            ],
            "caller_identity_forwarding_denied",
        ),
    ] {
        let response = git_handoff(&f, &headers).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[REASON_CODE_HEADER], reason);
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    }
    let response = git_handoff(&f, &[auth, caller, (EXECUTION_CONTEXT_HEADER, "external")]).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayUpstreamDenied.as_str()
    );
}
