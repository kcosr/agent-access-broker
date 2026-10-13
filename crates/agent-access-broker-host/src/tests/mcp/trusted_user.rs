//! HTTP MCP sessions bind the admitted human, gate, mapping, and caller epoch.
use super::*;
use agent_access_core::{
    BrokerTokensConfig, CredentialKeyRing, ManagedStore, ManagedStoreConfig, PrincipalRole,
    TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport,
};
use axum::http::HeaderMap;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};

const DIRECT: &str = "trusted-user-direct-secret-0123456789";
const RELAY: &str = "trusted-user-relay-secret-0123456789";
const USER: &str = "x-agent-access-user";
const CALLER: &str = "x-agent-access-caller-authorization";

struct ReleaseBlockingOnDrop(Arc<crate::state::McpBlockingBarrier>);
impl Drop for ReleaseBlockingOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct UserProvider {
    executions: AtomicUsize,
    writes: AtomicUsize,
    write_mode: std::sync::atomic::AtomicBool,
    block: std::sync::atomic::AtomicBool,
    pause_before_dispatch: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}
impl UserProvider {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            executions: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            write_mode: std::sync::atomic::AtomicBool::new(true),
            block: std::sync::atomic::AtomicBool::new(false),
            pause_before_dispatch: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        })
    }
}
impl agent_access_provider::test_support::DescribedProvider for UserProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.actions[0].read_only = !self.write_mode.load(Ordering::SeqCst);
        descriptor
    }
}
#[async_trait::async_trait]
impl Provider for UserProvider {
    fn resolve_scopes(
        &self,
        _action: &str,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        agent_access_fake::FakeProvider.resolve_scopes("echo", inputs)
    }
    async fn resolve_scopes_with_lookup(
        &self,
        action: &str,
        inputs: &Value,
        _credential: Option<&agent_access_provider::ExecutionCredential>,
    ) -> Result<ResourceScopes, ProviderError> {
        if self.pause_before_dispatch.load(Ordering::SeqCst) {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        self.resolve_scopes(action, inputs)
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        if self.write_mode.load(Ordering::SeqCst) {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        if self.block.load(Ordering::SeqCst) {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

fn fixture(max_sessions: usize) -> (Fixture, ManagedStore, Arc<UserProvider>) {
    let fixture = Fixture::new(|config| {
        let directory = PathBuf::from(&config.limits.upload_spool_dir);
        let directory = directory.parent().unwrap();
        config.identity.authority = "managed".into();
        config.identity.sources = vec![IdentitySourceConfig {
            name: "broker".into(),
            kind: "broker_tokens".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        }];
        config.managed_store = Some(ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("managed.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: true,
        });
        config.broker_tokens = Some(BrokerTokensConfig {
            hash_key_ref: format!(
                "file:{}",
                config.credential_encryption.as_ref().unwrap().keys[0]
                    .path
                    .as_ref()
                    .unwrap()
            ),
            ..Default::default()
        });
        for (name, secret, transport) in [
            (
                "direct",
                DIRECT,
                TrustedCallerCredentialTransport::AuthorizationUser,
            ),
            (
                "relay",
                RELAY,
                TrustedCallerCredentialTransport::CallerAuthorization,
            ),
        ] {
            let path = directory.join(name);
            std::fs::write(&path, secret).unwrap();
            config.identity.trusted_callers.insert(
                name.into(),
                TrustedCallerConfig {
                    credential_ref: format!("file:{}", path.display()),
                    credential_transport: transport,
                    username_namespace: Some("linux".into()),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: name == "relay",
                },
            );
        }
        config.mcp.max_sessions = max_sessions;
        config.mcp.max_sessions_per_principal = max_sessions;
        config.policy.grants[0].subjects = vec!["user:alice".into(), "user:bob".into()];
        let mut bootstrap = config.clone();
        bootstrap.policy.grants.clear();
        let runtime = BrokerRuntime::new(bootstrap).unwrap();
        let store = runtime.managed_store().unwrap();
        for principal in ["alice", "bob"] {
            store
                .create_principal(PrincipalWriteRequest {
                    principal_id: principal.into(),
                    kind: "user".into(),
                    role: PrincipalRole::User,
                    self_service_enabled: None,
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "fixture".into(),
                })
                .unwrap();
            store
                .create_username_binding(principal, "linux", principal, "fixture")
                .unwrap();
        }
    });
    let provider = UserProvider::new();
    let previous = fixture.state.current();
    let config = previous.runtime.config().clone();
    let runtime = BrokerRuntime::with_providers(config, vec![provider.clone()]).unwrap();
    let store = runtime.managed_store().unwrap().clone();
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        1,
        "trusted-user".into(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    ));
    (fixture, store, provider)
}

fn user_request(relayed: bool, session: Option<&str>, message: Value) -> Request<Body> {
    let mut request = request(
        Method::POST,
        (!relayed).then_some(DIRECT),
        session,
        Some(message),
    );
    request
        .headers_mut()
        .insert(USER, HeaderValue::from_static("alice"));
    if relayed {
        request.headers_mut().insert(
            CALLER,
            HeaderValue::from_str(&format!("Bearer {RELAY}")).unwrap(),
        );
    }
    request
}
fn init() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"identity-proof","version":"1"}
    }})
}
fn call(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":agent_access_core::mcp::tool_name("fake","echo"),
        "arguments":{"inputs":{"project":"TEST","message":"synthetic identity test"}}
    }})
}
async fn initialize(fixture: &Fixture, relayed: bool) -> String {
    let response = fixture.send(user_request(relayed, None, init())).await;
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = rpc_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = session.expect("initialized session header");
    assert_eq!(
        fixture
            .send(user_request(
                relayed,
                Some(&session),
                json!({
                    "jsonrpc":"2.0","method":"notifications/initialized"
                })
            ))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    session
}
fn gate_aba(store: &ManagedStore) {
    let gate = store.identity_access("alice").unwrap();
    let paused = store
        .set_identity_access_paused("alice", true, gate.version, "fixture")
        .unwrap();
    store
        .set_identity_access_paused("alice", false, paused.version, "fixture")
        .unwrap();
}
fn mapping_aba(store: &ManagedStore) {
    let binding = store
        .list_username_bindings("alice")
        .unwrap()
        .pop()
        .unwrap();
    store
        .delete_username_binding("alice", &binding.binding_id, binding.version)
        .unwrap();
    store
        .create_username_binding("alice", "linux", "alice", "fixture")
        .unwrap();
}
fn binding_enabled_aba(store: &ManagedStore) {
    let binding = store
        .list_username_bindings("alice")
        .unwrap()
        .pop()
        .unwrap();
    let disabled = store
        .set_username_binding_enabled(
            "alice",
            &binding.binding_id,
            false,
            binding.version,
            "fixture",
        )
        .unwrap();
    store
        .set_username_binding_enabled(
            "alice",
            &binding.binding_id,
            true,
            disabled.version,
            "fixture",
        )
        .unwrap();
}
fn reload(fixture: &Fixture, provider: Arc<UserProvider>, change: impl FnOnce(&mut BrokerConfig)) {
    let previous = fixture.state.current();
    let mut config = previous.runtime.config().clone();
    change(&mut config);
    let generation = previous.generation + 1;
    let runtime = BrokerRuntime::with_providers(config, vec![provider])
        .unwrap()
        .with_config_generation(generation);
    fixture.state.publish_snapshot(RuntimeSnapshot::new(
        generation,
        format!("generation-{generation}"),
        runtime,
        StateLockSet::empty(),
    ));
}
async fn assert_assertion_denied(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.headers().contains_key("www-authenticate"));
    let body = rpc_body(response).await;
    assert_eq!(body["service"], "broker", "{body}");
    assert_eq!(body["action"], "identity.authenticate");
    assert_eq!(body["reasonCode"], "identity_assertion_denied");
}

#[tokio::test]
async fn trusted_user_read_and_write_dispatch_as_mapped_human_for_both_transports() {
    let (fixture, store, provider) = fixture(8);
    store.remove_identity_token("alice").unwrap();
    for relayed in [false, true] {
        let session = initialize(&fixture, relayed).await;
        for (id, write) in [(10, false), (11, true)] {
            provider.write_mode.store(write, Ordering::SeqCst);
            reload(&fixture, provider.clone(), |_| {});
            let listing = rpc_body(
                fixture
                    .send(user_request(
                        relayed,
                        Some(&session),
                        json!({
                            "jsonrpc":"2.0","id":9,"method":"tools/call","params":{
                                "name":"actions_describe","arguments":{"service":"fake","action":"echo"}
                            }
                        }),
                    ))
                    .await,
            )
            .await;
            assert_eq!(structured(&listing)["readOnly"], !write, "{listing}");
            let response = fixture
                .send(user_request(relayed, Some(&session), call(id)))
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            let result = rpc_body(response).await;
            let envelope = structured(&result);
            assert_eq!(envelope["decision"], "allow", "{result}");
            assert_eq!(envelope["result"]["principal"], "alice");
        }
    }
    assert_eq!(provider.executions.load(Ordering::SeqCst), 4);
    assert_eq!(provider.writes.load(Ordering::SeqCst), 2);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(
        records.iter().filter(|r| r["decision"] == "allow").count(),
        4
    );
    for record in records {
        let serialized = record.to_string();
        assert!(!serialized.contains(DIRECT));
        assert!(!serialized.contains(RELAY));
        assert_eq!(record["identitySource"]["type"], "trusted_user");
        assert_eq!(record["identitySource"]["namespace"], "linux");
        assert!(record["identitySource"]["bindingId"].is_string());
        assert!(record["identitySource"].get("tokenId").is_none());
        assert!(["direct", "relay"].contains(&record["callerId"].as_str().unwrap()));
        assert!(!serialized.contains("gateVersion"));
        assert!(!serialized.contains("fingerprint"));
    }
}

#[tokio::test]
async fn trusted_user_old_sessions_never_revive_after_gate_and_mapping_aba_at_capacity() {
    let (fixture, store, _) = fixture(1);
    let mut session = initialize(&fixture, false).await;
    for change in [
        gate_aba as fn(&ManagedStore),
        mapping_aba,
        binding_enabled_aba,
    ] {
        change(&store);
        let stale = fixture
            .send(user_request(
                false,
                Some(&session),
                json!({"jsonrpc":"2.0","id":9,"method":"ping"}),
            ))
            .await;
        assert_eq!(stale.status(), StatusCode::NOT_FOUND);
        // Pruning occurs before the one-session capacity decision.
        session = initialize(&fixture, false).await;
    }
}

#[tokio::test]
async fn trusted_user_body_intake_cannot_rebind_to_replacement_human() {
    let (fixture, store, provider) = fixture(4);
    let session = initialize(&fixture, false).await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let payload = call(20).to_string();
    let stream = futures_util::stream::once(async move {
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        Ok::<_, std::io::Error>(bytes::Bytes::from(payload))
    });
    let mut request = user_request(false, Some(&session), Value::Null);
    *request.body_mut() = Body::from_stream(stream);
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let binding = store
        .list_username_bindings("alice")
        .unwrap()
        .pop()
        .unwrap();
    store
        .delete_username_binding("alice", &binding.binding_id, binding.version)
        .unwrap();
    store
        .create_username_binding("bob", "linux", "alice", "fixture")
        .unwrap();
    release_tx.send(()).unwrap();
    assert_assertion_denied(pending.await.unwrap()).await;
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    let session = initialize(&fixture, false).await;
    let result = rpc_body(
        fixture
            .send(user_request(false, Some(&session), call(21)))
            .await,
    )
    .await;
    assert_eq!(structured(&result)["result"]["principal"], "bob");
    assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn trusted_user_final_admission_rechecks_gate_mapping_and_caller_aba() {
    for mutation in 0..3 {
        let (fixture, store, provider) = fixture(4);
        let session = initialize(&fixture, false).await;
        let barrier = Arc::new(crate::state::McpAdmissionBarrier {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        *fixture.state.mcp_admission_barrier.lock().unwrap() = Some(barrier.clone());
        let response = fixture
            .send(user_request(false, Some(&session), call(30)))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::timeout(Duration::from_secs(5), barrier.reached.notified())
            .await
            .unwrap();
        match mutation {
            0 => gate_aba(&store),
            1 => mapping_aba(&store),
            _ => {
                reload(&fixture, provider.clone(), |config| {
                    config
                        .identity
                        .trusted_callers
                        .get_mut("direct")
                        .unwrap()
                        .username_namespace = Some("other".into())
                });
                reload(&fixture, provider.clone(), |config| {
                    config
                        .identity
                        .trusted_callers
                        .get_mut("direct")
                        .unwrap()
                        .username_namespace = Some("linux".into())
                });
            }
        }
        barrier.release.add_permits(1);
        let result = rpc_body(response).await;
        let envelope = structured(&result);
        assert_eq!(envelope["service"], "broker", "{result}");
        assert_eq!(envelope["action"], "identity.authenticate");
        assert_eq!(envelope["reasonCode"], "identity_assertion_denied");
        assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn trusted_user_session_reaping_does_not_cancel_already_admitted_write() {
    let (fixture, store, provider) = fixture(1);
    let session = initialize(&fixture, false).await;
    provider.block.store(true, Ordering::SeqCst);
    let response = fixture
        .send(user_request(false, Some(&session), call(40)))
        .await;
    tokio::time::timeout(Duration::from_secs(5), provider.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    gate_aba(&store);
    let stale_cancel = fixture
        .send(user_request(
            false,
            Some(&session),
            json!({
                "jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":40}
            }),
        ))
        .await;
    assert_eq!(stale_cancel.status(), StatusCode::NOT_FOUND);
    let mut stale_delete = user_request(false, Some(&session), Value::Null);
    *stale_delete.method_mut() = Method::DELETE;
    *stale_delete.body_mut() = Body::empty();
    assert_eq!(
        fixture.send(stale_delete).await.status(),
        StatusCode::NOT_FOUND
    );
    let _replacement = initialize(&fixture, false).await;
    provider.release.add_permits(1);
    // Session transport may close, but the independent operation completes once.
    drop(response);
    assert_eq!(
        fixture
            .state
            .operations
            .shutdown(Duration::from_secs(5))
            .await,
        0
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(
        records.iter().filter(|r| r["decision"] == "allow").count(),
        1
    );
}

#[tokio::test]
async fn trusted_user_unchanged_caller_reload_preserves_session_but_loaded_secret_aba_does_not() {
    let (fixture, _, provider) = fixture(1);
    let session = initialize(&fixture, false).await;
    let epoch = fixture.state.current().caller_security_epoch;
    reload(&fixture, provider.clone(), |_| {});
    assert_eq!(fixture.state.current().caller_security_epoch, epoch);
    assert_eq!(
        fixture
            .send(user_request(
                false,
                Some(&session),
                json!({"jsonrpc":"2.0","id":2,"method":"ping"})
            ))
            .await
            .status(),
        StatusCode::OK
    );
    let path = fixture
        .state
        .current()
        .runtime
        .config()
        .identity
        .trusted_callers["direct"]
        .credential_ref
        .strip_prefix("file:")
        .unwrap()
        .to_owned();
    std::fs::write(&path, "rotated-caller-secret-0123456789").unwrap();
    reload(&fixture, provider.clone(), |_| {});
    std::fs::write(&path, DIRECT).unwrap();
    reload(&fixture, provider, |_| {});
    assert_eq!(fixture.state.current().caller_security_epoch, epoch + 2);
    assert_eq!(
        fixture
            .send(user_request(
                false,
                Some(&session),
                json!({"jsonrpc":"2.0","id":3,"method":"ping"})
            ))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    initialize(&fixture, false).await;
}

#[tokio::test]
async fn trusted_user_unavailable_cleanup_retains_unconfirmed_sessions() {
    let (fixture, _, _) = fixture(1);
    let session = initialize(&fixture, false).await;
    let path = fixture
        .state
        .current()
        .runtime
        .config()
        .managed_store
        .as_ref()
        .unwrap()
        .path
        .clone();
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE principal_identity_access RENAME TO unavailable_identity_access",
        )
        .unwrap();
    assert_eq!(
        fixture
            .send(user_request(false, None, init()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Observe completed cleanup passes, including one that must have started
    // after the table became unavailable; no timing assumption establishes it.
    for _ in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(5),
            fixture.state.mcp_cleanup_completed.notified(),
        )
        .await
        .unwrap();
    }
    connection
        .execute_batch(
            "ALTER TABLE unavailable_identity_access RENAME TO principal_identity_access",
        )
        .unwrap();
    let response = fixture
        .send(user_request(
            false,
            Some(&session),
            json!({"jsonrpc":"2.0","id":4,"method":"ping"}),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture
            .send(user_request(false, None, init()))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn mcp_ordinary_and_fingerprint_reject_declared_and_actual_trailers() {
    let ordinary = Fixture::new(|_| {});
    let (managed, store, _) = fixture(4);
    let ring = CredentialKeyRing::load(
        managed
            .state
            .current()
            .runtime
            .config()
            .credential_encryption
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let token = store.reveal_identity_token("alice", &ring).unwrap();
    let fingerprint = format!("sha256:{:x}", Sha256::digest(token.as_bytes()));
    for fixture in [&ordinary, &managed] {
        for declared in [true, false] {
            let mut request = request(
                Method::POST,
                std::ptr::eq(fixture, &ordinary).then_some(TOKEN_A),
                None,
                Some(init()),
            );
            if std::ptr::eq(fixture, &managed) {
                request.headers_mut().insert(
                    CALLER,
                    HeaderValue::from_str(&format!("Bearer {RELAY}")).unwrap(),
                );
                request.headers_mut().insert(
                    "x-aw-identity-token-sha256",
                    HeaderValue::from_str(&fingerprint).unwrap(),
                );
            }
            if declared {
                request
                    .headers_mut()
                    .insert("trailer", HeaderValue::from_static("X-Other"));
            } else {
                let body = http_body_util::Full::new(bytes::Bytes::from(init().to_string()))
                    .with_trailers(async {
                        Some(Ok::<_, std::convert::Infallible>(HeaderMap::new()))
                    });
                *request.body_mut() = Body::new(body);
            }
            let response = fixture.send(request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(!response.headers().contains_key("www-authenticate"));
            assert_eq!(
                rpc_body(response).await,
                json!({"error":"MCP request trailers are not supported"})
            );
        }
    }
}

#[tokio::test]
async fn trusted_user_discovery_queue_rechecks_the_original_mapping() {
    for method in ["tools/list", "tools/call"] {
        let (fixture, store, provider) = fixture(4);
        let session = initialize(&fixture, false).await;
        let barrier = Arc::new(crate::state::McpAdmissionBarrier {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        *fixture.state.mcp_discovery_barrier.lock().unwrap() = Some(barrier.clone());
        let request = user_request(
            false,
            Some(&session),
            json!({
                "jsonrpc":"2.0","id":60,"method":method,
                "params": if method == "tools/call" {json!({"name":"services_list","arguments":{}})} else {json!({})}
            }),
        );
        let app = fixture.app.clone();
        let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), barrier.reached.notified())
            .await
            .unwrap();
        mapping_aba(&store);
        barrier.release.add_permits(1);
        assert_assertion_denied(pending.await.unwrap()).await;
        assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn trusted_user_inventory_changes_preserve_username_sessions_and_expire_fingerprint_sessions()
{
    let (fixture, store, _) = fixture(4);
    let ring = CredentialKeyRing::load(
        fixture
            .state
            .current()
            .runtime
            .config()
            .credential_encryption
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let token = store.reveal_identity_token("alice", &ring).unwrap();
    let fingerprint = format!("sha256:{:x}", Sha256::digest(token.as_bytes()));
    let fingerprint_request = |session: Option<&str>, body| {
        let mut request = request(Method::POST, None, session, Some(body));
        request.headers_mut().insert(
            CALLER,
            HeaderValue::from_str(&format!("Bearer {RELAY}")).unwrap(),
        );
        request.headers_mut().insert(
            "x-aw-identity-token-sha256",
            HeaderValue::from_str(&fingerprint).unwrap(),
        );
        request
    };
    let username_session = initialize(&fixture, false).await;
    let response = fixture.send(fingerprint_request(None, init())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let fingerprint_session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    rpc_body(response).await;
    let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    assert_eq!(
        fixture
            .send(fingerprint_request(Some(&fingerprint_session), initialized))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    store.remove_identity_token("alice").unwrap();
    store.set_identity_token("alice", &token, &ring).unwrap();
    let ping = json!({"jsonrpc":"2.0","id":70,"method":"ping"});
    assert_eq!(
        fixture
            .send(user_request(false, Some(&username_session), ping.clone()))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .send(fingerprint_request(Some(&fingerprint_session), ping))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn trusted_user_service_scoped_sessions_keep_original_tool_names_and_view_ownership() {
    let (fixture, _, provider) = fixture(4);
    for relayed in [false, true] {
        let scoped = |session: Option<&str>, message| {
            let mut request = user_request(relayed, session, message);
            *request.uri_mut() = "/mcp/fake".parse().unwrap();
            request
        };
        let response = fixture.send(scoped(None, init())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        rpc_body(response).await;
        assert_eq!(
            fixture
                .send(scoped(
                    Some(&session),
                    json!({"jsonrpc":"2.0","method":"notifications/initialized"})
                ))
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        for (id, write) in [(80, false), (81, true)] {
            provider.write_mode.store(write, Ordering::SeqCst);
            reload(&fixture, provider.clone(), |_| {});
            let mut message = call(id);
            message["params"]["name"] = json!("echo");
            let result = rpc_body(fixture.send(scoped(Some(&session), message)).await).await;
            assert_eq!(structured(&result)["decision"], "allow", "{result}");
            assert_eq!(structured(&result)["result"]["principal"], "alice");
        }
        let ping = json!({"jsonrpc":"2.0","id":82,"method":"ping"});
        assert_eq!(
            fixture
                .send(user_request(relayed, Some(&session), ping.clone()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut wrong_caller = user_request(!relayed, Some(&session), ping);
        *wrong_caller.uri_mut() = "/mcp/fake".parse().unwrap();
        assert_eq!(
            fixture.send(wrong_caller).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(provider.executions.load(Ordering::SeqCst), 4);
    assert_eq!(provider.writes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn trusted_user_aliases_share_principal_capacity_without_sharing_session_owners() {
    let (fixture, store, _) = fixture(1);
    store
        .create_username_binding("alice", "linux", "alias", "fixture")
        .unwrap();
    let session = initialize(&fixture, false).await;
    let mut alias_init = user_request(false, None, init());
    alias_init
        .headers_mut()
        .insert(USER, HeaderValue::from_static("alias"));
    assert_eq!(
        fixture.send(alias_init).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let mut alias_ping = user_request(
        false,
        Some(&session),
        json!({"jsonrpc":"2.0","id":90,"method":"ping"}),
    );
    alias_ping
        .headers_mut()
        .insert(USER, HeaderValue::from_static("alias"));
    assert_eq!(
        fixture.send(alias_ping).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn trusted_user_remapped_human_reclaims_stale_global_capacity_immediately() {
    let (fixture, store, _) = fixture(1);
    let _old_session = initialize(&fixture, false).await;
    let binding = store
        .list_username_bindings("alice")
        .unwrap()
        .pop()
        .unwrap();
    store
        .delete_username_binding("alice", &binding.binding_id, binding.version)
        .unwrap();
    store
        .create_username_binding("bob", "linux", "alice", "fixture")
        .unwrap();
    // The stale Alice session occupied the only global slot. Bob must not wait
    // for background expiry merely because the old binding names another human.
    initialize(&fixture, false).await;
}

#[tokio::test]
async fn trusted_user_cancelled_post_body_waiter_retains_principal_store_work_capacity() {
    let (fixture, _, provider) = fixture(4);
    reload(&fixture, provider, |config| {
        config.mcp.max_control_requests = 2;
        config.mcp.max_control_requests_per_principal = 1;
    });
    let session = initialize(&fixture, false).await;
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    struct ReleaseOnDrop(Arc<crate::state::McpBlockingBarrier>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let release = ReleaseOnDrop(barrier.clone());
    *fixture.state.mcp_intake_barrier.lock().unwrap() = Some(barrier.clone());
    let ping = json!({"jsonrpc":"2.0","id":95,"method":"ping"});
    let request = user_request(false, Some(&session), ping.clone());
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), barrier.reached.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let denied = fixture
        .send(user_request(false, Some(&session), ping.clone()))
        .await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rpc_body(denied).await,
        json!({"error":"MCP caller capacity exhausted"})
    );
    // The second global slot remains usable by another human while Alice's
    // cancelled request still owns Alice's authoritative proof worker.
    let mut other = user_request(false, None, init());
    other
        .headers_mut()
        .insert(USER, HeaderValue::from_static("bob"));
    let other = fixture.send(other).await;
    assert_eq!(other.status(), StatusCode::OK);
    rpc_body(other).await;
    drop(release);
    tokio::time::timeout(Duration::from_secs(5), barrier.completed.notified())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .send(user_request(false, Some(&session), ping))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn trusted_user_live_cancellation_and_delete_work_for_each_transport_and_view() {
    for relayed in [false, true] {
        for path in ["/mcp", "/mcp/fake"] {
            let (fixture, _, provider) = fixture(1);
            let send = |session: Option<&str>, message: Value| {
                let mut request = user_request(relayed, session, message);
                *request.uri_mut() = path.parse().unwrap();
                request
            };
            let initialized = fixture.send(send(None, init())).await;
            assert_eq!(initialized.status(), StatusCode::OK);
            let session = initialized.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .to_owned();
            rpc_body(initialized).await;
            assert_eq!(
                fixture
                    .send(send(
                        Some(&session),
                        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
                    ))
                    .await
                    .status(),
                StatusCode::ACCEPTED
            );
            assert_eq!(
                fixture.send(send(None, init())).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            provider.pause_before_dispatch.store(true, Ordering::SeqCst);
            let mut operation = call(100);
            if path == "/mcp/fake" {
                operation["params"]["name"] = json!("echo");
            }
            let response = fixture.send(send(Some(&session), operation)).await;
            assert_eq!(response.status(), StatusCode::OK);
            tokio::time::timeout(Duration::from_secs(5), provider.entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            let cancelled = fixture.send(send(Some(&session), json!({
                "jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":100}
            }))).await;
            assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
            // The SDK closes this request's SSE channel on cancellation. The
            // independently owned Broker operation records the final outcome.
            drop(response);
            assert_eq!(
                fixture
                    .state
                    .operations
                    .shutdown(Duration::from_secs(5))
                    .await,
                0
            );
            assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
            let records = read_audit_records(&fixture.audit_path);
            assert_eq!(records.len(), 1, "{records:?}");
            let cancelled = records
                .iter()
                .filter(|record| record["reasonCode"] == "operation_cancelled")
                .collect::<Vec<_>>();
            assert_eq!(cancelled.len(), 1, "{records:?}");
            assert_eq!(cancelled[0]["principal"], "alice");
            assert_eq!(cancelled[0]["identitySource"]["type"], "trusted_user");
            assert_eq!(
                cancelled[0]["callerId"],
                if relayed { "relay" } else { "direct" }
            );
            let mut deletion = send(Some(&session), Value::Null);
            *deletion.method_mut() = Method::DELETE;
            *deletion.body_mut() = Body::empty();
            let deleted = fixture.send(deletion).await;
            assert_eq!(deleted.status(), StatusCode::ACCEPTED);
            assert_eq!(deleted.headers()["cache-control"], "no-store");
            let gone = fixture
                .send(send(
                    Some(&session),
                    json!({"jsonrpc":"2.0","id":101,"method":"ping"}),
                ))
                .await;
            assert_eq!(gone.status(), StatusCode::NOT_FOUND);
            let replacement = fixture.send(send(None, init())).await;
            assert_eq!(replacement.status(), StatusCode::OK);
            assert_ne!(replacement.headers()["mcp-session-id"], session);
            rpc_body(replacement).await;
        }
    }
}

#[tokio::test]
async fn trusted_user_preprotocol_timeouts_preserve_identity_view_and_discovery_errors() {
    use crate::mcp::PreProtocolPhase;
    for (phase, method) in [
        (PreProtocolPhase::Identity, "tools/list"),
        (PreProtocolPhase::View, "initialize"),
        (PreProtocolPhase::Discovery, "tools/list"),
        (PreProtocolPhase::Discovery, "tools/call"),
    ] {
        let (fixture, _, provider) = fixture(2);
        reload(&fixture, provider, |config| {
            config.mcp.protocol_timeout_ms = 250
        });
        let session = if phase == PreProtocolPhase::View {
            None
        } else {
            Some(initialize(&fixture, false).await)
        };
        let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
        let _release = ReleaseBlockingOnDrop(barrier.clone());
        *fixture.state.mcp_preprotocol_barrier.lock().unwrap() = Some((phase, barrier.clone()));
        let message = if method == "initialize" {
            init()
        } else {
            json!({
                "jsonrpc":"2.0","id":102,"method":method,
                "params":if method == "tools/call" { json!({"name":"services_list","arguments":{}}) } else {json!({})}
            })
        };
        let mut request = user_request(false, session.as_deref(), message);
        if phase == PreProtocolPhase::View {
            *request.uri_mut() = "/mcp/fake".parse().unwrap();
        }
        let app = fixture.app.clone();
        let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), barrier.reached.notified())
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("www-authenticate"));
        let expected = match phase {
            PreProtocolPhase::Identity => StatusCode::SERVICE_UNAVAILABLE,
            PreProtocolPhase::View => StatusCode::REQUEST_TIMEOUT,
            PreProtocolPhase::Discovery => StatusCode::OK,
        };
        assert_eq!(response.status(), expected);
        let body = rpc_body(response).await;
        match phase {
            PreProtocolPhase::Identity => {
                assert_eq!(body["action"], "request.admit", "{body}");
                assert_eq!(body["reasonCode"], "identity_unavailable");
            }
            PreProtocolPhase::View => assert_eq!(
                body,
                json!({"error":"MCP view admission deadline exceeded"})
            ),
            PreProtocolPhase::Discovery => {
                assert_eq!(body["id"], 102);
                assert_eq!(body["error"]["code"], -32603);
                assert_eq!(body["error"]["message"], "MCP discovery deadline exceeded");
            }
        }
    }
}

#[tokio::test]
async fn trusted_user_prune_timeout_retains_worker_capacity_and_background_expiry_progresses() {
    let (fixture, _, provider) = fixture(2);
    reload(&fixture, provider, |config| {
        config.mcp.protocol_timeout_ms = 250;
        config.mcp.max_control_requests = 3;
        config.mcp.max_control_requests_per_principal = 1;
        config.mcp.session_idle_timeout_ms = 2_000;
    });
    let session = initialize(&fixture, false).await;
    let first = Arc::new(crate::state::McpBlockingBarrier::default());
    let release_first = ReleaseBlockingOnDrop(first.clone());
    *fixture.state.mcp_prune_barrier.lock().unwrap() = Some(first.clone());
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move {
        app.oneshot(user_request(false, None, init()))
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(5), first.reached.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = rpc_body(response).await;
    assert_eq!(body["action"], "request.admit", "{body}");
    assert_eq!(body["reasonCode"], "identity_unavailable");
    // The timed-out Alice request retains both leases until its store worker ends.
    let denied = fixture
        .send(user_request(
            false,
            Some(&session),
            json!({"jsonrpc":"2.0","id":103,"method":"ping"}),
        ))
        .await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rpc_body(denied).await,
        json!({"error":"MCP caller capacity exhausted"})
    );

    let second = Arc::new(crate::state::McpBlockingBarrier::default());
    let release_second = ReleaseBlockingOnDrop(second.clone());
    *fixture.state.mcp_prune_barrier.lock().unwrap() = Some(second);
    for _ in 0..2 {
        let mut other = user_request(false, None, init());
        other
            .headers_mut()
            .insert(USER, HeaderValue::from_static("bob"));
        let response = tokio::time::timeout(Duration::from_secs(2), fixture.send(other))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            rpc_body(response).await["reasonCode"],
            "identity_unavailable"
        );
        // Neither another request nor the background sweep starts another blocked worker.
        assert!(fixture.state.mcp_prune_barrier.lock().unwrap().is_some());
    }
    // Observe expiry performed by the background loop itself while the first
    // store worker remains blocked. No incoming request drives this reaping.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            fixture.state.mcp_reap_completed.notified().await;
            if fixture.state.mcp_session_count.load(Ordering::SeqCst) == 0 {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(fixture.state.mcp_prune_barrier.lock().unwrap().is_some());
    drop(release_second);
    drop(release_first);
    tokio::time::timeout(Duration::from_secs(5), first.completed.notified())
        .await
        .unwrap();
    fixture.state.mcp_prune_barrier.lock().unwrap().take();
    let old = fixture
        .send(user_request(
            false,
            Some(&session),
            json!({"jsonrpc":"2.0","id":104,"method":"ping"}),
        ))
        .await;
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
    initialize(&fixture, false).await;
}

#[tokio::test]
async fn trusted_user_initialize_runs_between_background_prune_batches() {
    use futures_util::FutureExt;

    let (fixture, _, _) = fixture(66);
    // A full background sweep now needs two authoritative store batches.
    for _ in 0..65 {
        initialize(&fixture, false).await;
    }
    let first = Arc::new(crate::state::McpBlockingBarrier::default());
    let release_first = ReleaseBlockingOnDrop(first.clone());
    *fixture.state.mcp_background_prune_barrier.lock().unwrap() = Some((64, first.clone()));
    tokio::time::timeout(Duration::from_secs(5), first.reached.notified())
        .await
        .unwrap();

    // Discard any notification from fixture setup, then observe the new request
    // actually queued on the semaphore held by this first background batch.
    let _ = fixture.state.mcp_prune_waiting.notified().now_or_never();
    let app = fixture.app.clone();
    let pending = tokio::spawn(async move {
        app.oneshot(user_request(false, None, init()))
            .await
            .unwrap()
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.state.mcp_prune_waiting.notified(),
    )
    .await
    .unwrap();
    let second = Arc::new(crate::state::McpBlockingBarrier::default());
    let _release_second = ReleaseBlockingOnDrop(second.clone());
    *fixture.state.mcp_background_prune_barrier.lock().unwrap() = Some((1, second.clone()));
    drop(release_first);
    tokio::time::timeout(Duration::from_secs(5), second.reached.notified())
        .await
        .unwrap();

    // The second background batch stays blocked here. FIFO admission must have
    // allowed the already-queued initialize's single batch to finish first.
    let response = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("mcp-session-id"));
    rpc_body(response).await;
}
