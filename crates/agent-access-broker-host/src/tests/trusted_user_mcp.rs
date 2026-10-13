//! Public HTTP acceptance for trusted username assertions and their failure contract.
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    CredentialEncryptionConfig, CredentialEncryptionKeyConfig, ManagedStore, ManagedStoreConfig,
    PrincipalRole, TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport,
};
use axum::http::{HeaderMap, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;

const DIRECT: &str = "Bearer synthetic-direct-caller-0123456789";
const RELAY: &str = "Bearer synthetic-relay-caller-0123456789";
const ASSERTED_RELAY: &str = "Bearer synthetic-asserted-relay-0123456789";
const OTHER: &str = "Bearer synthetic-other-caller-0123456789";
const INCAPABLE: &str = "Bearer synthetic-incapable-caller-0123456789";
const USER: &str = "x-agent-access-user";
const CALLER: &str = "x-agent-access-caller-authorization";

struct Fixture {
    _directory: tempfile::TempDir,
    runtime: BrokerRuntime,
    app: Router,
    store: ManagedStore,
    admin_token: String,
    agent_token: String,
}

fn fixture() -> Fixture {
    fixture_with(|_, _| {})
}

fn fixture_with(configure: impl FnOnce(&mut BrokerConfig, &Path)) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let key = directory.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([73_u8; 32])).unwrap();
    let upstream = directory.path().join("upstream");
    std::fs::write(&upstream, "synthetic-upstream-credential").unwrap();
    let mut config = fake_config("");
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.sources = ["Authorization", "X-Fixture-Token"]
        .into_iter()
        .enumerate()
        .map(|(index, header)| IdentitySourceConfig {
            name: format!("broker_{index}"),
            kind: "broker_tokens".into(),
            header: header.into(),
            scheme: "Bearer".into(),
            principals: vec![],
        })
        .collect();
    for (name, secret, transport, namespace) in [
        (
            "direct",
            DIRECT,
            TrustedCallerCredentialTransport::AuthorizationUser,
            Some("managed_linux"),
        ),
        (
            "relay",
            RELAY,
            TrustedCallerCredentialTransport::CallerAuthorization,
            Some("managed_linux"),
        ),
        (
            "other",
            OTHER,
            TrustedCallerCredentialTransport::AuthorizationUser,
            Some("other_authority"),
        ),
        (
            "incapable",
            INCAPABLE,
            TrustedCallerCredentialTransport::CallerAuthorization,
            None,
        ),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, secret.strip_prefix("Bearer ").unwrap()).unwrap();
        config.identity.trusted_callers.insert(
            name.into(),
            TrustedCallerConfig {
                credential_ref: format!("file:{}", path.display()),
                credential_transport: transport,
                username_namespace: namespace.map(str::to_owned),
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: name == "relay",
            },
        );
    }
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory
            .path()
            .join("managed.sqlite")
            .display()
            .to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(key.display().to_string()),
        }],
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    });
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", upstream.display()));
    config.management.enabled = true;
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    config.mcp.max_sessions_per_principal = 32;
    config.policy.grants[0].subjects = vec!["user:alice".into(), "user:bob".into()];
    configure(&mut config, directory.path());
    let mut bootstrap = config.clone();
    bootstrap.policy.grants.clear();
    let store = BrokerRuntime::new(bootstrap)
        .unwrap()
        .managed_store()
        .unwrap()
        .clone();
    for (principal, role) in [
        ("alice", PrincipalRole::User),
        ("bob", PrincipalRole::User),
        ("admin", PrincipalRole::Admin),
    ] {
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: principal.into(),
                kind: "user".into(),
                role,
                self_service_enabled: None,
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "fixture".into(),
            })
            .unwrap();
    }
    for (principal, namespace, username) in [
        ("alice", "managed_linux", "alice"),
        ("alice", "managed_linux", "12345"),
        ("bob", "managed_linux", "bob"),
        ("bob", "managed_linux", "Alice"),
        ("bob", "other_authority", "alice"),
    ] {
        store
            .create_username_binding(principal, namespace, username, "fixture")
            .unwrap();
    }
    // Identity assertions must not require the separate fingerprint inventory.
    store.remove_identity_token("alice").unwrap();
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, class| {
        let scopes = if class == BrokerTokenClass::AgentInvoke {
            json!({"allowedExecutionContexts": ["default"]})
        } else {
            json!({})
        };
        store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "fixture".into(),
                    token_class: class,
                    scopes,
                    expires_at: None,
                    created_by: "fixture".into(),
                },
            )
            .unwrap()
            .token
    };
    let admin_token = issue("admin", BrokerTokenClass::Admin);
    let agent_token = issue("alice", BrokerTokenClass::AgentInvoke);
    let runtime = BrokerRuntime::new(config).unwrap();
    Fixture {
        _directory: directory,
        app: build_router(runtime.clone()),
        runtime,
        store,
        admin_token,
        agent_token,
    }
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"trusted-user-acceptance","version":"1"}
    }})
}

fn request(path: &str, method: Method, headers: &[(&str, &str)], body: Body) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .extension(ConnectInfo("127.0.0.1:5791".parse::<SocketAddr>().unwrap()))
        .header("host", "broker.example.test")
        .header(REQUEST_ID_HEADER, "trusted-user-acceptance")
        .header(ACCEPT, "application/json, text/event-stream")
        .header(CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap()
}

async fn send(fixture: &Fixture, request: Request<Body>) -> axum::response::Response {
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.app.clone().oneshot(request),
    )
    .await
    .expect("trusted user request timed out")
    .unwrap()
}

async fn assert_denial(
    response: axum::response::Response,
    status: StatusCode,
    action: &str,
    reason: &str,
) {
    let actual = response.status();
    assert!(response.headers().get("mcp-session-id").is_none());
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    if status == StatusCode::UNAUTHORIZED {
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE],
            "Bearer realm=\"agent-access-broker\""
        );
    } else {
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }
    let body = response_json(response).await;
    assert_eq!(actual, status, "{body}");
    assert_eq!(body["service"], "broker", "{body}");
    assert_eq!(body["action"], action, "{body}");
    assert_eq!(body["reasonCode"], reason, "{body}");
    assert_eq!(
        body["decision"],
        if status == StatusCode::SERVICE_UNAVAILABLE {
            "error"
        } else {
            "deny"
        },
        "{body}"
    );
    assert_eq!(body["resourceScopes"], json!({}), "{body}");
    assert!(body.get("result").is_none(), "{body}");
    assert!(
        body.get("jsonrpc").is_none() && body.get("id").is_none(),
        "{body}"
    );
    let encoded = body.to_string();
    assert!(!encoded.contains("synthetic-") && !encoded.contains("unmapped-private-name"));
}

#[derive(Default)]
struct ContextProvider {
    calls: std::sync::Mutex<Vec<(String, String)>>,
}

impl agent_access_provider::test_support::DescribedProvider for ContextProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for ContextProvider {
    fn resolve_scopes(
        &self,
        action: &str,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        agent_access_fake::FakeProvider.resolve_scopes(action, inputs)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.calls.lock().unwrap().push((
            request.identity.principal.clone(),
            request.execution_context.clone(),
        ));
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

fn asserted_relay_fixture() -> (Fixture, Arc<ContextProvider>, PathBuf) {
    let mut f = fixture_with(|config, directory| {
        let contexts = ["default", "internal", "external", "restricted"];
        config.execution_context = Some(ExecutionContextConfig {
            allowed_values: contexts.iter().map(|value| (*value).into()).collect(),
            // Asserted callers must supply context even with a direct-client default.
            default_context: Some("default".into()),
        });
        config.policy.resources = fixture_resources(&contexts);
        config.policy.grants[0].execution_contexts =
            Some(contexts.iter().map(|value| (*value).into()).collect());
        let secret = directory.join("asserted-relay");
        std::fs::write(&secret, ASSERTED_RELAY.strip_prefix("Bearer ").unwrap()).unwrap();
        config.identity.trusted_callers.insert(
            "asserted_relay".into(),
            TrustedCallerConfig {
                credential_ref: format!("file:{}", secret.display()),
                credential_transport: TrustedCallerCredentialTransport::CallerAuthorization,
                username_namespace: Some("managed_linux".into()),
                context_mode: TrustedCallerContextMode::Asserted,
                execution_context: None,
                allowed_execution_contexts: Some(vec!["internal".into(), "external".into()]),
                allow_forwarded_identity: false,
            },
        );
        config.audit = Some(agent_access_core::AuditConfig::new(
            agent_access_core::AuditStoreType::Jsonl,
            directory.join("audit.jsonl").display().to_string(),
        ));
    });
    let provider = Arc::new(ContextProvider::default());
    f.runtime =
        BrokerRuntime::with_providers(f.runtime.config().clone(), vec![provider.clone()]).unwrap();
    f.app = build_router(f.runtime.clone());
    let audit_path = f._directory.path().join("audit.jsonl");
    (f, provider, audit_path)
}

#[tokio::test]
async fn trusted_user_asserted_relay_context_is_required_authorized_pinned_and_audited() {
    let (f, provider, audit_path) = asserted_relay_fixture();
    let mut expected_contexts = BTreeMap::new();
    for (path_index, path) in ["/mcp", "/mcp/fake"].into_iter().enumerate() {
        let tool = if path == "/mcp" {
            agent_access_core::mcp::tool_name("fake", "echo")
        } else {
            "echo".to_owned()
        };
        let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":tool,"arguments":{"inputs":{"project":"TEST","message":"context test"}}
        }});
        for context in ["internal", "external"] {
            let headers = [
                (CALLER, ASSERTED_RELAY),
                (USER, "alice"),
                (EXECUTION_CONTEXT_HEADER, context),
            ];
            let response = send(
                &f,
                request(
                    path,
                    Method::POST,
                    &headers,
                    Body::from(initialize().to_string()),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let session = response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .to_owned();
            assert!(super::mcp::rpc_body(response).await["result"]["serverInfo"].is_object());
            let mut session_headers = headers.to_vec();
            session_headers.extend([
                ("mcp-session-id", session.as_str()),
                ("mcp-protocol-version", "2025-11-25"),
            ]);
            let initialized = send(
                &f,
                request(
                    path,
                    Method::POST,
                    &session_headers,
                    Body::from(
                        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
                    ),
                ),
            )
            .await;
            assert_eq!(initialized.status(), StatusCode::ACCEPTED);
            let request_id = format!("asserted-{path_index}-{context}");
            let mut req = request(
                path,
                Method::POST,
                &session_headers,
                Body::from(call.to_string()),
            );
            req.headers_mut().insert(
                REQUEST_ID_HEADER,
                HeaderValue::from_str(&request_id).unwrap(),
            );
            let response = send(&f, req).await;
            assert_eq!(response.status(), StatusCode::OK);
            let result = super::mcp::rpc_body(response).await;
            let envelope = super::mcp::structured(&result);
            assert_eq!(envelope["decision"], "allow", "{result}");
            assert_eq!(envelope["result"]["principal"], "alice");
            expected_contexts.insert(request_id, context);

            let calls_before = provider.calls.lock().unwrap().len();
            // Test both session creation and an otherwise valid native tool call.
            for (bad_context, status, reason) in [
                (None, StatusCode::FORBIDDEN, "execution_context_required"),
                (
                    Some("unconfigured"),
                    StatusCode::FORBIDDEN,
                    "execution_context_invalid",
                ),
                (
                    Some("restricted"),
                    StatusCode::FORBIDDEN,
                    "execution_context_denied",
                ),
            ] {
                for (body, session_id) in
                    [(initialize(), None), (call.clone(), Some(session.as_str()))]
                {
                    let mut bad_headers = vec![(CALLER, ASSERTED_RELAY), (USER, "alice")];
                    if let Some(value) = bad_context {
                        bad_headers.push((EXECUTION_CONTEXT_HEADER, value));
                    }
                    if let Some(value) = session_id {
                        bad_headers.extend([
                            ("mcp-session-id", value),
                            ("mcp-protocol-version", "2025-11-25"),
                        ]);
                    }
                    assert_denial(
                        send(
                            &f,
                            request(
                                path,
                                Method::POST,
                                &bad_headers,
                                Body::from(body.to_string()),
                            ),
                        )
                        .await,
                        status,
                        "caller.authenticate",
                        reason,
                    )
                    .await;
                }
            }
            let other_context = if context == "internal" {
                "external"
            } else {
                "internal"
            };
            let mut changed_context = session_headers.clone();
            changed_context[2].1 = other_context;
            let response = send(
                &f,
                request(
                    path,
                    Method::POST,
                    &changed_context,
                    Body::from(call.to_string()),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(
                response_json(response).await,
                json!({"error":"MCP session unavailable; initialize again"})
            );
            assert_eq!(provider.calls.lock().unwrap().len(), calls_before);
            let response = send(
                &f,
                request(
                    path,
                    Method::POST,
                    &session_headers,
                    Body::from(json!({"jsonrpc":"2.0","id":3,"method":"ping"}).to_string()),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(super::mcp::rpc_body(response).await["result"], json!({}));
        }
    }
    assert_eq!(
        *provider.calls.lock().unwrap(),
        vec![
            ("alice".into(), "internal".into()),
            ("alice".into(), "external".into()),
            ("alice".into(), "internal".into()),
            ("alice".into(), "external".into()),
        ]
    );
    let records = read_audit_records(&audit_path);
    let invocations: Vec<_> = records
        .iter()
        .filter(|record| record["service"] == "fake" && record["action"] == "echo")
        .collect();
    assert_eq!(invocations.len(), 4);
    for record in invocations {
        assert_eq!(
            record["executionContext"],
            expected_contexts[record["agentRequestId"].as_str().unwrap()]
        );
        assert_eq!(record["callerId"], "asserted_relay");
        assert_eq!(record["identitySource"]["type"], "trusted_user");
        assert_eq!(record["identitySource"]["namespace"], "managed_linux");
        assert!(record["identitySource"]["bindingId"].is_string());
    }
}

#[tokio::test]
async fn trusted_user_caller_credentials_alone_never_authenticate_or_consume_session_capacity() {
    for path in ["/mcp", "/mcp/fake"] {
        let f = fixture_with(|config, _| {
            config.mcp.max_sessions = 1;
            config.mcp.max_sessions_per_principal = 1;
        });
        let agent = format!("Bearer {}", f.agent_token);
        for (headers, action, reason) in [
            (
                vec![("authorization", DIRECT)],
                "identity.authenticate",
                "identity_invalid",
            ),
            (
                vec![(CALLER, agent.as_str())],
                "caller.authenticate",
                "caller_authentication_invalid",
            ),
            (
                vec![(CALLER, agent.as_str()), ("authorization", agent.as_str())],
                "caller.authenticate",
                "caller_authentication_invalid",
            ),
        ] {
            assert_denial(
                send(
                    &f,
                    request(
                        path,
                        Method::POST,
                        &headers,
                        Body::from(initialize().to_string()),
                    ),
                )
                .await,
                StatusCode::UNAUTHORIZED,
                action,
                reason,
            )
            .await;
        }
        let response = send(
            &f,
            request(
                path,
                Method::POST,
                &[("authorization", DIRECT), (USER, "alice")],
                Body::from(initialize().to_string()),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("mcp-session-id").is_some());
        assert!(super::mcp::rpc_body(response).await["result"]["serverInfo"].is_object());
    }
}

#[tokio::test]
async fn trusted_user_direct_relay_exact_names_and_authorities_work_without_inventory() {
    let f = fixture();
    assert!(!f.store.identity_token_metadata("alice").unwrap().configured);
    for path in ["/mcp", "/mcp/fake"] {
        for (carrier, credential, username, principal) in [
            ("authorization", DIRECT, "alice", "alice"),
            (CALLER, RELAY, "alice", "alice"),
            ("authorization", DIRECT, "bob", "bob"),
            ("authorization", DIRECT, "Alice", "bob"),
            ("authorization", DIRECT, "12345", "alice"),
            ("authorization", OTHER, "alice", "bob"),
        ] {
            let req = request(
                path,
                Method::POST,
                &[(carrier, credential), (USER, username)],
                Body::from(initialize().to_string()),
            );
            let ingress = f.runtime.admit_mcp_ingress(req.headers()).unwrap();
            let resolved = f
                .runtime
                .resolve_admitted_identity_with_proof(req.headers(), &ingress)
                .unwrap();
            assert_eq!(resolved.identity.principal, principal);
            let source = resolved.identity.source.unwrap();
            assert_eq!(source.kind, "trusted_user");
            assert_eq!(source.token_class, Some(BrokerTokenClass::AgentInvoke));
            let response = send(&f, req).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{path} {carrier} {username}"
            );
            assert!(response.headers().get("mcp-session-id").is_some());
            assert!(super::mcp::rpc_body(response).await["result"]["serverInfo"].is_object());
        }
    }
    let response = send(
        &f,
        request(
            "/mcp",
            Method::GET,
            &[
                ("authorization", DIRECT),
                (USER, "alice"),
                ("cookie", "unrelated=incidental"),
            ],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn trusted_user_authentication_failure_matrix_preserves_exact_tuples() {
    let f = fixture();
    let admin = format!("Bearer {}", f.admin_token);
    let agent = format!("Bearer {}", f.agent_token);
    let cases = [
        (
            vec![(USER, "alice")],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_required",
        ),
        (
            vec![(USER, "alice"), ("authorization", "Bearer wrong")],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_invalid",
        ),
        (
            vec![(USER, "alice"), ("authorization", admin.as_str())],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_invalid",
        ),
        (
            vec![(USER, "alice"), ("authorization", agent.as_str())],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_invalid",
        ),
        (
            vec![(USER, "alice"), (CALLER, DIRECT)],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_invalid",
        ),
        (
            vec![(USER, "alice"), ("authorization", RELAY)],
            StatusCode::UNAUTHORIZED,
            "caller.authenticate",
            "caller_authentication_invalid",
        ),
        (
            vec![(USER, "alice"), (CALLER, INCAPABLE)],
            StatusCode::FORBIDDEN,
            "caller.authenticate",
            "caller_user_assertion_denied",
        ),
        (
            vec![(USER, "unmapped-private-name"), ("authorization", DIRECT)],
            StatusCode::FORBIDDEN,
            "identity.authenticate",
            "identity_assertion_denied",
        ),
        (
            vec![(USER, "alice"), ("authorization", DIRECT), (CALLER, RELAY)],
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        ),
        (
            vec![
                (USER, "alice"),
                ("authorization", DIRECT),
                ("x-fixture-token", agent.as_str()),
            ],
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        ),
        (
            vec![
                (USER, "alice"),
                (CALLER, RELAY),
                ("x-aw-identity-token-sha256", "sha256:invalid"),
            ],
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        ),
    ];
    for path in ["/mcp", "/mcp/fake"] {
        for (headers, status, action, reason) in &cases {
            let response = send(
                &f,
                request(
                    path,
                    Method::POST,
                    headers,
                    Body::from(initialize().to_string()),
                ),
            )
            .await;
            assert_denial(response, *status, action, reason).await;
        }
    }
    // A direct credential is not a context-only caller on a different carrier.
    assert_denial(
        send(
            &f,
            request(
                "/v1/me",
                Method::GET,
                &[(CALLER, DIRECT), ("authorization", &admin)],
                Body::empty(),
            ),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "caller.authenticate",
        "caller_authentication_invalid",
    )
    .await;
}

#[tokio::test]
async fn trusted_user_malformed_protected_fields_never_enter_mcp_protocol() {
    let f = fixture();
    let oversized = "a".repeat(129);
    for username in [
        "",
        " alice",
        "alice ",
        "ali ce",
        "alice,bob",
        "alice%40host",
        oversized.as_str(),
    ] {
        assert_denial(
            send(
                &f,
                request(
                    "/mcp",
                    Method::POST,
                    &[(USER, username), ("authorization", DIRECT)],
                    Body::from(initialize().to_string()),
                ),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        )
        .await;
    }
    for extra in [
        (USER, "alice"),
        (USER, "bob"),
        ("authorization", DIRECT),
        ("connection", "keep-alive, X-Agent-Access-User"),
        ("connection", "Authorization"),
        ("trailer", "x-any-trailer"),
    ] {
        assert_denial(
            send(
                &f,
                request(
                    "/mcp",
                    Method::POST,
                    &[(USER, "alice"), ("authorization", DIRECT), extra],
                    Body::from(initialize().to_string()),
                ),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        )
        .await;
    }
    for malformed in ["Basic wrong", "Bearer", "Bearer a,b", "Bearer a b"] {
        assert_denial(
            send(
                &f,
                request(
                    "/mcp",
                    Method::POST,
                    &[(USER, "alice"), ("authorization", malformed)],
                    Body::from(initialize().to_string()),
                ),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "identity.authenticate",
            "identity_assertion_invalid",
        )
        .await;
    }
    let mut req = request(
        "/mcp",
        Method::POST,
        &[("authorization", DIRECT)],
        Body::from(initialize().to_string()),
    );
    req.headers_mut()
        .insert(USER, HeaderValue::from_bytes(&[0xff]).unwrap());
    assert_denial(
        send(&f, req).await,
        StatusCode::BAD_REQUEST,
        "identity.authenticate",
        "identity_assertion_invalid",
    )
    .await;
    let mut trailers = HeaderMap::new();
    trailers.insert(USER, HeaderValue::from_static("bob"));
    let body = http_body_util::Full::new(Bytes::from(initialize().to_string()))
        .with_trailers(async move { Some(Ok::<_, std::convert::Infallible>(trailers)) });
    assert_denial(
        send(
            &f,
            request(
                "/mcp",
                Method::POST,
                &[(USER, "alice"), ("authorization", DIRECT)],
                Body::new(body),
            ),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "identity.authenticate",
        "identity_assertion_invalid",
    )
    .await;
}

#[tokio::test]
async fn trusted_user_unsupported_routes_reject_before_other_authentication() {
    let f = fixture();
    let admin = format!("Bearer {}", f.admin_token);
    for path in [
        "/v1/healthz",
        "/v1/readyz",
        "/ui",
        "/v1/me",
        "/v1/admin/principals",
        "/v1/invoke",
        "/mcp/fake/extra",
    ] {
        for credential in [DIRECT, admin.as_str()] {
            assert_denial(
                send(
                    &f,
                    request(
                        path,
                        Method::GET,
                        &[(USER, "alice"), ("authorization", credential)],
                        Body::empty(),
                    ),
                )
                .await,
                StatusCode::BAD_REQUEST,
                "identity.authenticate",
                "identity_assertion_unsupported",
            )
            .await;
        }
    }
}

#[tokio::test]
async fn trusted_user_storage_failure_is_unavailable_without_private_diagnostics() {
    let f = fixture();
    rusqlite::Connection::open(f.store.path())
        .unwrap()
        .execute_batch(
            "ALTER TABLE principal_username_bindings RENAME TO private_unavailable_bindings",
        )
        .unwrap();
    assert_denial(
        send(
            &f,
            request(
                "/mcp",
                Method::POST,
                &[(USER, "alice"), ("authorization", DIRECT)],
                Body::from(initialize().to_string()),
            ),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "request.admit",
        "identity_unavailable",
    )
    .await;
}

#[tokio::test]
async fn trusted_user_git_rejection_preserves_gateway_framing() {
    let f = fixture();
    let mut config = f.runtime.config().clone();
    config
        .gateways
        .insert("gitlab_git".into(), test_git_gateway_config());
    config.credentials.service.insert(
        "gitlab_git".into(),
        config.credentials.service["fake"].clone(),
    );
    let runtime = BrokerRuntime::new(config).unwrap();
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        Arc::new(crate::backend_registry()),
        RuntimeSnapshot::new(
            1,
            "trusted-user-git".into(),
            runtime.clone(),
            StateLockSet::empty(),
        ),
        runtime.max_http_body_bytes(),
        Duration::from_secs(30),
        Duration::from_secs(30),
        runtime.audit_registry(),
    ));
    let gateway = build_gateway_router(state);
    let mut req = request(
        "/sip/service.git/info/refs?service=git-upload-pack",
        Method::GET,
        &[(USER, "alice"), ("authorization", DIRECT)],
        Body::empty(),
    );
    req.headers_mut()
        .insert("host", HeaderValue::from_static("git.example.test"));
    let response = gateway.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "identity_assertion_unsupported"
    );
    assert!(
        response.headers()[CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(
        !body.starts_with(b"{"),
        "Git failures retain their protocol body"
    );
    assert!(!String::from_utf8_lossy(&body).contains("alice"));
}
