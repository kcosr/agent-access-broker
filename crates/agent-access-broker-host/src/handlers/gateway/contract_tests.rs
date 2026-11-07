use super::*;
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, GatewayBody, GatewayClassification,
    GatewayConfig as ProtocolConfig, GatewayForwardPlan, GatewayProtocol, GatewayRegistration,
    GatewayRequest, GatewayRequestHead, GatewayResponseProfile, GatewayServiceContext,
    GatewayStatusHeaders, GatewayStatusMatch, ProviderBuildError, ProviderFailureStatus,
    ProviderReasonDefinition, ServiceDescriptor, ServiceSurface,
};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use tokio::net::TcpListener;
use tower::ServiceExt;

static MISSING: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("http_fixture_missing", ProviderFailureStatus::NotFound);
static HTTP_FIXTURE: GatewayRegistration = GatewayRegistration::new(
    agent_access_provider::module_metadata!(),
    "http_fixture",
    parse_fixture,
)
.with_domain_reasons(&[&MISSING]);

#[derive(Debug)]
struct HttpFixture;
fn parse_fixture(value: toml::Value) -> Result<Arc<dyn ProtocolConfig>, String> {
    if value.as_table().is_none_or(|fields| !fields.is_empty()) {
        return Err("fixture settings must be empty".into());
    }
    Ok(Arc::new(HttpFixture))
}
impl ProtocolConfig for HttpFixture {
    fn validate(&self, _: &GatewayServiceContext, _: &mut Vec<String>) {}
    fn descriptor(&self, context: &GatewayServiceContext) -> ServiceDescriptor {
        ServiceDescriptor::new(&context.service, &context.display_name)
            .with_surface(ServiceSurface::Gateway {
                kind: "http_fixture".into(),
                broker_hosts: context.broker_hosts.clone(),
            })
            .with_resource_scopes(BTreeMap::from([(
                "repository".into(),
                agent_access_provider::ResourceScopeCapabilities::new(
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
                    vec!["exact".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new("read", "Fixture read", json!({"type":"object"}))
                    .read_only()
                    .credential_modes(["service"]),
                ActionDescriptor::new("scoped", "Fixture scoped read", json!({"type":"object"}))
                    .read_only()
                    .scope("repository")
                    .credential_modes(["service"]),
            ])
            .with_credentials(
                CredentialDescriptor::without_execution_credential().without_verification(),
            )
    }
    fn build(
        &self,
        _: &GatewayServiceContext,
    ) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError> {
        Ok(Arc::new(HttpFixture))
    }
}
impl GatewayProtocol for HttpFixture {
    fn classify(
        &self,
        head: GatewayRequestHead<'_>,
    ) -> Result<GatewayClassification, ProviderError> {
        let path = head.path_and_query().split('?').next().unwrap();
        if path == "/domain" {
            return Err(ProviderError::domain(&MISSING, "fixture route not found"));
        }
        if path == "/foreign" {
            return Err(ProviderError::deny(
                ReasonCode::RateLimited,
                "foreign reason",
            ));
        }
        assert!(!head.headers().contains_key(AUTHORIZATION));
        assert!(!head.headers().contains_key("cookie"));
        assert!(!head.headers().contains_key("x-aw-identity-token-sha256"));
        let scopes = if path == "/unexpected-scope" || path == "/scoped" {
            ResourceScopes::from([("repository".into(), vec!["team/project".into()])])
        } else {
            ResourceScopes::new()
        };
        Ok(GatewayClassification::new(
            if path == "/unknown-action" {
                "unknown"
            } else if path.starts_with("/scoped") {
                "scoped"
            } else {
                "read"
            },
            scopes,
            "request",
            Box::new(HttpRequest {
                method: head.method().clone(),
                path: path.into(),
            }),
        ))
    }
}
struct HttpRequest {
    method: Method,
    path: String,
}
#[async_trait]
impl GatewayRequest for HttpRequest {
    async fn preflight(
        self: Box<Self>,
        mut body: GatewayBody,
    ) -> Result<GatewayForwardPlan, ProviderError> {
        if self.path == "/swallow-body-failure" {
            let _ = body.next_frame().await;
        } else {
            while let Some(frame) = body.next_frame().await.map_err(|_| {
                ProviderError::deny(ReasonCode::GatewayRequestBodyDenied, "fixture body failed")
            })? {
                if matches!(frame, agent_access_provider::GatewayBodyFrame::Data(ref bytes) if !bytes.is_empty())
                {
                    break;
                }
            }
        }
        let mut plan = GatewayForwardPlan::new(self.method, self.path.clone(), body)
            .with_response(
                GatewayResponseProfile::new(vec![
                    "content-type".into(),
                    "content-encoding".into(),
                    "etag".into(),
                ])
                .preserve_content_length(),
            )
            .with_audit_target("/fixture/{item}")
            .with_replay(agent_access_provider::GatewayReplayProfile::ConfirmedUnprocessed);
        if self.path == "/reserved-header" {
            plan.headers
                .insert(AUTHORIZATION, HeaderValue::from_static("Bearer forbidden"));
        }
        if self.path == "/wrong-method" {
            plan.method = Method::DELETE;
        }
        Ok(plan)
    }
}

fn runtime_fixture(
    upstream: &str,
    directory: &std::path::Path,
) -> (BrokerRuntime, Arc<crate::state::ReloadableState>, String) {
    let identity = directory.join("identity-token");
    std::fs::write(&identity, "broker-token\n").unwrap();
    let mut config = tests::test_forwarding_config(
        &directory.join("absent-upstream-token"),
        &identity,
        &directory.join("audit.jsonl"),
    );
    config.credentials.service.clear();
    config.providers = agent_access_core::ProvidersConfig::new(Arc::new(
        agent_access_core::BackendRegistry::empty()
            .with_gateways([&HTTP_FIXTURE])
            .unwrap(),
    ));
    let mut gateway = GatewayConfig::new("http_fixture", "Fixture API", upstream);
    gateway.broker_hosts = vec!["api.example.test".into()];
    gateway.allowed_upstream_hosts = vec![format!("{upstream}/**")];
    gateway.auth_modes = vec!["basic_broker_token".into(), "bearer_broker_token".into()];
    gateway.credential_modes = vec!["service".into()];
    gateway.request_body_max_bytes = Some(8);
    gateway.response_body_max_bytes = Some(1024);
    let mut second = gateway.clone();
    second.broker_hosts = vec!["api-two.example.test".into()];
    config.gateways = BTreeMap::from([("api_one".into(), gateway), ("api_two".into(), second)]);
    config.policy.resources.clear();
    config.policy.grants[0].service = "api_one".into();
    config.policy.grants[0].actions = vec!["read".into()];
    config.policy.grants[0].resources = Default::default();
    config.policy.grants[0].subjects = vec!["user:gateway-user".into()];
    let mut second_grant = config.policy.grants[0].clone();
    second_grant.service = "api_two".into();
    config.policy.grants.push(second_grant);
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.identity.sources = vec![agent_access_core::IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    let hash_key = directory.join("hash-key");
    std::fs::write(
        &hash_key,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([47_u8; 32]),
    )
    .unwrap();
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(hash_key.display().to_string()),
        }],
    });
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    let store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.join("managed.sqlite").display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
    let store = agent_access_core::ManagedStore::open(
        &store_config,
        &contexts,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            },
            &contexts,
        )
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store.issue_broker_token(&hasher, agent_access_core::BrokerTokenIssueRequest {
        principal_id: "gateway-user".into(), name: "generic gateway fixture".into(),
        token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
        scopes: json!({"allowedServices":["api_one", "api_two"],"readOnly":false,"allowedExecutionContexts":["default"]}),
        expires_at: None, created_by: "test".into(),
    }).unwrap();
    drop(store);
    config.network.outbound_tls = agent_access_core::OutboundTlsConfig {
        trust: agent_access_core::OutboundTlsTrustMode::Custom,
        ca_certificate: Some(tls_fixture().join("ca-a.pem")),
    };
    let config_path = directory.join("broker.toml");
    std::fs::write(
        &config_path,
        crate::tests::ConfigDoc::from_config(&config).render(),
    )
    .unwrap();
    let registry = config.providers.registry().clone();
    let runtime = BrokerRuntime::new(config).unwrap();
    let snapshot = RuntimeSnapshot::new(
        1,
        "sha256:generic-gateway-fixture".into(),
        runtime.clone().with_config_generation(1),
        agent_access_core::StateLockSet::empty(),
    );
    let state = Arc::new(crate::state::ReloadableState::from_snapshot(
        config_path,
        registry,
        crate::broker_build_status(),
        snapshot,
        1024,
        Duration::from_secs(30),
        Duration::from_secs(30),
        runtime.audit_registry(),
    ));
    (runtime, state, format!("Bearer {}", issued.token))
}

fn request(method: Method, path: &str, authorization: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, "api.example.test")
        .header(AUTHORIZATION, authorization)
        .header("cookie", "secret-cookie")
        .extension(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ))
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn credential_free_http_protocol_uses_bearer_identity_and_passes_raw_response() {
    let temp = crate::tests::test_temp_dir();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (runtime, state, authorization) = runtime_fixture(&format!("https://{address}"), &temp);
    let upstream = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture upstream accept: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream =
            rustls::StreamOwned::new(rustls::ServerConnection::new(tls_server()).unwrap(), stream);
        let mut received = Vec::new();
        let mut bytes = [0u8; 1024];
        while !received.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0);
            received.extend_from_slice(&bytes[..count]);
        }
        let head = String::from_utf8(received).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /items http/1.1"));
        assert!(!head.contains("authorization:"));
        assert!(!head.contains("cookie:"));
        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nETag: \"v1\"\r\nSet-Cookie: hidden=secret\r\nConnection: close\r\n\r\n\x00\x01\xfe\xff").unwrap();
        stream.flush().unwrap();
    });
    let response = crate::router::build_gateway_router(state)
        .oneshot(request(
            Method::GET,
            "/items",
            &authorization,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[CONTENT_LENGTH], "4");
    assert_eq!(response.headers()["etag"], "\"v1\"");
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        &axum::body::to_bytes(response.into_body(), 16)
            .await
            .unwrap()[..],
        &[0, 1, 254, 255]
    );
    upstream.await.unwrap();
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = agent_access_core::test_support::read_audit_records(
        agent_access_core::AuditStoreType::Jsonl,
        &temp.join("audit.jsonl"),
    );
    let terminal: Vec<_> = records
        .iter()
        .filter(|record| record["providerAudit"]["gateway"]["phase"] == "completed")
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(
        terminal[0]["providerAudit"]["gateway"]["upstreamPath"],
        "/fixture/{item}"
    );
    assert_eq!(terminal[0]["providerAudit"]["gateway"]["responseBytes"], 4);
}

#[tokio::test]
async fn invalid_module_plans_and_local_outcomes_never_dispatch() {
    for (path, expected, body) in [
        (
            "/reserved-header",
            ReasonCode::BrokerProviderContractFailed,
            Body::empty(),
        ),
        (
            "/wrong-method",
            ReasonCode::BrokerProviderContractFailed,
            Body::empty(),
        ),
        (
            "/unknown-action",
            ReasonCode::BrokerProviderContractFailed,
            Body::empty(),
        ),
        (
            "/unexpected-scope",
            ReasonCode::BrokerProviderContractFailed,
            Body::empty(),
        ),
        (
            "/foreign",
            ReasonCode::BrokerProviderContractFailed,
            Body::empty(),
        ),
        (
            "/swallow-body-failure",
            ReasonCode::BrokerProviderContractFailed,
            Body::from("over-eight-bytes"),
        ),
    ] {
        let temp = crate::tests::test_temp_dir();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (runtime, state, authorization) = runtime_fixture(
            &format!("https://{}", listener.local_addr().unwrap()),
            &temp,
        );
        let response = crate::router::build_gateway_router(state)
            .oneshot(request(Method::GET, path, &authorization, body))
            .await
            .unwrap();
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            expected.as_str(),
            "{path}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err(),
            "{path}"
        );
        runtime
            .shutdown_audit(Duration::from_secs(5))
            .await
            .unwrap();
    }
}

#[test]
fn response_profile_is_exact_then_class_then_default_and_preserves_upstream_values() {
    let profile =
        GatewayResponseProfile::new(vec!["content-type".into()]).with_status_headers(vec![
            GatewayStatusHeaders::new(GatewayStatusMatch::Default, vec!["x-default".into()]),
            GatewayStatusHeaders::new(GatewayStatusMatch::Class(2), vec!["x-class".into()]),
            GatewayStatusHeaders::new(GatewayStatusMatch::Exact(201), vec!["x-exact".into()]),
        ]);
    let headers = HeaderMap::from_iter(
        [
            ("x-default", "d"),
            ("x-class", "c"),
            ("x-exact", "e"),
            ("content-type", "text/plain"),
        ]
        .map(|(name, value)| {
            (
                axum::http::header::HeaderName::from_static(name),
                HeaderValue::from_static(value),
            )
        }),
    );
    for (status, selected) in [(201, "x-exact"), (200, "x-class"), (404, "x-default")] {
        let result = selected_response_headers(&HTTP_FIXTURE, &profile, status, &headers).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[selected], headers[selected]);
    }
}

#[test]
fn repeated_selected_response_headers_fail_as_upstream_ambiguity() {
    let profile = GatewayResponseProfile::new(vec!["content-type".into()]);
    let mut headers = HeaderMap::new();
    headers.append("content-type", HeaderValue::from_static("text/plain"));
    headers.append("content-type", HeaderValue::from_static("application/json"));
    let error = selected_response_headers(&HTTP_FIXTURE, &profile, 200, &headers).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    headers.remove("content-type");
    headers.append("set-cookie", HeaderValue::from_static("a=private"));
    headers.append("set-cookie", HeaderValue::from_static("b=private"));
    assert!(
        selected_response_headers(&HTTP_FIXTURE, &profile, 200, &headers)
            .unwrap()
            .is_empty()
    );
}

#[derive(Debug)]
struct SelectedHeaderValues(Vec<&'static str>);
impl agent_access_provider::GatewayResponseValidator for SelectedHeaderValues {
    fn validate(&self, _: u16, _: &HeaderMap) -> Result<HeaderMap, ProviderError> {
        let mut headers = HeaderMap::new();
        for value in &self.0 {
            headers.append(CONTENT_TYPE, HeaderValue::from_static(value));
        }
        Ok(headers)
    }
}

#[test]
fn response_validators_may_omit_but_never_invent_duplicate_or_reorder_values() {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static("text/first"));
    headers.append(CONTENT_TYPE, HeaderValue::from_static("text/second"));
    for (values, valid) in [
        (vec!["text/first"], true),
        (vec!["text/second"], true),
        (vec!["text/first", "text/second"], true),
        (vec!["text/second", "text/first"], false),
        (vec!["text/first", "text/first"], false),
        (vec!["text/invented"], false),
    ] {
        let profile = GatewayResponseProfile::new(vec!["content-type".into()])
            .with_validator(Arc::new(SelectedHeaderValues(values.clone())));
        let result = selected_response_headers(&HTTP_FIXTURE, &profile, 200, &headers);
        assert_eq!(result.is_ok(), valid, "{values:?}");
        if let Err(error) = result {
            assert_eq!(
                error.reason_code(),
                ReasonCode::BrokerProviderContractFailed
            );
        }
    }
}

#[test]
fn identity_headers_and_debug_omit_secret_values() {
    let mut headers = HeaderMap::new();
    for name in [
        "authorization",
        "cookie",
        "x-aw-identity-token-sha256",
        "x-agent-access-user",
        "proxy-authorization",
        "x-request-id",
        "x-forwarded-unknown",
        "true-client-ip",
        "cf-connecting-ip",
        "x-client-ip",
        "via",
    ] {
        headers.insert(
            axum::http::header::HeaderName::from_static(name),
            HeaderValue::from_static("secret-sentinel"),
        );
    }
    headers.append("x-field", HeaderValue::from_static("one"));
    headers.append("x-field", HeaderValue::from_static("two"));
    let clean = protocol_headers(&headers);
    assert_eq!(clean.get_all("x-field").iter().count(), 2);
    assert_eq!(clean.len(), 2);
}

fn tls_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-access-core/tests/fixtures/outbound-tls")
}
fn tls_server() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certificate = std::fs::read(tls_fixture().join("leaf-a.pem")).unwrap();
    let key = std::fs::read(tls_fixture().join("leaf-a.key")).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            CertificateDer::pem_slice_iter(&certificate)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(&key).unwrap(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn one_kind_has_independent_service_identity_and_local_domain_reasons() {
    let temp = crate::tests::test_temp_dir();
    let (runtime, state, authorization) = runtime_fixture("https://unused.example.test", &temp);
    for (host, service) in [
        ("api.example.test", "api_one"),
        ("api-two.example.test", "api_two"),
    ] {
        let mut input = request(Method::GET, "/domain", &authorization, Body::empty());
        input
            .headers_mut()
            .insert(HOST, HeaderValue::from_static(host));
        let response = crate::router::build_gateway_router(state.clone())
            .oneshot(input)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "http_fixture_missing"
        );
        assert_eq!(
            runtime.service_descriptor(service).unwrap().service,
            service
        );
        assert!(runtime.gateway_protocol(service).is_some());
    }
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn scoped_classification_requires_the_declared_resource_dimension() {
    let temp = crate::tests::test_temp_dir();
    let (runtime, _, _) = runtime_fixture("https://unused.example.test", &temp);
    let matched = MatchedGateway {
        service: "api_one".into(),
        config: runtime.gateway_config("api_one").unwrap().clone(),
    };
    let classified = classify_gateway_request(
        &runtime,
        &matched,
        &Method::GET,
        &"/scoped".parse().unwrap(),
        &HeaderMap::new(),
    )
    .unwrap();
    assert_eq!(classified.action, "scoped");
    assert_eq!(classified.resource_scopes["repository"], ["team/project"]);
    let error = classify_gateway_request(
        &runtime,
        &matched,
        &Method::GET,
        &"/scoped-missing".parse().unwrap(),
        &HeaderMap::new(),
    )
    .err()
    .unwrap();
    assert_eq!(
        error.reason_code(),
        ReasonCode::BrokerProviderContractFailed
    );
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
}

#[derive(Debug)]
struct RewriteHeader;
impl agent_access_provider::GatewayResponseValidator for RewriteHeader {
    fn validate(&self, _: u16, _: &HeaderMap) -> Result<HeaderMap, ProviderError> {
        Ok(HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static("text/invented"),
        )]))
    }
}
#[test]
fn response_validators_cannot_rewrite_upstream_values_or_select_reserved_headers() {
    let profile = GatewayResponseProfile::new(vec!["content-type".into()])
        .with_validator(Arc::new(RewriteHeader));
    let headers = HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("text/plain"))]);
    assert_eq!(
        selected_response_headers(&HTTP_FIXTURE, &profile, 200, &headers)
            .unwrap_err()
            .reason_code(),
        ReasonCode::BrokerProviderContractFailed
    );
    for name in [
        "authorization",
        "www-authenticate",
        "location",
        "set-cookie",
        "connection",
    ] {
        let profile = GatewayResponseProfile::new(vec![name.into()]);
        let plan = GatewayForwardPlan::new(
            Method::GET,
            "/items",
            agent_access_provider::test_support::gateway_body(vec![], 8),
        )
        .with_response(profile);
        assert_eq!(
            validate_forward_plan(
                &GatewayConfig::new("http_fixture", "API", "https://unused.example.test"),
                &Method::GET,
                &plan
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::BrokerProviderContractFailed
        );
    }
}

type TlsOrigin = (
    String,
    std::sync::mpsc::Sender<()>,
    tokio::task::JoinHandle<(Vec<u8>, bool)>,
);

fn tls_origin(response: Option<Vec<u8>>) -> TlsOrigin {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let (ready, request_ready) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || {
        if request_ready
            .recv_timeout(Duration::from_secs(300))
            .is_err()
        {
            return (Vec::new(), false);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream =
            rustls::StreamOwned::new(rustls::ServerConnection::new(tls_server()).unwrap(), stream);
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() <= 16 * 1024);
        }
        let mut body = Vec::new();
        if String::from_utf8_lossy(&head)
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    line.push(byte[0]);
                    assert!(line.len() < 64);
                }
                let len = usize::from_str_radix(
                    std::str::from_utf8(&line[..line.len() - 2]).unwrap(),
                    16,
                )
                .unwrap();
                assert!(len <= 1024);
                let mut part = vec![0; len];
                stream.read_exact(&mut part).unwrap();
                body.extend(part);
                let mut crlf = [0; 2];
                stream.read_exact(&mut crlf).unwrap();
                assert_eq!(&crlf, b"\r\n");
                if len == 0 {
                    break;
                }
            }
        }
        if let Some(response) = response {
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        }
        drop(stream);
        let deadline = Instant::now() + Duration::from_millis(150);
        let second = loop {
            match listener.accept() {
                Ok(_) => break true,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break false,
                Err(error) => panic!("fixture second accept: {error}"),
            }
        };
        (body, second)
    });
    (url, ready, worker)
}

#[tokio::test]
async fn framing_completion_needs_no_extra_body_poll_and_releases_capacity() {
    for (method, status, length, bytes) in [
        (Method::HEAD, 200, 4096, ""),
        (Method::GET, 204, 0, ""),
        (Method::GET, 304, 4096, ""),
        (Method::GET, 200, 0, ""),
        (Method::GET, 200, 4, "data"),
    ] {
        let temp = crate::tests::test_temp_dir();
        let response = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{bytes}").into_bytes();
        let (url, ready, upstream) = tls_origin(Some(response));
        let (runtime, state, authorization) = runtime_fixture(&url, &temp);
        ready.send(()).unwrap();
        let response = crate::router::build_gateway_router(state.clone())
            .oneshot(request(
                method.clone(),
                "/items",
                &authorization,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        if status != 204 {
            assert_eq!(response.headers()[CONTENT_LENGTH], length.to_string());
        }
        let mut body = response.into_body();
        if !bytes.is_empty() {
            let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
            assert_eq!(&frame[..], bytes.as_bytes());
            // Deliberately no EOF poll and no drop of the response body yet.
        }
        drop(state.shared_ingress.try_global_concurrency(1).unwrap());
        drop(
            state
                .shared_ingress
                .try_principal_concurrency("gateway-user", 1)
                .unwrap(),
        );
        runtime
            .shutdown_audit(Duration::from_secs(5))
            .await
            .unwrap();
        let records = agent_access_core::test_support::read_audit_records(
            agent_access_core::AuditStoreType::Jsonl,
            &temp.join("audit.jsonl"),
        );
        let terminal: Vec<_> = records
            .iter()
            .filter(|record| record["providerAudit"]["gateway"]["phase"] == "completed")
            .collect();
        assert_eq!(terminal.len(), 1, "{method} {status}: {records:?}");
        assert_eq!(
            terminal[0]["providerAudit"]["gateway"]["responseBytes"],
            bytes.len()
        );
        assert!(!upstream.await.unwrap().1);
        drop(body);
    }
}

#[tokio::test]
async fn ambiguous_zero_length_chunked_response_is_rejected() {
    assert_raw_response_framing(Some(0)).await;
}

#[tokio::test]
async fn ambiguous_short_length_chunked_response_is_rejected() {
    assert_raw_response_framing(Some(4)).await;
}

#[tokio::test]
async fn unambiguous_chunked_response_completes_with_all_bytes() {
    assert_raw_response_framing(None).await;
}

async fn assert_raw_response_framing(content_length: Option<usize>) {
    let temp = crate::tests::test_temp_dir();
    let length = content_length
        .map(|length| format!("Content-Length: {length}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 200 OK\r\n{length}Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n4\r\nmore\r\n5\r\n-data\r\n0\r\n\r\n"
    );
    let (url, ready, upstream) = tls_origin(Some(response.into_bytes()));
    let (runtime, state, authorization) = runtime_fixture(&url, &temp);
    ready.send(()).unwrap();
    let response = crate::router::build_gateway_router(state.clone())
        .oneshot(request(
            Method::GET,
            "/items",
            &authorization,
            Body::empty(),
        ))
        .await
        .unwrap();
    if content_length.is_some() {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "upstream_protocol_failed"
        );
    } else {
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(CONTENT_LENGTH));
    }
    assert!(!response.headers().contains_key("transfer-encoding"));
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    if content_length.is_some() {
        assert!(!String::from_utf8_lossy(&body).contains("more-data"));
    } else {
        assert_eq!(&body[..], b"more-data");
    }
    let (request_body, replayed) = upstream.await.unwrap();
    assert!(request_body.is_empty());
    assert!(
        !replayed,
        "response framing failure must never replay a request"
    );
    drop(state.shared_ingress.try_global_concurrency(1).unwrap());
    drop(
        state
            .shared_ingress
            .try_principal_concurrency("gateway-user", 1)
            .unwrap(),
    );
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = agent_access_core::test_support::read_audit_records(
        agent_access_core::AuditStoreType::Jsonl,
        &temp.join("audit.jsonl"),
    );
    let lifecycle: Vec<_> = records
        .iter()
        .filter(|record| record["providerAudit"]["gateway"]["phase"].is_string())
        .collect();
    assert_eq!(lifecycle.len(), 2, "{records:?}");
    assert_eq!(lifecycle[0]["providerAudit"]["gateway"]["phase"], "started");
    let terminal = lifecycle[1];
    assert_eq!(terminal["upstreamStatus"], 200);
    if content_length.is_some() {
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
        assert_eq!(terminal["reasonCode"], "upstream_protocol_failed");
        assert_eq!(terminal["decision"], "error");
        assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 0);
    } else {
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "completed");
        assert_eq!(terminal["decision"], "allow");
        assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 9);
    }
}

#[tokio::test]
async fn a_committed_request_with_lost_response_is_never_replayed() {
    let temp = crate::tests::test_temp_dir();
    let (url, ready, upstream) = tls_origin(None);
    let (runtime, state, authorization) = runtime_fixture(&url, &temp);
    ready.send(()).unwrap();
    let response = crate::router::build_gateway_router(state.clone())
        .oneshot(request(
            Method::POST,
            "/items",
            &authorization,
            Body::from("data"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    // This buffered local error still owns delivery until the client consumes it.
    let _ = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let (body, second_attempt) = upstream.await.unwrap();
    assert_eq!(body, b"data");
    assert!(!second_attempt);
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let records = agent_access_core::test_support::read_audit_records(
        agent_access_core::AuditStoreType::Jsonl,
        &temp.join("audit.jsonl"),
    );
    let terminal: Vec<_> = records
        .iter()
        .filter(|record| record["providerAudit"]["gateway"]["phase"] == "failed")
        .collect();
    assert_eq!(terminal.len(), 1, "{records:?}");
    assert_eq!(terminal[0]["providerAudit"]["gateway"]["requestBytes"], 4);
    drop(state.shared_ingress.try_global_concurrency(1).unwrap());
}

#[test]
fn bounded_retry_after_is_owned_by_the_host_only_on_429() {
    let profile = GatewayResponseProfile::new(vec!["retry-after".into()]).bounded_retry_after();
    let headers = HeaderMap::from_iter([(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from_static("999999999"),
    )]);
    assert!(
        !selected_response_headers(&HTTP_FIXTURE, &profile, 503, &headers)
            .unwrap()
            .contains_key(axum::http::header::RETRY_AFTER)
    );
    assert_eq!(
        selected_response_headers(&HTTP_FIXTURE, &profile, 429, &headers).unwrap()
            [axum::http::header::RETRY_AFTER],
        "86400"
    );
}

#[tokio::test]
async fn unlinked_gateway_reload_preserves_the_current_instance_and_unsupported_probes_fail_locally()
 {
    let temp = crate::tests::test_temp_dir();
    let (runtime, state, authorization) = runtime_fixture("https://unused.example.test", &temp);
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".into(),
        None,
        None,
        vec![],
        None,
        None,
    );
    let unsupported = runtime
        .preflight_execution_credential_verification(
            "api_one",
            &identity,
            agent_access_core::CredentialVerificationInput::default(),
        )
        .unwrap_err();
    assert_eq!(unsupported.reason_code(), ReasonCode::ServiceActionDenied);
    assert!(
        unsupported
            .message
            .contains("no eligible credential verification consumer")
    );
    let previous = state.current();
    let mut candidate = runtime.config().clone();
    candidate.gateways.get_mut("api_one").unwrap().kind = "unlinked_gateway".into();
    let error = agent_access_core::validate_broker_config(&candidate).unwrap_err();
    assert!(
        error
            .errors()
            .iter()
            .any(|error| error.contains("not selected in this assembly")),
        "{error:?}"
    );
    std::fs::write(
        &state.config_path,
        crate::tests::ConfigDoc::from_config(&candidate).render(),
    )
    .unwrap();
    let failed = state.reload_from_signal().await;
    assert_ne!(failed.status, 200);
    assert!(Arc::ptr_eq(&previous, &state.current()));
    let response = crate::router::build_gateway_router(state.clone())
        .oneshot(request(
            Method::GET,
            "/domain",
            &authorization,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "http_fixture_missing"
    );
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap();
}

#[test]
fn protocol_audit_facts_cannot_assert_host_lifecycle_or_credential_fields() {
    let facts = json!({"phase":"forged","message":"forged","credentialMethod":"forged","durationMs":999,
        "upstreamStatus":999,"requestBytes":999,"responseBytes":999,"transferOutcome":"forged", "source":"fixture"});
    let audit = gateway_forward_audit(
        &Method::GET,
        &Url::parse("https://example.test/items").unwrap(),
        json!({"mode":"direct"}),
        4,
        GatewayAuditDetails {
            kind: "fixture_http".into(),
            key: "gateway".into(),
            facts: Some(facts),
            path: "/items".into(),
            request_bytes: Arc::new(AtomicU64::new(0)),
        },
    );
    assert_eq!(audit["gateway"]["source"], "fixture");
    assert_eq!(audit["gateway"]["responseBytes"], 4);
    assert_eq!(audit["gateway"]["requestBytes"], 0);
    for key in [
        "phase",
        "message",
        "credentialMethod",
        "durationMs",
        "upstreamStatus",
        "transferOutcome",
    ] {
        assert!(audit["gateway"].get(key).is_none(), "{key}");
    }
}
