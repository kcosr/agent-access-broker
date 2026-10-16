//! Delegated OAuth through the broker's HTTP surface, against a stubbed
//! authorization server and records API.
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenIssueRequest, BrokerTokensConfig, BrowserAuthConfig,
    CredentialEncryptionConfig, CredentialEncryptionKeyConfig, LocalPasswordConfig,
    LocalPasswordWriteRequest, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode,
    ManagementConfig, RightGrantRequest,
};
use agent_access_core::{
    ExecutionContext, GovernedOperationContext, InvokeRequest, OperationContext,
};
use agent_access_provider::{OAuthAdapter, OAuthPermissionProfile, OAuthRegistrationConfig};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use wiremock::matchers::{body_string_contains, header as header_is, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "oauth/delegated_lookups.rs"]
mod delegated_lookups;
#[path = "oauth/gitlab_dialect.rs"]
mod gitlab_dialect;
#[path = "oauth/gitlab_gateway.rs"]
mod gitlab_gateway;
#[path = "oauth/gitlab_rest.rs"]
mod gitlab_rest;
#[path = "oauth/token_only.rs"]
mod token_only;

const SOURCE: &str = "127.0.0.1:43200";

struct OAuthFixture {
    _dir: tempfile::TempDir,
    broker: TestBroker,
    config: BrokerConfig,
    audit_path: PathBuf,
    runtime: BrokerRuntime,
    app: Router,
    server: MockServer,
    cookie: String,
    csrf: String,
    agent_token: String,
}

async fn oauth_fixture() -> OAuthFixture {
    oauth_fixture_with_subject(Some("user:alice")).await
}

async fn oauth_fixture_with_subject(subject: Option<&str>) -> OAuthFixture {
    oauth_fixture_with(subject, |_, _| {}, Vec::new()).await
}

/// The OAuth fixture after `setup` adjusts its configuration, with
/// `providers` serving their configured services.
async fn oauth_fixture_with(
    subject: Option<&str>,
    setup: impl FnOnce(&Path, &mut BrokerConfig),
    providers: Vec<agent_access_provider::ServiceProvider>,
) -> OAuthFixture {
    let dir = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let write = |name: &str, contents: String| {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    };
    let hash_key = write("hash-key", URL_SAFE_NO_PAD.encode([21_u8; 32]));
    let csrf_key = write("csrf-key", URL_SAFE_NO_PAD.encode([22_u8; 32]));
    let pepper = write("pepper", URL_SAFE_NO_PAD.encode([23_u8; 32]));
    let encryption_key = write("encryption-key", URL_SAFE_NO_PAD.encode([24_u8; 32]));
    let client_secret = write("client-secret", "stub-client-secret".into());
    let server = MockServer::start().await;

    let audit_path = dir.path().join("audit.sqlite");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity.mode = "required".into();
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
        path: dir.path().join("store.sqlite").display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = ManagementConfig {
        enabled: true,
        ..ManagementConfig::default()
    };
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        default_user_manage_ttl: Some("8h".into()),
        max_self_issued_agent_invoke_ttl: Some("30d".into()),
        ..BrokerTokensConfig::default()
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "k1".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "k1".into(),
            provider: "file".into(),
            env: None,
            path: Some(encryption_key.display().to_string()),
        }],
    });
    config.browser_auth = BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://127.0.0.1".into()),
        session_cookie_name: "aab_session".into(),
        csrf_header: "X-Agent-Access-CSRF".into(),
        csrf_key_ref: Some(format!("file:{}", csrf_key.display())),
        session_ttl: "8h".into(),
        allowed_return_paths: vec!["/ui".into()],
        local_password: LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(format!("file:{}", pepper.display())),
            min_password_length: 8,
            max_failed_attempts: 3,
            lockout_ttl: "15m".into(),
        },
        oidc: Default::default(),
    };
    config.oauth.registrations.insert(
        "stub".into(),
        OAuthRegistrationConfig {
            login_binding: None,
            adapter_settings: Default::default(),
            adapter: OAuthAdapter::new("stub"),
            base_url: server.uri(),
            redirect_uri: "http://127.0.0.1/v1/oauth/callback/stub".into(),
            client_id: "broker".into(),
            client_secret_ref: format!("file:{}", client_secret.display()),
            client_auth: Default::default(),
            encoding: Default::default(),
            rotation: Default::default(),
            allow_insecure_loopback: true,
            permission_profiles: BTreeMap::from([(
                "read".into(),
                OAuthPermissionProfile {
                    scope_mode: agent_access_provider::OAuthScopeMode::Explicit,
                    scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                    audience: "records-api".into(),
                    target: "workspace-one".into(),
                },
            )]),
        },
    );
    // The records API and the authorization server are the same test server.
    config
        .providers
        .insert(agent_access_fake::OAuthStubProviderConfig {
            base_url: server.uri(),
        });
    config.credentials.connections.insert(
        "oauth_stub".into(),
        agent_access_core::ConnectionConfig {
            display_name: None,
            token_profile: None,
            oauth: Some(agent_access_core::ConnectionOAuthConfig {
                registration: "stub".into(),
                profile: "read".into(),
            }),
        },
    );
    config.credentials.per_user.insert(
        "oauth_stub".into(),
        super::connection_credential("oauth_stub"),
    );
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["default".into(), "setup-only".into()],
        default_context: Some("default".into()),
    });
    setup(dir.path(), &mut config);

    let store = ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "admin".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    if let Some(group) = subject.and_then(|value| value.strip_prefix("group:")) {
        store
            .create_group(agent_access_core::GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                created_by: "test".into(),
            })
            .unwrap();
        store.add_group("alice", group, "test").unwrap();
    }
    let broker = start_oauth_broker(&config, providers).await;
    let runtime = broker.runtime();
    if let Some(subject) = subject {
        runtime
            .create_managed_policy_grant(agent_access_core::ManagedPolicyGrantCreateRequest {
                grant_id: Some("personal-oauth".into()),
                subjects: vec![subject.into()],
                service: "oauth_stub".into(),
                actions: vec!["account.view".into()],
                resources: ResourceSelection::default(),
                execution_contexts: vec!["default".into()],
                credential_mode: "per_user".into(),
                priority: None,
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    store
        .enable_local_password(
            runtime.local_password_hasher().unwrap(),
            LocalPasswordWriteRequest {
                principal_id: "alice".into(),
                password: "alice-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "test".into(),
            },
        )
        .unwrap();
    let agent_token = store
        .issue_broker_token(
            runtime.broker_token_hasher().unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "oauth agent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token;
    let app = broker.app();
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/local/login")
                .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
                .header(REQUEST_ID_HEADER, "oauth-fixture-login")
                .header("Host", "127.0.0.1")
                .header("Origin", "http://127.0.0.1")
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
        .to_string();
    let csrf = response_json(login).await["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    OAuthFixture {
        _dir: dir,
        broker,
        config,
        audit_path,
        runtime,
        app,
        server,
        cookie,
        csrf,
        agent_token,
    }
}

/// `config`'s broker serving `providers`, with a gateway listener when it
/// configures gateways. A Microsoft sign-in it enables is never reached:
/// tests link Microsoft login methods in the store.
async fn start_oauth_broker(
    config: &BrokerConfig,
    providers: Vec<agent_access_provider::ServiceProvider>,
) -> TestBroker {
    let mut application = TestBroker::config_builder(config);
    if !config.gateways.is_empty() {
        application = application
            .gateway_listener()
            .expect("loopback gateway listener");
    }
    if config.browser_auth.oidc.microsoft.enabled {
        application = application.microsoft_oidc_components(
            Arc::new(UnreachableMicrosoft),
            Arc::new(agent_access_core::microsoft_oidc::SystemMicrosoftOidcClock),
        );
    }
    TestBroker::start_with(with_provider_instances(application, providers)).await
}

/// A Microsoft sign-in transport that fails every request without sending.
struct UnreachableMicrosoft;

impl crate::state::MicrosoftOidcTransport for UnreachableMicrosoft {
    fn call<'a>(
        &'a self,
        _: openidconnect::HttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        openidconnect::HttpResponse,
                        crate::state::MicrosoftOidcTransportError,
                    >,
                > + Send
                + Sync
                + 'a,
        >,
    > {
        Box::pin(async { Err(crate::state::MicrosoftOidcTransportError) })
    }
}

impl OAuthFixture {
    async fn browser(
        &self,
        method: Method,
        uri: &str,
        request_id: &str,
        body: Option<Value>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
            .header("Cookie", &self.cookie)
            .header("X-Agent-Access-CSRF", &self.csrf)
            .header("Host", "127.0.0.1")
            .header("Origin", "http://127.0.0.1")
            .header(CONTENT_TYPE, "application/json");
        if !request_id.is_empty() {
            request = request.header(REQUEST_ID_HEADER, request_id);
        }
        self.app
            .clone()
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Connects alice's account through the browser consent flow, completing
    /// the callback with `callback_request_id` (empty for none).
    async fn connect(&self, callback_request_id: &str) {
        self.connect_expiring(callback_request_id, 3600).await;
    }

    /// [`Self::connect`] with first access that expires in `expires_in`
    /// seconds.
    async fn connect_expiring(&self, callback_request_id: &str, expires_in: u64) {
        self.mock_consent("records.read offline_access", expires_in)
            .await;
        let state = self.begin_consent("oauth-connect").await;
        let callback = self.finish_consent(&state, callback_request_id).await;
        assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    }

    async fn mock_consent(&self, scopes: &str, expires_in: u64) {
        let mut grant = token(1, expires_in);
        grant["scope"] = json!(scopes);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(grant))
            .mount(&self.server)
            .await;
        // Only the consent flow's identity check; each test serves the
        // records API's `/me` itself.
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": "alice", "name": "Alice"})),
            )
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"targets": [{
                    "id": "workspace-one",
                    "name": "One",
                    "audience": "records-api",
                    "scopes": ["records.read"]
                }]})),
            )
            .mount(&self.server)
            .await;
    }

    async fn begin_consent(&self, request_id: &str) -> String {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                request_id,
                Some(json!({"registration": "stub", "intent": "connect"})),
            )
            .await;
        let status = connect.status();
        let connect = response_json(connect).await;
        assert_eq!(status, StatusCode::OK, "{connect}");
        let authorization_url =
            url::Url::parse(connect["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        authorization_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned()
    }

    async fn finish_consent(&self, state: &str, request_id: &str) -> axum::response::Response {
        self.browser(
            Method::GET,
            &format!(
                "/v1/oauth/callback/stub?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", state)
                    .append_pair("code", "one-use-code")
                    .append_pair("iss", &self.server.uri())
                    .finish()
            ),
            request_id,
            None,
        )
        .await
    }
}

async fn assert_completion_page(
    response: axum::response::Response,
    heading: &str,
    secrets: &[&str],
) {
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(headers.get("location").is_none());
    assert_eq!(headers["content-type"], "text/html; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    let csp = headers["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    let nonce = csp
        .split("script-src 'nonce-")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    assert!(csp.contains(&format!("style-src 'nonce-{nonce}'")));
    let body = axum::body::to_bytes(response.into_body(), 16_384)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains(&format!("<script nonce=\"{nonce}\">")));
    assert!(html.contains(&format!("<style nonce=\"{nonce}\">")));
    assert!(html.contains(&format!("<h1>{heading}</h1>")));
    assert!(
        html.contains("href=\"/ui/credentials\" target=\"_blank\" rel=\"noopener noreferrer\"")
    );
    for secret in secrets {
        assert!(
            !html.contains(secret),
            "callback value leaked into completion HTML"
        );
    }
}

#[tokio::test]
async fn callback_errors_have_safe_distinct_completions_and_replay_is_rejected() {
    for (provider_error, heading) in [
        ("access_denied", "Authorization canceled"),
        ("server_error", "Authorization was not completed"),
        (
            "untrusted-provider-error",
            "Authorization was not completed",
        ),
    ] {
        let f = oauth_fixture().await;
        let response = f
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "start-cancel",
                Some(json!({"registration": "stub", "intent":"connect"})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = response_json(response).await;
        let url =
            url::Url::parse(response["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let path = format!(
            "/v1/oauth/callback/stub?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &state)
                .append_pair("error", provider_error)
                .append_pair(
                    "error_description",
                    "<script>untrusted-provider-text</script>"
                )
                .append_pair("iss", &f.server.uri())
                .finish()
        );
        let response = f.browser(Method::GET, &path, "cancel-consent", None).await;
        assert_completion_page(
            response,
            heading,
            &[&state, "untrusted-provider-text", provider_error],
        )
        .await;
        let replay = f.browser(Method::GET, &path, "replay-consent", None).await;
        assert!(!replay.status().is_success());
        assert_eq!(replay.headers()["content-type"], "application/json");
        assert_eq!(response_json(replay).await["ok"], false);
        let invalid = f
            .browser(
                Method::GET,
                "/v1/oauth/callback/stub?state=unknown&code=invalid",
                "invalid-consent",
                None,
            )
            .await;
        assert!(!invalid.status().is_success());
        assert_eq!(invalid.headers()["content-type"], "application/json");
        assert_eq!(response_json(invalid).await["ok"], false);
    }
}

#[tokio::test]
async fn query_free_callback_is_an_authenticated_neutral_read_without_consent_audit() {
    let f = oauth_fixture().await;
    let denied = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/oauth/callback/stub")
                .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!denied.status().is_success());
    let audit_before = read_audit_records(&f.audit_path);
    let response = f
        .browser(
            Method::GET,
            "/v1/oauth/callback/stub",
            "neutral-before-consent",
            None,
        )
        .await;
    assert_completion_page(response, "Check connection status", &[]).await;
    assert_eq!(read_audit_records(&f.audit_path), audit_before);
    // With no pending flow it reports no outcome; after a real success it is
    // still a neutral read and must neither replay consent nor add failure audit.
    f.connect("authorize-before-reload").await;
    let audit_before = read_audit_records(&f.audit_path);
    let status_before = f
        .runtime
        .oauth_manager()
        .unwrap()
        .status("alice", "stub")
        .unwrap();
    let response = f
        .browser(
            Method::GET,
            "/v1/oauth/callback/stub",
            "neutral-after-consent",
            None,
        )
        .await;
    assert_completion_page(response, "Check connection status", &[]).await;
    assert_eq!(read_audit_records(&f.audit_path), audit_before);
    assert_eq!(
        f.runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id,
        status_before.connection_id
    );
    // Any supplied callback input still requires a valid flow and follows the
    // normal audited error path. This is not a missing-state success exception.
    let invalid = f
        .browser(
            Method::GET,
            "/v1/oauth/callback/stub?code=missing-state",
            "missing-state",
            None,
        )
        .await;
    assert!(!invalid.status().is_success());
    assert_eq!(response_json(invalid).await["ok"], false);
    assert!(read_audit_records(&f.audit_path).len() > audit_before.len());
}

impl OAuthFixture {
    /// Serves `/me` (the stub's account endpoint) to `access_token` with
    /// `status`.
    async fn account(&self, access_token: &str, status: u16) {
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header_is(
                "authorization",
                format!("Bearer {access_token}").as_str(),
            ))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"id": "alice", "name": "Alice"})),
            )
            .mount(&self.server)
            .await;
    }

    /// Answers refresh-token grants with access token 2.
    async fn refreshes(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(2, 3600)))
            .with_priority(1)
            .mount(&self.server)
            .await;
    }

    async fn invoke(&self, action: &str, request_id: &str, inputs: Value) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app.clone(),
            Method::POST,
            format!("/v1/invoke/oauth_stub/{action}"),
            request_id,
            "Authorization",
            format!("Bearer {}", self.agent_token),
            Some(&json!({"inputs": inputs}).to_string()),
        )
        .await;
        (response.status(), response_json(response).await)
    }

    /// Upstream requests after the three of the consent flow.
    async fn requests_after_consent(&self) -> Vec<wiremock::Request> {
        self.server.received_requests().await.unwrap().split_off(3)
    }
}

fn token(number: u32, expires_in: u64) -> Value {
    json!({
        "access_token": format!("stub-access-{number}"),
        "refresh_token": format!("stub-refresh-{number}"),
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "records.read offline_access"
    })
}

fn header<'a>(request: &'a wiremock::Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn consent_callback_requests_carry_the_callback_correlation() {
    let fixture = oauth_fixture().await;
    fixture.connect("oauth-callback-supplied").await;
    let requests = fixture.server.received_requests().await.unwrap();
    let paths: Vec<_> = requests.iter().map(|request| request.url.path()).collect();
    assert_eq!(paths, ["/oauth/token", "/me", "/targets"]);
    let broker_request_ids: BTreeSet<_> = requests
        .iter()
        .map(|request| {
            assert_eq!(
                header(request, REQUEST_ID_HEADER),
                Some("oauth-callback-supplied")
            );
            header(request, BROKER_REQUEST_ID_HEADER)
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(broker_request_ids.len(), 1);
}

#[tokio::test]
async fn consent_callback_without_a_request_id_correlates_with_a_generated_one() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    let requests = fixture.server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let agent_request_ids: BTreeSet<_> = requests
        .iter()
        .map(|request| header(request, REQUEST_ID_HEADER).unwrap().to_owned())
        .collect();
    assert_eq!(agent_request_ids.len(), 1);
    assert!(agent_request_ids.first().unwrap().starts_with("oauth-"));
}

#[tokio::test]
async fn delegated_invocations_present_the_callers_connection() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture.account("stub-access-1", 200).await;

    let (status, body) = fixture
        .invoke("account.view", "invoke-account", json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["id"], "alice");
    let requests = fixture.requests_after_consent().await;
    assert_eq!(requests.len(), 1);
    let records = &requests[0];
    assert_eq!(records.url.path(), "/me");
    assert_eq!(header(records, "x-stub-target"), Some("workspace-one"));
    assert_eq!(header(records, "x-stub-audience"), Some("records-api"));
    assert_eq!(header(records, REQUEST_ID_HEADER), Some("invoke-account"));
}

#[tokio::test]
async fn unauthorized_access_is_replaced_once_and_retried() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture.account("stub-access-1", 401).await;
    fixture.account("stub-access-2", 200).await;
    fixture.refreshes().await;

    let (status, body) = fixture
        .invoke("account.view", "invoke-recovered", json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["id"], "alice");
    let requests = fixture.requests_after_consent().await;
    let refreshes = requests
        .iter()
        .filter(|request| request.url.path() == "/oauth/token")
        .count();
    assert_eq!(refreshes, 1);
    for request in &requests {
        assert_eq!(header(request, REQUEST_ID_HEADER), Some("invoke-recovered"));
    }
    let last = requests.last().unwrap();
    assert_eq!(last.url.path(), "/me");
    assert_eq!(header(last, "authorization"), Some("Bearer stub-access-2"));
}

#[tokio::test]
async fn denied_invocations_never_refresh_the_connection() {
    let fixture = oauth_fixture().await;
    fixture.connect_expiring("", 1).await;
    fixture.account("stub-access-2", 200).await;
    fixture.refreshes().await;
    // The first access is now due for refresh.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let (status, body) = fixture
        .invoke(
            "record.list",
            "invoke-denied",
            json!({"collection": "alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(fixture.requests_after_consent().await.is_empty());

    let (status, body) = fixture
        .invoke("account.view", "invoke-refreshed", json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let requests = fixture.requests_after_consent().await;
    assert_eq!(requests[0].url.path(), "/oauth/token");
}

#[tokio::test]
async fn pending_consent_blocks_delegated_invocations() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture.account("stub-access-1", 200).await;
    let reconnect = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "oauth-reconnect",
            Some(json!({"registration": "stub", "intent": "reconnect"})),
        )
        .await;
    assert_eq!(reconnect.status(), StatusCode::OK);

    let (status, body) = fixture
        .invoke("account.view", "invoke-pending", json!({}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reasonCode"], "version_conflict");
    assert!(fixture.requests_after_consent().await.is_empty());
}

#[tokio::test]
async fn dispatch_rechecks_access_lent_at_preparation() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture.account("stub-access-1", 200).await;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", fixture.agent_token).parse().unwrap(),
    );
    let identity = fixture.runtime.resolve_identity(&headers).unwrap();
    let Ok(prepared) = fixture
        .runtime
        .begin_invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "prepared-account".into(),
                    broker_request_id: "broker-prepared-account".into(),
                    identity,
                    service: "oauth_stub".into(),
                    action: "account.view".into(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new("default").unwrap(),
            },
            InvokeRequest::new(json!({})),
        )
        .await
    else {
        panic!("preparation acquires the connection's access");
    };
    let disconnect = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "oauth-disconnect",
            None,
        )
        .await;
    assert_eq!(disconnect.status(), StatusCode::OK);

    let response = fixture
        .runtime
        .finish_prepared_invoke(prepared, Vec::new())
        .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::CredentialInvalid.into())
    );
    assert!(fixture.requests_after_consent().await.is_empty());
}

/// Completing a connection is audited (preflight and outcome); listing
/// connections is an unaudited read.
#[tokio::test]
async fn callbacks_are_audited_and_connection_lists_are_not() {
    let fixture = oauth_fixture().await;
    fixture.connect("oauth-audited-callback").await;
    let response = fixture
        .browser(
            Method::GET,
            "/v1/oauth/connections",
            "oauth-quiet-list",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let records = read_audit_records(&fixture.audit_path);
    let callback = records
        .iter()
        .filter(|record| {
            record["agentRequestId"] == "oauth-audited-callback"
                && record["action"] == "oauth.connections.callback"
        })
        .map(|record| record["providerAudit"]["management"]["phase"].clone())
        .collect::<Vec<_>>();
    assert_eq!(callback, [json!("preflight"), Value::Null], "{records:?}");
    assert!(
        records
            .iter()
            .all(|record| record["action"] != "oauth.connections.list")
    );
}

/// One row per registration names the consumers the user may set up
/// through, with their display names, and the description the backend
/// declares.
#[tokio::test]
async fn connection_rows_describe_services_from_their_descriptors() {
    let fixture = oauth_fixture().await;
    let response = fixture
        .browser(Method::GET, "/v1/oauth/connections", "oauth-list", None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let rows = response_json(response).await["result"].clone();
    let descriptor = fixture.runtime.service_descriptor("oauth_stub").unwrap();
    let connection = descriptor.credentials.delegated.as_ref().unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["registration"], "stub");
    // The connection has no configured display name: it shows its ID.
    assert_eq!(rows[0]["displayName"], "oauth_stub");
    assert_eq!(
        rows[0]["consumers"],
        json!([{"service": "oauth_stub", "displayName": descriptor.display_name,
            "credentialVerificationInputs": []}])
    );
    assert_eq!(rows[0]["otherConsumers"], 0);
    assert_eq!(rows[0]["connectionDescription"], connection.description);
    assert_eq!(rows[0]["canConnect"], true);
    assert_eq!(rows[0]["connectUnavailableReason"], Value::Null);
    assert_eq!(rows[0]["canDisconnect"], false);
}

/// A connection that selects OAuth for its user stores no token: the token
/// routes refuse it and point to the OAuth connection routes.
#[tokio::test]
async fn oauth_connections_refuse_stored_tokens() {
    let fixture = oauth_fixture().await;
    for (method, uri, body) in [
        (
            Method::PUT,
            "/v1/credentials/connections/oauth_stub",
            Some(json!({"secret": {"token": "not-a-connection-token"}})),
        ),
        (
            Method::GET,
            "/v1/credentials/connections/oauth_stub/input-schema",
            None,
        ),
    ] {
        let response = fixture
            .browser(method.clone(), uri, "oauth-token-refused", body)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = response_json(response).await;
        assert_eq!(body["reasonCode"], "input_invalid", "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("uses OAuth"),
            "{body}"
        );
    }
    let response = fixture
        .browser(Method::GET, "/v1/credentials", "oauth-token-list", None)
        .await;
    let list = response_json(response).await;
    let row = &list["result"]["connections"][0];
    assert_eq!(row["connection"], "oauth_stub", "{list}");
    assert_eq!(row["method"], "oauth");
    assert_eq!(row["registration"], "stub");
    assert_eq!(row["credential"], Value::Null);
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_credentials(Some("alice"))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn oauth_setup_accepts_direct_and_current_group_grants_without_rights() {
    for subject in ["user:alice", "group:readers"] {
        let fixture = oauth_fixture_with_subject(Some(subject)).await;
        fixture.connect("").await;
        assert!(
            fixture
                .runtime
                .oauth_manager()
                .unwrap()
                .status("alice", "stub")
                .unwrap()
                .connection_id
                .is_some()
        );
        if subject.starts_with("group:") {
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .remove_group("alice", "readers")
                .unwrap();
            let response = fixture
                .browser(
                    Method::POST,
                    "/v1/oauth/connect",
                    "group-lost",
                    Some(json!({"registration": "stub","intent":"reconnect"})),
                )
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = response_json(response).await;
            assert_eq!(body["reasonCode"], "service_action_denied");
            assert_eq!(body["error"]["message"], "oauth_setup_denied");
        }
    }
}

#[tokio::test]
async fn oauth_rights_without_personal_grants_do_not_allow_setup_or_expose_empty_rows() {
    for service in [Some("oauth_stub"), None] {
        let fixture = oauth_fixture_with_subject(None).await;
        for right in [
            "credentials:self:write",
            "credentials:self:read_metadata",
            "credentials:self:delete",
        ] {
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .grant_right(RightGrantRequest {
                    principal_id: "alice".into(),
                    right: right.into(),
                    service: service.map(str::to_owned),
                    credential_name: None,
                    resource_scope_json: None,
                    created_by: "admin".into(),
                    expires_at: None,
                    reason: None,
                })
                .unwrap();
        }
        let response = fixture
            .browser(Method::GET, "/v1/oauth/connections", "rights-list", None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["result"], json!([]));
        let response = fixture
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "rights-connect",
                Some(json!({"registration": "stub","intent":"connect"})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response_json(response).await;
        assert_eq!(body["reasonCode"], "service_action_denied");
        assert_eq!(body["error"]["message"], "oauth_setup_denied");
        assert!(fixture.server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn oauth_setup_does_not_require_matching_resources_or_execution_context() {
    let fixture = oauth_fixture_with_subject(None).await;
    fixture
        .runtime
        .create_managed_resource_group(agent_access_core::CreateResourceGroupRequest {
            id: Some("empty-collections".into()),
            name: "Empty collections".into(),
            included_resource_ids: vec![],
            excluded_resource_ids: vec![],
            created_by: "admin".into(),
        })
        .unwrap();
    fixture
        .runtime
        .create_managed_policy_grant(agent_access_core::ManagedPolicyGrantCreateRequest {
            grant_id: Some("prepare-account".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["setup-only".into()],
            service: "oauth_stub".into(),
            actions: vec!["record.list".into()],
            resources: ResourceSelection {
                resource_ids: vec![],
                resource_group_ids: vec!["empty-collections".into()],
            },
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    fixture.connect("").await;
    let (status, body) = fixture
        .invoke(
            "record.list",
            "resource-context-denied",
            json!({"collection":"alpha"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(fixture.requests_after_consent().await.is_empty());
}

#[tokio::test]
async fn oauth_owned_connection_remains_visible_and_disconnectable_after_grant_loss() {
    let fixture = oauth_fixture().await;
    fixture.connect("").await;
    fixture
        .runtime
        .disable_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
            grant_id: "personal-oauth".into(),
            expected_version: 1,
            updated_by: "admin".into(),
        })
        .unwrap();
    let response = fixture
        .browser(Method::GET, "/v1/oauth/connections", "cleanup-list", None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let rows = response_json(response).await["result"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["canConnect"], false);
    assert_eq!(rows[0]["connectUnavailableReason"], "no_personal_access");
    assert_eq!(rows[0]["canDisconnect"], true);
    assert!(rows[0]["connection"]["connectionId"].is_string());
    let response = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "cleanup-no-reconnect",
            Some(json!({"registration": "stub","intent":"reconnect"})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "service_action_denied");
    assert_eq!(body["error"]["message"], "oauth_setup_denied");
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "cleanup-disconnect",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"],
        json!({"disconnected":true,"remoteRevocation":"not_requested"})
    );
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "cleanup-disconnect-again",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"],
        json!({"disconnected":true,"remoteRevocation":"not_requested"})
    );
    let response = fixture
        .browser(
            Method::GET,
            "/v1/oauth/connections",
            "cleanup-complete",
            None,
        )
        .await;
    assert_eq!(response_json(response).await["result"], json!([]));
    assert!(fixture.requests_after_consent().await.is_empty());
}

/// An owned connection stays listed for local disconnect after its
/// registration loses its last selecting consumer, whether the consumer is
/// removed or rebound to another registration.
#[tokio::test]
async fn owned_connections_outlive_their_last_selecting_consumer() {
    for rebind in [false, true] {
        let fixture = oauth_fixture().await;
        fixture.connect("").await;
        let mut changed = fixture.config.clone();
        // Reload admission needs every configured service credential; the
        // fixture's development service credential names an unset variable.
        changed.credentials.service.remove("fake");
        if rebind {
            let mut registration = changed.oauth.registrations["stub"].clone();
            registration.redirect_uri = registration
                .redirect_uri
                .replace("/callback/stub", "/callback/stub_two");
            changed
                .oauth
                .registrations
                .insert("stub_two".into(), registration);
            changed
                .credentials
                .connections
                .get_mut("oauth_stub")
                .unwrap()
                .oauth
                .as_mut()
                .unwrap()
                .registration = "stub_two".into();
        } else {
            fixture
                .runtime
                .delete_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
                    grant_id: "personal-oauth".into(),
                    expected_version: 1,
                    updated_by: "admin".into(),
                })
                .unwrap();
            changed.credentials.per_user.remove("oauth_stub");
            changed.credentials.connections.remove("oauth_stub");
        }
        fixture.broker.reload_config(&changed).await;
        let response = fixture
            .browser(Method::GET, "/v1/oauth/connections", "orphan-list", None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let rows = response_json(response).await["result"].clone();
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["registration"] == "stub")
            .unwrap_or_else(|| panic!("rebind={rebind}: {rows}"))
            .clone();
        assert_eq!(row["displayName"], "stub");
        // No binding names its profile any more; none is invented.
        assert_eq!(row["permissionProfile"], Value::Null);
        assert_eq!(row["scopeMode"], Value::Null);
        assert_eq!(row["target"], Value::Null);
        assert_eq!(row["requestedScopes"], json!([]));
        assert_eq!(row["consumers"], json!([]));
        assert_eq!(row["otherConsumers"], 0);
        assert_eq!(row["connectionDescription"], Value::Null);
        assert_eq!(row["canConnect"], false);
        assert_eq!(row["connectUnavailableReason"], "no_personal_access");
        assert_eq!(row["canDisconnect"], true);
        assert!(row["connection"]["connectionId"].is_string());
        let response = fixture
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "orphan-reconnect",
                Some(json!({"registration": "stub", "intent": "reconnect"})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = fixture
            .browser(
                Method::DELETE,
                "/v1/oauth/connections/stub",
                "orphan-disconnect",
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await["result"],
            json!({"disconnected":true,"remoteRevocation":"not_requested"})
        );
        let response = fixture
            .browser(Method::GET, "/v1/oauth/connections", "orphan-gone", None)
            .await;
        let rows = response_json(response).await["result"].clone();
        assert!(
            rows.as_array()
                .unwrap()
                .iter()
                .all(|row| row["registration"] != "stub"),
            "rebind={rebind}: {rows}"
        );
        assert!(fixture.requests_after_consent().await.is_empty());
    }
}

/// A refresh failure clears the cached access but keeps the owned
/// connection; once its last selecting consumer is removed it is still
/// listed, on ownership alone, and can be disconnected.
#[tokio::test]
async fn owned_connections_without_cached_access_stay_listed_after_their_last_consumer() {
    let fixture = oauth_fixture().await;
    fixture.connect_expiring("", 1).await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .with_priority(1)
        .mount(&fixture.server)
        .await;
    // The access is now due for refresh, which the server rejects.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, body) = fixture
        .invoke("account.view", "invoke-refresh-rejected", json!({}))
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let response = fixture
        .browser(Method::GET, "/v1/oauth/connections", "rejected-list", None)
        .await;
    let rows = response_json(response).await["result"].clone();
    assert_eq!(
        rows[0]["connection"]["status"], "reconnect_required",
        "{rows}"
    );
    assert!(rows[0]["connection"]["connectionId"].is_string(), "{rows}");

    let mut changed = fixture.config.clone();
    changed.credentials.service.remove("fake");
    fixture
        .runtime
        .delete_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
            grant_id: "personal-oauth".into(),
            expected_version: 1,
            updated_by: "admin".into(),
        })
        .unwrap();
    changed.credentials.per_user.remove("oauth_stub");
    changed.credentials.connections.remove("oauth_stub");
    fixture.broker.reload_config(&changed).await;
    let response = fixture
        .browser(Method::GET, "/v1/oauth/connections", "uncached-list", None)
        .await;
    let rows = response_json(response).await["result"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
    let row = &rows[0];
    assert_eq!(row["registration"], "stub");
    assert_eq!(row["permissionProfile"], Value::Null);
    assert_eq!(row["scopeMode"], Value::Null);
    assert_eq!(row["canConnect"], false);
    assert_eq!(row["canDisconnect"], true);
    assert_eq!(row["connection"]["status"], "reconnect_required");
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "uncached-disconnect",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"],
        json!({"disconnected":true,"remoteRevocation":"not_requested"})
    );
    let response = fixture
        .browser(Method::GET, "/v1/oauth/connections", "uncached-gone", None)
        .await;
    assert_eq!(response_json(response).await["result"], json!([]));
}

#[tokio::test]
async fn oauth_callback_after_grant_loss_is_forbidden_and_does_not_block_new_consent() {
    let fixture = oauth_fixture().await;
    let response = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "consent-start",
            Some(json!({"registration": "stub","intent":"connect"})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = response_json(response).await;
    let url = url::Url::parse(response["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    fixture
        .runtime
        .disable_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
            grant_id: "personal-oauth".into(),
            expected_version: 1,
            updated_by: "admin".into(),
        })
        .unwrap();
    let response = fixture
        .browser(
            Method::GET,
            &format!(
                "/v1/oauth/callback/stub?state={state}&code=unused&iss={}",
                url::form_urlencoded::byte_serialize(fixture.server.uri().as_bytes())
                    .collect::<String>()
            ),
            "consent-denied",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "service_action_denied");
    assert_eq!(body["error"]["message"], "oauth_setup_denied");
    assert!(fixture.server.received_requests().await.unwrap().is_empty());
    fixture
        .runtime
        .enable_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
            grant_id: "personal-oauth".into(),
            expected_version: 2,
            updated_by: "admin".into(),
        })
        .unwrap();
    let response = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "consent-retry",
            Some(json!({"registration": "stub","intent":"connect"})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn oauth_callback_with_insufficient_upstream_scopes_is_a_credential_error() {
    let fixture = oauth_fixture().await;
    fixture.mock_consent("offline_access", 3600).await;
    let state = fixture.begin_consent("insufficient-scopes-start").await;
    let response = fixture
        .finish_consent(&state, "insufficient-scopes-callback")
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "credential_invalid");
    assert_eq!(body["error"]["message"], "oauth_permission_denied");
    let requests = fixture.server.received_requests().await.unwrap();
    let paths = requests
        .iter()
        .map(|request| request.url.path())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["/oauth/token", "/me", "/targets"]);
    assert!(
        fixture
            .runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_none()
    );
}

#[tokio::test]
async fn oauth_disconnect_without_a_connection_preserves_pending_consent() {
    let fixture = oauth_fixture().await;
    fixture
        .mock_consent("records.read offline_access", 3600)
        .await;
    let state = fixture.begin_consent("empty-disconnect-start").await;
    assert!(
        fixture
            .runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_none()
    );
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/stub",
            "empty-disconnect",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"],
        json!({"disconnected":true,"remoteRevocation":"not_requested"})
    );
    assert!(fixture.server.received_requests().await.unwrap().is_empty());
    let response = fixture
        .finish_consent(&state, "empty-disconnect-callback")
        .await;
    assert_completion_page(response, "Authorized", &[&state, "one-use-code"]).await;
    assert!(
        fixture
            .runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "stub")
            .unwrap()
            .connection_id
            .is_some()
    );
}
