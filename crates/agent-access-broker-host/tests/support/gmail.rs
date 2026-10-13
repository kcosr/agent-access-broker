//! Shared managed Google/Gmail wire fixture for broker and real CLI tests.
use super::{backend_registry, broker_build_status, build_router};
use agent_access_core::*;
use agent_access_provider::{
    OAuthAdapter, OAuthPermissionProfile, OAuthRegistrationConfig, REQUEST_ID_HEADER,
};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

pub(crate) async fn response_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}
const SOURCE: &str = "127.0.0.1:43200";

pub(crate) struct GmailFixture {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) runtime: BrokerRuntime,
    pub(crate) app: Router,
    pub(crate) server: MockServer,
    cookie: String,
    csrf: String,
    pub(crate) agent_token: String,
}

pub(crate) async fn gmail_fixture() -> GmailFixture {
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

    let mut config = parse_broker_config_raw(
        "gmail-fixture",
        r#"
[deployment]
enable_fake_service = true
[identity]
mode = "required"
authority = "managed"
[policy]
authority = "toml"
default_decision = "deny"
[providers.gmail]
"#,
        &Arc::new(backend_registry()),
    )
    .unwrap();
    config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
    config.mcp.enabled = true;
    config.mcp.public_url = Some("http://127.0.0.1/mcp".into());
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
        "google".into(),
        OAuthRegistrationConfig {
            adapter_settings: Default::default(),
            adapter: OAuthAdapter::new("google"),
            base_url: "https://accounts.google.com".into(),
            redirect_uri: "http://127.0.0.1/v1/oauth/callback/google".into(),
            client_id: "broker".into(),
            client_secret_ref: format!("file:{}", client_secret.display()),
            client_auth: Default::default(),
            encoding: Default::default(),
            rotation: agent_access_provider::OAuthRotation::PreserveOld,
            allow_insecure_loopback: true,
            permission_profiles: BTreeMap::from([(
                "read".into(),
                OAuthPermissionProfile {
                    scope_mode: agent_access_provider::OAuthScopeMode::Explicit,
                    scopes: Some(vec![
                        "openid".into(),
                        agent_access_gmail::GMAIL_SCOPE.into(),
                    ]),
                    audience: agent_access_gmail::GMAIL_AUDIENCE.into(),
                    target: "me".into(),
                },
            )]),
        },
    );
    config.credentials.per_user.insert(
        "gmail".into(),
        CredentialConfig {
            kind: "oauth".into(),
            provider: Some("google".into()),
            profile: Some("read".into()),
            username_ref: None,
            token_ref: None,
            path: None,
            read_only: None,
            credential_name: None,
        },
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:alice".into()],
        service: "gmail".into(),
        actions: agent_access_gmail::descriptor()
            .actions
            .iter()
            .map(|a| a.action.clone())
            .collect(),
        resources: ResourceSelection::default(),
        execution_contexts: None,
        credential_mode: "per_user".into(),
        priority: None,
    });

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
    let registry =
        agent_access_core::BackendRegistry::new(config.providers.registry().registrations())
            .unwrap()
            .with_oauth_dialects([agent_access_gmail::test_support::dialect(&server.uri())])
            .unwrap();
    config.providers = agent_access_core::ProvidersConfig::new(Arc::new(registry))
        .with(agent_access_gmail::GmailConfig::default());
    let runtime = BrokerRuntime::with_providers(
        config,
        [agent_access_gmail::test_support::provider(&server.uri())],
    )
    .unwrap();
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
    let app = build_router(runtime.clone(), broker_build_status());
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
    GmailFixture {
        _dir: dir,
        runtime,
        app,
        server,
        cookie,
        csrf,
        agent_token,
    }
}

impl GmailFixture {
    pub(crate) async fn browser(
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
    pub(crate) async fn connect(&self, callback_request_id: &str) {
        self.connect_expiring(callback_request_id, 3600).await;
    }

    /// [`Self::connect`] with first access that expires in `expires_in`
    /// seconds.
    pub(crate) async fn connect_expiring(&self, callback_request_id: &str, expires_in: u64) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1, expires_in)))
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"sub":"google-sub-alice"})),
            )
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/gmail/v1/users/me/profile"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"emailAddress":"alice@example.test","messagesTotal":3})),
            )
            .mount(&self.server)
            .await;
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "oauth-connect",
                Some(json!({"service": "gmail", "intent": "connect"})),
            )
            .await;
        let status = connect.status();
        let connect = response_json(connect).await;
        assert_eq!(status, StatusCode::OK, "{connect}");
        let authorization_url =
            url::Url::parse(connect["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        let state = authorization_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let callback = self
            .browser(
                Method::GET,
                &format!(
                    "/v1/oauth/callback/google?{}",
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("state", &state)
                        .append_pair("code", "one-use-code")
                        .append_pair("scope", "untrusted-callback-scope")
                        .append_pair("authuser", "0")
                        .append_pair("prompt", "consent")
                        .finish()
                ),
                callback_request_id,
                None,
            )
            .await;
        assert_eq!(callback.status(), StatusCode::OK);
        assert!(callback.headers().get("location").is_none());
        assert_eq!(
            callback.headers()["content-type"],
            "text/html; charset=utf-8"
        );
        let body = axum::body::to_bytes(callback.into_body(), 16_384)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("<h1>Authorized</h1>"));
        for secret in [state.as_str(), "one-use-code", "untrusted-callback-scope"] {
            assert!(!html.contains(secret));
        }
    }
}

fn token(number: u32, expires_in: u64) -> Value {
    json!({"access_token":format!("google-access-{number}"),"refresh_token":"google-reusable-refresh","token_type":"Bearer","expires_in":expires_in,"scope":format!("openid {}",agent_access_gmail::GMAIL_SCOPE)})
}
impl GmailFixture {
    pub(crate) async fn invoke(&self, action: &str, inputs: Value) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/invoke/gmail/{action}"))
                    .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
                    .header(REQUEST_ID_HEADER, "gmail-invoke")
                    .header(CONTENT_TYPE, "application/json")
                    .header("Authorization", format!("Bearer {}", self.agent_token))
                    .body(Body::from(json!({"inputs":inputs}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (response.status(), response_json(response).await)
    }
}
