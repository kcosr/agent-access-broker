use super::*;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::json;
use std::sync::{Arc, Mutex};

type CapturedRequest = (String, HeaderMap, BTreeMap<String, String>);

#[derive(Clone)]
struct FixtureState {
    resource: Arc<Mutex<Value>>,
    server: Arc<Mutex<Value>>,
    token: Arc<Mutex<(u16, Value)>>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}
async fn handler(
    State(state): State<FixtureState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let fields = url::form_urlencoded::parse(&body).into_owned().collect();
    state
        .requests
        .lock()
        .unwrap()
        .push((uri.path().into(), headers, fields));
    match uri.path() {
        "/resource-metadata" => axum::Json(state.resource.lock().unwrap().clone()).into_response(),
        "/server-metadata" => axum::Json(state.server.lock().unwrap().clone()).into_response(),
        "/token" => {
            let (status, body) = state.token.lock().unwrap().clone();
            (
                StatusCode::from_u16(status).unwrap(),
                [("location", "/unapproved"), ("retry-after", "1")],
                axum::Json(body),
            )
                .into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
struct Fixture {
    config: OAuthRegistrationConfig,
    state: FixtureState,
    http: OAuthHttp,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(auth: OAuthClientAuth) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let endpoint = |path| format!("{base}/{path}");
        let resource = endpoint("mcp");
        let issuer = endpoint("issuer");
        let config = OAuthRegistrationConfig {
            adapter: OAuthAdapter::new("mcp_oauth"),
            base_url: issuer.clone(),
            redirect_uri: "http://127.0.0.1:8787/v1/oauth/callback/mcp".into(),
            client_id: "app:id".into(),
            client_secret_ref: if auth == OAuthClientAuth::None {
                String::new()
            } else {
                "env:TEST_SECRET".into()
            },
            adapter_settings: BTreeMap::from([
                ("resource".into(), resource.clone()),
                (
                    "protected_resource_metadata_url".into(),
                    endpoint("resource-metadata"),
                ),
                (
                    "authorization_server_metadata_url".into(),
                    endpoint("server-metadata"),
                ),
                ("authorization_endpoint".into(), endpoint("authorize")),
                ("token_endpoint".into(), endpoint("token")),
            ]),
            client_auth: auth,
            encoding: OAuthTokenEncoding::Form,
            rotation: OAuthRotation::PreserveOld,
            allow_insecure_loopback: true,
            permission_profiles: BTreeMap::from([(
                "read".into(),
                OAuthPermissionProfile {
                    scope_mode: OAuthScopeMode::Explicit,
                    scopes: Some(vec!["read".into(), "offline_access".into()]),
                    audience: resource.clone(),
                    target: resource.clone(),
                },
            )]),
        };
        let state = FixtureState {
            resource: Arc::new(Mutex::new(
                json!({"resource":resource,"authorization_servers":[issuer]}),
            )),
            server: Arc::new(Mutex::new(
                json!({"issuer":issuer,"authorization_endpoint":endpoint("authorize"),"token_endpoint":endpoint("token"),"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":[client_auth_method(auth)],"grant_types_supported":["authorization_code","refresh_token"],"authorization_response_iss_parameter_supported":true}),
            )),
            token: Arc::new(Mutex::new((
                200,
                json!({"access_token":"access-secret","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-secret"}),
            ))),
            requests: Default::default(),
        };
        let app = Router::new().fallback(handler).with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let http = OAuthHttp::build(
            "mcp-oauth-test",
            "mcp_oauth",
            &Url::parse(&base).unwrap(),
            &McpOAuthDialect.upstream_allowlist(&config),
            &test_support::TestHost::default(),
        )
        .unwrap();
        Self {
            config,
            state,
            http,
            server,
        }
    }
    fn client(&self) -> OAuthClient<'_> {
        OAuthClient::new(
            "mcp",
            &self.config,
            if self.config.client_auth == OAuthClientAuth::None {
                ""
            } else {
                "secret&value"
            },
        )
    }
    fn profile(&self) -> &OAuthPermissionProfile {
        &self.config.permission_profiles["read"]
    }
    fn use_server_default(&mut self) {
        let profile = self.config.permission_profiles.get_mut("read").unwrap();
        profile.scope_mode = OAuthScopeMode::ServerDefault;
        profile.scopes = None;
    }
    async fn prepare(&self) -> Result<PreparedAuthorization, OAuthDialectError> {
        McpOAuthDialect
            .prepare_authorization(
                &self.http,
                &self.client(),
                self.profile(),
                AuthorizationRequest::new("flow-state", "pkce-challenge"),
            )
            .await
    }
    async fn code(&self) -> Result<TokenGrant, OAuthDialectError> {
        McpOAuthDialect
            .exchange_code(
                &self.http,
                &self.client(),
                CodeExchange::new("one-use-code", "pkce-verifier", self.profile()),
            )
            .await
    }
    fn token_calls(&self) -> usize {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _, _)| path == "/token")
            .count()
    }
}

#[tokio::test]
async fn pinned_metadata_prepares_pkce_and_binds_exact_callback_issuer() {
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        if scope_mode == OAuthScopeMode::ServerDefault {
            fixture.use_server_default();
        }
        let prepared = fixture.prepare().await.unwrap();
        let params: BTreeMap<_, _> = prepared.url.query_pairs().into_owned().collect();
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["resource"], fixture.profile().audience);
        if scope_mode == OAuthScopeMode::Explicit {
            assert_eq!(params["scope"], "read offline_access");
        } else {
            assert!(!params.contains_key("scope"));
        }
        assert_eq!(params["client_id"], fixture.config.client_id);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["code_challenge"], "pkce-challenge");
        assert_eq!(params["state"], "flow-state");
        assert_eq!(params["redirect_uri"], fixture.config.redirect_uri);
        assert!(!params.contains_key("client_secret"));
        assert!(
            prepared
                .callback_issuer
                .accepts(Some(&fixture.config.base_url))
        );
        assert!(!prepared.callback_issuer.accepts(None));
        assert!(
            !prepared
                .callback_issuer
                .accepts(Some(&format!("{}/", fixture.config.base_url)))
        );
        fixture.state.server.lock().unwrap()["authorization_response_iss_parameter_supported"] =
            json!(false);
        assert!(
            fixture
                .prepare()
                .await
                .unwrap()
                .callback_issuer
                .accepts(None)
        );
        assert_eq!(fixture.token_calls(), 0);
        for (_, headers, _) in fixture.state.requests.lock().unwrap().iter() {
            assert!(!headers.contains_key("authorization"));
        }
    }
}

#[tokio::test]
async fn code_and_refresh_support_public_post_and_basic_clients_without_identity_invention() {
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        for auth in [
            OAuthClientAuth::None,
            OAuthClientAuth::ClientSecretPost,
            OAuthClientAuth::ClientSecretBasic,
        ] {
            let mut fixture = Fixture::new(auth).await;
            if scope_mode == OAuthScopeMode::ServerDefault {
                fixture.use_server_default();
            }
            McpOAuthDialect
                .validate_registration(&fixture.config)
                .unwrap();
            let grant = fixture.code().await.unwrap();
            assert_eq!(grant.scopes, fixture.profile().requested_scopes());
            assert!(matches!(grant.refresh_token, IssuedRefreshToken::Issued(_)));
            let identity = McpOAuthDialect
                .identity(&fixture.http, &fixture.client(), &grant.access_token)
                .await
                .unwrap();
            assert!(identity.subject.is_none());
            let targets = McpOAuthDialect
                .discover_targets(
                    &fixture.http,
                    &fixture.client(),
                    &grant.access_token,
                    &BTreeSet::from(["read".into()]),
                )
                .await
                .unwrap();
            assert_eq!(targets[0].id, fixture.profile().audience);
            assert_eq!(targets[0].scopes, BTreeSet::from(["read".into()]));
            fixture.state.token.lock().unwrap().1 = json!({"access_token":"refreshed-secret","token_type":"Bearer","expires_in":600,"scope":"read"});
            let grant = McpOAuthDialect
                .refresh(
                    &fixture.http,
                    &fixture.client(),
                    fixture.profile(),
                    "refresh-secret",
                    &BTreeSet::from(["read".into(), "offline_access".into()]),
                )
                .await
                .unwrap();
            assert!(matches!(grant.refresh_token, IssuedRefreshToken::Retained));
            assert_eq!(grant.scopes, vec!["read"]);
            assert_eq!(fixture.token_calls(), 2);
            let requests = fixture.state.requests.lock().unwrap();
            let calls: Vec<_> = requests
                .iter()
                .filter(|(path, _, _)| path == "/token")
                .collect();
            for (_, headers, fields) in &calls {
                assert_eq!(fields["resource"], fixture.profile().audience);
                if scope_mode == OAuthScopeMode::Explicit {
                    assert_eq!(fields["scope"], "read offline_access");
                } else {
                    assert!(!fields.contains_key("scope"));
                }
                assert!(
                    headers["content-type"]
                        .to_str()
                        .unwrap()
                        .starts_with("application/x-www-form-urlencoded")
                );
                match auth {
                    OAuthClientAuth::None => {
                        assert!(!headers.contains_key("authorization"));
                        assert!(!fields.contains_key("client_secret"));
                        assert_eq!(fields["client_id"], "app:id");
                    }
                    OAuthClientAuth::ClientSecretPost => {
                        assert!(!headers.contains_key("authorization"));
                        assert_eq!(fields["client_secret"], "secret&value");
                    }
                    OAuthClientAuth::ClientSecretBasic => {
                        assert!(!fields.contains_key("client_secret"));
                        let encoded = headers["authorization"]
                            .to_str()
                            .unwrap()
                            .strip_prefix("Basic ")
                            .unwrap();
                        assert_eq!(
                            BASE64_STANDARD.decode(encoded).unwrap(),
                            b"app%3Aid:secret%26value"
                        );
                    }
                }
            }
            assert_eq!(calls[0].2["code_verifier"], "pkce-verifier");
            assert_eq!(calls[0].2["redirect_uri"], fixture.config.redirect_uri);
            assert_eq!(calls[0].2["grant_type"], "authorization_code");
            assert_eq!(calls[1].2["grant_type"], "refresh_token");
            assert_eq!(calls[1].2["refresh_token"], "refresh-secret");
            assert!(!calls[1].2.contains_key("code_verifier"));
        }
    }
}

#[tokio::test]
async fn server_default_initial_empty_scope_has_no_scope_evidence() {
    let mut fixture = Fixture::new(OAuthClientAuth::None).await;
    fixture.use_server_default();
    fixture.state.token.lock().unwrap().1["scope"] = json!("");

    let grant = fixture.code().await.unwrap();
    assert!(grant.scopes.is_empty());
    assert!(matches!(grant.refresh_token, IssuedRefreshToken::Issued(_)));
    assert_eq!(fixture.token_calls(), 1);
}

#[tokio::test]
async fn server_default_refresh_empty_scope_preserves_original_scope_evidence() {
    for original_grant_scopes in [
        BTreeSet::new(),
        BTreeSet::from(["original.read".into(), "offline_access".into()]),
    ] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        fixture.use_server_default();
        fixture.state.token.lock().unwrap().1 = json!({
            "access_token": "refreshed-secret", "token_type": "Bearer",
            "expires_in": 600, "scope": ""
        });

        let grant = McpOAuthDialect
            .refresh(
                &fixture.http,
                &fixture.client(),
                fixture.profile(),
                "refresh-secret",
                &original_grant_scopes,
            )
            .await
            .unwrap();
        assert_eq!(
            grant.scopes,
            original_grant_scopes.iter().cloned().collect::<Vec<_>>()
        );
        assert!(matches!(grant.refresh_token, IssuedRefreshToken::Retained));
        assert_eq!(fixture.token_calls(), 1);
    }
}

#[tokio::test]
async fn explicit_empty_scope_is_rejected_on_initial_exchange_and_refresh() {
    let fixture = Fixture::new(OAuthClientAuth::None).await;
    fixture.state.token.lock().unwrap().1["scope"] = json!("");

    assert!(matches!(
        fixture.code().await,
        Err(OAuthDialectError::InvalidResponse)
    ));
    assert!(matches!(
        McpOAuthDialect
            .refresh(
                &fixture.http,
                &fixture.client(),
                fixture.profile(),
                "refresh-secret",
                &BTreeSet::from(["read".into(), "offline_access".into()]),
            )
            .await,
        Err(OAuthDialectError::InvalidResponse)
    ));
    assert_eq!(fixture.token_calls(), 2);
}

#[tokio::test]
async fn server_default_refresh_retains_only_original_consent_scope_evidence() {
    for original_scope in [None, Some("original.read offline_access")] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        fixture.use_server_default();
        if let Some(scope) = original_scope {
            fixture.state.token.lock().unwrap().1["scope"] = json!(scope);
        }
        let initial = fixture.code().await.unwrap();
        let original_grant_scopes: BTreeSet<String> = initial.scopes.into_iter().collect();
        assert_eq!(
            original_grant_scopes,
            original_scope
                .into_iter()
                .flat_map(|scope| scope.split(' ').map(str::to_owned))
                .collect::<BTreeSet<_>>()
        );

        // A refresh response supplies evidence for that access token only.
        fixture.state.token.lock().unwrap().1 = json!({
            "access_token": "refreshed-secret", "token_type": "Bearer",
            "expires_in": 600, "scope": "later.read"
        });
        let reported = McpOAuthDialect
            .refresh(
                &fixture.http,
                &fixture.client(),
                fixture.profile(),
                "refresh-secret",
                &original_grant_scopes,
            )
            .await
            .unwrap();
        assert_eq!(reported.scopes, vec!["later.read"]);
        assert!(matches!(
            reported.refresh_token,
            IssuedRefreshToken::Retained
        ));

        fixture
            .state
            .token
            .lock()
            .unwrap()
            .1
            .as_object_mut()
            .unwrap()
            .remove("scope");
        let omitted = McpOAuthDialect
            .refresh(
                &fixture.http,
                &fixture.client(),
                fixture.profile(),
                "refresh-secret",
                &original_grant_scopes,
            )
            .await
            .unwrap();
        assert_eq!(
            omitted.scopes,
            original_grant_scopes.iter().cloned().collect::<Vec<_>>()
        );
        let targets = McpOAuthDialect
            .discover_targets(
                &fixture.http,
                &fixture.client(),
                &omitted.access_token,
                &omitted.scopes.iter().cloned().collect(),
            )
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, fixture.profile().target);
        assert_eq!(targets[0].audience, fixture.profile().audience);
        assert_eq!(targets[0].scopes, original_grant_scopes);
        for (_, _, fields) in fixture
            .state
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _, _)| path == "/token")
        {
            assert!(!fields.contains_key("scope"));
            assert_eq!(fields["resource"], fixture.profile().audience);
        }
    }
}

#[tokio::test]
async fn explicit_refresh_without_response_scope_confirms_narrower_requested_profile() {
    let mut fixture = Fixture::new(OAuthClientAuth::None).await;
    fixture
        .config
        .permission_profiles
        .get_mut("read")
        .unwrap()
        .scopes = Some(vec!["read".into()]);
    fixture.state.token.lock().unwrap().1 = json!({
        "access_token": "refreshed-secret", "token_type": "Bearer", "expires_in": 600
    });
    let grant = McpOAuthDialect
        .refresh(
            &fixture.http,
            &fixture.client(),
            fixture.profile(),
            "refresh-secret",
            &BTreeSet::from(["read".into(), "offline_access".into(), "write".into()]),
        )
        .await
        .unwrap();
    assert_eq!(grant.scopes, vec!["read"]);
    assert!(matches!(grant.refresh_token, IssuedRefreshToken::Retained));
    let requests = fixture.state.requests.lock().unwrap();
    let calls: Vec<_> = requests
        .iter()
        .filter(|(path, _, _)| path == "/token")
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2["scope"], "read");
}

#[tokio::test]
async fn metadata_changes_cannot_redirect_codes_tokens_or_claim_other_resources() {
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        for (document, key, value) in [
            ("resource", "resource", json!("https://other.example/mcp")),
            (
                "resource",
                "authorization_servers",
                json!(["https://other.example/issuer"]),
            ),
            ("resource", "bearer_methods_supported", json!(["query"])),
            ("server", "issuer", json!("https://other.example/issuer")),
            (
                "server",
                "token_endpoint",
                json!("https://other.example/token"),
            ),
            (
                "server",
                "authorization_endpoint",
                json!("https://other.example/authorize"),
            ),
            (
                "server",
                "code_challenge_methods_supported",
                json!(["plain"]),
            ),
            (
                "server",
                "token_endpoint_auth_methods_supported",
                json!(["client_secret_post"]),
            ),
            (
                "server",
                "authorization_response_iss_parameter_supported",
                json!("true"),
            ),
        ] {
            let mut fixture = Fixture::new(OAuthClientAuth::None).await;
            if scope_mode == OAuthScopeMode::ServerDefault {
                fixture.use_server_default();
            }
            let target = if document == "resource" {
                &fixture.state.resource
            } else {
                &fixture.state.server
            };
            target.lock().unwrap()[key] = value;
            assert!(fixture.prepare().await.is_err(), "{document}/{key}");
            assert!(matches!(
                fixture.code().await,
                Err(OAuthDialectError::NotSent)
            ));
            assert!(matches!(
                McpOAuthDialect
                    .refresh(
                        &fixture.http,
                        &fixture.client(),
                        fixture.profile(),
                        "refresh-secret",
                        &BTreeSet::new(),
                    )
                    .await,
                Err(OAuthDialectError::NotSent)
            ));
            assert_eq!(fixture.token_calls(), 0);
            assert!(
                fixture
                    .state
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(path, _, _)| ["/resource-metadata", "/server-metadata"]
                        .contains(&path.as_str()))
            );
        }
    }
}

#[tokio::test]
async fn token_errors_are_single_attempt_and_do_not_promise_refresh_replay() {
    for (status, body, expected) in [
        (
            429,
            json!({"error":"slow_down"}),
            OAuthDialectError::Throttled,
        ),
        (
            503,
            json!({"error":"server_error"}),
            OAuthDialectError::Failed,
        ),
        (
            400,
            json!({"error":"invalid_scope"}),
            OAuthDialectError::Failed,
        ),
        (
            400,
            json!({"error":"invalid_grant"}),
            OAuthDialectError::GrantInvalid,
        ),
        (302, json!({}), OAuthDialectError::Failed),
    ] {
        let fixture = Fixture::new(OAuthClientAuth::None).await;
        *fixture.state.token.lock().unwrap() = (status, body);
        let result = McpOAuthDialect
            .refresh(
                &fixture.http,
                &fixture.client(),
                fixture.profile(),
                "refresh-secret",
                &BTreeSet::new(),
            )
            .await;
        assert!(matches!(result, Err(ref error) if *error == expected));
        assert_eq!(fixture.token_calls(), 1);
        assert!(
            !fixture
                .state
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(path, _, _)| path == "/unapproved")
        );
        assert_eq!(
            McpOAuthDialect.refresh_replay(&fixture.config),
            RefreshReplay::Consuming
        );
    }
}

#[tokio::test]
async fn metadata_bounds_and_registration_errors_fail_closed() {
    let fixture = Fixture::new(OAuthClientAuth::None).await;
    for (key, value) in [
        ("token_endpoint", "https://evil.test/token?secret=x"),
        ("resource", "http://not-loopback.test/mcp"),
        ("authorization_endpoint", "https://evil.test/**"),
        (
            "authorization_server_metadata_url",
            "https://u:p@evil.test/meta",
        ),
    ] {
        let mut config = fixture.config.clone();
        config.adapter_settings.insert(key.into(), value.into());
        assert!(McpOAuthDialect.validate_registration(&config).is_err());
    }
    let mut config = fixture.config.clone();
    config.adapter_settings.insert("unknown".into(), "x".into());
    assert!(McpOAuthDialect.validate_registration(&config).is_err());
    config = fixture.config.clone();
    config.client_secret_ref = "env:SECRET".into();
    assert!(McpOAuthDialect.validate_registration(&config).is_err());
    fixture.state.server.lock().unwrap()["untrusted"] = json!("x".repeat(OAUTH_MAX_RESPONSE_BYTES));
    assert!(matches!(
        fixture.prepare().await,
        Err(OAuthDialectError::InvalidResponse)
    ));
    assert_eq!(fixture.token_calls(), 0);
}

/// Moves every approved endpoint, including the resource bound by each
/// profile, from the fixture's `http://127.0.0.1` origin to `origin`.
fn with_endpoint_origin(config: &OAuthRegistrationConfig, origin: &str) -> OAuthRegistrationConfig {
    let move_origin = |value: &str| value.replacen("http://127.0.0.1", origin, 1);
    let mut config = config.clone();
    config.base_url = move_origin(&config.base_url);
    for value in config.adapter_settings.values_mut() {
        *value = move_origin(value);
    }
    for profile in config.permission_profiles.values_mut() {
        profile.audience = move_origin(&profile.audience);
        profile.target = move_origin(&profile.target);
    }
    config
}

#[tokio::test]
async fn insecure_endpoints_require_literal_loopback_addresses() {
    let fixture = Fixture::new(OAuthClientAuth::None).await;
    for origin in ["http://127.0.0.1", "http://[::1]", "https://localhost"] {
        McpOAuthDialect
            .validate_registration(&with_endpoint_origin(&fixture.config, origin))
            .unwrap_or_else(|error| panic!("{origin}: {error}"));
    }
    for origin in ["http://localhost", "http://LOCALHOST", "http://mcp.example"] {
        assert!(
            McpOAuthDialect
                .validate_registration(&with_endpoint_origin(&fixture.config, origin))
                .is_err(),
            "{origin}"
        );
    }
    // Each endpoint is checked on its own: an approved loopback issuer does not
    // admit a plain-HTTP `localhost` endpoint beside it.
    let insecure = with_endpoint_origin(&fixture.config, "http://localhost");
    let mut config = fixture.config.clone();
    config.base_url = insecure.base_url.clone();
    assert!(McpOAuthDialect.validate_registration(&config).is_err());
    for key in SETTINGS {
        let mut config = fixture.config.clone();
        config
            .adapter_settings
            .insert(key.into(), insecure.adapter_settings[key].clone());
        if key == "resource" {
            config.permission_profiles = insecure.permission_profiles.clone();
        }
        assert!(
            McpOAuthDialect.validate_registration(&config).is_err(),
            "{key}"
        );
    }
    let mut config = fixture.config.clone();
    config.allow_insecure_loopback = false;
    assert!(McpOAuthDialect.validate_registration(&config).is_err());
}

#[tokio::test]
async fn both_permission_modes_require_exact_resource_and_valid_scope_configuration() {
    assert!(McpOAuthDialect.supports_server_default_scopes());
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        if scope_mode == OAuthScopeMode::ServerDefault {
            fixture.use_server_default();
        }
        McpOAuthDialect
            .validate_registration(&fixture.config)
            .unwrap();
        for field in ["audience", "target"] {
            let mut config = fixture.config.clone();
            let profile = config.permission_profiles.get_mut("read").unwrap();
            let value = format!("{}/", profile.target);
            if field == "audience" {
                profile.audience = value;
            } else {
                profile.target = value;
            }
            assert!(McpOAuthDialect.validate_registration(&config).is_err());
        }
        let invalid_scopes = match scope_mode {
            OAuthScopeMode::Explicit => vec![None, Some(vec![])],
            OAuthScopeMode::ServerDefault => vec![Some(vec![]), Some(vec!["read".into()])],
        };
        for scopes in invalid_scopes {
            let mut config = fixture.config.clone();
            config.permission_profiles.get_mut("read").unwrap().scopes = scopes;
            assert!(McpOAuthDialect.validate_registration(&config).is_err());
        }
    }
}

#[tokio::test]
async fn server_default_does_not_relax_token_response_validation() {
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        if scope_mode == OAuthScopeMode::ServerDefault {
            fixture.use_server_default();
        }
        for invalid_scope in [
            json!(""),
            json!(" "),
            json!("read "),
            json!("read  write"),
            json!("read read"),
            json!("read\twrite"),
            json!("read\nwrite"),
            json!("read\\write"),
            json!("read\"write"),
            json!("réad"),
            json!("x".repeat(257)),
            json!(
                (0..65)
                    .map(|i| format!("scope{i}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            json!(["read"]),
            json!(null),
            json!(true),
            json!(1),
        ] {
            // Empty server-default scope is covered by the focused exchange tests.
            if scope_mode == OAuthScopeMode::ServerDefault && invalid_scope == json!("") {
                continue;
            }
            fixture.state.token.lock().unwrap().1 = json!({
                "access_token": "access-secret", "token_type": "Bearer",
                "expires_in": 60, "scope": invalid_scope,
            });
            assert!(matches!(
                fixture.code().await,
                Err(OAuthDialectError::InvalidResponse)
            ));
            assert!(matches!(
                McpOAuthDialect
                    .refresh(
                        &fixture.http,
                        &fixture.client(),
                        fixture.profile(),
                        "refresh-secret",
                        &BTreeSet::new()
                    )
                    .await,
                Err(OAuthDialectError::InvalidResponse)
            ));
        }
        fixture.state.token.lock().unwrap().1 = json!({
            "access_token": "access-secret", "token_type": "Bearer", "expires_in": 60,
            "scope": "read write", "resource": fixture.profile().audience
        });
        let grant = fixture.code().await.unwrap();
        assert_eq!(grant.scopes, vec!["read", "write"]);
        assert!(matches!(grant.refresh_token, IssuedRefreshToken::Absent));
    }
}

#[tokio::test]
async fn access_only_and_rotation_scopes_follow_actual_grant_evidence() {
    for scope_mode in [OAuthScopeMode::Explicit, OAuthScopeMode::ServerDefault] {
        let mut fixture = Fixture::new(OAuthClientAuth::None).await;
        if scope_mode == OAuthScopeMode::ServerDefault {
            fixture.use_server_default();
        }
        let response = json!({"access_token":"access", "token_type":"Bearer","expires_in":60});
        assert!(matches!(
            parse_grant(
                response.clone(),
                fixture.profile(),
                None,
                OAuthRotation::RotateRefresh
            )
            .unwrap()
            .refresh_token,
            IssuedRefreshToken::Absent
        ));
        assert!(
            parse_grant(
                response.clone(),
                fixture.profile(),
                Some(&BTreeSet::new()),
                OAuthRotation::RotateRefresh
            )
            .is_err()
        );
        for (field, value) in [
            ("resource", json!("https://other.test/mcp")),
            ("scope", json!("read\noffline_access")),
            ("expires_in", json!(0)),
            ("token_type", json!("Basic")),
            ("access_token", json!("bad\r\nsecret")),
        ] {
            let mut response = response.clone();
            response[field] = value;
            assert!(
                parse_grant(
                    response,
                    fixture.profile(),
                    None,
                    OAuthRotation::PreserveOld
                )
                .is_err()
            );
        }
    }
}

#[tokio::test]
async fn the_import_companion_approves_only_the_validated_resource() {
    let fixture = Fixture::new(OAuthClientAuth::None).await;
    let resource = fixture.config.adapter_settings["resource"].clone();
    let approved = IMPORT_AUTHENTICATION.approved_resource;
    assert_eq!(approved(&fixture.config), Some(resource.clone()));
    let mut mismatched = fixture.config.clone();
    mismatched
        .permission_profiles
        .get_mut("read")
        .unwrap()
        .target = format!("{resource}/other");
    assert_eq!(approved(&mismatched), None);
    let mut missing = fixture.config.clone();
    missing.adapter_settings.remove("token_endpoint");
    assert_eq!(approved(&missing), None);
}

#[test]
fn the_mcp_selection_contributes_its_companion_exactly_once() {
    use agent_access_core::BackendRegistry;
    let registry = BackendRegistry::empty()
        .with_imported_adapters([crate::registration()])
        .unwrap();
    assert_eq!(
        registry.oauth_dialect_ids().collect::<Vec<_>>(),
        ["mcp_oauth"]
    );
    assert_eq!(
        registry
            .import_authentication("mcp_http")
            .map(|companion| companion.dialect.id()),
        Some("mcp_oauth")
    );
    // Selecting the same static again is a duplicate, in either order.
    let duplicate = ["OAuth dialect mcp_oauth is registered more than once"];
    assert_eq!(
        registry
            .with_oauth_dialects([&MCP_OAUTH_DIALECT])
            .unwrap_err(),
        duplicate
    );
    assert_eq!(
        BackendRegistry::empty()
            .with_oauth_dialects([&MCP_OAUTH_DIALECT])
            .unwrap()
            .with_imported_adapters([crate::registration()])
            .unwrap_err(),
        duplicate
    );
}
