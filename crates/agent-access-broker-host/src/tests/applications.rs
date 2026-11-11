//! Registered applications: the authorization-code flow with PKCE, the token
//! and revocation endpoints' error contract, the consent routes, and the
//! personal and administrative management of a person's application access.
use super::*;
use agent_access_core::{
    ApplicationConfig, ApplicationConnectLevel, PrincipalAccessPatchRequest, PrincipalPatchRequest,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const APP: &str = "example-runner";
const REDIRECT: &str = "https://runner.example.test/auth/broker/callback";
const SECRET: &str = "example-runner-client-secret-0123456789";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier-0123";

struct Apps {
    fixture: BrowserRateFixture,
    config: BrokerConfig,
}

fn application(connect: ApplicationConnectLevel, secret_path: &Path) -> ApplicationConfig {
    ApplicationConfig {
        display_name: "Example Runner".into(),
        client_secret_ref: format!("file:{}", secret_path.display()),
        redirect_uris: vec![REDIRECT.into()],
        connect,
        allowed_execution_contexts: vec!["default".into()],
        allowed_services: None,
        access_token_ttl: "8h".into(),
        refresh_idle_ttl: "90d".into(),
    }
}

async fn apps_fixture(connect: ApplicationConnectLevel) -> Apps {
    let secret_path = temp_path("application-client-secret");
    std::fs::write(&secret_path, SECRET).unwrap();
    // A file reference, so a reload can load the provider credential again.
    let provider_token = temp_path("application-fake-token");
    std::fs::write(&provider_token, "synthetic-fake-service-token").unwrap();
    let captured = Arc::new(std::sync::Mutex::new(None));
    let capture = captured.clone();
    let fixture = browser_rate_fixture_with(test_limits(), move |config| {
        config.identity.sources[0].header = "Authorization".into();
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!("file:{}", provider_token.display()));
        config
            .applications
            .insert(APP.into(), application(connect, &secret_path));
        *capture.lock().unwrap() = Some(config.clone());
    })
    .await;
    let config = captured.lock().unwrap().take().unwrap();
    Apps { fixture, config }
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

fn authorize_query(extra: &str) -> String {
    let redirect: String = url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect();
    format!(
        "/v1/applications/authorize?response_type=code&client_id={APP}&redirect_uri={redirect}\
         &state=client-state-1&code_challenge={}&code_challenge_method=S256{extra}",
        challenge()
    )
}

impl Apps {
    fn app(&self) -> Router {
        self.fixture.app.clone()
    }

    fn store(&self) -> agent_access_core::ManagedStore {
        self.fixture
            .state
            .current()
            .runtime
            .managed_store()
            .unwrap()
            .clone()
    }

    async fn get(&self, uri: &str) -> axum::response::Response {
        self.app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .extension(ConnectInfo(
                        "127.0.0.1:43200".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// A form post to the token or revocation endpoint.
    async fn form(
        &self,
        path: &str,
        authorization: Option<&str>,
        body: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:43201".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "application-protocol")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        let response = self
            .app()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, headers, body)
    }

    async fn token(&self, body: &str) -> (StatusCode, Value) {
        let (status, headers, body) = self
            .form("/v1/applications/token", Some(&basic(APP, SECRET)), body)
            .await;
        assert_eq!(headers["cache-control"], "no-store");
        // Never a Broker envelope.
        assert!(body.get("reasonCode").is_none() && body.get("ok").is_none());
        (status, body)
    }

    async fn revoke(&self, token: &str) -> StatusCode {
        self.form(
            "/v1/applications/revoke",
            Some(&basic(APP, SECRET)),
            &format!("token={token}"),
        )
        .await
        .0
    }

    /// Sends the browser to the authorization endpoint and returns the
    /// pending request's ID from the consent page's address.
    async fn start(&self) -> String {
        let response = self.get(&authorize_query("")).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let location = response.headers()["location"].to_str().unwrap();
        let id = location.strip_prefix("/ui/authorize/").unwrap().to_string();
        assert_eq!(
            id.len(),
            43,
            "a literal path the sign-in return rule accepts"
        );
        id
    }

    async fn inspect(&self, request: &str) -> (StatusCode, Value) {
        let response = self
            .fixture
            .browser_request(
                Method::GET,
                &format!("/v1/applications/authorizations/{request}"),
                None,
            )
            .await;
        (response.status(), response_json(response).await)
    }

    async fn decide(&self, request: &str, decision: &str) -> (StatusCode, Value) {
        let response = self
            .fixture
            .browser_request(
                Method::POST,
                &format!("/v1/applications/authorizations/{request}/decision"),
                Some(json!({ "decision": decision })),
            )
            .await;
        (response.status(), response_json(response).await)
    }

    /// Approves a new request and returns its code.
    async fn approve(&self) -> String {
        let request = self.start().await;
        let (status, body) = self.decide(&request, "approve").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["decision"], "approve");
        let redirect = redirect_parameters(&body);
        assert_eq!(redirect["state"], "client-state-1");
        redirect["code"].clone()
    }

    async fn exchange(&self, code: &str) -> (StatusCode, Value) {
        let redirect: String = url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect();
        self.token(&format!(
            "grant_type=authorization_code&code={code}&redirect_uri={redirect}&code_verifier={VERIFIER}"
        ))
        .await
    }

    /// Connects alice and returns the token response with the refresh token.
    async fn connect(&self) -> Value {
        let (status, body) = self.exchange(&self.approve().await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn refresh(&self, refresh_token: &str) -> (StatusCode, Value) {
        self.token(&format!(
            "grant_type=refresh_token&refresh_token={refresh_token}"
        ))
        .await
    }

    async fn bearer(
        &self,
        method: Method,
        token: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app(),
            method,
            uri,
            "application-management",
            "Authorization",
            format!("Bearer {token}"),
            body,
        )
        .await;
        (response.status(), response_json(response).await)
    }

    async fn invoke(&self, token: &str) -> StatusCode {
        invoke_fake_project_with_token(self.app(), "application-invoke", token, "TEST")
            .await
            .status()
    }

    async fn admin_access(&self) -> Value {
        let (status, body) = self
            .bearer(
                Method::GET,
                &self.fixture.admin_token,
                "/v1/admin/principals/alice/application-access",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["result"]["access"].clone()
    }

    fn sql(&self, statement: &str) {
        rusqlite::Connection::open(&self.fixture.store_path)
            .unwrap()
            .execute_batch(statement)
            .unwrap();
    }

    fn audit_actions(&self) -> Vec<String> {
        read_audit_records(&self.fixture.audit_path)
            .into_iter()
            .filter_map(|record| record["action"].as_str().map(str::to_string))
            .collect()
    }
}

/// The query parameters of a decision's `redirectTo`.
fn redirect_parameters(body: &Value) -> BTreeMap<String, String> {
    let redirect = url::Url::parse(body["result"]["redirectTo"].as_str().unwrap()).unwrap();
    assert!(redirect.as_str().starts_with(REDIRECT));
    redirect
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[tokio::test]
async fn code_flow_mints_a_working_agent_token_and_refreshes_and_revokes() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;

    let metadata = apps.get("/.well-known/oauth-authorization-server").await;
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(
        response_json(metadata).await,
        json!({
            "issuer": "http://localhost",
            "authorization_endpoint": "http://localhost/v1/applications/authorize",
            "token_endpoint": "http://localhost/v1/applications/token",
            "revocation_endpoint": "http://localhost/v1/applications/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic"],
        })
    );

    let request = apps.start().await;
    let (status, pending) = apps.inspect(&request).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let expires_at = pending["result"]["expiresAt"].clone();
    assert_eq!(
        pending["result"],
        json!({
            "applicationId": APP,
            "applicationName": "Example Runner",
            "connect": "read_write",
            "readOnly": false,
            "canConnect": true,
            "denialReason": null,
            "expiresAt": expires_at,
        })
    );
    let (status, decided) = apps.decide(&request, "approve").await;
    assert_eq!(status, StatusCode::OK, "{decided}");
    let code = redirect_parameters(&decided)["code"].clone();
    // The request is one use.
    let (status, body) = apps.inspect(&request).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["reasonCode"], "application_authorization_invalid");

    let (status, first) = apps.exchange(&code).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let access_token = first["access_token"].as_str().unwrap().to_string();
    let refresh_token = first["refresh_token"].as_str().unwrap().to_string();
    assert!(access_token.starts_with("aab_ai_"));
    assert!(!refresh_token.starts_with("aab_") && !code.starts_with("aab_"));
    assert_eq!(first["token_type"], "Bearer");
    assert_eq!(first["expires_in"], 28800);
    assert_eq!(first["principal_id"], "alice");
    assert_eq!(first["principal_name"], "alice");
    assert_eq!(first["read_only"], false);

    // The token is an ordinary agent token on the existing paths.
    assert_eq!(apps.invoke(&access_token).await, StatusCode::OK);
    let (status, me) = apps
        .bearer(Method::GET, &access_token, "/v1/me", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["principal"], "alice");
    assert_eq!(me["brokerToken"], json!({"readOnly": false}));

    let (status, second) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert!(second.get("refresh_token").is_none(), "{second}");
    let second_token = second["access_token"].as_str().unwrap().to_string();
    assert_ne!(second_token, access_token);
    assert_eq!(apps.invoke(&access_token).await, StatusCode::OK);
    assert_eq!(apps.invoke(&second_token).await, StatusCode::OK);

    // A code, refresh token or client secret is never a caller token.
    for secret in [code.as_str(), refresh_token.as_str(), SECRET] {
        let (status, body) = apps.bearer(Method::GET, secret, "/v1/me", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(apps.invoke(secret).await, StatusCode::UNAUTHORIZED);
    }

    // Individual token lists omit the tokens; the access carries a count.
    let (status, tokens) = apps
        .bearer(
            Method::GET,
            &apps.fixture.management_token,
            "/v1/tokens?includeRevoked=true&includeExpired=true",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let names = |tokens: &Value| -> Vec<String> {
        tokens["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(
        names(&tokens)
            .iter()
            .all(|name| name == "rate isolation fixture")
    );
    let (status, tokens) = apps
        .bearer(
            Method::GET,
            &apps.fixture.admin_token,
            "/v1/admin/tokens?principal=alice",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(
        names(&tokens)
            .iter()
            .all(|name| !name.starts_with("Application"))
    );
    let (status, own) = apps
        .bearer(
            Method::GET,
            &apps.fixture.management_token,
            "/v1/applications/access",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{own}");
    let access = &own["result"]["access"][0];
    assert_eq!(access["applicationId"], APP);
    assert_eq!(access["applicationName"], "Example Runner");
    assert_eq!(access["applicationAvailable"], true);
    assert_eq!(access["connect"], "read_write");
    assert_eq!(access["liveTokenCount"], 2);
    assert_eq!(access["connected"], true);
    assert_eq!(access["effectiveReadOnly"], false);
    assert!(access.get("refreshTokenHash").is_none());

    // Revocation: an access token alone, then the refresh token.
    assert_eq!(apps.revoke("unknown-token").await, StatusCode::OK);
    assert_eq!(apps.revoke(&access_token).await, StatusCode::OK);
    assert_eq!(apps.invoke(&access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(apps.invoke(&second_token).await, StatusCode::OK);
    assert_eq!(apps.revoke(&refresh_token).await, StatusCode::OK);
    assert_eq!(apps.invoke(&second_token).await, StatusCode::UNAUTHORIZED);
    let (status, body) = apps.refresh(&refresh_token).await;
    assert_eq!(
        (status, &body),
        (StatusCode::BAD_REQUEST, &json!({"error": "invalid_grant"}))
    );
    assert_eq!(apps.admin_access().await, json!([]));

    // Audit names the application and never a secret.
    let actions = apps.audit_actions();
    for action in [
        "applications.authorizations.decide",
        "applications.token.issued",
        "applications.token.refused",
        "applications.token.revoked",
    ] {
        assert!(
            actions.iter().any(|recorded| recorded == action),
            "{action}"
        );
    }
    let audit = serde_json::to_string(&read_audit_records(&apps.fixture.audit_path)).unwrap();
    assert!(audit.contains(APP));
    for secret in [
        code.as_str(),
        refresh_token.as_str(),
        access_token.as_str(),
        second_token.as_str(),
        request.as_str(),
        SECRET,
        VERIFIER,
        "client-state-1",
    ] {
        assert!(!audit.contains(secret), "a secret reached the audit log");
    }
}

#[tokio::test]
async fn token_and_revocation_refusals_follow_the_oauth_error_contract() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let refresh_token = apps.connect().await["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let grant = format!("grant_type=refresh_token&refresh_token={refresh_token}");

    // Client authentication.
    for authorization in [
        None,
        Some(basic(APP, "the-wrong-client-secret-0123456789")),
        Some(basic("unknown-application", SECRET)),
        Some(format!("Bearer {SECRET}")),
        Some("Basic not-base64!".to_string()),
    ] {
        for path in ["/v1/applications/token", "/v1/applications/revoke"] {
            let (status, headers, body) = apps.form(path, authorization.as_deref(), &grant).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization:?} {body}");
            assert_eq!(body, json!({"error": "invalid_client"}));
            assert!(
                headers["www-authenticate"]
                    .to_str()
                    .unwrap()
                    .starts_with("Basic ")
            );
            assert_eq!(headers["cache-control"], "no-store");
        }
    }
    // The refresh token still works: a failed client changed nothing.
    assert_eq!(apps.refresh(&refresh_token).await.0, StatusCode::OK);

    // Malformed requests.
    for (body, error) in [
        ("", "invalid_request"),
        ("grant_type=refresh_token", "invalid_request"),
        (
            "grant_type=authorization_code&code=aac_x",
            "invalid_request",
        ),
        (
            "grant_type=password&username=alice",
            "unsupported_grant_type",
        ),
        (
            "grant_type=refresh_token&refresh_token=a&refresh_token=b",
            "invalid_request",
        ),
        (
            "grant_type=refresh_token&refresh_token=a&client_secret=in-the-body",
            "invalid_request",
        ),
    ] {
        let (status, response) = apps.token(body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        assert_eq!(response, json!({ "error": error }), "{body}");
    }
    let (status, _, body) = apps
        .form("/v1/applications/revoke", Some(&basic(APP, SECRET)), "")
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_request"}))
    );
    // A JSON body is not the form the endpoint accepts.
    let json_response = apps
        .app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/applications/token")
                .extension(ConnectInfo(
                    "127.0.0.1:43202".parse::<SocketAddr>().unwrap(),
                ))
                .header("Authorization", basic(APP, SECRET))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"grant_type": "refresh_token", "refresh_token": refresh_token})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(json_response).await,
        json!({"error": "invalid_request"})
    );
    // Refusals made before the handler keep the contract too.
    let wrong_method = apps.get("/v1/applications/token").await;
    assert_eq!(wrong_method.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(wrong_method).await,
        json!({"error": "invalid_request"})
    );

    // Codes: wrong redirect URI, wrong verifier, replay and unknown values.
    let invalid_grant = (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}));
    let redirect: String = url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect();
    let code = apps.approve().await;
    assert_eq!(
        apps.token(&format!(
            "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Frunner.example.test%2Fother&code_verifier={VERIFIER}"
        ))
        .await,
        invalid_grant
    );
    assert_eq!(
        apps.exchange(&code).await,
        invalid_grant,
        "the code was consumed"
    );
    let code = apps.approve().await;
    assert_eq!(
        apps.token(&format!(
            "grant_type=authorization_code&code={code}&redirect_uri={redirect}&code_verifier=another-verifier-another-verifier-another-0123"
        ))
        .await,
        invalid_grant
    );
    let code = apps.approve().await;
    let (status, body) = apps.exchange(&code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(apps.exchange(&code).await, invalid_grant, "a replayed code");
    assert_eq!(apps.exchange("aac_unknown").await, invalid_grant);
    assert_eq!(apps.refresh("aar_unknown").await, invalid_grant);
    // An access token is not a refresh token.
    let access_token = body["access_token"].as_str().unwrap();
    assert_eq!(apps.refresh(access_token).await, invalid_grant);
    assert_eq!(apps.refresh(&refresh_token).await.0, StatusCode::OK);
}

#[tokio::test]
async fn authorization_endpoint_never_redirects_to_an_unregistered_address() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let other: String =
        url::form_urlencoded::byte_serialize(b"https://attacker.example.test/callback").collect();
    for uri in [
        "/v1/applications/authorize".to_string(),
        authorize_query("").replace(APP, "unknown-application"),
        format!(
            "/v1/applications/authorize?response_type=code&client_id={APP}&redirect_uri={other}&state=s&code_challenge={}&code_challenge_method=S256",
            challenge()
        ),
        // The registered URI must match exactly.
        authorize_query("").replace("%2Fcallback", "%2Fcallback%2Fextra"),
        // A repeated parameter is refused before anything is trusted.
        authorize_query(&format!("&client_id={APP}")),
    ] {
        let response = apps.get(&uri).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert!(response.headers().get("location").is_none(), "{uri}");
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let page = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("Authorization request refused"));
        assert!(!page.contains("attacker"), "nothing supplied is reflected");
    }

    // Every other refusal returns to the registered redirect URI with state.
    let returned = |response: axum::response::Response| {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()["location"].to_str().unwrap().to_string();
        assert!(location.starts_with(REDIRECT), "{location}");
        url::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<BTreeMap<_, _>>()
    };
    for (uri, error) in [
        (authorize_query("&scope=everything"), "invalid_scope"),
        (
            authorize_query("").replace("response_type=code", "response_type=token"),
            "invalid_request",
        ),
        (
            authorize_query("")
                .replace("code_challenge_method=S256", "code_challenge_method=plain"),
            "invalid_request",
        ),
        (
            authorize_query("").replace(&challenge(), "too-short"),
            "invalid_request",
        ),
    ] {
        let parameters = returned(apps.get(&uri).await);
        assert_eq!(parameters["error"], error, "{uri}");
        assert_eq!(parameters["state"], "client-state-1", "{uri}");
        assert!(!parameters.contains_key("code"));
    }
    let without_state = returned(
        apps.get(&authorize_query("").replace("&state=client-state-1", ""))
            .await,
    );
    assert_eq!(without_state["error"], "invalid_request");
    assert!(!without_state.contains_key("state"));
}

#[tokio::test]
async fn expired_requests_and_codes_are_refused() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let request = apps.start().await;
    apps.sql(
        "UPDATE application_authorization_requests SET created_at = '2000-01-01T00:00:00Z',
         expires_at = '2000-01-01T00:10:00Z'",
    );
    for (status, body) in [
        apps.inspect(&request).await,
        apps.decide(&request, "approve").await,
        apps.decide(&request, "cancel").await,
        apps.inspect("unknown-request").await,
    ] {
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["reasonCode"], "application_authorization_invalid");
    }
    let code = apps.approve().await;
    apps.sql(
        "UPDATE application_authorization_codes SET created_at = '2000-01-01T00:00:00Z',
         expires_at = '2000-01-01T00:01:00Z'",
    );
    assert_eq!(
        apps.exchange(&code).await,
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
    );
}

#[tokio::test]
async fn consent_requires_a_browser_session_with_csrf_and_cancel_returns_access_denied() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let request = apps.start().await;
    // Bearer tokens cannot consent, whatever their class.
    for token in [&apps.fixture.management_token, &apps.fixture.admin_token] {
        let (status, body) = apps
            .bearer(
                Method::GET,
                token,
                &format!("/v1/applications/authorizations/{request}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    let (status, body) = apps
        .bearer(
            Method::POST,
            &apps.fixture.management_token,
            &format!("/v1/applications/authorizations/{request}/decision"),
            Some(r#"{"decision":"approve"}"#),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "management_denied");
    // An agent token reaches none of the personal routes.
    let (status, body) = apps
        .bearer(
            Method::GET,
            &apps.fixture.agent_tokens[0],
            "/v1/applications/access",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "broker_token_class_denied");
    // The decision needs the CSRF header.
    let without_csrf = apps
        .app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/applications/authorizations/{request}/decision"
                ))
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "application-consent-without-csrf")
                .header("Cookie", &apps.fixture.cookie)
                .header("Host", "localhost")
                .header("Origin", "http://localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(without_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(without_csrf).await["reasonCode"],
        "csrf_invalid"
    );
    let (status, body) = apps.decide(&request, "maybe").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // None of that consumed the request. Cancel returns access_denied.
    let (status, body) = apps.decide(&request, "cancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["decision"], "cancel");
    let parameters = redirect_parameters(&body);
    assert_eq!(parameters["error"], "access_denied");
    assert_eq!(parameters["state"], "client-state-1");
    assert!(!parameters.contains_key("code"));
    assert_eq!(apps.admin_access().await, json!([]));
    let (status, _) = apps.decide(&request, "approve").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn level_none_connects_nobody_and_read_only_narrows_every_token() {
    let apps = apps_fixture(ApplicationConnectLevel::None).await;
    let request = apps.start().await;
    let (status, pending) = apps.inspect(&request).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["result"]["connect"], "none");
    assert_eq!(pending["result"]["canConnect"], false);
    assert_eq!(pending["result"]["denialReason"], "connecting_disabled");
    let (status, body) = apps.decide(&request, "approve").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "application_access_denied");
    assert_eq!(body["details"]["denialReason"], "connecting_disabled");
    // The person can still return to the application.
    let (status, body) = apps.decide(&request, "cancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(redirect_parameters(&body)["error"], "access_denied");

    // Read-only for everyone.
    let mut config = apps.config.clone();
    config.applications.get_mut(APP).unwrap().connect = ApplicationConnectLevel::ReadOnly;
    apps.fixture._broker.reload_config(&config).await;
    let request = apps.start().await;
    let (_, pending) = apps.inspect(&request).await;
    assert_eq!(pending["result"]["connect"], "read_only");
    assert_eq!(pending["result"]["readOnly"], true);
    assert_eq!(pending["result"]["canConnect"], true);
    let (_, decided) = apps.decide(&request, "approve").await;
    let (status, minted) = apps.exchange(&redirect_parameters(&decided)["code"]).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["read_only"], true);
    let access_token = minted["access_token"].as_str().unwrap();
    let refresh_token = minted["refresh_token"].as_str().unwrap().to_string();
    let (_, me) = apps.bearer(Method::GET, access_token, "/v1/me", None).await;
    assert_eq!(me["brokerToken"]["readOnly"], true);
    // The fixture's action is a read, which a read-only token may invoke.
    assert_eq!(apps.invoke(access_token).await, StatusCode::OK);
    assert_eq!(apps.admin_access().await[0]["effectiveReadOnly"], true);
    assert_eq!(apps.admin_access().await[0]["readOnly"], false);

    // Back to `none`: the refresh token mints nothing until the level returns.
    config.applications.get_mut(APP).unwrap().connect = ApplicationConnectLevel::None;
    apps.fixture._broker.reload_config(&config).await;
    assert_eq!(
        apps.refresh(&refresh_token).await,
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
    );
    config.applications.get_mut(APP).unwrap().connect = ApplicationConnectLevel::ReadWrite;
    apps.fixture._broker.reload_config(&config).await;
    let (status, minted) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["read_only"], false);
}

#[tokio::test]
async fn administrator_changes_end_live_tokens_and_are_version_checked() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let minted = apps.connect().await;
    let access_token = minted["access_token"].as_str().unwrap().to_string();
    let refresh_token = minted["refresh_token"].as_str().unwrap().to_string();
    let access = apps.admin_access().await[0].clone();
    let access_id = access["accessId"].as_str().unwrap().to_string();
    assert_eq!(
        (&access["version"], &access["liveTokenCount"]),
        (&json!(1), &json!(1))
    );
    let route = format!("/v1/admin/principals/alice/application-access/{access_id}");
    let admin = apps.fixture.admin_token.clone();

    // A person cannot administer, and an unknown access or owner is not found.
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &apps.fixture.management_token,
            &route,
            Some(r#"{"enabled":false,"expectedVersion":1}"#),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route.replace("alice", "admin"),
            Some(r#"{"enabled":false,"expectedVersion":1}"#),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["reasonCode"], "application_access_not_found");
    for invalid in [
        r#"{"expectedVersion":1}"#,
        r#"{"enabled":false}"#,
        r#"{"enabled":null,"expectedVersion":1}"#,
        r#"{"enabled":false,"expectedVersion":0}"#,
        r#"{"enabled":false,"expectedVersion":1,"applicationId":"other"}"#,
    ] {
        let (status, body) = apps
            .bearer(Method::PATCH, &admin, &route, Some(invalid))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}: {body}");
    }
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route,
            Some(r#"{"readOnly":true,"expectedVersion":7}"#),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reasonCode"], "version_conflict");
    // A no-op keeps the version and the live token.
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route,
            Some(r#"{"enabled":true,"readOnly":false,"expectedVersion":1}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["version"], 1);
    assert_eq!(apps.invoke(&access_token).await, StatusCode::OK);

    // Read-only ends the live token; the next one is read-only.
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route,
            Some(r#"{"readOnly":true,"expectedVersion":1}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["version"], 2);
    assert_eq!(body["result"]["readOnly"], true);
    assert_eq!(body["result"]["effectiveReadOnly"], true);
    assert_eq!(body["result"]["liveTokenCount"], 0);
    assert_eq!(body["result"]["updatedBy"], "admin");
    assert_eq!(apps.invoke(&access_token).await, StatusCode::UNAUTHORIZED);
    let (status, narrowed) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{narrowed}");
    assert_eq!(narrowed["read_only"], true);
    let narrowed_token = narrowed["access_token"].as_str().unwrap().to_string();

    // Disabled: the token ends, refresh is refused, and a new approval too.
    let (status, body) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route,
            Some(r#"{"enabled":false,"expectedVersion":2}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(apps.invoke(&narrowed_token).await, StatusCode::UNAUTHORIZED);
    let invalid_grant = (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}));
    assert_eq!(apps.refresh(&refresh_token).await, invalid_grant);
    let request = apps.start().await;
    let (_, pending) = apps.inspect(&request).await;
    assert_eq!(pending["result"]["canConnect"], false);
    assert_eq!(pending["result"]["denialReason"], "access_disabled");
    let (status, body) = apps.decide(&request, "approve").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["details"]["denialReason"], "access_disabled");

    // Enabled again: the same refresh token works.
    let (status, _) = apps
        .bearer(
            Method::PATCH,
            &admin,
            &route,
            Some(r#"{"enabled":true,"readOnly":false,"expectedVersion":3}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, restored) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert_eq!(restored["read_only"], false);
    let restored_token = restored["access_token"].as_str().unwrap().to_string();

    // Removal is version-checked and ends the token and the refresh token.
    for query in ["", "?expectedVersion=0", "?expectedVersion=1"] {
        let (status, body) = apps
            .bearer(Method::DELETE, &admin, &format!("{route}{query}"), None)
            .await;
        assert!(
            matches!(status, StatusCode::BAD_REQUEST | StatusCode::CONFLICT),
            "{query}: {body}"
        );
    }
    let (status, body) = apps
        .bearer(
            Method::DELETE,
            &admin,
            &format!("{route}?expectedVersion=4"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"], json!({"removed": true}));
    assert_eq!(apps.invoke(&restored_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(apps.refresh(&refresh_token).await, invalid_grant);
    assert_eq!(apps.admin_access().await, json!([]));

    let actions = apps.audit_actions();
    for action in [
        "admin.principals.application_access.patch",
        "admin.principals.application_access.delete",
    ] {
        assert!(
            actions.iter().any(|recorded| recorded == action),
            "{action}"
        );
    }
    assert!(
        !actions
            .iter()
            .any(|recorded| recorded == "admin.principals.application_access.list"),
        "plain reads are not audited"
    );
}

#[tokio::test]
async fn a_person_without_self_service_or_token_issuance_connects_and_manages_their_own_access() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    // Self-service off; personal token issuance is disabled by default.
    apps.store()
        .patch_principal_access(
            PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: None,
                self_service_enabled: Some(false),
                agent_token_issuance: None,
                actor: "admin".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let token = apps.fixture.management_token.clone();
    let (status, body) = apps.bearer(Method::GET, &token, "/v1/tokens", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "self_service_disabled");
    let (status, body) = apps
        .bearer(
            Method::POST,
            &token,
            "/v1/tokens",
            Some(r#"{"name":"mine","readOnly":true,"allowedExecutionContexts":["default"],"ttl":"8h"}"#),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Connecting is its own permission: the person never holds the token.
    let minted = apps.connect().await;
    let access_token = minted["access_token"].as_str().unwrap().to_string();
    assert_eq!(apps.invoke(&access_token).await, StatusCode::OK);

    // The personal list and removal work with a session or a user_manage token.
    let listed = apps
        .fixture
        .browser_request(Method::GET, "/v1/applications/access", None)
        .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed["result"]["access"][0]["liveTokenCount"], 1);
    let (status, body) = apps
        .bearer(Method::GET, &token, "/v1/applications/access", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access_id = body["result"]["access"][0]["accessId"]
        .as_str()
        .unwrap()
        .to_string();
    // The catalog lists these routes although self-service is off.
    let (status, catalog) = apps
        .bearer(Method::GET, &token, "/v1/spec/catalog", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    let listed_route = |route: &str| {
        catalog["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["route"] == route)
    };
    assert!(listed_route("/v1/applications/access"));
    assert!(listed_route("/v1/applications/authorizations/{request}"));
    assert!(!listed_route("/v1/tokens"));

    let unknown = "/v1/applications/access/00000000-0000-4000-8000-000000000000";
    let (status, body) = apps.bearer(Method::DELETE, &token, unknown, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["reasonCode"], "application_access_not_found");
    let (status, body) = apps
        .bearer(
            Method::DELETE,
            &token,
            &format!("/v1/applications/access/{access_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"], json!({"removed": true}));
    assert_eq!(apps.invoke(&access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        apps.refresh(minted["refresh_token"].as_str().unwrap())
            .await,
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
    );
    assert!(
        apps.audit_actions()
            .iter()
            .any(|action| action == "applications.access.remove")
    );
}

#[tokio::test]
async fn disabling_the_person_ends_their_application_tokens_at_once() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let minted = apps.connect().await;
    let access_token = minted["access_token"].as_str().unwrap().to_string();
    let refresh_token = minted["refresh_token"].as_str().unwrap().to_string();
    let status = |status: &str| PrincipalPatchRequest {
        principal_id: "alice".into(),
        display_name: None,
        email: None,
        status: Some(status.into()),
    };
    apps.store().patch_principal(status("disabled")).unwrap();
    assert_ne!(apps.invoke(&access_token).await, StatusCode::OK);
    assert_eq!(
        apps.refresh(&refresh_token).await,
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
    );
    // Enabling the person again does not restore the ended token; the
    // application refreshes instead.
    apps.store().patch_principal(status("active")).unwrap();
    assert_eq!(apps.invoke(&access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(apps.admin_access().await[0]["liveTokenCount"], 0);
    let (status, refreshed) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(
        apps.invoke(refreshed["access_token"].as_str().unwrap())
            .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn reload_removing_an_application_keeps_its_access_and_mints_nothing() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let minted = apps.connect().await;
    let refresh_token = minted["refresh_token"].as_str().unwrap().to_string();
    let mut removed = apps.config.clone();
    removed.applications.clear();
    apps.fixture._broker.reload_config(&removed).await;

    // The client is no longer registered.
    let (status, _, body) = apps
        .form(
            "/v1/applications/token",
            Some(&basic(APP, SECRET)),
            &format!("grant_type=refresh_token&refresh_token={refresh_token}"),
        )
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::UNAUTHORIZED, json!({"error": "invalid_client"}))
    );
    assert_eq!(
        apps.get(&authorize_query("")).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        apps.get("/.well-known/oauth-authorization-server")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    // The access stays, visible as unavailable.
    let access = apps.admin_access().await;
    assert_eq!(access[0]["applicationId"], APP);
    assert_eq!(access[0]["applicationAvailable"], false);
    assert_eq!(access[0]["applicationName"], Value::Null);
    assert_eq!(access[0]["connect"], Value::Null);

    // Registering it again restores the same refresh token.
    apps.fixture._broker.reload_config(&apps.config).await;
    let (status, refreshed) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(apps.admin_access().await[0]["applicationAvailable"], true);
}

#[tokio::test]
async fn connecting_again_replaces_the_refresh_token_and_ends_earlier_tokens() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let first = apps.connect().await;
    let first_token = first["access_token"].as_str().unwrap().to_string();
    let first_access = apps.admin_access().await[0]["accessId"].clone();
    let second = apps.connect().await;
    assert_eq!(apps.invoke(&first_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        apps.refresh(first["refresh_token"].as_str().unwrap()).await,
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant"}))
    );
    assert_eq!(
        apps.invoke(second["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    let access = apps.admin_access().await;
    assert_eq!(access.as_array().unwrap().len(), 1);
    assert_eq!(access[0]["accessId"], first_access);
    assert_eq!(access[0]["liveTokenCount"], 1);
}

#[tokio::test]
async fn a_failed_mint_audit_keeps_the_committed_token_and_withholds_its_secret() {
    let apps = apps_fixture(ApplicationConnectLevel::ReadWrite).await;
    let refresh_token = apps.connect().await["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let audit = rusqlite::Connection::open(&apps.fixture.audit_path).unwrap();
    audit
        .execute_batch(
            "CREATE TRIGGER fail_application_audit BEFORE INSERT ON audit_events
             WHEN NEW.action = 'applications.token.issued'
             BEGIN SELECT RAISE(ABORT, 'private-application-audit-failure'); END;",
        )
        .unwrap();
    let (status, body) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"error": "server_error"}));
    // The token was committed; the Broker never retries or reveals it.
    assert_eq!(apps.admin_access().await[0]["liveTokenCount"], 2);
    audit
        .execute_batch("DROP TRIGGER fail_application_audit")
        .unwrap();
    let (status, body) = apps.refresh(&refresh_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(apps.admin_access().await[0]["liveTokenCount"], 3);
}
