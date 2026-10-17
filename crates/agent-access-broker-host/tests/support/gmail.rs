//! Shared managed Google/Gmail wire fixture for broker and real CLI tests.
//!
//! The fixture starts an isolated broker whose composition selects the Gmail
//! native and the Google OAuth dialect pointed at a wiremock server, and
//! serves the Gmail provider against that server through the fixture control.
//! Requests reach the broker over its loopback listener. Each includer names
//! its test support types through its own module.
use super::{
    AssemblyIdentity, BrokerComposition, FixtureDir, IsolatedBroker, ProviderFixture, RunningBroker,
};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    LocalPasswordHasher, LocalPasswordWriteRequest, ManagedStore, ManagedStoreConfig,
    ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole, PrincipalWriteRequest,
};
use agent_access_provider::REQUEST_ID_HEADER;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, StatusCode, header::CONTENT_TYPE};
use serde_json::{Value, json};
use std::fmt::Display;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// The JSON body of `response`, or `null` when it is empty.
pub(crate) async fn body_json(response: reqwest::Response) -> Value {
    let bytes = response.bytes().await.unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

/// The host and origin browser requests name: the configured public origin.
const HOST: &str = "127.0.0.1";
const ORIGIN: &str = "http://127.0.0.1";

pub(crate) struct GmailFixture {
    pub(crate) broker: RunningBroker,
    pub(crate) server: MockServer,
    client: reqwest::Client,
    cookie: String,
    csrf: String,
    pub(crate) agent_token: String,
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// Managed identity and store with management, browser login, the
/// development Google registration and alice's per-user Gmail grant for every
/// action, under TOML policy. The broker's public origin, redirect URI and
/// HTTP MCP URL name `127.0.0.1` without a port; requests send that host.
fn gmail_document(directory: &FixtureDir) -> String {
    let secret_ref =
        |name: &str| toml_string(format_args!("file:{}", directory.join(name).display()));
    let actions: Vec<_> = agent_access_gmail::descriptor()
        .actions
        .iter()
        .map(|action| action.action.clone())
        .collect();
    format!(
        r#"
[deployment]
enable_fake_service = true

[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = {store}
require_registered_principal_for_invocation = false
auto_migrate = true

[management]
enabled = true

[broker_tokens]
hash_key_ref = {hash_key}
default_user_manage_ttl = "8h"
max_self_issued_agent_invoke_ttl = "30d"

[credential_encryption]
active_key = "k1"

[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = {encryption_key}

[browser_auth]
enabled = true
public_origin = "http://127.0.0.1"
session_cookie_name = "aab_session"
csrf_header = "X-Agent-Access-CSRF"
csrf_key_ref = {csrf_key}
session_ttl = "8h"
allowed_return_paths = ["/ui"]

[browser_auth.local_password]
enabled = true
pepper_ref = {pepper}
min_password_length = 8
max_failed_attempts = 3
lockout_ttl = "15m"

[oauth.registrations.google]
adapter = "google"
base_url = "https://accounts.google.com"
redirect_uri = "http://127.0.0.1/v1/oauth/callback/google"
client_id = "broker"
client_secret_ref = {client_secret}
rotation = "preserve_old"
allow_insecure_loopback = true

[oauth.registrations.google.permission_profiles.read]
scope_mode = "explicit"
scopes = ["openid", {gmail_scope}]
audience = {gmail_audience}
target = "me"

[credentials.connections.gmail]
oauth = {{ registration = "google", profile = "read" }}

[credentials.per_user.gmail]
type = "connection"
connection = "gmail"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.grants]]
subjects = ["user:alice"]
service = "gmail"
actions = {actions}
credential_mode = "per_user"

[mcp]
enabled = true
public_url = "http://127.0.0.1/mcp"

[providers.gmail]

[limits]
upload_spool_dir = {spool}
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = secret_ref("hash-key"),
        encryption_key = toml_string(directory.join("encryption-key").display()),
        csrf_key = secret_ref("csrf-key"),
        pepper = secret_ref("pepper"),
        client_secret = secret_ref("client-secret"),
        gmail_scope = toml_string(agent_access_gmail::GMAIL_SCOPE),
        gmail_audience = toml_string(agent_access_gmail::GMAIL_AUDIENCE),
        actions = serde_json::to_string(&actions).unwrap(),
        spool = toml_string(directory.join("spool").display()),
    )
}

pub(crate) async fn gmail_fixture() -> GmailFixture {
    let server = MockServer::start().await;
    // The Google dialect and the Gmail provider both reach the stub server.
    let composition = BrokerComposition::builder()
        .native(&agent_access_gmail::GMAIL_BACKEND)
        .oauth(agent_access_gmail::test_support::dialect(&server.uri()))
        .build()
        .unwrap();
    let application = IsolatedBroker::new(
        composition,
        AssemblyIdentity::new("example-assembly", "9.8.7"),
    )
    .unwrap();
    let directory = application.directory().clone();
    let secret = |name: &str, contents: String| {
        let path = directory.secret_file(name, contents).unwrap();
        format!("file:{}", path.display())
    };
    let hash_key = secret("hash-key", URL_SAFE_NO_PAD.encode([21_u8; 32]));
    secret("csrf-key", URL_SAFE_NO_PAD.encode([22_u8; 32]));
    let pepper = secret("pepper", URL_SAFE_NO_PAD.encode([23_u8; 32]));
    secret("encryption-key", URL_SAFE_NO_PAD.encode([24_u8; 32]));
    secret("client-secret", "stub-client-secret".into());

    // Seed the managed store before the broker opens and locks it.
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("store.sqlite").display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: PrincipalRole::User,
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
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    store
        .enable_local_password(
            &LocalPasswordHasher::load("browser_auth.local_password.pepper_ref", &pepper).unwrap(),
            LocalPasswordWriteRequest {
                principal_id: "alice".into(),
                password: "alice-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "test".into(),
            },
        )
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: hash_key,
        ..BrokerTokensConfig::default()
    })
    .unwrap();
    let agent_token = store
        .issue_broker_token(
            &hasher,
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
    drop(store);

    let broker = application
        .config_document(gmail_document(&directory))
        .provider_fixture(
            "gmail",
            ProviderFixture::instance(agent_access_gmail::test_support::provider(&server.uri())),
        )
        .start()
        .await
        .unwrap();
    // Responses are observed as sent: redirects are never followed.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let login = client
        .post(format!("{}/v1/auth/local/login", broker.public_url()))
        .header(REQUEST_ID_HEADER, "oauth-fixture-login")
        .header("Host", HOST)
        .header("Origin", ORIGIN)
        .header(CONTENT_TYPE, "application/json")
        .body(r#"{"principalId":"alice","password":"alice-password"}"#)
        .send()
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
    let csrf = body_json(login).await["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_string();
    GmailFixture {
        broker,
        server,
        client,
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
    ) -> reqwest::Response {
        let mut request = self
            .client
            .request(method, format!("{}{uri}", self.broker.public_url()))
            .header("Cookie", &self.cookie)
            .header("X-Agent-Access-CSRF", &self.csrf)
            .header("Host", HOST)
            .header("Origin", ORIGIN)
            .header(CONTENT_TYPE, "application/json");
        if !request_id.is_empty() {
            request = request.header(REQUEST_ID_HEADER, request_id);
        }
        if let Some(value) = body {
            request = request.body(value.to_string());
        }
        request.send().await.unwrap()
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
                Some(json!({"registration": "google", "intent": "connect"})),
            )
            .await;
        let status = connect.status();
        let connect = body_json(connect).await;
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
        let body = callback.bytes().await.unwrap();
        assert!(body.len() <= 16_384);
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("<h1>Authorized</h1>"));
        for secret in [state.as_str(), "one-use-code", "untrusted-callback-scope"] {
            assert!(!html.contains(secret));
        }
    }

    pub(crate) async fn invoke(&self, action: &str, inputs: Value) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!(
                "{}/v1/invoke/gmail/{action}",
                self.broker.public_url()
            ))
            .header(REQUEST_ID_HEADER, "gmail-invoke")
            .header(CONTENT_TYPE, "application/json")
            .header("Authorization", format!("Bearer {}", self.agent_token))
            .body(json!({"inputs":inputs}).to_string())
            .send()
            .await
            .unwrap();
        (response.status(), body_json(response).await)
    }

    /// Shuts the broker down and waits for it to release its state, returning
    /// its fixture directory and the Google stub for a broker restarted on
    /// them.
    pub(crate) async fn stop(self) -> (FixtureDir, MockServer) {
        let directory = self.broker.directory().clone();
        self.broker.shutdown();
        self.broker.join().await.unwrap();
        (directory, self.server)
    }
}

fn token(number: u32, expires_in: u64) -> Value {
    json!({"access_token":format!("google-access-{number}"),"refresh_token":"google-reusable-refresh","token_type":"Bearer","expires_in":expires_in,"scope":format!("openid {}",agent_access_gmail::GMAIL_SCOPE)})
}
