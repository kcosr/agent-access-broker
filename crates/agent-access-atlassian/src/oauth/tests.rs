use super::*;
use crate::AtlassianSite;
use agent_access_provider::OAuthAdapter;
use agent_access_provider::test_support::TestHost;
use std::collections::BTreeMap;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REDIRECT_URI: &str = "https://broker.example.com/v1/oauth/callback/atlassian";
const CLIENT_SECRET: &str = "app-secret&value";
const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_CLOUD_ID: &str = "99999999-8888-4777-8666-555555555555";
const JIRA_SCOPES: [&str; 3] = ["read:jira-work", "write:jira-work", "read:jira-user"];
const CONFLUENCE_SCOPES: [&str; 2] = ["search:confluence", "read:confluence-content.all"];

fn production() -> &'static dyn OAuthDialect {
    ATLASSIAN_OAUTH_DIALECT.dialect()
}

/// The profile scopes of a shared Jira and Confluence registration.
fn profile_scopes() -> Vec<String> {
    ["read:me", "offline_access"]
        .into_iter()
        .chain(JIRA_SCOPES)
        .chain(CONFLUENCE_SCOPES)
        .map(str::to_owned)
        .collect()
}

fn profile(target: &str) -> OAuthPermissionProfile {
    OAuthPermissionProfile {
        scope_mode: OAuthScopeMode::Explicit,
        scopes: Some(profile_scopes()),
        audience: ATLASSIAN_OAUTH_AUDIENCE.into(),
        target: target.into(),
    }
}

/// A valid registration whose profile `default` targets the site `target`.
fn registration(target: &str) -> OAuthRegistrationConfig {
    OAuthRegistrationConfig {
        login_binding: None,
        adapter: OAuthAdapter::new("atlassian"),
        base_url: "https://auth.atlassian.com".into(),
        redirect_uri: REDIRECT_URI.into(),
        client_id: "broker-app".into(),
        client_secret_ref: "env:ATLASSIAN_OAUTH_CLIENT_SECRET".into(),
        adapter_settings: BTreeMap::new(),
        client_auth: OAuthClientAuth::ClientSecretPost,
        encoding: OAuthTokenEncoding::Json,
        rotation: OAuthRotation::RotateRefresh,
        allow_insecure_loopback: false,
        permission_profiles: BTreeMap::from([("default".into(), profile(target))]),
    }
}

fn scopes(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// The authority Jira or Confluence declares for its site.
fn site_authority(cloud_id: Option<&str>, gateway: bool) -> UpstreamAuthority {
    let mut hosts = vec!["https://example.atlassian.net/rest/api/3/**".to_owned()];
    if gateway {
        hosts.push("https://api.atlassian.com/ex/jira/**".to_owned());
    }
    AtlassianSite {
        tenant_host: "example.atlassian.net",
        cloud_id,
        egress_proxy: None,
        allowed_upstream_hosts: &hosts,
    }
    .upstream_authority()
    .unwrap()
}

/// Stubbed Atlassian endpoints and a registration for the site `CLOUD_ID`.
struct Atlassian {
    server: MockServer,
    dialect: &'static dyn OAuthDialect,
    config: OAuthRegistrationConfig,
    http: OAuthHttp,
}

impl Atlassian {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let dialect = test_dialect(&server.uri()).dialect();
        let config = registration(CLOUD_ID);
        dialect.validate_registration(&config).unwrap();
        let http = OAuthHttp::build(
            "oauth.registrations.atlassian",
            "oauth",
            &Url::parse(&config.base_url).unwrap(),
            &dialect.upstream_allowlist(&config),
            &TestHost::default(),
        )
        .unwrap();
        Self {
            server,
            dialect,
            config,
            http,
        }
    }

    fn client(&self) -> OAuthClient<'_> {
        OAuthClient::new("atlassian", &self.config, CLIENT_SECRET)
    }

    fn profile(&self) -> &OAuthPermissionProfile {
        &self.config.permission_profiles["default"]
    }

    async fn token_responds(&self, grant_type: &str, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_partial_json(json!({"grant_type": grant_type})))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    async fn get_responds(&self, route: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    async fn exchange(&self) -> Result<TokenGrant, OAuthDialectError> {
        self.dialect
            .exchange_code(
                &self.http,
                &self.client(),
                CodeExchange::new("one-use-code", "pkce-verifier", self.profile()),
            )
            .await
    }

    async fn refresh(&self, granted: &BTreeSet<String>) -> Result<TokenGrant, OAuthDialectError> {
        self.dialect
            .refresh(
                &self.http,
                &self.client(),
                self.profile(),
                "refresh-1",
                granted,
            )
            .await
    }

    async fn sites(
        &self,
        granted: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        self.dialect
            .discover_targets(&self.http, &self.client(), "access-1", granted)
            .await
    }

    async fn sites_respond(&self, body: Value) {
        self.get_responds(
            "/oauth/token/accessible-resources",
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
    }

    /// The method and path of each request the stub received.
    async fn routes(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect()
    }

    async fn request(&self, index: usize) -> wiremock::Request {
        self.server.received_requests().await.unwrap()[index].clone()
    }
}

fn body(request: &wiremock::Request) -> Value {
    serde_json::from_slice(&request.body).unwrap()
}

fn header<'a>(request: &'a wiremock::Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn ok(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

/// A token response granting `scope`, or without `scope` when `None`.
fn token(access: &str, refresh: &str, scope: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 3600
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

/// The scope string of a full shared Jira and Confluence grant.
fn granted_scope_string() -> String {
    profile_scopes().join(" ")
}

/// A site entry of `accessible-resources`.
fn site(id: &str, name: &str, scopes: &[&str]) -> Value {
    json!({
        "id": id,
        "name": name,
        "url": format!("https://{name}.atlassian.net"),
        "scopes": scopes,
        "avatarUrl": "https://site-admin-avatar-cdn.example/avatars/240/flag.png"
    })
}

#[test]
fn registrations_need_rotate_refresh_json_secret_post_and_one_site_profile() {
    let valid = registration(CLOUD_ID);
    production().validate_registration(&valid).unwrap();
    let mut slash = valid.clone();
    slash.base_url = "https://auth.atlassian.com/".into();
    production().validate_registration(&slash).unwrap();
    assert!(!production().supports_server_default_scopes());
    assert!(!production().allows_access_without_refresh());
    assert!(!production().supports_login_binding());

    let wire = "Atlassian requires base_url https://auth.atlassian.com, client_auth = \"client_secret_post\", encoding = \"json\" and no adapter_settings";
    let mut variants = Vec::new();
    for base_url in [
        "https://auth.atlassian.com/authorize",
        "https://api.atlassian.com",
        "http://auth.atlassian.com",
        "https://auth.example.com",
    ] {
        let mut config = valid.clone();
        config.base_url = base_url.into();
        variants.push(config);
    }
    for client_auth in [OAuthClientAuth::ClientSecretBasic, OAuthClientAuth::None] {
        let mut config = valid.clone();
        config.client_auth = client_auth;
        variants.push(config);
    }
    let mut form = valid.clone();
    form.encoding = OAuthTokenEncoding::Form;
    variants.push(form);
    let mut settings = valid.clone();
    settings
        .adapter_settings
        .insert("audience".into(), "api.atlassian.com".into());
    variants.push(settings);
    for config in variants {
        assert_eq!(
            production().validate_registration(&config).unwrap_err(),
            wire,
            "{config:?}"
        );
    }
    for rotation in [OAuthRotation::PreserveOld, OAuthRotation::RotateBoth] {
        let mut config = valid.clone();
        config.rotation = rotation;
        assert_eq!(
            production().validate_registration(&config).unwrap_err(),
            "Atlassian requires rotation = \"rotate_refresh\": every refresh replaces the refresh token"
        );
    }

    let mut two = valid.clone();
    two.permission_profiles
        .insert("confluence".into(), profile(CLOUD_ID));
    assert_eq!(
        production().validate_registration(&two).unwrap_err(),
        "Atlassian registrations have exactly one permission profile"
    );
    let mut server_default = valid.clone();
    let default = server_default
        .permission_profiles
        .get_mut("default")
        .unwrap();
    default.scope_mode = OAuthScopeMode::ServerDefault;
    default.scopes = None;
    assert_eq!(
        production()
            .validate_registration(&server_default)
            .unwrap_err(),
        "permission_profiles.default must request explicit scopes"
    );
    let mut audience = valid.clone();
    audience
        .permission_profiles
        .get_mut("default")
        .unwrap()
        .audience = "https://api.atlassian.com".into();
    assert_eq!(
        production().validate_registration(&audience).unwrap_err(),
        "permission_profiles.default.audience must be api.atlassian.com"
    );
    // The target is written as Atlassian writes cloud IDs, so the lease a
    // consumer pins and the site discovery reports compare exactly.
    for target in [
        "",
        "example.atlassian.net",
        "https://example.atlassian.net",
        "11111111-2222-4333-8444-55555555555",
        "11111111-2222-4333-8444-55555555555G",
        "11111111-2222-4333-8444-55555555555A",
        "111111112222433384445555555555aa",
        "{11111111-2222-4333-8444-555555555555}",
    ] {
        let mut config = valid.clone();
        config
            .permission_profiles
            .get_mut("default")
            .unwrap()
            .target = target.into();
        assert_eq!(
            production().validate_registration(&config).unwrap_err(),
            "permission_profiles.default.target must be the site's cloud ID, a lowercase hyphenated UUID",
            "{target}"
        );
    }
    for required in ["read:me", "offline_access"] {
        let mut config = valid.clone();
        config
            .permission_profiles
            .get_mut("default")
            .unwrap()
            .scopes
            .as_mut()
            .unwrap()
            .retain(|scope| scope != required);
        assert_eq!(
            production().validate_registration(&config).unwrap_err(),
            "permission_profiles.default.scopes must include read:me, which identifies the connected account, and offline_access, which allows refresh",
            "{required}"
        );
    }
    // A single-product registration requests only its product's scopes.
    let mut jira_only = valid.clone();
    jira_only
        .permission_profiles
        .get_mut("default")
        .unwrap()
        .scopes = Some(
        ["read:me", "offline_access"]
            .into_iter()
            .chain(JIRA_SCOPES)
            .map(str::to_owned)
            .collect(),
    );
    production().validate_registration(&jira_only).unwrap();
}

#[test]
fn endpoints_are_fixed_on_the_authorization_server_and_the_gateway() {
    let config = registration(CLOUD_ID);
    assert_eq!(
        production().upstream_allowlist(&config),
        [
            "https://auth.atlassian.com/oauth/token",
            "https://api.atlassian.com/me",
            "https://api.atlassian.com/oauth/token/accessible-resources",
        ]
    );
    let issuer = production().callback_issuer(&config);
    assert!(issuer.accepts(None));
    assert!(issuer.accepts(Some("https://auth.atlassian.com")));
    assert!(!issuer.accepts(Some("https://evil.example")));
    assert_eq!(
        production().refresh_replay(&config),
        RefreshReplay::Consuming
    );
}

#[test]
fn authorization_asks_for_the_gateway_audience_and_consent_with_pkce() {
    let config = registration(CLOUD_ID);
    let client = OAuthClient::new("atlassian", &config, CLIENT_SECRET);
    let url = production()
        .authorization_url(
            &client,
            &config.permission_profiles["default"],
            AuthorizationRequest::new("flow-state", "pkce-challenge"),
        )
        .unwrap();
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://auth.atlassian.com/authorize")
    );
    let pairs = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    let scope = granted_scope_string();
    assert_eq!(
        pairs,
        BTreeMap::from(
            [
                ("audience", "api.atlassian.com"),
                ("client_id", "broker-app"),
                ("scope", scope.as_str()),
                ("redirect_uri", REDIRECT_URI),
                ("state", "flow-state"),
                ("response_type", "code"),
                ("prompt", "consent"),
                ("code_challenge", "pkce-challenge"),
                ("code_challenge_method", "S256"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
    assert!(!url.as_str().contains(CLIENT_SECRET));
}

/// Jira and Confluence declare their site's authority; only those routing
/// through the gateway with the profile's cloud ID act where the grants do.
#[test]
fn consumers_must_use_the_gateway_on_the_profiles_site() {
    let config = registration(CLOUD_ID);
    let profile = &config.permission_profiles["default"];
    let check = |consumer: Option<UpstreamAuthority>| {
        production().check_consumer_authority(&config, profile, consumer.as_ref())
    };
    check(Some(site_authority(Some(CLOUD_ID), true))).unwrap();
    assert_eq!(
        check(Some(site_authority(Some(OTHER_CLOUD_ID), true))).unwrap_err(),
        format!(
            "it acts through the Atlassian gateway on cloud ID {OTHER_CLOUD_ID}, not cloud ID {CLOUD_ID}"
        )
    );
    // The site route alone, with or without a cloud ID.
    assert_eq!(
        check(Some(site_authority(Some(CLOUD_ID), false))).unwrap_err(),
        format!(
            "it acts on https://example.atlassian.net (tenant {CLOUD_ID}) without the Atlassian gateway, and the grants act only through the gateway on cloud ID {CLOUD_ID}"
        )
    );
    assert_eq!(
        check(Some(site_authority(None, true))).unwrap_err(),
        format!(
            "it acts on https://example.atlassian.net without the Atlassian gateway, and the grants act only through the gateway on cloud ID {CLOUD_ID}"
        )
    );
    // Another service, even one on the gateway's own origin.
    for other in ["https://gitlab.example.com", "https://api.atlassian.com"] {
        let consumer = UpstreamAuthority::from_base_url(other).unwrap();
        assert_eq!(
            check(Some(consumer)).unwrap_err(),
            format!(
                "it acts on {other} without the Atlassian gateway, and the grants act only through the gateway on cloud ID {CLOUD_ID}"
            )
        );
    }
    let gateway_without_site = UpstreamAuthority::from_base_url("https://example.atlassian.net")
        .unwrap()
        .with_tenant_gateway("https://api.atlassian.com")
        .unwrap();
    assert_eq!(
        check(Some(gateway_without_site)).unwrap_err(),
        format!(
            "it names no cloud ID, and the grants act only through the Atlassian gateway on cloud ID {CLOUD_ID}"
        )
    );
    assert_eq!(
        check(None).unwrap_err(),
        format!(
            "it declares no upstream authority, and the grants act only through the Atlassian gateway on cloud ID {CLOUD_ID}"
        )
    );
}

#[tokio::test]
async fn exchange_sends_json_with_the_secret_and_uses_the_response_scope() {
    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds(
            "authorization_code",
            ok(token(
                "access-1",
                "refresh-1",
                Some(&granted_scope_string()),
            )),
        )
        .await;
    let grant = atlassian.exchange().await.unwrap();
    assert_eq!(grant.access_token, "access-1");
    assert_eq!(grant.token_type, "Bearer");
    assert_eq!(grant.expires_in, 3600);
    assert_eq!(grant.scopes, profile_scopes());
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-1")
    );
    assert!(!grant.supersedes_other_access);
    assert_eq!(atlassian.routes().await, ["POST /oauth/token"]);
    let request = atlassian.request(0).await;
    assert_eq!(
        body(&request),
        json!({
            "grant_type": "authorization_code",
            "code": "one-use-code",
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "pkce-verifier",
            "client_id": "broker-app",
            "client_secret": CLIENT_SECRET
        })
    );
    assert_eq!(header(&request, "content-type"), Some("application/json"));
    assert!(header(&request, "authorization").is_none());
}

/// Without `scope`, nothing establishes the product scopes, so the exchange
/// fails before the identity or site reads; nothing is stored.
#[tokio::test]
async fn exchange_without_scope_fails_as_an_invalid_response() {
    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds(
            "authorization_code",
            ok(token("access-1", "refresh-1", None)),
        )
        .await;
    assert_eq!(
        atlassian.exchange().await.err(),
        Some(OAuthDialectError::InvalidResponse)
    );
    assert_eq!(atlassian.routes().await, ["POST /oauth/token"]);

    let atlassian = Atlassian::start().await;
    let mut null_scope = token("access-1", "refresh-1", None);
    null_scope["scope"] = Value::Null;
    atlassian
        .token_responds("authorization_code", ok(null_scope))
        .await;
    assert_eq!(
        atlassian.exchange().await.err(),
        Some(OAuthDialectError::InvalidResponse)
    );
}

#[tokio::test]
async fn refresh_keeps_the_response_scope_or_else_the_granted_scopes() {
    // Consent evidence that differs from the profile's requested scopes.
    let granted = scopes(&["read:me", "offline_access", "read:jira-work"]);
    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds(
            "refresh_token",
            ok(token(
                "access-2",
                "refresh-2",
                Some("read:me offline_access read:jira-work write:jira-work"),
            )),
        )
        .await;
    let grant = atlassian.refresh(&granted).await.unwrap();
    assert_eq!(
        grant.scopes,
        [
            "read:me",
            "offline_access",
            "read:jira-work",
            "write:jira-work"
        ]
    );
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-2")
    );

    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds("refresh_token", ok(token("access-2", "refresh-2", None)))
        .await;
    let grant = atlassian.refresh(&granted).await.unwrap();
    assert_eq!(grant.access_token, "access-2");
    assert_eq!(grant.scopes, granted.iter().cloned().collect::<Vec<_>>());
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-2")
    );
    // One consuming request, and nothing between it and persistence.
    assert_eq!(atlassian.routes().await, ["POST /oauth/token"]);
    let request = atlassian.request(0).await;
    assert_eq!(
        body(&request),
        json!({
            "grant_type": "refresh_token",
            "refresh_token": "refresh-1",
            "client_id": "broker-app",
            "client_secret": CLIENT_SECRET
        })
    );
    assert_eq!(header(&request, "content-type"), Some("application/json"));

    // Unknown consent scopes stay unknown; the manager then rejects the
    // explicit grant. Requested scopes are never evidence.
    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds("refresh_token", ok(token("access-2", "refresh-2", None)))
        .await;
    assert!(
        atlassian
            .refresh(&BTreeSet::new())
            .await
            .unwrap()
            .scopes
            .is_empty()
    );
}

#[test]
fn token_responses_are_bounded_and_typed() {
    let valid = token("access-1", "refresh-1", Some("read:me offline_access"));
    let parsed = TokenResponse::parse(valid.clone()).unwrap();
    assert_eq!(
        parsed.scopes,
        Some(vec!["read:me".to_owned(), "offline_access".to_owned()])
    );
    assert_eq!(parsed.expires_in, 3600);
    // A response without a new refresh token never keeps the old one.
    let mut without_refresh = valid.clone();
    without_refresh
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    assert!(matches!(
        TokenResponse::parse(without_refresh).unwrap().refresh_token,
        IssuedRefreshToken::Absent
    ));
    let mut without_expiry = valid.clone();
    without_expiry.as_object_mut().unwrap().remove("expires_in");
    assert!(matches!(
        TokenResponse::parse(without_expiry),
        Err(OAuthDialectError::InvalidResponse)
    ));
    for (field, value) in [
        ("access_token", Value::Null),
        ("access_token", json!("")),
        ("access_token", json!("two words")),
        ("access_token", json!("x".repeat(MAX_TOKEN_BYTES + 1))),
        ("token_type", json!("mac")),
        ("token_type", Value::Null),
        ("expires_in", Value::Null),
        ("expires_in", json!(0)),
        ("expires_in", json!("3600")),
        ("expires_in", json!(-1)),
        ("scope", json!("")),
        ("scope", json!("   ")),
        ("scope", json!(["read:me"])),
        ("refresh_token", json!("")),
        ("refresh_token", json!(7)),
    ] {
        let mut body = valid.clone();
        body[field] = value.clone();
        assert!(
            matches!(
                TokenResponse::parse(body),
                Err(OAuthDialectError::InvalidResponse)
            ),
            "{field}: {value}"
        );
    }
}

/// Only explicit OAuth errors and throttling claim the grant was not
/// consumed; every token request is sent once. Atlassian answers a
/// revoked, expired or reused refresh token with 403 `invalid_grant`.
#[tokio::test]
async fn token_errors_classify_without_assuming_the_grant_was_kept() {
    for (response, expected) in [
        (
            ResponseTemplate::new(403).set_body_json(
                json!({"error": "invalid_grant", "error_description": "Unknown or invalid refresh token."}),
            ),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"})),
            OAuthDialectError::ClientRejected,
        ),
        (
            ResponseTemplate::new(401).set_body_json(json!({"error": "unauthorized_client"})),
            OAuthDialectError::ClientRejected,
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_request"})),
            OAuthDialectError::RequestRejected,
        ),
        (
            ResponseTemplate::new(403).set_body_json(json!({"error": "access_denied"})),
            OAuthDialectError::PermissionRejected,
        ),
        (
            ResponseTemplate::new(429).insert_header("Retry-After", "30"),
            OAuthDialectError::RetryAfter(30),
        ),
        (
            ResponseTemplate::new(429).insert_header("Retry-After", "999999"),
            OAuthDialectError::RetryAfter(86_400),
        ),
        (ResponseTemplate::new(429), OAuthDialectError::RetryAfter(1)),
        (
            ResponseTemplate::new(500).set_body_json(json!({"error": "invalid_grant"})),
            OAuthDialectError::Failed,
        ),
        (ResponseTemplate::new(503), OAuthDialectError::Failed),
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "server_error"})),
            OAuthDialectError::Failed,
        ),
        (
            ResponseTemplate::new(403).set_body_string("<html>blocked</html>"),
            OAuthDialectError::Failed,
        ),
        (
            ok(json!({"access_token": "access-2"})),
            OAuthDialectError::InvalidResponse,
        ),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian.token_responds("refresh_token", response).await;
        assert_eq!(
            atlassian.refresh(&scopes(&["read:me"])).await.err(),
            Some(expected.clone())
        );
        assert_eq!(
            atlassian.routes().await,
            ["POST /oauth/token"],
            "{expected:?}"
        );
    }
    // An exchange the authorization server refuses is classified alike.
    let atlassian = Atlassian::start().await;
    atlassian
        .token_responds(
            "authorization_code",
            ResponseTemplate::new(403).set_body_json(json!({"error": "invalid_grant"})),
        )
        .await;
    assert_eq!(
        atlassian.exchange().await.err(),
        Some(OAuthDialectError::GrantInvalid)
    );
}

#[tokio::test]
async fn identity_is_the_account_id_shown_by_email_or_name() {
    for (me, display) in [
        (
            json!({"account_id": "5b10ac8d82e05b22cc7d4ef5", "email": "alice@example.com", "name": "Alice Example", "account_status": "active"}),
            "alice@example.com",
        ),
        (
            json!({"account_id": "5b10ac8d82e05b22cc7d4ef5", "name": "Alice Example"}),
            "Alice Example",
        ),
        (
            json!({"account_id": "5b10ac8d82e05b22cc7d4ef5", "email": "", "name": 7}),
            "5b10ac8d82e05b22cc7d4ef5",
        ),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian.get_responds("/me", ok(me)).await;
        let identity = atlassian
            .dialect
            .identity(&atlassian.http, &atlassian.client(), "access-1")
            .await
            .unwrap();
        assert_eq!(
            identity.subject.as_deref(),
            Some("5b10ac8d82e05b22cc7d4ef5")
        );
        assert_eq!(identity.display_name, display);
        assert!(identity.linked_identities.is_empty());
        let request = atlassian.request(0).await;
        assert_eq!(header(&request, "authorization"), Some("Bearer access-1"));
    }

    for (response, expected) in [
        (
            ok(json!({"email": "alice@example.com"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"account_id": 42, "email": "alice@example.com"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"account_id": "", "email": "alice@example.com"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"account_id": "two words"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"account_id": "x".repeat(MAX_IDENTITY_BYTES + 1)})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ResponseTemplate::new(401)
                .set_body_json(json!({"code": 401, "message": "Unauthorized"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(403)
                .set_body_json(json!({"code": 403, "message": "scope does not match"})),
            OAuthDialectError::PermissionRejected,
        ),
        (ResponseTemplate::new(429), OAuthDialectError::Throttled),
        (ResponseTemplate::new(502), OAuthDialectError::Failed),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian.get_responds("/me", response).await;
        assert_eq!(
            atlassian
                .dialect
                .identity(&atlassian.http, &atlassian.client(), "access-1")
                .await
                .err(),
            Some(expected)
        );
    }
}

/// `accessible-resources` lists a site once per product container. Entries
/// with one cloud ID merge into one target with the union of their scopes,
/// and the granted account-level `read:me` joins every site.
#[tokio::test]
async fn sites_merge_product_containers_and_add_the_granted_account_scopes() {
    let atlassian = Atlassian::start().await;
    atlassian
        .sites_respond(json!([
            site(CLOUD_ID, "example", &JIRA_SCOPES),
            site(OTHER_CLOUD_ID, "other", &["read:jira-work"]),
            site(CLOUD_ID, "example", &CONFLUENCE_SCOPES),
            site(CLOUD_ID, "example", &["read:jira-work"]),
        ]))
        .await;
    let granted = scopes(
        &profile_scopes()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let targets = atlassian.sites(&granted).await.unwrap();
    let summary = targets
        .iter()
        .map(|target| {
            (
                target.id.as_str(),
                target.name.as_str(),
                target.audience.as_str(),
                target.scopes.clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut example = scopes(&JIRA_SCOPES);
    example.extend(scopes(&CONFLUENCE_SCOPES));
    example.insert("read:me".into());
    assert_eq!(
        summary,
        [
            (CLOUD_ID, "example", ATLASSIAN_OAUTH_AUDIENCE, example),
            (
                OTHER_CLOUD_ID,
                "other",
                ATLASSIAN_OAUTH_AUDIENCE,
                scopes(&["read:jira-work", "read:me"])
            ),
        ]
    );
    assert_eq!(
        atlassian.routes().await,
        ["GET /oauth/token/accessible-resources"]
    );
    let request = atlassian.request(0).await;
    assert_eq!(header(&request, "authorization"), Some("Bearer access-1"));
}

/// Only granted account-level scopes join a site: `read:me` is added when
/// the token carries it, and `offline_access` never is.
#[tokio::test]
async fn read_me_joins_the_sites_only_when_granted() {
    for (granted, expected) in [
        (
            scopes(&["read:me", "offline_access", "read:jira-work"]),
            scopes(&["read:jira-work", "read:me"]),
        ),
        (
            scopes(&["offline_access", "read:jira-work"]),
            scopes(&["read:jira-work"]),
        ),
        (BTreeSet::new(), scopes(&["read:jira-work"])),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian
            .sites_respond(json!([site(CLOUD_ID, "example", &["read:jira-work"])]))
            .await;
        let targets = atlassian.sites(&granted).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].scopes, expected, "{granted:?}");
    }
}

/// The person picked another site at consent: discovery reports the sites
/// they granted, none of which is the profile's, so the manager's
/// eligibility check (the profile's target with every requested scope)
/// fails the installation. An empty grant reports no site.
#[tokio::test]
async fn a_grant_for_another_site_omits_the_profiles_target() {
    for sites in [
        json!([site(OTHER_CLOUD_ID, "other", &JIRA_SCOPES)]),
        json!([]),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian.sites_respond(sites).await;
        let targets = atlassian
            .sites(&scopes(&["read:me", "read:jira-work"]))
            .await
            .unwrap();
        assert!(
            targets
                .iter()
                .all(|target| target.id != atlassian.profile().target)
        );
    }
}

/// Option A: the shared profile's scopes are checked as a whole on its
/// site. A site missing a product's scopes lacks requested scopes, and extra
/// scopes, on the site or in the token, are kept without harm.
#[tokio::test]
async fn site_scopes_are_reported_as_granted_without_filtering() {
    let atlassian = Atlassian::start().await;
    atlassian
        .sites_respond(json!([
            site(CLOUD_ID, "example", &JIRA_SCOPES),
            site(CLOUD_ID, "example", &["manage:jira-configuration"]),
        ]))
        .await;
    let granted = scopes(&[
        "read:me",
        "offline_access",
        "read:jira-work",
        "write:jira-work",
        "read:jira-user",
        "manage:jira-project",
    ]);
    let targets = atlassian.sites(&granted).await.unwrap();
    assert_eq!(targets.len(), 1);
    let site_scopes = &targets[0].scopes;
    // Confluence's scopes are absent, so a Jira and Confluence profile is
    // not satisfied on this site.
    let requested = atlassian.profile().requested_scopes();
    let missing = requested
        .iter()
        .filter(|scope| *scope != "offline_access" && !site_scopes.contains(*scope))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(missing, CONFLUENCE_SCOPES);
    // The extra site scope stays; the token's extra scope is not a site's.
    assert!(site_scopes.contains("manage:jira-configuration"));
    assert!(!site_scopes.contains("manage:jira-project"));
}

#[tokio::test]
async fn malformed_or_refused_site_reads_fail_discovery() {
    for (response, expected) in [
        (
            ok(json!({"id": CLOUD_ID, "scopes": []})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"name": "example", "scopes": ["read:jira-work"]}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": "", "scopes": ["read:jira-work"]}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": "two words", "scopes": ["read:jira-work"]}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": CLOUD_ID}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": CLOUD_ID, "scopes": "read:jira-work"}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": CLOUD_ID, "scopes": ["read:jira-work", "two words"]}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!([{"id": CLOUD_ID, "scopes": [7]}])),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ResponseTemplate::new(200).set_body_string("not json"),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ResponseTemplate::new(401)
                .set_body_json(json!({"code": 401, "message": "Unauthorized"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(403).set_body_json(json!({"code": 403})),
            OAuthDialectError::PermissionRejected,
        ),
        (ResponseTemplate::new(429), OAuthDialectError::Throttled),
        (ResponseTemplate::new(503), OAuthDialectError::Failed),
    ] {
        let atlassian = Atlassian::start().await;
        atlassian
            .get_responds("/oauth/token/accessible-resources", response)
            .await;
        assert_eq!(
            atlassian.sites(&scopes(&["read:me"])).await.err(),
            Some(expected)
        );
    }
    // A site name that is absent or out of bounds leaves the name empty.
    let atlassian = Atlassian::start().await;
    atlassian
        .sites_respond(json!([
            {"id": CLOUD_ID, "scopes": ["read:jira-work"]},
            {"id": OTHER_CLOUD_ID, "name": "x".repeat(MAX_SITE_NAME_BYTES + 1), "scopes": []},
        ]))
        .await;
    let targets = atlassian.sites(&scopes(&["read:me"])).await.unwrap();
    assert_eq!(
        targets
            .iter()
            .map(|target| target.name.as_str())
            .collect::<Vec<_>>(),
        ["", ""]
    );
    assert_eq!(targets[1].scopes, scopes(&["read:me"]));
}
