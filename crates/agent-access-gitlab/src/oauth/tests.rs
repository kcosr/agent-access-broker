use super::*;
use agent_access_provider::OAuthAdapter;
use agent_access_provider::test_support::TestHost;
use serde_json::json;
use std::collections::BTreeMap;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REDIRECT_URI: &str = "https://broker.example.com/v1/oauth/callback/gitlab";
const CLIENT_SECRET: &str = "app-secret&value";

fn dialect() -> &'static dyn OAuthDialect {
    GITLAB_OAUTH_DIALECT.dialect()
}

fn profile(target: &str) -> OAuthPermissionProfile {
    OAuthPermissionProfile {
        scope_mode: OAuthScopeMode::Explicit,
        scopes: Some(vec!["api".into(), "write_repository".into()]),
        audience: GITLAB_OAUTH_AUDIENCE.into(),
        target: target.into(),
    }
}

/// A valid registration for the instance at `base_url`, whose profile
/// `default` targets `target`.
fn registration(base_url: &str, target: &str) -> OAuthRegistrationConfig {
    OAuthRegistrationConfig {
        login_binding: None,
        adapter: OAuthAdapter::new("gitlab"),
        base_url: base_url.into(),
        redirect_uri: REDIRECT_URI.into(),
        client_id: "broker-app".into(),
        client_secret_ref: "env:GITLAB_OAUTH_CLIENT_SECRET".into(),
        adapter_settings: BTreeMap::new(),
        client_auth: OAuthClientAuth::ClientSecretPost,
        encoding: OAuthTokenEncoding::Form,
        rotation: OAuthRotation::RotateBoth,
        allow_insecure_loopback: true,
        permission_profiles: BTreeMap::from([("default".into(), profile(target))]),
    }
}

fn authority(base_url: &str) -> UpstreamAuthority {
    UpstreamAuthority::from_base_url(base_url).unwrap()
}

fn scopes(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// A stubbed GitLab instance and a registration on it.
struct Instance {
    server: MockServer,
    config: OAuthRegistrationConfig,
    http: OAuthHttp,
}

impl Instance {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let config = registration(&server.uri(), &server.uri());
        dialect().validate_registration(&config).unwrap();
        let http = OAuthHttp::build(
            "oauth.registrations.gitlab",
            "oauth",
            &Url::parse(&config.base_url).unwrap(),
            &dialect().upstream_allowlist(&config),
            &TestHost::default(),
        )
        .unwrap();
        Self {
            server,
            config,
            http,
        }
    }

    fn client(&self) -> OAuthClient<'_> {
        OAuthClient::new("gitlab", &self.config, CLIENT_SECRET)
    }

    fn profile(&self) -> &OAuthPermissionProfile {
        &self.config.permission_profiles["default"]
    }

    async fn token_responds(&self, grant_type: &str, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains(format!("grant_type={grant_type}")))
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
        dialect()
            .exchange_code(
                &self.http,
                &self.client(),
                CodeExchange::new("one-use-code", "pkce-verifier", self.profile()),
            )
            .await
    }

    async fn refresh(&self, granted: &BTreeSet<String>) -> Result<TokenGrant, OAuthDialectError> {
        dialect()
            .refresh(
                &self.http,
                &self.client(),
                self.profile(),
                "refresh-1",
                granted,
            )
            .await
    }

    /// The method and path of each request the instance received.
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

fn form(request: &wiremock::Request) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
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

#[test]
fn registrations_need_rotate_both_secret_post_and_one_instance_profile() {
    let base = "https://gitlab.example.com";
    let valid = registration(base, base);
    dialect().validate_registration(&valid).unwrap();
    assert!(!dialect().supports_server_default_scopes());
    assert!(!dialect().allows_access_without_refresh());

    for rotation in [OAuthRotation::PreserveOld, OAuthRotation::RotateRefresh] {
        let mut config = valid.clone();
        config.rotation = rotation;
        assert_eq!(
            dialect().validate_registration(&config).unwrap_err(),
            "GitLab requires rotation = \"rotate_both\": every refresh replaces both the access and the refresh token"
        );
    }
    let wire = "GitLab requires client_auth = \"client_secret_post\", form encoding and no adapter_settings";
    for client_auth in [OAuthClientAuth::ClientSecretBasic, OAuthClientAuth::None] {
        let mut config = valid.clone();
        config.client_auth = client_auth;
        assert_eq!(dialect().validate_registration(&config).unwrap_err(), wire);
    }
    let mut json = valid.clone();
    json.encoding = OAuthTokenEncoding::Json;
    assert_eq!(dialect().validate_registration(&json).unwrap_err(), wire);
    let mut settings = valid.clone();
    settings
        .adapter_settings
        .insert("resource".into(), base.into());
    assert_eq!(
        dialect().validate_registration(&settings).unwrap_err(),
        wire
    );

    let mut two = valid.clone();
    two.permission_profiles.insert("read".into(), profile(base));
    assert_eq!(
        dialect().validate_registration(&two).unwrap_err(),
        "GitLab registrations have exactly one permission profile"
    );
    let mut server_default = valid.clone();
    let profile = server_default
        .permission_profiles
        .get_mut("default")
        .unwrap();
    profile.scope_mode = OAuthScopeMode::ServerDefault;
    profile.scopes = None;
    assert_eq!(
        dialect()
            .validate_registration(&server_default)
            .unwrap_err(),
        "permission_profiles.default must request explicit scopes"
    );
    let mut audience = valid.clone();
    audience
        .permission_profiles
        .get_mut("default")
        .unwrap()
        .audience = "https://gitlab.example.com/api/v4".into();
    assert_eq!(
        dialect().validate_registration(&audience).unwrap_err(),
        "permission_profiles.default.audience must be gitlab"
    );
    for base_url in [
        "gitlab.example.com",
        "https://gitlab.example.com/?tenant=one",
        "https://user:secret@gitlab.example.com",
        "https://gitlab.example.com/*",
    ] {
        let mut config = valid.clone();
        config.base_url = base_url.into();
        assert!(
            dialect().validate_registration(&config).is_err(),
            "{base_url}"
        );
    }
}

#[test]
fn targets_are_the_normalized_instance_base() {
    for (base_url, target) in [
        (
            "https://GitLab.Example.com:443/",
            "https://gitlab.example.com",
        ),
        (
            "https://gitlab.example.com:8443",
            "https://gitlab.example.com:8443",
        ),
        ("https://example.com/gitlab/", "https://example.com/gitlab"),
    ] {
        let config = registration(base_url, target);
        dialect().validate_registration(&config).unwrap();
        assert_eq!(
            dialect().upstream_allowlist(&config),
            [
                format!("{target}/oauth/token"),
                format!("{target}/oauth/token/info"),
                format!("{target}/api/v4/user"),
            ]
        );
        let issuer = dialect().callback_issuer(&config);
        assert!(issuer.accepts(None));
        assert!(issuer.accepts(Some(target)));
        assert!(!issuer.accepts(Some("https://evil.example")));
        // The target must be written in its normalized form.
        for unnormalized in [base_url.to_owned(), format!("{target}/")]
            .into_iter()
            .filter(|written| written != target)
        {
            let config = registration(base_url, &unnormalized);
            assert_eq!(
                dialect().validate_registration(&config).unwrap_err(),
                format!(
                    "permission_profiles.default.target must be the GitLab instance base {target}"
                )
            );
        }
    }
    let config = registration("https://gitlab.example.com", "https://other.example.com");
    assert_eq!(
        dialect().validate_registration(&config).unwrap_err(),
        "permission_profiles.default.target must be the GitLab instance base https://gitlab.example.com"
    );
}

/// GitLab REST pins the target of the instance its `api_base_url` names,
/// which is the registration's target for the same instance.
#[test]
fn the_rest_providers_instance_pins_the_registrations_target() {
    for (api_base_url, base_url) in [
        (
            "https://gitlab.example.com/api/v4",
            "https://gitlab.example.com",
        ),
        (
            "https://GitLab.example.com:443/api/v4/",
            "https://gitlab.example.com/",
        ),
        (
            "https://example.com/gitlab/api/v4",
            "https://example.com/gitlab",
        ),
    ] {
        let rest = crate::gitlab_upstream_authority(api_base_url).unwrap();
        let target = oauth_target(&authority(base_url));
        assert_eq!(oauth_target(&rest), target, "{api_base_url}");
        let config = registration(base_url, &target);
        dialect().validate_registration(&config).unwrap();
        dialect()
            .check_consumer_authority(&config, &config.permission_profiles["default"], Some(&rest))
            .unwrap();
    }
}

#[test]
fn consumers_must_act_on_the_registrations_instance() {
    let base = "https://gitlab.example.com";
    let config = registration(base, base);
    let profile = &config.permission_profiles["default"];
    let check = |consumer: Option<UpstreamAuthority>| {
        dialect().check_consumer_authority(&config, profile, consumer.as_ref())
    };
    // GitLab REST and a Git gateway on the instance.
    check(crate::gitlab_upstream_authority(
        "https://gitlab.example.com/api/v4",
    ))
    .unwrap();
    check(Some(authority("https://GitLab.example.com:443/"))).unwrap();
    for other in [
        "https://git.example.com",
        "http://gitlab.example.com",
        "https://gitlab.example.com:8443",
        "https://gitlab.example.com/other",
    ] {
        let consumer = authority(other);
        assert_eq!(
            check(Some(consumer.clone())).unwrap_err(),
            format!("it acts on {consumer}, not the GitLab instance https://gitlab.example.com"),
        );
    }
    assert_eq!(
        check(None).unwrap_err(),
        "it declares no upstream authority, and the grants act only on the GitLab instance https://gitlab.example.com"
    );
    // A relative URL root is part of the instance.
    let rooted = registration("https://example.com/gitlab", "https://example.com/gitlab");
    let rooted_profile = &rooted.permission_profiles["default"];
    for (consumer, accepted) in [
        ("https://example.com/gitlab", true),
        ("https://example.com", false),
        ("https://example.com/gitlab/group", false),
    ] {
        assert_eq!(
            dialect()
                .check_consumer_authority(&rooted, rooted_profile, Some(&authority(consumer)))
                .is_ok(),
            accepted,
            "{consumer}"
        );
    }
}

#[test]
fn authorization_requests_the_profile_scopes_with_pkce() {
    let config = registration("https://example.com/gitlab/", "https://example.com/gitlab");
    let client = OAuthClient::new("gitlab", &config, CLIENT_SECRET);
    let url = dialect()
        .authorization_url(
            &client,
            &config.permission_profiles["default"],
            AuthorizationRequest::new("flow-state", "pkce-challenge"),
        )
        .unwrap();
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://example.com/gitlab/oauth/authorize")
    );
    let pairs = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
    assert_eq!(
        pairs,
        BTreeMap::from(
            [
                ("client_id", "broker-app"),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("scope", "api write_repository"),
                ("state", "flow-state"),
                ("code_challenge", "pkce-challenge"),
                ("code_challenge_method", "S256"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
    assert!(!url.as_str().contains(CLIENT_SECRET));
    assert_eq!(dialect().refresh_replay(&config), RefreshReplay::Consuming);
}

#[tokio::test]
async fn exchange_uses_the_response_scope_without_reading_token_info() {
    let instance = Instance::start().await;
    instance
        .token_responds(
            "authorization_code",
            ok(json!({
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "token_type": "Bearer",
                "expires_in": 7200,
                "scope": "api write_repository",
                "created_at": 1_760_000_000
            })),
        )
        .await;
    let grant = instance.exchange().await.unwrap();
    assert_eq!(grant.access_token, "access-1");
    assert_eq!(grant.token_type, "Bearer");
    assert_eq!(grant.expires_in, 7200);
    assert_eq!(grant.scopes, ["api", "write_repository"]);
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-1")
    );
    assert!(grant.supersedes_other_access);
    assert_eq!(instance.routes().await, ["POST /oauth/token"]);
    let request = instance.request(0).await;
    assert_eq!(
        form(&request),
        BTreeMap::from(
            [
                ("grant_type", "authorization_code"),
                ("code", "one-use-code"),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", "pkce-verifier"),
                ("client_id", "broker-app"),
                ("client_secret", CLIENT_SECRET),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
    assert_eq!(
        header(&request, "content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert!(header(&request, "authorization").is_none());
}

#[tokio::test]
async fn exchange_without_scope_reads_the_new_tokens_info() {
    let instance = Instance::start().await;
    // Without `expires_in`, GitLab's default lifetime applies.
    instance
        .token_responds(
            "authorization_code",
            ok(json!({
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "token_type": "bearer"
            })),
        )
        .await;
    instance
        .get_responds(
            "/oauth/token/info",
            ok(json!({
                "resource_owner_id": 42,
                "scope": ["read_api", "read_repository"],
                "expires_in": 7199,
                "application": {"uid": "broker-app"},
                "created_at": 1_760_000_000
            })),
        )
        .await;
    let grant = instance.exchange().await.unwrap();
    assert_eq!(grant.scopes, ["read_api", "read_repository"]);
    assert_eq!(grant.expires_in, 7200);
    assert!(grant.supersedes_other_access);
    assert_eq!(
        instance.routes().await,
        ["POST /oauth/token", "GET /oauth/token/info"]
    );
    let info = instance.request(1).await;
    assert_eq!(header(&info, "authorization"), Some("Bearer access-1"));
    assert!(info.url.query().is_none());
}

/// A failed token-info read fails the exchange, so the installation stores
/// nothing; no identity request follows.
#[tokio::test]
async fn token_info_failure_fails_the_exchange() {
    for (response, expected) in [
        (ResponseTemplate::new(500), OAuthDialectError::Failed),
        (
            ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_token"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(429).insert_header("Retry-After", "30"),
            OAuthDialectError::Throttled,
        ),
        (
            ok(json!({"resource_owner_id": 42})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"scope": "api write_repository"})),
            OAuthDialectError::InvalidResponse,
        ),
        (ok(json!({"scope": []})), OAuthDialectError::InvalidResponse),
        (
            ok(json!({"scope": ["api", ""]})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ResponseTemplate::new(200).set_body_string("not json"),
            OAuthDialectError::InvalidResponse,
        ),
    ] {
        let instance = Instance::start().await;
        instance
            .token_responds(
                "authorization_code",
                ok(json!({
                    "access_token": "access-1",
                    "refresh_token": "refresh-1",
                    "token_type": "Bearer",
                    "expires_in": 7200
                })),
            )
            .await;
        instance.get_responds("/oauth/token/info", response).await;
        assert_eq!(instance.exchange().await.err(), Some(expected.clone()));
        assert_eq!(
            instance.routes().await,
            ["POST /oauth/token", "GET /oauth/token/info"],
            "{expected:?}"
        );
    }
}

#[tokio::test]
async fn refresh_keeps_the_response_scope_or_else_the_granted_scopes() {
    // Consent evidence that differs from the profile's requested scopes.
    let granted = scopes(&["api", "read_repository"]);
    let instance = Instance::start().await;
    instance
        .token_responds(
            "refresh_token",
            ok(json!({
                "access_token": "access-2",
                "refresh_token": "refresh-2",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "read_api read_repository"
            })),
        )
        .await;
    let grant = instance.refresh(&granted).await.unwrap();
    assert_eq!(grant.scopes, ["read_api", "read_repository"]);
    assert_eq!(grant.expires_in, 300);
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-2")
    );
    assert!(grant.supersedes_other_access);

    let instance = Instance::start().await;
    instance
        .token_responds(
            "refresh_token",
            ok(json!({
                "access_token": "access-2",
                "refresh_token": "refresh-2",
                "token_type": "Bearer",
                "expires_in": 7200,
                "created_at": 1_760_000_000
            })),
        )
        .await;
    let grant = instance.refresh(&granted).await.unwrap();
    assert_eq!(grant.scopes, ["api", "read_repository"]);
    assert!(
        matches!(&grant.refresh_token, IssuedRefreshToken::Issued(token) if token == "refresh-2")
    );
    assert!(grant.supersedes_other_access);
    // One consuming request, and nothing between it and persistence.
    assert_eq!(instance.routes().await, ["POST /oauth/token"]);
    let request = instance.request(0).await;
    assert_eq!(
        form(&request),
        BTreeMap::from(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", "refresh-1"),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", "broker-app"),
                ("client_secret", CLIENT_SECRET),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );

    // Unknown consent scopes stay unknown; the manager then rejects the
    // explicit grant. Requested scopes are never evidence.
    let instance = Instance::start().await;
    instance
        .token_responds(
            "refresh_token",
            ok(json!({
                "access_token": "access-2",
                "refresh_token": "refresh-2",
                "token_type": "Bearer",
                "expires_in": 7200
            })),
        )
        .await;
    let grant = instance.refresh(&BTreeSet::new()).await.unwrap();
    assert!(grant.scopes.is_empty());
}

#[test]
fn token_responses_are_bounded_and_typed() {
    let valid = json!({
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "token_type": "Bearer",
        "expires_in": 7200,
        "scope": "api"
    });
    let parsed = TokenResponse::parse(valid.clone()).unwrap();
    assert_eq!(parsed.scopes, Some(vec!["api".to_owned()]));
    let mut without_refresh = valid.clone();
    without_refresh
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    assert!(matches!(
        TokenResponse::parse(without_refresh).unwrap().refresh_token,
        IssuedRefreshToken::Absent
    ));
    let mut null_expiry = valid.clone();
    null_expiry["expires_in"] = Value::Null;
    assert_eq!(
        TokenResponse::parse(null_expiry).unwrap().expires_in,
        DEFAULT_EXPIRES_IN_SECONDS
    );
    for (field, value) in [
        ("access_token", Value::Null),
        ("access_token", json!("")),
        ("access_token", json!("two words")),
        ("access_token", json!("x".repeat(MAX_TOKEN_BYTES + 1))),
        ("token_type", json!("mac")),
        ("token_type", Value::Null),
        ("expires_in", json!(0)),
        ("expires_in", json!("7200")),
        ("expires_in", json!(-1)),
        ("scope", json!("")),
        ("scope", json!(["api"])),
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

#[tokio::test]
async fn identity_is_the_numeric_user_id_and_username() {
    let instance = Instance::start().await;
    instance
        .get_responds(
            "/api/v4/user",
            ok(json!({"id": 42, "username": "alice", "name": "Alice Example"})),
        )
        .await;
    let identity = dialect()
        .identity(&instance.http, &instance.client(), "access-1")
        .await
        .unwrap();
    assert_eq!(identity.subject.as_deref(), Some("42"));
    assert_eq!(identity.display_name, "alice");
    let request = instance.request(0).await;
    assert_eq!(header(&request, "authorization"), Some("Bearer access-1"));

    for (response, expected) in [
        (
            ok(json!({"id": "42", "username": "alice"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"id": 0, "username": "alice"})),
            OAuthDialectError::InvalidResponse,
        ),
        (
            ok(json!({"id": 42, "username": ""})),
            OAuthDialectError::InvalidResponse,
        ),
        (ok(json!({"id": 42})), OAuthDialectError::InvalidResponse),
        (
            ResponseTemplate::new(401).set_body_json(json!({"message": "401 Unauthorized"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(403).set_body_json(json!({"error": "insufficient_scope"})),
            OAuthDialectError::PermissionRejected,
        ),
        (ResponseTemplate::new(502), OAuthDialectError::Failed),
    ] {
        let instance = Instance::start().await;
        instance.get_responds("/api/v4/user", response).await;
        assert_eq!(
            dialect()
                .identity(&instance.http, &instance.client(), "access-1")
                .await
                .err(),
            Some(expected)
        );
    }
}

/// The account's linked sign-ins are `/api/v4/user`'s `identities[]`, which
/// a registration's `login_binding` checks. An entry without a textual
/// provider and external UID within bounds is left out, so it can never
/// satisfy a binding, and an account reporting none still connects.
#[tokio::test]
async fn identity_reports_the_accounts_linked_sign_ins() {
    assert!(dialect().supports_login_binding());
    let object_id = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
    let directory = "uid=alice,ou=people,dc=example,dc=com";
    let instance = Instance::start().await;
    instance
        .get_responds(
            "/api/v4/user",
            ok(json!({
                "id": 42,
                "username": "alice",
                "identities": [
                    {"provider": "azure_activedirectory_v2", "extern_uid": object_id, "saml_provider_id": null},
                    {"provider": "ldapmain", "extern_uid": directory},
                    {"provider": "github", "extern_uid": 1234},
                    {"provider": "", "extern_uid": object_id},
                    {"extern_uid": object_id},
                    {"provider": "openid_connect", "extern_uid": "line\nbreak"},
                    {"provider": "saml", "extern_uid": "x".repeat(1025)},
                    "azure_activedirectory_v2"
                ]
            })),
        )
        .await;
    let identity = dialect()
        .identity(&instance.http, &instance.client(), "access-1")
        .await
        .unwrap();
    assert_eq!(
        identity.linked_identities,
        [
            LinkedIdentity::new("azure_activedirectory_v2", object_id),
            LinkedIdentity::new("ldapmain", directory),
        ]
    );

    let many = (0..70)
        .map(|n| json!({"provider": "saml", "extern_uid": format!("user-{n}")}))
        .collect::<Vec<_>>();
    for (identities, expected) in [
        (None, 0),
        (Some(Value::Null), 0),
        (Some(json!("azure_activedirectory_v2")), 0),
        (Some(json!([])), 0),
        (Some(Value::Array(many)), 64),
    ] {
        let mut user = json!({"id": 42, "username": "alice"});
        if let Some(identities) = identities {
            user["identities"] = identities;
        }
        let instance = Instance::start().await;
        instance.get_responds("/api/v4/user", ok(user)).await;
        let identity = dialect()
            .identity(&instance.http, &instance.client(), "access-1")
            .await
            .unwrap();
        assert_eq!(identity.subject.as_deref(), Some("42"));
        assert_eq!(identity.linked_identities.len(), expected);
    }
}

/// Only explicit OAuth errors and throttling claim the grant was not
/// consumed; every token request is sent once.
#[tokio::test]
async fn token_errors_classify_without_assuming_the_grant_was_kept() {
    for (response, expected) in [
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})),
            OAuthDialectError::GrantInvalid,
        ),
        (
            ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"})),
            OAuthDialectError::ClientRejected,
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_request"})),
            OAuthDialectError::RequestRejected,
        ),
        (
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_scope"})),
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
        let instance = Instance::start().await;
        instance.token_responds("refresh_token", response).await;
        assert_eq!(
            instance.refresh(&scopes(&["api"])).await.err(),
            Some(expected.clone())
        );
        assert_eq!(
            instance.routes().await,
            ["POST /oauth/token"],
            "{expected:?}"
        );
    }
}

#[tokio::test]
async fn the_one_target_is_the_instance_with_the_grants_scopes() {
    let instance = Instance::start().await;
    let granted = scopes(&["api", "write_repository"]);
    let targets = dialect()
        .discover_targets(&instance.http, &instance.client(), "access-1", &granted)
        .await
        .unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, instance.profile().target);
    assert_eq!(targets[0].id, instance.server.uri());
    assert_eq!(targets[0].audience, GITLAB_OAUTH_AUDIENCE);
    assert_eq!(targets[0].scopes, granted);
    assert_eq!(targets[0].name, "GitLab instance");
    assert!(instance.routes().await.is_empty());
}
