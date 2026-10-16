//! The `atlassian` OAuth dialect through the Broker's consent and lease
//! lifecycle against stubbed Atlassian endpoints, and offline validation of
//! the Atlassian connection table (design section 6.11) on full
//! configurations with Jira and Confluence.
use super::*;
use agent_access_atlassian::{ATLASSIAN_OAUTH_AUDIENCE, AtlassianSite};
use agent_access_core::{
    ConfigError, ConnectionOAuthConfig, OAuthConnectionStatus, ProvidersConfig,
    validate_broker_config,
};
use agent_access_provider::{
    ActionDescriptor, BackendConfig, BackendRegistration, BuildContext, CredentialDescriptor,
    DelegatedAccess, DelegatedAccessError, DelegatedCredential, EgressProxyConfig, OAuthClientAuth,
    OAuthRotation, OAuthScopeMode, OAuthTokenEncoding, Provider, ProviderBuildError, ProviderError,
    ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution, ServiceDescriptor,
    ValidationContext, parse_backend_config,
};
use wiremock::matchers::body_partial_json;

const CALLBACK: &str = "http://127.0.0.1/v1/oauth/callback/atlassian";
const CLOUD_ID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER_CLOUD_ID: &str = "99999999-8888-4777-8666-555555555555";
const ACCOUNT_ID: &str = "5b10ac8d82e05b22cc7d4ef5";
const JIRA_SCOPES: [&str; 3] = ["read:jira-work", "write:jira-work", "read:jira-user"];
const CONFLUENCE_SCOPES: [&str; 2] = ["search:confluence", "read:confluence-content.all"];

/// The scopes of a registration shared by Jira and Confluence.
fn profile_scopes() -> Vec<String> {
    ["read:me", "offline_access"]
        .into_iter()
        .chain(JIRA_SCOPES)
        .chain(CONFLUENCE_SCOPES)
        .map(str::to_owned)
        .collect()
}

fn scope_set<'a>(scopes: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    scopes.into_iter().map(str::to_owned).collect()
}

/// A test backend selected as `oauth_stub`: a consumer of one Atlassian
/// site through the gateway, as Jira and Confluence are. It declares the
/// site authority they declare and accepts delegated credentials; its
/// `account.view` pins the connection's access to the site's cloud ID and
/// the gateway audience before each use, and replaces the access once when
/// asked to, as after an upstream 401.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AtlassianSiteConsumer {
    pub(crate) cloud_id: String,
}

static ATLASSIAN_SITE_CONSUMER: BackendRegistration = BackendRegistration::new(
    agent_access_fake::OAUTH_STUB_BACKEND.module(),
    "oauth_stub",
    parse_backend_config::<AtlassianSiteConsumer>,
)
.with_resource_types(agent_access_fake::OAUTH_STUB_BACKEND.resource_types())
.development_only();

impl BackendConfig for AtlassianSiteConsumer {
    fn kind(&self) -> &'static str {
        "oauth_stub"
    }

    fn validate(&self, _context: &ValidationContext<'_>, _errors: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        let hosts = [
            "https://example.atlassian.net/rest/api/3/**".to_owned(),
            format!(
                "https://api.atlassian.com/ex/jira/{}/rest/api/3/**",
                self.cloud_id
            ),
        ];
        let authority = AtlassianSite {
            tenant_host: "example.atlassian.net",
            cloud_id: Some(&self.cloud_id),
            egress_proxy: None,
            allowed_upstream_hosts: &hosts,
        }
        .upstream_authority()
        .expect("the test site is valid");
        ServiceDescriptor::new("oauth_stub", "Atlassian site consumer")
            .with_actions(vec![
                ActionDescriptor::new(
                    "account.view",
                    "Read through the connected Atlassian account",
                    json!({
                        "type": "object",
                        "properties": {"recover": {"type": "boolean"}},
                        "additionalProperties": false
                    }),
                )
                .read_only()
                .credential_modes(["per_user"]),
            ])
            .with_credentials(
                CredentialDescriptor::default()
                    .delegated("Lets agents act as your Atlassian account."),
            )
            .with_upstream_authority(authority)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        Vec::new()
    }

    fn build(&self, _host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}

impl AtlassianSiteConsumer {
    async fn pinned(
        &self,
        credential: &DelegatedCredential,
    ) -> Result<DelegatedAccess, ProviderError> {
        credential
            .revalidated_access_for(&self.cloud_id, ATLASSIAN_OAUTH_AUDIENCE)
            .await
            .map_err(|error| match error {
                DelegatedAccessError::Revalidation(failure) => failure,
                _ => ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "the connection does not grant this Atlassian site",
                ),
            })
    }
}

#[async_trait::async_trait]
impl Provider for AtlassianSiteConsumer {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::no_resources())
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let credential = request.execution().delegated().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "Atlassian access is delegated",
            )
        })?;
        let mut access = self.pinned(credential).await?;
        let first = access.version().to_owned();
        if request.inputs()["recover"] == true {
            credential.mark_rejected(access.version())?;
            credential.recover_after_unauthorized().await?;
            access = self.pinned(credential).await?;
        }
        Ok(ProviderResult::new(json!({
            "target": access.target(),
            "audience": access.audience(),
            "firstVersion": first,
            "version": access.version(),
        })))
    }
}

/// The OAuth fixture with its stub registration replaced by an `atlassian`
/// registration for the site `CLOUD_ID`, whose dialect reaches the stub
/// `atlassian` and whose connection the site consumer uses as `oauth_stub`.
async fn atlassian_fixture(atlassian: &MockServer) -> OAuthFixture {
    let dialect = agent_access_atlassian::test_support::dialect(&atlassian.uri());
    oauth_fixture_with(
        Some("user:alice"),
        |_, config| {
            let stub = config.oauth.registrations.remove("stub").unwrap();
            config.oauth.registrations.insert(
                "atlassian".into(),
                OAuthRegistrationConfig {
                    login_binding: None,
                    adapter: OAuthAdapter::new("atlassian"),
                    base_url: "https://auth.atlassian.com".into(),
                    redirect_uri: CALLBACK.into(),
                    client_id: "broker-app".into(),
                    client_secret_ref: stub.client_secret_ref,
                    adapter_settings: Default::default(),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Json,
                    rotation: OAuthRotation::RotateRefresh,
                    allow_insecure_loopback: true,
                    permission_profiles: BTreeMap::from([(
                        "default".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(profile_scopes()),
                            audience: ATLASSIAN_OAUTH_AUDIENCE.into(),
                            target: CLOUD_ID.into(),
                        },
                    )]),
                },
            );
            config
                .credentials
                .connections
                .get_mut("oauth_stub")
                .unwrap()
                .oauth = Some(ConnectionOAuthConfig {
                registration: "atlassian".into(),
                profile: "default".into(),
            });
            config.providers = ProvidersConfig::new(Arc::new(
                crate::test_composition::backend_registry_replacing_with_dialect(
                    &ATLASSIAN_SITE_CONSUMER,
                    dialect,
                ),
            ))
            .with(agent_access_fake::FakeProviderConfig::default())
            .with(AtlassianSiteConsumer {
                cloud_id: CLOUD_ID.into(),
            });
        },
        Vec::new(),
    )
    .await
}

/// A token response granting `scope`, or without `scope` when `None`.
fn token(number: u32, scope: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": format!("atlassian-access-{number}"),
        "refresh_token": format!("atlassian-refresh-{number}"),
        "token_type": "Bearer",
        "expires_in": 3600
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

/// One `accessible-resources` entry: a site's product container.
fn site(id: &str, scopes: &[&str]) -> Value {
    json!({
        "id": id,
        "name": "example",
        "url": "https://example.atlassian.net",
        "scopes": scopes,
        "avatarUrl": "https://site-admin-avatar-cdn.example/avatars/240/site.png"
    })
}

/// The code exchange answers with `scope`, the account is alice's, and
/// `accessible-resources` lists `sites`.
async fn mount_consent(atlassian: &MockServer, scope: Option<&str>, sites: Value) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_partial_json(
            json!({"grant_type": "authorization_code"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(token(1, scope)))
        .mount(atlassian)
        .await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "account_id": ACCOUNT_ID,
            "email": "alice@example.com",
            "name": "Alice Example",
            "account_status": "active"
        })))
        .mount(atlassian)
        .await;
    mount_sites(atlassian, sites).await;
}

async fn mount_sites(atlassian: &MockServer, sites: Value) {
    Mock::given(method("GET"))
        .and(path("/oauth/token/accessible-resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sites))
        .mount(atlassian)
        .await;
}

async fn routes(atlassian: &MockServer) -> Vec<String> {
    atlassian
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect()
}

fn json_body(request: &wiremock::Request) -> Value {
    serde_json::from_slice(&request.body).unwrap()
}

impl OAuthFixture {
    /// Runs alice's consent on the `atlassian` registration through its
    /// callback, returning the authorization URL and the callback response.
    async fn atlassian_consent(&self) -> (String, url::Url, axum::response::Response) {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "atlassian-connect",
                Some(json!({"registration": "atlassian", "intent": "connect"})),
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
                    "/v1/oauth/callback/atlassian?{}",
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("state", &state)
                        .append_pair("code", "one-use-code")
                        .finish()
                ),
                "atlassian-callback",
                None,
            )
            .await;
        (state, authorization_url, callback)
    }

    fn atlassian_status(&self) -> agent_access_core::OAuthConnection {
        self.runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "atlassian")
            .unwrap()
    }
}

/// Consent asks for the gateway audience and fresh consent; the account is
/// `/me`'s `account_id`; the site's product containers merge into one target
/// with `read:me`, beside the other granted site, and extra scopes are kept
/// without harm. A consumer pins the site's cloud ID and the gateway
/// audience. A refresh without `scope` keeps the granted scopes and
/// revalidates the sites, and a refresh Atlassian answers with 403
/// `invalid_grant` requires reconnecting.
#[tokio::test]
async fn atlassian_consent_merges_the_site_and_refresh_keeps_the_granted_scopes() {
    let atlassian = MockServer::start().await;
    let fixture = atlassian_fixture(&atlassian).await;
    let granted = format!("{} read:account", profile_scopes().join(" "));
    let mut jira = JIRA_SCOPES.to_vec();
    jira.push("manage:jira-configuration");
    mount_consent(
        &atlassian,
        Some(&granted),
        json!([
            site(CLOUD_ID, &jira),
            site(OTHER_CLOUD_ID, &["read:jira-work"]),
            site(CLOUD_ID, &CONFLUENCE_SCOPES),
        ]),
    )
    .await;

    let (state, authorization_url, callback) = fixture.atlassian_consent().await;
    let query = authorization_url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(authorization_url.path(), "/authorize");
    assert_eq!(query["audience"], "api.atlassian.com");
    assert_eq!(query["prompt"], "consent");
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["redirect_uri"], CALLBACK);
    assert_eq!(query["scope"], profile_scopes().join(" "));
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query["code_challenge"].is_empty());
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    assert_eq!(
        routes(&atlassian).await,
        [
            "POST /oauth/token",
            "GET /me",
            "GET /oauth/token/accessible-resources"
        ]
    );
    let requests = atlassian.received_requests().await.unwrap();
    let exchange = json_body(&requests[0]);
    assert_eq!(
        header(&requests[0], "content-type"),
        Some("application/json")
    );
    let verifier = exchange["code_verifier"].as_str().unwrap();
    assert!(verifier.len() >= 43, "{exchange}");
    assert_eq!(
        exchange,
        json!({
            "grant_type": "authorization_code",
            "code": "one-use-code",
            "redirect_uri": CALLBACK,
            "code_verifier": verifier,
            "client_id": "broker-app",
            "client_secret": "stub-client-secret"
        })
    );
    for request in &requests[1..] {
        assert_eq!(
            header(request, "authorization"),
            Some("Bearer atlassian-access-1")
        );
    }

    let status = fixture.atlassian_status();
    assert!(status.connection_id.is_some());
    assert_eq!(status.subject_id.as_deref(), Some(ACCOUNT_ID));
    assert_eq!(status.display_name.as_deref(), Some("alice@example.com"));
    let mut site_scopes = scope_set(jira.iter().copied().chain(CONFLUENCE_SCOPES));
    site_scopes.insert("read:me".into());
    let other_scopes = scope_set(["read:jira-work", "read:me"]);
    let targets = status
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target.audience.as_str(), &target.scopes))
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            (CLOUD_ID, ATLASSIAN_OAUTH_AUDIENCE, &site_scopes),
            (OTHER_CLOUD_ID, ATLASSIAN_OAUTH_AUDIENCE, &other_scopes),
        ]
    );

    let (code, body) = fixture
        .invoke("account.view", "atlassian-pinned", json!({}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["target"], CLOUD_ID);
    assert_eq!(body["result"]["audience"], ATLASSIAN_OAUTH_AUDIENCE);
    let first_version = body["result"]["version"].clone();

    // The refresh answers without `scope`.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_partial_json(json!({"grant_type": "refresh_token"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token(2, None)))
        .mount(&atlassian)
        .await;
    let (code, body) = fixture
        .invoke(
            "account.view",
            "atlassian-recovered",
            json!({"recover": true}),
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["firstVersion"], first_version);
    assert_ne!(body["result"]["version"], first_version);
    assert_eq!(body["result"]["target"], CLOUD_ID);
    let requests = atlassian.received_requests().await.unwrap().split_off(3);
    assert_eq!(
        requests
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect::<Vec<_>>(),
        ["POST /oauth/token", "GET /oauth/token/accessible-resources"]
    );
    assert_eq!(
        json_body(&requests[0]),
        json!({
            "grant_type": "refresh_token",
            "refresh_token": "atlassian-refresh-1",
            "client_id": "broker-app",
            "client_secret": "stub-client-secret"
        })
    );
    assert_eq!(
        header(&requests[1], "authorization"),
        Some("Bearer atlassian-access-2")
    );
    let status = fixture.atlassian_status();
    assert_eq!(status.status, OAuthConnectionStatus::Ready);
    assert_eq!(status.subject_id.as_deref(), Some(ACCOUNT_ID));
    assert_eq!(status.targets[0].id, CLOUD_ID);
    assert_eq!(status.targets[0].scopes, site_scopes);

    // Atlassian refuses the next refresh: the rotated token was revoked.
    atlassian.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Unknown or invalid refresh token."
        })))
        .mount(&atlassian)
        .await;
    let (code, body) = fixture
        .invoke(
            "account.view",
            "atlassian-revoked",
            json!({"recover": true}),
        )
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
    assert_eq!(routes(&atlassian).await, ["POST /oauth/token"]);
    assert_eq!(
        fixture.atlassian_status().status,
        OAuthConnectionStatus::ReconnectRequired
    );
}

/// Installation stores nothing without scope evidence, for a grant on
/// another site, or for a site without one of the shared profile's products
/// (owner decision 8, option A); a later consent with the site and every
/// product, plus extra scopes, connects.
#[tokio::test]
async fn atlassian_installs_require_scope_evidence_the_site_and_every_product() {
    let atlassian = MockServer::start().await;
    let fixture = atlassian_fixture(&atlassian).await;
    let all = profile_scopes().join(" ");
    let jira_only = format!("read:me offline_access {}", JIRA_SCOPES.join(" "));
    let both_products = json!([
        site(CLOUD_ID, &JIRA_SCOPES),
        site(CLOUD_ID, &CONFLUENCE_SCOPES)
    ]);
    let consent_routes = [
        "POST /oauth/token",
        "GET /me",
        "GET /oauth/token/accessible-resources",
    ];
    for (scope, sites, error, sent) in [
        // No `scope` on the exchange: nothing is read after it.
        (
            None,
            both_products.clone(),
            "oauth_response_invalid",
            &consent_routes[..1],
        ),
        // The person picked another site.
        (
            Some(all.as_str()),
            json!([
                site(OTHER_CLOUD_ID, &JIRA_SCOPES),
                site(OTHER_CLOUD_ID, &CONFLUENCE_SCOPES)
            ]),
            "oauth_permission_denied",
            &consent_routes[..],
        ),
        // The site has Jira but not Confluence.
        (
            Some(jira_only.as_str()),
            json!([site(CLOUD_ID, &JIRA_SCOPES)]),
            "oauth_permission_denied",
            &consent_routes[..],
        ),
        // The token lacks Confluence's scopes that the site lists.
        (
            Some(jira_only.as_str()),
            both_products.clone(),
            "oauth_permission_denied",
            &consent_routes[..],
        ),
    ] {
        atlassian.reset().await;
        mount_consent(&atlassian, scope, sites).await;
        let (_, _, callback) = fixture.atlassian_consent().await;
        let status = callback.status();
        let body = response_json(callback).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["reasonCode"], "credential_invalid");
        assert_eq!(body["error"]["message"], error);
        assert_eq!(routes(&atlassian).await, sent, "{error}");
        let connection = fixture.atlassian_status();
        assert!(connection.connection_id.is_none());
        assert!(connection.targets.is_empty());
    }
    let (code, body) = fixture
        .invoke("account.view", "atlassian-unconnected", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");

    atlassian.reset().await;
    mount_consent(
        &atlassian,
        Some(&format!("{all} read:account write:confluence-content")),
        both_products,
    )
    .await;
    let (state, _, callback) = fixture.atlassian_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    assert!(fixture.atlassian_status().connection_id.is_some());
    let (code, body) = fixture
        .invoke("account.view", "atlassian-connected", json!({}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
}

/// What a full configuration fixes for Jira and Confluence on one site.
struct Deployment<'a> {
    /// Whether both providers allow `api.atlassian.com`.
    gateway: bool,
    /// The kind of each product's `credentials.service` entry.
    service: Option<&'a str>,
    /// `[credentials.connections.*]` and `[credentials.per_user.*]` tables.
    connections: &'a str,
    /// The cloud ID the `atlassian` registration's profile targets.
    target: &'a str,
    /// The `atlassian` registration's rotation.
    rotation: &'a str,
}

impl Default for Deployment<'_> {
    fn default() -> Self {
        Self {
            gateway: true,
            service: None,
            connections: "",
            target: CLOUD_ID,
            rotation: "rotate_refresh",
        }
    }
}

/// A registration table at `id` for the site `target`, requesting `scopes`.
fn registration_table(id: &str, target: &str, rotation: &str, scopes: &[String]) -> String {
    format!(
        r#"
[oauth.registrations.{id}]
adapter = "atlassian"
base_url = "https://auth.atlassian.com"
redirect_uri = "https://broker.example.com/v1/oauth/callback/{id}"
client_id = "{id}-app"
client_secret_ref = "file:/etc/agent-access-broker/secrets/{id}-oauth-client-secret"
client_auth = "client_secret_post"
encoding = "json"
rotation = "{rotation}"

[oauth.registrations.{id}.permission_profiles.default]
scopes = {scopes}
audience = "api.atlassian.com"
target = "{target}"
"#,
        scopes = serde_json::to_string(scopes).unwrap(),
    )
}

/// The production sample with Jira and Confluence on one site and the
/// shared `atlassian` registration.
fn atlassian_config(deployment: Deployment<'_>) -> String {
    let product_hosts = |site: &str, gateway: &str| {
        let mut hosts = vec![format!("https://example.atlassian.net/{site}")];
        if deployment.gateway {
            hosts.push(format!("https://api.atlassian.com/ex/{gateway}"));
        }
        serde_json::to_string(&hosts).unwrap()
    };
    let service = |product: &str| match deployment.service {
        Some("bearer_token") => format!(
            "[credentials.service.{product}]\ntype = \"bearer_token\"\ntoken_ref = \"file:/etc/agent-access-broker/secrets/{product}-service-token\"\n"
        ),
        Some("basic_api_token") => format!(
            "[credentials.service.{product}]\ntype = \"basic_api_token\"\nusername_ref = \"file:/etc/agent-access-broker/secrets/{product}-service-username\"\ntoken_ref = \"file:/etc/agent-access-broker/secrets/{product}-service-token\"\n"
        ),
        _ => String::new(),
    };
    format!(
        r#"{sample}
{registration}
{connections}
{jira_service}
{confluence_service}
[providers.jira]
tenant_host = "example.atlassian.net"
cloud_id = "{CLOUD_ID}"
allowed_upstream_hosts = {jira_hosts}

[providers.confluence]
tenant_host = "example.atlassian.net"
cloud_id = "{CLOUD_ID}"
allowed_upstream_hosts = {confluence_hosts}
"#,
        sample = include_str!("../../../../../agent-access-broker.production.sample.toml"),
        registration = registration_table(
            "atlassian",
            deployment.target,
            deployment.rotation,
            &profile_scopes()
        ),
        connections = deployment.connections,
        jira_service = service("jira"),
        confluence_service = service("confluence"),
        jira_hosts = product_hosts("rest/api/3/**", "jira/**"),
        confluence_hosts = product_hosts("wiki/**", "confluence/**"),
    )
}

/// Sorted validation errors of a full configuration.
fn validation_errors(raw: &str) -> Vec<String> {
    let config = agent_access_core::parse_broker_config_raw(
        "atlassian-oauth.toml",
        raw,
        &Arc::new(crate::test_composition::backend_registry()),
    )
    .unwrap();
    let mut errors = match validate_broker_config(&config) {
        Ok(()) => Vec::new(),
        Err(ConfigError::Invalid { errors }) => errors,
        Err(other) => panic!("unexpected validation failure: {other:?}"),
    };
    errors.sort();
    errors
}

fn sorted(errors: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut errors = errors.into_iter().collect::<Vec<_>>();
    errors.sort();
    errors
}

/// The core rejection of an OAuth connection whose consumer does not yet
/// declare delegated credentials. Jira and Confluence declare them in the
/// `atlassian-providers` lane, which removes these expectations.
fn not_yet_delegated(connection: &str, service: &str) -> String {
    format!(
        "credentials.connections.{connection}.oauth requires every consumer to accept delegated credentials, which {service} does not"
    )
}

/// A per-product connection consumed by its own product.
fn product_connections(
    token_profile: Option<&str>,
    registration: impl Fn(&str) -> String,
) -> String {
    ["jira", "confluence"]
        .map(|product| {
            let token = token_profile
                .map(|profile| format!("token_profile = \"{profile}\"\n"))
                .unwrap_or_default();
            format!(
                "[credentials.connections.{product}]\n{token}oauth = {{ registration = \"{}\", profile = \"default\" }}\n\n[credentials.per_user.{product}]\ntype = \"connection\"\nconnection = \"{product}\"\n",
                registration(product)
            )
        })
        .join("\n")
}

/// One `atlassian` connection both products consume.
fn shared_connection(token_profile: Option<&str>, oauth: bool) -> String {
    let token = token_profile
        .map(|profile| format!("token_profile = \"{profile}\"\n"))
        .unwrap_or_default();
    let oauth = if oauth {
        "oauth = { registration = \"atlassian\", profile = \"default\" }\n"
    } else {
        ""
    };
    format!(
        "[credentials.connections.atlassian]\ndisplay_name = \"Atlassian\"\n{token}{oauth}\n[credentials.per_user.jira]\ntype = \"connection\"\nconnection = \"atlassian\"\n\n[credentials.per_user.confluence]\ntype = \"connection\"\nconnection = \"atlassian\"\n"
    )
}

/// Every row of the Atlassian connection table, including simultaneous
/// bearer service credentials, through offline validation of full
/// configurations. Until Jira and Confluence declare delegated credentials,
/// the OAuth rows also report that they do not (see [`not_yet_delegated`]);
/// no other error remains for a supported row.
#[test]
fn atlassian_oauth_connections_follow_the_validation_table() {
    let none: Vec<String> = Vec::new();
    let basic_with_oauth = |service: &str| {
        format!(
            "credentials.per_user.{service} combines OAuth with a basic_api_token profile; OAuth acts through the Atlassian gateway, so the connection's token_profile must be atlassian-bearer-token or absent"
        )
    };
    let oauth_needs_gateway = |service: &str| {
        format!(
            "credentials.per_user.{service} offers delegated (OAuth) access, which requires providers.{service}.allowed_upstream_hosts to include api.atlassian.com"
        )
    };
    let site_route = |connection: &str, service: &str| {
        format!(
            "credentials.connections.{connection}.oauth: {service} does not act on the upstream registration atlassian grants access to: it acts on https://example.atlassian.net (tenant {CLOUD_ID}) without the Atlassian gateway, and the grants act only through the gateway on cloud ID {CLOUD_ID}"
        )
    };
    let shared_pending = || {
        [
            not_yet_delegated("atlassian", "jira"),
            not_yet_delegated("atlassian", "confluence"),
        ]
    };
    let product_pending = || {
        [
            not_yet_delegated("jira", "jira"),
            not_yet_delegated("confluence", "confluence"),
        ]
    };

    // Token only, atlassian-api-token, gateway off: the site route.
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            gateway: false,
            service: Some("basic_api_token"),
            connections: &shared_connection(Some("atlassian-api-token"), false),
            ..Deployment::default()
        })),
        none
    );
    // Token only, atlassian-bearer-token, gateway on.
    let bearer_tokens = ["jira", "confluence"]
        .map(|product| {
            format!(
                "[credentials.connections.{product}]\ntoken_profile = \"atlassian-bearer-token\"\n\n[credentials.per_user.{product}]\ntype = \"connection\"\nconnection = \"{product}\"\n"
            )
        })
        .join("\n");
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            service: Some("bearer_token"),
            connections: &bearer_tokens,
            ..Deployment::default()
        })),
        none
    );
    // OAuth only, gateway on, with and without bearer service credentials.
    for service in [None, Some("bearer_token")] {
        assert_eq!(
            validation_errors(&atlassian_config(Deployment {
                service,
                connections: &shared_connection(None, true),
                ..Deployment::default()
            })),
            sorted(shared_pending()),
            "{service:?}"
        );
    }
    // OAuth only requires the gateway.
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            gateway: false,
            connections: &shared_connection(None, true),
            ..Deployment::default()
        })),
        sorted(
            [
                oauth_needs_gateway("jira"),
                oauth_needs_gateway("confluence"),
                site_route("atlassian", "jira"),
                site_route("atlassian", "confluence"),
            ]
            .into_iter()
            .chain(shared_pending())
        )
    );
    // atlassian-bearer-token and OAuth on per-product connections sharing
    // one registration, with simultaneous bearer service credentials:
    // people use OAuth, service accounts bearer tokens, all through the
    // gateway.
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            service: Some("bearer_token"),
            connections: &product_connections(Some("atlassian-bearer-token"), |_| {
                "atlassian".into()
            }),
            ..Deployment::default()
        })),
        sorted(product_pending())
    );
    // atlassian-api-token and OAuth is rejected, with the gateway on or off.
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            service: Some("bearer_token"),
            connections: &shared_connection(Some("atlassian-api-token"), true),
            ..Deployment::default()
        })),
        sorted(
            [basic_with_oauth("jira"), basic_with_oauth("confluence")]
                .into_iter()
                .chain(shared_pending())
        )
    );
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            gateway: false,
            service: Some("basic_api_token"),
            connections: &shared_connection(Some("atlassian-api-token"), true),
            ..Deployment::default()
        })),
        sorted(
            [
                basic_with_oauth("jira"),
                basic_with_oauth("confluence"),
                oauth_needs_gateway("jira"),
                oauth_needs_gateway("confluence"),
                site_route("atlassian", "jira"),
                site_route("atlassian", "confluence"),
            ]
            .into_iter()
            .chain(shared_pending())
        )
    );
}

/// Owner decision 8, option A: a deployment with single-product users gives
/// each product connection its own registration, each requesting only its
/// product's scopes with `read:me` and `offline_access`.
#[test]
fn per_product_registrations_validate_for_single_product_deployments() {
    let scopes = |product: &[&str]| {
        ["read:me", "offline_access"]
            .into_iter()
            .chain(product.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let raw = format!(
        "{}{}{}",
        atlassian_config(Deployment {
            service: Some("bearer_token"),
            connections: &product_connections(Some("atlassian-bearer-token"), |product| {
                format!("atlassian_{product}")
            }),
            ..Deployment::default()
        }),
        registration_table(
            "atlassian_jira",
            CLOUD_ID,
            "rotate_refresh",
            &scopes(&JIRA_SCOPES)
        ),
        registration_table(
            "atlassian_confluence",
            CLOUD_ID,
            "rotate_refresh",
            &scopes(&CONFLUENCE_SCOPES)
        ),
    );
    assert_eq!(
        validation_errors(&raw),
        sorted([
            not_yet_delegated("jira", "jira"),
            not_yet_delegated("confluence", "confluence"),
        ])
    );
}

#[test]
fn atlassian_registration_and_site_mismatches_fail_offline_validation() {
    let elsewhere = |service: &str| {
        format!(
            "credentials.connections.atlassian.oauth: {service} does not act on the upstream registration atlassian grants access to: it acts through the Atlassian gateway on cloud ID {CLOUD_ID}, not cloud ID {OTHER_CLOUD_ID}"
        )
    };
    let pending = [
        not_yet_delegated("atlassian", "jira"),
        not_yet_delegated("atlassian", "confluence"),
    ];
    // The registration targets another site than Jira and Confluence use.
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            connections: &shared_connection(None, true),
            target: OTHER_CLOUD_ID,
            ..Deployment::default()
        })),
        sorted(
            [elsewhere("jira"), elsewhere("confluence")]
                .into_iter()
                .chain(pending.clone())
        )
    );
    assert_eq!(
        validation_errors(&atlassian_config(Deployment {
            connections: &shared_connection(None, true),
            rotation: "rotate_both",
            ..Deployment::default()
        })),
        sorted(
            [
                "oauth.registrations.atlassian is not a valid atlassian registration: Atlassian requires rotation = \"rotate_refresh\": every refresh replaces the refresh token".to_owned()
            ]
            .into_iter()
            .chain(pending)
        )
    );
}
