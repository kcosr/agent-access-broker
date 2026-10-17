//! The `gitlab` OAuth dialect through the Broker's consent and lease
//! lifecycle against a stubbed GitLab instance, and offline validation of
//! GitLab REST and a GitLab Git gateway sharing one GitLab OAuth connection.
use super::*;
use agent_access_core::{ConfigError, ConnectionOAuthConfig, validate_broker_config};
use agent_access_provider::test_support::DescribedProvider;
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, DelegatedAccess, DelegatedAccessError,
    DelegatedCredential, OAuthClientAuth, OAuthRotation, OAuthScopeMode, OAuthTokenEncoding,
    Provider, ProviderError, ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution,
    ServiceDescriptor, ServiceProvider, UpstreamAuthority,
};
use std::sync::Mutex;

#[path = "gitlab_login_binding.rs"]
mod login_binding;

const CALLBACK: &str = "http://127.0.0.1/v1/oauth/callback/gitlab";

/// What a GitLab consumer pins: the normalized instance base its upstream
/// authority names, with the `gitlab` audience.
fn instance_target(instance: &UpstreamAuthority) -> String {
    format!("{}{}", instance.origin(), instance.instance_path())
}

/// A consumer on the stubbed GitLab instance, served as `oauth_stub`. Its
/// `account.view` pins the connection's access to the instance target and
/// the `gitlab` audience before each use, as GitLab consumers do, and
/// replaces the access once when asked to.
struct InstanceConsumer {
    instance: UpstreamAuthority,
    /// The access version of each pinned use.
    versions: Mutex<Vec<String>>,
}

impl InstanceConsumer {
    fn new(base_url: &str) -> Arc<Self> {
        Arc::new(Self {
            instance: UpstreamAuthority::from_base_url(base_url).unwrap(),
            versions: Mutex::default(),
        })
    }

    async fn pinned(
        &self,
        credential: &DelegatedCredential,
    ) -> Result<DelegatedAccess, ProviderError> {
        let access = credential
            .revalidated_access_for(&instance_target(&self.instance), "gitlab")
            .await
            .map_err(|error| match error {
                DelegatedAccessError::Revalidation(failure) => failure,
                _ => ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "the connection does not grant this GitLab instance",
                ),
            })?;
        self.versions
            .lock()
            .unwrap()
            .push(access.version().to_owned());
        Ok(access)
    }

    fn versions(&self) -> Vec<String> {
        self.versions.lock().unwrap().clone()
    }
}

impl DescribedProvider for InstanceConsumer {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("oauth_stub", "GitLab instance consumer")
            .with_actions(vec![
                ActionDescriptor::new(
                    "account.view",
                    "Read the connected GitLab account",
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
                    .delegated("Lets agents act as your GitLab account."),
            )
            .with_upstream_authority(self.instance.clone())
    }
}

#[async_trait::async_trait]
impl Provider for InstanceConsumer {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::no_resources())
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let credential = request.execution().delegated().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "GitLab access is delegated",
            )
        })?;
        let mut access = self.pinned(credential).await?;
        if request.inputs()["recover"] == true {
            // As after an upstream 401: reject this access and replace it once.
            credential.mark_rejected(access.version())?;
            credential.recover_after_unauthorized().await?;
            access = self.pinned(credential).await?;
        }
        Ok(ProviderResult::new(
            json!({"target": access.target(), "audience": access.audience()}),
        ))
    }
}

/// The OAuth fixture with its stub registration replaced by a `gitlab`
/// registration on the stubbed instance `gitlab`, whose connection
/// `consumer` serves as `oauth_stub`.
async fn gitlab_fixture(gitlab: &MockServer, consumer: &Arc<InstanceConsumer>) -> OAuthFixture {
    gitlab_fixture_with(gitlab, consumer, |_, _| {}).await
}

/// [`gitlab_fixture`] after `adjust` changes its configuration further.
async fn gitlab_fixture_with(
    gitlab: &MockServer,
    consumer: &Arc<InstanceConsumer>,
    adjust: impl FnOnce(&Path, &mut BrokerConfig),
) -> OAuthFixture {
    let instance = gitlab.uri();
    oauth_fixture_with(
        Some("user:alice"),
        |directory, config| {
            let stub = config.oauth.registrations.remove("stub").unwrap();
            config.oauth.registrations.insert(
                "gitlab".into(),
                OAuthRegistrationConfig {
                    login_binding: None,
                    adapter: OAuthAdapter::new("gitlab"),
                    base_url: instance.clone(),
                    redirect_uri: CALLBACK.into(),
                    client_id: "broker-app".into(),
                    client_secret_ref: stub.client_secret_ref,
                    adapter_settings: Default::default(),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Form,
                    rotation: OAuthRotation::RotateBoth,
                    allow_insecure_loopback: true,
                    permission_profiles: BTreeMap::from([(
                        "default".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(vec!["api".into(), "write_repository".into()]),
                            audience: "gitlab".into(),
                            target: instance.clone(),
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
                registration: "gitlab".into(),
                profile: "default".into(),
            });
            // The consumer acts on the GitLab instance.
            config
                .providers
                .insert(agent_access_fake::OAuthStubProviderConfig {
                    base_url: instance.clone(),
                });
            adjust(directory, config);
        },
        vec![ServiceProvider::from(Arc::clone(consumer))],
    )
    .await
}

/// The code exchange answers without `scope`, so the dialect reads the new
/// token's info, which answers with `token_info`.
async fn mount_exchange(gitlab: &MockServer, token_info: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gitlab-access-1",
            "refresh_token": "gitlab-refresh-1",
            "token_type": "Bearer",
            "expires_in": 7200,
            "created_at": 1_760_000_000
        })))
        .mount(gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/oauth/token/info"))
        .respond_with(token_info)
        .mount(gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "username": "alice",
            "name": "Alice Example"
        })))
        .mount(gitlab)
        .await;
}

fn token_info_scopes() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "resource_owner_id": 42,
        "scope": ["api", "write_repository"],
        "expires_in": 7199,
        "application": {"uid": "broker-app"},
        "created_at": 1_760_000_000
    }))
}

async fn routes(gitlab: &MockServer) -> Vec<String> {
    gitlab
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect()
}

impl OAuthFixture {
    /// Runs alice's consent on the `gitlab` registration through its
    /// callback.
    async fn gitlab_consent(&self) -> (String, axum::response::Response) {
        let connect = self
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "gitlab-connect",
                Some(json!({"registration": "gitlab", "intent": "connect"})),
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
                    "/v1/oauth/callback/gitlab?{}",
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("state", &state)
                        .append_pair("code", "one-use-code")
                        .finish()
                ),
                "gitlab-callback",
                None,
            )
            .await;
        (state, callback)
    }

    fn gitlab_status(&self) -> agent_access_core::OAuthConnection {
        self.runtime
            .oauth_manager()
            .unwrap()
            .status("alice", "gitlab")
            .unwrap()
    }
}

/// Consent without a response `scope` takes the token info's scopes and the
/// `/api/v4/user` identity; leases carry the instance target and `gitlab`
/// audience a consumer pins; a refresh without `scope` keeps the granted
/// scopes and sends nothing else before the successor is stored.
#[tokio::test]
async fn gitlab_consent_reads_token_info_and_refresh_keeps_the_granted_scopes() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = gitlab_fixture(&gitlab, &consumer).await;
    mount_exchange(&gitlab, token_info_scopes()).await;

    let (state, callback) = fixture.gitlab_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    assert_eq!(
        routes(&gitlab).await,
        [
            "POST /oauth/token",
            "GET /oauth/token/info",
            "GET /api/v4/user"
        ]
    );
    let requests = gitlab.received_requests().await.unwrap();
    assert_eq!(
        header(&requests[1], "authorization"),
        Some("Bearer gitlab-access-1")
    );
    let status = fixture.gitlab_status();
    assert!(status.connection_id.is_some());
    assert_eq!(status.subject_id.as_deref(), Some("42"));
    assert_eq!(status.display_name.as_deref(), Some("alice"));
    let granted = BTreeSet::from(["api".to_owned(), "write_repository".to_owned()]);
    let targets = status
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target.audience.as_str(), &target.scopes))
        .collect::<Vec<_>>();
    assert_eq!(targets, [(gitlab.uri().as_str(), "gitlab", &granted)]);

    let (code, body) = fixture
        .invoke("account.view", "gitlab-pinned", json!({}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(
        body["result"],
        json!({"target": gitlab.uri(), "audience": "gitlab"})
    );

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gitlab-access-2",
            "refresh_token": "gitlab-refresh-2",
            "token_type": "Bearer",
            "expires_in": 7200
        })))
        .mount(&gitlab)
        .await;
    let (code, body) = fixture
        .invoke("account.view", "gitlab-recovered", json!({"recover": true}))
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let requests = gitlab.received_requests().await.unwrap().split_off(3);
    assert_eq!(
        requests
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect::<Vec<_>>(),
        ["POST /oauth/token"]
    );
    let refresh = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        refresh,
        BTreeMap::from(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", "gitlab-refresh-1"),
                ("redirect_uri", CALLBACK),
                ("client_id", "broker-app"),
                ("client_secret", "stub-client-secret"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
    let versions = consumer.versions();
    assert_eq!(versions.len(), 3, "{versions:?}");
    assert_eq!(versions[0], versions[1]);
    assert_ne!(versions[1], versions[2]);
    let status = fixture.gitlab_status();
    assert_eq!(status.subject_id.as_deref(), Some("42"));
    assert_eq!(status.targets.len(), 1);
    assert_eq!(status.targets[0].scopes, granted);
}

/// The exchange answers without `scope` and token info fails, so the
/// installation fails before anything is stored and no identity request
/// is made. A later consent starts afresh.
#[tokio::test]
async fn a_token_info_failure_fails_the_gitlab_install_and_stores_nothing() {
    let gitlab = MockServer::start().await;
    let consumer = InstanceConsumer::new(&gitlab.uri());
    let fixture = gitlab_fixture(&gitlab, &consumer).await;
    mount_exchange(&gitlab, ResponseTemplate::new(503)).await;

    let (_, callback) = fixture.gitlab_consent().await;
    let status = callback.status();
    let body = response_json(callback).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["message"], "oauth_provider_failed");
    assert_eq!(
        routes(&gitlab).await,
        ["POST /oauth/token", "GET /oauth/token/info"]
    );
    let connection = fixture.gitlab_status();
    assert!(connection.connection_id.is_none());
    assert!(connection.targets.is_empty());
    let (code, body) = fixture
        .invoke("account.view", "gitlab-unconnected", json!({}))
        .await;
    assert_ne!(code, StatusCode::OK, "{body}");
    assert!(consumer.versions().is_empty());

    gitlab.reset().await;
    mount_exchange(&gitlab, token_info_scopes()).await;
    let (state, callback) = fixture.gitlab_consent().await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
    assert!(fixture.gitlab_status().connection_id.is_some());
}

/// The production sample with GitLab REST and a GitLab Git gateway on
/// `gateway_base` sharing one `gitlab` connection, which people connect
/// through a GitLab registration on `registration_base` targeting `target`.
fn gitlab_oauth_config(
    registration_base: &str,
    target: &str,
    rotation: &str,
    gateway_base: &str,
) -> String {
    format!(
        r#"{sample}
[oauth.registrations.gitlab]
adapter = "gitlab"
base_url = "{registration_base}"
redirect_uri = "https://broker.example.com/v1/oauth/callback/gitlab"
client_id = "broker-app"
client_secret_ref = "file:/etc/agent-access-broker/secrets/gitlab-oauth-client-secret"
client_auth = "client_secret_post"
rotation = "{rotation}"

[oauth.registrations.gitlab.permission_profiles.default]
scopes = ["api", "write_repository"]
audience = "gitlab"
target = "{target}"

[credentials.connections.gitlab]
display_name = "GitLab"
token_profile = "gitlab-access-token"
oauth = {{ registration = "gitlab", profile = "default" }}

[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"

[credentials.per_user.gitlab_git]
type = "connection"
connection = "gitlab"

[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]

[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.example.test"]
upstream_base_url = "{gateway_base}"
allowed_upstream_hosts = ["{gateway_base}/**"]
auth_modes = ["basic_broker_token"]
basic_broker_token_username = "agent-access"
credential_modes = ["per_user"]
upstream_token_auth = {{ scheme = "basic", username = "oauth2" }}

[gateways.gitlab_git.git]
allow_fetch = true
allow_push = true
"#,
        sample = include_str!("../../../../../agent-access-broker.production.sample.toml"),
    )
}

fn validation_errors(raw: &str) -> Vec<String> {
    let config = agent_access_core::parse_broker_config_raw(
        "gitlab-oauth.toml",
        raw,
        &Arc::new(crate::test_composition::backend_registry()),
    )
    .unwrap();
    match validate_broker_config(&config) {
        Ok(()) => Vec::new(),
        Err(ConfigError::Invalid { errors }) => errors,
        Err(other) => panic!("unexpected validation failure: {other:?}"),
    }
}

/// GitLab REST and a GitLab Git gateway on the registration's instance pass
/// the dialect's offline authority check, in production, and both accept
/// delegated credentials, so the shared OAuth connection validates.
#[test]
fn gitlab_rest_and_git_share_one_gitlab_oauth_connection_on_the_instance() {
    let none: [String; 0] = [];
    let base = "https://gitlab.example.com";
    assert_eq!(
        validation_errors(&gitlab_oauth_config(base, base, "rotate_both", base)),
        none
    );
    // The registration's base URL normalizes to the written target.
    assert_eq!(
        validation_errors(&gitlab_oauth_config(
            "https://GitLab.example.com:443/",
            base,
            "rotate_both",
            "https://gitlab.example.com/"
        )),
        none
    );
}

#[test]
fn gitlab_registration_and_consumer_mismatches_fail_offline_validation() {
    let base = "https://gitlab.example.com";
    let registration = |reason: &str| {
        format!("oauth.registrations.gitlab is not a valid gitlab registration: {reason}")
    };
    let elsewhere = |service: &str, consumer: &str, instance: &str| {
        format!(
            "credentials.connections.gitlab.oauth: {service} does not act on the upstream registration gitlab grants access to: it acts on {consumer}, not the GitLab instance {instance}"
        )
    };

    // A target written other than as the normalized instance base.
    assert_eq!(
        validation_errors(&gitlab_oauth_config(
            base,
            "https://gitlab.example.com/",
            "rotate_both",
            base
        )),
        [registration(
            "permission_profiles.default.target must be the GitLab instance base https://gitlab.example.com"
        ),]
    );
    // A target on another instance than its consumers.
    let other = "https://gitlab.other.example";
    assert_eq!(
        validation_errors(&gitlab_oauth_config(base, other, "rotate_both", base)),
        [
            registration(
                "permission_profiles.default.target must be the GitLab instance base https://gitlab.example.com"
            ),
            elsewhere("gitlab", base, other),
            elsewhere("gitlab_git", base, other),
        ]
    );
    // A gateway on another instance than the registration and GitLab REST.
    assert_eq!(
        validation_errors(&gitlab_oauth_config(base, base, "rotate_both", other)),
        [
            format!(
                "credentials.connections.gitlab: gitlab acts on {base} but gitlab_git acts on {other}; a token connection's consumers must act on one upstream"
            ),
            elsewhere("gitlab_git", other, base),
        ]
    );
    assert_eq!(
        validation_errors(&gitlab_oauth_config(base, base, "rotate_refresh", base)),
        [registration(
            "GitLab requires rotation = \"rotate_both\": every refresh replaces both the access and the refresh token"
        ),]
    );
}
