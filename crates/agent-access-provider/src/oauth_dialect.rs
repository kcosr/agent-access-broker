//! OAuth dialects: how the broker talks to one family of authorization
//! servers. Core's OAuth manager owns consent flows, credential encryption,
//! refresh coordination, fences, and retry budgets; a dialect owns the wire:
//! the authorization URL, token requests, identity and target discovery, and
//! how failures classify. Dialects register with the broker binary, so an
//! authorization server family can live outside core.
use crate::{
    ClientProfile, HostError, UpstreamCall, UpstreamClient, UpstreamClientSpec, UpstreamError,
    UpstreamNetwork, complete_upstream_trace,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Largest OAuth response body the broker reads.
pub const OAUTH_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Every OAuth request completes within this bound, well inside a refresh
/// attempt's lifetime.
const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The registered dialect a registration speaks, such as `stub`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OAuthAdapter(Cow<'static, str>);

impl OAuthAdapter {
    pub const STUB: Self = Self(Cow::Borrowed("stub"));

    pub fn new(id: impl Into<String>) -> Self {
        Self(Cow::Owned(id.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRegistrationConfig {
    pub adapter: OAuthAdapter,
    pub base_url: String,
    pub redirect_uri: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_ref: String,
    /// Operator-approved dialect settings; never populated from imported tool metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_settings: BTreeMap<String, String>,
    #[serde(default)]
    pub client_auth: OAuthClientAuth,
    #[serde(default)]
    pub encoding: OAuthTokenEncoding,
    #[serde(default)]
    pub rotation: OAuthRotation,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    pub permission_profiles: BTreeMap<String, OAuthPermissionProfile>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthClientAuth {
    None,
    #[default]
    ClientSecretPost,
    ClientSecretBasic,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthTokenEncoding {
    #[default]
    Form,
    Json,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthRotation {
    PreserveOld,
    #[default]
    RotateRefresh,
    RotateBoth,
}

/// Whether a permission profile requests configured scopes or leaves the
/// resource-bound authorization decision to the authorization server.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthScopeMode {
    #[default]
    Explicit,
    ServerDefault,
}

impl OAuthScopeMode {
    pub fn is_explicit(&self) -> bool {
        *self == Self::Explicit
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthPermissionProfile {
    // Omitting the default mode preserves existing registration fingerprints.
    #[serde(default, skip_serializing_if = "OAuthScopeMode::is_explicit")]
    pub scope_mode: OAuthScopeMode,
    /// Must be present and nonempty for explicit mode, absent for server default.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_scopes"
    )]
    pub scopes: Option<Vec<String>>,
    pub audience: String,
    pub target: String,
}

impl OAuthPermissionProfile {
    pub fn requested_scopes(&self) -> &[String] {
        self.scopes.as_deref().unwrap_or_default()
    }
}

// A supplied null is not the same as an omitted configuration field.
fn present_scopes<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

/// A resource the authorization server lets a connection reach, with the
/// scopes it grants there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTarget {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub audience: String,
    pub scopes: BTreeSet<String>,
}

/// A dialect the broker binary links, under the `adapter` name registrations
/// select it by.
pub struct OAuthDialectRegistration {
    pub id: &'static str,
    /// Allowed only in non-production deployments with the development
    /// fixtures enabled.
    pub development_only: bool,
    pub dialect: &'static dyn OAuthDialect,
}

impl std::fmt::Debug for OAuthDialectRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthDialectRegistration")
            .field("id", &self.id)
            .field("development_only", &self.development_only)
            .finish_non_exhaustive()
    }
}

/// One registration as its dialect sees it.
pub struct OAuthClient<'a> {
    pub registration_id: &'a str,
    pub config: &'a OAuthRegistrationConfig,
    pub client_secret: &'a str,
}

impl std::fmt::Debug for OAuthClient<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthClient")
            .field("registration_id", &self.registration_id)
            .finish_non_exhaustive()
    }
}

/// What the authorization URL carries for one consent flow.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRequest<'a> {
    pub state: &'a str,
    /// The PKCE S256 challenge.
    pub code_challenge_s256: &'a str,
}

/// An authorization code to exchange, with its PKCE verifier.
#[derive(Clone, Copy)]
pub struct CodeExchange<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub profile: &'a OAuthPermissionProfile,
}

/// What a token response says about the refresh token.
pub enum IssuedRefreshToken {
    /// A new refresh token replaces the old one.
    Issued(String),
    /// No new token was issued and the old one stays valid.
    Retained,
    /// No refresh token was issued.
    Absent,
}

/// A token response. The manager validates its bounds.
pub struct TokenGrant {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// Known access-token scopes, from the response or protocol-defined inference.
    /// Empty represents unknown server-default permissions, never explicit authority.
    pub scopes: Vec<String>,
    pub refresh_token: IssuedRefreshToken,
    /// Whether this grant invalidates access tokens issued earlier for other
    /// permission profiles of the same connection.
    pub supersedes_other_access: bool,
}

/// Optional upstream account evidence. When present, the subject must be stable
/// across code exchange and later consent revalidation. Authorization-only
/// protocols must leave it absent instead of inventing an upstream user.
pub struct ConnectedIdentity {
    /// None means the grant authorizes a resource but proves no upstream account identity.
    pub subject: Option<String>,
    pub display_name: String,
}

/// How an OAuth request failed. The manager's refresh fences depend on the
/// distinction between failures that provably left a grant unused and those
/// that might have consumed it: a dialect must report `RetryAfter`,
/// `PermissionRejected`, and `RequestRejected` only when the authorization
/// server guarantees the grant was not consumed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OAuthDialectError {
    #[error("OAuth request was not sent")]
    NotSent,
    #[error("OAuth provider request failed")]
    Failed,
    #[error("OAuth provider response is invalid")]
    InvalidResponse,
    /// Token endpoint only.
    #[error("OAuth provider asked to retry after {0} seconds")]
    RetryAfter(u64),
    #[error("OAuth provider is throttling requests")]
    Throttled,
    #[error("OAuth provider rejected the requested permission")]
    PermissionRejected,
    #[error("OAuth provider rejected the request")]
    RequestRejected,
    #[error("OAuth grant is no longer valid")]
    GrantInvalid,
    #[error("OAuth provider rejected the application credential")]
    ClientRejected,
    #[error("OAuth registration is invalid for its dialect")]
    Configuration,
}

/// Whether an uncertain refresh exchange may safely reuse its input material.
/// This is a provider guarantee, independent of successful-response rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReplay {
    Consuming,
    Reusable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallbackIssuer {
    pub value: String,
    pub required: bool,
}

pub struct PreparedAuthorization {
    pub url: Url,
    pub callback_issuer: OAuthCallbackIssuer,
}

impl OAuthCallbackIssuer {
    pub fn accepts(&self, actual: Option<&str>) -> bool {
        match actual {
            Some(value) => value == self.value,
            None => !self.required,
        }
    }
}

/// One family of authorization servers. Each token method sends at most one
/// request and never retries.
#[async_trait]
pub trait OAuthDialect: Send + Sync + 'static {
    /// Whether registrations may explicitly opt in to server-default permissions.
    fn supports_server_default_scopes(&self) -> bool {
        false
    }

    /// Initial consent may omit refresh capability only when the dialect opts in.
    fn allows_access_without_refresh(&self) -> bool {
        false
    }
    /// Checks the dialect adds to a registration's generic validation; the
    /// error explains, without secrets, what the registration must change.
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String>;

    /// URL patterns the registration's requests may reach.
    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String>;

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError>;

    /// Dynamic dialects validate metadata before redirecting. The manager binds
    /// this issuer policy to the same flow record as state and the PKCE verifier.
    async fn prepare_authorization(
        &self,
        _http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<PreparedAuthorization, OAuthDialectError> {
        Ok(PreparedAuthorization {
            url: self.authorization_url(client, profile, request)?,
            callback_issuer: self.callback_issuer(client.config),
        })
    }

    /// The `iss` a consent callback must carry, when the dialect requires one.
    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer;

    fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay;

    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError>;

    /// `granted_scopes` is original consent evidence, never scopes learned only
    /// from later access-token responses. Empty means consent scopes are unknown.
    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError>;

    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError>;

    /// Receives validated known token scopes, including protocol-defined inference
    /// for omitted response scopes. Empty means unknown server-default permissions.
    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError>;
}

/// A registration's HTTP transport: an [`UpstreamClient`] with OAuth's own
/// timeouts, sending each request once.
#[derive(Debug, Clone)]
pub struct OAuthHttp {
    client: UpstreamClient,
    destinations: BTreeMap<String, UpstreamClient>,
}

impl OAuthHttp {
    /// Builds one client per approved destination origin, each routed on its
    /// own. A literal IPv4/IPv6 loopback origin connects directly; every other
    /// origin, including `localhost`, follows the host's proxy selection, so a
    /// loopback issuer never exempts another destination. Plain HTTP is
    /// accepted only for literal loopback origins.
    pub fn build(
        label: &str,
        provider: &'static str,
        base: &Url,
        allowed_upstream_hosts: &[String],
        network: UpstreamNetwork<'_>,
    ) -> Result<Self, HostError> {
        let direct = crate::EgressProxyRuntimeConfig::direct();
        let build = |base: &Url| {
            let loopback = crate::is_literal_loopback(base);
            if base.scheme() != "https" && !(loopback && base.scheme() == "http") {
                return Err(HostError::invalid(
                    "OAuth destinations require HTTPS; plain HTTP is limited to literal loopback IP addresses",
                ));
            }
            UpstreamClient::build(
                UpstreamClientSpec {
                    label,
                    provider,
                    base,
                    egress_proxy: None,
                    allowed_upstream_hosts,
                    profile: ClientProfile::Bounded {
                        total: OAUTH_REQUEST_TIMEOUT,
                        connect: OAUTH_CONNECT_TIMEOUT,
                    },
                    status_reasons: &[],
                },
                if loopback {
                    UpstreamNetwork {
                        egress: &direct,
                        ..network
                    }
                } else {
                    network
                },
            )
        };
        let client = build(base)?;
        let mut destinations = BTreeMap::new();
        for pattern in allowed_upstream_hosts {
            let endpoint = Url::parse(pattern)
                .map_err(|_| HostError::invalid("OAuth allowlist requires URL destinations"))?;
            if endpoint.host_str().is_none_or(|host| host.contains('*'))
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
            {
                return Err(HostError::invalid(
                    "OAuth allowlist requires fixed HTTP(S) destination origins",
                ));
            }
            let origin = endpoint.origin().ascii_serialization();
            if let std::collections::btree_map::Entry::Vacant(entry) = destinations.entry(origin) {
                entry.insert(build(&endpoint)?);
            }
        }
        Ok(Self {
            client,
            destinations,
        })
    }

    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.destinations
            .get(&url.origin().ascii_serialization())
            .unwrap_or(&self.client)
            .request(method, url)
    }

    /// Sends a request once. A request that never reached the server,
    /// including one outside the allowlist, fails as `NotSent`.
    pub async fn send(
        &self,
        request: RequestBuilder,
        operation: &str,
    ) -> Result<OAuthResponse, OAuthDialectError> {
        let (request_client, request) = request.build_split();
        let request = request.map_err(|_| OAuthDialectError::NotSent)?;
        let destination = self
            .destinations
            .get(&request.url().origin().ascii_serialization())
            .ok_or(OAuthDialectError::NotSent)?;
        let mut response = destination
            .send(
                RequestBuilder::from_parts(request_client, request),
                UpstreamCall::new(operation),
            )
            .await
            .map_err(|error| match error {
                UpstreamError::NotAllowed | UpstreamError::NotSent { .. } => {
                    OAuthDialectError::NotSent
                }
                UpstreamError::Timeout | UpstreamError::Transport(_) | UpstreamError::Redirect => {
                    OAuthDialectError::Failed
                }
            })?;
        complete_upstream_trace(&mut response, None);
        Ok(OAuthResponse { response })
    }
}

/// A response whose status is known before its body is read.
pub struct OAuthResponse {
    response: Response,
}

impl OAuthResponse {
    pub fn status(&self) -> u16 {
        self.response.status().as_u16()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    /// The body as JSON, read within [`OAUTH_MAX_RESPONSE_BYTES`].
    pub async fn json(self) -> Result<Value, OAuthDialectError> {
        if self
            .response
            .content_length()
            .is_some_and(|length| length > OAUTH_MAX_RESPONSE_BYTES as u64)
        {
            return Err(OAuthDialectError::InvalidResponse);
        }
        let mut stream = self.response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| OAuthDialectError::Failed)?;
            if body.len() + chunk.len() > OAUTH_MAX_RESPONSE_BYTES {
                return Err(OAuthDialectError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| OAuthDialectError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EgressProxyEnvironment, EgressProxyRuntimeConfig, ProviderLimits, test_support};
    use std::sync::Arc;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    #[test]
    fn permission_profiles_preserve_explicit_serialization_and_reject_null_scopes() {
        let old = serde_json::json!({
            "scopes": ["records.read"], "audience": "records-api", "target": "one"
        });
        let profile: OAuthPermissionProfile = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(profile.scope_mode, OAuthScopeMode::Explicit);
        assert_eq!(serde_json::to_value(profile).unwrap(), old);
        let default = serde_json::json!({
            "scope_mode": "server_default", "audience": "records-api", "target": "one"
        });
        let profile: OAuthPermissionProfile = serde_json::from_value(default.clone()).unwrap();
        assert_eq!(profile.scope_mode, OAuthScopeMode::ServerDefault);
        assert!(profile.scopes.is_none());
        assert_eq!(serde_json::to_value(profile).unwrap(), default);
        for mode in ["explicit", "server_default"] {
            assert!(
                serde_json::from_value::<OAuthPermissionProfile>(serde_json::json!({
                    "scope_mode": mode, "scopes": null,
                    "audience": "records-api", "target": "one"
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<OAuthPermissionProfile>(serde_json::json!({
                "scope_mode": "unknown", "audience": "records-api", "target": "one"
            }))
            .is_err()
        );
    }

    fn proxied_egress(proxy: &MockServer) -> EgressProxyRuntimeConfig {
        let proxy = proxy.uri();
        let environment = EgressProxyEnvironment::from_lookup(move |key| {
            Ok(match key {
                "HTTP_PROXY" | "HTTPS_PROXY" => Some(proxy.clone()),
                "NO_PROXY" => Some("issuer.internal".into()),
                _ => None,
            })
        })
        .unwrap();
        EgressProxyRuntimeConfig::new(Arc::new(environment), None)
    }

    fn build(
        base: &str,
        allowlist: &[String],
        egress: &EgressProxyRuntimeConfig,
    ) -> Result<OAuthHttp, HostError> {
        OAuthHttp::build(
            "oauth.test",
            "oauth",
            &Url::parse(base).unwrap(),
            allowlist,
            UpstreamNetwork {
                limits: &ProviderLimits::default(),
                egress,
                outbound_tls: &test_support::test_outbound_tls(),
            },
        )
    }

    #[tokio::test]
    async fn oauth_routes_each_destination_origin_independently() {
        let proxy = MockServer::start().await;
        let loopback = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok":true})))
            .expect(2)
            .mount(&loopback)
            .await;
        let egress = proxied_egress(&proxy);
        let token = format!("{}/token", loopback.uri());
        let urls = [
            "https://issuer.internal/metadata".to_owned(),
            "https://resource.external/metadata".to_owned(),
            "https://localhost:9/token".to_owned(),
            "https://127.0.0.2:9443/token".to_owned(),
            "http://[::1]:8787/token".to_owned(),
            token.clone(),
        ];
        // Neither a loopback issuer nor a proxied one decides another
        // destination's route.
        for base in [
            "https://issuer.internal/",
            "https://localhost/",
            "http://127.0.0.1:8787/",
            "http://[::1]:8787/",
        ] {
            let http = build(base, &urls, &egress).unwrap();
            let route = |origin: &str| http.destinations[origin].egress_proxy().audit_value();
            assert_eq!(route("https://issuer.internal")["mode"], "direct");
            assert_eq!(route("https://127.0.0.2:9443")["mode"], "direct");
            assert_eq!(route("http://[::1]:8787")["mode"], "direct");
            assert_eq!(route(&loopback.uri())["mode"], "direct");
            for proxied in ["https://resource.external", "https://localhost:9"] {
                assert_eq!(route(proxied)["mode"], "environment", "{base} {proxied}");
                assert_eq!(route(proxied)["proxy"], proxy.uri(), "{base} {proxied}");
            }
            let expected = if base == "https://localhost/" {
                serde_json::json!({"mode":"environment","proxy":proxy.uri()})
            } else {
                serde_json::json!({"mode":"direct"})
            };
            assert_eq!(http.client.egress_proxy().audit_value(), expected, "{base}");
        }

        // The literal loopback destination is reached directly, although the
        // environment names a proxy for both schemes.
        let http = build("https://localhost/", &urls, &egress).unwrap();
        let response = http
            .send(
                http.request(Method::POST, Url::parse(&token).unwrap())
                    .form(&[("code", "synthetic-code")]),
                "oauth.token",
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let http = build("http://127.0.0.1:8787/", &urls, &egress).unwrap();
        assert_eq!(
            http.send(
                http.request(Method::POST, Url::parse(&token).unwrap()),
                "oauth.token"
            )
            .await
            .unwrap()
            .status(),
            200
        );
        // `https://localhost` is tunneled through the proxy, never resolved
        // and connected to directly.
        assert!(
            http.send(
                http.request(Method::POST, Url::parse(&urls[2]).unwrap()),
                "oauth.token"
            )
            .await
            .is_err()
        );
        let tunneled = proxy.received_requests().await.unwrap();
        assert_eq!(tunneled.len(), 1);
        assert_eq!(tunneled[0].method.as_str(), "CONNECT");
        assert_eq!(tunneled[0].headers["host"], "localhost:9");
        assert!(matches!(
            http.send(
                http.request(
                    Method::GET,
                    Url::parse("https://not-approved.invalid/token").unwrap()
                ),
                "oauth.token"
            )
            .await,
            Err(OAuthDialectError::NotSent)
        ));
    }

    #[test]
    fn oauth_plain_http_requires_a_literal_loopback_address() {
        let egress = EgressProxyRuntimeConfig::direct();
        for base in ["http://127.0.0.1:8787/", "http://[::1]:8787/"] {
            build(base, &[format!("{base}token")], &egress).unwrap();
        }
        for insecure in [
            "http://localhost:8787/",
            "http://LOCALHOST:8787/",
            "http://token.example/",
            "http://[::ffff:127.0.0.1]:8787/",
        ] {
            // Rejected as the base and as any allowlisted destination, even
            // beside an approved loopback issuer.
            assert!(build(insecure, &[], &egress).is_err(), "{insecure}");
            assert!(
                build(
                    "http://127.0.0.1:8787/",
                    &[
                        "http://127.0.0.1:8787/token".into(),
                        format!("{insecure}token")
                    ],
                    &egress,
                )
                .is_err(),
                "{insecure}"
            );
        }
        for invalid in [
            "ftp://127.0.0.1/token",
            "https://*.example/token",
            "https://user:pass@token.example/token",
            "token.example/token",
        ] {
            assert!(
                build("https://issuer.example/", &[invalid.into()], &egress).is_err(),
                "{invalid}"
            );
        }
    }
}
