//! Atlassian's OAuth 2.0 (3LO) dialect (`adapter = "atlassian"`): an OAuth
//! 2.0 integration from Atlassian's developer console, whose grants act on
//! the Atlassian Cloud sites a person picks at consent, through the Atlassian
//! API gateway.
//!
//! Endpoints are fixed. Authorization and token requests go to the
//! authorization server `https://auth.atlassian.com`, the registration's
//! `base_url`; the connected account (`/me`) and its sites
//! (`/oauth/token/accessible-resources`) are read from the gateway
//! `https://api.atlassian.com`. Every authorization request asks for
//! `audience=api.atlassian.com` and `prompt=consent` and carries the host's
//! PKCE S256 challenge, whose enforcement Atlassian does not document. Token
//! requests are JSON with the client secret in the body. Atlassian rotates
//! the refresh token on every refresh, so registrations declare
//! `rotation = "rotate_refresh"` and refresh material is consuming.
//!
//! A registration has one permission profile. Its `target` is one site's
//! cloud ID and its `audience` is [`ATLASSIAN_OAUTH_AUDIENCE`]. Each target
//! the dialect discovers is one site `accessible-resources` lists, with the
//! union of the scopes its product entries grant there and the granted
//! account-level scopes (`read:me`), which no site lists. Scope evidence is
//! the token response's `scope`: a code exchange without it fails, and a
//! refresh without it keeps the scopes originally granted. Leases carry the
//! profile's cloud ID and audience, so Jira and Confluence present a
//! connection by pinning
//! `revalidated_access_for(<cloud_id>, ATLASSIAN_OAUTH_AUDIENCE)` for the
//! `cloud_id` their gateway route uses before every request; offline
//! validation has already checked that it is the profile's target.
use crate::ATLASSIAN_GATEWAY_ORIGIN;
use agent_access_provider::{
    AuthorizationRequest, CodeExchange, ConnectedIdentity, IssuedRefreshToken, OAuthCallbackIssuer,
    OAuthClient, OAuthClientAuth, OAuthDialect, OAuthDialectError, OAuthDialectRegistration,
    OAuthHttp, OAuthPermissionProfile, OAuthRegistrationConfig, OAuthResponse, OAuthRotation,
    OAuthScopeMode, OAuthTarget, OAuthTokenEncoding, RefreshReplay, TokenGrant, UpstreamAuthority,
    UpstreamRetryAfter,
};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::Url;

/// The audience of every Atlassian permission profile, and so of every
/// lease on an Atlassian OAuth connection: the Atlassian API gateway,
/// through which the grants reach a site.
pub const ATLASSIAN_OAUTH_AUDIENCE: &str = "api.atlassian.com";
/// Atlassian's authorization server, every registration's `base_url`.
const AUTHORIZATION_SERVER: &str = "https://auth.atlassian.com";
const AUTHORIZE_PATH: &str = "authorize";
const TOKEN_PATH: &str = "oauth/token";
const IDENTITY_PATH: &str = "me";
const SITES_PATH: &str = "oauth/token/accessible-resources";
/// Scopes that act on the Atlassian account rather than a site:
/// `accessible-resources` lists none of them, so a granted one applies to
/// every site.
const ACCOUNT_SCOPES: [&str; 1] = ["read:me"];
/// Scopes every profile requests: `read:me` identifies the connected account
/// and `offline_access` issues refresh tokens.
const REQUIRED_SCOPES: [&str; 2] = ["read:me", "offline_access"];
/// The manager's bound on access and refresh tokens.
const MAX_TOKEN_BYTES: usize = 32_768;
/// The manager's bound on a connected account's subject and display name.
const MAX_IDENTITY_BYTES: usize = 512;
/// The manager's bounds on a target's ID and display name.
const MAX_SITE_ID_BYTES: usize = 256;
const MAX_SITE_NAME_BYTES: usize = 512;

/// The `atlassian` OAuth dialect for Jira and Confluence connections through
/// the Atlassian gateway.
pub static ATLASSIAN_OAUTH_DIALECT: OAuthDialectRegistration = OAuthDialectRegistration::new(
    agent_access_provider::module_metadata!(),
    "atlassian",
    &AtlassianDialect {
        authorization_server: AUTHORIZATION_SERVER,
        api: ATLASSIAN_GATEWAY_ORIGIN,
    },
);

/// The dialect, with the origins it sends requests to. Only the test
/// fixture moves them; registrations cannot.
struct AtlassianDialect {
    /// The origin of the authorization and token endpoints.
    authorization_server: &'static str,
    /// The origin of the identity and site endpoints.
    api: &'static str,
}

/// The dialect with every endpoint below `base`, as a development fixture.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn test_dialect(base: &str) -> &'static OAuthDialectRegistration {
    let base: &'static str = Box::leak(base.trim_end_matches('/').to_owned().into_boxed_str());
    Box::leak(Box::new(
        OAuthDialectRegistration::new(
            agent_access_provider::module_metadata!(),
            "atlassian",
            Box::leak(Box::new(AtlassianDialect {
                authorization_server: base,
                api: base,
            })),
        )
        .development_only(),
    ))
}

fn endpoint(origin: &str, path: &str) -> Result<Url, OAuthDialectError> {
    Url::parse(&format!("{origin}/{path}")).map_err(|_| OAuthDialectError::Configuration)
}

/// A site's cloud ID as Atlassian writes it: a lowercase hyphenated UUID.
fn is_cloud_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

#[async_trait]
impl OAuthDialect for AtlassianDialect {
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
        if config.base_url.trim_end_matches('/') != AUTHORIZATION_SERVER
            || config.client_auth != OAuthClientAuth::ClientSecretPost
            || config.encoding != OAuthTokenEncoding::Json
            || !config.adapter_settings.is_empty()
        {
            return Err(format!(
                "Atlassian requires base_url {AUTHORIZATION_SERVER}, client_auth = \"client_secret_post\", encoding = \"json\" and no adapter_settings"
            ));
        }
        if config.rotation != OAuthRotation::RotateRefresh {
            return Err(
                "Atlassian requires rotation = \"rotate_refresh\": every refresh replaces the refresh token"
                    .into(),
            );
        }
        let mut profiles = config.permission_profiles.iter();
        let (Some((name, profile)), None) = (profiles.next(), profiles.next()) else {
            return Err("Atlassian registrations have exactly one permission profile".into());
        };
        if profile.scope_mode != OAuthScopeMode::Explicit {
            return Err(format!(
                "permission_profiles.{name} must request explicit scopes"
            ));
        }
        if profile.audience != ATLASSIAN_OAUTH_AUDIENCE {
            return Err(format!(
                "permission_profiles.{name}.audience must be {ATLASSIAN_OAUTH_AUDIENCE}"
            ));
        }
        if !is_cloud_id(&profile.target) {
            return Err(format!(
                "permission_profiles.{name}.target must be the site's cloud ID, a lowercase hyphenated UUID"
            ));
        }
        let requested = profile.requested_scopes();
        if !REQUIRED_SCOPES
            .iter()
            .all(|scope| requested.iter().any(|requested| requested == scope))
        {
            return Err(format!(
                "permission_profiles.{name}.scopes must include read:me, which identifies the connected account, and offline_access, which allows refresh"
            ));
        }
        Ok(())
    }

    /// Accepts only consumers that act through the Atlassian gateway on the
    /// site the profile's `target` names: Jira and Confluence with that
    /// `cloud_id` and the gateway enabled.
    fn check_consumer_authority(
        &self,
        _config: &OAuthRegistrationConfig,
        profile: &OAuthPermissionProfile,
        consumer: Option<&UpstreamAuthority>,
    ) -> Result<(), String> {
        let site = profile.target.as_str();
        let Some(consumer) = consumer else {
            return Err(format!(
                "it declares no upstream authority, and the grants act only through the Atlassian gateway on cloud ID {site}"
            ));
        };
        if consumer.tenant_gateway() != Some(ATLASSIAN_GATEWAY_ORIGIN) {
            return Err(format!(
                "it acts on {consumer} without the Atlassian gateway, and the grants act only through the gateway on cloud ID {site}"
            ));
        }
        match consumer.tenant() {
            Some(tenant) if tenant == site => Ok(()),
            Some(tenant) => Err(format!(
                "it acts through the Atlassian gateway on cloud ID {tenant}, not cloud ID {site}"
            )),
            None => Err(format!(
                "it names no cloud ID, and the grants act only through the Atlassian gateway on cloud ID {site}"
            )),
        }
    }

    fn upstream_allowlist(&self, _config: &OAuthRegistrationConfig) -> Vec<String> {
        vec![
            format!("{}/{TOKEN_PATH}", self.authorization_server),
            format!("{}/{IDENTITY_PATH}", self.api),
            format!("{}/{SITES_PATH}", self.api),
        ]
    }

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        let mut url = endpoint(self.authorization_server, AUTHORIZE_PATH)?;
        url.query_pairs_mut().extend_pairs([
            ("audience", ATLASSIAN_OAUTH_AUDIENCE),
            ("client_id", client.config.client_id.as_str()),
            ("scope", &profile.requested_scopes().join(" ")),
            ("redirect_uri", &client.config.redirect_uri),
            ("state", request.state),
            ("response_type", "code"),
            // Atlassian shows its consent screen and site picker on every
            // authorization.
            ("prompt", "consent"),
            ("code_challenge", request.code_challenge_s256),
            ("code_challenge_method", "S256"),
        ]);
        Ok(url)
    }

    fn callback_issuer(&self, _config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        // Atlassian's authorization responses do not carry `iss`.
        OAuthCallbackIssuer::new(self.authorization_server, false)
    }

    fn refresh_replay(&self, _config: &OAuthRegistrationConfig) -> RefreshReplay {
        RefreshReplay::Consuming
    }

    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        let response = self
            .token_request(
                http,
                client,
                json!({
                    "grant_type": "authorization_code",
                    "code": exchange.code,
                    "redirect_uri": client.config.redirect_uri,
                    "code_verifier": exchange.code_verifier,
                }),
            )
            .await?;
        // Atlassian documents `scope` on every token response. Without it no
        // evidence establishes the product scopes: `/me` would prove only the
        // account, and requested scopes are never evidence.
        let scopes = response
            .scopes
            .clone()
            .ok_or(OAuthDialectError::InvalidResponse)?;
        Ok(response.grant(scopes))
    }

    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        _profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        let response = self
            .token_request(
                http,
                client,
                json!({
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                }),
            )
            .await?;
        // A refresh without `scope` keeps the originally granted scopes
        // (RFC 6749 section 6). Nothing is sent between this consuming
        // refresh and the successor's persistence, and requested scopes are
        // never evidence.
        let scopes = response
            .scopes
            .clone()
            .unwrap_or_else(|| granted_scopes.iter().cloned().collect());
        Ok(response.grant(scopes))
    }

    async fn identity(
        &self,
        http: &OAuthHttp,
        _client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError> {
        let me = self
            .get_json(http, IDENTITY_PATH, access_token, "oauth.identity")
            .await?;
        let field = |name: &str| {
            me.get(name)
                .and_then(Value::as_str)
                .filter(|value| bounded_text(value, MAX_IDENTITY_BYTES))
        };
        let account_id = field("account_id")
            .filter(|id| !id.contains(char::is_whitespace))
            .ok_or(OAuthDialectError::InvalidResponse)?;
        let display_name = field("email")
            .or_else(|| field("name"))
            .unwrap_or(account_id);
        Ok(ConnectedIdentity::new(display_name).with_subject(account_id))
    }

    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        _client: &OAuthClient<'_>,
        access_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        let sites = self
            .get_json(http, SITES_PATH, access_token, "oauth.accessible_resources")
            .await?;
        merge_sites(&sites, granted_scopes)
    }
}

impl AtlassianDialect {
    async fn token_request(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        mut body: Value,
    ) -> Result<TokenResponse, OAuthDialectError> {
        if client.client_secret.is_empty() {
            return Err(OAuthDialectError::Configuration);
        }
        body["client_id"] = json!(client.config.client_id);
        body["client_secret"] = json!(client.client_secret);
        let request = http
            .request(
                Method::POST,
                endpoint(self.authorization_server, TOKEN_PATH)?,
            )
            .header("Accept", "application/json")
            .json(&body);
        let response = http.send(request, "oauth.token").await?;
        TokenResponse::parse(response_json(response, Endpoint::Token).await?)
    }

    async fn get_json(
        &self,
        http: &OAuthHttp,
        path: &str,
        access_token: &str,
        operation: &str,
    ) -> Result<Value, OAuthDialectError> {
        let request = http
            .request(Method::GET, endpoint(self.api, path)?)
            .bearer_auth(access_token)
            .header("Accept", "application/json");
        let response = http.send(request, operation).await?;
        response_json(response, Endpoint::Api).await
    }
}

/// The sites `accessible-resources` lists, one target per cloud ID: the
/// response lists a site once per product container, so entries with one ID
/// merge into one target with the union of their scopes. Each target also
/// carries the granted account-level scopes, which act on every site. A site
/// may be absent; the manager's eligibility check then fails for a profile
/// that targets it.
fn merge_sites(
    sites: &Value,
    granted_scopes: &BTreeSet<String>,
) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
    let invalid = || OAuthDialectError::InvalidResponse;
    let account_scopes = ACCOUNT_SCOPES
        .into_iter()
        .filter(|scope| granted_scopes.contains(*scope))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut targets: Vec<OAuthTarget> = Vec::new();
    for site in sites.as_array().ok_or_else(invalid)? {
        let id = site
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| bounded_text(id, MAX_SITE_ID_BYTES) && !id.contains(char::is_whitespace))
            .ok_or_else(invalid)?;
        let scopes = match site.get("scopes") {
            Some(Value::Array(scopes)) => scopes
                .iter()
                .map(|scope| scope.as_str().filter(|scope| scope_text(scope)))
                .map(|scope| scope.map(str::to_owned).ok_or_else(invalid))
                .collect::<Result<BTreeSet<_>, _>>()?,
            _ => return Err(invalid()),
        };
        let name = site
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| bounded_text(name, MAX_SITE_NAME_BYTES))
            .unwrap_or_default();
        match targets.iter_mut().find(|target| target.id == id) {
            Some(target) => {
                target.scopes.extend(scopes);
                if target.name.is_empty() {
                    target.name = name.to_owned();
                }
            }
            None => {
                targets.push(OAuthTarget::new(id, ATLASSIAN_OAUTH_AUDIENCE, scopes).with_name(name))
            }
        }
    }
    for target in &mut targets {
        target.scopes.extend(account_scopes.iter().cloned());
    }
    Ok(targets)
}

/// Nonempty text within `max` bytes without control characters.
fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// A scope name: nonempty, without whitespace or control characters.
fn scope_text(scope: &str) -> bool {
    !scope.is_empty() && !scope.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A token endpoint response. It holds the issued tokens, so it has no Debug.
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    /// `None` when the response omits `scope`.
    scopes: Option<Vec<String>>,
    refresh_token: IssuedRefreshToken,
}

impl TokenResponse {
    fn parse(body: Value) -> Result<Self, OAuthDialectError> {
        let invalid = || OAuthDialectError::InvalidResponse;
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| token_text(token))
            .ok_or_else(invalid)?;
        let token_type = body
            .get("token_type")
            .and_then(Value::as_str)
            .filter(|kind| kind.eq_ignore_ascii_case("bearer"))
            .ok_or_else(invalid)?;
        // Each response states its access token's lifetime.
        let expires_in = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .filter(|seconds| *seconds > 0)
            .ok_or_else(invalid)?;
        let scopes = match body.get("scope") {
            None | Some(Value::Null) => None,
            Some(Value::String(scope)) => {
                let scopes = scope
                    .split_ascii_whitespace()
                    .map(|scope| {
                        scope_text(scope)
                            .then(|| scope.to_owned())
                            .ok_or_else(invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if scopes.is_empty() {
                    return Err(invalid());
                }
                Some(scopes)
            }
            Some(_) => return Err(invalid()),
        };
        // Rotation issues a new refresh token on every response; one without
        // it is never read as keeping the old token.
        let refresh_token = match body.get("refresh_token") {
            None | Some(Value::Null) => IssuedRefreshToken::Absent,
            Some(Value::String(token)) if token_text(token) => {
                IssuedRefreshToken::Issued(token.clone())
            }
            Some(_) => return Err(invalid()),
        };
        Ok(Self {
            access_token: access_token.to_owned(),
            token_type: token_type.to_owned(),
            expires_in,
            scopes,
            refresh_token,
        })
    }

    fn grant(self, scopes: Vec<String>) -> TokenGrant {
        TokenGrant::new(
            self.access_token,
            self.token_type,
            self.expires_in,
            self.refresh_token,
        )
        .with_scopes(scopes)
    }
}

/// A token that can be presented in a header: visible ASCII within the
/// manager's bound.
fn token_text(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// The Atlassian endpoint a response came from: the token endpoint, or a
/// gateway endpoint the access token authenticates to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Token,
    Api,
}

/// The JSON body of a successful response, or the failure's class. Only an
/// explicit OAuth error proves that the token endpoint read and rejected the
/// grant without consuming it; anything else may have consumed it.
async fn response_json(
    response: OAuthResponse,
    endpoint: Endpoint,
) -> Result<Value, OAuthDialectError> {
    let status = response.status();
    if status == 429 {
        return Err(match endpoint {
            // Rate limits answer before the grant is read, so it was not
            // consumed; the wait is bounded to one day.
            Endpoint::Token => OAuthDialectError::RetryAfter(
                response
                    .header("retry-after")
                    .and_then(UpstreamRetryAfter::parse)
                    .map_or(1, |wait| wait.seconds()),
            ),
            Endpoint::Api => OAuthDialectError::Throttled,
        });
    }
    if status >= 500 {
        return Err(OAuthDialectError::Failed);
    }
    if (200..300).contains(&status) {
        return response.json().await;
    }
    let body = response.json().await.ok();
    let error = body
        .as_ref()
        .and_then(|body| body.get("error"))
        .and_then(Value::as_str);
    Err(match (endpoint, error) {
        // Atlassian answers an expired, revoked or reused refresh token
        // with HTTP 403 and `invalid_grant`.
        (_, Some("invalid_grant")) => OAuthDialectError::GrantInvalid,
        // At the token endpoint, HTTP 401 means client authentication
        // failed (RFC 6749 section 5.2), whatever the error code: Atlassian's
        // authorization server answers a wrong client secret with 401
        // `access_denied`. The grant was not read, and only the operator
        // can correct the application credential.
        (Endpoint::Token, _) if status == 401 => OAuthDialectError::ClientRejected,
        (_, Some("invalid_client" | "unauthorized_client")) => OAuthDialectError::ClientRejected,
        (_, Some("invalid_scope" | "access_denied")) => OAuthDialectError::PermissionRejected,
        (Endpoint::Token, Some("invalid_request")) => OAuthDialectError::RequestRejected,
        (Endpoint::Api, _) if status == 401 => OAuthDialectError::GrantInvalid,
        (Endpoint::Api, _) if status == 403 => OAuthDialectError::PermissionRejected,
        _ => OAuthDialectError::Failed,
    })
}

#[cfg(test)]
mod tests;
