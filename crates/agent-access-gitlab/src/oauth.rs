//! GitLab's OAuth dialect (`adapter = "gitlab"`): an instance-wide
//! confidential application on one GitLab instance, whose grants act on
//! that instance only.
//!
//! Every endpoint lives under the registration's `base_url`, the instance
//! base including any relative URL root. Token requests are form-encoded
//! with `client_secret_post`, and the host adds PKCE S256. GitLab
//! invalidates the previous access and refresh tokens on every refresh, so
//! registrations declare `rotation = "rotate_both"`, refresh material is
//! consuming, and each grant supersedes earlier access.
//!
//! The one target is the instance: a profile's `target` is the instance
//! base as [`oauth_target`] normalizes it, and its `audience` is
//! [`GITLAB_OAUTH_AUDIENCE`]. Leases carry that pair, so a consumer
//! presenting the connection pins
//! `revalidated_access_for(&oauth_target(&instance), GITLAB_OAUTH_AUDIENCE)`
//! for the instance its declared upstream authority names; offline
//! validation has already checked that this is the registration's instance.
use agent_access_provider::{
    AuthorizationRequest, CodeExchange, ConnectedIdentity, IssuedRefreshToken, OAuthCallbackIssuer,
    OAuthClient, OAuthClientAuth, OAuthDialect, OAuthDialectError, OAuthDialectRegistration,
    OAuthHttp, OAuthPermissionProfile, OAuthRegistrationConfig, OAuthResponse, OAuthRotation,
    OAuthScopeMode, OAuthTarget, OAuthTokenEncoding, RefreshReplay, TokenGrant, UpstreamAuthority,
    UpstreamRetryAfter,
};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

/// The audience of every GitLab permission profile, and so of every lease
/// on a GitLab OAuth connection.
pub(crate) const GITLAB_OAUTH_AUDIENCE: &str = "gitlab";
/// GitLab's default access-token lifetime, for a response without `expires_in`.
const DEFAULT_EXPIRES_IN_SECONDS: u64 = 7200;
/// The manager's bound on access and refresh tokens.
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_USERNAME_BYTES: usize = 255;
const AUTHORIZE_PATH: &str = "oauth/authorize";
const TOKEN_PATH: &str = "oauth/token";
const TOKEN_INFO_PATH: &str = "oauth/token/info";
const USER_PATH: &str = "api/v4/user";

/// The `gitlab` OAuth dialect for GitLab REST and Git gateway connections.
pub static GITLAB_OAUTH_DIALECT: OAuthDialectRegistration = OAuthDialectRegistration::new(
    agent_access_provider::module_metadata!(),
    "gitlab",
    &GitlabDialect,
);

struct GitlabDialect;

/// The OAuth target of a GitLab instance: its normalized origin and instance
/// path without a trailing slash, such as `https://gitlab.example.com` or
/// `https://example.com/gitlab`. A registration's profile `target` must be
/// this for its `base_url`.
pub(crate) fn oauth_target(instance: &UpstreamAuthority) -> String {
    format!("{}{}", instance.origin(), instance.instance_path())
}

/// The registration's instance base: `base_url` as [`oauth_target`]
/// normalizes it.
fn instance_base(config: &OAuthRegistrationConfig) -> Result<String, String> {
    let instance = UpstreamAuthority::from_base_url(&config.base_url)
        .map_err(|reason| format!("base_url {reason}"))?;
    let base = oauth_target(&instance);
    // Allowlist patterns read `*` path segments as wildcards.
    if base.contains('*') {
        return Err("base_url must not contain `*`".into());
    }
    Ok(base)
}

fn endpoint(config: &OAuthRegistrationConfig, path: &str) -> Result<Url, OAuthDialectError> {
    let base = instance_base(config).map_err(|_| OAuthDialectError::Configuration)?;
    Url::parse(&format!("{base}/{path}")).map_err(|_| OAuthDialectError::Configuration)
}

#[async_trait]
impl OAuthDialect for GitlabDialect {
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
        if config.client_auth != OAuthClientAuth::ClientSecretPost
            || config.encoding != OAuthTokenEncoding::Form
            || !config.adapter_settings.is_empty()
        {
            return Err(
                "GitLab requires client_auth = \"client_secret_post\", form encoding and no adapter_settings"
                    .into(),
            );
        }
        if config.rotation != OAuthRotation::RotateBoth {
            return Err(
                "GitLab requires rotation = \"rotate_both\": every refresh replaces both the access and the refresh token"
                    .into(),
            );
        }
        let base = instance_base(config)?;
        let mut profiles = config.permission_profiles.iter();
        let (Some((name, profile)), None) = (profiles.next(), profiles.next()) else {
            return Err("GitLab registrations have exactly one permission profile".into());
        };
        if profile.scope_mode != OAuthScopeMode::Explicit {
            return Err(format!(
                "permission_profiles.{name} must request explicit scopes"
            ));
        }
        if profile.target != base {
            return Err(format!(
                "permission_profiles.{name}.target must be the GitLab instance base {base}"
            ));
        }
        if profile.audience != GITLAB_OAUTH_AUDIENCE {
            return Err(format!(
                "permission_profiles.{name}.audience must be {GITLAB_OAUTH_AUDIENCE}"
            ));
        }
        Ok(())
    }

    /// Accepts only consumers on the instance the profile's `target` names,
    /// such as GitLab REST and a Git gateway on that instance.
    fn check_consumer_authority(
        &self,
        _config: &OAuthRegistrationConfig,
        profile: &OAuthPermissionProfile,
        consumer: Option<&UpstreamAuthority>,
    ) -> Result<(), String> {
        let instance = UpstreamAuthority::from_base_url(&profile.target).map_err(|_| {
            "the permission profile target is not a GitLab instance URL".to_string()
        })?;
        let base = oauth_target(&instance);
        match consumer {
            Some(consumer) if consumer.same_instance(&instance) => Ok(()),
            Some(consumer) => Err(format!(
                "it acts on {consumer}, not the GitLab instance {base}"
            )),
            None => Err(format!(
                "it declares no upstream authority, and the grants act only on the GitLab instance {base}"
            )),
        }
    }

    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
        instance_base(config)
            .map(|base| {
                [TOKEN_PATH, TOKEN_INFO_PATH, USER_PATH]
                    .map(|path| format!("{base}/{path}"))
                    .to_vec()
            })
            .unwrap_or_default()
    }

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        let mut url = endpoint(client.config, AUTHORIZE_PATH)?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", client.config.client_id.as_str()),
            ("redirect_uri", &client.config.redirect_uri),
            ("response_type", "code"),
            ("scope", &profile.requested_scopes().join(" ")),
            ("state", request.state),
            ("code_challenge", request.code_challenge_s256),
            ("code_challenge_method", "S256"),
        ]);
        Ok(url)
    }

    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        // GitLab's authorization responses do not carry `iss`.
        OAuthCallbackIssuer::new(
            instance_base(config).unwrap_or_else(|_| config.base_url.clone()),
            false,
        )
    }

    fn refresh_replay(&self, _: &OAuthRegistrationConfig) -> RefreshReplay {
        RefreshReplay::Consuming
    }

    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        let response = token_request(
            http,
            client,
            &[
                ("grant_type", "authorization_code"),
                ("code", exchange.code),
                ("redirect_uri", &client.config.redirect_uri),
                ("code_verifier", exchange.code_verifier),
            ],
        )
        .await?;
        // GitLab's documented token responses may omit `scope`. The new
        // token's own info is then the evidence of what was granted; when it
        // cannot be read, the installation fails before anything is stored.
        let scopes = match response.scopes.clone() {
            Some(scopes) => scopes,
            None => token_info_scopes(http, client.config, &response.access_token).await?,
        };
        Ok(response.grant(scopes))
    }

    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        _: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        let response = token_request(
            http,
            client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("redirect_uri", &client.config.redirect_uri),
            ],
        )
        .await?;
        // A refresh without `scope` keeps the originally granted scopes
        // (RFC 6749 section 6), which GitLab cannot widen. Nothing is sent
        // between this consuming refresh and the successor's persistence,
        // and requested scopes are never evidence.
        let scopes = response
            .scopes
            .clone()
            .unwrap_or_else(|| granted_scopes.iter().cloned().collect());
        Ok(response.grant(scopes))
    }

    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError> {
        let user = get_json(
            http,
            endpoint(client.config, USER_PATH)?,
            access_token,
            "oauth.identity",
        )
        .await?;
        let invalid = || OAuthDialectError::InvalidResponse;
        let id = user
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or_else(invalid)?;
        let username = user
            .get("username")
            .and_then(Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= MAX_USERNAME_BYTES
                    && !name.chars().any(char::is_control)
            })
            .ok_or_else(invalid)?;
        Ok(ConnectedIdentity::new(username).with_subject(id.to_string()))
    }

    async fn discover_targets(
        &self,
        _: &OAuthHttp,
        client: &OAuthClient<'_>,
        _: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        // The grant acts on the registration's instance with the scopes the
        // token carries; nothing is fetched.
        let base = instance_base(client.config).map_err(|_| OAuthDialectError::Configuration)?;
        Ok(vec![
            OAuthTarget::new(base, GITLAB_OAUTH_AUDIENCE, granted_scopes.clone())
                .with_name("GitLab instance"),
        ])
    }
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
        let expires_in = match body.get("expires_in") {
            None | Some(Value::Null) => DEFAULT_EXPIRES_IN_SECONDS,
            Some(seconds) => seconds
                .as_u64()
                .filter(|seconds| *seconds > 0)
                .ok_or_else(invalid)?,
        };
        let scopes = match body.get("scope") {
            None | Some(Value::Null) => None,
            Some(Value::String(scope)) => {
                Some(scope_list(scope.split_ascii_whitespace().map(Some))?)
            }
            Some(_) => return Err(invalid()),
        };
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
        .with_supersedes_other_access(true)
    }
}

/// A token that can be presented in a header: visible ASCII within the
/// manager's bound.
fn token_text(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// A nonempty list of scope names without whitespace or control characters.
fn scope_list<'a>(
    scopes: impl Iterator<Item = Option<&'a str>>,
) -> Result<Vec<String>, OAuthDialectError> {
    let scopes = scopes
        .map(|scope| {
            scope
                .filter(|scope| {
                    !scope.is_empty() && !scope.chars().any(|c| c.is_whitespace() || c.is_control())
                })
                .map(str::to_owned)
                .ok_or(OAuthDialectError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scopes.is_empty() {
        return Err(OAuthDialectError::InvalidResponse);
    }
    Ok(scopes)
}

async fn token_request(
    http: &OAuthHttp,
    client: &OAuthClient<'_>,
    grant: &[(&str, &str)],
) -> Result<TokenResponse, OAuthDialectError> {
    if client.client_secret.is_empty() {
        return Err(OAuthDialectError::Configuration);
    }
    let mut form = grant.to_vec();
    form.push(("client_id", &client.config.client_id));
    form.push(("client_secret", client.client_secret));
    let request = http
        .request(Method::POST, endpoint(client.config, TOKEN_PATH)?)
        .header("Accept", "application/json")
        .form(&form);
    let response = http.send(request, "oauth.token").await?;
    TokenResponse::parse(response_json(response, Endpoint::Token).await?)
}

/// The scopes GitLab's token info reports for a newly issued access token.
async fn token_info_scopes(
    http: &OAuthHttp,
    config: &OAuthRegistrationConfig,
    access_token: &str,
) -> Result<Vec<String>, OAuthDialectError> {
    let info = get_json(
        http,
        endpoint(config, TOKEN_INFO_PATH)?,
        access_token,
        "oauth.token_info",
    )
    .await?;
    match info.get("scope") {
        Some(Value::Array(scopes)) => scope_list(scopes.iter().map(Value::as_str)),
        _ => Err(OAuthDialectError::InvalidResponse),
    }
}

async fn get_json(
    http: &OAuthHttp,
    url: Url,
    access_token: &str,
    operation: &str,
) -> Result<Value, OAuthDialectError> {
    let request = http
        .request(Method::GET, url)
        .bearer_auth(access_token)
        .header("Accept", "application/json");
    let response = http.send(request, operation).await?;
    response_json(response, Endpoint::Api).await
}

/// The GitLab endpoint a response came from: the token endpoint, or an API
/// endpoint a newly issued access token authenticates to.
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
            // GitLab's rate limits answer before the grant is read, so the
            // grant was not consumed; the wait is bounded to one day.
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
        (_, Some("invalid_grant")) => OAuthDialectError::GrantInvalid,
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
