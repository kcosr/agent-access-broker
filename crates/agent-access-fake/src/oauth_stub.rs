//! The development `stub` OAuth dialect: the independent OAuth test server
//! whose contract the broker's refresh fences were designed against.
use agent_access_provider::{
    AuthorizationRequest, CodeExchange, ConnectedIdentity, IssuedRefreshToken, OAuthCallbackIssuer,
    OAuthClient, OAuthClientAuth, OAuthDialect, OAuthDialectError, OAuthDialectRegistration,
    OAuthHttp, OAuthPermissionProfile, OAuthRegistrationConfig, OAuthRotation, OAuthTarget,
    OAuthTokenEncoding, RefreshReplay, TokenGrant, UpstreamRetryAfter,
};
use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

/// The development `stub` OAuth dialect, selected independently of the
/// `oauth_stub` records backend.
pub static STUB_OAUTH_DIALECT: OAuthDialectRegistration = OAuthDialectRegistration::new(
    agent_access_provider::module_metadata!(),
    "stub",
    &StubDialect,
)
.development_only();

struct StubDialect;

#[derive(Deserialize)]
struct IdentityResponse {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct TargetsResponse {
    targets: Vec<OAuthTarget>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    refresh_token: Option<String>,
}

#[async_trait]
impl OAuthDialect for StubDialect {
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
        if !matches!(
            config.client_auth,
            OAuthClientAuth::ClientSecretPost | OAuthClientAuth::ClientSecretBasic
        ) || !matches!(
            config.rotation,
            OAuthRotation::PreserveOld | OAuthRotation::RotateRefresh | OAuthRotation::RotateBoth
        ) || !config.adapter_settings.is_empty()
        {
            return Err(
                "stub requires secret-post/basic client authentication, a supported rotation and no adapter settings"
                    .into(),
            );
        }
        let base = Url::parse(&config.base_url).map_err(|_| "base_url must be a URL")?;
        if base.path() != "/" || base.query().is_some() {
            return Err("base_url must be an origin with no path or query".into());
        }
        for (name, profile) in &config.permission_profiles {
            if !bounded(&profile.target, 256) || !bounded(&profile.audience, 256) {
                return Err(format!(
                    "permission_profiles.{name} needs a target and audience of at most 256 characters"
                ));
            }
            if !profile
                .requested_scopes()
                .iter()
                .any(|scope| scope == "offline_access")
            {
                return Err(format!(
                    "permission_profiles.{name}.scopes must include offline_access"
                ));
            }
        }
        Ok(())
    }

    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
        vec![format!("{}/**", config.base_url.trim_end_matches('/'))]
    }

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        let mut url = Url::parse(&client.config.base_url)
            .and_then(|base| base.join("oauth/authorize"))
            .map_err(|_| OAuthDialectError::Configuration)?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", client.config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", client.config.redirect_uri.as_str()),
            ("scope", &profile.requested_scopes().join(" ")),
            ("state", request.state),
            ("code_challenge", request.code_challenge_s256),
            ("code_challenge_method", "S256"),
            ("audience", &profile.audience),
            ("target", &profile.target),
        ]);
        Ok(url)
    }

    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        OAuthCallbackIssuer::new(config.base_url.trim_end_matches('/').to_string(), true)
    }

    fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay {
        match config.rotation {
            OAuthRotation::PreserveOld => RefreshReplay::Reusable,
            _ => RefreshReplay::Consuming,
        }
    }

    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        token(
            http,
            client,
            BTreeMap::from([
                ("grant_type", "authorization_code".to_string()),
                ("code", exchange.code.to_string()),
                ("redirect_uri", client.config.redirect_uri.clone()),
                ("code_verifier", exchange.code_verifier.to_string()),
            ]),
        )
        .await
    }

    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        _granted_scopes: &std::collections::BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        token(
            http,
            client,
            BTreeMap::from([
                ("grant_type", "refresh_token".into()),
                ("refresh_token", refresh_token.to_string()),
                ("scope", profile.requested_scopes().join(" ")),
                ("audience", profile.audience.clone()),
                ("target", profile.target.clone()),
            ]),
        )
        .await
    }

    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError> {
        let identity: IdentityResponse = get(http, client, "me", access_token).await?;
        Ok(ConnectedIdentity::new(identity.name).with_subject(identity.id))
    }

    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
        _granted_scopes: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        let response: TargetsResponse = get(http, client, "targets", access_token).await?;
        Ok(response.targets)
    }
}

async fn token(
    http: &OAuthHttp,
    client: &OAuthClient<'_>,
    mut fields: BTreeMap<&str, String>,
) -> Result<TokenGrant, OAuthDialectError> {
    fields.insert("client_id", client.config.client_id.clone());
    if client.config.client_auth == OAuthClientAuth::ClientSecretPost {
        fields.insert("client_secret", client.client_secret.to_string());
    }
    let url = Url::parse(&format!(
        "{}/oauth/token",
        client.config.base_url.trim_end_matches('/')
    ))
    .map_err(|_| OAuthDialectError::Configuration)?;
    let mut request = http.request(Method::POST, url);
    if client.config.client_auth == OAuthClientAuth::ClientSecretBasic {
        let client_id: String =
            url::form_urlencoded::byte_serialize(client.config.client_id.as_bytes()).collect();
        let client_secret: String =
            url::form_urlencoded::byte_serialize(client.client_secret.as_bytes()).collect();
        request = request.basic_auth(client_id, Some(client_secret));
    }
    request = match client.config.encoding {
        OAuthTokenEncoding::Form => request.form(&fields),
        OAuthTokenEncoding::Json => request.json(&fields),
        _ => return Err(OAuthDialectError::Configuration),
    };
    let value = response(http, request, "oauth.token", true).await?;
    grant_from_value(value, client.config)
}

fn grant_from_value(
    value: Value,
    config: &OAuthRegistrationConfig,
) -> Result<TokenGrant, OAuthDialectError> {
    let response: TokenResponse =
        serde_json::from_value(value).map_err(|_| OAuthDialectError::InvalidResponse)?;
    let refresh_token = match response.refresh_token {
        Some(token) => IssuedRefreshToken::Issued(token),
        None if config.rotation == OAuthRotation::PreserveOld => IssuedRefreshToken::Retained,
        None => IssuedRefreshToken::Absent,
    };
    Ok(TokenGrant::new(
        response.access_token,
        response.token_type,
        response.expires_in,
        refresh_token,
    )
    .with_scopes(
        response
            .scope
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect(),
    )
    .with_supersedes_other_access(config.rotation == OAuthRotation::RotateBoth))
}

async fn get<T: serde::de::DeserializeOwned>(
    http: &OAuthHttp,
    client: &OAuthClient<'_>,
    path: &str,
    token: &str,
) -> Result<T, OAuthDialectError> {
    let url = Url::parse(&format!(
        "{}/{path}",
        client.config.base_url.trim_end_matches('/')
    ))
    .map_err(|_| OAuthDialectError::Configuration)?;
    let request = http.request(Method::GET, url).bearer_auth(token);
    let value = response(http, request, &format!("oauth.{path}"), false).await?;
    serde_json::from_value(value).map_err(|_| OAuthDialectError::InvalidResponse)
}

/// Sends a request and classifies the stub's RFC 6749 error responses.
async fn response(
    http: &OAuthHttp,
    request: reqwest::RequestBuilder,
    operation: &str,
    token_request: bool,
) -> Result<Value, OAuthDialectError> {
    let response = http.send(request, operation).await?;
    let status = response.status();
    let retry_after = retry_after_seconds(response.header("retry-after"));
    // The enabled stub contract guarantees a 429 is non-consuming; its body is not needed
    // to preserve the refresh token, and may legitimately be empty or plain text.
    if token_request && status == 429 {
        return Err(OAuthDialectError::RetryAfter(retry_after));
    }
    let value = response.json().await?;
    if (500..600).contains(&status) {
        return Err(OAuthDialectError::Failed);
    }
    if !(200..300).contains(&status) {
        let error = value.get("error").and_then(Value::as_str);
        if token_request && (400..500).contains(&status) {
            match error {
                Some("invalid_scope" | "access_denied") => {
                    return Err(OAuthDialectError::PermissionRejected);
                }
                Some("invalid_request") => return Err(OAuthDialectError::RequestRejected),
                _ => {}
            }
        }
        return Err(match error {
            Some("invalid_grant") => OAuthDialectError::GrantInvalid,
            Some("invalid_client") => OAuthDialectError::ClientRejected,
            Some("invalid_scope" | "access_denied") => OAuthDialectError::PermissionRejected,
            _ if status == 429 => OAuthDialectError::Throttled,
            _ => OAuthDialectError::Failed,
        });
    }
    Ok(value)
}

/// Seconds or an HTTP date, bounded to between one second and one day.
fn retry_after_seconds(value: Option<&str>) -> u64 {
    value
        .and_then(UpstreamRetryAfter::parse)
        .map_or(1, |wait| wait.seconds())
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::OAuthAdapter;
    use serde_json::json;

    fn registration(rotation: OAuthRotation) -> OAuthRegistrationConfig {
        OAuthRegistrationConfig {
            adapter: OAuthAdapter::new("stub"),
            base_url: "https://stub.example/".into(),
            redirect_uri: "https://broker.example/v1/oauth/callback/stub".into(),
            client_id: "broker".into(),
            client_secret_ref: "env:STUB_SECRET".into(),
            adapter_settings: BTreeMap::new(),
            client_auth: OAuthClientAuth::ClientSecretPost,
            encoding: OAuthTokenEncoding::Form,
            rotation,
            allow_insecure_loopback: false,
            permission_profiles: BTreeMap::new(),
        }
    }

    fn token() -> Value {
        json!({"access_token":"access","token_type":"Bearer","expires_in":3600,"scope":"records.read offline_access"})
    }

    #[test]
    fn token_responses_need_expiry_and_scope() {
        for field in ["expires_in", "scope", "access_token", "token_type"] {
            let mut value = token();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                matches!(
                    grant_from_value(value, &registration(OAuthRotation::RotateRefresh)),
                    Err(OAuthDialectError::InvalidResponse)
                ),
                "{field}"
            );
        }
        let grant = grant_from_value(token(), &registration(OAuthRotation::RotateRefresh)).unwrap();
        assert_eq!(grant.scopes, ["records.read", "offline_access"]);
    }

    #[test]
    fn rotation_decides_what_a_missing_refresh_token_means() {
        let retained =
            grant_from_value(token(), &registration(OAuthRotation::PreserveOld)).unwrap();
        assert!(matches!(
            retained.refresh_token,
            IssuedRefreshToken::Retained
        ));
        assert!(!retained.supersedes_other_access);
        let absent = grant_from_value(token(), &registration(OAuthRotation::RotateBoth)).unwrap();
        assert!(matches!(absent.refresh_token, IssuedRefreshToken::Absent));
        assert!(absent.supersedes_other_access);
        let mut issued = token();
        issued["refresh_token"] = json!("next");
        let issued = grant_from_value(issued, &registration(OAuthRotation::RotateRefresh)).unwrap();
        assert!(
            matches!(issued.refresh_token, IssuedRefreshToken::Issued(token) if token == "next")
        );
    }

    #[test]
    fn registrations_need_a_root_base_and_offline_access() {
        let mut config = registration(OAuthRotation::RotateRefresh);
        config.permission_profiles.insert(
            "read".into(),
            OAuthPermissionProfile {
                scope_mode: Default::default(),
                scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                audience: "records-api".into(),
                target: "workspace-one".into(),
            },
        );
        StubDialect.validate_registration(&config).unwrap();
        let mut nested = config.clone();
        nested.base_url = "https://stub.example/tenant/".into();
        assert!(StubDialect.validate_registration(&nested).is_err());
        let mut online = config.clone();
        online.permission_profiles.get_mut("read").unwrap().scopes =
            Some(vec!["records.read".into()]);
        assert_eq!(
            StubDialect.validate_registration(&online).unwrap_err(),
            "permission_profiles.read.scopes must include offline_access"
        );
    }

    #[test]
    fn retry_after_is_bounded_to_one_second_through_one_day() {
        assert_eq!(retry_after_seconds(Some("9999999")), 86_400);
        assert_eq!(retry_after_seconds(Some("3600")), 3600);
        assert_eq!(retry_after_seconds(Some("invalid")), 1);
        assert_eq!(retry_after_seconds(None), 1);
    }
}
