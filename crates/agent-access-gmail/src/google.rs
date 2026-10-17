//! Google's confidential web-client OAuth dialect. Endpoints are fixed; only
//! the redirect URI may use the manager's explicit loopback exception.
use agent_access_provider::*;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";
pub const GMAIL_AUDIENCE: &str = "https://gmail.googleapis.com/";
pub const GMAIL_TARGET: &str = "me";
const ISSUER: &str = "https://accounts.google.com";
const TOKEN: &str = "https://oauth2.googleapis.com/token";
const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";

pub static GOOGLE_OAUTH_DIALECT: OAuthDialectRegistration = OAuthDialectRegistration::new(
    agent_access_provider::module_metadata!(),
    "google",
    &GoogleDialect {
        token: TOKEN,
        userinfo: USERINFO,
        profile: "https://gmail.googleapis.com/gmail/v1/users/me/profile",
    },
);
struct GoogleDialect {
    token: &'static str,
    userinfo: &'static str,
    profile: &'static str,
}

#[cfg(feature = "test-support")]
pub(crate) fn test_dialect(base: &str) -> &'static OAuthDialectRegistration {
    let endpoint = |path| &*Box::leak(format!("{base}{path}").into_boxed_str());
    Box::leak(Box::new(
        OAuthDialectRegistration::new(
            agent_access_provider::module_metadata!(),
            "google",
            Box::leak(Box::new(GoogleDialect {
                token: endpoint("/token"),
                userinfo: endpoint("/userinfo"),
                profile: endpoint("/gmail/v1/users/me/profile"),
            })),
        )
        .development_only(),
    ))
}

#[async_trait]
impl OAuthDialect for GoogleDialect {
    fn validate_registration(&self, c: &OAuthRegistrationConfig) -> Result<(), String> {
        if c.base_url.trim_end_matches('/') != ISSUER
            || c.encoding != OAuthTokenEncoding::Form
            || c.client_auth != OAuthClientAuth::ClientSecretPost
            || c.rotation != OAuthRotation::PreserveOld
            || !c.adapter_settings.is_empty()
        {
            return Err("Google requires base_url https://accounts.google.com, form encoding, client_secret_post and preserve_old rotation".into());
        }
        for profile in c.permission_profiles.values() {
            let scopes: BTreeSet<_> = profile
                .requested_scopes()
                .iter()
                .map(String::as_str)
                .collect();
            if profile.scope_mode != OAuthScopeMode::Explicit
                || scopes != BTreeSet::from(["openid", GMAIL_SCOPE])
                || profile.target != GMAIL_TARGET
                || profile.audience != GMAIL_AUDIENCE
            {
                return Err("Google Gmail profiles require openid and gmail.modify, target me and audience https://gmail.googleapis.com/".into());
            }
        }
        Ok(())
    }
    fn upstream_allowlist(&self, _: &OAuthRegistrationConfig) -> Vec<String> {
        vec![self.token.into(), self.userinfo.into(), self.profile.into()]
    }
    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
        url.query_pairs_mut().extend_pairs([
            ("client_id", client.config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", &client.config.redirect_uri),
            ("scope", &profile.requested_scopes().join(" ")),
            ("state", request.state),
            ("code_challenge", request.code_challenge_s256),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            // Connect/reconnect requires fresh refresh material. Do not silently
            // reuse material from a possibly different account or consent grant.
            ("prompt", "consent select_account"),
        ]);
        Ok(url)
    }
    fn callback_issuer(&self, _: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        OAuthCallbackIssuer::new(ISSUER, false)
    }
    fn refresh_replay(&self, _: &OAuthRegistrationConfig) -> RefreshReplay {
        RefreshReplay::Reusable
    }
    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        token(
            self.token,
            http,
            client,
            BTreeMap::from([
                ("grant_type", "authorization_code"),
                ("code", exchange.code),
                ("redirect_uri", client.config.redirect_uri.as_str()),
                ("code_verifier", exchange.code_verifier),
            ]),
            None,
        )
        .await
    }
    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        _: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        token(
            self.token,
            http,
            client,
            BTreeMap::from([
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ]),
            Some(granted_scopes),
        )
        .await
    }
    async fn identity(
        &self,
        http: &OAuthHttp,
        _: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError> {
        let value = get(http, self.userinfo, access_token, "oauth.identity").await?;
        let subject = value["sub"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 255)
            .ok_or(OAuthDialectError::InvalidResponse)?;
        let profile = get(http, self.profile, access_token, "oauth.mailbox").await?;
        let email = profile["emailAddress"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .ok_or(OAuthDialectError::InvalidResponse)?;
        Ok(ConnectedIdentity::new(email).with_subject(subject))
    }
    async fn discover_targets(
        &self,
        _: &OAuthHttp,
        _: &OAuthClient<'_>,
        _: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        // Google's token-response evidence is authoritative for this fixed
        // account target. Never manufacture evidence from requested scopes.
        Ok(vec![
            OAuthTarget::new(GMAIL_TARGET, GMAIL_AUDIENCE, granted_scopes.clone())
                .with_name("Connected Gmail mailbox"),
        ])
    }
}
async fn get(
    http: &OAuthHttp,
    url: &str,
    token: &str,
    operation: &str,
) -> Result<Value, OAuthDialectError> {
    let response = http
        .send(
            http.request(Method::GET, Url::parse(url).unwrap())
                .bearer_auth(token),
            operation,
        )
        .await?;
    response_json(response).await
}
async fn response_json(response: OAuthResponse) -> Result<Value, OAuthDialectError> {
    let status = response.status();
    // Only HTTP 429 is throttling, with its Retry-After wait bounded to one
    // day. Server failures are failures: they pause refresh with the failure
    // backoff but are never reported as a rate limit.
    if status == 429 {
        let delay = response
            .header("retry-after")
            .and_then(UpstreamRetryAfter::parse)
            .map_or(1, |wait| wait.seconds());
        return Err(OAuthDialectError::RetryAfter(delay));
    }
    if status >= 500 {
        return Err(OAuthDialectError::Failed);
    }
    let value = response.json().await?;
    if (200..300).contains(&status) {
        return Ok(value);
    }
    Err(match value["error"].as_str() {
        Some("invalid_grant") => OAuthDialectError::GrantInvalid,
        Some("invalid_client" | "unauthorized_client") => OAuthDialectError::ClientRejected,
        Some("temporarily_unavailable" | "server_error") => OAuthDialectError::Failed,
        Some("invalid_scope" | "access_denied") => OAuthDialectError::PermissionRejected,
        _ if status == 401 => OAuthDialectError::GrantInvalid,
        _ if status == 403 => OAuthDialectError::PermissionRejected,
        _ => OAuthDialectError::RequestRejected,
    })
}
async fn token(
    endpoint: &str,
    http: &OAuthHttp,
    client: &OAuthClient<'_>,
    mut fields: BTreeMap<&str, &str>,
    prior_scopes: Option<&BTreeSet<String>>,
) -> Result<TokenGrant, OAuthDialectError> {
    fields.insert("client_id", &client.config.client_id);
    fields.insert("client_secret", client.client_secret);
    let response = http
        .send(
            http.request(Method::POST, Url::parse(endpoint).unwrap())
                .form(&fields),
            "oauth.token",
        )
        .await?;
    parse_grant(response_json(response).await?, prior_scopes)
}
fn parse_grant(
    value: Value,
    prior_scopes: Option<&BTreeSet<String>>,
) -> Result<TokenGrant, OAuthDialectError> {
    let invalid = || OAuthDialectError::InvalidResponse;
    let scopes = match value.get("scope") {
        Some(Value::String(scope)) => scope.split_ascii_whitespace().map(str::to_owned).collect(),
        None => prior_scopes.ok_or_else(invalid)?.iter().cloned().collect(),
        _ => return Err(invalid()),
    };
    // OAuth 2.0 refresh omitting scope retains the original *granted* scopes.
    // Code exchange must provide evidence; configured scopes are not evidence.
    let refresh_token = match value.get("refresh_token") {
        Some(Value::String(token)) if !token.is_empty() => {
            IssuedRefreshToken::Issued(token.clone())
        }
        None if prior_scopes.is_some() => IssuedRefreshToken::Retained,
        None => IssuedRefreshToken::Absent,
        _ => return Err(invalid()),
    };
    Ok(TokenGrant::new(
        value["access_token"].as_str().ok_or_else(invalid)?,
        value["token_type"].as_str().ok_or_else(invalid)?,
        value["expires_in"].as_u64().ok_or_else(invalid)?,
        refresh_token,
    )
    .with_scopes(scopes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    fn config() -> OAuthRegistrationConfig {
        OAuthRegistrationConfig {
            login_binding: None,
            adapter: OAuthAdapter::new("google"),
            base_url: ISSUER.into(),
            redirect_uri: "http://127.0.0.1:8787/v1/oauth/callback/google".into(),
            client_id: "test-app".into(),
            client_secret_ref: "env:NOT_READ".into(),
            adapter_settings: BTreeMap::new(),
            client_auth: OAuthClientAuth::ClientSecretPost,
            encoding: OAuthTokenEncoding::Form,
            rotation: OAuthRotation::PreserveOld,
            allow_insecure_loopback: true,
            permission_profiles: BTreeMap::from([(
                "mail".into(),
                OAuthPermissionProfile {
                    scope_mode: OAuthScopeMode::Explicit,
                    scopes: Some(vec!["openid".into(), GMAIL_SCOPE.into()]),
                    audience: GMAIL_AUDIENCE.into(),
                    target: GMAIL_TARGET.into(),
                },
            )]),
        }
    }
    #[test]
    fn endpoints_consent_and_issuer_are_explicit() {
        let dialect = GOOGLE_OAUTH_DIALECT.dialect();
        let mut c = config();
        dialect.validate_registration(&c).unwrap();
        let client = OAuthClient::new("google", &c, "secret");
        let url = dialect
            .authorization_url(
                &client,
                &c.permission_profiles["mail"],
                AuthorizationRequest::new("state", "challenge"),
            )
            .unwrap();
        let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs["access_type"], "offline");
        assert_eq!(pairs["prompt"], "consent select_account");
        assert!(!pairs.contains_key("include_granted_scopes"));
        assert_eq!(pairs["code_challenge_method"], "S256");
        let issuer = dialect.callback_issuer(&c);
        assert!(issuer.accepts(None));
        assert!(issuer.accepts(Some(ISSUER)));
        assert!(!issuer.accepts(Some("https://evil.test")));
        assert!(!issuer.accepts(Some("")));
        c.base_url = "https://evil.test".into();
        assert!(dialect.validate_registration(&c).is_err());
        c = config();
        c.permission_profiles
            .get_mut("mail")
            .unwrap()
            .scopes
            .as_mut()
            .unwrap()
            .push("https://mail.google.com/".into());
        assert!(dialect.validate_registration(&c).is_err());
        c = config();
        let profile = c.permission_profiles.get_mut("mail").unwrap();
        profile.scope_mode = OAuthScopeMode::ServerDefault;
        profile.scopes = None;
        assert!(!dialect.supports_server_default_scopes());
        assert!(dialect.validate_registration(&c).is_err());
    }
    #[test]
    fn refresh_omissions_use_granted_evidence_but_partial_consent_never_expands() {
        let v = json!({"access_token":"access","expires_in":3600,"token_type":"Bearer"});
        assert!(parse_grant(v.clone(), None).is_err());
        let original = BTreeSet::from(["openid".into()]);
        let grant = parse_grant(v.clone(), Some(&original)).unwrap();
        assert_eq!(grant.scopes, vec!["openid"]);
        assert!(matches!(grant.refresh_token, IssuedRefreshToken::Retained));
        let mut v = v;
        v["scope"] = json!("openid");
        let grant = parse_grant(v.clone(), None).unwrap();
        assert_eq!(grant.scopes, vec!["openid"]);
        assert!(matches!(grant.refresh_token, IssuedRefreshToken::Absent));
        v["refresh_token"] = json!("new");
        assert!(matches!(
            parse_grant(v, None).unwrap().refresh_token,
            IssuedRefreshToken::Issued(_)
        ));
    }
    #[tokio::test]
    async fn token_wire_is_form_encoded_and_error_classification_preserves_recovery() {
        let server = MockServer::start().await;
        let base = Url::parse(&server.uri()).unwrap();
        let http = OAuthHttp::build(
            "test",
            "google",
            &base,
            &[format!("{}/**", server.uri())],
            &agent_access_provider::test_support::TestHost::default(),
        )
        .unwrap();
        let c = config();
        let client = OAuthClient::new("google", &c, "secret&value");
        for (status, error, retry_after, expected) in [
            (400, "invalid_grant", "3", OAuthDialectError::GrantInvalid),
            (
                400,
                "invalid_client",
                "3",
                OAuthDialectError::ClientRejected,
            ),
            // Only 429 is throttling; its wait is kept up to one day.
            (
                429,
                "rate_limit_exceeded",
                "3",
                OAuthDialectError::RetryAfter(3),
            ),
            (
                429,
                "rate_limit_exceeded",
                "3600",
                OAuthDialectError::RetryAfter(3600),
            ),
            (
                429,
                "rate_limit_exceeded",
                "999999",
                OAuthDialectError::RetryAfter(86_400),
            ),
            (503, "server_error", "3", OAuthDialectError::Failed),
            (500, "internal_failure", "3", OAuthDialectError::Failed),
            (400, "server_error", "3", OAuthDialectError::Failed),
            (
                400,
                "temporarily_unavailable",
                "3",
                OAuthDialectError::Failed,
            ),
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("client_secret=secret%26value"))
                .and(body_string_contains("grant_type=refresh_token"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Retry-After", retry_after)
                        .set_body_json(json!({"error":error})),
                )
                .expect(1)
                .mount(&server)
                .await;
            let result = token(
                &format!("{}/token", server.uri()),
                &http,
                &client,
                BTreeMap::from([
                    ("grant_type", "refresh_token"),
                    ("refresh_token", "refresh"),
                ]),
                Some(&BTreeSet::from(["openid".into()])),
            )
            .await;
            assert_eq!(result.err(), Some(expected));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}
