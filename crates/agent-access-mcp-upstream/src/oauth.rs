//! Preregistered MCP OAuth clients with operator-pinned resource and AS metadata.
//! Metadata is evidence to validate, never authority to choose a new destination.
use agent_access_provider::*;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub static MCP_OAUTH_DIALECT: OAuthDialectRegistration = OAuthDialectRegistration {
    id: "mcp_oauth",
    development_only: false,
    dialect: &McpOAuthDialect,
};

struct McpOAuthDialect;
const SETTINGS: [&str; 5] = [
    "resource",
    "protected_resource_metadata_url",
    "authorization_server_metadata_url",
    "authorization_endpoint",
    "token_endpoint",
];

struct Endpoints<'a> {
    resource: &'a str,
    resource_metadata: &'a str,
    server_metadata: &'a str,
    authorization: &'a str,
    token: &'a str,
}

fn approved_url(raw: &str, insecure_loopback: bool) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "MCP OAuth endpoint must be an absolute URL")?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if raw.len() > 2048
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || raw.contains('*')
        || raw.chars().any(char::is_control)
        || !(url.scheme() == "https" || (insecure_loopback && loopback && url.scheme() == "http"))
    {
        return Err("MCP OAuth endpoints require HTTPS without credentials, query, fragment or wildcards; HTTP needs explicit loopback permission".into());
    }
    Ok(url)
}

fn endpoints(config: &OAuthRegistrationConfig) -> Result<Endpoints<'_>, String> {
    if config.adapter_settings.len() != SETTINGS.len()
        || SETTINGS
            .iter()
            .any(|key| !config.adapter_settings.contains_key(*key))
    {
        return Err("MCP OAuth requires exactly resource, protected_resource_metadata_url, authorization_server_metadata_url, authorization_endpoint and token_endpoint adapter settings".into());
    }
    for value in config.adapter_settings.values() {
        approved_url(value, config.allow_insecure_loopback)?;
    }
    approved_url(&config.base_url, config.allow_insecure_loopback)?;
    if config.encoding != OAuthTokenEncoding::Form || config.rotation == OAuthRotation::RotateBoth {
        return Err(
            "MCP OAuth requires form token encoding and preserve_old or rotate_refresh rotation"
                .into(),
        );
    }
    if (config.client_auth == OAuthClientAuth::None) != config.client_secret_ref.is_empty() {
        return Err("public clients require an empty client_secret_ref; confidential clients require a secret reference".into());
    }
    let settings = &config.adapter_settings;
    let result = Endpoints {
        resource: &settings["resource"],
        resource_metadata: &settings["protected_resource_metadata_url"],
        server_metadata: &settings["authorization_server_metadata_url"],
        authorization: &settings["authorization_endpoint"],
        token: &settings["token_endpoint"],
    };
    for profile in config.permission_profiles.values() {
        validate_profile(&result, profile)?;
    }
    Ok(result)
}

fn scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 256
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn validate_profile(
    endpoints: &Endpoints<'_>,
    profile: &OAuthPermissionProfile,
) -> Result<(), String> {
    if profile.target != endpoints.resource || profile.audience != endpoints.resource {
        return Err(
            "MCP OAuth profile target and audience must equal the approved resource".into(),
        );
    }
    match profile.scope_mode {
        OAuthScopeMode::Explicit => {
            let scopes = profile.requested_scopes();
            if scopes.is_empty()
                || scopes.len() > 64
                || !scopes.iter().all(|scope| scope_token(scope))
                || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len()
            {
                return Err(
                    "MCP OAuth explicit profiles require bounded, unique OAuth scopes".into(),
                );
            }
        }
        OAuthScopeMode::ServerDefault if profile.scopes.is_some() => {
            return Err("MCP OAuth server-default profiles must omit scopes".into());
        }
        OAuthScopeMode::ServerDefault => {}
    }
    Ok(())
}

fn client_auth_method(auth: OAuthClientAuth) -> &'static str {
    match auth {
        OAuthClientAuth::None => "none",
        OAuthClientAuth::ClientSecretPost => "client_secret_post",
        OAuthClientAuth::ClientSecretBasic => "client_secret_basic",
    }
}

fn string_list<'a>(
    value: &'a Value,
    field: &str,
) -> Result<Option<Vec<&'a str>>, OAuthDialectError> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .filter(|v| v.len() <= 128)
        .ok_or(OAuthDialectError::InvalidResponse)?;
    values
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control))
                .ok_or(OAuthDialectError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

async fn metadata(http: &OAuthHttp, endpoint: &str) -> Result<Value, OAuthDialectError> {
    let response = http
        .send(
            http.request(
                Method::GET,
                Url::parse(endpoint).map_err(|_| OAuthDialectError::Configuration)?,
            )
            .header("Accept", "application/json"),
            "oauth.metadata",
        )
        .await?;
    if response.status() == 429 {
        return Err(OAuthDialectError::Throttled);
    }
    if response.status() != 200 {
        return Err(OAuthDialectError::Failed);
    }
    let value = response.json().await?;
    if !value.is_object() {
        return Err(OAuthDialectError::InvalidResponse);
    }
    Ok(value)
}

async fn discover(
    http: &OAuthHttp,
    config: &OAuthRegistrationConfig,
    refresh: bool,
) -> Result<OAuthCallbackIssuer, OAuthDialectError> {
    let endpoints = endpoints(config).map_err(|_| OAuthDialectError::Configuration)?;
    let resource = metadata(http, endpoints.resource_metadata).await?;
    if resource.get("resource").and_then(Value::as_str) != Some(endpoints.resource)
        || !string_list(&resource, "authorization_servers")?
            .is_some_and(|servers| servers.contains(&config.base_url.as_str()))
        || string_list(&resource, "bearer_methods_supported")?
            .is_some_and(|methods| !methods.contains(&"header"))
    {
        return Err(OAuthDialectError::InvalidResponse);
    }
    string_list(&resource, "scopes_supported")?;
    let server = metadata(http, endpoints.server_metadata).await?;
    if server.get("issuer").and_then(Value::as_str) != Some(config.base_url.as_str())
        || server.get("authorization_endpoint").and_then(Value::as_str)
            != Some(endpoints.authorization)
        || server.get("token_endpoint").and_then(Value::as_str) != Some(endpoints.token)
        || !string_list(&server, "response_types_supported")?
            .is_some_and(|types| types.contains(&"code"))
        || !string_list(&server, "code_challenge_methods_supported")?
            .is_some_and(|methods| methods.contains(&"S256"))
        || !string_list(&server, "token_endpoint_auth_methods_supported")?
            .unwrap_or_else(|| vec!["client_secret_basic"])
            .contains(&client_auth_method(config.client_auth))
        || string_list(&server, "grant_types_supported")?.is_some_and(|types| {
            !types.contains(&if refresh {
                "refresh_token"
            } else {
                "authorization_code"
            })
        })
    {
        return Err(OAuthDialectError::InvalidResponse);
    }
    string_list(&server, "scopes_supported")?;
    let required = match server.get("authorization_response_iss_parameter_supported") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(OAuthDialectError::InvalidResponse),
    };
    Ok(OAuthCallbackIssuer {
        value: config.base_url.clone(),
        required,
    })
}

#[async_trait]
impl OAuthDialect for McpOAuthDialect {
    fn supports_server_default_scopes(&self) -> bool {
        true
    }

    fn allows_access_without_refresh(&self) -> bool {
        true
    }
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
        endpoints(config).map(|_| ())
    }

    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
        [
            "protected_resource_metadata_url",
            "authorization_server_metadata_url",
            "token_endpoint",
        ]
        .iter()
        .filter_map(|key| config.adapter_settings.get(*key).cloned())
        .collect()
    }

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError> {
        let endpoints = endpoints(client.config).map_err(|_| OAuthDialectError::Configuration)?;
        validate_profile(&endpoints, profile).map_err(|_| OAuthDialectError::Configuration)?;
        let mut url =
            Url::parse(endpoints.authorization).map_err(|_| OAuthDialectError::Configuration)?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &client.config.client_id),
            ("redirect_uri", &client.config.redirect_uri),
            ("state", request.state),
            ("code_challenge", request.code_challenge_s256),
            ("code_challenge_method", "S256"),
            ("resource", endpoints.resource),
        ]);
        if profile.scope_mode == OAuthScopeMode::Explicit {
            url.query_pairs_mut()
                .append_pair("scope", &profile.requested_scopes().join(" "));
        }
        Ok(url)
    }

    async fn prepare_authorization(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<PreparedAuthorization, OAuthDialectError> {
        let callback_issuer = discover(http, client.config, false).await?;
        Ok(PreparedAuthorization {
            url: self.authorization_url(client, profile, request)?,
            callback_issuer,
        })
    }

    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
        // Dynamic preparation supplies the authoritative advertised requirement.
        OAuthCallbackIssuer {
            value: config.base_url.clone(),
            required: true,
        }
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
        token(
            http,
            client,
            exchange.profile,
            BTreeMap::from([
                ("grant_type", "authorization_code".into()),
                ("code", exchange.code.into()),
                ("code_verifier", exchange.code_verifier.into()),
                ("redirect_uri", client.config.redirect_uri.clone()),
            ]),
            None,
        )
        .await
    }

    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError> {
        token(
            http,
            client,
            profile,
            BTreeMap::from([
                ("grant_type", "refresh_token".into()),
                ("refresh_token", refresh_token.into()),
            ]),
            Some(granted_scopes),
        )
        .await
    }

    async fn identity(
        &self,
        _: &OAuthHttp,
        _: &OAuthClient<'_>,
        _: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError> {
        Ok(ConnectedIdentity {
            subject: None,
            display_name: "Connected; upstream account identity unavailable".into(),
        })
    }

    async fn discover_targets(
        &self,
        _: &OAuthHttp,
        client: &OAuthClient<'_>,
        _: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
        let endpoints = endpoints(client.config).map_err(|_| OAuthDialectError::Configuration)?;
        // Resource binding was validated before issuing/refreshing the token;
        // only the actual grant's scopes supply authorization evidence here.
        Ok(vec![OAuthTarget {
            id: endpoints.resource.into(),
            audience: endpoints.resource.into(),
            name: "Connected MCP resource".into(),
            scopes: granted_scopes.clone(),
        }])
    }
}

async fn token(
    http: &OAuthHttp,
    client: &OAuthClient<'_>,
    profile: &OAuthPermissionProfile,
    mut fields: BTreeMap<&str, String>,
    original_grant_scopes: Option<&BTreeSet<String>>,
) -> Result<TokenGrant, OAuthDialectError> {
    let endpoints = endpoints(client.config).map_err(|_| OAuthDialectError::Configuration)?;
    validate_profile(&endpoints, profile).map_err(|_| OAuthDialectError::Configuration)?;
    // A failed metadata GET cannot have consumed this code/refresh token. Never
    // classify a failure after the token POST as NotSent on this basis.
    discover(http, client.config, original_grant_scopes.is_some())
        .await
        .map_err(|_| OAuthDialectError::NotSent)?;
    fields.insert("resource", endpoints.resource.into());
    if profile.scope_mode == OAuthScopeMode::Explicit {
        fields.insert("scope", profile.requested_scopes().join(" "));
    }
    let mut request = http.request(
        Method::POST,
        Url::parse(endpoints.token).map_err(|_| OAuthDialectError::Configuration)?,
    );
    match client.config.client_auth {
        OAuthClientAuth::None => {
            fields.insert("client_id", client.config.client_id.clone());
        }
        OAuthClientAuth::ClientSecretPost => {
            if client.client_secret.is_empty() {
                return Err(OAuthDialectError::Configuration);
            }
            fields.insert("client_id", client.config.client_id.clone());
            fields.insert("client_secret", client.client_secret.into());
        }
        OAuthClientAuth::ClientSecretBasic => {
            if client.client_secret.is_empty() {
                return Err(OAuthDialectError::Configuration);
            }
            let encode = |value: &str| {
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            };
            request = request.basic_auth(
                encode(&client.config.client_id),
                Some(encode(client.client_secret)),
            );
        }
    }
    let response = http
        .send(
            request.header("Accept", "application/json").form(&fields),
            "oauth.token",
        )
        .await?;
    let status = response.status();
    if status == 429 {
        return Err(OAuthDialectError::Throttled);
    }
    if status >= 500 {
        return Err(OAuthDialectError::Failed);
    }
    let body = response.json().await?;
    if status != 200 {
        return Err(match body.get("error").and_then(Value::as_str) {
            Some("invalid_grant") => OAuthDialectError::GrantInvalid,
            Some("invalid_client" | "unauthorized_client") => OAuthDialectError::ClientRejected,
            _ => OAuthDialectError::Failed,
        });
    }
    parse_grant(body, profile, original_grant_scopes, client.config.rotation)
}

fn parse_grant(
    body: Value,
    profile: &OAuthPermissionProfile,
    original_grant_scopes: Option<&BTreeSet<String>>,
    rotation: OAuthRotation,
) -> Result<TokenGrant, OAuthDialectError> {
    let invalid = || OAuthDialectError::InvalidResponse;
    if body
        .get("resource")
        .is_some_and(|value| value.as_str() != Some(profile.audience.as_str()))
    {
        return Err(invalid());
    }
    // Some servers report no scope details as an empty string in default mode.
    let response_scope = body.get("scope").filter(|scope| {
        !(profile.scope_mode == OAuthScopeMode::ServerDefault && scope.as_str() == Some(""))
    });
    let scopes = match response_scope {
        Some(Value::String(scope)) => {
            let scopes: Vec<_> = scope.split(' ').map(str::to_owned).collect();
            if scopes.len() > 64
                || !scopes.iter().all(|scope| scope_token(scope))
                || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len()
            {
                return Err(invalid());
            }
            scopes
        }
        // RFC6749§5.1: absent response scope confirms the explicit request.
        // With no request scope, default consent has unknown scopes unless
        // the original grant supplied them. Refresh does not acquire current
        // server defaults, nor turn later token scopes into consent evidence.
        None => match profile.scope_mode {
            OAuthScopeMode::Explicit => profile.requested_scopes().to_vec(),
            OAuthScopeMode::ServerDefault => original_grant_scopes
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
        },
        _ => return Err(invalid()),
    };
    let refresh_token = match body.get("refresh_token") {
        Some(Value::String(token))
            if !token.is_empty()
                && token.len() <= 32768
                && !token.chars().any(char::is_control) =>
        {
            IssuedRefreshToken::Issued(token.clone())
        }
        None if original_grant_scopes.is_some() && rotation == OAuthRotation::PreserveOld => {
            IssuedRefreshToken::Retained
        }
        None if original_grant_scopes.is_none() => IssuedRefreshToken::Absent,
        _ => return Err(invalid()),
    };
    let access_token = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| {
            !token.is_empty()
                && token.len() <= 32768
                && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
        .ok_or_else(invalid)?;
    let token_type = body
        .get("token_type")
        .and_then(Value::as_str)
        .filter(|value| value.eq_ignore_ascii_case("Bearer"))
        .ok_or_else(invalid)?;
    Ok(TokenGrant {
        access_token: access_token.into(),
        token_type: token_type.into(),
        expires_in: body
            .get("expires_in")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(invalid)?,
        scopes,
        refresh_token,
        supersedes_other_access: false,
    })
}

#[cfg(test)]
mod tests;
