//! Helpers shared by the Jira and Confluence backends.
use agent_access_provider::{ExecutionCredential, ServiceCredentialKinds};
use thiserror::Error;
use url::Url;

pub fn validate_atlassian_gateway_credential(
    service: &str,
    patterns: &[String],
    cloud_id: Option<&str>,
    credentials: ServiceCredentialKinds<'_>,
    errors: &mut Vec<String>,
) {
    let uses_gateway = uses_atlassian_gateway_host(patterns);
    let execution_credentials = [
        ("credentials.service", credentials.service),
        ("credentials.per_user", credentials.per_user),
    ];
    let mut has_bearer_execution_credential = false;

    for (mode, credential) in execution_credentials {
        if let Some(kind) = credential {
            if kind == "bearer_token" {
                has_bearer_execution_credential = true;
            } else if uses_gateway {
                errors.push(format!(
                    "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but {mode}.{service}.type is not bearer_token"
                ));
            }
        }
    }

    if has_bearer_execution_credential && !uses_gateway {
        errors.push(format!(
            "{mode}.{service}.type bearer_token requires providers.{service}.allowed_upstream_hosts to include api.atlassian.com",
            mode = if credentials.service == Some("bearer_token") {
                "credentials.service"
            } else {
                "credentials.per_user"
            }
        ));
    }

    if !uses_gateway {
        return;
    }

    match cloud_id {
        Some(value) if uuid::Uuid::parse_str(value).is_ok() => {}
        Some(_) => errors.push(format!(
            "providers.{service}.cloud_id must be a valid Atlassian cloud UUID when api.atlassian.com is allowed"
        )),
        None => errors.push(format!(
            "providers.{service}.cloud_id is required when api.atlassian.com is allowed"
        )),
    }

    if !has_bearer_execution_credential {
        errors.push(format!(
            "providers.{service}.allowed_upstream_hosts includes api.atlassian.com but no bearer_token execution credential is configured"
        ));
    }
}

/// Whether an Atlassian provider allowlist routes through the Atlassian API
/// gateway. Only an exact `api.atlassian.com` host counts.
pub fn uses_atlassian_gateway_host(allowed_upstream_hosts: &[String]) -> bool {
    allowed_upstream_hosts.iter().any(|pattern| {
        Url::parse(pattern)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .is_some_and(|host| host == "api.atlassian.com")
    })
}

/// How an Atlassian execution credential authenticates a request: HTTP
/// Basic for a tenant API token, a bearer token through the gateway.
pub enum AtlassianAuthorization<'a> {
    Basic {
        username: &'a str,
        token: Option<&'a str>,
    },
    Bearer(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AtlassianCredentialError {
    #[error("basic username missing")]
    BasicUsernameMissing,
    #[error("bearer token missing")]
    BearerTokenMissing,
    #[error("unsupported credential kind")]
    UnsupportedKind,
}

impl<'a> AtlassianAuthorization<'a> {
    pub fn new(credential: &'a ExecutionCredential) -> Result<Self, AtlassianCredentialError> {
        match credential.kind.as_str() {
            "basic_api_token" => Ok(Self::Basic {
                username: credential
                    .username
                    .as_deref()
                    .ok_or(AtlassianCredentialError::BasicUsernameMissing)?,
                token: credential.token.as_deref(),
            }),
            "bearer_token" => Ok(Self::Bearer(
                credential
                    .token
                    .as_deref()
                    .ok_or(AtlassianCredentialError::BearerTokenMissing)?,
            )),
            _ => Err(AtlassianCredentialError::UnsupportedKind),
        }
    }

    pub fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::Basic { username, token } => builder.basic_auth(username, *token),
            Self::Bearer(token) => builder.bearer_auth(token),
        }
    }
}
