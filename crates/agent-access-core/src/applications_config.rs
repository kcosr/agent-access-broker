//! `[applications.<id>]`: operator-approved client applications that obtain
//! short-lived agent tokens for a person who approved them in the portal.
use crate::{
    BrokerConfig, DEFAULT_EXECUTION_CONTEXT, DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS,
    HostConfigError, is_safe_identifier, is_valid_execution_context_value, load_secret_ref_value,
    parse_ttl_seconds,
};
use agent_access_provider::{is_loopback_or_localhost, is_service_name};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use url::Url;

/// `[applications]`, keyed by application ID, which is the OAuth client ID.
pub type ApplicationsConfig = BTreeMap<String, ApplicationConfig>;

pub const APPLICATION_ID_MAX_BYTES: usize = 64;
pub const APPLICATION_REDIRECT_URI_MAX_BYTES: usize = 2048;
const APPLICATION_MAX_REDIRECT_URIS: usize = 16;
const APPLICATION_DISPLAY_NAME_MAX_BYTES: usize = 128;
const APPLICATION_SECRET_MIN_BYTES: usize = 16;
const APPLICATION_SECRET_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationConfig {
    pub display_name: String,
    pub client_secret_ref: String,
    pub redirect_uris: Vec<String>,
    pub connect: ApplicationConnectLevel,
    pub allowed_execution_contexts: Vec<String>,
    pub allowed_services: Option<Vec<String>>,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: String,
    #[serde(default = "default_refresh_idle_ttl")]
    pub refresh_idle_ttl: String,
}

pub fn default_access_token_ttl() -> String {
    "8h".to_string()
}

pub fn default_refresh_idle_ttl() -> String {
    "90d".to_string()
}

/// What every person who connects the application receives. The person does
/// not choose; `none` connects nobody and ends existing access at reload.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationConnectLevel {
    None,
    ReadOnly,
    ReadWrite,
}

impl ApplicationConnectLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }
}

fn max_access_token_ttl_seconds(config: &BrokerConfig) -> u64 {
    config
        .broker_tokens
        .as_ref()
        .and_then(|tokens| tokens.max_self_issued_agent_invoke_ttl.as_deref())
        .and_then(parse_ttl_seconds)
        .unwrap_or(DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS)
}

/// Whether `value` may be registered as a redirect URI: absolute `https`
/// (plain `http` only for a loopback host), without fragment or credentials.
pub fn is_valid_application_redirect_uri(value: &str) -> bool {
    if value.is_empty()
        || value.len() > APPLICATION_REDIRECT_URI_MAX_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.host().is_some()
        && url.fragment().is_none()
        && !value.contains('#')
        && url.username().is_empty()
        && url.password().is_none()
        && match url.scheme() {
            "https" => true,
            "http" => is_loopback_or_localhost(url.host()),
            _ => false,
        }
}

pub(crate) fn validate(config: &BrokerConfig, errors: &mut Vec<String>) {
    if config.applications.is_empty() {
        return;
    }
    if config.identity.authority != "managed"
        || config.managed_store.is_none()
        || config.broker_tokens.is_none()
        || !config
            .identity
            .sources
            .iter()
            .any(|source| source.kind == "broker_tokens")
    {
        errors.push(
            "applications requires managed identity, managed_store, broker_tokens and a broker_tokens identity source"
                .to_string(),
        );
    }
    if !config.browser_auth.enabled || config.browser_auth.public_origin.is_none() {
        errors.push(
            "applications requires browser_auth.enabled and browser_auth.public_origin".to_string(),
        );
    }
    if !config.management.enabled {
        errors.push("applications requires management.enabled".to_string());
    }
    let max_ttl = max_access_token_ttl_seconds(config);
    for (id, application) in &config.applications {
        let label = format!("applications.{id}");
        if !is_safe_identifier(id) || id.len() > APPLICATION_ID_MAX_BYTES || id.contains(':') {
            errors.push(format!(
                "{label} has an invalid application ID; use at most {APPLICATION_ID_MAX_BYTES} safe identifier characters"
            ));
        }
        let name = application.display_name.as_str();
        if name.trim().is_empty()
            || name.trim() != name
            || name.len() > APPLICATION_DISPLAY_NAME_MAX_BYTES
            || name.chars().any(char::is_control)
        {
            errors.push(format!(
                "{label}.display_name must be 1 to {APPLICATION_DISPLAY_NAME_MAX_BYTES} bytes without control characters or surrounding whitespace"
            ));
        }
        if application.client_secret_ref.trim().is_empty() {
            errors.push(format!("{label}.client_secret_ref is required"));
        }
        if application.redirect_uris.is_empty()
            || application.redirect_uris.len() > APPLICATION_MAX_REDIRECT_URIS
        {
            errors.push(format!(
                "{label}.redirect_uris must list 1 to {APPLICATION_MAX_REDIRECT_URIS} URIs"
            ));
        }
        let mut seen = BTreeSet::new();
        for uri in &application.redirect_uris {
            if !is_valid_application_redirect_uri(uri) {
                errors.push(format!(
                    "{label}.redirect_uris entries must be absolute https URIs (http only for loopback hosts) without fragment or credentials"
                ));
            }
            if !seen.insert(uri) {
                errors.push(format!("{label}.redirect_uris must not repeat a URI"));
            }
        }
        if application.allowed_execution_contexts.is_empty() {
            errors.push(format!(
                "{label}.allowed_execution_contexts must not be empty"
            ));
        }
        let mut seen = BTreeSet::new();
        for context in &application.allowed_execution_contexts {
            if !is_valid_execution_context_value(context)
                || !seen.insert(context)
                || !config
                    .execution_context
                    .as_ref()
                    .map_or(context == DEFAULT_EXECUTION_CONTEXT, |configured| {
                        configured.allowed_values.contains(context)
                    })
            {
                errors.push(format!(
                    "{label} has an invalid, duplicate, or unconfigured execution context"
                ));
            }
        }
        if let Some(services) = &application.allowed_services {
            let mut seen = BTreeSet::new();
            if services.is_empty()
                || services
                    .iter()
                    .any(|service| !is_service_name(service) || !seen.insert(service))
            {
                errors.push(format!(
                    "{label}.allowed_services must list distinct service names when set"
                ));
            }
        }
        match parse_ttl_seconds(&application.access_token_ttl) {
            Some(seconds) if seconds <= max_ttl => {}
            Some(_) => errors.push(format!(
                "{label}.access_token_ttl must not exceed broker_tokens.max_self_issued_agent_invoke_ttl"
            )),
            None => errors.push(format!(
                "{label}.access_token_ttl must be a duration such as 30m, 8h, or 1d"
            )),
        }
        if parse_ttl_seconds(&application.refresh_idle_ttl)
            .is_none_or(|seconds| seconds > 3650 * 24 * 60 * 60)
        {
            errors.push(format!(
                "{label}.refresh_idle_ttl must be a duration of at most 3650d, such as 90d"
            ));
        }
    }
}

/// What a connected person's tokens receive from the application's current
/// registration. Built only for an application whose level is not `none`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationAccessTerms {
    pub application_id: String,
    /// The application's level is `read_only`.
    pub read_only: bool,
    pub allowed_execution_contexts: Vec<String>,
    pub allowed_services: Option<Vec<String>>,
    pub access_token_ttl_seconds: u64,
    pub refresh_idle_ttl_seconds: u64,
}

/// One application's current registration as the store checks it: where it
/// may be returned to and what it may mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationRegistration {
    pub application_id: String,
    pub redirect_uris: Vec<String>,
    /// `None` while the application's level is `none`.
    pub terms: Option<ApplicationAccessTerms>,
}

impl ApplicationRegistration {
    pub fn accepts_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered == redirect_uri)
    }
}

/// One loaded application: its registration and client secret.
#[derive(Clone)]
pub struct RegisteredApplication {
    id: String,
    config: ApplicationConfig,
    secret: Arc<str>,
    access_token_ttl_seconds: u64,
    refresh_idle_ttl_seconds: u64,
}

impl std::fmt::Debug for RegisteredApplication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredApplication")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RegisteredApplication {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.config.display_name
    }

    pub fn connect(&self) -> ApplicationConnectLevel {
        self.config.connect
    }

    pub fn accepts_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.config
            .redirect_uris
            .iter()
            .any(|registered| registered == redirect_uri)
    }

    pub fn access_token_ttl_seconds(&self) -> u64 {
        self.access_token_ttl_seconds
    }

    /// What the store checks pending requests, codes and tokens against.
    pub fn registration(&self) -> ApplicationRegistration {
        ApplicationRegistration {
            application_id: self.id.clone(),
            redirect_uris: self.config.redirect_uris.clone(),
            terms: self.terms(),
        }
    }

    /// The terms of this registration, or `None` while its level is `none`.
    pub fn terms(&self) -> Option<ApplicationAccessTerms> {
        (self.config.connect != ApplicationConnectLevel::None).then(|| ApplicationAccessTerms {
            application_id: self.id.clone(),
            read_only: self.config.connect == ApplicationConnectLevel::ReadOnly,
            allowed_execution_contexts: self.config.allowed_execution_contexts.clone(),
            allowed_services: self.config.allowed_services.clone(),
            access_token_ttl_seconds: self.access_token_ttl_seconds,
            refresh_idle_ttl_seconds: self.refresh_idle_ttl_seconds,
        })
    }
}

/// The applications of one runtime generation.
#[derive(Debug, Clone, Default)]
pub struct RegisteredApplications {
    applications: BTreeMap<String, RegisteredApplication>,
}

impl RegisteredApplications {
    /// Loads every client secret. A secret has 16 to 1024 visible ASCII
    /// bytes, is distinct from every other application's and from
    /// `other_secrets` (the trusted caller credentials), and stays out of the
    /// managed-token namespace.
    pub fn load(config: &BrokerConfig, other_secrets: &[&str]) -> Result<Self, HostConfigError> {
        let mut applications = BTreeMap::<String, RegisteredApplication>::new();
        for (id, application) in &config.applications {
            let secret = load_secret_ref_value(
                &format!("applications.{id}.client_secret_ref"),
                &application.client_secret_ref,
            )?;
            if secret.len() < APPLICATION_SECRET_MIN_BYTES
                || secret.len() > APPLICATION_SECRET_MAX_BYTES
                || !secret.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(HostConfigError::invalid(format!(
                    "application {id} client secret must contain {APPLICATION_SECRET_MIN_BYTES} to {APPLICATION_SECRET_MAX_BYTES} visible ASCII bytes"
                )));
            }
            if secret.starts_with("aab_") {
                return Err(HostConfigError::invalid(format!(
                    "application {id} client secret uses the reserved managed-token namespace"
                )));
            }
            let equals = |other: &str| bool::from(secret.as_bytes().ct_eq(other.as_bytes()));
            if applications.values().any(|other| equals(&other.secret))
                || other_secrets.iter().any(|other| equals(other))
            {
                return Err(HostConfigError::invalid(
                    "application client secrets must be distinct from each other and from trusted caller credentials",
                ));
            }
            let ttl = |value: &str| {
                parse_ttl_seconds(value).ok_or_else(|| {
                    HostConfigError::invalid(format!("application {id} has an invalid duration"))
                })
            };
            applications.insert(
                id.clone(),
                RegisteredApplication {
                    id: id.clone(),
                    access_token_ttl_seconds: ttl(&application.access_token_ttl)?,
                    refresh_idle_ttl_seconds: ttl(&application.refresh_idle_ttl)?,
                    config: application.clone(),
                    secret: Arc::from(secret),
                },
            );
        }
        Ok(Self { applications })
    }

    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&RegisteredApplication> {
        self.applications.get(id)
    }

    /// The current registration of `id`, or `None` when it is not registered.
    pub fn registration(&self, id: &str) -> Option<ApplicationRegistration> {
        self.get(id).map(RegisteredApplication::registration)
    }

    /// The application `client_id` names when `client_secret` is its secret.
    /// Every registration is compared, so timing does not reveal which IDs
    /// exist.
    pub fn authenticate(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Option<&RegisteredApplication> {
        let mut matched = None;
        for application in self.applications.values() {
            let secret_matches = bool::from(
                client_secret
                    .as_bytes()
                    .ct_eq(application.secret.as_bytes()),
            );
            if secret_matches && application.id == client_id {
                matched = Some(application);
            }
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_require_https_or_loopback_http_without_fragment_or_credentials() {
        for accepted in [
            "https://runner.example.test/auth/broker/callback",
            "https://runner.example.test:8443/callback?tenant=a",
            "http://localhost:3000/callback",
            "http://127.0.0.1/callback",
            "http://[::1]:8080/callback",
        ] {
            assert!(is_valid_application_redirect_uri(accepted), "{accepted}");
        }
        for refused in [
            "",
            "/callback",
            "http://runner.example.test/callback",
            "https://runner.example.test/callback#fragment",
            "https://runner.example.test/callback#",
            "https://user:secret@runner.example.test/callback",
            "https://user@runner.example.test/callback",
            "custom://callback",
            "https://runner.example.test/call back",
        ] {
            assert!(!is_valid_application_redirect_uri(refused), "{refused}");
        }
    }
}
