//! Egress proxy selection: the process proxy environment captured at startup,
//! configured service and global proxies, `NO_PROXY` matching, and proxy
//! credential resolution. Secret-bearing values stay inside this module; the
//! rest of the host sees sanitized [`EgressRoute`]s.
use crate::{ConfigError, HostConfigError, load_secret_ref_value};
use agent_access_provider::{EgressProxyConfig, EgressProxySource, EgressRoute};
use percent_encoding::percent_decode_str;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use url::Url;

#[derive(Clone, PartialEq, Eq)]
pub struct EgressProxyEnvironment {
    https_proxy: Option<ProxyTarget>,
    http_proxy: Option<ProxyTarget>,
    no_proxy: NoProxyMatcher,
}

impl EgressProxyEnvironment {
    pub fn from_process_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
        })
    }

    /// No proxy variables: every ordinary route is direct.
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            https_proxy: None,
            http_proxy: None,
            no_proxy: NoProxyMatcher::default(),
        }
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<Option<String>, String>,
    {
        let https_upper = parse_env_proxy("HTTPS_PROXY", lookup_env(&lookup, "HTTPS_PROXY")?)?;
        let https_lower = parse_env_proxy("https_proxy", lookup_env(&lookup, "https_proxy")?)?;
        let http_upper = parse_env_proxy("HTTP_PROXY", lookup_env(&lookup, "HTTP_PROXY")?)?;
        let http_lower = parse_env_proxy("http_proxy", lookup_env(&lookup, "http_proxy")?)?;
        let no_proxy_upper = parse_env_no_proxy("NO_PROXY", lookup_env(&lookup, "NO_PROXY")?)?;
        let no_proxy_lower = parse_env_no_proxy("no_proxy", lookup_env(&lookup, "no_proxy")?)?;
        Ok(Self {
            https_proxy: https_upper.or(https_lower),
            http_proxy: http_lower.or(http_upper),
            no_proxy: no_proxy_upper.or(no_proxy_lower).unwrap_or_default(),
        })
    }

    fn proxy_for_scheme(&self, scheme: &str) -> Option<ProxyTarget> {
        match scheme {
            "https" => self.https_proxy.clone(),
            "http" => self.http_proxy.clone(),
            _ => None,
        }
    }
}

impl fmt::Debug for EgressProxyEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressProxyEnvironment")
            .field("https_proxy", &self.https_proxy)
            .field("http_proxy", &self.http_proxy)
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

/// Ordinary egress route selection for one runtime generation: the captured
/// proxy environment and the configured global proxy.
#[derive(Clone)]
pub(crate) struct EgressProxyResolver {
    environment: Arc<EgressProxyEnvironment>,
    global_proxy: Option<EgressProxyConfig>,
}

impl EgressProxyResolver {
    pub(crate) fn new(
        environment: Arc<EgressProxyEnvironment>,
        global_proxy: Option<EgressProxyConfig>,
    ) -> Self {
        Self {
            environment,
            global_proxy,
        }
    }

    pub(crate) fn environment(&self) -> &Arc<EgressProxyEnvironment> {
        &self.environment
    }

    /// `NO_PROXY`, then the environment proxy for the scheme, then the
    /// service proxy, then the global proxy, and otherwise direct.
    pub(crate) fn resolve(
        &self,
        label: &str,
        upstream_base: &Url,
        service_proxy: Option<&EgressProxyConfig>,
    ) -> Result<EgressProxySelection, HostConfigError> {
        if self.environment.no_proxy.matches(upstream_base) {
            return Ok(EgressProxySelection::direct());
        }
        if let Some(proxy) = self.environment.proxy_for_scheme(upstream_base.scheme()) {
            return Ok(EgressProxySelection::proxied(
                EgressProxySource::Environment,
                proxy,
            ));
        }
        if let Some(config) = service_proxy {
            return ProxyTarget::from_application_config(label, config)
                .map(|target| EgressProxySelection::proxied(EgressProxySource::Service, target));
        }
        if let Some(config) = &self.global_proxy {
            return ProxyTarget::from_application_config("network.egress_proxy", config)
                .map(|target| EgressProxySelection::proxied(EgressProxySource::Global, target));
        }
        Ok(EgressProxySelection::direct())
    }
}

/// Resolves a configured proxy, including its credential references, without
/// using it, so startup rejects a proxy that a higher-precedence route hides.
pub(crate) fn preflight_egress_proxy(
    label: &str,
    config: Option<&EgressProxyConfig>,
) -> Result<(), HostConfigError> {
    if let Some(config) = config {
        let _ = ProxyTarget::from_application_config(label, config)?;
    }
    Ok(())
}

/// A selected route, holding the proxy's resolved credentials.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EgressProxySelection {
    proxy: Option<(EgressProxySource, ProxyTarget)>,
}

impl EgressProxySelection {
    pub(crate) fn direct() -> Self {
        Self { proxy: None }
    }

    fn proxied(source: EgressProxySource, proxy: ProxyTarget) -> Self {
        Self {
            proxy: Some((source, proxy)),
        }
    }

    /// The sanitized route: the mode and the proxy origin, never credentials.
    pub(crate) fn route(&self) -> EgressRoute {
        match &self.proxy {
            Some((source, proxy)) => EgressRoute::proxied(*source, &proxy.url),
            None => EgressRoute::direct(),
        }
    }

    /// Replaces reqwest's own environment proxies with this selection.
    pub(crate) fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, HostConfigError> {
        let builder = builder.no_proxy();
        match &self.proxy {
            Some((_, proxy)) => Ok(builder.proxy(proxy.reqwest_proxy()?)),
            None => Ok(builder),
        }
    }
}

impl fmt::Debug for EgressProxySelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressProxySelection")
            .field("route", &self.route())
            .field(
                "credentials",
                &self
                    .proxy
                    .as_ref()
                    .and_then(|(_, proxy)| proxy.credentials.as_ref())
                    .map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ProxyTarget {
    url: Url,
    credentials: Option<ProxyCredentials>,
}

impl ProxyTarget {
    fn from_application_config(
        label: &str,
        config: &EgressProxyConfig,
    ) -> Result<Self, HostConfigError> {
        let mut target = parse_proxy_url(
            &format!("{label}.url"),
            &config.url,
            ProxyUrlSource::ApplicationConfig,
        )
        .map_err(config_error)?;
        if let (Some(username_ref), Some(password_ref)) =
            (&config.username_ref, &config.password_ref)
        {
            let username =
                load_nonempty_proxy_secret(&format!("{label}.username_ref"), username_ref)?;
            let password =
                load_nonempty_proxy_secret(&format!("{label}.password_ref"), password_ref)?;
            target.credentials = Some(ProxyCredentials::new(username, password));
        }
        Ok(target)
    }

    fn sanitized_origin(&self) -> String {
        let port = self
            .url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        format!(
            "{}://{}{}",
            self.url.scheme(),
            self.url.host_str().unwrap_or("<unknown>"),
            port
        )
    }

    fn reqwest_proxy(&self) -> Result<reqwest::Proxy, HostConfigError> {
        let mut proxy = reqwest::Proxy::all(self.url.as_str()).map_err(|_| {
            HostConfigError::invalid(format!(
                "egress proxy {} could not be applied",
                self.sanitized_origin()
            ))
        })?;
        if let Some(credentials) = &self.credentials {
            proxy = proxy.basic_auth(&credentials.username, &credentials.password);
        }
        Ok(proxy)
    }
}

impl fmt::Debug for ProxyTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyTarget")
            .field("url", &self.sanitized_origin())
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ProxyCredentials {
    username: String,
    password: String,
}

impl ProxyCredentials {
    fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyCredentials(<redacted>)")
    }
}

fn load_nonempty_proxy_secret(label: &str, reference: &str) -> Result<String, HostConfigError> {
    let value = load_secret_ref_value(label, reference)?;
    if value.is_empty() {
        return Err(HostConfigError::invalid(format!(
            "{label} must resolve to a non-empty secret"
        )));
    }
    Ok(value)
}

fn parse_env_proxy(label: &str, value: Option<String>) -> Result<Option<ProxyTarget>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    parse_proxy_url(label, &value, ProxyUrlSource::Environment)
        .map(Some)
        .map_err(config_error)
}

fn lookup_env<F>(lookup: &F, name: &str) -> Result<Option<String>, ConfigError>
where
    F: Fn(&str) -> Result<Option<String>, String>,
{
    lookup(name).map_err(|error| ConfigError::Invalid {
        errors: vec![error],
    })
}

fn parse_env_no_proxy(
    label: &str,
    value: Option<String>,
) -> Result<Option<NoProxyMatcher>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    NoProxyMatcher::parse(label, &value)
        .map(Some)
        .map_err(config_error)
}

#[derive(Clone, Copy)]
enum ProxyUrlSource {
    ApplicationConfig,
    Environment,
}

fn parse_proxy_url(
    label: &str,
    value: &str,
    source: ProxyUrlSource,
) -> Result<ProxyTarget, Vec<String>> {
    let mut errors = Vec::new();
    let mut url = match Url::parse(value) {
        Ok(url) => url,
        Err(_) => return Err(vec![format!("{label} must be a valid URL")]),
    };
    if !matches!(url.scheme(), "http" | "https") {
        errors.push(format!("{label} must use http or https"));
    }
    if url.host_str().is_none() {
        errors.push(format!("{label} must include a host"));
    }
    if !matches!(url.path(), "" | "/") {
        errors.push(format!("{label} must be a proxy origin without a path"));
    }
    if url.query().is_some() {
        errors.push(format!("{label} must not include a query"));
    }
    if url.fragment().is_some() {
        errors.push(format!("{label} must not include a fragment"));
    }
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    let credentials = if has_userinfo {
        match source {
            ProxyUrlSource::ApplicationConfig => {
                errors.push(format!("{label} must not include username or password"));
                None
            }
            ProxyUrlSource::Environment => {
                if url.scheme() != "https" {
                    errors.push(format!(
                        "{label} must use https when proxy credentials are embedded"
                    ));
                    None
                } else {
                    match proxy_credentials_from_url(label, &url) {
                        Ok(credentials) => Some(credentials),
                        Err(error) => {
                            errors.push(error);
                            None
                        }
                    }
                }
            }
        }
    } else {
        None
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    if errors.is_empty() {
        Ok(ProxyTarget { url, credentials })
    } else {
        Err(errors)
    }
}

fn proxy_credentials_from_url(label: &str, url: &Url) -> Result<ProxyCredentials, String> {
    let username = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| format!("{label} username must be valid UTF-8"))?
        .to_string();
    let password = url
        .password()
        .map(|password| {
            percent_decode_str(password)
                .decode_utf8()
                .map(|value| value.to_string())
                .map_err(|_| format!("{label} password must be valid UTF-8"))
        })
        .transpose()?
        .unwrap_or_default();
    if username.is_empty() {
        return Err(format!("{label} username must not be empty"));
    }
    Ok(ProxyCredentials::new(username, password))
}

fn config_error(errors: Vec<String>) -> ConfigError {
    ConfigError::Invalid { errors }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct NoProxyMatcher {
    match_all: bool,
    rules: Vec<NoProxyRule>,
}

impl NoProxyMatcher {
    fn parse(label: &str, value: &str) -> Result<Self, Vec<String>> {
        let mut matcher = Self::default();
        let mut errors = Vec::new();
        for raw in value.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            match NoProxyRule::parse(token) {
                Ok(NoProxyRule::MatchAll) => matcher.match_all = true,
                Ok(rule) => matcher.rules.push(rule),
                Err(error) => errors.push(format!("{label} token {token} is invalid: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(matcher)
        } else {
            Err(errors)
        }
    }

    fn matches(&self, upstream: &Url) -> bool {
        if self.match_all {
            return true;
        }
        self.rules.iter().any(|rule| rule.matches(upstream))
    }
}

impl fmt::Debug for NoProxyMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoProxyMatcher")
            .field("match_all", &self.match_all)
            .field("rules", &self.rules)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
enum NoProxyRule {
    MatchAll,
    Host {
        host: NoProxyHost,
        port: Option<u16>,
    },
}

impl NoProxyRule {
    fn parse(token: &str) -> Result<Self, String> {
        if token == "*" {
            return Ok(Self::MatchAll);
        }
        let (host, port) = split_host_port(token)?;
        let host = if let Some(suffix) = host.strip_prefix('.') {
            if suffix.is_empty() {
                return Err("suffix host must not be empty".to_string());
            }
            validate_dns_host(suffix)?;
            NoProxyHost::DomainSuffix(suffix.to_ascii_lowercase())
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            NoProxyHost::Ip(ip)
        } else {
            validate_dns_host(&host)?;
            NoProxyHost::Exact(host.to_ascii_lowercase())
        };
        Ok(Self::Host { host, port })
    }

    fn matches(&self, upstream: &Url) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Host { host, port } => {
                if let Some(port) = port
                    && upstream.port_or_known_default() != Some(*port)
                {
                    return false;
                }
                let Some(upstream_host) = upstream.host_str() else {
                    return false;
                };
                host.matches(upstream_host)
            }
        }
    }
}

impl fmt::Debug for NoProxyRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MatchAll => formatter.write_str("*"),
            Self::Host { host, port } => formatter
                .debug_struct("Host")
                .field("host", host)
                .field("port", port)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum NoProxyHost {
    Exact(String),
    DomainSuffix(String),
    Ip(IpAddr),
}

impl NoProxyHost {
    fn matches(&self, upstream_host: &str) -> bool {
        match self {
            Self::Exact(host) => upstream_host.eq_ignore_ascii_case(host),
            Self::DomainSuffix(suffix) => {
                let upstream = upstream_host.to_ascii_lowercase();
                upstream == *suffix || upstream.ends_with(&format!(".{suffix}"))
            }
            Self::Ip(ip) => upstream_host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(upstream_host)
                .parse::<IpAddr>()
                .is_ok_and(|candidate| candidate == *ip),
        }
    }
}

impl fmt::Debug for NoProxyHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(host) => write!(formatter, "{host}"),
            Self::DomainSuffix(suffix) => write!(formatter, ".{suffix}"),
            Self::Ip(ip) => write!(formatter, "{ip}"),
        }
    }
}

fn split_host_port(token: &str) -> Result<(String, Option<u16>), String> {
    if let Some(remainder) = token.strip_prefix('[') {
        let Some((host, rest)) = remainder.split_once(']') else {
            return Err("bracketed IPv6 host is not closed".to_string());
        };
        let ip = host
            .parse::<IpAddr>()
            .map_err(|_| "bracketed host must be an IPv6 literal".to_string())?;
        if !ip.is_ipv6() {
            return Err("bracketed host must be an IPv6 literal".to_string());
        }
        let port = if rest.is_empty() {
            None
        } else {
            let Some(port) = rest.strip_prefix(':') else {
                return Err("unexpected text after bracketed IPv6 host".to_string());
            };
            Some(parse_port(port)?)
        };
        return Ok((host.to_string(), port));
    }
    if token.contains('[') || token.contains(']') {
        return Err("IPv6 literals must use brackets".to_string());
    }
    if token.matches(':').count() > 1 {
        return Err("IPv6 literals must use brackets".to_string());
    }
    if let Some((host, port)) = token.rsplit_once(':') {
        if host.is_empty() || port.is_empty() || !port.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("port must be numeric".to_string());
        }
        return Ok((host.to_string(), Some(parse_port(port)?)));
    }
    Ok((token.to_string(), None))
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "port must be between 1 and 65535".to_string())?;
    if port == 0 {
        return Err("port must be between 1 and 65535".to_string());
    }
    Ok(port)
}

fn validate_dns_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err("host length is invalid".to_string());
    }
    if host.chars().any(|ch| {
        ch.is_ascii_whitespace() || ch.is_ascii_control() || matches!(ch, '/' | '\\' | ':' | '*')
    }) {
        return Err("host contains an invalid character".to_string());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("host label length is invalid".to_string());
        }
        let mut chars = label.chars();
        if !matches!(chars.next(), Some(ch) if ch.is_ascii_alphanumeric()) {
            return Err("host label must start with a letter or digit".to_string());
        }
        if !matches!(label.chars().last(), Some(ch) if ch.is_ascii_alphanumeric()) {
            return Err("host label must end with a letter or digit".to_string());
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err("host label contains an invalid character".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const TLS_PROXY_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw\nHTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\nDzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+\n5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP\nBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP\nBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop\nPAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik\ncy4eNw==\n-----END CERTIFICATE-----\n";
    const TLS_PROXY_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUUg3keFcU1xXWK8BNVb1KynPulV8wCgYIKoZIzj0EAwIw\nJjEkMCIGA1UEAwwbUnVzdGxzIFJvYnVzdCBSb290IC0gUnVuZyAyMCAXDTc1MDEw\nMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAhMR8wHQYDVQQDDBZyY2dlbiBzZWxm\nIHNpZ25lZCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEud6w4gtZ0xbw\nJ3E69SSMy5TZfdIifl9L5ZY+hgEe4UiUsBWS32f6Y5NR5Jo8FO1f6o13b3+FvVHR\nEHCGdvppL6NoMGYwFQYDVR0RBA4wDIIKZm9vYmFyLmNvbTAdBgNVHSUEFjAUBggr\nBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFELvxbj5tD75n4pYFvJyr+c8qVEi\nMA8GA1UdEwEB/wQFMAMBAQAwCgYIKoZIzj0EAwIDSAAwRQIhALxSSdUsrRFnwNMu\n/doBqI8i8u5HdohVAheFTDwObkOMAiASSjULUtkWSD15u/7Sr01Wm9J1MpqW1pob\nBVqU3CNRlA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBiTCCATCgAwIBAgIUHWiVYIvMMWoZEFYvSz46COf2FqowCgYIKoZIzj0EAwIw\nHTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\nDzQwOTYwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtSdXN0bHMgUm9idXN0IFJvb3Qg\nLSBSdW5nIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAOCcBD7dXjmAZ3te5\nD47cCJ9ec93PWv7BKYIL826CJsKfXQOGrBTthLm77hXLhHu6uv8E5QXNLZpfowLQ\nDo1ao0MwQTAPBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRdza76r11Ok9vRmlg6\nNn/wL/N+jTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFmZrXeK\nhnfkahocvkhhNT3cDv1LWf6WBoFaCiBwZXFPAiARaKRiSCMG7PCHmSqFe82TBVmL\nodHGogAVax1Dh/aYAA==\n-----END CERTIFICATE-----\n";
    const TLS_PROXY_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTbAQpfjAT46fgF4B\nmP15n37woNG5ZNJmwcqsred/7tmhRANCAAS53rDiC1nTFvAncTr1JIzLlNl90iJ+\nX0vllj6GAR7hSJSwFZLfZ/pjk1HkmjwU7V/qjXdvf4W9UdEQcIZ2+mkv\n-----END PRIVATE KEY-----\n";

    struct TlsProxyTestServer {
        proxy_url: String,
        addr: SocketAddr,
        request_rx: mpsc::Receiver<String>,
    }

    fn env_from(entries: &[(&str, &str)]) -> Result<EgressProxyEnvironment, ConfigError> {
        EgressProxyEnvironment::from_lookup(|name| {
            Ok(entries
                .iter()
                .find(|(entry, _)| *entry == name)
                .map(|(_, value)| (*value).to_string()))
        })
    }

    fn temp_proxy_secret(value: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agent-access-proxy-secret-{}-{unique}",
            std::process::id()
        ));
        std::fs::write(&path, value).unwrap();
        path
    }

    fn spawn_tls_proxy() -> TlsProxyTestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let certs =
            rustls::pki_types::CertificateDer::pem_slice_iter(TLS_PROXY_CHAIN_PEM.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(TLS_PROXY_KEY_PEM.as_bytes()).unwrap();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        );
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls_stream = rustls::StreamOwned::new(connection, stream);
            let request = read_http_headers(&mut tls_stream);
            let _ = request_tx.send(request);
            let body = "proxied";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tls_stream.write_all(response.as_bytes());
        });

        TlsProxyTestServer {
            proxy_url: format!("https://foobar.com:{}", addr.port()),
            addr,
            request_rx,
        }
    }

    fn read_http_headers(reader: &mut impl Read) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let read = reader.read(&mut buffer).unwrap_or_default();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") || bytes.len() > 8192 {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[test]
    fn parses_environment_precedence_and_no_proxy() {
        let env = env_from(&[
            ("HTTPS_PROXY", "http://upper.example:8080"),
            ("https_proxy", "http://lower.example:8080"),
            ("HTTP_PROXY", "http://upper-http.example:8080"),
            ("http_proxy", "http://lower-http.example:8080"),
            ("NO_PROXY", ".internal,example.com:8443"),
            ("no_proxy", "*"),
        ])
        .unwrap();
        let https = Url::parse("https://service.example.com/").unwrap();
        let http = Url::parse("http://service.example.com/").unwrap();
        assert_eq!(
            env.proxy_for_scheme("https").unwrap().sanitized_origin(),
            "http://upper.example:8080"
        );
        assert_eq!(
            env.proxy_for_scheme("http").unwrap().sanitized_origin(),
            "http://lower-http.example:8080"
        );
        assert!(
            env.no_proxy
                .matches(&Url::parse("https://api.internal/").unwrap())
        );
        assert!(
            env.no_proxy
                .matches(&Url::parse("https://example.com:8443/").unwrap())
        );
        assert!(!env.no_proxy.matches(&https));
        assert!(!env.no_proxy.matches(&http));
    }

    #[test]
    fn rejects_invalid_environment_proxy_credentials() {
        let error =
            env_from(&[("HTTPS_PROXY", "http://user:pass@proxy.example:8080")]).unwrap_err();
        assert!(error.errors().iter().any(|error| {
            error.contains("HTTPS_PROXY must use https when proxy credentials are embedded")
        }));
    }

    #[test]
    fn matches_no_proxy_forms() {
        let matcher = NoProxyMatcher::parse(
            "NO_PROXY",
            "*,example.com,.internal,api.example.com:8443,127.0.0.1,[::1]",
        )
        .unwrap();
        assert!(matcher.matches(&Url::parse("https://anything.test/").unwrap()));

        let matcher = NoProxyMatcher::parse(
            "NO_PROXY",
            "example.com,.internal,api.example.com:8443,127.0.0.1,[::1]",
        )
        .unwrap();
        assert!(matcher.matches(&Url::parse("https://example.com/").unwrap()));
        assert!(matcher.matches(&Url::parse("https://svc.internal/").unwrap()));
        assert!(matcher.matches(&Url::parse("https://internal/").unwrap()));
        assert!(matcher.matches(&Url::parse("https://api.example.com:8443/").unwrap()));
        assert!(!matcher.matches(&Url::parse("https://api.example.com/").unwrap()));
        assert!(matcher.matches(&Url::parse("http://127.0.0.1/").unwrap()));
        assert!(matcher.matches(&Url::parse("http://[::1]/").unwrap()));
    }

    #[test]
    fn rejects_invalid_no_proxy_tokens() {
        let errors = NoProxyMatcher::parse("NO_PROXY", "valid.example,::1,host:abc").unwrap_err();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn redacts_debug_output() {
        let env = env_from(&[("HTTPS_PROXY", "https://user:pass@proxy.example:8443")]).unwrap();
        let debug = format!("{env:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("user"));
        assert!(!debug.contains("pass"));
    }

    #[tokio::test]
    async fn reqwest_https_proxy_sends_proxy_authorization_over_tls() {
        let proxy = spawn_tls_proxy();
        let username_path = temp_proxy_secret("proxy-user");
        let password_path = temp_proxy_secret("proxy-password");
        let target = ProxyTarget::from_application_config(
            "test.egress_proxy",
            &EgressProxyConfig {
                url: proxy.proxy_url,
                username_ref: Some(format!("file:{}", username_path.display())),
                password_ref: Some(format!("file:{}", password_path.display())),
            },
        )
        .unwrap();
        let selection = EgressProxySelection::proxied(EgressProxySource::Service, target);
        assert!(!format!("{selection:?}").contains("proxy-password"));
        let root_certificate =
            reqwest::Certificate::from_pem(TLS_PROXY_ROOT_PEM.as_bytes()).unwrap();
        let client = selection
            .apply(
                reqwest::Client::builder()
                    .add_root_certificate(root_certificate)
                    .resolve("foobar.com", proxy.addr),
            )
            .unwrap()
            .build()
            .unwrap();

        let response = client
            .get("http://upstream.example.test/resource")
            .send()
            .await
            .unwrap();

        assert_eq!(response.text().await.unwrap(), "proxied");
        let request = proxy
            .request_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(
            request.starts_with("GET http://upstream.example.test/resource HTTP/1.1"),
            "{request}"
        );
        let proxy_authorization = request
            .lines()
            .find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("proxy-authorization:")
            })
            .unwrap();
        assert_eq!(
            proxy_authorization,
            "proxy-authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA=="
        );
        let _ = std::fs::remove_file(username_path);
        let _ = std::fs::remove_file(password_path);
    }
}
