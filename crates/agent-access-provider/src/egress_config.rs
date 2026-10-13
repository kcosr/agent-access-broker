use serde::Deserialize;
use url::Url;

/// A backend's `egress_proxy` configuration table.
///
/// Configuration schema is intentionally exhaustive, like
/// [`AttachmentLimitsConfig`](crate::AttachmentLimitsConfig).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressProxyConfig {
    pub url: String,
    pub username_ref: Option<String>,
    pub password_ref: Option<String>,
}

impl std::fmt::Debug for EgressProxyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressProxyConfig")
            .field("url", &redacted_proxy_url_for_debug(&self.url))
            .field(
                "username_ref",
                &self.username_ref.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "password_ref",
                &self.password_ref.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn redacted_proxy_url_for_debug(value: &str) -> String {
    let Ok(url) = Url::parse(value) else {
        return "<invalid>".to_string();
    };
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    match url.host_str() {
        Some(host) => format!("{}://{}{}", url.scheme(), host, port),
        None => "<invalid>".to_string(),
    }
}

/// How an upstream client's traffic is routed. The host decides the route;
/// a provider only declares which kind it needs.
#[derive(Debug, Clone, Copy)]
pub enum EgressDeclaration<'a> {
    /// The host's ordinary selection: a `NO_PROXY` match connects directly;
    /// otherwise the environment proxy for the URL scheme, then this client's
    /// configured service proxy, then the global `network.egress_proxy`, and
    /// otherwise a direct connection. Loopback URLs are no exception.
    Ordinary(Option<&'a EgressProxyConfig>),
    /// A direct connection to a literal IPv4 or IPv6 loopback base URL,
    /// bypassing every proxy. The host grants it only to its OAuth clients and
    /// to enabled development-only registrations, and only for a literal
    /// loopback IP address: it rejects the client for any other caller and for
    /// any other URL, including `localhost`.
    LiteralLoopback,
}

/// Which proxy setting a proxied route came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressProxySource {
    Environment,
    Service,
    Global,
}

impl EgressProxySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Service => "service",
            Self::Global => "global",
        }
    }
}

/// The sanitized route a client's traffic takes, for traces and audit. It
/// records a proxy by its origin alone and never carries proxy credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRoute {
    proxy: Option<(EgressProxySource, String)>,
}

impl EgressRoute {
    pub fn direct() -> Self {
        Self { proxy: None }
    }

    /// A route through `proxy`, recorded as its scheme, host and port.
    pub fn proxied(source: EgressProxySource, proxy: &Url) -> Self {
        let port = proxy
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let origin = format!(
            "{}://{}{}",
            proxy.scheme(),
            proxy.host_str().unwrap_or("<unknown>"),
            port
        );
        Self {
            proxy: Some((source, origin)),
        }
    }

    /// `direct`, `environment`, `service` or `global`.
    pub fn mode(&self) -> &'static str {
        self.proxy
            .as_ref()
            .map_or("direct", |(source, _)| source.as_str())
    }

    /// The proxy origin, for proxied routes.
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_ref().map(|(_, origin)| origin.as_str())
    }

    /// The `egressProxy` audit value: the mode, plus the proxy origin when
    /// proxied.
    pub fn audit_value(&self) -> serde_json::Value {
        match self.proxy() {
            Some(proxy) => serde_json::json!({"mode": self.mode(), "proxy": proxy}),
            None => serde_json::json!({"mode": self.mode()}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_record_only_the_proxy_origin() {
        assert_eq!(
            EgressRoute::direct().audit_value(),
            serde_json::json!({"mode": "direct"})
        );
        let proxy = Url::parse("https://user:secret@proxy.example:8443/path?q=1").unwrap();
        let route = EgressRoute::proxied(EgressProxySource::Service, &proxy);
        assert_eq!(
            route.audit_value(),
            serde_json::json!({"mode": "service", "proxy": "https://proxy.example:8443"})
        );
        assert!(!format!("{route:?}").contains("secret"));
    }
}
