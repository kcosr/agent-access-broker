use serde::Deserialize;
use url::Url;

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
