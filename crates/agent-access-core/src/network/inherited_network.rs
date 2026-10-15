//! The network settings command imports inherit (`network = "inherit"`).
//!
//! Each runtime generation builds one [`InheritedNetwork`]: the route the
//! Broker takes to an HTTPS destination outside `NO_PROXY` (the environment
//! proxy, else `[network.egress_proxy]`, else none) with that proxy's
//! credentials, the `NO_PROXY` entries as given, and the generation's
//! `[network.outbound_tls]` trust mode with its `ca_certificate` path. The
//! path is passed as configured: the Broker never reads, copies or writes
//! certificates for a command, which loads the file itself.
//!
//! The command request carries [`InheritedNetwork::wire`] as its `network`
//! field; the command's environment adds [`InheritedNetwork::environment`] as a
//! convenience. The value has no `Serialize`, and its `Debug` redacts the
//! proxy credentials.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the command request builder and the process supervisor consume these settings"
    )
)]
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::egress_proxy::ExportedProxy;
use super::outbound_tls::{OutboundTlsConfig, OutboundTlsTrustMode};

/// Variables naming the proxy, credentials percent-encoded in the URL.
pub(crate) const PROXY_VARIABLES: [&str; 4] =
    ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"];
/// Variables listing the `NO_PROXY` entries, comma-separated.
pub(crate) const NO_PROXY_VARIABLES: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// Replaces a runtime's default roots (OpenSSL and its users).
const SSL_CERT_FILE: &str = "SSL_CERT_FILE";
/// Replaces Python Requests' default roots.
const REQUESTS_CA_BUNDLE: &str = "REQUESTS_CA_BUNDLE";
/// Adds to Node's bundled roots.
const NODE_EXTRA_CA_CERTS: &str = "NODE_EXTRA_CA_CERTS";
/// Variables naming the configured CA certificate file. Which of them a
/// command receives depends on the trust mode, but all of them are reserved
/// to the Broker under `network = "inherit"`.
pub(crate) const TRUST_VARIABLES: [&str; 3] =
    [SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS];

/// Whether `name` is one of the variables the Broker may set from its egress
/// settings under `network = "inherit"`: [`PROXY_VARIABLES`],
/// [`NO_PROXY_VARIABLES`] or [`TRUST_VARIABLES`]. A command's `env` may set
/// them only with `network = "none"`.
pub(crate) fn is_inherited_network_variable(name: &str) -> bool {
    PROXY_VARIABLES
        .iter()
        .chain(&NO_PROXY_VARIABLES)
        .chain(&TRUST_VARIABLES)
        .any(|variable| *variable == name)
}

/// One generation's network settings for command imports.
pub(crate) struct InheritedNetwork {
    proxy: Option<CommandProxy>,
    no_proxy: Vec<String>,
    trust: OutboundTlsTrustMode,
    /// The configured `ca_certificate`, unchanged: absolute, and absent
    /// exactly under `system` trust, as configuration validation requires.
    ca_certificate: Option<PathBuf>,
}

/// The inherited proxy: its origin, its credentialed URL for the
/// environment, and its credentials for the request.
struct CommandProxy {
    url: String,
    credentialed_url: String,
    credentials: Option<ProxyCredentials>,
}

struct ProxyCredentials {
    username: String,
    password: String,
}

impl InheritedNetwork {
    pub(super) fn new(
        proxy: Option<ExportedProxy>,
        no_proxy: Vec<String>,
        outbound_tls: &OutboundTlsConfig,
    ) -> Self {
        let proxy = proxy.map(|proxy| CommandProxy {
            url: proxy.origin(),
            credentialed_url: proxy.credentialed_url(),
            credentials: proxy
                .credentials()
                .map(|(username, password)| ProxyCredentials {
                    username: username.to_owned(),
                    password: password.to_owned(),
                }),
        });
        Self {
            proxy,
            no_proxy,
            trust: outbound_tls.trust,
            ca_certificate: outbound_tls.ca_certificate.clone(),
        }
    }

    /// The proxy origin without credentials, when a proxy is inherited.
    fn proxy_url(&self) -> Option<&str> {
        self.proxy.as_ref().map(|proxy| proxy.url.as_str())
    }

    /// The request's `network` object:
    /// `{"proxy": {url, username?, password?} | null, "noProxy": [...],
    /// "trust": mode, "caCertificate": path | null}`, with `username` and
    /// `password` only for a proxy that needs them. Serializing it fails for
    /// a `caCertificate` path that is not UTF-8.
    pub(crate) fn wire(&self) -> InheritedNetworkWire<'_> {
        InheritedNetworkWire {
            proxy: self.proxy.as_ref().map(|proxy| ProxyWire {
                url: &proxy.url,
                username: proxy
                    .credentials
                    .as_ref()
                    .map(|credentials| credentials.username.as_str()),
                password: proxy
                    .credentials
                    .as_ref()
                    .map(|credentials| credentials.password.as_str()),
            }),
            no_proxy: &self.no_proxy,
            trust: trust_name(self.trust),
            ca_certificate: self.ca_certificate.as_deref(),
        }
    }

    /// The convenience variables: [`PROXY_VARIABLES`] with an inherited
    /// proxy, [`NO_PROXY_VARIABLES`] when there are entries, and the
    /// [`TRUST_VARIABLES`] the trust mode sets to the `ca_certificate` path.
    pub(crate) fn environment(&self) -> Vec<(&'static str, OsString)> {
        let trust_variables: Vec<(&'static str, OsString)> = match &self.ca_certificate {
            Some(path) => trust_variables(self.trust)
                .iter()
                .map(|name| (*name, path.as_os_str().to_owned()))
                .collect(),
            None => Vec::new(),
        };
        let mut variables = Vec::with_capacity(
            PROXY_VARIABLES.len() + NO_PROXY_VARIABLES.len() + trust_variables.len(),
        );
        if let Some(proxy) = &self.proxy {
            variables.extend(
                PROXY_VARIABLES.map(|name| (name, OsString::from(&proxy.credentialed_url))),
            );
        }
        if !self.no_proxy.is_empty() {
            let entries = OsString::from(self.no_proxy.join(","));
            variables.extend(NO_PROXY_VARIABLES.map(|name| (name, entries.clone())));
        }
        variables.extend(trust_variables);
        variables
    }

    /// The secrets these settings supply to a command: the proxy password,
    /// when it is not empty. Command output must not echo them.
    pub(crate) fn supplied_secrets(&self) -> impl Iterator<Item = &str> {
        self.proxy
            .iter()
            .filter_map(|proxy| proxy.credentials.as_ref())
            .map(|credentials| credentials.password.as_str())
            .filter(|password| !password.is_empty())
    }
}

/// The trust mode as `[network.outbound_tls] trust` spells it.
fn trust_name(trust: OutboundTlsTrustMode) -> &'static str {
    match trust {
        OutboundTlsTrustMode::System => "system",
        OutboundTlsTrustMode::Custom => "custom",
        OutboundTlsTrustMode::SystemPlusCustom => "system_plus_custom",
    }
}

/// The [`TRUST_VARIABLES`] a trust mode sets. `SSL_CERT_FILE` and
/// `REQUESTS_CA_BUNDLE` replace a runtime's default roots, so only `custom`
/// trust sets them; `NODE_EXTRA_CA_CERTS` adds to Node's bundled roots, so
/// both modes with a custom certificate set it.
fn trust_variables(trust: OutboundTlsTrustMode) -> &'static [&'static str] {
    match trust {
        OutboundTlsTrustMode::System => &[],
        OutboundTlsTrustMode::Custom => &[SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS],
        OutboundTlsTrustMode::SystemPlusCustom => &[NODE_EXTRA_CA_CERTS],
    }
}

impl fmt::Debug for InheritedNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InheritedNetwork")
            .field("proxy", &self.proxy_url())
            .field(
                "proxy_credentials",
                &self
                    .proxy
                    .as_ref()
                    .and_then(|proxy| proxy.credentials.as_ref())
                    .map(|_| "<redacted>"),
            )
            .field("no_proxy", &self.no_proxy)
            .field("trust", &self.trust)
            .field("ca_certificate", &self.ca_certificate)
            .finish()
    }
}

/// [`InheritedNetwork`] as the request's `network` object, borrowing its
/// values. Serialize it only into the request encoding.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InheritedNetworkWire<'a> {
    proxy: Option<ProxyWire<'a>>,
    no_proxy: &'a [String],
    trust: &'static str,
    ca_certificate: Option<&'a Path>,
}

#[derive(Serialize)]
struct ProxyWire<'a> {
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostConfigError;
    use crate::network::{EgressProxyEnvironment, HostNetwork};
    use agent_access_provider::{EgressProxyConfig, ProviderLimits};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// A path no test creates: exporting it shows the Broker passes the
    /// configured value without opening the file.
    const CA_PATH: &str = "/nonexistent/agent-access-command-network/corporate ca.pem";

    fn trusting(trust: OutboundTlsTrustMode, ca_certificate: Option<&str>) -> OutboundTlsConfig {
        OutboundTlsConfig {
            trust,
            ca_certificate: ca_certificate.map(PathBuf::from),
        }
    }

    fn custom() -> OutboundTlsConfig {
        trusting(OutboundTlsTrustMode::Custom, Some(CA_PATH))
    }

    fn system() -> OutboundTlsConfig {
        trusting(OutboundTlsTrustMode::System, None)
    }

    fn host_network(
        environment: &[(&str, &str)],
        global: Option<EgressProxyConfig>,
    ) -> HostNetwork {
        let environment = EgressProxyEnvironment::from_lookup(|name| {
            Ok(environment
                .iter()
                .find(|(entry, _)| *entry == name)
                .map(|(_, value)| (*value).to_owned()))
        })
        .unwrap();
        HostNetwork::new(
            ProviderLimits::default(),
            crate::tests::test_outbound_tls(),
            Arc::new(environment),
            global,
        )
    }

    fn export(
        environment: &[(&str, &str)],
        global: Option<EgressProxyConfig>,
        outbound_tls: &OutboundTlsConfig,
    ) -> InheritedNetwork {
        host_network(environment, global)
            .export_inherited_network(outbound_tls)
            .unwrap()
    }

    fn global(url: &str) -> Option<EgressProxyConfig> {
        Some(EgressProxyConfig {
            url: url.into(),
            username_ref: None,
            password_ref: None,
        })
    }

    fn wire(network: &InheritedNetwork) -> serde_json::Value {
        serde_json::to_value(network.wire()).unwrap()
    }

    fn variables(entries: &[(&'static str, &str)]) -> Vec<(&'static str, OsString)> {
        entries
            .iter()
            .map(|(name, value)| (*name, OsString::from(*value)))
            .collect()
    }

    #[test]
    fn inherits_the_environment_proxy_with_its_credentials() {
        let network = export(
            &[
                (
                    "HTTPS_PROXY",
                    "https://proxy%20user:p%40ss%3Aw%2Frd@proxy.example:8443",
                ),
                ("HTTP_PROXY", "http://http-only.example:3128"),
                ("NO_PROXY", ".internal.example, localhost"),
            ],
            global("http://global-proxy.example:3128"),
            &custom(),
        );
        assert_eq!(
            wire(&network),
            json!({
                "proxy": {
                    "url": "https://proxy.example:8443",
                    "username": "proxy user",
                    "password": "p@ss:w/rd",
                },
                "noProxy": [".internal.example", "localhost"],
                "trust": "custom",
                "caCertificate": CA_PATH,
            })
        );
        let proxied = "https://proxy%20user:p%40ss%3Aw%2Frd@proxy.example:8443";
        assert_eq!(
            network.environment(),
            variables(&[
                ("HTTPS_PROXY", proxied),
                ("HTTP_PROXY", proxied),
                ("https_proxy", proxied),
                ("http_proxy", proxied),
                ("NO_PROXY", ".internal.example,localhost"),
                ("no_proxy", ".internal.example,localhost"),
                ("SSL_CERT_FILE", CA_PATH),
                ("REQUESTS_CA_BUNDLE", CA_PATH),
                ("NODE_EXTRA_CA_CERTS", CA_PATH),
            ])
        );
        assert_eq!(
            network.supplied_secrets().collect::<Vec<_>>(),
            ["p@ss:w/rd"]
        );
        let debug = format!("{network:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("https://proxy.example:8443"), "{debug}");
        assert!(debug.contains(CA_PATH), "{debug}");
        assert!(
            !debug.contains("p@ss") && !debug.contains("proxy user"),
            "{debug}"
        );
        assert!(!debug.contains("%40") && !debug.contains("%20"), "{debug}");
    }

    #[test]
    fn a_global_proxy_without_credentials_carries_only_its_url() {
        let network = export(
            &[("http_proxy", "http://http-only.example:3128")],
            global("http://global-proxy.example:3128"),
            &trusting(OutboundTlsTrustMode::SystemPlusCustom, Some(CA_PATH)),
        );
        assert_eq!(
            wire(&network),
            json!({
                "proxy": {"url": "http://global-proxy.example:3128"},
                "noProxy": [],
                "trust": "system_plus_custom",
                "caCertificate": CA_PATH,
            })
        );
        let proxied = "http://global-proxy.example:3128";
        assert_eq!(
            network.environment(),
            variables(&[
                ("HTTPS_PROXY", proxied),
                ("HTTP_PROXY", proxied),
                ("https_proxy", proxied),
                ("http_proxy", proxied),
                ("NODE_EXTRA_CA_CERTS", CA_PATH),
            ])
        );
        assert_eq!(network.supplied_secrets().count(), 0);
        assert!(!format!("{network:?}").contains("<redacted>"));
    }

    #[test]
    fn system_trust_without_a_proxy_passes_no_path_or_variables() {
        let network = export(&[], None, &system());
        assert_eq!(
            wire(&network),
            json!({"proxy": null, "noProxy": [], "trust": "system", "caCertificate": null})
        );
        assert!(network.environment().is_empty());
        assert_eq!(network.supplied_secrets().count(), 0);
        // `NO_PROXY` entries pass through even without a proxy.
        let network = export(&[("no_proxy", "*")], None, &system());
        assert_eq!(
            wire(&network),
            json!({"proxy": null, "noProxy": ["*"], "trust": "system", "caCertificate": null})
        );
        assert_eq!(
            network.environment(),
            variables(&[("NO_PROXY", "*"), ("no_proxy", "*")])
        );
    }

    #[test]
    fn each_trust_mode_sets_its_variables_to_the_configured_path() {
        for (trust, name, expected) in [
            (OutboundTlsTrustMode::System, "system", &[][..]),
            (
                OutboundTlsTrustMode::Custom,
                "custom",
                &["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"][..],
            ),
            (
                OutboundTlsTrustMode::SystemPlusCustom,
                "system_plus_custom",
                &["NODE_EXTRA_CA_CERTS"][..],
            ),
        ] {
            let path = (trust != OutboundTlsTrustMode::System).then_some(CA_PATH);
            // With and without a proxy, the trust fields are the same.
            for proxy in [None, global("http://global-proxy.example:3128")] {
                let proxied = proxy.is_some();
                let network = export(&[], proxy, &trusting(trust, path));
                let request = wire(&network);
                assert_eq!(request["trust"], name, "{trust:?}");
                assert_eq!(request["caCertificate"], json!(path), "{trust:?}");
                assert_eq!(request["proxy"].is_null(), !proxied, "{trust:?}");
                let environment = network.environment();
                let trust_set = environment
                    .iter()
                    .filter(|(variable, _)| TRUST_VARIABLES.contains(variable))
                    .collect::<Vec<_>>();
                assert_eq!(
                    trust_set
                        .iter()
                        .map(|(variable, _)| *variable)
                        .collect::<Vec<_>>(),
                    expected,
                    "{trust:?}"
                );
                assert!(
                    trust_set.iter().all(|(_, value)| value == CA_PATH),
                    "{trust:?}"
                );
                assert_eq!(
                    environment.len(),
                    expected.len() + if proxied { PROXY_VARIABLES.len() } else { 0 },
                    "{trust:?}"
                );
            }
            // The wire name is the configuration's spelling.
            assert_eq!(
                serde_json::from_value::<OutboundTlsTrustMode>(json!(name)).unwrap(),
                trust
            );
        }
        // Every reserved trust variable is set by some mode.
        let set = [
            OutboundTlsTrustMode::System,
            OutboundTlsTrustMode::Custom,
            OutboundTlsTrustMode::SystemPlusCustom,
        ]
        .into_iter()
        .flat_map(trust_variables)
        .copied()
        .collect::<BTreeSet<_>>();
        assert_eq!(set, BTreeSet::from(TRUST_VARIABLES));
    }

    #[test]
    fn every_variable_the_environment_can_hold_is_reserved() {
        for name in PROXY_VARIABLES
            .iter()
            .chain(&NO_PROXY_VARIABLES)
            .chain(&TRUST_VARIABLES)
        {
            assert!(is_inherited_network_variable(name), "{name}");
        }
        for name in ["PATH", "LANG", "HOME", "ALL_PROXY", "https_proxy_extra"] {
            assert!(!is_inherited_network_variable(name), "{name}");
        }
        let network = export(
            &[
                ("HTTPS_PROXY", "https://user:secret@proxy.example:8443"),
                ("NO_PROXY", ".internal.example"),
            ],
            None,
            &custom(),
        );
        let set = network.environment();
        assert_eq!(set.len(), 9);
        assert!(set.iter().all(|(name, _)| is_inherited_network_variable(name)));
    }

    #[test]
    fn an_empty_proxy_password_is_sent_but_is_not_a_supplied_secret() {
        let network = export(
            &[("HTTPS_PROXY", "https://user@proxy.example:8443")],
            None,
            &system(),
        );
        assert_eq!(
            wire(&network)["proxy"],
            json!({"url": "https://proxy.example:8443", "username": "user", "password": ""})
        );
        assert_eq!(network.supplied_secrets().count(), 0);
        assert_eq!(
            network.environment()[0],
            (
                "HTTPS_PROXY",
                OsString::from("https://user:@proxy.example:8443")
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_reaches_the_environment_but_not_the_request() {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::OsStr::from_bytes(b"/etc/agent-access/ca-\xff.pem");
        let network = export(
            &[],
            None,
            &OutboundTlsConfig {
                trust: OutboundTlsTrustMode::SystemPlusCustom,
                ca_certificate: Some(PathBuf::from(path)),
            },
        );
        assert_eq!(
            network.environment(),
            [("NODE_EXTRA_CA_CERTS", path.to_owned())]
        );
        assert!(serde_json::to_value(network.wire()).is_err());
    }

    #[test]
    fn an_unresolvable_proxy_credential_fails_the_export() {
        let network = host_network(
            &[],
            Some(EgressProxyConfig {
                url: "https://global-proxy.example:8443".into(),
                username_ref: Some("env:AGENT_ACCESS_COMMAND_NETWORK_TEST_MISSING_USER".into()),
                password_ref: Some("env:AGENT_ACCESS_COMMAND_NETWORK_TEST_MISSING_PASSWORD".into()),
            }),
        );
        let error = network.export_inherited_network(&custom()).unwrap_err();
        assert!(matches!(
            error,
            HostConfigError::MissingEnv { label, .. }
                if label == "network.egress_proxy.username_ref"
        ));
    }
}
