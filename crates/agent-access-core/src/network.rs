//! Host network construction for one runtime generation: outbound TLS trust,
//! egress proxy selection and the upstream client factories that providers,
//! import adapters and the OAuth manager build their clients through.
//!
//! Each factory serves one caller category, captured when core constructs it.
//! Only the host's OAuth clients and enabled development-only native
//! registrations may receive the direct literal-loopback route; every other
//! caller, and every other URL, uses ordinary proxy selection.
mod egress_proxy;
mod outbound_tls;

pub use egress_proxy::EgressProxyEnvironment;
pub(crate) use egress_proxy::preflight_egress_proxy;
pub use outbound_tls::{
    OutboundTlsConfig, OutboundTlsTrustMode, PreparedOutboundTls,
    parse_strict_certificate_pem_bundle,
};

use crate::{DeploymentConfig, HostConfigError};
use agent_access_provider::host::{
    ClientTransportSpec, TransportClient, UpstreamClientFactory, UpstreamClientFactoryError,
    configure_client_profile,
};
use agent_access_provider::{
    BackendRegistration, ClientProfile, EgressDeclaration, EgressProxyConfig, EgressRoute,
    ProviderLimits, is_literal_loopback,
};
use egress_proxy::{EgressProxyResolver, EgressProxySelection};
use std::sync::Arc;
use url::Url;

/// Who asks the host for upstream clients. Core captures it when it
/// constructs a factory; neither a client's label nor its provider identity
/// can change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientCaller {
    /// The host's OAuth manager, for every registration's approved origins.
    HostOAuth,
    /// One native backend registration. `development` holds only for a
    /// development-only registration the deployment enables.
    Native {
        kind: &'static str,
        development: bool,
    },
    /// A shipped import adapter: always the ordinary routing category.
    ImportAdapter { kind: &'static str },
}

impl ClientCaller {
    pub(crate) fn native(
        registration: &BackendRegistration,
        deployment: &DeploymentConfig,
    ) -> Self {
        Self::Native {
            kind: registration.kind(),
            development: registration.is_development_only()
                && development_fixtures_enabled(deployment),
        }
    }

    fn grants_literal_loopback(&self) -> bool {
        matches!(
            self,
            Self::HostOAuth
                | Self::Native {
                    development: true,
                    ..
                }
        )
    }
}

/// Whether the deployment admits development fixtures.
pub(crate) fn development_fixtures_enabled(deployment: &DeploymentConfig) -> bool {
    deployment.environment != "production" && deployment.enable_fake_service
}

/// One runtime generation's outbound network: provider limits, the prepared
/// outbound TLS trust and egress proxy selection over the proxy environment
/// captured at startup.
#[derive(Clone)]
pub(crate) struct HostNetwork {
    limits: ProviderLimits,
    outbound_tls: PreparedOutboundTls,
    egress: EgressProxyResolver,
}

impl HostNetwork {
    pub(crate) fn new(
        limits: ProviderLimits,
        outbound_tls: PreparedOutboundTls,
        environment: Arc<EgressProxyEnvironment>,
        global_proxy: Option<EgressProxyConfig>,
    ) -> Self {
        Self {
            limits,
            outbound_tls,
            egress: EgressProxyResolver::new(environment, global_proxy),
        }
    }

    pub(crate) fn limits(&self) -> &ProviderLimits {
        &self.limits
    }

    pub(crate) fn outbound_tls(&self) -> &PreparedOutboundTls {
        &self.outbound_tls
    }

    /// The proxy environment captured at startup; reloads keep it.
    pub(crate) fn environment(&self) -> &Arc<EgressProxyEnvironment> {
        self.egress.environment()
    }

    /// The client factory serving `caller`.
    pub(crate) fn client_factory(&self, caller: ClientCaller) -> HostClientFactory {
        HostClientFactory {
            network: self.clone(),
            caller,
        }
    }

    fn build_client(
        &self,
        caller: &ClientCaller,
        spec: &ClientTransportSpec<'_>,
    ) -> Result<TransportClient, HostConfigError> {
        let label = spec.label();
        let selection = match spec.egress() {
            EgressDeclaration::Ordinary(service_proxy) => {
                self.egress.resolve(label, spec.base(), service_proxy)?
            }
            EgressDeclaration::LiteralLoopback => {
                if !is_literal_loopback(spec.base()) {
                    return Err(HostConfigError::invalid(format!(
                        "{label} requests the direct loopback route for an address that is not a literal loopback IP"
                    )));
                }
                if !caller.grants_literal_loopback() {
                    return Err(HostConfigError::invalid(format!(
                        "{label} requests the direct loopback route, which only OAuth and enabled development fixtures receive"
                    )));
                }
                EgressProxySelection::direct()
            }
        };
        let client = self
            .client(&selection, spec.profile())?
            .build()
            .map_err(|error| HostConfigError::invalid(format!("{label} HTTP client: {error}")))?;
        Ok(TransportClient::new(client, selection.route()))
    }

    /// A Git gateway's client: the gateway's ordinary route, a connect
    /// timeout only, and no automatic redirects.
    pub(crate) fn gateway_client(
        &self,
        label: &str,
        upstream_base: &Url,
        gateway_proxy: Option<&EgressProxyConfig>,
    ) -> Result<(reqwest::Client, EgressRoute), HostConfigError> {
        let selection = self.egress.resolve(label, upstream_base, gateway_proxy)?;
        let client = self
            .client(&selection, ClientProfile::Upload)?
            .build()
            .map_err(|error| HostConfigError::invalid(format!("gateway HTTP client: {error}")))?;
        Ok((client, selection.route()))
    }

    fn client(
        &self,
        selection: &EgressProxySelection,
        profile: ClientProfile,
    ) -> Result<reqwest::ClientBuilder, HostConfigError> {
        selection.apply(configure_client_profile(
            self.outbound_tls.apply(reqwest::Client::builder()),
            profile,
            &self.limits,
        ))
    }
}

/// The host's [`UpstreamClientFactory`] for one caller and generation.
pub(crate) struct HostClientFactory {
    network: HostNetwork,
    caller: ClientCaller,
}

impl UpstreamClientFactory for HostClientFactory {
    fn build_client(
        &self,
        spec: &ClientTransportSpec<'_>,
    ) -> Result<TransportClient, UpstreamClientFactoryError> {
        self.network
            .build_client(&self.caller, spec)
            .map_err(UpstreamClientFactoryError::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{
        EgressDeclaration, OAuthDialectError, OAuthHttp, ProviderBuildError, UpstreamClient,
        UpstreamClientSpec,
    };
    use reqwest::Method;
    use std::sync::Mutex;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    const PRODUCTION: ClientCaller = ClientCaller::Native {
        kind: "jira",
        development: false,
    };
    const DEVELOPMENT: ClientCaller = ClientCaller::Native {
        kind: "oauth_stub",
        development: true,
    };
    const IMPORT: ClientCaller = ClientCaller::ImportAdapter { kind: "mcp_http" };

    fn network(
        environment: &[(&str, String)],
        global_proxy: Option<EgressProxyConfig>,
    ) -> HostNetwork {
        let environment = EgressProxyEnvironment::from_lookup(|name| {
            Ok(environment
                .iter()
                .find(|(entry, _)| *entry == name)
                .map(|(_, value)| value.clone()))
        })
        .unwrap();
        HostNetwork::new(
            ProviderLimits::default(),
            crate::tests::test_outbound_tls(),
            Arc::new(environment),
            global_proxy,
        )
    }

    fn proxied_environment(proxy: &str) -> HostNetwork {
        network(
            &[
                ("HTTPS_PROXY", proxy.to_owned()),
                ("HTTP_PROXY", proxy.to_owned()),
            ],
            None,
        )
    }

    fn proxy(url: &str) -> EgressProxyConfig {
        EgressProxyConfig {
            url: url.into(),
            username_ref: None,
            password_ref: None,
        }
    }

    fn build(
        network: &HostNetwork,
        caller: ClientCaller,
        label: &str,
        provider: &'static str,
        base: &str,
        egress: EgressDeclaration<'_>,
    ) -> Result<UpstreamClient, ProviderBuildError> {
        let base = Url::parse(base).unwrap();
        UpstreamClient::build(
            UpstreamClientSpec::new(
                label,
                provider,
                &base,
                egress,
                &[format!("{base}**")],
                ClientProfile::Request,
            ),
            &network.client_factory(caller),
        )
    }

    fn route(result: Result<UpstreamClient, ProviderBuildError>) -> serde_json::Value {
        result.unwrap().egress_route().audit_value()
    }

    fn denied(result: Result<UpstreamClient, ProviderBuildError>) -> String {
        let (diagnostics, cause) = result.unwrap_err().into_parts();
        assert!(diagnostics[0].ends_with("HTTP client could not be constructed"));
        match *cause
            .expect("a host cause")
            .downcast::<HostConfigError>()
            .unwrap()
        {
            HostConfigError::Config(crate::ConfigError::Invalid { errors }) => errors.join("; "),
            other => panic!("unexpected host cause: {other:?}"),
        }
    }

    #[test]
    fn only_host_oauth_and_enabled_development_registrations_get_the_loopback_route() {
        let network = proxied_environment("http://proxy.example:3128");
        let environment =
            serde_json::json!({"mode":"environment","proxy":"http://proxy.example:3128"});
        for base in [
            "http://127.0.0.1:8787/",
            "http://[::1]:8787/",
            "https://127.0.0.2:9443/",
        ] {
            for caller in [ClientCaller::HostOAuth, DEVELOPMENT] {
                let granted = build(
                    &network,
                    caller.clone(),
                    "fixture",
                    "fixture",
                    base,
                    EgressDeclaration::LiteralLoopback,
                );
                assert_eq!(
                    route(granted),
                    serde_json::json!({"mode":"direct"}),
                    "{caller:?} {base}"
                );
            }
            let disabled = ClientCaller::Native {
                kind: "oauth_stub",
                development: false,
            };
            for caller in [PRODUCTION, disabled, IMPORT] {
                let refused = build(
                    &network,
                    caller.clone(),
                    "fixture",
                    "fixture",
                    base,
                    EgressDeclaration::LiteralLoopback,
                );
                assert!(
                    denied(refused).contains("only OAuth and enabled development fixtures"),
                    "{caller:?} {base}"
                );
                // Production natives and import adapters route loopback
                // ordinarily, through the environment proxy.
                let ordinary = build(
                    &network,
                    caller.clone(),
                    "fixture",
                    "fixture",
                    base,
                    EgressDeclaration::Ordinary(None),
                );
                assert_eq!(route(ordinary), environment, "{caller:?} {base}");
            }
        }
        // Host names, including localhost, and non-loopback addresses never
        // receive the exception, whoever asks.
        for base in [
            "http://localhost:8787/",
            "https://localhost/",
            "https://service.example/",
            "http://[::ffff:127.0.0.1]:8787/",
            "http://10.0.0.1/",
        ] {
            for caller in [ClientCaller::HostOAuth, DEVELOPMENT, PRODUCTION, IMPORT] {
                let refused = build(
                    &network,
                    caller.clone(),
                    "fixture",
                    "fixture",
                    base,
                    EgressDeclaration::LiteralLoopback,
                );
                assert!(
                    denied(refused).contains("not a literal loopback IP"),
                    "{caller:?} {base}"
                );
            }
        }
    }

    #[test]
    fn caller_category_ignores_labels_and_provider_identity() {
        let network = proxied_environment("http://proxy.example:3128");
        for label in [
            "oauth.registrations.stub",
            "providers.oauth_stub",
            "credentials.per_user.oauth_stub",
            "imports.mcp_http",
        ] {
            for provider in ["oauth", "oauth_stub", "mcp_http", "jira"] {
                let base = "http://127.0.0.1:8787/";
                let loopback = EgressDeclaration::LiteralLoopback;
                assert_eq!(
                    route(build(
                        &network,
                        ClientCaller::HostOAuth,
                        label,
                        provider,
                        base,
                        loopback
                    )),
                    serde_json::json!({"mode":"direct"}),
                    "{label} {provider}"
                );
                for caller in [PRODUCTION, IMPORT] {
                    denied(build(&network, caller, label, provider, base, loopback));
                }
            }
        }
    }

    #[test]
    fn the_deployment_decides_the_development_category() {
        let registration = |development_only| {
            let registration = BackendRegistration::new(
                agent_access_provider::module_metadata!(),
                "fixture",
                agent_access_provider::parse_backend_config::<agent_access_fake::FakeProviderConfig>,
            );
            if development_only {
                registration.development_only()
            } else {
                registration
            }
        };
        let deployment = |environment: &str, enable_fake_service| DeploymentConfig {
            environment: environment.into(),
            enable_fake_service,
            ..DeploymentConfig::default()
        };
        let development =
            |caller| matches!(caller, ClientCaller::Native { development, .. } if development);
        assert!(development(ClientCaller::native(
            &registration(true),
            &deployment("development", true)
        )));
        for (environment, enabled, development_only) in [
            ("development", false, true),
            ("production", true, true),
            ("development", true, false),
        ] {
            assert!(
                !development(ClientCaller::native(
                    &registration(development_only),
                    &deployment(environment, enabled)
                )),
                "{environment} {enabled} {development_only}"
            );
        }
    }

    #[test]
    fn ordinary_routes_follow_no_proxy_environment_service_global_precedence() {
        let service = proxy("http://service-proxy.example:3128");
        let global = Some(proxy("http://global-proxy.example:3128"));
        let ordinary = |network: &HostNetwork, base: &str, service: Option<&EgressProxyConfig>| {
            route(build(
                network,
                PRODUCTION,
                "providers.jira.egress_proxy",
                "jira",
                base,
                EgressDeclaration::Ordinary(service),
            ))
        };
        let environment = network(
            &[
                (
                    "HTTPS_PROXY",
                    "http://environment-proxy.example:3128".into(),
                ),
                ("NO_PROXY", "direct.example".into()),
            ],
            global.clone(),
        );
        assert_eq!(
            ordinary(&environment, "https://direct.example/", Some(&service)),
            serde_json::json!({"mode":"direct"})
        );
        assert_eq!(
            ordinary(&environment, "https://jira.example/", Some(&service)),
            serde_json::json!({"mode":"environment","proxy":"http://environment-proxy.example:3128"})
        );
        // No environment proxy for plain HTTP: the service proxy wins.
        assert_eq!(
            ordinary(&environment, "http://jira.example/", Some(&service)),
            serde_json::json!({"mode":"service","proxy":"http://service-proxy.example:3128"})
        );
        assert_eq!(
            ordinary(&environment, "http://jira.example/", None),
            serde_json::json!({"mode":"global","proxy":"http://global-proxy.example:3128"})
        );
        let empty = network(&[], None);
        assert_eq!(
            ordinary(&empty, "https://jira.example/", None),
            serde_json::json!({"mode":"direct"})
        );
        // Import adapters share the ordinary selection.
        assert_eq!(
            route(build(
                &environment,
                IMPORT,
                "imports.mcp_http",
                "mcp_http",
                "http://127.0.0.1:9/mcp",
                EgressDeclaration::Ordinary(None),
            )),
            serde_json::json!({"mode":"global","proxy":"http://global-proxy.example:3128"})
        );
    }

    #[test]
    fn unresolvable_proxy_secrets_keep_their_host_diagnostics() {
        let network = network(&[], None);
        let service = EgressProxyConfig {
            url: "https://proxy.example:8443".into(),
            username_ref: Some("env:AGENT_ACCESS_NETWORK_TEST_MISSING_USER".into()),
            password_ref: Some("env:AGENT_ACCESS_NETWORK_TEST_MISSING_PASSWORD".into()),
        };
        let error = build(
            &network,
            PRODUCTION,
            "providers.jira.egress_proxy",
            "jira",
            "https://jira.example/",
            EgressDeclaration::Ordinary(Some(&service)),
        )
        .unwrap_err();
        assert!(matches!(
            crate::RuntimeError::from(error),
            crate::RuntimeError::MissingEnv { label, name }
                if label == "providers.jira.egress_proxy.username_ref"
                    && name == "AGENT_ACCESS_NETWORK_TEST_MISSING_USER"
        ));
    }

    /// Records the route the host selected for each client's origin.
    struct RecordingFactory<'a> {
        inner: &'a dyn UpstreamClientFactory,
        routes: Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl UpstreamClientFactory for RecordingFactory<'_> {
        fn build_client(
            &self,
            spec: &ClientTransportSpec<'_>,
        ) -> Result<TransportClient, UpstreamClientFactoryError> {
            let (client, route) = self.inner.build_client(spec)?.into_parts();
            self.routes.lock().unwrap().push((
                spec.base().origin().ascii_serialization(),
                route.audit_value(),
            ));
            Ok(TransportClient::new(client, route))
        }
    }

    #[tokio::test]
    async fn oauth_routes_each_destination_origin_independently() {
        let proxy = MockServer::start().await;
        let loopback = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok":true})))
            .expect(2)
            .mount(&loopback)
            .await;
        let network = network(
            &[
                ("HTTP_PROXY", proxy.uri()),
                ("HTTPS_PROXY", proxy.uri()),
                ("NO_PROXY", "issuer.internal".into()),
            ],
            None,
        );
        let oauth = network.client_factory(ClientCaller::HostOAuth);
        let token = format!("{}/token", loopback.uri());
        let urls = [
            "https://issuer.internal/metadata".to_owned(),
            "https://resource.external/metadata".to_owned(),
            "https://localhost:9/token".to_owned(),
            "https://127.0.0.2:9443/token".to_owned(),
            "http://[::1]:8787/token".to_owned(),
            token.clone(),
        ];
        let build = |base: &str| {
            let recording = RecordingFactory {
                inner: &oauth,
                routes: Mutex::new(Vec::new()),
            };
            let http = OAuthHttp::build(
                "oauth.registrations.test",
                "oauth",
                &Url::parse(base).unwrap(),
                &urls,
                &recording,
            )
            .unwrap();
            (http, recording.routes.into_inner().unwrap())
        };
        let proxied = serde_json::json!({"mode":"environment","proxy":proxy.uri()});
        let direct = serde_json::json!({"mode":"direct"});
        // Neither a loopback issuer nor a proxied one decides another
        // destination's route.
        for base in [
            "https://issuer.internal/",
            "https://localhost/",
            "http://127.0.0.1:8787/",
            "http://[::1]:8787/",
        ] {
            let (_, routes) = build(base);
            let (issuer, destinations) = routes.split_first().unwrap();
            let expected = if base == "https://localhost/" {
                &proxied
            } else {
                &direct
            };
            assert_eq!(&issuer.1, expected, "{base}");
            for (origin, route) in destinations {
                let expected = if ["https://resource.external", "https://localhost:9"]
                    .contains(&origin.as_str())
                {
                    &proxied
                } else {
                    &direct
                };
                assert_eq!(route, expected, "{base} {origin}");
            }
        }

        // The literal loopback destination is reached directly, although the
        // environment names a proxy for both schemes.
        let (http, _) = build("https://localhost/");
        let response = http
            .send(
                http.request(Method::POST, Url::parse(&token).unwrap())
                    .form(&[("code", "synthetic-code")]),
                "oauth.token",
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let (http, _) = build("http://127.0.0.1:8787/");
        assert_eq!(
            http.send(
                http.request(Method::POST, Url::parse(&token).unwrap()),
                "oauth.token"
            )
            .await
            .unwrap()
            .status(),
            200
        );
        // `https://localhost` is tunneled through the proxy, never resolved
        // and connected to directly.
        assert!(
            http.send(
                http.request(Method::POST, Url::parse(&urls[2]).unwrap()),
                "oauth.token"
            )
            .await
            .is_err()
        );
        let tunneled = proxy.received_requests().await.unwrap();
        assert_eq!(tunneled.len(), 1);
        assert_eq!(tunneled[0].method.as_str(), "CONNECT");
        assert_eq!(tunneled[0].headers["host"], "localhost:9");
        assert!(matches!(
            http.send(
                http.request(
                    Method::GET,
                    Url::parse("https://not-approved.invalid/token").unwrap()
                ),
                "oauth.token"
            )
            .await,
            Err(OAuthDialectError::NotSent)
        ));
        // A factory serving a production native registration cannot build
        // OAuth's loopback clients.
        assert!(
            OAuthHttp::build(
                "oauth.registrations.test",
                "oauth",
                &Url::parse("http://127.0.0.1:8787/").unwrap(),
                &urls,
                &network.client_factory(PRODUCTION),
            )
            .is_err()
        );
    }
}
