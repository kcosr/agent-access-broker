//! The host-implementation interface: construction ports the broker host
//! implements and calls while it builds providers for a runtime generation.
//!
//! Provider code consumes the resulting capabilities ([`BuildContext`] and the
//! [`UpstreamClient`](crate::UpstreamClient)s built through it). Provider tests
//! may implement these ports with deterministic doubles; `test_support::TestHost`
//! is one. Nothing here resolves secret references, loads TLS files, reads the
//! process environment or touches a store: those stay inside the host.
use crate::{
    BuildContext, ClientProfile, EgressDeclaration, EgressRoute, ProviderAttributionConfig,
    ProviderLimits, StableSigningKey,
};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Constructs configured upstream HTTP clients for one runtime generation.
///
/// The host's implementation captures the generation's limits, outbound TLS
/// trust and proxy environment, together with the category of the caller it
/// serves: the host's OAuth manager, or one native registration with its
/// development-only marker. A spec's label or provider identity never changes
/// that category.
///
/// Every returned client applies the requested [`ClientProfile`] (see
/// [`configure_client_profile`]), never follows a redirect on its own, and is
/// routed as its [`EgressDeclaration`] asks. A route the host does not grant to
/// this caller fails construction instead of silently routing elsewhere.
pub trait UpstreamClientFactory: Send + Sync {
    fn build_client(
        &self,
        spec: &ClientTransportSpec<'_>,
    ) -> Result<TransportClient, UpstreamClientFactoryError>;
}

/// What one upstream client needs from the host transport.
#[derive(Debug, Clone, Copy)]
pub struct ClientTransportSpec<'a> {
    label: &'a str,
    provider: &'static str,
    base: &'a Url,
    egress: EgressDeclaration<'a>,
    profile: ClientProfile,
}

impl<'a> ClientTransportSpec<'a> {
    pub(crate) fn new(
        label: &'a str,
        provider: &'static str,
        base: &'a Url,
        egress: EgressDeclaration<'a>,
        profile: ClientProfile,
    ) -> Self {
        Self {
            label,
            provider,
            base,
            egress,
            profile,
        }
    }

    /// The configuration path naming the client in diagnostics, such as
    /// `providers.jira.egress_proxy`. It is safe to show and decides nothing.
    pub fn label(&self) -> &'a str {
        self.label
    }

    /// The `provider` the client's traces record. It decides nothing.
    pub fn provider(&self) -> &'static str {
        self.provider
    }

    /// The service's base URL, whose origin the route is selected for.
    pub fn base(&self) -> &'a Url {
        self.base
    }

    pub fn egress(&self) -> EgressDeclaration<'a> {
        self.egress
    }

    pub fn profile(&self) -> ClientProfile {
        self.profile
    }
}

/// A configured client and the sanitized route its traffic takes.
#[derive(Debug, Clone)]
pub struct TransportClient {
    client: reqwest::Client,
    route: EgressRoute,
}

impl TransportClient {
    pub fn new(client: reqwest::Client, route: EgressRoute) -> Self {
        Self { client, route }
    }

    pub fn into_parts(self) -> (reqwest::Client, EgressRoute) {
        (self.client, self.route)
    }
}

/// Why the host could not construct a client. Providers treat the cause as
/// opaque; the host recovers its own diagnostics from it.
pub struct UpstreamClientFactoryError(Box<dyn Error + Send + Sync>);

impl UpstreamClientFactoryError {
    pub fn new(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }

    pub fn into_cause(self) -> Box<dyn Error + Send + Sync> {
        self.0
    }
}

impl fmt::Debug for UpstreamClientFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UpstreamClientFactoryError")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for UpstreamClientFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for UpstreamClientFactoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

/// The context a backend builds its provider from for one runtime generation.
/// `stable_signing_key` must already be scoped to the backend's service.
pub fn build_context<'a>(
    limits: &'a ProviderLimits,
    clients: &'a dyn UpstreamClientFactory,
    attribution: ProviderAttributionConfig,
    stable_signing_key: Option<Arc<dyn StableSigningKey>>,
) -> BuildContext<'a> {
    BuildContext {
        limits,
        clients,
        attribution,
        stable_signing_key,
    }
}

/// Applies `profile`'s time bounds and retry policy, measured against
/// `limits`, and disables automatic redirects. Every
/// [`UpstreamClientFactory`] applies it to the clients it builds.
pub fn configure_client_profile(
    builder: reqwest::ClientBuilder,
    profile: ClientProfile,
    limits: &ProviderLimits,
) -> reqwest::ClientBuilder {
    let timeout = Duration::from_millis(limits.request_timeout_ms);
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    match profile {
        ClientProfile::Request => builder.timeout(timeout),
        ClientProfile::SingleAttempt => builder.timeout(timeout).retry(reqwest::retry::never()),
        ClientProfile::Stream => builder,
        ClientProfile::Upload => builder.connect_timeout(timeout),
        ClientProfile::Bounded { total, connect } => builder
            .timeout(total)
            .connect_timeout(connect)
            .retry(reqwest::retry::never()),
    }
}
