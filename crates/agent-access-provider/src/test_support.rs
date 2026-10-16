//! Helpers for backend and host tests. Fixtures are embedded from
//! `test_support/fixtures/`; nothing is read from the filesystem.
use crate::host::{
    ClientTransportSpec, ScopeRequestParts, TransportClient, UpstreamClientFactory,
    UpstreamClientFactoryError, scope_request,
};
use crate::{
    BuildContext, ClientProfile, CorrelationContext, DelegatedBindingId, DelegatedCredential,
    EgressDeclaration, EgressProxySource, EgressRoute, ExecutionCredential, InvocationIdentity,
    LookupAccess, Provider, ProviderAttributionConfig, ProviderLimits, ScopeRequest,
    ServiceDescriptor, ServiceProvider, SigningError, StableSigningKey, is_literal_loopback,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::Value;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use url::Url;

mod invocation;
mod trace_capture;

pub use invocation::InvocationBuilder;
pub use trace_capture::{TraceCapture, TraceCaptureDispatcher, install_trace_capture};

/// A test provider that states its own descriptor, so tests can inject it
/// without a backend configuration.
pub trait DescribedProvider: Provider + 'static {
    fn descriptor(&self) -> ServiceDescriptor;
}

impl<P: DescribedProvider> From<Arc<P>> for ServiceProvider {
    fn from(provider: Arc<P>) -> Self {
        Self {
            descriptor: provider.descriptor(),
            provider,
        }
    }
}

/// A self-signed CA certificate for PEM parsing tests.
pub const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw\nHTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\nDzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+\n5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP\nBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP\nBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop\nPAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik\ncy4eNw==\n-----END CERTIFICATE-----\n";

/// The host side of provider construction for tests: limits, attribution, an
/// optional stable signing key, and a deterministic, offline
/// [`UpstreamClientFactory`] with no host dependency.
///
/// Its clients trust only this package's embedded test CA
/// (`test_support/fixtures/outbound-tls-ca.pem`), apply the requested profile
/// against [`Self::limits`] at construction time, and never follow redirects.
/// Routing is fixed and environment-independent: an ordinary client with a
/// configured service proxy uses that proxy (credential references are
/// rejected, because nothing here resolves secrets); every other ordinary
/// client connects directly; a literal-loopback request is granted for a
/// literal loopback IP base and rejected otherwise. Every client built is
/// recorded in [`Self::built_clients`].
pub struct TestHost {
    pub limits: ProviderLimits,
    pub attribution: ProviderAttributionConfig,
    pub stable_signing_key: Option<Arc<dyn StableSigningKey>>,
    built: Mutex<Vec<BuiltClient>>,
}

/// One client a [`TestHost`] built.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltClient {
    pub label: String,
    pub provider: &'static str,
    pub base: Url,
    pub profile: ClientProfile,
    /// Whether the client asked for the direct literal-loopback route.
    pub literal_loopback: bool,
    pub route: EgressRoute,
}

impl Default for TestHost {
    fn default() -> Self {
        Self::with_limits(ProviderLimits::default())
    }
}

impl TestHost {
    pub fn with_limits(limits: ProviderLimits) -> Self {
        Self {
            limits,
            attribution: ProviderAttributionConfig::default(),
            stable_signing_key: None,
            built: Mutex::new(Vec::new()),
        }
    }

    /// The build context a backend receives, lending this host's settings
    /// and client factory.
    pub fn context(&self) -> BuildContext<'_> {
        crate::host::build_context(
            &self.limits,
            self,
            self.attribution.clone(),
            self.stable_signing_key.clone(),
        )
    }

    /// The clients built so far, in construction order.
    pub fn built_clients(&self) -> Vec<BuiltClient> {
        self.built
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl std::fmt::Debug for TestHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestHost")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl UpstreamClientFactory for TestHost {
    fn build_client(
        &self,
        spec: &ClientTransportSpec<'_>,
    ) -> Result<TransportClient, UpstreamClientFactoryError> {
        let label = spec.label();
        let (route, proxy) = match spec.egress() {
            EgressDeclaration::Ordinary(None) => (EgressRoute::direct(), None),
            EgressDeclaration::Ordinary(Some(config)) => {
                if config.username_ref.is_some() || config.password_ref.is_some() {
                    return Err(UpstreamClientFactoryError::new(format!(
                        "{label}: the test host does not resolve proxy credentials"
                    )));
                }
                let url = Url::parse(&config.url).map_err(|_| {
                    UpstreamClientFactoryError::new(format!("{label}.url must be a valid URL"))
                })?;
                let proxy = reqwest::Proxy::all(url.as_str()).map_err(|_| {
                    UpstreamClientFactoryError::new(format!("{label}.url could not be applied"))
                })?;
                (
                    EgressRoute::proxied(EgressProxySource::Service, &url),
                    Some(proxy),
                )
            }
            EgressDeclaration::LiteralLoopback if is_literal_loopback(spec.base()) => {
                (EgressRoute::direct(), None)
            }
            EgressDeclaration::LiteralLoopback => {
                return Err(UpstreamClientFactoryError::new(format!(
                    "{label}: the direct loopback route needs a literal loopback IP address"
                )));
            }
        };
        let builder = crate::host::configure_client_profile(
            reqwest::Client::builder()
                .use_preconfigured_tls(rustls::ClientConfig::clone(test_tls()))
                .no_proxy(),
            spec.profile(),
            &self.limits,
        );
        let builder = match proxy {
            Some(proxy) => builder.proxy(proxy),
            None => builder,
        };
        let client = builder.build().map_err(|error| {
            UpstreamClientFactoryError::new(format!("{label} HTTP client: {error}"))
        })?;
        self.built
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(BuiltClient {
                label: label.to_owned(),
                provider: spec.provider(),
                base: spec.base().clone(),
                profile: spec.profile(),
                literal_loopback: matches!(spec.egress(), EgressDeclaration::LiteralLoopback),
                route: route.clone(),
            });
        Ok(TransportClient::new(client, route))
    }
}

/// TLS that trusts only the embedded test CA, with HTTP/1.1 ALPN like the
/// host's prepared trust.
fn test_tls() -> &'static Arc<rustls::ClientConfig> {
    static TLS: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    TLS.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(include_bytes!(
            "test_support/fixtures/outbound-tls-ca.pem"
        )) {
            roots
                .add(certificate.expect("test CA is valid PEM"))
                .expect("test CA is a valid trust anchor");
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("default TLS versions are supported")
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(tls)
    })
}

/// A `basic_api_token` credential for tests. Credentials compare with `==`,
/// so a test double records the credential it received and compares it with
/// the one the test expects, without reading its material.
pub fn basic_credential(username: &str, token: &str) -> ExecutionCredential {
    ExecutionCredential::basic(username.to_owned(), token.to_owned())
}

/// A `bearer_token` credential for tests.
pub fn bearer_credential(token: &str) -> ExecutionCredential {
    ExecutionCredential::bearer(token.to_owned())
}

/// Runs `future` as the invocation hook of `service`'s `action`, as the host
/// runs a provider's invoke, so upstream traces it starts are checked against
/// that hook. The backend's registered domain reasons are not included.
pub async fn in_invocation_hook<F: std::future::Future>(
    service: &str,
    action: &str,
    future: F,
) -> F::Output {
    crate::host::with_hook_context(
        crate::host::hook_context(service, action, crate::HookPhase::Invocation, &[]),
        future,
    )
    .await
}

/// A delegated binding identity derived from `seed`, for lease doubles.
pub fn delegated_binding_id(seed: &str) -> DelegatedBindingId {
    use sha2::{Digest, Sha256};
    crate::host::delegated_binding_id(Sha256::digest(seed.as_bytes()).into())
}

/// A stable signing key of `byte` repeated, for handles and cursors that
/// tests sign and verify.
pub fn test_signing_key(byte: u8) -> Arc<dyn StableSigningKey> {
    struct FixedKey([u8; 32]);

    impl StableSigningKey for FixedKey {
        fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
            Ok(URL_SAFE_NO_PAD.encode(crate::signing::local_hmac(&self.0, context, payload)))
        }
    }

    Arc::new(FixedKey([byte; 32]))
}

/// Owned inputs for a [`ScopeRequest`] in provider tests: an anonymous
/// caller in the `internal` execution context, with no lookup access unless
/// some is supplied.
#[derive(Debug, Clone)]
pub struct ScopeRequestFixture {
    service: String,
    action: String,
    inputs: Value,
    execution_context: String,
    identity: InvocationIdentity,
    correlation: CorrelationContext,
    lookup_access: Option<LookupAccess>,
}

impl ScopeRequestFixture {
    pub fn new(service: &str, action: &str, inputs: Value) -> Self {
        Self {
            service: service.to_owned(),
            action: action.to_owned(),
            inputs,
            execution_context: "internal".to_owned(),
            identity: InvocationIdentity::anonymous(),
            correlation: CorrelationContext::for_tests(),
            lookup_access: None,
        }
    }

    /// Static lookup access, replacing any other lookup access.
    pub fn lookup_credential(self, credential: ExecutionCredential) -> Self {
        self.lookup_access(Some(LookupAccess::Static(credential)))
    }

    /// Delegated lookup access, replacing any other lookup access.
    pub fn delegated_lookup(self, credential: DelegatedCredential) -> Self {
        self.lookup_access(Some(LookupAccess::Delegated(credential)))
    }

    pub fn lookup_access(mut self, lookup_access: Option<LookupAccess>) -> Self {
        self.lookup_access = lookup_access;
        self
    }

    pub fn execution_context(mut self, execution_context: &str) -> Self {
        self.execution_context = execution_context.to_owned();
        self
    }

    pub fn identity(mut self, identity: InvocationIdentity) -> Self {
        self.identity = identity;
        self
    }

    pub fn request(&self) -> ScopeRequest<'_> {
        scope_request(ScopeRequestParts {
            service: &self.service,
            action: &self.action,
            inputs: &self.inputs,
            execution_context: &self.execution_context,
            identity: &self.identity,
            correlation: &self.correlation,
            lookup_access: self.lookup_access.as_ref(),
        })
    }
}
