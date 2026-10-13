//! Helpers for backend and host tests. Fixtures are embedded from
//! `test_support/fixtures/`; nothing is read from the filesystem.
use crate::{
    OpaqueTokenSigner, PreparedOutboundTls, Provider, ServiceDescriptor, ServiceProvider,
    SigningError, StableSigningKey,
};
use std::sync::Arc;

mod trace_capture;

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

/// Outbound TLS trust that accepts only this package's embedded test CA
/// (`test_support/fixtures/outbound-tls-ca.pem`).
pub fn test_outbound_tls() -> PreparedOutboundTls {
    PreparedOutboundTls::custom_from_pem(
        include_bytes!("test_support/fixtures/outbound-tls-ca.pem").as_slice(),
    )
    .expect("test CA is valid")
}

/// A stable signing key of `byte` repeated, for handles and cursors that
/// tests sign and verify.
pub fn test_signing_key(byte: u8) -> Arc<dyn StableSigningKey> {
    struct FixedKey([u8; 32]);

    impl StableSigningKey for FixedKey {
        fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
            OpaqueTokenSigner::ProcessLocal(Arc::new(self.0)).sign(context, payload)
        }
    }

    Arc::new(FixedKey([byte; 32]))
}
