//! Helpers for backend and host tests. Fixtures are embedded from
//! `test_support/fixtures/`; nothing is read from the filesystem.
use crate::{
    OpaqueTokenSigner, PreparedOutboundTls, Provider, ServiceDescriptor, ServiceProvider,
    SigningError, StableSigningKey,
};
use serde_json::Value;
use std::sync::Arc;

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

std::thread_local! {
    static CAPTURED: std::cell::RefCell<Option<Vec<Value>>> = const { std::cell::RefCell::new(None) };
}

/// Records event fields on threads that are capturing. It is installed
/// once as the global subscriber, so every callsite sees it regardless
/// of which test reached the callsite first.
struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(serde_json::Map<String, Value>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), serde_json::json!(value));
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.0.insert(field.name().into(), serde_json::json!(value));
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().into(), serde_json::json!(format!("{value:?}")));
            }
        }
        CAPTURED.with(|captured| {
            if let Some(events) = captured.borrow_mut().as_mut() {
                let mut fields = Fields(serde_json::Map::new());
                event.record(&mut fields);
                events.push(Value::Object(fields.0));
            }
        });
    }
}

/// Starts recording the fields of tracing events emitted on this thread.
pub fn start_capturing_events() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(CaptureLayer))
            .expect("no other global subscriber in this test binary");
    });
    CAPTURED.with(|captured| *captured.borrow_mut() = Some(Vec::new()));
}

/// The events recorded on this thread since [`start_capturing_events`],
/// which stops recording.
pub fn captured_events() -> Vec<Value> {
    CAPTURED.with(|captured| captured.borrow_mut().take().unwrap_or_default())
}

/// The `upstream_request_completed` trace events among [`captured_events`].
pub fn captured_upstream_requests() -> Vec<Value> {
    captured_events()
        .into_iter()
        .filter(|event| event["event"] == "upstream_request_completed")
        .collect()
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
