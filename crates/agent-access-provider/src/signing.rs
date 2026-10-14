use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// A broker-held HMAC key that survives restarts and reloads. Handles and
/// cursors signed with it stay valid across runtime generations.
pub trait StableSigningKey: Send + Sync {
    /// URL-safe base64 HMAC-SHA256 over `context` then `payload`.
    fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError>;
}

/// The signing key is unavailable. A unit error by design: it carries no
/// detail about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signing key is unavailable")]
pub struct SigningError;

/// HMAC-SHA256 over `context` then `payload` with a key held in this process.
pub(crate) fn local_hmac(key: &[u8; 32], context: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(context);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// A fresh random 32-byte key that never leaves this process.
pub(crate) fn generate_local_key() -> Arc<[u8; 32]> {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    Arc::new(key)
}

/// Scopes a stable key to one service: every signature also covers the
/// service name, so a token one backend issues never verifies for another.
pub fn service_signing_key(
    key: Arc<dyn StableSigningKey>,
    service: &str,
) -> Arc<dyn StableSigningKey> {
    Arc::new(ServiceSigningKey {
        key,
        prefix: [
            b"agent-access/service/".as_slice(),
            service.as_bytes(),
            b"\0",
        ]
        .concat(),
    })
}

struct ServiceSigningKey {
    key: Arc<dyn StableSigningKey>,
    /// Service names never contain NUL, so the separator keeps prefixes of
    /// different services apart.
    prefix: Vec<u8>,
}

impl StableSigningKey for ServiceSigningKey {
    fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
        self.key
            .hmac_base64url(&[self.prefix.as_slice(), context].concat(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_keys_sign_apart() {
        let key = crate::test_support::test_signing_key(7);
        let confluence = service_signing_key(key.clone(), "confluence");
        let gitlab = service_signing_key(key.clone(), "gitlab");
        let signature = confluence.hmac_base64url(b"cursor", b"page=2").unwrap();
        assert_eq!(
            signature,
            confluence.hmac_base64url(b"cursor", b"page=2").unwrap()
        );
        assert_ne!(
            signature,
            gitlab.hmac_base64url(b"cursor", b"page=2").unwrap()
        );
        assert_ne!(signature, key.hmac_base64url(b"cursor", b"page=2").unwrap());
        // The service name and context cannot trade bytes.
        assert_ne!(
            service_signing_key(key.clone(), "conf")
                .hmac_base64url(b"luencecursor", b"page=2")
                .unwrap(),
            signature
        );
    }

    #[test]
    fn local_hmac_is_keyed_and_context_separated() {
        let key = [3_u8; 32];
        assert_eq!(
            local_hmac(&key, b"context", b"payload"),
            local_hmac(&key, b"context", b"payload")
        );
        assert_ne!(
            local_hmac(&key, b"context", b"payload"),
            local_hmac(&[4_u8; 32], b"context", b"payload")
        );
        assert_ne!(*generate_local_key(), *generate_local_key());
    }
}
