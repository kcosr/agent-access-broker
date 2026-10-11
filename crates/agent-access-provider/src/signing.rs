use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A broker-held HMAC key that survives restarts and reloads. Handles and
/// cursors signed with it stay valid across runtime generations.
pub trait StableSigningKey: Send + Sync {
    /// URL-safe base64 HMAC-SHA256 over `context` then `payload`.
    fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signing key is unavailable")]
pub struct SigningError;

/// Signs opaque tokens with the broker's stable key when one is configured,
/// and otherwise with a key that lives only as long as this process.
#[derive(Clone)]
pub enum OpaqueTokenSigner {
    Stable(Arc<dyn StableSigningKey>),
    ProcessLocal(Arc<[u8; 32]>),
}

impl OpaqueTokenSigner {
    pub fn new(stable: Option<Arc<dyn StableSigningKey>>) -> Self {
        match stable {
            Some(key) => Self::Stable(key),
            None => {
                let mut key = [0_u8; 32];
                OsRng.fill_bytes(&mut key);
                Self::ProcessLocal(Arc::new(key))
            }
        }
    }

    pub fn sign(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
        match self {
            Self::Stable(key) => key.hmac_base64url(context, payload),
            Self::ProcessLocal(key) => {
                let mut mac =
                    <HmacSha256 as Mac>::new_from_slice(key.as_ref()).map_err(|_| SigningError)?;
                mac.update(context);
                mac.update(payload);
                Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
            }
        }
    }

    pub fn verify(
        &self,
        context: &[u8],
        payload: &[u8],
        signature: &str,
    ) -> Result<bool, SigningError> {
        let expected = self.sign(context, payload)?;
        Ok(bool::from(expected.as_bytes().ct_eq(signature.as_bytes())))
    }

    /// Whether signatures survive restarts and reloads.
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Stable(_))
    }

    /// [`Self::sign`] for tokens that must survive restarts and reloads, such
    /// as draft handles: without a stable key it fails instead of signing with
    /// the process-local one.
    pub fn sign_durable(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
        match self {
            Self::Stable(key) => key.hmac_base64url(context, payload),
            Self::ProcessLocal(_) => Err(SigningError),
        }
    }

    pub fn verify_durable(
        &self,
        context: &[u8],
        payload: &[u8],
        signature: &str,
    ) -> Result<bool, SigningError> {
        let expected = self.sign_durable(context, payload)?;
        Ok(bool::from(expected.as_bytes().ct_eq(signature.as_bytes())))
    }
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
    fn service_keys_sign_apart_and_verify_their_own_tokens() {
        let key = crate::test_support::test_signing_key(7);
        let confluence =
            OpaqueTokenSigner::new(Some(service_signing_key(key.clone(), "confluence")));
        let gitlab = OpaqueTokenSigner::new(Some(service_signing_key(key.clone(), "gitlab")));
        let token = confluence.sign(b"cursor", b"page=2").unwrap();
        assert!(confluence.verify(b"cursor", b"page=2", &token).unwrap());
        assert!(!gitlab.verify(b"cursor", b"page=2", &token).unwrap());
        assert_ne!(
            token,
            OpaqueTokenSigner::new(Some(key))
                .sign(b"cursor", b"page=2")
                .unwrap()
        );
    }

    #[test]
    fn durable_tokens_require_a_stable_key() {
        let local = OpaqueTokenSigner::new(None);
        assert!(!local.is_durable());
        assert_eq!(local.sign_durable(b"draft", b"id"), Err(SigningError));
        assert_eq!(
            local.verify_durable(b"draft", b"id", "x"),
            Err(SigningError)
        );
        let stable = OpaqueTokenSigner::new(Some(crate::test_support::test_signing_key(7)));
        let handle = stable.sign_durable(b"draft", b"id").unwrap();
        assert!(stable.is_durable());
        assert!(stable.verify_durable(b"draft", b"id", &handle).unwrap());
        assert!(!stable.verify_durable(b"draft", b"other", &handle).unwrap());
    }
}
