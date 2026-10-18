//! The confidential v1 wire format and its operation-local authenticated expiry.
use super::*;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};

pub(super) const HEADER_BYTES: usize = 26;
pub(super) const TAG_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MAGIC: &[u8] = b"AACE";
const FORMAT_VERSION: u8 = 1;
const PROTECTION: u8 = 1;
const SEED_DOMAIN: &[u8] = b"agent-access/continuation-aead-seed/v1\0";
const EXTRACT_DOMAIN: &[u8] = b"agent-access/continuation-aead-extract/v1\0";
const KEY_DOMAIN: &[u8] = b"agent-access/continuation-aead-key/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"agent-access/continuation-aead-envelope/v1\0";
const AEAD_BINDING_DOMAIN: &[u8] = b"agent-access/continuation-aead-binding/v1\0";

/// An authenticated confidential token opened for this in-process operation.
/// The provider may read its payload and original expiry, but cannot construct,
/// serialize, or change the proof used by [`ContinuationSigner::seal_resumed`].
/// Do not cache or persist this value between operations; admit and open each
/// incoming token again. Debug output reveals no payload or binding data.
pub struct OpenedContinuation {
    family: ContinuationFamily,
    binding_digest: [u8; 32],
    expiry: u64,
    payload: Vec<u8>,
}

impl OpenedContinuation {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The unchanged absolute expiry, in whole seconds since the Unix epoch.
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
}

impl fmt::Debug for OpenedContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedContinuation")
            .finish_non_exhaustive()
    }
}

impl ContinuationSigner {
    /// Fixes a first operation's expiry using the SDK clock and family TTL.
    /// Call at admission, before upstream work, and use [`Self::seal_until`]
    /// after that work. Only expiring confidential families support this API.
    pub fn deadline(&self, binding: &ContinuationBinding) -> Result<u64, ContinuationError> {
        self.deadline_at(binding, SystemTime::now())
    }

    /// [`Self::deadline`] at `now`.
    pub fn deadline_at(
        &self,
        binding: &ContinuationBinding,
        now: SystemTime,
    ) -> Result<u64, ContinuationError> {
        let ttl = confidential_ttl(&binding.family)?;
        unix_seconds(now)
            .checked_add(ttl)
            .ok_or(ContinuationError::Invalid)
    }

    /// Seals a first continuation with the operation's original absolute
    /// expiry. Requires `now < expiry <= now + TTL`; no clock-skew allowance
    /// extends a newly issued token. Use [`Self::seal_resumed`] after opening
    /// an incoming token, so pagination never renews its expiry.
    pub fn seal_until(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        expiry: u64,
    ) -> Result<String, ContinuationError> {
        let token = self.seal_until_at(binding, payload, expiry, SystemTime::now())?;
        // A slow key port must not return a token that expired while sealing.
        check_live(expiry, unix_seconds(SystemTime::now()))?;
        Ok(token)
    }

    /// [`Self::seal_until`] at `now`.
    pub fn seal_until_at(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        expiry: u64,
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        let ttl = confidential_ttl(&binding.family)?;
        let now = unix_seconds(now);
        check_live(expiry, now)?;
        if expiry > now.saturating_add(ttl) {
            return Err(ContinuationError::Invalid);
        }
        self.seal_confidential(binding, payload, expiry)
    }

    /// Authenticates and decrypts an admitted confidential token, preserving
    /// its original expiry for [`Self::seal_resumed`]. The expiry must still
    /// be in the future and at most TTL plus the declared clock skew ahead.
    /// The skew allowance never permits an expired token.
    pub fn open_confidential(
        &self,
        binding: &ContinuationBinding,
        token: &str,
    ) -> Result<OpenedContinuation, ContinuationError> {
        self.open_confidential_at(binding, token, SystemTime::now())
    }

    /// [`Self::open_confidential`] at `now`.
    pub fn open_confidential_at(
        &self,
        binding: &ContinuationBinding,
        token: &str,
        now: SystemTime,
    ) -> Result<OpenedContinuation, ContinuationError> {
        let family = &binding.family;
        let ttl = confidential_ttl(family)?;
        if token.len() > family.max_token_bytes() {
            return Err(ContinuationError::TokenTooLarge {
                limit: family.max_token_bytes(),
            });
        }
        let encoded = token
            .strip_prefix(family.token_prefix)
            .ok_or(ContinuationError::Invalid)?;
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ContinuationError::Invalid)?;
        let payload_len = raw
            .len()
            .checked_sub(HEADER_BYTES + TAG_BYTES)
            .ok_or(ContinuationError::Invalid)?;
        if payload_len > family.max_payload_bytes
            || (family.fixed_payload_length && payload_len != family.max_payload_bytes)
            || &raw[..4] != MAGIC
            || raw[4] != FORMAT_VERSION
        {
            return Err(ContinuationError::Invalid);
        }
        if raw[5] != family.version {
            return Err(ContinuationError::UnsupportedVersion);
        }
        let (header, ciphertext) = raw.split_at(HEADER_BYTES);
        let binding_digest = confidential_binding_digest(binding)?;
        let cipher = self.confidential_cipher(binding, &binding_digest)?;
        let aad = confidential_aad(binding, header)?;
        let payload = cipher
            .decrypt(
                Nonce::from_slice(&header[14..]),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ContinuationError::Invalid)?;
        // Nothing in the authenticated header or plaintext is interpreted
        // until authentication succeeds, apart from dispatch/length checks.
        let expiry = u64::from_be_bytes(header[6..14].try_into().expect("eight expiry bytes"));
        let now = unix_seconds(now);
        check_live(expiry, now)?;
        if expiry
            > now
                .saturating_add(ttl)
                .saturating_add(family.clock_skew.as_secs())
        {
            return Err(ContinuationError::Invalid);
        }
        Ok(OpenedContinuation {
            family: *family,
            binding_digest,
            expiry,
            payload,
        })
    }

    /// Seals with the exact deadline authenticated by `opened` for this
    /// family and complete binding. Requires only that the deadline has not
    /// passed, allowing clock skew accepted at opening without renewing it.
    pub fn seal_resumed(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        opened: &OpenedContinuation,
    ) -> Result<String, ContinuationError> {
        let token = self.seal_resumed_at(binding, payload, opened, SystemTime::now())?;
        check_live(opened.expiry, unix_seconds(SystemTime::now()))?;
        Ok(token)
    }

    /// [`Self::seal_resumed`] at `now`.
    pub fn seal_resumed_at(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        opened: &OpenedContinuation,
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        confidential_ttl(&binding.family)?;
        if binding.family != opened.family
            || !bool::from(confidential_binding_digest(binding)?.ct_eq(&opened.binding_digest))
        {
            return Err(ContinuationError::Invalid);
        }
        check_live(opened.expiry, unix_seconds(now))?;
        self.seal_confidential(binding, payload, opened.expiry)
    }

    fn seal_confidential(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        expiry: u64,
    ) -> Result<String, ContinuationError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ContinuationError::SigningUnavailable)?;
        self.seal_confidential_with_nonce(binding, payload, expiry, nonce)
    }

    // Fixed nonces are private and used only by deterministic test vectors.
    fn seal_confidential_with_nonce(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        expiry: u64,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<String, ContinuationError> {
        let family = &binding.family;
        if payload.len() > family.max_payload_bytes {
            return Err(ContinuationError::PayloadTooLarge {
                limit: family.max_payload_bytes,
            });
        }
        if family.fixed_payload_length && payload.len() != family.max_payload_bytes {
            return Err(ContinuationError::Invalid);
        }
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.push(family.version);
        header.extend_from_slice(&expiry.to_be_bytes());
        header.extend_from_slice(&nonce);
        let cipher = self.confidential_cipher(binding, &confidential_binding_digest(binding)?)?;
        let aad = confidential_aad(binding, &header)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &aad,
                },
            )
            .map_err(|_| ContinuationError::SigningUnavailable)?;
        header.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            family.token_prefix,
            URL_SAFE_NO_PAD.encode(header)
        ))
    }

    fn confidential_cipher(
        &self,
        binding: &ContinuationBinding,
        binding_digest: &[u8; 32],
    ) -> Result<Aes256Gcm, ContinuationError> {
        let family = &binding.family;
        let mut seed_input = SEED_DOMAIN.to_vec();
        push_lp(&mut seed_input, family.service.as_bytes())?;
        // mac() decodes the stable port's base64url into exactly 32 raw bytes.
        let seed = self.mac(family, &seed_input, &[])?;
        let mut info = KEY_DOMAIN.to_vec();
        push_lp(&mut info, family.service.as_bytes())?;
        push_lp(&mut info, family.purpose.as_bytes())?;
        info.extend_from_slice(&[family.version, PROTECTION]);
        info.extend_from_slice(binding_digest);
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(EXTRACT_DOMAIN), &seed)
            .expand(&info, &mut key)
            .map_err(|_| ContinuationError::SigningUnavailable)?;
        Ok(Aes256Gcm::new((&key).into()))
    }
}

fn confidential_ttl(family: &ContinuationFamily) -> Result<u64, ContinuationError> {
    if !family.confidential || family.scope_resolved {
        return Err(ContinuationError::Invalid);
    }
    family
        .time_to_live
        .map(|ttl| ttl.as_secs())
        .ok_or(ContinuationError::Invalid)
}

fn check_live(expiry: u64, now: u64) -> Result<(), ContinuationError> {
    if expiry <= now {
        Err(ContinuationError::Expired)
    } else {
        Ok(())
    }
}

fn confidential_binding_digest(
    binding: &ContinuationBinding,
) -> Result<[u8; 32], ContinuationError> {
    let mut encoded = AEAD_BINDING_DOMAIN.to_vec();
    push_lp(&mut encoded, &binding.encoded)?;
    Ok(Sha256::digest(encoded).into())
}

fn confidential_aad(
    binding: &ContinuationBinding,
    header: &[u8],
) -> Result<Vec<u8>, ContinuationError> {
    let mut aad = ENVELOPE_DOMAIN.to_vec();
    push_lp(&mut aad, binding.family.service.as_bytes())?;
    push_lp(&mut aad, binding.family.purpose.as_bytes())?;
    aad.push(PROTECTION);
    push_lp(&mut aad, &binding.encoded)?;
    aad.extend_from_slice(header);
    Ok(aad)
}

// Confidential v1 uses u32 LP, independently of the existing canonical
// binding's internal u64 lengths. Neither encoding may change implicitly.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ContinuationError> {
    let length = u32::try_from(bytes.len()).map_err(|_| ContinuationError::Invalid)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests;
