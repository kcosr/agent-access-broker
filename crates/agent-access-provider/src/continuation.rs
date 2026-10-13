//! Signed continuation envelopes: the opaque, versioned tokens a provider
//! returns so a caller can resume an operation, such as a page token, a log
//! cursor or a draft handle.
//!
//! A provider declares each token family once as a [`ContinuationFamily`]
//! constant: its service and purpose name, a version, how long its signing
//! key lives ([`ContinuationLifetime`]), whose continuation it is
//! ([`ContinuationOwner`]), an optional expiry and an explicit payload cap.
//! For each token it builds a [`ContinuationBinding`] from the admitted
//! context and the request's normalized settings, and seals or opens the
//! envelope with the provider instance's [`ContinuationSigner`].
//!
//! The binding never appears in the token. Its canonical, length-delimited
//! encoding is digested into the MAC context together with the service,
//! purpose and version, so the token carries only the version, the expiry, the
//! provider's payload and the MAC. A token opens only for the same family and
//! the same binding: a changed execution context, principal, credential mode,
//! configuration, resource or setting is indistinguishable from forgery and
//! fails as [`ContinuationError::Invalid`]. A token never carries authority;
//! the host authorizes every continuation again and the provider re-applies
//! its containment checks.
//!
//! ```
//! use agent_access_provider::{
//!     ContinuationError, ContinuationFamily, ContinuationLifetime, ContinuationSigner,
//!     ProviderInvocation,
//! };
//! use std::time::Duration;
//!
//! /// Page tokens carry the next upstream offset.
//! const PAGES: ContinuationFamily = ContinuationFamily::new(
//!     "example",
//!     "list-page",
//!     1,
//!     ContinuationLifetime::Generation,
//!     8,
//! )
//! .expires_after(Duration::from_secs(15 * 60));
//!
//! fn next_page_token(
//!     signer: &ContinuationSigner,
//!     request: &ProviderInvocation,
//!     configuration: &str,
//!     project: &str,
//!     offset: u64,
//! ) -> Result<String, ContinuationError> {
//!     let binding = PAGES
//!         .bind(request.context(), configuration)
//!         .text("project", project);
//!     signer.seal(&binding, &offset.to_be_bytes())
//! }
//! ```
use crate::signing::{generate_local_key, local_hmac};
use crate::{AdmittedContext, CredentialMode, DelegatedCredential, StableSigningKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const VERSION_BYTES: usize = 1;
const EXPIRY_BYTES: usize = 8;
const MAC_BYTES: usize = 32;
/// Upper bound for a family's declared payload cap.
const MAX_PAYLOAD_CAP: usize = 64 * 1024;
const MAC_DOMAIN: &[u8] = b"agent-access/continuation/v1\0";
const BINDING_DOMAIN: &[u8] = b"agent-access/continuation-binding/v1\0";
const ROLE_ENVELOPE: u8 = 1;
const ROLE_COMMITMENT: u8 = 2;
const TAG_ABSENT: u8 = 0;
const TAG_BYTES: u8 = 1;
const TAG_NUMBER: u8 = 2;
const TAG_FLAG: u8 = 3;
const TAG_LIST: u8 = 4;

/// Which key signs a family's tokens, and therefore how long they stay valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContinuationLifetime {
    /// A key generated for this provider instance, so one runtime
    /// generation: a reload or restart invalidates every token, even when the
    /// host has a stable key.
    Generation,
    /// The host's service-scoped stable key when one is configured, so tokens
    /// survive reloads and are shared by instances with that key; otherwise
    /// the generation key.
    StableWhenConfigured,
    /// Only the host's service-scoped stable key. Without one, sealing and
    /// opening fail with [`ContinuationError::DurableKeyUnavailable`] instead
    /// of falling back to a key that a reload would discard.
    Durable,
}

/// Whose continuation a token is: which parts of the caller's admitted
/// identity its binding includes. Every family binds the credential mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContinuationOwner {
    /// The admitted principal, and whether it authenticated.
    Caller,
    /// The admitted principal only in per-user mode. A service-mode token is
    /// deliberately shared by every principal admitted in service mode under
    /// an otherwise identical binding.
    PerUserCaller,
}

/// A declared token family: one service's tokens for one purpose. Families
/// with different services, purposes or versions never open each other's
/// tokens, even under the same key and binding.
///
/// The token cap is not declared separately: [`Self::max_token_bytes`] is
/// the exact encoded size of a token carrying the largest permitted payload,
/// so action schemas can bound the token input by it. Neither cap ever
/// truncates: an oversized payload or token is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationFamily {
    service: &'static str,
    purpose: &'static str,
    version: u8,
    lifetime: ContinuationLifetime,
    max_payload_bytes: usize,
    time_to_live: Option<Duration>,
    clock_skew: Duration,
    owner: ContinuationOwner,
    action_bound: bool,
    token_prefix: &'static str,
}

impl ContinuationFamily {
    /// A family whose tokens carry at most `max_payload_bytes` (at most
    /// 64 KiB) of provider payload. Its tokens are bound to the admitted
    /// action and caller ([`ContinuationOwner::Caller`]) and never expire
    /// until [`Self::expires_after`] gives them a lifetime.
    ///
    /// # Panics
    ///
    /// When `service` or `purpose` is empty or longer than 255 bytes, or the
    /// payload cap exceeds 64 KiB. In a `const` declaration this is a
    /// compile-time error.
    pub const fn new(
        service: &'static str,
        purpose: &'static str,
        version: u8,
        lifetime: ContinuationLifetime,
        max_payload_bytes: usize,
    ) -> Self {
        assert!(
            !service.is_empty() && service.len() <= 255,
            "continuation service must be 1-255 bytes"
        );
        assert!(
            !purpose.is_empty() && purpose.len() <= 255,
            "continuation purpose must be 1-255 bytes"
        );
        assert!(
            max_payload_bytes <= MAX_PAYLOAD_CAP,
            "continuation payload cap must be at most 64 KiB"
        );
        Self {
            service,
            purpose,
            version,
            lifetime,
            max_payload_bytes,
            time_to_live: None,
            clock_skew: Duration::ZERO,
            owner: ContinuationOwner::Caller,
            action_bound: true,
            token_prefix: "",
        }
    }

    /// Tokens expire `time_to_live` (whole seconds, at least one) after
    /// they are sealed.
    pub const fn expires_after(mut self, time_to_live: Duration) -> Self {
        assert!(
            time_to_live.as_secs() > 0,
            "continuation lifetime must be at least one second"
        );
        self.time_to_live = Some(time_to_live);
        self
    }

    /// Accepts tokens whose expiry lies up to `clock_skew` (whole seconds)
    /// further ahead than a fresh token's would, for instances sharing a
    /// stable key whose clocks differ.
    pub const fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = Duration::from_secs(clock_skew.as_secs());
        self
    }

    pub const fn owner(mut self, owner: ContinuationOwner) -> Self {
        self.owner = owner;
        self
    }

    /// Tokens continue under any action of the service instead of only the
    /// action that sealed them, such as a handle several actions accept.
    pub const fn shared_across_actions(mut self) -> Self {
        self.action_bound = false;
        self
    }

    /// A fixed, visible ASCII prefix that identifies the family's tokens.
    /// It counts toward [`Self::max_token_bytes`].
    pub const fn token_prefix(mut self, prefix: &'static str) -> Self {
        assert!(prefix.is_ascii(), "continuation token prefix must be ASCII");
        self.token_prefix = prefix;
        self
    }

    pub const fn service(&self) -> &'static str {
        self.service
    }

    pub const fn purpose(&self) -> &'static str {
        self.purpose
    }

    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn lifetime(&self) -> ContinuationLifetime {
        self.lifetime
    }

    pub const fn time_to_live(&self) -> Option<Duration> {
        self.time_to_live
    }

    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    /// The exact encoded length of a token carrying a
    /// [`Self::max_payload_bytes`] payload: the prefix plus the URL-safe
    /// base64 (unpadded) of a version byte, an 8-byte expiry when the family
    /// expires, the payload and a 32-byte MAC.
    pub const fn max_token_bytes(&self) -> usize {
        self.token_prefix.len() + unpadded_base64_len(self.raw_overhead() + self.max_payload_bytes)
    }

    /// Binds a token to `context`: the admitted service, the action (unless
    /// [`Self::shared_across_actions`]), the execution context, the credential
    /// mode and the caller as [`Self::owner`] declares, plus `configuration`,
    /// the provider's fingerprint of the configuration a token depends on
    /// (never credentials). Add the resource identifiers and the normalized
    /// filter, query and output settings with the field methods.
    pub fn bind(
        &self,
        context: &AdmittedContext,
        configuration: impl AsRef<[u8]>,
    ) -> ContinuationBinding {
        let mut binding = ContinuationBinding {
            family: *self,
            encoded: BINDING_DOMAIN.to_vec(),
            labels: Vec::new(),
        };
        binding = binding.text("service", context.service());
        binding = if self.action_bound {
            binding.text("action", context.action())
        } else {
            binding.absent("action")
        };
        binding = binding
            .text("executionContext", context.execution_context())
            .text("credentialMode", context.credential_mode().as_str());
        let identity = context.identity();
        let principal_bound = match self.owner {
            ContinuationOwner::Caller => true,
            ContinuationOwner::PerUserCaller => {
                context.credential_mode() == CredentialMode::PerUser
            }
        };
        binding = if principal_bound {
            binding
                .text("principal", &identity.principal)
                .flag("authenticated", identity.authenticated)
        } else {
            binding.absent("principal").absent("authenticated")
        };
        binding.bytes("configuration", configuration.as_ref())
    }

    const fn raw_overhead(&self) -> usize {
        VERSION_BYTES
            + if self.time_to_live.is_some() {
                EXPIRY_BYTES
            } else {
                0
            }
            + MAC_BYTES
    }

    const fn header_bytes(&self) -> usize {
        self.raw_overhead() - MAC_BYTES
    }
}

/// What one token is bound to: its family, the admitted context and the
/// fields the provider adds. Fields are encoded in the order they are added,
/// each with its label, a type tag and a length, so no two different field
/// sequences share an encoding; the provider's code fixes that order. The
/// encoding is digested into the MAC context and never enters the token.
/// Debug output names the family and labels, never values.
#[derive(Clone)]
pub struct ContinuationBinding {
    family: ContinuationFamily,
    encoded: Vec<u8>,
    labels: Vec<&'static str>,
}

impl ContinuationBinding {
    pub fn family(&self) -> &ContinuationFamily {
        &self.family
    }

    pub fn text(self, label: &'static str, value: &str) -> Self {
        self.bytes(label, value.as_bytes())
    }

    pub fn bytes(mut self, label: &'static str, value: &[u8]) -> Self {
        self.label(label, TAG_BYTES);
        push_length_prefixed(&mut self.encoded, value);
        self
    }

    pub fn number(mut self, label: &'static str, value: u64) -> Self {
        self.label(label, TAG_NUMBER);
        self.encoded.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn flag(mut self, label: &'static str, value: bool) -> Self {
        self.label(label, TAG_FLAG);
        self.encoded.push(u8::from(value));
        self
    }

    /// Absence is distinct from every present value, including `""`.
    pub fn optional_text(self, label: &'static str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.text(label, value),
            None => self.absent(label),
        }
    }

    /// Absence is distinct from every present value, including zero.
    pub fn optional_number(self, label: &'static str, value: Option<u64>) -> Self {
        match value {
            Some(value) => self.number(label, value),
            None => self.absent(label),
        }
    }

    /// An ordered list; the order is significant.
    pub fn texts<'v>(
        mut self,
        label: &'static str,
        values: impl IntoIterator<Item = &'v str>,
    ) -> Self {
        let values: Vec<&str> = values.into_iter().collect();
        self.label(label, TAG_LIST);
        self.encoded
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            push_length_prefixed(&mut self.encoded, value.as_bytes());
        }
        self
    }

    /// The delegated binding a lease was acquired under and the target and
    /// audience of its access. Routine refresh keeps all three; new consent,
    /// replacement or reconnection changes the binding identity.
    pub fn delegated(self, credential: &DelegatedCredential) -> Self {
        let access = credential.access();
        self.bytes("delegatedBinding", credential.binding_identity().digest())
            .text("delegatedTarget", &access.target())
            .text("delegatedAudience", &access.audience())
    }

    fn absent(mut self, label: &'static str) -> Self {
        self.label(label, TAG_ABSENT);
        self
    }

    fn label(&mut self, label: &'static str, tag: u8) {
        push_length_prefixed(&mut self.encoded, label.as_bytes());
        self.encoded.push(tag);
        self.labels.push(label);
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }

    /// The MAC context for `role`: the domain, the family's service, purpose
    /// and version, the role (and a commitment's label) and the binding
    /// digest. Every part is fixed-size or length-prefixed, so the context
    /// stays unambiguous when a key appends the MAC payload to it.
    fn mac_context(&self, role: u8, label: Option<&str>) -> Vec<u8> {
        let family = &self.family;
        let mut context = MAC_DOMAIN.to_vec();
        push_length_prefixed(&mut context, family.service.as_bytes());
        push_length_prefixed(&mut context, family.purpose.as_bytes());
        context.push(family.version);
        context.push(role);
        if let Some(label) = label {
            push_length_prefixed(&mut context, label.as_bytes());
        }
        context.extend_from_slice(&self.digest());
        context
    }
}

impl fmt::Debug for ContinuationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationBinding")
            .field("service", &self.family.service)
            .field("purpose", &self.family.purpose)
            .field("version", &self.family.version)
            .field("fields", &self.labels)
            .finish_non_exhaustive()
    }
}

/// Seals and opens one provider instance's continuation tokens. It holds a
/// key generated when it is created, for [`ContinuationLifetime::Generation`]
/// families and the stable-key fallback, and the host's service-scoped
/// stable key when one is configured. Build one per provider instance, from
/// [`crate::BuildContext::stable_signing_key`]; clones share the keys.
#[derive(Clone)]
pub struct ContinuationSigner {
    generation: Arc<[u8; 32]>,
    stable: Option<Arc<dyn StableSigningKey>>,
}

impl ContinuationSigner {
    pub fn new(stable: Option<Arc<dyn StableSigningKey>>) -> Self {
        Self {
            generation: generate_local_key(),
            stable,
        }
    }

    /// Whether [`ContinuationLifetime::Durable`] families can seal and open.
    pub fn is_durable(&self) -> bool {
        self.stable.is_some()
    }

    /// Seals `payload` into a token for `binding`, expiring (when the family
    /// expires) relative to the current system time.
    pub fn seal(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
    ) -> Result<String, ContinuationError> {
        self.seal_at(binding, payload, SystemTime::now())
    }

    /// [`Self::seal`] at `now`.
    pub fn seal_at(
        &self,
        binding: &ContinuationBinding,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        let family = binding.family;
        if payload.len() > family.max_payload_bytes {
            return Err(ContinuationError::PayloadTooLarge {
                limit: family.max_payload_bytes,
            });
        }
        let mut body = Vec::with_capacity(family.raw_overhead() + payload.len());
        body.push(family.version);
        if let Some(time_to_live) = family.time_to_live {
            let expires_at = unix_seconds(now).saturating_add(time_to_live.as_secs());
            body.extend_from_slice(&expires_at.to_be_bytes());
        }
        body.extend_from_slice(payload);
        let mac = self.mac(&family, &binding.mac_context(ROLE_ENVELOPE, None), &body)?;
        body.extend_from_slice(&mac);
        let token = format!("{}{}", family.token_prefix, URL_SAFE_NO_PAD.encode(&body));
        // The encoded cap is derived from the payload cap checked above.
        debug_assert!(token.len() <= family.max_token_bytes());
        Ok(token)
    }

    /// Opens a token sealed for this family and an identical binding,
    /// returning its payload. The size cap, version, MAC and expiry are all
    /// checked before any payload byte is returned.
    pub fn open(
        &self,
        binding: &ContinuationBinding,
        token: &str,
    ) -> Result<Vec<u8>, ContinuationError> {
        self.open_at(binding, token, SystemTime::now())
    }

    /// [`Self::open`] at `now`.
    pub fn open_at(
        &self,
        binding: &ContinuationBinding,
        token: &str,
        now: SystemTime,
    ) -> Result<Vec<u8>, ContinuationError> {
        let family = binding.family;
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
        if raw.len() < family.raw_overhead() {
            return Err(ContinuationError::Invalid);
        }
        if raw[0] != family.version {
            return Err(ContinuationError::UnsupportedVersion);
        }
        let (body, mac) = raw.split_at(raw.len() - MAC_BYTES);
        let expected = self.mac(&family, &binding.mac_context(ROLE_ENVELOPE, None), body)?;
        if !bool::from(expected.as_slice().ct_eq(mac)) {
            return Err(ContinuationError::Invalid);
        }
        if let Some(time_to_live) = family.time_to_live {
            let expires_at = u64::from_be_bytes(
                body[VERSION_BYTES..VERSION_BYTES + EXPIRY_BYTES]
                    .try_into()
                    .expect("eight expiry bytes"),
            );
            let now = unix_seconds(now);
            if expires_at <= now {
                return Err(ContinuationError::Expired);
            }
            let latest = now
                .saturating_add(time_to_live.as_secs())
                .saturating_add(family.clock_skew.as_secs());
            if expires_at > latest {
                return Err(ContinuationError::Invalid);
            }
        }
        let payload = &body[family.header_bytes()..];
        if payload.len() > family.max_payload_bytes {
            return Err(ContinuationError::Invalid);
        }
        Ok(payload.to_vec())
    }

    /// A keyed commitment to `value` under `binding` and `label`, for a
    /// provider to carry in its payload and check later with
    /// [`Self::verify_commitment`] against a value it learns again, such as a
    /// digest of upstream content already consumed. It reveals nothing about
    /// `value` without the key, so a leaked token cannot test guesses offline.
    pub fn commit(
        &self,
        binding: &ContinuationBinding,
        label: &'static str,
        value: &[u8],
    ) -> Result<[u8; 32], ContinuationError> {
        self.mac(
            &binding.family,
            &binding.mac_context(ROLE_COMMITMENT, Some(label)),
            value,
        )
    }

    /// Whether `commitment` is [`Self::commit`]'s commitment to `value`;
    /// otherwise [`ContinuationError::Invalid`].
    pub fn verify_commitment(
        &self,
        binding: &ContinuationBinding,
        label: &'static str,
        value: &[u8],
        commitment: &[u8],
    ) -> Result<(), ContinuationError> {
        let expected = self.commit(binding, label, value)?;
        if bool::from(expected.as_slice().ct_eq(commitment)) {
            Ok(())
        } else {
            Err(ContinuationError::Invalid)
        }
    }

    fn mac(
        &self,
        family: &ContinuationFamily,
        context: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], ContinuationError> {
        let stable = match (family.lifetime, &self.stable) {
            (ContinuationLifetime::Generation, _)
            | (ContinuationLifetime::StableWhenConfigured, None) => {
                return Ok(local_hmac(&self.generation, context, payload));
            }
            (ContinuationLifetime::Durable, None) => {
                return Err(ContinuationError::DurableKeyUnavailable);
            }
            (
                ContinuationLifetime::StableWhenConfigured | ContinuationLifetime::Durable,
                Some(stable),
            ) => stable,
        };
        let encoded = stable
            .hmac_base64url(context, payload)
            .map_err(|_| ContinuationError::SigningUnavailable)?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|mac| <[u8; 32]>::try_from(mac).ok())
            .ok_or(ContinuationError::SigningUnavailable)
    }
}

impl fmt::Debug for ContinuationSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationSigner")
            .field("durable", &self.is_durable())
            .finish_non_exhaustive()
    }
}

/// Why a continuation could not be sealed or opened. Providers map these to
/// their own reason and decision: [`Self::is_token_rejection`] separates a
/// token the caller must not reuse from a broker-side failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContinuationError {
    /// Not an authentic token of this family for this binding: malformed,
    /// tampered, signed by another key or family, or issued for a different
    /// context, caller, configuration, resource or setting. Binding fields
    /// never enter the token, so a changed binding is indistinguishable from
    /// forgery.
    #[error("continuation token is not valid for this request")]
    Invalid,
    /// The token names a version other than the family's current one.
    /// Obsolete tokens are never decoded.
    #[error("continuation token version is not supported")]
    UnsupportedVersion,
    /// An authentic token for this binding whose expiry has passed.
    #[error("continuation token has expired")]
    Expired,
    /// The presented token is longer than the family's encoded cap. Sealing
    /// never produces one: the cap is the size of the largest payload's token.
    #[error("continuation token exceeds its {limit}-byte limit")]
    TokenTooLarge { limit: usize },
    /// The provider's payload exceeds the family's cap; nothing was sealed.
    #[error("continuation payload exceeds its {limit}-byte limit")]
    PayloadTooLarge { limit: usize },
    /// The host's stable key failed to sign.
    #[error("continuation signing key is unavailable")]
    SigningUnavailable,
    /// The family is [`ContinuationLifetime::Durable`] and the host has no
    /// stable key configured.
    #[error("continuation family requires a durable signing key")]
    DurableKeyUnavailable,
}

impl ContinuationError {
    /// Whether the presented token was rejected (the caller's input is at
    /// fault), as opposed to the broker being unable to seal or verify.
    pub const fn is_token_rejection(self) -> bool {
        matches!(
            self,
            Self::Invalid | Self::UnsupportedVersion | Self::Expired | Self::TokenTooLarge { .. }
        )
    }
}

const fn unpadded_base64_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

fn push_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{InvocationBuilder, delegated_binding_id, test_signing_key};
    use crate::{
        DelegatedAccess, DelegatedBindingId, DelegatedLease, InvocationIdentity, ProviderError,
        ProviderInvocation, SigningError,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TTL: Duration = Duration::from_secs(900);
    const PAGES: ContinuationFamily =
        ContinuationFamily::new("svc", "list-page", 1, ContinuationLifetime::Generation, 16)
            .expires_after(TTL);

    fn invocation() -> ProviderInvocation {
        InvocationBuilder::new("svc", "item.list")
            .identity(InvocationIdentity {
                principal: "alice".to_string(),
                authenticated: true,
            })
            .build()
    }

    fn binding(family: &ContinuationFamily, request: &ProviderInvocation) -> ContinuationBinding {
        family
            .bind(request.context(), "config-a")
            .text("project", "team/service")
            .number("maxResults", 20)
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn sealed_payloads_open_only_for_the_same_binding() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let token = signer
            .seal(&binding(&PAGES, &request), b"offset-40")
            .unwrap();
        assert_eq!(
            signer.open(&binding(&PAGES, &request), &token).unwrap(),
            b"offset-40"
        );

        let rejected = |binding: ContinuationBinding| {
            assert_eq!(
                signer.open(&binding, &token),
                Err(ContinuationError::Invalid)
            );
        };
        for changed in [
            InvocationBuilder::from(request.clone())
                .execution_context("external")
                .build(),
            InvocationBuilder::from(request.clone())
                .principal("mallory")
                .build(),
            InvocationBuilder::from(request.clone())
                .identity(InvocationIdentity {
                    principal: "alice".to_string(),
                    authenticated: false,
                })
                .build(),
            InvocationBuilder::from(request.clone())
                .credential_mode(CredentialMode::PerUser)
                .build(),
            InvocationBuilder::from(request.clone())
                .action("item.search")
                .build(),
            InvocationBuilder::from(request.clone())
                .service("other")
                .build(),
        ] {
            rejected(binding(&PAGES, &changed));
        }
        // Configuration, resource and settings changes.
        rejected(
            PAGES
                .bind(request.context(), "config-b")
                .text("project", "team/service")
                .number("maxResults", 20),
        );
        rejected(
            PAGES
                .bind(request.context(), "config-a")
                .text("project", "team/other")
                .number("maxResults", 20),
        );
        rejected(
            PAGES
                .bind(request.context(), "config-a")
                .text("project", "team/service")
                .number("maxResults", 21),
        );
        rejected(
            PAGES
                .bind(request.context(), "config-a")
                .text("project", "team/service"),
        );
    }

    #[test]
    fn purpose_service_and_version_separate_families() {
        let signer = ContinuationSigner::new(Some(test_signing_key(3)));
        let request = invocation();
        let stable = PAGES.lifetime_for_tests(ContinuationLifetime::StableWhenConfigured);
        let token = signer.seal(&binding(&stable, &request), b"1").unwrap();
        let other_purpose = ContinuationFamily::new(
            "svc",
            "other-page",
            1,
            ContinuationLifetime::StableWhenConfigured,
            16,
        )
        .expires_after(TTL);
        let other_service = ContinuationFamily::new(
            "other",
            "list-page",
            1,
            ContinuationLifetime::StableWhenConfigured,
            16,
        )
        .expires_after(TTL);
        for family in [other_purpose, other_service] {
            assert_eq!(
                signer.open(&binding(&family, &request), &token),
                Err(ContinuationError::Invalid)
            );
        }
        // An obsolete version is rejected by version, never decoded.
        let next = ContinuationFamily::new(
            "svc",
            "list-page",
            2,
            ContinuationLifetime::StableWhenConfigured,
            16,
        )
        .expires_after(TTL);
        assert_eq!(
            signer.open(&binding(&next, &request), &token),
            Err(ContinuationError::UnsupportedVersion)
        );
        let newer = signer.seal(&binding(&next, &request), b"1").unwrap();
        assert_eq!(
            signer.open(&binding(&stable, &request), &newer),
            Err(ContinuationError::UnsupportedVersion)
        );
    }

    #[test]
    fn lifetimes_choose_the_generation_or_stable_key() {
        let request = invocation();
        let key = test_signing_key(9);
        let first = ContinuationSigner::new(Some(key.clone()));
        let second = ContinuationSigner::new(Some(key));

        // Generation tokens never outlive their instance, even with a key.
        let generation = first.seal(&binding(&PAGES, &request), b"g").unwrap();
        assert_eq!(
            first.open(&binding(&PAGES, &request), &generation).unwrap(),
            b"g"
        );
        assert_eq!(
            second.open(&binding(&PAGES, &request), &generation),
            Err(ContinuationError::Invalid)
        );

        let stable = PAGES.lifetime_for_tests(ContinuationLifetime::StableWhenConfigured);
        let shared = first.seal(&binding(&stable, &request), b"s").unwrap();
        assert_eq!(
            second.open(&binding(&stable, &request), &shared).unwrap(),
            b"s"
        );
        let local_only = ContinuationSigner::new(None);
        let local = local_only.seal(&binding(&stable, &request), b"l").unwrap();
        assert_eq!(
            local_only
                .open(&binding(&stable, &request), &local)
                .unwrap(),
            b"l"
        );
        assert_eq!(
            ContinuationSigner::new(None).open(&binding(&stable, &request), &local),
            Err(ContinuationError::Invalid)
        );

        let durable = PAGES.lifetime_for_tests(ContinuationLifetime::Durable);
        assert!(!local_only.is_durable());
        assert_eq!(
            local_only.seal(&binding(&durable, &request), b"d"),
            Err(ContinuationError::DurableKeyUnavailable)
        );
        let handle = first.seal(&binding(&durable, &request), b"d").unwrap();
        assert!(second.is_durable());
        assert_eq!(
            second.open(&binding(&durable, &request), &handle).unwrap(),
            b"d"
        );
        assert_eq!(
            local_only.open(&binding(&durable, &request), &handle),
            Err(ContinuationError::DurableKeyUnavailable)
        );
        assert_eq!(
            local_only.commit(&binding(&durable, &request), "x", b"v"),
            Err(ContinuationError::DurableKeyUnavailable)
        );
    }

    #[test]
    fn expiry_and_clock_skew_bound_token_lifetimes() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let issued = 1_800_000_000;
        let token = signer
            .seal_at(&binding(&PAGES, &request), b"p", at(issued))
            .unwrap();
        let open = |now| signer.open_at(&binding(&PAGES, &request), &token, at(now));
        assert_eq!(open(issued + 899).unwrap(), b"p");
        assert_eq!(open(issued + 900), Err(ContinuationError::Expired));
        // A token from the future is not authentic for this clock.
        assert_eq!(open(issued - 1), Err(ContinuationError::Invalid));

        let skewed = PAGES.clock_skew(Duration::from_secs(60));
        let token = signer
            .seal_at(&binding(&skewed, &request), b"p", at(issued))
            .unwrap();
        let open = |now| signer.open_at(&binding(&skewed, &request), &token, at(now));
        assert_eq!(open(issued - 60).unwrap(), b"p");
        assert_eq!(open(issued - 61), Err(ContinuationError::Invalid));

        // Families without a lifetime carry no expiry.
        let handles =
            ContinuationFamily::new("svc", "handle", 1, ContinuationLifetime::Generation, 4);
        let handle = signer
            .seal_at(&binding(&handles, &request), b"h", at(0))
            .unwrap();
        assert_eq!(
            signer
                .open_at(&binding(&handles, &request), &handle, at(u64::MAX / 2))
                .unwrap(),
            b"h"
        );
    }

    #[test]
    fn size_caps_are_exact_and_never_truncate() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        // The measured worst case equals the declared encoded cap exactly.
        for family in [
            PAGES,
            ContinuationFamily::new("svc", "handle", 1, ContinuationLifetime::Generation, 0),
            ContinuationFamily::new("svc", "upstream", 1, ContinuationLifetime::Generation, 2048)
                .expires_after(TTL)
                .token_prefix("aab_svc_"),
        ] {
            let largest = vec![0xff; family.max_payload_bytes()];
            let token = signer.seal(&binding(&family, &request), &largest).unwrap();
            assert_eq!(token.len(), family.max_token_bytes(), "{family:?}");
            assert_eq!(
                signer.open(&binding(&family, &request), &token).unwrap(),
                largest
            );
            let over = vec![0; family.max_payload_bytes() + 1];
            assert_eq!(
                signer.seal(&binding(&family, &request), &over),
                Err(ContinuationError::PayloadTooLarge {
                    limit: family.max_payload_bytes()
                })
            );
            let oversized = format!("{token}A");
            assert_eq!(
                signer.open(&binding(&family, &request), &oversized),
                Err(ContinuationError::TokenTooLarge {
                    limit: family.max_token_bytes()
                })
            );
        }
        // 1 version + 8 expiry + 32 MAC bytes around the payload, in
        // unpadded base64: 57 raw bytes encode to 76 characters.
        assert_eq!(PAGES.max_token_bytes(), 76);
        assert_eq!(
            ContinuationFamily::new("svc", "upstream", 1, ContinuationLifetime::Generation, 2048)
                .expires_after(TTL)
                .max_token_bytes(),
            2786
        );
    }

    #[test]
    fn tampered_malformed_and_foreign_tokens_are_invalid() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let bound = binding(&PAGES, &request);
        let token = signer.seal(&bound, b"payload").unwrap();
        let bytes = token.as_bytes();
        for index in 0..bytes.len() {
            let mut tampered = bytes.to_vec();
            tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(tampered).unwrap();
            let result = signer.open(&bound, &tampered);
            assert!(
                matches!(
                    result,
                    Err(ContinuationError::Invalid | ContinuationError::UnsupportedVersion)
                ),
                "byte {index}: {result:?}"
            );
        }
        for malformed in ["", "!", "a.b", &token[..token.len() - 1]] {
            assert!(
                signer
                    .open(&bound, malformed)
                    .unwrap_err()
                    .is_token_rejection()
            );
        }
        let prefixed = PAGES.token_prefix("aab_");
        let prefixed_token = signer.seal(&binding(&prefixed, &request), b"p").unwrap();
        assert!(prefixed_token.starts_with("aab_"));
        assert_eq!(
            signer.open(&binding(&prefixed, &request), &prefixed_token[4..]),
            Err(ContinuationError::Invalid)
        );
    }

    #[test]
    fn binding_fields_never_appear_in_tokens() {
        let signer = ContinuationSigner::new(None);
        let request = InvocationBuilder::from(invocation())
            .principal("principal-secret")
            .execution_context("context-secret")
            .build();
        let bound = PAGES
            .bind(request.context(), "configuration-secret")
            .text("query", "query-secret");
        let token = signer.seal(&bound, b"").unwrap();
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert_eq!(raw.len(), 41);
        let debug = format!("{bound:?}");
        for secret in [
            "principal-secret",
            "context-secret",
            "configuration-secret",
            "query-secret",
        ] {
            assert!(!raw.windows(secret.len()).any(|w| w == secret.as_bytes()));
            assert!(!token.contains(secret));
            assert!(!debug.contains(secret), "{debug}");
        }
        assert!(debug.contains("query"), "{debug}");
        assert_eq!(
            format!("{signer:?}"),
            "ContinuationSigner { durable: false, .. }"
        );
    }

    #[test]
    fn field_encoding_is_canonical_and_length_delimited() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let base = || PAGES.bind(request.context(), "c");
        let pairs: [(ContinuationBinding, ContinuationBinding); 6] = [
            (base().text("a", "bc"), base().text("ab", "c")),
            (
                base().text("a", "x").text("b", "y"),
                base().text("a", "xb").text("", "y"),
            ),
            (
                base().optional_text("q", None),
                base().optional_text("q", Some("")),
            ),
            (
                base().optional_number("n", None),
                base().optional_number("n", Some(0)),
            ),
            (base().texts("l", ["a", "b"]), base().texts("l", ["b", "a"])),
            (base().texts("l", ["ab"]), base().texts("l", ["a", "b"])),
        ];
        for (left, right) in pairs {
            let token = signer.seal(&left, b"").unwrap();
            assert!(signer.open(&left, &token).is_ok());
            assert_eq!(signer.open(&right, &token), Err(ContinuationError::Invalid));
        }
        // Equal field sequences bind equally, whichever value types built them.
        let token = signer.seal(&base().text("t", "v"), b"").unwrap();
        assert!(signer.open(&base().bytes("t", b"v"), &token).is_ok());
        assert_eq!(
            signer.open(&base().flag("t", true), &token),
            Err(ContinuationError::Invalid)
        );
    }

    #[test]
    fn per_user_owner_shares_service_mode_tokens_only() {
        let signer = ContinuationSigner::new(None);
        let handles = PAGES
            .owner(ContinuationOwner::PerUserCaller)
            .shared_across_actions();
        let service_alice = invocation();
        let service_bob = InvocationBuilder::from(invocation())
            .principal("bob")
            .build();
        let token = signer
            .seal(&binding(&handles, &service_alice), b"shared")
            .unwrap();
        assert_eq!(
            signer
                .open(&binding(&handles, &service_bob), &token)
                .unwrap(),
            b"shared"
        );
        let other_action = InvocationBuilder::from(invocation())
            .action("item.update")
            .build();
        assert!(
            signer
                .open(&binding(&handles, &other_action), &token)
                .is_ok()
        );
        let other_context = InvocationBuilder::from(invocation())
            .execution_context("external")
            .build();
        assert_eq!(
            signer.open(&binding(&handles, &other_context), &token),
            Err(ContinuationError::Invalid)
        );

        let per_user = |principal: &str| {
            InvocationBuilder::from(invocation())
                .credential_mode(CredentialMode::PerUser)
                .principal(principal)
                .build()
        };
        assert_eq!(
            signer.open(&binding(&handles, &per_user("alice")), &token),
            Err(ContinuationError::Invalid)
        );
        let owned = signer
            .seal(&binding(&handles, &per_user("alice")), b"mine")
            .unwrap();
        assert_eq!(
            signer
                .open(&binding(&handles, &per_user("alice")), &owned)
                .unwrap(),
            b"mine"
        );
        for other in [per_user("bob"), service_alice] {
            assert_eq!(
                signer.open(&binding(&handles, &other), &owned),
                Err(ContinuationError::Invalid)
            );
        }
    }

    struct Lease {
        binding: DelegatedBindingId,
        target: &'static str,
        audience: &'static str,
        token: &'static str,
    }

    #[async_trait::async_trait]
    impl DelegatedLease for Lease {
        fn access(&self) -> DelegatedAccess {
            DelegatedAccess::new(
                self.token.to_string(),
                self.target.to_string(),
                self.audience.to_string(),
                self.token.to_string(),
                0,
            )
        }

        fn binding_identity(&self) -> DelegatedBindingId {
            self.binding
        }

        async fn revalidate(&self) -> Result<(), ProviderError> {
            Ok(())
        }

        fn mark_rejected(&self, _version: &str) -> Result<(), ProviderError> {
            Ok(())
        }

        async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
            Ok(self.access())
        }
    }

    fn lease(
        binding: &str,
        target: &'static str,
        audience: &'static str,
        token: &'static str,
    ) -> DelegatedCredential {
        DelegatedCredential::new(Arc::new(Lease {
            binding: delegated_binding_id(binding),
            target,
            audience,
            token,
        }))
    }

    #[test]
    fn delegated_bindings_survive_refresh_but_not_rebinding() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let bound =
            |credential: &DelegatedCredential| binding(&PAGES, &request).delegated(credential);
        let token = signer
            .seal(
                &bound(&lease("binding-1", "mailbox", "gmail", "access-1")),
                b"p",
            )
            .unwrap();
        // A refreshed access token keeps the binding.
        assert!(
            signer
                .open(
                    &bound(&lease("binding-1", "mailbox", "gmail", "access-2")),
                    &token
                )
                .is_ok()
        );
        for changed in [
            lease("binding-2", "mailbox", "gmail", "access-1"),
            lease("binding-1", "other", "gmail", "access-1"),
            lease("binding-1", "mailbox", "other", "access-1"),
        ] {
            assert_eq!(
                signer.open(&bound(&changed), &token),
                Err(ContinuationError::Invalid)
            );
        }
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"access"));
    }

    #[test]
    fn commitments_bind_value_label_and_binding() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let bound = binding(&PAGES, &request);
        let commitment = signer.commit(&bound, "prefix", b"digest").unwrap();
        assert_eq!(
            signer.verify_commitment(&bound, "prefix", b"digest", &commitment),
            Ok(())
        );
        let other = binding(
            &PAGES,
            &InvocationBuilder::from(invocation())
                .principal("bob")
                .build(),
        );
        for (binding, label, value, commitment) in [
            (
                &bound,
                "prefix",
                b"other!".as_slice(),
                commitment.as_slice(),
            ),
            (&bound, "suffix", b"digest", &commitment),
            (&other, "prefix", b"digest", &commitment),
            (&bound, "prefix", b"digest", &commitment[..31]),
        ] {
            assert_eq!(
                signer.verify_commitment(binding, label, value, commitment),
                Err(ContinuationError::Invalid)
            );
        }
        // A commitment is not an envelope MAC under the same binding.
        let token = signer.seal(&bound, b"digest").unwrap();
        let raw = URL_SAFE_NO_PAD.decode(token).unwrap();
        assert_ne!(&raw[raw.len() - 32..], commitment.as_slice());
    }

    struct FailingKey {
        inner: Arc<dyn StableSigningKey>,
        successes: AtomicUsize,
    }

    impl StableSigningKey for FailingKey {
        fn hmac_base64url(&self, context: &[u8], payload: &[u8]) -> Result<String, SigningError> {
            if self
                .successes
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_err()
            {
                return Err(SigningError);
            }
            self.inner.hmac_base64url(context, payload)
        }
    }

    #[test]
    fn stable_key_failures_are_signing_unavailable() {
        let request = invocation();
        let stable = PAGES.lifetime_for_tests(ContinuationLifetime::StableWhenConfigured);
        let healthy = ContinuationSigner::new(Some(test_signing_key(5)));
        let token = healthy.seal(&binding(&stable, &request), b"p").unwrap();
        let failing = ContinuationSigner::new(Some(Arc::new(FailingKey {
            inner: test_signing_key(5),
            successes: AtomicUsize::new(0),
        })));
        assert_eq!(
            failing.seal(&binding(&stable, &request), b"p"),
            Err(ContinuationError::SigningUnavailable)
        );
        assert_eq!(
            failing.open(&binding(&stable, &request), &token),
            Err(ContinuationError::SigningUnavailable)
        );
        assert_eq!(
            failing.commit(&binding(&stable, &request), "x", b"v"),
            Err(ContinuationError::SigningUnavailable)
        );
        for error in [
            ContinuationError::SigningUnavailable,
            ContinuationError::DurableKeyUnavailable,
            ContinuationError::PayloadTooLarge { limit: 1 },
        ] {
            assert!(!error.is_token_rejection());
        }
    }

    impl ContinuationFamily {
        const fn lifetime_for_tests(mut self, lifetime: ContinuationLifetime) -> Self {
            self.lifetime = lifetime;
            self
        }
    }
}
