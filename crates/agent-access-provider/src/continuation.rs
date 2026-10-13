//! Signed continuation envelopes: the opaque, versioned tokens a provider
//! returns so a caller can resume an operation, such as a page token, a log
//! cursor or a draft handle.
//!
//! A provider declares each token family once as a [`ContinuationFamily`]
//! constant: its service and purpose name, a version, how long its signing
//! key lives ([`ContinuationLifetime`]), whose continuation it is
//! ([`ContinuationOwner`]), an optional expiry and a payload cap. For each
//! token it builds a [`ContinuationBinding`] from the admitted context and
//! the request's normalized settings, and seals or opens the envelope with
//! the provider instance's [`ContinuationSigner`].
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
//! Two token shapes have dedicated support:
//!
//! - **Relayed upstream cursors.** [`ContinuationSigner::seal_relayed`] seals
//!   an upstream service's own page token as text, optionally with a keyed
//!   commitment to the upstream query the provider composed for it, so a
//!   token is never replayed against a recomposed query
//!   ([`ContinuationError::UpstreamQueryChanged`]).
//!   [`ContinuationFamily::max_payload_bytes_within`] sizes such a family
//!   from the provider's response limit through
//!   [`ContinuationFamily::with_max_payload_bytes`] instead of a separate cap.
//! - **Tokens opened during scope resolution.** A family declared
//!   [`ContinuationFamily::opened_during_scope_resolution`] can be opened
//!   with [`ContinuationFamily::bind_scope`] before the host admits a
//!   credential mode, for example to read the resource a handle names. Its
//!   owner is carried as a keyed ownership commitment inside the token and
//!   checked again after admission.
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
use crate::{AdmittedContext, CredentialMode, DelegatedCredential, ScopeRequest, StableSigningKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::{Choice, ConstantTimeEq};

const VERSION_BYTES: usize = 1;
const EXPIRY_BYTES: usize = 8;
const OWNER_COMMITMENT_BYTES: usize = 32;
const MAC_BYTES: usize = 32;
/// The size of the upstream-query commitment
/// [`ContinuationSigner::seal_relayed`] puts before the upstream token; it
/// counts toward the family's payload cap.
pub const UPSTREAM_QUERY_COMMITMENT_BYTES: usize = 32;
/// Upper bound for a family's declared payload cap.
const MAX_PAYLOAD_CAP: usize = 64 * 1024;
const MAC_DOMAIN: &[u8] = b"agent-access/continuation/v1\0";
const BINDING_DOMAIN: &[u8] = b"agent-access/continuation-binding/v1\0";
const OWNER_DOMAIN: &[u8] = b"agent-access/continuation-owner/v1\0";
const ROLE_ENVELOPE: u8 = 1;
const ROLE_COMMITMENT: u8 = 2;
const ROLE_OWNER: u8 = 3;
const ROLE_RELAYED: u8 = 4;
const ROLE_RELAYED_WITH_QUERY: u8 = 5;
const ROLE_UPSTREAM_QUERY: u8 = 6;
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
/// identity it is bound to. Every family binds the credential mode.
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

impl ContinuationOwner {
    const fn binds_principal(self, mode: CredentialMode) -> bool {
        match self {
            Self::Caller => true,
            Self::PerUserCaller => matches!(mode, CredentialMode::PerUser),
        }
    }
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
    scope_resolved: bool,
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
            scope_resolved: false,
            token_prefix: "",
        }
    }

    /// The same family with a payload cap chosen at run time, such as a
    /// provider relaying an upstream token whose size only a configured limit
    /// bounds. Unlike the cap given to [`Self::new`], this one is not limited
    /// to 64 KiB; [`Self::max_token_bytes`] follows it, saturating at
    /// `usize::MAX`.
    pub const fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes;
        self
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

    /// Tokens are also opened during scope resolution, before the host
    /// admits a credential mode, through [`Self::bind_scope`] and
    /// [`ContinuationSigner::open_during_scope_resolution`].
    ///
    /// The binding then covers only what scope resolution knows: the
    /// service, the action (unless [`Self::shared_across_actions`]), the
    /// execution context, the configuration and the provider's fields. The
    /// token's owner, as [`Self::owner`] declares it from the credential mode
    /// and principal it was sealed under, travels in the token as a keyed
    /// 32-byte ownership commitment. Scope resolution accepts a token only
    /// when the current principal could own it in some credential mode;
    /// [`ContinuationSigner::open`] accepts it only for the admitted mode and
    /// principal.
    pub const fn opened_during_scope_resolution(mut self) -> Self {
        self.scope_resolved = true;
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

    /// The largest payload whose token, prefix included, is at most
    /// `token_bytes` long, for [`Self::with_max_payload_bytes`] when a
    /// provider's response limit bounds a relayed upstream token: the
    /// continuation then always fits the result it is returned in. Declare
    /// the family's expiry, prefix and scope-resolution opening first; they
    /// count toward the overhead.
    pub const fn max_payload_bytes_within(&self, token_bytes: usize) -> usize {
        let encoded = token_bytes.saturating_sub(self.token_prefix.len());
        // Unpadded base64 of `n` bytes is ceil(4n / 3) characters, so
        // floor(3m / 4) raw bytes encode within `m` characters.
        let raw = encoded / 4 * 3 + encoded % 4 * 3 / 4;
        raw.saturating_sub(self.raw_overhead())
    }

    /// The exact encoded length of a token carrying a
    /// [`Self::max_payload_bytes`] payload: the prefix plus the URL-safe
    /// base64 (unpadded) of a version byte, an 8-byte expiry when the family
    /// expires, a 32-byte ownership commitment when
    /// [`Self::opened_during_scope_resolution`], the payload and a 32-byte
    /// MAC.
    pub const fn max_token_bytes(&self) -> usize {
        self.token_prefix.len().saturating_add(unpadded_base64_len(
            self.raw_overhead().saturating_add(self.max_payload_bytes),
        ))
    }

    /// Binds a token to `context`: the admitted service, the action (unless
    /// [`Self::shared_across_actions`]), the execution context, the credential
    /// mode and the caller as [`Self::owner`] declares, plus `configuration`,
    /// the provider's fingerprint of the configuration a token depends on
    /// (never credentials). Add the resource identifiers and the normalized
    /// filter, query and output settings with the field methods.
    ///
    /// For a family [`Self::opened_during_scope_resolution`], the credential
    /// mode and caller become the token's ownership commitment instead of
    /// binding fields, so this binding equals [`Self::bind_scope`]'s for the
    /// same service, action, execution context and configuration.
    pub fn bind(
        &self,
        context: &AdmittedContext,
        configuration: impl AsRef<[u8]>,
    ) -> ContinuationBinding {
        let identity = context.identity();
        let mode = context.credential_mode();
        let mut binding = self.start_binding(
            context.service(),
            context.action(),
            context.execution_context(),
            AdmissionStage {
                owner: OwnerClaim {
                    mode,
                    principal: identity.principal.clone(),
                    authenticated: identity.authenticated,
                },
            },
        );
        if !self.scope_resolved {
            binding = binding.text("credentialMode", mode.as_str());
            binding = if self.owner.binds_principal(mode) {
                binding
                    .text("principal", &identity.principal)
                    .flag("authenticated", identity.authenticated)
            } else {
                binding.absent("principal").absent("authenticated")
            };
        }
        binding.bytes("configuration", configuration.as_ref())
    }

    /// Binds a token during scope resolution, for a family
    /// [`Self::opened_during_scope_resolution`]: the service, the action
    /// (unless [`Self::shared_across_actions`]), the execution context and
    /// `configuration`, followed by the same provider fields as at
    /// admission. Such a binding only opens tokens, with
    /// [`ContinuationSigner::open_during_scope_resolution`]; for any other
    /// family it opens none.
    pub fn bind_scope(
        &self,
        request: &ScopeRequest<'_>,
        configuration: impl AsRef<[u8]>,
    ) -> ContinuationBinding<ScopeResolutionStage> {
        debug_assert!(
            self.scope_resolved,
            "{}/{} is not opened during scope resolution",
            self.service, self.purpose
        );
        let identity = request.identity();
        self.start_binding(
            request.service(),
            request.action(),
            request.execution_context(),
            ScopeResolutionStage {
                principal: identity.principal.clone(),
                authenticated: identity.authenticated,
            },
        )
        .bytes("configuration", configuration.as_ref())
    }

    fn start_binding<S: ContinuationStage>(
        &self,
        service: &str,
        action: &str,
        execution_context: &str,
        stage: S,
    ) -> ContinuationBinding<S> {
        let binding = ContinuationBinding {
            family: *self,
            encoded: BINDING_DOMAIN.to_vec(),
            labels: Vec::new(),
            stage,
        }
        .text("service", service);
        let binding = if self.action_bound {
            binding.text("action", action)
        } else {
            binding.absent("action")
        };
        let binding = binding.text("executionContext", execution_context);
        if self.scope_resolved {
            binding.flag("ownerCommitted", true)
        } else {
            binding
        }
    }

    const fn raw_overhead(&self) -> usize {
        VERSION_BYTES
            + if self.time_to_live.is_some() {
                EXPIRY_BYTES
            } else {
                0
            }
            + if self.scope_resolved {
                OWNER_COMMITMENT_BYTES
            } else {
                0
            }
            + MAC_BYTES
    }

    /// The bytes before the payload: version, expiry and ownership
    /// commitment.
    const fn header_bytes(&self) -> usize {
        self.raw_overhead() - MAC_BYTES
    }

    const fn expiry_offset(&self) -> usize {
        VERSION_BYTES
    }

    const fn owner_offset(&self) -> usize {
        VERSION_BYTES
            + if self.time_to_live.is_some() {
                EXPIRY_BYTES
            } else {
                0
            }
    }
}

mod sealed {
    pub trait Stage {}
}

/// When a [`ContinuationBinding`] was built: [`AdmissionStage`], when it
/// seals and opens tokens, or [`ScopeResolutionStage`], when it only opens
/// them.
pub trait ContinuationStage: sealed::Stage + Clone {}

/// The stage of a binding built by [`ContinuationFamily::bind`] from the
/// admitted context. It knows the admitted credential mode and caller.
#[derive(Clone)]
pub struct AdmissionStage {
    owner: OwnerClaim,
}

/// The stage of a binding built by [`ContinuationFamily::bind_scope`] before
/// admission. It knows the principal but not the credential mode, so it
/// cannot seal.
#[derive(Clone)]
pub struct ScopeResolutionStage {
    principal: String,
    authenticated: bool,
}

impl sealed::Stage for AdmissionStage {}
impl sealed::Stage for ScopeResolutionStage {}
impl ContinuationStage for AdmissionStage {}
impl ContinuationStage for ScopeResolutionStage {}

/// The admitted owner of a token sealed for a family opened during scope
/// resolution.
#[derive(Clone)]
struct OwnerClaim {
    mode: CredentialMode,
    principal: String,
    authenticated: bool,
}

/// What one token is bound to: its family, the admitted context and the
/// fields the provider adds. Fields are encoded in the order they are added,
/// each with its label, a type tag and a length, so no two different field
/// sequences share an encoding; the provider's code fixes that order. The
/// encoding is digested into the MAC context and never enters the token.
/// Debug output names the family and labels, never values.
#[derive(Clone)]
pub struct ContinuationBinding<Stage: ContinuationStage = AdmissionStage> {
    family: ContinuationFamily,
    encoded: Vec<u8>,
    labels: Vec<&'static str>,
    stage: Stage,
}

impl<Stage: ContinuationStage> ContinuationBinding<Stage> {
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
            .text("delegatedTarget", access.target())
            .text("delegatedAudience", access.audience())
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

impl<Stage: ContinuationStage> fmt::Debug for ContinuationBinding<Stage> {
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
        self.seal_role(binding, ROLE_ENVELOPE, &[payload], now)
    }

    /// Opens a token sealed for this family and an identical binding,
    /// returning its payload. The size cap, version, MAC, expiry and, for a
    /// family opened during scope resolution, the admitted owner are all
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
        self.open_admitted(binding, ROLE_ENVELOPE, token, now)
    }

    /// Opens a token during scope resolution, for a family
    /// [`ContinuationFamily::opened_during_scope_resolution`]: the size cap,
    /// version, MAC and expiry, and that the token's owner is the current
    /// principal in some credential mode (or, for
    /// [`ContinuationOwner::PerUserCaller`], any service-mode principal).
    /// Open the token again with [`Self::open`] after admission, which checks
    /// the owner against the admitted credential mode.
    pub fn open_during_scope_resolution(
        &self,
        binding: &ContinuationBinding<ScopeResolutionStage>,
        token: &str,
    ) -> Result<Vec<u8>, ContinuationError> {
        if !binding.family.scope_resolved {
            return Err(ContinuationError::Invalid);
        }
        let opened = self.open_role(binding, ROLE_ENVELOPE, token, SystemTime::now())?;
        let stage = &binding.stage;
        let mut owned = Choice::from(0);
        for mode in [CredentialMode::Service, CredentialMode::PerUser] {
            let expected =
                self.owner_commitment(binding, mode, &stage.principal, stage.authenticated)?;
            owned |= expected.as_slice().ct_eq(&opened.owner);
        }
        if bool::from(owned) {
            Ok(opened.payload)
        } else {
            Err(ContinuationError::Invalid)
        }
    }

    /// Seals `upstream_token`, an upstream service's own continuation token,
    /// for the provider to send back upstream on the next page. With
    /// `upstream_query`, the token also carries a keyed commitment to the
    /// upstream query the provider composed for this page, such as a query
    /// rewritten under the current authorization, which the binding does not
    /// cover. Relayed tokens are sealed under their own role, so they open
    /// only through [`Self::open_relayed`] with the same choice of query
    /// commitment. The commitment counts toward the family's payload cap,
    /// so [`ContinuationError::PayloadTooLarge`] reports the longest upstream
    /// token the family relays.
    pub fn seal_relayed(
        &self,
        binding: &ContinuationBinding,
        upstream_query: Option<&[u8]>,
        upstream_token: &str,
    ) -> Result<String, ContinuationError> {
        self.seal_relayed_at(binding, upstream_query, upstream_token, SystemTime::now())
    }

    /// [`Self::seal_relayed`] at `now`.
    pub fn seal_relayed_at(
        &self,
        binding: &ContinuationBinding,
        upstream_query: Option<&[u8]>,
        upstream_token: &str,
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        let commitment_bytes = if upstream_query.is_some() {
            UPSTREAM_QUERY_COMMITMENT_BYTES
        } else {
            0
        };
        let limit = binding
            .family
            .max_payload_bytes()
            .saturating_sub(commitment_bytes);
        if upstream_token.len() > limit || commitment_bytes > binding.family.max_payload_bytes() {
            return Err(ContinuationError::PayloadTooLarge { limit });
        }
        match upstream_query {
            Some(query) => {
                let commitment = self.upstream_query_commitment(binding, query)?;
                self.seal_role(
                    binding,
                    ROLE_RELAYED_WITH_QUERY,
                    &[&commitment, upstream_token.as_bytes()],
                    now,
                )
            }
            None => self.seal_role(binding, ROLE_RELAYED, &[upstream_token.as_bytes()], now),
        }
    }

    /// Opens a token sealed by [`Self::seal_relayed`] for an identical
    /// binding and returns the upstream token. With `upstream_query`, the
    /// query the provider composed for this page must be the one the token
    /// was sealed with; otherwise [`ContinuationError::UpstreamQueryChanged`]
    /// rejects it before the upstream sees it.
    pub fn open_relayed(
        &self,
        binding: &ContinuationBinding,
        upstream_query: Option<&[u8]>,
        token: &str,
    ) -> Result<String, ContinuationError> {
        self.open_relayed_at(binding, upstream_query, token, SystemTime::now())
    }

    /// [`Self::open_relayed`] at `now`.
    pub fn open_relayed_at(
        &self,
        binding: &ContinuationBinding,
        upstream_query: Option<&[u8]>,
        token: &str,
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        let role = if upstream_query.is_some() {
            ROLE_RELAYED_WITH_QUERY
        } else {
            ROLE_RELAYED
        };
        let mut payload = self.open_admitted(binding, role, token, now)?;
        if let Some(query) = upstream_query {
            if payload.len() < UPSTREAM_QUERY_COMMITMENT_BYTES {
                return Err(ContinuationError::Invalid);
            }
            let expected = self.upstream_query_commitment(binding, query)?;
            if !bool::from(
                expected
                    .as_slice()
                    .ct_eq(&payload[..UPSTREAM_QUERY_COMMITMENT_BYTES]),
            ) {
                return Err(ContinuationError::UpstreamQueryChanged);
            }
            payload.drain(..UPSTREAM_QUERY_COMMITMENT_BYTES);
        }
        String::from_utf8(payload).map_err(|_| ContinuationError::Invalid)
    }

    /// A keyed commitment to `value` under `binding` and `label`, for a
    /// provider to carry in its payload and check later with
    /// [`Self::verify_commitment`] against a value it learns again, such as a
    /// digest of upstream content already consumed. It reveals nothing about
    /// `value` without the key, so a leaked token cannot test guesses offline.
    pub fn commit<Stage: ContinuationStage>(
        &self,
        binding: &ContinuationBinding<Stage>,
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
    pub fn verify_commitment<Stage: ContinuationStage>(
        &self,
        binding: &ContinuationBinding<Stage>,
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

    /// Seals the concatenated `parts` as one payload under `role`, after the
    /// header and, for a family opened during scope resolution, the admitted
    /// owner's commitment.
    fn seal_role(
        &self,
        binding: &ContinuationBinding,
        role: u8,
        parts: &[&[u8]],
        now: SystemTime,
    ) -> Result<String, ContinuationError> {
        let family = binding.family;
        let payload_len = parts.iter().map(|part| part.len()).sum::<usize>();
        let max_payload_bytes = family.max_payload_bytes();
        if payload_len > max_payload_bytes {
            return Err(ContinuationError::PayloadTooLarge {
                limit: max_payload_bytes,
            });
        }
        let mut body = Vec::with_capacity(family.raw_overhead() + payload_len);
        body.push(family.version);
        if let Some(time_to_live) = family.time_to_live {
            let expires_at = unix_seconds(now).saturating_add(time_to_live.as_secs());
            body.extend_from_slice(&expires_at.to_be_bytes());
        }
        if family.scope_resolved {
            let owner = &binding.stage.owner;
            body.extend_from_slice(&self.owner_commitment(
                binding,
                owner.mode,
                &owner.principal,
                owner.authenticated,
            )?);
        }
        for part in parts {
            body.extend_from_slice(part);
        }
        let mac = self.mac(&family, &binding.mac_context(role, None), &body)?;
        body.extend_from_slice(&mac);
        let token = format!("{}{}", family.token_prefix, URL_SAFE_NO_PAD.encode(&body));
        // The encoded cap is derived from the payload cap checked above.
        debug_assert!(token.len() <= family.max_token_bytes());
        Ok(token)
    }

    /// Opens a token under `role` for an admitted binding, checking a
    /// family opened during scope resolution against the admitted owner.
    fn open_admitted(
        &self,
        binding: &ContinuationBinding,
        role: u8,
        token: &str,
        now: SystemTime,
    ) -> Result<Vec<u8>, ContinuationError> {
        let opened = self.open_role(binding, role, token, now)?;
        if binding.family.scope_resolved {
            let owner = &binding.stage.owner;
            let expected =
                self.owner_commitment(binding, owner.mode, &owner.principal, owner.authenticated)?;
            if !bool::from(expected.as_slice().ct_eq(&opened.owner)) {
                return Err(ContinuationError::Invalid);
            }
        }
        Ok(opened.payload)
    }

    fn open_role<Stage: ContinuationStage>(
        &self,
        binding: &ContinuationBinding<Stage>,
        role: u8,
        token: &str,
        now: SystemTime,
    ) -> Result<Opened, ContinuationError> {
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
        let expected = self.mac(&family, &binding.mac_context(role, None), body)?;
        if !bool::from(expected.as_slice().ct_eq(mac)) {
            return Err(ContinuationError::Invalid);
        }
        if let Some(time_to_live) = family.time_to_live {
            let offset = family.expiry_offset();
            let expires_at = u64::from_be_bytes(
                body[offset..offset + EXPIRY_BYTES]
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
        let owner = if family.scope_resolved {
            let offset = family.owner_offset();
            body[offset..offset + OWNER_COMMITMENT_BYTES].to_vec()
        } else {
            Vec::new()
        };
        let payload = &body[family.header_bytes()..];
        if payload.len() > family.max_payload_bytes() {
            return Err(ContinuationError::Invalid);
        }
        Ok(Opened {
            owner,
            payload: payload.to_vec(),
        })
    }

    /// The keyed commitment to a token's owner: the credential mode and, when
    /// the family's owner policy binds it in that mode, the principal and
    /// whether it authenticated.
    fn owner_commitment<Stage: ContinuationStage>(
        &self,
        binding: &ContinuationBinding<Stage>,
        mode: CredentialMode,
        principal: &str,
        authenticated: bool,
    ) -> Result<[u8; 32], ContinuationError> {
        let mut owner = OWNER_DOMAIN.to_vec();
        push_length_prefixed(&mut owner, mode.as_str().as_bytes());
        if binding.family.owner.binds_principal(mode) {
            owner.push(1);
            push_length_prefixed(&mut owner, principal.as_bytes());
            owner.push(u8::from(authenticated));
        } else {
            owner.push(0);
        }
        self.mac(
            &binding.family,
            &binding.mac_context(ROLE_OWNER, None),
            &owner,
        )
    }

    fn upstream_query_commitment(
        &self,
        binding: &ContinuationBinding,
        query: &[u8],
    ) -> Result<[u8; 32], ContinuationError> {
        self.mac(
            &binding.family,
            &binding.mac_context(ROLE_UPSTREAM_QUERY, None),
            query,
        )
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

/// An authentic token's ownership commitment (empty unless the family is
/// opened during scope resolution) and payload.
struct Opened {
    owner: Vec<u8>,
    payload: Vec<u8>,
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
    /// tampered, signed by another key or family, issued for a different
    /// context, caller, configuration, resource or setting, or owned by
    /// another caller. Binding fields never enter the token, so a changed
    /// binding is indistinguishable from forgery.
    #[error("continuation token is not valid for this request")]
    Invalid,
    /// The token names a version other than the family's current one.
    /// Obsolete tokens are never decoded.
    #[error("continuation token version is not supported")]
    UnsupportedVersion,
    /// An authentic token for this binding whose expiry has passed.
    #[error("continuation token has expired")]
    Expired,
    /// An authentic relayed token for this binding whose upstream query
    /// differs from the one the provider composed for this page, such as
    /// after an authorization change rewrote it. The upstream token belongs
    /// to the old query and is never sent with the new one.
    #[error("continuation token belongs to a different upstream query")]
    UpstreamQueryChanged,
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
            Self::Invalid
                | Self::UnsupportedVersion
                | Self::Expired
                | Self::UpstreamQueryChanged
                | Self::TokenTooLarge { .. }
        )
    }
}

const fn unpadded_base64_len(bytes: usize) -> usize {
    match bytes.checked_mul(4) {
        Some(quadrupled) => quadrupled.div_ceil(3),
        None => usize::MAX,
    }
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
            .identity(InvocationIdentity::new("alice".to_string(), true))
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
                .identity(InvocationIdentity::new("alice".to_string(), false))
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
    fn runtime_payload_caps_may_exceed_the_const_ceiling() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let relayed = PAGES.with_max_payload_bytes(MAX_PAYLOAD_CAP + 1024);
        assert_eq!(relayed.max_payload_bytes(), MAX_PAYLOAD_CAP + 1024);
        let largest = vec![0x5a; relayed.max_payload_bytes()];
        let token = signer.seal(&binding(&relayed, &request), &largest).unwrap();
        assert_eq!(token.len(), relayed.max_token_bytes());
        assert_eq!(
            signer.open(&binding(&relayed, &request), &token).unwrap(),
            largest
        );
        assert_eq!(
            signer.seal(
                &binding(&relayed, &request),
                &vec![0; relayed.max_payload_bytes() + 1]
            ),
            Err(ContinuationError::PayloadTooLarge {
                limit: relayed.max_payload_bytes()
            })
        );
        // The cap is part of the family, so a smaller one rejects the token.
        assert_eq!(
            signer.open(&binding(&PAGES, &request), &token),
            Err(ContinuationError::TokenTooLarge {
                limit: PAGES.max_token_bytes()
            })
        );
        // Unbounded caps saturate instead of overflowing.
        assert_eq!(
            PAGES.with_max_payload_bytes(usize::MAX).max_token_bytes(),
            usize::MAX
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

    const HANDLES: ContinuationFamily =
        ContinuationFamily::new("svc", "handle", 1, ContinuationLifetime::Durable, 16)
            .owner(ContinuationOwner::PerUserCaller)
            .shared_across_actions()
            .opened_during_scope_resolution()
            .token_prefix("aab_svc_handle_");

    fn admitted(mode: CredentialMode, principal: &str) -> ProviderInvocation {
        InvocationBuilder::new("svc", "item.view")
            .credential_mode(mode)
            .identity(InvocationIdentity::new(principal.to_string(), true))
            .build()
    }

    fn scope_fixture(principal: &str, context: &str) -> crate::test_support::ScopeRequestFixture {
        scope_fixture_for("item.update", principal, context)
    }

    fn scope_fixture_for(
        action: &str,
        principal: &str,
        context: &str,
    ) -> crate::test_support::ScopeRequestFixture {
        crate::test_support::ScopeRequestFixture::new("svc", action, serde_json::json!({}))
            .execution_context(context)
            .identity(InvocationIdentity::new(principal.to_string(), true))
    }

    fn handle_binding(request: &ProviderInvocation) -> ContinuationBinding {
        HANDLES
            .bind(request.context(), "tenant-a")
            .text("item", "42")
    }

    #[test]
    fn scope_resolution_bindings_open_admitted_tokens_for_possible_owners() {
        let signer = ContinuationSigner::new(Some(test_signing_key(4)));
        let service_alice = admitted(CredentialMode::Service, "alice");
        let shared = signer
            .seal(&handle_binding(&service_alice), b"space=ENG")
            .unwrap();
        assert!(shared.starts_with("aab_svc_handle_"));
        let open_in_scope = |principal: &str, context: &str, token: &str| {
            let fixture = scope_fixture(principal, context);
            let binding = HANDLES
                .bind_scope(&fixture.request(), "tenant-a")
                .text("item", "42");
            signer.open_during_scope_resolution(&binding, token)
        };
        // A service-mode token may be shared: any principal may resolve it,
        // in the context and configuration it was issued for.
        for principal in ["alice", "bob"] {
            assert_eq!(
                open_in_scope(principal, "internal", &shared).unwrap(),
                b"space=ENG"
            );
        }
        assert_eq!(
            open_in_scope("alice", "external", &shared),
            Err(ContinuationError::Invalid)
        );
        let fixture = scope_fixture("alice", "internal");
        for binding in [
            HANDLES
                .bind_scope(&fixture.request(), "tenant-b")
                .text("item", "42"),
            HANDLES
                .bind_scope(&fixture.request(), "tenant-a")
                .text("item", "43"),
        ] {
            assert_eq!(
                signer.open_during_scope_resolution(&binding, &shared),
                Err(ContinuationError::Invalid)
            );
        }
        // After admission it opens for any service-mode principal and action,
        // never in per-user mode.
        let service_bob = InvocationBuilder::from(admitted(CredentialMode::Service, "bob"))
            .action("item.delete")
            .build();
        assert_eq!(
            signer.open(&handle_binding(&service_bob), &shared).unwrap(),
            b"space=ENG"
        );
        assert_eq!(
            signer.open(
                &handle_binding(&admitted(CredentialMode::PerUser, "alice")),
                &shared
            ),
            Err(ContinuationError::Invalid)
        );

        // A per-user token belongs to its principal at every stage.
        let per_user_alice = admitted(CredentialMode::PerUser, "alice");
        let owned = signer
            .seal(&handle_binding(&per_user_alice), b"space=OPS")
            .unwrap();
        assert_eq!(
            open_in_scope("alice", "internal", &owned).unwrap(),
            b"space=OPS"
        );
        assert_eq!(
            open_in_scope("bob", "internal", &owned),
            Err(ContinuationError::Invalid)
        );
        assert_eq!(
            signer
                .open(&handle_binding(&per_user_alice), &owned)
                .unwrap(),
            b"space=OPS"
        );
        for other in [
            admitted(CredentialMode::PerUser, "bob"),
            admitted(CredentialMode::Service, "alice"),
            InvocationBuilder::from(per_user_alice.clone())
                .identity(InvocationIdentity::new("alice".to_string(), false))
                .build(),
            InvocationBuilder::from(per_user_alice.clone())
                .execution_context("external")
                .build(),
        ] {
            assert_eq!(
                signer.open(&handle_binding(&other), &owned),
                Err(ContinuationError::Invalid)
            );
        }
    }

    #[test]
    fn caller_owned_scope_tokens_bind_the_principal_in_both_modes() {
        let signer = ContinuationSigner::new(None);
        let family =
            ContinuationFamily::new("svc", "lease", 1, ContinuationLifetime::Generation, 4)
                .opened_during_scope_resolution();
        let request = admitted(CredentialMode::Service, "alice");
        let token = signer
            .seal(&family.bind(request.context(), "c"), b"p")
            .unwrap();
        let open_in_scope = |action: &str, principal: &str| {
            let fixture = scope_fixture_for(action, principal, "internal");
            signer.open_during_scope_resolution(&family.bind_scope(&fixture.request(), "c"), &token)
        };
        assert_eq!(open_in_scope("item.view", "alice").unwrap(), b"p");
        assert_eq!(
            open_in_scope("item.view", "bob"),
            Err(ContinuationError::Invalid)
        );
        // An action-bound family binds the action at scope resolution too.
        assert_eq!(
            open_in_scope("item.update", "alice"),
            Err(ContinuationError::Invalid)
        );
        assert_eq!(
            signer.open(
                &family.bind(admitted(CredentialMode::Service, "bob").context(), "c"),
                &token
            ),
            Err(ContinuationError::Invalid)
        );
    }

    #[test]
    fn scope_resolution_tokens_keep_family_version_and_durable_key_rules() {
        let key = test_signing_key(4);
        let signer = ContinuationSigner::new(Some(key.clone()));
        let request = admitted(CredentialMode::Service, "alice");
        let token = signer.seal(&handle_binding(&request), b"h").unwrap();
        // 1 version + 32 owner commitment + 16 payload + 32 MAC bytes.
        assert_eq!(HANDLES.max_token_bytes(), 15 + 108);
        let largest = signer.seal(&handle_binding(&request), &[7; 16]).unwrap();
        assert_eq!(largest.len(), HANDLES.max_token_bytes());
        // Another instance with the same stable key opens it (durable).
        assert_eq!(
            ContinuationSigner::new(Some(key))
                .open(&handle_binding(&request), &token)
                .unwrap(),
            b"h"
        );
        let fixture = scope_fixture("alice", "internal");
        let scope = HANDLES
            .bind_scope(&fixture.request(), "tenant-a")
            .text("item", "42");
        // Without a stable key, durable handles fail explicitly.
        let local = ContinuationSigner::new(None);
        assert_eq!(
            local.open_during_scope_resolution(&scope, &token),
            Err(ContinuationError::DurableKeyUnavailable)
        );
        assert_eq!(
            local.seal(&handle_binding(&request), b"h"),
            Err(ContinuationError::DurableKeyUnavailable)
        );
        // A newer version rejects the old token by version.
        let next = ContinuationFamily::new("svc", "handle", 2, ContinuationLifetime::Durable, 16)
            .owner(ContinuationOwner::PerUserCaller)
            .shared_across_actions()
            .opened_during_scope_resolution()
            .token_prefix("aab_svc_handle_");
        assert_eq!(
            signer.open_during_scope_resolution(
                &next
                    .bind_scope(&fixture.request(), "tenant-a")
                    .text("item", "42"),
                &token
            ),
            Err(ContinuationError::UnsupportedVersion)
        );
        // An ordinary family's tokens never open as scope-resolution tokens,
        // and its scope bindings open nothing.
        let ordinary = PAGES.lifetime_for_tests(ContinuationLifetime::Durable);
        let ordinary_token = signer
            .seal(&ordinary.bind(request.context(), "tenant-a"), b"h")
            .unwrap();
        assert_eq!(
            signer.open(&handle_binding(&request), &ordinary_token),
            Err(ContinuationError::Invalid)
        );
    }

    #[test]
    fn relayed_tokens_commit_the_upstream_query_and_open_only_as_relayed() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        let family = ContinuationFamily::new(
            "svc",
            "search-page",
            1,
            ContinuationLifetime::Generation,
            64,
        )
        .expires_after(TTL);
        let bound = binding(&family, &request);
        let token = signer
            .seal_relayed(&bound, Some(b"q AND scope"), "upstream-2")
            .unwrap();
        assert_eq!(
            signer
                .open_relayed(&bound, Some(b"q AND scope"), &token)
                .unwrap(),
            "upstream-2"
        );
        // A recomposed query is a distinct rejection, before the upstream.
        assert_eq!(
            signer.open_relayed(&bound, Some(b"q AND other"), &token),
            Err(ContinuationError::UpstreamQueryChanged)
        );
        assert!(ContinuationError::UpstreamQueryChanged.is_token_rejection());
        // Query-committed, plain relayed and ordinary tokens never cross.
        assert_eq!(
            signer.open_relayed(&bound, None, &token),
            Err(ContinuationError::Invalid)
        );
        assert_eq!(signer.open(&bound, &token), Err(ContinuationError::Invalid));
        let plain = signer.seal_relayed(&bound, None, "upstream-2").unwrap();
        assert_eq!(
            signer.open_relayed(&bound, None, &plain).unwrap(),
            "upstream-2"
        );
        assert_eq!(
            signer.open_relayed(&bound, Some(b"q AND scope"), &plain),
            Err(ContinuationError::Invalid)
        );
        let ordinary = signer.seal(&bound, b"upstream-2").unwrap();
        assert_eq!(
            signer.open_relayed(&bound, None, &ordinary),
            Err(ContinuationError::Invalid)
        );
        // The binding still decides: another caller gets Invalid, not a
        // query change.
        let other = binding(
            &family,
            &InvocationBuilder::from(invocation())
                .principal("bob")
                .build(),
        );
        assert_eq!(
            signer.open_relayed(&other, Some(b"q AND scope"), &token),
            Err(ContinuationError::Invalid)
        );
        // The commitment counts toward the payload cap; nothing truncates.
        let cap = family.max_payload_bytes();
        assert!(signer.seal_relayed(&bound, None, &"u".repeat(cap)).is_ok());
        assert_eq!(
            signer.seal_relayed(&bound, Some(b"q"), &"u".repeat(cap - 31)),
            Err(ContinuationError::PayloadTooLarge {
                limit: cap - UPSTREAM_QUERY_COMMITMENT_BYTES
            })
        );
        assert!(
            signer
                .seal_relayed(&bound, Some(b"q"), &"u".repeat(cap - 32))
                .is_ok()
        );
        // A cap that cannot hold the commitment relays no token at all.
        let tiny = binding(&family.with_max_payload_bytes(31), &request);
        assert_eq!(
            signer.seal_relayed(&tiny, Some(b"q"), ""),
            Err(ContinuationError::PayloadTooLarge { limit: 0 })
        );
        // The upstream token is integrity-protected, not hidden.
        let raw = URL_SAFE_NO_PAD.decode(&plain).unwrap();
        assert!(raw.windows(10).any(|w| w == b"upstream-2"));
        assert!(
            !URL_SAFE_NO_PAD
                .decode(&token)
                .unwrap()
                .windows(5)
                .any(|w| w == b"scope")
        );
    }

    #[test]
    fn relayed_tokens_of_scope_resolution_families_check_the_admitted_owner() {
        let signer = ContinuationSigner::new(Some(test_signing_key(4)));
        let per_user = admitted(CredentialMode::PerUser, "alice");
        let token = signer
            .seal_relayed(&handle_binding(&per_user), None, "cursor")
            .unwrap();
        assert_eq!(
            signer
                .open_relayed(&handle_binding(&per_user), None, &token)
                .unwrap(),
            "cursor"
        );
        assert_eq!(
            signer.open_relayed(
                &handle_binding(&admitted(CredentialMode::PerUser, "bob")),
                None,
                &token
            ),
            Err(ContinuationError::Invalid)
        );
    }

    #[test]
    fn payloads_within_a_token_bound_fit_it_exactly() {
        let signer = ContinuationSigner::new(None);
        let request = invocation();
        for bound in [0_usize, 40, 98, 99, 100, 101, 4_096, 70_000, 1 << 20] {
            for declared in [
                ContinuationFamily::new("svc", "list-page", 1, ContinuationLifetime::Generation, 0),
                ContinuationFamily::new("svc", "list-page", 1, ContinuationLifetime::Generation, 0)
                    .expires_after(TTL)
                    .token_prefix("aab_"),
                ContinuationFamily::new("svc", "list-page", 1, ContinuationLifetime::Generation, 0)
                    .opened_during_scope_resolution(),
            ] {
                let family =
                    declared.with_max_payload_bytes(declared.max_payload_bytes_within(bound));
                let cap = family.max_payload_bytes();
                let token = signer
                    .seal(&binding(&family, &request), &vec![1; cap])
                    .unwrap();
                assert_eq!(token.len(), family.max_token_bytes(), "{family:?}");
                if cap > 0 {
                    assert!(token.len() <= bound, "{family:?}");
                    // One more payload byte would not fit the bound.
                    let one_more = family.raw_overhead() + cap + 1;
                    assert!(
                        family.token_prefix.len() + unpadded_base64_len(one_more) > bound,
                        "{family:?}"
                    );
                }
            }
        }
        // The default response limit, beyond the declared-cap ceiling.
        let response = 512 * 1024 * 1024;
        let large = PAGES.with_max_payload_bytes(PAGES.max_payload_bytes_within(response));
        assert!(large.max_payload_bytes() > MAX_PAYLOAD_CAP);
        assert_eq!(large.max_token_bytes(), response);
        assert!(PAGES.max_payload_bytes_within(usize::MAX) > 0);
    }

    impl ContinuationFamily {
        const fn lifetime_for_tests(mut self, lifetime: ContinuationLifetime) -> Self {
            self.lifetime = lifetime;
            self
        }
    }
}
