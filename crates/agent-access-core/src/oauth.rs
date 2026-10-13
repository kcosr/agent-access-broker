//! Delegated OAuth lifecycle: consent flows, encrypted refresh material,
//! refresh coordination, fences, and budgets. Each registration's wire
//! protocol comes from its registered dialect.
//! Provider material never crosses the Broker credential boundary.
mod lease;

pub(crate) use lease::ManagedOAuthLease;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::network::{ClientCaller, HostNetwork};
use crate::{BackendRegistry, CredentialKeyRing, ManagedStore, ManagedStoreError};
use agent_access_provider::{
    AuthorizationRequest, CodeExchange, InvocationScope, IssuedRefreshToken, OAuthCallbackIssuer,
    OAuthClient, OAuthDialect, OAuthDialectError, OAuthHttp, OAuthPermissionProfile,
    OAuthRegistrationConfig, OAuthScopeMode, OAuthTarget, RefreshReplay, TokenGrant,
    UPSTREAM_RETRY_AFTER_MAX_SECONDS,
};

const MAX_FLOWS: usize = 1;
const FLOW_TTL: i64 = 300;
const ATTEMPT_TTL: i64 = 45;
const REJECTION_BUDGET: u8 = 3;
/// Cap on the locally computed exponential backoff after failed refreshes.
/// An authorization server's explicit throttling wait is honored beyond it,
/// up to [`UPSTREAM_RETRY_AFTER_MAX_SECONDS`].
const MAX_RETRY_DELAY: u64 = 300;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    #[serde(default)]
    pub registrations: BTreeMap<String, OAuthRegistrationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthBinding {
    pub registration: String,
    pub permission_profile: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthConnectIntent {
    #[default]
    Connect,
    Reconnect,
    ReplaceAccount,
}

/// Characters escaped in a portal path segment: everything but RFC 3986 unreserved.
const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Fixed portal destinations; caller-supplied URLs never become redirects.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OAuthReturnPath {
    /// My access › Credentials.
    #[serde(rename = "/ui/credentials")]
    Credentials,
    /// Admin › Catalog: the initiating imported service's Import tab.
    #[serde(rename = "/ui/admin/catalog")]
    Catalog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthManagementAdmission {
    pub service: String,
    pub credential_name: String,
    #[serde(default)]
    pub imported_service_version: Option<u64>,
    #[serde(default)]
    pub return_path: Option<OAuthReturnPath>,
}

/// Loads current published configuration without acquiring policy or reload
/// locks. Consent calls retain this resolver, never the request's snapshot.
pub type OAuthRuntimeResolver = Arc<dyn Fn() -> Arc<crate::BrokerRuntime> + Send + Sync>;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthConnectStart {
    pub authorization_url: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthConnectionStatus {
    Ready,
    ReconnectRequired,
    OperatorActionRequired,
    Disconnected,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthConnection {
    pub registration: String,
    pub connection_id: Option<String>,
    pub subject_id: Option<String>,
    pub display_name: Option<String>,
    pub status: OAuthConnectionStatus,
    pub reason: Option<String>,
    pub targets: Vec<OAuthTarget>,
}

#[derive(Clone)]
pub struct OAuthLease {
    token: String,
    owner: String,
    binding: OAuthBinding,
    config_fingerprint: String,
    generation: String,
    connection_id: String,
    access_version: String,
    target: String,
    audience: String,
    expires_at: i64,
}
impl std::fmt::Debug for OAuthLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthLease")
            .field("connection_id", &self.connection_id)
            .field("access_version", &self.access_version)
            .finish_non_exhaustive()
    }
}
impl OAuthLease {
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn access_version(&self) -> &str {
        &self.access_version
    }
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth configuration is invalid")]
    Configuration,
    #[error("OAuth application credential is unavailable")]
    ApplicationCredential,
    #[error("OAuth storage is unavailable")]
    Storage,
    #[error("OAuth principal is unavailable")]
    Principal,
    #[error("OAuth browser transaction is invalid or expired")]
    InvalidFlow,
    #[error("OAuth connection changed; restart the operation")]
    Stale,
    #[error("OAuth account identity does not match the connected account")]
    IdentityMismatch,
    #[error("OAuth target or permission is not authorized")]
    Permission,
    #[error("OAuth personal connection setup is not authorized")]
    SetupDenied,
    #[error("self-service is disabled")]
    SelfServiceDisabled,
    #[error("OAuth reconnect is required")]
    ReconnectRequired,
    #[error("OAuth refresh outcome is uncertain; reconnect is required")]
    RefreshUncertain,
    #[error("OAuth refresh is already in progress")]
    RefreshBusy,
    #[error("OAuth provider request failed")]
    Provider,
    #[error("OAuth provider could not be reached before sending the request")]
    BeforeSend,
    #[error("OAuth provider rejected the token request")]
    RequestRejected,
    /// The provider throttled refresh; retry after this many seconds.
    #[error("OAuth provider requested a bounded retry delay")]
    RetryLater(u64),
    /// Refresh is paused for `seconds` after a failed attempt; `failure` is
    /// the error that failed it. Never throttling: see [`Self::RetryLater`].
    #[error("OAuth refresh is paused after a failed attempt")]
    RefreshPaused {
        seconds: u64,
        failure: Box<OAuthError>,
    },
    #[error("OAuth consent is pending")]
    ConsentPending,
    #[error("OAuth provider returned an invalid response")]
    InvalidResponse,
    #[error("OAuth provider throttled the request")]
    Throttled,
    #[error("OAuth pending transaction limit reached")]
    FlowLimit,
}
impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "oauth_configuration_invalid",
            Self::ApplicationCredential => "oauth_application_credential",
            Self::Storage => "oauth_storage_unavailable",
            Self::Principal => "oauth_principal_unavailable",
            Self::InvalidFlow => "oauth_flow_invalid",
            Self::Stale => "oauth_stale",
            Self::IdentityMismatch => "oauth_identity_mismatch",
            Self::Permission => "oauth_permission_denied",
            Self::SetupDenied => "oauth_setup_denied",
            Self::SelfServiceDisabled => "self_service_disabled",
            Self::ReconnectRequired => "oauth_reconnect_required",
            Self::RefreshUncertain => "oauth_refresh_uncertain",
            Self::RefreshBusy => "oauth_refresh_busy",
            Self::Provider => "oauth_provider_failed",
            Self::BeforeSend => "oauth_provider_unavailable",
            Self::RequestRejected => "oauth_request_rejected",
            Self::RetryLater(_) => "oauth_throttled",
            Self::RefreshPaused { failure, .. } => failure.code(),
            Self::ConsentPending => "oauth_consent_pending",
            Self::InvalidResponse => "oauth_response_invalid",
            Self::Throttled => "oauth_throttled",
            Self::FlowLimit => "oauth_flow_limit",
        }
    }
}
impl From<OAuthDialectError> for OAuthError {
    fn from(error: OAuthDialectError) -> Self {
        match error {
            OAuthDialectError::NotSent => Self::BeforeSend,
            OAuthDialectError::Failed => Self::Provider,
            OAuthDialectError::InvalidResponse => Self::InvalidResponse,
            OAuthDialectError::RetryAfter(seconds) => Self::RetryLater(seconds),
            OAuthDialectError::Throttled => Self::Throttled,
            OAuthDialectError::PermissionRejected => Self::Permission,
            OAuthDialectError::RequestRejected => Self::RequestRejected,
            OAuthDialectError::GrantInvalid => Self::ReconnectRequired,
            OAuthDialectError::ClientRejected => Self::ApplicationCredential,
            OAuthDialectError::Configuration => Self::Configuration,
        }
    }
}
impl From<ManagedStoreError> for OAuthError {
    fn from(_: ManagedStoreError) -> Self {
        Self::Storage
    }
}

impl OAuthConfig {
    pub fn validate(&self) -> Result<(), OAuthError> {
        if self.registrations.len() > 32 {
            return Err(OAuthError::Configuration);
        }
        for (name, registration) in &self.registrations {
            if !identifier(name)
                || registration.client_id.is_empty()
                || registration.client_id.len() > 512
                || registration.permission_profiles.is_empty()
                || registration.permission_profiles.len() > 16
            {
                return Err(OAuthError::Configuration);
            }
            checked_url(&registration.base_url, registration.allow_insecure_loopback)?;
            checked_url(
                &registration.redirect_uri,
                registration.allow_insecure_loopback,
            )?;
            let reference = &registration.client_secret_ref;
            if registration.client_auth == agent_access_provider::OAuthClientAuth::None {
                if !reference.is_empty() {
                    return Err(OAuthError::Configuration);
                }
            } else if !reference.strip_prefix("env:").is_some_and(identifier)
                && !reference
                    .strip_prefix("file:")
                    .is_some_and(|p| std::path::Path::new(p).is_absolute())
            {
                return Err(OAuthError::Configuration);
            }
            let scope_mode = registration
                .permission_profiles
                .values()
                .next()
                .unwrap()
                .scope_mode;
            for (id, profile) in &registration.permission_profiles {
                if !identifier(id)
                    || !bounded(&profile.target, 256)
                    || !bounded(&profile.audience, 256)
                    || profile.scope_mode != scope_mode
                {
                    return Err(OAuthError::Configuration);
                }
                match profile.scope_mode {
                    OAuthScopeMode::Explicit => {
                        let scopes = profile.requested_scopes();
                        if scopes.is_empty()
                            || scopes.len() > 64
                            || !scopes
                                .iter()
                                .all(|s| bounded(s, 256) && !s.chars().any(char::is_whitespace))
                            || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len()
                        {
                            return Err(OAuthError::Configuration);
                        }
                    }
                    OAuthScopeMode::ServerDefault if profile.scopes.is_some() => {
                        return Err(OAuthError::Configuration);
                    }
                    OAuthScopeMode::ServerDefault => {}
                }
            }
        }
        Ok(())
    }
}
/// Identifies a registration's authority. Stored connections are discarded
/// when it changes, so its encoding must never drift. Secret rotation does not
/// alter authority, consent, or the refresh lifecycle.
fn registration_fingerprint(registration: &OAuthRegistrationConfig) -> Result<String, OAuthError> {
    let mut identity_config = registration.clone();
    identity_config.client_secret_ref.clear();
    Ok(digest(
        serde_json::to_vec(&identity_config).map_err(|_| OAuthError::Configuration)?,
    ))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
}
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn checked_url(raw: &str, insecure: bool) -> Result<Url, OAuthError> {
    let url = Url::parse(raw).map_err(|_| OAuthError::Configuration)?;
    let loopback = agent_access_provider::is_literal_loopback(&url);
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || (url.scheme() != "https" && !(insecure && loopback && url.scheme() == "http"))
    {
        return Err(OAuthError::Configuration);
    }
    Ok(url)
}
fn digest(data: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(data.as_ref()))
}
fn random_secret() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}
fn now() -> i64 {
    // Wall-clock rollback must not extend a live process's access or browser-flow deadlines.
    // Absolute UTC expirations remain durable across restart; in-process passage uses Instant.
    static CLOCK: OnceLock<Mutex<(Instant, i64)>> = OnceLock::new();
    let wall = Utc::now().timestamp();
    let mut clock = CLOCK
        .get_or_init(|| Mutex::new((Instant::now(), wall)))
        .lock()
        .expect("OAuth clock");
    let elapsed = i64::try_from(clock.0.elapsed().as_secs()).unwrap_or(i64::MAX);
    let monotonic = clock.1.saturating_add(elapsed);
    if wall > monotonic {
        *clock = (Instant::now(), wall);
        wall
    } else {
        monotonic
    }
}

// These are encrypted, bounded typed records; never serialize them into management responses.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotState {
    pub generation: String,
    pub config_fingerprint: String,
    pub credential_revision: String,
    pub flows: BTreeMap<String, Flow>,
    pub connection: Option<ConnectionState>,
}
impl SlotState {
    fn empty(fingerprint: &str, credential_revision: &str) -> Self {
        Self {
            generation: Uuid::new_v4().to_string(),
            config_fingerprint: fingerprint.into(),
            credential_revision: credential_revision.into(),
            flows: BTreeMap::new(),
            connection: None,
        }
    }
    /// Non-secret semantic identity used to fence import discovery previews.
    /// Encryption nonces, refresh cooldowns and bookkeeping do not change it.
    pub(crate) fn discovery_revision(&self) -> String {
        let connection = self.connection.as_ref().map(|c| {
            let access = c
                .family
                .access
                .iter()
                .map(|(profile, entry)| (profile, &entry.version))
                .collect::<Vec<_>>();
            serde_json::json!([
                c.id,
                c.status,
                c.revalidation,
                c.family.id,
                c.family.material_version,
                c.family.targets,
                c.family.consent_scopes,
                access
            ])
        });
        digest(
            serde_json::to_string(&(&self.generation, &self.config_fingerprint, connection))
                .expect("typed revision"),
        )
    }

    pub(crate) fn reconcile_credential(&mut self, revision: &str) {
        if self.credential_revision != revision {
            self.credential_revision = revision.into();
            if let Some(connection) = &mut self.connection
                && connection.status == OAuthConnectionStatus::OperatorActionRequired
                && connection.reason.as_deref() == Some("oauth_application_credential")
            {
                connection.status = OAuthConnectionStatus::Ready;
                connection.reason = None;
                connection.family.reset_failures();
            }
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Flow {
    session_hash: String,
    verifier: String,
    expires_at: i64,
    profile: String,
    generation: String,
    intent: OAuthConnectIntent,
    consumed: bool,
    admission: OAuthManagementAdmission,
    // Older pending flows must restart; no issuer-validation fallback.
    #[serde(default)]
    expected_issuer: Option<OAuthCallbackIssuer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectionState {
    id: String,
    subject: Option<String>,
    display_name: String,
    status: OAuthConnectionStatus,
    reason: Option<String>,
    revalidation: ConsentRevalidation,
    family: Family,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConsentRevalidation {
    None,
    Required,
    Pending,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Family {
    id: String,
    material_version: String,
    refresh_token: Option<String>,
    // Original consent evidence, never backfilled by refresh. Empty is unknown
    // only under server-default mode, whose meaning is pinned by the slot fingerprint.
    consent_scopes: BTreeSet<String>,
    targets: Vec<OAuthTarget>,
    access: BTreeMap<String, AccessEntry>,
    attempt: Option<RefreshAttempt>,
    retry_not_before: i64,
    retry_count: u8,
    rejection_count: u8,
}
impl Family {
    fn reset_failures(&mut self) {
        self.retry_not_before = 0;
        self.retry_count = 0;
        self.rejection_count = 0;
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessEntry {
    token: String,
    version: String,
    scopes: BTreeSet<String>,
    expires_at: i64,
    refresh_after: i64,
    targets_validated: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshAttempt {
    id: String,
    material_version: String,
    expires_at: i64,
}

struct ResolvedRegistration {
    id: String,
    credential_revision: String,
    config: OAuthRegistrationConfig,
    secret: String,
    fingerprint: String,
    dialect: &'static dyn OAuthDialect,
    http: OAuthHttp,
}

impl ResolvedRegistration {
    fn client(&self) -> OAuthClient<'_> {
        OAuthClient {
            registration_id: &self.id,
            config: &self.config,
            client_secret: &self.secret,
        }
    }
}
type SlotLocks = Mutex<BTreeMap<(String, String), Arc<tokio::sync::Mutex<()>>>>;

/// A saved attempt is live only while the task that created it owns this guard.
/// Other slot operations and discovery cannot lend it an owner accidentally.
struct LiveRefreshAttempt<'a> {
    attempts: &'a Mutex<BTreeSet<String>>,
    id: String,
}

impl<'a> LiveRefreshAttempt<'a> {
    fn new(attempts: &'a Mutex<BTreeSet<String>>, id: &str) -> Self {
        attempts
            .lock()
            .expect("OAuth live refresh attempts")
            .insert(id.into());
        Self {
            attempts,
            id: id.into(),
        }
    }
}

impl Drop for LiveRefreshAttempt<'_> {
    fn drop(&mut self) {
        self.attempts
            .lock()
            .expect("OAuth live refresh attempts")
            .remove(&self.id);
    }
}

struct ManagerInner {
    store: ManagedStore,
    ring: CredentialKeyRing,
    config: OAuthConfig,
    registrations: BTreeMap<String, ResolvedRegistration>,
    locks: SlotLocks,
    live_refresh_attempts: Mutex<BTreeSet<String>>,
    active: AtomicBool,
}
#[derive(Clone)]
pub struct OAuthManager {
    inner: Arc<ManagerInner>,
}
impl std::fmt::Debug for OAuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthManager").finish_non_exhaustive()
    }
}

impl OAuthManager {
    /// Preparation has no database side effects. Call activate only when publishing a validated runtime.
    /// Every registration's clients come from `network` in the host OAuth
    /// category.
    pub(crate) fn new_with_host(
        store: ManagedStore,
        ring: CredentialKeyRing,
        config: OAuthConfig,
        dialects: &BackendRegistry,
        network: &HostNetwork,
    ) -> Result<Self, OAuthError> {
        config.validate()?;
        let clients = network.client_factory(ClientCaller::HostOAuth);
        let mut registrations = BTreeMap::new();
        for (id, registration) in &config.registrations {
            let dialect = dialects
                .oauth_dialect(registration.adapter.as_str())
                .ok_or(OAuthError::Configuration)?
                .dialect();
            if !dialect.supports_server_default_scopes()
                && registration
                    .permission_profiles
                    .values()
                    .any(|profile| profile.scope_mode == OAuthScopeMode::ServerDefault)
            {
                return Err(OAuthError::Configuration);
            }
            dialect
                .validate_registration(registration)
                .map_err(|_| OAuthError::Configuration)?;
            let secret = if registration.client_auth == agent_access_provider::OAuthClientAuth::None
            {
                String::new()
            } else {
                crate::load_secret_ref_value("OAuth application", &registration.client_secret_ref)
                    .map_err(|_| OAuthError::ApplicationCredential)?
            };
            if registration.client_auth != agent_access_provider::OAuthClientAuth::None
                && !bounded(&secret, 16384)
            {
                return Err(OAuthError::ApplicationCredential);
            }
            let fingerprint = registration_fingerprint(registration)?;
            let base = Url::parse(&registration.base_url).map_err(|_| OAuthError::Configuration)?;
            let http = OAuthHttp::build(
                &format!("oauth.registrations.{id}"),
                "oauth",
                &base,
                &dialect.upstream_allowlist(registration),
                &clients,
            )
            .map_err(|_| OAuthError::Configuration)?;
            registrations.insert(
                id.clone(),
                ResolvedRegistration {
                    id: id.clone(),
                    credential_revision: digest(&secret),
                    config: registration.clone(),
                    secret,
                    fingerprint,
                    dialect,
                    http,
                },
            );
        }
        Ok(Self {
            inner: Arc::new(ManagerInner {
                store,
                ring,
                config,
                registrations,
                locks: Mutex::new(BTreeMap::new()),
                live_refresh_attempts: Mutex::new(BTreeSet::new()),
                active: AtomicBool::new(false),
            }),
        })
    }
    pub fn activate(&self) -> Result<(), OAuthError> {
        self.inner.store.oauth_reconcile(
            &self.inner.ring,
            &self
                .inner
                .registrations
                .iter()
                .map(|(id, r)| {
                    (
                        id.clone(),
                        (r.fingerprint.clone(), r.credential_revision.clone()),
                    )
                })
                .collect(),
        )?;
        self.inner.active.store(true, Ordering::Release);
        Ok(())
    }
    pub fn deactivate(&self) {
        self.inner.active.store(false, Ordering::Release);
    }
    pub fn disable_all(store: &ManagedStore) -> Result<(), OAuthError> {
        store.oauth_disable_all()
    }
    pub fn config(&self) -> &OAuthConfig {
        &self.inner.config
    }
    fn active(&self) -> Result<(), OAuthError> {
        if !self.inner.active.load(Ordering::Acquire) {
            return Err(OAuthError::Stale);
        }
        Ok(())
    }
    /// The `iss` a consent callback for `registration` must carry, if its
    /// dialect requires one.
    pub fn callback_issuer(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
    ) -> Result<OAuthCallbackIssuer, OAuthError> {
        self.callback_flow(owner, session, registration, state)?
            .expected_issuer
            .ok_or(OAuthError::InvalidFlow)
    }
    /// Resolve navigation before completing or cancelling the one-use flow.
    pub fn callback_return_path(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
    ) -> Result<String, OAuthError> {
        let flow = self.callback_flow(owner, session, registration, state)?;
        Ok(match flow.admission.return_path {
            Some(OAuthReturnPath::Catalog) => format!(
                "/ui/admin/catalog/services/{}/import",
                percent_encoding::utf8_percent_encode(&flow.admission.service, PATH_SEGMENT)
            ),
            Some(OAuthReturnPath::Credentials) | None => "/ui/credentials".into(),
        })
    }
    fn callback_flow(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
    ) -> Result<Flow, OAuthError> {
        self.active()?;
        let slot = self.read(owner, registration)?;
        let flow = slot
            .flows
            .get(&digest(state))
            .ok_or(OAuthError::InvalidFlow)?;
        if flow.session_hash != digest(session)
            || flow.expires_at <= now()
            || flow.generation != slot.generation
            || flow.consumed
        {
            return Err(OAuthError::InvalidFlow);
        }
        Ok(flow.clone())
    }
    fn registration(&self, id: &str) -> Result<&ResolvedRegistration, OAuthError> {
        self.inner
            .registrations
            .get(id)
            .ok_or(OAuthError::Configuration)
    }
    fn profile(
        &self,
        binding: &OAuthBinding,
    ) -> Result<(&ResolvedRegistration, &OAuthPermissionProfile), OAuthError> {
        let r = self.registration(&binding.registration)?;
        Ok((
            r,
            r.config
                .permission_profiles
                .get(&binding.permission_profile)
                .ok_or(OAuthError::Configuration)?,
        ))
    }
    fn read(&self, owner: &str, registration: &str) -> Result<SlotState, OAuthError> {
        let r = self.registration(registration)?;
        self.inner
            .store
            .oauth_read(&self.inner.ring, owner, registration, &r.fingerprint)?
            .ok_or(OAuthError::ReconnectRequired)
    }
    fn update<T>(
        &self,
        owner: &str,
        registration: &str,
        change: impl FnOnce(
            &rusqlite::Connection,
            Option<SlotState>,
        ) -> Result<(SlotState, T), OAuthError>,
    ) -> Result<T, OAuthError> {
        let r = self.registration(registration)?;
        self.inner.store.oauth_update(
            &self.inner.ring,
            owner,
            registration,
            &r.fingerprint,
            change,
        )
    }
    fn lock(&self, owner: &str, registration: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.inner.locks.lock().expect("OAuth lock registry");
        // Only in-flight callers retain strong references; do not accumulate arbitrary principal IDs.
        locks.retain(|_, value| Arc::strong_count(value) > 1);
        locks
            .entry((owner.into(), registration.into()))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
    pub async fn connect(
        &self,
        owner: &str,
        session: &str,
        binding: &OAuthBinding,
        intent: OAuthConnectIntent,
        admission: OAuthManagementAdmission,
        runtime: OAuthRuntimeResolver,
    ) -> Result<OAuthConnectStart, OAuthError> {
        let lock = self.lock(owner, &binding.registration);
        let _guard = lock.lock().await;
        self.active()?;
        let (r, profile) = self.profile(binding)?;
        match self.read(owner, &binding.registration) {
            Ok(slot) => {
                if intent == OAuthConnectIntent::Reconnect
                    && slot
                        .connection
                        .as_ref()
                        .is_some_and(|c| c.subject.is_none())
                {
                    return Err(OAuthError::IdentityMismatch);
                }
                if let Some(attempt) = slot
                    .connection
                    .as_ref()
                    .and_then(|c| c.family.attempt.as_ref())
                    && attempt.expires_at <= now()
                {
                    self.fail_attempt(
                        owner,
                        &binding.registration,
                        &attempt.id,
                        OAuthError::RefreshUncertain,
                    )?;
                }
            }
            Err(OAuthError::ReconnectRequired) => {}
            Err(error) => return Err(error),
        }
        if !bounded(session, 512)
            || !identifier(&admission.service)
            || !identifier(&admission.credential_name)
        {
            return Err(OAuthError::InvalidFlow);
        }
        let state = random_secret();
        let verifier = random_secret();
        let state_hash = digest(&state);
        let expires_at = now() + FLOW_TTL;
        let prepared = r
            .dialect
            .prepare_authorization(
                &r.http,
                &r.client(),
                profile,
                AuthorizationRequest {
                    state: &state,
                    code_challenge_s256: &URL_SAFE_NO_PAD
                        .encode(Sha256::digest(verifier.as_bytes())),
                },
            )
            .await?;
        self.update(owner, &binding.registration, |conn, current| {
            crate::managed_store::oauth::check_session(conn, owner, session)?;
            crate::managed_store::oauth::check_admission(
                conn,
                owner,
                &admission,
                binding,
                &runtime(),
            )?;
            let mut slot =
                current.unwrap_or_else(|| SlotState::empty(&r.fingerprint, &r.credential_revision));
            if intent == OAuthConnectIntent::Connect && slot.connection.is_some() {
                return Err(OAuthError::Stale);
            }
            if intent == OAuthConnectIntent::Reconnect {
                let connection = slot
                    .connection
                    .as_ref()
                    .ok_or(OAuthError::ReconnectRequired)?;
                if connection.subject.is_none() {
                    return Err(OAuthError::IdentityMismatch);
                }
            }
            slot.flows.retain(|_, f| f.expires_at > now());
            if slot.flows.len() >= MAX_FLOWS {
                return Err(OAuthError::FlowLimit);
            }
            if let Some(connection) = &mut slot.connection {
                if connection.family.attempt.is_some() {
                    return Err(OAuthError::RefreshBusy);
                }
                // Keep the family intact. While consent may change its grant, execution and renewal
                // are suspended, and ending this flow requires fresh provider evidence before reuse.
                if connection.status == OAuthConnectionStatus::Ready
                    && (connection.subject.is_some() || connection.family.refresh_token.is_some())
                {
                    connection.revalidation = ConsentRevalidation::Required;
                }
                // An access-only, identity-less connection cannot be renewed or
                // identity-checked. A cancelled replacement leaves its existing
                // token usable until expiry; pending flows still suspend execution.
            }
            slot.flows.insert(
                state_hash,
                Flow {
                    session_hash: digest(session),
                    verifier,
                    expires_at,
                    profile: binding.permission_profile.clone(),
                    generation: slot.generation.clone(),
                    intent,
                    consumed: false,
                    admission,
                    expected_issuer: Some(prepared.callback_issuer),
                },
            );
            Ok((slot, ()))
        })?;
        tracing::info!(target:"agent_access_core::oauth",event="consent_pending",owner,registration=%binding.registration);
        Ok(OAuthConnectStart {
            authorization_url: prepared.url.to_string(),
            expires_at,
        })
    }
    pub async fn cancel(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
    ) -> Result<(), OAuthError> {
        let lock = self.lock(owner, registration);
        let _guard = lock.lock().await;
        self.active()?;
        self.update(owner, registration, |conn, current| {
            crate::managed_store::oauth::check_session(conn, owner, session)?;
            let mut slot = current.ok_or(OAuthError::InvalidFlow)?;
            let key = digest(state);
            let flow = slot.flows.get(&key).ok_or(OAuthError::InvalidFlow)?;
            if flow.session_hash != digest(session) {
                return Err(OAuthError::InvalidFlow);
            }
            slot.flows.remove(&key);
            Ok((slot, ()))
        })?;
        tracing::info!(target:"agent_access_core::oauth",event="consent_cancelled",owner,registration,outcome="revalidation_required");
        Ok(())
    }
    pub async fn complete(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
        code: &str,
        runtime: OAuthRuntimeResolver,
    ) -> Result<OAuthConnection, OAuthError> {
        self.active()?;
        if code.is_empty() {
            self.cancel(owner, session, registration, state).await?;
            return Err(OAuthError::InvalidFlow);
        }
        if !bounded(code, 16384) || !bounded(state, 256) {
            return Err(OAuthError::InvalidFlow);
        }
        let manager = self.clone();
        let owner = owner.to_owned();
        let session = session.to_owned();
        let registration = registration.to_owned();
        let state = state.to_owned();
        let code = code.to_owned();
        // A disconnected browser waiter cannot interrupt code redemption between consumption and durable install.
        tokio::spawn(InvocationScope::current().run(async move {
            manager
                .complete_inner(&owner, &session, &registration, &state, &code, runtime)
                .await
        }))
        .await
        .map_err(|_| OAuthError::Provider)?
    }
    async fn complete_inner(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        state: &str,
        code: &str,
        runtime: OAuthRuntimeResolver,
    ) -> Result<OAuthConnection, OAuthError> {
        let lock = self.lock(owner, registration);
        let _guard = lock.lock().await;
        self.active()?;
        let key = digest(state);
        let flow = self.update(owner, registration, |conn, current| {
            crate::managed_store::oauth::check_session(conn, owner, session)?;
            let mut slot = current.ok_or(OAuthError::InvalidFlow)?;
            let flow = slot.flows.get_mut(&key).ok_or(OAuthError::InvalidFlow)?;
            if flow.consumed
                || flow.expires_at <= now()
                || flow.session_hash != digest(session)
                || flow.generation != slot.generation
            {
                return Err(OAuthError::InvalidFlow);
            }
            let binding = OAuthBinding {
                registration: registration.into(),
                permission_profile: flow.profile.clone(),
            };
            if let Err(error) = crate::managed_store::oauth::check_admission(
                conn,
                owner,
                &flow.admission,
                &binding,
                &runtime(),
            ) {
                if matches!(error, OAuthError::SetupDenied | OAuthError::Stale) {
                    // Only the exact valid, unclaimed flow may be retired on
                    // deterministic admission loss. Preserve cancellation's
                    // revalidation and generation semantics.
                    slot.flows.remove(&key);
                    return Ok((slot, Err(error)));
                }
                return Err(error);
            }
            flow.consumed = true;
            let out = flow.clone();
            Ok((slot, Ok(out)))
        })??;
        let result = self
            .complete_claimed(owner, session, registration, (&key, &flow), code, runtime)
            .await;
        if result.is_err() {
            // Only a transaction actually claimed by this callback may be cleaned up.
            // Replay/wrong-session failures above cannot cancel another callback's work.
            let _ = self.update(owner, registration, |_, current| {
                let mut slot = current.ok_or(OAuthError::Stale)?;
                if slot.generation == flow.generation
                    && slot
                        .flows
                        .get(&key)
                        .is_some_and(|f| f.consumed && f.session_hash == flow.session_hash)
                {
                    slot.flows.remove(&key);
                }
                Ok((slot, ()))
            });
        }
        result
    }
    async fn complete_claimed(
        &self,
        owner: &str,
        session: &str,
        registration: &str,
        claimed: (&str, &Flow),
        code: &str,
        runtime: OAuthRuntimeResolver,
    ) -> Result<OAuthConnection, OAuthError> {
        let (key, flow) = claimed;
        let binding = OAuthBinding {
            registration: registration.into(),
            permission_profile: flow.profile.clone(),
        };
        let (r, profile) = self.profile(&binding)?;
        let client = r.client();
        let grant = r
            .dialect
            .exchange_code(
                &r.http,
                &client,
                CodeExchange {
                    code,
                    code_verifier: &flow.verifier,
                    profile,
                },
            )
            .await?;
        let scopes = grant_scopes(&grant, profile.scope_mode)?;
        // Validate token bounds before presenting it to discovery endpoints.
        validate_access_grant(&grant)?;
        let identity = r
            .dialect
            .identity(&r.http, &client, &grant.access_token)
            .await?;
        if identity
            .subject
            .as_ref()
            .is_some_and(|subject| !bounded(subject, 512))
            || !bounded(&identity.display_name, 512)
        {
            return Err(OAuthError::InvalidResponse);
        }
        let targets = validate_targets(
            r.dialect
                .discover_targets(&r.http, &client, &grant.access_token, &scopes)
                .await?,
        )?;
        eligible(profile, &scopes, &targets)?;
        let refresh_token = match &grant.refresh_token {
            IssuedRefreshToken::Issued(token) if bounded(token, 32768) => Some(token.clone()),
            IssuedRefreshToken::Absent if r.dialect.allows_access_without_refresh() => None,
            _ => return Err(OAuthError::InvalidResponse),
        };
        let mut access = access_entry(grant, profile.scope_mode)?;
        access.targets_validated = true;
        self.active()?;
        self.update(owner, registration, |conn, current| {
            let mut slot = current.ok_or(OAuthError::Stale)?;
            crate::managed_store::oauth::check_session(conn, owner, session)?;
            crate::managed_store::oauth::check_admission(
                conn,
                owner,
                &flow.admission,
                &binding,
                &runtime(),
            )?;
            if slot.generation != flow.generation
                || !slot
                    .flows
                    .get(key)
                    .is_some_and(|f| f.consumed && f.expires_at > now())
            {
                return Err(OAuthError::Stale);
            }
            if flow.intent != OAuthConnectIntent::ReplaceAccount
                && slot.connection.as_ref().is_some_and(|c| {
                    c.subject.is_none()
                        || identity.subject.is_none()
                        || c.subject != identity.subject
                })
            {
                return Err(OAuthError::IdentityMismatch);
            }
            slot.generation = Uuid::new_v4().to_string();
            slot.flows.clear();
            slot.connection = Some(ConnectionState {
                id: Uuid::new_v4().to_string(),
                subject: identity.subject,
                display_name: identity.display_name,
                status: OAuthConnectionStatus::Ready,
                reason: None,
                revalidation: ConsentRevalidation::None,
                family: Family {
                    id: Uuid::new_v4().to_string(),
                    material_version: Uuid::new_v4().to_string(),
                    refresh_token,
                    consent_scopes: scopes,
                    targets,
                    access: BTreeMap::from([(flow.profile.clone(), access)]),
                    attempt: None,
                    retry_not_before: 0,
                    retry_count: 0,
                    rejection_count: 0,
                },
            });
            let public = public_connection(registration, &slot);
            Ok((slot, public))
        })
    }
    pub fn list(&self, owner: &str) -> Result<Vec<OAuthConnection>, OAuthError> {
        self.active()?;
        self.inner
            .registrations
            .iter()
            .map(|(id, r)| {
                let slot = self
                    .inner
                    .store
                    .oauth_read(&self.inner.ring, owner, id, &r.fingerprint)?
                    .unwrap_or_else(|| SlotState::empty(&r.fingerprint, &r.credential_revision));
                Ok(public_connection(id, &slot))
            })
            .collect()
    }
    pub fn status(&self, owner: &str, registration: &str) -> Result<OAuthConnection, OAuthError> {
        self.active()?;
        let r = self.registration(registration)?;
        let slot = self
            .inner
            .store
            .oauth_read(&self.inner.ring, owner, registration, &r.fingerprint)?
            .unwrap_or_else(|| SlotState::empty(&r.fingerprint, &r.credential_revision));
        Ok(public_connection(registration, &slot))
    }
    pub async fn disconnect(&self, owner: &str, registration: &str) -> Result<(), OAuthError> {
        self.active()?;
        let r = self.registration(registration)?;
        self.update(owner, registration, |_, _| {
            Ok((SlotState::empty(&r.fingerprint, &r.credential_revision), ()))
        })
    }
    /// Local discovery only: inspect the exact binding without acquiring,
    /// refreshing, validating targets upstream, or changing durable state.
    pub(crate) fn check_credential(
        &self,
        owner: &str,
        binding: &OAuthBinding,
    ) -> Result<(), OAuthError> {
        self.active()?;
        let (registration, profile) = self.profile(binding)?;
        let slot = self.read(owner, &binding.registration)?;
        if slot.flows.values().any(|flow| flow.expires_at > now()) {
            return Err(OAuthError::ConsentPending);
        }
        let connection = slot
            .connection
            .as_ref()
            .ok_or(OAuthError::ReconnectRequired)?;
        if connection.status != OAuthConnectionStatus::Ready {
            return Err(status_error(connection));
        }
        if let Some(attempt) = &connection.family.attempt {
            let refresh_in_progress = self
                .inner
                .live_refresh_attempts
                .lock()
                .expect("OAuth live refresh attempts")
                .contains(&attempt.id);
            if refresh_in_progress && connection.family.refresh_token.is_some() {
                return eligible(
                    profile,
                    &connection.family.consent_scopes,
                    &connection.family.targets,
                );
            }
            if attempt.expires_at <= now() {
                // Match execution's interrupted-attempt classification without
                // retiring the attempt or writing a cooldown during discovery.
                return Err(refresh_error(
                    OAuthError::RefreshUncertain,
                    registration.dialect.refresh_replay(&registration.config),
                ));
            }
            return Err(OAuthError::RefreshBusy);
        }
        if let Some(entry) = connection.family.access.get(&binding.permission_profile)
            && (entry.refresh_after > now()
                || (connection.family.refresh_token.is_none() && entry.expires_at > now()))
            && connection.revalidation != ConsentRevalidation::Required
        {
            return eligible(profile, &entry.scopes, &connection.family.targets);
        }
        if connection.family.retry_not_before > now_millis() {
            return Err(cooldown_error(connection));
        }
        if connection.family.refresh_token.is_none() {
            return Err(OAuthError::ReconnectRequired);
        }
        eligible(
            profile,
            &connection.family.consent_scopes,
            &connection.family.targets,
        )
    }

    pub fn validate_lease(&self, lease: &OAuthLease) -> Result<(), OAuthError> {
        self.active()?;
        let slot = self.read(&lease.owner, &lease.binding.registration)?;
        let c = slot.connection.as_ref().ok_or(OAuthError::Stale)?;
        if slot.flows.values().any(|f| f.expires_at > now())
            || consent_revalidation(c)
            || slot.generation != lease.generation
            || slot.config_fingerprint != lease.config_fingerprint
            || c.id != lease.connection_id
            || c.status != OAuthConnectionStatus::Ready
            || lease.expires_at <= now()
            || !c
                .family
                .access
                .get(&lease.binding.permission_profile)
                .is_some_and(|a| a.version == lease.access_version && a.targets_validated)
        {
            return Err(OAuthError::Stale);
        }
        let (_, profile) = self.profile(&lease.binding)?;
        eligible(
            profile,
            &c.family.access[&lease.binding.permission_profile].scopes,
            &c.family.targets,
        )
    }
    pub async fn acquire(
        &self,
        owner: &str,
        binding: &OAuthBinding,
    ) -> Result<OAuthLease, OAuthError> {
        self.acquire_owned(owner, binding, None, None).await
    }
    pub async fn recover_after_unauthorized(
        &self,
        owner: &str,
        binding: &OAuthBinding,
        access_version: &str,
    ) -> Result<OAuthLease, OAuthError> {
        self.acquire_owned(owner, binding, Some(access_version.into()), None)
            .await
    }
    async fn reacquire_pinned(
        &self,
        lease: &OAuthLease,
        rejected: bool,
    ) -> Result<OAuthLease, OAuthError> {
        self.acquire_owned(
            &lease.owner,
            &lease.binding,
            rejected.then(|| lease.access_version.clone()),
            Some((lease.generation.clone(), lease.connection_id.clone())),
        )
        .await
    }
    async fn acquire_owned(
        &self,
        owner: &str,
        binding: &OAuthBinding,
        rejected: Option<String>,
        pinned: Option<(String, String)>,
    ) -> Result<OAuthLease, OAuthError> {
        self.active()?;
        self.profile(binding)?;
        let manager = self.clone();
        let owner = owner.to_owned();
        let binding = binding.clone();
        // The owned task retains the single-flight lock through durable commitment even if every waiter cancels.
        // It keeps the caller's invocation context, so its upstream requests trace against it.
        tokio::spawn(InvocationScope::current().run(async move {
            manager
                .acquire_inner(&owner, &binding, rejected.as_deref(), pinned.as_ref())
                .await
        }))
        .await
        .map_err(|_| OAuthError::RefreshUncertain)?
    }
    async fn acquire_inner(
        &self,
        owner: &str,
        binding: &OAuthBinding,
        rejected: Option<&str>,
        pinned: Option<&(String, String)>,
    ) -> Result<OAuthLease, OAuthError> {
        let lock = self.lock(owner, &binding.registration);
        let _guard = lock.lock().await;
        self.active()?;
        let (r, profile) = self.profile(binding)?;
        let slot = self.read(owner, &binding.registration)?;
        if slot.flows.values().any(|flow| flow.expires_at > now()) {
            return Err(OAuthError::ConsentPending);
        }
        let connection = slot
            .connection
            .as_ref()
            .ok_or(OAuthError::ReconnectRequired)?;
        if pinned
            .is_some_and(|(generation, id)| generation != &slot.generation || id != &connection.id)
        {
            return Err(OAuthError::Stale);
        }
        if connection.status != OAuthConnectionStatus::Ready {
            return Err(status_error(connection));
        }
        if let Some(attempt) = &connection.family.attempt {
            if attempt.expires_at <= now() {
                self.fail_attempt(
                    owner,
                    &binding.registration,
                    &attempt.id,
                    OAuthError::RefreshUncertain,
                )?;
                return Err(
                    if r.dialect.refresh_replay(&r.config) == RefreshReplay::Reusable {
                        let current = self.read(owner, &binding.registration)?;
                        cooldown_error(current.connection.as_ref().ok_or(OAuthError::Stale)?)
                    } else {
                        OAuthError::RefreshUncertain
                    },
                );
            }
            return Err(OAuthError::RefreshBusy);
        }
        if let Some(entry) = connection.family.access.get(&binding.permission_profile)
            && (entry.refresh_after > now()
                || (connection.family.refresh_token.is_none() && entry.expires_at > now()))
            && rejected != Some(entry.version.as_str())
            && connection.revalidation != ConsentRevalidation::Required
        {
            if !entry.targets_validated {
                return self
                    .validate_entry_targets(owner, binding, &slot, entry, profile, r)
                    .await;
            }
            eligible(profile, &entry.scopes, &connection.family.targets)?;
            return Ok(make_lease(
                owner, binding, &slot, connection, entry, profile,
            ));
        }
        if connection.family.retry_not_before > now_millis() {
            return Err(cooldown_error(connection));
        }
        let refresh_token = connection
            .family
            .refresh_token
            .as_deref()
            .ok_or(OAuthError::ReconnectRequired)?;
        eligible(
            profile,
            &connection.family.consent_scopes,
            &connection.family.targets,
        )?;
        let attempt = RefreshAttempt {
            id: Uuid::new_v4().to_string(),
            material_version: connection.family.material_version.clone(),
            expires_at: now() + ATTEMPT_TTL,
        };
        // Register before persistence so every visible saved attempt already
        // has its owner. Any failure or cancellation drops the marker.
        let _live_attempt = LiveRefreshAttempt::new(&self.inner.live_refresh_attempts, &attempt.id);
        self.update(owner, &binding.registration, |_, current| {
            let mut current = current.ok_or(OAuthError::Stale)?;
            current.flows.retain(|_, flow| flow.expires_at > now());
            let c = current.connection.as_mut().ok_or(OAuthError::Stale)?;
            if !current.flows.is_empty()
                || current.generation != slot.generation
                || c.family.material_version != attempt.material_version
                || c.family.attempt.is_some()
                || c.status != OAuthConnectionStatus::Ready
            {
                return Err(OAuthError::Stale);
            }
            c.family.attempt = Some(attempt.clone());
            Ok((current, ()))
        })?;
        // The persisted attempt means possibly sent, even if the process dies immediately before this call.
        let started = Instant::now();
        let result = r
            .dialect
            .refresh(
                &r.http,
                &r.client(),
                profile,
                refresh_token,
                &connection.family.consent_scopes,
            )
            .await
            .map_err(OAuthError::from);
        let response = match result {
            Ok(value) => value,
            Err(error) => {
                self.fail_attempt(owner, &binding.registration, &attempt.id, error.clone())?;
                let current = self.read(owner, &binding.registration)?;
                let c = current.connection.as_ref().ok_or(OAuthError::Stale)?;
                if c.status != OAuthConnectionStatus::Ready {
                    return Err(status_error(c));
                }
                if matches!(error, OAuthError::RetryLater(_)) {
                    return Err(cooldown_error(c));
                }
                return Err(refresh_error(error, r.dialect.refresh_replay(&r.config)));
            }
        };
        let next_refresh = match &response.refresh_token {
            IssuedRefreshToken::Issued(token) if bounded(token, 32768) => Some(token.clone()),
            IssuedRefreshToken::Retained => connection.family.refresh_token.clone(),
            _ => {
                self.fail_attempt(
                    owner,
                    &binding.registration,
                    &attempt.id,
                    OAuthError::InvalidResponse,
                )?;
                return Err(refresh_error(
                    OAuthError::InvalidResponse,
                    r.dialect.refresh_replay(&r.config),
                ));
            }
        };
        let supersedes_other_access = response.supersedes_other_access;
        let entry = match access_entry(response, profile.scope_mode) {
            Ok(entry) => entry,
            Err(_) => {
                self.fail_attempt(
                    owner,
                    &binding.registration,
                    &attempt.id,
                    OAuthError::InvalidResponse,
                )?;
                return Err(refresh_error(
                    OAuthError::InvalidResponse,
                    r.dialect.refresh_replay(&r.config),
                ));
            }
        };
        // Once rotation succeeds, persist the successor before any fallible target API call. Never repeat refresh to retry discovery.
        self.update(owner, &binding.registration, |_, current| {
            let mut current = current.ok_or(OAuthError::Stale)?;
            current.flows.retain(|_, flow| flow.expires_at > now());
            let c = current.connection.as_mut().ok_or(OAuthError::Stale)?;
            if current.generation != slot.generation
                || !c.family.attempt.as_ref().is_some_and(|a| {
                    a.id == attempt.id && a.material_version == attempt.material_version
                })
            {
                return Err(OAuthError::Stale);
            }
            c.family.refresh_token = next_refresh;
            c.family.material_version = Uuid::new_v4().to_string();
            c.family.attempt = None;
            c.family.reset_failures();
            c.reason = None;
            if consent_revalidation(c) {
                c.revalidation = ConsentRevalidation::Pending;
            }
            // Keep the prior admission evidence for successor renewal if discovery is unavailable,
            // but no cached token may execute until its target evidence is revalidated.
            for cached in c.family.access.values_mut() {
                cached.targets_validated = false;
            }
            if supersedes_other_access {
                c.family.access.clear();
            }
            c.family
                .access
                .insert(binding.permission_profile.clone(), entry.clone());
            Ok((current, ()))
        })?;
        tracing::info!(target:"agent_access_core::oauth",event="refresh_result",owner,registration=%binding.registration,connection_id=%connection.id,attempt_id=%attempt.id,outcome="committed",duration_ms=started.elapsed().as_millis() as u64);
        self.validate_entry_targets(owner, binding, &slot, &entry, profile, r)
            .await
    }
    async fn validate_entry_targets(
        &self,
        owner: &str,
        binding: &OAuthBinding,
        slot: &SlotState,
        entry: &AccessEntry,
        profile: &OAuthPermissionProfile,
        r: &ResolvedRegistration,
    ) -> Result<OAuthLease, OAuthError> {
        // Discovery failures keep the already committed successor; later calls retry discovery, never refresh replay.
        self.active()?;
        let live = self.read(owner, &binding.registration)?;
        let observed = live.connection.as_ref().ok_or(OAuthError::Stale)?;
        // A same-configuration reload has independent task locks. Consent may have started
        // since the caller selected this entry, so discovery cannot satisfy a required refresh.
        if live.generation != slot.generation
            || live.flows.values().any(|flow| flow.expires_at > now())
            || observed.revalidation == ConsentRevalidation::Required
            || !observed
                .family
                .access
                .get(&binding.permission_profile)
                .is_some_and(|e| e.version == entry.version)
        {
            return Err(OAuthError::Stale);
        }
        let revalidating = consent_revalidation(observed);
        if revalidating && observed.subject.is_some() {
            let identity = r
                .dialect
                .identity(&r.http, &r.client(), &entry.token)
                .await?;
            if live.connection.as_ref().is_none_or(|c| {
                c.subject.is_none() || identity.subject.is_none() || c.subject != identity.subject
            }) {
                return Err(OAuthError::IdentityMismatch);
            }
        }
        let targets = validate_targets(
            r.dialect
                .discover_targets(&r.http, &r.client(), &entry.token, &entry.scopes)
                .await?,
        )?;
        let current = self.update(owner, &binding.registration, |_, current| {
            let mut current = current.ok_or(OAuthError::Stale)?;
            current.flows.retain(|_, flow| flow.expires_at > now());
            let c = current.connection.as_mut().ok_or(OAuthError::Stale)?;
            if !current.flows.is_empty()
                || current.generation != slot.generation
                || c.revalidation != observed.revalidation
                || c.family.material_version != observed.family.material_version
                || !c
                    .family
                    .access
                    .get(&binding.permission_profile)
                    .is_some_and(|e| e.version == entry.version)
            {
                return Err(OAuthError::Stale);
            }
            c.family.targets = targets;
            let eligible = eligible(profile, &entry.scopes, &c.family.targets).is_ok();
            c.reason = (!eligible).then(|| OAuthError::Permission.code().into());
            if revalidating && eligible {
                c.revalidation = ConsentRevalidation::None;
            }
            c.family
                .access
                .get_mut(&binding.permission_profile)
                .expect("checked entry")
                .targets_validated = true;
            let result = current.clone();
            Ok((current, result))
        })?;
        self.active()?;
        let c = current.connection.as_ref().ok_or(OAuthError::Stale)?;
        let eligibility = eligible(profile, &entry.scopes, &c.family.targets);
        tracing::info!(target:"agent_access_core::oauth",event="target_revalidation",owner,registration=%binding.registration,connection_id=%c.id,outcome=if eligibility.is_ok(){"admitted"}else{"permission_denied"});
        eligibility?;
        Ok(make_lease(owner, binding, &current, c, entry, profile))
    }
    fn fail_attempt(
        &self,
        owner: &str,
        registration: &str,
        id: &str,
        error: OAuthError,
    ) -> Result<(), OAuthError> {
        let registration_config = self.registration(registration)?;
        let replay = registration_config
            .dialect
            .refresh_replay(&registration_config.config);
        let error = refresh_error(error, replay);
        let minimum_delay = match error {
            OAuthError::BeforeSend
            | OAuthError::Permission
            | OAuthError::RequestRejected
            | OAuthError::Provider
            | OAuthError::InvalidResponse => Some(1),
            // The authorization server's own wait, up to one day.
            OAuthError::RetryLater(seconds) => {
                Some(seconds.clamp(1, UPSTREAM_RETRY_AFTER_MAX_SECONDS))
            }
            _ => None,
        };
        let (connection_id, delay, status, material_preserved) =
            self.update(owner, registration, |_, current| {
                let mut slot = current.ok_or(OAuthError::Stale)?;
                let c = slot.connection.as_mut().ok_or(OAuthError::Stale)?;
                if !c.family.attempt.as_ref().is_some_and(|a| a.id == id) {
                    return Err(OAuthError::Stale);
                }
                let connection_id = c.id.clone();
                if let Some(minimum) = minimum_delay {
                    if replay == RefreshReplay::Reusable {
                        // Never lend rejected or uncertain access during the cooldown.
                        c.family.access.clear();
                    }
                    c.family.retry_count = c.family.retry_count.saturating_add(1).min(10);
                    // Local backoff is capped at five minutes; an explicit
                    // throttling wait from the provider may be longer.
                    let delay = (1u64 << (c.family.retry_count - 1))
                        .min(MAX_RETRY_DELAY)
                        .max(minimum);
                    c.family.rejection_count = if matches!(
                        error,
                        OAuthError::Permission
                            | OAuthError::RequestRejected
                            | OAuthError::InvalidResponse
                    ) {
                        c.family
                            .rejection_count
                            .saturating_add(1)
                            .min(REJECTION_BUDGET)
                    } else {
                        0
                    };
                    c.family.attempt = None;
                    c.family.retry_not_before = now_millis() + delay as i64 * 1000;
                    c.reason = Some(error.code().into());
                    if c.family.rejection_count >= REJECTION_BUDGET {
                        c.status = if error == OAuthError::RequestRejected {
                            OAuthConnectionStatus::OperatorActionRequired
                        } else {
                            OAuthConnectionStatus::ReconnectRequired
                        };
                        if error == OAuthError::InvalidResponse {
                            c.family.refresh_token = None;
                        }
                    }
                    let material_preserved = c.family.refresh_token.is_some();
                    let status = c.status.clone();
                    return Ok((slot, (connection_id, delay, status, material_preserved)));
                }
                if error == OAuthError::ApplicationCredential
                    && slot.credential_revision
                        != self.registration(registration)?.credential_revision
                {
                    c.family.attempt = None;
                    let material_preserved = c.family.refresh_token.is_some();
                    let status = c.status.clone();
                    return Ok((slot, (connection_id, 0, status, material_preserved)));
                }
                c.status = if error == OAuthError::ApplicationCredential {
                    OAuthConnectionStatus::OperatorActionRequired
                } else {
                    OAuthConnectionStatus::ReconnectRequired
                };
                c.reason = Some(error.code().into());
                c.family.access.clear();
                c.family.attempt = None;
                if error != OAuthError::ApplicationCredential {
                    c.family.refresh_token = None;
                }
                let material_preserved = c.family.refresh_token.is_some();
                let status = c.status.clone();
                Ok((slot, (connection_id, 0, status, material_preserved)))
            })?;
        tracing::info!(target:"agent_access_core::oauth",event="refresh_result",owner,registration,connection_id,attempt_id=id,outcome=error.code(),retry_after_seconds=delay,status=?status,material_preserved);
        Ok(())
    }
}

fn grant_scopes(
    grant: &TokenGrant,
    scope_mode: OAuthScopeMode,
) -> Result<BTreeSet<String>, OAuthError> {
    let scopes: BTreeSet<String> = grant.scopes.iter().cloned().collect();
    if (scopes.is_empty() && scope_mode == OAuthScopeMode::Explicit)
        || scopes.len() > 64
        || scopes.iter().any(|s| !bounded(s, 256))
    {
        return Err(OAuthError::InvalidResponse);
    }
    Ok(scopes)
}
fn validate_access_grant(grant: &TokenGrant) -> Result<(), OAuthError> {
    if !grant.token_type.eq_ignore_ascii_case("bearer")
        || !bounded(&grant.access_token, 32768)
        || grant.expires_in == 0
        || grant.expires_in > 31_536_000
    {
        return Err(OAuthError::InvalidResponse);
    }
    Ok(())
}
fn access_entry(grant: TokenGrant, scope_mode: OAuthScopeMode) -> Result<AccessEntry, OAuthError> {
    validate_access_grant(&grant)?;
    let scopes = grant_scopes(&grant, scope_mode)?;
    let lifetime = grant.expires_in as i64;
    let now = now();
    Ok(AccessEntry {
        token: grant.access_token,
        version: Uuid::new_v4().to_string(),
        scopes,
        expires_at: now + lifetime,
        refresh_after: now + lifetime - (lifetime / 10).clamp(0, 30),
        targets_validated: false,
    })
}
/// Bounds every dialect's target discovery before it is stored.
fn validate_targets(targets: Vec<OAuthTarget>) -> Result<Vec<OAuthTarget>, OAuthError> {
    if targets.len() > 64
        || targets.iter().any(|t| {
            !bounded(&t.id, 256)
                || !bounded(&t.audience, 256)
                || t.name.len() > 512
                || t.scopes.len() > 64
                || t.scopes.iter().any(|s| !bounded(s, 256))
        })
    {
        return Err(OAuthError::InvalidResponse);
    }
    let unique = targets
        .iter()
        .map(|t| (&t.id, &t.audience))
        .collect::<BTreeSet<_>>();
    if unique.len() != targets.len() {
        return Err(OAuthError::InvalidResponse);
    }
    Ok(targets)
}
fn eligible(
    profile: &OAuthPermissionProfile,
    token_scopes: &BTreeSet<String>,
    targets: &[OAuthTarget],
) -> Result<(), OAuthError> {
    let target = targets
        .iter()
        .find(|t| t.id == profile.target && t.audience == profile.audience)
        .ok_or(OAuthError::Permission)?;
    for scope in profile
        .requested_scopes()
        .iter()
        .filter(|s| s.as_str() != "offline_access")
    {
        if !token_scopes.contains(scope) || !target.scopes.contains(scope) {
            return Err(OAuthError::Permission);
        }
    }
    Ok(())
}
fn expired_without_refresh(connection: &ConnectionState) -> bool {
    connection.status == OAuthConnectionStatus::Ready
        && connection.family.refresh_token.is_none()
        && connection
            .family
            .access
            .values()
            .all(|entry| entry.expires_at <= now())
}
fn public_connection(registration: &str, slot: &SlotState) -> OAuthConnection {
    match &slot.connection {
        Some(c) => OAuthConnection {
            registration: registration.into(),
            connection_id: Some(c.id.clone()),
            subject_id: c.subject.clone(),
            display_name: Some(c.display_name.clone()),
            status: if expired_without_refresh(c) {
                OAuthConnectionStatus::ReconnectRequired
            } else {
                c.status.clone()
            },
            reason: if slot.flows.values().any(|f| f.expires_at > now()) {
                Some("consent_pending".into())
            } else if expired_without_refresh(c) {
                Some(OAuthError::ReconnectRequired.code().into())
            } else {
                c.reason.clone().or_else(|| revalidation_reason(c))
            },
            targets: c.family.targets.clone(),
        },
        None => OAuthConnection {
            registration: registration.into(),
            connection_id: None,
            subject_id: None,
            display_name: None,
            status: OAuthConnectionStatus::Disconnected,
            reason: None,
            targets: Vec::new(),
        },
    }
}
fn consent_revalidation(c: &ConnectionState) -> bool {
    c.revalidation != ConsentRevalidation::None
}
fn revalidation_reason(c: &ConnectionState) -> Option<String> {
    match c.revalidation {
        ConsentRevalidation::None => None,
        ConsentRevalidation::Required => Some("consent_revalidation_required".into()),
        ConsentRevalidation::Pending => Some("consent_revalidation_pending".into()),
    }
}
fn now_millis() -> i64 {
    Utc::now()
        .timestamp_millis()
        .max(now().saturating_mul(1000))
}
fn status_error(c: &ConnectionState) -> OAuthError {
    if c.status == OAuthConnectionStatus::OperatorActionRequired {
        if c.reason.as_deref() == Some("oauth_request_rejected") {
            OAuthError::RequestRejected
        } else {
            OAuthError::ApplicationCredential
        }
    } else if c.reason.as_deref() == Some("oauth_refresh_uncertain") {
        OAuthError::RefreshUncertain
    } else {
        OAuthError::ReconnectRequired
    }
}
/// The error for a refresh requested while `c`'s cooldown runs. The
/// connection's persisted reason is the code of the failure that started the
/// cooldown (see `fail_attempt`), so the cause survives restarts: throttling
/// stays [`OAuthError::RetryLater`]; any other failure is
/// [`OAuthError::RefreshPaused`] with that failure.
fn cooldown_error(c: &ConnectionState) -> OAuthError {
    let seconds = ((c.family.retry_not_before - now_millis()).max(0) as u64)
        .div_ceil(1000)
        .max(1);
    match c.reason.as_deref().and_then(cooldown_cause) {
        Some(OAuthError::Throttled) => OAuthError::RetryLater(seconds),
        failure => OAuthError::RefreshPaused {
            seconds,
            // A reason overwritten since the cooldown began leaves the cause
            // unknown: report a provider failure, never throttling.
            failure: Box::new(failure.unwrap_or(OAuthError::Provider)),
        },
    }
}
/// The error whose code a cooldown's persisted reason names. Only failures
/// that start a cooldown in `fail_attempt` qualify; `oauth_throttled` is
/// throttling.
fn cooldown_cause(code: &str) -> Option<OAuthError> {
    [
        OAuthError::Throttled,
        OAuthError::BeforeSend,
        OAuthError::Provider,
        OAuthError::Permission,
        OAuthError::RequestRejected,
        OAuthError::InvalidResponse,
    ]
    .into_iter()
    .find(|error| error.code() == code)
}
fn refresh_error(error: OAuthError, replay: RefreshReplay) -> OAuthError {
    if replay == RefreshReplay::Reusable {
        match error {
            OAuthError::RefreshUncertain => return OAuthError::Provider,
            OAuthError::Provider | OAuthError::InvalidResponse => return error,
            OAuthError::Throttled => return OAuthError::RetryLater(1),
            _ => {}
        }
    }
    match error {
        OAuthError::ReconnectRequired
        | OAuthError::ApplicationCredential
        | OAuthError::BeforeSend
        | OAuthError::Permission
        | OAuthError::RequestRejected
        | OAuthError::RetryLater(_) => error,
        _ => OAuthError::RefreshUncertain,
    }
}
fn make_lease(
    owner: &str,
    binding: &OAuthBinding,
    slot: &SlotState,
    connection: &ConnectionState,
    entry: &AccessEntry,
    profile: &OAuthPermissionProfile,
) -> OAuthLease {
    OAuthLease {
        token: entry.token.clone(),
        owner: owner.into(),
        binding: binding.clone(),
        config_fingerprint: slot.config_fingerprint.clone(),
        generation: slot.generation.clone(),
        connection_id: connection.id.clone(),
        access_version: entry.version.clone(),
        target: profile.target.clone(),
        audience: profile.audience.clone(),
        expires_at: entry.expires_at,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::managed_store::oauth::{test_fixture, test_sql};
    use crate::network::EgressProxyEnvironment;
    use crate::{OutboundTlsConfig, PreparedOutboundTls};
    use agent_access_fake::{OAUTH_STUB_BACKEND, STUB_OAUTH_DIALECT};
    use agent_access_provider::{
        OAuthAdapter, OAuthClientAuth, OAuthRotation, OAuthTokenEncoding, ProviderLimits,
        ReasonCode,
    };
    use std::sync::atomic::AtomicUsize;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Tests core's mode-aware lifecycle without changing the production stub's
    // explicit-scope contract or coupling core to a protocol adapter.
    struct DefaultScopeDialect;
    pub(crate) static DEFAULT_SCOPE_DIALECT: agent_access_provider::OAuthDialectRegistration =
        agent_access_provider::OAuthDialectRegistration::new(
            agent_access_provider::module_metadata!(),
            "default_scope_fixture",
            &DefaultScopeDialect,
        )
        .development_only();

    #[async_trait::async_trait]
    impl OAuthDialect for DefaultScopeDialect {
        fn supports_server_default_scopes(&self) -> bool {
            true
        }
        fn validate_registration(&self, _config: &OAuthRegistrationConfig) -> Result<(), String> {
            Ok(())
        }
        fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
            STUB_OAUTH_DIALECT.dialect().upstream_allowlist(config)
        }
        fn authorization_url(
            &self,
            client: &OAuthClient<'_>,
            _profile: &OAuthPermissionProfile,
            request: AuthorizationRequest<'_>,
        ) -> Result<Url, OAuthDialectError> {
            let mut url = Url::parse(&client.config.base_url).unwrap();
            url.query_pairs_mut().extend_pairs([
                ("state", request.state),
                ("code_challenge", request.code_challenge_s256),
                ("code_challenge_method", "S256"),
            ]);
            Ok(url)
        }
        fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
            STUB_OAUTH_DIALECT.dialect().callback_issuer(config)
        }
        fn refresh_replay(&self, _config: &OAuthRegistrationConfig) -> RefreshReplay {
            RefreshReplay::Consuming
        }
        async fn exchange_code(
            &self,
            _http: &OAuthHttp,
            _client: &OAuthClient<'_>,
            exchange: CodeExchange<'_>,
        ) -> Result<TokenGrant, OAuthDialectError> {
            let mut grant = grant("Bearer", 3600);
            if exchange.code == "unknown-scopes" {
                grant.scopes.clear();
            }
            grant.refresh_token =
                IssuedRefreshToken::Issued(format!("report-later:{}", exchange.code));
            Ok(grant)
        }
        async fn refresh(
            &self,
            _http: &OAuthHttp,
            _client: &OAuthClient<'_>,
            _profile: &OAuthPermissionProfile,
            refresh_token: &str,
            granted_scopes: &BTreeSet<String>,
        ) -> Result<TokenGrant, OAuthDialectError> {
            let mut grant = grant("Bearer", 3600);
            // Carry the original fixture consent in its refresh material so
            // concurrent tests need no shared recorder to verify the argument.
            let (response, original) = refresh_token.split_once(':').unwrap();
            let original_scopes = match original {
                "unknown-scopes" => BTreeSet::new(),
                "known-scopes" => grant.scopes.iter().cloned().collect(),
                _ => panic!("unexpected fixture consent"),
            };
            assert_eq!(granted_scopes, &original_scopes);
            grant.scopes = match response {
                "report-later" => vec!["records.audit".into()],
                // Model the adapter's omitted-scope response fallback using
                // exactly the evidence the manager supplies.
                "omit" => granted_scopes.iter().cloned().collect(),
                _ => panic!("unexpected fixture refresh"),
            };
            grant.refresh_token = IssuedRefreshToken::Issued(format!("omit:{original}"));
            Ok(grant)
        }
        async fn identity(
            &self,
            _http: &OAuthHttp,
            _client: &OAuthClient<'_>,
            _access_token: &str,
        ) -> Result<agent_access_provider::ConnectedIdentity, OAuthDialectError> {
            Ok(agent_access_provider::ConnectedIdentity {
                subject: None,
                display_name: "Example connection".into(),
            })
        }
        async fn discover_targets(
            &self,
            _http: &OAuthHttp,
            client: &OAuthClient<'_>,
            _access_token: &str,
            granted_scopes: &BTreeSet<String>,
        ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
            let profile = client.config.permission_profiles.values().next().unwrap();
            Ok(vec![OAuthTarget {
                id: profile.target.clone(),
                name: "Example resource".into(),
                audience: profile.audience.clone(),
                scopes: granted_scopes.clone(),
            }])
        }
    }

    /// The selections these tests configure: the development records
    /// backend, its `stub` dialect and the default-scope fixture dialect.
    fn test_registry() -> BackendRegistry {
        BackendRegistry::new([&OAUTH_STUB_BACKEND])
            .unwrap()
            .with_oauth_dialects([&STUB_OAUTH_DIALECT, &DEFAULT_SCOPE_DIALECT])
            .unwrap()
    }

    /// A manager over [`test_registry`]'s explicitly selected dialects,
    /// sending directly.
    fn stub_manager(
        store: ManagedStore,
        ring: CredentialKeyRing,
        config: OAuthConfig,
    ) -> Result<OAuthManager, OAuthError> {
        OAuthManager::new_with_host(store, ring, config, &test_registry(), &direct_network())
    }

    fn default_scope_manager(
        store: ManagedStore,
        ring: CredentialKeyRing,
        config: OAuthConfig,
    ) -> OAuthManager {
        stub_manager(store, ring, config).unwrap()
    }

    /// Direct routes and system trust.
    fn direct_network() -> HostNetwork {
        HostNetwork::new(
            ProviderLimits::default(),
            PreparedOutboundTls::load(&OutboundTlsConfig::default()).unwrap(),
            Arc::new(EgressProxyEnvironment::empty()),
            None,
        )
    }

    #[test]
    fn registration_fingerprints_never_drift() {
        let registration = OAuthRegistrationConfig {
            adapter_settings: Default::default(),
            adapter: OAuthAdapter::new("stub"),
            base_url: "https://stub.example/".into(),
            redirect_uri: "https://broker.example/v1/oauth/callback/stub".into(),
            client_id: "broker".into(),
            client_secret_ref: "env:STUB_SECRET".into(),
            client_auth: OAuthClientAuth::ClientSecretBasic,
            encoding: OAuthTokenEncoding::Form,
            rotation: OAuthRotation::PreserveOld,
            allow_insecure_loopback: false,
            permission_profiles: BTreeMap::from([(
                "read".into(),
                OAuthPermissionProfile {
                    scope_mode: OAuthScopeMode::Explicit,
                    scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                    audience: "records-api".into(),
                    target: "workspace-one".into(),
                },
            )]),
        };
        // A changed digest discards every stored connection at activation.
        assert_eq!(
            registration_fingerprint(&registration).unwrap(),
            "e77c185f9dc0231eeefbeb48cccc745033fc8bd172fa06a9af13a983d4a7e1fb"
        );
    }
    fn binding() -> OAuthBinding {
        OAuthBinding {
            registration: "stub".into(),
            permission_profile: "read".into(),
        }
    }
    fn admission() -> OAuthManagementAdmission {
        OAuthManagementAdmission {
            service: "oauth_stub".into(),
            credential_name: "default".into(),
            imported_service_version: None,
            return_path: None,
        }
    }
    fn runtime(manager: &OAuthManager) -> OAuthRuntimeResolver {
        let directory = manager.inner.store.path().parent().unwrap();
        let key = directory.join("runtime-test-key");
        std::fs::write(&key, URL_SAFE_NO_PAD.encode([1_u8; 32])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let key_ref = format!("file:{}", key.display());
        let raw = format!(
            r#"
            [deployment]
            enable_fake_service = true
            [identity]
            mode = "anonymous"
            authority = "managed"
            [policy]
            authority = "managed"
            default_decision = "deny"
            [managed_store]
            type = "sqlite"
            path = {:?}
            auto_migrate = true
            [credential_encryption]
            active_key = "one"
            [[credential_encryption.keys]]
            id = "one"
            provider = "file"
            path = {:?}
            [broker_tokens]
            hash_key_ref = {key_ref:?}
            [management]
            enabled = true
            [browser_auth]
            enabled = true
            public_origin = "http://127.0.0.1:9000"
            csrf_key_ref = {key_ref:?}
            [browser_auth.local_password]
            enabled = true
            pepper_ref = {key_ref:?}
            [credentials.per_user.oauth_stub]
            type = "oauth"
            provider = "stub"
            profile = "read"
            # The records API is never contacted by these lifecycle tests.
            [providers.oauth_stub]
            base_url = "http://127.0.0.1:9"
            "#,
            directory.join("oauth.sqlite").display().to_string(),
            key.display().to_string()
        );
        let mut config = crate::parse_broker_config_raw(
            "oauth-runtime-fixture",
            &raw,
            &Arc::new(test_registry()),
        )
        .unwrap();
        config.oauth = manager.config().clone();
        let runtime = Arc::new(crate::BrokerRuntime::new(config).unwrap());
        Arc::new(move || Arc::clone(&runtime))
    }
    fn config(server: &MockServer, secret_file: &std::path::Path) -> OAuthConfig {
        OAuthConfig {
            registrations: BTreeMap::from([(
                "stub".into(),
                OAuthRegistrationConfig {
                    adapter_settings: Default::default(),
                    adapter: OAuthAdapter::new("stub"),
                    base_url: server.uri(),
                    redirect_uri: "http://127.0.0.1:9000/v1/oauth/callback/stub".into(),
                    client_id: "broker".into(),
                    client_secret_ref: format!("file:{}", secret_file.display()),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Json,
                    rotation: OAuthRotation::RotateBoth,
                    allow_insecure_loopback: true,
                    permission_profiles: BTreeMap::from([(
                        "read".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                            audience: "records-api".into(),
                            target: "workspace-one".into(),
                        },
                    )]),
                },
            )]),
        }
    }
    #[tokio::test]
    async fn discovery_checks_exact_oauth_binding_without_network_or_state_changes() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        assert_eq!(
            manager.check_credential("user", &binding()),
            Err(OAuthError::ReconnectRequired)
        );
        connected(&manager, &server).await;
        let original = manager.read("user", "stub").unwrap();
        let request_count = server.received_requests().await.unwrap().len();
        for scenario in [
            "ready",
            "expired_refreshable",
            "expired_access_only",
            "wrong_scope",
            "pending_target_validation",
            "cooldown",
        ] {
            let mut candidate = original.clone();
            let connection = candidate.connection.as_mut().unwrap();
            let access = connection.family.access.get_mut("read").unwrap();
            match scenario {
                "expired_refreshable" | "expired_access_only" | "cooldown" => {
                    access.expires_at = now() - 10;
                    access.refresh_after = now() - 20;
                    if scenario == "expired_access_only" {
                        connection.family.refresh_token = None;
                    }
                    if scenario == "cooldown" {
                        connection.family.retry_not_before = now_millis() + 30_000;
                    }
                }
                "wrong_scope" => {
                    access.scopes.clear();
                }
                "pending_target_validation" => {
                    access.targets_validated = false;
                }
                _ => {}
            }
            manager
                .update("user", "stub", |_, _| Ok((candidate, ())))
                .unwrap();
            let before = serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap();
            let result = manager.check_credential("user", &binding());
            assert_eq!(
                result.is_ok(),
                matches!(
                    scenario,
                    "ready" | "expired_refreshable" | "pending_target_validation"
                ),
                "{scenario}: {result:?}"
            );
            assert_eq!(
                before,
                serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap()
            );
            assert_eq!(
                request_count,
                server.received_requests().await.unwrap().len()
            );
        }
        let mut wrong = binding();
        wrong.permission_profile = "unconfigured".into();
        assert_eq!(
            manager.check_credential("user", &wrong),
            Err(OAuthError::Configuration)
        );
    }

    #[tokio::test]
    async fn discovery_classifies_orphaned_refresh_attempts_without_retiring_them() {
        for rotation in [OAuthRotation::RotateBoth, OAuthRotation::PreserveOld] {
            let (_dir, store, ring, original, server) = fixture().await;
            let mut config = original.config().clone();
            config.registrations.get_mut("stub").unwrap().rotation = rotation;
            let manager = stub_manager(store, ring, config).unwrap();
            manager.activate().unwrap();
            connected(&manager, &server).await;
            let requests = server.received_requests().await.unwrap().len();
            for expired in [false, true] {
                manager
                    .update("user", "stub", |_, current| {
                        let mut slot = current.unwrap();
                        let family = &mut slot.connection.as_mut().unwrap().family;
                        family.attempt = Some(RefreshAttempt {
                            id: "orphaned".into(),
                            material_version: family.material_version.clone(),
                            expires_at: now() + if expired { -1 } else { ATTEMPT_TTL },
                        });
                        Ok((slot, ()))
                    })
                    .unwrap();
                let before = serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap();
                // A concurrent setup/acquire operation holding this lock is
                // not the owner of the abandoned refresh attempt.
                let lock = manager.lock("user", "stub");
                let _other_operation = lock.lock().await;
                assert_eq!(
                    manager.check_credential("user", &binding()),
                    Err(if !expired {
                        OAuthError::RefreshBusy
                    } else if rotation == OAuthRotation::PreserveOld {
                        OAuthError::Provider
                    } else {
                        OAuthError::RefreshUncertain
                    })
                );
                assert_eq!(
                    before,
                    serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap()
                );
                assert_eq!(requests, server.received_requests().await.unwrap().len());
            }
        }
    }

    #[tokio::test]
    async fn discovery_reports_operator_action_and_reload_without_user_setup_requirements() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                let connection = slot.connection.as_mut().unwrap();
                connection.status = OAuthConnectionStatus::OperatorActionRequired;
                connection.reason = Some(OAuthError::RequestRejected.code().into());
                Ok((slot, ()))
            })
            .unwrap();
        let broker = runtime(&manager)();
        let identity = crate::IdentityContext {
            principal: "user".into(),
            authenticated: true,
            ..crate::IdentityContext::anonymous()
        };
        let context = crate::ExecutionContext::new("default").unwrap();
        let service = broker
            .service_capabilities(&identity, &context, "oauth_stub")
            .unwrap();
        assert!(service.actions.is_empty());
        assert_eq!(
            service.availability.state,
            crate::AvailabilityState::Unavailable
        );
        assert_eq!(
            service.availability.requirements[0].reason,
            "oauth_request_rejected"
        );
        assert_eq!(
            service.availability.requirements[0].resolution,
            "administrator"
        );
        broker.deactivate_oauth();
        let service = broker
            .service_capabilities(&identity, &context, "oauth_stub")
            .unwrap();
        assert!(service.actions.is_empty());
        assert_eq!(
            service.availability.state,
            crate::AvailabilityState::Unknown
        );
        assert_eq!(service.availability.requirements[0].reason, "oauth_stale");
        assert_eq!(
            service.availability.requirements[0].resolution,
            "administrator"
        );
    }

    async fn fixture() -> (
        tempfile::TempDir,
        ManagedStore,
        CredentialKeyRing,
        OAuthManager,
        MockServer,
    ) {
        let (dir, store, ring) = test_fixture();
        let server = MockServer::start().await;
        let secret_file = dir.path().join("client-secret");
        std::fs::write(&secret_file, "application-secret").unwrap();
        let manager =
            stub_manager(store.clone(), ring.clone(), config(&server, &secret_file)).unwrap();
        manager.activate().unwrap();
        (dir, store, ring, manager, server)
    }
    async fn identity(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"alice","name":"Alice"})),
            )
            .mount(server)
            .await;
        Mock::given(method("GET")).and(path("/targets")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"targets":[{"id":"workspace-one","name":"One","audience":"records-api","scopes":["records.read"]}]}))).mount(server).await;
    }
    fn token(number: usize) -> serde_json::Value {
        serde_json::json!({"access_token":format!("protected-access-{number}"),"refresh_token":format!("protected-refresh-{number}"),"token_type":"Bearer","expires_in":3600,"scope":"records.read offline_access"})
    }
    async fn start(manager: &OAuthManager, intent: OAuthConnectIntent) -> String {
        let started = manager
            .connect(
                "user",
                "session",
                &binding(),
                intent,
                admission(),
                runtime(manager),
            )
            .await
            .unwrap();
        let url = Url::parse(&started.authorization_url).unwrap();
        let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["code_challenge"].len(), 43);
        params["state"].clone()
    }
    async fn connected(manager: &OAuthManager, server: &MockServer) {
        identity(server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(0)))
            .mount(server)
            .await;
        let state = start(manager, OAuthConnectIntent::Connect).await;
        let public = manager
            .complete(
                "user",
                "session",
                "stub",
                &state,
                "one-use-code",
                runtime(manager),
            )
            .await
            .unwrap();
        assert_eq!(public.subject_id.as_deref(), Some("alice"));
        assert_eq!(public.status, OAuthConnectionStatus::Ready);
        assert_eq!(
            manager
                .complete(
                    "user",
                    "session",
                    "stub",
                    &state,
                    "one-use-code",
                    runtime(manager)
                )
                .await
                .unwrap_err(),
            OAuthError::InvalidFlow
        );
    }
    fn expire(manager: &OAuthManager) {
        manager
            .update("user", "stub", |_, current| {
                let mut current = current.unwrap();
                let entry = current
                    .connection
                    .as_mut()
                    .unwrap()
                    .family
                    .access
                    .get_mut("read")
                    .unwrap();
                entry.expires_at = now() - 1;
                entry.refresh_after = now() - 1;
                Ok((current, ()))
            })
            .unwrap();
    }

    #[tokio::test]
    async fn scope_modes_require_distinct_valid_profiles_and_dialect_support() {
        let (_dir, store, ring, manager, _server) = fixture().await;
        let explicit = manager.config().clone();
        for scopes in [
            None,
            Some(vec![]),
            Some(vec!["records.read".into(), "records.read".into()]),
            Some(vec!["two scopes".into()]),
            Some(vec!["x".repeat(257)]),
            Some((0..65).map(|i| format!("scope-{i}")).collect()),
        ] {
            let mut changed = explicit.clone();
            changed
                .registrations
                .get_mut("stub")
                .unwrap()
                .permission_profiles
                .get_mut("read")
                .unwrap()
                .scopes = scopes;
            assert_eq!(changed.validate(), Err(OAuthError::Configuration));
        }
        let mut default = explicit.clone();
        let profile = default
            .registrations
            .get_mut("stub")
            .unwrap()
            .permission_profiles
            .get_mut("read")
            .unwrap();
        profile.scope_mode = OAuthScopeMode::ServerDefault;
        profile.scopes = None;
        default.validate().unwrap();
        // A generic registration is well formed, but a dialect must opt in.
        assert!(matches!(
            stub_manager(store, ring, default.clone()),
            Err(OAuthError::Configuration)
        ));
        for scopes in [vec![], vec!["records.read".into()]] {
            let mut changed = default.clone();
            changed
                .registrations
                .get_mut("stub")
                .unwrap()
                .permission_profiles
                .get_mut("read")
                .unwrap()
                .scopes = Some(scopes);
            assert_eq!(changed.validate(), Err(OAuthError::Configuration));
        }
        let mut mixed = default.clone();
        mixed
            .registrations
            .get_mut("stub")
            .unwrap()
            .permission_profiles
            .insert(
                "explicit".into(),
                explicit.registrations["stub"].permission_profiles["read"].clone(),
            );
        assert_eq!(mixed.validate(), Err(OAuthError::Configuration));
        let mut uniform = default.clone();
        uniform
            .registrations
            .get_mut("stub")
            .unwrap()
            .permission_profiles
            .insert(
                "another".into(),
                default.registrations["stub"].permission_profiles["read"].clone(),
            );
        uniform.validate().unwrap();
    }

    #[test]
    fn unknown_scopes_only_authorize_default_mode_with_exact_target_and_audience() {
        let profile = OAuthPermissionProfile {
            scope_mode: OAuthScopeMode::ServerDefault,
            scopes: None,
            audience: "records-api".into(),
            target: "one".into(),
        };
        let mut grant = grant("Bearer", 3600);
        grant.scopes.clear();
        assert_eq!(
            grant_scopes(&grant, OAuthScopeMode::Explicit),
            Err(OAuthError::InvalidResponse)
        );
        assert!(
            grant_scopes(&grant, OAuthScopeMode::ServerDefault)
                .unwrap()
                .is_empty()
        );
        let mut targets = vec![OAuthTarget {
            id: "one".into(),
            name: "One".into(),
            audience: "records-api".into(),
            scopes: BTreeSet::new(),
        }];
        assert!(eligible(&profile, &BTreeSet::new(), &targets).is_ok());
        assert_eq!(
            eligible(&profile, &BTreeSet::new(), &[]),
            Err(OAuthError::Permission)
        );
        targets[0].id = "two".into();
        assert_eq!(
            eligible(&profile, &BTreeSet::new(), &targets),
            Err(OAuthError::Permission)
        );
        targets[0].id = "one".into();
        targets[0].audience = "other-api".into();
        assert_eq!(
            eligible(&profile, &BTreeSet::new(), &targets),
            Err(OAuthError::Permission)
        );
        targets[0].audience = "records-api".into();
        let explicit = OAuthPermissionProfile {
            scope_mode: OAuthScopeMode::Explicit,
            scopes: Some(vec!["records.read".into()]),
            ..profile
        };
        assert_eq!(
            eligible(&explicit, &BTreeSet::new(), &targets),
            Err(OAuthError::Permission)
        );
        grant.scopes = vec![String::new()];
        assert!(grant_scopes(&grant, OAuthScopeMode::ServerDefault).is_err());
        grant.scopes = vec!["x".repeat(257)];
        assert!(grant_scopes(&grant, OAuthScopeMode::ServerDefault).is_err());
        grant.scopes = (0..65).map(|i| format!("scope-{i}")).collect();
        assert!(grant_scopes(&grant, OAuthScopeMode::ServerDefault).is_err());
    }

    #[tokio::test]
    async fn server_default_refresh_uses_original_consent_scopes_across_restarts() {
        for code in ["unknown-scopes", "known-scopes"] {
            let (_dir, store, ring, original, _server) = fixture().await;
            let mut config = original.config().clone();
            let registration = config.registrations.get_mut("stub").unwrap();
            registration.adapter = OAuthAdapter::new(DEFAULT_SCOPE_DIALECT.id());
            let profile = registration.permission_profiles.get_mut("read").unwrap();
            profile.scope_mode = OAuthScopeMode::ServerDefault;
            profile.scopes = None;
            let mut manager = default_scope_manager(store.clone(), ring.clone(), config.clone());
            manager.activate().unwrap();
            let state = start(&manager, OAuthConnectIntent::Connect).await;
            let connected = manager
                .complete("user", "session", "stub", &state, code, runtime(&manager))
                .await
                .unwrap();
            let original_scopes = if code == "unknown-scopes" {
                BTreeSet::new()
            } else {
                BTreeSet::from(["records.read".into(), "offline_access".into()])
            };
            assert_eq!(connected.status, OAuthConnectionStatus::Ready);
            assert!(connected.subject_id.is_none());
            assert_eq!(connected.targets[0].scopes, original_scopes);
            let mut lease = manager.acquire("user", &binding()).await.unwrap();
            manager.validate_lease(&lease).unwrap();
            // The first response reports different scopes. The next omits them
            // and must recover original consent, even across a manager restart.
            for expected_scopes in [
                BTreeSet::from(["records.audit".into()]),
                original_scopes.clone(),
            ] {
                let slot = manager.read("user", "stub").unwrap();
                let evidence = slot.discovery_revision();
                let restarted = default_scope_manager(store.clone(), ring.clone(), config.clone());
                restarted.activate().unwrap();
                manager.deactivate();
                manager = restarted;
                let restarted_slot = manager.read("user", "stub").unwrap();
                assert_eq!(restarted_slot.discovery_revision(), evidence);
                assert_eq!(
                    restarted_slot
                        .connection
                        .as_ref()
                        .unwrap()
                        .family
                        .consent_scopes,
                    original_scopes
                );
                assert_eq!(
                    manager
                        .acquire("user", &binding())
                        .await
                        .unwrap()
                        .access_version(),
                    lease.access_version()
                );
                expire(&manager);
                let fresh = manager.acquire("user", &binding()).await.unwrap();
                manager.validate_lease(&fresh).unwrap();
                assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
                let slot = manager.read("user", "stub").unwrap();
                let family = &slot.connection.as_ref().unwrap().family;
                assert_eq!(family.consent_scopes, original_scopes);
                assert_eq!(family.access["read"].scopes, expected_scopes);
                assert_eq!(family.targets[0].scopes, expected_scopes);
                lease = fresh;
            }
            manager.disconnect("user", "stub").await.unwrap();
            assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
        }
    }

    #[tokio::test]
    async fn changing_scope_mode_invalidates_connection_flow_and_discovery_evidence() {
        let (_dir, store, ring, original, _server) = fixture().await;
        let mut explicit = original.config().clone();
        explicit.registrations.get_mut("stub").unwrap().adapter =
            OAuthAdapter::new(DEFAULT_SCOPE_DIALECT.id());
        let manager = default_scope_manager(store.clone(), ring.clone(), explicit.clone());
        manager.activate().unwrap();
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        manager
            .complete(
                "user",
                "session",
                "stub",
                &state,
                "known-scopes",
                runtime(&manager),
            )
            .await
            .unwrap();
        let lease = manager.acquire("user", &binding()).await.unwrap();
        let old_evidence = manager.read("user", "stub").unwrap().discovery_revision();
        // Explicitly writing the default mode leaves the registration unchanged.
        let reloaded = default_scope_manager(store.clone(), ring.clone(), explicit.clone());
        reloaded.activate().unwrap();
        reloaded.validate_lease(&lease).unwrap();
        assert_eq!(
            reloaded.read("user", "stub").unwrap().discovery_revision(),
            old_evidence
        );
        let pending = start(&reloaded, OAuthConnectIntent::ReplaceAccount).await;
        let mut changed = explicit;
        let profile = changed
            .registrations
            .get_mut("stub")
            .unwrap()
            .permission_profiles
            .get_mut("read")
            .unwrap();
        profile.scope_mode = OAuthScopeMode::ServerDefault;
        profile.scopes = None;
        let successor = default_scope_manager(store, ring, changed);
        successor.activate().unwrap();
        assert_eq!(
            successor.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::Disconnected
        );
        assert_eq!(
            successor.validate_lease(&lease),
            Err(OAuthError::ReconnectRequired)
        );
        assert_eq!(
            successor
                .complete(
                    "user",
                    "session",
                    "stub",
                    &pending,
                    "known-scopes",
                    runtime(&successor)
                )
                .await
                .unwrap_err(),
            OAuthError::InvalidFlow
        );
        assert!(matches!(
            successor.read("user", "stub"),
            Err(OAuthError::ReconnectRequired)
        ));
        assert_eq!(
            successor.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
        let state = start(&successor, OAuthConnectIntent::Connect).await;
        successor
            .complete(
                "user",
                "session",
                "stub",
                &state,
                "unknown-scopes",
                runtime(&successor),
            )
            .await
            .unwrap();
        assert_ne!(
            successor.read("user", "stub").unwrap().discovery_revision(),
            old_evidence
        );
    }

    #[tokio::test]
    async fn access_without_refresh_is_usable_until_expiry_then_requires_reconnect() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        manager
            .update("user", "stub", |_, current| {
                let mut current = current.unwrap();
                let connection = current.connection.as_mut().unwrap();
                // Model a dialect-approved access-only connection; stub itself
                // continues to require fresh refresh material at code exchange.
                connection.family.refresh_token = None;
                connection
                    .family
                    .access
                    .get_mut("read")
                    .unwrap()
                    .refresh_after = now() - 1;
                Ok((current, ()))
            })
            .unwrap();
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap().token(),
            "protected-access-0"
        );
        expire(&manager);
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
        assert_eq!(
            manager.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::ReconnectRequired
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/oauth/token")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn stub_initial_consent_still_requires_refresh_material() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        identity(&server).await;
        let mut response = token(0);
        response.as_object_mut().unwrap().remove("refresh_token");
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager))
                .await
                .unwrap_err(),
            OAuthError::InvalidResponse
        );
        assert!(manager.read("user", "stub").unwrap().connection.is_none());
    }

    #[tokio::test]
    async fn rejected_access_version_is_invalidated_without_refreshing_or_revoking_its_successor() {
        for has_refresh in [false, true] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            let rejected = manager.acquire("user", &binding()).await.unwrap();
            if !has_refresh {
                manager
                    .update("user", "stub", |_, current| {
                        let mut slot = current.unwrap();
                        slot.connection.as_mut().unwrap().family.refresh_token = None;
                        Ok((slot, ()))
                    })
                    .unwrap();
            }
            manager.mark_access_rejected(&rejected).unwrap();
            assert!(manager.validate_lease(&rejected).is_err());
            assert_eq!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|r| r.url.path() == "/oauth/token")
                    .count(),
                1
            );
            if has_refresh {
                Mock::given(method("POST"))
                    .and(path("/oauth/token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
                    .with_priority(1)
                    .expect(1)
                    .mount(&server)
                    .await;
                let current = manager.acquire("user", &binding()).await.unwrap();
                assert_ne!(current.access_version(), rejected.access_version());
                manager.mark_access_rejected(&rejected).unwrap();
                assert!(manager.validate_lease(&current).is_ok());
            } else {
                assert_eq!(
                    manager.status("user", "stub").unwrap().status,
                    OAuthConnectionStatus::ReconnectRequired
                );
                assert_eq!(
                    manager.acquire("user", &binding()).await.unwrap_err(),
                    OAuthError::ReconnectRequired
                );
            }
        }
    }

    #[tokio::test]
    async fn unknown_upstream_identity_requires_explicit_replacement() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let old_lease = manager.acquire("user", &binding()).await.unwrap();
        manager
            .update("user", "stub", |_, current| {
                let mut current = current.unwrap();
                current.connection.as_mut().unwrap().subject = None;
                Ok((current, ()))
            })
            .unwrap();
        assert!(manager.status("user", "stub").unwrap().subject_id.is_none());
        assert_eq!(
            manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Reconnect,
                    admission(),
                    runtime(&manager)
                )
                .await
                .err()
                .unwrap(),
            OAuthError::IdentityMismatch
        );
        let state = start(&manager, OAuthConnectIntent::ReplaceAccount).await;
        manager
            .complete("user", "session", "stub", &state, "code", runtime(&manager))
            .await
            .unwrap();
        assert!(manager.validate_lease(&old_lease).is_err());
    }

    #[tokio::test]
    async fn cancelling_unknown_identity_replacement_preserves_access_only_connection() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                let connection = slot.connection.as_mut().unwrap();
                connection.subject = None;
                connection.family.refresh_token = None;
                Ok((slot, ()))
            })
            .unwrap();
        let lease = manager.acquire("user", &binding()).await.unwrap();
        let state = start(&manager, OAuthConnectIntent::ReplaceAccount).await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ConsentPending
        );
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        let recovered = manager.acquire("user", &binding()).await.unwrap();
        assert_eq!(recovered.access_version, lease.access_version);
        assert!(manager.validate_lease(&lease).is_ok());
    }

    #[tokio::test]
    async fn unknown_identity_cancel_refreshes_same_family_and_semantic_revision_ignores_bookkeeping()
     {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                slot.connection.as_mut().unwrap().subject = None;
                Ok((slot, ()))
            })
            .unwrap();
        let initial = manager.read("user", "stub").unwrap();
        let mut bookkeeping = initial.clone();
        bookkeeping.connection.as_mut().unwrap().family.retry_count = 2;
        bookkeeping
            .connection
            .as_mut()
            .unwrap()
            .family
            .retry_not_before = now_millis() + 1000;
        assert_eq!(
            initial.discovery_revision(),
            bookkeeping.discovery_revision()
        );
        let state = start(&manager, OAuthConnectIntent::ReplaceAccount).await;
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .expect(1)
            .mount(&server)
            .await;
        let lease = manager.acquire("user", &binding()).await.unwrap();
        assert_eq!(lease.token(), "protected-access-1");
        let current = manager.read("user", "stub").unwrap();
        assert_eq!(
            current.connection.as_ref().unwrap().revalidation,
            ConsentRevalidation::None
        );
        assert_ne!(initial.discovery_revision(), current.discovery_revision());
    }

    #[tokio::test]
    async fn callback_return_path_is_bound_to_the_pending_browser_flow() {
        let (_dir, _store, _ring, manager, _server) = fixture().await;
        let mut request = admission();
        request.return_path = Some(OAuthReturnPath::Catalog);
        let started = manager
            .connect(
                "user",
                "session",
                &binding(),
                OAuthConnectIntent::Connect,
                request,
                runtime(&manager),
            )
            .await
            .unwrap();
        let url = Url::parse(&started.authorization_url).unwrap();
        let state = url.query_pairs().find(|(key, _)| key == "state").unwrap().1;
        assert_eq!(
            manager
                .callback_return_path("user", "session", "stub", &state)
                .unwrap(),
            "/ui/admin/catalog/services/oauth_stub/import"
        );
        assert!(
            manager
                .callback_return_path("user", "other-session", "stub", &state)
                .is_err()
        );
        assert!(
            manager
                .callback_return_path("user", "session", "stub", "wrong-state")
                .is_err()
        );
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        assert!(
            manager
                .callback_return_path("user", "session", "stub", &state)
                .is_err()
        );
        let default_state = start(&manager, OAuthConnectIntent::Connect).await;
        assert_eq!(
            manager
                .callback_return_path("user", "session", "stub", &default_state)
                .unwrap(),
            "/ui/credentials"
        );
    }

    #[test]
    fn oauth_return_paths_reject_arbitrary_redirects() {
        for path in [
            "https://outside.example/ui/admin/catalog",
            "//outside.example",
            "/ui/admin/catalog?service=other",
            "/ui/admin/catalog#fragment",
            "/ui/admin/catalog/",
            "/ui/admin/catalog/services/other/import",
            "/ui/admin/imports",
            "/ui/tokens",
        ] {
            assert!(
                serde_json::from_value::<OAuthReturnPath>(serde_json::json!(path)).is_err(),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn callback_issuer_is_pinned_to_the_pending_browser_flow() {
        let (_dir, _store, _ring, manager, _server) = fixture().await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        let expected = manager
            .callback_issuer("user", "session", "stub", &state)
            .unwrap();
        assert!(expected.accepts(Some(&manager.config().registrations["stub"].base_url)));
        assert!(!expected.accepts(Some("https://other-issuer.example")));
        assert!(
            manager
                .callback_issuer("user", "other-session", "stub", &state)
                .is_err()
        );
        assert!(
            manager
                .callback_issuer("user", "session", "stub", "wrong-state")
                .is_err()
        );
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        assert!(
            manager
                .callback_issuer("user", "session", "stub", &state)
                .is_err()
        );
    }

    #[tokio::test]
    async fn lifecycle_encrypts_restart_and_revokes_stale_lease() {
        let (dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let lease = manager.acquire("user", &binding()).await.unwrap();
        manager.validate_lease(&lease).unwrap();
        assert_eq!(lease.token(), "protected-access-0");
        for name in ["oauth.sqlite", "oauth.sqlite-wal"] {
            if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
                assert!(!bytes.windows(16).any(|w| w == b"protected-access"));
                assert!(!bytes.windows(17).any(|w| w == b"protected-refresh"));
            }
        }
        store.check_ready(Some(&ring)).unwrap();
        let restarted =
            stub_manager(store.clone(), ring.clone(), manager.config().clone()).unwrap();
        restarted.activate().unwrap();
        assert_eq!(
            restarted
                .acquire("user", &binding())
                .await
                .unwrap()
                .access_version(),
            lease.access_version()
        );
        restarted.disconnect("user", "stub").await.unwrap();
        assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
        assert_eq!(
            restarted.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
    }

    #[tokio::test]
    async fn session_grant_and_account_binding_are_rechecked() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        assert!(matches!(
            manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Connect,
                    admission(),
                    runtime(&manager)
                )
                .await,
            Err(OAuthError::FlowLimit)
        ));
        assert_eq!(
            manager
                .complete(
                    "user",
                    "wrong-session",
                    "stub",
                    &state,
                    "code",
                    runtime(&manager)
                )
                .await
                .unwrap_err(),
            OAuthError::InvalidFlow
        );
        test_sql(&store, "UPDATE policy_grants SET status='disabled'");
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager))
                .await
                .unwrap_err(),
            OAuthError::SetupDenied
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(manager.read("user", "stub").unwrap().flows.is_empty());
        test_sql(&store, "UPDATE policy_grants SET status='active'");
        connected(&manager, &server).await;
        let state = start(&manager, OAuthConnectIntent::Reconnect).await;
        server.reset().await;
        identity(&server).await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"bob","name":"Alice"})),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .mount(&server)
            .await;
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager))
                .await
                .unwrap_err(),
            OAuthError::IdentityMismatch
        );
        assert_eq!(
            manager
                .status("user", "stub")
                .unwrap()
                .subject_id
                .as_deref(),
            Some("alice")
        );
        // A failed, consumed callback is cleaned up; retry does not wait for the flow TTL.
        start(&manager, OAuthConnectIntent::Reconnect).await;
    }

    #[tokio::test]
    async fn oauth_rights_alone_do_not_authorize_setup() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        test_sql(
            &store,
            "UPDATE policy_grants SET status='disabled';
            INSERT INTO rights(right_id,principal_id,right_name,created_by,created_at)
            VALUES('legacy','user','credentials:self:write','admin','2026-01-01T00:00:00Z');",
        );
        assert!(matches!(
            manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Connect,
                    admission(),
                    runtime(&manager),
                )
                .await,
            Err(OAuthError::SetupDenied)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(matches!(
            manager.read("user", "stub"),
            Err(OAuthError::ReconnectRequired)
        ));
    }

    #[tokio::test]
    async fn grant_withdrawal_during_exchange_does_not_install_tokens() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        identity(&server).await;
        let during_exchange = store.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                test_sql(
                    &during_exchange,
                    "UPDATE policy_grants SET status='disabled'",
                );
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager),)
                .await
                .unwrap_err(),
            OAuthError::SetupDenied
        );
        let slot = manager.read("user", "stub").unwrap();
        assert!(slot.connection.is_none());
        assert!(slot.flows.is_empty());
        test_sql(&store, "UPDATE policy_grants SET status='active'");
        start(&manager, OAuthConnectIntent::Connect).await;
    }

    #[tokio::test]
    async fn admission_storage_failure_preserves_the_matching_unclaimed_flow() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        let current = runtime(&manager);
        test_sql(
            &store,
            "UPDATE policy_grants SET actions_json='invalid-json'",
        );
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", current,)
                .await
                .unwrap_err(),
            OAuthError::Storage
        );
        let slot = manager.read("user", "stub").unwrap();
        assert_eq!(slot.flows.len(), 1);
        assert!(!slot.flows[&digest(&state)].consumed);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn group_removal_or_evidence_expiry_during_exchange_preserves_old_connection() {
        for external_evidence in [false, true] {
            let (_dir, store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            let current = runtime(&manager);
            test_sql(&store, "INSERT INTO groups(group_id,status,created_at,created_by,updated_at,updated_by)
                VALUES('oauth-users','active','2020-01-01T00:00:00Z','admin','2020-01-01T00:00:00Z','admin');
                UPDATE policy_grant_subjects SET subject='group:oauth-users' WHERE grant_id='oauth';");
            if external_evidence {
                test_sql(&store, "INSERT INTO principal_login_methods(login_method_id,principal_id,method,external_provider,external_subject,status,created_at,updated_at,created_by,updated_by)
                    VALUES('oidc-login','user','oidc','microsoft','external-user','active','2020-01-01T00:00:00Z','2020-01-01T00:00:00Z','admin','admin');
                    INSERT INTO oidc_provider_state(provider_id,tenant_id,client_id,enabled,config_generation,config_fingerprint,external_membership_ttl_s,updated_at)
                    VALUES('microsoft','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222',1,1,'test',3600,'2020-01-01T00:00:00Z')
                    ON CONFLICT(provider_id) DO UPDATE SET enabled=1;
                    INSERT INTO external_group_bindings(binding_id,external_group_id,group_id,status,created_at,created_by,updated_at,updated_by)
                    VALUES('binding','33333333-3333-3333-3333-333333333333','oauth-users','active','2020-01-01T00:00:00Z','admin','2020-01-01T00:00:00Z','admin');
                    INSERT INTO oidc_membership_refresh_state(login_method_id,observed_at,evidence_at,valid_until,updated_at)
                    VALUES('oidc-login','2020-01-01T00:00:00Z','2020-01-01T00:00:00Z','2099-01-01T00:00:00Z','2020-01-01T00:00:00Z');
                    INSERT INTO external_principal_groups(login_method_id,binding_id,observed_at,evidence_at,valid_until,updated_at)
                    VALUES('oidc-login','binding','2020-01-01T00:00:00Z','2020-01-01T00:00:00Z','2099-01-01T00:00:00Z','2020-01-01T00:00:00Z');");
            } else {
                test_sql(
                    &store,
                    "INSERT INTO principal_groups VALUES('user','oauth-users','2020-01-01T00:00:00Z','admin')",
                );
            }
            let started = manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Reconnect,
                    admission(),
                    Arc::clone(&current),
                )
                .await
                .unwrap();
            let url = Url::parse(&started.authorization_url).unwrap();
            let state = url
                .query_pairs()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1
                .into_owned();
            let before = manager.read("user", "stub").unwrap();
            server.reset().await;
            identity(&server).await;
            let during_exchange = store.clone();
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(move |_: &wiremock::Request| {
                    test_sql(&during_exchange, if external_evidence {
                        "UPDATE external_principal_groups SET valid_until='2020-01-02T00:00:00Z'"
                    } else {
                        "DELETE FROM principal_groups WHERE principal_id='user' AND group_id='oauth-users'"
                    });
                    ResponseTemplate::new(200).set_body_json(token(1))
                })
                .expect(1)
                .mount(&server).await;
            assert_eq!(
                manager
                    .complete(
                        "user",
                        "session",
                        "stub",
                        &state,
                        "code",
                        Arc::clone(&current),
                    )
                    .await
                    .unwrap_err(),
                OAuthError::SetupDenied
            );
            let after = manager.read("user", "stub").unwrap();
            assert_eq!(after.generation, before.generation);
            assert_eq!(
                serde_json::to_value(&after.connection).unwrap(),
                serde_json::to_value(&before.connection).unwrap()
            );
            assert!(after.flows.is_empty());
            assert!(matches!(
                manager
                    .connect(
                        "user",
                        "session",
                        &binding(),
                        OAuthConnectIntent::Reconnect,
                        admission(),
                        current,
                    )
                    .await,
                Err(OAuthError::SetupDenied)
            ));
        }
    }

    #[tokio::test]
    async fn current_runtime_binding_is_rechecked_before_exchange_and_install() {
        for publish_during_exchange in [false, true] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            let resolver = runtime(&manager);
            let published = Arc::new(arc_swap::ArcSwap::from(resolver()));
            let current = Arc::clone(&published);
            let resolver: OAuthRuntimeResolver = Arc::new(move || current.load_full());
            let start = manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Connect,
                    admission(),
                    Arc::clone(&resolver),
                )
                .await
                .unwrap();
            let url = Url::parse(&start.authorization_url).unwrap();
            let state = url
                .query_pairs()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1
                .into_owned();
            let mut changed = published.load().config().clone();
            let alternate = changed.oauth.registrations["stub"].permission_profiles["read"].clone();
            changed
                .oauth
                .registrations
                .get_mut("stub")
                .unwrap()
                .permission_profiles
                .insert("other".into(), alternate);
            changed
                .credentials
                .per_user
                .get_mut("oauth_stub")
                .unwrap()
                .profile = Some("other".into());
            let changed =
                Arc::new(crate::BrokerRuntime::new_for_reload(changed, &published.load()).unwrap());
            if publish_during_exchange {
                identity(&server).await;
                let current = Arc::clone(&published);
                Mock::given(method("POST"))
                    .and(path("/oauth/token"))
                    .respond_with(move |_: &wiremock::Request| {
                        current.store(Arc::clone(&changed));
                        ResponseTemplate::new(200).set_body_json(token(1))
                    })
                    .expect(1)
                    .mount(&server)
                    .await;
            } else {
                published.store(changed);
            }
            assert_eq!(
                manager
                    .complete("user", "session", "stub", &state, "code", resolver,)
                    .await
                    .unwrap_err(),
                OAuthError::Stale
            );
            if !publish_during_exchange {
                assert!(server.received_requests().await.unwrap().is_empty());
            }
            let slot = manager.read("user", "stub").unwrap();
            assert!(slot.flows.is_empty());
            assert!(slot.connection.is_none());
        }
    }

    #[tokio::test]
    async fn runtime_publication_does_not_preserve_a_withdrawn_setup_grant() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        let published = Arc::new(arc_swap::ArcSwap::from(runtime(&manager)()));
        let current = Arc::clone(&published);
        let resolver: OAuthRuntimeResolver = Arc::new(move || current.load_full());
        let started = manager
            .connect(
                "user",
                "session",
                &binding(),
                OAuthConnectIntent::Connect,
                admission(),
                Arc::clone(&resolver),
            )
            .await
            .unwrap();
        let url = Url::parse(&started.authorization_url).unwrap();
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        // Like an unrelated imported-catalog publication, this gives the new
        // runtime its own policy holder while retaining the old OAuth manager.
        let next = Arc::new(crate::BrokerRuntime::new(published.load().config().clone()).unwrap());
        published.store(Arc::clone(&next));
        test_sql(&store, "UPDATE policy_grants SET status='disabled'");
        let identity = next.identity_from_principal_groups(
            "user".into(),
            Some("user".into()),
            Vec::new(),
            None,
            None,
        );
        assert!(next.has_any_per_user_policy_for_service(&identity, "oauth_stub"));
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", resolver,)
                .await
                .unwrap_err(),
            OAuthError::SetupDenied
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(manager.read("user", "stub").unwrap().flows.is_empty());
    }

    #[tokio::test]
    async fn denied_flow_retirement_preserves_cancel_revalidation_semantics() {
        for unknown_access_only in [false, true] {
            let (_dir, store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            if unknown_access_only {
                manager
                    .update("user", "stub", |_, current| {
                        let mut slot = current.unwrap();
                        let connection = slot.connection.as_mut().unwrap();
                        connection.subject = None;
                        connection.family.refresh_token = None;
                        Ok((slot, ()))
                    })
                    .unwrap();
            }
            let lease = manager.acquire("user", &binding()).await.unwrap();
            let state = start(&manager, OAuthConnectIntent::ReplaceAccount).await;
            let before = manager.read("user", "stub").unwrap();
            test_sql(&store, "UPDATE policy_grants SET status='disabled'");
            // A valid session with unrelated state must never retire the real flow.
            assert_eq!(
                manager
                    .complete(
                        "user",
                        "session",
                        "stub",
                        "wrong-state",
                        "code",
                        runtime(&manager),
                    )
                    .await
                    .unwrap_err(),
                OAuthError::InvalidFlow
            );
            assert_eq!(manager.read("user", "stub").unwrap().flows.len(), 1);
            assert_eq!(
                manager
                    .complete("user", "session", "stub", &state, "code", runtime(&manager),)
                    .await
                    .unwrap_err(),
                OAuthError::SetupDenied
            );
            let after = manager.read("user", "stub").unwrap();
            assert!(after.flows.is_empty());
            assert_eq!(after.generation, before.generation);
            assert_eq!(
                serde_json::to_value(&after.connection).unwrap(),
                serde_json::to_value(&before.connection).unwrap()
            );
            assert_eq!(manager.validate_lease(&lease).is_ok(), unknown_access_only);
            test_sql(&store, "UPDATE policy_grants SET status='active'");
            start(&manager, OAuthConnectIntent::ReplaceAccount).await;
        }
    }

    #[tokio::test]
    async fn self_service_disablement_is_rechecked_before_and_after_oauth_exchange() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        test_sql(
            &store,
            "UPDATE principals SET self_service_enabled=0 WHERE principal_id='user'",
        );
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager))
                .await
                .unwrap_err(),
            OAuthError::SelfServiceDisabled
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(matches!(
            manager
                .connect(
                    "user",
                    "session",
                    &binding(),
                    OAuthConnectIntent::Connect,
                    admission(),
                    runtime(&manager)
                )
                .await,
            Err(OAuthError::SelfServiceDisabled)
        ));
        test_sql(
            &store,
            "UPDATE principals SET self_service_enabled=1 WHERE principal_id='user'",
        );
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        identity(&server).await;
        let during_exchange = store.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                test_sql(
                    &during_exchange,
                    "UPDATE principals SET self_service_enabled=0 WHERE principal_id='user'",
                );
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .mount(&server)
            .await;
        assert_eq!(
            manager
                .complete("user", "session", "stub", &state, "code", runtime(&manager))
                .await
                .unwrap_err(),
            OAuthError::SelfServiceDisabled
        );
        // The upstream exchange succeeded, but its result must never become a
        // stored connection after the owner loses personal management access.
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
    }

    /// Serves refresh grants with successive tokens, starting at 1.
    async fn successive_refreshes(server: &MockServer) {
        server.reset().await;
        identity(server).await;
        let issued = AtomicUsize::new(1);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .set_body_json(token(issued.fetch_add(1, Ordering::SeqCst)))
            })
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn delegated_leases_follow_superseded_access_and_recover_once() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        successive_refreshes(&server).await;
        let credential =
            ManagedOAuthLease::acquire(manager.clone(), "records".into(), "user".into(), binding())
                .await
                .unwrap();
        let first = credential.access();
        assert_eq!(first.token, "protected-access-0");
        assert_eq!(first.target, "workspace-one");
        credential.revalidate().await.unwrap();
        assert_eq!(credential.access(), first);

        // Another invocation refreshed the connection: the lent access is
        // stale, and revalidation moves to the current access.
        expire(&manager);
        let current = manager.acquire("user", &binding()).await.unwrap();
        assert_eq!(current.token(), "protected-access-1");
        credential.revalidate().await.unwrap();
        assert_eq!(credential.access().version, current.access_version());

        let recovered = credential.recover_after_unauthorized().await.unwrap();
        assert_eq!(recovered.token, "protected-access-2");
        assert_eq!(credential.access(), recovered);
        let again = credential.recover_after_unauthorized().await.unwrap_err();
        assert_eq!(again.reason_code, ReasonCode::CredentialInvalid);

        manager.disconnect("user", "stub").await.unwrap();
        let revoked = credential.revalidate().await.unwrap_err();
        assert_eq!(revoked.reason_code, ReasonCode::CredentialInvalid);
    }

    #[tokio::test]
    async fn delegated_binding_identity_survives_refresh_and_changes_on_reconnect() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        successive_refreshes(&server).await;
        let credential =
            ManagedOAuthLease::acquire(manager.clone(), "records".into(), "user".into(), binding())
                .await
                .unwrap();
        let identity = credential.binding_identity();
        assert_eq!(format!("{identity:?}"), "DelegatedBindingId(<redacted>)");

        // Routine refresh by another invocation and this invocation's own
        // recovery keep the binding.
        expire(&manager);
        manager.acquire("user", &binding()).await.unwrap();
        credential.revalidate().await.unwrap();
        assert_eq!(credential.binding_identity(), identity);
        credential.recover_after_unauthorized().await.unwrap();
        assert_eq!(credential.binding_identity(), identity);

        // Another service lent the same connection is another binding.
        let other_service =
            ManagedOAuthLease::acquire(manager.clone(), "other".into(), "user".into(), binding())
                .await
                .unwrap();
        assert_ne!(other_service.binding_identity(), identity);

        // A disconnect and new consent create a new connection and binding.
        manager.disconnect("user", "stub").await.unwrap();
        server.reset().await;
        connected(&manager, &server).await;
        let reconnected =
            ManagedOAuthLease::acquire(manager.clone(), "records".into(), "user".into(), binding())
                .await
                .unwrap();
        assert_ne!(reconnected.binding_identity(), identity);
        assert!(credential.revalidate().await.is_err());
    }

    #[test]
    fn delegated_binding_identity_covers_binding_fields_but_not_access() {
        let lease = OAuthLease {
            token: "access-token".into(),
            owner: "user".into(),
            binding: binding(),
            config_fingerprint: "fingerprint".into(),
            generation: "generation".into(),
            connection_id: "connection".into(),
            access_version: "version-1".into(),
            target: "target".into(),
            audience: "audience".into(),
            expires_at: 100,
        };
        let identity = lease::delegated_binding_identity("records", &lease);
        let refreshed = OAuthLease {
            token: "renewed-token".into(),
            access_version: "version-2".into(),
            expires_at: 200,
            ..lease.clone()
        };
        assert_eq!(
            lease::delegated_binding_identity("records", &refreshed),
            identity
        );
        let changed = |change: fn(&mut OAuthLease)| {
            let mut changed = lease.clone();
            change(&mut changed);
            lease::delegated_binding_identity("records", &changed)
        };
        for other in [
            changed(|lease| lease.owner = "other-user".into()),
            changed(|lease| lease.binding.registration = "other-registration".into()),
            changed(|lease| lease.binding.permission_profile = "write".into()),
            changed(|lease| lease.config_fingerprint = "other-fingerprint".into()),
            changed(|lease| lease.generation = "other-generation".into()),
            changed(|lease| lease.connection_id = "other-connection".into()),
            lease::delegated_binding_identity("other-service", &lease),
        ] {
            assert_ne!(other, identity);
        }
        // Length delimiting keeps adjacent fields from running together:
        // "records" + "user" and "recordsu" + "ser" concatenate identically.
        let shifted = OAuthLease {
            owner: "ser".into(),
            ..lease.clone()
        };
        assert_ne!(
            lease::delegated_binding_identity("recordsu", &shifted),
            identity
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_is_single_flight_and_survives_waiter_cancellation() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        identity(&server).await;
        let count = Arc::new(AtomicUsize::new(0));
        let called = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let count2 = count.clone();
        let called2 = called.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["refresh_token"], "protected-refresh-0");
                assert_eq!(body["client_secret"], "application-secret");
                count2.fetch_add(1, Ordering::SeqCst);
                called2.notify_one();
                released.lock().unwrap().recv().unwrap();
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .mount(&server)
            .await;
        let worker = manager.clone();
        let task = tokio::spawn(async move { worker.acquire("user", &binding()).await });
        called.notified().await;
        let before = serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap();
        let discovered = manager.check_credential("user", &binding());
        let after = serde_json::to_value(manager.read("user", "stub").unwrap()).unwrap();
        task.abort();
        release.send(()).unwrap();
        assert_eq!(discovered, Ok(()), "discovery must retain a live refresh");
        assert_eq!(before, after, "discovery must not write refresh state");
        let mut waiters = Vec::new();
        for _ in 0..12 {
            let m = manager.clone();
            waiters.push(tokio::spawn(async move {
                m.acquire("user", &binding()).await.unwrap()
            }));
        }
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().token(), "protected-access-1");
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(
            manager
                .inner
                .live_refresh_attempts
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            manager
                .read("user", "stub")
                .unwrap()
                .connection
                .unwrap()
                .family
                .refresh_token
                .as_deref(),
            Some("protected-refresh-1")
        );
    }

    #[tokio::test]
    async fn delegated_invocations_never_follow_replacement_accounts() {
        for recover in [false, true] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            let credential = ManagedOAuthLease::acquire(
                manager.clone(),
                "records".into(),
                "user".into(),
                binding(),
            )
            .await
            .unwrap();
            manager
                .update("user", "stub", |_, current| {
                    let mut slot = current.unwrap();
                    slot.generation = Uuid::new_v4().to_string();
                    let c = slot.connection.as_mut().unwrap();
                    c.id = Uuid::new_v4().to_string();
                    c.subject = Some("different-account".into());
                    Ok((slot, ()))
                })
                .unwrap();
            server.reset().await;
            let result = if recover {
                credential.recover_after_unauthorized().await.map(|_| ())
            } else {
                credential.revalidate().await
            };
            assert_eq!(
                result.unwrap_err().reason_code,
                ReasonCode::CredentialInvalid
            );
            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn reusable_refresh_recovers_interruption_and_bounds_protocol_failures() {
        let (_dir, store, ring, original, server) = fixture().await;
        let mut config = original.config().clone();
        config.registrations.get_mut("stub").unwrap().rotation = OAuthRotation::PreserveOld;
        let manager = stub_manager(store.clone(), ring.clone(), config.clone()).unwrap();
        manager.activate().unwrap();
        connected(&manager, &server).await;
        expire(&manager);
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                let family = &mut slot.connection.as_mut().unwrap().family;
                family.retry_count = 5;
                family.attempt = Some(RefreshAttempt {
                    id: "interrupted".into(),
                    material_version: family.material_version.clone(),
                    expires_at: now() - 1,
                });
                Ok((slot, ()))
            })
            .unwrap();
        let manager = stub_manager(store, ring, config).unwrap();
        manager.activate().unwrap();
        let recovery_start = now_millis();
        // An interrupted attempt is a failure, not throttling: refresh is
        // paused after it, reporting the failure.
        let Err(OAuthError::RefreshPaused {
            seconds: retry,
            failure,
        }) = manager.acquire("user", &binding()).await
        else {
            panic!("expected cooldown")
        };
        assert_eq!(*failure, OAuthError::Provider);
        let family = manager
            .read("user", "stub")
            .unwrap()
            .connection
            .unwrap()
            .family;
        assert!(family.retry_not_before >= recovery_start + 32_000);
        let remaining = ((family.retry_not_before - now_millis()).max(0) as u64).div_ceil(1000);
        assert!(retry >= remaining && retry <= 32);
        assert_eq!(family.refresh_token.as_deref(), Some("protected-refresh-0"));
        assert!(family.access.is_empty());
        release_cooldown(&manager);
        server.reset().await;
        identity(&server).await;
        let mut response = token(1);
        response.as_object_mut().unwrap().remove("refresh_token");
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap().token(),
            "protected-access-1"
        );
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{broken"))
            .expect(3)
            .mount(&server)
            .await;
        for attempt in 0..3 {
            release_cooldown(&manager);
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                if attempt < 2 {
                    OAuthError::InvalidResponse
                } else {
                    OAuthError::ReconnectRequired
                }
            );
            let c = manager.read("user", "stub").unwrap().connection.unwrap();
            assert!(c.family.access.is_empty());
            assert_eq!(
                c.family.refresh_token.as_deref(),
                if attempt < 2 {
                    Some("protected-refresh-0")
                } else {
                    None
                }
            );
        }
        assert_eq!(
            manager.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::ReconnectRequired
        );
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
    }

    #[tokio::test]
    async fn reusable_material_survives_sent_transport_and_server_failures_but_not_invalid_grant() {
        use tokio::io::AsyncReadExt;
        for failure in ["transport", "server", "retry_after", "invalid_grant"] {
            let (_dir, store, ring, original, server) = fixture().await;
            let mut config = original.config().clone();
            config.registrations.get_mut("stub").unwrap().rotation = OAuthRotation::PreserveOld;
            let mut manager = stub_manager(store.clone(), ring.clone(), config.clone()).unwrap();
            manager.activate().unwrap();
            connected(&manager, &server).await;
            expire(&manager);
            server.reset().await;
            let dropped = if failure == "transport" {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let r = Arc::get_mut(&mut manager.inner)
                    .unwrap()
                    .registrations
                    .get_mut("stub")
                    .unwrap();
                r.config.base_url = url;
                r.http = OAuthHttp::build(
                    "drop-test",
                    "oauth",
                    &Url::parse(&r.config.base_url).unwrap(),
                    &r.dialect.upstream_allowlist(&r.config),
                    &direct_network().client_factory(ClientCaller::HostOAuth),
                )
                .unwrap();
                Some(tokio::spawn(async move {
                    let (mut socket, _) =
                        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                            .await
                            .expect("refresh request must reach drop server")
                            .unwrap();
                    let mut received = Vec::new();
                    loop {
                        let mut buf = [0; 4096];
                        let n = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            socket.read(&mut buf),
                        )
                        .await
                        .expect("refresh body must arrive")
                        .unwrap();
                        assert!(n > 0);
                        received.extend_from_slice(&buf[..n]);
                        if String::from_utf8_lossy(&received).contains("protected-refresh-0") {
                            break;
                        }
                    }
                    // Drop only after observing refresh material in the sent body.
                }))
            } else {
                let status = match failure {
                    "server" => 503,
                    "retry_after" => 429,
                    _ => 400,
                };
                Mock::given(method("POST"))
                    .and(path("/oauth/token"))
                    .respond_with(
                        ResponseTemplate::new(status)
                            .insert_header("Retry-After", "2")
                            .set_body_json(serde_json::json!({"error":failure})),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                None
            };
            let error = manager.acquire("user", &binding()).await.unwrap_err();
            if let Some(task) = dropped {
                task.await.unwrap();
            }
            let c = manager.read("user", "stub").unwrap().connection.unwrap();
            assert!(c.family.access.is_empty());
            assert!(c.family.attempt.is_none());
            if failure == "invalid_grant" {
                assert_eq!(error, OAuthError::ReconnectRequired);
                assert_eq!(c.status, OAuthConnectionStatus::ReconnectRequired);
                assert!(c.family.refresh_token.is_none());
                continue;
            }
            assert_eq!(c.status, OAuthConnectionStatus::Ready);
            assert_eq!(
                c.family.refresh_token.as_deref(),
                Some("protected-refresh-0")
            );
            assert!(c.family.retry_not_before > 0);
            if failure == "retry_after" {
                assert!(matches!(error, OAuthError::RetryLater(1..=2)));
            }
            let restarted = stub_manager(store, ring, config).unwrap();
            restarted.activate().unwrap();
            // The cooldown's cause survives a restart: only throttling reads
            // as throttling; a failure pauses refresh and names the failure.
            match restarted.acquire("user", &binding()).await.unwrap_err() {
                OAuthError::RetryLater(_) => assert_eq!(failure, "retry_after"),
                OAuthError::RefreshPaused {
                    failure: cause,
                    seconds,
                } => {
                    assert_ne!(failure, "retry_after");
                    assert_eq!(*cause, error);
                    assert!(seconds >= 1);
                }
                other => panic!("{failure}: {other:?}"),
            }
            assert_eq!(
                restarted
                    .read("user", "stub")
                    .unwrap()
                    .connection
                    .unwrap()
                    .family
                    .retry_not_before,
                c.family.retry_not_before
            );
            release_cooldown(&restarted);
            server.reset().await;
            identity(&server).await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                restarted.acquire("user", &binding()).await.unwrap().token(),
                "protected-access-1"
            );
        }
    }

    #[tokio::test]
    async fn lost_response_fences_family_and_restart_never_replays() {
        let (_dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{truncated"))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::RefreshUncertain
        );
        let restarted = stub_manager(store, ring, manager.config().clone()).unwrap();
        restarted.activate().unwrap();
        assert_eq!(
            restarted.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::RefreshUncertain
        );
        assert_eq!(
            restarted.status("user", "stub").unwrap().reason.as_deref(),
            Some("oauth_refresh_uncertain")
        );
    }

    #[tokio::test]
    async fn discovery_failure_keeps_rotated_successor_without_replaying_refresh() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"error":"unavailable"})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        assert!(manager.acquire("user", &binding()).await.is_err());
        identity(&server).await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap().token(),
            "protected-access-1"
        );
    }

    #[tokio::test]
    async fn config_activation_is_staged_secret_rotation_preserves_material() {
        let (dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let lease = manager.acquire("user", &binding()).await.unwrap();
        let new_secret = dir.path().join("rotated-secret");
        std::fs::write(&new_secret, "rotated").unwrap();
        let mut changed = manager.config().clone();
        changed
            .registrations
            .get_mut("stub")
            .unwrap()
            .client_secret_ref = format!("file:{}", new_secret.display());
        let successor = stub_manager(store.clone(), ring.clone(), changed).unwrap();
        manager.validate_lease(&lease).unwrap();
        successor.activate().unwrap();
        manager.deactivate();
        assert_eq!(
            successor
                .acquire("user", &binding())
                .await
                .unwrap()
                .access_version(),
            lease.access_version()
        );
        assert_eq!(manager.validate_lease(&lease), Err(OAuthError::Stale));
        let mut changed = successor.config().clone();
        changed.registrations.get_mut("stub").unwrap().client_id = "different-application".into();
        let changed = stub_manager(store, ring, changed).unwrap();
        successor.validate_lease(&lease).unwrap();
        changed.activate().unwrap();
        assert_eq!(
            successor.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::Stale
        );
        assert_eq!(
            changed.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ReconnectRequired
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnected_inflight_refresh_cannot_resurrect_material() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        let called = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let signal = called.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                signal.notify_one();
                released.lock().unwrap().recv().unwrap();
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .mount(&server)
            .await;
        let m = manager.clone();
        let task = tokio::spawn(async move { m.acquire("user", &binding()).await });
        called.notified().await;
        manager.disconnect("user", "stub").await.unwrap();
        release.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap_err(), OAuthError::Stale);
        assert_eq!(
            manager.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::Disconnected
        );
    }

    #[test]
    fn target_scope_evidence_is_not_a_union_and_http_is_literal_loopback_only() {
        let profile = OAuthPermissionProfile {
            scope_mode: OAuthScopeMode::Explicit,
            scopes: Some(vec!["records.read".into(), "offline_access".into()]),
            audience: "records-api".into(),
            target: "one".into(),
        };
        let targets = vec![
            OAuthTarget {
                id: "one".into(),
                name: "One".into(),
                audience: "records-api".into(),
                scopes: BTreeSet::new(),
            },
            OAuthTarget {
                id: "two".into(),
                name: "Two".into(),
                audience: "records-api".into(),
                scopes: BTreeSet::from(["records.read".into()]),
            },
        ];
        assert_eq!(
            eligible(&profile, &BTreeSet::from(["records.read".into()]), &targets),
            Err(OAuthError::Permission)
        );
        assert!(checked_url("http://localhost:8000", true).is_err());
        assert!(checked_url("http://127.0.0.1:8000", true).is_ok());
        assert!(checked_url("http://127.0.0.1:8000", false).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn logout_during_code_redemption_prevents_install() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        identity(&server).await;
        let called = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let signal = called.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                signal.notify_one();
                released.lock().unwrap().recv().unwrap();
                ResponseTemplate::new(200).set_body_json(token(0))
            })
            .mount(&server)
            .await;
        let state = start(&manager, OAuthConnectIntent::Connect).await;
        let m = manager.clone();
        let callback = tokio::spawn(async move {
            m.complete("user", "session", "stub", &state, "code", runtime(&m))
                .await
        });
        called.notified().await;
        test_sql(
            &store,
            "UPDATE broker_tokens SET revoked_at='2026-01-01T00:00:00Z' WHERE token_id='session'",
        );
        release.send(()).unwrap();
        assert_eq!(
            callback.await.unwrap().unwrap_err(),
            OAuthError::InvalidFlow
        );
        assert_eq!(
            manager.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::Disconnected
        );
    }

    #[tokio::test]
    async fn fixing_application_secret_resumes_without_new_consent() {
        let (dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error":"invalid_client"})),
            )
            .mount(&server)
            .await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::ApplicationCredential
        );
        assert_eq!(
            manager.status("user", "stub").unwrap().status,
            OAuthConnectionStatus::OperatorActionRequired
        );
        let secret_file = dir.path().join("new-secret");
        std::fs::write(&secret_file, "fixed-app-secret").unwrap();
        let mut config = manager.config().clone();
        config
            .registrations
            .get_mut("stub")
            .unwrap()
            .client_secret_ref = format!("file:{}", secret_file.display());
        let replacement = stub_manager(store, ring, config).unwrap();
        replacement.activate().unwrap();
        manager.deactivate();
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(|request: &wiremock::Request| {
                let request: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(request["refresh_token"], "protected-refresh-0");
                assert_eq!(request["client_secret"], "fixed-app-secret");
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            replacement
                .acquire("user", &binding())
                .await
                .unwrap()
                .token(),
            "protected-access-1"
        );
    }

    #[tokio::test]
    async fn reduced_scope_or_removed_target_cannot_issue_a_lease() {
        for remove_target in [false, true] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            expire(&manager);
            server.reset().await;
            let mut response = token(1);
            if !remove_target {
                response["scope"] = serde_json::json!("offline_access");
            }
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            if remove_target {
                Mock::given(method("GET"))
                    .and(path("/targets"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({"targets":[]})),
                    )
                    .mount(&server)
                    .await;
            } else {
                identity(&server).await;
            }
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                OAuthError::Permission
            );
            assert_eq!(
                manager.status("user", "stub").unwrap().reason.as_deref(),
                Some("oauth_permission_denied")
            );
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                OAuthError::Permission
            );
            assert_eq!(
                manager.status("user", "stub").unwrap().reason.as_deref(),
                Some("oauth_permission_denied")
            );
        }
    }

    #[tokio::test]
    async fn refresh_omission_is_adapter_policy_and_rotating_profile_fails_closed() {
        for rotation in [OAuthRotation::PreserveOld, OAuthRotation::RotateRefresh] {
            let (_dir, store, ring, manager, server) = fixture().await;
            let mut config = manager.config().clone();
            config.registrations.get_mut("stub").unwrap().rotation = rotation;
            let manager = stub_manager(store, ring, config).unwrap();
            manager.activate().unwrap();
            connected(&manager, &server).await;
            expire(&manager);
            server.reset().await;
            identity(&server).await;
            let mut response = token(1);
            response.as_object_mut().unwrap().remove("refresh_token");
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            if rotation == OAuthRotation::PreserveOld {
                assert_eq!(
                    manager.acquire("user", &binding()).await.unwrap().token(),
                    "protected-access-1"
                );
                assert_eq!(
                    manager
                        .read("user", "stub")
                        .unwrap()
                        .connection
                        .unwrap()
                        .family
                        .refresh_token
                        .as_deref(),
                    Some("protected-refresh-0")
                );
            } else {
                assert_eq!(
                    manager.acquire("user", &binding()).await.unwrap_err(),
                    OAuthError::RefreshUncertain
                );
            }
        }
    }

    fn grant(token_type: &str, expires_in: u64) -> TokenGrant {
        TokenGrant {
            access_token: "protected-access-1".into(),
            token_type: token_type.into(),
            expires_in,
            scopes: vec!["records.read".into(), "offline_access".into()],
            refresh_token: IssuedRefreshToken::Issued("protected-refresh-1".into()),
            supersedes_other_access: false,
        }
    }

    #[test]
    fn unknown_token_type_and_zero_or_excessive_expiry_are_rejected() {
        assert!(access_entry(grant("Bearer", 3600), OAuthScopeMode::Explicit).is_ok());
        assert!(access_entry(grant("DPoP", 3600), OAuthScopeMode::Explicit).is_err());
        assert!(access_entry(grant("Bearer", 0), OAuthScopeMode::Explicit).is_err());
        assert!(access_entry(grant("Bearer", 31_536_001), OAuthScopeMode::Explicit).is_err());
    }

    fn release_cooldown(manager: &OAuthManager) {
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                slot.connection.as_mut().unwrap().family.retry_not_before = 0;
                Ok((slot, ()))
            })
            .unwrap();
    }

    #[tokio::test]
    async fn proven_connection_failure_preserves_family_and_later_refresh_recovers() {
        let (_dir, _store, _ring, mut manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        // Point this test's private transport at a closed listener; exercise reqwest's real is_connect classification.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        Arc::get_mut(&mut manager.inner)
            .unwrap()
            .registrations
            .get_mut("stub")
            .unwrap()
            .config
            .base_url = unavailable;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::BeforeSend
        );
        let slot = manager.read("user", "stub").unwrap();
        let c = slot.connection.unwrap();
        assert_eq!(c.status, OAuthConnectionStatus::Ready);
        assert_eq!(
            c.family.refresh_token.as_deref(),
            Some("protected-refresh-0")
        );
        assert!(c.family.attempt.is_none());
        Arc::get_mut(&mut manager.inner)
            .unwrap()
            .registrations
            .get_mut("stub")
            .unwrap()
            .config
            .base_url = server.uri();
        release_cooldown(&manager);
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["refresh_token"], "protected-refresh-0");
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap().token(),
            "protected-access-1"
        );
    }

    #[tokio::test]
    async fn explicit_nonconsuming_rejections_preserve_material_and_enforce_cooldown() {
        for (status, code, expected) in [
            (429, "temporarily_unavailable", OAuthError::RetryLater(2)),
            (400, "invalid_scope", OAuthError::Permission),
            (400, "invalid_request", OAuthError::RequestRejected),
        ] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            expire(&manager);
            server.reset().await;
            identity(&server).await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Retry-After", "2")
                        .set_body_string(if status == 429 {
                            "retry later".into()
                        } else {
                            serde_json::json!({"error":code}).to_string()
                        }),
                )
                .up_to_n_times(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(|request: &wiremock::Request| {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["refresh_token"], "protected-refresh-0");
                    ResponseTemplate::new(200).set_body_json(token(1))
                })
                .with_priority(2)
                .mount(&server)
                .await;
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                expected
            );
            assert_eq!(
                manager.status("user", "stub").unwrap().status,
                OAuthConnectionStatus::Ready
            );
            // During the cooldown, throttling stays throttling and any other
            // failure pauses refresh, naming that failure.
            match manager.acquire("user", &binding()).await.unwrap_err() {
                OAuthError::RetryLater(_) => assert_eq!(status, 429),
                OAuthError::RefreshPaused { failure, .. } => assert_eq!(*failure, expected),
                other => panic!("{other:?}"),
            }
            assert_eq!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|r| r.url.path() == "/oauth/token")
                    .count(),
                1
            );
            release_cooldown(&manager);
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap().token(),
                "protected-access-1"
            );
        }
    }

    #[tokio::test]
    async fn cancel_expiry_and_partial_consent_failure_revalidate_before_resuming() {
        for ending in ["cancel", "expiry", "failure"] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            let original = manager.acquire("user", &binding()).await.unwrap();
            let connection_id = original.connection_id().to_owned();
            let state = start(&manager, OAuthConnectIntent::Reconnect).await;
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                OAuthError::ConsentPending
            );
            assert_eq!(manager.validate_lease(&original), Err(OAuthError::Stale));
            server.reset().await;
            identity(&server).await;
            match ending {
                "cancel" => manager
                    .cancel("user", "session", "stub", &state)
                    .await
                    .unwrap(),
                "expiry" => manager
                    .update("user", "stub", |_, current| {
                        let mut slot = current.unwrap();
                        for flow in slot.flows.values_mut() {
                            flow.expires_at = now() - 1;
                        }
                        Ok((slot, ()))
                    })
                    .unwrap(),
                _ => {
                    Mock::given(method("POST"))
                        .and(path("/oauth/token"))
                        .respond_with(
                            ResponseTemplate::new(400)
                                .set_body_json(serde_json::json!({"error":"invalid_request"})),
                        )
                        .up_to_n_times(1)
                        .with_priority(1)
                        .mount(&server)
                        .await;
                    assert_eq!(
                        manager
                            .complete("user", "session", "stub", &state, "code", runtime(&manager))
                            .await
                            .unwrap_err(),
                        OAuthError::RequestRejected
                    );
                }
            }
            assert_eq!(
                manager.status("user", "stub").unwrap().status,
                OAuthConnectionStatus::Ready
            );
            assert_eq!(manager.validate_lease(&original), Err(OAuthError::Stale));
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(|request: &wiremock::Request| {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["grant_type"], "refresh_token");
                    assert_eq!(body["refresh_token"], "protected-refresh-0");
                    ResponseTemplate::new(200).set_body_json(token(1))
                })
                .with_priority(2)
                .mount(&server)
                .await;
            let recovered = manager.acquire("user", &binding()).await.unwrap();
            assert_eq!(recovered.connection_id(), connection_id);
            assert_eq!(recovered.token(), "protected-access-1");
            manager.validate_lease(&recovered).unwrap();
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|r| r.url.path() == "/me")
            );
            assert!(manager.status("user", "stub").unwrap().reason.is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_consent_never_blindly_restores_old_account_or_permissions() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let old = manager.acquire("user", &binding()).await.unwrap();
        let state = start(&manager, OAuthConnectIntent::ReplaceAccount).await;
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"different-account","name":"Alice"})),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::IdentityMismatch
        );
        assert_eq!(
            manager.acquire("user", &binding()).await.unwrap_err(),
            OAuthError::IdentityMismatch
        );
        assert_eq!(manager.validate_lease(&old), Err(OAuthError::Stale));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consent_waits_for_inflight_refresh_without_erasing_its_attempt() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        identity(&server).await;
        let called = Arc::new(tokio::sync::Notify::new());
        let signal = called.clone();
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |_: &wiremock::Request| {
                signal.notify_one();
                released.lock().unwrap().recv().unwrap();
                ResponseTemplate::new(200).set_body_json(token(1))
            })
            .mount(&server)
            .await;
        let m = manager.clone();
        let refresh = tokio::spawn(async move { m.acquire("user", &binding()).await });
        called.notified().await;
        let m = manager.clone();
        let consent = tokio::spawn(async move {
            m.connect(
                "user",
                "session",
                &binding(),
                OAuthConnectIntent::Reconnect,
                admission(),
                runtime(&m),
            )
            .await
        });
        assert!(
            manager
                .read("user", "stub")
                .unwrap()
                .connection
                .unwrap()
                .family
                .attempt
                .is_some()
        );
        assert!(manager.read("user", "stub").unwrap().flows.is_empty());
        release.send(()).unwrap();
        refresh.await.unwrap().unwrap();
        consent.await.unwrap().unwrap();
        let current = manager.read("user", "stub").unwrap();
        assert_eq!(
            current.connection.unwrap().family.refresh_token.as_deref(),
            Some("protected-refresh-1")
        );
        assert_eq!(current.flows.len(), 1);
    }

    #[tokio::test]
    async fn cached_acquires_do_not_reencrypt_or_touch_the_persisted_slot() {
        let (_dir, store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let database = rusqlite::Connection::open_with_flags(
            store.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let snapshot = || {
            database.query_row("SELECT hex(ciphertext)||'|'||hex(nonce)||'|'||updated_at||'|'||generation||'|'||config_fingerprint||'|'||key_id FROM oauth_slots WHERE owner_principal_id='user' AND registration_id='stub'",[],|row|row.get::<_,String>(0)).unwrap()
        };
        let before = snapshot();
        let first = manager.acquire("user", &binding()).await.unwrap();
        let second = manager.acquire("user", &binding()).await.unwrap();
        assert_eq!(first.access_version(), second.access_version());
        assert_eq!(snapshot(), before);
    }

    #[tokio::test]
    async fn explicit_throttling_wait_beyond_the_backoff_cap_is_honored_and_persisted() {
        let (_dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
            .expect(1)
            .mount(&server)
            .await;
        let before = now_millis();
        let OAuthError::RetryLater(remaining) =
            manager.acquire("user", &binding()).await.unwrap_err()
        else {
            panic!("expected throttling")
        };
        let after = now_millis();
        assert!((3590..=3600).contains(&remaining), "{remaining}");
        let family = manager
            .read("user", "stub")
            .unwrap()
            .connection
            .unwrap()
            .family;
        assert!(family.retry_not_before >= before + 3_600_000);
        assert!(family.retry_not_before <= after + 3_600_000);
        // The deadline survives a restart, and no refresh is sent before it.
        let restarted = stub_manager(store, ring, manager.config().clone()).unwrap();
        restarted.activate().unwrap();
        let OAuthError::RetryLater(remaining) =
            restarted.acquire("user", &binding()).await.unwrap_err()
        else {
            panic!("expected throttling")
        };
        assert!((3590..=3600).contains(&remaining), "{remaining}");
    }

    #[tokio::test]
    async fn transient_backoff_grows_to_bound_is_visible_and_resets_after_success() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        expire(&manager);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
            .expect(10)
            .mount(&server)
            .await;
        for (index, delay) in [1u64, 2, 4, 8, 16, 32, 64, 128, 256, 300]
            .into_iter()
            .enumerate()
        {
            release_cooldown(&manager);
            let before = now_millis();
            let error = manager.acquire("user", &binding()).await.unwrap_err();
            let after = now_millis();
            // Persistence and scheduling can consume part of the cooldown.
            // Assert the exact persisted delay below, and bound the returned
            // remaining delay by the measured interval rather than wall speed.
            let OAuthError::RetryLater(remaining) = error else {
                panic!("{error:?}")
            };
            let elapsed_seconds = (after - before).max(0) as u64 / 1000;
            assert!((delay.saturating_sub(elapsed_seconds).max(1)..=delay).contains(&remaining));
            let slot = manager.read("user", "stub").unwrap();
            let c = slot.connection.unwrap();
            assert_eq!(c.status, OAuthConnectionStatus::Ready);
            assert_eq!(
                c.family.refresh_token.as_deref(),
                Some("protected-refresh-0")
            );
            assert_eq!(c.family.retry_count as usize, index + 1);
            assert!(c.family.retry_not_before >= before + delay as i64 * 1000);
            assert!(c.family.retry_not_before <= after + delay as i64 * 1000);
            assert_eq!(
                manager.status("user", "stub").unwrap().reason.as_deref(),
                Some("oauth_throttled")
            );
        }
        server.reset().await;
        identity(&server).await;
        release_cooldown(&manager);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .mount(&server)
            .await;
        manager.acquire("user", &binding()).await.unwrap();
        let c = manager.read("user", "stub").unwrap().connection.unwrap();
        assert_eq!(c.family.retry_count, 0);
        assert_eq!(c.family.retry_not_before, 0);
        assert!(manager.status("user", "stub").unwrap().reason.is_none());
    }

    #[tokio::test]
    async fn rejection_budget_has_distinct_terminal_states_and_retains_material() {
        for (code, expected_status, terminal) in [
            (
                "invalid_scope",
                OAuthConnectionStatus::ReconnectRequired,
                OAuthError::ReconnectRequired,
            ),
            (
                "invalid_request",
                OAuthConnectionStatus::OperatorActionRequired,
                OAuthError::RequestRejected,
            ),
        ] {
            let (_dir, _store, _ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            expire(&manager);
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(
                    ResponseTemplate::new(400).set_body_json(serde_json::json!({"error":code})),
                )
                .expect(3)
                .mount(&server)
                .await;
            for count in 1..=3 {
                release_cooldown(&manager);
                let error = manager.acquire("user", &binding()).await.unwrap_err();
                let c = manager.read("user", "stub").unwrap().connection.unwrap();
                assert_eq!(c.family.rejection_count, count);
                assert_eq!(
                    c.family.refresh_token.as_deref(),
                    Some("protected-refresh-0")
                );
                if count < 3 {
                    assert_eq!(c.status, OAuthConnectionStatus::Ready);
                } else {
                    assert_eq!(c.status, expected_status);
                    assert_eq!(error, terminal);
                }
            }
            assert_eq!(
                manager.acquire("user", &binding()).await.unwrap_err(),
                terminal
            );
        }
    }

    #[tokio::test]
    async fn secret_recovery_preserves_consent_revalidation_and_request_rejection_is_not_secret_failure()
     {
        for token_error in ["invalid_client", "invalid_request"] {
            let (dir, store, ring, manager, server) = fixture().await;
            connected(&manager, &server).await;
            let old = manager.acquire("user", &binding()).await.unwrap();
            let state = start(&manager, OAuthConnectIntent::Reconnect).await;
            manager
                .cancel("user", "session", "stub", &state)
                .await
                .unwrap();
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(serde_json::json!({"error":token_error})),
                )
                .mount(&server)
                .await;
            let count = if token_error == "invalid_request" {
                3
            } else {
                1
            };
            for _ in 0..count {
                release_cooldown(&manager);
                assert!(manager.acquire("user", &binding()).await.is_err());
            }
            let c = manager.read("user", "stub").unwrap().connection.unwrap();
            assert_eq!(c.revalidation, ConsentRevalidation::Required);
            assert_eq!(c.status, OAuthConnectionStatus::OperatorActionRequired);
            let secret = dir.path().join("fixed-credential");
            std::fs::write(&secret, "new-secret").unwrap();
            let mut config = manager.config().clone();
            config
                .registrations
                .get_mut("stub")
                .unwrap()
                .client_secret_ref = format!("file:{}", secret.display());
            let successor = stub_manager(store, ring, config).unwrap();
            successor.activate().unwrap();
            manager.deactivate();
            assert_eq!(successor.validate_lease(&old), Err(OAuthError::Stale));
            let c = successor.read("user", "stub").unwrap().connection.unwrap();
            assert_eq!(c.revalidation, ConsentRevalidation::Required);
            if token_error == "invalid_request" {
                assert_eq!(c.status, OAuthConnectionStatus::OperatorActionRequired);
                assert_eq!(
                    successor.acquire("user", &binding()).await.unwrap_err(),
                    OAuthError::RequestRejected
                );
                continue;
            }
            assert_eq!(c.status, OAuthConnectionStatus::Ready);
            assert_eq!(c.family.retry_count, 0);
            server.reset().await;
            identity(&server).await;
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/me"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"id":"wrong-account","name":"Alice"})),
                )
                .with_priority(1)
                .mount(&server)
                .await;
            assert_eq!(
                successor.acquire("user", &binding()).await.unwrap_err(),
                OAuthError::IdentityMismatch
            );
        }
    }

    #[tokio::test]
    async fn discovery_rejects_consent_or_entry_changed_before_its_live_read() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let slot = manager.read("user", "stub").unwrap();
        let entry = slot.connection.as_ref().unwrap().family.access["read"].clone();
        let state = start(&manager, OAuthConnectIntent::Reconnect).await;
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        server.reset().await;
        let binding = binding();
        let (registration, profile) = manager.profile(&binding).unwrap();
        assert_eq!(
            manager
                .validate_entry_targets("user", &binding, &slot, &entry, profile, registration)
                .await
                .unwrap_err(),
            OAuthError::Stale
        );
        manager
            .update("user", "stub", |_, current| {
                let mut current = current.unwrap();
                let c = current.connection.as_mut().unwrap();
                assert_eq!(c.revalidation, ConsentRevalidation::Required);
                c.revalidation = ConsentRevalidation::Pending;
                c.family.access.get_mut("read").unwrap().version = Uuid::new_v4().to_string();
                Ok((current, ()))
            })
            .unwrap();
        assert_eq!(
            manager
                .validate_entry_targets("user", &binding, &slot, &entry, profile, registration)
                .await
                .unwrap_err(),
            OAuthError::Stale
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_manager_discovery_cannot_clear_new_consent_after_reload() {
        let (_dir, store, ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let state = start(&manager, OAuthConnectIntent::Reconnect).await;
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        // Establish a real committed successor awaiting discovery.
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        assert!(manager.acquire("user", &binding()).await.is_err());
        let before = manager.read("user", "stub").unwrap();
        let c = before.connection.as_ref().unwrap();
        assert_eq!(c.revalidation, ConsentRevalidation::Pending);
        let version = c.family.access["read"].version.clone();
        server.reset().await;
        identity(&server).await;
        let called = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let signal = called.clone();
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(move |_: &wiremock::Request| {
                signal.notify_one();
                released.lock().unwrap().recv().unwrap();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"targets":[{"id":"workspace-one","name":"One","audience":"records-api","scopes":["records.read"]}]}))
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let old = manager.clone();
        let discovery = tokio::spawn(async move { old.acquire("user", &binding()).await });
        called.notified().await;
        let replacement = stub_manager(store, ring, manager.config().clone()).unwrap();
        replacement.activate().unwrap();
        manager.deactivate();
        let state = start(&replacement, OAuthConnectIntent::Reconnect).await;
        replacement
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(discovery.await.unwrap().unwrap_err(), OAuthError::Stale);
        let c = replacement
            .read("user", "stub")
            .unwrap()
            .connection
            .unwrap();
        assert_eq!(c.revalidation, ConsentRevalidation::Required);
        assert_eq!(c.family.access["read"].version, version);
        assert!(!c.family.access["read"].targets_validated);
    }

    #[tokio::test]
    async fn expired_flow_does_not_block_pending_successor_discovery() {
        let (_dir, _store, _ring, manager, server) = fixture().await;
        connected(&manager, &server).await;
        let state = start(&manager, OAuthConnectIntent::Reconnect).await;
        let mut expired = manager
            .read("user", "stub")
            .unwrap()
            .flows
            .values()
            .next()
            .unwrap()
            .clone();
        expired.expires_at = now() - 1;
        manager
            .cancel("user", "session", "stub", &state)
            .await
            .unwrap();
        server.reset().await;
        identity(&server).await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token(1)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/targets"))
            .respond_with(
                ResponseTemplate::new(503).set_body_json(serde_json::json!({"error":"temporary"})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        assert!(manager.acquire("user", &binding()).await.is_err());
        manager
            .update("user", "stub", |_, current| {
                let mut slot = current.unwrap();
                assert_eq!(
                    slot.connection.as_ref().unwrap().revalidation,
                    ConsentRevalidation::Pending
                );
                slot.flows.insert("expired".into(), expired);
                Ok((slot, ()))
            })
            .unwrap();
        manager.acquire("user", &binding()).await.unwrap();
        let slot = manager.read("user", "stub").unwrap();
        assert!(slot.flows.is_empty());
        assert_eq!(
            slot.connection.unwrap().revalidation,
            ConsentRevalidation::None
        );
    }
}
