//! Microsoft membership renewal records (migration
//! `031_oidc_membership_renewal`): one row per Microsoft login method whose
//! latest sign-in ran with `membership_renewal` enabled. A row holds the
//! Microsoft refresh token that sign-in returned, encrypted together with the
//! values of the ID token it came with that a refreshed ID token must repeat
//! (OIDC Core §12.2), or the reason renewal ended.
//!
//! The payload's AAD binds the login method, its external subject, the
//! provider's tenant and client, the row's token version and its key, so a
//! payload cannot move to another method, subject, tenant, client or token
//! version. State-only updates keep the token version and do not re-encrypt;
//! rewrap keeps it too.
//!
//! The row's `observation_iat` is the highest raw `iat` of any trusted ID
//! token observed for the method. While a row exists, complete groups replace
//! the method's evidence only from a strictly newer token, and every trusted
//! observation, complete or incomplete, raises it.
use super::*;
use crate::microsoft_oidc::{
    MICROSOFT_OIDC_MAX_REFRESH_TOKEN_BYTES, MICROSOFT_OIDC_MAX_SUBJECT_BYTES,
};

const AAD_DOMAIN: &str = "aab-oidc-membership-renewal";
const AAD_VERSION: u32 = 1;
const PAYLOAD_VERSION: i64 = 1;
const COLUMNS: &str = "r.login_method_id, r.token_version, r.state, r.ended_reason,
    r.payload_version, r.key_id, r.nonce, r.ciphertext, r.recorded_at, r.observation_iat,
    r.last_renewed_at, r.last_attempt_at, r.failure_count, r.last_failure_code,
    r.last_failure_at, r.next_attempt_after, r.updated_at, lm.method, lm.external_provider,
    lm.external_subject";
const FROM: &str = "FROM oidc_membership_renewals r
    LEFT JOIN principal_login_methods lm ON lm.login_method_id = r.login_method_id";

/// A renewal row's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcMembershipRenewalState {
    Active,
    Retrying,
    Blocked,
    Ended,
}

impl OidcMembershipRenewalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retrying => "retrying",
            Self::Blocked => "blocked",
            Self::Ended => "ended",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "active" => Self::Active,
            "retrying" => Self::Retrying,
            "blocked" => Self::Blocked,
            "ended" => Self::Ended,
            _ => return None,
        })
    }
}

/// Why renewal ended for a login method until its next sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcMembershipRenewalEndedReason {
    SignInRequired,
    NotIssued,
    IdentityMismatch,
}

impl OidcMembershipRenewalEndedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignInRequired => "sign_in_required",
            Self::NotIssued => "not_issued",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "sign_in_required" => Self::SignInRequired,
            "not_issued" => Self::NotIssued,
            "identity_mismatch" => Self::IdentityMismatch,
            _ => return None,
        })
    }
}

/// The sanitized classification of a row's latest failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcMembershipRenewalFailureCode {
    GroupsIncomplete,
    ClientRejected,
    RequestRejected,
    InvalidResponse,
    Throttled,
    Unavailable,
}

impl OidcMembershipRenewalFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GroupsIncomplete => "groups_incomplete",
            Self::ClientRejected => "client_rejected",
            Self::RequestRejected => "request_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::Throttled => "throttled",
            Self::Unavailable => "unavailable",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "groups_incomplete" => Self::GroupsIncomplete,
            "client_rejected" => Self::ClientRejected,
            "request_rejected" => Self::RequestRejected,
            "invalid_response" => Self::InvalidResponse,
            "throttled" => Self::Throttled,
            "unavailable" => Self::Unavailable,
            _ => return None,
        })
    }
}

/// Whether a successful Microsoft sign-in's complete groups replaced its
/// login method's evidence, or the stored evidence came from a token at
/// least as new and was kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcMembershipEvidence {
    Replaced,
    KeptNewer,
}

impl OidcMembershipEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replaced => "replaced",
            Self::KeptNewer => "kept_newer",
        }
    }
}

/// A renewal row without its payload: what may be shown, logged or audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcMembershipRenewalRecord {
    pub login_method_id: String,
    pub token_version: String,
    pub state: OidcMembershipRenewalState,
    pub ended_reason: Option<OidcMembershipRenewalEndedReason>,
    pub recorded_at: String,
    pub observation_iat: i64,
    pub last_renewed_at: Option<String>,
    pub last_attempt_at: Option<String>,
    pub failure_count: u32,
    pub last_failure_code: Option<OidcMembershipRenewalFailureCode>,
    pub last_failure_at: Option<String>,
    pub next_attempt_after: Option<String>,
    pub updated_at: String,
}

/// The values of the ID token a refresh token came with that a refreshed ID
/// token must repeat (OIDC Core §12.2): the OIDC `sub`, the `aud` claim
/// exactly as issued (a string or an array of strings), `azp`, the unpadded
/// base64url SHA-256 of the sign-in flow's nonce and `auth_time`. They are
/// carried forward unchanged through rotation, rewrap and renewal.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcRenewalReference {
    subject: String,
    audience: Value,
    azp: Option<String>,
    nonce_sha256: String,
    auth_time: Option<i64>,
}

impl std::fmt::Debug for OidcRenewalReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcRenewalReference")
            .finish_non_exhaustive()
    }
}

impl OidcRenewalReference {
    pub fn new(
        subject: String,
        audience: Value,
        azp: Option<String>,
        nonce_sha256: String,
        auth_time: Option<i64>,
    ) -> Result<Self, ManagedStoreError> {
        let reference = Self {
            subject,
            audience,
            azp,
            nonce_sha256,
            auth_time,
        };
        if !reference.well_formed() {
            return Err(input_invalid(
                "Microsoft membership renewal reference is invalid",
            ));
        }
        Ok(reference)
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The `aud` claim exactly as issued.
    pub fn audience(&self) -> &Value {
        &self.audience
    }

    pub fn azp(&self) -> Option<&str> {
        self.azp.as_deref()
    }

    pub fn nonce_sha256(&self) -> &str {
        &self.nonce_sha256
    }

    pub fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }

    fn well_formed(&self) -> bool {
        let audience = match &self.audience {
            Value::String(audience) => !audience.is_empty(),
            Value::Array(audiences) => {
                !audiences.is_empty()
                    && audiences
                        .iter()
                        .all(|audience| audience.as_str().is_some_and(|value| !value.is_empty()))
            }
            _ => false,
        };
        audience
            && !self.subject.is_empty()
            && self.subject.len() <= MICROSOFT_OIDC_MAX_SUBJECT_BYTES
            && self
                .azp
                .as_ref()
                .is_none_or(|azp| !azp.is_empty() && azp.len() <= MICROSOFT_OIDC_MAX_SUBJECT_BYTES)
            && self.nonce_sha256.len() == 43
            && URL_SAFE_NO_PAD
                .decode(&self.nonce_sha256)
                .is_ok_and(|digest| digest.len() == 32)
    }
}

/// What a Microsoft sign-in with membership renewal enabled records: the
/// refresh token Microsoft returned and the [`OidcRenewalReference`] of its
/// ID token, encrypted under `key_ring`'s active key, or that no usable
/// refresh token was issued. Its debug output never shows the token.
#[derive(Clone)]
pub struct OidcMembershipRenewalSignIn {
    key_ring: CredentialKeyRing,
    issued: Option<Box<RenewalPayload>>,
}

impl std::fmt::Debug for OidcMembershipRenewalSignIn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcMembershipRenewalSignIn")
            .field("key_ring", &self.key_ring)
            .field("issued", &self.issued.is_some())
            .finish()
    }
}

impl OidcMembershipRenewalSignIn {
    /// A sign-in that returned `refresh_token` with an ID token whose
    /// comparison values are `reference`. The token must be nonempty and at
    /// most 16 KiB; the caller treats a longer one as not issued.
    pub fn issued(
        key_ring: CredentialKeyRing,
        refresh_token: String,
        reference: OidcRenewalReference,
    ) -> Result<Self, ManagedStoreError> {
        if !refresh_token_well_formed(&refresh_token) {
            return Err(input_invalid(
                "Microsoft refresh token is empty or too large",
            ));
        }
        Ok(Self {
            key_ring,
            issued: Some(Box::new(RenewalPayload::new(refresh_token, reference))),
        })
    }

    /// A sign-in for which Microsoft returned no usable refresh token.
    pub fn not_issued(key_ring: CredentialKeyRing) -> Self {
        Self {
            key_ring,
            issued: None,
        }
    }
}

/// A decrypted renewal payload: the stored refresh token, the token version
/// it is stored under and the reference a refreshed ID token must repeat.
/// Its debug output never shows the token.
pub struct OidcMembershipRenewalMaterial {
    token_version: String,
    refresh_token: String,
    reference: OidcRenewalReference,
}

impl std::fmt::Debug for OidcMembershipRenewalMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcMembershipRenewalMaterial")
            .field("token_version", &self.token_version)
            .finish_non_exhaustive()
    }
}

impl OidcMembershipRenewalMaterial {
    pub fn token_version(&self) -> &str {
        &self.token_version
    }

    /// The Microsoft refresh token, for a redemption request only.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub fn reference(&self) -> &OidcRenewalReference {
        &self.reference
    }
}

/// The encrypted plaintext, payload version 1. Field order is the stored
/// JSON encoding and part of the persisted contract.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenewalPayload {
    refresh_token: String,
    subject: String,
    audience: Value,
    azp: Option<String>,
    nonce_sha256: String,
    auth_time: Option<i64>,
}

impl RenewalPayload {
    fn new(refresh_token: String, reference: OidcRenewalReference) -> Self {
        let OidcRenewalReference {
            subject,
            audience,
            azp,
            nonce_sha256,
            auth_time,
        } = reference;
        Self {
            refresh_token,
            subject,
            audience,
            azp,
            nonce_sha256,
            auth_time,
        }
    }

    fn into_material(self, token_version: String) -> Option<OidcMembershipRenewalMaterial> {
        let reference = OidcRenewalReference {
            subject: self.subject,
            audience: self.audience,
            azp: self.azp,
            nonce_sha256: self.nonce_sha256,
            auth_time: self.auth_time,
        };
        (refresh_token_well_formed(&self.refresh_token) && reference.well_formed()).then_some(
            OidcMembershipRenewalMaterial {
                token_version,
                refresh_token: self.refresh_token,
                reference,
            },
        )
    }
}

fn refresh_token_well_formed(token: &str) -> bool {
    !token.is_empty() && token.len() <= MICROSOFT_OIDC_MAX_REFRESH_TOKEN_BYTES
}

/// The stored facts a payload is bound to.
struct Binding<'a> {
    login_method_id: &'a str,
    external_subject: &'a str,
    tenant_id: &'a str,
    client_id: &'a str,
    token_version: &'a str,
}

/// The authenticated data of a payload under `key_id`: the JSON tuple
/// `("aab-oidc-membership-renewal", 1, login_method_id, external_subject,
/// tenant_id, client_id, token_version, key_id)`.
fn aad(binding: &Binding<'_>, key_id: &str) -> Vec<u8> {
    serde_json::to_vec(&(
        AAD_DOMAIN,
        AAD_VERSION,
        binding.login_method_id,
        binding.external_subject,
        binding.tenant_id,
        binding.client_id,
        binding.token_version,
        key_id,
    ))
    .expect("string tuple")
}

fn cipher(ring: &CredentialKeyRing, key_id: &str) -> Result<Aes256Gcm, ManagedStoreError> {
    let bytes = ring
        .keys
        .get(key_id)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key_id.into()))?;
    Aes256Gcm::new_from_slice(bytes)
        .map_err(|_| ManagedStoreError::EncryptionKeyInvalid(key_id.into()))
}

fn encrypt(
    ring: &CredentialKeyRing,
    binding: &Binding<'_>,
    key_id: &str,
    payload: &RenewalPayload,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let plaintext =
        serde_json::to_vec(payload).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(ring, key_id)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(binding, key_id),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: key_id.into(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

fn decrypt(
    ring: &CredentialKeyRing,
    binding: &Binding<'_>,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<RenewalPayload, ManagedStoreError> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let plaintext = cipher(ring, key_id)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(binding, key_id),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    serde_json::from_slice(&plaintext).map_err(|_| ManagedStoreError::CredentialDecryptFailed)
}

fn invalid_row() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("OIDC membership renewal row is invalid".into())
}

struct StoredRow {
    login_method_id: String,
    token_version: String,
    state: String,
    ended_reason: Option<String>,
    payload_version: Option<i64>,
    key_id: Option<String>,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    recorded_at: String,
    observation_iat: i64,
    last_renewed_at: Option<String>,
    last_attempt_at: Option<String>,
    failure_count: i64,
    last_failure_code: Option<String>,
    last_failure_at: Option<String>,
    next_attempt_after: Option<String>,
    updated_at: String,
    method: Option<String>,
    external_provider: Option<String>,
    external_subject: Option<String>,
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRow> {
    Ok(StoredRow {
        login_method_id: row.get(0)?,
        token_version: row.get(1)?,
        state: row.get(2)?,
        ended_reason: row.get(3)?,
        payload_version: row.get(4)?,
        key_id: row.get(5)?,
        nonce: row.get(6)?,
        ciphertext: row.get(7)?,
        recorded_at: row.get(8)?,
        observation_iat: row.get(9)?,
        last_renewed_at: row.get(10)?,
        last_attempt_at: row.get(11)?,
        failure_count: row.get(12)?,
        last_failure_code: row.get(13)?,
        last_failure_at: row.get(14)?,
        next_attempt_after: row.get(15)?,
        updated_at: row.get(16)?,
        method: row.get(17)?,
        external_provider: row.get(18)?,
        external_subject: row.get(19)?,
    })
}

fn timestamp_valid(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value).is_ok()
}

impl StoredRow {
    /// The row's typed record, after checking the invariants the table's
    /// constraints cannot express: a canonical token version, parseable
    /// timestamps and a Microsoft login method with an external subject.
    fn record(&self) -> Result<OidcMembershipRenewalRecord, ManagedStoreError> {
        let state = OidcMembershipRenewalState::parse(&self.state).ok_or_else(invalid_row)?;
        let ended_reason = self
            .ended_reason
            .as_deref()
            .map(|reason| OidcMembershipRenewalEndedReason::parse(reason).ok_or_else(invalid_row))
            .transpose()?;
        let last_failure_code = self
            .last_failure_code
            .as_deref()
            .map(|code| OidcMembershipRenewalFailureCode::parse(code).ok_or_else(invalid_row))
            .transpose()?;
        let ended = state == OidcMembershipRenewalState::Ended;
        let failing = matches!(
            state,
            OidcMembershipRenewalState::Retrying | OidcMembershipRenewalState::Blocked
        );
        let encrypted = self.ciphertext.is_some();
        let well_formed = ended == ended_reason.is_some()
            && ended != encrypted
            && self.payload_version == encrypted.then_some(PAYLOAD_VERSION)
            && self.key_id.is_some() == encrypted
            && self.nonce.as_ref().map(Vec::len) == encrypted.then_some(12)
            && failing == last_failure_code.is_some()
            && failing == self.next_attempt_after.is_some()
            && last_failure_code.is_some() == self.last_failure_at.is_some()
            && Uuid::parse_str(&self.token_version)
                .is_ok_and(|version| version.hyphenated().to_string() == self.token_version)
            && timestamp_valid(&self.recorded_at)
            && timestamp_valid(&self.updated_at)
            && [
                &self.last_renewed_at,
                &self.last_attempt_at,
                &self.last_failure_at,
                &self.next_attempt_after,
            ]
            .into_iter()
            .all(|value| value.as_deref().is_none_or(timestamp_valid))
            && self.method.as_deref() == Some("oidc")
            && self.external_provider.as_deref() == Some("microsoft")
            && self
                .external_subject
                .as_deref()
                .is_some_and(|subject| !subject.is_empty());
        if !well_formed {
            return Err(invalid_row());
        }
        Ok(OidcMembershipRenewalRecord {
            login_method_id: self.login_method_id.clone(),
            token_version: self.token_version.clone(),
            state,
            ended_reason,
            recorded_at: self.recorded_at.clone(),
            observation_iat: self.observation_iat,
            last_renewed_at: self.last_renewed_at.clone(),
            last_attempt_at: self.last_attempt_at.clone(),
            failure_count: u32::try_from(self.failure_count).map_err(|_| invalid_row())?,
            last_failure_code,
            last_failure_at: self.last_failure_at.clone(),
            next_attempt_after: self.next_attempt_after.clone(),
            updated_at: self.updated_at.clone(),
        })
    }

    fn binding<'a>(&'a self, provider: &'a OidcProviderStateRecord) -> Binding<'a> {
        Binding {
            login_method_id: &self.login_method_id,
            external_subject: self.external_subject.as_deref().unwrap_or_default(),
            tenant_id: &provider.tenant_id,
            client_id: &provider.client_id,
            token_version: &self.token_version,
        }
    }

    /// The decrypted payload of a row holding one, checked well formed.
    fn material(
        &self,
        ring: &CredentialKeyRing,
        provider: &OidcProviderStateRecord,
    ) -> Result<Option<OidcMembershipRenewalMaterial>, ManagedStoreError> {
        let (Some(key_id), Some(nonce), Some(ciphertext)) =
            (&self.key_id, &self.nonce, &self.ciphertext)
        else {
            return Ok(None);
        };
        decrypt(ring, &self.binding(provider), key_id, nonce, ciphertext)?
            .into_material(self.token_version.clone())
            .map(Some)
            .ok_or(ManagedStoreError::CredentialDecryptFailed)
    }
}

fn rows(
    conn: &Connection,
    filter: &str,
    value: Option<&str>,
) -> Result<Vec<StoredRow>, ManagedStoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {COLUMNS} {FROM} {filter} ORDER BY r.login_method_id"
        ))
        .map_err(sql_unavailable)?;
    let rows = match value {
        Some(value) => statement.query_map([value], from_row),
        None => statement.query_map([], from_row),
    }
    .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn row(conn: &Connection, login_method_id: &str) -> Result<Option<StoredRow>, ManagedStoreError> {
    Ok(
        rows(conn, "WHERE r.login_method_id = ?1", Some(login_method_id))?
            .into_iter()
            .next(),
    )
}

/// The provider row whose tenant and client the payloads of `rows` are
/// bound to; required while any of them holds a payload.
fn provider_for(
    conn: &Connection,
    rows: &[StoredRow],
) -> Result<Option<OidcProviderStateRecord>, ManagedStoreError> {
    if rows.iter().all(|row| row.ciphertext.is_none()) {
        return Ok(None);
    }
    oidc_provider_state(conn)?.map(Some).ok_or_else(invalid_row)
}

/// Every row is well formed and belongs to a Microsoft login method. The
/// 031 structural validator and readiness run it.
pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    for row in rows(conn, "", None)? {
        row.record()?;
    }
    Ok(())
}

/// Every row is well formed, and every row holding a token decrypts under
/// `ring` to a well-formed payload.
pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    let rows = rows(conn, "", None)?;
    for row in &rows {
        row.record()?;
    }
    let Some(provider) = provider_for(conn, &rows)? else {
        return Ok(());
    };
    for row in rows.iter().filter(|row| row.ciphertext.is_some()) {
        let ring = ring.ok_or_else(|| {
            ManagedStoreError::EncryptionKeyMissing(row.key_id.clone().unwrap_or_default())
        })?;
        row.material(ring, &provider)?;
    }
    Ok(())
}

/// Re-encrypts every payload under `from` with `to`, keeping its token
/// version and every plain column.
pub(super) fn rewrap(
    conn: &mut Connection,
    ring: &CredentialKeyRing,
    from: &str,
    to: &str,
) -> Result<u64, ManagedStoreError> {
    let tx = conn.transaction().map_err(sql_unavailable)?;
    let rows = rows(&tx, "WHERE r.key_id = ?1", Some(from))?;
    let count = rows.len() as u64;
    if let Some(provider) = provider_for(&tx, &rows)? {
        for row in &rows {
            row.record()?;
            let (Some(key_id), Some(nonce), Some(ciphertext)) =
                (&row.key_id, &row.nonce, &row.ciphertext)
            else {
                return Err(invalid_row());
            };
            let binding = row.binding(&provider);
            let payload = decrypt(ring, &binding, key_id, nonce, ciphertext)?;
            let encrypted = encrypt(ring, &binding, to, &payload)?;
            tx.execute(
                "UPDATE oidc_membership_renewals SET key_id = ?3, nonce = ?4, ciphertext = ?5
                 WHERE login_method_id = ?1 AND token_version = ?2",
                params![
                    row.login_method_id,
                    row.token_version,
                    encrypted.key_id,
                    encrypted.nonce,
                    encrypted.ciphertext
                ],
            )
            .map_err(sql_unavailable)?;
        }
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}

/// The `observation_iat` of `login_method_id`'s row, when it has one.
pub(super) fn observation_iat(
    conn: &Connection,
    login_method_id: &str,
) -> Result<Option<i64>, ManagedStoreError> {
    conn.query_row(
        "SELECT observation_iat FROM oidc_membership_renewals WHERE login_method_id = ?1",
        [login_method_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_unavailable)
}

/// Raises the row's `observation_iat` to `issued_at` if that is higher. A
/// method without a row is unchanged.
pub(super) fn raise_observation(
    conn: &Connection,
    login_method_id: &str,
    issued_at: i64,
    now: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "UPDATE oidc_membership_renewals SET observation_iat = ?2, updated_at = ?3
         WHERE login_method_id = ?1 AND observation_iat < ?2",
        params![login_method_id, issued_at, now],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Raises the `observation_iat` of the row of `external_subject`'s
/// Microsoft login method to `issued_at` if that is higher. A subject
/// without a method or a method without a row is unchanged.
pub(super) fn raise_observation_for_subject(
    conn: &Connection,
    external_subject: &str,
    issued_at: i64,
    now: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "UPDATE oidc_membership_renewals SET observation_iat = ?2, updated_at = ?3
         WHERE observation_iat < ?2 AND login_method_id IN (
           SELECT login_method_id FROM principal_login_methods
           WHERE method = 'oidc' AND external_provider = 'microsoft' AND external_subject = ?1
         )",
        params![external_subject, issued_at, now],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Records a sign-in with membership renewal enabled for `method`, inside
/// the sign-in's transaction: a new token version holding the returned token
/// in state `active`, or `ended` with `not_issued` when none was returned.
/// Failures and the backoff are cleared and `observation_iat` raised to
/// `issued_at`; `last_attempt_at` and `last_renewed_at` are kept, so a
/// sign-in never shortens the minimum interval between attempts.
pub(super) fn record_sign_in(
    conn: &Connection,
    method: &LoginMethodRecord,
    provider: &OidcProviderStateRecord,
    sign_in: &OidcMembershipRenewalSignIn,
    issued_at: i64,
    now: &str,
) -> Result<(), ManagedStoreError> {
    let external_subject = method
        .external_subject
        .as_deref()
        .filter(|_| method.method == "oidc")
        .ok_or_else(invalid_row)?;
    let token_version = Uuid::new_v4().to_string();
    let encrypted = sign_in
        .issued
        .as_deref()
        .map(|payload| {
            encrypt(
                &sign_in.key_ring,
                &Binding {
                    login_method_id: &method.login_method_id,
                    external_subject,
                    tenant_id: &provider.tenant_id,
                    client_id: &provider.client_id,
                    token_version: &token_version,
                },
                sign_in.key_ring.active_key_id(),
                payload,
            )
        })
        .transpose()?;
    let (state, ended_reason) = match encrypted {
        Some(_) => (OidcMembershipRenewalState::Active, None),
        None => (
            OidcMembershipRenewalState::Ended,
            Some(OidcMembershipRenewalEndedReason::NotIssued),
        ),
    };
    conn.execute(
        "INSERT INTO oidc_membership_renewals
         (login_method_id, token_version, state, ended_reason, payload_version, key_id, nonce,
          ciphertext, recorded_at, observation_iat, last_renewed_at, last_attempt_at,
          failure_count, last_failure_code, last_failure_at, next_attempt_after, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, 0, NULL, NULL, NULL, ?9)
         ON CONFLICT(login_method_id) DO UPDATE SET
           token_version = excluded.token_version,
           state = excluded.state,
           ended_reason = excluded.ended_reason,
           payload_version = excluded.payload_version,
           key_id = excluded.key_id,
           nonce = excluded.nonce,
           ciphertext = excluded.ciphertext,
           recorded_at = excluded.recorded_at,
           observation_iat = max(oidc_membership_renewals.observation_iat, excluded.observation_iat),
           failure_count = 0,
           last_failure_code = NULL,
           last_failure_at = NULL,
           next_attempt_after = NULL,
           updated_at = excluded.updated_at",
        params![
            method.login_method_id,
            token_version,
            state.as_str(),
            ended_reason.map(OidcMembershipRenewalEndedReason::as_str),
            encrypted.as_ref().map(|_| PAYLOAD_VERSION),
            encrypted.as_ref().map(|encrypted| encrypted.key_id.clone()),
            encrypted.as_ref().map(|encrypted| encrypted.nonce.clone()),
            encrypted.as_ref().map(|encrypted| encrypted.ciphertext.clone()),
            now,
            issued_at,
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Deletes `login_method_id`'s row, when it has one.
pub(super) fn delete_for_method(
    conn: &Connection,
    login_method_id: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "DELETE FROM oidc_membership_renewals WHERE login_method_id = ?1",
        [login_method_id],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Deletes the rows of every login method of `principal_id`.
pub(super) fn delete_for_principal(
    conn: &Connection,
    principal_id: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "DELETE FROM oidc_membership_renewals WHERE login_method_id IN (
           SELECT login_method_id FROM principal_login_methods WHERE principal_id = ?1
         )",
        [principal_id],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Deletes every row.
pub(super) fn delete_all(conn: &Connection) -> Result<(), ManagedStoreError> {
    conn.execute("DELETE FROM oidc_membership_renewals", [])
        .map_err(sql_unavailable)?;
    Ok(())
}

impl ManagedStore {
    /// The membership-renewal row of `login_method_id`, without its payload.
    pub fn oidc_membership_renewal(
        &self,
        login_method_id: &str,
    ) -> Result<Option<OidcMembershipRenewalRecord>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        row(&conn, login_method_id)?
            .map(|row| row.record())
            .transpose()
    }

    /// Test support: the decrypted payload of `login_method_id`'s row, when
    /// it holds one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn oidc_membership_renewal_material(
        &self,
        ring: &CredentialKeyRing,
        login_method_id: &str,
    ) -> Result<Option<OidcMembershipRenewalMaterial>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let Some(row) = row(&conn, login_method_id)? else {
            return Ok(None);
        };
        row.record()?;
        let Some(provider) = provider_for(&conn, std::slice::from_ref(&row))? else {
            return Ok(None);
        };
        row.material(ring, &provider)
    }
}

#[cfg(test)]
#[path = "oidc_membership_renewal_tests.rs"]
mod tests;
