//! A person's approval of a registered client application: pending browser
//! authorization requests, one-use codes, the refresh token and the agent
//! tokens minted through it. Raw request IDs, codes, verifiers and refresh
//! tokens are never stored and never reach errors or `Debug` output.
use super::*;
use crate::ApplicationRegistration;
use sha2::Digest;

/// How long a pending authorization request can be approved.
pub const APPLICATION_AUTHORIZATION_REQUEST_TTL_SECONDS: i64 = 10 * 60;
/// How long an authorization code can be exchanged.
pub const APPLICATION_AUTHORIZATION_CODE_TTL_SECONDS: i64 = 60;
/// Pending authorization requests the store holds at once.
pub const APPLICATION_AUTHORIZATION_MAX_PENDING: u64 = 1000;
/// Unexpired, unrevoked agent tokens one application access may hold.
pub const APPLICATION_ACCESS_MAX_LIVE_TOKENS: u64 = 256;
/// How long an expired or revoked application-minted token row is kept.
pub const APPLICATION_TOKEN_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;

const REFRESH_TOKEN_PREFIX: &str = "aar_";
const AUTHORIZATION_CODE_PREFIX: &str = "aac_";
const REQUEST_PAYLOAD_KEY_CONTEXT: &[u8] = b"agent-access/application-authorization/payload/v1";
const APPLICATION_STATE_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAccessRecord {
    pub access_id: String,
    pub principal_id: String,
    pub application_id: String,
    pub enabled: bool,
    pub read_only: bool,
    pub version: i64,
    /// Whether the application holds a refresh token for this access.
    pub connected: bool,
    pub created_at: String,
    pub connected_at: String,
    pub updated_at: String,
    pub updated_by: String,
    pub last_used_at: Option<String>,
    /// Unexpired, unrevoked agent tokens minted through this access.
    pub live_token_count: u64,
}

/// A change to an application access's settings; absent fields keep their value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplicationAccessUpdate {
    pub enabled: Option<bool>,
    pub read_only: Option<bool>,
}

/// Why a person may not connect an application.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationConnectDenial {
    /// The application's level is `none`.
    ConnectingDisabled,
    /// An administrator disabled this person's access to the application.
    AccessDisabled,
    /// Only human accounts connect applications.
    NotHuman,
    AccountDisabled,
}

impl ApplicationConnectDenial {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectingDisabled => "connecting_disabled",
            Self::AccessDisabled => "access_disabled",
            Self::NotHuman => "not_human",
            Self::AccountDisabled => "account_disabled",
        }
    }
}

/// The validated authorization request an application sent the browser with.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationAuthorizationParameters {
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
}

impl std::fmt::Debug for ApplicationAuthorizationParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApplicationAuthorizationParameters([redacted])")
    }
}

/// A pending authorization request, read with its raw ID.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingApplicationAuthorization {
    pub application_id: String,
    pub parameters: ApplicationAuthorizationParameters,
    pub expires_at: String,
}

impl std::fmt::Debug for PendingApplicationAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingApplicationAuthorization")
            .field("application_id", &self.application_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The outcome of a person's decision: where the browser returns, with the
/// one-use code of an approval.
#[derive(Clone)]
pub struct ApplicationAuthorizationDecision {
    pub application_id: String,
    pub parameters: ApplicationAuthorizationParameters,
    /// `Some` for an approval.
    pub code: Option<String>,
    pub access: Option<ApplicationAccessRecord>,
}

impl std::fmt::Debug for ApplicationAuthorizationDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationAuthorizationDecision")
            .field("application_id", &self.application_id)
            .field("approved", &self.code.is_some())
            .finish_non_exhaustive()
    }
}

/// What an application presents at the token endpoint.
#[derive(Clone, Copy)]
pub enum ApplicationGrant<'a> {
    AuthorizationCode {
        code: &'a str,
        redirect_uri: &'a str,
        code_verifier: &'a str,
    },
    RefreshToken {
        refresh_token: &'a str,
    },
}

impl ApplicationGrant<'_> {
    pub const fn grant_type(&self) -> &'static str {
        match self {
            Self::AuthorizationCode { .. } => "authorization_code",
            Self::RefreshToken { .. } => "refresh_token",
        }
    }
}

/// Why a grant mints nothing. Every variant except `TokenLimit` is the
/// protocol's `invalid_grant`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationGrantRefusal {
    /// The code or refresh token is unknown, used, expired, or was issued to
    /// another client, redirect URI or verifier.
    GrantInvalid,
    /// The application is no longer registered or its level is `none`.
    ApplicationUnavailable,
    AccessDisabled,
    /// The person is disabled or not a human account.
    PrincipalUnavailable,
    RefreshTokenIdle,
    /// The access already holds the most live tokens it may.
    TokenLimit,
}

impl ApplicationGrantRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GrantInvalid => "grant_invalid",
            Self::ApplicationUnavailable => "application_unavailable",
            Self::AccessDisabled => "access_disabled",
            Self::PrincipalUnavailable => "principal_unavailable",
            Self::RefreshTokenIdle => "refresh_token_idle",
            Self::TokenLimit => "token_limit",
        }
    }
}

/// A refused grant, with the access it named when one was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationGrantRefused {
    pub refusal: ApplicationGrantRefusal,
    pub principal_id: Option<String>,
    pub access_id: Option<String>,
}

/// A newly minted agent token and, after a code exchange, the refresh token.
#[derive(Clone)]
pub struct ApplicationTokenMint {
    pub token: String,
    pub record: BrokerTokenRecord,
    pub refresh_token: Option<String>,
    pub access: ApplicationAccessRecord,
    pub principal_name: String,
    pub read_only: bool,
    pub expires_in_seconds: u64,
    /// Earlier tokens of the access that a code exchange ended.
    pub replaced_tokens: u64,
}

impl std::fmt::Debug for ApplicationTokenMint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationTokenMint")
            .field("token_id", &self.record.token_id)
            .field("access_id", &self.access.access_id)
            .finish_non_exhaustive()
    }
}

/// What a revocation request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationRevocation {
    /// The token was not one this application may revoke; nothing changed.
    Unknown,
    AccessToken {
        principal_id: String,
        access_id: String,
        token_id: String,
    },
    /// The refresh token: the consent ends with its live tokens. The row is
    /// kept, disconnected, when it carries an administrator's restriction.
    Access {
        access: ApplicationAccessRecord,
        revoked_tokens: u64,
        row_removed: bool,
    },
}

/// Live tokens a startup or reload ended because the application's current
/// registration would no longer mint them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTokenReconciliation {
    pub application_id: String,
    pub reason: ApplicationTokenReconciliationReason,
    pub revoked_tokens: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationTokenReconciliationReason {
    /// The application is no longer registered.
    RegistrationRemoved,
    /// The application's level is `none`.
    ConnectingDisabled,
    /// The level became `read_only`, or the contexts or services changed.
    RegistrationNarrowed,
}

fn generate_application_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_application_secret(prefix: &str, value: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_request_id)
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// Whether `value` is an S256 PKCE challenge: an unpadded base64url SHA-256.
pub fn is_valid_application_code_challenge(value: &str) -> bool {
    valid_request_id(value)
}

fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

fn validate_parameters(
    parameters: &ApplicationAuthorizationParameters,
) -> Result<(), ManagedStoreError> {
    if !crate::is_valid_application_redirect_uri(&parameters.redirect_uri)
        || parameters.state.is_empty()
        || parameters.state.len() > APPLICATION_STATE_MAX_BYTES
        || !parameters
            .state
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
        || !is_valid_application_code_challenge(&parameters.code_challenge)
    {
        return Err(input_invalid(
            "application authorization request is invalid",
        ));
    }
    Ok(())
}

fn validate_application_id(application_id: &str) -> Result<(), ManagedStoreError> {
    if is_safe_identifier(application_id)
        && application_id.len() <= crate::APPLICATION_ID_MAX_BYTES
        && !application_id.contains(':')
    {
        Ok(())
    } else {
        Err(input_invalid("application ID is invalid"))
    }
}

fn request_hash(request_id: &str) -> Vec<u8> {
    Sha256::digest(request_id.as_bytes()).to_vec()
}

/// The request payload's key exists only while the raw request ID is
/// presented: the store keeps the ID's hash, never the ID.
fn request_payload_cipher(
    hasher: &BrokerTokenHasher,
    request_id: &str,
) -> Result<Aes256Gcm, ManagedStoreError> {
    let key = URL_SAFE_NO_PAD
        .decode(hasher.hmac_base64url(REQUEST_PAYLOAD_KEY_CONTEXT, request_id.as_bytes())?)
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| ManagedStoreError::CredentialEncryptFailed)
}

fn access_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApplicationAccessRecord> {
    let live: i64 = row.get(12)?;
    Ok(ApplicationAccessRecord {
        access_id: row.get(0)?,
        principal_id: row.get(1)?,
        application_id: row.get(2)?,
        enabled: row.get(3)?,
        read_only: row.get(4)?,
        version: row.get(5)?,
        connected: row.get(6)?,
        created_at: row.get(7)?,
        connected_at: row.get(8)?,
        updated_at: row.get(9)?,
        updated_by: row.get(10)?,
        last_used_at: row.get(11)?,
        live_token_count: live.max(0) as u64,
    })
}

const ACCESS_COLUMNS: &str =
    "a.access_id, a.principal_id, a.application_id, a.enabled, a.read_only,
    a.version, a.refresh_token_hash IS NOT NULL, a.created_at, a.connected_at, a.updated_at,
    a.updated_by, a.last_used_at,
    (SELECT COUNT(1) FROM broker_tokens t WHERE t.application_access_id = a.access_id
       AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?1))";

fn access_by(
    conn: &Connection,
    condition: &str,
    value: &str,
    now: &str,
) -> Result<Option<ApplicationAccessRecord>, ManagedStoreError> {
    conn.query_row(
        &format!("SELECT {ACCESS_COLUMNS} FROM application_access a WHERE {condition} = ?2"),
        params![now, value],
        access_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

fn access_for_principal(
    conn: &Connection,
    principal: &str,
    access_id: &str,
    now: &str,
) -> Result<ApplicationAccessRecord, ManagedStoreError> {
    access_by(conn, "a.access_id", access_id, now)?
        .filter(|access| access.principal_id == principal)
        .ok_or(ManagedStoreError::ApplicationAccessNotFound)
}

/// Ends every live token of `access_id` and returns how many it ended.
fn revoke_access_tokens(
    conn: &Connection,
    access_id: &str,
    actor: &str,
    now: &str,
) -> Result<u64, ManagedStoreError> {
    conn.execute(
        "UPDATE broker_tokens SET revoked_at = ?2, revoked_by = ?3
         WHERE application_access_id = ?1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?2)",
        params![access_id, now, actor],
    )
    .map(|count| count as u64)
    .map_err(sql_unavailable)
}

/// Retention: used or expired requests and codes go at once, and
/// application-minted tokens once expired or revoked for the retention time.
fn purge(conn: &Connection, now: DateTime<Utc>) -> Result<(), ManagedStoreError> {
    let current = normalized_timestamp(now);
    let cutoff = normalized_timestamp(now - Duration::seconds(APPLICATION_TOKEN_RETENTION_SECONDS));
    conn.execute(
        "DELETE FROM application_authorization_requests WHERE expires_at <= ?1 OR consumed_at IS NOT NULL",
        params![current],
    )
    .map_err(sql_unavailable)?;
    conn.execute(
        "DELETE FROM application_authorization_codes WHERE expires_at <= ?1",
        params![current],
    )
    .map_err(sql_unavailable)?;
    // An access that is neither connected, awaiting its code exchange nor
    // restricted by an administrator records nothing.
    conn.execute(
        "DELETE FROM application_access
         WHERE refresh_token_hash IS NULL AND enabled = 1 AND read_only = 0
           AND NOT EXISTS (SELECT 1 FROM application_authorization_codes c
             WHERE c.access_id = application_access.access_id)
           AND NOT EXISTS (SELECT 1 FROM broker_tokens t
             WHERE t.application_access_id = application_access.access_id
               AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?1))",
        params![current],
    )
    .map_err(sql_unavailable)?;
    conn.execute(
        "DELETE FROM broker_tokens WHERE application_access_id IS NOT NULL
           AND ((revoked_at IS NOT NULL AND revoked_at <= ?1)
             OR (expires_at IS NOT NULL AND expires_at <= ?1))",
        params![cutoff],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Why `principal` may not connect an application whose registration is
/// `connectable`, or `None` when they may.
fn connect_denial(
    conn: &Connection,
    principal: &str,
    application_id: &str,
    connectable: bool,
    now: &str,
) -> Result<Option<ApplicationConnectDenial>, ManagedStoreError> {
    let record = principal_by_id_without_groups(conn, principal)?;
    if record.kind != "user" {
        return Ok(Some(ApplicationConnectDenial::NotHuman));
    }
    if record.status != "active" {
        return Ok(Some(ApplicationConnectDenial::AccountDisabled));
    }
    if !connectable {
        return Ok(Some(ApplicationConnectDenial::ConnectingDisabled));
    }
    let existing = existing_access(conn, principal, application_id, now)?;
    Ok(existing
        .filter(|access| !access.enabled)
        .map(|_| ApplicationConnectDenial::AccessDisabled))
}

fn existing_access(
    conn: &Connection,
    principal: &str,
    application_id: &str,
    now: &str,
) -> Result<Option<ApplicationAccessRecord>, ManagedStoreError> {
    conn.query_row(
        &format!(
            "SELECT {ACCESS_COLUMNS} FROM application_access a
             WHERE a.principal_id = ?2 AND a.application_id = ?3"
        ),
        params![now, principal, application_id],
        access_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

impl ManagedStore {
    /// Stores a pending authorization request and returns its raw ID, which
    /// only the browser holds.
    pub fn create_application_authorization_request(
        &self,
        hasher: &BrokerTokenHasher,
        application_id: &str,
        parameters: &ApplicationAuthorizationParameters,
    ) -> Result<String, ManagedStoreError> {
        validate_application_id(application_id)?;
        validate_parameters(parameters)?;
        let request_id = generate_application_secret("");
        let hash = request_hash(&request_id);
        let plaintext = serde_json::to_vec(parameters)
            .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = request_payload_cipher(hasher, &request_id)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &hash,
                },
            )
            .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
        let now = Utc::now();
        let created_at = normalized_timestamp(now);
        let expires_at = normalized_timestamp(
            now + Duration::seconds(APPLICATION_AUTHORIZATION_REQUEST_TTL_SECONDS),
        );
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        purge(&tx, now)?;
        let pending: i64 = tx
            .query_row(
                "SELECT COUNT(1) FROM application_authorization_requests",
                [],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        if pending as u64 >= APPLICATION_AUTHORIZATION_MAX_PENDING {
            tx.commit().map_err(sql_unavailable)?;
            return Err(ManagedStoreError::ApplicationAuthorizationCapacity);
        }
        tx.execute(
            "INSERT INTO application_authorization_requests
             (request_hash, application_id, encrypted_payload, encryption_nonce, created_at,
              expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                hash,
                application_id,
                ciphertext,
                nonce.as_slice(),
                created_at,
                expires_at
            ],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(request_id)
    }

    /// The pending request `request_id` names. An unknown, used or expired
    /// request is one error.
    pub fn application_authorization_request(
        &self,
        hasher: &BrokerTokenHasher,
        request_id: &str,
    ) -> Result<PendingApplicationAuthorization, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        pending_request(&conn, hasher, request_id, &normalized_now_string())
    }

    /// Why `principal` may not connect `application_id`, or `None` when they
    /// may. `connectable` is whether the registration's level permits it.
    pub fn application_connect_denial(
        &self,
        principal: &str,
        application_id: &str,
        connectable: bool,
    ) -> Result<Option<ApplicationConnectDenial>, ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_application_id(application_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let denial = connect_denial(
            &tx,
            principal,
            application_id,
            connectable,
            &normalized_now_string(),
        )?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(denial)
    }

    /// Consumes the pending request. `registration` gives an application's
    /// current registration; a request whose application is no longer
    /// registered with the request's exact redirect URI is invalid, for an
    /// approval and a cancellation alike, so nothing is returned to an
    /// address the operator removed. An approval only issues the one-use
    /// code, for the person's existing access or, for a first approval, a
    /// placeholder that is not yet connected. A working consent is untouched
    /// until that code is exchanged, so an approval the application never
    /// redeems changes nothing and expires with its code. A refused approval
    /// changes nothing either, so the person can still return to the
    /// application.
    pub fn decide_application_authorization(
        &self,
        hasher: &BrokerTokenHasher,
        request_id: &str,
        principal: &str,
        registration: &dyn Fn(&str) -> Option<ApplicationRegistration>,
        approve: bool,
    ) -> Result<ApplicationAuthorizationDecision, ManagedStoreError> {
        validate_principal_id(principal)?;
        let now = Utc::now();
        let current = normalized_timestamp(now);
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let pending = pending_request(&tx, hasher, request_id, &current)?;
        let registration = registration(&pending.application_id)
            .filter(|registration| {
                registration.application_id == pending.application_id
                    && registration.accepts_redirect_uri(&pending.parameters.redirect_uri)
            })
            .ok_or(ManagedStoreError::ApplicationAuthorizationInvalid)?;
        let consumed = tx
            .execute(
                "UPDATE application_authorization_requests SET consumed_at = ?2
                 WHERE request_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                params![request_hash(request_id), current],
            )
            .map_err(sql_unavailable)?;
        if consumed != 1 {
            return Err(ManagedStoreError::ApplicationAuthorizationInvalid);
        }
        let mut decision = ApplicationAuthorizationDecision {
            application_id: pending.application_id.clone(),
            parameters: pending.parameters,
            code: None,
            access: None,
        };
        if !approve {
            tx.commit().map_err(sql_unavailable)?;
            return Ok(decision);
        }
        if let Some(denial) = connect_denial(
            &tx,
            principal,
            &pending.application_id,
            registration.terms.is_some(),
            &current,
        )? {
            return Err(ManagedStoreError::ApplicationAccessDenied(denial));
        }
        let access_id = match existing_access(&tx, principal, &pending.application_id, &current)? {
            // The existing consent, its tokens and its settings stay as
            // they are until the code is exchanged.
            Some(existing) => existing.access_id,
            None => {
                let access_id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO application_access
                     (access_id, principal_id, application_id, enabled, read_only, version,
                      refresh_token_hash, created_at, connected_at, updated_at, updated_by,
                      last_used_at)
                     VALUES (?1, ?2, ?3, 1, 0, 1, NULL, ?4, ?4, ?4, ?2, NULL)",
                    params![access_id, principal, pending.application_id, current],
                )
                .map_err(sql_unavailable)?;
                access_id
            }
        };
        let code = generate_application_secret(AUTHORIZATION_CODE_PREFIX);
        tx.execute(
            "INSERT INTO application_authorization_codes
             (code_hash, access_id, application_id, redirect_uri, code_challenge, created_at,
              expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            params![
                hasher.hash(&code)?,
                access_id,
                pending.application_id,
                decision.parameters.redirect_uri,
                decision.parameters.code_challenge,
                current,
                normalized_timestamp(
                    now + Duration::seconds(APPLICATION_AUTHORIZATION_CODE_TTL_SECONDS)
                )
            ],
        )
        .map_err(sql_unavailable)?;
        decision.access = Some(access_for_principal(&tx, principal, &access_id, &current)?);
        decision.code = Some(code);
        tx.commit().map_err(sql_unavailable)?;
        Ok(decision)
    }

    /// Exchanges a code or refresh token of `application_id` for a new agent
    /// token. `registration` is the application's current registration, or
    /// `None` when it is not registered; every condition is checked again in
    /// this transaction, including that a code's redirect URI is still
    /// registered. A code is consumed by its first presentation, whatever the
    /// outcome.
    pub fn mint_application_token(
        &self,
        hasher: &BrokerTokenHasher,
        application_id: &str,
        registration: Option<&ApplicationRegistration>,
        grant: ApplicationGrant<'_>,
    ) -> Result<Result<ApplicationTokenMint, ApplicationGrantRefused>, ManagedStoreError> {
        validate_application_id(application_id)?;
        let now = Utc::now();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        purge(&tx, now)?;
        let registration =
            registration.filter(|registration| registration.application_id == application_id);
        let outcome = mint_tx(&tx, hasher, application_id, registration, grant, now)?;
        // A refusal still commits the code's consumption and retention.
        tx.commit().map_err(sql_unavailable)?;
        Ok(outcome)
    }

    /// RFC 7009 revocation by `application_id`: one of its access tokens, or
    /// its refresh token, which ends the consent and its live tokens.
    pub fn revoke_application_token(
        &self,
        hasher: &BrokerTokenHasher,
        application_id: &str,
        token: &str,
    ) -> Result<ApplicationRevocation, ManagedStoreError> {
        validate_application_id(application_id)?;
        let token_hash = hasher.hash(token)?;
        let now = normalized_now_string();
        let actor = format!("application:{application_id}");
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let minted: Option<(String, String, String)> = tx
            .query_row(
                "SELECT t.token_id, t.principal_id, a.access_id FROM broker_tokens t
                 JOIN application_access a ON a.access_id = t.application_access_id
                 WHERE t.token_hash = ?1 AND a.application_id = ?2",
                params![token_hash, application_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql_unavailable)?;
        let outcome = if let Some((token_id, principal_id, access_id)) = minted {
            tx.execute(
                "UPDATE broker_tokens SET revoked_at = COALESCE(revoked_at, ?2),
                 revoked_by = COALESCE(revoked_by, ?3) WHERE token_id = ?1",
                params![token_id, now, actor],
            )
            .map_err(sql_unavailable)?;
            ApplicationRevocation::AccessToken {
                principal_id,
                access_id,
                token_id,
            }
        } else if let Some(access) = access_by(&tx, "a.refresh_token_hash", &token_hash, &now)?
            .filter(|access| access.application_id == application_id)
        {
            let (revoked_tokens, row_removed) = disconnect_access(&tx, &access, &actor, &now)?;
            ApplicationRevocation::Access {
                access,
                revoked_tokens,
                row_removed,
            }
        } else {
            ApplicationRevocation::Unknown
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(outcome)
    }

    pub fn list_application_access(
        &self,
        principal: &str,
    ) -> Result<Vec<ApplicationAccessRecord>, ManagedStoreError> {
        validate_principal_id(principal)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal)?;
        let records = {
            let mut statement = tx
                .prepare(&format!(
                    "SELECT {ACCESS_COLUMNS} FROM application_access a
                     WHERE a.principal_id = ?2 ORDER BY a.application_id, a.access_id"
                ))
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map(params![normalized_now_string(), principal], access_from_row)
                    .map_err(sql_unavailable)?,
            )?
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(records)
    }

    /// Applies the requested settings with one version increment and ends the
    /// access's live tokens, or writes nothing when they already hold.
    /// Returns the access before and after, read in the transaction.
    pub fn update_application_access(
        &self,
        principal: &str,
        access_id: &str,
        update: ApplicationAccessUpdate,
        expected_version: i64,
        updated_by: &str,
    ) -> Result<(ApplicationAccessRecord, ApplicationAccessRecord), ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_canonical_uuid(access_id, "application access ID")?;
        validate_actor(updated_by)?;
        if expected_version < 1 {
            return Err(input_invalid("expectedVersion must be positive"));
        }
        if update.enabled.is_none() && update.read_only.is_none() {
            return Err(input_invalid(
                "application access update requires enabled or readOnly",
            ));
        }
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal)?;
        let before = access_for_principal(&tx, principal, access_id, &now)?;
        if before.version != expected_version {
            return Err(ManagedStoreError::VersionConflict);
        }
        let enabled = update.enabled.unwrap_or(before.enabled);
        let read_only = update.read_only.unwrap_or(before.read_only);
        if (enabled, read_only) != (before.enabled, before.read_only) {
            tx.execute(
                "UPDATE application_access SET enabled = ?2, read_only = ?3,
                 version = version + 1, updated_at = ?4, updated_by = ?5 WHERE access_id = ?1",
                params![access_id, enabled, read_only, now, updated_by],
            )
            .map_err(sql_unavailable)?;
            revoke_access_tokens(&tx, access_id, updated_by, &now)?;
        }
        let after = access_for_principal(&tx, principal, access_id, &now)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok((before, after))
    }

    /// The person ends their own consent: the refresh token and live tokens
    /// end. Returns the access as it was and whether its row was removed; a
    /// row carrying an administrator's restriction is kept, disconnected, so
    /// that removing and approving again cannot lift the restriction. An
    /// access that is not connected is not found.
    pub fn disconnect_application_access(
        &self,
        principal: &str,
        access_id: &str,
        actor: &str,
    ) -> Result<(ApplicationAccessRecord, bool), ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_canonical_uuid(access_id, "application access ID")?;
        validate_actor(actor)?;
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal)?;
        let previous = access_for_principal(&tx, principal, access_id, &now)?;
        if !previous.connected {
            return Err(ManagedStoreError::ApplicationAccessNotFound);
        }
        let (_, row_removed) = disconnect_access(&tx, &previous, actor, &now)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok((previous, row_removed))
    }

    /// An administrator removes the access, whatever its settings, with its
    /// refresh token and live tokens, fenced by `expected_version`.
    pub fn remove_application_access(
        &self,
        principal: &str,
        access_id: &str,
        expected_version: i64,
        actor: &str,
    ) -> Result<ApplicationAccessRecord, ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_canonical_uuid(access_id, "application access ID")?;
        validate_actor(actor)?;
        if expected_version < 1 {
            return Err(input_invalid("expectedVersion must be positive"));
        }
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, principal)?;
        let previous = access_for_principal(&tx, principal, access_id, &now)?;
        if expected_version != previous.version {
            return Err(ManagedStoreError::VersionConflict);
        }
        revoke_access_tokens(&tx, access_id, actor, &now)?;
        tx.execute(
            "DELETE FROM application_access WHERE access_id = ?1",
            [access_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(previous)
    }

    /// Ends every live application-minted token that its application's
    /// current registration would no longer mint: the application is not
    /// registered or its level is `none`; its level is `read_only` and the
    /// token is not; or the token's contexts or services differ from the
    /// registration's. Refresh tokens are untouched. Run at startup and under
    /// the reload fence, so a narrowed registration takes effect at once.
    pub fn reconcile_application_tokens(
        &self,
        registration: &dyn Fn(&str) -> Option<ApplicationRegistration>,
    ) -> Result<Vec<ApplicationTokenReconciliation>, ManagedStoreError> {
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let live: Vec<(String, String, String)> = {
            let mut statement = tx
                .prepare(
                    "SELECT t.token_id, a.application_id, t.scopes_json FROM broker_tokens t
                     JOIN application_access a ON a.access_id = t.application_access_id
                     WHERE t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?1)
                     ORDER BY a.application_id, t.token_id",
                )
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map([&now], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .map_err(sql_unavailable)?,
            )?
        };
        let mut registrations = BTreeMap::<String, Option<ApplicationRegistration>>::new();
        let mut ended = BTreeMap::<String, ApplicationTokenReconciliation>::new();
        for (token_id, application_id, scopes) in live {
            let current = registrations
                .entry(application_id.clone())
                .or_insert_with(|| {
                    registration(&application_id)
                        .filter(|current| current.application_id == application_id)
                });
            let reason = match current.as_ref().map(|current| current.terms.as_ref()) {
                None => ApplicationTokenReconciliationReason::RegistrationRemoved,
                Some(None) => ApplicationTokenReconciliationReason::ConnectingDisabled,
                Some(Some(terms)) if !token_within_terms(&scopes, terms) => {
                    ApplicationTokenReconciliationReason::RegistrationNarrowed
                }
                Some(Some(_)) => continue,
            };
            tx.execute(
                "UPDATE broker_tokens SET revoked_at = ?2,
                 revoked_by = 'system:application_registration'
                 WHERE token_id = ?1 AND revoked_at IS NULL",
                params![token_id, now],
            )
            .map_err(sql_unavailable)?;
            ended
                .entry(application_id.clone())
                .or_insert(ApplicationTokenReconciliation {
                    application_id,
                    reason,
                    revoked_tokens: 0,
                })
                .revoked_tokens += 1;
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(ended.into_values().collect())
    }
}

/// Whether the registration would still mint a token with these caveats: a
/// read-only level admits only read-only tokens, and the contexts and
/// services are exactly the registration's. Unreadable caveats are not.
fn token_within_terms(scopes: &str, terms: &crate::ApplicationAccessTerms) -> bool {
    let Ok(caveats) = serde_json::from_str::<Value>(scopes)
        .map_err(|_| ())
        .and_then(|scopes| AgentInvokeTokenCaveats::parse_stored(&scopes).map_err(|_| ()))
    else {
        return false;
    };
    let set = |values: &[String]| values.iter().cloned().collect::<BTreeSet<_>>();
    let contexts = caveats.allowed_execution_contexts.as_ref().map(|contexts| {
        contexts
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
    });
    (caveats.read_only || !terms.read_only)
        && contexts == Some(set(&terms.allowed_execution_contexts))
        && caveats.allowed_services.as_deref().map(set)
            == terms.allowed_services.as_deref().map(set)
        && caveats.service_restrictions.is_none()
}

/// Ends a consent: its live tokens, codes and refresh token. The row goes
/// too unless it carries an administrator's restriction (disabled or
/// read-only), which then stays for a later approval to reuse. Returns the
/// tokens ended and whether the row was removed.
fn disconnect_access(
    conn: &Connection,
    access: &ApplicationAccessRecord,
    actor: &str,
    now: &str,
) -> Result<(u64, bool), ManagedStoreError> {
    let revoked = revoke_access_tokens(conn, &access.access_id, actor, now)?;
    let unrestricted = access.enabled && !access.read_only;
    if unrestricted {
        conn.execute(
            "DELETE FROM application_access WHERE access_id = ?1",
            [&access.access_id],
        )
        .map_err(sql_unavailable)?;
    } else {
        conn.execute(
            "DELETE FROM application_authorization_codes WHERE access_id = ?1",
            [&access.access_id],
        )
        .map_err(sql_unavailable)?;
        conn.execute(
            "UPDATE application_access SET refresh_token_hash = NULL WHERE access_id = ?1",
            [&access.access_id],
        )
        .map_err(sql_unavailable)?;
    }
    Ok((revoked, unrestricted))
}

fn pending_request(
    conn: &Connection,
    hasher: &BrokerTokenHasher,
    request_id: &str,
    now: &str,
) -> Result<PendingApplicationAuthorization, ManagedStoreError> {
    let invalid = || ManagedStoreError::ApplicationAuthorizationInvalid;
    if !valid_request_id(request_id) {
        return Err(invalid());
    }
    let hash = request_hash(request_id);
    let (application_id, ciphertext, nonce, expires_at): (String, Vec<u8>, Vec<u8>, String) = conn
        .query_row(
            "SELECT application_id, encrypted_payload, encryption_nonce, expires_at
             FROM application_authorization_requests
             WHERE request_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
            params![hash, now],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or_else(invalid)?;
    if nonce.len() != 12 {
        return Err(invalid());
    }
    let plaintext = request_payload_cipher(hasher, request_id)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &hash,
            },
        )
        .map_err(|_| invalid())?;
    let parameters: ApplicationAuthorizationParameters =
        serde_json::from_slice(&plaintext).map_err(|_| invalid())?;
    validate_parameters(&parameters).map_err(|_| invalid())?;
    Ok(PendingApplicationAuthorization {
        application_id,
        parameters,
        expires_at,
    })
}

fn mint_tx(
    tx: &rusqlite::Transaction<'_>,
    hasher: &BrokerTokenHasher,
    application_id: &str,
    registration: Option<&ApplicationRegistration>,
    grant: ApplicationGrant<'_>,
    now: DateTime<Utc>,
) -> Result<Result<ApplicationTokenMint, ApplicationGrantRefused>, ManagedStoreError> {
    let current = normalized_timestamp(now);
    let refused = |refusal, access: Option<&ApplicationAccessRecord>| {
        Ok(Err(ApplicationGrantRefused {
            refusal,
            principal_id: access.map(|access| access.principal_id.clone()),
            access_id: access.map(|access| access.access_id.clone()),
        }))
    };
    let access = match grant {
        ApplicationGrant::AuthorizationCode {
            code,
            redirect_uri,
            code_verifier,
        } => {
            if !valid_application_secret(AUTHORIZATION_CODE_PREFIX, code) {
                return refused(ApplicationGrantRefusal::GrantInvalid, None);
            }
            let code_hash = hasher.hash(code)?;
            let consumed: Option<(String, String, String, String)> = tx
                .query_row(
                    "UPDATE application_authorization_codes SET consumed_at = ?2
                     WHERE code_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2
                     RETURNING access_id, application_id, redirect_uri, code_challenge",
                    params![code_hash, current],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(sql_unavailable)?;
            let Some((access_id, code_application, code_redirect, challenge)) = consumed else {
                return refused(ApplicationGrantRefusal::GrantInvalid, None);
            };
            let access = access_by(tx, "a.access_id", &access_id, &current)?;
            let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
            if code_application != application_id
                || code_redirect != redirect_uri
                // The operator may have removed the address since approval.
                || registration
                    .is_some_and(|registration| !registration.accepts_redirect_uri(&code_redirect))
                || !valid_code_verifier(code_verifier)
                || !constant_time_eq(computed.as_bytes(), challenge.as_bytes())
            {
                return refused(ApplicationGrantRefusal::GrantInvalid, access.as_ref());
            }
            access
        }
        ApplicationGrant::RefreshToken { refresh_token } => {
            if !valid_application_secret(REFRESH_TOKEN_PREFIX, refresh_token) {
                return refused(ApplicationGrantRefusal::GrantInvalid, None);
            }
            access_by(
                tx,
                "a.refresh_token_hash",
                &hasher.hash(refresh_token)?,
                &current,
            )?
        }
    };
    let Some(access) = access.filter(|access| access.application_id == application_id) else {
        return refused(ApplicationGrantRefusal::GrantInvalid, None);
    };
    let Some(terms) = registration.and_then(|registration| registration.terms.as_ref()) else {
        return refused(
            ApplicationGrantRefusal::ApplicationUnavailable,
            Some(&access),
        );
    };
    if !access.enabled {
        return refused(ApplicationGrantRefusal::AccessDisabled, Some(&access));
    }
    let principal = principal_by_id_without_groups(tx, &access.principal_id)?;
    if principal.kind != "user" || principal.status != "active" {
        return refused(ApplicationGrantRefusal::PrincipalUnavailable, Some(&access));
    }
    if matches!(grant, ApplicationGrant::RefreshToken { .. }) {
        let last = access
            .last_used_at
            .as_deref()
            .unwrap_or(&access.connected_at);
        let idle_from = DateTime::parse_from_rfc3339(last)
            .map_err(|_| ManagedStoreError::SchemaInvalid("application access is invalid".into()))?
            .with_timezone(&Utc);
        let idle = i64::try_from(terms.refresh_idle_ttl_seconds).unwrap_or(i64::MAX);
        if idle_from
            .checked_add_signed(Duration::seconds(idle))
            .is_some_and(|deadline| deadline <= now)
        {
            return refused(ApplicationGrantRefusal::RefreshTokenIdle, Some(&access));
        }
    }
    // A redeemed code is the new grant: it ends the previous refresh token
    // (replaced below), the tokens minted through it and every other code
    // outstanding for the access. Until here an approval changed nothing.
    let replaced_tokens = match grant {
        ApplicationGrant::AuthorizationCode { .. } => {
            tx.execute(
                "DELETE FROM application_authorization_codes WHERE access_id = ?1",
                [&access.access_id],
            )
            .map_err(sql_unavailable)?;
            revoke_access_tokens(tx, &access.access_id, &access.principal_id, &current)?
        }
        ApplicationGrant::RefreshToken { .. } => {
            if access.live_token_count >= APPLICATION_ACCESS_MAX_LIVE_TOKENS {
                return refused(ApplicationGrantRefusal::TokenLimit, Some(&access));
            }
            0
        }
    };
    let read_only = terms.read_only || access.read_only;
    let mut scopes = serde_json::json!({
        "readOnly": read_only,
        "allowedExecutionContexts": terms.allowed_execution_contexts,
    });
    if let Some(services) = &terms.allowed_services {
        scopes["allowedServices"] = serde_json::json!(services);
    }
    AgentInvokeTokenCaveats::parse_issuance_structure(&scopes)
        .map_err(|error| input_invalid(error.to_string()))?;
    let ttl = i64::try_from(terms.access_token_ttl_seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| input_invalid("application access token lifetime is invalid"))?;
    let token = generate_broker_token(&BrokerTokenClass::AgentInvoke);
    let token_id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO broker_tokens
         (token_id, token_hash, principal_id, name, token_class, scopes_json, created_at,
          expires_at, revoked_at, revoked_by, last_used_at, created_by, application_access_id)
         VALUES (?1, ?2, ?3, ?4, 'agent_invoke', ?5, ?6, ?7, NULL, NULL, NULL, ?3, ?8)",
        params![
            token_id,
            hasher.hash(&token)?,
            access.principal_id,
            format!("Application {application_id}"),
            scopes.to_string(),
            now_string(),
            normalized_timestamp(now + Duration::seconds(ttl)),
            access.access_id
        ],
    )
    .map_err(sql_unavailable)?;
    let refresh_token = match grant {
        ApplicationGrant::AuthorizationCode { .. } => {
            let refresh_token = generate_application_secret(REFRESH_TOKEN_PREFIX);
            tx.execute(
                "UPDATE application_access SET refresh_token_hash = ?2, connected_at = ?3,
                 last_used_at = ?3 WHERE access_id = ?1",
                params![access.access_id, hasher.hash(&refresh_token)?, current],
            )
            .map_err(sql_unavailable)?;
            Some(refresh_token)
        }
        ApplicationGrant::RefreshToken { .. } => {
            tx.execute(
                "UPDATE application_access SET last_used_at = ?2 WHERE access_id = ?1",
                params![access.access_id, current],
            )
            .map_err(sql_unavailable)?;
            None
        }
    };
    let access = access_by(tx, "a.access_id", &access.access_id, &current)?
        .ok_or(ManagedStoreError::ApplicationAccessNotFound)?;
    Ok(Ok(ApplicationTokenMint {
        token,
        record: broker_token_by_id(tx, &token_id)?,
        refresh_token,
        principal_name: application_principal_name(
            principal.display_name.as_deref(),
            &principal.principal_id,
        ),
        access,
        read_only,
        expires_in_seconds: terms.access_token_ttl_seconds,
        replaced_tokens,
    }))
}

/// The name an application shows for the person: their display name, at most
/// 256 characters, or their principal ID when they have none. Never empty.
fn application_principal_name(display_name: Option<&str>, principal_id: &str) -> String {
    display_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(256).collect())
        .unwrap_or_else(|| principal_id.to_string())
}

pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let invalid: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM application_access a JOIN principals p
               ON p.principal_id = a.principal_id WHERE p.kind <> 'user')
             OR EXISTS(SELECT 1 FROM broker_tokens
               WHERE application_access_id IS NOT NULL AND token_class <> 'agent_invoke')",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if invalid {
        return Err(ManagedStoreError::SchemaInvalid(
            "application access is invalid".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(conn, MANAGED_STORE_APPLICATION_ACCESS_VERSION)?;
    agent_token_issuance::validate_context_rows(conn)?;
    imported_gateway_routes::check_rows(conn)?;
    microsoft_enrollments::check_rows(conn)?;
    check_rows(conn)
}

#[cfg(test)]
#[path = "application_access_tests.rs"]
mod tests;
