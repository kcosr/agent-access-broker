//! Access keys: bearer tokens the Broker issues for a service that asks the
//! Broker whose they are. They live in their own table, so no Broker path
//! resolves one, and the raw token is returned once and never stored.
use super::account_usernames::{
    self, AccountUsernameHolderKind, AccountUsernameRecord, AccountUsernameState,
    PrincipalAccountUsername,
};
use super::*;
use crate::{
    ACCESS_KEY_MAX_TYPES, AccessKeyLifetime, AccessKeyTypes, AccountUsernamePolicy,
    is_valid_execution_context_value, parse_access_key_lifetime,
};

/// Every access key starts with this; 43 unpadded base64url characters of
/// 32 random bytes follow.
pub const ACCESS_KEY_PREFIX: &str = "aab_ak_";
/// The least time between two last-used writes of one token.
pub const ACCESS_KEY_LAST_USED_INTERVAL_SECONDS: i64 = 5 * 60;
/// The longest name a person may give a token.
pub const ACCESS_KEY_NAME_MAX_BYTES: usize = 128;
/// Groups a resolution may return.
pub const ACCESS_KEY_RESOLUTION_MAX_GROUPS: usize = 64;
/// The largest resolution answer, in bytes.
pub const ACCESS_KEY_RESOLUTION_MAX_ANSWER_BYTES: usize = 16 * 1024;

const ACCESS_KEY_ID_PREFIX: &str = "ak_";

/// Whether `value` has the shape of an access key: the prefix and 43
/// characters of `[A-Za-z0-9_-]`. A value that starts with the prefix and
/// fails this is malformed, never another kind of token.
pub fn is_access_key(value: &str) -> bool {
    value.strip_prefix(ACCESS_KEY_PREFIX).is_some_and(|secret| {
        secret.len() == 43
            && secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

/// Whether `value` starts with the namespace reserved for Broker secrets.
/// Management identifiers must never carry these values to audit or storage.
pub fn has_broker_secret_prefix(value: &str) -> bool {
    value.starts_with("aab_")
}

/// Whether `value` starts with the access-key prefix, well formed or not.
/// Such a value is never a Broker credential of any other kind.
pub fn has_access_key_prefix(value: &str) -> bool {
    value.starts_with(ACCESS_KEY_PREFIX)
}

#[cfg(test)]
pub(crate) fn test_token_hasher() -> BrokerTokenHasher {
    BrokerTokenHasher {
        key: Arc::new([9; 32]),
    }
}

fn generate_access_key() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{ACCESS_KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// A key ID is `ak_` plus 1 to 60 ASCII letters, digits, underscores or
/// hyphens. Its remainder must not start with the Broker secret prefix `aab_`.
pub fn is_access_key_id(value: &str) -> bool {
    value.strip_prefix(ACCESS_KEY_ID_PREFIX).is_some_and(|id| {
        (1..=60).contains(&id.len())
            && !has_broker_secret_prefix(id)
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

/// How a token was issued.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyOrigin {
    /// A signed-in person created it for themselves.
    Portal,
    /// An administrator issued it for its owner, a person or a service
    /// account.
    Administrator,
    /// A registered application minted it for a person. No operation issues
    /// or resolves this origin yet.
    Application,
}

impl AccessKeyOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portal => "portal",
            Self::Administrator => "administrator",
            Self::Application => "application",
        }
    }

    fn from_stored(value: &str) -> Option<Self> {
        match value {
            "portal" => Some(Self::Portal),
            "administrator" => Some(Self::Administrator),
            "application" => Some(Self::Application),
            _ => None,
        }
    }
}

/// One access key, without its secret or hash.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyRecord {
    pub key_id: String,
    pub principal_id: String,
    pub name: String,
    pub origin: AccessKeyOrigin,
    /// The access key type names it carries, in the order they were requested.
    pub access_key_types: Vec<String>,
    /// The owner's username incarnation when it was minted.
    pub username_incarnation: String,
    pub created_at: String,
    pub created_by: String,
    /// The immutable key expiry; `None` means never.
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    pub last_used_at: Option<String>,
}

impl AccessKeyRecord {
    /// The allowlisted facts an audit record keeps about this token.
    pub fn audit_details(&self) -> Value {
        serde_json::json!({
            "keyId": self.key_id,
            "principal": self.principal_id,
            "origin": self.origin,
            "accessKeyTypes": self.access_key_types,
            "usernameIncarnation": self.username_incarnation,
            "expiresAt": self.expires_at,
        })
    }
}

/// A newly minted token. The secret is available only here.
#[derive(Clone)]
pub struct IssuedAccessKey {
    pub key: String,
    pub record: AccessKeyRecord,
}

impl std::fmt::Debug for IssuedAccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedAccessKey")
            .field("key_id", &self.record.key_id)
            .finish_non_exhaustive()
    }
}

/// A signed-in person's request for a token of their own.
#[derive(Debug, Clone)]
pub struct PortalAccessKeyRequest {
    pub principal_id: String,
    /// The token ID of the browser session the request arrived with. The
    /// mint requires that session to be the person's and still live.
    pub session_token_id: String,
    pub name: String,
    pub access_key_types: Vec<String>,
    pub lifetime: String,
}

/// An administrator's request for a token that belongs to a person or a
/// service account.
#[derive(Debug, Clone)]
pub struct AdministratorAccessKeyRequest {
    /// The person or service account the token belongs to.
    pub principal_id: String,
    pub name: String,
    pub access_key_types: Vec<String>,
    pub lifetime: String,
    /// The administrator.
    pub created_by: String,
}

/// Why a mint issued nothing.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyRefusal {
    /// The request did not arrive with a live browser session of the person.
    SessionRequired,
    PrincipalDisabled,
    /// The person's identity access is paused.
    IdentityAccessPaused,
    /// The person has no identity-access gate: no key of theirs resolves.
    IdentityAccessMissing,
    /// Only a person creates a token for themselves, and an administrator
    /// issues one only for a person or a service account.
    OwnerKind,
    /// The owner holds no username.
    NoAccountUsername,
    /// The owner's name awaits an administrator's confirmation.
    AccountUsernameAwaitingConfirmation,
    /// The operator reserved the owner's name.
    AccountUsernameReserved,
    /// The owner is in more local groups than a resolution returns: no key
    /// of theirs resolves until they are in fewer.
    GroupLimitExceeded,
    /// A requested access key type is not configured. Said to an
    /// administrator only: a person's own request is answered
    /// [`Self::AccessKeyTypeNotEligible`] for it.
    AccessKeyTypeUnknown,
    /// People may not create tokens of a requested access key type, which
    /// the person may hold.
    AccessKeyTypeNotSelfService,
    /// A requested access key type is not one the owner may hold: the
    /// owner's access key type setting does not allow it or, on a person's
    /// own request, it is not configured.
    AccessKeyTypeNotEligible,
    /// A requested access key type does not offer the lifetime.
    LifetimeNotOffered,
}

impl AccessKeyRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionRequired => "session_required",
            Self::PrincipalDisabled => "principal_disabled",
            Self::IdentityAccessPaused => "identity_access_paused",
            Self::IdentityAccessMissing => "identity_access_missing",
            Self::OwnerKind => "owner_kind",
            Self::NoAccountUsername => "no_account_username",
            Self::AccountUsernameAwaitingConfirmation => "account_username_awaiting_confirmation",
            Self::AccountUsernameReserved => "account_username_reserved",
            Self::GroupLimitExceeded => "group_limit_exceeded",
            Self::AccessKeyTypeUnknown => "access_key_type_unknown",
            Self::AccessKeyTypeNotSelfService => "access_key_type_not_self_service",
            Self::AccessKeyTypeNotEligible => "access_key_type_not_eligible",
            Self::LifetimeNotOffered => "lifetime_not_offered",
        }
    }
}

/// A refused mint, with the access key type that refused it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyRefused {
    pub refusal: AccessKeyRefusal,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_type: Option<String>,
}

impl AccessKeyRefused {
    pub fn new(refusal: AccessKeyRefusal) -> Self {
        Self {
            refusal,
            access_key_type: None,
        }
    }

    fn access_key_type(refusal: AccessKeyRefusal, access_key_type: &str) -> Self {
        Self {
            access_key_type: Some(access_key_type.to_string()),
            ..Self::new(refusal)
        }
    }

    /// The allowlisted facts an audit record keeps about this refusal.
    pub fn audit_details(&self) -> Value {
        serde_json::json!(self)
    }

    /// What the person reading the refusal is told: why no token was issued.
    pub const fn message(&self) -> &'static str {
        match self.refusal {
            AccessKeyRefusal::SessionRequired => {
                "an access key is created from a signed-in browser session"
            }
            AccessKeyRefusal::PrincipalDisabled => "the account is disabled",
            AccessKeyRefusal::IdentityAccessPaused => "the account's identity access is paused",
            AccessKeyRefusal::IdentityAccessMissing => {
                "the account has no identity access record; an access key would not work"
            }
            AccessKeyRefusal::OwnerKind => {
                "an access key belongs to a person or a service account; only a person creates their own"
            }
            AccessKeyRefusal::NoAccountUsername => {
                "the account has no username; an administrator can set one"
            }
            AccessKeyRefusal::AccountUsernameAwaitingConfirmation => {
                "the account's username awaits an administrator's confirmation"
            }
            AccessKeyRefusal::AccountUsernameReserved => {
                "the account's username is reserved by the operator and cannot be used"
            }
            AccessKeyRefusal::GroupLimitExceeded => {
                "the account is in more than 64 local groups; an access key would not work until it is in fewer"
            }
            AccessKeyRefusal::AccessKeyTypeUnknown => {
                "a requested access key type is not configured"
            }
            AccessKeyRefusal::AccessKeyTypeNotSelfService => {
                "a requested access key type cannot be created by people for themselves"
            }
            AccessKeyRefusal::AccessKeyTypeNotEligible => {
                "a requested access key type is not one the account may hold"
            }
            AccessKeyRefusal::LifetimeNotOffered => {
                "a requested access key type does not offer this lifetime"
            }
        }
    }
}

/// Whether a token resolves now, and why not when it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKeyStatus {
    Active,
    Inactive(AccessKeyInactiveReason),
}

impl AccessKeyStatus {
    /// `active`, or the reason a resolution finds the key inactive.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive(reason) => reason.as_str(),
        }
    }
}

impl Serialize for AccessKeyStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One access key type a key carries, as a listing shows it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyTypeState {
    pub id: String,
    /// The type's configured display name; `None` when the configuration no
    /// longer defines the type.
    pub display_name: Option<String>,
    /// Whether the key still holds the type, by the decision a resolution
    /// makes for each type: it is configured, the owner's access key type
    /// setting allows it, and its current maximum lifetime has not ended it
    /// before the key's own expiry, if any. It says nothing about the key itself,
    /// which `status` covers.
    pub held: bool,
}

/// How much of what a key carries it resolves with now.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyAccess {
    /// The key is active with every type it carries.
    Full,
    /// The key is active with only some of the types it carries.
    Partial,
    /// The key is not active: it resolves with no type.
    None,
}

/// A token as its owner and administrators see it: the stored record with
/// what the token would resolve as now. Reading it records no use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyView {
    #[serde(flatten)]
    pub record: AccessKeyRecord,
    pub status: AccessKeyStatus,
    /// The access key types an active token may use now and when each
    /// stops; empty otherwise.
    pub usable_access_key_types: Vec<ResolvedAccessKeyType>,
    /// Every type the key carries, in the key's order, with its display
    /// name and whether the key still holds it.
    pub access_key_type_states: Vec<AccessKeyTypeState>,
    pub access: AccessKeyAccess,
}

/// Which tokens a listing returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessKeyListFilter {
    /// Only this principal's tokens.
    pub principal_id: Option<String>,
    pub include_revoked: bool,
    pub include_expired: bool,
}

/// What a signed-in person may hold and create for themselves now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyOptions {
    /// The person's name: its mode, the name held and where it stands, with
    /// the reason when there is none. `None` for a principal that is neither
    /// a person nor a service account.
    pub account_username: Option<PrincipalAccountUsername>,
    /// Why the person can create no token of any type, when they cannot:
    /// what a mint of their own would answer whatever it asked for.
    pub refusal: Option<AccessKeyRefusal>,
    /// The access key types the person's access key type setting allows, by ID.
    /// The person may create a token only of those whose `self_service` is
    /// set; an administrator can issue any of them for the person.
    pub access_key_types: Vec<crate::AccessKeyType>,
    /// Whether the person owns any access key, whoever issued it and
    /// whatever its state.
    pub has_keys: bool,
    /// Why no access key of the person's can work now, when the person can
    /// create a key or owns one and the cause is one only an administrator
    /// can remove: no usable username, or more local groups than a
    /// resolution returns. The reason is the status every key of theirs
    /// lists. `None` when `refusal` names a disabled account or identity
    /// access that is paused or missing, which a resolution finds first.
    pub problem: Option<AccessKeyInactiveReason>,
}

/// The outcome of a revocation request for an existing token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyRevocation {
    pub record: AccessKeyRecord,
    /// `false` when the token was already revoked and nothing was written.
    pub newly_revoked: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeySubjectKind {
    User,
    ServiceAccount,
}

/// Who a key resolves as at the resolving service: a person under their username, or
/// a service account under its principal ID.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccessKeySubject {
    pub kind: AccessKeySubjectKind,
    pub id: String,
}

/// One access key type a token may currently use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedAccessKeyType {
    pub name: String,
    /// When this access key type stops being returned for the token: the earlier
    /// of the token's expiry and its mint time plus the access key type's
    /// current maximum lifetime. `None` means both are unlimited.
    pub valid_until: Option<String>,
}

/// The facts of an active token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyFacts {
    /// The Broker principal that owns the token. Not part of the answer.
    pub principal_id: String,
    pub subject: AccessKeySubject,
    pub username_incarnation: String,
    /// Groups the subject holds by active local membership.
    pub groups: Vec<String>,
    pub access_key_types: Vec<ResolvedAccessKeyType>,
    pub origin: AccessKeyOrigin,
    /// The application of an application-minted token.
    pub application: Option<String>,
    pub key_id: String,
    /// The immutable key expiry; `None` means never.
    pub expires_at: Option<String>,
}

/// Why a value is not active. Stored-key reasons are returned to the resolving service.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyInactiveReason {
    /// Not the shape of an access key.
    Malformed,
    Unknown,
    Revoked,
    Expired,
    PrincipalDisabled,
    /// The person's identity access is paused.
    IdentityAccessPaused,
    /// The person has no identity-access gate; resolution fails closed.
    IdentityAccessMissing,
    /// No operation resolves this origin yet.
    OriginUnsupported,
    NoAccountUsername,
    AccountUsernameAwaitingConfirmation,
    AccountUsernameReserved,
    /// The owner's name was changed or released after the token was minted.
    UsernameIncarnationChanged,
    /// The subject holds more groups than a resolution may return.
    GroupLimitExceeded,
    /// No carried access key type is configured, within its lifetime and one the
    /// subject's access key type setting allows.
    NoAccessKeyType,
}

impl AccessKeyInactiveReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unknown => "unknown",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::PrincipalDisabled => "principal_disabled",
            Self::IdentityAccessPaused => "identity_access_paused",
            Self::IdentityAccessMissing => "identity_access_missing",
            Self::OriginUnsupported => "origin_unsupported",
            Self::NoAccountUsername => "no_account_username",
            Self::AccountUsernameAwaitingConfirmation => "account_username_awaiting_confirmation",
            Self::AccountUsernameReserved => "account_username_reserved",
            Self::UsernameIncarnationChanged => "username_incarnation_changed",
            Self::GroupLimitExceeded => "group_limit_exceeded",
            Self::NoAccessKeyType => "no_access_key_type",
        }
    }
}

/// A value that is not active, with current identity facts for a stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyInactive {
    pub reason: AccessKeyInactiveReason,
    /// The key ID when the secret named a stored key.
    pub key_id: Option<String>,
    /// Its owner's current usable username or service-account ID.
    pub owner: Option<AccessKeySubject>,
}

impl AccessKeyInactive {
    fn unmatched(reason: AccessKeyInactiveReason) -> Self {
        Self {
            reason,
            key_id: None,
            owner: None,
        }
    }
}

/// Whose access key a secret is, or that it is not active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessKeyResolution {
    Active(Box<AccessKeyFacts>),
    Inactive(AccessKeyInactive),
}

impl AccessKeyResolution {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active(_))
    }
}

/// Active facts, stored-key identity and reason, or bare `{"active":false}`
/// for an unknown or malformed value.
impl Serialize for AccessKeyResolution {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Active<'a> {
            active: bool,
            subject: &'a AccessKeySubject,
            username_incarnation: &'a str,
            groups: &'a [String],
            types: &'a [ResolvedAccessKeyType],
            origin: AccessKeyOrigin,
            application: Option<&'a str>,
            key_id: &'a str,
            expires_at: Option<&'a str>,
        }
        #[derive(Serialize)]
        struct Unmatched {
            active: bool,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct StoredInactive<'a> {
            active: bool,
            key_id: &'a str,
            owner: Option<&'a AccessKeySubject>,
            reason: AccessKeyInactiveReason,
        }
        match self {
            Self::Active(facts) => Active {
                active: true,
                subject: &facts.subject,
                username_incarnation: &facts.username_incarnation,
                groups: &facts.groups,
                types: &facts.access_key_types,
                origin: facts.origin,
                application: facts.application.as_deref(),
                key_id: &facts.key_id,
                expires_at: facts.expires_at.as_deref(),
            }
            .serialize(serializer),
            Self::Inactive(inactive) => match inactive.key_id.as_deref() {
                Some(key_id) => StoredInactive {
                    active: false,
                    key_id,
                    owner: inactive.owner.as_ref(),
                    reason: inactive.reason,
                }
                .serialize(serializer),
                None => Unmatched { active: false }.serialize(serializer),
            },
        }
    }
}

/// The size of the largest answer a key can resolve to under the limits:
/// [`ACCESS_KEY_MAX_TYPES`] access key types with the longest IDs, a subject
/// with the longest name, [`ACCESS_KEY_RESOLUTION_MAX_GROUPS`] groups with the
/// longest IDs, and the username incarnation and key ID at the longest the
/// store admits. It is the largest over the answers that can be emitted: a
/// person's portal key, and an administrator's key for a person or for a
/// service account, all with no application. Finite timestamps give the largest
/// form; null key expiry, with finite or null type validity, is smaller. It is within
/// [`ACCESS_KEY_RESOLUTION_MAX_ANSWER_BYTES`], which a test holds, so no
/// configuration is refused for the size of its answers; the route still
/// refuses an answer over the limit. Extend the combinations when another
/// origin is resolved.
pub fn largest_access_key_resolution_answer_bytes() -> usize {
    const TIME: &str = "9999-12-31T23:59:59Z";
    let types: Vec<ResolvedAccessKeyType> = (0..ACCESS_KEY_MAX_TYPES)
        .map(|index| ResolvedAccessKeyType {
            name: format!("{}{index:02}", "x".repeat(62)),
            valid_until: Some(TIME.to_string()),
        })
        .collect();
    [
        (AccessKeyOrigin::Portal, AccessKeySubjectKind::User),
        (AccessKeyOrigin::Administrator, AccessKeySubjectKind::User),
        (
            AccessKeyOrigin::Administrator,
            AccessKeySubjectKind::ServiceAccount,
        ),
    ]
    .into_iter()
    .map(|(origin, kind)| {
        serialized_bytes(&AccessKeyResolution::Active(Box::new(AccessKeyFacts {
            principal_id: String::new(),
            subject: AccessKeySubject {
                kind,
                id: "x".repeat(256),
            },
            username_incarnation: "x".repeat(64),
            groups: vec!["x".repeat(128); ACCESS_KEY_RESOLUTION_MAX_GROUPS],
            access_key_types: types.clone(),
            origin,
            application: None,
            key_id: format!("{ACCESS_KEY_ID_PREFIX}{}", "x".repeat(60)),
            expires_at: Some(TIME.to_string()),
        })))
    })
    .max()
    .unwrap_or(usize::MAX)
}

/// The size of `value` as JSON.
fn serialized_bytes<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

fn invalid_row() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("access key is invalid".into())
}

fn stored_time(value: &str) -> Result<DateTime<Utc>, ManagedStoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid_row())
}

const TOKEN_COLUMNS: &str = "key_id, principal_id, name, origin, username_incarnation, created_at, \
     created_by, expires_at, revoked_at, revoked_by, last_used_at";

fn token_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<AccessKeyRecord, ManagedStoreError>> {
    let origin: String = row.get(3)?;
    let Some(origin) = AccessKeyOrigin::from_stored(&origin) else {
        return Ok(Err(invalid_row()));
    };
    Ok(Ok(AccessKeyRecord {
        key_id: row.get(0)?,
        principal_id: row.get(1)?,
        name: row.get(2)?,
        origin,
        access_key_types: Vec::new(),
        username_incarnation: row.get(4)?,
        created_at: row.get(5)?,
        created_by: row.get(6)?,
        expires_at: row.get(7)?,
        revoked_at: row.get(8)?,
        revoked_by: row.get(9)?,
        last_used_at: row.get(10)?,
    }))
}

fn load_access_key_types(
    conn: &Connection,
    record: &mut AccessKeyRecord,
) -> Result<(), ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT access_key_type FROM access_key_type_links
             WHERE key_id = ?1 ORDER BY access_key_type_order",
        )
        .map_err(sql_unavailable)?;
    record.access_key_types = collect_rows(
        statement
            .query_map([&record.key_id], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    Ok(())
}

fn token_by(
    conn: &Connection,
    column: &str,
    value: &str,
) -> Result<Option<AccessKeyRecord>, ManagedStoreError> {
    let Some(mut record) = conn
        .query_row(
            &format!("SELECT {TOKEN_COLUMNS} FROM access_keys WHERE {column} = ?1"),
            [value],
            token_from_row,
        )
        .optional()
        .map_err(sql_unavailable)?
        .transpose()?
    else {
        return Ok(None);
    };
    load_access_key_types(conn, &mut record)?;
    Ok(Some(record))
}

fn tokens_where(
    conn: &Connection,
    condition: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<Vec<AccessKeyRecord>, ManagedStoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {TOKEN_COLUMNS} FROM access_keys WHERE {condition}
             ORDER BY created_at DESC, key_id"
        ))
        .map_err(sql_unavailable)?;
    let mut records = collect_rows(
        statement
            .query_map(values, token_from_row)
            .map_err(sql_unavailable)?,
    )?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    for record in &mut records {
        load_access_key_types(conn, record)?;
    }
    Ok(records)
}

/// The groups `principal_id` holds by active local membership, by group ID.
/// Membership that comes only from directory evidence is not included.
fn active_local_groups(
    conn: &Connection,
    principal_id: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT g.group_id FROM principal_groups pg JOIN groups g ON g.group_id = pg.group_id
             WHERE pg.principal_id = ?1 AND g.status = 'active' ORDER BY g.group_id",
        )
        .map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([principal_id], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )
}

struct Owner {
    kind: String,
    active: bool,
}

fn owner(conn: &Connection, principal_id: &str) -> Result<Option<Owner>, ManagedStoreError> {
    conn.query_row(
        "SELECT kind, status FROM principals WHERE principal_id = ?1",
        [principal_id],
        |row| {
            Ok(Owner {
                kind: row.get(0)?,
                active: row.get::<_, String>(1)? == "active",
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)
}

/// Whether a person's identity access is paused: the same gate that pauses
/// their attested identity paths. `None` when the gate row is missing, which
/// every caller treats as not usable.
fn identity_access_paused(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<bool>, ManagedStoreError> {
    conn.query_row(
        "SELECT paused FROM principal_identity_access WHERE principal_id = ?1",
        [principal_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_unavailable)
}

/// A state of an account in which no access key of it resolves, whatever
/// the key. A mint is refused for it, with the same code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountProblem {
    PrincipalDisabled,
    IdentityAccessPaused,
    IdentityAccessMissing,
    NoAccountUsername,
    AccountUsernameAwaitingConfirmation,
    AccountUsernameReserved,
    GroupLimitExceeded,
}

impl AccountProblem {
    /// The reason a resolution of a key of the account records.
    const fn reason(self) -> AccessKeyInactiveReason {
        match self {
            Self::PrincipalDisabled => AccessKeyInactiveReason::PrincipalDisabled,
            Self::IdentityAccessPaused => AccessKeyInactiveReason::IdentityAccessPaused,
            Self::IdentityAccessMissing => AccessKeyInactiveReason::IdentityAccessMissing,
            Self::NoAccountUsername => AccessKeyInactiveReason::NoAccountUsername,
            Self::AccountUsernameAwaitingConfirmation => {
                AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation
            }
            Self::AccountUsernameReserved => AccessKeyInactiveReason::AccountUsernameReserved,
            Self::GroupLimitExceeded => AccessKeyInactiveReason::GroupLimitExceeded,
        }
    }

    /// Why a key is not issued for the account: the same code.
    const fn refusal(self) -> AccessKeyRefusal {
        match self {
            Self::PrincipalDisabled => AccessKeyRefusal::PrincipalDisabled,
            Self::IdentityAccessPaused => AccessKeyRefusal::IdentityAccessPaused,
            Self::IdentityAccessMissing => AccessKeyRefusal::IdentityAccessMissing,
            Self::NoAccountUsername => AccessKeyRefusal::NoAccountUsername,
            Self::AccountUsernameAwaitingConfirmation => {
                AccessKeyRefusal::AccountUsernameAwaitingConfirmation
            }
            Self::AccountUsernameReserved => AccessKeyRefusal::AccountUsernameReserved,
            Self::GroupLimitExceeded => AccessKeyRefusal::GroupLimitExceeded,
        }
    }

    /// Whether a resolution finds the state before it looks at the
    /// account's name.
    const fn precedes_name(self) -> bool {
        matches!(
            self,
            Self::PrincipalDisabled | Self::IdentityAccessPaused | Self::IdentityAccessMissing
        )
    }
}

/// Where the account of a person or a service account stands for access
/// keys: the name its keys resolve under, or the first state, in the order
/// a resolution finds it, in which none of them resolves. A key is issued
/// only for an account in good standing, so that none is issued that could
/// not work; [`evaluate`] makes the same decisions for a stored key, among
/// those that depend on the key.
fn account_standing(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    owner: &Owner,
    principal_id: &str,
) -> Result<Result<AccountUsernameRecord, AccountProblem>, ManagedStoreError> {
    if !owner.active {
        return Ok(Err(AccountProblem::PrincipalDisabled));
    }
    // A service account has no gate.
    if owner.kind == "user" {
        match identity_access_paused(conn, principal_id)? {
            Some(false) => {}
            Some(true) => return Ok(Err(AccountProblem::IdentityAccessPaused)),
            None => return Ok(Err(AccountProblem::IdentityAccessMissing)),
        }
    }
    let name = match usable_name(
        account_usernames::name_of(conn, policy, principal_id)?,
        AccountProblem::NoAccountUsername,
        AccountProblem::AccountUsernameAwaitingConfirmation,
        AccountProblem::AccountUsernameReserved,
    ) {
        Ok(name) => name,
        Err(problem) => return Ok(Err(problem)),
    };
    if active_local_groups(conn, principal_id)?.len() > ACCESS_KEY_RESOLUTION_MAX_GROUPS {
        return Ok(Err(AccountProblem::GroupLimitExceeded));
    }
    Ok(Ok(name))
}

/// The owner's name, when it is one a token can be minted or resolved under.
fn usable_name<R>(
    name: Option<AccountUsernameRecord>,
    none: R,
    awaiting: R,
    reserved: R,
) -> Result<AccountUsernameRecord, R> {
    let name = name.ok_or(none)?;
    match name.state {
        AccountUsernameState::Usable => Ok(name),
        AccountUsernameState::AwaitingConfirmation => Err(awaiting),
        AccountUsernameState::Reserved => Err(reserved),
    }
}

fn validate_mint_request(
    name: &str,
    access_key_types: &[String],
    lifetime: &str,
) -> Result<(), ManagedStoreError> {
    if name.trim().is_empty()
        || name.trim() != name
        || name.len() > ACCESS_KEY_NAME_MAX_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(input_invalid(format!(
            "access key name must be 1 to {ACCESS_KEY_NAME_MAX_BYTES} bytes without control characters or surrounding whitespace"
        )));
    }
    let mut seen = BTreeSet::new();
    if access_key_types.is_empty()
        || access_key_types.len() > ACCESS_KEY_MAX_TYPES
        || access_key_types
            .iter()
            .any(|id| !is_valid_execution_context_value(id) || !seen.insert(id))
    {
        return Err(input_invalid(format!(
            "an access key carries 1 to {ACCESS_KEY_MAX_TYPES} distinct access key types"
        )));
    }
    if parse_access_key_lifetime(lifetime).is_none() {
        return Err(input_invalid(
            "access key lifetime must be a positive duration of at most 3650d or never",
        ));
    }
    Ok(())
}

struct Mint<'a> {
    principal_id: &'a str,
    name: &'a str,
    access_key_types: &'a [String],
    lifetime: &'a str,
    origin: AccessKeyOrigin,
    created_by: &'a str,
}

/// Checks every requested access key type against the current
/// configuration and inserts the token under `name`, the usable name of an
/// owner in good standing ([`account_standing`]). Nothing is trimmed: one
/// failing access key type refuses the request.
fn mint(
    conn: &Connection,
    hasher: &BrokerTokenHasher,
    name: &AccountUsernameRecord,
    access_key_types: &AccessKeyTypes,
    request: &Mint<'_>,
    now: DateTime<Utc>,
) -> Result<Result<IssuedAccessKey, AccessKeyRefused>, ManagedStoreError> {
    let access = access_key_types::policy_at_conn(conn, access_key_types, request.principal_id)?;
    let mut selected_types = Vec::with_capacity(request.access_key_types.len());
    let refused = |refusal, id: &str| Ok(Err(AccessKeyRefused::access_key_type(refusal, id)));
    for id in request.access_key_types {
        let configured = access_key_types.get(id);
        let access_key_type = if request.origin == AccessKeyOrigin::Portal {
            // A person is shown only the types they may hold. One they may
            // not hold is refused the same way whether or not it is
            // configured and whoever may create it, so that a guessed ID
            // tells them nothing; `self_service` is said only of a type
            // their options already list.
            let Some(access_key_type) = configured.filter(|_| access.allows(id)) else {
                return refused(AccessKeyRefusal::AccessKeyTypeNotEligible, id);
            };
            if !access_key_type.self_service {
                return refused(AccessKeyRefusal::AccessKeyTypeNotSelfService, id);
            }
            access_key_type
        } else {
            let Some(access_key_type) = configured else {
                return refused(AccessKeyRefusal::AccessKeyTypeUnknown, id);
            };
            if !access.allows(id) {
                return refused(AccessKeyRefusal::AccessKeyTypeNotEligible, id);
            }
            access_key_type
        };
        selected_types.push(access_key_type);
    }
    let lifetime =
        parse_access_key_lifetime(request.lifetime).expect("validated access key lifetime");
    for access_key_type in selected_types {
        if !access_key_type.offers_lifetime(lifetime) {
            return refused(AccessKeyRefusal::LifetimeNotOffered, &access_key_type.id);
        }
    }
    let created = stored_time(&normalized_timestamp(now))?;
    let expires = match lifetime {
        AccessKeyLifetime::Finite(seconds) => Some(
            created
                .checked_add_signed(Duration::seconds(seconds as i64))
                .ok_or_else(|| input_invalid("access key lifetime is too long"))?,
        ),
        AccessKeyLifetime::Never => None,
    };
    let token = generate_access_key();
    let key_id = format!("{ACCESS_KEY_ID_PREFIX}{}", Uuid::new_v4().simple());
    conn.execute(
        "INSERT INTO access_keys
         (key_id, key_hash, principal_id, name, origin, username_incarnation, created_at,
          created_by, expires_at, revoked_at, revoked_by, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL)",
        params![
            key_id,
            hasher.hash(&token)?,
            request.principal_id,
            request.name,
            request.origin.as_str(),
            name.incarnation,
            normalized_timestamp(created),
            request.created_by,
            expires.map(normalized_timestamp),
        ],
    )
    .map_err(sql_unavailable)?;
    for (order, id) in request.access_key_types.iter().enumerate() {
        conn.execute(
            "INSERT INTO access_key_type_links (key_id, access_key_type, access_key_type_order)
             VALUES (?1, ?2, ?3)",
            params![key_id, id, order as i64],
        )
        .map_err(sql_unavailable)?;
    }
    let record = token_by(conn, "key_id", &key_id)?.ok_or_else(invalid_row)?;
    Ok(Ok(IssuedAccessKey { key: token, record }))
}

/// Whether `session_token_id` is a browser session of `principal_id` that
/// is signed in now, by every condition the session resolver applies
/// (`resolve_browser_session`) and its consumers add: the session's token
/// is a person's, neither revoked, paused nor expired; the sign-in method
/// it came from is still that person's and active; the password was not
/// set after the sign-in; and neither the session nor the method must
/// change its password first.
fn live_browser_session(
    conn: &Connection,
    principal_id: &str,
    session_token_id: &str,
) -> Result<bool, ManagedStoreError> {
    let session: Option<(bool, Option<String>)> = conn
        .query_row(
            "SELECT t.revoked_at IS NULL AND t.paused_at IS NULL
                    AND s.password_change_required = 0
                    AND m.status = 'active' AND m.must_change_password = 0
                    AND (m.password_set_at IS NULL OR m.password_set_at <= s.auth_time),
                    t.expires_at
             FROM browser_sessions s
             JOIN broker_tokens t ON t.token_id = s.token_id
             JOIN principals p ON p.principal_id = s.principal_id
             JOIN principal_login_methods m ON m.login_method_id = s.login_method_id
             WHERE s.token_id = ?1 AND s.principal_id = ?2 AND t.principal_id = ?2
               AND t.token_class = 'user_manage' AND p.kind = 'user'
               AND m.principal_id = s.principal_id AND m.method = s.login_method",
            params![session_token_id, principal_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql_unavailable)?;
    Ok(session.is_some_and(|(signed_in, expires_at)| {
        signed_in && !timestamp_is_past(expires_at.as_deref())
    }))
}

/// What a resolution decides about one access key type a key carries.
struct CarriedType<'a> {
    id: &'a str,
    /// The type as the current configuration defines it, when it does.
    configured: Option<&'a crate::AccessKeyType>,
    /// Whether the current configuration and owner's settings permit the type.
    eligible: bool,
    /// Until when a resolution returns the type for the key: the earlier of
    /// the key's expiry and its mint time plus the type's current maximum
    /// lifetime. `None` means no deadline for an eligible type.
    valid_until: Option<DateTime<Utc>>,
    /// Whether the type lasts as long as the key does: its current maximum
    /// lifetime does not end before the key expires.
    outlasts_key: bool,
}

impl CarriedType<'_> {
    /// Whether a resolution at `now` returns the type.
    fn resolves_at(&self, now: DateTime<Utc>) -> bool {
        self.eligible && self.valid_until.is_none_or(|valid_until| valid_until > now)
    }

    /// Whether the key still holds the type at `now`: a resolution returns
    /// it, or would have until the key itself expired. Before the key's
    /// expiry this is exactly [`Self::resolves_at`].
    fn held_at(&self, now: DateTime<Utc>) -> bool {
        self.eligible && (self.resolves_at(now) || self.outlasts_key)
    }
}

/// The per-type decision of a resolution, for every type `record` carries,
/// in the key's order: read from the current configuration and the owner's
/// current access key type setting. Reads only.
fn carried_types<'a>(
    conn: &Connection,
    access_key_types: &'a AccessKeyTypes,
    record: &'a AccessKeyRecord,
) -> Result<Vec<CarriedType<'a>>, ManagedStoreError> {
    let created = stored_time(&record.created_at)?;
    let expires = record.expires_at.as_deref().map(stored_time).transpose()?;
    let access = access_key_types::policy_at_conn(conn, access_key_types, &record.principal_id)?;
    Ok(record
        .access_key_types
        .iter()
        .map(|id| {
            let configured = access_key_types.get(id);
            let maximum = configured
                .filter(|_| access.allows(id))
                .map(crate::AccessKeyType::maximum_lifetime_seconds);
            let (eligible, valid_until, outlasts_key) = match maximum {
                None => (false, None, false),
                Some(None) => (true, expires, true),
                Some(Some(seconds)) => i64::try_from(seconds)
                    .ok()
                    .and_then(|seconds| created.checked_add_signed(Duration::seconds(seconds)))
                    .map_or((false, None, false), |limit| {
                        (
                            true,
                            Some(expires.map_or(limit, |expires| limit.min(expires))),
                            expires.is_some_and(|expires| limit >= expires),
                        )
                    }),
            };
            CarriedType {
                id,
                configured,
                eligible,
                valid_until,
                outlasts_key,
            }
        })
        .collect())
}

/// Evaluates a stored token against the current principal, name, groups and
/// access key types. Reads only.
fn evaluate(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    access_key_types: &AccessKeyTypes,
    record: &AccessKeyRecord,
    now: DateTime<Utc>,
) -> Result<AccessKeyResolution, ManagedStoreError> {
    // Informational identity comes from the current name, even when a key or
    // account state prevents use. Read it under the same transaction as the reason.
    let name = account_usernames::name_of(conn, policy, &record.principal_id)?;
    let current_owner = name
        .as_ref()
        .filter(|name| name.state == AccountUsernameState::Usable)
        .map(|name| AccessKeySubject {
            kind: match name.holder_kind {
                AccountUsernameHolderKind::User => AccessKeySubjectKind::User,
                AccountUsernameHolderKind::ServiceAccount => AccessKeySubjectKind::ServiceAccount,
            },
            id: name.account_username.clone(),
        });
    let inactive = |reason| {
        Ok(AccessKeyResolution::Inactive(AccessKeyInactive {
            reason,
            key_id: Some(record.key_id.clone()),
            owner: current_owner.clone(),
        }))
    };
    if record.revoked_at.is_some() {
        return inactive(AccessKeyInactiveReason::Revoked);
    }
    let expires = record.expires_at.as_deref().map(stored_time).transpose()?;
    if expires.is_some_and(|expires| expires <= now) {
        return inactive(AccessKeyInactiveReason::Expired);
    }
    let Some(owner) = owner(conn, &record.principal_id)?.filter(|owner| owner.active) else {
        return inactive(AccessKeyInactiveReason::PrincipalDisabled);
    };
    // Pausing a person's identity access pauses their access keys too;
    // resuming it makes them resolve again. A service account has no gate.
    if owner.kind == "user" {
        match identity_access_paused(conn, &record.principal_id)? {
            Some(false) => {}
            Some(true) => return inactive(AccessKeyInactiveReason::IdentityAccessPaused),
            None => return inactive(AccessKeyInactiveReason::IdentityAccessMissing),
        }
    }
    if record.origin == AccessKeyOrigin::Application {
        return inactive(AccessKeyInactiveReason::OriginUnsupported);
    }
    let name = match usable_name(
        name,
        AccessKeyInactiveReason::NoAccountUsername,
        AccessKeyInactiveReason::AccountUsernameAwaitingConfirmation,
        AccessKeyInactiveReason::AccountUsernameReserved,
    ) {
        Ok(name) => name,
        Err(reason) => return inactive(reason),
    };
    if name.incarnation != record.username_incarnation {
        return inactive(AccessKeyInactiveReason::UsernameIncarnationChanged);
    }
    let groups = active_local_groups(conn, &record.principal_id)?;
    if groups.len() > ACCESS_KEY_RESOLUTION_MAX_GROUPS {
        // Dropping a group could lift a rule that names it.
        return inactive(AccessKeyInactiveReason::GroupLimitExceeded);
    }
    // What the subject may hold is read now, as its groups are: access
    // withdrawn after the mint stops the token.
    let resolved: Vec<ResolvedAccessKeyType> = carried_types(conn, access_key_types, record)?
        .into_iter()
        .filter(|carried| carried.resolves_at(now))
        .map(|carried| ResolvedAccessKeyType {
            name: carried.id.to_string(),
            valid_until: carried.valid_until.map(normalized_timestamp),
        })
        .collect();
    if resolved.is_empty() {
        return inactive(AccessKeyInactiveReason::NoAccessKeyType);
    }
    Ok(AccessKeyResolution::Active(Box::new(AccessKeyFacts {
        principal_id: record.principal_id.clone(),
        subject: AccessKeySubject {
            kind: match name.holder_kind {
                AccountUsernameHolderKind::User => AccessKeySubjectKind::User,
                AccountUsernameHolderKind::ServiceAccount => AccessKeySubjectKind::ServiceAccount,
            },
            id: name.account_username,
        },
        username_incarnation: name.incarnation,
        groups,
        access_key_types: resolved,
        origin: record.origin,
        application: None,
        key_id: record.key_id.clone(),
        expires_at: expires.map(normalized_timestamp),
    })))
}

impl ManagedStore {
    /// Mints a token for a signed-in person. The person's account must be
    /// one whose keys resolve ([`account_standing`]: enabled, identity
    /// access neither paused nor missing, a usable username, no more local
    /// groups than a resolution returns), so that no key is issued that
    /// could not work; the person must present a live browser session of
    /// their own; every requested access key type must be configured, open
    /// to self-service and one the person is eligible for; and the lifetime
    /// must be offered by every one of them.
    pub fn mint_portal_access_key(
        &self,
        hasher: &BrokerTokenHasher,
        access_key_types: &AccessKeyTypes,
        request: &PortalAccessKeyRequest,
    ) -> Result<Result<IssuedAccessKey, AccessKeyRefused>, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_uuid_id(&request.session_token_id, "sessionTokenId")?;
        validate_mint_request(&request.name, &request.access_key_types, &request.lifetime)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let owner =
            owner(&tx, &request.principal_id)?.ok_or(ManagedStoreError::PrincipalNotFound)?;
        let refused = |refusal| Ok(Err(AccessKeyRefused::new(refusal)));
        if owner.kind != "user" {
            return refused(AccessKeyRefusal::OwnerKind);
        }
        // No key is issued that could not work: the account must be one
        // whose keys resolve. This comes before any type is judged, so the
        // refusal says nothing about a type the person may not hold.
        let standing = account_standing(&tx, &policy, &owner, &request.principal_id)?;
        if let Err(problem) = standing
            && problem.precedes_name()
        {
            return refused(problem.refusal());
        }
        if !live_browser_session(&tx, &request.principal_id, &request.session_token_id)? {
            return refused(AccessKeyRefusal::SessionRequired);
        }
        let name = match standing {
            Ok(name) => name,
            Err(problem) => return refused(problem.refusal()),
        };
        let outcome = mint(
            &tx,
            hasher,
            &name,
            access_key_types,
            &Mint {
                principal_id: &request.principal_id,
                name: &request.name,
                access_key_types: &request.access_key_types,
                lifetime: &request.lifetime,
                origin: AccessKeyOrigin::Portal,
                created_by: &request.principal_id,
            },
            Utc::now(),
        )?;
        if outcome.is_ok() {
            tx.commit().map_err(sql_unavailable)?;
        }
        Ok(outcome)
    }

    /// Mints a token an administrator issues for a person or a service
    /// account. The token is the owner's: it resolves as them, is in their
    /// own list and stops working by the same rules as one they created.
    /// The owner's account must be one whose keys resolve, as for a
    /// person's own mint and with the same refusals, the owner's access key
    /// type setting must allow every requested access key type, and the
    /// lifetime must be offered by every one of them. Whether people may
    /// create a type themselves does not matter here, and no browser
    /// session of the owner is needed.
    pub fn mint_administrator_access_key(
        &self,
        hasher: &BrokerTokenHasher,
        access_key_types: &AccessKeyTypes,
        request: &AdministratorAccessKeyRequest,
    ) -> Result<Result<IssuedAccessKey, AccessKeyRefused>, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_actor(&request.created_by)?;
        validate_mint_request(&request.name, &request.access_key_types, &request.lifetime)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let owner =
            owner(&tx, &request.principal_id)?.ok_or(ManagedStoreError::PrincipalNotFound)?;
        let refused = |refusal| Ok(Err(AccessKeyRefused::new(refusal)));
        if !matches!(owner.kind.as_str(), "user" | "service_account") {
            return refused(AccessKeyRefusal::OwnerKind);
        }
        // A key issued for an account whose keys do not resolve would not
        // work: the same refusal as the person's own mint, for every such
        // state of the account.
        let name = match account_standing(&tx, &policy, &owner, &request.principal_id)? {
            Ok(name) => name,
            Err(problem) => return refused(problem.refusal()),
        };
        let outcome = mint(
            &tx,
            hasher,
            &name,
            access_key_types,
            &Mint {
                principal_id: &request.principal_id,
                name: &request.name,
                access_key_types: &request.access_key_types,
                lifetime: &request.lifetime,
                origin: AccessKeyOrigin::Administrator,
                created_by: &request.created_by,
            },
            Utc::now(),
        )?;
        if outcome.is_ok() {
            tx.commit().map_err(sql_unavailable)?;
        }
        Ok(outcome)
    }

    /// The tokens `filter` selects, newest first, each with what it would
    /// resolve as now under `access_key_types`. A revoked token is listed only
    /// when the filter asks for revoked tokens, and an expired token that
    /// was never revoked only when it asks for expired ones.
    pub fn list_access_key_views(
        &self,
        access_key_types: &AccessKeyTypes,
        filter: &AccessKeyListFilter,
    ) -> Result<Vec<AccessKeyView>, ManagedStoreError> {
        self.list_access_key_views_at(access_key_types, filter, Utc::now())
    }

    pub(crate) fn list_access_key_views_at(
        &self,
        access_key_types: &AccessKeyTypes,
        filter: &AccessKeyListFilter,
        now: DateTime<Utc>,
    ) -> Result<Vec<AccessKeyView>, ManagedStoreError> {
        if let Some(principal_id) = &filter.principal_id {
            validate_principal_id(principal_id)?;
        }
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        if let Some(principal_id) = &filter.principal_id
            && owner(&tx, principal_id)?.is_none()
        {
            return Err(ManagedStoreError::PrincipalNotFound);
        }
        // A revoked token is selected only on request; an expired one that
        // was never revoked likewise. Neither is evaluated otherwise.
        let records = tokens_where(
            &tx,
            "(?1 IS NULL OR principal_id = ?1)
             AND ((revoked_at IS NOT NULL AND ?2)
               OR (revoked_at IS NULL AND (?3 OR expires_at IS NULL OR expires_at > ?4)))",
            &[
                &filter.principal_id,
                &filter.include_revoked,
                &filter.include_expired,
                &normalized_timestamp(now),
            ],
        )?;
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            let (status, usable_access_key_types) =
                match evaluate(&tx, &policy, access_key_types, &record, now)? {
                    AccessKeyResolution::Active(facts) => {
                        (AccessKeyStatus::Active, facts.access_key_types)
                    }
                    AccessKeyResolution::Inactive(inactive) => {
                        (AccessKeyStatus::Inactive(inactive.reason), Vec::new())
                    }
                };
            // The same per-type decision the evaluation above made, for
            // every type the key carries and whatever the key's own state.
            let access_key_type_states = carried_types(&tx, access_key_types, &record)?
                .into_iter()
                .map(|carried| AccessKeyTypeState {
                    id: carried.id.to_string(),
                    display_name: carried
                        .configured
                        .map(|access_key_type| access_key_type.display_name.clone()),
                    held: carried.held_at(now),
                })
                .collect();
            let access = match status {
                AccessKeyStatus::Inactive(_) => AccessKeyAccess::None,
                AccessKeyStatus::Active
                    if usable_access_key_types.len() == record.access_key_types.len() =>
                {
                    AccessKeyAccess::Full
                }
                AccessKeyStatus::Active => AccessKeyAccess::Partial,
            };
            views.push(AccessKeyView {
                record,
                status,
                usable_access_key_types,
                access_key_type_states,
                access,
            });
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(views)
    }

    /// What the person `principal_id` may hold and create for themselves
    /// now: their name, why no token can be created when none can, and the
    /// access key types their access key type setting allows, each saying whether
    /// people may create it themselves. A mint decides again in its own
    /// transaction.
    pub fn portal_access_key_options(
        &self,
        access_key_types: &AccessKeyTypes,
        principal_id: &str,
    ) -> Result<AccessKeyOptions, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let owner = owner(&tx, principal_id)?.ok_or(ManagedStoreError::PrincipalNotFound)?;
        let account_username = matches!(owner.kind.as_str(), "user" | "service_account")
            .then(|| account_usernames::principal_account_username(&tx, &policy, principal_id))
            .transpose()?;
        // Why a request of the person's own is refused whatever it asks
        // for: the decision a mint makes.
        let standing = if owner.kind == "user" {
            account_standing(&tx, &policy, &owner, principal_id)?.err()
        } else {
            None
        };
        let refusal = if owner.kind != "user" {
            Some(AccessKeyRefusal::OwnerKind)
        } else {
            standing.map(AccountProblem::refusal)
        };
        let access = access_key_types::policy_at_conn(&tx, access_key_types, principal_id)?;
        let held: Vec<crate::AccessKeyType> = access_key_types
            .iter()
            .filter(|access_key_type| access.allows(&access_key_type.id))
            .cloned()
            .collect();
        let has_keys: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM access_keys WHERE principal_id = ?1)",
                [principal_id],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        // What keeps every key of the person's from resolving and only an
        // administrator can remove, in the order a resolution finds it. A
        // resolution finds a disabled or paused account before either, and
        // `refusal` names that; and a person who can create no key and owns
        // none has nothing the problem could stop.
        let stops_something = has_keys || held.iter().any(|held| held.self_service);
        let problem = standing
            .filter(|problem| stops_something && !problem.precedes_name())
            .map(AccountProblem::reason);
        tx.commit().map_err(sql_unavailable)?;
        Ok(AccessKeyOptions {
            account_username,
            refusal,
            access_key_types: held,
            has_keys,
            problem,
        })
    }

    /// Why no access key of the person or service account `principal_id`
    /// can resolve now, when the cause is in the account and not in a key:
    /// the account is disabled, a person's identity access is paused, the
    /// account has no usable username, or it is in more local groups than
    /// a resolution returns. The reason is the status every key of the
    /// account lists, found in the order a resolution finds it; `None`
    /// when nothing in the account stands in the way, and for a principal
    /// that is neither a person nor a service account.
    pub fn access_key_account_problem(
        &self,
        principal_id: &str,
    ) -> Result<Option<AccessKeyInactiveReason>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let owner = owner(&tx, principal_id)?.ok_or(ManagedStoreError::PrincipalNotFound)?;
        let problem = if matches!(owner.kind.as_str(), "user" | "service_account") {
            account_standing(&tx, &policy, &owner, principal_id)?
                .err()
                .map(AccountProblem::reason)
        } else {
            None
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(problem)
    }

    /// The token `key_id` names, or `None`.
    pub fn access_key(&self, key_id: &str) -> Result<Option<AccessKeyRecord>, ManagedStoreError> {
        if !is_access_key_id(key_id) {
            return Ok(None);
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let record = token_by(&tx, "key_id", key_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    /// Revokes the token `key_id` names; `owner`, when given, must own it.
    /// Returns `None` when there is no such token. Revocation is final: a
    /// second request writes nothing.
    pub fn revoke_access_key(
        &self,
        key_id: &str,
        owner: Option<&str>,
        actor: &str,
    ) -> Result<Option<AccessKeyRevocation>, ManagedStoreError> {
        validate_actor(actor)?;
        if let Some(owner) = owner {
            validate_principal_id(owner)?;
        }
        if !is_access_key_id(key_id) {
            return Ok(None);
        }
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let Some(before) = token_by(&tx, "key_id", key_id)?
            .filter(|record| owner.is_none_or(|owner| record.principal_id == owner))
        else {
            return Ok(None);
        };
        if before.revoked_at.is_some() {
            return Ok(Some(AccessKeyRevocation {
                record: before,
                newly_revoked: false,
            }));
        }
        tx.execute(
            "UPDATE access_keys SET revoked_at = ?2, revoked_by = ?3
             WHERE key_id = ?1 AND revoked_at IS NULL",
            params![key_id, now, actor],
        )
        .map_err(sql_unavailable)?;
        let record = token_by(&tx, "key_id", key_id)?.ok_or_else(invalid_row)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(Some(AccessKeyRevocation {
            record,
            newly_revoked: true,
        }))
    }

    /// Whose access key `raw_token` is: the facts of an active token under
    /// the current principal, name, local groups and `access_key_types`, or that
    /// it is not active, with current owner and reason for a stored key. Read-only apart from the
    /// token's last-used time, written at most once every five minutes; a
    /// failed write does not fail the resolution.
    pub fn resolve_access_key(
        &self,
        hasher: &BrokerTokenHasher,
        access_key_types: &AccessKeyTypes,
        raw_token: &str,
    ) -> Result<AccessKeyResolution, ManagedStoreError> {
        self.resolve_access_key_at(hasher, access_key_types, raw_token, Utc::now())
    }

    pub(crate) fn resolve_access_key_at(
        &self,
        hasher: &BrokerTokenHasher,
        access_key_types: &AccessKeyTypes,
        raw_token: &str,
        now: DateTime<Utc>,
    ) -> Result<AccessKeyResolution, ManagedStoreError> {
        if !is_access_key(raw_token) {
            return Ok(AccessKeyResolution::Inactive(AccessKeyInactive::unmatched(
                AccessKeyInactiveReason::Malformed,
            )));
        }
        let key_hash = hasher.hash(raw_token)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let (resolution, last_used_at) = {
            let tx = conn.transaction().map_err(sql_unavailable)?;
            let Some(record) = token_by(&tx, "key_hash", &key_hash)? else {
                return Ok(AccessKeyResolution::Inactive(AccessKeyInactive::unmatched(
                    AccessKeyInactiveReason::Unknown,
                )));
            };
            let resolution = evaluate(&tx, &policy, access_key_types, &record, now)?;
            tx.commit().map_err(sql_unavailable)?;
            (resolution, record.last_used_at)
        };
        if let AccessKeyResolution::Active(facts) = &resolution {
            let interval = Duration::seconds(ACCESS_KEY_LAST_USED_INTERVAL_SECONDS);
            let due = last_used_at
                .as_deref()
                .is_none_or(|last| stored_time(last).map_or(true, |last| last + interval <= now));
            if due
                && let Err(error) = conn.execute(
                    "UPDATE access_keys SET last_used_at = ?2
                     WHERE key_id = ?1 AND (last_used_at IS NULL OR last_used_at <= ?3)",
                    params![
                        facts.key_id,
                        normalized_timestamp(now),
                        normalized_timestamp(now - interval)
                    ],
                )
            {
                // The answer does not depend on this write.
                tracing::warn!(
                    event = "access_key_last_used_write_failed",
                    keyId = facts.key_id.as_str(),
                    error = %error,
                    "an access key's last-used time was not recorded"
                );
            }
        }
        Ok(resolution)
    }

    /// What `key_id` would resolve as now, without recording a use; `None`
    /// when there is no such token.
    pub fn access_key_resolution(
        &self,
        access_key_types: &AccessKeyTypes,
        key_id: &str,
    ) -> Result<Option<AccessKeyResolution>, ManagedStoreError> {
        if !is_access_key_id(key_id) {
            return Ok(None);
        }
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let resolution = token_by(&tx, "key_id", key_id)?
            .map(|record| evaluate(&tx, &policy, access_key_types, &record, Utc::now()))
            .transpose()?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(resolution)
    }
}

/// Row invariants the schema cannot state: every token carries at least one
/// access key type and has a stored origin this store reads.
pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let invalid: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM access_keys t WHERE NOT EXISTS
               (SELECT 1 FROM access_key_type_links e WHERE e.key_id = t.key_id))",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if invalid {
        return Err(invalid_row());
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
    imported_store::validate_structure_through(conn, MANAGED_STORE_ACCESS_KEYS_VERSION)?;
    agent_token_issuance::validate_context_rows(conn)?;
    imported_gateway_routes::check_rows(conn)?;
    microsoft_enrollments::check_rows(conn)?;
    application_access::check_rows(conn)?;
    account_usernames::check_rows(conn)?;
    check_rows(conn)
}

#[cfg(test)]
#[path = "access_keys_tests.rs"]
mod tests;
