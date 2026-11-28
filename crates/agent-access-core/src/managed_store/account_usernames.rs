//! Usernames: the ID a person or a service account is known by to the
//! services that resolve their access keys. A person's name either follows
//! their profile email (`from_email`, the default) or is set by an
//! administrator (`manual`); a service account's is its principal ID.
//!
//! The name is stored, never computed at lookup. The store keeps it in step
//! itself, in the transaction that changes an input: account creation, an
//! administrator's change of the account's email or mode, a sign-in of a
//! person who holds none, and the fill of missing names after startup and
//! reload. The profile email only names the account it is stored on: it
//! never finds or merges accounts.
use super::*;
use crate::{AccountUsernameCandidateError, AccountUsernamePolicy, is_valid_account_username};

/// Recorded as the assigner of a name derived when its person signed in.
const SIGN_IN_ACTOR: &str = "system:sign_in";
/// The most accounts one batch of the startup and reload fill examines,
/// whether or not it can name them.
pub const ACCOUNT_USERNAME_FILL_BATCH_SIZE: usize = 200;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameHolderKind {
    User,
    ServiceAccount,
}

impl AccountUsernameHolderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
        }
    }

    fn from_stored(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            _ => None,
        }
    }
}

/// How a name was allocated.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameOrigin {
    /// Derived from the account's profile email.
    Derived,
    /// Set by an administrator.
    Administrator,
    /// A service account's principal ID.
    ServiceAccount,
}

impl AccountUsernameOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Administrator => "administrator",
            Self::ServiceAccount => "service_account",
        }
    }

    fn from_stored(value: &str) -> Option<Self> {
        match value {
            "derived" => Some(Self::Derived),
            "administrator" => Some(Self::Administrator),
            "service_account" => Some(Self::ServiceAccount),
            _ => None,
        }
    }
}

/// Whether a held name can be used, under the store's current username
/// settings. Only a usable name mints or resolves access keys.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameState {
    Usable,
    /// The name is an ID that services already use for a person and no
    /// administrator has confirmed that this account is that person.
    AwaitingConfirmation,
    /// The operator reserved the name: after it was allocated to a person,
    /// or, for a service account, on either of the operator's lists.
    Reserved,
}

impl AccountUsernameState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::AwaitingConfirmation => "awaiting_confirmation",
            Self::Reserved => "reserved",
        }
    }
}

/// One allocation of a username. Every allocation has its own incarnation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsernameRecord {
    pub principal_id: String,
    pub account_username: String,
    pub holder_kind: AccountUsernameHolderKind,
    pub incarnation: String,
    pub origin: AccountUsernameOrigin,
    pub assigned_at: String,
    pub assigned_by: String,
    pub confirmed_at: Option<String>,
    pub confirmed_by: Option<String>,
    pub state: AccountUsernameState,
}

impl AccountUsernameRecord {
    pub fn is_usable(&self) -> bool {
        self.state == AccountUsernameState::Usable
    }

    /// The allowlisted facts an audit record keeps about this allocation.
    pub fn audit_details(&self) -> Value {
        serde_json::json!({
            "accountUsername": self.account_username,
            "usernameIncarnation": self.incarnation,
            "origin": self.origin,
            "state": self.state,
        })
    }
}

/// How a person's name is decided.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameMode {
    /// The lower-cased local part of the profile email, while the email's
    /// domain is listed. The name follows the email.
    FromEmail,
    /// What an administrator set, until an administrator changes it. No
    /// value means the person has no name.
    Manual,
}

impl AccountUsernameMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FromEmail => "from_email",
            Self::Manual => "manual",
        }
    }

    fn from_stored(value: &str) -> Option<Self> {
        match value {
            "from_email" => Some(Self::FromEmail),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// Where an account's name stands now, under the store's current settings.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAccountUsernameState {
    Usable,
    /// The held name awaits an administrator's confirmation.
    AwaitingConfirmation,
    /// The operator reserved the held name.
    Reserved,
    /// The person holds no name because another principal holds the one
    /// their email derives.
    Conflict,
    /// The account holds no name; the reason says why.
    None,
}

impl From<AccountUsernameState> for PrincipalAccountUsernameState {
    fn from(state: AccountUsernameState) -> Self {
        match state {
            AccountUsernameState::Usable => Self::Usable,
            AccountUsernameState::AwaitingConfirmation => Self::AwaitingConfirmation,
            AccountUsernameState::Reserved => Self::Reserved,
        }
    }
}

/// Why an account holds no name.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameReason {
    NoEmail,
    /// The profile email is not one address with a local part and a domain.
    EmailUnusable,
    DomainNotListed,
    /// The lower-cased local part is not a valid username.
    NameInvalid,
    /// The operator reserved the name the email derives.
    NameReserved,
    /// Another person holds the name the email derives, or it is a service
    /// account's ID. The holder keeps it.
    NameTaken,
    /// The account is in manual mode and an administrator set no name.
    NotSet,
    /// The email derives a free name that is not allocated yet: it is at
    /// the person's next sign-in or the next startup or reload.
    NotYetAssigned,
    /// A service account whose principal ID is not a valid username.
    IdUnusable,
}

impl AccountUsernameReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEmail => "no_email",
            Self::EmailUnusable => "email_unusable",
            Self::DomainNotListed => "domain_not_listed",
            Self::NameInvalid => "name_invalid",
            Self::NameReserved => "name_reserved",
            Self::NameTaken => "name_taken",
            Self::NotSet => "not_set",
            Self::NotYetAssigned => "not_yet_assigned",
            Self::IdUnusable => "id_unusable",
        }
    }
}

impl From<AccountUsernameCandidateError> for AccountUsernameReason {
    fn from(error: AccountUsernameCandidateError) -> Self {
        match error {
            AccountUsernameCandidateError::NoEmail => Self::NoEmail,
            AccountUsernameCandidateError::EmailUnusable => Self::EmailUnusable,
            AccountUsernameCandidateError::DomainNotListed => Self::DomainNotListed,
            AccountUsernameCandidateError::NameInvalid => Self::NameInvalid,
        }
    }
}

/// The name a person's email derives, when another principal holds it. The
/// holder keeps it: an administrator sets another name for this person, or
/// changes the holder's.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsernameConflict {
    pub account_username: String,
    /// The person who holds the name, or the service account whose ID it is.
    pub held_by: String,
}

/// What following the email gives a person for the email saved on their
/// account now: the name, or why there is none.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsernameFromEmail {
    /// The name the saved email gives the person. It is the name a person
    /// who follows their email holds or is about to be given, and the name
    /// a person whose name is set by hand would hold on switching.
    pub account_username: Option<String>,
    /// Why the saved email gives no name; `None` when it gives one.
    pub reason: Option<AccountUsernameReason>,
    /// The name the email derives and who holds it, when it is taken.
    pub conflict: Option<AccountUsernameConflict>,
}

/// The username of one person or service account: how it is decided, the
/// name held and where it stands.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalAccountUsername {
    pub principal_id: String,
    pub holder_kind: AccountUsernameHolderKind,
    /// The account's profile, for a listing an administrator reads.
    pub display_name: Option<String>,
    pub email: Option<String>,
    /// `None` for a service account, whose name is its principal ID.
    pub mode: Option<AccountUsernameMode>,
    pub state: PrincipalAccountUsernameState,
    /// Why the account holds no name; `None` while it holds one.
    pub reason: Option<AccountUsernameReason>,
    /// The allocation held, with how it was allocated (`origin`).
    pub name: Option<AccountUsernameRecord>,
    /// Who holds the name the email derives, for the `conflict` state.
    pub conflict: Option<AccountUsernameConflict>,
    /// What following the email gives the person for their saved email;
    /// `None` for a service account.
    pub from_email: Option<AccountUsernameFromEmail>,
    /// The account's unexpired, unrevoked access keys minted under the name
    /// held: the keys that stop resolving when the name changes or is
    /// released. Zero while no name is held.
    pub live_keys: u64,
}

/// What an administrator asks a person's name to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountUsernameSetting {
    /// Follow the profile email, deriving at once.
    FromEmail,
    /// Stop following the email and keep the name held now, if any.
    Manual,
    /// Stop following the email and hold this name.
    ManualName(String),
    /// Stop following the email and hold no name.
    ManualNone,
}

/// A change to a person's name or mode, read in its transaction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsernameChange {
    pub principal_id: String,
    /// The mode before the change; the view carries the mode after it.
    pub previous_mode: AccountUsernameMode,
    pub before: Option<AccountUsernameRecord>,
    pub after: Option<AccountUsernameRecord>,
    /// Unexpired, unrevoked access keys of the previous incarnation, which
    /// no longer resolve.
    pub ended_keys: u64,
    /// The account as the change's transaction left it.
    pub view: PrincipalAccountUsername,
}

impl AccountUsernameChange {
    /// Whether the change wrote anything.
    pub fn changed(&self) -> bool {
        self.before != self.after || Some(self.previous_mode) != self.view.mode
    }

    /// Whether the name itself changed: another name, or none.
    pub fn renamed(&self) -> bool {
        self.before.as_ref().map(|name| &name.incarnation)
            != self.after.as_ref().map(|name| &name.incarnation)
    }

    /// The allowlisted facts an audit record keeps about this change.
    pub fn audit_details(&self) -> Value {
        serde_json::json!({
            "principal": self.principal_id,
            "previousMode": self.previous_mode,
            "mode": self.view.mode,
            "before": self.before.as_ref().map(AccountUsernameRecord::audit_details),
            "after": self.after.as_ref().map(AccountUsernameRecord::audit_details),
            "endedKeys": self.ended_keys,
        })
    }

    /// What the operation did to the person's name, as its response reports
    /// it: the mode and the name before and after, whether the name held is
    /// another allocation or none, how many live access keys that ended,
    /// and why there is no name when there is none.
    pub fn outcome(&self) -> Value {
        serde_json::json!({
            "previousMode": self.previous_mode,
            "mode": self.view.mode,
            "before": self.before,
            "after": self.after,
            "renamed": self.renamed(),
            "endedKeys": self.ended_keys,
            "reason": self.view.reason,
            "conflict": self.view.conflict,
        })
    }
}

/// Why a username operation changed nothing.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountUsernameRefusal {
    /// Only a person's name is set or confirmed.
    NotHuman,
    /// Not 1 to 256 bytes of letters, digits and `._@+-`, or `anonymous`.
    NameInvalid,
    /// The operator reserved the name.
    NameReserved,
    /// Another person holds the name, or it is a service account's ID. The
    /// holder keeps it until an administrator changes it there.
    NameTaken,
    /// The account holds no name.
    NoName,
    /// The account no longer holds the name the request named.
    NameChanged,
    /// The name is not one the operator listed as needing confirmation.
    ConfirmationNotRequired,
}

impl AccountUsernameRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotHuman => "not_human",
            Self::NameInvalid => "name_invalid",
            Self::NameReserved => "name_reserved",
            Self::NameTaken => "name_taken",
            Self::NoName => "no_name",
            Self::NameChanged => "name_changed",
            Self::ConfirmationNotRequired => "confirmation_not_required",
        }
    }

    /// The reason code a management response reports for this refusal.
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::NameInvalid => ReasonCode::InputInvalid,
            Self::NameTaken | Self::NameChanged => ReasonCode::BrokerAccountUsernameConflict,
            Self::NoName => ReasonCode::BrokerAccountUsernameNotFound,
            Self::NotHuman | Self::NameReserved | Self::ConfirmationNotRequired => {
                ReasonCode::BrokerAccountUsernameDenied
            }
        }
    }

    /// What a person reading the refusal is told.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotHuman => "only a person's username can be changed",
            Self::NameInvalid => {
                "a username is 1 to 256 letters, digits and ._@+- and is not anonymous"
            }
            Self::NameReserved => "the username is reserved by the operator",
            Self::NameTaken => {
                "the username is held by another account or is a service account's ID; change it there first"
            }
            Self::NoName => "the account holds no username",
            Self::NameChanged => "the account no longer holds the username the request named",
            Self::ConfirmationNotRequired => {
                "the username is not on the operator's list of names that need confirmation"
            }
        }
    }
}

/// A refused username operation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsernameRefused {
    pub refusal: AccountUsernameRefusal,
}

impl AccountUsernameRefused {
    pub const fn message(&self) -> &'static str {
        self.refusal.message()
    }
}

impl From<AccountUsernameRefusal> for AccountUsernameRefused {
    fn from(refusal: AccountUsernameRefusal) -> Self {
        Self { refusal }
    }
}

/// One batch of the fill that names the `from_email` people who hold no
/// name. A batch is one transaction and examines a bounded number of
/// accounts, whether or not it can name them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUsernameFillBatch {
    /// The accounts this batch looked at.
    pub examined: usize,
    /// The names it allocated.
    pub assigned: Vec<AccountUsernameRecord>,
    /// The principal ID to continue after, when the batch was full and
    /// accounts may remain; `None` when the fill is complete.
    pub next: Option<String>,
}

fn new_incarnation() -> String {
    Uuid::new_v4().simple().to_string()
}

fn invalid_row() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("username is invalid".into())
}

fn state_of(
    policy: &AccountUsernamePolicy,
    kind: AccountUsernameHolderKind,
    name: &str,
    confirmed: bool,
) -> AccountUsernameState {
    match kind {
        // Both of the operator's lists reserve a name against a service
        // account: one is never assigned, the other belongs to a person, so
        // no confirmation can make it a service account's.
        AccountUsernameHolderKind::ServiceAccount
            if policy.is_reserved(name) || policy.requires_confirmation(name) =>
        {
            AccountUsernameState::Reserved
        }
        AccountUsernameHolderKind::ServiceAccount => AccountUsernameState::Usable,
        AccountUsernameHolderKind::User if policy.is_reserved(name) => {
            AccountUsernameState::Reserved
        }
        AccountUsernameHolderKind::User if policy.requires_confirmation(name) && !confirmed => {
            AccountUsernameState::AwaitingConfirmation
        }
        AccountUsernameHolderKind::User => AccountUsernameState::Usable,
    }
}

const NAME_COLUMNS: &str = "principal_id, account_username, holder_kind, incarnation, origin, \
     assigned_at, assigned_by, confirmed_at, confirmed_by";

fn record_from_row(
    policy: &AccountUsernamePolicy,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<AccountUsernameRecord, ManagedStoreError>> {
    let account_username: String = row.get(1)?;
    let holder_kind: String = row.get(2)?;
    let origin: String = row.get(4)?;
    let confirmed_at: Option<String> = row.get(7)?;
    let (Some(holder_kind), Some(origin)) = (
        AccountUsernameHolderKind::from_stored(&holder_kind),
        AccountUsernameOrigin::from_stored(&origin),
    ) else {
        return Ok(Err(invalid_row()));
    };
    Ok(Ok(AccountUsernameRecord {
        principal_id: row.get(0)?,
        state: state_of(
            policy,
            holder_kind,
            &account_username,
            confirmed_at.is_some(),
        ),
        account_username,
        holder_kind,
        incarnation: row.get(3)?,
        origin,
        assigned_at: row.get(5)?,
        assigned_by: row.get(6)?,
        confirmed_at,
        confirmed_by: row.get(8)?,
    }))
}

/// The name `principal_id` holds, with its state under `policy`.
pub(super) fn name_of(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
) -> Result<Option<AccountUsernameRecord>, ManagedStoreError> {
    conn.query_row(
        &format!("SELECT {NAME_COLUMNS} FROM account_usernames WHERE principal_id = ?1"),
        [principal_id],
        |row| record_from_row(policy, row),
    )
    .optional()
    .map_err(sql_unavailable)?
    .transpose()
}

/// Whether `name` is unavailable to a person: another principal holds it, or
/// it is a service account's ID.
fn name_is_held(conn: &Connection, name: &str) -> Result<bool, ManagedStoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_usernames WHERE account_username = ?1)
             OR EXISTS(SELECT 1 FROM principals
                  WHERE principal_id = ?1 AND kind = 'service_account')",
        [name],
        |row| row.get(0),
    )
    .map_err(sql_unavailable)
}

/// Refuses a service-account ID that a person holds as a username, which
/// the store's triggers refuse too, or that the operator reserved: a name
/// never to be assigned, or an ID that services already use for a person.
pub(super) fn require_service_account_id_free(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
) -> Result<(), ManagedStoreError> {
    if !is_valid_account_username(principal_id) {
        return Err(input_invalid(
            "principal ID must be a valid service-account username",
        ));
    }
    if policy.is_reserved(principal_id) || policy.requires_confirmation(principal_id) {
        return Err(input_invalid(
            "principal ID is a reserved username; choose another ID for the service account",
        ));
    }
    let held: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM account_usernames
               WHERE account_username = ?1 AND principal_id <> ?1)",
            [principal_id],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if held {
        return Err(input_invalid(
            "principal ID is held as a person's username; release the name or choose another ID",
        ));
    }
    Ok(())
}

fn live_tokens_of_incarnation(
    conn: &Connection,
    principal_id: &str,
    incarnation: &str,
    now: &str,
) -> Result<u64, ManagedStoreError> {
    conn.query_row(
        "SELECT COUNT(1) FROM access_keys
         WHERE principal_id = ?1 AND username_incarnation = ?2 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?3)",
        params![principal_id, incarnation, now],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count.max(0) as u64)
    .map_err(sql_unavailable)
}

struct Person {
    kind: String,
    display_name: Option<String>,
    email: Option<String>,
    mode: AccountUsernameMode,
}

fn person(conn: &Connection, principal_id: &str) -> Result<Person, ManagedStoreError> {
    let (kind, display_name, email, mode): (String, Option<String>, Option<String>, String) = conn
        .query_row(
            "SELECT kind, display_name, email, account_username_mode
             FROM principals WHERE principal_id = ?1",
            [principal_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::PrincipalNotFound)?;
    Ok(Person {
        kind,
        display_name,
        email,
        mode: AccountUsernameMode::from_stored(&mode).ok_or_else(invalid_row)?,
    })
}

fn insert_name(
    conn: &Connection,
    principal_id: &str,
    name: &str,
    origin: AccountUsernameOrigin,
    actor: &str,
    now: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "INSERT INTO account_usernames
         (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
         VALUES (?1, ?2, 'user', ?3, ?4, ?5, ?6)",
        params![
            name,
            principal_id,
            new_incarnation(),
            origin.as_str(),
            now,
            actor
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Takes the name `before` from its person and reports how many live access
/// keys of that incarnation stop resolving.
fn remove_name(
    conn: &Connection,
    before: &AccountUsernameRecord,
    now: &str,
) -> Result<u64, ManagedStoreError> {
    let ended = live_tokens_of_incarnation(conn, &before.principal_id, &before.incarnation, now)?;
    conn.execute(
        "DELETE FROM account_usernames WHERE principal_id = ?1",
        [&before.principal_id],
    )
    .map_err(sql_unavailable)?;
    Ok(ended)
}

/// The principal that keeps `name` from `principal_id`: the person who holds
/// it, or the service account whose ID it is.
fn holder_of(
    conn: &Connection,
    name: &str,
    principal_id: &str,
) -> Result<Option<String>, ManagedStoreError> {
    conn.query_row(
        "SELECT principal_id FROM account_usernames WHERE account_username = ?1 AND principal_id <> ?2
         UNION ALL
         SELECT principal_id FROM principals
          WHERE principal_id = ?1 AND kind = 'service_account' AND principal_id <> ?2
         LIMIT 1",
        params![name, principal_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_unavailable)
}

/// Why an email derives no name for its person, with the holder of a name
/// that is taken.
type NotDerivable = (AccountUsernameReason, Option<AccountUsernameConflict>);

/// The name `email` gives the person `principal_id` under `policy` now, or
/// why it gives none. The first holder keeps a name: one that another
/// principal holds is never given to a second.
fn derivable(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
    email: Option<&str>,
) -> Result<Result<String, NotDerivable>, ManagedStoreError> {
    let name = match policy.candidate(email) {
        Ok(name) => name,
        Err(error) => return Ok(Err((error.into(), None))),
    };
    if policy.is_reserved(&name) {
        return Ok(Err((AccountUsernameReason::NameReserved, None)));
    }
    Ok(match holder_of(conn, &name, principal_id)? {
        Some(held_by) => Err((
            AccountUsernameReason::NameTaken,
            Some(AccountUsernameConflict {
                account_username: name,
                held_by,
            }),
        )),
        None => Ok(name),
    })
}

/// What bringing a name in step did.
struct Synced {
    before: Option<AccountUsernameRecord>,
    after: Option<AccountUsernameRecord>,
    ended_keys: u64,
}

/// Brings the stored name of a `from_email` person in step with their email:
/// the name the email derives now, or none. A name that is already the one
/// derived stays as it is, incarnation included; any other is released, and
/// the derived one allocated when it is free.
fn sync_with_email(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
    email: Option<&str>,
    actor: &str,
    now: &str,
) -> Result<Synced, ManagedStoreError> {
    let before = name_of(conn, policy, principal_id)?;
    let derived = derivable(conn, policy, principal_id, email)?.ok();
    if before.as_ref().map(|name| &name.account_username) == derived.as_ref() {
        return Ok(Synced {
            after: before.clone(),
            before,
            ended_keys: 0,
        });
    }
    let ended_keys = match &before {
        Some(before) => remove_name(conn, before, now)?,
        None => 0,
    };
    if let Some(name) = &derived {
        insert_name(
            conn,
            principal_id,
            name,
            AccountUsernameOrigin::Derived,
            actor,
            now,
        )?;
    }
    Ok(Synced {
        before,
        after: name_of(conn, policy, principal_id)?,
        ended_keys,
    })
}

/// Allocates the name a `from_email` person's email derives when they hold
/// none. It never touches a name that is held. Returns the allocation, when
/// one was made.
fn fill_missing(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
    actor: &str,
    now: &str,
) -> Result<Option<AccountUsernameRecord>, ManagedStoreError> {
    let person = person(conn, principal_id)?;
    if person.kind != "user"
        || person.mode != AccountUsernameMode::FromEmail
        || name_of(conn, policy, principal_id)?.is_some()
    {
        return Ok(None);
    }
    let Ok(name) = derivable(conn, policy, principal_id, person.email.as_deref())? else {
        return Ok(None);
    };
    insert_name(
        conn,
        principal_id,
        &name,
        AccountUsernameOrigin::Derived,
        actor,
        now,
    )?;
    name_of(conn, policy, principal_id)
}

/// The name of a person the caller's transaction just created. Returns the
/// allocation, when one was made.
pub(super) fn derive_on_creation(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
    kind: &str,
    actor: &str,
) -> Result<Option<AccountUsernameRecord>, ManagedStoreError> {
    if kind != "user" {
        return Ok(None);
    }
    fill_missing(conn, policy, principal_id, actor, &normalized_now_string())
}

/// In the transaction of a person's successful sign-in: the name their
/// email derives, when they hold none. Returns the allocation, when one was
/// made.
pub(super) fn derive_on_sign_in(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
) -> Result<Option<AccountUsernameRecord>, ManagedStoreError> {
    fill_missing(
        conn,
        policy,
        principal_id,
        SIGN_IN_ACTOR,
        &normalized_now_string(),
    )
}

/// In the transaction that changed the profile email of `principal_id`:
/// a `from_email` person is renamed to what the new email derives, or left
/// without a name when it derives none, and a `manual` person keeps what
/// they hold. Returns what that did to the person's name, which is nothing
/// for a `manual` person, or `None` for an account that is not a person.
pub(super) fn sync_after_email_change(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
    actor: &str,
) -> Result<Option<AccountUsernameChange>, ManagedStoreError> {
    let person = person(conn, principal_id)?;
    if person.kind != "user" {
        return Ok(None);
    }
    let synced = match person.mode {
        AccountUsernameMode::FromEmail => sync_with_email(
            conn,
            policy,
            principal_id,
            person.email.as_deref(),
            actor,
            &normalized_now_string(),
        )?,
        AccountUsernameMode::Manual => {
            let before = name_of(conn, policy, principal_id)?;
            Synced {
                after: before.clone(),
                before,
                ended_keys: 0,
            }
        }
    };
    Ok(Some(AccountUsernameChange {
        principal_id: principal_id.to_string(),
        previous_mode: person.mode,
        before: synced.before,
        after: synced.after,
        ended_keys: synced.ended_keys,
        view: principal_account_username(conn, policy, principal_id)?,
    }))
}

/// The name of the person or service account `principal_id` as it stands.
pub(super) fn principal_account_username(
    conn: &Connection,
    policy: &AccountUsernamePolicy,
    principal_id: &str,
) -> Result<PrincipalAccountUsername, ManagedStoreError> {
    let person = person(conn, principal_id)?;
    let holder_kind = AccountUsernameHolderKind::from_stored(&person.kind)
        .ok_or_else(|| input_invalid("only people and service accounts have usernames"))?;
    let name = name_of(conn, policy, principal_id)?;
    let is_person = holder_kind == AccountUsernameHolderKind::User;
    // What following the saved email gives a person now, whatever their
    // mode and whatever they hold.
    let from_email = if is_person {
        Some(
            match derivable(conn, policy, principal_id, person.email.as_deref())? {
                Ok(account_username) => AccountUsernameFromEmail {
                    account_username: Some(account_username),
                    reason: None,
                    conflict: None,
                },
                Err((reason, conflict)) => AccountUsernameFromEmail {
                    account_username: None,
                    reason: Some(reason),
                    conflict,
                },
            },
        )
    } else {
        None
    };
    let (state, reason, conflict) = match (&name, &from_email) {
        (Some(name), _) => (name.state.into(), None, None),
        (None, None) => (
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::IdUnusable),
            None,
        ),
        (None, Some(_)) if person.mode == AccountUsernameMode::Manual => (
            PrincipalAccountUsernameState::None,
            Some(AccountUsernameReason::NotSet),
            None,
        ),
        // What the email derives now, for a person who follows it.
        (None, Some(from_email)) => match from_email.reason {
            None => (
                PrincipalAccountUsernameState::None,
                Some(AccountUsernameReason::NotYetAssigned),
                None,
            ),
            Some(AccountUsernameReason::NameTaken) => (
                PrincipalAccountUsernameState::Conflict,
                Some(AccountUsernameReason::NameTaken),
                from_email.conflict.clone(),
            ),
            Some(reason) => (PrincipalAccountUsernameState::None, Some(reason), None),
        },
    };
    let live_keys = match &name {
        Some(name) => live_tokens_of_incarnation(
            conn,
            principal_id,
            &name.incarnation,
            &normalized_now_string(),
        )?,
        None => 0,
    };
    Ok(PrincipalAccountUsername {
        principal_id: principal_id.to_string(),
        holder_kind,
        display_name: person.display_name,
        email: person.email,
        mode: is_person.then_some(person.mode),
        state,
        reason,
        name,
        conflict,
        from_email,
        live_keys,
    })
}

fn set_mode(
    conn: &Connection,
    principal_id: &str,
    mode: AccountUsernameMode,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "UPDATE principals SET account_username_mode = ?2
         WHERE principal_id = ?1 AND account_username_mode <> ?2",
        params![principal_id, mode.as_str()],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

impl ManagedStore {
    /// Installs the username settings of the configuration this store
    /// serves. Without them no email derives a name and no name is reserved
    /// or awaits confirmation.
    pub fn configure_account_usernames(&self, policy: AccountUsernamePolicy) {
        *self.account_username_policy.lock().unwrap() = Arc::new(policy);
    }

    pub(super) fn account_username_policy(&self) -> Arc<AccountUsernamePolicy> {
        Arc::clone(&self.account_username_policy.lock().unwrap())
    }

    /// The username of one person or service account: its mode, the name
    /// held and where it stands.
    pub fn principal_account_username(
        &self,
        principal_id: &str,
    ) -> Result<PrincipalAccountUsername, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let record = principal_account_username(&tx, &policy, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    /// Every person and service account, by principal ID, with the name each
    /// holds: the names awaiting confirmation and the conflicts are read
    /// from here.
    pub fn list_principal_account_usernames(
        &self,
    ) -> Result<Vec<PrincipalAccountUsername>, ManagedStoreError> {
        let policy = self.account_username_policy();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let ids: Vec<String> = {
            let mut statement = tx
                .prepare(
                    "SELECT principal_id FROM principals
                     WHERE kind IN ('user', 'service_account') ORDER BY principal_id",
                )
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map([], |row| row.get(0))
                    .map_err(sql_unavailable)?,
            )?
        };
        let records = ids
            .iter()
            .map(|id| principal_account_username(&tx, &policy, id))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(records)
    }

    /// An administrator sets how a person's name is decided, and with it the
    /// name, in one transaction.
    ///
    /// - `FromEmail`, for a person who was in manual mode, derives at once:
    ///   the person holds what their email derives, or nothing. For a person
    ///   who already follows their email it changes nothing they hold:
    ///   neither their email nor their mode changed, so a name stays even
    ///   when the email would no longer derive it, and only a missing name
    ///   is filled in.
    /// - `Manual` keeps the name held now as the one set by hand.
    /// - `ManualName` holds the given name. A name another principal holds
    ///   is refused, never moved.
    /// - `ManualNone` holds no name.
    ///
    /// A name that stays the same keeps its incarnation; any other change is
    /// a new incarnation or none, under which the person's earlier access
    /// keys no longer resolve.
    pub fn set_account_username_setting(
        &self,
        principal_id: &str,
        setting: &AccountUsernameSetting,
        actor: &str,
    ) -> Result<Result<AccountUsernameChange, AccountUsernameRefusal>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_actor(actor)?;
        if let AccountUsernameSetting::ManualName(name) = setting
            && !is_valid_account_username(name)
        {
            return Ok(Err(AccountUsernameRefusal::NameInvalid));
        }
        let policy = self.account_username_policy();
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let person = person(&tx, principal_id)?;
        if person.kind != "user" {
            return Ok(Err(AccountUsernameRefusal::NotHuman));
        }
        let synced = match setting {
            AccountUsernameSetting::FromEmail if person.mode == AccountUsernameMode::FromEmail => {
                let before = name_of(&tx, &policy, principal_id)?;
                let after = match &before {
                    Some(_) => before.clone(),
                    None => fill_missing(&tx, &policy, principal_id, actor, &now)?,
                };
                Synced {
                    before,
                    after,
                    ended_keys: 0,
                }
            }
            AccountUsernameSetting::FromEmail => {
                set_mode(&tx, principal_id, AccountUsernameMode::FromEmail)?;
                sync_with_email(
                    &tx,
                    &policy,
                    principal_id,
                    person.email.as_deref(),
                    actor,
                    &now,
                )?
            }
            AccountUsernameSetting::Manual => {
                set_mode(&tx, principal_id, AccountUsernameMode::Manual)?;
                let before = name_of(&tx, &policy, principal_id)?;
                Synced {
                    after: before.clone(),
                    before,
                    ended_keys: 0,
                }
            }
            AccountUsernameSetting::ManualNone => {
                set_mode(&tx, principal_id, AccountUsernameMode::Manual)?;
                let before = name_of(&tx, &policy, principal_id)?;
                let ended_keys = match &before {
                    Some(before) => remove_name(&tx, before, &now)?,
                    None => 0,
                };
                Synced {
                    before,
                    after: None,
                    ended_keys,
                }
            }
            AccountUsernameSetting::ManualName(name) => {
                if policy.is_reserved(name) {
                    return Ok(Err(AccountUsernameRefusal::NameReserved));
                }
                let before = name_of(&tx, &policy, principal_id)?;
                if before
                    .as_ref()
                    .is_some_and(|before| before.account_username == *name)
                {
                    set_mode(&tx, principal_id, AccountUsernameMode::Manual)?;
                    Synced {
                        after: before.clone(),
                        before,
                        ended_keys: 0,
                    }
                } else {
                    if name_is_held(&tx, name)? {
                        return Ok(Err(AccountUsernameRefusal::NameTaken));
                    }
                    set_mode(&tx, principal_id, AccountUsernameMode::Manual)?;
                    let ended_keys = match &before {
                        Some(before) => remove_name(&tx, before, &now)?,
                        None => 0,
                    };
                    insert_name(
                        &tx,
                        principal_id,
                        name,
                        AccountUsernameOrigin::Administrator,
                        actor,
                        &now,
                    )?;
                    Synced {
                        before,
                        after: name_of(&tx, &policy, principal_id)?,
                        ended_keys,
                    }
                }
            }
        };
        let view = principal_account_username(&tx, &policy, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(Ok(AccountUsernameChange {
            principal_id: principal_id.to_string(),
            previous_mode: person.mode,
            before: synced.before,
            after: synced.after,
            ended_keys: synced.ended_keys,
            view,
        }))
    }

    /// An administrator sets a person's name by hand: the person stops
    /// following their email and holds `account_username`.
    pub fn set_account_username(
        &self,
        principal_id: &str,
        account_username: &str,
        actor: &str,
    ) -> Result<Result<AccountUsernameChange, AccountUsernameRefusal>, ManagedStoreError> {
        self.set_account_username_setting(
            principal_id,
            &AccountUsernameSetting::ManualName(account_username.to_string()),
            actor,
        )
    }

    /// An administrator confirms that the account is the person already
    /// known by the name `account_username` that it holds. Naming the name keeps a
    /// confirmation from applying to a name allocated after the
    /// administrator looked. A name already confirmed writes nothing, and
    /// confirmation keeps the incarnation.
    pub fn confirm_account_username(
        &self,
        principal_id: &str,
        account_username: &str,
        actor: &str,
    ) -> Result<Result<AccountUsernameChange, AccountUsernameRefusal>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_actor(actor)?;
        if !is_valid_account_username(account_username) {
            return Ok(Err(AccountUsernameRefusal::NameInvalid));
        }
        let policy = self.account_username_policy();
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let person = person(&tx, principal_id)?;
        if person.kind != "user" {
            return Ok(Err(AccountUsernameRefusal::NotHuman));
        }
        let Some(before) = name_of(&tx, &policy, principal_id)? else {
            return Ok(Err(AccountUsernameRefusal::NoName));
        };
        if before.account_username != account_username {
            return Ok(Err(AccountUsernameRefusal::NameChanged));
        }
        if !policy.requires_confirmation(&before.account_username) {
            return Ok(Err(AccountUsernameRefusal::ConfirmationNotRequired));
        }
        if before.confirmed_at.is_none() {
            tx.execute(
                "UPDATE account_usernames SET confirmed_at = ?2, confirmed_by = ?3
                 WHERE principal_id = ?1 AND confirmed_at IS NULL",
                params![principal_id, now, actor],
            )
            .map_err(sql_unavailable)?;
        }
        let view = principal_account_username(&tx, &policy, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(Ok(AccountUsernameChange {
            principal_id: principal_id.to_string(),
            previous_mode: person.mode,
            after: view.name.clone(),
            before: Some(before),
            ended_keys: 0,
            view,
        }))
    }

    /// One batch of the fill that runs after startup and reload: in one
    /// transaction, examines up to `limit` `from_email` people who hold no
    /// name, in principal-ID order after `after`, and allocates the name
    /// each one's email derives when it is free. It moves no name and
    /// changes no account that holds one. Every account examined counts
    /// towards the batch, named or not, so a population nobody in which can
    /// be named is still walked in bounded steps. `actor` is the system's
    /// name for the trigger, recorded as the assigner.
    pub fn fill_missing_account_usernames(
        &self,
        after: Option<&str>,
        limit: usize,
        actor: &str,
    ) -> Result<AccountUsernameFillBatch, ManagedStoreError> {
        if limit == 0 {
            return Err(input_invalid("a fill batch examines at least one account"));
        }
        let policy = self.account_username_policy();
        let now = normalized_now_string();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let candidates: Vec<String> = {
            let mut statement = tx
                .prepare(
                    "SELECT p.principal_id FROM principals p
                     WHERE p.kind = 'user' AND p.account_username_mode = 'from_email'
                       AND p.principal_id > ?1
                       AND NOT EXISTS (SELECT 1 FROM account_usernames n
                                       WHERE n.principal_id = p.principal_id)
                     ORDER BY p.principal_id LIMIT ?2",
                )
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map(
                        params![
                            after.unwrap_or(""),
                            i64::try_from(limit).unwrap_or(i64::MAX)
                        ],
                        |row| row.get(0),
                    )
                    .map_err(sql_unavailable)?,
            )?
        };
        let mut assigned = Vec::new();
        for principal_id in &candidates {
            if let Some(name) = fill_missing(&tx, &policy, principal_id, actor, &now)? {
                assigned.push(name);
            }
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(AccountUsernameFillBatch {
            examined: candidates.len(),
            assigned,
            next: (candidates.len() == limit)
                .then(|| candidates.last().cloned())
                .flatten(),
        })
    }
}

/// Row invariants the schema cannot state: every name's holder has the
/// name's kind.
pub(super) fn check_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let invalid: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM account_usernames n JOIN principals p
               ON p.principal_id = n.principal_id WHERE p.kind <> n.holder_kind)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if invalid {
        return Err(invalid_row());
    }
    Ok(())
}

#[cfg(test)]
#[path = "account_usernames_tests.rs"]
mod tests;
