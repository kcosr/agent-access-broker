//! Remote revocation of the OAuth token families the Broker ends.
//!
//! A local fence always comes first: disconnect, a replacing consent and
//! principal disablement end the family in the same transaction that keeps
//! its tokens in an encrypted pending revocation, and an uncertain consuming
//! refresh keeps its predecessor before clearing it. Only a registration
//! whose dialect revokes (`OAuthDialect::supports_revocation`) keeps them;
//! every other connection reports [`RemoteRevocation::NotRequested`].
//!
//! Revocation passes then revoke each kept token at the provider, with a
//! bounded number of tries on each token's own schedule, from the stored
//! record, so they resume after a restart. A refresh in flight when its
//! family was fenced is recorded with the revocation, which names it until
//! its process reports what it did: a successor it returns is never
//! installed and joins the revocation, even after the attempt was presumed
//! lost or every other token was revoked. An outcome nobody learns leaves an
//! unknown successor, so the family is only ever reported
//! [`RemoteRevocation::Unconfirmed`]. A remote failure never restores local
//! access.
use super::*;
use crate::managed_store::oauth_revocation::{self as store, NewRevocation, RevocationRow};
use agent_access_provider::{OAuthTokenType, RevocationOutcome, TokenRevocation};
use std::time::Duration;

/// How long a finished revocation keeps answering for its owner's
/// connection before it is pruned.
pub(crate) const RETENTION_SECONDS: i64 = 30 * 24 * 3600;
/// The waits after each retryable failure of one token; it fails for good
/// on the try after the last wait.
const RETRY_DELAYS: [i64; 4] = [30, 120, 600, 3600];
const MAX_TRIES: u8 = RETRY_DELAYS.len() as u8 + 1;
/// A family has one refresh token, at most one access token per permission
/// profile and, after a late refresh, their successors.
const MAX_MEMBERS: usize = 64;
const MAX_TOKEN_BYTES: usize = 32_768;
/// Revocations one pass takes up.
const PASS_LIMIT: usize = 32;

/// What the Broker knows about revoking an owner's ended OAuth token
/// families at the provider, most severe first when several apply:
/// `unconfirmed` (a successor the Broker never learned may exist; revoke
/// the application at the provider), `failed` (a known token could not be
/// revoked), `pending` (revocation is in progress), `revoked` (every known
/// token was revoked and no unknown successor can exist) and
/// `not_requested` (nothing was kept for revocation, as for a dialect that
/// does not revoke).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRevocation {
    NotRequested,
    Pending,
    Revoked,
    Failed,
    Unconfirmed,
}

impl RemoteRevocation {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Pending => "pending",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
            Self::Unconfirmed => "unconfirmed",
        }
    }

    /// Whether revocation is still in progress or needs provider-side
    /// cleanup: `pending`, `failed` or `unconfirmed`. Connection listings
    /// keep such a registration whatever its owner's entitlement.
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Pending | Self::Failed | Self::Unconfirmed)
    }

    /// A stored revocation's state; `not_requested` is never stored.
    pub(crate) fn parse_stored(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "revoked" => Some(Self::Revoked),
            "failed" => Some(Self::Failed),
            "unconfirmed" => Some(Self::Unconfirmed),
            _ => None,
        }
    }

    fn severity(self) -> u8 {
        match self {
            Self::NotRequested => 0,
            Self::Revoked => 1,
            Self::Pending => 2,
            Self::Failed => 3,
            Self::Unconfirmed => 4,
        }
    }

    /// The most severe of `states`; `not_requested` when there are none.
    pub(crate) fn summarize(states: impl IntoIterator<Item = Self>) -> Self {
        states
            .into_iter()
            .max_by_key(|state| state.severity())
            .unwrap_or(Self::NotRequested)
    }
}

/// Why the Broker ended a family it keeps for revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevocationCause {
    /// The owner disconnected.
    Disconnect,
    /// A new consent replaced it: a reconnect or an account replacement.
    Superseded,
    /// An administrator disabled the owner.
    PrincipalDisabled,
    /// A consuming refresh's outcome was lost.
    RefreshUncertain,
}

impl RevocationCause {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnect => "disconnect",
            Self::Superseded => "superseded",
            Self::PrincipalDisabled => "principal_disabled",
            Self::RefreshUncertain => "refresh_uncertain",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        [
            Self::Disconnect,
            Self::Superseded,
            Self::PrincipalDisabled,
            Self::RefreshUncertain,
        ]
        .into_iter()
        .find(|cause| cause.as_str() == value)
    }
}

/// A kept family's encrypted payload: its known tokens and what each
/// revocation found, until when a refresh in flight at the fence is awaited
/// (the row names that attempt), and whether a successor the Broker never
/// learned may exist.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationMaterial {
    pub(crate) members: Vec<RevocationMember>,
    pub(crate) refresh_awaited_until: Option<i64>,
    pub(crate) unknown_successor: bool,
}

/// One known token, with its outcome, its tries so far and when it may be
/// tried next: at once, after its retry wait, or after the provider's longer
/// `Retry-After`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationMember {
    pub(crate) token: String,
    pub(crate) token_type: MemberType,
    pub(crate) outcome: MemberOutcome,
    pub(crate) tries: u8,
    pub(crate) not_before: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberType {
    AccessToken,
    RefreshToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberOutcome {
    Pending,
    Revoked,
    Failed,
}

impl MemberType {
    fn sdk(self) -> OAuthTokenType {
        match self {
            Self::AccessToken => OAuthTokenType::AccessToken,
            Self::RefreshToken => OAuthTokenType::RefreshToken,
        }
    }
}

impl RevocationMaterial {
    fn new() -> Self {
        Self {
            members: Vec::new(),
            refresh_awaited_until: None,
            unknown_successor: false,
        }
    }

    /// Adds `token`, due at `now`, unless the family already holds it or is
    /// full.
    fn add(&mut self, token: &str, token_type: MemberType, now: i64) {
        if self.members.len() < MAX_MEMBERS && !self.members.iter().any(|m| m.token == token) {
            self.members.push(RevocationMember {
                token: token.into(),
                token_type,
                outcome: MemberOutcome::Pending,
                tries: 0,
                not_before: now,
            });
        }
    }

    pub(crate) fn well_formed(&self) -> bool {
        self.members.len() <= MAX_MEMBERS
            && self.members.iter().all(|member| {
                !member.token.is_empty()
                    && member.token.len() <= MAX_TOKEN_BYTES
                    && member.tries <= MAX_TRIES
            })
    }

    fn pending(&self) -> impl Iterator<Item = &RevocationMember> {
        self.members
            .iter()
            .filter(|member| member.outcome == MemberOutcome::Pending)
    }

    fn finished(&self) -> bool {
        self.refresh_awaited_until.is_none() && self.pending().next().is_none()
    }

    /// When a pass next has something to do: the earliest pending token's
    /// next try, or just after an awaited refresh expires, independently of
    /// each other. `now` when there is nothing left.
    pub(crate) fn next_due(&self, now: i64) -> i64 {
        self.pending()
            .map(|member| member.not_before)
            .chain(self.refresh_awaited_until.map(|until| until + 1))
            .min()
            .unwrap_or(now)
    }

    /// Test support: every pending token may be tried at once.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn make_due(&mut self) {
        for member in &mut self.members {
            member.not_before = 0;
        }
    }

    /// The state this payload reports.
    pub(crate) fn state(&self) -> RemoteRevocation {
        if self.unknown_successor {
            RemoteRevocation::Unconfirmed
        } else if !self.finished() {
            RemoteRevocation::Pending
        } else if self
            .members
            .iter()
            .any(|member| member.outcome == MemberOutcome::Failed)
        {
            RemoteRevocation::Failed
        } else {
            RemoteRevocation::Revoked
        }
    }
}

/// A family to keep for revocation: its ID, the refresh attempt whose
/// outcome its process may still report, and its payload.
pub(crate) struct KeptFamily {
    pub(crate) family_id: String,
    pub(crate) refresh_attempt: Option<String>,
    pub(crate) material: RevocationMaterial,
}

/// The tokens of `connection`'s family, each due at `now`, and its refresh
/// in flight. The refresh is awaited until it expires unless `outcome_lost`
/// ended the family because its outcome is unknown; it is named for a late
/// successor unless `outcome_lost` and this process ran it (`live`), whose
/// result is then lost for good. `None` when there is nothing to revoke.
fn kept_family(
    connection: &ConnectionState,
    now: i64,
    outcome_lost: bool,
    live: impl FnOnce(&str) -> bool,
) -> Option<KeptFamily> {
    let family = &connection.family;
    let mut material = RevocationMaterial::new();
    if let Some(token) = &family.refresh_token {
        material.add(token, MemberType::RefreshToken, now);
    }
    for entry in family.access.values() {
        material.add(&entry.token, MemberType::AccessToken, now);
    }
    material.unknown_successor = outcome_lost;
    let mut refresh_attempt = family.attempt.as_ref();
    if outcome_lost {
        refresh_attempt = refresh_attempt.filter(|attempt| !live(&attempt.id));
    } else {
        material.refresh_awaited_until = refresh_attempt.map(|attempt| attempt.expires_at);
    }
    (!material.members.is_empty() || refresh_attempt.is_some()).then(|| KeptFamily {
        family_id: family.id.clone(),
        refresh_attempt: refresh_attempt.map(|attempt| attempt.id.clone()),
        material,
    })
}

/// The family a stored slot holds, as principal disablement keeps it.
pub(crate) fn slot_family(slot: &SlotState, now: i64) -> Option<KeptFamily> {
    slot.connection
        .as_ref()
        .and_then(|connection| kept_family(connection, now, false, |_| false))
}

/// The OAuth clock, as revocation schedules use it.
pub(crate) fn clock() -> i64 {
    now()
}

/// Sets `row`'s state from its payload and schedules it: a finished
/// revocation drops its tokens and answers until the retention ends; any
/// other is next due when one of its tokens or its awaited refresh is.
fn schedule(row: &mut RevocationRow, now: i64) {
    let Some(material) = &row.material else {
        return;
    };
    row.state = material.state();
    if material.finished() {
        row.material = None;
        row.due_at = now + RETENTION_SECONDS;
    } else {
        row.due_at = material.next_due(now);
    }
}

/// Failures the provider may not repeat: the token is tried again later.
/// A rejected client authentication is among them, because an operator can
/// correct the registration's client secret in the meantime.
fn retryable(error: &OAuthDialectError) -> bool {
    matches!(
        error,
        OAuthDialectError::NotSent
            | OAuthDialectError::Failed
            | OAuthDialectError::Throttled
            | OAuthDialectError::RetryAfter(_)
            | OAuthDialectError::ClientRejected
    )
}

type Tries = Vec<(String, Result<RevocationOutcome, OAuthDialectError>)>;

/// Applies one pass's `tries` to `row` as it is now; each tried token gets
/// its own outcome and next try, and the others keep theirs. `revocable` is
/// false when no configured registration can revoke the family any more;
/// its tokens then fail without a request and no successor is captured. A
/// refresh awaited past its expiry that is not live in this process leaves
/// an unknown successor, but the row keeps naming it, so a successor its
/// process still reports joins the revocation.
fn apply_pass(
    row: &mut RevocationRow,
    tries: &Tries,
    revocable: bool,
    live: &BTreeSet<String>,
    now: i64,
) {
    let Some(material) = row.material.as_mut() else {
        return;
    };
    if !revocable {
        row.refresh_attempt = None;
    }
    if let Some(until) = material.refresh_awaited_until
        && (!revocable
            || (until <= now
                && !row
                    .refresh_attempt
                    .as_ref()
                    .is_some_and(|attempt| live.contains(attempt))))
    {
        material.refresh_awaited_until = None;
        material.unknown_successor = true;
    }
    for member in material
        .members
        .iter_mut()
        .filter(|member| member.outcome == MemberOutcome::Pending)
    {
        if !revocable {
            member.outcome = MemberOutcome::Failed;
            continue;
        }
        let Some((_, result)) = tries.iter().find(|(token, _)| *token == member.token) else {
            continue;
        };
        match result {
            Ok(_) => member.outcome = MemberOutcome::Revoked,
            Err(error) if retryable(error) => {
                member.tries = member.tries.saturating_add(1);
                if member.tries >= MAX_TRIES {
                    member.outcome = MemberOutcome::Failed;
                    continue;
                }
                let wait = RETRY_DELAYS[usize::from(member.tries - 1).min(RETRY_DELAYS.len() - 1)];
                let retry_after = match error {
                    OAuthDialectError::RetryAfter(seconds) => (*seconds)
                        .min(agent_access_provider::UPSTREAM_RETRY_AFTER_MAX_SECONDS)
                        as i64,
                    _ => 0,
                };
                member.not_before = now + wait.max(retry_after);
            }
            Err(_) => member.outcome = MemberOutcome::Failed,
        }
    }
    schedule(row, now);
}

/// What a refresh in flight when its family was fenced turned out to do.
pub(super) enum FencedRefresh {
    /// It issued this successor, which was never installed.
    Succeeded {
        refresh: Option<String>,
        access: String,
    },
    /// The provider proved it consumed nothing.
    NotConsumed,
    /// Its outcome was lost: a successor may exist.
    Uncertain,
}

struct Coordination {
    signal: tokio::sync::Notify,
    claims: Mutex<BTreeSet<String>>,
}

fn coordination() -> &'static Coordination {
    static COORDINATION: OnceLock<Coordination> = OnceLock::new();
    COORDINATION.get_or_init(|| Coordination {
        signal: tokio::sync::Notify::new(),
        claims: Mutex::new(BTreeSet::new()),
    })
}

/// Notified whenever the Broker keeps an ended family for revocation, or a
/// late refresh adds to one. The host's revocation worker waits on it
/// between passes.
pub fn oauth_revocation_signal() -> &'static tokio::sync::Notify {
    &coordination().signal
}

pub(crate) fn wake() {
    coordination().signal.notify_waiters();
}

/// One pass in this process works on a revocation at a time; across
/// processes, revocation is idempotent and outcomes merge.
struct Claim(String);

impl Claim {
    fn take(id: &str) -> Option<Self> {
        coordination()
            .claims
            .lock()
            .expect("OAuth revocation claims")
            .insert(id.into())
            .then(|| Self(id.into()))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        coordination()
            .claims
            .lock()
            .expect("OAuth revocation claims")
            .remove(&self.0);
    }
}

impl OAuthManager {
    /// What the Broker knows about revoking `owner`'s ended `registration`
    /// families at the provider.
    pub fn remote_revocation(
        &self,
        owner: &str,
        registration: &str,
    ) -> Result<RemoteRevocation, OAuthError> {
        self.active()?;
        Ok(RemoteRevocation::summarize(
            self.inner
                .store
                .oauth_revocation_states(owner, registration)?,
        ))
    }

    /// What the Broker knows about revoking `owner`'s ended families at the
    /// provider, by registration, for every registration with a stored
    /// revocation, configured or not. Every other registration is
    /// `not_requested`.
    pub fn remote_revocations(
        &self,
        owner: &str,
    ) -> Result<BTreeMap<String, RemoteRevocation>, OAuthError> {
        self.active()?;
        Ok(self
            .inner
            .store
            .oauth_revocation_states_by_registration(owner)?
            .into_iter()
            .map(|(registration, states)| (registration, RemoteRevocation::summarize(states)))
            .collect())
    }

    /// Works through the revocations due now, prunes finished ones whose
    /// answering period ended, and returns how long until the next one is
    /// due. The host's revocation worker calls it at startup, after each
    /// signal and when the returned wait ends.
    pub async fn revoke_due(&self) -> Result<Option<Duration>, OAuthError> {
        self.active()?;
        let started = now();
        self.inner.store.oauth_revocations_prune(started)?;
        let due = self
            .inner
            .store
            .oauth_revocations_due(started, PASS_LIMIT)?;
        self.revoke_records(&due).await;
        Ok(self
            .inner
            .store
            .oauth_revocation_next_due()?
            .map(|at| Duration::from_secs(u64::try_from(at - now()).unwrap_or(0))))
    }

    /// One pass over each of `ids`, due or not.
    pub(crate) async fn revoke_records(&self, ids: &[String]) {
        for id in ids {
            if let Err(error) = self.revoke_record(id).await {
                tracing::warn!(target:"agent_access_core::oauth",event="remote_revocation",revocation_id=%id,outcome=error.code());
            }
        }
    }

    async fn revoke_record(&self, id: &str) -> Result<(), OAuthError> {
        self.active()?;
        let Some(_claim) = Claim::take(id) else {
            return Ok(());
        };
        let Some(row) = self
            .inner
            .store
            .oauth_revocation_read(&self.inner.ring, id)?
        else {
            return Ok(());
        };
        let Some(material) = &row.material else {
            return Ok(());
        };
        // Only tokens whose own retry wait has ended are tried; an awaited
        // refresh's expiry or a new successor tries no other token early.
        let started = now();
        let eligible = material
            .pending()
            .filter(|member| member.not_before <= started);
        // Only the registration that issued the family, unchanged, has a
        // client the provider accepts its revocation from.
        let registration = self
            .inner
            .registrations
            .get(&row.registration)
            .filter(|r| r.fingerprint == row.fingerprint && r.dialect.supports_revocation());
        let tries: Tries = match registration {
            Some(r) => {
                let client = r.client();
                futures_util::future::join_all(eligible.map(|member| {
                    let client = &client;
                    async move {
                        let result = r
                            .dialect
                            .revoke(
                                &r.http,
                                client,
                                TokenRevocation::new(&member.token, member.token_type.sdk()),
                            )
                            .await;
                        (member.token.clone(), result)
                    }
                }))
                .await
            }
            None => Vec::new(),
        };
        let live = self
            .inner
            .live_refresh_attempts
            .lock()
            .expect("OAuth live refresh attempts")
            .clone();
        let revocable = registration.is_some();
        let stored = self
            .inner
            .store
            .oauth_revocation_update(&self.inner.ring, id, |row| {
                apply_pass(row, &tries, revocable, &live, now());
            })?;
        if let Some(row) = stored {
            let revoked = tries.iter().filter(|(_, result)| result.is_ok()).count();
            tracing::info!(target:"agent_access_core::oauth",event="remote_revocation",owner=%row.owner,registration=%row.registration,revocation_id=%row.id,cause=row.cause.as_str(),requests=tries.len(),revoked,revocable,outcome=row.state.as_str());
        }
        Ok(())
    }

    /// Keeps `connection`'s family for revocation in the transaction `conn`
    /// that ends it, when the registration's dialect revokes. Returns the
    /// new revocation's ID.
    pub(super) fn keep_family(
        &self,
        conn: &rusqlite::Connection,
        owner: &str,
        r: &ResolvedRegistration,
        connection: &ConnectionState,
        cause: RevocationCause,
    ) -> Result<Option<String>, OAuthError> {
        if !r.dialect.supports_revocation() {
            return Ok(None);
        }
        let now = now();
        let Some(family) = kept_family(
            connection,
            now,
            cause == RevocationCause::RefreshUncertain,
            |attempt| {
                self.inner
                    .live_refresh_attempts
                    .lock()
                    .expect("OAuth live refresh attempts")
                    .contains(attempt)
            },
        ) else {
            return Ok(None);
        };
        Ok(Some(store::insert(
            conn,
            &self.inner.ring,
            NewRevocation {
                owner,
                registration: &r.id,
                fingerprint: &r.fingerprint,
                cause,
                family,
                now,
            },
        )?))
    }

    /// Records what refresh attempt `attempt` of `owner`'s `registration`
    /// family `family` did after a fence ended that family. A successor
    /// joins the revocation that names the attempt and is never installed,
    /// also when the revocation presumed the attempt lost or had finished,
    /// which it reopens; it then stays unconfirmed. A lost outcome leaves an
    /// unknown successor; a proof that nothing was consumed ends the wait.
    /// Nothing changes when no revocation names the attempt.
    pub(super) fn settle_fenced_refresh(
        &self,
        (owner, registration, family): (&str, &str, &str),
        attempt: &str,
        outcome: FencedRefresh,
    ) {
        let result = self.inner.store.oauth_revocation_settle(
            &self.inner.ring,
            (owner, registration, family),
            attempt,
            |row| {
                row.refresh_attempt = None;
                let now = now();
                if row.material.is_none() {
                    // The attempt was presumed lost and every other token
                    // has its outcome: only a successor reopens the
                    // revocation, which stays unconfirmed.
                    if !matches!(outcome, FencedRefresh::Succeeded { .. }) {
                        return;
                    }
                    let mut material = RevocationMaterial::new();
                    material.unknown_successor = true;
                    row.material = Some(material);
                }
                let material = row.material.as_mut().expect("open revocation");
                material.refresh_awaited_until = None;
                match outcome {
                    FencedRefresh::Succeeded { refresh, access } => {
                        if let Some(refresh) = &refresh {
                            material.add(refresh, MemberType::RefreshToken, now);
                        }
                        material.add(&access, MemberType::AccessToken, now);
                    }
                    FencedRefresh::Uncertain => material.unknown_successor = true,
                    FencedRefresh::NotConsumed => {}
                }
                schedule(row, now);
            },
        );
        match result {
            Ok(Some(row)) => {
                tracing::info!(target:"agent_access_core::oauth",event="remote_revocation_refresh_settled",owner,registration,revocation_id=%row.id,attempt_id=attempt,outcome=row.state.as_str());
                wake();
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(target:"agent_access_core::oauth",event="remote_revocation_refresh_settled",owner,registration,attempt_id=attempt,outcome="oauth_storage_unavailable");
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
