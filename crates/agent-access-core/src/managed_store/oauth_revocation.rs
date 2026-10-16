//! Pending remote revocations of the OAuth token families the Broker ends:
//! one row per ended family, whose tokens stay encrypted only until each has
//! a final outcome. The OAuth manager's revocation passes work through them;
//! see `crate::oauth::revocation`.
//!
//! The encrypted payload's AAD binds the row's identity (revocation ID,
//! owner, registration, registration fingerprint, family ID and cause) and
//! its key, so a payload cannot move to another row or back into an OAuth
//! slot. Its state, schedule and the refresh attempt whose outcome may still
//! add a successor are plain columns, rewritten without re-encryption; the
//! attempt stays named after the payload is erased, so a late successor is
//! still captured.
use super::*;
use crate::oauth::RemoteRevocation;
use crate::oauth::revocation::{KeptFamily, RevocationCause, RevocationMaterial};

const AAD_DOMAIN: &str = "broker-oauth-revocation";
const COLUMNS: &str = "revocation_id,owner_principal_id,registration_id,config_fingerprint,family_id,cause,state,refresh_attempt_id,due_at,key_id,nonce,ciphertext";

/// One stored revocation with its payload decrypted. `material` is `None`
/// once every known token has a final outcome; the row then only answers
/// for its owner's connection until `due_at`, when it is pruned.
/// `refresh_attempt` names the refresh in flight when the family ended
/// until its process reports what it did, whether or not the payload still
/// awaits it.
pub(crate) struct RevocationRow {
    pub(crate) id: String,
    pub(crate) owner: String,
    pub(crate) registration: String,
    pub(crate) fingerprint: String,
    pub(crate) family_id: String,
    pub(crate) cause: RevocationCause,
    pub(crate) state: RemoteRevocation,
    pub(crate) refresh_attempt: Option<String>,
    pub(crate) due_at: i64,
    pub(crate) material: Option<RevocationMaterial>,
}

/// A family to keep for revocation: the registration that issued it, as
/// its fingerprint identifies it, why the Broker ended it and the family as
/// [`crate::oauth::revocation::KeptFamily`] describes it.
pub(crate) struct NewRevocation<'a> {
    pub(crate) owner: &'a str,
    pub(crate) registration: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) cause: RevocationCause,
    pub(crate) family: KeptFamily,
    pub(crate) now: i64,
}

/// What principal disablement needs to keep an owner's families for
/// revocation inside its own transaction: the key ring and, for each
/// registration whose dialect revokes, its current fingerprint. The active
/// OAuth configuration sets it.
#[derive(Clone)]
pub(crate) struct RevocationCapture {
    pub(crate) ring: CredentialKeyRing,
    pub(crate) registrations: BTreeMap<String, String>,
}

struct StoredRow {
    id: String,
    owner: String,
    registration: String,
    fingerprint: String,
    family_id: String,
    cause: String,
    state: String,
    refresh_attempt: Option<String>,
    due_at: i64,
    key: Option<String>,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
}

impl StoredRow {
    fn identity(&self) -> Identity<'_> {
        (
            &self.id,
            &self.owner,
            &self.registration,
            &self.fingerprint,
            &self.family_id,
        )
    }
}

impl RevocationRow {
    fn identity(&self) -> Identity<'_> {
        (
            &self.id,
            &self.owner,
            &self.registration,
            &self.fingerprint,
            &self.family_id,
        )
    }
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRow> {
    Ok(StoredRow {
        id: row.get(0)?,
        owner: row.get(1)?,
        registration: row.get(2)?,
        fingerprint: row.get(3)?,
        family_id: row.get(4)?,
        cause: row.get(5)?,
        state: row.get(6)?,
        refresh_attempt: row.get(7)?,
        due_at: row.get(8)?,
        key: row.get(9)?,
        nonce: row.get(10)?,
        ciphertext: row.get(11)?,
    })
}

/// A row's bound identity: revocation ID, owner, registration, registration
/// fingerprint and family ID.
type Identity<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);

/// The authenticated data of a row's payload under `key`.
pub(super) fn aad(
    (id, owner, registration, fingerprint, family): Identity<'_>,
    cause: &str,
    key: &str,
) -> Vec<u8> {
    serde_json::to_vec(&(
        AAD_DOMAIN,
        1,
        id,
        owner,
        registration,
        fingerprint,
        family,
        cause,
        key,
    ))
    .expect("string tuple")
}

fn cipher(ring: &CredentialKeyRing, key: &str) -> Result<Aes256Gcm, ManagedStoreError> {
    let bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    Aes256Gcm::new_from_slice(bytes)
        .map_err(|_| ManagedStoreError::EncryptionKeyInvalid(key.into()))
}

fn encrypt(
    ring: &CredentialKeyRing,
    identity: Identity<'_>,
    cause: &str,
    material: &RevocationMaterial,
    key: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let plaintext =
        serde_json::to_vec(material).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(ring, key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(identity, cause, key),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: key.into(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

fn decrypt(
    ring: &CredentialKeyRing,
    row: &StoredRow,
) -> Result<Option<RevocationMaterial>, ManagedStoreError> {
    let (Some(key), Some(nonce), Some(ciphertext)) = (&row.key, &row.nonce, &row.ciphertext) else {
        return Ok(None);
    };
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let plaintext = cipher(ring, key)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(row.identity(), &row.cause, key),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let material: RevocationMaterial = serde_json::from_slice(&plaintext)
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    if !material.well_formed() {
        return Err(ManagedStoreError::CredentialDecryptFailed);
    }
    Ok(Some(material))
}

fn invalid_row() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("OAuth revocation row is invalid".into())
}

fn decode(ring: &CredentialKeyRing, row: StoredRow) -> Result<RevocationRow, ManagedStoreError> {
    let material = decrypt(ring, &row)?;
    Ok(RevocationRow {
        cause: RevocationCause::parse(&row.cause).ok_or_else(invalid_row)?,
        state: RemoteRevocation::parse_stored(&row.state).ok_or_else(invalid_row)?,
        id: row.id,
        owner: row.owner,
        registration: row.registration,
        fingerprint: row.fingerprint,
        family_id: row.family_id,
        refresh_attempt: row.refresh_attempt,
        due_at: row.due_at,
        material,
    })
}

/// Stores a new revocation, with each of its tokens due at once, and
/// returns its ID.
pub(crate) fn insert(
    conn: &Connection,
    ring: &CredentialKeyRing,
    new: NewRevocation<'_>,
) -> Result<String, ManagedStoreError> {
    let id = Uuid::new_v4().to_string();
    let cause = new.cause.as_str();
    let KeptFamily {
        family_id,
        refresh_attempt,
        material,
    } = new.family;
    let encrypted = encrypt(
        ring,
        (
            &id,
            new.owner,
            new.registration,
            new.fingerprint,
            &family_id,
        ),
        cause,
        &material,
        ring.active_key_id(),
    )?;
    let at = now_string();
    conn.execute(
        &format!(
            "INSERT INTO oauth_revocations({COLUMNS},created_at,updated_at,payload_version)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13,1)"
        ),
        params![
            id,
            new.owner,
            new.registration,
            new.fingerprint,
            family_id,
            cause,
            material.state().as_str(),
            refresh_attempt,
            material.next_due(new.now),
            encrypted.key_id,
            encrypted.nonce,
            encrypted.ciphertext,
            at,
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(id)
}

/// Rewrites `row`'s state, refresh attempt, schedule and payload under the
/// active key, or erases the payload once `material` is `None`.
fn write(
    conn: &Connection,
    ring: &CredentialKeyRing,
    row: &RevocationRow,
) -> Result<(), ManagedStoreError> {
    let encrypted = row
        .material
        .as_ref()
        .map(|material| {
            encrypt(
                ring,
                row.identity(),
                row.cause.as_str(),
                material,
                ring.active_key_id(),
            )
        })
        .transpose()?;
    conn.execute(
        "UPDATE oauth_revocations
         SET state=?2, refresh_attempt_id=?3, due_at=?4, payload_version=?5, key_id=?6, nonce=?7,
             ciphertext=?8, updated_at=?9
         WHERE revocation_id=?1",
        params![
            row.id,
            row.state.as_str(),
            row.refresh_attempt,
            row.due_at,
            encrypted.as_ref().map(|_| 1),
            encrypted.as_ref().map(|e| e.key_id.clone()),
            encrypted.as_ref().map(|e| e.nonce.clone()),
            encrypted.as_ref().map(|e| e.ciphertext.clone()),
            now_string(),
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

fn read_one(
    conn: &Connection,
    ring: &CredentialKeyRing,
    id: &str,
) -> Result<Option<RevocationRow>, ManagedStoreError> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM oauth_revocations WHERE revocation_id=?1"),
        [id],
        from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .map(|row| decode(ring, row))
    .transpose()
}

/// Keeps every family of `owner`'s slots that a revoking registration
/// issued, then deletes the slots. Principal disablement calls it inside
/// its transaction, so the owner's connections end and their families are
/// kept atomically. Returns how many families it kept.
pub(super) fn end_owner_slots(
    conn: &Connection,
    capture: Option<&RevocationCapture>,
    owner: &str,
) -> Result<usize, ManagedStoreError> {
    let mut kept = 0;
    if let Some(capture) = capture {
        for (registration, state) in oauth::owner_slots(conn, &capture.ring, owner)? {
            let Some(fingerprint) = capture.registrations.get(&registration) else {
                continue;
            };
            if state.config_fingerprint != *fingerprint {
                continue;
            }
            let now = crate::oauth::revocation::clock();
            let Some(family) = crate::oauth::revocation::slot_family(&state, now) else {
                continue;
            };
            insert(
                conn,
                &capture.ring,
                NewRevocation {
                    owner,
                    registration: &registration,
                    fingerprint,
                    cause: RevocationCause::PrincipalDisabled,
                    family,
                    now,
                },
            )?;
            kept += 1;
        }
    }
    conn.execute(
        "DELETE FROM oauth_slots WHERE owner_principal_id=?1",
        [owner],
    )
    .map_err(sql_unavailable)?;
    Ok(kept)
}

/// Every revocation still holding tokens decrypts under `ring`.
pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {COLUMNS} FROM oauth_revocations WHERE ciphertext IS NOT NULL"
        ))
        .map_err(sql_unavailable)?;
    let rows = collect_rows(statement.query_map([], from_row).map_err(sql_unavailable)?)?;
    for row in rows {
        let ring = ring.ok_or_else(|| {
            ManagedStoreError::EncryptionKeyMissing(row.key.clone().unwrap_or_default())
        })?;
        decode(ring, row)?;
    }
    Ok(())
}

/// Re-encrypts every payload under `from` with `to`, keeping its state,
/// schedule and outcomes.
pub(super) fn rewrap(
    conn: &mut Connection,
    ring: &CredentialKeyRing,
    from: &str,
    to: &str,
) -> Result<u64, ManagedStoreError> {
    let tx = conn.transaction().map_err(sql_unavailable)?;
    let rows = {
        let mut statement = tx
            .prepare(&format!(
                "SELECT {COLUMNS} FROM oauth_revocations WHERE key_id=?1"
            ))
            .map_err(sql_unavailable)?;
        collect_rows(
            statement
                .query_map([from], from_row)
                .map_err(sql_unavailable)?,
        )?
    };
    let count = rows.len() as u64;
    for row in rows {
        let material = decrypt(ring, &row)?.ok_or_else(invalid_row)?;
        let encrypted = encrypt(ring, row.identity(), &row.cause, &material, to)?;
        tx.execute(
            "UPDATE oauth_revocations SET key_id=?2, nonce=?3, ciphertext=?4 WHERE revocation_id=?1",
            params![row.id, encrypted.key_id, encrypted.nonce, encrypted.ciphertext],
        )
        .map_err(sql_unavailable)?;
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}

/// Gives every revocation still holding tokens a final outcome without
/// contacting a provider: no configured registration can revoke them, nor
/// the successor a refresh still in flight may return, which leaves that
/// family unconfirmed and is no longer captured. OAuth disablement calls it
/// inside its transaction.
pub(super) fn abandon_all(conn: &Connection, now: i64) -> Result<u64, ManagedStoreError> {
    let changed = conn
        .execute(
            "UPDATE oauth_revocations
             SET state = CASE WHEN state = 'unconfirmed' OR refresh_attempt_id IS NOT NULL
                              THEN 'unconfirmed' ELSE 'failed' END,
                 refresh_attempt_id=NULL, due_at=?1, payload_version=NULL, key_id=NULL,
                 nonce=NULL, ciphertext=NULL, updated_at=?2
             WHERE ciphertext IS NOT NULL",
            params![
                now + crate::oauth::revocation::RETENTION_SECONDS,
                now_string()
            ],
        )
        .map_err(sql_unavailable)?;
    conn.execute(
        "UPDATE oauth_revocations SET refresh_attempt_id=NULL WHERE refresh_attempt_id IS NOT NULL",
        [],
    )
    .map_err(sql_unavailable)?;
    Ok(changed as u64)
}

impl ManagedStore {
    /// The stored states of `owner`'s `registration` revocations.
    pub(crate) fn oauth_revocation_states(
        &self,
        owner: &str,
        registration: &str,
    ) -> Result<Vec<RemoteRevocation>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT state FROM oauth_revocations
                 WHERE owner_principal_id=?1 AND registration_id=?2",
            )
            .map_err(sql_unavailable)?;
        let states = collect_rows(
            statement
                .query_map(params![owner, registration], |row| row.get::<_, String>(0))
                .map_err(sql_unavailable)?,
        )?;
        states
            .iter()
            .map(|state| RemoteRevocation::parse_stored(state).ok_or_else(invalid_row))
            .collect()
    }

    /// The states of every revocation of `owner`'s families, by
    /// registration, configured or not.
    pub(crate) fn oauth_revocation_states_by_registration(
        &self,
        owner: &str,
    ) -> Result<BTreeMap<String, Vec<RemoteRevocation>>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT registration_id,state FROM oauth_revocations
                 WHERE owner_principal_id=?1",
            )
            .map_err(sql_unavailable)?;
        let rows = collect_rows(
            statement
                .query_map([owner], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sql_unavailable)?,
        )?;
        let mut states = BTreeMap::<String, Vec<RemoteRevocation>>::new();
        for (registration, state) in rows {
            states
                .entry(registration)
                .or_default()
                .push(RemoteRevocation::parse_stored(&state).ok_or_else(invalid_row)?);
        }
        Ok(states)
    }

    /// Up to `limit` revocations due at `now`, earliest first.
    pub(crate) fn oauth_revocations_due(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<String>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT revocation_id FROM oauth_revocations
                 WHERE due_at<=?1 AND ciphertext IS NOT NULL
                 ORDER BY due_at, revocation_id LIMIT ?2",
            )
            .map_err(sql_unavailable)?;
        collect_rows(
            statement
                .query_map(params![now, limit as i64], |row| row.get(0))
                .map_err(sql_unavailable)?,
        )
    }

    /// When the earliest revocation still holding tokens is due.
    pub(crate) fn oauth_revocation_next_due(&self) -> Result<Option<i64>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        conn.query_row(
            "SELECT MIN(due_at) FROM oauth_revocations WHERE ciphertext IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)
    }

    /// Deletes the finished revocations whose answering period ended.
    pub(crate) fn oauth_revocations_prune(&self, now: i64) -> Result<u64, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let deleted = conn
            .execute(
                "DELETE FROM oauth_revocations WHERE ciphertext IS NULL AND due_at<=?1",
                [now],
            )
            .map_err(sql_unavailable)?;
        Ok(deleted as u64)
    }

    pub(crate) fn oauth_revocation_read(
        &self,
        ring: &CredentialKeyRing,
        id: &str,
    ) -> Result<Option<RevocationRow>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        read_one(&conn, ring, id)
    }

    /// Applies `change` to revocation `id` as it is now, in one transaction,
    /// and returns the stored result.
    pub(crate) fn oauth_revocation_update(
        &self,
        ring: &CredentialKeyRing,
        id: &str,
        change: impl FnOnce(&mut RevocationRow),
    ) -> Result<Option<RevocationRow>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let Some(mut row) = read_one(&tx, ring, id)? else {
            return Ok(None);
        };
        change(&mut row);
        write(&tx, ring, &row)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(Some(row))
    }

    /// Applies `change`, in one transaction, to the revocation of
    /// `owner`'s `registration` family `family` that still names refresh
    /// attempt `attempt`, whether or not it holds tokens any more, and
    /// returns the stored result. `None` when no revocation names it.
    pub(crate) fn oauth_revocation_settle(
        &self,
        ring: &CredentialKeyRing,
        (owner, registration, family): (&str, &str, &str),
        attempt: &str,
        change: impl FnOnce(&mut RevocationRow),
    ) -> Result<Option<RevocationRow>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let Some(stored) = tx
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM oauth_revocations
                     WHERE owner_principal_id=?1 AND registration_id=?2 AND family_id=?3
                       AND refresh_attempt_id=?4"
                ),
                params![owner, registration, family, attempt],
                from_row,
            )
            .optional()
            .map_err(sql_unavailable)?
        else {
            return Ok(None);
        };
        let mut row = decode(ring, stored)?;
        change(&mut row);
        write(&tx, ring, &row)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(Some(row))
    }

    /// Lets principal disablement keep revoking registrations' families:
    /// the active OAuth configuration sets it, and disablement clears it.
    pub(crate) fn configure_oauth_revocation(&self, capture: Option<RevocationCapture>) {
        *self.oauth_revocation.lock().unwrap() = capture;
    }

    pub(super) fn oauth_revocation_capture(&self) -> Option<RevocationCapture> {
        self.oauth_revocation.lock().unwrap().clone()
    }

    /// Test support: makes every revocation still holding tokens due now,
    /// with each of its pending tokens, as if every retry wait had ended.
    /// A refresh still awaited keeps its expiry. Decrypts with the key ring
    /// the active OAuth configuration set. Returns how many it changed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn oauth_revocations_due_now(&self) -> Result<usize, ManagedStoreError> {
        let ring = self
            .oauth_revocation_capture()
            .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing("oauth".into()))?
            .ring;
        let ids: Vec<String> = {
            let conn = self.connection.lock().unwrap();
            let mut statement = conn
                .prepare("SELECT revocation_id FROM oauth_revocations WHERE ciphertext IS NOT NULL")
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map([], |row| row.get(0))
                    .map_err(sql_unavailable)?,
            )?
        };
        for id in &ids {
            self.oauth_revocation_update(&ring, id, |row| {
                if let Some(material) = row.material.as_mut() {
                    material.make_due();
                }
                row.due_at = 0;
            })?;
        }
        Ok(ids.len())
    }
}

#[cfg(test)]
#[path = "oauth_revocation_tests.rs"]
mod tests;
