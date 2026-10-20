//! Managed attested identities. The human gate is independent of bearer inventory.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAccessRecord {
    pub principal_id: String,
    pub incarnation: String,
    pub paused: bool,
    pub version: i64,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsernameBindingRecord {
    pub binding_id: String,
    pub principal_id: String,
    pub namespace: String,
    pub username: String,
    pub enabled: bool,
    pub read_only: bool,
    pub version: i64,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

/// A change to a username binding's settings; absent fields keep their value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsernameBindingUpdate {
    pub enabled: Option<bool>,
    pub read_only: Option<bool>,
}

/// Private authentication evidence, never an API DTO or a reusable credential.
#[derive(Clone, PartialEq, Eq)]
pub struct AttestedIdentityProof {
    principal_id: String,
    gate_incarnation: String,
    gate_version: i64,
    /// The admitted path's read-only setting. Its version or revision already
    /// fences changes; the value makes the admitted snapshot explicit.
    read_only: bool,
    kind: AttestedIdentityKind,
}

#[derive(Clone, PartialEq, Eq)]
enum AttestedIdentityKind {
    Username {
        namespace: String,
        username: String,
        binding_id: String,
        binding_version: i64,
    },
    Fingerprint {
        fingerprint: String,
        inventory_revision: i64,
    },
}

impl std::fmt::Debug for AttestedIdentityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestedIdentityProof([redacted])")
    }
}

impl AttestedIdentityProof {
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn namespace(&self) -> Option<&str> {
        match &self.kind {
            AttestedIdentityKind::Username { namespace, .. } => Some(namespace),
            AttestedIdentityKind::Fingerprint { .. } => None,
        }
    }

    pub fn binding_id(&self) -> Option<&str> {
        match &self.kind {
            AttestedIdentityKind::Username { binding_id, .. } => Some(binding_id),
            AttestedIdentityKind::Fingerprint { .. } => None,
        }
    }

    pub fn is_username(&self) -> bool {
        matches!(self.kind, AttestedIdentityKind::Username { .. })
    }

    /// Whether the admitted path is limited to actions classified as reads.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn matches_username(&self, namespace: &str, username: &str) -> bool {
        matches!(&self.kind, AttestedIdentityKind::Username {
            namespace: expected_namespace, username: expected_username, ..
        } if expected_namespace == namespace && expected_username == username)
    }

    pub fn matches_fingerprint(&self, fingerprint: &str) -> bool {
        matches!(&self.kind, AttestedIdentityKind::Fingerprint {
            fingerprint: expected, ..
        } if expected == fingerprint)
    }

    /// Length-delimited private input for the keyed MCP session-owner digest.
    /// These bytes contain identity evidence and must never be exposed or logged.
    pub fn session_binding(&self) -> Vec<u8> {
        fn field(bytes: &mut Vec<u8>, value: &[u8]) {
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        let mut bytes = b"agent-access/attested-identity/v2".to_vec();
        field(&mut bytes, self.principal_id.as_bytes());
        field(&mut bytes, self.gate_incarnation.as_bytes());
        bytes.extend_from_slice(&self.gate_version.to_be_bytes());
        bytes.push(u8::from(self.read_only));
        match &self.kind {
            AttestedIdentityKind::Username {
                namespace,
                username,
                binding_id,
                binding_version,
            } => {
                bytes.push(1);
                field(&mut bytes, namespace.as_bytes());
                field(&mut bytes, username.as_bytes());
                field(&mut bytes, binding_id.as_bytes());
                bytes.extend_from_slice(&binding_version.to_be_bytes());
            }
            AttestedIdentityKind::Fingerprint {
                fingerprint,
                inventory_revision,
            } => {
                bytes.push(2);
                field(&mut bytes, fingerprint.as_bytes());
                bytes.extend_from_slice(&inventory_revision.to_be_bytes());
            }
        }
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedAttestedIdentity {
    pub principal: PrincipalRecord,
    pub policy_groups: Vec<String>,
    pub proof: AttestedIdentityProof,
}

impl ResolvedAttestedIdentity {
    /// Whether the resolved path is limited to actions classified as reads.
    pub fn read_only(&self) -> bool {
        self.proof.read_only()
    }
}

impl ManagedStore {
    pub fn identity_access(
        &self,
        principal: &str,
    ) -> Result<IdentityAccessRecord, ManagedStoreError> {
        validate_principal_id(principal)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        let record = identity_access_conn(&tx, principal)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn set_identity_access_paused(
        &self,
        principal: &str,
        paused: bool,
        expected_version: i64,
        updated_by: &str,
    ) -> Result<IdentityAccessRecord, ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_actor(updated_by)?;
        validate_expected_version(expected_version)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        let previous = identity_access_conn(&tx, principal)?;
        require_version(previous.version, expected_version)?;
        if previous.paused != paused {
            tx.execute(
                "UPDATE principal_identity_access SET paused=?2, version=version+1,
                 updated_at=?3, updated_by=?4 WHERE principal_id=?1",
                params![principal, paused, normalized_now_string(), updated_by],
            )
            .map_err(sql_unavailable)?;
        }
        let record = identity_access_conn(&tx, principal)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn list_username_bindings(
        &self,
        principal: &str,
    ) -> Result<Vec<UsernameBindingRecord>, ManagedStoreError> {
        validate_principal_id(principal)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        identity_access_conn(&tx, principal)?;
        let records = {
            let mut statement = tx
                .prepare(
                    "SELECT binding_id, principal_id, namespace, username, enabled, read_only,
                     version, created_at, created_by, updated_at, updated_by
                     FROM principal_username_bindings WHERE principal_id=?1
                     ORDER BY namespace, username, binding_id",
                )
                .map_err(sql_unavailable)?;
            collect_rows(
                statement
                    .query_map([principal], binding_from_row)
                    .map_err(sql_unavailable)?,
            )?
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(records)
    }

    /// The management owner additionally admits the namespace against its pinned config.
    pub fn create_username_binding(
        &self,
        principal: &str,
        namespace: &str,
        username: &str,
        read_only: bool,
        created_by: &str,
    ) -> Result<UsernameBindingRecord, ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_username_identity(namespace, username)?;
        validate_actor(created_by)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        identity_access_conn(&tx, principal)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM principal_username_bindings WHERE namespace=?1 AND username=?2)",
                params![namespace, username],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        if exists {
            return Err(ManagedStoreError::IdentityBindingConflict);
        }
        let binding_id = Uuid::new_v4().to_string();
        let now = normalized_now_string();
        tx.execute(
            "INSERT INTO principal_username_bindings
             (binding_id, principal_id, namespace, username, enabled, read_only, version,
              created_at, created_by, updated_at, updated_by)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, 1, ?6, ?7, ?6, ?7)",
            params![
                binding_id, principal, namespace, username, read_only, now, created_by
            ],
        )
        .map_err(sql_unavailable)?;
        let record = username_binding_conn(&tx, principal, &binding_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    /// Applies the requested settings with one version increment, or writes
    /// nothing when they already hold. Returns the binding before and after,
    /// read in the transaction.
    pub fn update_username_binding(
        &self,
        principal: &str,
        binding_id: &str,
        update: UsernameBindingUpdate,
        expected_version: i64,
        updated_by: &str,
    ) -> Result<(UsernameBindingRecord, UsernameBindingRecord), ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_canonical_uuid(binding_id, "identity binding ID")?;
        validate_actor(updated_by)?;
        validate_expected_version(expected_version)?;
        if update.enabled.is_none() && update.read_only.is_none() {
            return Err(input_invalid(
                "identity binding update requires enabled or readOnly",
            ));
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        identity_access_conn(&tx, principal)?;
        let before = username_binding_conn(&tx, principal, binding_id)?;
        require_version(before.version, expected_version)?;
        let enabled = update.enabled.unwrap_or(before.enabled);
        let read_only = update.read_only.unwrap_or(before.read_only);
        if (enabled, read_only) != (before.enabled, before.read_only) {
            tx.execute(
                "UPDATE principal_username_bindings SET enabled=?2, read_only=?3,
                 version=version+1, updated_at=?4, updated_by=?5 WHERE binding_id=?1",
                params![
                    binding_id,
                    enabled,
                    read_only,
                    normalized_now_string(),
                    updated_by
                ],
            )
            .map_err(sql_unavailable)?;
        }
        let after = username_binding_conn(&tx, principal, binding_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok((before, after))
    }

    pub fn delete_username_binding(
        &self,
        principal: &str,
        binding_id: &str,
        expected_version: i64,
    ) -> Result<UsernameBindingRecord, ManagedStoreError> {
        validate_principal_id(principal)?;
        validate_canonical_uuid(binding_id, "identity binding ID")?;
        validate_expected_version(expected_version)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_human(&tx, principal)?;
        identity_access_conn(&tx, principal)?;
        let previous = username_binding_conn(&tx, principal, binding_id)?;
        require_version(previous.version, expected_version)?;
        tx.execute(
            "DELETE FROM principal_username_bindings WHERE binding_id=?1",
            [binding_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(previous)
    }

    pub fn resolve_username_identity(
        &self,
        namespace: &str,
        username: &str,
    ) -> Result<ResolvedAttestedIdentity, ManagedStoreError> {
        if !is_safe_identifier(namespace) || !crate::is_valid_identity_username(username) {
            return Err(ManagedStoreError::AttestedIdentityDenied);
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let (principal, proof) = resolve_username_conn(&tx, namespace, username)?;
        let resolved = with_membership(&tx, principal, proof)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(resolved)
    }

    pub fn resolve_identity_fingerprint_with_proof(
        &self,
        fingerprint: &str,
    ) -> Result<ResolvedAttestedIdentity, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let (principal, proof) = resolve_fingerprint_conn(&tx, fingerprint)?;
        let resolved = with_membership(&tx, principal, proof)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(resolved)
    }

    /// Atomic final admission: an old proof cannot resolve as a newly mapped human.
    pub fn revalidate_attested_identity(
        &self,
        expected: &AttestedIdentityProof,
    ) -> Result<ResolvedAttestedIdentity, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let (principal, current) = resolve_proof_conn(&tx, expected)?;
        if current != *expected {
            return Err(ManagedStoreError::AttestedIdentityDenied);
        }
        let resolved = with_membership(&tx, principal, current)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(resolved)
    }

    /// One authoritative read snapshot for a caller-bounded cleanup batch.
    /// Unavailability/corruption is an error, never evidence that a session is stale.
    pub fn batch_proof_current(
        &self,
        proofs: &[AttestedIdentityProof],
    ) -> Result<Vec<bool>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let mut current = Vec::with_capacity(proofs.len());
        for expected in proofs {
            match resolve_proof_conn(&tx, expected) {
                Ok((_, proof)) => current.push(proof == *expected),
                Err(ManagedStoreError::AttestedIdentityDenied) => current.push(false),
                Err(error) => return Err(error),
            }
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(current)
    }

    /// What a command-import request names about its caller, read in one
    /// transaction: the stored principal's kind, display name and email, the
    /// label of the agent token the call used, and the namespace and name of
    /// the trusted username binding it asserted.
    pub(crate) fn command_caller(
        &self,
        principal_id: &str,
        token_id: Option<&str>,
        username_binding_id: Option<&str>,
    ) -> Result<CommandCallerRecord, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let principal = principal_by_id_without_groups(&tx, principal_id)?;
        let token_label = token_id
            .map(|token_id| {
                let token = broker_token_by_id(&tx, token_id)?;
                if token.principal_id != principal_id {
                    return Err(ManagedStoreError::BrokerTokenNotFound);
                }
                Ok(token.name)
            })
            .transpose()?;
        let username = username_binding_id
            .map(|binding_id| {
                username_binding_conn(&tx, principal_id, binding_id)
                    .map(|binding| (binding.namespace, binding.username))
            })
            .transpose()?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(CommandCallerRecord {
            kind: principal.kind,
            display_name: principal.display_name,
            email: principal.email,
            token_label,
            username,
        })
    }
}

/// The stored facts [`ManagedStore::command_caller`] reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandCallerRecord {
    pub kind: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub token_label: Option<String>,
    /// The asserted username binding's namespace and username.
    pub username: Option<(String, String)>,
}

fn validate_username_identity(namespace: &str, username: &str) -> Result<(), ManagedStoreError> {
    if !is_safe_identifier(namespace) {
        return Err(input_invalid("identity namespace is invalid"));
    }
    if !crate::is_valid_identity_username(username) {
        return Err(input_invalid("identity username is invalid"));
    }
    Ok(())
}

fn validate_expected_version(version: i64) -> Result<(), ManagedStoreError> {
    if version < 1 {
        return Err(input_invalid("expectedVersion must be positive"));
    }
    Ok(())
}

fn require_version(actual: i64, expected: i64) -> Result<(), ManagedStoreError> {
    if actual != expected {
        return Err(ManagedStoreError::IdentityVersionConflict);
    }
    Ok(())
}

fn require_human(conn: &Connection, principal: &str) -> Result<PrincipalRecord, ManagedStoreError> {
    let record = principal_by_id_without_groups(conn, principal)?;
    require_interactive_principal(&record)?;
    Ok(record)
}

pub(super) fn identity_access_conn(
    conn: &Connection,
    principal: &str,
) -> Result<IdentityAccessRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT principal_id, incarnation, paused, version, updated_at, updated_by
         FROM principal_identity_access WHERE principal_id=?1",
        [principal],
        |row| {
            Ok(IdentityAccessRecord {
                principal_id: row.get(0)?,
                incarnation: row.get(1)?,
                paused: row.get(2)?,
                version: row.get(3)?,
                updated_at: row.get(4)?,
                updated_by: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or_else(|| ManagedStoreError::SchemaInvalid("human identity access gate is missing".into()))
}

fn binding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsernameBindingRecord> {
    Ok(UsernameBindingRecord {
        binding_id: row.get(0)?,
        principal_id: row.get(1)?,
        namespace: row.get(2)?,
        username: row.get(3)?,
        enabled: row.get(4)?,
        read_only: row.get(5)?,
        version: row.get(6)?,
        created_at: row.get(7)?,
        created_by: row.get(8)?,
        updated_at: row.get(9)?,
        updated_by: row.get(10)?,
    })
}

fn username_binding_conn(
    conn: &Connection,
    principal: &str,
    binding_id: &str,
) -> Result<UsernameBindingRecord, ManagedStoreError> {
    conn.query_row(
        "SELECT binding_id, principal_id, namespace, username, enabled, read_only, version,
         created_at, created_by, updated_at, updated_by
         FROM principal_username_bindings WHERE binding_id=?1 AND principal_id=?2",
        params![binding_id, principal],
        binding_from_row,
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or(ManagedStoreError::IdentityBindingNotFound)
}

fn eligible_human(
    conn: &Connection,
    principal_id: &str,
) -> Result<(PrincipalRecord, IdentityAccessRecord), ManagedStoreError> {
    let principal = match principal_by_id_without_groups(conn, principal_id) {
        Ok(principal) => principal,
        Err(ManagedStoreError::PrincipalNotFound) => {
            return Err(ManagedStoreError::AttestedIdentityDenied);
        }
        Err(error) => return Err(error),
    };
    if principal.kind != "user" {
        return Err(ManagedStoreError::AttestedIdentityDenied);
    }
    // A missing gate is corruption even for an inactive human, never an unpaused default.
    let gate = identity_access_conn(conn, principal_id)?;
    if principal.status != "active" || gate.paused {
        return Err(ManagedStoreError::AttestedIdentityDenied);
    }
    Ok((principal, gate))
}

fn resolve_username_conn(
    conn: &Connection,
    namespace: &str,
    username: &str,
) -> Result<(PrincipalRecord, AttestedIdentityProof), ManagedStoreError> {
    let binding = conn
        .query_row(
            "SELECT binding_id, principal_id, namespace, username, enabled, read_only, version,
             created_at, created_by, updated_at, updated_by
             FROM principal_username_bindings WHERE namespace=?1 AND username=?2",
            params![namespace, username],
            binding_from_row,
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::AttestedIdentityDenied)?;
    if !binding.enabled {
        return Err(ManagedStoreError::AttestedIdentityDenied);
    }
    let (principal, gate) = eligible_human(conn, &binding.principal_id)?;
    let proof = AttestedIdentityProof {
        principal_id: binding.principal_id,
        gate_incarnation: gate.incarnation,
        gate_version: gate.version,
        read_only: binding.read_only,
        kind: AttestedIdentityKind::Username {
            namespace: binding.namespace,
            username: binding.username,
            binding_id: binding.binding_id,
            binding_version: binding.version,
        },
    };
    Ok((principal, proof))
}

fn resolve_fingerprint_conn(
    conn: &Connection,
    fingerprint: &str,
) -> Result<(PrincipalRecord, AttestedIdentityProof), ManagedStoreError> {
    let (principal_id, inventory_revision, enabled, read_only): (String, i64, bool, bool) = conn
        .query_row(
            "SELECT principal_id, revision, enabled, read_only
             FROM principal_identity_tokens WHERE fingerprint=?1",
            [fingerprint],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::AttestedIdentityDenied)?;
    // A disabled token keeps its secret but resolves like an unknown fingerprint.
    if !enabled {
        return Err(ManagedStoreError::AttestedIdentityDenied);
    }
    let (principal, gate) = eligible_human(conn, &principal_id)?;
    let proof = AttestedIdentityProof {
        principal_id,
        gate_incarnation: gate.incarnation,
        gate_version: gate.version,
        read_only,
        kind: AttestedIdentityKind::Fingerprint {
            fingerprint: fingerprint.to_owned(),
            inventory_revision,
        },
    };
    Ok((principal, proof))
}

fn resolve_proof_conn(
    conn: &Connection,
    proof: &AttestedIdentityProof,
) -> Result<(PrincipalRecord, AttestedIdentityProof), ManagedStoreError> {
    match &proof.kind {
        AttestedIdentityKind::Username {
            namespace,
            username,
            ..
        } => resolve_username_conn(conn, namespace, username),
        AttestedIdentityKind::Fingerprint { fingerprint, .. } => {
            resolve_fingerprint_conn(conn, fingerprint)
        }
    }
}

fn with_membership(
    conn: &Connection,
    mut principal: PrincipalRecord,
    proof: AttestedIdentityProof,
) -> Result<ResolvedAttestedIdentity, ManagedStoreError> {
    let membership =
        effective_membership_at_conn(conn, &principal.principal_id, &normalized_now_string())?;
    principal.groups = membership.groups;
    Ok(ResolvedAttestedIdentity {
        principal,
        policy_groups: membership.policy_groups,
        proof,
    })
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
    for migration in MANAGED_STORE_MIGRATIONS {
        expected
            .execute_batch(migration.sql)
            .map_err(sql_unavailable)?;
        if migration.version == MANAGED_STORE_TRUSTED_USER_IDENTITY_VERSION {
            break;
        }
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_integrity(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

/// The identity-token row invariant of `029_identity_access_path_controls`:
/// exactly one row for every human (rows for non-humans fail
/// [`check_integrity`]). It applies only from that version, so the historical
/// validators, which run before its backfill, keep using [`check_integrity`]
/// alone.
pub(super) fn check_identity_token_rows(conn: &Connection) -> Result<(), ManagedStoreError> {
    let missing: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals p LEFT JOIN principal_identity_tokens t
               ON t.principal_id=p.principal_id WHERE p.kind='user' AND t.principal_id IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if missing {
        return Err(identity_tokens::missing_row());
    }
    Ok(())
}

pub(super) fn check_integrity(conn: &Connection) -> Result<(), ManagedStoreError> {
    let invalid: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals p LEFT JOIN principal_identity_access a
           ON a.principal_id=p.principal_id WHERE p.kind='user' AND a.principal_id IS NULL)
         OR EXISTS(SELECT 1 FROM principal_identity_access a JOIN principals p
           ON p.principal_id=a.principal_id WHERE p.kind<>'user')
         OR EXISTS(SELECT 1 FROM principal_username_bindings b JOIN principals p
           ON p.principal_id=b.principal_id WHERE p.kind<>'user')
         OR EXISTS(SELECT 1 FROM principal_identity_tokens t JOIN principals p
           ON p.principal_id=t.principal_id WHERE p.kind<>'user')",
            [],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if invalid {
        return Err(ManagedStoreError::SchemaInvalid(
            "attested identity records require complete human gate coverage".into(),
        ));
    }
    let mut statement = conn
        .prepare("SELECT namespace, username FROM principal_username_bindings")
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (namespace, username) = row.map_err(sql_unavailable)?;
        if !is_safe_identifier(&namespace) || !crate::is_valid_identity_username(&username) {
            return Err(ManagedStoreError::SchemaInvalid(
                "username binding identity is invalid".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(read_only: bool, kind: AttestedIdentityKind) -> AttestedIdentityProof {
        AttestedIdentityProof {
            principal_id: "alice".into(),
            gate_incarnation: "incarnation".into(),
            gate_version: 1,
            read_only,
            kind,
        }
    }

    #[test]
    fn read_only_takes_part_in_proof_equality_and_session_binding() {
        for kind in [
            AttestedIdentityKind::Username {
                namespace: "linux".into(),
                username: "alice".into(),
                binding_id: Uuid::new_v4().to_string(),
                binding_version: 1,
            },
            AttestedIdentityKind::Fingerprint {
                fingerprint: "sha256:00".into(),
                inventory_revision: 1,
            },
        ] {
            let full = proof(false, kind.clone());
            let read_only = proof(true, kind);
            assert!(!full.read_only() && read_only.read_only());
            assert_ne!(full, read_only);
            assert_ne!(full.session_binding(), read_only.session_binding());
            assert!(
                read_only
                    .session_binding()
                    .starts_with(b"agent-access/attested-identity/v2")
            );
        }
    }
}
