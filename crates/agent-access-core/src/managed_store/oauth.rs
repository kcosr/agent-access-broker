//! Authenticated, typed OAuth slot snapshots. All family/cache/flow changes are one commit.
use super::*;
use crate::oauth::{OAuthBinding, OAuthError, OAuthManagementAdmission, SlotState};

fn aad(owner: &str, registration: &str, generation: &str, fingerprint: &str, key: &str) -> Vec<u8> {
    serde_json::to_vec(&(
        "broker-oauth-slot",
        1,
        owner,
        registration,
        generation,
        fingerprint,
        key,
    ))
    .expect("string tuple")
}

fn encrypt(
    ring: &CredentialKeyRing,
    owner: &str,
    registration: &str,
    state: &SlotState,
    key: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let plaintext =
        serde_json::to_vec(state).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    encrypt_plaintext(
        ring,
        (owner, registration),
        (&state.generation, &state.config_fingerprint),
        &plaintext,
        key,
    )
}

fn encrypt_plaintext(
    ring: &CredentialKeyRing,
    (owner, registration): (&str, &str),
    (generation, fingerprint): (&str, &str),
    plaintext: &[u8],
    key: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let key_bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    if plaintext.len() > 1024 * 1024 - 16 {
        return Err(ManagedStoreError::CredentialEncryptFailed);
    }
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(owner, registration, generation, fingerprint, key),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: key.into(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

struct Row {
    owner: String,
    registration: String,
    generation: String,
    fingerprint: String,
    key: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        owner: r.get(0)?,
        registration: r.get(1)?,
        generation: r.get(2)?,
        fingerprint: r.get(3)?,
        key: r.get(4)?,
        nonce: r.get(5)?,
        ciphertext: r.get(6)?,
    })
}
fn decrypt(ring: &CredentialKeyRing, row: &Row) -> Result<SlotState, ManagedStoreError> {
    let key = ring
        .keys
        .get(&row.key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key.clone()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let nonce: [u8; 12] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &row.ciphertext,
                aad: &aad(
                    &row.owner,
                    &row.registration,
                    &row.generation,
                    &row.fingerprint,
                    &row.key,
                ),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let state: SlotState =
        serde_json::from_slice(&plain).map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    if state.generation != row.generation || state.config_fingerprint != row.fingerprint {
        return Err(ManagedStoreError::CredentialDecryptFailed);
    }
    Ok(state)
}
/// Rewrites a stored slot's plaintext JSON in place, under the same
/// generation and fingerprint, as an earlier version might have stored it.
#[cfg(test)]
pub(crate) fn edit_stored_slot_json(
    store: &ManagedStore,
    ring: &CredentialKeyRing,
    owner: &str,
    registration: &str,
    edit: impl FnOnce(&mut serde_json::Value),
) {
    let conn = store.connection.lock().unwrap();
    let row = conn
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM oauth_slots WHERE owner_principal_id=?1 AND registration_id=?2"
            ),
            params![owner, registration],
            from_row,
        )
        .unwrap();
    let mut state = serde_json::to_value(decrypt(ring, &row).unwrap()).unwrap();
    edit(&mut state);
    let encrypted = encrypt_plaintext(
        ring,
        (owner, registration),
        (&row.generation, &row.fingerprint),
        &serde_json::to_vec(&state).unwrap(),
        &row.key,
    )
    .unwrap();
    conn.execute(
        "UPDATE oauth_slots SET nonce=?3, ciphertext=?4 WHERE owner_principal_id=?1 AND registration_id=?2",
        params![owner, registration, encrypted.nonce, encrypted.ciphertext],
    )
    .unwrap();
}

const COLUMNS: &str =
    "owner_principal_id,registration_id,generation,config_fingerprint,key_id,nonce,ciphertext";
fn read(
    conn: &Connection,
    ring: &CredentialKeyRing,
    owner: &str,
    registration: &str,
) -> Result<Option<SlotState>, ManagedStoreError> {
    let row = conn.query_row(&format!("SELECT {COLUMNS} FROM oauth_slots WHERE owner_principal_id=?1 AND registration_id=?2"),params![owner,registration],from_row)
        .optional().map_err(sql_unavailable)?;
    row.map(|r| decrypt(ring, &r)).transpose()
}
fn write(
    conn: &Connection,
    ring: &CredentialKeyRing,
    owner: &str,
    registration: &str,
    state: &SlotState,
) -> Result<(), ManagedStoreError> {
    let encrypted = encrypt(ring, owner, registration, state, ring.active_key_id())?;
    conn.execute("INSERT INTO oauth_slots(owner_principal_id,registration_id,generation,config_fingerprint,payload_version,key_id,nonce,ciphertext,updated_at,discovery_revision) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9) ON CONFLICT(owner_principal_id,registration_id) DO UPDATE SET generation=excluded.generation,config_fingerprint=excluded.config_fingerprint,key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=excluded.updated_at,discovery_revision=excluded.discovery_revision",
        params![owner,registration,state.generation,state.config_fingerprint,encrypted.key_id,encrypted.nonce,encrypted.ciphertext,now_string(),state.discovery_revision()]).map_err(sql_unavailable)?;
    Ok(())
}

pub(crate) fn check_session(
    conn: &Connection,
    owner: &str,
    session: &str,
) -> Result<(), OAuthError> {
    require_self_service(conn, owner).map_err(|error| match error {
        ManagedStoreError::SelfServiceDisabled => OAuthError::SelfServiceDisabled,
        _ => OAuthError::Principal,
    })?;
    let allowed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM browser_sessions s JOIN broker_tokens t ON t.token_id=s.token_id JOIN principal_login_methods l ON l.login_method_id=s.login_method_id WHERE s.token_id=?1 AND s.principal_id=?2 AND t.principal_id=?2 AND t.token_class IN ('user_manage','admin') AND t.revoked_at IS NULL AND t.paused_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?3) AND l.status='active' AND s.password_change_required=0)",params![session,owner,normalized_now_string()],|r|r.get(0)).map_err(|_|OAuthError::Storage)?;
    if !allowed {
        return Err(OAuthError::InvalidFlow);
    }
    Ok(())
}

/// Called only with the slot transaction held. The caller loads the currently
/// published runtime here, never a runtime retained when consent started.
///
/// Consent is admitted for the registration: at least one current consumer
/// of a credential connection that selects `binding` for the owner's
/// current kind must admit the owner, under current runtime policy and the
/// transaction's grants and group membership. A native consumer admits
/// through an active `per_user` grant. An imported consumer counts only at
/// the version recorded when the flow started (its fence), with an allowed
/// destination, and admits through a grant or its service-keyed
/// administrator-discovery admission. A connection rebound to another
/// registration or profile, or a flow naming a service that no longer
/// consumes the registration, is stale.
pub(crate) fn check_admission(
    conn: &Connection,
    owner: &str,
    admission: &OAuthManagementAdmission,
    binding: &OAuthBinding,
    runtime: &crate::BrokerRuntime,
) -> Result<(), OAuthError> {
    let owner_kind = super::principal_kind_at_conn(conn, owner).map_err(|_| OAuthError::Storage)?;
    let credentials = runtime.effective_credentials();
    let mut consumers = Vec::new();
    for (id, connection) in &credentials.connections {
        let crate::Selection::OAuth(oauth) = crate::select(connection, owner_kind) else {
            continue;
        };
        if oauth.registration != binding.registration {
            continue;
        }
        if oauth.binding() != *binding {
            return Err(OAuthError::Stale);
        }
        consumers.extend(credentials.connection_consumers(id));
    }
    if consumers.is_empty() {
        return Err(OAuthError::Stale);
    }
    if let Some(imported) = &admission.imported_service
        && !consumers.contains(&imported.as_str())
    {
        return Err(OAuthError::Stale);
    }
    let mut fenced = false;
    for service in consumers {
        if let Some(record) = runtime.imported_catalog().service(service) {
            let current = admission.imported_versions.get(service) == Some(&record.version)
                && runtime
                    .require_import_destination(&record.definition)
                    .is_ok()
                && super::imported_store::oauth_admission_version(conn, service, record.version)
                    .map_err(|_| OAuthError::Storage)?;
            if !current {
                fenced = true;
                continue;
            }
            if runtime
                .has_per_user_setup_grant_at_conn(conn, owner, service)
                .map_err(|_| OAuthError::Storage)?
                || super::imported_store::admin_oauth_admission(conn, owner, service)
                    .map_err(|_| OAuthError::Storage)?
            {
                return Ok(());
            }
        } else if runtime
            .has_per_user_setup_grant_at_conn(conn, owner, service)
            .map_err(|_| OAuthError::Storage)?
        {
            return Ok(());
        }
    }
    Err(if fenced {
        OAuthError::Stale
    } else {
        OAuthError::SetupDenied
    })
}
fn active(conn: &Connection, owner: &str) -> Result<(), OAuthError> {
    let p = principal_by_id(conn, owner).map_err(|_| OAuthError::Principal)?;
    if p.status != "active" || p.kind != "user" {
        return Err(OAuthError::Principal);
    }
    Ok(())
}

impl ManagedStore {
    pub(crate) fn oauth_update<T>(
        &self,
        ring: &CredentialKeyRing,
        owner: &str,
        registration: &str,
        configuration: &str,
        change: impl FnOnce(&Connection, Option<SlotState>) -> Result<(SlotState, T), OAuthError>,
    ) -> Result<T, OAuthError> {
        let mut conn = self.connection.lock().map_err(|_| OAuthError::Storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OAuthError::Storage)?;
        check_configuration(&tx, registration, configuration)?;
        active(&tx, owner)?;
        let current = read(&tx, ring, owner, registration)?;
        let (next, result) = change(&tx, current)?;
        write(&tx, ring, owner, registration, &next)?;
        tx.commit().map_err(|_| OAuthError::Storage)?;
        Ok(result)
    }
    pub(crate) fn oauth_read(
        &self,
        ring: &CredentialKeyRing,
        owner: &str,
        registration: &str,
        configuration: &str,
    ) -> Result<Option<SlotState>, OAuthError> {
        let conn = self.connection.lock().map_err(|_| OAuthError::Storage)?;
        check_configuration(&conn, registration, configuration)?;
        active(&conn, owner)?;
        Ok(read(&conn, ring, owner, registration)?)
    }
    pub(crate) fn oauth_reconcile(
        &self,
        ring: &CredentialKeyRing,
        registrations: &BTreeMap<String, (String, String)>,
    ) -> Result<(), OAuthError> {
        let mut conn = self.connection.lock().map_err(|_| OAuthError::Storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OAuthError::Storage)?;
        tx.execute("DELETE FROM oauth_registrations", [])
            .map_err(|_| OAuthError::Storage)?;
        for (id, (fingerprint, _)) in registrations {
            tx.execute(
                "INSERT INTO oauth_registrations(registration_id,fingerprint) VALUES(?1,?2)",
                params![id, fingerprint],
            )
            .map_err(|_| OAuthError::Storage)?;
        }
        let rows = {
            let mut statement = tx
                .prepare(&format!("SELECT {COLUMNS} FROM oauth_slots"))
                .map_err(|_| OAuthError::Storage)?;
            collect_rows(
                statement
                    .query_map([], from_row)
                    .map_err(|_| OAuthError::Storage)?,
            )?
        };
        let mut events = Vec::new();
        for row in rows {
            if registrations.get(&row.registration).map(|v| &v.0) != Some(&row.fingerprint) {
                events.push((
                    row.owner.clone(),
                    row.registration.clone(),
                    "configuration_invalidated",
                ));
                // Deleting the slot also deletes every flow/attempt ID. Late jobs cannot install without a matching ID.
                tx.execute(
                    "DELETE FROM oauth_slots WHERE owner_principal_id=?1 AND registration_id=?2",
                    params![row.owner, row.registration],
                )
                .map_err(|_| OAuthError::Storage)?;
            } else {
                let mut state = decrypt(ring, &row)?;
                let revision = &registrations[&row.registration].1;
                if state.credential_revision != *revision {
                    events.push((
                        row.owner.clone(),
                        row.registration.clone(),
                        "application_credential_rotated",
                    ));
                    state.reconcile_credential(revision);
                    write(&tx, ring, &row.owner, &row.registration, &state)?;
                }
            }
        }
        tx.commit().map_err(|_| OAuthError::Storage)?;
        for (owner, registration, outcome) in events {
            tracing::info!(target:"agent_access_core::oauth",event="activation_reconciliation",owner,registration,outcome);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_fixture() -> (tempfile::TempDir, ManagedStore, CredentialKeyRing) {
    let dir = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: dir.path().join("oauth.sqlite").display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let ring = CredentialKeyRing {
        active_key: "one".into(),
        keys: Arc::new(BTreeMap::from([
            ("one".into(), [1u8; 32]),
            ("two".into(), [2u8; 32]),
        ])),
    };
    {
        let conn = store.connection.lock().unwrap();
        conn.execute_batch(r#"INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled) VALUES('user','user','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','user',1);
            INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled) VALUES('admin','user','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','admin',0);
            INSERT INTO principal_login_methods(login_method_id,principal_id,method,status,password_hash_phc,created_at,updated_at,created_by,updated_by) VALUES('login','user','local_password','active','unused-test-password-hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','admin');
            INSERT INTO broker_tokens(token_id,token_hash,principal_id,name,token_class,scopes_json,created_at,created_by) VALUES('session','session-hash','user','browser','user_manage','[]','2026-01-01T00:00:00Z','admin');
            INSERT INTO browser_sessions(token_id,principal_id,login_method,login_method_id,auth_time,created_at) VALUES('session','user','local_password','login','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
            INSERT INTO policy_grants(grant_id,grant_order,service,actions_json,resources_json,credential_mode,status,version,created_at,created_by,updated_at,updated_by) VALUES('oauth','0','oauth_stub','["account.view"]','{"resourceIds":[],"resourceGroupIds":[]}','per_user','active',1,'2026-01-01T00:00:00Z','admin','2026-01-01T00:00:00Z','admin');
            INSERT INTO policy_grant_subjects VALUES('oauth','user:user',0);
            INSERT INTO policy_grant_contexts VALUES('oauth','default',0);"#).unwrap();
    }
    (dir, store, ring)
}

#[cfg(test)]
pub(crate) fn test_sql(store: &ManagedStore, sql: &str) {
    store.connection.lock().unwrap().execute_batch(sql).unwrap();
}

pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    let mut stmt = conn
        .prepare(&format!("SELECT {COLUMNS} FROM oauth_slots"))
        .map_err(sql_unavailable)?;
    let rows = stmt.query_map([], from_row).map_err(sql_unavailable)?;
    for row in rows {
        let row = row.map_err(sql_unavailable)?;
        let ring = ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key.clone()))?;
        decrypt(ring, &row)?;
    }
    Ok(())
}
pub(super) fn rewrap(
    conn: &mut Connection,
    ring: &CredentialKeyRing,
    from: &str,
    to: &str,
) -> Result<u64, ManagedStoreError> {
    let tx = conn.transaction().map_err(sql_unavailable)?;
    let rows = {
        let mut stmt = tx
            .prepare(&format!(
                "SELECT {COLUMNS} FROM oauth_slots WHERE key_id=?1"
            ))
            .map_err(sql_unavailable)?;
        collect_rows(stmt.query_map([from], from_row).map_err(sql_unavailable)?)?
    };
    let count = rows.len() as u64;
    for row in rows {
        let state = decrypt(ring, &row)?;
        let encrypted = encrypt(ring, &row.owner, &row.registration, &state, to)?;
        tx.execute("UPDATE oauth_slots SET key_id=?3,nonce=?4,ciphertext=?5 WHERE owner_principal_id=?1 AND registration_id=?2",params![row.owner,row.registration,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}

fn check_configuration(
    conn: &Connection,
    registration: &str,
    configuration: &str,
) -> Result<(), OAuthError> {
    let current: Option<String> = conn
        .query_row(
            "SELECT fingerprint FROM oauth_registrations WHERE registration_id=?1",
            [registration],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| OAuthError::Storage)?;
    if current.as_deref() != Some(configuration) {
        return Err(OAuthError::Stale);
    }
    Ok(())
}
impl ManagedStore {
    pub(crate) fn oauth_disable_all(&self) -> Result<(), OAuthError> {
        let mut conn = self.connection.lock().map_err(|_| OAuthError::Storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OAuthError::Storage)?;
        let affected = {
            let mut statement = tx
                .prepare("SELECT owner_principal_id,registration_id FROM oauth_slots")
                .map_err(|_| OAuthError::Storage)?;
            collect_rows(
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(|_| OAuthError::Storage)?,
            )?
        };
        tx.execute("DELETE FROM oauth_slots", [])
            .map_err(|_| OAuthError::Storage)?;
        tx.execute("DELETE FROM oauth_registrations", [])
            .map_err(|_| OAuthError::Storage)?;
        tx.commit().map_err(|_| OAuthError::Storage)?;
        for (owner, registration) in affected {
            tracing::info!(target:"agent_access_core::oauth",event="activation_reconciliation",owner,registration,outcome="oauth_disabled");
        }
        Ok(())
    }
}

/// The additive revision column leaves existing encrypted OAuth slots intact.
pub(super) fn validate_discovery_revision_structure(
    conn: &Connection,
) -> Result<(), ManagedStoreError> {
    super::imported_store::validate_structure_with_extension(
        conn,
        include_str!("oauth_discovery_revision.sql"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_aad_key_readiness_rewrap_and_principal_disable() {
        let (_dir, store, ring) = test_fixture();
        store
            .oauth_reconcile(
                &ring,
                &BTreeMap::from([("stub".into(), ("fingerprint".into(), "credential".into()))]),
            )
            .unwrap();
        let state = SlotState {
            generation: "generation".into(),
            config_fingerprint: "fingerprint".into(),
            credential_revision: "credential".into(),
            flows: BTreeMap::new(),
            connection: None,
        };
        store
            .oauth_update(&ring, "user", "stub", "fingerprint", |_, _| Ok((state, ())))
            .unwrap();
        assert!(store.active_credentials_need_key_ring().unwrap());
        assert_eq!(store.active_credential_key_ids().unwrap(), ["one"]);
        assert!(store.check_ready(None).is_err());
        store.check_ready(Some(&ring)).unwrap();
        let revision = || {
            store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT discovery_revision FROM oauth_slots WHERE owner_principal_id='user'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
        };
        let original_revision = revision();
        assert!(!original_revision.is_empty());
        assert_eq!(
            store
                .rewrap_credentials(&ring, "one", "two", "admin")
                .unwrap()
                .rewrapped,
            1
        );
        assert_eq!(store.active_credential_key_ids().unwrap(), ["two"]);
        assert_eq!(revision(), original_revision);
        store.check_ready(Some(&ring)).unwrap();
        // Altering unencrypted routing metadata must fail authenticated decryption.
        test_sql(&store, "UPDATE oauth_slots SET generation='attacker'");
        assert!(store.check_ready(Some(&ring)).is_err());
        test_sql(&store, "UPDATE oauth_slots SET generation='generation'");
        store.set_principal_enabled("user", false).unwrap();
        assert!(store.active_credential_key_ids().unwrap().is_empty());
        store.set_principal_enabled("user", true).unwrap();
        assert!(
            store
                .oauth_read(&ring, "user", "stub", "fingerprint")
                .unwrap()
                .is_none()
        );
    }
}
