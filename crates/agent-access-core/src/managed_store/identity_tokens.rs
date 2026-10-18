use super::*;

/// One human's identity-token row: whether a secret is configured and the
/// path settings, which secret writes keep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTokenMetadata {
    pub principal_id: String,
    pub configured: bool,
    pub enabled: bool,
    pub read_only: bool,
    pub revision: i64,
    pub updated_at: String,
}

/// A change to the identity token's path settings; absent fields keep their value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdentityTokenSettingsUpdate {
    pub enabled: Option<bool>,
    pub read_only: Option<bool>,
}

impl ManagedStore {
    pub fn configure_identity_token_encryption(&self, key_ring: Option<CredentialKeyRing>) {
        *self.identity_key_ring.lock().unwrap() = key_ring;
    }

    /// Completes a new human's row, which the creation trigger made: with a
    /// key ring, a generated secret is written into it.
    pub(super) fn initialize_identity_token(
        &self,
        conn: &Connection,
        principal: &str,
        kind: &str,
    ) -> Result<(), ManagedStoreError> {
        if kind != "user" {
            return Ok(());
        }
        // Standalone store consumers opt into encrypted inventory through configuration.
        match self.identity_key_ring.lock().unwrap().as_ref() {
            Some(ring) => set_token(conn, ring, principal, &Uuid::new_v4().to_string()),
            None => require_row(conn, principal),
        }
    }

    pub fn identity_token_metadata(
        &self,
        principal: &str,
    ) -> Result<IdentityTokenMetadata, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        metadata(&conn, principal)
    }

    pub fn set_identity_token(
        &self,
        principal: &str,
        token: &str,
        ring: &CredentialKeyRing,
    ) -> Result<IdentityTokenMetadata, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_interactive_principal(&principal_by_id(&tx, principal)?)?;
        identity_access::identity_access_conn(&tx, principal)?;
        set_token(&tx, ring, principal, token)?;
        let result = metadata(&tx, principal)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    pub fn reveal_identity_token(
        &self,
        principal: &str,
        ring: &CredentialKeyRing,
    ) -> Result<String, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        require_interactive_principal(&principal_by_id(&conn, principal)?)?;
        let (key, nonce, ciphertext): (String, Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT key_id, nonce, ciphertext FROM principal_identity_tokens WHERE principal_id=?1 AND fingerprint IS NOT NULL", [principal],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
            .optional().map_err(sql_unavailable)?.ok_or_else(|| input_invalid("identity token is not configured"))?;
        decrypt(ring, principal, &key, &nonce, &ciphertext)
    }

    pub fn remove_identity_token(
        &self,
        principal: &str,
    ) -> Result<IdentityTokenMetadata, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_interactive_principal(&principal_by_id(&tx, principal)?)?;
        identity_access::identity_access_conn(&tx, principal)?;
        let changed = tx
            .execute(
                "UPDATE principal_identity_tokens SET fingerprint=NULL, key_id=NULL, nonce=NULL,
                 ciphertext=NULL, revision=revision+1, updated_at=?2 WHERE principal_id=?1",
                params![principal, now_string()],
            )
            .map_err(sql_unavailable)?;
        require_updated(changed)?;
        let result = metadata(&tx, principal)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    /// Changes the token's path settings, never its secret. A change advances
    /// the revision once, which ends fingerprint sessions; a no-op writes
    /// nothing. Returns the metadata before and after, read in the transaction.
    pub fn update_identity_token_settings(
        &self,
        principal: &str,
        update: IdentityTokenSettingsUpdate,
        expected_revision: i64,
    ) -> Result<(IdentityTokenMetadata, IdentityTokenMetadata), ManagedStoreError> {
        validate_principal_id(principal)?;
        if update.enabled.is_none() && update.read_only.is_none() {
            return Err(input_invalid(
                "identity token update requires enabled or readOnly",
            ));
        }
        if expected_revision < 1 {
            return Err(input_invalid("expectedRevision must be positive"));
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_interactive_principal(&principal_by_id(&tx, principal)?)?;
        identity_access::identity_access_conn(&tx, principal)?;
        let before = metadata(&tx, principal)?;
        if before.revision != expected_revision {
            return Err(ManagedStoreError::IdentityVersionConflict);
        }
        let enabled = update.enabled.unwrap_or(before.enabled);
        let read_only = update.read_only.unwrap_or(before.read_only);
        if (enabled, read_only) != (before.enabled, before.read_only) {
            let changed = tx
                .execute(
                    "UPDATE principal_identity_tokens SET enabled=?2, read_only=?3,
                     revision=revision+1, updated_at=?4 WHERE principal_id=?1",
                    params![principal, enabled, read_only, now_string()],
                )
                .map_err(sql_unavailable)?;
            require_updated(changed)?;
        }
        let after = metadata(&tx, principal)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok((before, after))
    }

    pub fn resolve_identity_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<(PrincipalRecord, Vec<String>), ManagedStoreError> {
        let resolved = self.resolve_identity_fingerprint_with_proof(fingerprint)?;
        Ok((resolved.principal, resolved.policy_groups))
    }
}

fn metadata(
    conn: &Connection,
    principal: &str,
) -> Result<IdentityTokenMetadata, ManagedStoreError> {
    require_interactive_principal(&principal_by_id(conn, principal)?)?;
    conn.query_row(
        "SELECT fingerprint IS NOT NULL, enabled, read_only, revision, updated_at
         FROM principal_identity_tokens WHERE principal_id=?1",
        [principal],
        |row| {
            Ok(IdentityTokenMetadata {
                principal_id: principal.into(),
                configured: row.get(0)?,
                enabled: row.get(1)?,
                read_only: row.get(2)?,
                revision: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)?
    .ok_or_else(missing_row)
}
/// Every human has exactly one row. A missing row is corruption, never a
/// not-configured default, and no operation recreates it.
pub(super) fn missing_row() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("human identity token inventory is missing".into())
}
fn require_row(conn: &Connection, principal: &str) -> Result<(), ManagedStoreError> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principal_identity_tokens WHERE principal_id=?1)",
            [principal],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if !exists {
        return Err(missing_row());
    }
    Ok(())
}
fn require_updated(changed: usize) -> Result<(), ManagedStoreError> {
    if changed == 0 {
        return Err(missing_row());
    }
    Ok(())
}
fn aad(principal: &str, key: &str) -> String {
    format!("aw-identity-token:v1:{}:{principal}:{key}", principal.len())
}
fn encrypt(
    ring: &CredentialKeyRing,
    principal: &str,
    key: &str,
    token: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let key_bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: aad(principal, key).as_bytes(),
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
    principal: &str,
    key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<String, ManagedStoreError> {
    let key_bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let value = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: aad(principal, key).as_bytes(),
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    String::from_utf8(value).map_err(|_| ManagedStoreError::CredentialDecryptFailed)
}
fn set_token(
    conn: &Connection,
    ring: &CredentialKeyRing,
    principal: &str,
    token: &str,
) -> Result<(), ManagedStoreError> {
    if token.len() < 32
        || token.len() > 4096
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(input_invalid(
            "identity token must be 32-4096 RFC 9110 token bytes",
        ));
    }
    let fingerprint = format!("sha256:{}", sha256_hex(token.as_bytes()));
    let encrypted = encrypt(ring, principal, ring.active_key_id(), token)?;
    // Only the secret columns change, so the path settings survive rotation.
    let changed = conn
        .execute(
            "UPDATE principal_identity_tokens SET fingerprint=?2, key_id=?3, nonce=?4,
             ciphertext=?5, revision=revision+1, updated_at=?6 WHERE principal_id=?1",
            params![
                principal,
                fingerprint,
                encrypted.key_id,
                encrypted.nonce,
                encrypted.ciphertext,
                now_string()
            ],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(ref e, _)
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                input_invalid("identity token is already assigned")
            }
            other => sql_unavailable(other),
        })?;
    require_updated(changed)
}
pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    let mut stmt=conn.prepare("SELECT principal_id,key_id,nonce,ciphertext,fingerprint FROM principal_identity_tokens WHERE fingerprint IS NOT NULL").map_err(sql_unavailable)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (p, k, n, c, h) = row.map_err(sql_unavailable)?;
        let ring = ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(k.clone()))?;
        let token = decrypt(ring, &p, &k, &n, &c)?;
        if format!("sha256:{}", sha256_hex(token.as_bytes())) != h {
            return Err(ManagedStoreError::CredentialDecryptFailed);
        }
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
        let mut stmt=tx.prepare("SELECT principal_id,nonce,ciphertext FROM principal_identity_tokens WHERE key_id=?1").map_err(sql_unavailable)?;
        collect_rows(
            stmt.query_map([from], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(sql_unavailable)?,
        )?
    };
    let count = rows.len() as u64;
    for (p, n, c) in rows {
        let raw = decrypt(ring, &p, from, &n, &c)?;
        let encrypted = encrypt(ring, &p, to, &raw)?;
        tx.execute("UPDATE principal_identity_tokens SET key_id=?2,nonce=?3,ciphertext=?4 WHERE principal_id=?1",params![p,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> (tempfile::TempDir, ManagedStore, CredentialKeyRing) {
        let dir = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let ring = CredentialKeyRing {
            active_key: "one".into(),
            keys: Arc::new(BTreeMap::from([
                ("one".into(), [1; 32]),
                ("two".into(), [2; 32]),
            ])),
        };
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: dir.path().join("store.sqlite").display().to_string(),
                require_registered_principal_for_invocation: false,
                auto_migrate: true,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store.configure_identity_token_encryption(Some(ring.clone()));
        (dir, store, ring)
    }
    fn user(store: &ManagedStore, id: &str) {
        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: id.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    #[test]
    fn generated_inventory_is_uuid_encrypted_unique_and_pause_survives_rotation() {
        let (_dir, store, ring) = store();
        user(&store, "alice");
        user(&store, "bob");
        let raw = store.reveal_identity_token("alice", &ring).unwrap();
        let uuid = Uuid::parse_str(&raw).unwrap();
        assert_eq!(uuid.get_version_num(), 4);
        assert_eq!(uuid.to_string(), raw);
        let hash = format!("sha256:{}", sha256_hex(raw.as_bytes()));
        assert_eq!(
            store
                .resolve_identity_fingerprint(&hash)
                .unwrap()
                .0
                .principal_id,
            "alice"
        );
        assert!(store.set_identity_token("bob", &raw, &ring).is_err());
        assert!(
            !serde_json::to_string(&store.identity_token_metadata("alice").unwrap())
                .unwrap()
                .contains(&raw)
        );
        assert!(!format!("{:?}", store).contains(&raw));
        let version = store.identity_access("alice").unwrap().version;
        store
            .set_identity_access_paused("alice", true, version, "admin")
            .unwrap();
        assert!(store.resolve_identity_fingerprint(&hash).is_err());
        store.remove_identity_token("alice").unwrap();
        store.set_identity_token("alice", &raw, &ring).unwrap();
        assert!(store.identity_access("alice").unwrap().paused);
        assert!(store.resolve_identity_fingerprint(&hash).is_err());
        let version = store.identity_access("alice").unwrap().version;
        store
            .set_identity_access_paused("alice", false, version, "admin")
            .unwrap();
        assert!(store.resolve_identity_fingerprint(&hash).is_ok());
        store.set_principal_enabled("alice", false).unwrap();
        assert!(store.resolve_identity_fingerprint(&hash).is_err());
        store.set_principal_enabled("alice", true).unwrap();
        assert!(store.resolve_identity_fingerprint(&hash).is_ok());
        let conn = store.connection.lock().unwrap();
        let cipher: Vec<u8> = conn
            .query_row(
                "SELECT ciphertext FROM principal_identity_tokens WHERE principal_id='alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!cipher.windows(raw.len()).any(|w| w == raw.as_bytes()));
    }
    #[test]
    fn removal_survives_existing_principal_update_and_rewrap_preserves_lookup() {
        let (_dir, store, ring) = store();
        user(&store, "alice");
        let raw = store.reveal_identity_token("alice", &ring).unwrap();
        assert_eq!(
            store
                .rewrap_credentials(&ring, "one", "two", "admin")
                .unwrap()
                .rewrapped,
            1
        );
        let ring2 = CredentialKeyRing {
            active_key: "two".into(),
            keys: Arc::new(BTreeMap::from([("two".into(), [2; 32])])),
        };
        store.check_ready(Some(&ring2)).unwrap();
        assert_eq!(store.reveal_identity_token("alice", &ring2).unwrap(), raw);
        assert!(
            store
                .check_ready(Some(&CredentialKeyRing {
                    active_key: "one".into(),
                    keys: Arc::new(BTreeMap::from([("one".into(), [1; 32])]))
                }))
                .is_err()
        );
        store.remove_identity_token("alice").unwrap();
        store
            .create_or_update_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        assert!(!store.identity_token_metadata("alice").unwrap().configured);
    }
    #[test]
    fn import_validates_exact_bearer_bytes() {
        let (_dir, store, ring) = store();
        user(&store, "alice");
        for invalid in [
            "short".into(),
            format!("{}\n", Uuid::new_v4()),
            format!("{}=", Uuid::new_v4()),
            "x".repeat(4097),
        ] {
            assert!(store.set_identity_token("alice", &invalid, &ring).is_err());
        }
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn baseline_upgrade_preserves_users_and_does_not_assign_existing_tokens() {
        let dir = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.path().join("store.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(MANAGED_STORE_BASELINE_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(?1,?2,?3)",
            params![
                MANAGED_STORE_BASELINE_SCHEMA_VERSION,
                MANAGED_STORE_BASELINE_CHECKSUM,
                now_string()
            ],
        )
        .unwrap();
        conn.execute("INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by) VALUES('legacy','user','active',?1,?1,'admin')",[now_string()]).unwrap();
        drop(conn);
        let mut config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: false,
        };
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Startup),
            Err(ManagedStoreError::MigrationRequired)
        ));
        config.auto_migrate = true;
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload),
            Err(ManagedStoreError::MigrationRequired)
        ));
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(store.principal_count().unwrap(), 1);
        assert_eq!(store.principal("legacy").unwrap().kind, "user");
        assert!(!store.identity_token_metadata("legacy").unwrap().configured);
    }
}
