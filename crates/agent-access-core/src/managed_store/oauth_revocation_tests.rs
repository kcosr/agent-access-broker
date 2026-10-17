//! Pending OAuth revocation storage: migration `028_oauth_revocations` from
//! a schema-027 store, its structural validator and ledger row, key
//! readiness, the used-key inventory, rewrap, and the frozen encrypted
//! record.
use super::*;
use crate::oauth::revocation::{KeptFamily, MemberOutcome, MemberType, RevocationMember};

// A pending revocation as the first release of `028_oauth_revocations`
// wrote it under key `golden` (`[9; 32]`). Upgrades must keep decrypting
// it, so its columns, AAD inputs and encoding, the cause and state
// spellings and the payload encoding are a persisted contract. Adapt
// assertions to a changed API, but never regenerate this vector to make a
// change pass.
const GOLDEN_FAMILY: &str = "9a5e2b8f-3c71-4d0a-8e6b-1f2c3d4e5f60";
const GOLDEN_ATTEMPT: &str = "4b7d2c9e-8f1a-4e3b-9c6d-2a5f8e1b7c30";
const GOLDEN_REVOCATION: (&str, &str, &str, &str) = (
    "5d1c3c1e-6c0f-4f0e-9b1a-6a3f2f0d8c41",
    "d11c02781d5768a3b87793792b940453b12faf457979621c595b76cb8873765d",
    "42bf499aafd9be8ba40c40ab",
    "82b55d94f8cc2b0606fe2df3e0e57c9b9be73c24750607dcb04cac5938579a38c6801bdab46dac9fd24611ec7028eb61fe77b16f9cc0b13429888055ff4526a6ea1d2b8fd8e23a3bef2dad859e769e80c340e5885e48625b2cf2b123ee521fbc6d28663a98eab2fe6939747b816f710bf33f69b4287f32c8f307554e0e78de05ae5cdfe75015987570ffdace2be1efdb66dbefdf36704af3f5d66f206e639be2522b652b0e0cdbf66e316eb8b85b061a5d44677d7104f2d7eee63719604a2dee1b9b4828d0a366d008307a4c4d4443c4191da9dac7189541b356ccc70aff6acb1cff77cd94fa1cdcf80ff647a8b0268ba4c296ca6fa3ea55802f1de6228967bb44861151f01ea7ca2e2535c4879cc2612aa40f8360c1fb775828891bdee8516025c0cfb070d5bf8918062f84dacd4cd4f96c46b435b57b206f02513f084de652",
);

fn golden_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn golden_ring() -> CredentialKeyRing {
    CredentialKeyRing {
        active_key: "golden".into(),
        keys: Arc::new(BTreeMap::from([
            ("golden".into(), [9; 32]),
            ("next".into(), [10; 32]),
        ])),
    }
}

fn golden_material() -> RevocationMaterial {
    RevocationMaterial {
        members: vec![
            RevocationMember {
                token: "golden-refresh-token".into(),
                token_type: MemberType::RefreshToken,
                outcome: MemberOutcome::Pending,
                tries: 2,
                not_before: 1_792_000_120,
            },
            RevocationMember {
                token: "golden-access-token".into(),
                token_type: MemberType::AccessToken,
                outcome: MemberOutcome::Revoked,
                tries: 1,
                not_before: 1_791_999_990,
            },
        ],
        refresh_awaited_until: Some(1_792_000_000),
        unknown_successor: false,
    }
}

fn store_at(path: &Path, through: Option<&str>) -> ManagedStore {
    let config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: path.display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    };
    let migrations = match through {
        Some(version) => {
            let end = MANAGED_STORE_MIGRATIONS
                .iter()
                .position(|migration| migration.version == version)
                .unwrap()
                + 1;
            &MANAGED_STORE_MIGRATIONS[..end]
        }
        None => MANAGED_STORE_MIGRATIONS,
    };
    ManagedStore::open_with_catalog(
        &config,
        ManagedStoreOpenMode::Startup,
        ManagedStoreMigrationCatalog { migrations },
    )
    .unwrap()
}

fn private_dir() -> tempfile::TempDir {
    let temp = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn insert_golden(store: &ManagedStore) {
    let (id, fingerprint, nonce, ciphertext) = GOLDEN_REVOCATION;
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO oauth_revocations(revocation_id,owner_principal_id,registration_id,config_fingerprint,family_id,cause,state,refresh_attempt_id,due_at,created_at,updated_at,payload_version,key_id,nonce,ciphertext)
             VALUES(?1,'alice','gitlab',?2,?3,'disconnect','pending',?4,1792000001,'2026-10-16T00:00:00Z','2026-10-16T00:00:00Z',1,'golden',?5,?6)",
            params![
                id,
                fingerprint,
                GOLDEN_FAMILY,
                GOLDEN_ATTEMPT,
                golden_hex(nonce),
                golden_hex(ciphertext)
            ],
        )
        .unwrap();
}

fn assert_golden(row: &RevocationRow) {
    let (id, fingerprint, _, _) = GOLDEN_REVOCATION;
    assert_eq!(row.id, id);
    assert_eq!(row.owner, "alice");
    assert_eq!(row.registration, "gitlab");
    assert_eq!(row.fingerprint, fingerprint);
    assert_eq!(row.family_id, GOLDEN_FAMILY);
    assert_eq!(row.cause, RevocationCause::Disconnect);
    assert_eq!(row.state, RemoteRevocation::Pending);
    assert_eq!(row.refresh_attempt.as_deref(), Some(GOLDEN_ATTEMPT));
    assert_eq!(row.due_at, 1_792_000_001);
    let material = row.material.as_ref().unwrap();
    let expected = golden_material();
    assert_eq!(material.members.len(), 2);
    for (member, expected) in material.members.iter().zip(&expected.members) {
        assert_eq!(member.token, expected.token);
        assert_eq!(member.token_type, expected.token_type);
        assert_eq!(member.outcome, expected.outcome);
        assert_eq!(member.tries, expected.tries);
        assert_eq!(member.not_before, expected.not_before);
    }
    assert_eq!(material.refresh_awaited_until, Some(1_792_000_000));
    assert!(!material.unknown_successor);
    assert_eq!(material.state(), RemoteRevocation::Pending);
}

#[test]
fn golden_revocation_record_still_decrypts() {
    let temp = private_dir();
    let store = store_at(&temp.path().join("store.sqlite"), None);
    insert_golden(&store);
    let ring = golden_ring();
    let (id, fingerprint, _, _) = GOLDEN_REVOCATION;
    assert_eq!(
        String::from_utf8(aad(
            (id, "alice", "gitlab", fingerprint, GOLDEN_FAMILY),
            "disconnect",
            "golden"
        ))
        .unwrap(),
        format!(
            r#"["broker-oauth-revocation",1,"{id}","alice","gitlab","{fingerprint}","{GOLDEN_FAMILY}","disconnect","golden"]"#
        )
    );
    assert_golden(&store.oauth_revocation_read(&ring, id).unwrap().unwrap());
    store.check_ready(Some(&ring)).unwrap();
    // Every bound column is authenticated.
    for (column, value) in [
        ("owner_principal_id", "mallory"),
        ("registration_id", "other"),
        ("config_fingerprint", "changed"),
        ("family_id", "other-family"),
        ("cause", "superseded"),
    ] {
        test_sql_revocation(
            &store,
            &format!("UPDATE oauth_revocations SET {column}='{value}'"),
        );
        assert!(store.check_ready(Some(&ring)).is_err(), "{column}");
        test_sql_revocation(&store, "DELETE FROM oauth_revocations");
        insert_golden(&store);
    }
}

fn test_sql_revocation(store: &ManagedStore, sql: &str) {
    store.connection.lock().unwrap().execute_batch(sql).unwrap();
}

/// A store at schema 027 with OAuth slots and credentials upgrades to 028
/// with its rows unchanged and its ledger extended by one row; the new
/// table then holds and checks revocations.
#[test]
fn schema_027_upgrades_to_028_with_rows_unchanged() {
    let temp = private_dir();
    let path = temp.path().join("store.sqlite");
    let previous = store_at(&path, Some(MANAGED_STORE_COMMAND_IMPORTS_VERSION));
    let ring = golden_ring();
    let snapshot = |conn: &Connection| -> Vec<String> {
        let mut statement = conn
            .prepare("SELECT owner_principal_id||'|'||registration_id||'|'||generation||'|'||config_fingerprint||'|'||key_id||'|'||hex(nonce)||'|'||hex(ciphertext)||'|'||discovery_revision FROM oauth_slots ORDER BY 1")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let before = {
        let conn = previous.connection.lock().unwrap();
        conn.execute_batch(
            "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled) VALUES('alice','user','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','admin','user',1);
             INSERT INTO oauth_registrations(registration_id,fingerprint) VALUES('gitlab','fingerprint');
             INSERT INTO oauth_slots(owner_principal_id,registration_id,generation,config_fingerprint,payload_version,key_id,nonce,ciphertext,updated_at,discovery_revision)
               VALUES('alice','gitlab','generation','fingerprint',1,'golden',x'000102030405060708090a0b',x'00112233445566778899aabbccddeeff00','2026-01-01T00:00:00Z','revision');",
        )
        .unwrap();
        assert!(!sqlite_object_exists(&conn, "table", "oauth_revocations").unwrap());
        snapshot(&conn)
    };
    drop(previous);
    let ledger_before = migration_ledger(&path);
    assert_eq!(
        ledger_before.last().map(|row| row.0.as_str()),
        Some("027_command_imports")
    );

    let store = store_at(&path, None);
    assert!(store.migration_applied_this_open(MANAGED_STORE_OAUTH_REVOCATIONS_VERSION));
    let ledger = migration_ledger(&path);
    assert_eq!(&ledger[..ledger_before.len()], ledger_before.as_slice());
    assert_eq!(ledger.len(), MANAGED_STORE_MIGRATIONS.len());
    assert_eq!(
        &ledger[ledger_before.len()],
        &(
            "028_oauth_revocations".to_string(),
            sha256_hex(include_str!("oauth_revocations.sql").as_bytes())
        )
    );
    assert_eq!(
        store.status().unwrap().schema_version,
        MANAGED_STORE_SCHEMA_VERSION
    );
    let conn = store.connection.lock().unwrap();
    assert_eq!(snapshot(&conn), before);
    assert!(sqlite_object_exists(&conn, "table", "oauth_revocations").unwrap());
    // The constraints keep pending rows encrypted and finished rows empty,
    // and name a refresh attempt only while revocation is pending or
    // unconfirmed.
    for (state, attempt, material) in [
        ("pending", "NULL", "NULL,NULL,NULL,NULL"),
        (
            "revoked",
            "NULL",
            "1,'golden',x'000102030405060708090a0b',x'00112233445566778899aabbccddeeff'",
        ),
        ("pending", "NULL", "1,NULL,NULL,NULL"),
        ("unknown", "NULL", "NULL,NULL,NULL,NULL"),
        ("revoked", "'attempt'", "NULL,NULL,NULL,NULL"),
        ("failed", "'attempt'", "NULL,NULL,NULL,NULL"),
        ("unconfirmed", "''", "NULL,NULL,NULL,NULL"),
    ] {
        assert!(
            conn.execute(
                &format!(
                    "INSERT INTO oauth_revocations(revocation_id,owner_principal_id,registration_id,config_fingerprint,family_id,cause,state,refresh_attempt_id,due_at,created_at,updated_at,payload_version,key_id,nonce,ciphertext)
                     VALUES('00000000-0000-4000-8000-000000000000','alice','gitlab','fingerprint','family','disconnect','{state}',{attempt},0,'t','t',{material})"
                ),
                [],
            )
            .is_err(),
            "{state} {attempt} {material}"
        );
    }
    // A finished unconfirmed revocation may still name its attempt.
    conn.execute(
        "INSERT INTO oauth_revocations(revocation_id,owner_principal_id,registration_id,config_fingerprint,family_id,cause,state,refresh_attempt_id,due_at,created_at,updated_at)
         VALUES('00000000-0000-4000-8000-000000000000','alice','gitlab','fingerprint','family','refresh_uncertain','unconfirmed','attempt',0,'t','t')",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM oauth_revocations", []).unwrap();
    drop(conn);
    insert_golden(&store);
    assert_golden(
        &store
            .oauth_revocation_read(&ring, GOLDEN_REVOCATION.0)
            .unwrap()
            .unwrap(),
    );
    drop(store);
    // A fully migrated store is admitted again through its validator.
    store_at(&path, None);
}

fn migration_ledger(path: &Path) -> Vec<(String, String)> {
    let conn = Connection::open(path).unwrap();
    let mut statement = conn
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The 028 validator rejects a store whose revocation table drifted from
/// the migration.
#[test]
fn structural_validator_rejects_a_drifted_revocation_table() {
    for drift in [
        "DROP INDEX oauth_revocations_due",
        "DROP TABLE oauth_revocations; CREATE TABLE oauth_revocations(revocation_id TEXT PRIMARY KEY)",
    ] {
        let temp = private_dir();
        let path = temp.path().join("store.sqlite");
        drop(store_at(&path, None));
        Connection::open(&path)
            .unwrap()
            .execute_batch(drift)
            .unwrap();
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: path.display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        assert!(
            matches!(
                ManagedStore::open(&config, ManagedStoreOpenMode::Startup),
                Err(ManagedStoreError::SchemaInvalid(_))
            ),
            "{drift}"
        );
    }
}

/// Pending revocations join key readiness and the used-key inventory, and
/// rewrap moves them with their state, schedule and outcomes; finished ones
/// hold no key.
#[test]
fn revocations_join_key_readiness_inventory_and_rewrap() {
    let temp = private_dir();
    let store = store_at(&temp.path().join("store.sqlite"), None);
    let ring = golden_ring();
    assert!(store.active_credential_key_ids().unwrap().is_empty());
    insert_golden(&store);
    let finished = {
        let conn = store.connection.lock().unwrap();
        let mut material = golden_material();
        material.refresh_awaited_until = None;
        material.members.truncate(1);
        insert(
            &conn,
            &ring,
            NewRevocation {
                owner: "alice",
                registration: "gitlab",
                fingerprint: "fingerprint",
                cause: RevocationCause::PrincipalDisabled,
                family: KeptFamily {
                    family_id: "family".into(),
                    refresh_attempt: None,
                    material,
                },
                now: 5,
            },
        )
        .unwrap()
    };
    store
        .oauth_revocation_update(&ring, &finished, |row| {
            row.material.as_mut().unwrap().members[0].outcome = MemberOutcome::Revoked;
            let material = row.material.take().unwrap();
            row.state = material.state();
            row.due_at = 99;
        })
        .unwrap();
    assert_eq!(store.active_credential_key_ids().unwrap(), ["golden"]);
    assert!(store.active_credentials_need_key_ring().unwrap());
    assert!(store.check_ready(None).is_err());
    let without_golden = CredentialKeyRing {
        active_key: "next".into(),
        keys: Arc::new(BTreeMap::from([("next".into(), [10; 32])])),
    };
    assert!(store.check_ready(Some(&without_golden)).is_err());
    store.check_ready(Some(&ring)).unwrap();
    let mut states = store.oauth_revocation_states("alice", "gitlab").unwrap();
    states.sort_by_key(|state| state.as_str());
    assert_eq!(
        states,
        [RemoteRevocation::Pending, RemoteRevocation::Revoked]
    );
    assert_eq!(
        store
            .rewrap_credentials(&ring, "golden", "next", "admin")
            .unwrap()
            .rewrapped,
        1
    );
    assert_eq!(store.active_credential_key_ids().unwrap(), ["next"]);
    store.check_ready(Some(&without_golden)).unwrap();
    let row = store
        .oauth_revocation_read(&without_golden, GOLDEN_REVOCATION.0)
        .unwrap()
        .unwrap();
    assert_golden(&row);
    // The schedule and the finished row's answer are unchanged.
    let finished = store
        .oauth_revocation_read(&without_golden, &finished)
        .unwrap()
        .unwrap();
    assert!(finished.material.is_none());
    assert_eq!(finished.state, RemoteRevocation::Revoked);
    assert_eq!(finished.due_at, 99);
    assert_eq!(
        store.oauth_revocation_next_due().unwrap(),
        Some(1_792_000_001)
    );
    assert_eq!(
        store.oauth_revocations_due(1_792_000_001, 8).unwrap(),
        [GOLDEN_REVOCATION.0]
    );
    assert!(
        store
            .oauth_revocations_due(1_792_000_000, 8)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.oauth_revocations_prune(99).unwrap(), 1);
    assert_eq!(store.oauth_revocations_prune(99).unwrap(), 0);
}
