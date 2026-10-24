//! Microsoft membership renewal storage: migration
//! `031_oidc_membership_renewal` from a schema-030 store, its structural
//! validator and ledger row, the frozen encrypted record, key readiness, the
//! used-key inventory and rewrap, sign-in recording, evidence ordering by raw
//! `iat`, and the lifecycle events that delete rows.
use super::*;
use crate::microsoft_oidc::microsoft_oidc_nonce_sha256;
use serde_json::json;
use tempfile::TempDir;

const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const CLIENT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
const OTHER_CLIENT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb9";
const USER: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
const OTHER_USER: &str = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4";
const THIRD_USER: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc7";
const GROUP_A: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5";
const GROUP_B: &str = "ffffffff-ffff-4fff-8fff-fffffffffff6";

// A renewal record as the first release of `031_oidc_membership_renewal`
// wrote it under key `golden` (`[23; 32]`) with nonce GOLDEN_NONCE. Upgrades
// must keep decrypting it, so its columns, AAD inputs and encoding, the state
// and reason spellings and the payload encoding are a persisted contract.
// Adapt assertions to a changed API, but never regenerate this vector to make
// a change pass.
const GOLDEN_METHOD: &str = "7f3c9a2e-5b1d-4e8f-9a6c-3d2b1e0f4a57";
const GOLDEN_TOKEN_VERSION: &str = "2c6e8a41-9d3f-4b7a-8e15-6f0a9c3d7b28";
const GOLDEN_NONCE: &str = "0a1b2c3d4e5f60718293a4b5";
const GOLDEN_NONCE_SHA256: &str = "2wuvOk5iHptFXsDJbvpPlwE6rOkMzwRLcYx0htmEU9I";
const GOLDEN_PAYLOAD: &str = r#"{"refreshToken":"golden-microsoft-refresh-token","subject":"golden-pairwise-subject","audience":["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2","api://golden-resource"],"azp":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2","nonceSha256":"2wuvOk5iHptFXsDJbvpPlwE6rOkMzwRLcYx0htmEU9I","authTime":1792000000}"#;
const GOLDEN_CIPHERTEXT: &str = "f2faf55ba545eac3ffe4503eb5411e0eb23d4291be2b5e45bee533bfb591c4c80f7ce6b84c31c0aa4a6dd72104f741ce6bf88c7ba6b5f3467aa85f5656c1eb8238a24493c8aca2317d31dd9f10f685fe502655c573082ac77295e867aedeb9a0eef87fd2815cb82d579cef754d7b6b55f842473cfc05fcf5415d93626f923002475c6c01bccbba3ce2592d146cfce5ad7e9988404cb89fc750e963a36c8087b169ed8bd6c73b72b15bab4299c59cf31881db43bc9a173b5a2b68ade1f447676e097ec6dde68345917da4a5f5cd61f39fc2b7a3ef1f68960d90778eb2bfce43c28db666e7cdaf2195ec8a6a20001784c31cf192a5f7d65f5df0bdf6b8bbadca561f2044aea7aaee7941473421611ac76c9429d88c2fe5ef269199affb44e14bb71549e4a14d98b840f77677599f9e0029";

fn golden_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn ring() -> CredentialKeyRing {
    CredentialKeyRing {
        active_key: "golden".into(),
        keys: Arc::new(BTreeMap::from([
            ("golden".into(), [23; 32]),
            ("next".into(), [24; 32]),
        ])),
    }
}

fn next_only_ring() -> CredentialKeyRing {
    CredentialKeyRing {
        active_key: "next".into(),
        keys: Arc::new(BTreeMap::from([("next".into(), [24; 32])])),
    }
}

fn private_dir() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn config_at(path: &Path) -> ManagedStoreConfig {
    ManagedStoreConfig {
        kind: "sqlite".into(),
        path: path.display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    }
}

fn catalog_through(version: &str) -> ManagedStoreMigrationCatalog<'static> {
    let end = MANAGED_STORE_MIGRATIONS
        .iter()
        .position(|migration| migration.version == version)
        .unwrap();
    ManagedStoreMigrationCatalog {
        migrations: &MANAGED_STORE_MIGRATIONS[..=end],
    }
}

fn store_at(path: &Path, through: Option<&str>) -> ManagedStore {
    let catalog = match through {
        Some(version) => catalog_through(version),
        None => production_migration_catalog(),
    };
    ManagedStore::open_with_catalog(&config_at(path), ManagedStoreOpenMode::Startup, catalog)
        .unwrap()
}

fn sql(store: &ManagedStore, statements: &str) {
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch(statements)
        .unwrap();
}

fn subject(user_object_id: &str) -> String {
    format!("entra:v1:{TENANT}:{user_object_id}")
}

fn reconcile(
    store: &ManagedStore,
    enabled: bool,
    membership_renewal: bool,
    client_id: &str,
    fingerprint: &str,
    ttl_seconds: u64,
) -> OidcProviderStateRecord {
    store
        .reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
            tenant_id: TENANT.into(),
            client_id: client_id.into(),
            enabled,
            config_fingerprint: fingerprint.into(),
            external_membership_ttl_seconds: ttl_seconds,
            membership_renewal,
            invalidate_existing_evidence: false,
            actor: "system".into(),
        })
        .unwrap()
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

fn schema(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare(
            "SELECT type || ':' || name || ':' || COALESCE(sql, '') FROM sqlite_master
             ORDER BY type, name",
        )
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Every row of `tables`, column by column.
fn table_rows(conn: &Connection, tables: &[&str]) -> Vec<String> {
    let mut rows = Vec::new();
    for table in tables {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = statement.column_count();
        let mut query = statement.query([]).unwrap();
        while let Some(row) = query.next().unwrap() {
            let values = (0..columns)
                .map(|index| format!("{:?}", row.get::<_, rusqlite::types::Value>(index).unwrap()))
                .collect::<Vec<_>>();
            rows.push(format!("{table}|{}", values.join("|")));
        }
    }
    rows
}

fn rejected_validation(_: &Connection) -> Result<(), ManagedStoreError> {
    Err(ManagedStoreError::SchemaInvalid(
        "injected validation failure".into(),
    ))
}

fn assert_schema_invalid(path: &Path, case: &str) {
    let error = ManagedStore::open(&config_at(path), ManagedStoreOpenMode::Startup).unwrap_err();
    assert!(
        matches!(error, ManagedStoreError::SchemaInvalid(_)),
        "{case}: {error}"
    );
}

const PRINCIPAL_SQL: &str = "INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by,role,self_service_enabled)";
const METHOD_SQL: &str = "INSERT INTO principal_login_methods(login_method_id,principal_id,method,external_provider,external_subject,status,created_at,updated_at,created_by,updated_by)";
const RENEWAL_SQL: &str = "INSERT INTO oidc_membership_renewals(login_method_id,token_version,state,ended_reason,payload_version,key_id,nonce,ciphertext,recorded_at,observation_iat,updated_at)";

/// A user `principal` with a Microsoft login method `method` for `user`.
fn microsoft_user_sql(principal: &str, method: &str, user: &str) -> String {
    format!(
        "{PRINCIPAL_SQL} VALUES('{principal}','user','active','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z','admin','user',1);
         {METHOD_SQL} VALUES('{method}','{principal}','oidc','microsoft','{}','active','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z','admin','admin');",
        subject(user)
    )
}

fn ended_row_sql(method: &str, token_version: &str) -> String {
    format!(
        "{RENEWAL_SQL} VALUES('{method}','{token_version}','ended','not_issued',NULL,NULL,NULL,NULL,'2026-10-20T00:00:00Z',1792000000,'2026-10-20T00:00:00Z');"
    )
}

/// The store holding the golden record of `alice`, a second Microsoft
/// method `bob-method` and a third user's subject that no method uses.
fn golden_store(path: &Path) -> ManagedStore {
    let store = store_at(path, None);
    reconcile(&store, true, true, CLIENT, "golden", 3_600);
    sql(&store, &microsoft_user_sql("alice", GOLDEN_METHOD, USER));
    sql(&store, &microsoft_user_sql("bob", "bob-method", OTHER_USER));
    insert_golden(&store);
    store
}

fn insert_golden(store: &ManagedStore) {
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            &format!(
                "{RENEWAL_SQL} VALUES(?1,?2,'active',NULL,1,'golden',?3,?4,'2026-10-20T00:00:00Z',1792000000,'2026-10-20T00:00:00Z')"
            ),
            params![
                GOLDEN_METHOD,
                GOLDEN_TOKEN_VERSION,
                golden_hex(GOLDEN_NONCE),
                golden_hex(GOLDEN_CIPHERTEXT)
            ],
        )
        .unwrap();
}

#[test]
fn golden_renewal_record_still_decrypts_and_binds_every_column() {
    let temp = private_dir();
    let store = golden_store(&temp.path().join("store.sqlite"));
    let ring = ring();
    assert_eq!(
        microsoft_oidc_nonce_sha256("golden-flow-nonce"),
        GOLDEN_NONCE_SHA256
    );
    let golden_subject = subject(USER);
    let binding = Binding {
        login_method_id: GOLDEN_METHOD,
        external_subject: &golden_subject,
        tenant_id: TENANT,
        client_id: CLIENT,
        token_version: GOLDEN_TOKEN_VERSION,
    };
    assert_eq!(
        String::from_utf8(aad(&binding, "golden")).unwrap(),
        format!(
            r#"["aab-oidc-membership-renewal",1,"{GOLDEN_METHOD}","{golden_subject}","{TENANT}","{CLIENT}","{GOLDEN_TOKEN_VERSION}","golden"]"#
        )
    );
    // The exact payload bytes.
    let plaintext = Aes256Gcm::new_from_slice(&[23; 32])
        .unwrap()
        .decrypt(
            Nonce::from_slice(&golden_hex(GOLDEN_NONCE)),
            Payload {
                msg: &golden_hex(GOLDEN_CIPHERTEXT),
                aad: &aad(&binding, "golden"),
            },
        )
        .unwrap();
    assert_eq!(String::from_utf8(plaintext).unwrap(), GOLDEN_PAYLOAD);
    let material = store
        .oidc_membership_renewal_material(&ring, GOLDEN_METHOD)
        .unwrap()
        .unwrap();
    assert_eq!(material.token_version(), GOLDEN_TOKEN_VERSION);
    assert_eq!(material.refresh_token(), "golden-microsoft-refresh-token");
    let reference = material.reference();
    assert_eq!(reference.subject(), "golden-pairwise-subject");
    assert_eq!(
        reference.audience(),
        &json!([CLIENT, "api://golden-resource"])
    );
    assert_eq!(reference.azp(), Some(CLIENT));
    assert_eq!(reference.nonce_sha256(), GOLDEN_NONCE_SHA256);
    assert_eq!(reference.auth_time(), Some(1_792_000_000));
    let debug = format!("{material:?}");
    assert!(!debug.contains("golden-microsoft-refresh-token"), "{debug}");
    let record = store
        .oidc_membership_renewal(GOLDEN_METHOD)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, OidcMembershipRenewalState::Active);
    assert_eq!(record.observation_iat, 1_792_000_000);
    store.check_ready(Some(&ring)).unwrap();

    // Every bound column is authenticated: the method, its subject, the
    // provider's tenant and client, the token version and the key.
    let other_subject = subject(THIRD_USER);
    for (column, tamper, restore) in [
        (
            "login_method_id",
            "UPDATE oidc_membership_renewals SET login_method_id='bob-method'".to_string(),
            format!("UPDATE oidc_membership_renewals SET login_method_id='{GOLDEN_METHOD}'"),
        ),
        (
            "external_subject",
            format!(
                "UPDATE principal_login_methods SET external_subject='{other_subject}' WHERE login_method_id='{GOLDEN_METHOD}'"
            ),
            format!(
                "UPDATE principal_login_methods SET external_subject='{golden_subject}' WHERE login_method_id='{GOLDEN_METHOD}'"
            ),
        ),
        (
            "tenant_id",
            "UPDATE oidc_provider_state SET tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9'"
                .to_string(),
            format!("UPDATE oidc_provider_state SET tenant_id='{TENANT}'"),
        ),
        (
            "client_id",
            format!("UPDATE oidc_provider_state SET client_id='{OTHER_CLIENT}'"),
            format!("UPDATE oidc_provider_state SET client_id='{CLIENT}'"),
        ),
        (
            "token_version",
            "UPDATE oidc_membership_renewals SET token_version='3c6e8a41-9d3f-4b7a-8e15-6f0a9c3d7b28'"
                .to_string(),
            format!("UPDATE oidc_membership_renewals SET token_version='{GOLDEN_TOKEN_VERSION}'"),
        ),
        (
            "key_id",
            "UPDATE oidc_membership_renewals SET key_id='next'".to_string(),
            "UPDATE oidc_membership_renewals SET key_id='golden'".to_string(),
        ),
    ] {
        sql(&store, &tamper);
        assert!(
            matches!(
                store.check_ready(Some(&ring)),
                Err(ManagedStoreError::CredentialDecryptFailed)
            ),
            "{column}"
        );
        sql(&store, &restore);
        store.check_ready(Some(&ring)).unwrap();
    }
}

/// A store at schema 030 with Microsoft sign-in state and a group that
/// enrolls new Microsoft users upgrades to 031 with its rows unchanged and its
/// ledger extended by one row; the new table is empty and its constraints keep
/// rows well formed.
#[test]
fn schema_030_upgrades_to_031_with_rows_unchanged() {
    let temp = private_dir();
    let path = temp.path().join("store.sqlite");
    let previous = store_at(&path, Some(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION));
    sql(
        &previous,
        &microsoft_user_sql("alice", "alice-method", USER),
    );
    sql(
        &previous,
        "INSERT INTO oidc_provider_state(provider_id,tenant_id,client_id,enabled,config_generation,config_fingerprint,external_membership_ttl_s,updated_at)
           VALUES('microsoft','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',1,3,'previous',3600,'2026-10-20T00:00:00Z');
         INSERT INTO oidc_membership_refresh_state(login_method_id,observed_at,evidence_at,valid_until,updated_at)
           VALUES('alice-method','2026-10-20T00:00:00Z','2026-10-20T00:00:00Z','2026-10-20T08:00:00Z','2026-10-20T00:00:00Z');
         INSERT INTO oidc_subject_flow_watermarks(external_subject,last_flow_sequence,updated_at)
           VALUES('entra:v1:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1:cccccccc-cccc-4ccc-8ccc-ccccccccccc3',7,'2026-10-20T00:00:00Z');
         INSERT INTO groups(group_id,status,created_at,created_by,updated_at,updated_by,auto_enroll_new_microsoft_users)
           VALUES('defaults','active','2026-10-20T00:00:00Z','admin','2026-10-20T00:00:00Z','admin',1);",
    );
    let tables = [
        "principals",
        "groups",
        "principal_login_methods",
        "principal_identity_tokens",
        "oidc_provider_state",
        "oidc_membership_refresh_state",
        "oidc_subject_flow_watermarks",
    ];
    let before = {
        let conn = previous.connection.lock().unwrap();
        assert!(!sqlite_object_exists(&conn, "table", "oidc_membership_renewals").unwrap());
        table_rows(&conn, &tables)
    };
    assert!(before.len() >= 7);
    drop(previous);
    let ledger_before = migration_ledger(&path);
    assert_eq!(
        ledger_before.last().map(|row| row.0.as_str()),
        Some(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION)
    );

    let store = store_at(&path, None);
    assert!(store.migration_applied_this_open(MANAGED_STORE_OIDC_MEMBERSHIP_RENEWAL_VERSION));
    let ledger = migration_ledger(&path);
    assert_eq!(&ledger[..ledger_before.len()], ledger_before.as_slice());
    assert_eq!(ledger.len(), MANAGED_STORE_MIGRATIONS.len());
    assert_eq!(
        ledger[ledger_before.len()],
        (
            "031_oidc_membership_renewal".to_string(),
            sha256_hex(include_str!("oidc_membership_renewal.sql").as_bytes())
        )
    );
    assert_eq!(
        store.status().unwrap().schema_version,
        MANAGED_STORE_SCHEMA_VERSION
    );
    store.check_ready(None).unwrap();
    let conn = store.connection.lock().unwrap();
    assert_eq!(table_rows(&conn, &tables), before);
    assert!(sqlite_object_exists(&conn, "table", "oidc_membership_renewals").unwrap());
    assert!(sqlite_object_exists(&conn, "index", "idx_oidc_membership_renewals_key").unwrap());
    assert!(table_rows(&conn, &["oidc_membership_renewals"]).is_empty());
    // The constraints couple state, reason, payload and failure columns.
    let version = "4d6e8a41-9d3f-4b7a-8e15-6f0a9c3d7b28";
    let payload = "1,'golden',x'000102030405060708090a0b',x'00112233445566778899aabbccddeeff'";
    for (case, columns, values) in [
        ("active-without-payload", "", "'active',NULL,NULL,NULL,NULL,NULL".to_string()),
        ("ended-without-reason", "", "'ended',NULL,NULL,NULL,NULL,NULL".to_string()),
        ("ended-with-payload", "", format!("'ended','not_issued',{payload}")),
        ("active-with-reason", "", format!("'active','not_issued',{payload}")),
        ("unknown-state", "", format!("'paused',NULL,{payload}")),
        ("unknown-reason", "", "'ended','revoked',NULL,NULL,NULL,NULL".to_string()),
        ("payload-version-2", "", "'active',NULL,2,'golden',x'000102030405060708090a0b',x'00112233445566778899aabbccddeeff'".to_string()),
        ("short-nonce", "", "'active',NULL,1,'golden',x'0001',x'00112233445566778899aabbccddeeff'".to_string()),
        ("partial-payload", "", "'active',NULL,1,NULL,x'000102030405060708090a0b',x'00112233445566778899aabbccddeeff'".to_string()),
        ("retrying-without-failure", "", format!("'retrying',NULL,{payload}")),
        (
            "failure-without-time",
            ",last_failure_code,next_attempt_after",
            format!("'retrying',NULL,{payload},'unavailable','2026-10-20T00:01:00Z'"),
        ),
        (
            "active-with-failure",
            ",last_failure_code,last_failure_at",
            format!("'active',NULL,{payload},'unavailable','2026-10-20T00:00:00Z'"),
        ),
        (
            "unknown-failure-code",
            ",last_failure_code,last_failure_at,next_attempt_after",
            format!("'blocked',NULL,{payload},'oops','2026-10-20T00:00:00Z','2026-10-20T01:00:00Z'"),
        ),
        ("missing-method", "", "'ended','not_issued',NULL,NULL,NULL,NULL".to_string()),
    ] {
        let method = if case == "missing-method" {
            "no-such-method"
        } else {
            "alice-method"
        };
        assert!(
            conn.execute(
                &format!(
                    "INSERT INTO oidc_membership_renewals(login_method_id,token_version,recorded_at,observation_iat,updated_at,state,ended_reason,payload_version,key_id,nonce,ciphertext{columns})
                     VALUES('{method}','{version}','t',0,'t',{values})"
                ),
                [],
            )
            .is_err(),
            "{case}"
        );
    }
    conn.execute(
        &format!(
            "INSERT INTO oidc_membership_renewals(login_method_id,token_version,recorded_at,observation_iat,updated_at,state,ended_reason,payload_version,key_id,nonce,ciphertext,last_failure_code,last_failure_at,next_attempt_after,failure_count)
             VALUES('alice-method','{version}','t',0,'t','blocked',NULL,{payload},'client_rejected','t','t',2)"
        ),
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM oidc_membership_renewals", [])
        .unwrap();
    drop(conn);
    drop(store);
    // A fully migrated store is admitted again through its validator.
    store_at(&path, None);
}

/// A 030 store that drifted from its schema, or breaks its invariants, is
/// rejected before migration and left byte for byte as it was.
#[test]
fn migration_rejects_prior_schema_drift_without_modification() {
    for (name, drift) in [
        (
            "premature-table",
            "CREATE TABLE oidc_membership_renewals(login_method_id TEXT PRIMARY KEY);",
        ),
        ("dropped-index", "DROP INDEX oauth_revocations_due;"),
        (
            "dropped-enrollment-column",
            "ALTER TABLE groups DROP COLUMN auto_enroll_new_microsoft_users;",
        ),
        (
            "missing-identity-token",
            "DELETE FROM principal_identity_tokens WHERE principal_id = 'alice';",
        ),
    ] {
        let temp = private_dir();
        let path = temp.path().join(format!("{name}.sqlite"));
        let previous = store_at(&path, Some(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION));
        sql(
            &previous,
            &microsoft_user_sql("alice", "alice-method", USER),
        );
        sql(&previous, drift);
        let before_schema = schema(&previous.connection.lock().unwrap());
        drop(previous);
        let before_ledger = migration_ledger(&path);
        let before_file = fs::read(&path).unwrap();

        assert_schema_invalid(&path, name);
        assert_eq!(fs::read(&path).unwrap(), before_file, "{name}");
        assert_eq!(migration_ledger(&path), before_ledger, "{name}");
        assert_eq!(
            schema(&Connection::open(&path).unwrap()),
            before_schema,
            "{name}"
        );
    }
}

/// A failed migration leaves the 030 store as it was; once migrated, an
/// older binary refuses the newer ledger, so rollback needs the
/// pre-migration backup.
#[test]
fn failed_migration_keeps_the_old_schema_and_ledger() {
    let temp = private_dir();
    let path = temp.path().join("store.sqlite");
    let previous = store_at(&path, Some(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION));
    sql(
        &previous,
        &microsoft_user_sql("alice", "alice-method", USER),
    );
    let before_schema = schema(&previous.connection.lock().unwrap());
    drop(previous);
    let ledger = migration_ledger(&path);
    let mut failing = catalog_through(MANAGED_STORE_OIDC_MEMBERSHIP_RENEWAL_VERSION)
        .migrations
        .to_vec();
    let last = failing.last_mut().unwrap();
    assert_eq!(last.version, MANAGED_STORE_OIDC_MEMBERSHIP_RENEWAL_VERSION);
    last.structural_validation = rejected_validation;
    assert!(matches!(
        ManagedStore::open_with_catalog(
            &config_at(&path),
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &failing,
            },
        ),
        Err(ManagedStoreError::SchemaInvalid(ref message)) if message == "injected validation failure"
    ));
    assert_eq!(migration_ledger(&path), ledger);
    {
        let conn = Connection::open(&path).unwrap();
        assert_eq!(schema(&conn), before_schema);
        assert!(!sqlite_object_exists(&conn, "table", "oidc_membership_renewals").unwrap());
    }

    let store = store_at(&path, None);
    assert!(store.migration_applied_this_open(MANAGED_STORE_OIDC_MEMBERSHIP_RENEWAL_VERSION));
    drop(store);
    let migrated = fs::read(&path).unwrap();
    let error = ManagedStore::open_with_catalog(
        &config_at(&path),
        ManagedStoreOpenMode::Startup,
        catalog_through(MANAGED_STORE_GROUP_AUTO_ENROLLMENT_VERSION),
    )
    .unwrap_err();
    assert!(
        matches!(error, ManagedStoreError::SchemaInvalid(ref message) if message.contains("newer than this broker supports")),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), migrated);
}

/// The 031 validator rejects a migrated store whose renewal table drifted,
/// whose rows break the typed invariants, or that lost the group setting of
/// 030 or the 029 invariant of one identity-token row per human; a
/// well-formed ended row is admitted.
#[test]
fn structural_validator_rejects_drift_and_invalid_rows() {
    let version = "5e6e8a41-9d3f-4b7a-8e15-6f0a9c3d7b28";
    let bob_local = format!(
        "{PRINCIPAL_SQL} VALUES('bob','user','active','t','t','admin','user',1);
         INSERT INTO principal_login_methods(login_method_id,principal_id,method,status,password_hash_phc,created_at,updated_at,created_by,updated_by)
           VALUES('bob-local','bob','local_password','active','unused-test-password-hash','t','t','admin','admin');
         {}",
        ended_row_sql("bob-local", version)
    );
    // Schema drift fails admission only; invalid rows fail readiness too.
    enum Expect {
        Admitted,
        SchemaRejected,
        RowsRejected,
    }
    for (name, drift, expect) in [
        (
            "well-formed-ended-row",
            ended_row_sql("alice-method", version),
            Expect::Admitted,
        ),
        (
            "dropped-index",
            "DROP INDEX idx_oidc_membership_renewals_key;".to_string(),
            Expect::SchemaRejected,
        ),
        (
            "relaxed-table",
            "DROP TABLE oidc_membership_renewals;
             CREATE TABLE oidc_membership_renewals(login_method_id TEXT PRIMARY KEY);"
                .to_string(),
            Expect::SchemaRejected,
        ),
        (
            "dropped-enrollment-column",
            "ALTER TABLE groups DROP COLUMN auto_enroll_new_microsoft_users;".to_string(),
            Expect::SchemaRejected,
        ),
        ("local-password-row", bob_local, Expect::RowsRejected),
        (
            "non-canonical-token-version",
            ended_row_sql("alice-method", &version.to_uppercase()),
            Expect::RowsRejected,
        ),
        (
            "unparseable-timestamp",
            ended_row_sql("alice-method", version).replace("'2026-10-20T00:00:00Z'", "'yesterday'"),
            Expect::RowsRejected,
        ),
        (
            "missing-identity-token",
            "DELETE FROM principal_identity_tokens WHERE principal_id = 'alice';".to_string(),
            Expect::RowsRejected,
        ),
    ] {
        let temp = private_dir();
        let path = temp.path().join(format!("{name}.sqlite"));
        let store = store_at(&path, None);
        sql(&store, &microsoft_user_sql("alice", "alice-method", USER));
        sql(&store, &drift);
        let readiness = store.check_ready(None);
        drop(store);
        match expect {
            Expect::Admitted => {
                readiness.unwrap();
                store_at(&path, None);
            }
            Expect::SchemaRejected => assert_schema_invalid(&path, name),
            Expect::RowsRejected => {
                assert!(
                    matches!(readiness, Err(ManagedStoreError::SchemaInvalid(_))),
                    "{name}"
                );
                assert_schema_invalid(&path, name);
            }
        }
    }
}

fn hasher() -> BrokerTokenHasher {
    BrokerTokenHasher {
        key: Arc::new([5; 32]),
    }
}

fn reference() -> OidcRenewalReference {
    OidcRenewalReference::new(
        "pairwise-subject".into(),
        json!(CLIENT),
        None,
        microsoft_oidc_nonce_sha256("flow-nonce"),
        None,
    )
    .unwrap()
}

fn issued(ring: &CredentialKeyRing, token: &str) -> Option<OidcMembershipRenewalSignIn> {
    Some(OidcMembershipRenewalSignIn::issued(ring.clone(), token.into(), reference()).unwrap())
}

fn not_issued(ring: &CredentialKeyRing) -> Option<OidcMembershipRenewalSignIn> {
    Some(OidcMembershipRenewalSignIn::not_issued(ring.clone()))
}

struct Fixture {
    _temp: TempDir,
    store: ManagedStore,
    ring: CredentialKeyRing,
    generation: u64,
    flow: std::cell::Cell<u64>,
    now: i64,
}

fn fixture(membership_renewal: bool) -> Fixture {
    let temp = private_dir();
    let store = store_at(&temp.path().join("store.sqlite"), None);
    let provider = reconcile(&store, true, membership_renewal, CLIENT, "fixture", 3_600);
    for (group, external) in [("team-a", GROUP_A), ("team-b", GROUP_B)] {
        store
            .create_group(GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                created_by: "admin".into(),
            })
            .unwrap();
        store
            .create_external_group_binding(ExternalGroupBindingCreateRequest {
                external_group_id: external.into(),
                group_id: group.into(),
                actor: "admin".into(),
            })
            .unwrap();
    }
    Fixture {
        _temp: temp,
        store,
        ring: ring(),
        generation: provider.config_generation,
        flow: std::cell::Cell::new(0),
        now: Utc::now().timestamp(),
    }
}

impl Fixture {
    /// A sign-in of `user` (JIT-created as `principal`) at the next flow
    /// sequence, whose ID token was issued `iat_offset` seconds from the
    /// fixture's start by Microsoft's clock.
    fn sign_in(
        &self,
        user: &str,
        principal: &str,
        groups: &[&str],
        iat_offset: i64,
        membership_renewal: Option<OidcMembershipRenewalSignIn>,
    ) -> OidcCompletionOutcome {
        self.flow.set(self.flow.get() + 1);
        self.sign_in_at(
            self.flow.get(),
            user,
            principal,
            groups,
            iat_offset,
            membership_renewal,
        )
    }

    fn sign_in_at(
        &self,
        flow: u64,
        user: &str,
        principal: &str,
        groups: &[&str],
        iat_offset: i64,
        membership_renewal: Option<OidcMembershipRenewalSignIn>,
    ) -> OidcCompletionOutcome {
        let now = Utc::now();
        let issued_at = self.now + iat_offset;
        let evidence_at =
            DateTime::<Utc>::from_timestamp(issued_at.min(now.timestamp()), 0).unwrap();
        self.store
            .complete_oidc_login(
                &hasher(),
                OidcCompleteLoginRequest {
                    flow_sequence: flow,
                    provider_generation: self.generation,
                    external_subject: subject(user),
                    external_group_ids: groups.iter().map(|group| group.to_string()).collect(),
                    jit_provisioning: true,
                    jit_principal_id: principal.into(),
                    display_name: None,
                    email: None,
                    evidence_at: normalized_timestamp(evidence_at),
                    callback_now: normalized_timestamp(now),
                    session_ttl_seconds: 3_600,
                    created_by: "oidc-microsoft".into(),
                    issued_at,
                    membership_renewal,
                },
            )
            .unwrap()
    }

    fn incomplete(&self, flow: u64, user: &str, iat_offset: i64) -> bool {
        self.store
            .record_trusted_incomplete_oidc_callback(
                &subject(user),
                flow,
                self.generation,
                &normalized_now_string(),
                self.now + iat_offset,
            )
            .unwrap()
    }

    fn groups(&self, principal: &str) -> Vec<String> {
        self.store
            .effective_membership_at(principal, &normalized_now_string())
            .unwrap()
            .groups
    }

    fn renewal(&self, method: &str) -> Option<OidcMembershipRenewalRecord> {
        self.store.oidc_membership_renewal(method).unwrap()
    }

    fn material(&self, method: &str) -> Option<OidcMembershipRenewalMaterial> {
        self.store
            .oidc_membership_renewal_material(&self.ring, method)
            .unwrap()
    }
}

fn succeeded(outcome: OidcCompletionOutcome) -> OidcCompleteLoginResult {
    match outcome {
        OidcCompletionOutcome::Succeeded { result, .. } => *result,
        other => panic!("expected a successful sign-in, got {other:?}"),
    }
}

/// With renewal enabled a sign-in stores its refresh token under a new token
/// version, or records `not_issued`; either way failures and the backoff are
/// cleared and the attempt and renewal times are kept. Without renewal, a
/// sign-in stores nothing.
#[test]
fn sign_in_records_the_refresh_token_or_not_issued_and_keeps_the_attempt_interval() {
    let fixture = fixture(true);
    let first = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -100,
        issued(&fixture.ring, "refresh-1"),
    ));
    let method = first.login_method.login_method_id.clone();
    assert_eq!(first.membership_evidence, OidcMembershipEvidence::Replaced);
    let row = fixture.renewal(&method).unwrap();
    assert_eq!(row.state, OidcMembershipRenewalState::Active);
    assert_eq!(row.ended_reason, None);
    assert_eq!(row.observation_iat, fixture.now - 100);
    assert_eq!(row.failure_count, 0);
    assert_eq!(row.last_attempt_at, None);
    assert_eq!(row.last_renewed_at, None);
    assert_eq!(row.recorded_at, first.session.record.created_at);
    assert!(Uuid::parse_str(&row.token_version).is_ok());
    let material = fixture.material(&method).unwrap();
    assert_eq!(material.refresh_token(), "refresh-1");
    assert_eq!(material.token_version(), row.token_version);
    assert_eq!(material.reference(), &reference());
    assert_eq!(
        fixture.store.active_credential_key_ids().unwrap(),
        ["golden"]
    );
    {
        let conn = fixture.store.connection.lock().unwrap();
        let ciphertext: Vec<u8> = conn
            .query_row(
                "SELECT ciphertext FROM oidc_membership_renewals WHERE login_method_id = ?1",
                [&method],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!ciphertext.windows(9).any(|window| window == b"refresh-1"));
    }

    // A renewal attempt recorded its start, a renewal and a failure.
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_renewals SET state='retrying', failure_count=3,
               last_failure_code='unavailable', last_failure_at='2026-10-20T01:00:00Z',
               next_attempt_after='2099-01-01T00:00:00Z', last_attempt_at='2026-10-20T01:00:00Z',
               last_renewed_at='2026-10-20T00:30:00Z'
             WHERE login_method_id='{method}'"
        ),
    );
    let second = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -50,
        issued(&fixture.ring, "refresh-2"),
    ));
    assert_eq!(second.membership_evidence, OidcMembershipEvidence::Replaced);
    let renewed = fixture.renewal(&method).unwrap();
    assert_ne!(renewed.token_version, row.token_version);
    assert_eq!(renewed.state, OidcMembershipRenewalState::Active);
    assert_eq!(renewed.failure_count, 0);
    assert_eq!(renewed.last_failure_code, None);
    assert_eq!(renewed.last_failure_at, None);
    assert_eq!(renewed.next_attempt_after, None);
    assert_eq!(
        renewed.last_attempt_at.as_deref(),
        Some("2026-10-20T01:00:00Z")
    );
    assert_eq!(
        renewed.last_renewed_at.as_deref(),
        Some("2026-10-20T00:30:00Z")
    );
    assert_eq!(renewed.observation_iat, fixture.now - 50);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-2"
    );

    let third =
        succeeded(fixture.sign_in(USER, "alice", &[GROUP_A], -40, not_issued(&fixture.ring)));
    assert_eq!(third.membership_evidence, OidcMembershipEvidence::Replaced);
    let ended = fixture.renewal(&method).unwrap();
    assert_ne!(ended.token_version, renewed.token_version);
    assert_eq!(ended.state, OidcMembershipRenewalState::Ended);
    assert_eq!(
        ended.ended_reason,
        Some(OidcMembershipRenewalEndedReason::NotIssued)
    );
    assert_eq!(
        ended.last_attempt_at.as_deref(),
        Some("2026-10-20T01:00:00Z")
    );
    assert_eq!(ended.observation_iat, fixture.now - 40);
    assert!(fixture.material(&method).is_none());
    assert!(
        fixture
            .store
            .active_credential_key_ids()
            .unwrap()
            .is_empty()
    );
    fixture.store.check_ready(None).unwrap();

    // Renewal disabled for this sign-in: nothing is stored for a method
    // without a row.
    let other = succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_B], -10, None));
    assert!(
        fixture
            .renewal(&other.login_method.login_method_id)
            .is_none()
    );
    // And a refresh token never reaches the request's debug output.
    let debug = format!("{:?}", issued(&fixture.ring, "debug-sentinel-token"));
    assert!(!debug.contains("debug-sentinel-token"), "{debug}");
}

/// A JIT sign-in with renewal enabled adds the new account to the groups that
/// enroll new Microsoft users and records its refresh token in the same
/// transaction: when an enrollment insert fails, neither the account nor its
/// renewal row remains. A returning sign-in records its token without
/// enrolling the account again.
#[test]
fn jit_sign_in_records_the_renewal_row_with_group_enrollment_in_one_transaction() {
    let fixture = fixture(true);
    fixture
        .store
        .create_group(GroupWriteRequest {
            group_id: "defaults".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: true,
            created_by: "admin".into(),
        })
        .unwrap();
    sql(
        &fixture.store,
        "CREATE TEMP TRIGGER reject_enrollment BEFORE INSERT ON principal_groups
         WHEN NEW.group_id = 'defaults' BEGIN SELECT RAISE(ABORT, 'enrollment failure'); END;",
    );
    fixture.flow.set(fixture.flow.get() + 1);
    let now = normalized_now_string();
    assert!(matches!(
        fixture.store.complete_oidc_login(
            &hasher(),
            OidcCompleteLoginRequest {
                flow_sequence: fixture.flow.get(),
                provider_generation: fixture.generation,
                external_subject: subject(USER),
                external_group_ids: [GROUP_A.to_string()].into(),
                jit_provisioning: true,
                jit_principal_id: "alice".into(),
                display_name: None,
                email: None,
                evidence_at: now.clone(),
                callback_now: now,
                session_ttl_seconds: 3_600,
                created_by: "oidc-microsoft".into(),
                issued_at: fixture.now,
                membership_renewal: issued(&fixture.ring, "refresh-rolled-back"),
            },
        ),
        Err(ManagedStoreError::Unavailable(_))
    ));
    {
        let conn = fixture.store.connection.lock().unwrap();
        for table in [
            "principals",
            "principal_login_methods",
            "principal_groups",
            "oidc_membership_renewals",
        ] {
            assert!(table_rows(&conn, &[table]).is_empty(), "{table}");
        }
    }
    sql(&fixture.store, "DROP TRIGGER reject_enrollment;");

    let created = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        0,
        issued(&fixture.ring, "refresh-1"),
    ));
    assert_eq!(created.auto_enrolled_group_ids, ["defaults"]);
    assert_eq!(created.membership.groups, ["defaults", "team-a"]);
    let method = created.login_method.login_method_id.clone();
    assert_eq!(
        fixture.renewal(&method).unwrap().state,
        OidcMembershipRenewalState::Active
    );
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-1"
    );

    let returning = succeeded(fixture.sign_in(
        USER,
        "unused",
        &[GROUP_A],
        1,
        issued(&fixture.ring, "refresh-2"),
    ));
    assert!(returning.auto_enrolled_group_ids.is_empty());
    assert_eq!(returning.login_method.login_method_id, method);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-2"
    );
    assert_eq!(fixture.store.group_members("defaults").unwrap().len(), 1);
}

/// Without a renewal row a sign-in replaces the evidence unconditionally,
/// as before renewal existed. With one, complete groups replace it only from
/// a token whose raw `iat` is strictly newer than every trusted observation;
/// a sign-in that keeps the evidence still issues its session and records its
/// token. The ordering key is never clamped to the Broker's clock.
#[test]
fn evidence_ordering_uses_raw_iat_only_while_a_renewal_row_exists() {
    let fixture = fixture(true);
    // No row: an older token still replaces the evidence.
    succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_A], -10, None));
    let older = succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_B], -100, None));
    assert_eq!(older.membership_evidence, OidcMembershipEvidence::Replaced);
    assert_eq!(fixture.groups("bob"), ["team-b"]);

    let first = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -50,
        issued(&fixture.ring, "refresh-1"),
    ));
    let method = first.login_method.login_method_id.clone();
    assert_eq!(fixture.groups("alice"), ["team-a"]);
    for (offset, token) in [(-50, "refresh-equal"), (-60, "refresh-older")] {
        let before = fixture.renewal(&method).unwrap();
        let kept = succeeded(fixture.sign_in(
            USER,
            "alice",
            &[GROUP_B],
            offset,
            issued(&fixture.ring, token),
        ));
        assert_eq!(
            kept.membership_evidence,
            OidcMembershipEvidence::KeptNewer,
            "{token}"
        );
        assert_eq!(kept.membership.groups, ["team-a"], "{token}");
        assert_eq!(fixture.groups("alice"), ["team-a"], "{token}");
        assert!(
            fixture
                .store
                .resolve_browser_session(&hasher(), &kept.session.token)
                .is_ok(),
            "{token}"
        );
        let after = fixture.renewal(&method).unwrap();
        assert_ne!(after.token_version, before.token_version, "{token}");
        assert_eq!(after.observation_iat, fixture.now - 50, "{token}");
        assert_eq!(fixture.material(&method).unwrap().refresh_token(), token);
    }
    let newer = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_B],
        -40,
        issued(&fixture.ring, "refresh-newer"),
    ));
    assert_eq!(newer.membership_evidence, OidcMembershipEvidence::Replaced);
    assert_eq!(fixture.groups("alice"), ["team-b"]);
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now - 40
    );

    // Microsoft's clock 60 s ahead of the Broker's: the evidence time is
    // clamped to now, the ordering key is not, so a token issued 30 s ahead
    // cannot look newer.
    let ahead = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        60,
        issued(&fixture.ring, "refresh-ahead"),
    ));
    assert_eq!(ahead.membership_evidence, OidcMembershipEvidence::Replaced);
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now + 60
    );
    let behind = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_B],
        30,
        issued(&fixture.ring, "refresh-behind"),
    ));
    assert_eq!(
        behind.membership_evidence,
        OidcMembershipEvidence::KeptNewer
    );
    assert_eq!(fixture.groups("alice"), ["team-a"]);
}

/// A trusted incomplete sign-in raises only an existing row's watermark and
/// changes no evidence or token; once Microsoft reported an incomplete claim,
/// only a newer complete claim replaces the evidence. Superseded flows,
/// complete or incomplete, still raise the watermark of their trusted
/// observation but write nothing else; denied sign-ins never touch the row.
#[test]
fn incomplete_observations_raise_only_an_existing_row_and_denials_never_touch_it() {
    let fixture = fixture(true);
    succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_A], -10, None));
    let flow = fixture.flow.get() + 1;
    fixture.flow.set(flow);
    assert!(fixture.incomplete(flow, OTHER_USER, 50));
    let bob = fixture.store.list_login_methods("bob").unwrap().remove(0);
    assert!(fixture.renewal(&bob.login_method_id).is_none());

    let first = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -100,
        issued(&fixture.ring, "refresh-1"),
    ));
    let method = first.login_method.login_method_id.clone();
    let before = fixture.renewal(&method).unwrap();
    let flow = fixture.flow.get() + 1;
    fixture.flow.set(flow);
    assert!(fixture.incomplete(flow, USER, -20));
    let raised = fixture.renewal(&method).unwrap();
    assert_eq!(raised.observation_iat, fixture.now - 20);
    assert_eq!(raised.token_version, before.token_version);
    assert_eq!(fixture.groups("alice"), ["team-a"]);
    // A lower incomplete observation leaves the watermark.
    let flow = fixture.flow.get() + 1;
    fixture.flow.set(flow);
    assert!(fixture.incomplete(flow, USER, -90));
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now - 20
    );

    let kept = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_B],
        -30,
        issued(&fixture.ring, "refresh-2"),
    ));
    assert_eq!(kept.membership_evidence, OidcMembershipEvidence::KeptNewer);
    assert_eq!(fixture.groups("alice"), ["team-a"]);
    let replaced = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_B],
        -10,
        issued(&fixture.ring, "refresh-3"),
    ));
    assert_eq!(
        replaced.membership_evidence,
        OidcMembershipEvidence::Replaced
    );
    assert_eq!(fixture.groups("alice"), ["team-b"]);

    // Superseded flows, complete or incomplete, raise the watermark to their
    // trusted `iat` and write nothing else: no session, token or evidence.
    let current = fixture.renewal(&method).unwrap();
    let sessions = |store: &ManagedStore| -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM browser_sessions", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    let session_count = sessions(&fixture.store);
    assert!(!fixture.incomplete(1, USER, 100));
    let raised = fixture.renewal(&method).unwrap();
    assert_eq!(raised.observation_iat, fixture.now + 100);
    assert_eq!(
        OidcMembershipRenewalRecord {
            observation_iat: current.observation_iat,
            updated_at: current.updated_at.clone(),
            ..raised.clone()
        },
        current
    );
    assert_eq!(
        fixture.sign_in_at(
            1,
            USER,
            "alice",
            &[GROUP_A],
            110,
            issued(&fixture.ring, "stale")
        ),
        OidcCompletionOutcome::Superseded
    );
    let raised = fixture.renewal(&method).unwrap();
    assert_eq!(raised.observation_iat, fixture.now + 110);
    assert_eq!(
        OidcMembershipRenewalRecord {
            observation_iat: current.observation_iat,
            updated_at: current.updated_at.clone(),
            ..raised.clone()
        },
        current
    );
    assert_eq!(sessions(&fixture.store), session_count);
    assert_eq!(fixture.groups("alice"), ["team-b"]);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-3"
    );
    // A lower superseded observation leaves the watermark.
    assert!(!fixture.incomplete(1, USER, 50));
    assert_eq!(fixture.renewal(&method).unwrap(), raised);
    let current = raised;
    // A denied sign-in writes nothing either.
    sql(
        &fixture.store,
        &format!(
            "UPDATE principal_login_methods SET status='disabled' WHERE login_method_id='{method}'"
        ),
    );
    assert!(matches!(
        fixture.sign_in(USER, "alice", &[GROUP_A], 100, issued(&fixture.ring, "denied")),
        OidcCompletionOutcome::Denied { ref reason } if reason == "login_method_disabled"
    ));
    assert_eq!(fixture.renewal(&method).unwrap(), current);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-3"
    );
}

/// Flow creation order need not match Microsoft's issuance order. A trusted
/// observation from a superseded flow, incomplete or complete, still raises
/// the watermark, so a later flow whose token predates it keeps the stored
/// evidence (and still issues its session and records its token).
#[test]
fn superseded_trusted_observations_still_order_later_flows() {
    let fixture = fixture(true);
    // Flow 2 commits its token issued at -30.
    let second = succeeded(fixture.sign_in_at(
        2,
        USER,
        "alice",
        &[GROUP_A],
        -30,
        issued(&fixture.ring, "refresh-2"),
    ));
    let method = second.login_method.login_method_id.clone();
    assert_eq!(fixture.groups("alice"), ["team-a"]);
    // Flow 1's delayed incomplete callback carries a token issued at -10.
    assert!(!fixture.incomplete(1, USER, -10));
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now - 10
    );
    // Flow 3's token, issued at -20, predates that incomplete observation.
    let third = succeeded(fixture.sign_in_at(
        3,
        USER,
        "alice",
        &[GROUP_B],
        -20,
        issued(&fixture.ring, "refresh-3"),
    ));
    assert_eq!(third.membership_evidence, OidcMembershipEvidence::KeptNewer);
    assert_eq!(third.membership.groups, ["team-a"]);
    assert_eq!(fixture.groups("alice"), ["team-a"]);
    assert!(
        fixture
            .store
            .resolve_browser_session(&hasher(), &third.session.token)
            .is_ok()
    );
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-3"
    );
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now - 10
    );

    // The same holds for a superseded complete callback: flow 5 commits at
    // 0, delayed flow 4 (issued at +20) is superseded, and flow 6 (issued at
    // +10) keeps flow 5's evidence.
    let fifth = succeeded(fixture.sign_in_at(
        5,
        USER,
        "alice",
        &[GROUP_B],
        0,
        issued(&fixture.ring, "refresh-5"),
    ));
    assert_eq!(fifth.membership_evidence, OidcMembershipEvidence::Replaced);
    assert_eq!(fixture.groups("alice"), ["team-b"]);
    assert_eq!(
        fixture.sign_in_at(
            4,
            USER,
            "alice",
            &[GROUP_A],
            20,
            issued(&fixture.ring, "refresh-4")
        ),
        OidcCompletionOutcome::Superseded
    );
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-5"
    );
    assert_eq!(
        fixture.renewal(&method).unwrap().observation_iat,
        fixture.now + 20
    );
    let sixth = succeeded(fixture.sign_in_at(
        6,
        USER,
        "alice",
        &[GROUP_A],
        10,
        issued(&fixture.ring, "refresh-6"),
    ));
    assert_eq!(sixth.membership_evidence, OidcMembershipEvidence::KeptNewer);
    assert_eq!(fixture.groups("alice"), ["team-b"]);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-6"
    );
}

/// Unlinking the method, disabling the principal (either route), disabling
/// the provider, changing its client and turning renewal off delete stored
/// tokens; turning renewal on, other provider changes and re-enabling a
/// principal store nothing.
#[test]
fn lifecycle_events_delete_renewal_rows() {
    let fixture = fixture(true);
    let sign_in = |user: &str, principal: &str| {
        succeeded(fixture.sign_in(
            user,
            principal,
            &[GROUP_A],
            -10,
            issued(&fixture.ring, "refresh"),
        ))
        .login_method
        .login_method_id
    };
    let alice = sign_in(USER, "alice");
    let bob = sign_in(OTHER_USER, "bob");
    let carol = sign_in(THIRD_USER, "carol");

    fixture
        .store
        .unlink_oidc_login_method("alice", "admin")
        .unwrap();
    assert!(fixture.renewal(&alice).is_none());
    assert!(fixture.renewal(&bob).is_some());

    fixture.store.set_principal_enabled("bob", false).unwrap();
    assert!(fixture.renewal(&bob).is_none());
    fixture.store.set_principal_enabled("bob", true).unwrap();
    assert!(fixture.renewal(&bob).is_none());

    fixture
        .store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "carol".into(),
            display_name: None,
            email: None,
            status: Some("disabled".into()),
        })
        .unwrap();
    assert!(fixture.renewal(&carol).is_none());
    fixture
        .store
        .patch_principal(PrincipalPatchRequest {
            principal_id: "carol".into(),
            display_name: None,
            email: None,
            status: Some("active".into()),
        })
        .unwrap();
    let bob = sign_in(OTHER_USER, "bob");
    let carol = sign_in(THIRD_USER, "carol");

    // Other provider changes keep the rows: a new fingerprint (for example a
    // rotated client secret) and a lower TTL.
    reconcile(&fixture.store, true, true, CLIENT, "rotated", 3_600);
    reconcile(&fixture.store, true, true, CLIENT, "rotated", 900);
    assert!(fixture.renewal(&bob).is_some() && fixture.renewal(&carol).is_some());
    fixture.store.check_ready(Some(&fixture.ring)).unwrap();

    // Renewal off deletes every row; on again stores nothing until sign-in.
    reconcile(&fixture.store, true, false, CLIENT, "renewal-off", 3_600);
    assert!(fixture.renewal(&bob).is_none() && fixture.renewal(&carol).is_none());
    let generation = reconcile(&fixture.store, true, true, CLIENT, "renewal-on", 3_600);
    assert!(fixture.renewal(&bob).is_none());
    let fixture = Fixture {
        generation: generation.config_generation,
        ..fixture
    };
    let bob = succeeded(fixture.sign_in(
        OTHER_USER,
        "bob",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh"),
    ))
    .login_method
    .login_method_id;
    assert!(fixture.renewal(&bob).is_some());

    reconcile(
        &fixture.store,
        true,
        true,
        OTHER_CLIENT,
        "client-change",
        3_600,
    );
    assert!(fixture.renewal(&bob).is_none());
    let generation = reconcile(&fixture.store, true, true, CLIENT, "client-back", 3_600);
    let fixture = Fixture {
        generation: generation.config_generation,
        ..fixture
    };
    let bob = succeeded(fixture.sign_in(
        OTHER_USER,
        "bob",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh"),
    ))
    .login_method
    .login_method_id;
    assert!(fixture.renewal(&bob).is_some());
    reconcile(&fixture.store, false, false, CLIENT, "client-back", 3_600);
    assert!(fixture.renewal(&bob).is_none());
}

/// Rows holding tokens join key readiness and the used-key inventory, and
/// rewrap moves them to another key keeping their token version and plain
/// columns; ended rows hold no key.
#[test]
fn renewal_rows_join_key_readiness_inventory_and_rewrap() {
    let fixture = fixture(true);
    let alice = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh-alice"),
    ))
    .login_method
    .login_method_id;
    let bob = succeeded(fixture.sign_in(
        OTHER_USER,
        "bob",
        &[GROUP_A],
        -10,
        not_issued(&fixture.ring),
    ))
    .login_method
    .login_method_id;
    assert_eq!(
        fixture.store.active_credential_key_ids().unwrap(),
        ["golden"]
    );
    assert!(fixture.store.active_credentials_need_key_ring().unwrap());
    assert!(matches!(
        fixture.store.check_ready(None),
        Err(ManagedStoreError::EncryptionKeyMissing(ref key)) if key == "golden"
    ));
    assert!(matches!(
        fixture.store.check_ready(Some(&next_only_ring())),
        Err(ManagedStoreError::EncryptionKeyMissing(_))
    ));
    fixture.store.check_ready(Some(&fixture.ring)).unwrap();

    let before = (
        fixture.renewal(&alice).unwrap(),
        fixture.renewal(&bob).unwrap(),
    );
    assert_eq!(
        fixture
            .store
            .rewrap_credentials(&fixture.ring, "golden", "next", "admin")
            .unwrap()
            .rewrapped,
        1
    );
    assert_eq!(fixture.store.active_credential_key_ids().unwrap(), ["next"]);
    assert_eq!(
        (
            fixture.renewal(&alice).unwrap(),
            fixture.renewal(&bob).unwrap()
        ),
        before
    );
    fixture.store.check_ready(Some(&next_only_ring())).unwrap();
    let material = fixture
        .store
        .oidc_membership_renewal_material(&next_only_ring(), &alice)
        .unwrap()
        .unwrap();
    assert_eq!(material.refresh_token(), "refresh-alice");
    assert_eq!(material.token_version(), before.0.token_version);

    // Without the token row, the ended row needs no key.
    fixture
        .store
        .unlink_oidc_login_method("alice", "admin")
        .unwrap();
    assert!(
        fixture
            .store
            .active_credential_key_ids()
            .unwrap()
            .is_empty()
    );
    fixture.store.check_ready(None).unwrap();
}

/// Readiness rejects payloads that do not decrypt or are not well formed,
/// and a payload row without the provider row it is bound to.
#[test]
fn corrupt_payloads_fail_readiness() {
    let encrypt_raw = |fixture: &Fixture, method: &str, plaintext: &[u8]| {
        let row = fixture.renewal(method).unwrap();
        let method_subject = subject(USER);
        let binding = Binding {
            login_method_id: method,
            external_subject: &method_subject,
            tenant_id: TENANT,
            client_id: CLIENT,
            token_version: &row.token_version,
        };
        let nonce = [7_u8; 12];
        let ciphertext = Aes256Gcm::new_from_slice(&[23; 32])
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(&binding, "golden"),
                },
            )
            .unwrap();
        fixture
            .store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE oidc_membership_renewals SET nonce=?2, ciphertext=?3 WHERE login_method_id=?1",
                params![method, nonce.to_vec(), ciphertext],
            )
            .unwrap();
    };
    let valid = |refresh_token: &str| {
        serde_json::to_vec(&json!({
            "refreshToken": refresh_token,
            "subject": "pairwise-subject",
            "audience": CLIENT,
            "azp": null,
            "nonceSha256": microsoft_oidc_nonce_sha256("flow-nonce"),
            "authTime": null,
        }))
        .unwrap()
    };
    let mut unknown_field: Value = serde_json::from_slice(&valid("refresh")).unwrap();
    unknown_field["extra"] = json!(1);
    let mut array_of_numbers: Value = serde_json::from_slice(&valid("refresh")).unwrap();
    array_of_numbers["audience"] = json!([1]);
    let mut bad_digest: Value = serde_json::from_slice(&valid("refresh")).unwrap();
    bad_digest["nonceSha256"] = json!("flow-nonce");
    for (case, plaintext) in [
        ("empty-token", valid("")),
        ("oversized-token", valid(&"r".repeat(16 * 1024 + 1))),
        ("unknown-field", serde_json::to_vec(&unknown_field).unwrap()),
        (
            "non-string-audience",
            serde_json::to_vec(&array_of_numbers).unwrap(),
        ),
        ("bad-digest", serde_json::to_vec(&bad_digest).unwrap()),
        ("not-json", b"not json".to_vec()),
    ] {
        let fixture = fixture(true);
        let method = succeeded(fixture.sign_in(
            USER,
            "alice",
            &[GROUP_A],
            -10,
            issued(&fixture.ring, "refresh"),
        ))
        .login_method
        .login_method_id;
        encrypt_raw(&fixture, &method, &valid("re-encrypted"));
        fixture.store.check_ready(Some(&fixture.ring)).unwrap();
        encrypt_raw(&fixture, &method, &plaintext);
        assert!(
            matches!(
                fixture.store.check_ready(Some(&fixture.ring)),
                Err(ManagedStoreError::CredentialDecryptFailed)
            ),
            "{case}"
        );
    }
    let fixture = fixture(true);
    let method = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh"),
    ))
    .login_method
    .login_method_id;
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_renewals SET ciphertext=x'00112233445566778899aabbccddeeff00' WHERE login_method_id='{method}'"
        ),
    );
    assert!(matches!(
        fixture.store.check_ready(Some(&fixture.ring)),
        Err(ManagedStoreError::CredentialDecryptFailed)
    ));
    sql(&fixture.store, "DELETE FROM oidc_provider_state");
    assert!(matches!(
        fixture.store.check_ready(Some(&fixture.ring)),
        Err(ManagedStoreError::SchemaInvalid(_))
    ));
}

/// The sign-in inputs refuse malformed reference values and tokens.
#[test]
fn renewal_sign_in_inputs_are_validated() {
    let digest = microsoft_oidc_nonce_sha256("flow-nonce");
    for (case, subject, audience, azp, nonce_sha256) in [
        ("empty-subject", "", json!(CLIENT), None, digest.clone()),
        (
            "long-subject",
            &*"s".repeat(1025),
            json!(CLIENT),
            None,
            digest.clone(),
        ),
        ("empty-audience", "subject", json!(""), None, digest.clone()),
        (
            "empty-audience-array",
            "subject",
            json!([]),
            None,
            digest.clone(),
        ),
        (
            "numeric-audience",
            "subject",
            json!(7),
            None,
            digest.clone(),
        ),
        (
            "empty-azp",
            "subject",
            json!(CLIENT),
            Some(String::new()),
            digest.clone(),
        ),
        (
            "raw-nonce",
            "subject",
            json!(CLIENT),
            None,
            "flow-nonce".to_string(),
        ),
    ] {
        assert!(
            OidcRenewalReference::new(subject.into(), audience, azp, nonce_sha256, None).is_err(),
            "{case}"
        );
    }
    for token in [String::new(), "r".repeat(16 * 1024 + 1)] {
        assert!(OidcMembershipRenewalSignIn::issued(ring(), token, reference()).is_err());
    }
    assert!(
        OidcMembershipRenewalSignIn::issued(ring(), "r".repeat(16 * 1024), reference()).is_ok()
    );
}

// Renewal attempts and their outcome writes (design §8.4, §8.7, §8.8). The
// fixture's provider TTL is one hour, so its renewal window is 15 minutes.

fn at(fixture: &Fixture, offset: i64) -> String {
    normalized_timestamp(DateTime::<Utc>::from_timestamp(fixture.now + offset, 0).unwrap())
}

impl Fixture {
    fn attempt(&self, method: &str, offset: i64) -> OidcMembershipRenewalAttempt {
        self.attempt_at_generation(method, offset, self.generation)
    }

    fn attempt_at_generation(
        &self,
        method: &str,
        offset: i64,
        config_generation: u64,
    ) -> OidcMembershipRenewalAttempt {
        self.store
            .start_oidc_membership_renewal(
                &self.ring,
                &OidcMembershipRenewalAttemptRequest {
                    login_method_id: method.into(),
                    config_generation,
                },
                || DateTime::<Utc>::from_timestamp(self.now + offset, 0).unwrap(),
            )
            .unwrap()
    }

    fn start(&self, method: &str, offset: i64) -> OidcMembershipRenewalStart {
        match self.attempt(method, offset) {
            OidcMembershipRenewalAttempt::Started(start) => *start,
            OidcMembershipRenewalAttempt::Skipped(reason) => panic!("attempt skipped: {reason:?}"),
        }
    }

    fn commit(
        &self,
        fence: &OidcMembershipRenewalFence,
        offset: i64,
        result: OidcMembershipRenewalResult,
        rotation: Option<&str>,
    ) -> OidcMembershipRenewalCommit {
        self.store
            .commit_oidc_membership_renewal(OidcMembershipRenewalCommitRequest {
                fence: fence.clone(),
                now: at(self, offset),
                result,
                rotation: rotation.map(|token| {
                    OidcMembershipRenewalRotation::new(self.ring.clone(), token.into(), reference())
                        .unwrap()
                }),
            })
            .unwrap()
    }

    fn groups_at(&self, principal: &str, offset: i64) -> Vec<String> {
        self.store
            .effective_membership_at(principal, &at(self, offset))
            .unwrap()
            .groups
    }
}

fn committed(commit: OidcMembershipRenewalCommit) -> OidcMembershipRenewalCommitted {
    match commit {
        OidcMembershipRenewalCommit::Committed(committed) => *committed,
        OidcMembershipRenewalCommit::Superseded => panic!("superseded"),
    }
}

fn renewed(issued_at: i64, groups: &[&str]) -> OidcMembershipRenewalResult {
    OidcMembershipRenewalResult::Renewed {
        issued_at,
        external_group_ids: groups.iter().map(|group| group.to_string()).collect(),
    }
}

fn failed(
    code: OidcMembershipRenewalFailureCode,
    observed_issued_at: Option<i64>,
    next: String,
) -> OidcMembershipRenewalResult {
    OidcMembershipRenewalResult::Failed {
        code,
        observed_issued_at,
        next_attempt_after: next,
    }
}

/// Signs `alice` in with renewal at `iat_offset`; her evidence lasts until
/// `iat_offset + 3600`.
fn renewable_alice(fixture: &Fixture, iat_offset: i64) -> String {
    succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        iat_offset,
        issued(&fixture.ring, "refresh-1"),
    ))
    .login_method
    .login_method_id
}

/// The hint is read with the membership on every store identity path, and
/// only while renewal applies: an enabled user, an active Microsoft method
/// with a non-ended row, and an enabled provider.
#[test]
fn renewal_hint_is_read_with_identity_only_when_renewal_applies() {
    let fixture = fixture(true);
    let first = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh-1"),
    ));
    let method = first.login_method.login_method_id.clone();
    let row = fixture.renewal(&method).unwrap();
    let session = fixture
        .store
        .resolve_browser_session(&hasher(), &first.session.token)
        .unwrap();
    let hint = session.membership_renewal.clone().unwrap();
    assert_eq!(hint.login_method_id, method);
    assert_eq!(hint.state, OidcMembershipRenewalState::Active);
    assert_eq!(hint.token_version, row.token_version);
    assert_eq!(hint.next_attempt_after, None);
    let valid_until = fixture
        .store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
            [&method],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    assert_eq!(hint.valid_until.as_deref(), Some(valid_until.as_str()));
    let token = fixture
        .store
        .resolve_broker_token(&hasher(), &first.session.token)
        .unwrap();
    assert_eq!(token.membership_renewal, Some(hint.clone()));

    // Retrying and blocked rows still renew, and report their backoff.
    for state in ["retrying", "blocked"] {
        sql(
            &fixture.store,
            &format!(
                "UPDATE oidc_membership_renewals SET state='{state}',
                   last_failure_code='unavailable', last_failure_at='2026-10-20T00:00:00Z',
                   next_attempt_after='2026-10-20T01:00:00Z'
                 WHERE login_method_id='{method}'"
            ),
        );
        let hint = fixture
            .store
            .resolve_broker_token(&hasher(), &first.session.token)
            .unwrap()
            .membership_renewal
            .unwrap();
        assert_eq!(hint.state.as_str(), state);
        assert_eq!(
            hint.next_attempt_after.as_deref(),
            Some("2026-10-20T01:00:00Z")
        );
    }
    // A disabled provider, an inactive method and an ended row do not.
    let resolve = || {
        fixture
            .store
            .resolve_broker_token(&hasher(), &first.session.token)
            .unwrap()
            .membership_renewal
    };
    sql(&fixture.store, "UPDATE oidc_provider_state SET enabled = 0");
    assert_eq!(resolve(), None);
    sql(&fixture.store, "UPDATE oidc_provider_state SET enabled = 1");
    assert!(resolve().is_some());
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_renewals SET state='ended', ended_reason='sign_in_required',
               payload_version=NULL, key_id=NULL, nonce=NULL, ciphertext=NULL,
               last_failure_code=NULL, last_failure_at=NULL, next_attempt_after=NULL
             WHERE login_method_id='{method}'"
        ),
    );
    assert_eq!(resolve(), None);
    // No row, as without renewal: no hint.
    let other = succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_A], -10, None));
    assert_eq!(
        fixture
            .store
            .resolve_broker_token(&hasher(), &other.session.token)
            .unwrap()
            .membership_renewal,
        None
    );
}

/// An attempt starts only inside the renewal window, at the provider's
/// generation, for an eligible non-ended row whose backoff passed and whose
/// previous attempt started at least 60 s ago. The start is durable and
/// decrypts the payload; a skip writes nothing.
#[test]
fn attempt_start_rechecks_eligibility_and_records_the_interval() {
    let fixture = fixture(true);
    // Evidence until +3600-2800 = +800, inside the 900 s window now.
    let method = renewable_alice(&fixture, -2800);
    let before = fixture.renewal(&method).unwrap();
    // Outside the window (at -200 the evidence has 1000 s left): nothing.
    assert!(matches!(
        fixture.attempt(&method, -200),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::EvidenceCurrent)
    ));
    assert!(matches!(
        fixture.attempt_at_generation(&method, 0, fixture.generation + 1),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::ProviderChanged)
    ));
    assert_eq!(fixture.renewal(&method).unwrap(), before);

    let start = fixture.start(&method, 0);
    assert_eq!(start.fence.login_method_id, method);
    assert_eq!(start.fence.principal_id, "alice");
    assert_eq!(start.fence.external_subject, subject(USER));
    assert_eq!(start.fence.config_generation, fixture.generation);
    assert_eq!(start.fence.tenant_id, TENANT);
    assert_eq!(start.fence.client_id, CLIENT);
    assert_eq!(start.fence.token_version, before.token_version);
    assert_eq!(start.failure_count, 0);
    assert_eq!(start.material.refresh_token(), "refresh-1");
    assert_eq!(start.material.reference(), &reference());
    let started = fixture.renewal(&method).unwrap();
    assert_eq!(started.last_attempt_at, Some(at(&fixture, 0)));
    assert_eq!(started.token_version, before.token_version);
    assert!(!format!("{start:?}").contains("refresh-1"));

    // The durable interval: 59 s later no attempt starts; 60 s later one does.
    assert!(matches!(
        fixture.attempt(&method, 59),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::AttemptInterval)
    ));
    let _ = fixture.start(&method, 60);
    // A backoff in the future, an ended row and an inactive method skip.
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_renewals SET state='retrying',
               last_failure_code='unavailable', last_failure_at='{now}',
               next_attempt_after='{next}'
             WHERE login_method_id='{method}'",
            now = at(&fixture, 60),
            next = at(&fixture, 300),
        ),
    );
    assert!(matches!(
        fixture.attempt(&method, 200),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::NotDue)
    ));
    let retried = fixture.start(&method, 300);
    assert_eq!(retried.fence.token_version, before.token_version);
    sql(
        &fixture.store,
        &format!(
            "UPDATE principal_login_methods SET status='disabled' WHERE login_method_id='{method}'"
        ),
    );
    assert!(matches!(
        fixture.attempt(&method, 400),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::NotRenewable)
    ));
    sql(
        &fixture.store,
        &format!(
            "UPDATE principal_login_methods SET status='active' WHERE login_method_id='{method}';
             UPDATE oidc_membership_renewals SET state='ended', ended_reason='sign_in_required',
               payload_version=NULL, key_id=NULL, nonce=NULL, ciphertext=NULL,
               last_failure_code=NULL, last_failure_at=NULL, next_attempt_after=NULL
             WHERE login_method_id='{method}'"
        ),
    );
    assert!(matches!(
        fixture.attempt(&method, 500),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::NotRenewable)
    ));
    // Absent evidence counts as expired.
    let bob = succeeded(fixture.sign_in(
        OTHER_USER,
        "bob",
        &[GROUP_A],
        -10,
        issued(&fixture.ring, "refresh-bob"),
    ))
    .login_method
    .login_method_id;
    sql(
        &fixture.store,
        &format!("DELETE FROM oidc_membership_refresh_state WHERE login_method_id='{bob}'"),
    );
    let _ = fixture.start(&bob, 0);
}

/// A renewal with complete groups from a strictly newer token replaces the
/// evidence with the same matching as sign-in, rotates the returned token
/// under a new version and clears failures; one not newer keeps the stored
/// evidence but still succeeds.
#[test]
fn successful_renewals_replace_or_keep_evidence_and_rotate_the_token() {
    let fixture = fixture(true);
    let method = renewable_alice(&fixture, -2800);
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_renewals SET state='retrying', failure_count=2,
               last_failure_code='unavailable', last_failure_at='{now}', next_attempt_after='{now}'
             WHERE login_method_id='{method}'",
            now = at(&fixture, -1),
        ),
    );
    let start = fixture.start(&method, 0);
    assert_eq!(start.failure_count, 2);
    assert_eq!(fixture.groups_at("alice", 0), ["team-a"]);
    let done = committed(fixture.commit(
        &start.fence,
        1,
        renewed(fixture.now, &[GROUP_B]),
        Some("refresh-2"),
    ));
    assert_eq!(done.evidence, Some(OidcMembershipEvidence::Replaced));
    assert!(done.membership_changed);
    assert_eq!(done.membership.groups, ["team-b"]);
    assert_eq!(done.principal_id, "alice");
    // Evidence counts from min(iat, now) for the provider's TTL.
    assert_eq!(done.valid_until, Some(at(&fixture, 3600)));
    let row = fixture.renewal(&method).unwrap();
    assert_eq!(done.record, row);
    assert_eq!(row.state, OidcMembershipRenewalState::Active);
    assert_eq!(row.failure_count, 0);
    assert_eq!(row.last_failure_code, None);
    assert_eq!(row.next_attempt_after, None);
    assert_eq!(row.last_renewed_at, Some(at(&fixture, 1)));
    assert_eq!(row.recorded_at, at(&fixture, 1));
    assert_eq!(row.observation_iat, fixture.now);
    assert_ne!(row.token_version, start.fence.token_version);
    let material = fixture.material(&method).unwrap();
    assert_eq!(material.refresh_token(), "refresh-2");
    assert_eq!(material.reference(), &reference());
    assert_eq!(fixture.groups_at("alice", 3599), ["team-b"]);
    assert!(fixture.groups_at("alice", 3600).is_empty());

    // The same groups from a newer token: replaced, unchanged.
    let start = fixture.start(&method, 2900);
    let same = committed(fixture.commit(
        &start.fence,
        2900,
        renewed(fixture.now + 2900, &[GROUP_B]),
        None,
    ));
    assert_eq!(same.evidence, Some(OidcMembershipEvidence::Replaced));
    assert!(!same.membership_changed);
    assert_eq!(same.valid_until, Some(at(&fixture, 6500)));
    // Without a returned token the stored one stays at its version.
    assert_eq!(same.record.token_version, start.fence.token_version);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-2"
    );

    // A token not newer than the watermark (equal `iat`) keeps the evidence.
    let start = fixture.start(&method, 5800);
    let kept = committed(fixture.commit(
        &start.fence,
        5800,
        renewed(fixture.now + 2900, &[GROUP_A]),
        Some("refresh-3"),
    ));
    assert_eq!(kept.evidence, Some(OidcMembershipEvidence::KeptNewer));
    assert!(!kept.membership_changed);
    assert_eq!(kept.membership.groups, ["team-b"]);
    assert_eq!(kept.valid_until, Some(at(&fixture, 6500)));
    assert_eq!(kept.record.last_renewed_at, Some(at(&fixture, 5800)));
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-3"
    );

    // Microsoft's clock ahead: evidence counts from now, the watermark keeps
    // the raw `iat`.
    let start = fixture.start(&method, 5900);
    let ahead = committed(fixture.commit(
        &start.fence,
        5900,
        renewed(fixture.now + 5960, &[GROUP_A]),
        None,
    ));
    assert_eq!(ahead.evidence, Some(OidcMembershipEvidence::Replaced));
    assert_eq!(ahead.valid_until, Some(at(&fixture, 9500)));
    assert_eq!(ahead.record.observation_iat, fixture.now + 5960);
}

/// Renewal never creates an account, so it never enrolls one: a group that
/// adds new Microsoft users gains no member when an existing account renews.
#[test]
fn renewal_never_runs_group_auto_enrollment() {
    let fixture = fixture(true);
    let method = renewable_alice(&fixture, -2800);
    fixture
        .store
        .create_group(GroupWriteRequest {
            group_id: "defaults".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: true,
            created_by: "admin".into(),
        })
        .unwrap();
    let start = fixture.start(&method, 0);
    let done = committed(fixture.commit(
        &start.fence,
        1,
        renewed(fixture.now, &[GROUP_A, GROUP_B]),
        Some("refresh-2"),
    ));
    assert_eq!(done.evidence, Some(OidcMembershipEvidence::Replaced));
    assert_eq!(done.membership.groups, ["team-a", "team-b"]);
    assert!(fixture.store.group_members("defaults").unwrap().is_empty());
}

/// Failures leave the evidence to expire: throttled and unavailable retry,
/// the rest block; incomplete groups and a stale `iat` raise the watermark,
/// and only incomplete groups store a returned token; endings delete it.
#[test]
fn failed_renewals_retry_block_or_end_without_extending_evidence() {
    use OidcMembershipRenewalFailureCode as Code;
    let fixture = fixture(true);
    let method = renewable_alice(&fixture, -2800);
    let evidence = |fixture: &Fixture| {
        fixture
            .store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
                [&method],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
    };
    let initial_evidence = evidence(&fixture);
    let mut offset = 0;
    let mut failures = 0;
    for (code, observed, rotation, state) in [
        (Code::Unavailable, None, None, "retrying"),
        (Code::Throttled, None, None, "retrying"),
        (Code::ClientRejected, None, None, "blocked"),
        (Code::RequestRejected, None, None, "blocked"),
        (Code::InvalidResponse, None, None, "blocked"),
        (Code::InvalidResponse, Some(-2000), None, "blocked"),
        (
            Code::GroupsIncomplete,
            Some(-1000),
            Some("refresh-incomplete"),
            "blocked",
        ),
    ] {
        let before = fixture.renewal(&method).unwrap();
        let start = fixture.start(&method, offset);
        let next = at(&fixture, offset + 30);
        let done = committed(fixture.commit(
            &start.fence,
            offset,
            failed(
                code,
                observed.map(|delta| fixture.now + delta),
                next.clone(),
            ),
            rotation,
        ));
        failures += 1;
        let row = fixture.renewal(&method).unwrap();
        assert_eq!(done.record, row, "{code:?}");
        assert_eq!(done.evidence, None);
        assert_eq!(row.state.as_str(), state, "{code:?}");
        assert_eq!(row.last_failure_code, Some(code), "{code:?}");
        assert_eq!(row.last_failure_at, Some(at(&fixture, offset)));
        assert_eq!(row.next_attempt_after, Some(next));
        assert_eq!(row.failure_count, failures);
        assert_eq!(
            row.observation_iat,
            observed
                .map(|delta| fixture.now + delta)
                .unwrap_or(before.observation_iat)
                .max(before.observation_iat),
            "{code:?}"
        );
        match rotation {
            Some(token) => {
                assert_ne!(row.token_version, before.token_version);
                assert_eq!(fixture.material(&method).unwrap().refresh_token(), token);
            }
            None => {
                assert_eq!(row.token_version, before.token_version, "{code:?}");
                assert_eq!(
                    fixture.material(&method).unwrap().refresh_token(),
                    "refresh-1",
                    "{code:?}"
                );
            }
        }
        assert_eq!(evidence(&fixture), initial_evidence, "{code:?}");
        offset += 60;
    }
    // Only a renewal or incomplete groups may store a returned token.
    let start = fixture.start(&method, offset);
    assert!(matches!(
        fixture
            .store
            .commit_oidc_membership_renewal(OidcMembershipRenewalCommitRequest {
                fence: start.fence.clone(),
                now: at(&fixture, offset),
                result: failed(Code::Unavailable, None, at(&fixture, offset + 30)),
                rotation: Some(
                    OidcMembershipRenewalRotation::new(
                        fixture.ring.clone(),
                        "refresh-x".into(),
                        reference()
                    )
                    .unwrap()
                ),
            }),
        Err(ManagedStoreError::InputInvalid(_))
    ));
    // Ending deletes the token; readiness and inventory accept the row.
    for reason in [
        OidcMembershipRenewalEndedReason::IdentityMismatch,
        OidcMembershipRenewalEndedReason::SignInRequired,
    ] {
        let method = renewable_alice(&fixture, -2800);
        let start = fixture.start(&method, offset + 600);
        let done = committed(fixture.commit(
            &start.fence,
            offset + 600,
            OidcMembershipRenewalResult::Ended(reason),
            None,
        ));
        assert_eq!(done.record.state, OidcMembershipRenewalState::Ended);
        assert_eq!(done.record.ended_reason, Some(reason));
        assert_eq!(done.record.next_attempt_after, None);
        assert_eq!(done.record.last_failure_code, None);
        assert_eq!(done.record.recorded_at, at(&fixture, offset + 600));
        assert!(fixture.material(&method).is_none());
        fixture.store.check_ready(Some(&fixture.ring)).unwrap();
        assert!(matches!(
            fixture.attempt(&method, offset + 1200),
            OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::NotRenewable)
        ));
        offset += 1200;
    }
}

/// Every outcome write runs under the full fence: a provider at another
/// generation, tenant or client, a disabled or relinked method, a disabled
/// principal and a token version replaced by a sign-in each discard it.
#[test]
fn outcome_writes_are_discarded_when_the_fence_fails() {
    let fixture = fixture(true);
    let method = renewable_alice(&fixture, -2800);
    let start = fixture.start(&method, 0);
    let attempted = fixture.renewal(&method).unwrap();
    let outcomes = || {
        [
            renewed(fixture.now, &[GROUP_B]),
            failed(
                OidcMembershipRenewalFailureCode::Unavailable,
                None,
                at(&fixture, 30),
            ),
            OidcMembershipRenewalResult::Ended(OidcMembershipRenewalEndedReason::SignInRequired),
        ]
    };
    // The stored evidence: its window and matched bindings.
    let evidence = || -> (String, Vec<String>) {
        let conn = fixture.store.connection.lock().unwrap();
        let valid_until = conn
            .query_row(
                "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
                [&method],
                |row| row.get(0),
            )
            .unwrap();
        (valid_until, evidence_bindings(&conn, &method).unwrap())
    };
    let initial = evidence();
    let superseded = |fence: &OidcMembershipRenewalFence, case: &str| {
        let before = fixture.renewal(&method);
        for result in outcomes() {
            assert!(
                matches!(
                    fixture.commit(fence, 1, result, None),
                    OidcMembershipRenewalCommit::Superseded
                ),
                "{case}"
            );
            assert_eq!(fixture.renewal(&method), before, "{case}");
            assert_eq!(evidence(), initial, "{case}");
        }
    };
    for (case, fence) in [
        (
            "generation",
            OidcMembershipRenewalFence {
                config_generation: start.fence.config_generation + 1,
                ..start.fence.clone()
            },
        ),
        (
            "tenant",
            OidcMembershipRenewalFence {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9".into(),
                ..start.fence.clone()
            },
        ),
        (
            "client",
            OidcMembershipRenewalFence {
                client_id: OTHER_CLIENT.into(),
                ..start.fence.clone()
            },
        ),
        (
            "subject",
            OidcMembershipRenewalFence {
                external_subject: subject(OTHER_USER),
                ..start.fence.clone()
            },
        ),
        (
            "principal",
            OidcMembershipRenewalFence {
                principal_id: "bob".into(),
                ..start.fence.clone()
            },
        ),
        (
            "token version",
            OidcMembershipRenewalFence {
                token_version: Uuid::new_v4().to_string(),
                ..start.fence.clone()
            },
        ),
    ] {
        superseded(&fence, case);
    }
    // The row still holds the attempt's start only.
    assert_eq!(fixture.renewal(&method).unwrap(), attempted);

    // A disabled method or provider discards it too.
    sql(
        &fixture.store,
        &format!(
            "UPDATE principal_login_methods SET status='disabled' WHERE login_method_id='{method}'"
        ),
    );
    superseded(&start.fence, "method disabled");
    sql(
        &fixture.store,
        &format!(
            "UPDATE principal_login_methods SET status='active' WHERE login_method_id='{method}';
             UPDATE principals SET status='disabled' WHERE principal_id='alice'"
        ),
    );
    superseded(&start.fence, "principal disabled");
    sql(
        &fixture.store,
        "UPDATE principals SET status='active' WHERE principal_id='alice';
         UPDATE oidc_provider_state SET enabled = 0",
    );
    superseded(&start.fence, "provider disabled");
    sql(&fixture.store, "UPDATE oidc_provider_state SET enabled = 1");

    // A sign-in during the attempt wins: its new token version fences the
    // renewal out, whatever the renewal's `iat`.
    let signed_in = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -2700,
        issued(&fixture.ring, "refresh-sign-in"),
    ));
    assert_eq!(
        signed_in.membership_evidence,
        OidcMembershipEvidence::Replaced
    );
    let after_sign_in = fixture.renewal(&method).unwrap();
    assert!(matches!(
        fixture.commit(
            &start.fence,
            1,
            renewed(fixture.now + 60, &[GROUP_B]),
            Some("late")
        ),
        OidcMembershipRenewalCommit::Superseded
    ));
    assert_eq!(fixture.renewal(&method).unwrap(), after_sign_in);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-sign-in"
    );
    // The sign-in kept the attempt time, so no new attempt starts yet.
    assert_eq!(after_sign_in.last_attempt_at, Some(at(&fixture, 0)));
    assert!(matches!(
        fixture.attempt(&method, 30),
        OidcMembershipRenewalAttempt::Skipped(OidcMembershipRenewalSkip::AttemptInterval)
    ));
}

/// Sign-in and renewal order evidence by raw `iat` in both completion
/// orders, and incomplete observations from either writer keep older
/// complete claims out (design §8.7).
#[test]
fn sign_in_and_renewal_order_evidence_by_raw_iat() {
    use OidcMembershipRenewalFailureCode as Code;
    let fixture = fixture(true);
    // Renewal first (iat -100), then a delayed sign-in with an older token
    // (iat -200): the sign-in keeps the renewal's evidence but records its
    // session and token.
    let method = renewable_alice(&fixture, -2800);
    let start = fixture.start(&method, 0);
    committed(fixture.commit(
        &start.fence,
        0,
        renewed(fixture.now - 100, &[GROUP_B]),
        None,
    ));
    let delayed = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -200,
        issued(&fixture.ring, "refresh-delayed"),
    ));
    assert_eq!(
        delayed.membership_evidence,
        OidcMembershipEvidence::KeptNewer
    );
    assert_eq!(fixture.groups_at("alice", 0), ["team-b"]);
    assert_eq!(
        fixture.material(&method).unwrap().refresh_token(),
        "refresh-delayed"
    );

    // A trusted stale-`iat` renewal (iat -50) raises the watermark, so a
    // delayed older sign-in (iat -60) does not replace the evidence either.
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_refresh_state SET valid_until='{until}'
             WHERE login_method_id='{method}'",
            until = at(&fixture, 200),
        ),
    );
    let start = fixture.start(&method, 100);
    committed(fixture.commit(
        &start.fence,
        100,
        failed(
            Code::InvalidResponse,
            Some(fixture.now - 50),
            at(&fixture, 3700),
        ),
        None,
    ));
    let older = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -60,
        issued(&fixture.ring, "refresh-older"),
    ));
    assert_eq!(older.membership_evidence, OidcMembershipEvidence::KeptNewer);
    assert_eq!(fixture.groups_at("alice", 0), ["team-b"]);

    // An incomplete sign-in (iat -20) keeps an older renewal (iat -30) out.
    let flow = fixture.flow.get() + 1;
    fixture.flow.set(flow);
    assert!(fixture.incomplete(flow, USER, -20));
    sql(
        &fixture.store,
        &format!(
            "UPDATE oidc_membership_refresh_state SET valid_until='{until}'
             WHERE login_method_id='{method}';
             UPDATE oidc_membership_renewals SET state='active', last_failure_code=NULL,
               last_failure_at=NULL, next_attempt_after=NULL
             WHERE login_method_id='{method}'",
            until = at(&fixture, 300),
        ),
    );
    let start = fixture.start(&method, 200);
    let kept = committed(fixture.commit(
        &start.fence,
        200,
        renewed(fixture.now - 30, &[GROUP_A]),
        None,
    ));
    assert_eq!(kept.evidence, Some(OidcMembershipEvidence::KeptNewer));
    assert_eq!(fixture.groups_at("alice", 0), ["team-b"]);
    // An incomplete renewal (iat -10) keeps an older complete sign-in out.
    let start = fixture.start(&method, 300);
    committed(fixture.commit(
        &start.fence,
        300,
        failed(
            Code::GroupsIncomplete,
            Some(fixture.now - 10),
            at(&fixture, 3900),
        ),
        None,
    ));
    let older = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -15,
        issued(&fixture.ring, "refresh-15"),
    ));
    assert_eq!(older.membership_evidence, OidcMembershipEvidence::KeptNewer);
    assert_eq!(fixture.groups_at("alice", 0), ["team-b"]);
    // A newer complete one replaces it.
    let newer = succeeded(fixture.sign_in(
        USER,
        "alice",
        &[GROUP_A],
        -5,
        issued(&fixture.ring, "refresh-5"),
    ));
    assert_eq!(newer.membership_evidence, OidcMembershipEvidence::Replaced);
    assert_eq!(fixture.groups_at("alice", 0), ["team-a"]);
}

/// One renewal status shape serves every API: every key is present, an
/// ended row reports its reason as its state, and the accessors read a
/// method's evidence window and renewal row.
#[test]
fn renewal_status_and_microsoft_membership_report_each_state() {
    let fixture = fixture(true);
    let method = renewable_alice(&fixture, -10);
    let valid_until = fixture
        .store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT valid_until FROM oidc_membership_refresh_state WHERE login_method_id = ?1",
            [&method],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    assert_eq!(
        fixture.store.oidc_membership_valid_until(&method).unwrap(),
        Some(valid_until.clone())
    );
    let membership = fixture
        .store
        .microsoft_membership("alice")
        .unwrap()
        .unwrap();
    assert_eq!(membership.login_method_id, method);
    assert_eq!(membership.valid_until, Some(valid_until));
    assert_eq!(membership.renewal, fixture.renewal(&method));
    let status = |fixture: &Fixture| {
        serde_json::to_value(fixture.renewal(&method).unwrap().status()).unwrap()
    };
    assert_eq!(
        status(&fixture),
        json!({"state": "active", "lastRenewedAt": null, "nextAttemptAfter": null, "lastFailure": null})
    );
    for state in ["retrying", "blocked"] {
        sql(
            &fixture.store,
            &format!(
                "UPDATE oidc_membership_renewals SET state='{state}',
                   last_renewed_at='2026-10-20T00:30:00Z', last_failure_code='client_rejected',
                   last_failure_at='2026-10-20T01:00:00Z', next_attempt_after='2026-10-20T02:00:00Z'
                 WHERE login_method_id='{method}'"
            ),
        );
        assert_eq!(
            status(&fixture),
            json!({
                "state": state,
                "lastRenewedAt": "2026-10-20T00:30:00Z",
                "nextAttemptAfter": "2026-10-20T02:00:00Z",
                "lastFailure": {"code": "client_rejected", "at": "2026-10-20T01:00:00Z"},
            })
        );
    }
    for reason in ["sign_in_required", "not_issued", "identity_mismatch"] {
        sql(
            &fixture.store,
            &format!(
                "UPDATE oidc_membership_renewals SET state='ended', ended_reason='{reason}',
                   payload_version=NULL, key_id=NULL, nonce=NULL, ciphertext=NULL,
                   last_failure_code=NULL, last_failure_at=NULL, next_attempt_after=NULL
                 WHERE login_method_id='{method}'"
            ),
        );
        assert_eq!(
            status(&fixture),
            json!({
                "state": reason,
                "lastRenewedAt": "2026-10-20T00:30:00Z",
                "nextAttemptAfter": null,
                "lastFailure": null,
            })
        );
    }

    // A method without a renewal row or evidence, and a principal without a
    // Microsoft method.
    let bob = succeeded(fixture.sign_in(OTHER_USER, "bob", &[GROUP_A], -10, None))
        .login_method
        .login_method_id;
    sql(
        &fixture.store,
        &format!("DELETE FROM oidc_membership_refresh_state WHERE login_method_id='{bob}'"),
    );
    assert_eq!(
        fixture.store.microsoft_membership("bob").unwrap(),
        Some(MicrosoftMembershipRecord {
            login_method_id: bob.clone(),
            valid_until: None,
            renewal: None,
        })
    );
    assert_eq!(
        fixture.store.oidc_membership_valid_until(&bob).unwrap(),
        None
    );
    fixture
        .store
        .create_principal(PrincipalWriteRequest {
            principal_id: "carol".into(),
            kind: "user".into(),
            role: PrincipalRole::User,
            self_service_enabled: None,
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    assert_eq!(fixture.store.microsoft_membership("carol").unwrap(), None);
}
