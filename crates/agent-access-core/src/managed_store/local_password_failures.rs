//! Failed local-password verifications, counted per `(principal, source)`.
//!
//! A lockout from one source never blocks another source, so a third party
//! cannot lock a named user out from the user's own address. Rows are keyed
//! by the principal ID exactly as submitted, whether or not it names an
//! existing principal, so lockout responses do not reveal principal existence.
//!
//! Rotating sources never avoids lockout. Each principal keeps at most
//! [`MAX_SOURCES_PER_PRINCIPAL`] per-source rows, and rows holding live
//! failures are never evicted to make room. Once a principal is at that cap,
//! failures from sources without their own row count into the principal's
//! single overflow row ([`OVERFLOW_SOURCE`]), which locks as a unit; while it
//! is locked, every source without its own row is locked for the principal.
//! [`MAX_ROWS`] bounds the table by evicting rows of unregistered principal IDs.

use super::*;

/// Maximum per-source rows kept per principal, not counting the overflow row.
pub(super) const MAX_SOURCES_PER_PRINCIPAL: i64 = 256;
/// Reserved `source` of a principal's overflow row. Real sources are IPv4
/// addresses, IPv6 /64 prefixes, or `unknown`, and [`validate_source`]
/// rejects this value, so it never names a real source.
pub(super) const OVERFLOW_SOURCE: &str = "*";
/// Global row cap. When a new row would exceed it, rows whose principal ID is
/// not a registered principal are evicted, oldest `last_failed_at` first.
/// Rows of registered principals are never evicted by this cap: they are
/// already bounded at [`MAX_SOURCES_PER_PRINCIPAL`] plus one overflow row per
/// principal, so the table may exceed the cap only by such rows.
pub(super) const MAX_ROWS: i64 = 65_536;
const MAX_SOURCE_BYTES: usize = 64;
// Keeps timestamp arithmetic in range for absurdly long configured TTLs.
const MAX_LOCKOUT_TTL_SECONDS: u64 = 100 * 365 * 24 * 60 * 60;

pub(super) fn validate_source(source: &str) -> Result<(), ManagedStoreError> {
    if source.is_empty()
        || source == OVERFLOW_SOURCE
        || source.len() > MAX_SOURCE_BYTES
        || !source.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(input_invalid("local password source is invalid"));
    }
    Ok(())
}

/// Whether `source` is locked out for the principal: by its own row when it
/// has a live one, otherwise by the principal's overflow row. A row that
/// [`prune`] would delete counts as absent, so a stale own row cannot exempt
/// its source from an active overflow lockout.
pub(super) fn source_locked(
    conn: &Connection,
    principal_id: &str,
    source: &str,
    lockout_ttl_seconds: u64,
    now: DateTime<Utc>,
) -> Result<bool, ManagedStoreError> {
    let ttl = Duration::seconds(lockout_ttl_seconds.min(MAX_LOCKOUT_TTL_SECONDS) as i64);
    let now_text = normalized_timestamp(now);
    let own: Option<Option<String>> = conn
        .query_row(
            "SELECT locked_until FROM local_password_failures
             WHERE principal_id = ?1 AND source = ?2
               AND NOT (last_failed_at <= ?3 AND (locked_until IS NULL OR locked_until <= ?4))",
            params![
                principal_id,
                source,
                normalized_timestamp(now - ttl),
                now_text
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    let locked_until = match own {
        Some(locked_until) => locked_until,
        None => failure_row(conn, principal_id, OVERFLOW_SOURCE)?
            .and_then(|(_, locked_until)| locked_until),
    };
    Ok(locked_until.is_some_and(|locked_until| locked_until > now_text))
}

/// Records one failed verification and returns whether the source is now
/// locked out for the principal. A source without its own row gets one while
/// the principal has fewer than [`MAX_SOURCES_PER_PRINCIPAL`] per-source rows;
/// otherwise the failure counts into the principal's overflow row.
pub(super) fn record_failure(
    conn: &mut Connection,
    principal_id: &str,
    source: &str,
    max_failed_attempts: u32,
    lockout_ttl_seconds: u64,
    now: DateTime<Utc>,
) -> Result<bool, ManagedStoreError> {
    let ttl = Duration::seconds(lockout_ttl_seconds.min(MAX_LOCKOUT_TTL_SECONDS) as i64);
    let now_text = normalized_timestamp(now);
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_unavailable)?;
    prune(&tx, now, ttl)?;
    let mut row_source = source;
    let mut existing = failure_row(&tx, principal_id, source)?;
    if existing.is_none() && source_row_count(&tx, principal_id)? >= MAX_SOURCES_PER_PRINCIPAL {
        row_source = OVERFLOW_SOURCE;
        existing = failure_row(&tx, principal_id, OVERFLOW_SOURCE)?;
    }
    let failed_attempts = match existing {
        // An expired lockout restarts the count.
        Some((_, Some(locked_until))) if locked_until <= now_text => 1,
        Some((failed_attempts, _)) => failed_attempts.saturating_add(1),
        None => {
            make_global_room(&tx, MAX_ROWS)?;
            1
        }
    };
    let locked_until = (failed_attempts >= i64::from(max_failed_attempts))
        .then(|| normalized_timestamp(now + ttl));
    tx.execute(
        "INSERT INTO local_password_failures
         (principal_id, source, failed_attempts, last_failed_at, locked_until)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(principal_id, source) DO UPDATE SET
           failed_attempts = excluded.failed_attempts,
           last_failed_at = excluded.last_failed_at,
           locked_until = excluded.locked_until",
        params![
            principal_id,
            row_source,
            failed_attempts,
            now_text,
            locked_until
        ],
    )
    .map_err(sql_unavailable)?;
    tx.commit().map_err(sql_unavailable)?;
    Ok(locked_until.is_some())
}

/// `(failed_attempts, locked_until)` of one row.
fn failure_row(
    conn: &Connection,
    principal_id: &str,
    source: &str,
) -> Result<Option<(i64, Option<String>)>, ManagedStoreError> {
    conn.query_row(
        "SELECT failed_attempts, locked_until FROM local_password_failures
         WHERE principal_id = ?1 AND source = ?2",
        params![principal_id, source],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(sql_unavailable)
}

/// Per-source rows of a principal, excluding its overflow row.
fn source_row_count(conn: &Connection, principal_id: &str) -> Result<i64, ManagedStoreError> {
    conn.query_row(
        "SELECT COUNT(1) FROM local_password_failures
         WHERE principal_id = ?1 AND source <> ?2",
        params![principal_id, OVERFLOW_SOURCE],
        |row| row.get(0),
    )
    .map_err(sql_unavailable)
}

/// Deletes rows whose lockout has expired and whose last failure is older
/// than the lockout TTL. The `last_failed_at` index bounds the scan to
/// candidate rows. Every remaining row holds live failures.
fn prune(conn: &Connection, now: DateTime<Utc>, ttl: Duration) -> Result<(), ManagedStoreError> {
    conn.execute(
        "DELETE FROM local_password_failures
         WHERE last_failed_at <= ?1 AND (locked_until IS NULL OR locked_until <= ?2)",
        params![normalized_timestamp(now - ttl), normalized_timestamp(now)],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Makes room for one new row under `max_rows` by evicting rows whose
/// principal ID is not a registered principal, oldest `last_failed_at` first.
/// Rows of registered principals are never evicted; when too few other rows
/// exist, the new row is still recorded.
fn make_global_room(conn: &Connection, max_rows: i64) -> Result<(), ManagedStoreError> {
    let rows: i64 = conn
        .query_row("SELECT COUNT(1) FROM local_password_failures", [], |row| {
            row.get(0)
        })
        .map_err(sql_unavailable)?;
    let excess = rows - max_rows + 1;
    if excess <= 0 {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM local_password_failures WHERE rowid IN (
           SELECT failures.rowid FROM local_password_failures AS failures
           WHERE NOT EXISTS (
             SELECT 1 FROM principals WHERE principals.principal_id = failures.principal_id)
           ORDER BY failures.last_failed_at, failures.principal_id, failures.source
           LIMIT ?1)",
        params![excess],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

pub(super) fn clear_source(
    conn: &Connection,
    principal_id: &str,
    source: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "DELETE FROM local_password_failures WHERE principal_id = ?1 AND source = ?2",
        params![principal_id, source],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

pub(super) fn clear_principal(
    conn: &Connection,
    principal_id: &str,
) -> Result<(), ManagedStoreError> {
    conn.execute(
        "DELETE FROM local_password_failures WHERE principal_id = ?1",
        params![principal_id],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

/// Fills the lockout summary of a local-password login method: whether any
/// source is currently locked and the latest `locked_until`. Source
/// addresses are never exposed.
pub(super) fn attach_lockout(
    conn: &Connection,
    record: &mut LoginMethodRecord,
) -> Result<(), ManagedStoreError> {
    if record.method != "local_password" {
        return Ok(());
    }
    let locked_until: Option<String> = conn
        .query_row(
            "SELECT MAX(locked_until) FROM local_password_failures
             WHERE principal_id = ?1 AND locked_until > ?2",
            params![record.principal_id, normalized_now_string()],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    record.locked = locked_until.is_some();
    record.locked_until = locked_until;
    Ok(())
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
    for migration in MANAGED_STORE_MIGRATIONS {
        expected
            .execute_batch(migration.sql)
            .map_err(sql_unavailable)?;
        if migration.version == MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION {
            break;
        }
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL_SECONDS: u64 = 15 * 60;

    fn store_at(temp: &tempfile::TempDir, name: &str) -> (ManagedStoreConfig, ManagedStore) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join(name).display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        (config, store)
    }

    fn fixture() -> (tempfile::TempDir, ManagedStore, LocalPasswordHasher) {
        let temp = tempfile::TempDir::new().unwrap();
        let (_, store) = store_at(&temp, "store.sqlite");
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
        let hasher = LocalPasswordHasher {
            verification_hook: None,
            key: Arc::new([21; 32]),
        };
        store
            .enable_local_password(
                &hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".into(),
                    password: "correct-password".into(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".into(),
                },
            )
            .unwrap();
        (temp, store, hasher)
    }

    fn verify(
        store: &ManagedStore,
        hasher: &LocalPasswordHasher,
        principal_id: &str,
        password: &str,
        source: &str,
    ) -> Result<VerifiedLocalPassword, ManagedStoreError> {
        store.verify_local_password(
            hasher,
            LocalPasswordVerifyRequest {
                principal_id: principal_id.into(),
                password: password.into(),
                source: source.into(),
                max_failed_attempts: 2,
                lockout_ttl_seconds: TTL_SECONDS,
            },
        )
    }

    fn record(store: &ManagedStore, principal_id: &str, source: &str, now: DateTime<Utc>) -> bool {
        let mut conn = store.connection.lock().unwrap();
        record_failure(&mut conn, principal_id, source, 3, TTL_SECONDS, now).unwrap()
    }

    fn rows(store: &ManagedStore, principal_id: &str) -> Vec<(String, i64, Option<String>)> {
        let conn = store.connection.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT source, failed_attempts, locked_until FROM local_password_failures
                 WHERE principal_id = ?1 ORDER BY source",
            )
            .unwrap();
        statement
            .query_map(params![principal_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn insert_row(
        store: &ManagedStore,
        principal_id: &str,
        source: &str,
        last_failed_at: DateTime<Utc>,
        locked_until: Option<DateTime<Utc>>,
    ) {
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO local_password_failures VALUES (?1, ?2, 1, ?3, ?4)",
                params![
                    principal_id,
                    source,
                    normalized_timestamp(last_failed_at),
                    locked_until.map(normalized_timestamp)
                ],
            )
            .unwrap();
    }

    fn assert_locked(result: Result<VerifiedLocalPassword, ManagedStoreError>) {
        assert!(matches!(result, Err(ManagedStoreError::LocalLoginLocked)));
    }

    fn assert_failed(result: Result<VerifiedLocalPassword, ManagedStoreError>) {
        assert!(matches!(result, Err(ManagedStoreError::LocalLoginFailed)));
    }

    #[test]
    fn lockout_from_one_source_does_not_block_another_and_unlock_clears_all() {
        let (_temp, store, hasher) = fixture();
        assert_failed(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "198.51.100.7",
        ));
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "198.51.100.7",
        ));
        // The locked source is rejected before hashing, even with the right password.
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "correct-password",
            "198.51.100.7",
        ));
        // The user's own source is unaffected.
        verify(&store, &hasher, "alice", "correct-password", "203.0.113.10").unwrap();

        let method = store.list_login_methods("alice").unwrap().remove(0);
        assert_eq!(method.status, "active");
        assert!(method.locked);
        let locked_until = method.locked_until.clone().unwrap();
        assert_eq!(
            rows(&store, "alice")[0].2.as_deref(),
            Some(locked_until.as_str())
        );
        let serialized = serde_json::to_value(&method).unwrap();
        assert_eq!(serialized["locked"], true);
        assert_eq!(serialized["lockedUntil"], locked_until);
        assert!(serialized.get("failedAttempts").is_none());
        assert!(!serialized.to_string().contains("198.51.100.7"));

        let unlocked = store.unlock_local_password("alice", "admin").unwrap();
        assert!(!unlocked.locked);
        assert_eq!(unlocked.locked_until, None);
        assert!(rows(&store, "alice").is_empty());
        verify(&store, &hasher, "alice", "correct-password", "198.51.100.7").unwrap();
    }

    #[test]
    fn success_clears_only_the_verifying_source() {
        let (_temp, store, hasher) = fixture();
        assert_failed(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "198.51.100.7",
        ));
        assert_failed(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "2001:db8:1:2::/64",
        ));
        verify(&store, &hasher, "alice", "correct-password", "198.51.100.7").unwrap();
        assert_eq!(
            rows(&store, "alice"),
            vec![("2001:db8:1:2::/64".to_string(), 1, None)]
        );
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "2001:db8:1:2::/64",
        ));
    }

    #[test]
    fn unknown_principals_lock_out_like_existing_ones() {
        let (_temp, store, hasher) = fixture();
        assert_failed(verify(
            &store,
            &hasher,
            "ghost",
            "wrong-password",
            "198.51.100.7",
        ));
        assert_locked(verify(
            &store,
            &hasher,
            "ghost",
            "wrong-password",
            "198.51.100.7",
        ));
        assert_locked(verify(
            &store,
            &hasher,
            "ghost",
            "wrong-password",
            "198.51.100.7",
        ));
        assert!(rows(&store, "alice").is_empty());
    }

    #[test]
    fn lockout_expires_after_ttl_and_restarts_the_count() {
        let (_temp, store, _) = fixture();
        let start = Utc::now();
        assert!(!record(&store, "alice", "198.51.100.7", start));
        assert!(!record(&store, "alice", "198.51.100.7", start));
        assert!(record(&store, "alice", "198.51.100.7", start));
        let conn = store.connection.lock().unwrap();
        let ttl = Duration::seconds(TTL_SECONDS as i64);
        let before_expiry = start + ttl - Duration::seconds(1);
        let after_expiry = start + ttl + Duration::seconds(1);
        assert!(source_locked(&conn, "alice", "198.51.100.7", TTL_SECONDS, before_expiry).unwrap());
        assert!(!source_locked(&conn, "alice", "198.51.100.7", TTL_SECONDS, after_expiry).unwrap());
        drop(conn);
        assert!(!record(&store, "alice", "198.51.100.7", after_expiry));
        assert_eq!(rows(&store, "alice")[0].1, 1);
    }

    #[test]
    fn unlocked_counters_are_forgotten_after_ttl() {
        let (_temp, store, _) = fixture();
        let start = Utc::now();
        assert!(!record(&store, "alice", "198.51.100.7", start));
        assert!(!record(&store, "alice", "198.51.100.7", start));
        let later = start + Duration::seconds(TTL_SECONDS as i64 + 1);
        assert!(!record(&store, "alice", "198.51.100.7", later));
        assert_eq!(rows(&store, "alice")[0].1, 1);
    }

    #[test]
    fn pruning_keeps_active_lockouts_and_recent_failures() {
        let (_temp, store, _) = fixture();
        let now = Utc::now();
        let old = now - Duration::hours(1);
        insert_row(&store, "bob", "stale-unlocked", old, None);
        insert_row(
            &store,
            "bob",
            "expired-lock",
            old,
            Some(old + Duration::minutes(15)),
        );
        insert_row(
            &store,
            "bob",
            "active-lock",
            old,
            Some(now + Duration::minutes(5)),
        );
        insert_row(&store, "bob", "recent", now - Duration::minutes(1), None);
        record(&store, "alice", "198.51.100.7", now);
        let remaining = rows(&store, "bob")
            .into_iter()
            .map(|(source, _, _)| source)
            .collect::<Vec<_>>();
        assert_eq!(remaining, ["active-lock", "recent"]);
    }

    fn total_rows(store: &ManagedStore) -> i64 {
        store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(1) FROM local_password_failures", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn fill_source_cap(store: &ManagedStore, principal_id: &str, last_failed_at: DateTime<Utc>) {
        for index in 0..MAX_SOURCES_PER_PRINCIPAL {
            insert_row(
                store,
                principal_id,
                &format!("source-{index:03}"),
                last_failed_at,
                None,
            );
        }
    }

    #[test]
    fn rotating_sources_past_the_cap_lock_through_the_overflow_row() {
        let (_temp, store, hasher) = fixture();
        // Rotated sources fill the per-source cap with live failures.
        fill_source_cap(&store, "alice", Utc::now() - Duration::minutes(1));
        // Further sources share one overflow row, which locks as a unit.
        assert_failed(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "198.51.100.1",
        ));
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "wrong-password",
            "198.51.100.2",
        ));
        // Every source without its own row is now locked, even with the
        // right password.
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "correct-password",
            "198.51.100.3",
        ));
        // No row holding live failures was evicted to make room.
        let stored = rows(&store, "alice");
        assert_eq!(stored.len() as i64, MAX_SOURCES_PER_PRINCIPAL + 1);
        assert_eq!(stored[0].0, OVERFLOW_SOURCE);
        assert_eq!(stored[0].1, 2);
        assert!(stored[0].2.is_some());
        assert!(stored[1..].iter().all(|(_, attempts, _)| *attempts == 1));
        let method = store.list_login_methods("alice").unwrap().remove(0);
        assert!(method.locked);
        assert_eq!(method.locked_until, stored[0].2);

        // A source with its own row keeps its own state. Success clears only
        // that row, after which the source falls under the overflow lockout.
        verify(&store, &hasher, "alice", "correct-password", "source-000").unwrap();
        assert_eq!(
            rows(&store, "alice").len() as i64,
            MAX_SOURCES_PER_PRINCIPAL
        );
        assert_locked(verify(
            &store,
            &hasher,
            "alice",
            "correct-password",
            "source-000",
        ));

        // Unlock clears the overflow row with every other source.
        store.unlock_local_password("alice", "admin").unwrap();
        assert!(rows(&store, "alice").is_empty());
        verify(&store, &hasher, "alice", "correct-password", "198.51.100.3").unwrap();
    }

    #[test]
    fn overflow_rows_behave_identically_for_unknown_principals_and_expire() {
        let (_temp, store, _) = fixture();
        let start = Utc::now();
        let ttl = Duration::seconds(TTL_SECONDS as i64);
        let later = start + ttl + Duration::seconds(1);
        for principal in ["alice", "ghost"] {
            // Per-source rows stay live past `later`; the overflow row does not.
            fill_source_cap(&store, principal, later);
            assert!(!record(&store, principal, "new-1", start));
            assert!(!record(&store, principal, "new-2", start));
            assert!(record(&store, principal, "new-3", start));
            {
                let conn = store.connection.lock().unwrap();
                assert!(source_locked(&conn, principal, "new-4", TTL_SECONDS, start).unwrap());
                assert!(
                    !source_locked(&conn, principal, "source-001", TTL_SECONDS, start).unwrap()
                );
                assert!(!source_locked(&conn, principal, "new-4", TTL_SECONDS, later).unwrap());
            }
            // After the lockout expires the overflow count restarts.
            assert!(!record(&store, principal, "new-5", later));
            let stored = rows(&store, principal);
            assert_eq!(stored.len() as i64, MAX_SOURCES_PER_PRINCIPAL + 1);
            assert_eq!(stored[0], (OVERFLOW_SOURCE.to_string(), 1, None));
        }
    }

    #[test]
    fn stale_own_row_does_not_exempt_a_source_from_the_overflow_lockout() {
        let (_temp, store, _) = fixture();
        let start = Utc::now();
        let ttl = Duration::seconds(TTL_SECONDS as i64);
        // The per-source rows are still live at `start`, so these failures
        // fill and lock the overflow row until `start + ttl`.
        fill_source_cap(&store, "alice", start - ttl + Duration::seconds(10));
        assert!(!record(&store, "alice", "new-1", start));
        assert!(!record(&store, "alice", "new-2", start));
        assert!(record(&store, "alice", "new-3", start));
        let conn = store.connection.lock().unwrap();
        // Before pruning runs again, source-001's own row has gone stale; it
        // must count as absent while the overflow lockout is still active.
        let check = start + Duration::seconds(20);
        assert!(source_locked(&conn, "alice", "source-001", TTL_SECONDS, check).unwrap());
        // While its own row is live, it keeps its own (unlocked) state.
        assert!(!source_locked(&conn, "alice", "source-001", TTL_SECONDS, start).unwrap());
    }

    #[test]
    fn global_cap_evicts_unregistered_rows_oldest_first() {
        let (_temp, store, _) = fixture();
        let now = Utc::now();
        // Registered alice holds the oldest rows.
        for index in 0..3 {
            insert_row(
                &store,
                "alice",
                &format!("alice-{index}"),
                now - Duration::minutes(10),
                None,
            );
        }
        insert_row(
            &store,
            "ghost-oldest",
            "s",
            now - Duration::minutes(5),
            Some(now + Duration::minutes(5)),
        );
        insert_row(&store, "ghost-older", "s", now - Duration::minutes(4), None);
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
                 INSERT INTO local_password_failures
                 SELECT 'ghost-' || i, 's', 1, ?2, NULL FROM n",
                params![
                    MAX_ROWS - 5,
                    normalized_timestamp(now - Duration::minutes(1))
                ],
            )
            .unwrap();
        assert_eq!(total_rows(&store), MAX_ROWS);

        // A new row evicts the oldest unregistered row, locked or not, and
        // never the registered principal's older rows.
        record(&store, "intruder", "198.51.100.7", now);
        assert_eq!(total_rows(&store), MAX_ROWS);
        assert!(rows(&store, "ghost-oldest").is_empty());
        assert_eq!(rows(&store, "ghost-older").len(), 1);
        record(&store, "alice", "198.51.100.7", now);
        assert_eq!(total_rows(&store), MAX_ROWS);
        assert!(rows(&store, "ghost-older").is_empty());
        assert_eq!(rows(&store, "alice").len(), 4);
        // Updating an existing row evicts nothing.
        record(&store, "intruder", "198.51.100.7", now);
        assert_eq!(total_rows(&store), MAX_ROWS);
        assert_eq!(rows(&store, "intruder")[0].1, 2);
    }

    #[test]
    fn global_cap_never_evicts_registered_principals_rows() {
        let (_temp, store, _) = fixture();
        let now = Utc::now();
        for index in 0..4 {
            insert_row(
                &store,
                "alice",
                &format!("alice-{index}"),
                now - Duration::minutes(10),
                None,
            );
        }
        insert_row(&store, "ghost", "s", now, None);
        let conn = store.connection.lock().unwrap();
        make_global_room(&conn, 4).unwrap();
        make_global_room(&conn, 2).unwrap();
        drop(conn);
        assert!(rows(&store, "ghost").is_empty());
        assert_eq!(rows(&store, "alice").len(), 4);
    }

    #[test]
    fn listing_reports_latest_lockout_and_password_writes_clear_every_source() {
        let (_temp, store, hasher) = fixture();
        let now = Utc::now();
        insert_row(&store, "alice", "a", now, Some(now + Duration::minutes(5)));
        insert_row(&store, "alice", "b", now, Some(now + Duration::minutes(9)));
        insert_row(&store, "alice", "c", now, Some(now - Duration::minutes(1)));
        let method = store.list_login_methods("alice").unwrap().remove(0);
        assert!(method.locked);
        assert_eq!(
            method.locked_until,
            Some(normalized_timestamp(now + Duration::minutes(9)))
        );
        let reset = store
            .reset_local_password(
                &hasher,
                LocalPasswordWriteRequest {
                    principal_id: "alice".into(),
                    password: "another-password".into(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".into(),
                },
            )
            .unwrap();
        assert!(!reset.locked);
        assert!(rows(&store, "alice").is_empty());
        insert_row(&store, "alice", "a", now, Some(now + Duration::minutes(5)));
        let disabled = store.disable_local_password("alice", "admin").unwrap();
        assert!(!disabled.locked);
        assert!(rows(&store, "alice").is_empty());
    }

    #[test]
    fn sources_are_bounded_printable_ascii() {
        validate_source("203.0.113.10").unwrap();
        validate_source("2001:db8:1:2::/64").unwrap();
        for invalid in [
            "",
            " ",
            "a b",
            "é",
            OVERFLOW_SOURCE,
            &"x".repeat(MAX_SOURCE_BYTES + 1),
        ] {
            assert!(validate_source(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn schema_20_upgrade_clears_account_wide_lockouts() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("schema20.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let previous_len = MANAGED_STORE_MIGRATIONS
            .iter()
            .position(|migration| {
                migration.version == MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION
            })
            .unwrap();
        assert_eq!(
            MANAGED_STORE_MIGRATIONS[previous_len - 1].version,
            "020_resource_attributes"
        );
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..previous_len],
            },
        )
        .unwrap();
        let hasher = LocalPasswordHasher {
            verification_hook: None,
            key: Arc::new([22; 32]),
        };
        let password_hash_phc = hasher.hash_password("correct-password").unwrap();
        let locked_until = normalized_timestamp(Utc::now() + Duration::hours(1));
        previous
            .connection
            .lock()
            .unwrap()
            .execute_batch(&format!(
                "INSERT INTO principals
                 (principal_id, kind, display_name, email, external_subject, status, created_at,
                  updated_at, disabled_at, created_by)
                 VALUES ('alice', 'user', NULL, NULL, NULL, 'active', 't', 't', NULL, 'admin');
                 INSERT INTO principal_login_methods
                 (login_method_id, principal_id, method, external_provider, external_subject,
                  status, password_hash_phc, password_set_at, must_change_password,
                  failed_attempts, locked_until, created_at, updated_at, created_by, updated_by)
                 VALUES ('11111111-1111-4111-8111-111111111111', 'alice', 'local_password',
                         NULL, NULL, 'locked', '{password_hash_phc}', 't', 0, 10,
                         '{locked_until}', 't', 't', 'admin', 'admin');"
            ))
            .unwrap();
        drop(previous);
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload),
            Err(ManagedStoreError::MigrationRequired)
        ));

        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(store.migration_applied_this_open(MANAGED_STORE_LOCAL_PASSWORD_FAILURES_VERSION));
        {
            let conn = store.connection.lock().unwrap();
            let columns = table_info(&conn, "principal_login_methods")
                .unwrap()
                .into_iter()
                .map(|column| column.name)
                .collect::<Vec<_>>();
            assert!(!columns.contains(&"failed_attempts".to_string()));
            assert!(!columns.contains(&"locked_until".to_string()));
        }
        let method = store.list_login_methods("alice").unwrap().remove(0);
        assert_eq!(method.status, "active");
        assert!(!method.locked);
        assert_eq!(method.updated_at, "t");
        store
            .verify_local_password(
                &hasher,
                LocalPasswordVerifyRequest {
                    principal_id: "alice".into(),
                    password: "correct-password".into(),
                    source: "203.0.113.10".into(),
                    max_failed_attempts: 3,
                    lockout_ttl_seconds: TTL_SECONDS,
                },
            )
            .unwrap();
        drop(store);
        ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
    }
}
