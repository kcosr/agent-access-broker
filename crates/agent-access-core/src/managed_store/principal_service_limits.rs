//! Per-principal service invocation limit overrides for managed identity
//! authority. One row per `(principal, service)`; rows are deleted with their
//! principal. Service names are not checked against configuration here:
//! callers accept writes only for configured services, and overrides for a
//! service later removed from config stay stored but dormant.
use super::*;
use crate::InvocationLimit;

/// A stored override. Serializes camelCase for admin views.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalServiceLimitRecord {
    pub principal_id: String,
    pub service: String,
    pub requests: u32,
    pub window_seconds: u32,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl PrincipalServiceLimitRecord {
    /// The stored value as a validated limit.
    pub fn limit(&self) -> Result<InvocationLimit, ManagedStoreError> {
        InvocationLimit::new(u64::from(self.requests), u64::from(self.window_seconds))
            .map_err(|_| schema_invalid_limit())
    }
}

/// Input to [`ManagedStore::upsert_principal_service_limit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalServiceLimitWriteRequest {
    pub principal_id: String,
    pub service: String,
    pub limit: InvocationLimit,
    /// Principal recorded as `created_by` on insert and `updated_by` always.
    pub actor: String,
}

const SELECT_COLUMNS: &str = "principal_id, service, requests, window_seconds, created_at, created_by, updated_at, updated_by";

impl ManagedStore {
    /// The override for one principal and service, if any. A single
    /// primary-key read, cheap enough for per-request admission. Does not
    /// require the principal to exist.
    pub fn principal_service_limit(
        &self,
        principal_id: &str,
        service: &str,
    ) -> Result<Option<PrincipalServiceLimitRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_limit_service(service)?;
        let conn = self.connection.lock().unwrap();
        select_one(&conn, principal_id, service)
    }

    /// Every override stored for a principal, ordered by service, including
    /// dormant overrides for services no longer configured.
    pub fn list_principal_service_limits(
        &self,
        principal_id: &str,
    ) -> Result<Vec<PrincipalServiceLimitRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM principal_service_limits
                 WHERE principal_id = ?1 ORDER BY service"
            ))
            .map_err(sql_unavailable)?;
        let rows = statement
            .query_map([principal_id], record_from_row)
            .map_err(sql_unavailable)?;
        collect_rows(rows)
    }

    /// Creates or replaces the override for `(principal, service)`. The
    /// principal must exist (any kind or status); `created_*` is kept on
    /// update. Visible to the next admission without a reload.
    pub fn upsert_principal_service_limit(
        &self,
        request: PrincipalServiceLimitWriteRequest,
    ) -> Result<PrincipalServiceLimitRecord, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_limit_service(&request.service)?;
        validate_actor(&request.actor)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, &request.principal_id)?;
        let now = normalized_now_string();
        tx.execute(
            "INSERT INTO principal_service_limits
             (principal_id, service, requests, window_seconds, created_at, created_by,
              updated_at, updated_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, ?6)
             ON CONFLICT(principal_id, service) DO UPDATE SET
               requests = excluded.requests,
               window_seconds = excluded.window_seconds,
               updated_at = excluded.updated_at,
               updated_by = excluded.updated_by",
            params![
                request.principal_id,
                request.service,
                request.limit.requests(),
                request.limit.window_seconds(),
                now,
                request.actor,
            ],
        )
        .map_err(sql_unavailable)?;
        let record = select_one(&tx, &request.principal_id, &request.service)?
            .ok_or_else(|| sql_unavailable(rusqlite::Error::QueryReturnedNoRows))?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    /// Removes the override and returns what was removed, or `None` when no
    /// override existed. Callers own mutation audit, including the actor.
    pub fn delete_principal_service_limit(
        &self,
        principal_id: &str,
        service: &str,
    ) -> Result<Option<PrincipalServiceLimitRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        validate_limit_service(service)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let existing = select_one(&tx, principal_id, service)?;
        if existing.is_some() {
            tx.execute(
                "DELETE FROM principal_service_limits WHERE principal_id = ?1 AND service = ?2",
                params![principal_id, service],
            )
            .map_err(sql_unavailable)?;
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(existing)
    }
}

fn select_one(
    conn: &Connection,
    principal_id: &str,
    service: &str,
) -> Result<Option<PrincipalServiceLimitRecord>, ManagedStoreError> {
    conn.query_row(
        &format!(
            "SELECT {SELECT_COLUMNS} FROM principal_service_limits
             WHERE principal_id = ?1 AND service = ?2"
        ),
        params![principal_id, service],
        record_from_row,
    )
    .optional()
    .map_err(sql_unavailable)
}

fn record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PrincipalServiceLimitRecord> {
    Ok(PrincipalServiceLimitRecord {
        principal_id: row.get(0)?,
        service: row.get(1)?,
        requests: row.get(2)?,
        window_seconds: row.get(3)?,
        created_at: row.get(4)?,
        created_by: row.get(5)?,
        updated_at: row.get(6)?,
        updated_by: row.get(7)?,
    })
}

fn validate_limit_service(service: &str) -> Result<(), ManagedStoreError> {
    if is_service_name(service) {
        Ok(())
    } else {
        Err(input_invalid("service name is invalid"))
    }
}

fn schema_invalid_limit() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("stored principal service limit is out of range".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn private_temp() -> (TempDir, ManagedStoreConfig) {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        };
        (temp, config)
    }

    fn create_principals(store: &ManagedStore) {
        for (principal_id, kind) in [("alice", "user"), ("robot", "service_account")] {
            store
                .create_principal(PrincipalWriteRequest {
                    role: crate::PrincipalRole::User,
                    self_service_enabled: None,
                    principal_id: principal_id.into(),
                    kind: kind.into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                })
                .unwrap();
        }
    }

    fn store() -> (TempDir, ManagedStore) {
        let (temp, config) = private_temp();
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        create_principals(&store);
        (temp, store)
    }

    #[test]
    fn schema_21_store_upgrades_to_principal_service_limits() {
        let (_temp, config) = private_temp();
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..8],
            },
        )
        .unwrap();
        previous.connection.lock().unwrap().execute_batch("INSERT INTO principals(principal_id,kind,status,created_at,updated_at,created_by) VALUES('alice','user','active','2026-01-01','2026-01-01','test'),('robot','service_account','active','2026-01-01','2026-01-01','test')").unwrap();
        assert!(
            !sqlite_object_exists(
                &previous.connection.lock().unwrap(),
                "table",
                "principal_service_limits"
            )
            .unwrap()
        );
        drop(previous);
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap_err(),
            ManagedStoreError::MigrationRequired
        ));

        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(store.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert_eq!(
            store.status().unwrap().schema_version,
            MANAGED_STORE_SCHEMA_VERSION
        );
        assert_eq!(store.principal("alice").unwrap().kind, "user");
        store
            .upsert_principal_service_limit(write("robot", "gitlab_git", 4, 60, "admin"))
            .unwrap();
        drop(store);
        let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        assert_eq!(
            reopened
                .principal_service_limit("robot", "gitlab_git")
                .unwrap()
                .unwrap()
                .requests,
            4
        );
    }

    fn write(
        principal: &str,
        service: &str,
        requests: u64,
        window: u64,
        actor: &str,
    ) -> PrincipalServiceLimitWriteRequest {
        PrincipalServiceLimitWriteRequest {
            principal_id: principal.into(),
            service: service.into(),
            limit: InvocationLimit::new(requests, window).unwrap(),
            actor: actor.into(),
        }
    }

    #[test]
    fn upsert_read_list_and_delete_round_trip_with_actor_and_timestamps() {
        let (_temp, store) = store();
        assert_eq!(
            store.principal_service_limit("alice", "jira").unwrap(),
            None
        );
        assert!(
            store
                .list_principal_service_limits("alice")
                .unwrap()
                .is_empty()
        );

        let created = store
            .upsert_principal_service_limit(write("alice", "jira", 10, 60, "admin"))
            .unwrap();
        assert_eq!(created.principal_id, "alice");
        assert_eq!(created.service, "jira");
        assert_eq!((created.requests, created.window_seconds), (10, 60));
        assert_eq!(created.created_by, "admin");
        assert_eq!(created.updated_by, "admin");
        assert_eq!(created.created_at, created.updated_at);
        DateTime::parse_from_rfc3339(&created.created_at).unwrap();
        assert_eq!(
            created.limit().unwrap(),
            InvocationLimit::new(10, 60).unwrap()
        );

        let updated = store
            .upsert_principal_service_limit(write("alice", "jira", 5, 3_600, "operator"))
            .unwrap();
        assert_eq!((updated.requests, updated.window_seconds), (5, 3_600));
        assert_eq!(updated.created_by, "admin");
        assert_eq!(updated.created_at, created.created_at);
        assert_eq!(updated.updated_by, "operator");
        assert_eq!(
            store.principal_service_limit("alice", "jira").unwrap(),
            Some(updated.clone())
        );

        store
            .upsert_principal_service_limit(write("alice", "confluence", 1, 1, "admin"))
            .unwrap();
        store
            .upsert_principal_service_limit(write("robot", "jira", 2, 86_400, "admin"))
            .unwrap();
        let listed = store.list_principal_service_limits("alice").unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|record| record.service.as_str())
                .collect::<Vec<_>>(),
            ["confluence", "jira"]
        );

        assert_eq!(
            store
                .delete_principal_service_limit("alice", "jira")
                .unwrap(),
            Some(updated)
        );
        assert_eq!(
            store.principal_service_limit("alice", "jira").unwrap(),
            None
        );
        assert_eq!(
            store
                .delete_principal_service_limit("alice", "jira")
                .unwrap(),
            None
        );
        assert_eq!(
            store.list_principal_service_limits("alice").unwrap().len(),
            1
        );
        assert_eq!(
            store.list_principal_service_limits("robot").unwrap().len(),
            1
        );
    }

    #[test]
    fn writes_require_an_existing_principal_and_valid_names() {
        let (_temp, store) = store();
        assert!(matches!(
            store.upsert_principal_service_limit(write("missing", "jira", 1, 60, "admin")),
            Err(ManagedStoreError::PrincipalNotFound)
        ));
        for (principal, service, actor) in [
            ("anonymous", "jira", "admin"),
            ("bad principal", "jira", "admin"),
            ("alice", "Jira", "admin"),
            ("alice", "", "admin"),
            ("alice", "jira", "bad actor"),
        ] {
            assert!(
                matches!(
                    store.upsert_principal_service_limit(write(principal, service, 1, 60, actor)),
                    Err(ManagedStoreError::InputInvalid(_))
                ),
                "{principal} {service} {actor}"
            );
        }
        assert!(matches!(
            store.principal_service_limit("alice", "not a service"),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        // Services are not checked against configuration here, so dormant
        // overrides for removed services remain readable.
        store
            .upsert_principal_service_limit(write("alice", "retired_service", 3, 60, "admin"))
            .unwrap();
        assert!(
            store
                .principal_service_limit("alice", "retired_service")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn schema_rejects_out_of_range_rows_and_cascades_with_the_principal() {
        let (_temp, store) = store();
        store
            .upsert_principal_service_limit(write("alice", "jira", 10, 60, "admin"))
            .unwrap();
        let conn = store.connection.lock().unwrap();
        for (requests, window) in [(0, 60), (1_000_001, 60), (1, 0), (1, 86_401)] {
            assert!(
                conn.execute(
                    "INSERT INTO principal_service_limits VALUES ('robot', 'jira', ?1, ?2, 't', 'admin', 't', 'admin')",
                    params![requests, window],
                )
                .is_err(),
                "{requests} {window}"
            );
        }
        conn.execute("DELETE FROM principals WHERE principal_id = 'alice'", [])
            .unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM principal_service_limits", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 0);
    }
}
