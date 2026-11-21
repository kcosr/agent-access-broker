//! The resource selector extension keeps all previously stored identities and
//! encrypted attribute material unchanged while rebuilding SQLite constraints.
use super::*;

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(conn, MANAGED_STORE_CONTENT_RESOURCES_VERSION)?;
    agent_token_issuance::validate_context_rows(conn)?;
    imported_gateway_routes::check_rows(conn)?;
    microsoft_enrollments::check_rows(conn)?;
    application_access::check_rows(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_resources_members_and_encrypted_attributes() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for migration in MANAGED_STORE_MIGRATIONS {
            if migration.version == MANAGED_STORE_CONTENT_RESOURCES_VERSION {
                break;
            }
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO resources VALUES
             ('existing', 'teams_destination', 'exact', 'release', 'Release',
              '[\"default\"]', 0, 7, '2026-01-01', 'creator', '2026-02-01', 'editor'),
             ('space', 'confluence_space', 'exact', '~Alex', 'Personal space',
              '[\"default\"]', 1, 4, '2026-01-01', 'creator', '2026-02-01', 'editor'),
             ('all-spaces', 'confluence_space', 'all', '', 'All spaces',
              '[\"default\"]', 0, 9, '2026-01-01', 'creator', '2026-02-01', 'editor');
             INSERT INTO resource_groups VALUES
             ('included', 'Included', 3, '2026-01-01', 'creator', '2026-02-01', 'editor'),
             ('excluded', 'Excluded', 4, '2026-01-01', 'creator', '2026-02-01', 'editor');
             INSERT INTO resource_group_members VALUES
             ('included', 'existing', 'include'), ('excluded', 'existing', 'exclude'),
             ('included', 'all-spaces', 'include'), ('excluded', 'space', 'exclude');
             INSERT INTO resource_secret_material VALUES
             ('existing', 'webhookUrl', 'material-v1', 'key-v1',
              X'000102030405060708090A0B', X'000102030405060708090A0B0C0D0E0F');",
        )
        .unwrap();
        let snapshot = |table: &str| -> Vec<Vec<rusqlite::types::Value>> {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let tables = [
            "resources",
            "resource_groups",
            "resource_group_members",
            "resource_secret_material",
        ];
        let before = tables.map(snapshot);
        let migration = MANAGED_STORE_MIGRATIONS.last().unwrap();
        assert_eq!(migration.version, MANAGED_STORE_CONTENT_RESOURCES_VERSION);
        conn.execute_batch(migration.sql).unwrap();
        let after = tables.map(snapshot);
        assert_eq!(before, after);
        run_foreign_key_check(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO resources VALUES
             ('folder', 'confluence_content', 'subtree',
              'https://example.atlassian.net/wiki/content/folder/123', NULL,
              '[\"default\"]', 1, 1, '2026-01-01', 'admin', '2026-01-01', 'admin');",
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE resources SET selector_value = '' WHERE resource_id = 'folder'",
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE resources SET selector_kind = 'unsupported' WHERE resource_id = 'folder'",
                []
            )
            .is_err()
        );
        assert!(conn.execute("INSERT INTO resources SELECT 'duplicate', resource_type, selector_kind, selector_value, display_name, allowed_execution_contexts_json, enabled, version, created_at, created_by, updated_at, updated_by FROM resources WHERE resource_id = 'folder'", []).is_err());
        conn.execute("DELETE FROM resources WHERE resource_id = 'folder'", [])
            .unwrap();
        let temporary: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE 'content_resources_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(temporary, 0);
    }

    #[test]
    fn upgrade_requires_admission_preserves_revision_and_reopens_subtrees() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("managed.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let previous_end = MANAGED_STORE_MIGRATIONS
            .iter()
            .position(|migration| migration.version == MANAGED_STORE_APPLICATION_ACCESS_VERSION)
            .unwrap();
        let old = ManagedStore::open_with_catalog(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..=previous_end],
            },
        )
        .unwrap();
        let before = old.policy_revision().unwrap();
        let old_ledger = {
            let conn = old.connection.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version",
                )
                .unwrap();
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        drop(old);
        config.auto_migrate = false;
        let rejected = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        );
        assert!(matches!(
            rejected,
            Err(ManagedStoreError::MigrationRequired)
        ));
        config.auto_migrate = true;
        let upgraded = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert!(upgraded.migration_applied_this_open(MANAGED_STORE_CONTENT_RESOURCES_VERSION));
        assert_eq!(upgraded.policy_revision().unwrap(), before);
        upgraded.check_ready(None).unwrap();
        {
            let conn = upgraded.connection.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version",
                )
                .unwrap();
            let ledger = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(&ledger[..old_ledger.len()], old_ledger.as_slice());
            assert_eq!(ledger.len(), old_ledger.len() + 1);
            assert_eq!(
                ledger.last().unwrap().0,
                MANAGED_STORE_CONTENT_RESOURCES_VERSION
            );
            assert_eq!(
                ledger.last().unwrap().1,
                sha256_hex(include_str!("confluence_content_resources.sql").as_bytes())
            );
            conn.execute_batch("INSERT INTO resources VALUES ('page-tree','confluence_content','subtree','https://example.atlassian.net/wiki/content/page/123',NULL,'[\"default\"]',1,1,'2026-01-01','admin','2026-01-01','admin');").unwrap();
        }
        let expected = upgraded.resource("page-tree").unwrap();
        assert!(matches!(
            expected.definition.selector,
            ResourceSelector::Subtree { .. }
        ));
        drop(upgraded);
        config.auto_migrate = false;
        let reopened = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert!(!reopened.migration_applied_this_open(MANAGED_STORE_CONTENT_RESOURCES_VERSION));
        assert_eq!(reopened.resource("page-tree").unwrap(), expected);
        reopened.check_ready(None).unwrap();
    }
}
