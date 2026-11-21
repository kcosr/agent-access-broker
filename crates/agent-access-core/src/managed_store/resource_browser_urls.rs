//! Browser navigation metadata does not change resource selector authority.
use super::*;

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(conn, MANAGED_STORE_RESOURCE_BROWSER_URLS_VERSION)?;
    agent_token_issuance::validate_context_rows(conn)?;
    imported_gateway_routes::check_rows(conn)?;
    microsoft_enrollments::check_rows(conn)?;
    application_access::check_rows(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_requires_admission_preserves_rows_and_cannot_be_opened_by_prior_schema() {
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
        let previous = ManagedStoreMigrationCatalog {
            migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS.len() - 1],
        };
        let old = ManagedStore::open_with_catalog(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
            previous,
        )
        .unwrap();
        let revision = old.policy_revision().unwrap();
        {
            let conn = old.connection.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO resources(resource_id,resource_type,selector_kind,selector_value,display_name,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by) VALUES
                 ('runbooks','confluence_content','subtree','https://example.atlassian.net/wiki/content/folder/123','Runbooks','[\"default\"]',1,7,'2026-01-01','admin','2026-02-01','editor');
                 INSERT INTO resource_groups VALUES
                 ('readers','Readers',2,'2026-01-01','admin','2026-01-01','admin');
                 INSERT INTO resource_group_members VALUES ('readers','runbooks','include');",
            )
            .unwrap();
        }
        let ledger = |path: &str| {
            let conn = Connection::open(path).unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT version,checksum,applied_at FROM schema_migrations ORDER BY version",
                )
                .unwrap();
            statement
                .query_map([], |row| {
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
        let before = ledger(&config.path);
        drop(old);
        config.auto_migrate = false;
        assert!(matches!(
            ManagedStore::open(
                &config,
                &test_execution_contexts(),
                ManagedStoreOpenMode::Startup
            ),
            Err(ManagedStoreError::MigrationRequired)
        ));
        assert_eq!(ledger(&config.path), before);
        config.auto_migrate = true;
        let current = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert!(current.migration_applied_this_open(MANAGED_STORE_RESOURCE_BROWSER_URLS_VERSION));
        let after = ledger(&config.path);
        assert_eq!(&after[..before.len()], before.as_slice());
        assert_eq!(after.len(), before.len() + 1);
        assert_eq!(
            after.last().unwrap().0,
            MANAGED_STORE_RESOURCE_BROWSER_URLS_VERSION
        );
        assert_eq!(
            after.last().unwrap().1,
            sha256_hex(include_str!("resource_browser_urls.sql").as_bytes())
        );
        assert_eq!(current.policy_revision().unwrap(), revision);
        let resource = current.resource("runbooks").unwrap();
        assert_eq!(resource.version, 7);
        assert_eq!(
            resource.definition.display_name.as_deref(),
            Some("Runbooks")
        );
        assert_eq!(resource.created_at, "2026-01-01");
        assert_eq!(resource.updated_at, "2026-02-01");
        assert_eq!(resource.updated_by, "editor");
        assert!(resource.definition.browser_url.is_none());
        assert_eq!(
            current
                .resource_group("readers")
                .unwrap()
                .definition
                .included_resource_ids,
            ["runbooks"]
        );
        current.check_ready(None).unwrap();
        drop(current);
        config.auto_migrate = false;
        assert!(
            ManagedStore::open_with_catalog(
                &config,
                &test_execution_contexts(),
                ManagedStoreOpenMode::Startup,
                previous
            )
            .is_err()
        );
        let reopened = ManagedStore::open(
            &config,
            &test_execution_contexts(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        assert!(!reopened.migration_applied_this_open(MANAGED_STORE_RESOURCE_BROWSER_URLS_VERSION));
        assert_eq!(reopened.resource("runbooks").unwrap(), resource);
        assert_eq!(ledger(&config.path), after);
    }
}
