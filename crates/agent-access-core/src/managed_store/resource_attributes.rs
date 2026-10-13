//! Private, versioned resource configuration. Plaintext never enters catalog records.
use super::*;
use agent_access_provider::ResourceAttributes;

struct AttributeRow {
    resource_id: String,
    resource_type: String,
    name: String,
    material_version: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl ManagedStore {
    /// Admin-only at the HTTP boundary; callers must pre-audit before decryption.
    pub fn reveal_resource_attribute(
        &self,
        resource_id: &str,
        name: &str,
        ring: &CredentialKeyRing,
    ) -> Result<String, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let row = rows(&conn, Some(resource_id))?
            .into_iter()
            .find(|row| row.name == name)
            .ok_or(ManagedStoreError::ResourceNotFound)?;
        decrypt(ring, &row)
    }

    /// Revalidate precisely the binding admitted by policy. Never refresh a stale
    /// binding onto a newly configured endpoint, even when the alias is unchanged.
    pub fn resolve_resource_attributes(
        &self,
        binding: &ResourceAttributeBinding,
        context: &str,
        ring: &CredentialKeyRing,
    ) -> Result<ResourceAttributes, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let record = resources::resource_metadata_by_id(&tx, &binding.resource_id)?;
        let definition = &record.definition;
        if record.version != binding.resource_version
            || definition.resource_type != binding.resource_type
            || definition.selector
                != (ResourceSelector::Exact {
                    value: binding.selector_value.clone(),
                })
        {
            return Err(ManagedStoreError::VersionConflict);
        }
        if !definition.enabled
            || !definition
                .allowed_execution_contexts
                .iter()
                .any(|value| value == context)
            || binding.material_versions.is_empty()
        {
            return Err(input_invalid(
                "resource private configuration is unavailable",
            ));
        }
        let material = rows(&tx, Some(&binding.resource_id))?;
        let material_versions = material
            .iter()
            .map(|row| (row.name.clone(), row.material_version.clone()))
            .collect::<BTreeMap<_, _>>();
        if material_versions != binding.material_versions {
            return Err(ManagedStoreError::VersionConflict);
        }
        let mut result = BTreeMap::new();
        for row in material {
            result.insert(row.name.clone(), decrypt(ring, &row)?);
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(ResourceAttributes::from(result))
    }
}

pub(super) fn versions(
    conn: &Connection,
    resource_id: &str,
) -> Result<BTreeMap<String, String>, ManagedStoreError> {
    let mut statement = conn.prepare(
        "SELECT attribute_name,material_version FROM resource_secret_material WHERE resource_id=?1 ORDER BY attribute_name",
    ).map_err(sql_unavailable)?;
    statement
        .query_map([resource_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(sql_unavailable)?
        .collect::<Result<_, _>>()
        .map_err(sql_unavailable)
}

/// One metadata-only read for catalog/list callers, regardless of resource count.
pub(super) fn catalog_versions(
    conn: &Connection,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, ManagedStoreError> {
    let mut statement = conn.prepare(
        "SELECT resource_id,attribute_name,material_version FROM resource_secret_material ORDER BY resource_id,attribute_name",
    ).map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_unavailable)?;
    let mut result: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for row in rows {
        let (resource, attribute, version) = row.map_err(sql_unavailable)?;
        result
            .entry(resource)
            .or_default()
            .insert(attribute, version);
    }
    Ok(result)
}

pub(super) fn write(
    conn: &Connection,
    record: &ManagedResourceRecord,
    attributes: &ResourceAttributes,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    if attributes.is_empty() {
        return Ok(());
    }
    if !matches!(record.definition.selector, ResourceSelector::Exact { .. }) {
        return Err(input_invalid(
            "private resource attributes require an exact selector",
        ));
    }
    let ring = ring.ok_or_else(|| {
        ManagedStoreError::EncryptionKeyMissing("resource attribute key ring".into())
    })?;
    for (name, value) in attributes.iter() {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || value.trim().is_empty()
            || value.len() > 8192
        {
            return Err(input_invalid("invalid private resource attribute"));
        }
        let mut row = AttributeRow {
            resource_id: record.definition.id.clone(),
            resource_type: record.definition.resource_type.as_str().into(),
            name: name.to_owned(),
            material_version: Uuid::new_v4().to_string(),
            key_id: ring.active_key_id().into(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
        };
        let encrypted = encrypt(ring, &row, value)?;
        row.nonce = encrypted.nonce;
        row.ciphertext = encrypted.ciphertext;
        conn.execute(
            "INSERT INTO resource_secret_material(resource_id,attribute_name,material_version,key_id,nonce,ciphertext) VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(resource_id,attribute_name) DO UPDATE SET material_version=excluded.material_version,key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext",
            params![row.resource_id,row.name,row.material_version,row.key_id,row.nonce,row.ciphertext],
        ).map_err(sql_unavailable)?;
    }
    Ok(())
}

const RESOURCE_ATTRIBUTES_BY_ID_SQL: &str = "SELECT m.resource_id,r.resource_type,m.attribute_name,m.material_version,m.key_id,m.nonce,m.ciphertext
    FROM resource_secret_material m JOIN resources r ON r.resource_id=m.resource_id
    WHERE m.resource_id=?1 ORDER BY m.attribute_name";
const ALL_RESOURCE_ATTRIBUTES_SQL: &str = "SELECT m.resource_id,r.resource_type,m.attribute_name,m.material_version,m.key_id,m.nonce,m.ciphertext
    FROM resource_secret_material m JOIN resources r ON r.resource_id=m.resource_id
    ORDER BY m.resource_id,m.attribute_name";

fn rows(
    conn: &Connection,
    resource_id: Option<&str>,
) -> Result<Vec<AttributeRow>, ManagedStoreError> {
    // Separate SQL shapes let SQLite use the resource key for dispatch/reveal.
    // An optional-filter OR here would scan unrelated encrypted rows.
    let sql = if resource_id.is_some() {
        RESOURCE_ATTRIBUTES_BY_ID_SQL
    } else {
        ALL_RESOURCE_ATTRIBUTES_SQL
    };
    let mut statement = conn.prepare(sql).map_err(sql_unavailable)?;
    let rows = match resource_id {
        Some(id) => statement.query_map([id], attribute_row_from_row),
        None => statement.query_map([], attribute_row_from_row),
    }
    .map_err(sql_unavailable)?;
    collect_rows(rows)
}

fn attribute_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttributeRow> {
    Ok(AttributeRow {
        resource_id: row.get(0)?,
        resource_type: row.get(1)?,
        name: row.get(2)?,
        material_version: row.get(3)?,
        key_id: row.get(4)?,
        nonce: row.get(5)?,
        ciphertext: row.get(6)?,
    })
}

fn aad(row: &AttributeRow) -> Result<Vec<u8>, ManagedStoreError> {
    // JSON tuple encoding is unambiguous even when fields contain delimiters.
    // Row version is intentionally absent: metadata changes do not reencrypt.
    serde_json::to_vec(&(
        "aab-resource-attribute:v1",
        &row.resource_id,
        &row.resource_type,
        &row.name,
        &row.material_version,
        &row.key_id,
    ))
    .map_err(|_| ManagedStoreError::CredentialEncryptFailed)
}
fn encrypt(
    ring: &CredentialKeyRing,
    row: &AttributeRow,
    value: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let key = ring
        .keys
        .get(&row.key_id)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: value.as_bytes(),
                aad: &aad(row)?,
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: row.key_id.clone(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}
fn decrypt(ring: &CredentialKeyRing, row: &AttributeRow) -> Result<String, ManagedStoreError> {
    let key = ring
        .keys
        .get(&row.key_id)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let nonce: [u8; 12] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let value = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &row.ciphertext,
                aad: &aad(row)?,
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    String::from_utf8(value).map_err(|_| ManagedStoreError::CredentialDecryptFailed)
}

pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    // Disabled resources retain secrets and must still be decryptable/revealable.
    for row in rows(conn, None)? {
        let ring =
            ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
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
    let mut count = 0;
    for mut row in rows(&tx, None)?
        .into_iter()
        .filter(|row| row.key_id == from)
    {
        let plaintext = decrypt(ring, &row)?;
        row.key_id = to.into();
        let encrypted = encrypt(ring, &row, &plaintext)?;
        tx.execute(
            "UPDATE resource_secret_material SET key_id=?3,nonce=?4,ciphertext=?5 WHERE resource_id=?1 AND attribute_name=?2",
            params![row.resource_id,row.name,to,encrypted.nonce,encrypted.ciphertext],
        ).map_err(sql_unavailable)?;
        count += 1;
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SECRET: &str =
        "https://environment.environment.api.powerplatform.com/private-path?sig=secret-sentinel";

    fn fixture() -> (tempfile::TempDir, ManagedStore, CredentialKeyRing) {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: temp.path().join("store.sqlite").display().to_string(),
                auto_migrate: true,
                require_registered_principal_for_invocation: false,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        let ring = CredentialKeyRing {
            active_key: "old".into(),
            keys: Arc::new(BTreeMap::from([
                ("old".into(), [7; 32]),
                ("new".into(), [8; 32]),
            ])),
        };
        store.configure_identity_token_encryption(Some(ring.clone()));
        (temp, store, ring)
    }
    fn accept(
        _: &[ManagedPolicyGrantRecord],
        _: &ManagedPolicyRevision,
        _: &ManagedPolicySubjectCatalog,
        _: &ManagedResourceCatalog,
    ) -> Result<(), ManagedStoreError> {
        Ok(())
    }
    fn attributes(value: &str) -> ResourceAttributes {
        ResourceAttributes::from(BTreeMap::from([("webhookUrl".into(), value.into())]))
    }
    fn create(id: &str) -> CreateResourceRequest {
        CreateResourceRequest {
            id: Some(id.into()),
            display_name: None,
            resource_type: ResourceType::from_static("test_destination"),
            selector: ResourceSelector::Exact { value: id.into() },
            allowed_execution_contexts: vec!["internal".into()],
            enabled: true,
            attributes: attributes(SECRET),
            created_by: "admin".into(),
        }
    }
    fn patch(version: i64) -> PatchResourceRequest {
        PatchResourceRequest {
            id: "release".into(),
            expected_version: version,
            display_name: None,
            resource_type: None,
            selector: None,
            allowed_execution_contexts: None,
            enabled: None,
            attributes: ResourceAttributes::default(),
            updated_by: "admin".into(),
        }
    }

    #[test]
    fn catalog_metadata_groups_attributes_and_dispatch_reads_only_its_binding() {
        let (_temp, store, ring) = fixture();
        let mut release = create("release");
        release.attributes = ResourceAttributes::from(BTreeMap::from([
            ("webhookUrl".into(), SECRET.into()),
            ("secondary".into(), "private-secondary-value".into()),
        ]));
        let created = store.create_resource(release, accept).unwrap();
        let binding = created.catalog.attribute_bindings[0].clone();
        let mut other = create("other");
        other.enabled = false;
        store.create_resource(other, accept).unwrap();
        let mut empty = create("empty");
        empty.attributes = ResourceAttributes::default();
        store.create_resource(empty, accept).unwrap();

        let records = store.resources().unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| (
                    record.definition.id.as_str(),
                    record
                        .configured_attributes
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ))
                .collect::<Vec<_>>(),
            [
                ("empty", vec![]),
                ("other", vec!["webhookUrl"]),
                ("release", vec!["secondary", "webhookUrl"]),
            ]
        );
        let catalog = store.load_policy_snapshot().unwrap().catalog;
        assert_eq!(catalog.attribute_bindings.len(), 2);
        assert_eq!(catalog.attribute_bindings[1], binding);
        assert_eq!(catalog.attribute_bindings[0].resource_id, "other");
        assert_eq!(catalog.attribute_bindings[0].material_versions.len(), 1);

        // Catalog/list read metadata only, including for disabled resources.
        store.connection.lock().unwrap().execute(
            "UPDATE resource_secret_material SET ciphertext=zeroblob(length(ciphertext)) WHERE resource_id='other'", [],
        ).unwrap();
        assert_eq!(store.resources().unwrap(), records);
        assert_eq!(store.load_policy_snapshot().unwrap().catalog, catalog);
        assert!(
            store
                .reveal_resource_attribute("other", "webhookUrl", &ring)
                .is_err()
        );

        // An unrelated malformed row must not be decoded under the dispatch
        // lock. The complete catalog still rejects the corruption when loaded.
        store.connection.lock().unwrap().execute(
            "UPDATE resources SET allowed_execution_contexts_json='[42]' WHERE resource_id='other'", [],
        ).unwrap();
        assert!(store.resources().is_err());
        assert_eq!(store.resource("release").unwrap(), records[2]);
        assert_eq!(
            store
                .resolve_resource_attributes(&binding, "internal", &ring)
                .unwrap()
                .get("webhookUrl"),
            Some(SECRET)
        );
        assert!(matches!(
            store.resource("missing"),
            Err(ManagedStoreError::ResourceNotFound)
        ));
    }

    #[test]
    fn exact_attribute_lookup_uses_resource_indexes_without_full_scans() {
        let (_temp, store, _) = fixture();
        store.create_resource(create("release"), accept).unwrap();
        let conn = store.connection.lock().unwrap();
        let mut statement = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {RESOURCE_ATTRIBUTES_BY_ID_SQL}"
            ))
            .unwrap();
        let details = statement
            .query_map(["release"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details.iter().any(|detail| detail.starts_with("SEARCH m ")),
            "{details:?}"
        );
        assert!(
            details.iter().all(|detail| !detail.starts_with("SCAN ")),
            "{details:?}"
        );
    }

    #[test]
    fn private_material_is_encrypted_redacted_and_atomic_with_resource_versions() {
        let (_temp, store, ring) = fixture();
        let created = store.create_resource(create("release"), accept).unwrap();
        assert_eq!(created.record.configured_attributes, ["webhookUrl"]);
        assert!(
            !serde_json::to_string(&created.record)
                .unwrap()
                .contains(SECRET)
        );
        let exported = serde_json::to_string(&store.load_policy_export().unwrap()).unwrap();
        assert!(!exported.contains(SECRET));
        assert!(!exported.contains("attributeBindings"));
        assert!(!format!("{:?}", create("release")).contains(SECRET));
        let ciphertext: Vec<u8> = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT ciphertext FROM resource_secret_material",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !ciphertext
                .windows(SECRET.len())
                .any(|bytes| bytes == SECRET.as_bytes())
        );
        let binding = created.catalog.attribute_bindings[0].clone();
        assert_eq!(
            store
                .resolve_resource_attributes(&binding, "internal", &ring)
                .unwrap()
                .get("webhookUrl"),
            Some(SECRET)
        );
        assert!(
            store
                .resolve_resource_attributes(&binding, "external", &ring)
                .is_err()
        );
        assert_eq!(
            store
                .reveal_resource_attribute("release", "webhookUrl", &ring)
                .unwrap(),
            SECRET
        );

        let mut replacement = patch(1);
        replacement.attributes = attributes("replacement-sentinel");
        assert!(
            store
                .patch_resource(replacement.clone(), |_, _, _, _| Err(input_invalid(
                    "reject"
                )))
                .is_err()
        );
        assert_eq!(store.resource("release").unwrap().version, 1);
        assert_eq!(store.policy_revision().unwrap(), created.revision);
        assert_eq!(
            store
                .resolve_resource_attributes(&binding, "internal", &ring)
                .unwrap()
                .get("webhookUrl"),
            Some(SECRET)
        );
        let replaced = store.patch_resource(replacement.clone(), accept).unwrap();
        assert_eq!(replaced.record.version, 2);
        assert_ne!(
            replaced.catalog.attribute_bindings[0].material_versions,
            binding.material_versions
        );
        assert!(matches!(
            store.resolve_resource_attributes(&binding, "internal", &ring),
            Err(ManagedStoreError::VersionConflict)
        ));
        assert!(matches!(
            store.patch_resource(replacement, accept),
            Err(ManagedStoreError::VersionConflict)
        ));
        let mut metadata = patch(2);
        metadata.display_name = Some(Some("Friendly".into()));
        let updated = store.patch_resource(metadata, accept).unwrap();
        assert_eq!(
            updated.catalog.attribute_bindings[0].material_versions,
            replaced.catalog.attribute_bindings[0].material_versions
        );
        assert_eq!(
            store
                .reveal_resource_attribute("release", "webhookUrl", &ring)
                .unwrap(),
            "replacement-sentinel"
        );
        let mut incompatible = patch(3);
        incompatible.selector = Some(ResourceSelector::All);
        assert!(store.patch_resource(incompatible, accept).is_err());
        let mut incompatible = patch(3);
        incompatible.resource_type = Some(ResourceType::from_static("another_type"));
        assert!(store.patch_resource(incompatible, accept).is_err());
        store
            .delete_resource(
                DeleteResourceRequest {
                    id: "release".into(),
                    expected_version: 3,
                    updated_by: "admin".into(),
                },
                accept,
            )
            .unwrap();
        assert_eq!(
            count_table(
                &store.connection.lock().unwrap(),
                "resource_secret_material"
            )
            .unwrap(),
            0
        );
        assert!(
            store
                .resolve_resource_attributes(
                    &updated.catalog.attribute_bindings[0],
                    "internal",
                    &ring
                )
                .is_err()
        );
    }

    #[test]
    fn disabled_material_participates_in_readiness_key_accounting_and_rewrap() {
        let (temp, store, ring) = fixture();
        let mut request = create("release");
        request.enabled = false;
        let created = store.create_resource(request, accept).unwrap();
        let binding = created.catalog.attribute_bindings[0].clone();
        assert!(
            store
                .resolve_resource_attributes(&binding, "internal", &ring)
                .is_err()
        );
        store.check_ready(Some(&ring)).unwrap();
        assert!(store.check_ready(None).is_err());
        assert_eq!(store.active_credential_key_ids().unwrap(), ["old"]);
        let summary = store
            .rewrap_credentials(&ring, "old", "new", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 1);
        assert_eq!(
            store
                .load_policy_snapshot()
                .unwrap()
                .catalog
                .attribute_bindings[0],
            binding
        );
        let new_ring = CredentialKeyRing {
            active_key: "new".into(),
            keys: Arc::new(BTreeMap::from([("new".into(), [8; 32])])),
        };
        store.check_ready(Some(&new_ring)).unwrap();
        assert_eq!(store.active_credential_key_ids().unwrap(), ["new"]);
        assert_eq!(
            store
                .reveal_resource_attribute("release", "webhookUrl", &new_ring)
                .unwrap(),
            SECRET
        );
        drop(store);
        let reopened = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: temp.path().join("store.sqlite").display().to_string(),
                auto_migrate: false,
                require_registered_principal_for_invocation: false,
            },
            ManagedStoreOpenMode::Reload,
        )
        .unwrap();
        reopened.check_ready(Some(&new_ring)).unwrap();
        assert_eq!(
            reopened
                .reveal_resource_attribute("release", "webhookUrl", &new_ring)
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn ciphertext_authenticates_resource_type_field_material_and_key_binding() {
        let (_temp, store, ring) = fixture();
        store.create_resource(create("release"), accept).unwrap();
        let conn = store.connection.lock().unwrap();
        for field in 0..5 {
            let mut row = rows(&conn, Some("release")).unwrap().remove(0);
            match field {
                0 => row.resource_id = "another".into(),
                1 => row.resource_type = "another_type".into(),
                2 => row.name = "anotherField".into(),
                3 => row.material_version = "another-version".into(),
                _ => row.key_id = "new".into(),
            }
            assert!(matches!(
                decrypt(&ring, &row),
                Err(ManagedStoreError::CredentialDecryptFailed)
            ));
        }
        conn.execute("UPDATE resource_secret_material SET nonce=zeroblob(12)", [])
            .unwrap();
        assert!(matches!(
            check_ready(&conn, Some(&ring)),
            Err(ManagedStoreError::CredentialDecryptFailed)
        ));
    }

    #[test]
    fn schema_19_upgrade_preserves_catalog_and_adds_empty_encrypted_storage() {
        let (temp, store, _) = fixture();
        drop(store);
        let path = temp.path().join("schema19.sqlite");
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: path.display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..6],
            },
        )
        .unwrap();
        previous.connection.lock().unwrap().execute(
            "INSERT INTO resources VALUES('saved','git_repository','exact','group/project',NULL,'[\"internal\"]',1,4,'t','admin','t','admin')", [],
        ).unwrap();
        drop(previous);
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload),
            Err(ManagedStoreError::MigrationRequired)
        ));
        let upgraded = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(upgraded.resource("saved").unwrap().version, 4);
        assert!(
            upgraded
                .load_policy_snapshot()
                .unwrap()
                .catalog
                .attribute_bindings
                .is_empty()
        );
        upgraded.check_ready(None).unwrap();
    }
}
