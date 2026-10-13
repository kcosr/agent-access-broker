use super::*;

mod audit;
pub use audit::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedResourceCatalog {
    pub resources: Vec<ResourceDefinition>,
    pub resource_groups: Vec<ResourceGroupDefinition>,
    /// Private versioned references used during execution; never exported.
    #[serde(skip)]
    pub attribute_bindings: Vec<ResourceAttributeBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAttributeBinding {
    pub resource_id: String,
    pub resource_type: ResourceType,
    pub selector_value: String,
    pub resource_version: i64,
    pub material_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicyState {
    pub revision: ManagedPolicyRevision,
    pub active_grants: Vec<ManagedPolicyGrantRecord>,
    pub catalog: ManagedResourceCatalog,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPolicyExport {
    pub revision: ManagedPolicyRevision,
    pub grants: Vec<ManagedPolicyGrantRecord>,
    pub catalog: ManagedResourceCatalog,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedResourceRecord {
    #[serde(flatten)]
    pub definition: ResourceDefinition,
    pub version: i64,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
    #[serde(default)]
    pub configured_attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedResourceGroupRecord {
    #[serde(flatten)]
    pub definition: ResourceGroupDefinition,
    pub version: i64,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct ManagedCatalogMutationResult<T> {
    pub previous_revision: ManagedPolicyRevision,
    pub revision: ManagedPolicyRevision,
    pub record: T,
    pub audit: ManagedCatalogAuditChange,
    pub catalog: ManagedResourceCatalog,
    pub active_grants: Vec<ManagedPolicyGrantRecord>,
}

#[derive(Debug, Clone)]
pub struct CreateResourceRequest {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
    pub allowed_execution_contexts: Vec<String>,
    pub enabled: bool,
    pub attributes: agent_access_provider::ResourceAttributes,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct PatchResourceRequest {
    pub id: String,
    pub expected_version: i64,
    pub display_name: Option<Option<String>>,
    pub resource_type: Option<ResourceType>,
    pub selector: Option<ResourceSelector>,
    pub allowed_execution_contexts: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub attributes: agent_access_provider::ResourceAttributes,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct CreateResourceGroupRequest {
    pub id: Option<String>,
    pub name: String,
    pub included_resource_ids: Vec<String>,
    pub excluded_resource_ids: Vec<String>,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct PatchResourceGroupRequest {
    pub id: String,
    pub expected_version: i64,
    pub name: Option<String>,
    pub included_resource_ids: Option<Vec<String>>,
    pub excluded_resource_ids: Option<Vec<String>>,
    pub updated_by: String,
}

#[derive(Debug, Clone)]
pub struct DeleteResourceRequest {
    pub id: String,
    pub expected_version: i64,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceReference {
    pub kind: String,
    pub id: String,
    pub service: Option<String>,
    pub principal_id: Option<String>,
    pub via_group_id: Option<String>,
    pub effect: Option<String>,
}

impl ManagedStore {
    pub fn load_policy_snapshot(&self) -> Result<ManagedPolicyState, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let result = ManagedPolicyState {
            revision: policy_revision(&tx)?,
            active_grants: policy_grants(&tx, Some("active"))?,
            catalog: resource_catalog(&tx)?,
        };
        validate_grant_resource_references(&result.active_grants, &result.catalog)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    pub fn load_policy_export(&self) -> Result<ManagedPolicyExport, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let result = ManagedPolicyExport {
            revision: policy_revision(&tx)?,
            grants: policy_grants(&tx, None)?,
            catalog: resource_catalog(&tx)?,
        };
        validate_grant_resource_references(&result.grants, &result.catalog)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    pub fn resources(&self) -> Result<Vec<ManagedResourceRecord>, ManagedStoreError> {
        resource_records(&self.connection.lock().unwrap())
    }

    pub fn resource(&self, id: &str) -> Result<ManagedResourceRecord, ManagedStoreError> {
        resource_by_id(&self.connection.lock().unwrap(), id)
    }

    pub fn resource_groups(&self) -> Result<Vec<ManagedResourceGroupRecord>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let records = resource_group_records(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(records)
    }

    pub fn resource_group(
        &self,
        id: &str,
    ) -> Result<ManagedResourceGroupRecord, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let record = resource_group_by_id(&tx, id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn resource_used_by(&self, id: &str) -> Result<Vec<ResourceReference>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        resource_by_id(&tx, id)?;
        let references = resource_references(&tx, id, false)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(references)
    }

    pub fn resource_group_used_by(
        &self,
        id: &str,
    ) -> Result<Vec<ResourceReference>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        resource_group_by_id(&tx, id)?;
        let references = resource_references(&tx, id, true)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(references)
    }

    /// Read live token references using an authoritative catalog captured by the caller.
    /// TOML policy does not mirror its catalog into the managed store.
    pub fn token_resource_used_by(
        &self,
        id: &str,
        is_group: bool,
        catalog: &ManagedResourceCatalog,
    ) -> Result<Vec<ResourceReference>, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let references = token_resource_references(&tx, id, is_group, catalog)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(references)
    }

    fn mutate_resource_catalog<T, M, V>(
        &self,
        actor: &str,
        mutate: M,
        mut validate: V,
    ) -> Result<ManagedCatalogMutationResult<T>, ManagedStoreError>
    where
        M: FnOnce(&Connection, &str) -> Result<(T, ManagedCatalogAuditChange), ManagedStoreError>,
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        validate_actor(actor)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let previous_revision = policy_revision(&tx)?;
        let now = normalized_now_string();
        let (record, audit) = mutate(&tx, &now)?;
        let catalog = resource_catalog(&tx)?;
        let all_grants = policy_grants(&tx, None)?;
        validate_grant_resource_references(&all_grants, &catalog)?;
        let active_grants: Vec<_> = all_grants
            .into_iter()
            .filter(|grant| grant.status == "active")
            .collect();
        let revision = next_policy_revision(&previous_revision, &now, actor)?;
        let subjects = policy_subject_catalog(&tx)?;
        validate(&active_grants, &revision, &subjects, &catalog)?;
        update_policy_revision(&tx, &revision)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(ManagedCatalogMutationResult {
            previous_revision,
            revision,
            record,
            audit,
            catalog,
            active_grants,
        })
    }

    pub fn create_resource<V>(
        &self,
        request: CreateResourceRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceRecord>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.created_by,
            |conn, now| {
                let mut record = ManagedResourceRecord {
                    definition: ResourceDefinition {
                        id: request
                            .id
                            .clone()
                            .unwrap_or_else(|| Uuid::new_v4().to_string()),
                        display_name: normalize_optional_text(request.display_name.clone()),
                        resource_type: request.resource_type,
                        selector: request.selector.clone(),
                        allowed_execution_contexts: request.allowed_execution_contexts.clone(),
                        enabled: request.enabled,
                    },
                    version: 1,
                    created_at: now.into(),
                    created_by: request.created_by.clone(),
                    updated_at: now.into(),
                    updated_by: request.created_by.clone(),
                    configured_attributes: Vec::new(),
                };
                persist_resource(conn, &record, false)?;
                resource_attributes::write(
                    conn,
                    &record,
                    &request.attributes,
                    self.identity_key_ring.lock().unwrap().as_ref(),
                )?;
                record.configured_attributes =
                    resource_attributes::versions(conn, &record.definition.id)?
                        .into_keys()
                        .collect();
                let audit =
                    audit::resource_change(None, Some(&record), !request.attributes.is_empty());
                Ok((record, audit))
            },
            validate,
        )
    }

    pub fn patch_resource<V>(
        &self,
        request: PatchResourceRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceRecord>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.updated_by,
            |conn, now| {
                let mut record = resource_by_id(conn, &request.id)?;
                let before = record.clone();
                check_catalog_version(record.version, request.expected_version)?;
                if !record.configured_attributes.is_empty()
                    && (request.resource_type.as_ref().is_some_and(|value| value != &record.definition.resource_type)
                        || request.selector.as_ref().is_some_and(|value| !matches!(value, ResourceSelector::Exact { .. })))
                {
                    return Err(input_invalid("resource type and selector kind cannot change while private attributes are configured"));
                }
                if let Some(value) = request.display_name.clone() {
                    record.definition.display_name = normalize_optional_text(value);
                }
                if let Some(value) = request.resource_type {
                    record.definition.resource_type = value;
                }
                if let Some(value) = request.selector.clone() {
                    record.definition.selector = value;
                }
                if let Some(value) = request.allowed_execution_contexts.clone() {
                    record.definition.allowed_execution_contexts = value;
                }
                if let Some(value) = request.enabled {
                    record.definition.enabled = value;
                }
                record.version = record
                    .version
                    .checked_add(1)
                    .ok_or(ManagedStoreError::VersionConflict)?;
                record.updated_at = now.into();
                record.updated_by = request.updated_by.clone();
                persist_resource(conn, &record, true)?;
                resource_attributes::write(conn, &record, &request.attributes, self.identity_key_ring.lock().unwrap().as_ref())?;
                record.configured_attributes = resource_attributes::versions(conn, &record.definition.id)?.into_keys().collect();
                let audit = audit::resource_change(Some(&before), Some(&record), !request.attributes.is_empty());
                Ok((record, audit))
            },
            validate,
        )
    }

    pub fn delete_resource<V>(
        &self,
        request: DeleteResourceRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<()>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.updated_by,
            |conn, _| {
                let before = resource_by_id(conn, &request.id)?;
                check_catalog_version(before.version, request.expected_version)?;
                if !resource_references(conn, &request.id, false)?.is_empty() {
                    return Err(ManagedStoreError::ResourceInUse);
                }
                conn.execute(
                    "DELETE FROM resources WHERE resource_id = ?1",
                    [&request.id],
                )
                .map_err(sql_unavailable)?;
                Ok((
                    (),
                    audit::resource_change(
                        Some(&before),
                        None,
                        !before.configured_attributes.is_empty(),
                    ),
                ))
            },
            validate,
        )
    }

    pub fn create_resource_group<V>(
        &self,
        request: CreateResourceGroupRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceGroupRecord>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.created_by,
            |conn, now| {
                let record = ManagedResourceGroupRecord {
                    definition: ResourceGroupDefinition {
                        id: request
                            .id
                            .clone()
                            .unwrap_or_else(|| Uuid::new_v4().to_string()),
                        name: request.name.clone(),
                        included_resource_ids: request.included_resource_ids.clone(),
                        excluded_resource_ids: request.excluded_resource_ids.clone(),
                    },
                    version: 1,
                    created_at: now.into(),
                    created_by: request.created_by.clone(),
                    updated_at: now.into(),
                    updated_by: request.created_by.clone(),
                };
                persist_resource_group(conn, &record, false)?;
                let audit = audit::group_change(conn, None, Some(&record))?;
                Ok((record, audit))
            },
            validate,
        )
    }

    pub fn patch_resource_group<V>(
        &self,
        request: PatchResourceGroupRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceGroupRecord>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.updated_by,
            |conn, now| {
                let mut record = resource_group_by_id(conn, &request.id)?;
                let before = record.clone();
                check_catalog_version(record.version, request.expected_version)?;
                if let Some(value) = request.name.clone() {
                    record.definition.name = value;
                }
                if let Some(value) = request.included_resource_ids.clone() {
                    record.definition.included_resource_ids = value;
                }
                if let Some(value) = request.excluded_resource_ids.clone() {
                    record.definition.excluded_resource_ids = value;
                }
                record.version = record
                    .version
                    .checked_add(1)
                    .ok_or(ManagedStoreError::VersionConflict)?;
                record.updated_at = now.into();
                record.updated_by = request.updated_by.clone();
                persist_resource_group(conn, &record, true)?;
                let audit = audit::group_change(conn, Some(&before), Some(&record))?;
                Ok((record, audit))
            },
            validate,
        )
    }

    pub fn delete_resource_group<V>(
        &self,
        request: DeleteResourceRequest,
        validate: V,
    ) -> Result<ManagedCatalogMutationResult<()>, ManagedStoreError>
    where
        V: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> Result<(), ManagedStoreError>,
    {
        self.mutate_resource_catalog(
            &request.updated_by,
            |conn, _| {
                let before = resource_group_by_id(conn, &request.id)?;
                check_catalog_version(before.version, request.expected_version)?;
                if !resource_references(conn, &request.id, true)?.is_empty() {
                    return Err(ManagedStoreError::ResourceInUse);
                }
                conn.execute(
                    "DELETE FROM resource_group_members WHERE resource_group_id = ?1",
                    [&request.id],
                )
                .map_err(sql_unavailable)?;
                conn.execute(
                    "DELETE FROM resource_groups WHERE resource_group_id = ?1",
                    [&request.id],
                )
                .map_err(sql_unavailable)?;
                Ok(((), audit::group_change(conn, Some(&before), None)?))
            },
            validate,
        )
    }
}

fn check_catalog_version(actual: i64, expected: i64) -> Result<(), ManagedStoreError> {
    if expected < 1 || actual != expected {
        Err(ManagedStoreError::VersionConflict)
    } else {
        Ok(())
    }
}

const RESOURCE_RECORD_COLUMNS: &str = "resource_id,resource_type,selector_kind,selector_value,display_name,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by";
const RESOURCE_BY_ID_SQL: &str = "SELECT resource_id,resource_type,selector_kind,selector_value,display_name,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by FROM resources WHERE resource_id=?1";

pub(super) fn resource_by_id(
    conn: &Connection,
    id: &str,
) -> Result<ManagedResourceRecord, ManagedStoreError> {
    let mut record = resource_metadata_by_id(conn, id)?;
    record.configured_attributes = resource_attributes::versions(conn, id)?
        .into_keys()
        .collect();
    Ok(record)
}

/// Dispatch reads the admitted resource alone, then loads its encrypted material
/// once. It has no need to populate the admin record's configured-name list.
pub(super) fn resource_metadata_by_id(
    conn: &Connection,
    id: &str,
) -> Result<ManagedResourceRecord, ManagedStoreError> {
    conn.query_row(RESOURCE_BY_ID_SQL, [id], resource_record_from_row)
        .optional()
        .map_err(sql_unavailable)?
        .ok_or(ManagedStoreError::ResourceNotFound)
}

fn resource_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedResourceRecord> {
    let kind: String = row.get(2)?;
    let value: String = row.get(3)?;
    let selector_json = if kind == "all" {
        serde_json::json!({"kind":kind})
    } else {
        serde_json::json!({"kind":kind,"value":value})
    };
    let resource_type: String = row.get(1)?;
    let contexts: String = row.get(5)?;
    Ok(ManagedResourceRecord {
        definition: ResourceDefinition {
            id: row.get(0)?,
            resource_type: serde_json::from_value(Value::String(resource_type)).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(1, Type::Text, Box::new(e))
            })?,
            selector: serde_json::from_value(selector_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(2, Type::Text, Box::new(e))
            })?,
            display_name: row.get(4)?,
            allowed_execution_contexts: serde_json::from_str(&contexts).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(5, Type::Text, Box::new(e))
            })?,
            enabled: row.get(6)?,
        },
        version: row.get(7)?,
        created_at: row.get(8)?,
        created_by: row.get(9)?,
        updated_at: row.get(10)?,
        updated_by: row.get(11)?,
        configured_attributes: Vec::new(),
    })
}

fn resource_group_by_id(
    conn: &Connection,
    id: &str,
) -> Result<ManagedResourceGroupRecord, ManagedStoreError> {
    resource_group_records(conn)?
        .into_iter()
        .find(|record| record.definition.id == id)
        .ok_or(ManagedStoreError::ResourceGroupNotFound)
}

fn resource_records(conn: &Connection) -> Result<Vec<ManagedResourceRecord>, ManagedStoreError> {
    let attributes = resource_attributes::catalog_versions(conn)?;
    resource_records_with_attributes(conn, &attributes)
}

fn resource_records_with_attributes(
    conn: &Connection,
    attributes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<Vec<ManagedResourceRecord>, ManagedStoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {RESOURCE_RECORD_COLUMNS} FROM resources ORDER BY resource_id"
        ))
        .map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], resource_record_from_row)
        .map_err(sql_unavailable)?;
    let mut records = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_unavailable)?;
    for record in &mut records {
        record.configured_attributes = attributes
            .get(&record.definition.id)
            .map(|values| values.keys().cloned().collect())
            .unwrap_or_default();
    }
    Ok(records)
}

fn resource_group_records(
    conn: &Connection,
) -> Result<Vec<ManagedResourceGroupRecord>, ManagedStoreError> {
    let mut statement = conn.prepare("SELECT resource_group_id,name,version,created_at,created_by,updated_at,updated_by FROM resource_groups ORDER BY resource_group_id").map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok(ManagedResourceGroupRecord {
                definition: ResourceGroupDefinition {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    included_resource_ids: Vec::new(),
                    excluded_resource_ids: Vec::new(),
                },
                version: row.get(2)?,
                created_at: row.get(3)?,
                created_by: row.get(4)?,
                updated_at: row.get(5)?,
                updated_by: row.get(6)?,
            })
        })
        .map_err(sql_unavailable)?;
    let mut groups = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_unavailable)?;
    for group in &mut groups {
        let mut statement = conn.prepare("SELECT resource_id,effect FROM resource_group_members WHERE resource_group_id = ?1 ORDER BY resource_id,effect").map_err(sql_unavailable)?;
        let members = statement
            .query_map([&group.definition.id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_unavailable)?;
        for member in members {
            let (id, effect) = member.map_err(sql_unavailable)?;
            if effect == "include" {
                group.definition.included_resource_ids.push(id);
            } else {
                group.definition.excluded_resource_ids.push(id);
            }
        }
    }
    Ok(groups)
}

pub(super) fn resource_catalog(
    conn: &Connection,
) -> Result<ManagedResourceCatalog, ManagedStoreError> {
    let mut attributes = resource_attributes::catalog_versions(conn)?;
    let records = resource_records_with_attributes(conn, &attributes)?;
    let attribute_bindings = records
        .iter()
        .filter(|record| !record.configured_attributes.is_empty())
        .map(|record| {
            let ResourceSelector::Exact { value } = &record.definition.selector else {
                return Err(input_invalid(
                    "private resource attributes require an exact selector",
                ));
            };
            Ok(ResourceAttributeBinding {
                resource_id: record.definition.id.clone(),
                resource_type: record.definition.resource_type.clone(),
                selector_value: value.clone(),
                resource_version: record.version,
                material_versions: attributes.remove(&record.definition.id).unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, ManagedStoreError>>()?;
    let catalog = ManagedResourceCatalog {
        resources: records
            .into_iter()
            .map(|record| record.definition)
            .collect(),
        attribute_bindings,
        resource_groups: resource_group_records(conn)?
            .into_iter()
            .map(|record| record.definition)
            .collect(),
    };
    ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
        .map_err(|errors| input_invalid(errors.join("; ")))?;
    Ok(catalog)
}

pub(super) fn validate_grant_resource_references(
    grants: &[ManagedPolicyGrantRecord],
    catalog: &ManagedResourceCatalog,
) -> Result<(), ManagedStoreError> {
    let catalog = ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
        .map_err(|errors| input_invalid(errors.join("; ")))?;
    for grant in grants.iter().filter(|grant| grant.status != "deleted") {
        catalog
            .validate_selection(&grant.resources)
            .map_err(|errors| input_invalid(errors.join("; ")))?;
    }
    Ok(())
}

fn persist_resource(
    conn: &Connection,
    record: &ManagedResourceRecord,
    update: bool,
) -> Result<(), ManagedStoreError> {
    let definition = &record.definition;
    let mut catalog = resource_catalog(conn)?;
    if update {
        catalog.resources.retain(|r| r.id != definition.id);
    }
    if let Some(existing) = catalog.resources.iter().find(|resource| {
        resource.resource_type == definition.resource_type
            && resource.selector == definition.selector
    }) {
        let existing = resource_metadata_by_id(conn, &existing.id)?;
        return Err(ManagedStoreError::ResourceConflict(Box::new(
            audit::resource_entity(&existing),
        )));
    }
    catalog.resources.push(definition.clone());
    ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
        .map_err(|errors| input_invalid(errors.join("; ")))?;
    let selector = serde_json::to_value(&definition.selector)
        .map_err(|_| input_invalid("invalid selector"))?;
    let resource_type = serde_json::to_value(&definition.resource_type)
        .map_err(|_| input_invalid("invalid resource type"))?;
    let contexts = serde_json::to_string(&definition.allowed_execution_contexts)
        .map_err(|_| input_invalid("invalid resource contexts"))?;
    let sql = if update {
        "UPDATE resources SET resource_type=?2,selector_kind=?3,selector_value=?4,display_name=?5,allowed_execution_contexts_json=?6,enabled=?7,version=?8,created_at=?9,created_by=?10,updated_at=?11,updated_by=?12 WHERE resource_id=?1"
    } else {
        "INSERT INTO resources(resource_id,resource_type,selector_kind,selector_value,display_name,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
    };
    conn.execute(
        sql,
        params![
            definition.id,
            resource_type.as_str().unwrap(),
            selector["kind"].as_str().unwrap(),
            selector.get("value").and_then(Value::as_str).unwrap_or(""),
            definition.display_name,
            contexts,
            definition.enabled,
            record.version,
            record.created_at,
            record.created_by,
            record.updated_at,
            record.updated_by
        ],
    )
    .map_err(sql_unavailable)?;
    Ok(())
}

fn persist_resource_group(
    conn: &Connection,
    record: &ManagedResourceGroupRecord,
    update: bool,
) -> Result<(), ManagedStoreError> {
    let definition = &record.definition;
    let mut catalog = resource_catalog(conn)?;
    if update {
        catalog.resource_groups.retain(|g| g.id != definition.id);
    }
    catalog.resource_groups.push(definition.clone());
    ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
        .map_err(|errors| input_invalid(errors.join("; ")))?;
    let sql = if update {
        "UPDATE resource_groups SET name=?2,version=?3,created_at=?4,created_by=?5,updated_at=?6,updated_by=?7 WHERE resource_group_id=?1"
    } else {
        "INSERT INTO resource_groups(resource_group_id,name,version,created_at,created_by,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)"
    };
    conn.execute(
        sql,
        params![
            definition.id,
            definition.name,
            record.version,
            record.created_at,
            record.created_by,
            record.updated_at,
            record.updated_by
        ],
    )
    .map_err(sql_unavailable)?;
    conn.execute(
        "DELETE FROM resource_group_members WHERE resource_group_id=?1",
        [&definition.id],
    )
    .map_err(sql_unavailable)?;
    for (effect, ids) in [
        ("include", &definition.included_resource_ids),
        ("exclude", &definition.excluded_resource_ids),
    ] {
        for id in ids {
            conn.execute("INSERT INTO resource_group_members(resource_group_id,resource_id,effect) VALUES(?1,?2,?3)", params![definition.id,id,effect]).map_err(sql_unavailable)?;
        }
    }
    Ok(())
}

fn selection_references(
    selection: &ResourceSelection,
    id: &str,
    is_group: bool,
    groups: &[ResourceGroupDefinition],
) -> Vec<(Option<String>, Option<String>)> {
    let mut references = Vec::new();
    if is_group {
        if selection.resource_group_ids.iter().any(|value| value == id) {
            references.push((None, None));
        }
    } else {
        if selection.resource_ids.iter().any(|value| value == id) {
            references.push((None, Some("include".into())));
        }
        for group in groups
            .iter()
            .filter(|group| selection.resource_group_ids.contains(&group.id))
        {
            for (effect, ids) in [
                ("include", &group.included_resource_ids),
                ("exclude", &group.excluded_resource_ids),
            ] {
                if ids.iter().any(|value| value == id) {
                    references.push((Some(group.id.clone()), Some(effect.into())));
                }
            }
        }
    }
    references
}

fn resource_references(
    conn: &Connection,
    id: &str,
    is_group: bool,
) -> Result<Vec<ResourceReference>, ManagedStoreError> {
    let catalog = resource_catalog(conn)?;
    let mut result = Vec::new();
    if !is_group {
        for group in &catalog.resource_groups {
            for (effect, ids) in [
                ("include", &group.included_resource_ids),
                ("exclude", &group.excluded_resource_ids),
            ] {
                if ids.iter().any(|value| value == id) {
                    result.push(ResourceReference {
                        kind: "resource_group".into(),
                        id: group.id.clone(),
                        service: None,
                        principal_id: None,
                        via_group_id: None,
                        effect: Some(effect.into()),
                    });
                }
            }
        }
    }
    for grant in policy_grants(conn, None)?
        .into_iter()
        .filter(|grant| grant.status != "deleted")
    {
        for (via_group_id, effect) in
            selection_references(&grant.resources, id, is_group, &catalog.resource_groups)
        {
            result.push(ResourceReference {
                kind: "grant".into(),
                id: grant.grant_id.clone(),
                service: Some(grant.service.clone()),
                principal_id: None,
                via_group_id,
                effect,
            });
        }
    }
    result.extend(token_resource_references(conn, id, is_group, &catalog)?);
    Ok(result)
}

fn token_resource_references(
    conn: &Connection,
    id: &str,
    is_group: bool,
    catalog: &ManagedResourceCatalog,
) -> Result<Vec<ResourceReference>, ManagedStoreError> {
    let mut result = Vec::new();
    let now = Utc::now();
    let mut statement = conn.prepare("SELECT token_id,principal_id,scopes_json,expires_at FROM broker_tokens WHERE token_class='agent_invoke' AND revoked_at IS NULL ORDER BY token_id").map_err(sql_unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(sql_unavailable)?;
    for row in rows {
        let (token_id, principal_id, scopes, expires_at) = row.map_err(sql_unavailable)?;
        if let Some(expiry) = expires_at {
            let expiry = DateTime::parse_from_rfc3339(&expiry)
                .map_err(|_| ManagedStoreError::SchemaInvalid("invalid token expiration".into()))?;
            if expiry <= now {
                continue;
            }
        }
        let scopes: Value = serde_json::from_str(&scopes)
            .map_err(|_| ManagedStoreError::SchemaInvalid("invalid token caveats".into()))?;
        let caveats = AgentInvokeTokenCaveats::parse_stored(&scopes)
            .map_err(|error| input_invalid(error.to_string()))?;
        for (service, restriction) in caveats.service_restrictions.unwrap_or_default() {
            if let Some(selection) = restriction.resources {
                for (via_group_id, effect) in
                    selection_references(&selection, id, is_group, &catalog.resource_groups)
                {
                    result.push(ResourceReference {
                        kind: "token".into(),
                        id: token_id.clone(),
                        service: Some(service.clone()),
                        principal_id: Some(principal_id.clone()),
                        via_group_id,
                        effect,
                    });
                }
            }
        }
    }
    Ok(result)
}

pub(super) fn validate_token_resource_references(
    conn: &Connection,
    scopes: &Value,
    supplied_catalog: Option<&ManagedResourceCatalog>,
) -> Result<(), ManagedStoreError> {
    let caveats = AgentInvokeTokenCaveats::parse_stored(scopes)
        .map_err(|error| input_invalid(error.to_string()))?;
    let stored_catalog;
    let catalog = match supplied_catalog {
        Some(catalog) => catalog,
        None => {
            stored_catalog = resource_catalog(conn)?;
            &stored_catalog
        }
    };
    let catalog = ResourceCatalog::new(&catalog.resources, &catalog.resource_groups)
        .map_err(|errors| input_invalid(errors.join("; ")))?;
    for restriction in caveats.service_restrictions.unwrap_or_default().values() {
        if let Some(selection) = &restriction.resources {
            catalog
                .validate_selection(selection)
                .map_err(|errors| input_invalid(errors.join("; ")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    pub(super) fn store() -> (TempDir, ManagedStore) {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        (temp, store)
    }

    pub(super) fn accept(
        _: &[ManagedPolicyGrantRecord],
        _: &ManagedPolicyRevision,
        _: &ManagedPolicySubjectCatalog,
        _: &ManagedResourceCatalog,
    ) -> Result<(), ManagedStoreError> {
        Ok(())
    }

    pub(super) fn create(id: &str, selector: ResourceSelector) -> CreateResourceRequest {
        CreateResourceRequest {
            id: Some(id.into()),
            display_name: None,
            resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            selector,
            allowed_execution_contexts: vec!["internal".into()],
            enabled: true,
            attributes: agent_access_provider::ResourceAttributes::default(),
            created_by: "admin".into(),
        }
    }

    pub(super) fn group(
        id: &str,
        includes: &[&str],
        excludes: &[&str],
    ) -> CreateResourceGroupRequest {
        CreateResourceGroupRequest {
            id: Some(id.into()),
            name: id.into(),
            included_resource_ids: includes.iter().map(|id| (*id).into()).collect(),
            excluded_resource_ids: excludes.iter().map(|id| (*id).into()).collect(),
            created_by: "admin".into(),
        }
    }

    pub(super) fn delete(id: &str, version: i64) -> DeleteResourceRequest {
        DeleteResourceRequest {
            id: id.into(),
            expected_version: version,
            updated_by: "admin".into(),
        }
    }

    fn token_request(selection: ResourceSelection) -> BrokerTokenIssueRequest {
        BrokerTokenIssueRequest {
            principal_id: "alice".into(),
            name: "restricted".into(),
            token_class: BrokerTokenClass::AgentInvoke,
            scopes: serde_json::json!({"allowedServices":["gitlab"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"gitlab":{"actions":["repository.view"],"resources":selection}}}),
            expires_at: None,
            created_by: "admin".into(),
        }
    }

    fn token_setup(store: &ManagedStore) -> BrokerTokenHasher {
        store
            .create_principal(PrincipalWriteRequest {
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
        BrokerTokenHasher {
            key: Arc::new([7; 32]),
        }
    }

    #[test]
    fn catalog_mutation_validates_full_graph_and_rolls_back_atomically() {
        let (_temp, store) = store();
        let first = store
            .create_resource(create("all", ResourceSelector::All), accept)
            .unwrap();
        assert_eq!(first.revision.generation, 1);
        let duplicate = store.create_resource(create("duplicate", ResourceSelector::All), accept);
        assert!(duplicate.is_err());
        assert_eq!(store.policy_revision().unwrap().generation, 1);
        store
            .create_resource_group(
                group("external", &["all"], &[]),
                |grants, revision, _, catalog| {
                    assert!(grants.is_empty());
                    assert_eq!(revision.generation, 2);
                    assert_eq!(catalog.resources.len(), 1);
                    assert_eq!(
                        catalog.resource_groups[0].included_resource_ids,
                        vec!["all"]
                    );
                    Err(input_invalid("candidate rejected"))
                },
            )
            .unwrap_err();
        assert!(store.resource_groups().unwrap().is_empty());
        assert_eq!(store.load_policy_snapshot().unwrap().revision.generation, 1);
        let mut duplicate_disabled = create("disabled-all", ResourceSelector::All);
        duplicate_disabled.enabled = false;
        duplicate_disabled.allowed_execution_contexts = vec!["external".into()];
        assert!(store.create_resource(duplicate_disabled, accept).is_err());
    }

    #[test]
    fn disabled_exclusions_stay_referenced_and_used_by_explains_group_paths() {
        let (_temp, store) = store();
        store
            .create_resource(create("all", ResourceSelector::All), accept)
            .unwrap();
        store
            .create_resource(
                create(
                    "private",
                    ResourceSelector::Namespace {
                        value: "private".into(),
                    },
                ),
                accept,
            )
            .unwrap();
        store
            .create_resource_group(group("external", &["all"], &["private"]), accept)
            .unwrap();
        let grant = ManagedPolicyGrantCreateRequest {
            grant_id: Some("grant".into()),
            subjects: vec!["group:anonymous".into()],
            execution_contexts: vec!["external".into()],
            service: "gitlab".into(),
            actions: vec!["repository.view".into()],
            resources: ResourceSelection {
                resource_ids: vec![],
                resource_group_ids: vec!["external".into()],
            },
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        };
        store.create_policy_grant(grant, accept).unwrap();
        store
            .patch_resource(
                PatchResourceRequest {
                    id: "private".into(),
                    expected_version: 1,
                    attributes: agent_access_provider::ResourceAttributes::default(),
                    display_name: None,
                    resource_type: None,
                    selector: None,
                    allowed_execution_contexts: None,
                    enabled: Some(false),
                    updated_by: "admin".into(),
                },
                accept,
            )
            .unwrap();
        let usages = store.resource_used_by("private").unwrap();
        assert_eq!(usages.len(), 2);
        assert!(usages.iter().any(|reference| reference.kind == "grant"
            && reference.via_group_id.as_deref() == Some("external")
            && reference.effect.as_deref() == Some("exclude")));
        assert!(store.delete_resource(delete("private", 2), accept).is_err());
        assert!(
            store
                .delete_resource_group(delete("external", 1), accept)
                .is_err()
        );
        store
            .delete_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: "grant".into(),
                    expected_version: 1,
                    updated_by: "admin".into(),
                },
                accept,
            )
            .unwrap();
        store
            .delete_resource_group(delete("external", 1), accept)
            .unwrap();
        store.delete_resource(delete("private", 2), accept).unwrap();
        assert!(store.resource("private").is_err());
    }

    #[test]
    fn live_token_references_block_delete_until_revoked_or_expired() {
        let (_temp, store) = store();
        let hasher = token_setup(&store);
        store
            .create_resource(create("all", ResourceSelector::All), accept)
            .unwrap();
        let issued = store
            .issue_broker_token(
                &hasher,
                token_request(ResourceSelection {
                    resource_ids: vec!["all".into()],
                    resource_group_ids: vec![],
                }),
            )
            .unwrap();
        store
            .pause_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        assert_eq!(store.resource_used_by("all").unwrap().len(), 1);
        assert!(store.delete_resource(delete("all", 1), accept).is_err());
        store
            .revoke_broker_token(&issued.record.token_id, "admin")
            .unwrap();
        assert!(store.resource_used_by("all").unwrap().is_empty());
        let expiring = store
            .issue_broker_token(
                &hasher,
                token_request(ResourceSelection {
                    resource_ids: vec!["all".into()],
                    resource_group_ids: vec![],
                }),
            )
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE broker_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE token_id=?1",
                [&expiring.record.token_id],
            )
            .unwrap();
        store.delete_resource(delete("all", 1), accept).unwrap();
        assert!(
            store
                .resume_broker_token(&expiring.record.token_id, "admin")
                .is_err()
        );
        assert!(
            store
                .issue_broker_token(
                    &hasher,
                    token_request(ResourceSelection {
                        resource_ids: vec!["all".into()],
                        resource_group_ids: vec![]
                    })
                )
                .is_err()
        );
    }

    #[test]
    fn token_empty_selection_is_preserved_and_toml_catalog_is_authoritative() {
        let (_temp, store) = store();
        let hasher = token_setup(&store);
        let issued = store
            .issue_broker_token(&hasher, token_request(ResourceSelection::default()))
            .unwrap();
        assert_eq!(
            AgentInvokeTokenCaveats::parse_stored(&issued.record.scopes)
                .unwrap()
                .service_restrictions
                .unwrap()["gitlab"]
                .resources,
            Some(ResourceSelection::default())
        );
        let catalog = ManagedResourceCatalog {
            attribute_bindings: Vec::new(),
            resources: vec![ResourceDefinition {
                id: "configured".into(),
                display_name: None,
                resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
                selector: ResourceSelector::All,
                allowed_execution_contexts: vec!["internal".into()],
                enabled: true,
            }],
            resource_groups: vec![],
        };
        let request = token_request(ResourceSelection {
            resource_ids: vec!["configured".into()],
            resource_group_ids: vec![],
        });
        assert!(store.issue_broker_token(&hasher, request.clone()).is_err());
        let configured = store
            .issue_broker_token_with_catalog(&hasher, request, Some(&catalog))
            .unwrap();
        store
            .pause_broker_token(&configured.record.token_id, "admin")
            .unwrap();
        assert!(
            store
                .resume_broker_token(&configured.record.token_id, "admin")
                .is_err()
        );
        store
            .resume_broker_token_with_catalog(&configured.record.token_id, "admin", Some(&catalog))
            .unwrap();
        assert!(store.resources().unwrap().is_empty());
    }

    #[test]
    fn token_issuance_and_catalog_deletion_cannot_leave_live_dangling_references() {
        let (_temp, store) = store();
        let hasher = token_setup(&store);
        store
            .create_resource(create("all", ResourceSelector::All), accept)
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let issuer = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: store.path.display().to_string(),
                auto_migrate: false,
                require_registered_principal_for_invocation: false,
            },
            ManagedStoreOpenMode::Reload,
        )
        .unwrap();
        let issuer_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            issuer_barrier.wait();
            issuer.issue_broker_token(
                &hasher,
                token_request(ResourceSelection {
                    resource_ids: vec!["all".into()],
                    resource_group_ids: vec![],
                }),
            )
        });
        barrier.wait();
        let deleted = store.delete_resource(delete("all", 1), accept);
        let issued = worker.join().unwrap();
        assert_ne!(
            deleted.is_ok(),
            issued.is_ok(),
            "either issuance retains the resource or deletion prevents issuance"
        );
    }

    #[test]
    fn managed_resource_record_roundtrips_metadata_and_definition() {
        let (_temp, store) = store();
        let record = store
            .create_resource(create("all", ResourceSelector::All), accept)
            .unwrap()
            .record;
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["id"], "all");
        assert_eq!(json["version"], 1);
        assert_eq!(
            serde_json::from_value::<ManagedResourceRecord>(json).unwrap(),
            record
        );
    }

    #[test]
    fn resource_by_id_uses_the_resource_primary_key() {
        let (_temp, store) = store();
        let conn = store.connection.lock().unwrap();
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {RESOURCE_BY_ID_SQL}"))
            .unwrap();
        let details = statement
            .query_map(["resource-id"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details
                .iter()
                .any(|detail| detail.starts_with("SEARCH resources ")),
            "{details:?}"
        );
        assert!(
            details.iter().all(|detail| !detail.starts_with("SCAN ")),
            "{details:?}"
        );
    }
}
