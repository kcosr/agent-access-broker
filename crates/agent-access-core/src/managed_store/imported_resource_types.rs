//! Stored resources of imported types and the effects of an acceptance's
//! resource type changes, applied inside the acceptance transaction.
//!
//! Selector values are plaintext, so checking them against a changed grammar
//! is a query on the type's resources. Attribute values stay encrypted: only
//! the names of configured attributes are read, and a removed attribute's
//! values are deleted without decrypting them.
use super::*;
use crate::imports::{
    ImportedTypeAcceptance, ImportedTypeResource, ImportedTypeUsage, describe_type_violations,
};

/// The values one acceptance deleted from one resource: the removed
/// attributes the resource had configured. Its version advanced.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeletedResourceAttributes {
    pub resource_id: String,
    pub attributes: Vec<String>,
}

/// What an acceptance's resource type changes did to stored state.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTypeEffects {
    /// Resources whose removed attributes' values were deleted.
    pub deleted_attribute_values: Vec<DeletedResourceAttributes>,
    /// Removed types without resources that the acceptance dropped.
    pub dropped_types: Vec<String>,
    /// The managed policy revision before and after the acceptance, which
    /// advances when values were deleted or types dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_revision: Option<ManagedPolicyRevision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<ManagedPolicyRevision>,
}

/// What an acceptance that changes an import's resource types leaves in its
/// transaction, for the publishing generation to check against its new
/// registry and publish.
#[derive(Debug, Clone, Copy)]
pub struct ImportedTypeTransaction<'a> {
    /// The resource catalog after the acceptance's effects.
    pub catalog: &'a ManagedResourceCatalog,
    /// The advanced policy state, when the acceptance deleted attribute values
    /// or dropped types.
    pub policy: Option<&'a ManagedPolicyState>,
}

impl ImportedTypeEffects {
    pub fn is_empty(&self) -> bool {
        self.deleted_attribute_values.is_empty() && self.dropped_types.is_empty()
    }
}

impl ManagedStore {
    /// The stored resources of `types`, with the names of their configured
    /// private attributes; a type without resources maps to an empty list.
    pub fn imported_type_usage<'a>(
        &self,
        types: impl IntoIterator<Item = &'a str>,
    ) -> Result<ImportedTypeUsage, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        type_usage(&conn, types)
    }
}

pub(super) fn type_usage<'a>(
    conn: &Connection,
    types: impl IntoIterator<Item = &'a str>,
) -> Result<ImportedTypeUsage, ManagedStoreError> {
    let mut resources = conn
        .prepare(
            "SELECT resource_id,selector_kind,selector_value FROM resources
             WHERE resource_type=?1 ORDER BY resource_id",
        )
        .map_err(sql_unavailable)?;
    let mut attributes = conn
        .prepare(
            "SELECT m.resource_id,m.attribute_name FROM resource_secret_material m
             JOIN resources r ON r.resource_id=m.resource_id
             WHERE r.resource_type=?1 ORDER BY m.resource_id,m.attribute_name",
        )
        .map_err(sql_unavailable)?;
    let mut usage = ImportedTypeUsage::new();
    for resource_type in types {
        let mut configured = BTreeMap::<String, BTreeSet<String>>::new();
        let rows = attributes
            .query_map([resource_type], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_unavailable)?;
        for row in rows {
            let (resource, name) = row.map_err(sql_unavailable)?;
            configured.entry(resource).or_default().insert(name);
        }
        let rows = resources
            .query_map([resource_type], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sql_unavailable)?;
        let mut stored = Vec::new();
        for row in rows {
            let (id, kind, value) = row.map_err(sql_unavailable)?;
            let selector = match kind.as_str() {
                "exact" => ResourceSelector::Exact { value },
                "namespace" => ResourceSelector::Namespace { value },
                "all" => ResourceSelector::All,
                _ => {
                    return Err(ManagedStoreError::SchemaInvalid(
                        "resource selector kind is invalid".into(),
                    ));
                }
            };
            stored.push(ImportedTypeResource {
                attributes: configured.remove(&id).unwrap_or_default(),
                id,
                selector,
            });
        }
        usage.insert(resource_type.to_owned(), stored);
    }
    Ok(usage)
}

/// Rechecks and applies an acceptance's resource type changes. A change that
/// no longer applies to the stored resources rejects the acceptance, naming
/// them. Removed attributes' values are deleted, advancing each affected
/// resource's version as attribute edits do. When values were deleted or a
/// type dropped, the managed policy revision advances and the resulting
/// policy state is returned for publication with the catalog.
pub(super) fn apply_type_acceptance(
    conn: &Connection,
    plan: &ImportedTypeAcceptance,
    actor: &str,
) -> Result<(ImportedTypeEffects, Option<ManagedPolicyState>), ManagedStoreError> {
    let usage = type_usage(conn, plan.resource_types())?;
    let violations = plan.violations(&usage);
    if !violations.is_empty() {
        return Err(input_invalid(describe_type_violations(&violations)));
    }
    let now = normalized_now_string();
    let mut effects = ImportedTypeEffects {
        dropped_types: plan.dropped().to_vec(),
        ..ImportedTypeEffects::default()
    };
    for (resource_type, names) in plan.deletions() {
        for resource in usage.get(resource_type).into_iter().flatten() {
            let deleted = names
                .iter()
                .filter(|name| resource.attributes.contains(*name))
                .cloned()
                .collect::<Vec<_>>();
            if deleted.is_empty() {
                continue;
            }
            for name in &deleted {
                conn.execute(
                    "DELETE FROM resource_secret_material WHERE resource_id=?1 AND attribute_name=?2",
                    params![resource.id, name],
                )
                .map_err(sql_unavailable)?;
            }
            let updated = conn
                .execute(
                    "UPDATE resources SET version=version+1,updated_at=?2,updated_by=?3
                     WHERE resource_id=?1",
                    params![resource.id, now, actor],
                )
                .map_err(sql_unavailable)?;
            if updated != 1 {
                return Err(ManagedStoreError::VersionConflict);
            }
            effects
                .deleted_attribute_values
                .push(DeletedResourceAttributes {
                    resource_id: resource.id.clone(),
                    attributes: deleted,
                });
        }
    }
    if effects.is_empty() {
        return Ok((effects, None));
    }
    let previous_revision = policy_revision(conn)?;
    let revision = next_policy_revision(&previous_revision, &now, actor)?;
    update_policy_revision(conn, &revision)?;
    effects.previous_revision = Some(previous_revision);
    effects.revision = Some(revision.clone());
    let catalog = resources::resource_catalog(conn)?;
    let active_grants = policy_grants(conn, Some("active"))?;
    resources::validate_grant_resource_references(&active_grants, &catalog)?;
    Ok((
        effects,
        Some(ManagedPolicyState {
            revision,
            active_grants,
            catalog,
        }),
    ))
}
