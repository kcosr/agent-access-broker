//! Stored resources of imported types and the effects of an acceptance's
//! resource type changes, applied inside the acceptance transaction.
//!
//! Selector values are plaintext, so checking them against a changed grammar
//! is a query on the type's resources. Attribute values stay encrypted: only
//! the names of configured attributes are read, and a removed attribute's
//! values are deleted without decrypting them.
use super::*;
use crate::imports::{
    IMPORT_TYPE_RESOURCE_SAMPLE, ImportedTypeAcceptance, ImportedTypeResource, ImportedTypeUsage,
    describe_type_violations,
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
    let mut exclusions = conn
        .prepare(
            "SELECT m.resource_id,m.resource_group_id FROM resource_group_members m
         JOIN resources r ON r.resource_id=m.resource_id
         WHERE r.resource_type=?1 AND m.effect='exclude'
         ORDER BY m.resource_id,m.resource_group_id",
        )
        .map_err(sql_unavailable)?;
    let mut usage = ImportedTypeUsage::new();
    for resource_type in types {
        let mut excluded_by = BTreeMap::<String, BTreeSet<String>>::new();
        let rows = exclusions
            .query_map([resource_type], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_unavailable)?;
        for row in rows {
            let (resource, group) = row.map_err(sql_unavailable)?;
            excluded_by.entry(resource).or_default().insert(group);
        }
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
                excluded_by: excluded_by.remove(&id).unwrap_or_default(),
                id,
                selector,
            });
        }
        usage.insert(resource_type.to_owned(), stored);
    }
    Ok(usage)
}

/// Keep human-readable errors concise; the structured target carries the
/// separately bounded resource memberships needed to resolve each blocker.
fn describe_acceptance_violations(
    resources: &BTreeMap<String, Vec<String>>,
    groups: &BTreeMap<String, Vec<crate::imports::ImportedTypeBlockingGroup>>,
) -> String {
    const NAMED_GROUPS: usize = 20;
    let mut messages = Vec::new();
    if !resources.is_empty() {
        messages.push(describe_type_violations(resources));
    }
    if !groups.is_empty() {
        let count: usize = groups.values().map(Vec::len).sum();
        let mut references = groups
            .iter()
            .flat_map(|(kind, entries)| {
                entries.iter().map(move |group| {
                    format!(
                        "{kind}: group {} excludes {} resource(s)",
                        group.id,
                        group.resource_ids.len()
                    )
                })
            })
            .take(NAMED_GROUPS)
            .collect::<Vec<_>>()
            .join("; ");
        if count > NAMED_GROUPS {
            references.push_str(&format!("; and {} more group(s)", count - NAMED_GROUPS));
        }
        messages.push(format!(
            "resource types cannot disable exclusions while groups exclude their resources; edit the groups first ({references})"
        ));
    }
    messages.join("; ")
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
    let group_violations = plan.group_violations(&usage);
    if !violations.is_empty() || !group_violations.is_empty() {
        return Err(ManagedStoreError::ImportChangeBlocked(Box::new(
            crate::ImportChangeBlocked {
                message: describe_acceptance_violations(&violations, &group_violations),
                resource_groups: group_violations
                    .iter()
                    .flat_map(|(kind, groups)| {
                        groups
                            .iter()
                            .map(move |group| crate::ImportBlockingResourceGroup {
                                resource_type: kind.clone(),
                                id: group.id.clone(),
                                resource_ids: group
                                    .resource_ids
                                    .iter()
                                    .take(IMPORT_TYPE_RESOURCE_SAMPLE)
                                    .cloned()
                                    .collect(),
                            })
                    })
                    .take(IMPORT_TYPE_RESOURCE_SAMPLE)
                    .collect(),
                affected_grants: Vec::new(),
                resources: violations
                    .iter()
                    .flat_map(|(broker_type, ids)| {
                        ids.iter().take(IMPORT_TYPE_RESOURCE_SAMPLE).map(|id| {
                            crate::ImportBlockingResource {
                                resource_type: broker_type.clone(),
                                id: id.clone(),
                            }
                        })
                    })
                    .collect(),
            },
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::ImportedTypeBlockingGroup;

    #[test]
    fn acceptance_error_reports_resource_and_group_remedies_together() {
        let resources = BTreeMap::from([("tickets_project".into(), vec!["legacy".into()])]);
        let groups = BTreeMap::from([(
            "tickets_project".into(),
            vec![ImportedTypeBlockingGroup {
                id: "unused".into(),
                resource_ids: vec!["ops".into()],
            }],
        )]);
        let message = describe_acceptance_violations(&resources, &groups);
        assert!(message.contains("edit or delete them"), "{message}");
        assert!(message.contains("tickets_project: legacy"), "{message}");
        assert!(message.contains("edit the groups first"), "{message}");
        assert!(
            message.contains("tickets_project: group unused excludes 1 resource(s)"),
            "{message}"
        );
        assert_eq!(
            describe_acceptance_violations(&resources, &BTreeMap::new()),
            describe_type_violations(&resources)
        );
        let groups_only = describe_acceptance_violations(&BTreeMap::new(), &groups);
        assert!(!groups_only.contains("edit or delete"), "{groups_only}");
    }

    #[test]
    fn acceptance_error_bounds_group_names_across_types_and_counts_memberships() {
        let members = (0..150)
            .map(|n| format!("private-member-{n:03}"))
            .collect::<Vec<_>>();
        let groups = ["tickets_project", "tickets_queue"]
            .into_iter()
            .map(|kind| {
                (
                    kind.to_owned(),
                    (0..15)
                        .map(|n| ImportedTypeBlockingGroup {
                            id: format!("group-{n:02}"),
                            resource_ids: members.clone(),
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let message = describe_acceptance_violations(&BTreeMap::new(), &groups);
        assert_eq!(
            message.matches("excludes 150 resource(s)").count(),
            20,
            "{message}"
        );
        assert!(
            message.contains("tickets_project: group group-14"),
            "{message}"
        );
        assert!(
            message.contains("tickets_queue: group group-04"),
            "{message}"
        );
        assert!(
            !message.contains("tickets_queue: group group-05"),
            "{message}"
        );
        assert!(message.contains("and 10 more group(s)"), "{message}");
        assert!(!message.contains("private-member-"), "{message}");
        // Membership cardinality changes only the count, not the volume of names.
        assert!(message.len() < 1600, "{} bytes: {message}", message.len());
    }
}
