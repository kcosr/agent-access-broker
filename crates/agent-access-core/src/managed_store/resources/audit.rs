//! Explicit, bounded event-time projections. Private resource attributes never
//! enter these types; snapshots and member labels are captured in the write transaction.
use super::*;

const MAX_TEXT_CHARS: usize = 512;
const MAX_LIST_ITEMS: usize = 50;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogAuditEntityKind {
    Resource,
    ResourceGroup,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CatalogAuditEntity {
    pub kind: CatalogAuditEntityKind,
    pub id: String,
    pub display_name: Option<String>,
    pub display_name_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<ResourceSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_truncated: Option<bool>,
    pub version: i64,
}

impl std::fmt::Display for CatalogAuditEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.display_name {
            return f.write_str(name);
        }
        match &self.selector {
            Some(ResourceSelector::Exact { value }) => f.write_str(value),
            Some(ResourceSelector::Namespace { value }) => write!(f, "{value}/*"),
            Some(ResourceSelector::All) => f.write_str("All resources"),
            None => f.write_str(&self.id),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogAuditSnapshot {
    #[serde(flatten)]
    pub entity: CatalogAuditEntity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_execution_contexts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_execution_contexts_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_execution_contexts_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub included_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogAuditMemberList {
    pub count: usize,
    pub items: Vec<CatalogAuditEntity>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogAuditMembership {
    pub included_added: CatalogAuditMemberList,
    pub included_removed: CatalogAuditMemberList,
    pub excluded_added: CatalogAuditMemberList,
    pub excluded_removed: CatalogAuditMemberList,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedCatalogAuditChange {
    pub before: Option<CatalogAuditSnapshot>,
    pub after: Option<CatalogAuditSnapshot>,
    pub changed_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<CatalogAuditMembership>,
}

impl ManagedCatalogAuditChange {
    pub fn target(&self) -> &CatalogAuditEntity {
        &self
            .after
            .as_ref()
            .or(self.before.as_ref())
            .expect("catalog mutation has a target")
            .entity
    }
}

fn bounded_text(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let text: String = chars.by_ref().take(MAX_TEXT_CHARS).collect();
    (text, chars.next().is_some())
}

pub(super) fn resource_entity(record: &ManagedResourceRecord) -> CatalogAuditEntity {
    let definition = &record.definition;
    let (display_name, display_name_truncated) = definition
        .display_name
        .as_deref()
        .map(|name| {
            let (name, truncated) = bounded_text(name);
            (Some(name), truncated)
        })
        .unwrap_or((None, false));
    let (selector, selector_truncated) = match &definition.selector {
        ResourceSelector::Exact { value } => {
            let (value, truncated) = bounded_text(value);
            (ResourceSelector::Exact { value }, truncated)
        }
        ResourceSelector::Namespace { value } => {
            let (value, truncated) = bounded_text(value);
            (ResourceSelector::Namespace { value }, truncated)
        }
        ResourceSelector::All => (ResourceSelector::All, false),
    };
    CatalogAuditEntity {
        kind: CatalogAuditEntityKind::Resource,
        id: definition.id.clone(),
        display_name,
        display_name_truncated,
        resource_type: Some(definition.resource_type.clone()),
        selector: Some(selector),
        selector_truncated: Some(selector_truncated),
        version: record.version,
    }
}

fn resource_snapshot(record: &ManagedResourceRecord) -> CatalogAuditSnapshot {
    let contexts = &record.definition.allowed_execution_contexts;
    let mut truncated = contexts.len() > MAX_LIST_ITEMS;
    let contexts = contexts
        .iter()
        .take(MAX_LIST_ITEMS)
        .map(|value| {
            let (value, was_truncated) = bounded_text(value);
            truncated |= was_truncated;
            value
        })
        .collect();
    CatalogAuditSnapshot {
        entity: resource_entity(record),
        enabled: Some(record.definition.enabled),
        allowed_execution_contexts: Some(contexts),
        allowed_execution_contexts_count: Some(record.definition.allowed_execution_contexts.len()),
        allowed_execution_contexts_truncated: Some(truncated),
        included_count: None,
        excluded_count: None,
    }
}

pub(super) fn resource_change(
    before: Option<&ManagedResourceRecord>,
    after: Option<&ManagedResourceRecord>,
    private_attributes_changed: bool,
) -> ManagedCatalogAuditChange {
    let mut fields = Vec::new();
    macro_rules! field {
        ($field:ident, $name:literal) => {
            if before.map(|r| &r.definition.$field) != after.map(|r| &r.definition.$field) {
                fields.push($name.into());
            }
        };
    }
    field!(display_name, "displayName");
    field!(resource_type, "resourceType");
    field!(selector, "selector");
    field!(enabled, "enabled");
    field!(allowed_execution_contexts, "allowedExecutionContexts");
    if private_attributes_changed {
        fields.push("privateAttributes".into());
    }
    ManagedCatalogAuditChange {
        before: before.map(resource_snapshot),
        after: after.map(resource_snapshot),
        changed_fields: fields,
        membership: None,
    }
}

fn group_snapshot(record: &ManagedResourceGroupRecord) -> CatalogAuditSnapshot {
    let (display_name, display_name_truncated) = bounded_text(&record.definition.name);
    CatalogAuditSnapshot {
        entity: CatalogAuditEntity {
            kind: CatalogAuditEntityKind::ResourceGroup,
            id: record.definition.id.clone(),
            display_name: Some(display_name),
            display_name_truncated,
            resource_type: None,
            selector: None,
            selector_truncated: None,
            version: record.version,
        },
        enabled: None,
        allowed_execution_contexts: None,
        allowed_execution_contexts_count: None,
        allowed_execution_contexts_truncated: None,
        included_count: Some(record.definition.included_resource_ids.len()),
        excluded_count: Some(record.definition.excluded_resource_ids.len()),
    }
}

fn member_difference(
    conn: &Connection,
    from: &[String],
    against: &[String],
) -> Result<CatalogAuditMemberList, ManagedStoreError> {
    let against: BTreeSet<_> = against.iter().collect();
    let ids: BTreeSet<_> = from.iter().filter(|id| !against.contains(id)).collect();
    let items = ids
        .iter()
        .take(MAX_LIST_ITEMS)
        .map(|id| resource_metadata_by_id(conn, id).map(|record| resource_entity(&record)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CatalogAuditMemberList {
        count: ids.len(),
        truncated: ids.len() > items.len(),
        items,
    })
}

pub(super) fn group_change(
    conn: &Connection,
    before: Option<&ManagedResourceGroupRecord>,
    after: Option<&ManagedResourceGroupRecord>,
) -> Result<ManagedCatalogAuditChange, ManagedStoreError> {
    let before_included = before
        .map(|r| r.definition.included_resource_ids.as_slice())
        .unwrap_or_default();
    let after_included = after
        .map(|r| r.definition.included_resource_ids.as_slice())
        .unwrap_or_default();
    let before_excluded = before
        .map(|r| r.definition.excluded_resource_ids.as_slice())
        .unwrap_or_default();
    let after_excluded = after
        .map(|r| r.definition.excluded_resource_ids.as_slice())
        .unwrap_or_default();
    let membership = CatalogAuditMembership {
        included_added: member_difference(conn, after_included, before_included)?,
        included_removed: member_difference(conn, before_included, after_included)?,
        excluded_added: member_difference(conn, after_excluded, before_excluded)?,
        excluded_removed: member_difference(conn, before_excluded, after_excluded)?,
    };
    let mut fields = Vec::new();
    if before.map(|r| &r.definition.name) != after.map(|r| &r.definition.name) {
        fields.push("name".into());
    }
    if membership.included_added.count + membership.included_removed.count > 0 {
        fields.push("includedResourceIds".into());
    }
    if membership.excluded_added.count + membership.excluded_removed.count > 0 {
        fields.push("excludedResourceIds".into());
    }
    Ok(ManagedCatalogAuditChange {
        before: before.map(group_snapshot),
        after: after.map(group_snapshot),
        changed_fields: fields,
        membership: Some(membership),
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::{accept, create, delete, group, store};
    use super::*;

    fn patch(id: &str, version: i64) -> PatchResourceRequest {
        PatchResourceRequest {
            id: id.into(),
            expected_version: version,
            display_name: None,
            resource_type: None,
            selector: None,
            allowed_execution_contexts: None,
            enabled: None,
            attributes: crate::ResourceAttributes::default(),
            updated_by: "admin".into(),
        }
    }

    #[test]
    fn snapshots_preserve_event_time_labels_and_real_membership_deltas() {
        let (_temp, store) = store();
        let mut request = create(
            "repo",
            ResourceSelector::Exact {
                value: "team/project".into(),
            },
        );
        request.display_name = Some("  Original repository  ".into());
        let created = store.create_resource(request, accept).unwrap();
        assert_eq!(
            created.audit.target().display_name.as_deref(),
            Some("Original repository")
        );
        assert!(created.audit.before.is_none());
        assert_eq!(created.audit.after.as_ref().unwrap().entity.version, 1);
        let mut group_request = group("group", &["repo"], &[]);
        group_request.name = "Engineering repositories".into();
        let group_created = store.create_resource_group(group_request, accept).unwrap();
        let members = &group_created
            .audit
            .membership
            .as_ref()
            .unwrap()
            .included_added;
        assert_eq!(members.count, 1);
        assert_eq!(
            members.items[0].display_name.as_deref(),
            Some("Original repository")
        );
        assert!(!members.truncated);
        let mut rename = patch("repo", 1);
        rename.display_name = Some(Some("Renamed repository".into()));
        let renamed = store.patch_resource(rename, accept).unwrap();
        assert_eq!(
            renamed
                .audit
                .before
                .as_ref()
                .unwrap()
                .entity
                .display_name
                .as_deref(),
            Some("Original repository")
        );
        assert_eq!(
            renamed
                .audit
                .after
                .as_ref()
                .unwrap()
                .entity
                .display_name
                .as_deref(),
            Some("Renamed repository")
        );
        assert_eq!(renamed.audit.changed_fields, ["displayName"]);
        let changed = store
            .patch_resource_group(
                PatchResourceGroupRequest {
                    id: "group".into(),
                    expected_version: 1,
                    name: Some("Exclusions".into()),
                    included_resource_ids: Some(vec![]),
                    excluded_resource_ids: Some(vec!["repo".into()]),
                    updated_by: "admin".into(),
                },
                accept,
            )
            .unwrap();
        let membership = changed.audit.membership.as_ref().unwrap();
        assert_eq!(membership.included_removed.count, 1);
        assert_eq!(membership.excluded_added.count, 1);
        assert_eq!(membership.included_added.count, 0);
        assert_eq!(membership.excluded_removed.count, 0);
        assert_eq!(
            membership.excluded_added.items[0].display_name.as_deref(),
            Some("Renamed repository")
        );
        assert_eq!(
            changed.audit.changed_fields,
            ["name", "includedResourceIds", "excludedResourceIds"]
        );
        let no_op = store
            .patch_resource_group(
                PatchResourceGroupRequest {
                    id: "group".into(),
                    expected_version: 2,
                    name: None,
                    included_resource_ids: None,
                    excluded_resource_ids: Some(vec!["repo".into()]),
                    updated_by: "admin".into(),
                },
                accept,
            )
            .unwrap();
        assert!(no_op.audit.changed_fields.is_empty());
        let deleted_group = store
            .delete_resource_group(delete("group", 3), accept)
            .unwrap();
        assert_eq!(
            deleted_group.audit.target().display_name.as_deref(),
            Some("Exclusions")
        );
        assert!(deleted_group.audit.after.is_none());
        assert_eq!(
            deleted_group
                .audit
                .membership
                .unwrap()
                .excluded_removed
                .count,
            1
        );
        let deleted = store.delete_resource(delete("repo", 2), accept).unwrap();
        assert_eq!(
            deleted.audit.target().display_name.as_deref(),
            Some("Renamed repository")
        );
        assert!(deleted.audit.after.is_none());
        // Earlier immutable projections remain independent of later rename/delete.
        assert_eq!(
            created.audit.target().display_name.as_deref(),
            Some("Original repository")
        );
        assert_eq!(
            members.items[0].display_name.as_deref(),
            Some("Original repository")
        );
    }

    #[test]
    fn snapshots_preserve_absent_and_cleared_display_names() {
        let (_temp, store) = store();
        let created = store
            .create_resource(
                create(
                    "unnamed",
                    ResourceSelector::Exact {
                        value: "team/unnamed".into(),
                    },
                ),
                accept,
            )
            .unwrap();
        assert_eq!(created.audit.target().display_name, None);
        assert!(!created.audit.target().display_name_truncated);
        assert_eq!(created.audit.target().to_string(), "team/unnamed");
        let serialized = serde_json::to_value(&created.audit).unwrap();
        assert_eq!(serialized["after"]["displayName"], Value::Null);
        assert!(serialized["after"].get("displayName").is_some());
        let grouped = store
            .create_resource_group(group("unnamed-group", &["unnamed"], &[]), accept)
            .unwrap();
        let member = &grouped
            .audit
            .membership
            .as_ref()
            .unwrap()
            .included_added
            .items[0];
        assert_eq!(member.display_name, None);
        assert_eq!(member.to_string(), "team/unnamed");
        assert_eq!(
            grouped.audit.target().display_name.as_deref(),
            Some("unnamed-group")
        );

        // An explicit name equal to the selector is still distinct from no name.
        let mut named_request = patch("unnamed", 1);
        named_request.display_name = Some(Some("team/unnamed".into()));
        let named = store.patch_resource(named_request, accept).unwrap();
        assert_eq!(
            named.audit.before.as_ref().unwrap().entity.display_name,
            None
        );
        assert_eq!(
            named
                .audit
                .after
                .as_ref()
                .unwrap()
                .entity
                .display_name
                .as_deref(),
            Some("team/unnamed")
        );
        let mut clear_request = patch("unnamed", 2);
        clear_request.display_name = Some(None);
        let cleared = store.patch_resource(clear_request, accept).unwrap();
        let cleared_json = serde_json::to_value(&cleared.audit).unwrap();
        assert_eq!(cleared_json["before"]["displayName"], "team/unnamed");
        assert_eq!(cleared_json["after"]["displayName"], Value::Null);
        assert_eq!(cleared.audit.changed_fields, ["displayName"]);
        assert!(!cleared.audit.target().display_name_truncated);
        assert_eq!(cleared.audit.target().to_string(), "team/unnamed");
        assert_eq!(created.audit.target().display_name, None);

        let mut record = cleared.record;
        record.definition.selector = ResourceSelector::Namespace {
            value: "team".into(),
        };
        assert_eq!(resource_entity(&record).to_string(), "team/*");
        record.definition.selector = ResourceSelector::All;
        assert_eq!(resource_entity(&record).to_string(), "All resources");
        record.definition.selector = ResourceSelector::Exact {
            value: "界".repeat(700),
        };
        let bounded = resource_entity(&record);
        assert_eq!(bounded.display_name, None);
        assert!(!bounded.display_name_truncated);
        assert_eq!(bounded.selector_truncated, Some(true));
        assert_eq!(bounded.to_string().chars().count(), 512);
    }

    #[test]
    fn duplicate_error_identifies_existing_entry_and_rolls_back_patch() {
        let (_temp, store) = store();
        store
            .create_resource(
                create(
                    "existing",
                    ResourceSelector::Exact {
                        value: "team/original".into(),
                    },
                ),
                accept,
            )
            .unwrap();
        store
            .create_resource(
                create(
                    "other",
                    ResourceSelector::Exact {
                        value: "team/other".into(),
                    },
                ),
                accept,
            )
            .unwrap();
        let revision = store.policy_revision().unwrap();
        let duplicate = store
            .create_resource(
                create(
                    "zzz-new",
                    ResourceSelector::Exact {
                        value: "team/original".into(),
                    },
                ),
                accept,
            )
            .unwrap_err();
        let ManagedStoreError::ResourceConflict(existing) = duplicate else {
            panic!("expected structured conflict")
        };
        assert_eq!(existing.id, "existing");
        assert_eq!(existing.display_name, None);
        assert_eq!(existing.to_string(), "team/original");
        let mut change = patch("other", 1);
        change.selector = Some(ResourceSelector::Exact {
            value: "team/original".into(),
        });
        let ManagedStoreError::ResourceConflict(existing) =
            store.patch_resource(change, accept).unwrap_err()
        else {
            panic!("expected structured patch conflict")
        };
        assert_eq!(existing.id, "existing");
        assert_eq!(store.policy_revision().unwrap(), revision);
        assert_eq!(store.resource("other").unwrap().version, 1);
        // Keeping one's own selector is not a duplicate.
        let no_op = store.patch_resource(patch("existing", 1), accept).unwrap();
        assert!(no_op.audit.changed_fields.is_empty());
        assert!(matches!(
            store.patch_resource(patch("existing", 1), accept),
            Err(ManagedStoreError::VersionConflict)
        ));
    }

    #[test]
    fn audit_bounds_are_explicit_and_unicode_safe() {
        let (_temp, store) = store();
        let mut ids = Vec::new();
        for index in 0..55 {
            let id = format!("repo-{index:02}");
            let mut request = create(
                &id,
                ResourceSelector::Exact {
                    value: format!("team/{index}"),
                },
            );
            request.display_name = Some("界".repeat(600));
            store.create_resource(request, accept).unwrap();
            ids.push(id);
        }
        let refs: Vec<_> = ids.iter().map(String::as_str).collect();
        let result = store
            .create_resource_group(group("many", &refs, &[]), accept)
            .unwrap();
        let included = &result.audit.membership.unwrap().included_added;
        assert_eq!(included.count, 55);
        assert_eq!(included.items.len(), 50);
        assert!(included.truncated);
        assert_eq!(
            included.items[0]
                .display_name
                .as_deref()
                .unwrap()
                .chars()
                .count(),
            512
        );
        assert!(included.items[0].display_name_truncated);
        assert_eq!(result.audit.after.unwrap().included_count, Some(55));
        let mut raw = store.resource("repo-00").unwrap();
        raw.definition.selector = ResourceSelector::Exact {
            value: "x".repeat(700),
        };
        raw.definition.allowed_execution_contexts = vec!["ctx".repeat(250); 51];
        let snapshot = resource_snapshot(&raw);
        assert_eq!(snapshot.entity.selector_truncated, Some(true));
        assert_eq!(
            snapshot.allowed_execution_contexts.as_ref().unwrap().len(),
            50
        );
        assert_eq!(snapshot.allowed_execution_contexts_count, Some(51));
        assert_eq!(snapshot.allowed_execution_contexts_truncated, Some(true));
        let serialized = serde_json::to_value(snapshot).unwrap();
        assert!(serialized.get("configuredAttributes").is_none());
        assert!(serialized.get("attributes").is_none());
    }
}
