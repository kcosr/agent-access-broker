//! Resource type changes of imported services in previews and acceptances.
//!
//! Discovery plans the declared types over the accepted ones against the
//! stored resources: the preview records the metadata an acceptance stores
//! and a decision per changed type, and actions whose type changed in a way
//! its stored resources cannot follow become unsupported. Preview responses
//! show each decision with the resources it currently depends on. An
//! acceptance may choose the Broker type IDs of added types; the store
//! rechecks every resource-dependent decision in the acceptance transaction.
use agent_access_core::imports::{
    IMPORT_TYPE_RESOURCE_SAMPLE, ImportedDiscovery, ImportedResourceTypeChange,
    ImportedResourceTypeChangeKind, ImportedResourceTypeOutcome, ImportedServiceMetadata,
    ImportedTypeAcceptance, ImportedTypePreview, command_action_resource_type,
};
use agent_access_core::{
    BrokerRuntime, ImportedPreview, ImportedServiceRecord, ManagedStore, ManagedStoreError,
};
use agent_access_provider::ResourceType;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(message: impl Into<String>) -> ManagedStoreError {
    ManagedStoreError::InputInvalid(message.into())
}

/// Plans the resource types `discovery` proposes over `record`'s accepted
/// types: the discovery then carries the metadata an acceptance stores and
/// the decision for every changed type, and actions using a type whose
/// change needs a new type id are unsupported.
pub(super) fn plan_discovery(
    store: &ManagedStore,
    record: &ImportedServiceRecord,
    discovery: &mut ImportedDiscovery,
) -> Result<(), ManagedStoreError> {
    let Some(proposed) = &discovery.service_metadata else {
        return Ok(());
    };
    let accepted = record.accepted_metadata.as_ref();
    let usage = store.imported_type_usage(
        accepted
            .into_iter()
            .flat_map(|accepted| &accepted.resource_types)
            .map(|declared| declared.broker_type.as_str()),
    )?;
    let preview = ImportedTypePreview::plan(accepted, proposed, &usage).map_err(invalid)?;
    preview.target.validate().map_err(invalid)?;
    let needs_new_id = preview
        .needs_new_id()
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for tool in &mut discovery.tools {
        if tool.unsupported_reason.is_some() {
            continue;
        }
        if let Some(resource_type) = command_action_resource_type(&tool.definition)
            .filter(|resource_type| needs_new_id.contains(*resource_type))
        {
            tool.unsupported_reason = Some(format!(
                "resource type {resource_type} changed in a way its stored resources cannot follow; declare it under a new id"
            ));
        }
    }
    discovery.service_metadata = Some(preview.target);
    discovery.resource_type_changes = preview.changes;
    Ok(())
}

/// A preview's decision for one type with the stored resources it currently
/// depends on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TypeChangeStatus<'a> {
    #[serde(flatten)]
    change: &'a ImportedResourceTypeChange,
    /// Stored resources of the type.
    resource_count: usize,
    /// Resources that keep a needs-new-id or retained type in its accepted
    /// form, or that currently prevent an applied change or drop. At most
    /// [`IMPORT_TYPE_RESOURCE_SAMPLE`].
    blocking_resources: Vec<String>,
    /// Resources whose removed attributes' values the acceptance deletes. At
    /// most [`IMPORT_TYPE_RESOURCE_SAMPLE`].
    affected_resources: Vec<String>,
    /// The Broker type ID of an added type can still be chosen.
    editable: bool,
    /// Accepting now would be rejected because of this type: resources
    /// prevent its change or drop, or another owner registers its ID.
    blocked: bool,
}

fn sample(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    ids.into_iter().take(IMPORT_TYPE_RESOURCE_SAMPLE).collect()
}

/// The resource type changes of `preview` with the stored resources each
/// currently depends on; an empty list for a preview that changes none.
pub(super) fn type_changes(
    store: &ManagedStore,
    runtime: &BrokerRuntime,
    record: &ImportedServiceRecord,
    preview: Option<&ImportedPreview>,
) -> Result<serde_json::Value, ManagedStoreError> {
    let Some(preview) = preview else {
        return Ok(serde_json::json!([]));
    };
    let manifest: ImportedDiscovery = serde_json::from_value(preview.manifest.clone())
        .map_err(|_| invalid("stored discovery preview is invalid"))?;
    let Some(target) = &manifest.service_metadata else {
        return Ok(serde_json::json!([]));
    };
    let plan = ImportedTypeAcceptance::plan(record.accepted_metadata.as_ref(), target)
        .map_err(|_| invalid("stored discovery preview is invalid"))?;
    let usage = store.imported_type_usage(
        manifest
            .resource_type_changes
            .iter()
            .map(|change| change.broker_type.as_str()),
    )?;
    let violations = plan.violations(&usage);
    let deletions = plan
        .deletions()
        .iter()
        .map(|(broker_type, names)| (broker_type.as_str(), names))
        .collect::<BTreeMap<_, _>>();
    let service = &record.definition.service;
    let statuses = manifest
        .resource_type_changes
        .iter()
        .map(|change| {
            let resources = usage
                .get(&change.broker_type)
                .map_or(&[][..], Vec::as_slice);
            let blocking = match change.outcome {
                ImportedResourceTypeOutcome::NeedsNewId | ImportedResourceTypeOutcome::Retained => {
                    resources
                        .iter()
                        .map(|resource| resource.id.clone())
                        .collect()
                }
                _ => violations
                    .get(&change.broker_type)
                    .cloned()
                    .unwrap_or_default(),
            };
            let affected = deletions
                .get(change.broker_type.as_str())
                .map(|names| {
                    resources
                        .iter()
                        .filter(|resource| {
                            names.iter().any(|name| resource.attributes.contains(name))
                        })
                        .map(|resource| resource.id.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let editable = change.change == ImportedResourceTypeChangeKind::Added;
            TypeChangeStatus {
                change,
                resource_count: resources.len(),
                blocked: violations.contains_key(&change.broker_type)
                    || (editable
                        && runtime.imported_resource_type_taken(service, &change.broker_type)),
                blocking_resources: sample(blocking),
                affected_resources: sample(affected),
                editable,
            }
        })
        .collect::<Vec<_>>();
    serde_json::to_value(statuses).map_err(|_| invalid("resource type changes cannot be encoded"))
}

/// Applies the administrator's Broker type IDs to the types an acceptance
/// adds, then checks every added type's ID: well formed, distinct within the
/// import, and registered by no other owner. Accepted types keep their IDs.
pub(super) fn choose_type_ids(
    runtime: &BrokerRuntime,
    record: &ImportedServiceRecord,
    metadata: &mut ImportedServiceMetadata,
    chosen: &BTreeMap<String, String>,
) -> Result<(), ManagedStoreError> {
    let accepted = |id: &str| {
        record.accepted_metadata.as_ref().is_some_and(|accepted| {
            accepted
                .resource_types
                .iter()
                .any(|declared| declared.id == id)
        })
    };
    for (id, broker_type) in chosen {
        let declared = metadata
            .resource_types
            .iter_mut()
            .find(|declared| declared.id == *id)
            .ok_or_else(|| {
                invalid(format!(
                    "resourceTypeIds names {id}, which the preview does not declare"
                ))
            })?;
        if accepted(id) {
            return Err(invalid(format!(
                "resource type {id} keeps its accepted Broker type ID {}",
                declared.broker_type
            )));
        }
        ResourceType::new(broker_type.clone()).map_err(invalid)?;
        declared.broker_type = broker_type.clone();
    }
    let service = &record.definition.service;
    for declared in metadata
        .resource_types
        .iter()
        .filter(|declared| !accepted(&declared.id))
    {
        if runtime.imported_resource_type_taken(service, &declared.broker_type) {
            return Err(invalid(format!(
                "resource type ID {} is already registered; choose another in resourceTypeIds",
                declared.broker_type
            )));
        }
    }
    metadata.validate().map_err(invalid)
}
