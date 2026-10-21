//! Changes to an import's accepted resource types.
//!
//! Accepted types are keyed by Broker type ID. A refresh compares each
//! declared type with the accepted one and records a decision per changed
//! type in the preview, together with the metadata an acceptance would
//! store. Safe changes apply in place; a change that would need decrypting
//! stored attribute values applies only while the type has no resources;
//! a type the source no longer declares stays registered, accepting no new
//! resources, until its resources are deleted. An acceptance rechecks every
//! decision that depends on stored resources in its own transaction.
use super::{ImportedActionDefinition, ImportedResourceTypeDeclaration, ImportedServiceMetadata};
use agent_access_provider::{
    ResourceAttributeDescriptor, ResourcePattern, ResourceSelector, ResourceType,
    ResourceTypeDescriptor,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The longest private attribute value, which bounds attribute patterns.
pub const IMPORT_MAX_ATTRIBUTE_VALUE_BYTES: usize = 8 * 1024;

/// The registry descriptor of an accepted imported type: its Broker type ID,
/// labels, selector grammar and private attributes, all from the
/// declaration.
pub fn imported_type_descriptor(
    declared: &ImportedResourceTypeDeclaration,
) -> Result<ResourceTypeDescriptor, String> {
    let id = ResourceType::new(declared.broker_type.clone())?;
    let pattern = ResourcePattern::new(declared.pattern.clone(), declared.max_length as usize)?;
    let attributes = declared
        .attributes
        .iter()
        .map(|attribute| {
            let pattern = attribute
                .pattern
                .as_ref()
                .map(|pattern| {
                    ResourcePattern::new(pattern.clone(), IMPORT_MAX_ATTRIBUTE_VALUE_BYTES)
                })
                .transpose()?;
            Ok(ResourceAttributeDescriptor::declared(
                attribute.name.clone(),
                attribute.label.clone(),
                attribute.description.clone(),
                attribute.required,
                pattern,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ResourceTypeDescriptor::declared(
        id,
        declared.label.clone(),
        declared.plural_label.clone(),
        declared.example.clone(),
        pattern,
        attributes,
    )
    .with_supports_exclusions(declared.supports_exclusions))
}

/// The manifest type id a command action names in
/// `annotations.command.resources.type`, if it declares one.
pub fn command_action_resource_type(action: &ImportedActionDefinition) -> Option<&str> {
    action
        .annotations
        .get("command")?
        .get("resources")?
        .get("type")?
        .as_str()
}

/// How a type in the preview relates to the accepted metadata.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedResourceTypeChangeKind {
    /// Declared for the first time; its Broker type ID is editable until it
    /// is accepted.
    Added,
    /// Declared with a different definition.
    Changed,
    /// Declared again after the source had removed it.
    Restored,
    /// No longer declared.
    Removed,
}

/// What an acceptance of the preview does with a type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedResourceTypeOutcome {
    /// The declaration is stored.
    Applied,
    /// The change needs a new type id because stored resources of the type
    /// can hold attribute values: the accepted declaration stays and the
    /// actions using the type are unsupported.
    NeedsNewId,
    /// The removed type keeps its accepted declaration, accepting no new
    /// resources, until its resources are deleted.
    Retained,
    /// The removed type has no resources and is dropped.
    Dropped,
}

/// One difference between a declared type and its accepted declaration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedResourceTypeChangeDetail {
    Label,
    PluralLabel,
    Example,
    /// A new optional attribute.
    AttributeAdded,
    /// A required attribute became optional.
    AttributeMadeOptional,
    /// An attribute's label or description.
    AttributeText,
    /// The attributes' order.
    AttributeOrder,
    /// An attribute was removed; its stored values are deleted.
    AttributeRemoved,
    /// The selector pattern; stored values must still match.
    Pattern,
    /// The selector `maxLength`; stored values must still fit.
    MaxLength,
    /// A new required attribute.
    AttributeAddedRequired,
    /// An optional attribute became required.
    AttributeMadeRequired,
    /// An attribute's pattern changed.
    AttributePattern,
    /// Resources may no longer be excluded by groups.
    ExclusionsUnsupported,
    /// Resources may again be excluded by groups.
    ExclusionsSupported,
}

impl ImportedResourceTypeChangeDetail {
    /// Whether the change applies only while no stored resource of the type
    /// can hold attribute values: checking stored values would mean
    /// decrypting them. Only exact resources hold attribute values.
    pub fn needs_value_free_type(self) -> bool {
        matches!(
            self,
            Self::AttributeAddedRequired | Self::AttributeMadeRequired | Self::AttributePattern
        )
    }

    /// Whether stored selector values must match the declared grammar.
    pub fn checks_values(self) -> bool {
        matches!(self, Self::Pattern | Self::MaxLength)
    }
}

/// The preview's decision for one changed type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedResourceTypeChange {
    /// The source's type id.
    pub id: String,
    pub broker_type: String,
    pub change: ImportedResourceTypeChangeKind,
    pub outcome: ImportedResourceTypeOutcome,
    /// What changed, for a changed or restored type.
    pub details: Vec<ImportedResourceTypeChangeDetail>,
}

/// One stored resource of an imported type: its selector and the names of
/// its configured private attributes. Values stay encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedTypeResource {
    pub id: String,
    pub selector: ResourceSelector,
    pub attributes: BTreeSet<String>,
    /// Every group that excludes this resource, including unused groups.
    pub excluded_by: BTreeSet<String>,
}

/// A group preventing a type from disabling exclusions.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTypeBlockingGroup {
    pub id: String,
    pub resource_ids: Vec<String>,
}

impl ImportedTypeResource {
    /// Whether the resource can hold private attribute values. The store and
    /// the SDK accept attribute values only on exact resources, and a
    /// resource with values cannot change its selector kind, so `all`
    /// resources never hold any.
    pub fn holds_attribute_values(&self) -> bool {
        matches!(self.selector, ResourceSelector::Exact { .. })
    }
}

/// Stored resources by Broker type ID.
pub type ImportedTypeUsage = BTreeMap<String, Vec<ImportedTypeResource>>;

struct Comparison {
    details: BTreeSet<ImportedResourceTypeChangeDetail>,
    removed_attributes: Vec<String>,
}

impl Comparison {
    fn needs_value_free_type(&self) -> bool {
        self.details
            .iter()
            .any(|detail| detail.needs_value_free_type())
    }

    fn checks_values(&self) -> bool {
        self.details.iter().any(|detail| detail.checks_values())
    }
}

/// Compares a declaration with the accepted one, ignoring the Broker type ID
/// and the removed marker.
fn compare(
    accepted: &ImportedResourceTypeDeclaration,
    declared: &ImportedResourceTypeDeclaration,
) -> Comparison {
    use ImportedResourceTypeChangeDetail as Detail;
    let mut details = BTreeSet::new();
    for (changed, detail) in [
        (accepted.label != declared.label, Detail::Label),
        (
            accepted.plural_label != declared.plural_label,
            Detail::PluralLabel,
        ),
        (accepted.example != declared.example, Detail::Example),
        (accepted.pattern != declared.pattern, Detail::Pattern),
        (
            accepted.max_length != declared.max_length,
            Detail::MaxLength,
        ),
    ] {
        if changed {
            details.insert(detail);
        }
    }
    if accepted.supports_exclusions != declared.supports_exclusions {
        details.insert(if declared.supports_exclusions {
            Detail::ExclusionsSupported
        } else {
            Detail::ExclusionsUnsupported
        });
    }
    let old = accepted
        .attributes
        .iter()
        .map(|attribute| (attribute.name.as_str(), attribute))
        .collect::<BTreeMap<_, _>>();
    let removed_attributes = accepted
        .attributes
        .iter()
        .filter(|attribute| {
            !declared
                .attributes
                .iter()
                .any(|declared| declared.name == attribute.name)
        })
        .map(|attribute| attribute.name.clone())
        .collect::<Vec<_>>();
    if !removed_attributes.is_empty() {
        details.insert(Detail::AttributeRemoved);
    }
    for attribute in &declared.attributes {
        let Some(previous) = old.get(attribute.name.as_str()) else {
            details.insert(if attribute.required {
                Detail::AttributeAddedRequired
            } else {
                Detail::AttributeAdded
            });
            continue;
        };
        if previous.required && !attribute.required {
            details.insert(Detail::AttributeMadeOptional);
        }
        if !previous.required && attribute.required {
            details.insert(Detail::AttributeMadeRequired);
        }
        if previous.pattern != attribute.pattern {
            details.insert(Detail::AttributePattern);
        }
        if previous.label != attribute.label || previous.description != attribute.description {
            details.insert(Detail::AttributeText);
        }
    }
    if kept_names(&accepted.attributes, &declared.attributes)
        != kept_names(&declared.attributes, &accepted.attributes)
    {
        details.insert(Detail::AttributeOrder);
    }
    Comparison {
        details,
        removed_attributes,
    }
}

/// The names in `attributes` that `other` also declares, in order.
fn kept_names<'a>(
    attributes: &'a [super::ImportedResourceAttributeDeclaration],
    other: &[super::ImportedResourceAttributeDeclaration],
) -> Vec<&'a str> {
    attributes
        .iter()
        .filter(|attribute| other.iter().any(|other| other.name == attribute.name))
        .map(|attribute| attribute.name.as_str())
        .collect()
}

fn has_resources(usage: &ImportedTypeUsage, broker_type: &str) -> bool {
    usage
        .get(broker_type)
        .is_some_and(|resources| !resources.is_empty())
}

/// The stored resources of `broker_type` that can hold attribute values.
fn value_resources<'a>(
    usage: &'a ImportedTypeUsage,
    broker_type: &str,
) -> impl Iterator<Item = &'a ImportedTypeResource> {
    usage
        .get(broker_type)
        .into_iter()
        .flatten()
        .filter(|resource| resource.holds_attribute_values())
}

/// What a preview proposes for the import's resource types.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedTypePreview {
    /// The metadata an acceptance of the preview stores: the declared types
    /// as they apply, accepted declarations kept for changes that need a new
    /// type id, and removed types that still have resources.
    pub target: ImportedServiceMetadata,
    /// The decision for every type that is added, changed, restored or
    /// removed.
    pub changes: Vec<ImportedResourceTypeChange>,
}

impl ImportedTypePreview {
    /// The manifest type ids whose changes need a new type id; actions using
    /// them are unsupported.
    pub fn needs_new_id(&self) -> BTreeSet<&str> {
        self.changes
            .iter()
            .filter(|change| change.outcome == ImportedResourceTypeOutcome::NeedsNewId)
            .map(|change| change.id.as_str())
            .collect()
    }

    /// Plans `proposed`, a source's declaration as its adapter proposes it,
    /// over the `accepted` metadata, given the resources currently stored for
    /// the accepted types.
    pub fn plan(
        accepted: Option<&ImportedServiceMetadata>,
        proposed: &ImportedServiceMetadata,
        usage: &ImportedTypeUsage,
    ) -> Result<Self, String> {
        use ImportedResourceTypeChangeKind as Kind;
        use ImportedResourceTypeOutcome as Outcome;
        let accepted_types = accepted.map_or(&[][..], |accepted| &accepted.resource_types[..]);
        let mut target = Vec::new();
        let mut changes = Vec::new();
        for declared in &proposed.resource_types {
            if declared.removed {
                return Err("a declared resource type cannot be marked removed".into());
            }
            let Some(previous) = accepted_types
                .iter()
                .find(|previous| previous.id == declared.id)
            else {
                changes.push(ImportedResourceTypeChange {
                    id: declared.id.clone(),
                    broker_type: declared.broker_type.clone(),
                    change: Kind::Added,
                    outcome: Outcome::Applied,
                    details: Vec::new(),
                });
                target.push(declared.clone());
                continue;
            };
            if previous.broker_type != declared.broker_type {
                return Err(format!(
                    "resource type {} keeps its accepted Broker type ID {}",
                    declared.id, previous.broker_type
                ));
            }
            let comparison = compare(previous, declared);
            if comparison.details.is_empty() && !previous.removed {
                target.push(declared.clone());
                continue;
            }
            let outcome = if comparison.needs_value_free_type()
                && value_resources(usage, &previous.broker_type)
                    .next()
                    .is_some()
            {
                target.push(previous.clone());
                Outcome::NeedsNewId
            } else {
                target.push(declared.clone());
                Outcome::Applied
            };
            changes.push(ImportedResourceTypeChange {
                id: declared.id.clone(),
                broker_type: declared.broker_type.clone(),
                change: if previous.removed {
                    Kind::Restored
                } else {
                    Kind::Changed
                },
                outcome,
                details: comparison.details.into_iter().collect(),
            });
        }
        for previous in accepted_types {
            if proposed
                .resource_types
                .iter()
                .any(|declared| declared.id == previous.id)
            {
                continue;
            }
            let outcome = if has_resources(usage, &previous.broker_type) {
                target.push(ImportedResourceTypeDeclaration {
                    removed: true,
                    ..previous.clone()
                });
                Outcome::Retained
            } else {
                Outcome::Dropped
            };
            changes.push(ImportedResourceTypeChange {
                id: previous.id.clone(),
                broker_type: previous.broker_type.clone(),
                change: Kind::Removed,
                outcome,
                details: Vec::new(),
            });
        }
        Ok(Self {
            target: ImportedServiceMetadata {
                resource_types: target,
                ..proposed.clone()
            },
            changes,
        })
    }
}

/// The resource-dependent checks and effects of storing new metadata over
/// the accepted metadata. Derived from the two alone, so an acceptance
/// rechecks exactly what its preview decided.
#[derive(Debug, Clone, Default)]
pub struct ImportedTypeAcceptance {
    /// Types whose change applies only while none of their resources can
    /// hold attribute values.
    value_free: Vec<String>,
    /// Types whose stored exact values must match their new grammar.
    matching: Vec<(String, ResourcePattern)>,
    /// Removed attributes whose stored values are deleted, by type.
    deletions: Vec<(String, Vec<String>)>,
    /// Removed types the acceptance drops; they must have no resources.
    dropped: Vec<String>,
    /// Types being changed to disallow excluded memberships.
    exclusion_free: Vec<String>,
}

impl ImportedTypeAcceptance {
    /// The checks and effects of storing `next` over `previous`. Broker type
    /// IDs are fixed once accepted, and a new type may not take an ID the
    /// accepted metadata holds.
    pub fn plan(
        previous: Option<&ImportedServiceMetadata>,
        next: &ImportedServiceMetadata,
    ) -> Result<Self, String> {
        let previous_types = previous.map_or(&[][..], |previous| &previous.resource_types[..]);
        let mut plan = Self::default();
        for declared in &next.resource_types {
            let Some(accepted) = previous_types
                .iter()
                .find(|accepted| accepted.id == declared.id)
            else {
                if declared.removed {
                    return Err(format!(
                        "resource type {} is new and cannot be removed",
                        declared.id
                    ));
                }
                if previous_types
                    .iter()
                    .any(|accepted| accepted.broker_type == declared.broker_type)
                {
                    return Err(format!(
                        "resource type ID {} already belongs to another type of this import",
                        declared.broker_type
                    ));
                }
                continue;
            };
            if accepted.broker_type != declared.broker_type {
                return Err(format!(
                    "resource type {} keeps its accepted Broker type ID {}",
                    declared.id, accepted.broker_type
                ));
            }
            let comparison = compare(accepted, declared);
            if accepted.supports_exclusions && !declared.supports_exclusions {
                plan.exclusion_free.push(declared.broker_type.clone());
            }
            if comparison.needs_value_free_type() {
                plan.value_free.push(declared.broker_type.clone());
            }
            if comparison.checks_values() {
                plan.matching.push((
                    declared.broker_type.clone(),
                    ResourcePattern::new(declared.pattern.clone(), declared.max_length as usize)?,
                ));
            }
            if !comparison.removed_attributes.is_empty() {
                plan.deletions
                    .push((declared.broker_type.clone(), comparison.removed_attributes));
            }
        }
        for accepted in previous_types {
            if !next
                .resource_types
                .iter()
                .any(|declared| declared.id == accepted.id)
            {
                plan.dropped.push(accepted.broker_type.clone());
            }
        }
        Ok(plan)
    }

    /// Every Broker type ID whose stored resources the acceptance reads.
    pub fn resource_types(&self) -> BTreeSet<&str> {
        self.value_free
            .iter()
            .chain(self.matching.iter().map(|(broker_type, _)| broker_type))
            .chain(self.deletions.iter().map(|(broker_type, _)| broker_type))
            .chain(&self.dropped)
            .chain(&self.exclusion_free)
            .map(String::as_str)
            .collect()
    }

    /// The stored resources that prevent the acceptance, by type: resources
    /// that can hold attribute values of a type whose change needs none, any
    /// resource of a dropped type, and exact resources whose values no longer
    /// match a changed grammar.
    pub fn violations(&self, usage: &ImportedTypeUsage) -> BTreeMap<String, Vec<String>> {
        let mut violations = BTreeMap::<String, BTreeSet<String>>::new();
        for broker_type in &self.value_free {
            for resource in value_resources(usage, broker_type) {
                violations
                    .entry(broker_type.clone())
                    .or_default()
                    .insert(resource.id.clone());
            }
        }
        for broker_type in &self.dropped {
            for resource in usage.get(broker_type).into_iter().flatten() {
                violations
                    .entry(broker_type.clone())
                    .or_default()
                    .insert(resource.id.clone());
            }
        }
        for (broker_type, pattern) in &self.matching {
            for resource in usage.get(broker_type).into_iter().flatten() {
                if let ResourceSelector::Exact { value } = &resource.selector
                    && !pattern.is_match(value)
                {
                    violations
                        .entry(broker_type.clone())
                        .or_default()
                        .insert(resource.id.clone());
                }
            }
        }
        violations
            .into_iter()
            .map(|(broker_type, ids)| (broker_type, ids.into_iter().collect()))
            .collect()
    }

    /// All excluded memberships blocking a downgrade, grouped by type and group.
    /// Keep this separate from resource grammar/attribute violations: the remedy
    /// is to edit group memberships, not to delete otherwise valid resources.
    pub fn group_violations(
        &self,
        usage: &ImportedTypeUsage,
    ) -> BTreeMap<String, Vec<ImportedTypeBlockingGroup>> {
        let mut violations = BTreeMap::new();
        for broker_type in &self.exclusion_free {
            let mut groups = BTreeMap::<String, BTreeSet<String>>::new();
            for resource in usage.get(broker_type).into_iter().flatten() {
                for group in &resource.excluded_by {
                    groups
                        .entry(group.clone())
                        .or_default()
                        .insert(resource.id.clone());
                }
            }
            if !groups.is_empty() {
                violations.insert(
                    broker_type.clone(),
                    groups
                        .into_iter()
                        .map(|(id, resources)| ImportedTypeBlockingGroup {
                            id,
                            resource_ids: resources.into_iter().collect(),
                        })
                        .collect(),
                );
            }
        }
        violations
    }

    /// Removed attributes whose stored values the acceptance deletes, by
    /// type.
    pub fn deletions(&self) -> &[(String, Vec<String>)] {
        &self.deletions
    }

    /// Removed types the acceptance drops.
    pub fn dropped(&self) -> &[String] {
        &self.dropped
    }
}

/// The most resource IDs one rejection or preview list names per type.
pub const IMPORT_TYPE_RESOURCE_SAMPLE: usize = 100;

/// The rejection of an acceptance whose type changes no longer apply,
/// naming the resources that prevent them.
pub fn describe_type_violations(violations: &BTreeMap<String, Vec<String>>) -> String {
    const NAMED: usize = 20;
    let types = violations
        .iter()
        .map(|(broker_type, ids)| {
            let mut named = ids
                .iter()
                .take(NAMED)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if ids.len() > NAMED {
                named.push_str(&format!(" and {} more", ids.len() - NAMED));
            }
            format!("{broker_type}: {named}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "resource type changes no longer apply to stored resources; edit or delete them, or refresh the preview ({types})"
    )
}

#[cfg(test)]
#[path = "type_changes_tests.rs"]
mod tests;
