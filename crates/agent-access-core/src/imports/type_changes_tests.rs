use super::*;
use crate::imports::{
    ImportedCredentialDeclaration, ImportedCredentialKind, ImportedCredentialMode,
    ImportedResourceAttributeDeclaration,
};
use serde_json::json;

use ImportedResourceTypeChangeDetail as Detail;
use ImportedResourceTypeChangeKind as Kind;
use ImportedResourceTypeOutcome as Outcome;

fn attribute(
    name: &str,
    required: bool,
    pattern: Option<&str>,
) -> ImportedResourceAttributeDeclaration {
    ImportedResourceAttributeDeclaration {
        name: name.into(),
        label: name.into(),
        description: format!("The {name}."),
        required,
        pattern: pattern.map(str::to_owned),
    }
}

fn project() -> ImportedResourceTypeDeclaration {
    ImportedResourceTypeDeclaration {
        id: "project".into(),
        broker_type: "ticketing_project".into(),
        removed: false,
        supports_exclusions: true,
        label: "Project".into(),
        plural_label: "Projects".into(),
        pattern: "[A-Z][A-Z0-9]{1,9}".into(),
        max_length: 256,
        example: "OPS".into(),
        attributes: vec![
            attribute("region", false, Some("[a-z0-9-]{1,32}")),
            attribute("webhookSecret", false, None),
        ],
    }
}

fn queue() -> ImportedResourceTypeDeclaration {
    ImportedResourceTypeDeclaration {
        id: "queue".into(),
        broker_type: "ticketing_queue".into(),
        removed: false,
        supports_exclusions: true,
        label: "Queue".into(),
        plural_label: "Queues".into(),
        pattern: "[a-z]+".into(),
        max_length: 64,
        example: "triage".into(),
        attributes: Vec::new(),
    }
}

fn metadata(types: Vec<ImportedResourceTypeDeclaration>) -> ImportedServiceMetadata {
    ImportedServiceMetadata {
        format: "agent-access-command/1".into(),
        version: "1.0.0".into(),
        credential: Some(ImportedCredentialDeclaration {
            kind: ImportedCredentialKind::Token,
            modes: vec![ImportedCredentialMode::Service],
        }),
        verify: false,
        resource_types: types,
    }
}

fn exact(id: &str, value: &str, attributes: &[&str]) -> ImportedTypeResource {
    ImportedTypeResource {
        id: id.into(),
        selector: ResourceSelector::Exact {
            value: value.into(),
        },
        excluded_by: BTreeSet::new(),
        attributes: attributes.iter().map(|name| (*name).to_owned()).collect(),
    }
}

fn usage(entries: &[(&str, Vec<ImportedTypeResource>)]) -> ImportedTypeUsage {
    entries
        .iter()
        .map(|(broker_type, resources)| ((*broker_type).to_owned(), resources.clone()))
        .collect()
}

fn details(
    previous: &ImportedResourceTypeDeclaration,
    next: &ImportedResourceTypeDeclaration,
) -> Vec<Detail> {
    compare(previous, next).details.into_iter().collect()
}

#[test]
fn resource_type_comparisons_classify_every_difference() {
    let base = project();
    assert!(details(&base, &base).is_empty());
    let mut next = base.clone();
    next.removed = true;
    next.broker_type = "other".into();
    assert!(
        details(&base, &next).is_empty(),
        "identity and marker are not compared"
    );
    type Mutation = fn(&mut ImportedResourceTypeDeclaration);
    let cases: Vec<(Mutation, Vec<Detail>)> = vec![
        (|t| t.label = "Space".into(), vec![Detail::Label]),
        (
            |t| t.plural_label = "Spaces".into(),
            vec![Detail::PluralLabel],
        ),
        (|t| t.example = "ENG".into(), vec![Detail::Example]),
        (|t| t.pattern = "[A-Z]+".into(), vec![Detail::Pattern]),
        (|t| t.max_length = 12, vec![Detail::MaxLength]),
        (
            |t| t.attributes.push(attribute("owner", false, Some("[a-z]+"))),
            vec![Detail::AttributeAdded],
        ),
        (
            |t| t.attributes.push(attribute("owner", true, None)),
            vec![Detail::AttributeAddedRequired],
        ),
        (
            |t| t.attributes[0].required = true,
            vec![Detail::AttributeMadeRequired],
        ),
        (
            |t| t.attributes[0].pattern = Some("[a-z]+".into()),
            vec![Detail::AttributePattern],
        ),
        (
            |t| t.attributes[0].pattern = None,
            vec![Detail::AttributePattern],
        ),
        (
            |t| t.attributes[1].description = "Rotated monthly.".into(),
            vec![Detail::AttributeText],
        ),
        (
            |t| t.attributes[1].label = "Secret".into(),
            vec![Detail::AttributeText],
        ),
        (|t| t.attributes.reverse(), vec![Detail::AttributeOrder]),
        (
            |t| {
                t.attributes.remove(1);
            },
            vec![Detail::AttributeRemoved],
        ),
    ];
    for (mutate, expected) in cases {
        let mut next = base.clone();
        mutate(&mut next);
        assert_eq!(details(&base, &next), expected, "{next:?}");
    }
    let mut required = base.clone();
    required.attributes[0].required = true;
    assert_eq!(details(&required, &base), [Detail::AttributeMadeOptional]);
    let mut next = base.clone();
    next.attributes.remove(0);
    assert_eq!(compare(&base, &next).removed_attributes, ["region"]);
    for detail in [
        Detail::AttributeAddedRequired,
        Detail::AttributeMadeRequired,
        Detail::AttributePattern,
    ] {
        assert!(detail.needs_value_free_type());
        assert!(!detail.checks_values());
    }
    for detail in [Detail::Pattern, Detail::MaxLength] {
        assert!(detail.checks_values());
        assert!(!detail.needs_value_free_type());
    }
}

#[test]
fn resource_type_previews_apply_safe_changes_and_keep_types_their_resources_need() {
    let accepted = metadata(vec![project(), queue()]);
    // Unchanged types are not listed and stay as accepted.
    let preview = ImportedTypePreview::plan(Some(&accepted), &accepted, &usage(&[])).unwrap();
    assert!(preview.changes.is_empty());
    assert_eq!(preview.target, accepted);

    // A new required attribute applies to an unused type ...
    let mut declared = project();
    declared.attributes.push(attribute("owner", true, None));
    let mut proposed = metadata(vec![declared.clone()]);
    proposed.version = "2.0.0".into();
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &usage(&[])).unwrap();
    assert_eq!(preview.target.version, "2.0.0");
    assert_eq!(preview.target.resource_types, [declared.clone()]);
    assert_eq!(
        preview.changes,
        [
            ImportedResourceTypeChange {
                id: "project".into(),
                broker_type: "ticketing_project".into(),
                change: Kind::Changed,
                outcome: Outcome::Applied,
                details: vec![Detail::AttributeAddedRequired],
            },
            ImportedResourceTypeChange {
                id: "queue".into(),
                broker_type: "ticketing_queue".into(),
                change: Kind::Removed,
                outcome: Outcome::Dropped,
                details: Vec::new(),
            },
        ]
    );
    assert!(preview.needs_new_id().is_empty());

    // ... but needs a new type id while the type has resources, and a
    // removed type with resources is retained.
    let stored = usage(&[
        ("ticketing_project", vec![exact("ops", "OPS", &["region"])]),
        ("ticketing_queue", vec![exact("triage", "triage", &[])]),
    ]);
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &stored).unwrap();
    let mut retained = queue();
    retained.removed = true;
    assert_eq!(preview.target.resource_types, [project(), retained.clone()]);
    assert_eq!(preview.changes[0].outcome, Outcome::NeedsNewId);
    assert_eq!(preview.changes[1].outcome, Outcome::Retained);
    assert_eq!(preview.needs_new_id(), BTreeSet::from(["project"]));

    // A pattern change applies; its stored values are checked at acceptance.
    let mut declared = project();
    declared.pattern = "[A-Z]{3}".into();
    let preview = ImportedTypePreview::plan(
        Some(&accepted),
        &metadata(vec![declared.clone(), queue()]),
        &stored,
    )
    .unwrap();
    assert_eq!(preview.changes[0].outcome, Outcome::Applied);
    assert_eq!(preview.changes[0].details, [Detail::Pattern]);
    assert_eq!(preview.target.resource_types[0], declared);

    // A retained type declared again is restored; a type still unused is
    // dropped; new types are added.
    let restored_accepted = metadata(vec![project(), retained]);
    let preview = ImportedTypePreview::plan(
        Some(&restored_accepted),
        &metadata(vec![project(), queue()]),
        &usage(&[]),
    )
    .unwrap();
    assert_eq!(preview.target.resource_types, [project(), queue()]);
    assert_eq!(preview.changes.len(), 1);
    assert_eq!(preview.changes[0].change, Kind::Restored);
    assert_eq!(preview.changes[0].outcome, Outcome::Applied);
    let preview = ImportedTypePreview::plan(None, &accepted, &usage(&[])).unwrap();
    assert_eq!(
        preview
            .changes
            .iter()
            .map(|change| (change.change, change.outcome))
            .collect::<Vec<_>>(),
        [
            (Kind::Added, Outcome::Applied),
            (Kind::Added, Outcome::Applied)
        ]
    );

    // Accepted Broker type IDs are fixed, and declarations are never removed.
    let mut renamed = project();
    renamed.broker_type = "tickets".into();
    assert!(
        ImportedTypePreview::plan(Some(&accepted), &metadata(vec![renamed]), &usage(&[])).is_err()
    );
    let mut removed = project();
    removed.removed = true;
    assert!(ImportedTypePreview::plan(None, &metadata(vec![removed]), &usage(&[])).is_err());
}

#[test]
fn resource_type_acceptances_recheck_the_resources_each_change_depends_on() {
    let accepted = metadata(vec![project(), queue()]);
    let mut declared = project();
    declared.attributes.remove(1);
    declared.attributes[0].required = true;
    declared.max_length = 3;
    let next = metadata(vec![declared]);
    let plan = ImportedTypeAcceptance::plan(Some(&accepted), &next).unwrap();
    assert_eq!(
        plan.resource_types(),
        BTreeSet::from(["ticketing_project", "ticketing_queue"])
    );
    assert_eq!(
        plan.deletions(),
        [(
            "ticketing_project".to_owned(),
            vec!["webhookSecret".to_owned()]
        )]
    );
    assert_eq!(plan.dropped(), ["ticketing_queue"]);
    assert!(plan.violations(&usage(&[])).is_empty());
    let stored = usage(&[
        (
            "ticketing_project",
            vec![
                exact("ops", "OPS", &["region"]),
                exact("legacy", "LEGACY", &[]),
                ImportedTypeResource {
                    id: "all-projects".into(),
                    selector: ResourceSelector::All,
                    attributes: BTreeSet::new(),
                    excluded_by: BTreeSet::new(),
                },
            ],
        ),
        ("ticketing_queue", vec![exact("triage", "triage", &[])]),
    ]);
    assert_eq!(
        plan.violations(&stored),
        BTreeMap::from([
            (
                "ticketing_project".to_owned(),
                vec!["legacy".to_owned(), "ops".to_owned()]
            ),
            ("ticketing_queue".to_owned(), vec!["triage".to_owned()]),
        ])
    );

    // A grammar change alone checks exact values only.
    let mut declared = project();
    declared.max_length = 3;
    let plan =
        ImportedTypeAcceptance::plan(Some(&accepted), &metadata(vec![declared, queue()])).unwrap();
    assert_eq!(
        plan.violations(&stored),
        BTreeMap::from([("ticketing_project".to_owned(), vec!["legacy".to_owned()])])
    );
    assert!(plan.deletions().is_empty() && plan.dropped().is_empty());

    // Retaining or restoring a type and keeping an accepted declaration
    // check nothing.
    let mut retained = queue();
    retained.removed = true;
    let plan = ImportedTypeAcceptance::plan(
        Some(&accepted),
        &metadata(vec![project(), retained.clone()]),
    )
    .unwrap();
    assert!(plan.resource_types().is_empty());
    let plan = ImportedTypeAcceptance::plan(Some(&metadata(vec![project(), retained])), &accepted)
        .unwrap();
    assert!(plan.resource_types().is_empty());
    let plan = ImportedTypeAcceptance::plan(None, &accepted).unwrap();
    assert!(plan.resource_types().is_empty());

    // Broker type IDs stay fixed and unique within the import.
    let mut renamed = project();
    renamed.broker_type = "tickets".into();
    assert!(ImportedTypeAcceptance::plan(Some(&accepted), &metadata(vec![renamed])).is_err());
    let mut taken = queue();
    taken.id = "board".into();
    assert!(
        ImportedTypeAcceptance::plan(Some(&accepted), &metadata(vec![project(), taken]))
            .unwrap_err()
            .contains("already belongs")
    );
    let mut removed = queue();
    removed.id = "board".into();
    removed.broker_type = "ticketing_board".into();
    removed.removed = true;
    assert!(ImportedTypeAcceptance::plan(Some(&accepted), &metadata(vec![removed])).is_err());
}

#[test]
fn resource_type_violations_name_bounded_resource_lists() {
    let violations = BTreeMap::from([
        (
            "ticketing_project".to_owned(),
            (0..25).map(|n| format!("p{n:02}")).collect::<Vec<_>>(),
        ),
        ("ticketing_queue".to_owned(), vec!["triage".to_owned()]),
    ]);
    let message = describe_type_violations(&violations);
    assert!(message.contains("ticketing_project: p00, p01"), "{message}");
    assert!(
        message.contains("p19 and 5 more; ticketing_queue: triage"),
        "{message}"
    );
    assert!(!message.contains("p20"), "{message}");
}

#[test]
fn accepted_resource_type_declarations_build_registry_descriptors() {
    let descriptor = imported_type_descriptor(&project()).unwrap();
    assert_eq!(descriptor.id().as_str(), "ticketing_project");
    assert_eq!(descriptor.label(), "Project");
    assert!(descriptor.is_canonical_target("OPS"));
    assert!(!descriptor.is_canonical_target("ops"));
    assert_eq!(descriptor.attributes().len(), 2);
    assert!(descriptor.attributes()[0].is_valid("eu-1"));
    assert!(!descriptor.attributes()[0].is_valid("EU 1"));
    assert!(descriptor.attributes()[1].is_valid("any secret"));
    let mut invalid = project();
    invalid.pattern = "x)|(?s:.*".into();
    assert!(imported_type_descriptor(&invalid).is_err());
    let mut invalid = project();
    invalid.broker_type = "Ticketing".into();
    assert!(imported_type_descriptor(&invalid).is_err());
}

#[test]
fn command_actions_name_their_declared_resource_type() {
    let mut action = ImportedActionDefinition {
        download: false,
        action: "issue_view".into(),
        source: json!({"name": "issue.view"}),
        label: None,
        description: String::new(),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: json!({"command": {"resources": {"type": "project", "inputs": ["/project"]}}}),
        read_only: true,
    };
    assert_eq!(command_action_resource_type(&action), Some("project"));
    action.annotations = json!({"command": {}});
    assert_eq!(command_action_resource_type(&action), None);
}

fn all_selector(id: &str) -> ImportedTypeResource {
    ImportedTypeResource {
        id: id.into(),
        selector: ResourceSelector::All,
        attributes: BTreeSet::new(),
        excluded_by: BTreeSet::new(),
    }
}

#[test]
fn resource_type_attribute_rules_ignore_all_selector_resources() {
    let accepted = metadata(vec![project(), queue()]);
    let mut declared = project();
    declared.attributes.push(attribute("owner", true, None));
    declared.attributes[0].required = true;
    declared.attributes[1].pattern = Some("[a-z]+".into());
    let proposed = metadata(vec![declared.clone()]);
    // `all` resources carry no attribute values, so the attribute rules apply
    // in place; they still keep a removed type.
    let only_all = usage(&[
        ("ticketing_project", vec![all_selector("all-projects")]),
        ("ticketing_queue", vec![all_selector("all-queues")]),
    ]);
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &only_all).unwrap();
    assert_eq!(preview.changes[0].outcome, Outcome::Applied);
    assert_eq!(preview.changes[1].outcome, Outcome::Retained);
    assert_eq!(preview.target.resource_types[0], declared);
    let plan = ImportedTypeAcceptance::plan(Some(&accepted), &preview.target).unwrap();
    assert!(plan.violations(&only_all).is_empty());
    // An exact resource still needs a new type id, and a dropped type still
    // counts every resource.
    let with_exact = usage(&[(
        "ticketing_project",
        vec![all_selector("all-projects"), exact("ops", "OPS", &[])],
    )]);
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &with_exact).unwrap();
    assert_eq!(preview.changes[0].outcome, Outcome::NeedsNewId);
    let plan = ImportedTypeAcceptance::plan(Some(&accepted), &proposed).unwrap();
    assert_eq!(
        plan.violations(&with_exact),
        BTreeMap::from([("ticketing_project".to_owned(), vec!["ops".to_owned()])])
    );
    assert_eq!(
        plan.violations(&only_all),
        BTreeMap::from([("ticketing_queue".to_owned(), vec!["all-queues".to_owned()])])
    );
}

#[test]
fn resource_type_previews_of_full_commands_keep_retained_types_within_bounds() {
    let declared = |id: String| ImportedResourceTypeDeclaration {
        broker_type: format!("ticketing_{id}"),
        id,
        ..queue()
    };
    let ids = (1..=16).map(|n| format!("t{n:02}")).collect::<Vec<_>>();
    let accepted = metadata(ids.iter().cloned().map(declared).collect());
    accepted.validate().unwrap();
    let mut renamed = ids.clone();
    renamed[0] = "t17".into();
    let proposed = metadata(renamed.into_iter().map(declared).collect());
    let stored = usage(&[("ticketing_t01", vec![exact("kept", "kept", &[])])]);
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &stored).unwrap();
    assert_eq!(preview.target.resource_types.len(), 17);
    preview.target.validate().unwrap();
}

#[test]
fn exclusion_capability_changes_check_group_memberships_without_changing_retention() {
    let accepted = metadata(vec![project(), queue()]);
    let mut next = project();
    next.supports_exclusions = false;
    assert_eq!(
        details(&project(), &next),
        vec![Detail::ExclusionsUnsupported]
    );
    assert_eq!(
        details(&next, &project()),
        vec![Detail::ExclusionsSupported]
    );
    assert!(
        !imported_type_descriptor(&next)
            .unwrap()
            .supports_exclusions()
    );
    let mut exact = exact("ops", "OPS", &[]);
    exact.excluded_by = BTreeSet::from(["unused".into(), "mixed".into()]);
    let mut all = all_selector("all");
    all.excluded_by = BTreeSet::from(["mixed".into()]);
    let stored = usage(&[("ticketing_project", vec![exact, all])]);
    let proposed = metadata(vec![next.clone(), queue()]);
    let preview = ImportedTypePreview::plan(Some(&accepted), &proposed, &stored).unwrap();
    assert_eq!(preview.changes[0].outcome, Outcome::Applied);
    let plan = ImportedTypeAcceptance::plan(Some(&accepted), &preview.target).unwrap();
    assert!(plan.violations(&stored).is_empty());
    assert_eq!(
        plan.group_violations(&stored)["ticketing_project"],
        vec![
            ImportedTypeBlockingGroup {
                id: "mixed".into(),
                resource_ids: vec!["all".into(), "ops".into()]
            },
            ImportedTypeBlockingGroup {
                id: "unused".into(),
                resource_ids: vec!["ops".into()]
            },
        ]
    );
    // The same preview can be accepted once the memberships are removed.
    assert!(plan.group_violations(&usage(&[])).is_empty());
    // Upgrades do not block on memberships.
    assert!(
        ImportedTypeAcceptance::plan(Some(&proposed), &accepted)
            .unwrap()
            .group_violations(&stored)
            .is_empty()
    );
    // A simultaneous incompatible attribute change keeps the whole old type.
    next.attributes[0].required = true;
    let combined =
        ImportedTypePreview::plan(Some(&accepted), &metadata(vec![next, queue()]), &stored)
            .unwrap();
    assert_eq!(combined.changes[0].outcome, Outcome::NeedsNewId);
    assert!(
        combined.changes[0]
            .details
            .contains(&Detail::ExclusionsUnsupported)
    );
    assert_eq!(combined.target, accepted);
    assert!(
        ImportedTypeAcceptance::plan(Some(&accepted), &combined.target)
            .unwrap()
            .group_violations(&stored)
            .is_empty()
    );
    // Removing a type retains its capability while resources remain.
    let removed =
        ImportedTypePreview::plan(Some(&proposed), &metadata(vec![queue()]), &stored).unwrap();
    let retained = removed
        .target
        .resource_types
        .iter()
        .find(|t| t.id == "project")
        .unwrap();
    assert!(retained.removed);
    assert!(!retained.supports_exclusions);
    let dropped =
        ImportedTypePreview::plan(Some(&removed.target), &metadata(vec![queue()]), &usage(&[]))
            .unwrap();
    assert!(
        dropped
            .target
            .resource_types
            .iter()
            .all(|t| t.id != "project")
    );
    // Restoring a formerly removed, exclusion-capable type still checks downgrades.
    let mut retired = project();
    retired.removed = true;
    let retired_metadata = metadata(vec![retired, queue()]);
    assert!(retired_metadata.resource_types[0].removed);
    assert!(retired_metadata.resource_types[0].supports_exclusions);
    let restored = ImportedTypePreview::plan(Some(&retired_metadata), &proposed, &stored).unwrap();
    assert_eq!(restored.changes[0].change, Kind::Restored);
    assert!(
        !ImportedTypeAcceptance::plan(Some(&retired_metadata), &restored.target)
            .unwrap()
            .group_violations(&stored)
            .is_empty()
    );
}
