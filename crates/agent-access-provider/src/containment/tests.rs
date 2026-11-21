use super::*;
use crate::{
    LocationNormalizationError, ResourceTypeDescriptor, ScalarResourceSelector, ScopeResolution,
    SubtreeSelectorDescriptor,
};

const ORIGIN: &str = "https://docs.example.test";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn content_type() -> ResourceType {
    ResourceType::from_static("content_item")
}
fn area_type() -> ResourceType {
    ResourceType::from_static("work_area")
}
fn canonical(value: &str) -> bool {
    project_value(value).is_ok()
}
fn area(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}
fn exact(value: &str) -> bool {
    project_value(value).is_ok_and(|p| matches!(p.root_kind.as_str(), "document" | "journal"))
}
fn subtree(value: &str) -> bool {
    project_value(value).is_ok_and(|p| matches!(p.root_kind.as_str(), "document" | "directory"))
}
fn project_value(value: &str) -> Result<ResourceSelectorProjection, LocationNormalizationError> {
    let invalid =
        || LocationNormalizationError::new("selector", "invalid synthetic canonical locator");
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    let parts: Vec<_> = url.path().split('/').collect();
    if parts.len() != 4
        || parts[1] != "content"
        || !matches!(parts[2], "document" | "directory" | "journal")
        || parts[3].is_empty()
        || !parts[3].bytes().all(|byte| byte.is_ascii_digit())
        || parts[3].starts_with('0')
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(invalid());
    }
    Ok(ResourceSelectorProjection::new(
        url.origin().ascii_serialization(),
        parts[2],
    ))
}
fn project(
    selector: &ResourceSelector,
) -> Result<ResourceSelectorProjection, LocationNormalizationError> {
    project_value(
        selector.value().ok_or_else(|| {
            LocationNormalizationError::new("selector", "missing synthetic value")
        })?,
    )
}
static AREA: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("work_area"),
    "Area",
    "Areas",
    "ENG",
    area,
    &[],
);
static CONTENT: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("content_item"),
    "Content",
    "Content",
    "https://docs.example.test/content/document/1",
    canonical,
    &[],
)
.with_supports_all(false)
.with_exact_validator(exact)
.with_subtree(SubtreeSelectorDescriptor::new(
    subtree,
    "This content and descendants",
    "Content",
    "https://docs.example.test/content/directory/10",
))
.with_selector_projection(project);
fn registry() -> ResourceTypeRegistry {
    ResourceTypeRegistry::new([&AREA, &CONTENT]).unwrap()
}
fn contract(effects: Vec<ContainmentEffect>) -> ContainmentScopeCapabilities {
    ContainmentScopeCapabilities::new(
        "documents",
        BTreeMap::from([
            (area_type(), vec!["exact".into(), "all".into()]),
            (content_type(), vec!["exact".into(), "subtree".into()]),
        ]),
        vec![area_type()],
        vec!["document".into()],
        vec!["document".into(), "directory".into()],
        effects,
    )
}
fn identity(kind: &str, id: u64) -> ContainmentIdentity {
    identity_in(ORIGIN, kind, id)
}
fn identity_in(origin: &str, kind: &str, id: u64) -> ContainmentIdentity {
    ContainmentIdentity::new(
        content_type(),
        kind,
        format!("{origin}/content/{kind}/{id}"),
    )
}
fn location(kind: &str, id: u64, ancestors: Vec<ContainmentIdentity>) -> ContentLocation {
    ContentLocation::new(
        identity(kind, id),
        vec![ResourceContainer::new(area_type(), "ENG")],
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .with_ancestors(
        ancestors
            .into_iter()
            .map(|identity| {
                ContainmentAncestor::new(identity, vec![ResourceContainer::new(area_type(), "ENG")])
            })
            .collect(),
    )
}
fn point(location: ContentLocation) -> ContainmentEvidence {
    ContainmentEvidence::new(
        "documents",
        ORIGIN,
        vec![ContainmentObligation::Content(location)],
    )
}
fn typed(selector: ResourceSelector) -> TypedResourceSelector {
    registry()
        .typed_selector(&content_type(), &selector)
        .unwrap()
}
fn exact_id(kind: &str, id: u64) -> TypedResourceSelector {
    typed(ResourceSelector::Exact {
        value: identity(kind, id).value,
    })
}
fn subtree_id(kind: &str, id: u64) -> TypedResourceSelector {
    typed(ResourceSelector::Subtree {
        value: identity(kind, id).value,
    })
}
fn space(key: &str) -> TypedResourceSelector {
    registry()
        .typed_selector(&area_type(), &ResourceSelector::Exact { value: key.into() })
        .unwrap()
}
fn all() -> TypedResourceSelector {
    registry()
        .typed_selector(&area_type(), &ResourceSelector::All)
        .unwrap()
}
fn boundary(
    positive: Vec<TypedResourceSelector>,
    negative: Vec<TypedResourceSelector>,
) -> ContainmentBoundary {
    ContainmentBoundary::new(positive, negative)
}
fn move_evidence() -> ContainmentEvidence {
    let current = location(
        "document",
        30,
        vec![identity("document", 9), identity("directory", 10)],
    );
    let destination = location("document", 40, vec![identity("directory", 20)]);
    let proposed = location(
        "document",
        30,
        vec![identity("document", 40), identity("directory", 20)],
    )
    .with_provenance(ContainmentProvenance::Proposed);
    ContainmentEvidence::new(
        "documents",
        ORIGIN,
        vec![
            ContainmentObligation::SubtreeImpact { current, proposed },
            ContainmentObligation::ChildPlacement(destination.clone()),
            ContainmentObligation::Content(destination),
        ],
    )
}
fn move_contract() -> ContainmentScopeCapabilities {
    contract(vec![
        ContainmentEffect::SubtreeImpact,
        ContainmentEffect::ChildPlacement,
        ContainmentEffect::Content,
    ])
}

#[test]
fn stored_subtrees_cannot_enter_scalar_matching_or_search_in_either_polarity() {
    let subtree = ResourceSelector::Subtree {
        value: identity("directory", 10).value,
    };
    assert!(ScalarResourceSelector::try_from(&subtree).is_err());
    assert!(ScalarResourceSelector::try_from(subtree.clone()).is_err());
    let encoded = serde_json::to_value(&subtree).unwrap();
    assert_eq!(
        serde_json::from_value::<ResourceSelector>(encoded.clone()).unwrap(),
        subtree
    );
    assert!(serde_json::from_value::<ScalarResourceSelector>(encoded.clone()).is_err());
    for clause in [
        serde_json::json!({"included":[encoded],"excluded":[]}),
        serde_json::json!({"included":[{"kind":"all"}],"excluded":[encoded]}),
    ] {
        assert!(serde_json::from_value::<crate::SearchAuthorizationClause>(clause).is_err());
    }
    for stored in [
        ResourceSelector::Exact {
            value: "ENG".into(),
        },
        ResourceSelector::Namespace {
            value: "engineering".into(),
        },
        ResourceSelector::All,
    ] {
        let scalar = ScalarResourceSelector::try_from(&stored).unwrap();
        assert_eq!(
            serde_json::to_value(&scalar).unwrap(),
            serde_json::to_value(&stored).unwrap()
        );
        assert_eq!(ResourceSelector::from(scalar), stored);
    }
}

#[test]
fn per_kind_grammars_are_distinct_and_targets_do_not_become_exact_selectors() {
    let registry = registry();
    assert_eq!(CONTENT.selector_kinds(), ["exact", "subtree"]);
    assert!(
        registry
            .typed_selector(
                &content_type(),
                &ResourceSelector::Exact {
                    value: identity("directory", 10).value
                }
            )
            .is_err()
    );
    assert!(
        registry
            .typed_selector(
                &content_type(),
                &ResourceSelector::Subtree {
                    value: identity("journal", 11).value
                }
            )
            .is_err()
    );
    assert!(
        registry
            .typed_selector(&content_type(), &ResourceSelector::All)
            .is_err()
    );
    assert_eq!(
        CONTENT
            .project_target(&identity("directory", 10).value)
            .unwrap()
            .unwrap()
            .root_kind,
        "directory"
    );
    assert_eq!(
        CONTENT.metadata().subtree.unwrap().label,
        "This content and descendants"
    );
}

#[test]
fn exact_subtree_and_cross_type_exclusions_match_current_facts() {
    let target = point(location(
        "document",
        31,
        vec![identity("document", 30), identity("directory", 10)],
    ));
    target
        .validate(
            &contract(vec![ContainmentEffect::Content]),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    assert!(
        boundary(vec![subtree_id("directory", 10)], vec![])
            .matches_evidence(&target)
            .unwrap()
    );
    assert!(
        !boundary(vec![exact_id("document", 30)], vec![])
            .matches_evidence(&target)
            .unwrap()
    );
    assert!(
        !boundary(
            vec![space("ENG"), exact_id("document", 31)],
            vec![subtree_id("directory", 10)]
        )
        .matches_evidence(&target)
        .unwrap()
    );
    assert!(
        boundary(vec![space("ENG")], vec![exact_id("document", 30)])
            .matches_evidence(&target)
            .unwrap()
    );
    assert!(
        !boundary(vec![space("OPS")], vec![])
            .matches_evidence(&target)
            .unwrap()
    );
    let other_site = typed(ResourceSelector::Subtree {
        value: identity_in("https://other.example.test", "directory", 10).value,
    });
    assert!(
        boundary(vec![space("ENG")], vec![other_site])
            .matches_evidence(&target)
            .unwrap()
    );
}

#[test]
fn child_slot_is_not_the_parent_content_point_in_either_polarity() {
    let parent = location("document", 30, vec![identity("directory", 10)]);
    let evidence = ContainmentEvidence::new(
        "documents",
        ORIGIN,
        vec![ContainmentObligation::ChildPlacement(parent)],
    );
    evidence
        .validate(
            &contract(vec![ContainmentEffect::ChildPlacement]),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    assert!(
        !boundary(vec![exact_id("document", 30)], vec![])
            .matches_evidence(&evidence)
            .unwrap()
    );
    assert!(
        boundary(
            vec![subtree_id("document", 30)],
            vec![exact_id("document", 30)]
        )
        .matches_evidence(&evidence)
        .unwrap()
    );
    assert!(
        !boundary(vec![space("ENG")], vec![subtree_id("document", 30)])
            .matches_evidence(&evidence)
            .unwrap()
    );
}

#[test]
fn move_requires_complete_region_before_and_after_in_one_boundary() {
    let evidence = move_evidence();
    evidence
        .validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    let source = boundary(vec![subtree_id("directory", 10)], vec![]);
    let destination = boundary(vec![subtree_id("directory", 20)], vec![]);
    assert!(!source.matches_evidence(&evidence).unwrap());
    assert!(!destination.matches_evidence(&evidence).unwrap());
    assert!(
        boundary(
            vec![subtree_id("directory", 10), subtree_id("directory", 20)],
            vec![]
        )
        .matches_evidence(&evidence)
        .unwrap()
    );
    assert!(
        !boundary(
            vec![exact_id("document", 30), exact_id("document", 40)],
            vec![]
        )
        .matches_evidence(&evidence)
        .unwrap()
    );
    assert!(
        boundary(vec![space("ENG")], vec![exact_id("document", 9)])
            .matches_evidence(&evidence)
            .unwrap()
    );
}

#[test]
fn hidden_descendant_exclusion_and_unresolved_root_never_disappear() {
    let excluded = exact_id("document", 31);
    let selected = boundary(vec![space("ENG")], vec![excluded]);
    assert_eq!(
        selected.matches_evidence(&move_evidence()),
        Err(ContainmentError::UnresolvedRelation)
    );
    let hidden = location(
        "document",
        31,
        vec![
            identity("document", 30),
            identity("document", 9),
            identity("directory", 10),
        ],
    );
    let evidence = move_evidence().with_related_roots(vec![hidden]);
    evidence
        .validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    assert!(!selected.matches_evidence(&evidence).unwrap());
    let unrelated = location("document", 31, vec![identity("directory", 99)]);
    let disjoint = move_evidence().with_related_roots(vec![unrelated]);
    assert!(selected.matches_evidence(&disjoint).unwrap());
    assert!(
        !boundary(vec![space("ENG")], vec![subtree_id("directory", 20)])
            .matches_evidence(&move_evidence())
            .unwrap()
    );
}

#[test]
fn region_transform_and_provenance_are_structurally_checked() {
    let mut evidence = move_evidence();
    if let ContainmentObligation::SubtreeImpact { proposed, .. } = &mut evidence.obligations[0] {
        proposed.ancestors = vec![ContainmentAncestor::new(
            identity("directory", 99),
            proposed.containers.clone(),
        )];
    }
    assert_eq!(
        evidence.validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InvalidEvidence)
    );
    let forged =
        point(location("document", 30, vec![]).with_provenance(ContainmentProvenance::Proposed));
    assert_eq!(
        forged.validate(
            &contract(vec![ContainmentEffect::Content]),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InvalidEvidence)
    );
}

#[test]
fn collection_preserves_grant_local_exclusions_and_token_ceiling() {
    let grants = vec![
        boundary(vec![space("ENG")], vec![subtree_id("directory", 10)]),
        boundary(vec![exact_id("document", 31)], vec![]),
    ];
    let candidate = location("document", 31, vec![identity("directory", 10)]);
    let authority = crate::host::containment_collection_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        grants.clone(),
        None,
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    assert!(authority.matches_candidate(&candidate).unwrap());
    let restricted = crate::host::containment_collection_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        grants,
        Some(boundary(vec![all()], vec![exact_id("document", 31)])),
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    assert!(!restricted.matches_candidate(&candidate).unwrap());
    let mut malformed = candidate;
    malformed.containers[0].value = "OPS".into();
    assert_eq!(
        restricted.matches_candidate(&malformed),
        Err(ContainmentError::InvalidEvidence)
    );
}

#[test]
fn evidence_level_and_final_location_equality_do_not_select_new_authority() {
    let initial = point(location("document", 31, vec![identity("directory", 10)]));
    let moved = point(location("document", 31, vec![identity("directory", 20)]));
    let full = crate::host::containment_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        initial.clone(),
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    assert_eq!(
        full.check_same_location(&moved),
        Err(ContainmentError::ChangedLocation)
    );
    let broad = crate::host::containment_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        initial,
        &registry(),
        ContainmentEvidenceLevel::ContainerOnly,
        DIGEST.into(),
    )
    .unwrap();
    assert!(broad.check_same_location(&moved).is_ok());
    let shallow = point(ContentLocation::new(
        identity("document", 31),
        vec![ResourceContainer::new(area_type(), "ENG")],
        ContainmentEvidenceLevel::ContainerOnly,
    ));
    assert_eq!(
        full.check_same_location(&shallow),
        Err(ContainmentError::InsufficientEvidence)
    );
}

#[test]
fn signed_initial_edge_must_become_observed_at_the_final_fence() {
    let location = location("document", 31, vec![identity("directory", 10)]);
    let initial = point(
        location
            .clone()
            .with_provenance(ContainmentProvenance::SignedLocator),
    );
    let authority = crate::host::containment_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        initial.clone(),
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    assert!(authority.check_same_location(&point(location)).is_ok());
    assert_eq!(
        authority.check_same_location(&initial),
        Err(ContainmentError::InvalidEvidence)
    );
}

#[test]
fn malformed_cyclic_overdeep_duplicate_or_wrong_domain_evidence_fails() {
    let contract = contract(vec![ContainmentEffect::Content]);
    let registry = registry();
    let cyclic = point(location("document", 31, vec![identity("document", 31)]));
    assert_eq!(
        cyclic.validate(
            &contract,
            &registry,
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InvalidEvidence)
    );
    let deep = point(location(
        "document",
        100,
        (1..=64).map(|id| identity("document", id)).collect(),
    ));
    assert!(
        deep.validate(
            &contract,
            &registry,
            ContainmentEvidenceLevel::CompleteLineage
        )
        .is_err()
    );
    let target = location("document", 31, vec![]);
    let duplicate = ContainmentEvidence::new(
        "documents",
        ORIGIN,
        vec![
            ContainmentObligation::Content(target.clone()),
            ContainmentObligation::Content(target),
        ],
    );
    assert!(
        duplicate
            .validate(
                &contract,
                &registry,
                ContainmentEvidenceLevel::CompleteLineage
            )
            .is_err()
    );
    let mut wrong = point(location("document", 31, vec![]));
    wrong.domain = "journals".into();
    assert!(
        wrong
            .validate(
                &contract,
                &registry,
                ContainmentEvidenceLevel::CompleteLineage
            )
            .is_err()
    );
    assert!(ScopeResolution::containment(wrong).into_scopes().is_err());
}

#[test]
fn offline_proofs_keep_unknown_subtrees_conditional_and_kind_site_filters_explicit() {
    let contract = contract(vec![ContainmentEffect::Content]);
    let a = boundary(vec![subtree_id("directory", 10)], vec![]);
    let b = boundary(vec![subtree_id("directory", 20)], vec![]);
    assert_eq!(
        a.prove_intersection(&b, &contract, ORIGIN),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        a.prove_intersection(&boundary(vec![space("OPS")], vec![]), &contract, ORIGIN),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        boundary(vec![space("ENG")], vec![]).prove_covers(&a, &contract, ORIGIN),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        boundary(vec![space("ENG")], vec![subtree_id("directory", 10)])
            .prove_covers(&b, &contract, ORIGIN),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        boundary(vec![exact_id("document", 31)], vec![]).prove_intersection(
            &boundary(vec![exact_id("document", 32)], vec![]),
            &contract,
            ORIGIN
        ),
        OfflineContainmentProof::Empty
    );
    assert_eq!(
        boundary(
            vec![subtree_id("directory", 10)],
            vec![subtree_id("directory", 10)]
        )
        .prove_nonempty(&contract, ORIGIN),
        OfflineContainmentProof::Empty
    );
    assert!(!contract.selector_applicable(&exact_id("journal", 31), ORIGIN));
    assert!(boundary(vec![all()], vec![]).is_universe(&contract, ORIGIN));
    assert!(!a.is_universe(&contract, ORIGIN));
    assert_eq!(
        boundary(vec![exact_id("document", 31)], vec![]).prove_nonempty(&move_contract(), ORIGIN),
        OfflineContainmentProof::Empty
    );
}

#[test]
fn requested_space_proof_keeps_the_token_conjunction_and_local_exclusions() {
    let authority = crate::host::containment_collection_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        vec![boundary(vec![exact_id("document", 31)], vec![])],
        Some(boundary(vec![exact_id("document", 32)], vec![])),
        &registry(),
        ContainmentEvidenceLevel::ContainerOnly,
        DIGEST.into(),
    )
    .unwrap();
    assert_eq!(
        authority.requested_container_coverage(&ResourceContainer::new(area_type(), "ENG")),
        OfflineContainmentProof::Empty
    );
    let conditional = crate::host::containment_collection_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        vec![boundary(vec![subtree_id("directory", 10)], vec![])],
        Some(boundary(vec![subtree_id("directory", 20)], vec![])),
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    assert_eq!(
        conditional.requested_container_coverage(&ResourceContainer::new(area_type(), "ENG")),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        conditional.requested_container_coverage(&ResourceContainer::new(area_type(), "OPS")),
        OfflineContainmentProof::Conditional
    );
    assert!(
        crate::host::containment_collection_authorization(
            ORIGIN,
            contract(vec![ContainmentEffect::Content]),
            vec![boundary(vec![subtree_id("directory", 10)], vec![])],
            None,
            &registry(),
            ContainmentEvidenceLevel::ContainerOnly,
            DIGEST.into()
        )
        .is_err()
    );
}

#[test]
fn region_proof_budget_counts_unique_nodes_across_all_roots() {
    let roots = (0..64)
        .map(|index| {
            location(
                "document",
                1000 + index * 5,
                (1..=4)
                    .map(|offset| identity("document", 1000 + index * 5 + offset))
                    .collect(),
            )
        })
        .collect();
    let evidence = move_evidence().with_related_roots(roots);
    assert_eq!(
        evidence.validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::BudgetExceeded)
    );
}

#[test]
fn authority_and_evidence_debug_do_not_dump_ancestor_or_exclusion_inventories() {
    let evidence = point(location("document", 31, vec![identity("directory", 98765)]));
    let selected = boundary(vec![space("ENG")], vec![exact_id("document", 87654)]);
    let dump = format!("{evidence:?} {selected:?}");
    assert!(!dump.contains("98765"));
    assert!(!dump.contains("87654"));
    assert_eq!(
        serde_json::to_value(&selected).unwrap()["excluded"][0]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn scope_request_debug_hides_private_root_values_in_both_wrappers() {
    let roots = [exact_id("document", 87654), subtree_id("directory", 98765)];
    let identity = crate::InvocationIdentity::new("synthetic-user", true);
    let correlation = crate::CorrelationContext::for_tests();
    let inputs = serde_json::json!({"documentId": "31"});
    let parts = crate::host::ScopeRequestParts {
        service: "docs",
        action: "document.move",
        inputs: &inputs,
        execution_context: "development",
        identity: &identity,
        correlation: &correlation,
        lookup_access: None,
        containment_evidence_level: ContainmentEvidenceLevel::CompleteLineage,
        containment_roots: &roots,
        locator_state: None,
    };
    let request = crate::host::scope_request(parts);
    for dump in [
        format!("{parts:?}"),
        format!("{parts:#?}"),
        format!("{request:?}"),
        format!("{request:#?}"),
    ] {
        for private in ["87654", "98765", ORIGIN] {
            assert!(!dump.contains(private), "private root printed: {dump}");
        }
        assert!(dump.contains("containment_root_count: 2"));
        assert!(dump.contains("CompleteLineage"));
        assert!(dump.contains("synthetic-user"));
        assert!(dump.contains("document.move"));
        assert!(dump.contains("documentId"));
    }
    assert_eq!(request.containment_roots(), &roots);
}

#[test]
fn offline_empty_and_coverage_claims_agree_with_independent_finite_tree_semantics() {
    // The finite oracle evaluates selector membership directly against known
    // parent IDs; it does not use the SDK matcher or its offline relation code.
    let points = [
        (31_u64, vec![30_u64, 10]),
        (30, vec![10]),
        (32, vec![20]),
        (33, vec![]),
    ];
    let selectors = vec![
        all(),
        space("ENG"),
        space("OPS"),
        exact_id("document", 30),
        exact_id("document", 31),
        exact_id("document", 32),
        subtree_id("directory", 10),
        subtree_id("directory", 20),
        subtree_id("document", 30),
    ];
    let oracle_selector = |selector: &TypedResourceSelector, index: usize| {
        let (id, parents) = &points[index];
        match (selector.projection(), selector.selector()) {
            (None, ResourceSelector::All) => true,
            (None, ResourceSelector::Exact { value }) => value == "ENG",
            (Some(_), ResourceSelector::Exact { value }) => {
                value == &identity("document", *id).value
            }
            (Some(_), ResourceSelector::Subtree { value }) => {
                value == &identity("document", *id).value
                    || parents.iter().any(|parent| {
                        value
                            == &identity(
                                if *parent >= 30 {
                                    "document"
                                } else {
                                    "directory"
                                },
                                *parent,
                            )
                            .value
                    })
            }
            _ => false,
        }
    };
    let mut boundaries = vec![boundary(vec![], vec![])];
    for positive in &selectors {
        boundaries.push(boundary(vec![positive.clone()], vec![]));
        for negative in &selectors {
            boundaries.push(boundary(vec![positive.clone()], vec![negative.clone()]));
        }
    }
    boundaries.push(boundary(
        vec![subtree_id("directory", 10), subtree_id("directory", 20)],
        vec![exact_id("document", 31)],
    ));
    let oracle = |boundary: &ContainmentBoundary| -> BTreeSet<usize> {
        (0..points.len())
            .filter(|index| {
                boundary
                    .included()
                    .iter()
                    .any(|selector| oracle_selector(selector, *index))
                    && !boundary
                        .excluded()
                        .iter()
                        .any(|selector| oracle_selector(selector, *index))
            })
            .collect()
    };
    let contract = contract(vec![ContainmentEffect::Content]);
    let observed: Vec<_> = boundaries.iter().map(oracle).collect();
    for (left_index, left) in boundaries.iter().enumerate() {
        if left.prove_nonempty(&contract, ORIGIN) == OfflineContainmentProof::Empty {
            assert!(
                observed[left_index].is_empty(),
                "empty boundary {left_index}"
            );
        }
        if left.is_universe(&contract, ORIGIN) {
            assert_eq!(observed[left_index].len(), points.len());
        }
        for (right_index, right) in boundaries.iter().enumerate() {
            if left.prove_intersection(right, &contract, ORIGIN) == OfflineContainmentProof::Empty {
                assert!(
                    observed[left_index].is_disjoint(&observed[right_index]),
                    "intersection {left_index},{right_index}"
                );
            }
            if left.prove_covers(right, &contract, ORIGIN) == OfflineContainmentProof::Covered {
                assert!(
                    observed[right_index].is_subset(&observed[left_index]),
                    "coverage {left_index},{right_index}"
                );
            }
        }
    }
}

#[test]
fn native_containment_descriptor_rejects_imported_private_gateway_and_invalid_local_hooks() {
    use crate::{
        ActionDescriptor, CredentialDescriptor, LookupRequirement, ResourceScopeCapabilities,
        ScopedMcpNameSource, ServiceDescriptor, ServiceSurface, UpstreamAuthority,
    };
    let action = ActionDescriptor::new(
        "document.view",
        "Read a document",
        serde_json::json!({"type":"object"}),
    )
    .scope("location")
    .credential_modes(["service"])
    .read_only();
    let service = ServiceDescriptor::new("docs", "Docs")
        .with_upstream_authority(UpstreamAuthority::from_base_url(ORIGIN).unwrap())
        .with_resource_scopes(BTreeMap::from([(
            "location".into(),
            ResourceScopeCapabilities::containment(contract(vec![ContainmentEffect::Content])),
        )]))
        .with_credentials(CredentialDescriptor::without_execution_credential())
        .with_actions(vec![action.clone()]);
    assert!(service.validate().is_ok());
    assert!(service.validate_resource_types(&registry()).is_empty());
    let mut imported = service.clone();
    imported.actions[0].scoped_mcp_name_source = ScopedMcpNameSource::Imported {
        name: Some("read".into()),
    };
    assert!(imported.validate().is_err());
    let mut private = service.clone();
    private.actions[0].requires_resource_attributes = true;
    assert!(private.validate().is_err());
    let mut gateway = service.clone();
    gateway.surface = ServiceSurface::Gateway {
        kind: "test".into(),
        broker_hosts: vec!["broker.example.test".into()],
    };
    assert!(gateway.validate().is_err());
    let mut local = service.clone();
    local.actions[0].requires_scope_locator_validation = true;
    assert!(local.validate().is_err());
    local.actions[0].lookup = LookupRequirement::ScopeResolution;
    assert!(local.validate().is_ok());
    let mut invalid = service.clone();
    invalid.upstream_authority = None;
    assert!(invalid.validate().is_err());
    let mut invalid = service;
    invalid
        .resource_scopes
        .get_mut("location")
        .and_then(|binding| {
            if let ResourceScopeCapabilities::Containment(contract) = binding {
                contract.effects.clear();
                Some(())
            } else {
                None
            }
        });
    assert!(invalid.validate().is_err());
}

mod refinement;
