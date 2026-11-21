use super::*;

fn containers(key: &str) -> Vec<ResourceContainer> {
    vec![ResourceContainer::new(area_type(), key)]
}

fn relocated(mut location: ContentLocation, key: &str) -> ContentLocation {
    location.containers = containers(key);
    for ancestor in &mut location.ancestors {
        ancestor.containers = containers(key);
    }
    location
}

fn shallow(id: u64, key: &str) -> ContentLocation {
    ContentLocation::new(
        identity("document", id),
        containers(key),
        ContainmentEvidenceLevel::ContainerOnly,
    )
}

fn collection(
    grants: Vec<ContainmentBoundary>,
    token: Option<ContainmentBoundary>,
    level: ContainmentEvidenceLevel,
) -> ContainmentCollectionAuthorization {
    crate::host::containment_collection_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        grants,
        token,
        &registry(),
        level,
        DIGEST.into(),
    )
    .unwrap()
}

#[test]
fn stable_content_identity_follows_current_space_and_independent_token_does_not() {
    let before = location("document", 31, vec![identity("directory", 10)]);
    let after = relocated(before.clone(), "OPS");
    assert_eq!(before.target, after.target);
    let root = subtree_id("directory", 10);
    let content = collection(
        vec![boundary(vec![root.clone()], vec![])],
        Some(boundary(vec![root], vec![])),
        ContainmentEvidenceLevel::CompleteLineage,
    );
    assert!(content.matches_candidate(&before).unwrap());
    assert!(content.matches_candidate(&after).unwrap());
    let scalar_token = collection(
        vec![boundary(vec![exact_id("document", 31)], vec![])],
        Some(boundary(vec![space("ENG")], vec![])),
        ContainmentEvidenceLevel::ContainerOnly,
    );
    assert!(scalar_token.matches_candidate(&before).unwrap());
    assert!(!scalar_token.matches_candidate(&after).unwrap());
    let scalar_exclusion = collection(
        vec![boundary(vec![exact_id("document", 31)], vec![space("ENG")])],
        None,
        ContainmentEvidenceLevel::ContainerOnly,
    );
    assert!(!scalar_exclusion.matches_candidate(&before).unwrap());
    assert!(scalar_exclusion.matches_candidate(&after).unwrap());
    let left_subtree = relocated(
        location("document", 31, vec![identity("directory", 20)]),
        "OPS",
    );
    assert!(!content.matches_candidate(&left_subtree).unwrap());
    let authorization = crate::host::containment_authorization(
        ORIGIN,
        contract(vec![ContainmentEffect::Content]),
        point(before),
        &registry(),
        ContainmentEvidenceLevel::ContainerOnly,
        DIGEST.into(),
    )
    .unwrap();
    assert_eq!(
        authorization.check_same_location(&point(after)),
        Err(ContainmentError::ChangedLocation)
    );
}

#[test]
fn projections_publish_identity_only_and_ancestor_debug_is_redacted() {
    let projection = project_value(&identity("document", 314159).value).unwrap();
    assert_eq!(
        serde_json::to_value(projection).unwrap(),
        serde_json::json!({"siteOrigin": ORIGIN, "rootKind": "document"})
    );
    let ancestor = ContainmentAncestor::new(identity("directory", 271828), containers("PRIVATE"));
    let location = ContentLocation::new(
        identity("document", 314159),
        containers("PRIVATE"),
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .with_ancestors(vec![ancestor.clone()]);
    let debug = format!("{ancestor:?} {location:?}");
    for private in ["271828", "314159", "PRIVATE", ORIGIN] {
        assert!(!debug.contains(private));
    }
    let alternate_type = ResourceType::from_static("alternate_area");
    let unsorted = vec![
        ResourceContainer::new(area_type(), "ENG"),
        ResourceContainer::new(alternate_type.clone(), "OPS"),
    ];
    let normalized = ContainmentAncestor::new(identity("document", 1), unsorted);
    assert_eq!(normalized.containers[0].resource_type, alternate_type);
}

#[test]
fn each_ancestor_requires_complete_valid_same_site_kind_and_container_observations() {
    let valid = location("document", 31, vec![identity("directory", 10)]);
    let mut cases = Vec::new();
    let mut missing = valid.clone();
    missing.ancestors[0].containers.clear();
    cases.push(missing);
    let mut duplicate = valid.clone();
    duplicate.ancestors[0].containers.extend(containers("ENG"));
    cases.push(duplicate);
    let mut mismatched = valid.clone();
    mismatched.ancestors[0].containers = containers("OPS");
    cases.push(mismatched);
    let mut wrong_type = valid.clone();
    wrong_type.ancestors[0].containers[0].resource_type = content_type();
    cases.push(wrong_type);
    let mut wrong_site = valid.clone();
    wrong_site.ancestors[0].identity = identity_in("https://other.example.test", "directory", 10);
    cases.push(wrong_site);
    let mut wrong_kind = valid.clone();
    wrong_kind.ancestors[0].identity.content_kind = "document".into();
    cases.push(wrong_kind);
    let mut unsupported_kind = valid.clone();
    unsupported_kind.ancestors[0].identity = identity("journal", 10);
    cases.push(unsupported_kind);
    let mut repeated = valid.clone();
    repeated.ancestors.push(repeated.ancestors[0].clone());
    cases.push(repeated);
    let mut cycle = valid;
    cycle.ancestors.push(ContainmentAncestor::new(
        cycle.target.clone(),
        containers("ENG"),
    ));
    cases.push(cycle);
    for malformed in cases {
        assert_eq!(
            point(malformed).validate(
                &contract(vec![ContainmentEffect::Content]),
                &registry(),
                ContainmentEvidenceLevel::CompleteLineage,
            ),
            Err(ContainmentError::InvalidEvidence)
        );
    }
}

#[test]
fn repeated_identity_cannot_have_conflicting_containers_across_operation_roles_or_probes() {
    let evidence = ContainmentEvidence::new(
        "documents",
        ORIGIN,
        vec![
            ContainmentObligation::Content(location("document", 31, vec![])),
            ContainmentObligation::ChildPlacement(relocated(
                location("document", 31, vec![]),
                "OPS",
            )),
        ],
    );
    assert_eq!(
        evidence.validate(
            &contract(vec![
                ContainmentEffect::Content,
                ContainmentEffect::ChildPlacement
            ]),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        ),
        Err(ContainmentError::InvalidEvidence)
    );
    // A forged foreign-root classification cannot contradict a known ancestor.
    let evidence = move_evidence().with_related_roots(vec![shallow(9, "OPS")]);
    assert_eq!(
        evidence.validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InvalidEvidence)
    );
}

#[test]
fn disjoint_root_witnesses_are_retained_bounded_and_rechecked_at_final_fence() {
    let foreign = move_evidence().with_related_roots(vec![shallow(31, "OPS")]);
    foreign
        .validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    let selected = boundary(vec![space("ENG")], vec![exact_id("document", 31)]);
    assert!(selected.matches_evidence(&foreign).unwrap());
    assert_eq!(
        selected.matches_evidence(&move_evidence()),
        Err(ContainmentError::UnresolvedRelation)
    );
    let overlapping = move_evidence().with_related_roots(vec![shallow(31, "ENG")]);
    assert_eq!(
        overlapping.validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InsufficientEvidence)
    );
    let authorization = crate::host::containment_authorization(
        ORIGIN,
        move_contract(),
        foreign,
        &registry(),
        ContainmentEvidenceLevel::CompleteLineage,
        DIGEST.into(),
    )
    .unwrap();
    let now_inside = move_evidence().with_related_roots(vec![location("document", 31, vec![])]);
    assert_eq!(
        authorization.check_same_location(&now_inside),
        Err(ContainmentError::ChangedLocation)
    );
    assert_eq!(
        authorization.check_same_location(&move_evidence()),
        Err(ContainmentError::ChangedLocation)
    );

    let foreign_roots = (1000..1065).map(|id| shallow(id, "OPS")).collect();
    move_evidence()
        .with_related_roots(foreign_roots)
        .validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    let overlapping_roots = (1000..1065)
        .map(|id| location("document", id, vec![]))
        .collect();
    assert_eq!(
        move_evidence()
            .with_related_roots(overlapping_roots)
            .validate(
                &move_contract(),
                &registry(),
                ContainmentEvidenceLevel::CompleteLineage
            ),
        Err(ContainmentError::BudgetExceeded)
    );
    let exactly_256_nodes = (1000..1251).map(|id| shallow(id, "OPS")).collect();
    move_evidence()
        .with_related_roots(exactly_256_nodes)
        .validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage,
        )
        .unwrap();
    let too_many_nodes = (1000..1252).map(|id| shallow(id, "OPS")).collect();
    assert_eq!(
        move_evidence().with_related_roots(too_many_nodes).validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::BudgetExceeded)
    );
    let too_many_raw_entries = vec![shallow(1000, "OPS"); 257];
    assert_eq!(
        move_evidence()
            .with_related_roots(too_many_raw_entries)
            .validate(
                &move_contract(),
                &registry(),
                ContainmentEvidenceLevel::CompleteLineage
            ),
        Err(ContainmentError::BudgetExceeded)
    );
}

#[test]
fn foreign_root_must_be_disjoint_from_every_impact_region() {
    let mut evidence = move_evidence();
    let mut second = move_evidence();
    for obligation in &mut second.obligations {
        let shift = |location: &mut ContentLocation| {
            location.target.value.push('0');
            for ancestor in &mut location.ancestors {
                ancestor.identity.value.push('0');
            }
            *location = relocated(location.clone(), "OPS");
        };
        match obligation {
            ContainmentObligation::Content(location)
            | ContainmentObligation::ChildPlacement(location) => shift(location),
            ContainmentObligation::SubtreeImpact { current, proposed } => {
                shift(current);
                shift(proposed);
            }
        }
    }
    evidence.obligations.extend(second.obligations);
    evidence.related_roots.push(shallow(1000, "OPS"));
    assert_eq!(
        evidence.validate(
            &move_contract(),
            &registry(),
            ContainmentEvidenceLevel::CompleteLineage
        ),
        Err(ContainmentError::InsufficientEvidence)
    );
}

#[test]
fn requested_container_conjunction_keeps_every_grant_token_and_exclusion_operand() {
    use OfflineContainmentProof::{Conditional, Covered, Empty};
    let root = subtree_id("document", 10);
    let cases = [
        (
            boundary(vec![exact_id("document", 31)], vec![]),
            None,
            "ENG",
            Conditional,
        ),
        (
            boundary(vec![root.clone()], vec![]),
            Some(boundary(vec![root.clone()], vec![])),
            "ENG",
            Conditional,
        ),
        (
            boundary(vec![root.clone()], vec![]),
            Some(boundary(vec![space("ENG")], vec![])),
            "OPS",
            Empty,
        ),
        (
            boundary(vec![space("ENG")], vec![]),
            Some(boundary(vec![root.clone()], vec![])),
            "OPS",
            Empty,
        ),
        (
            boundary(vec![space("ENG")], vec![]),
            Some(boundary(vec![all()], vec![])),
            "ENG",
            Covered,
        ),
        (
            boundary(vec![root.clone()], vec![]),
            Some(boundary(vec![all()], vec![space("ENG")])),
            "ENG",
            Empty,
        ),
        (
            boundary(vec![root.clone()], vec![space("ENG")]),
            None,
            "ENG",
            Empty,
        ),
        (
            boundary(vec![root.clone()], vec![]),
            Some(boundary(vec![root.clone()], vec![root.clone()])),
            "OPS",
            Empty,
        ),
        (
            boundary(vec![space("ENG")], vec![root.clone()]),
            Some(boundary(vec![all()], vec![])),
            "ENG",
            Conditional,
        ),
    ];
    for (grant, token, key, expected) in cases {
        assert_eq!(
            collection(
                vec![grant],
                token,
                ContainmentEvidenceLevel::CompleteLineage
            )
            .requested_container_coverage(&ResourceContainer::new(area_type(), key)),
            expected,
        );
    }
    let union = collection(
        vec![
            boundary(vec![space("ENG")], vec![]),
            boundary(vec![root], vec![]),
        ],
        Some(boundary(vec![space("OPS")], vec![])),
        ContainmentEvidenceLevel::CompleteLineage,
    );
    assert_eq!(
        union.requested_container_coverage(&ResourceContainer::new(area_type(), "ENG")),
        Empty
    );
    assert_eq!(
        union.requested_container_coverage(&ResourceContainer::new(area_type(), "OPS")),
        Conditional
    );
}

#[test]
fn scalar_search_classifier_checks_all_positive_negative_and_token_selectors() {
    let scalar = boundary(vec![all()], vec![space("OPS")]);
    let exact = exact_id("document", 31);
    let cases = [
        (
            vec![scalar.clone()],
            None,
            ContainmentEvidenceLevel::ContainerOnly,
            true,
        ),
        (
            vec![scalar.clone()],
            Some(boundary(vec![space("ENG")], vec![])),
            ContainmentEvidenceLevel::ContainerOnly,
            true,
        ),
        (
            vec![scalar.clone()],
            None,
            ContainmentEvidenceLevel::CompleteLineage,
            false,
        ),
        (
            vec![scalar.clone(), boundary(vec![exact.clone()], vec![])],
            None,
            ContainmentEvidenceLevel::ContainerOnly,
            false,
        ),
        (
            vec![boundary(vec![all()], vec![exact.clone()])],
            None,
            ContainmentEvidenceLevel::ContainerOnly,
            false,
        ),
        (
            vec![scalar.clone()],
            Some(boundary(vec![exact.clone()], vec![])),
            ContainmentEvidenceLevel::ContainerOnly,
            false,
        ),
        (
            vec![scalar],
            Some(boundary(vec![all()], vec![exact])),
            ContainmentEvidenceLevel::ContainerOnly,
            false,
        ),
    ];
    for (grants, token, level, expected) in cases {
        assert_eq!(
            collection(grants, token, level).uses_only_scalar_container_selectors(),
            expected
        );
    }
}

#[test]
fn finite_model_proofs_remain_sound_for_all_admissible_space_and_parent_assignments() {
    let selectors = [
        all(),
        space("ENG"),
        space("OPS"),
        exact_id("document", 1),
        exact_id("document", 2),
        exact_id("document", 3),
        subtree_id("document", 1),
        subtree_id("document", 2),
        subtree_id("document", 3),
    ];
    let mut boundaries = vec![boundary(vec![], vec![])];
    for positive in &selectors {
        boundaries.push(boundary(vec![positive.clone()], vec![]));
        for negative in &selectors {
            boundaries.push(boundary(vec![positive.clone()], vec![negative.clone()]));
        }
    }
    boundaries.push(boundary(
        vec![space("ENG"), subtree_id("document", 1)],
        vec![exact_id("document", 3)],
    ));
    let contract = contract(vec![ContainmentEffect::Content]);
    let nonempty: Vec<_> = boundaries
        .iter()
        .map(|boundary| boundary.prove_nonempty(&contract, ORIGIN))
        .collect();
    let pair_proofs: Vec<Vec<_>> = boundaries
        .iter()
        .map(|left| {
            boundaries
                .iter()
                .map(|right| {
                    (
                        left.prove_intersection(right, &contract, ORIGIN),
                        left.prove_covers(right, &contract, ORIGIN),
                    )
                })
                .collect()
        })
        .collect();
    let requested_proofs: Vec<Vec<_>> = boundaries
        .iter()
        .map(|grant| {
            boundaries
                .iter()
                .map(|token| {
                    let authority = collection(
                        vec![grant.clone()],
                        Some(token.clone()),
                        ContainmentEvidenceLevel::CompleteLineage,
                    );
                    ["ENG", "OPS"].map(|key| {
                        authority
                            .requested_container_coverage(&ResourceContainer::new(area_type(), key))
                    })
                })
                .collect()
        })
        .collect();
    let mut model_count = 0;
    for assignment in 0_u8..8 {
        let spaces = [0, 1, 2].map(|bit| {
            if assignment & (1 << bit) == 0 {
                "ENG"
            } else {
                "OPS"
            }
        });
        for parent_two in [None, Some(1_usize)] {
            for parent_three in [None, Some(1_usize), Some(2_usize)] {
                let parents = [None, parent_two, parent_three];
                if parents.iter().enumerate().any(|(index, parent)| {
                    parent.is_some_and(|parent| spaces[index] != spaces[parent - 1])
                }) {
                    continue;
                }
                model_count += 1;
                // All authored roots exist. Additional points witness both scalar
                // spaces independently of the locations assigned to those roots.
                let nodes = [
                    (1, spaces[0]),
                    (2, spaces[1]),
                    (3, spaces[2]),
                    (90, "ENG"),
                    (91, "OPS"),
                ];
                let selector_matches = |selector: &TypedResourceSelector, node: usize| {
                    let (id, key) = nodes[node];
                    match (selector.projection(), selector.selector()) {
                        (None, ResourceSelector::All) => true,
                        (None, ResourceSelector::Exact { value }) => value == key,
                        (Some(_), ResourceSelector::Exact { value }) => {
                            value == &identity("document", id).value
                        }
                        (Some(_), ResourceSelector::Subtree { value }) => {
                            let mut current = Some(id as usize);
                            let mut found = false;
                            while let Some(id) = current {
                                found |= value == &identity("document", id as u64).value;
                                current = if id <= 3 { parents[id - 1] } else { None };
                            }
                            found
                        }
                        _ => false,
                    }
                };
                let observed: Vec<BTreeSet<usize>> = boundaries
                    .iter()
                    .map(|boundary| {
                        (0..nodes.len())
                            .filter(|node| {
                                boundary
                                    .included
                                    .iter()
                                    .any(|selector| selector_matches(selector, *node))
                                    && !boundary
                                        .excluded
                                        .iter()
                                        .any(|selector| selector_matches(selector, *node))
                            })
                            .collect()
                    })
                    .collect();
                for (left, set) in observed.iter().enumerate() {
                    if nonempty[left] == OfflineContainmentProof::Empty {
                        assert!(set.is_empty());
                    }
                    if nonempty[left] == OfflineContainmentProof::Covered {
                        assert!(!set.is_empty());
                    }
                    for (right, other) in observed.iter().enumerate() {
                        let (intersection, covers) = pair_proofs[left][right];
                        if intersection == OfflineContainmentProof::Empty {
                            assert!(set.is_disjoint(other));
                        }
                        if intersection == OfflineContainmentProof::Covered {
                            assert!(!set.is_disjoint(other));
                        }
                        if covers == OfflineContainmentProof::Covered {
                            assert!(other.is_subset(set));
                        }
                        if covers == OfflineContainmentProof::Empty {
                            assert!(set.is_disjoint(other));
                        }
                        for (space_index, key) in ["ENG", "OPS"].iter().enumerate() {
                            let any = set.intersection(other).any(|node| nodes[*node].1 == *key);
                            match requested_proofs[left][right][space_index] {
                                OfflineContainmentProof::Empty => assert!(!any),
                                OfflineContainmentProof::Covered => assert!(any),
                                OfflineContainmentProof::Conditional => {}
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(model_count, 24);
}

#[test]
fn declared_container_dimensions_coexist_and_all_covers_each_dimension() {
    const ZONE: ResourceType = ResourceType::from_static("location_zone");
    static ZONE_DESCRIPTOR: ResourceTypeDescriptor =
        ResourceTypeDescriptor::new(ZONE, "Zone", "Zones", "WEST", area, &[]);
    let registry = ResourceTypeRegistry::new([&AREA, &CONTENT, &ZONE_DESCRIPTOR]).unwrap();
    let mut contract = contract(vec![ContainmentEffect::Content]);
    contract.container_types.push(ZONE);
    contract
        .selectors_by_type
        .insert(ZONE, vec!["exact".into(), "all".into()]);
    contract.validate(&registry).unwrap();
    let zone = registry
        .typed_selector(
            &ZONE,
            &ResourceSelector::Exact {
                value: "WEST".into(),
            },
        )
        .unwrap();
    let zone_all = registry
        .typed_selector(&ZONE, &ResourceSelector::All)
        .unwrap();
    let area_boundary = boundary(vec![space("ENG")], vec![]);
    let zone_boundary = boundary(vec![zone.clone()], vec![]);
    assert_eq!(
        area_boundary.prove_intersection(&zone_boundary, &contract, ORIGIN),
        OfflineContainmentProof::Conditional,
    );
    for (universe, finite) in [(all(), zone.clone()), (zone_all.clone(), space("ENG"))] {
        let full = boundary(vec![universe.clone()], vec![]);
        let narrow = boundary(vec![finite.clone()], vec![]);
        assert_eq!(
            full.prove_intersection(&narrow, &contract, ORIGIN),
            OfflineContainmentProof::Covered
        );
        assert_eq!(
            full.prove_covers(&narrow, &contract, ORIGIN),
            OfflineContainmentProof::Covered
        );
        assert_eq!(
            boundary(vec![finite], vec![universe]).prove_nonempty(&contract, ORIGIN),
            OfflineContainmentProof::Empty
        );
    }
    assert_eq!(
        boundary(vec![all()], vec![]).prove_intersection(
            &boundary(vec![zone_all], vec![]),
            &contract,
            ORIGIN
        ),
        OfflineContainmentProof::Covered,
    );
    let authority = crate::host::containment_collection_authorization(
        ORIGIN,
        contract.clone(),
        vec![area_boundary],
        Some(zone_boundary),
        &registry,
        ContainmentEvidenceLevel::ContainerOnly,
        DIGEST.into(),
    )
    .unwrap();
    assert!(authority.uses_only_scalar_container_selectors());
    assert_eq!(
        authority.requested_container_coverage(&ResourceContainer::new(area_type(), "ENG")),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        authority.requested_container_coverage(&ResourceContainer::new(area_type(), "OPS")),
        OfflineContainmentProof::Empty
    );
    for (key, zone, expected) in [
        ("ENG", "WEST", true),
        ("ENG", "EAST", false),
        ("OPS", "WEST", false),
    ] {
        let candidate = ContentLocation::new(
            identity("document", 1),
            vec![
                ResourceContainer::new(area_type(), key),
                ResourceContainer::new(ZONE, zone),
            ],
            ContainmentEvidenceLevel::ContainerOnly,
        );
        assert_eq!(authority.matches_candidate(&candidate).unwrap(), expected);
    }
}

#[test]
fn conjunction_budget_exhaustion_keeps_unknown_roots_conditional() {
    let left = boundary(
        (1..=200).map(|id| exact_id("document", id)).collect(),
        vec![],
    );
    let right = boundary(
        (1000..1200).map(|id| subtree_id("document", id)).collect(),
        vec![],
    );
    assert_eq!(
        left.prove_intersection(&right, &contract(vec![ContainmentEffect::Content]), ORIGIN),
        OfflineContainmentProof::Conditional
    );
}
