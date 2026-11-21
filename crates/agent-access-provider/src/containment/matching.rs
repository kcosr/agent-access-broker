use super::*;
use crate::ScalarResourceSelector;

impl ContainmentBoundary {
    /// Checks a complete operation against this one boundary. This does not
    /// select grants, combine grants, or acquire any new evidence.
    pub fn matches_evidence(
        &self,
        evidence: &ContainmentEvidence,
    ) -> Result<bool, ContainmentError> {
        if evidence.obligations.is_empty() {
            return Err(ContainmentError::InvalidEvidence);
        }
        for obligation in &evidence.obligations {
            if !self.matches_obligation(
                obligation,
                &evidence.related_roots,
                &evidence.site_origin,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Checks one declared effect. Region exclusions must be proven disjoint;
    /// a missing related-root probe is never evidence that a root is outside.
    pub fn matches_obligation(
        &self,
        obligation: &ContainmentObligation,
        related_roots: &[ContentLocation],
        site_origin: &str,
    ) -> Result<bool, ContainmentError> {
        let mut positive = false;
        let mut unresolved = None;
        for selector in self.included.iter().filter(|selector| {
            selector
                .projection
                .as_ref()
                .is_none_or(|projection| projection.site_origin == site_origin)
        }) {
            let result = match obligation {
                ContainmentObligation::Content(location) => matches_point(selector, location),
                ContainmentObligation::ChildPlacement(parent) => {
                    matches_placement(selector, parent)
                }
                ContainmentObligation::SubtreeImpact { current, proposed } => {
                    // A union can cover the before and after regions with
                    // different complete roots, but never with visible exact IDs.
                    matches_region_positive(selector, current).and_then(|before| {
                        if before {
                            Ok(true)
                        } else {
                            matches_region_positive(selector, proposed)
                        }
                    })
                }
            };
            match result {
                Ok(true) => positive = true,
                Err(error) => unresolved = Some(error),
                Ok(false) => {}
            }
        }
        if !positive {
            return unresolved.map_or(Ok(false), Err);
        }
        // Before and after are independent complete-region obligations within
        // this one grant. A root covering only the source must not cover a move
        // out to an unauthorized destination (or conversely).
        if let ContainmentObligation::SubtreeImpact { current, proposed } = obligation {
            for region in [current, proposed] {
                let mut covered = false;
                let mut error = None;
                for selector in self.included.iter().filter(|selector| {
                    selector
                        .projection
                        .as_ref()
                        .is_none_or(|projection| projection.site_origin == site_origin)
                }) {
                    match matches_region_positive(selector, region) {
                        Ok(true) => covered = true,
                        Err(cause) => error = Some(cause),
                        Ok(false) => {}
                    }
                }
                if !covered {
                    return error.map_or(Ok(false), Err);
                }
            }
        }
        let mut unresolved = None;
        for selector in self.excluded.iter().filter(|selector| {
            selector
                .projection
                .as_ref()
                .is_none_or(|projection| projection.site_origin == site_origin)
        }) {
            let excluded = match obligation {
                ContainmentObligation::Content(location) => matches_point(selector, location),
                ContainmentObligation::ChildPlacement(parent) => {
                    matches_placement(selector, parent)
                }
                ContainmentObligation::SubtreeImpact { current, proposed } => {
                    region_intersects(selector, current, proposed, related_roots)
                }
            };
            match excluded {
                Ok(true) => return Ok(false),
                Err(error) => unresolved = Some(error),
                Ok(false) => {}
            }
        }
        unresolved.map_or(Ok(true), Err)
    }

    /// Conservative proof that this boundary has a possible operation in the
    /// declared domain. Covered is a definite unexcluded authored witness, not
    /// a claim that a particular upstream object currently exists.
    pub fn prove_nonempty(
        &self,
        contract: &ContainmentScopeCapabilities,
        site_origin: &str,
    ) -> OfflineContainmentProof {
        prove_conjunction(&[self], contract, site_origin)
    }

    /// Proves nonempty overlap while preserving both boundaries and exclusions.
    pub fn prove_intersection(
        &self,
        other: &Self,
        contract: &ContainmentScopeCapabilities,
        site_origin: &str,
    ) -> OfflineContainmentProof {
        prove_conjunction(&[self, other], contract, site_origin)
    }

    /// Proves complete coverage of the other boundary. Empty means provably
    /// disjoint; partial or unknown overlap is Conditional. No DNF expansion.
    pub fn prove_covers(
        &self,
        other: &Self,
        contract: &ContainmentScopeCapabilities,
        site_origin: &str,
    ) -> OfflineContainmentProof {
        if other.prove_nonempty(contract, site_origin) == OfflineContainmentProof::Empty
            || self.is_universe(contract, site_origin)
        {
            return OfflineContainmentProof::Covered;
        }
        if self == other {
            return OfflineContainmentProof::Covered;
        }
        let positives: Vec<_> = self
            .included
            .iter()
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .collect();
        let negatives: Vec<_> = self
            .excluded
            .iter()
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .collect();
        let other_negatives: Vec<_> = other
            .excluded
            .iter()
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .collect();
        let covered = other
            .included
            .iter()
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .all(|required| {
                // An entirely excluded positive contributes no requested members.
                if other_negatives.iter().any(|negative| {
                    selector_relation(negative, required, contract) == Relation::Contains
                }) {
                    return true;
                }
                positives.iter().any(|positive| {
                    selector_relation(positive, required, contract) == Relation::Contains
                }) && negatives.iter().all(|negative| {
                    (selector_relation(negative, required, contract) == Relation::Disjoint
                        && selector_relation(required, negative, contract) == Relation::Disjoint)
                        || other_negatives.iter().any(|already_excluded| {
                            selector_relation(already_excluded, negative, contract)
                                == Relation::Contains
                        })
                })
            });
        if covered {
            OfflineContainmentProof::Covered
        } else if self.prove_intersection(other, contract, site_origin)
            == OfflineContainmentProof::Empty
        {
            OfflineContainmentProof::Empty
        } else {
            OfflineContainmentProof::Conditional
        }
    }

    /// A same-site, complete-domain proof. Narrow roots and unknown relationships
    /// never count as a universe, even if the catalog currently lists no peers.
    pub fn is_universe(&self, contract: &ContainmentScopeCapabilities, site_origin: &str) -> bool {
        self.excluded
            .iter()
            .all(|selector| !contract.selector_applicable(selector, site_origin))
            && self.included.iter().any(|selector| {
                contract.selector_applicable(selector, site_origin)
                    && selector.projection.is_none()
                    && matches!(selector.selector, ResourceSelector::All)
                    && contract.container_types.contains(&selector.resource_type)
            })
    }
}

/// Bounded conjunction proof. Operands remain separate; the traversal retains
/// every positive and every local exclusion without constructing a DNF result.
/// Exhausting the proof budget preserves a possible intersection as Conditional.
pub(super) fn prove_conjunction(
    boundaries: &[&ContainmentBoundary],
    contract: &ContainmentScopeCapabilities,
    site_origin: &str,
) -> OfflineContainmentProof {
    const MAX_PROOF_STEPS: usize = 16_384;
    if boundaries.is_empty() || boundaries.len() > 3 {
        return OfflineContainmentProof::Conditional;
    }
    let mut remaining = MAX_PROOF_STEPS;
    let mut conditional = false;
    for effect in &contract.effects {
        let choices: Vec<Vec<_>> = boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .included
                    .iter()
                    .filter(|selector| {
                        contract.selector_applicable(selector, site_origin)
                            && can_cover_effect(selector, *effect)
                    })
                    .collect()
            })
            .collect();
        if choices.iter().any(Vec::is_empty) {
            return OfflineContainmentProof::Empty;
        }
        let negatives: Vec<_> = boundaries
            .iter()
            .flat_map(|boundary| &boundary.excluded)
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .collect();
        let mut selected = Vec::with_capacity(boundaries.len());
        let proof = prove_choices(
            &choices,
            &negatives,
            &mut selected,
            contract,
            &mut remaining,
        );
        if proof == OfflineContainmentProof::Empty {
            return proof;
        }
        conditional |= proof == OfflineContainmentProof::Conditional;
    }
    if conditional {
        OfflineContainmentProof::Conditional
    } else {
        OfflineContainmentProof::Covered
    }
}

fn prove_choices<'a>(
    choices: &[Vec<&'a TypedResourceSelector>],
    negatives: &[&TypedResourceSelector],
    selected: &mut Vec<&'a TypedResourceSelector>,
    contract: &ContainmentScopeCapabilities,
    remaining: &mut usize,
) -> OfflineContainmentProof {
    let mut conditional = false;
    if selected.len() < choices.len() {
        for candidate in &choices[selected.len()] {
            if *remaining == 0 {
                return OfflineContainmentProof::Conditional;
            }
            *remaining -= 1;
            let mut impossible = false;
            for previous in selected.iter() {
                if *remaining == 0 {
                    return OfflineContainmentProof::Conditional;
                }
                *remaining -= 1;
                if selector_relation(previous, candidate, contract) == Relation::Disjoint
                    || selector_relation(candidate, previous, contract) == Relation::Disjoint
                {
                    impossible = true;
                    break;
                }
            }
            if impossible {
                continue;
            }
            for negative in negatives {
                if *remaining == 0 {
                    return OfflineContainmentProof::Conditional;
                }
                *remaining -= 1;
                if selector_relation(negative, candidate, contract) == Relation::Contains {
                    impossible = true;
                    break;
                }
            }
            if impossible {
                continue;
            }
            selected.push(candidate);
            let proof = prove_choices(choices, negatives, selected, contract, remaining);
            selected.pop();
            match proof {
                OfflineContainmentProof::Covered => return proof,
                OfflineContainmentProof::Conditional => conditional = true,
                OfflineContainmentProof::Empty => {}
            }
        }
    } else {
        for witness in selected.iter() {
            let mut contained = true;
            for operand in selected.iter() {
                if *remaining == 0 {
                    return OfflineContainmentProof::Conditional;
                }
                *remaining -= 1;
                if selector_relation(operand, witness, contract) != Relation::Contains {
                    contained = false;
                    break;
                }
            }
            if !contained {
                continue;
            }
            let mut unexcluded = true;
            for negative in negatives {
                if *remaining == 0 {
                    return OfflineContainmentProof::Conditional;
                }
                *remaining -= 1;
                if selector_relation(negative, witness, contract) != Relation::Disjoint
                    || selector_relation(witness, negative, contract) != Relation::Disjoint
                {
                    unexcluded = false;
                    break;
                }
            }
            if unexcluded {
                return OfflineContainmentProof::Covered;
            }
        }
        return OfflineContainmentProof::Conditional;
    }
    if conditional {
        OfflineContainmentProof::Conditional
    } else {
        OfflineContainmentProof::Empty
    }
}

fn can_cover_effect(selector: &TypedResourceSelector, effect: ContainmentEffect) -> bool {
    match effect {
        ContainmentEffect::Content => true,
        ContainmentEffect::ChildPlacement | ContainmentEffect::SubtreeImpact => {
            selector.projection.is_none()
                || matches!(selector.selector, ResourceSelector::Subtree { .. })
        }
    }
}

fn matches_point(
    selector: &TypedResourceSelector,
    location: &ContentLocation,
) -> Result<bool, ContainmentError> {
    if let Some(projection) = &selector.projection {
        // Canonical identity contains its site; projection is checked when
        // evidence is validated. Comparing value never parses a provider URL.
        match &selector.selector {
            ResourceSelector::Exact { value } => Ok(selector.resource_type
                == location.target.resource_type
                && projection.root_kind == location.target.content_kind
                && value == &location.target.value),
            ResourceSelector::Subtree { value } => {
                let identity_matches = |identity: &ContainmentIdentity| {
                    selector.resource_type == identity.resource_type
                        && projection.root_kind == identity.content_kind
                        && value == &identity.value
                };
                if identity_matches(&location.target) {
                    return Ok(true);
                }
                if location.evidence_level != ContainmentEvidenceLevel::CompleteLineage {
                    return Err(ContainmentError::InsufficientEvidence);
                }
                Ok(location
                    .ancestors
                    .iter()
                    .any(|ancestor| identity_matches(&ancestor.identity)))
            }
            _ => Err(ContainmentError::InvalidSelector),
        }
    } else {
        let scalar = ScalarResourceSelector::try_from(&selector.selector)
            .map_err(|_| ContainmentError::InvalidSelector)?;
        Ok(location.containers.iter().any(|container| {
            container.resource_type == selector.resource_type && scalar.matches(&container.value)
        }))
    }
}

fn matches_placement(
    selector: &TypedResourceSelector,
    parent: &ContentLocation,
) -> Result<bool, ContainmentError> {
    if selector.projection.is_some() && matches!(selector.selector, ResourceSelector::Exact { .. })
    {
        return Ok(false);
    }
    matches_point(selector, parent)
}

fn matches_region_positive(
    selector: &TypedResourceSelector,
    root: &ContentLocation,
) -> Result<bool, ContainmentError> {
    if selector.projection.is_some()
        && !matches!(selector.selector, ResourceSelector::Subtree { .. })
    {
        return Ok(false);
    }
    matches_point(selector, root)
}

fn region_intersects(
    selector: &TypedResourceSelector,
    current: &ContentLocation,
    proposed: &ContentLocation,
    related_roots: &[ContentLocation],
) -> Result<bool, ContainmentError> {
    let Some(projection) = &selector.projection else {
        return matches_point(selector, current);
    };
    if matches_point(selector, current)? || matches_point(selector, proposed)? {
        return Ok(true);
    }
    let value = match &selector.selector {
        ResourceSelector::Exact { value } | ResourceSelector::Subtree { value } => value,
        _ => return Err(ContainmentError::InvalidSelector),
    };
    let is_root = |identity: &ContainmentIdentity| {
        identity.resource_type == selector.resource_type
            && identity.content_kind == projection.root_kind
            && &identity.value == value
    };
    // A known proper ancestor cannot be carried below its own descendant. Exact
    // exclusion of that ancestor does not become a subtree exclusion.
    if current
        .ancestors
        .iter()
        .chain(&proposed.ancestors)
        .any(|ancestor| is_root(&ancestor.identity))
    {
        return Ok(false);
    }
    let root = related_roots
        .iter()
        .find(|location| is_root(&location.target))
        .ok_or(ContainmentError::UnresolvedRelation)?;
    if coordinates_disjoint(&root.containers, &current.containers)
        && coordinates_disjoint(&root.containers, &proposed.containers)
    {
        return Ok(false);
    }
    if root.evidence_level != ContainmentEvidenceLevel::CompleteLineage {
        return Err(ContainmentError::InsufficientEvidence);
    }
    // Relationships internal to the carried region are preserved by the move.
    Ok(root.target == current.target
        || root
            .ancestors
            .iter()
            .any(|ancestor| ancestor.identity == current.target))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Contains,
    Disjoint,
    Unknown,
}

/// Authored set relation only. Unknown never becomes false/disjoint.
fn selector_relation(
    left: &TypedResourceSelector,
    right: &TypedResourceSelector,
    contract: &ContainmentScopeCapabilities,
) -> Relation {
    match (&left.projection, &right.projection) {
        (None, None) => {
            if left.resource_type != right.resource_type {
                return if contract.container_types.contains(&left.resource_type)
                    && contract.container_types.contains(&right.resource_type)
                    && matches!(left.selector, ResourceSelector::All)
                {
                    Relation::Contains
                } else {
                    // Distinct declared dimensions coexist on the same content.
                    Relation::Unknown
                };
            }
            let (Ok(left), Ok(right)) = (
                ScalarResourceSelector::try_from(&left.selector),
                ScalarResourceSelector::try_from(&right.selector),
            ) else {
                return Relation::Unknown;
            };
            if left.contains(&right) {
                Relation::Contains
            } else if left.intersection(&right).is_none() {
                Relation::Disjoint
            } else {
                Relation::Unknown
            }
        }
        (None, Some(_)) => {
            if contract.container_types.contains(&left.resource_type)
                && matches!(left.selector, ResourceSelector::All)
            {
                Relation::Contains
            } else {
                // Stable content identity carries no observed container value.
                Relation::Unknown
            }
        }
        (Some(_), None) => match selector_relation(right, left, contract) {
            Relation::Disjoint => Relation::Disjoint,
            _ => Relation::Unknown,
        },
        (Some(left_projection), Some(right_projection)) => {
            if left_projection.site_origin != right_projection.site_origin {
                return Relation::Disjoint;
            }
            match (&left.selector, &right.selector) {
                (
                    ResourceSelector::Exact { value: left_value },
                    ResourceSelector::Exact { value: right_value },
                ) => {
                    if left.resource_type == right.resource_type
                        && left_value == right_value
                        && left_projection.root_kind == right_projection.root_kind
                    {
                        Relation::Contains
                    } else {
                        Relation::Disjoint
                    }
                }
                (
                    ResourceSelector::Subtree { value: left_value },
                    ResourceSelector::Exact { value: right_value }
                    | ResourceSelector::Subtree { value: right_value },
                ) if left.resource_type == right.resource_type
                    && left_value == right_value
                    && left_projection.root_kind == right_projection.root_kind =>
                {
                    Relation::Contains
                }
                _ => Relation::Unknown,
            }
        }
    }
}

pub(super) fn coordinates_disjoint(
    left: &[ResourceContainer],
    right: &[ResourceContainer],
) -> bool {
    left.iter().any(|left| {
        right
            .iter()
            .any(|right| left.resource_type == right.resource_type && left.value != right.value)
    })
}
