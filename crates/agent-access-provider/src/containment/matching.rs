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
        if positives.is_empty() {
            return OfflineContainmentProof::Empty;
        }
        let mut conditional = false;
        for effect in &contract.effects {
            let mut found = false;
            let mut uncertain = false;
            for positive in &positives {
                if !can_cover_effect(positive, *effect) {
                    continue;
                }
                if negatives
                    .iter()
                    .any(|negative| selector_relation(negative, positive) == Relation::Contains)
                {
                    continue;
                }
                if negatives.iter().all(|negative| {
                    selector_relation(negative, positive) == Relation::Disjoint
                        && selector_relation(positive, negative) == Relation::Disjoint
                }) {
                    found = true;
                } else {
                    uncertain = true;
                }
            }
            if !found && !uncertain {
                return OfflineContainmentProof::Empty;
            }
            conditional |= !found;
        }
        if conditional {
            OfflineContainmentProof::Conditional
        } else {
            OfflineContainmentProof::Covered
        }
    }

    /// Proves nonempty overlap without inferring relations between distinct
    /// subtree roots. Exclusions stay local to each input boundary.
    pub fn prove_intersection(
        &self,
        other: &Self,
        contract: &ContainmentScopeCapabilities,
        site_origin: &str,
    ) -> OfflineContainmentProof {
        if self.prove_nonempty(contract, site_origin) == OfflineContainmentProof::Empty
            || other.prove_nonempty(contract, site_origin) == OfflineContainmentProof::Empty
        {
            return OfflineContainmentProof::Empty;
        }
        let negatives: Vec<_> = self
            .excluded
            .iter()
            .chain(&other.excluded)
            .filter(|selector| contract.selector_applicable(selector, site_origin))
            .collect();
        let mut conditional = false;
        for effect in &contract.effects {
            let mut found = false;
            let mut uncertain = false;
            for left in self.included.iter().filter(|selector| {
                contract.selector_applicable(selector, site_origin)
                    && can_cover_effect(selector, *effect)
            }) {
                for right in other.included.iter().filter(|selector| {
                    contract.selector_applicable(selector, site_origin)
                        && can_cover_effect(selector, *effect)
                }) {
                    let left_relation = selector_relation(left, right);
                    let right_relation = selector_relation(right, left);
                    if left_relation == Relation::Disjoint || right_relation == Relation::Disjoint {
                        continue;
                    }
                    let witness = if left_relation == Relation::Contains {
                        Some(right)
                    } else if right_relation == Relation::Contains {
                        Some(left)
                    } else {
                        None
                    };
                    match witness {
                        Some(witness) => {
                            if negatives.iter().any(|negative| {
                                selector_relation(negative, witness) == Relation::Contains
                            }) {
                                continue;
                            }
                            if negatives.iter().all(|negative| {
                                selector_relation(negative, witness) == Relation::Disjoint
                                    && selector_relation(witness, negative) == Relation::Disjoint
                            }) {
                                found = true;
                            } else {
                                uncertain = true;
                            }
                        }
                        None => {
                            // If either complete positive is excluded, their
                            // intersection is excluded as well.
                            if !negatives.iter().any(|negative| {
                                selector_relation(negative, left) == Relation::Contains
                                    || selector_relation(negative, right) == Relation::Contains
                            }) {
                                uncertain = true;
                            }
                        }
                    }
                }
            }
            if !found && !uncertain {
                return OfflineContainmentProof::Empty;
            }
            conditional |= !found;
        }
        if conditional {
            OfflineContainmentProof::Conditional
        } else {
            OfflineContainmentProof::Covered
        }
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
                if other_negatives
                    .iter()
                    .any(|negative| selector_relation(negative, required) == Relation::Contains)
                {
                    return true;
                }
                positives
                    .iter()
                    .any(|positive| selector_relation(positive, required) == Relation::Contains)
                    && negatives.iter().all(|negative| {
                        (selector_relation(negative, required) == Relation::Disjoint
                            && selector_relation(required, negative) == Relation::Disjoint)
                            || other_negatives.iter().any(|already_excluded| {
                                selector_relation(already_excluded, negative) == Relation::Contains
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

    /// Restricts a proof operand to one explicit scalar container. This helper
    /// is not an authority constructor: it is used solely for offline emptiness
    /// proofs, and any unknown relationship retains the original positive.
    pub(super) fn restrict_to_container(&self, restriction: &Self) -> Self {
        let Some(container) = restriction.included.first() else {
            return Self::new(vec![], vec![]);
        };
        let included = self
            .included
            .iter()
            .filter_map(|selector| {
                match (
                    selector_relation(container, selector),
                    selector_relation(selector, container),
                ) {
                    (Relation::Disjoint, _) | (_, Relation::Disjoint) => None,
                    (Relation::Contains, _) => Some(selector.clone()),
                    (_, Relation::Contains) => Some(container.clone()),
                    _ => Some(selector.clone()),
                }
            })
            .collect();
        Self::new(included, self.excluded.clone())
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
        if coordinates_disjoint(&projection.containers, &location.containers) {
            return Ok(false);
        }
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
                Ok(location.ancestors.iter().any(identity_matches))
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
    if coordinates_disjoint(&projection.containers, &current.containers) {
        return Ok(false);
    }
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
        .any(is_root)
    {
        return Ok(false);
    }
    let root = related_roots
        .iter()
        .find(|location| is_root(&location.target))
        .ok_or(ContainmentError::UnresolvedRelation)?;
    if root.evidence_level != ContainmentEvidenceLevel::CompleteLineage {
        return Err(ContainmentError::InsufficientEvidence);
    }
    // Relationships internal to the carried region are preserved by the move.
    Ok(root.target == current.target || root.ancestors.contains(&current.target))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Contains,
    Disjoint,
    Unknown,
}

/// Authored set relation only. Unknown never becomes false/disjoint.
fn selector_relation(left: &TypedResourceSelector, right: &TypedResourceSelector) -> Relation {
    match (&left.projection, &right.projection) {
        (None, None) => {
            if left.resource_type != right.resource_type {
                return Relation::Unknown;
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
        (None, Some(right_projection)) => {
            let Some(container) = right_projection
                .containers
                .iter()
                .find(|container| container.resource_type == left.resource_type)
            else {
                return Relation::Unknown;
            };
            let Ok(selector) = ScalarResourceSelector::try_from(&left.selector) else {
                return Relation::Unknown;
            };
            if selector.matches(&container.value) {
                Relation::Contains
            } else {
                Relation::Disjoint
            }
        }
        (Some(_), None) => match selector_relation(right, left) {
            Relation::Disjoint => Relation::Disjoint,
            _ => Relation::Unknown,
        },
        (Some(left_projection), Some(right_projection)) => {
            if left_projection.site_origin != right_projection.site_origin
                || coordinates_disjoint(&left_projection.containers, &right_projection.containers)
            {
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

fn coordinates_disjoint(left: &[ResourceContainer], right: &[ResourceContainer]) -> bool {
    left.iter().any(|left| {
        right
            .iter()
            .any(|right| left.resource_type == right.resource_type && left.value != right.value)
    })
}
