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
    let negatives: Vec<_> = boundaries
        .iter()
        .flat_map(|boundary| &boundary.excluded)
        .filter(|selector| contract.selector_applicable(selector, site_origin))
        .collect();
    let negative_index = KnownSelectorIndex::new(negatives.iter().copied());
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
                            && !negative_index.contains(selector)
                    })
                    .collect()
            })
            .collect();
        if choices.iter().any(Vec::is_empty) {
            return OfflineContainmentProof::Empty;
        }
        let proof = prove_known_relations(&choices, &negative_index).unwrap_or_else(|| {
            let mut selected = Vec::with_capacity(boundaries.len());
            prove_choices(
                &choices,
                &negatives,
                &mut selected,
                contract,
                &mut remaining,
            )
        });
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

/// Index only relations that are decided by the stable selector contract.
/// Every input has already been filtered to one scope/site/effect. Scalar All
/// covers that whole domain; a finite container is never inferred for content.
type ContentSelectorKey<'a> = (&'a ResourceType, &'a str, &'a str);

#[derive(Default)]
struct KnownSelectorIndex<'a> {
    all: bool,
    scalar_exact: BTreeMap<&'a ResourceType, BTreeSet<&'a str>>,
    content_exact: BTreeSet<ContentSelectorKey<'a>>,
    content_subtree: BTreeSet<ContentSelectorKey<'a>>,
}

impl<'a> KnownSelectorIndex<'a> {
    fn new(selectors: impl IntoIterator<Item = &'a TypedResourceSelector>) -> Self {
        let mut index = Self::default();
        for selector in selectors {
            match (selector.projection(), selector.selector()) {
                (None, ResourceSelector::All) => index.all = true,
                (None, ResourceSelector::Exact { value }) => {
                    index
                        .scalar_exact
                        .entry(selector.resource_type())
                        .or_default()
                        .insert(value);
                }
                (Some(projection), ResourceSelector::Exact { value }) => {
                    index.content_exact.insert((
                        selector.resource_type(),
                        &projection.root_kind,
                        value,
                    ));
                }
                (Some(projection), ResourceSelector::Subtree { value }) => {
                    index.content_subtree.insert((
                        selector.resource_type(),
                        &projection.root_kind,
                        value,
                    ));
                }
                _ => {}
            }
        }
        index
    }

    fn is_empty(&self) -> bool {
        !self.all
            && self.scalar_exact.is_empty()
            && self.content_exact.is_empty()
            && self.content_subtree.is_empty()
    }

    /// Whether one indexed positive contains the complete witness selector.
    fn contains(&self, witness: &TypedResourceSelector) -> bool {
        if self.all {
            return true;
        }
        match (witness.projection(), witness.selector()) {
            (None, ResourceSelector::Exact { value }) => self
                .scalar_exact
                .get(witness.resource_type())
                .is_some_and(|values| values.contains(value.as_str())),
            (Some(projection), ResourceSelector::Exact { value }) => {
                let key = (
                    witness.resource_type(),
                    projection.root_kind.as_str(),
                    value.as_str(),
                );
                self.content_exact.contains(&key) || self.content_subtree.contains(&key)
            }
            (Some(projection), ResourceSelector::Subtree { value }) => {
                self.content_subtree.contains(&(
                    witness.resource_type(),
                    projection.root_kind.as_str(),
                    value.as_str(),
                ))
            }
            _ => false,
        }
    }

    /// Every negative must be proven disjoint. Unknown cross-dimension,
    /// container/content and distinct-subtree relations remain unknown.
    fn disjoint_from(&self, witness: &TypedResourceSelector) -> bool {
        if self.all {
            return false;
        }
        match (witness.projection(), witness.selector()) {
            (None, ResourceSelector::Exact { value }) => {
                self.content_exact.is_empty()
                    && self.content_subtree.is_empty()
                    && self.scalar_exact.iter().all(|(resource_type, values)| {
                        *resource_type == witness.resource_type()
                            && !values.contains(value.as_str())
                    })
            }
            (Some(projection), ResourceSelector::Exact { value }) => {
                self.scalar_exact.is_empty()
                    && self.content_subtree.is_empty()
                    && !self.content_exact.contains(&(
                        witness.resource_type(),
                        projection.root_kind.as_str(),
                        value.as_str(),
                    ))
            }
            (None, ResourceSelector::All) | (Some(_), ResourceSelector::Subtree { .. }) => {
                self.is_empty()
            }
            _ => false,
        }
    }

    fn scalar_partition(&self) -> Option<(&ResourceType, &BTreeSet<&'a str>)> {
        if self.all
            || !self.content_exact.is_empty()
            || !self.content_subtree.is_empty()
            || self.scalar_exact.len() != 1
        {
            return None;
        }
        self.scalar_exact
            .iter()
            .next()
            .map(|(resource_type, values)| (*resource_type, values))
    }

    fn content_partition(&self) -> Option<&BTreeSet<ContentSelectorKey<'a>>> {
        (!self.all
            && self.scalar_exact.is_empty()
            && self.content_subtree.is_empty()
            && !self.content_exact.is_empty())
        .then_some(&self.content_exact)
    }
}

/// Set lookups decide cheap relations before bounded relationship search. This
/// is linearithmic in the input lists, with at most three operands and no
/// Cartesian-product allocation. Large disjoint exact sets and a late shared
/// identity therefore do not consume the budget for unresolved relationships.
fn prove_known_relations(
    choices: &[Vec<&TypedResourceSelector>],
    negatives: &KnownSelectorIndex<'_>,
) -> Option<OfflineContainmentProof> {
    let indexes: Vec<_> = choices
        .iter()
        .map(|choices| KnownSelectorIndex::new(choices.iter().copied()))
        .collect();
    if choices.iter().flatten().any(|witness| {
        indexes.iter().all(|index| index.contains(witness)) && negatives.disjoint_from(witness)
    }) {
        return Some(OfflineContainmentProof::Covered);
    }
    // Any contradiction among whole operands disproves the full conjunction,
    // including scalar token/requested-container operands beside content roots.
    for index in &indexes {
        if let Some((resource_type, values)) = index.scalar_partition() {
            let possible = values.iter().any(|value| {
                indexes.iter().all(|other| {
                    other
                        .scalar_partition()
                        .is_none_or(|(other_type, other_values)| {
                            other_type != resource_type || other_values.contains(value)
                        })
                })
            });
            if !possible {
                return Some(OfflineContainmentProof::Empty);
            }
        }
        if let Some(values) = index.content_partition() {
            let possible = values.iter().any(|value| {
                indexes.iter().all(|other| {
                    other
                        .content_partition()
                        .is_none_or(|other_values| other_values.contains(value))
                })
            });
            if !possible {
                return Some(OfflineContainmentProof::Empty);
            }
        }
    }
    None
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
