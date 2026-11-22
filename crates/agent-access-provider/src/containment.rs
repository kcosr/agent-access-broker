//! Typed containment evidence and immutable host-issued location authority.
//!
//! Authored selectors and observed locations are separate types. Evidence has
//! no deserializer: providers construct it after validating upstream facts.
use crate::{
    ResourceContainer, ResourceScopes, ResourceSelector, ResourceSelectorProjection, ResourceType,
    ResourceTypeRegistry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod matching;
#[cfg(test)]
mod tests;

const MAX_LOCATION_NODES: usize = 64;
const MAX_RELATED_ROOTS: usize = 256;
const MAX_OVERLAPPING_ROOTS: usize = 64;
const MAX_OPERATION_NODES: usize = 256;
const MAX_OBLIGATIONS: usize = 64;

/// How much current hierarchy the host requires. Container-only never stands
/// in for unknown ancestor evidence.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentEvidenceLevel {
    ContainerOnly,
    CompleteLineage,
}

/// The semantic effect a containment scope admits.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentEffect {
    Content,
    ChildPlacement,
    SubtreeImpact,
}

/// Why the target-to-parent edge is available. Signed locator facts remain
/// provisional until execution observes the actual object. A proposed region
/// is an explicit graph transform, not an observed upstream location.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentProvenance {
    Observed,
    SignedLocator,
    Proposed,
}

/// Native scope declaration. Kinds are provider-owned vocabulary, not inferred
/// by the policy engine from service or action names.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainmentScopeCapabilities {
    pub domain: String,
    pub selectors_by_type: BTreeMap<ResourceType, Vec<String>>,
    pub container_types: Vec<ResourceType>,
    pub target_kinds: Vec<String>,
    pub ancestor_kinds: Vec<String>,
    pub effects: Vec<ContainmentEffect>,
}

impl ContainmentScopeCapabilities {
    pub fn new(
        domain: impl Into<String>,
        selectors_by_type: BTreeMap<ResourceType, Vec<String>>,
        container_types: Vec<ResourceType>,
        target_kinds: Vec<String>,
        ancestor_kinds: Vec<String>,
        effects: Vec<ContainmentEffect>,
    ) -> Self {
        Self {
            domain: domain.into(),
            selectors_by_type,
            container_types,
            target_kinds,
            ancestor_kinds,
            effects,
        }
    }

    /// Validates descriptor shape without a registry or any upstream access.
    pub fn validate_shape(&self) -> Result<(), ContainmentError> {
        if !crate::location::is_kind(&self.domain)
            || self.selectors_by_type.is_empty()
            || self.selectors_by_type.len() > 16
            || self.container_types.is_empty()
            || self.container_types.len() > 8
            || self.target_kinds.is_empty()
            || self.target_kinds.len() > 16
            || self.ancestor_kinds.len() > 16
            || self.effects.is_empty()
            || self.effects.len() > 3
            || !unique(&self.container_types)
            || !unique(&self.target_kinds)
            || !unique(&self.ancestor_kinds)
            || !unique(&self.effects)
            || self
                .target_kinds
                .iter()
                .chain(&self.ancestor_kinds)
                .any(|kind| !crate::location::is_kind(kind))
        {
            return Err(ContainmentError::InvalidContract);
        }
        if self.selectors_by_type.values().any(|kinds| {
            kinds.is_empty()
                || kinds.len() > 3
                || !unique(kinds)
                || kinds
                    .iter()
                    .any(|kind| !matches!(kind.as_str(), "exact" | "all" | "subtree"))
        }) {
            return Err(ContainmentError::InvalidContract);
        }
        if self.effects.iter().any(|effect| {
            matches!(
                effect,
                ContainmentEffect::ChildPlacement | ContainmentEffect::SubtreeImpact
            )
        }) && self.ancestor_kinds.is_empty()
        {
            return Err(ContainmentError::InvalidContract);
        }
        Ok(())
    }

    pub fn validate(&self, registry: &ResourceTypeRegistry) -> Result<(), ContainmentError> {
        self.validate_shape()?;
        for (resource_type, kinds) in &self.selectors_by_type {
            let descriptor = registry
                .get(resource_type)
                .ok_or(ContainmentError::InvalidContract)?;
            if kinds.is_empty()
                || !unique(kinds)
                || !descriptor.attributes().is_empty()
                || kinds.iter().any(|kind| {
                    !matches!(kind.as_str(), "exact" | "all" | "subtree")
                        || !descriptor.selector_kinds().contains(&kind.as_str())
                })
            {
                return Err(ContainmentError::InvalidContract);
            }
        }
        for resource_type in &self.container_types {
            let selectors = self
                .selectors_by_type
                .get(resource_type)
                .ok_or(ContainmentError::InvalidContract)?;
            if selectors
                .iter()
                .any(|kind| !matches!(kind.as_str(), "exact" | "all"))
            {
                return Err(ContainmentError::InvalidContract);
            }
        }
        if self.effects.iter().any(|effect| {
            matches!(
                effect,
                ContainmentEffect::ChildPlacement | ContainmentEffect::SubtreeImpact
            )
        }) && self.ancestor_kinds.is_empty()
        {
            return Err(ContainmentError::InvalidContract);
        }
        Ok(())
    }

    /// Pure action-domain and site filtering. An exact selector remains relevant
    /// to a move's point anchor and negative descendant predicates; it does not
    /// by itself prove that the whole moved region is covered.
    pub fn selector_applicable(&self, selector: &TypedResourceSelector, site_origin: &str) -> bool {
        if self
            .selectors_by_type
            .get(selector.resource_type())
            .is_none_or(|kinds| !kinds.iter().any(|kind| kind == selector.selector().kind()))
        {
            return false;
        }
        match selector.projection() {
            None => {
                self.container_types.contains(selector.resource_type())
                    && matches!(
                        selector.selector(),
                        ResourceSelector::Exact { .. } | ResourceSelector::All
                    )
            }
            Some(projection) => {
                projection.site_origin == site_origin
                    && match selector.selector() {
                        ResourceSelector::Exact { .. } => {
                            self.effects
                                .iter()
                                .any(|effect| !matches!(effect, ContainmentEffect::ChildPlacement))
                                && self.target_kinds.contains(&projection.root_kind)
                        }
                        ResourceSelector::Subtree { .. } => {
                            self.ancestor_kinds.contains(&projection.root_kind)
                        }
                        _ => false,
                    }
            }
        }
    }
}

/// A canonical content identity, distinct from its observed containing space.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainmentIdentity {
    pub resource_type: ResourceType,
    pub content_kind: String,
    pub value: String,
}
impl ContainmentIdentity {
    pub fn new(
        resource_type: ResourceType,
        content_kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            resource_type,
            content_kind: content_kind.into(),
            value: value.into(),
        }
    }
}

/// One selectable ancestor with authenticated current container observations.
/// Evidence is provider-constructed, non-deserializable and redacted in Debug.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct ContainmentAncestor {
    pub identity: ContainmentIdentity,
    pub containers: Vec<ResourceContainer>,
}
impl ContainmentAncestor {
    pub fn new(identity: ContainmentIdentity, mut containers: Vec<ResourceContainer>) -> Self {
        containers.sort();
        Self {
            identity,
            containers,
        }
    }
}
impl std::fmt::Debug for ContainmentAncestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentAncestor")
            .finish_non_exhaustive()
    }
}

/// One point or parent with authenticated coordinates. Public ancestors contain
/// selectable kinds only, in immediate-parent-first order. Providers retain all
/// other typed edges privately and compare those graphs at the final fence.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct ContentLocation {
    pub target: ContainmentIdentity,
    pub containers: Vec<ResourceContainer>,
    pub ancestors: Vec<ContainmentAncestor>,
    pub evidence_level: ContainmentEvidenceLevel,
    pub provenance: ContainmentProvenance,
}
impl ContentLocation {
    pub fn new(
        target: ContainmentIdentity,
        mut containers: Vec<ResourceContainer>,
        evidence_level: ContainmentEvidenceLevel,
    ) -> Self {
        containers.sort();
        Self {
            target,
            containers,
            ancestors: Vec::new(),
            evidence_level,
            provenance: ContainmentProvenance::Observed,
        }
    }
    pub fn with_ancestors(mut self, ancestors: Vec<ContainmentAncestor>) -> Self {
        self.ancestors = ancestors;
        self
    }
    pub fn with_provenance(mut self, provenance: ContainmentProvenance) -> Self {
        self.provenance = provenance;
        self
    }
}
impl std::fmt::Debug for ContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentLocation")
            .field("evidence_level", &self.evidence_level)
            .field("provenance", &self.provenance)
            .field("ancestor_count", &self.ancestors.len())
            .finish_non_exhaustive()
    }
}

/// Every obligation in an operation must fit one grant and the independent token
/// boundary. Parent metadata does not implicitly become another content target.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentObligation {
    Content(ContentLocation),
    ChildPlacement(ContentLocation),
    SubtreeImpact {
        current: ContentLocation,
        proposed: ContentLocation,
    },
}
impl ContainmentObligation {
    pub fn effect(&self) -> ContainmentEffect {
        match self {
            Self::Content(_) => ContainmentEffect::Content,
            Self::ChildPlacement(_) => ContainmentEffect::ChildPlacement,
            Self::SubtreeImpact { .. } => ContainmentEffect::SubtreeImpact,
        }
    }
    pub fn target(&self) -> &ContainmentIdentity {
        match self {
            Self::Content(location)
            | Self::ChildPlacement(location)
            | Self::SubtreeImpact {
                current: location, ..
            } => &location.target,
        }
    }
}

/// Trusted operation evidence. No Deserialize implementation exists.
#[derive(Clone, PartialEq, Eq)]
pub struct ContainmentEvidence {
    domain: String,
    site_origin: String,
    obligations: Vec<ContainmentObligation>,
    related_roots: Vec<ContentLocation>,
}
impl ContainmentEvidence {
    pub fn new(
        domain: impl Into<String>,
        site_origin: impl Into<String>,
        obligations: Vec<ContainmentObligation>,
    ) -> Self {
        Self {
            domain: domain.into(),
            site_origin: site_origin.into(),
            obligations,
            related_roots: Vec::new(),
        }
    }
    pub fn with_related_roots(mut self, roots: Vec<ContentLocation>) -> Self {
        self.related_roots = roots;
        self
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn site_origin(&self) -> &str {
        &self.site_origin
    }
    pub fn obligations(&self) -> &[ContainmentObligation] {
        &self.obligations
    }
    pub fn related_roots(&self) -> &[ContentLocation] {
        &self.related_roots
    }

    pub fn validate(
        &self,
        contract: &ContainmentScopeCapabilities,
        registry: &ResourceTypeRegistry,
        required_level: ContainmentEvidenceLevel,
    ) -> Result<(), ContainmentError> {
        contract.validate(registry)?;
        if self.domain != contract.domain
            || !crate::location::is_canonical_https_dns_origin(&self.site_origin)
            || self.obligations.is_empty()
            || self.obligations.len() > MAX_OBLIGATIONS
        {
            return Err(ContainmentError::InvalidEvidence);
        }
        if self.related_roots.len() > MAX_RELATED_ROOTS {
            return Err(ContainmentError::BudgetExceeded);
        }
        if !self.related_roots.is_empty()
            && !self
                .obligations
                .iter()
                .any(|obligation| matches!(obligation, ContainmentObligation::SubtreeImpact { .. }))
        {
            return Err(ContainmentError::InvalidEvidence);
        }
        let mut roles = BTreeSet::new();
        let mut effects = BTreeSet::new();
        let mut nodes = BTreeMap::new();
        for obligation in &self.obligations {
            let effect = obligation.effect();
            if !contract.effects.contains(&effect) || !roles.insert((effect, obligation.target())) {
                return Err(ContainmentError::InvalidEvidence);
            }
            effects.insert(effect);
            match obligation {
                ContainmentObligation::Content(location) => {
                    if location.provenance == ContainmentProvenance::Proposed {
                        return Err(ContainmentError::InvalidEvidence);
                    }
                    validate_location(
                        location,
                        contract,
                        registry,
                        required_level,
                        &self.site_origin,
                        &contract.target_kinds,
                        &mut nodes,
                    )?;
                }
                ContainmentObligation::ChildPlacement(location) => {
                    if location.provenance != ContainmentProvenance::Observed {
                        return Err(ContainmentError::InvalidEvidence);
                    }
                    validate_location(
                        location,
                        contract,
                        registry,
                        required_level,
                        &self.site_origin,
                        &contract.ancestor_kinds,
                        &mut nodes,
                    )?;
                }
                ContainmentObligation::SubtreeImpact { current, proposed } => {
                    if current.target != proposed.target
                        || current.containers != proposed.containers
                        || current.provenance != ContainmentProvenance::Observed
                        || proposed.provenance != ContainmentProvenance::Proposed
                    {
                        return Err(ContainmentError::InvalidEvidence);
                    }
                    validate_location(
                        current,
                        contract,
                        registry,
                        ContainmentEvidenceLevel::CompleteLineage,
                        &self.site_origin,
                        &contract.target_kinds,
                        &mut nodes,
                    )?;
                    validate_location(
                        proposed,
                        contract,
                        registry,
                        ContainmentEvidenceLevel::CompleteLineage,
                        &self.site_origin,
                        &contract.target_kinds,
                        &mut nodes,
                    )?;
                }
            }
        }
        if effects != contract.effects.iter().copied().collect() {
            return Err(ContainmentError::InvalidEvidence);
        }
        let mut roots = BTreeSet::new();
        let mut overlapping_roots = 0;
        for root in &self.related_roots {
            if !roots.insert(&root.target) || root.provenance != ContainmentProvenance::Observed {
                return Err(ContainmentError::InvalidEvidence);
            }
            let kinds: Vec<_> = contract
                .target_kinds
                .iter()
                .chain(&contract.ancestor_kinds)
                .cloned()
                .collect();
            let disjoint = self.obligations.iter().all(|obligation| {
                let ContainmentObligation::SubtreeImpact { current, proposed } = obligation else {
                    return true;
                };
                matching::coordinates_disjoint(&root.containers, &current.containers)
                    && matching::coordinates_disjoint(&root.containers, &proposed.containers)
            });
            if !disjoint {
                overlapping_roots += 1;
                if overlapping_roots > MAX_OVERLAPPING_ROOTS {
                    return Err(ContainmentError::BudgetExceeded);
                }
            }
            validate_location(
                root,
                contract,
                registry,
                if disjoint {
                    ContainmentEvidenceLevel::ContainerOnly
                } else {
                    ContainmentEvidenceLevel::CompleteLineage
                },
                &self.site_origin,
                &kinds,
                &mut nodes,
            )?;
        }
        if nodes.len() > MAX_OPERATION_NODES {
            return Err(ContainmentError::BudgetExceeded);
        }
        // A proposed region must use the admitted destination parent chain. This
        // checks the public transform; the provider additionally checks private
        // nonselectable edges and upstream ordering/cycle constraints.
        for obligation in &self.obligations {
            if let ContainmentObligation::SubtreeImpact { proposed, .. } = obligation {
                let valid_destination = self.obligations.iter().any(|candidate| {
                    let ContainmentObligation::ChildPlacement(parent) = candidate else {
                        return false;
                    };
                    proposed.containers == parent.containers
                        && proposed.ancestors.first().is_some_and(|ancestor| {
                            ancestor.identity == parent.target
                                && ancestor.containers == parent.containers
                        })
                        && proposed.ancestors[1..] == parent.ancestors
                });
                if !valid_destination {
                    return Err(ContainmentError::InvalidEvidence);
                }
            }
        }
        Ok(())
    }

    /// Operated locations only; never relation probes or incidental ancestors.
    pub fn projection(&self, scope_name: &str) -> ResourceScopes {
        let values: BTreeSet<_> = self
            .obligations
            .iter()
            .map(|obligation| obligation.target().value.clone())
            .collect();
        BTreeMap::from([(scope_name.to_owned(), values.into_iter().collect())])
    }

    pub fn has_signed_locator(&self) -> bool {
        self.obligations.iter().any(|obligation| matches!(obligation, ContainmentObligation::Content(location) if location.provenance == ContainmentProvenance::SignedLocator))
    }
}
impl std::fmt::Debug for ContainmentEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentEvidence")
            .field("domain", &self.domain)
            .field("obligation_count", &self.obligations.len())
            .field("related_root_count", &self.related_roots.len())
            .finish_non_exhaustive()
    }
}

fn validate_location<'a>(
    location: &'a ContentLocation,
    contract: &ContainmentScopeCapabilities,
    registry: &ResourceTypeRegistry,
    required_level: ContainmentEvidenceLevel,
    origin: &str,
    target_kinds: &[String],
    nodes: &mut BTreeMap<&'a ContainmentIdentity, &'a [ResourceContainer]>,
) -> Result<(), ContainmentError> {
    if location.evidence_level < required_level {
        return Err(ContainmentError::InsufficientEvidence);
    }
    if location.ancestors.len() >= MAX_LOCATION_NODES
        || !target_kinds.contains(&location.target.content_kind)
        || (location.evidence_level == ContainmentEvidenceLevel::ContainerOnly
            && !location.ancestors.is_empty())
    {
        return Err(ContainmentError::InvalidEvidence);
    }
    let mut lineage = BTreeSet::new();
    for (index, (identity, containers)) in std::iter::once((&location.target, &location.containers))
        .chain(
            location
                .ancestors
                .iter()
                .map(|ancestor| (&ancestor.identity, &ancestor.containers)),
        )
        .enumerate()
    {
        if containers.len() != contract.container_types.len()
            || containers != &location.containers
            || !lineage.insert(identity)
            || (index > 0 && !contract.ancestor_kinds.contains(&identity.content_kind))
            || !contract
                .selectors_by_type
                .contains_key(&identity.resource_type)
            || contract.container_types.contains(&identity.resource_type)
        {
            return Err(ContainmentError::InvalidEvidence);
        }
        let mut types = BTreeSet::new();
        for container in containers {
            if !contract.container_types.contains(&container.resource_type)
                || !types.insert(&container.resource_type)
                || registry
                    .get(&container.resource_type)
                    .is_none_or(|descriptor| !descriptor.is_canonical_target(&container.value))
            {
                return Err(ContainmentError::InvalidEvidence);
            }
        }
        let descriptor = registry
            .get(&identity.resource_type)
            .ok_or(ContainmentError::InvalidEvidence)?;
        let projection = descriptor
            .project_target(&identity.value)
            .map_err(|_| ContainmentError::InvalidEvidence)?
            .ok_or(ContainmentError::InvalidEvidence)?;
        projection
            .validate()
            .map_err(|_| ContainmentError::InvalidEvidence)?;
        if projection.site_origin != origin || projection.root_kind != identity.content_kind {
            return Err(ContainmentError::InvalidEvidence);
        }
        if nodes
            .insert(identity, containers)
            .is_some_and(|previous| previous != containers)
        {
            return Err(ContainmentError::InvalidEvidence);
        }
        if nodes.len() > MAX_OPERATION_NODES {
            return Err(ContainmentError::BudgetExceeded);
        }
    }
    Ok(())
}

/// One validated authored selector. Serialization deliberately contains only
/// policy-authored fields; the pure projection is rehydrated through a registry.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedResourceSelector {
    resource_type: ResourceType,
    selector: ResourceSelector,
    #[serde(skip)]
    projection: Option<ResourceSelectorProjection>,
}
impl TypedResourceSelector {
    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }
    pub fn selector(&self) -> &ResourceSelector {
        &self.selector
    }
    pub fn projection(&self) -> Option<&ResourceSelectorProjection> {
        self.projection.as_ref()
    }
}
impl std::fmt::Debug for TypedResourceSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedResourceSelector")
            .field("resource_type", &self.resource_type)
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}
impl ResourceTypeRegistry {
    pub fn typed_selector(
        &self,
        resource_type: &ResourceType,
        selector: &ResourceSelector,
    ) -> Result<TypedResourceSelector, ContainmentError> {
        let descriptor = self
            .get(resource_type)
            .ok_or(ContainmentError::InvalidSelector)?;
        let projection = descriptor
            .project_selector(selector)
            .map_err(|_| ContainmentError::InvalidSelector)?;
        if let Some(projection) = &projection {
            projection
                .validate()
                .map_err(|_| ContainmentError::InvalidSelector)?;
        }
        if matches!(selector, ResourceSelector::Subtree { .. }) && projection.is_none() {
            return Err(ContainmentError::InvalidSelector);
        }
        Ok(TypedResourceSelector {
            resource_type: resource_type.clone(),
            selector: selector.clone(),
            projection,
        })
    }
}

/// One grant or token selection, retaining grant-local exclusions.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ContainmentBoundary {
    included: Vec<TypedResourceSelector>,
    excluded: Vec<TypedResourceSelector>,
}
impl ContainmentBoundary {
    pub fn new(
        mut included: Vec<TypedResourceSelector>,
        mut excluded: Vec<TypedResourceSelector>,
    ) -> Self {
        included.sort();
        included.dedup();
        excluded.sort();
        excluded.dedup();
        Self { included, excluded }
    }
    pub fn included(&self) -> &[TypedResourceSelector] {
        &self.included
    }
    pub fn excluded(&self) -> &[TypedResourceSelector] {
        &self.excluded
    }
    pub fn is_empty(&self) -> bool {
        self.included.is_empty()
    }
}
impl std::fmt::Debug for ContainmentBoundary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentBoundary")
            .field("included_count", &self.included.len())
            .field("excluded_count", &self.excluded.len())
            .finish_non_exhaustive()
    }
}

/// A conservative authored-identity proof. Empty proves no possible member;
/// Covered proves the requested predicate (nonemptiness or complete coverage,
/// as documented by the method); Conditional requires live relationships.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineContainmentProof {
    Empty,
    Covered,
    Conditional,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentError {
    #[error("containment declaration is invalid")]
    InvalidContract,
    #[error("containment evidence is invalid")]
    InvalidEvidence,
    #[error("containment evidence is less complete than required")]
    InsufficientEvidence,
    #[error("containment relationship could not be established")]
    UnresolvedRelation,
    #[error("admitted content location changed")]
    ChangedLocation,
    #[error("containment selector is invalid")]
    InvalidSelector,
    #[error("containment evidence exceeds its budget")]
    BudgetExceeded,
}
impl From<ContainmentError> for crate::ProviderError {
    fn from(error: ContainmentError) -> Self {
        match error {
            ContainmentError::UnresolvedRelation
            | ContainmentError::ChangedLocation
            | ContainmentError::BudgetExceeded => crate::ProviderError::deny(
                crate::ReasonCode::ScopeUnresolved,
                "content location could not be confirmed",
            ),
            _ => crate::host::port_failure(
                crate::host::HostPort::AdmittedOperation,
                crate::ProviderError::error(
                    crate::ReasonCode::BrokerProviderContractFailed,
                    "provider containment contract failed",
                )
                .with_internal_diagnostic_code("provider_containment_invalid"),
            ),
        }
    }
}

/// Exact admitted operation and required evidence, created through the host port.
#[derive(Clone)]
pub struct ContainmentAuthorization {
    contract: ContainmentScopeCapabilities,
    evidence: ContainmentEvidence,
    evidence_level: ContainmentEvidenceLevel,
    authority_digest: String,
    registry: ResourceTypeRegistry,
}
impl ContainmentAuthorization {
    pub(crate) fn new(
        site_origin: &str,
        contract: ContainmentScopeCapabilities,
        evidence: ContainmentEvidence,
        registry: &ResourceTypeRegistry,
        evidence_level: ContainmentEvidenceLevel,
        authority_digest: String,
    ) -> Result<Self, ContainmentError> {
        if evidence.site_origin != site_origin || !valid_digest(&authority_digest) {
            return Err(ContainmentError::InvalidEvidence);
        }
        evidence.validate(&contract, registry, evidence_level)?;
        Ok(Self {
            contract,
            evidence,
            evidence_level,
            authority_digest,
            registry: registry.clone(),
        })
    }
    pub fn contract(&self) -> &ContainmentScopeCapabilities {
        &self.contract
    }
    pub fn evidence(&self) -> &ContainmentEvidence {
        &self.evidence
    }
    pub fn evidence_level(&self) -> ContainmentEvidenceLevel {
        self.evidence_level
    }
    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }
    pub fn check_same_location(&self, fresh: &ContainmentEvidence) -> Result<(), ContainmentError> {
        fresh.validate(&self.contract, &self.registry, self.evidence_level)?;
        if self.evidence.site_origin != fresh.site_origin
            || self.evidence.domain != fresh.domain
            || self.evidence.obligations.len() != fresh.obligations.len()
            || self.evidence.related_roots.len() != fresh.related_roots.len()
        {
            return Err(ContainmentError::ChangedLocation);
        }
        for (admitted, current) in self.evidence.obligations.iter().zip(&fresh.obligations) {
            match (admitted, current) {
                (ContainmentObligation::Content(before), ContainmentObligation::Content(after))
                | (
                    ContainmentObligation::ChildPlacement(before),
                    ContainmentObligation::ChildPlacement(after),
                ) => same_location(before, after, self.evidence_level)?,
                (
                    ContainmentObligation::SubtreeImpact {
                        current: before_current,
                        proposed: before_proposed,
                    },
                    ContainmentObligation::SubtreeImpact {
                        current: after_current,
                        proposed: after_proposed,
                    },
                ) => {
                    same_location(
                        before_current,
                        after_current,
                        ContainmentEvidenceLevel::CompleteLineage,
                    )?;
                    same_location(
                        before_proposed,
                        after_proposed,
                        ContainmentEvidenceLevel::CompleteLineage,
                    )?;
                }
                _ => return Err(ContainmentError::ChangedLocation),
            }
        }
        for (before, after) in self.evidence.related_roots.iter().zip(&fresh.related_roots) {
            same_location(
                before,
                after,
                before.evidence_level.max(after.evidence_level),
            )?;
        }
        Ok(())
    }
}
impl std::fmt::Debug for ContainmentAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentAuthorization")
            .field("domain", &self.contract.domain)
            .field("evidence_level", &self.evidence_level)
            .finish_non_exhaustive()
    }
}

fn same_location(
    before: &ContentLocation,
    after: &ContentLocation,
    level: ContainmentEvidenceLevel,
) -> Result<(), ContainmentError> {
    if before.target != after.target
        || before.containers != after.containers
        || (level == ContainmentEvidenceLevel::CompleteLineage
            && before.ancestors != after.ancestors)
    {
        return Err(ContainmentError::ChangedLocation);
    }
    // A fresh pass must observe the provisional edge rather than recycling a
    // signed locator. Provider private state also checks its immediate typed edge.
    if after.provenance == ContainmentProvenance::SignedLocator {
        return Err(ContainmentError::InvalidEvidence);
    }
    Ok(())
}

/// One immutable collection band and mode, with its independent token ceiling.
#[derive(Clone)]
pub struct ContainmentCollectionAuthorization {
    site_origin: String,
    contract: ContainmentScopeCapabilities,
    grant_boundaries: Vec<ContainmentBoundary>,
    token_boundary: Option<ContainmentBoundary>,
    evidence_level: ContainmentEvidenceLevel,
    authority_digest: String,
    registry: ResourceTypeRegistry,
}
impl ContainmentCollectionAuthorization {
    pub(crate) fn new(
        site_origin: &str,
        contract: ContainmentScopeCapabilities,
        grant_boundaries: Vec<ContainmentBoundary>,
        token_boundary: Option<ContainmentBoundary>,
        registry: &ResourceTypeRegistry,
        evidence_level: ContainmentEvidenceLevel,
        authority_digest: String,
    ) -> Result<Self, ContainmentError> {
        contract.validate(registry)?;
        if !crate::location::is_canonical_https_dns_origin(site_origin)
            || !valid_digest(&authority_digest)
            || contract.effects != [ContainmentEffect::Content]
            || grant_boundaries.is_empty()
        {
            return Err(ContainmentError::InvalidContract);
        }
        for boundary in grant_boundaries.iter().chain(token_boundary.iter()) {
            if boundary
                .included
                .iter()
                .chain(&boundary.excluded)
                .any(|selector| !contract.selector_applicable(selector, site_origin))
            {
                return Err(ContainmentError::InvalidSelector);
            }
            if evidence_level == ContainmentEvidenceLevel::ContainerOnly
                && boundary
                    .included
                    .iter()
                    .chain(&boundary.excluded)
                    .any(|selector| matches!(selector.selector(), ResourceSelector::Subtree { .. }))
            {
                return Err(ContainmentError::InsufficientEvidence);
            }
        }
        Ok(Self {
            site_origin: site_origin.into(),
            contract,
            grant_boundaries,
            token_boundary,
            evidence_level,
            authority_digest,
            registry: registry.clone(),
        })
    }
    pub fn site_origin(&self) -> &str {
        &self.site_origin
    }
    pub fn contract(&self) -> &ContainmentScopeCapabilities {
        &self.contract
    }
    pub fn grant_boundaries(&self) -> &[ContainmentBoundary] {
        &self.grant_boundaries
    }
    pub fn token_boundary(&self) -> Option<&ContainmentBoundary> {
        self.token_boundary.as_ref()
    }
    pub fn evidence_level(&self) -> ContainmentEvidenceLevel {
        self.evidence_level
    }
    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }
    /// True only when every selected grant and token selector is a declared
    /// scalar container Exact/All and no hierarchy proof is required.
    pub fn uses_only_scalar_container_selectors(&self) -> bool {
        self.evidence_level == ContainmentEvidenceLevel::ContainerOnly
            && self
                .grant_boundaries
                .iter()
                .chain(self.token_boundary.iter())
                .all(|boundary| {
                    boundary
                        .included
                        .iter()
                        .chain(&boundary.excluded)
                        .all(|selector| {
                            selector.projection.is_none()
                                && self
                                    .contract
                                    .container_types
                                    .contains(&selector.resource_type)
                                && matches!(
                                    selector.selector,
                                    ResourceSelector::Exact { .. } | ResourceSelector::All
                                )
                        })
                })
    }
    pub fn matches_candidate(&self, candidate: &ContentLocation) -> Result<bool, ContainmentError> {
        if candidate.provenance != ContainmentProvenance::Observed {
            return Err(ContainmentError::InvalidEvidence);
        }
        let evidence = ContainmentEvidence::new(
            &self.contract.domain,
            &self.site_origin,
            vec![ContainmentObligation::Content(candidate.clone())],
        );
        evidence.validate(&self.contract, &self.registry, self.evidence_level)?;
        let mut allowed = false;
        for boundary in &self.grant_boundaries {
            allowed |= boundary.matches_evidence(&evidence)?;
        }
        if let Some(token) = &self.token_boundary {
            allowed &= token.matches_evidence(&evidence)?;
        }
        Ok(allowed)
    }

    /// Proves nonempty intersection with a requested container, preserving
    /// grant-local exclusions and the token conjunction. Conditional is usable
    /// as a query restriction; only Empty proves the requested key unauthorized.
    pub fn requested_container_coverage(
        &self,
        container: &ResourceContainer,
    ) -> OfflineContainmentProof {
        if !self
            .contract
            .container_types
            .contains(&container.resource_type)
            || self
                .registry
                .get(&container.resource_type)
                .is_none_or(|descriptor| !descriptor.is_canonical_target(&container.value))
        {
            return OfflineContainmentProof::Empty;
        }
        let Ok(selector) = self.registry.typed_selector(
            &container.resource_type,
            &ResourceSelector::Exact {
                value: container.value.clone(),
            },
        ) else {
            return OfflineContainmentProof::Empty;
        };
        let restriction = ContainmentBoundary::new(vec![selector], vec![]);
        let mut conditional = false;
        for boundary in &self.grant_boundaries {
            let mut operands = vec![boundary, &restriction];
            if let Some(token) = &self.token_boundary {
                operands.push(token);
            }
            let proof = matching::prove_conjunction(&operands, &self.contract, &self.site_origin);
            match proof {
                OfflineContainmentProof::Covered => return OfflineContainmentProof::Covered,
                OfflineContainmentProof::Conditional => conditional = true,
                OfflineContainmentProof::Empty => {}
            }
        }
        if conditional {
            OfflineContainmentProof::Conditional
        } else {
            OfflineContainmentProof::Empty
        }
    }
}
impl std::fmt::Debug for ContainmentCollectionAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentCollectionAuthorization")
            .field("domain", &self.contract.domain)
            .field("grant_boundary_count", &self.grant_boundaries.len())
            .field("has_token_boundary", &self.token_boundary.is_some())
            .field("evidence_level", &self.evidence_level)
            .finish_non_exhaustive()
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
