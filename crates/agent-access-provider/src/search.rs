//! Normalized search authority, shared by native providers and host policy consumers.
use crate::ResourceSelector;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

/// One independently granted region: included selectors minus its exclusions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SearchAuthorizationClause {
    included: Vec<ResourceSelector>,
    excluded: Vec<ResourceSelector>,
}

impl SearchAuthorizationClause {
    /// Normalize a clause using the shared selector algebra. Exclusions remain local.
    pub fn new(mut included: Vec<ResourceSelector>, mut excluded: Vec<ResourceSelector>) -> Self {
        included.sort();
        included.dedup();
        excluded.sort();
        excluded.dedup();
        let included: Vec<_> = included
            .iter()
            .enumerate()
            .filter(|(index, selector)| {
                !excluded.iter().any(|negative| negative.contains(selector))
                    && !included
                        .iter()
                        .enumerate()
                        .any(|(other, broad)| other != *index && broad.contains(selector))
            })
            .map(|(_, selector)| selector.clone())
            .collect();
        let excluded = excluded
            .iter()
            .enumerate()
            .filter(|(index, selector)| {
                included
                    .iter()
                    .any(|positive| positive.intersection(selector).is_some())
                    && !excluded
                        .iter()
                        .enumerate()
                        .any(|(other, broad)| other != *index && broad.contains(selector))
            })
            .map(|(_, selector)| selector.clone())
            .collect();
        Self { included, excluded }
    }

    pub fn included(&self) -> &[ResourceSelector] {
        &self.included
    }
    pub fn excluded(&self) -> &[ResourceSelector] {
        &self.excluded
    }
    pub fn matches(&self, value: &str) -> bool {
        self.included.iter().any(|selector| selector.matches(value))
            && !self.excluded.iter().any(|selector| selector.matches(value))
    }
    pub fn is_empty(&self) -> bool {
        self.included.is_empty()
    }
    pub fn intersection(&self, other: &Self) -> Self {
        Self::new(
            self.included
                .iter()
                .flat_map(|left| {
                    other
                        .included
                        .iter()
                        .filter_map(|right| left.intersection(right))
                })
                .collect(),
            self.excluded
                .iter()
                .chain(&other.excluded)
                .cloned()
                .collect(),
        )
    }
    /// C \\ (I \\ E) = (C \\ I) union (C intersect E).
    pub fn subtract(&self, other: &Self) -> Vec<Self> {
        let mut exclusions = self.excluded.clone();
        exclusions.extend(other.included.iter().cloned());
        let outside = Self::new(self.included.clone(), exclusions);
        let inside = self.intersection(&Self::new(other.excluded.clone(), Vec::new()));
        [outside, inside]
            .into_iter()
            .filter(|clause| !clause.is_empty())
            .collect()
    }
}

impl<'de> Deserialize<'de> for SearchAuthorizationClause {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            included: Vec<ResourceSelector>,
            excluded: Vec<ResourceSelector>,
        }
        let input = Input::deserialize(deserializer)?;
        Ok(Self::new(input.included, input.excluded))
    }
}

/// The union of independent normalized search clauses. No clauses admits nothing.
/// Construct this authority through its constructors; never flatten exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SearchAuthorizationScope {
    clauses: Vec<SearchAuthorizationClause>,
}

impl SearchAuthorizationScope {
    pub fn new(clauses: Vec<SearchAuthorizationClause>) -> Self {
        let mut clauses: Vec<_> = clauses
            .into_iter()
            .filter(|clause| !clause.is_empty())
            .collect();
        clauses.sort();
        clauses.dedup();
        // Remove clauses covered by the complete union of the others, not by an overlap.
        let mut index = clauses.len();
        while index > 0 {
            index -= 1;
            let mut remaining = vec![clauses[index].clone()];
            for (other, clause) in clauses.iter().enumerate() {
                if other != index {
                    remaining = remaining
                        .iter()
                        .flat_map(|part| part.subtract(clause))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                }
            }
            if remaining.is_empty() {
                clauses.remove(index);
            }
        }
        Self { clauses }
    }
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn from_selectors(
        included: Vec<ResourceSelector>,
        excluded: Vec<ResourceSelector>,
    ) -> Self {
        Self::new(vec![SearchAuthorizationClause::new(included, excluded)])
    }
    /// Construct a clause from exact positive values.
    pub fn from_exact_values(values: Vec<String>) -> Self {
        Self::from_selectors(
            values
                .into_iter()
                .map(|value| ResourceSelector::Exact { value })
                .collect(),
            Vec::new(),
        )
    }
    /// Construct an all clause with exact exclusions.
    pub fn excluding_exact_values(values: Vec<String>) -> Self {
        Self::from_selectors(
            vec![ResourceSelector::All],
            values
                .into_iter()
                .map(|value| ResourceSelector::Exact { value })
                .collect(),
        )
    }
    pub fn clauses(&self) -> &[SearchAuthorizationClause] {
        &self.clauses
    }
    pub fn matches(&self, value: &str) -> bool {
        self.clauses.iter().any(|clause| clause.matches(value))
    }
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }
    pub fn is_universe(&self) -> bool {
        self.covers(&ResourceSelector::All)
    }
    /// Prove coverage by subtracting every clause from the requested selector.
    pub fn covers(&self, selector: &ResourceSelector) -> bool {
        let mut remaining = vec![SearchAuthorizationClause::new(
            vec![selector.clone()],
            Vec::new(),
        )];
        for clause in &self.clauses {
            remaining = remaining
                .iter()
                .flat_map(|part| part.subtract(clause))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        }
        remaining.is_empty()
    }
    pub fn union(&self, other: &Self) -> Self {
        Self::new(self.clauses.iter().chain(&other.clauses).cloned().collect())
    }
    pub fn intersection(&self, other: &Self) -> Self {
        Self::new(
            self.clauses
                .iter()
                .flat_map(|left| other.clauses.iter().map(|right| left.intersection(right)))
                .collect(),
        )
    }
    /// Lossy envelope summary; never sufficient for authorization.
    pub fn resource_scope_summary(&self) -> Vec<String> {
        if self.clauses.iter().any(|clause| {
            clause
                .included
                .iter()
                .any(|selector| !matches!(selector, ResourceSelector::Exact { .. }))
        }) {
            return vec!["*".into()];
        }
        self.clauses
            .iter()
            .flat_map(|clause| &clause.included)
            .filter_map(|selector| match selector {
                ResourceSelector::Exact { value } if self.matches(value) => Some(value.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    /// Derive the exact-only query representation. Namespace authority is a contract error.
    pub fn exact_projection(&self) -> Result<ExactSearchProjection, SearchProjectionError> {
        let mut finite = BTreeSet::new();
        let mut exclusions: Option<BTreeSet<String>> = None;
        for clause in &self.clauses {
            if clause
                .included
                .iter()
                .chain(&clause.excluded)
                .any(|selector| {
                    !matches!(
                        selector,
                        ResourceSelector::Exact { .. } | ResourceSelector::All
                    )
                })
            {
                return Err(SearchProjectionError);
            }
            if clause.included.contains(&ResourceSelector::All) {
                let current: BTreeSet<_> = clause
                    .excluded
                    .iter()
                    .filter_map(|selector| match selector {
                        ResourceSelector::Exact { value } => Some(value.clone()),
                        _ => None,
                    })
                    .collect();
                exclusions = Some(exclusions.map_or_else(
                    || current.clone(),
                    |prior| prior.intersection(&current).cloned().collect(),
                ));
            } else {
                finite.extend(
                    clause
                        .included
                        .iter()
                        .filter_map(|selector| match selector {
                            ResourceSelector::Exact { value } if clause.matches(value) => {
                                Some(value.clone())
                            }
                            _ => None,
                        }),
                );
            }
        }
        Ok(match exclusions {
            Some(excluded) => ExactSearchProjection::AllExcept {
                excluded_values: excluded.difference(&finite).cloned().collect(),
            },
            None => ExactSearchProjection::Finite {
                values: finite.into_iter().collect(),
            },
        })
    }
}

impl<'de> Deserialize<'de> for SearchAuthorizationScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            clauses: Vec<SearchAuthorizationClause>,
        }
        Ok(Self::new(Input::deserialize(deserializer)?.clauses))
    }
}

/// Derived query data for consumers whose resource types allow only exact/all selectors.
/// This is not an accepted invocation authority or a serialized authority format.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactSearchProjection {
    Finite { values: Vec<String> },
    AllExcept { excluded_values: Vec<String> },
}

/// The authority cannot be represented by an exact-only query boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchProjectionError;
impl std::fmt::Display for SearchProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("search authority is not exact-only")
    }
}
impl std::error::Error for SearchProjectionError {}

impl From<SearchProjectionError> for crate::ProviderError {
    fn from(_: SearchProjectionError) -> Self {
        crate::host::port_failure(
            crate::host::HostPort::AdmittedOperation,
            crate::ProviderError::error(
                crate::ReasonCode::BrokerProviderContractFailed,
                "provider search authority is not exact-only",
            )
            .with_internal_diagnostic_code("provider_search_authority_not_exact"),
        )
    }
}

#[cfg(test)]
#[path = "search_tests.rs"]
mod tests;
