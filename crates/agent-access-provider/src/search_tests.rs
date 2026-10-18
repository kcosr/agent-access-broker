use crate::{
    ExactSearchProjection, ResourceSelector, SearchAuthorizationClause, SearchAuthorizationScope,
};
use serde_json::json;
use std::collections::BTreeSet;

fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}

fn namespace(value: &str) -> ResourceSelector {
    ResourceSelector::Namespace {
        value: value.into(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn namespaces_match_descendants_but_not_their_own_path_or_sibling_prefixes() {
    let scope = SearchAuthorizationScope::from_selectors(vec![namespace("engineering")], vec![]);
    for allowed in [
        "engineering/tool",
        "engineering/platform/tool",
        "engineering/platform/nested/tool",
    ] {
        assert!(scope.matches(allowed), "{allowed}");
    }
    for denied in [
        "engineering",
        "engineering/",
        "engineering-tools/tool",
        "engineering2/tool",
        "other/engineering/tool",
    ] {
        assert!(!scope.matches(denied), "{denied}");
    }
    let nested =
        SearchAuthorizationScope::from_selectors(vec![namespace("engineering/platform")], vec![]);
    assert!(nested.matches("engineering/platform/tool"));
    assert!(!nested.matches("engineering/platform"));
    assert!(!nested.matches("engineering/platform-tools/tool"));
}

#[test]
fn union_keeps_exclusions_local_and_restores_only_the_independent_grant() {
    let broad = SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::All],
        vec![namespace("engineering/private")],
    );
    let restored =
        SearchAuthorizationScope::from_exact_values(strings(&["engineering/private/tool"]));
    let scope = broad.union(&restored);

    assert!(!broad.matches("engineering/private/tool"));
    assert!(scope.matches("engineering/private/tool"));
    assert!(scope.matches("engineering/public/tool"));
    // A namespace exclusion has the same descendant-only semantics as an inclusion.
    assert!(scope.matches("engineering/private"));
    assert!(scope.matches("engineering/private-tools/tool"));
    assert!(!scope.matches("engineering/private/other"));
    assert!(!scope.matches("engineering/private/tool/child"));
    assert_eq!(scope, restored.union(&broad));
}

#[test]
fn intersection_distributes_across_clauses_and_combines_local_exclusions() {
    let grants = SearchAuthorizationScope::from_selectors(
        vec![namespace("engineering")],
        vec![namespace("engineering/private")],
    )
    .union(&SearchAuthorizationScope::from_exact_values(strings(&[
        "engineering/private/tool",
        "labs/tool",
    ])));
    let token = SearchAuthorizationScope::from_selectors(
        vec![namespace("engineering/private"), namespace("labs")],
        vec![exact("labs/tool"), exact("engineering/private/other")],
    );
    let scope = grants.intersection(&token);
    assert_eq!(
        scope,
        SearchAuthorizationScope::from_exact_values(strings(&["engineering/private/tool"]))
    );
    for denied in [
        "engineering/public/tool",
        "engineering/private/other",
        "labs/tool",
        "labs/other",
    ] {
        assert!(!scope.matches(denied), "{denied}");
    }
    assert_eq!(scope, token.intersection(&grants));

    let first = SearchAuthorizationClause::new(
        vec![namespace("engineering")],
        vec![exact("engineering/platform/blocked")],
    );
    let second = SearchAuthorizationClause::new(
        vec![namespace("engineering/platform")],
        vec![namespace("engineering/platform/private")],
    );
    let intersection = first.intersection(&second);
    assert!(intersection.matches("engineering/platform/tool"));
    assert!(!intersection.matches("engineering/platform/blocked"));
    assert!(!intersection.matches("engineering/platform/private/tool"));
    assert!(!intersection.matches("engineering/other/tool"));
}

#[test]
fn empty_clauses_and_fully_excluded_regions_admit_nothing() {
    let empty = SearchAuthorizationScope::empty();
    for clause in [
        SearchAuthorizationClause::new(vec![], vec![ResourceSelector::All]),
        SearchAuthorizationClause::new(
            vec![exact("engineering/tool")],
            vec![namespace("engineering")],
        ),
        SearchAuthorizationClause::new(
            vec![namespace("engineering")],
            vec![namespace("engineering")],
        ),
        SearchAuthorizationClause::new(vec![ResourceSelector::All], vec![ResourceSelector::All]),
    ] {
        assert!(clause.is_empty());
        assert!(!clause.matches("engineering/tool"));
        assert_eq!(SearchAuthorizationScope::new(vec![clause]), empty);
    }
    let allowed = SearchAuthorizationScope::from_exact_values(strings(&["engineering/tool"]));
    assert!(empty.is_empty());
    assert!(!empty.is_universe());
    assert!(!empty.covers(&exact("engineering/tool")));
    assert_eq!(allowed.union(&empty), allowed);
    assert_eq!(allowed.intersection(&empty), empty);
    assert_eq!(
        allowed.intersection(&SearchAuthorizationScope::excluding_exact_values(strings(
            &["engineering/tool",]
        ))),
        empty
    );
}

#[test]
fn normalization_removes_redundant_terms_and_is_order_independent() {
    let included = vec![
        namespace("engineering/platform"),
        exact("labs/tool"),
        namespace("engineering"),
        exact("engineering/tool"),
        namespace("engineering"),
    ];
    let excluded = vec![
        namespace("other"),
        exact("engineering/private/tool"),
        namespace("engineering/private"),
        namespace("engineering/private/nested"),
        exact("engineering/blocked"),
        exact("engineering/blocked"),
    ];
    let clause = SearchAuthorizationClause::new(included.clone(), excluded.clone());
    assert_eq!(
        clause.included(),
        &[exact("labs/tool"), namespace("engineering")]
    );
    assert_eq!(
        clause.excluded(),
        &[
            exact("engineering/blocked"),
            namespace("engineering/private")
        ]
    );
    assert_eq!(
        clause,
        SearchAuthorizationClause::new(
            included.into_iter().rev().collect(),
            excluded.into_iter().rev().collect(),
        )
    );
    let restored = SearchAuthorizationClause::new(vec![exact("engineering/private/tool")], vec![]);
    let clauses = vec![
        clause.clone(),
        SearchAuthorizationClause::new(vec![], vec![]),
        restored.clone(),
        SearchAuthorizationClause::new(vec![exact("engineering/public/tool")], vec![]),
        clause,
        restored,
    ];
    let scope = SearchAuthorizationScope::new(clauses.clone());
    assert_eq!(scope.clauses().len(), 2);
    assert_eq!(
        scope,
        SearchAuthorizationScope::new(clauses.into_iter().rev().collect())
    );
    assert_eq!(
        scope,
        SearchAuthorizationScope::new(scope.clauses().to_vec())
    );
    assert_eq!(
        serde_json::to_string(&scope).unwrap(),
        serde_json::to_string(&scope.union(&scope)).unwrap()
    );
}

#[test]
fn coverage_proves_the_complete_union_without_mistaking_overlap_for_coverage() {
    let namespace_region = namespace("engineering");
    let outside_private = SearchAuthorizationScope::from_selectors(
        vec![namespace_region.clone()],
        vec![namespace("engineering/private")],
    );
    let private_except_one = SearchAuthorizationScope::from_selectors(
        vec![namespace("engineering/private")],
        vec![exact("engineering/private/secret")],
    );
    let with_hole = outside_private.union(&private_except_one);
    assert!(!outside_private.covers(&namespace_region));
    assert!(!with_hole.covers(&namespace_region));
    assert!(!with_hole.covers(&namespace("engineering/private")));
    assert!(with_hole.covers(&exact("engineering/private/tool")));
    assert!(!with_hole.covers(&exact("engineering/private/secret")));

    let restored = with_hole.union(&SearchAuthorizationScope::from_exact_values(strings(&[
        "engineering/private/secret",
    ])));
    assert!(restored.covers(&namespace_region));
    assert!(!restored.covers(&ResourceSelector::All));
    assert!(!restored.covers(&exact("engineering")));

    let outside_namespace = SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::All],
        vec![namespace_region],
    );
    assert!(outside_namespace.union(&restored).is_universe());
    assert!(!outside_namespace.union(&with_hole).is_universe());
    let finite = SearchAuthorizationScope::from_exact_values(strings(&[
        "engineering/tool",
        "engineering/private/tool",
    ]));
    assert!(!finite.covers(&namespace("engineering")));
}

#[test]
fn exact_projection_preserves_restored_values_and_intersects_cofinite_exclusions() {
    let left =
        SearchAuthorizationScope::excluding_exact_values(strings(&["OPS", "PRIVATE", "SHARED"]));
    let right = SearchAuthorizationScope::excluding_exact_values(strings(&["SHARED", "TEAM"]));
    assert_eq!(
        left.union(&right).exact_projection().unwrap(),
        ExactSearchProjection::AllExcept {
            excluded_values: strings(&["SHARED"]),
        }
    );
    assert_eq!(
        left.intersection(&right).exact_projection().unwrap(),
        ExactSearchProjection::AllExcept {
            excluded_values: strings(&["OPS", "PRIVATE", "SHARED", "TEAM"]),
        }
    );
    let restored = SearchAuthorizationScope::from_exact_values(strings(&["PRIVATE", "PRIVATE"]));
    assert_eq!(
        left.union(&restored).exact_projection().unwrap(),
        ExactSearchProjection::AllExcept {
            excluded_values: strings(&["OPS", "SHARED"]),
        }
    );
    assert_eq!(
        left.union(&right)
            .union(&SearchAuthorizationScope::from_exact_values(strings(&[
                "SHARED"
            ])))
            .exact_projection()
            .unwrap(),
        ExactSearchProjection::AllExcept {
            excluded_values: vec![],
        }
    );
    let finite = SearchAuthorizationScope::from_exact_values(strings(&["TEAM", "OPS", "TEAM"]));
    assert_eq!(
        finite.intersection(&left).exact_projection().unwrap(),
        ExactSearchProjection::Finite {
            values: strings(&["TEAM"]),
        }
    );
    assert_eq!(
        SearchAuthorizationScope::empty()
            .exact_projection()
            .unwrap(),
        ExactSearchProjection::Finite { values: vec![] }
    );
}

#[test]
fn exact_projection_rejects_surviving_positive_and_negative_namespaces() {
    for scope in [
        SearchAuthorizationScope::from_selectors(vec![namespace("engineering")], vec![]),
        SearchAuthorizationScope::from_selectors(
            vec![ResourceSelector::All],
            vec![namespace("engineering/private")],
        ),
        SearchAuthorizationScope::from_exact_values(strings(&["labs/tool"])).union(
            &SearchAuthorizationScope::from_selectors(vec![namespace("engineering")], vec![]),
        ),
    ] {
        assert!(scope.exact_projection().is_err());
    }
}

#[test]
fn resource_summaries_are_descriptive_and_preserve_exact_restorations() {
    let finite = SearchAuthorizationScope::from_selectors(
        vec![exact("TEAM"), exact("OPS"), exact("PRIVATE")],
        vec![exact("PRIVATE")],
    )
    .union(&SearchAuthorizationScope::from_exact_values(strings(&[
        "PRIVATE",
    ])));
    assert_eq!(
        finite.resource_scope_summary(),
        strings(&["OPS", "PRIVATE", "TEAM"])
    );
    let namespace_scope = SearchAuthorizationScope::from_selectors(
        vec![namespace("engineering")],
        vec![exact("engineering/private")],
    );
    assert_eq!(namespace_scope.resource_scope_summary(), strings(&["*"]));
    assert!(!namespace_scope.matches("engineering/private"));
    let cofinite = SearchAuthorizationScope::excluding_exact_values(strings(&["PRIVATE"]));
    assert_eq!(cofinite.resource_scope_summary(), strings(&["*"]));
    assert!(!cofinite.matches("PRIVATE"));
    assert!(
        SearchAuthorizationScope::empty()
            .resource_scope_summary()
            .is_empty()
    );
}

#[test]
fn serialization_uses_only_normalized_clauses_and_rejects_the_replaced_format() {
    let scope = SearchAuthorizationScope::from_selectors(
        vec![namespace("engineering")],
        vec![namespace("engineering/private")],
    )
    .union(&SearchAuthorizationScope::from_exact_values(strings(&[
        "engineering/private/tool",
    ])));
    let serialized = serde_json::to_value(&scope).unwrap();
    assert_eq!(
        serialized,
        json!({"clauses": [
            {"included": [{"kind": "exact", "value": "engineering/private/tool"}], "excluded": []},
            {"included": [{"kind": "namespace", "value": "engineering"}],
             "excluded": [{"kind": "namespace", "value": "engineering/private"}]}
        ]})
    );
    assert_eq!(
        serde_json::from_value::<SearchAuthorizationScope>(serialized).unwrap(),
        scope
    );
    let unsorted = json!({"clauses": [
        {"included": [{"kind": "exact", "value": "TEAM"}, {"kind": "exact", "value": "OPS"},
                      {"kind": "exact", "value": "TEAM"}], "excluded": []},
        {"included": [], "excluded": [{"kind": "all"}]}
    ]});
    assert_eq!(
        serde_json::from_value::<SearchAuthorizationScope>(unsorted).unwrap(),
        SearchAuthorizationScope::from_exact_values(strings(&["OPS", "TEAM"]))
    );
    for invalid in [
        json!({"type": "finite", "values": ["OPS"]}),
        json!({"type": "all_except", "excludedValues": ["PRIVATE"]}),
        json!({"clauses": [], "type": "finite", "values": []}),
        json!({"clauses": [{"included": [], "excluded": [], "values": []}]}),
        json!({"clauses": [{"included": []}]}),
    ] {
        assert!(
            serde_json::from_value::<SearchAuthorizationScope>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum ModelSelector {
    Exact(&'static str),
    Namespace(&'static str),
    All,
}

impl ModelSelector {
    fn to_selector(self) -> ResourceSelector {
        match self {
            Self::Exact(value) => exact(value),
            Self::Namespace(value) => namespace(value),
            Self::All => ResourceSelector::All,
        }
    }

    // Independent finite-model semantics: compare path components, not SDK selectors.
    fn accepts(self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => value == expected,
            Self::Namespace(prefix) => {
                let prefix: Vec<_> = prefix.split('/').collect();
                let components: Vec<_> = value.split('/').collect();
                components.len() > prefix.len() && components.starts_with(&prefix)
            }
            Self::All => true,
        }
    }
}

#[derive(Debug)]
struct ModelClause {
    included: Vec<ModelSelector>,
    excluded: Vec<ModelSelector>,
}

impl ModelClause {
    fn accepts(&self, value: &str) -> bool {
        self.included.iter().any(|selector| selector.accepts(value))
            && !self.excluded.iter().any(|selector| selector.accepts(value))
    }

    fn to_clause(&self) -> SearchAuthorizationClause {
        SearchAuthorizationClause::new(
            self.included
                .iter()
                .map(|selector| selector.to_selector())
                .collect(),
            self.excluded
                .iter()
                .map(|selector| selector.to_selector())
                .collect(),
        )
    }
}

struct DeterministicRng(u64);

impl DeterministicRng {
    fn below(&mut self, upper: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % upper as u64) as usize
    }

    fn selectors(&mut self, pool: &[ModelSelector]) -> Vec<ModelSelector> {
        (0..self.below(5))
            .map(|_| pool[self.below(pool.len())])
            .collect()
    }

    fn clauses(&mut self, pool: &[ModelSelector]) -> Vec<ModelClause> {
        (0..self.below(5))
            .map(|_| ModelClause {
                included: self.selectors(pool),
                excluded: self.selectors(pool),
            })
            .collect()
    }
}

#[test]
fn randomized_clause_algebra_matches_an_independent_finite_set_oracle() {
    use ModelSelector::{All, Exact, Namespace};

    let universe = [
        "engineering",
        "engineering/tool",
        "engineering/other",
        "engineering/private",
        "engineering/private/tool",
        "engineering/private/other",
        "engineering/private/nested/tool",
        "engineering/private-tools/tool",
        "engineering/platform",
        "engineering/platform/tool",
        "engineering2/tool",
        "labs",
        "labs/tool",
        "labs/other",
        "labs/team/tool",
        "elsewhere/tool",
    ];
    let pool = [
        All,
        Exact("engineering"),
        Exact("engineering/tool"),
        Exact("engineering/private"),
        Exact("engineering/private/tool"),
        Exact("engineering/platform/tool"),
        Exact("labs/tool"),
        Exact("elsewhere/tool"),
        Namespace("engineering"),
        Namespace("engineering/private"),
        Namespace("engineering/private/nested"),
        Namespace("engineering/platform"),
        Namespace("engineering2"),
        Namespace("labs"),
        Namespace("labs/team"),
        Namespace("not-in-universe"),
    ];
    let expected_set = |clauses: &[ModelClause]| -> BTreeSet<&str> {
        universe
            .iter()
            .copied()
            .filter(|value| clauses.iter().any(|clause| clause.accepts(value)))
            .collect()
    };
    let actual_set = |scope: &SearchAuthorizationScope| -> BTreeSet<&str> {
        universe
            .iter()
            .copied()
            .filter(|value| scope.matches(value))
            .collect()
    };
    let mut rng = DeterministicRng(0x63e8_b27a_9054_f1cd);
    for case in 0..512 {
        let left_model = rng.clauses(&pool);
        let right_model = rng.clauses(&pool);
        for model in left_model.iter().chain(&right_model) {
            let clause = model.to_clause();
            for value in universe {
                assert_eq!(
                    clause.matches(value),
                    model.accepts(value),
                    "case {case}, path {value}, clause {model:?}"
                );
            }
        }
        let left =
            SearchAuthorizationScope::new(left_model.iter().map(ModelClause::to_clause).collect());
        let right =
            SearchAuthorizationScope::new(right_model.iter().map(ModelClause::to_clause).collect());
        let expected_left = expected_set(&left_model);
        let expected_right = expected_set(&right_model);
        assert_eq!(
            actual_set(&left),
            expected_left,
            "left normalization, case {case}: {left_model:?}"
        );
        assert_eq!(
            actual_set(&right),
            expected_right,
            "right normalization, case {case}: {right_model:?}"
        );
        assert_eq!(
            actual_set(&left.union(&right)),
            expected_left.union(&expected_right).copied().collect(),
            "union, case {case}: {left_model:?} / {right_model:?}"
        );
        assert_eq!(
            actual_set(&left.intersection(&right)),
            expected_left
                .intersection(&expected_right)
                .copied()
                .collect(),
            "intersection, case {case}: {left_model:?} / {right_model:?}"
        );
        for value in universe {
            assert_eq!(
                left.covers(&exact(value)),
                expected_left.contains(value),
                "exact coverage, case {case}, path {value}"
            );
        }
    }
}

#[test]
fn native_search_modes_require_scopes_and_forbid_private_attribute_binding() {
    use crate::{
        ActionDescriptor, GIT_REPOSITORY_RESOURCE, NativeSearchEnforcement,
        ResourceScopeCapabilities, ServiceDescriptor,
    };
    for mode in [
        NativeSearchEnforcement::UpstreamConstrained,
        NativeSearchEnforcement::ResultFiltered,
    ] {
        let action =
            ActionDescriptor::new("search", "Search", serde_json::json!({"type": "object"}))
                .credential_modes(["service"])
                .native_search(mode);
        let service =
            ServiceDescriptor::new("fixture", "Fixture").with_actions(vec![action.clone()]);
        assert!(service.validate().is_err());
        let service = ServiceDescriptor::new("fixture", "Fixture")
            .with_resource_scopes(std::collections::BTreeMap::from([(
                "repository".into(),
                ResourceScopeCapabilities::new(
                    GIT_REPOSITORY_RESOURCE.id().clone(),
                    vec!["exact".into(), "namespace".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![action.scope("repository")]);
        assert!(service.validate().is_ok());
        let mut invalid = service.clone();
        invalid.actions[0].requires_resource_attributes = true;
        assert!(invalid.validate().is_err());
    }
}
