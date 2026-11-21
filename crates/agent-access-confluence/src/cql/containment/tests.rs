use super::*;
use agent_access_provider::{
    ContainmentEffect, ContainmentEvidenceLevel, ContainmentScopeCapabilities,
    ResourceTypeRegistry, host,
};

const SITE: &str = "https://example.atlassian.net";

fn authority(
    grants: Vec<ContainmentBoundary>,
    token: Option<ContainmentBoundary>,
) -> ContainmentCollectionAuthorization {
    let registry = ResourceTypeRegistry::new([
        &crate::CONFLUENCE_SPACE_RESOURCE,
        &crate::CONFLUENCE_CONTENT_RESOURCE,
    ])
    .unwrap();
    let contract = ContainmentScopeCapabilities::new(
        "page",
        BTreeMap::from([
            (
                ResourceType::from_static("confluence_space"),
                vec!["exact".into(), "all".into()],
            ),
            (
                ResourceType::from_static("confluence_content"),
                vec!["exact".into(), "subtree".into()],
            ),
        ]),
        vec![ResourceType::from_static("confluence_space")],
        vec!["page".into()],
        vec!["page".into(), "folder".into()],
        vec![ContainmentEffect::Content],
    );
    host::containment_collection_authorization(
        SITE,
        contract,
        grants,
        token,
        &registry,
        ContainmentEvidenceLevel::CompleteLineage,
        "a".repeat(64),
    )
    .unwrap()
}

fn selector(resource_type: &str, selector: ResourceSelector) -> TypedResourceSelector {
    ResourceTypeRegistry::new([
        &crate::CONFLUENCE_SPACE_RESOURCE,
        &crate::CONFLUENCE_CONTENT_RESOURCE,
    ])
    .unwrap()
    .typed_selector(&ResourceType::new(resource_type).unwrap(), &selector)
    .unwrap()
}

fn content(kind: &str, id: &str, subtree: bool) -> TypedResourceSelector {
    let value = format!("{SITE}/wiki/content/{kind}/{id}");
    selector(
        "confluence_content",
        if subtree {
            ResourceSelector::Subtree { value }
        } else {
            ResourceSelector::Exact { value }
        },
    )
}

fn compile_boundary(boundary: ContainmentBoundary) -> String {
    let mut output = QueryWriter::new();
    write_boundary(
        &mut output,
        &boundary,
        ConfluenceSearchContentKind::Page,
        SITE,
    )
    .unwrap();
    output.0
}

#[test]
fn folder_exclusion_negates_unpinned_ancestry_predicate() {
    let value = compile_boundary(ContainmentBoundary::new(
        vec![selector("confluence_space", ResourceSelector::All)],
        vec![content("folder", "123", true)],
    ));
    assert_eq!(value, "((type = page) AND NOT (ancestor = 123))");
    // Site identity is checked before compilation; current space never narrows
    // a content selector, including a negative subtree predicate.
    assert!(value.contains("NOT (ancestor = 123)"));
}

#[test]
fn page_subtree_includes_self_but_exact_page_has_no_ancestor_predicate() {
    assert_eq!(
        compile_boundary(ContainmentBoundary::new(
            vec![content("page", "123", true)],
            vec![]
        )),
        "(((id = 123 OR ancestor = 123)))"
    );
    assert_eq!(
        compile_boundary(ContainmentBoundary::new(
            vec![content("page", "123", false)],
            vec![]
        )),
        "((id = 123))"
    );
}

#[test]
fn inapplicable_blog_or_other_site_never_broadens_page_authority() {
    let mut output = QueryWriter::new();
    write_selector(
        &mut output,
        &content("blog", "123", false),
        ConfluenceSearchContentKind::Page,
        SITE,
    )
    .unwrap();
    assert_eq!(output.0, "(type = page AND type = blogpost)");
    let mut output = QueryWriter::new();
    write_selector(
        &mut output,
        &content("page", "123", false),
        ConfluenceSearchContentKind::Page,
        "https://other.atlassian.net",
    )
    .unwrap();
    assert_eq!(output.0, "(type = page AND type = blogpost)");
}

#[test]
fn empty_boundary_is_a_contradiction_not_a_space_universe() {
    assert_eq!(
        compile_boundary(ContainmentBoundary::new(vec![], vec![])),
        "((type = page AND type = blogpost))"
    );
}

#[test]
fn personal_space_key_is_quoted_and_preserves_case() {
    assert_eq!(
        compile_boundary(ContainmentBoundary::new(
            vec![selector(
                "confluence_space",
                ResourceSelector::Exact {
                    value: "~Alice".into()
                }
            )],
            vec![],
        )),
        "((space = \"~Alice\"))"
    );
}

#[test]
fn winning_union_preserves_local_subtraction_and_independent_token_conjunction() {
    let authorization = authority(
        vec![
            ContainmentBoundary::new(
                vec![selector("confluence_space", ResourceSelector::All)],
                vec![content("folder", "10", true)],
            ),
            // Another same-band grant restores the page but not the token's deny.
            ContainmentBoundary::new(vec![content("page", "20", false)], vec![]),
        ],
        Some(ContainmentBoundary::new(
            vec![content("folder", "30", true)],
            vec![content("page", "40", false)],
        )),
    );
    assert_eq!(
        compile_content_authority(&authorization, SITE).unwrap(),
        "(((type = page) AND NOT (ancestor = 10)) OR ((id = 20))) AND ((ancestor = 30) AND NOT (id = 40))"
    );
}

#[test]
fn caller_filter_is_grouped_after_complete_authority_and_sort_is_last() {
    let authorization = authority(
        vec![ContainmentBoundary::new(
            vec![content("folder", "10", true)],
            vec![],
        )],
        Some(ContainmentBoundary::new(
            vec![content("folder", "20", true)],
            vec![],
        )),
    );
    let query = ConfluenceSearchQueryInput::Cql {
        value: "title ~ \"sentinel\" OR space = OTHER ORDER BY title".into(),
    };
    let built = build_containment_search_query(
        &query,
        &authorization,
        &BTreeSet::from(["ENG".into()]),
        &SearchLimitsConfig::default(),
        ConfluenceSearchContentKind::Page,
        SITE,
    )
    .unwrap();
    assert_eq!(
        built.cql,
        "type = page AND ((((ancestor = 10))) AND ((ancestor = 20))) AND (space = \"ENG\") AND (title ~ \"sentinel\" OR space = OTHER) ORDER BY title ASC"
    );
    assert!(!built.canonical_caller_cql.contains("ancestor"));
    assert_eq!(built.kind, "cql");
}

#[test]
fn requested_spaces_keep_unpinned_content_roots_conditional_in_every_space() {
    let authorization = authority(
        vec![ContainmentBoundary::new(
            vec![content("folder", "10", true)],
            vec![],
        )],
        Some(ContainmentBoundary::new(
            vec![content("folder", "20", true)],
            vec![],
        )),
    );
    assert_eq!(
        requested_space_coverage(&authorization, "ENG").unwrap(),
        OfflineContainmentProof::Conditional
    );
    assert_eq!(
        requested_space_coverage(&authorization, "OTHER").unwrap(),
        OfflineContainmentProof::Conditional
    );
    let query = build_containment_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: String::new(),
        },
        &authorization,
        &BTreeSet::from(["ENG".into(), "OTHER".into()]),
        &SearchLimitsConfig::default(),
        ConfluenceSearchContentKind::Page,
        SITE,
    )
    .unwrap();
    assert!(query.cql.contains("(space = \"ENG\" OR space = \"OTHER\")"));
}

#[test]
fn empty_token_and_foreign_site_never_widen_collection_authority() {
    let authorization = authority(
        vec![ContainmentBoundary::new(
            vec![selector("confluence_space", ResourceSelector::All)],
            vec![],
        )],
        Some(ContainmentBoundary::new(vec![], vec![])),
    );
    assert_eq!(
        requested_space_coverage(&authorization, "ENG").unwrap(),
        OfflineContainmentProof::Empty
    );
    assert!(
        compile_content_authority(&authorization, SITE)
            .unwrap()
            .contains("AND ((type = page AND type = blogpost))")
    );
    assert_eq!(
        compile_content_authority(&authorization, "https://other.atlassian.net")
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[test]
fn compiler_counts_occurrences_and_bounds_output_before_transport_encoding() {
    let repeated = ContainmentBoundary::new(vec![content("page", "10", false)], vec![]);
    let authorization = authority(vec![repeated; MAX_AUTHORITY_SELECTOR_OCCURRENCES + 1], None);
    assert_eq!(
        compile_content_authority(&authorization, SITE)
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    // Below the occurrence ceiling, long canonical IDs still exceed the private
    // output allocation cap. The backend separately checks percent-encoded URI size.
    let selected = (0..3000u64)
        .map(|index| {
            content(
                "page",
                &(10000000000000000000u64 + index).to_string(),
                false,
            )
        })
        .collect();
    let authorization = authority(vec![ContainmentBoundary::new(selected, vec![])], None);
    assert_eq!(
        compile_content_authority(&authorization, SITE)
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}
