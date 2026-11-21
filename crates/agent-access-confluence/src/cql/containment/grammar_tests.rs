//! Caller grammar exercised through the current containment compiler.
use super::*;
use crate::tests::confluence_config;
use agent_access_provider::ResourceTypeRegistry;

fn finite() -> FixtureSpaces {
    FixtureSpaces::Finite(BTreeSet::from(["ENG".into()]))
}

#[test]
fn raw_cql_is_reemitted_and_rejects_unsafe_literals() {
    let query = build_fixture_page_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"(space in ("ENG") and title ~ "runbook") or (content.id = 123456)"#.into(),
        },
        &finite(),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        query.cql,
        r#"type = page AND ((((space = "ENG")))) AND ((space IN (ENG) AND title ~ "runbook") OR id = 123456)"#
    );
    for raw in [
        "title ~ \"x\\\"",
        "space in (\"ENG)",
        "title ~ \"runbook\")",
    ] {
        assert_eq!(
            parse_cql_query(raw).unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[test]
fn blog_cql_composes_blogpost_type_and_rejects_page_hierarchy_fields() {
    let query = build_fixture_blog_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"space = ENG AND type = blogpost AND title ~ "release""#.into(),
        },
        &finite(),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        query.cql,
        r#"type = blogpost AND ((((space = "ENG")))) AND (space = ENG AND type = blogpost AND title ~ "release")"#
    );
    assert_eq!(query.injected_type_predicate, "type_blogpost");
    for raw in ["type = page", "ancestor = 123456", "parent IN (123456)"] {
        assert_eq!(
            build_fixture_blog_query(
                &ConfluenceSearchQueryInput::Cql { value: raw.into() },
                &finite(),
                &SearchLimitsConfig::default()
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[test]
fn all_except_cql_preserves_caller_grouping_and_exclusions() {
    let boundary = FixtureSpaces::AllExcept(BTreeSet::from(["PRIVATE".into(), "IN".into()]));
    for (raw, suffix) in [
        (
            "space = PRIVATE OR title ~ \"runbook\" ORDER BY title",
            "(space = PRIVATE OR title ~ \"runbook\") ORDER BY title ASC",
        ),
        ("space IN (PRIVATE, ENG)", "(space IN (PRIVATE, ENG))"),
    ] {
        let query = build_fixture_page_query(
            &ConfluenceSearchQueryInput::Cql { value: raw.into() },
            &boundary,
            &SearchLimitsConfig::default(),
        )
        .unwrap();
        assert_eq!(
            query.cql,
            format!(
                "type = page AND ((((type = page) AND NOT (space = \"IN\" OR space = \"PRIVATE\")))) AND {suffix}"
            )
        );
        assert_eq!(query.injected_space_predicate, "content_authority");
    }
    assert!(!boundary.authorizes_value("PRIVATE"));
    assert!(boundary.authorizes_value("NEW"));
    let authorization = boundary.authority(ConfluenceSearchContentKind::Page);
    assert_eq!(
        requested_space_coverage(&authorization, "PRIVATE").unwrap(),
        OfflineContainmentProof::Empty
    );
    assert_eq!(
        requested_space_coverage(&authorization, "NEW").unwrap(),
        OfflineContainmentProof::Covered
    );
}

#[test]
fn cql_quote_style_hashes_are_stable_for_equivalent_canonical_queries() {
    let build = |raw: &str| {
        build_fixture_page_query(
            &ConfluenceSearchQueryInput::Cql { value: raw.into() },
            &finite(),
            &SearchLimitsConfig::default(),
        )
        .unwrap()
    };
    let quoted = build(r#"label = "security""#);
    let bare = build("label = security");
    assert_eq!(
        quoted.canonical_caller_cql_hash,
        bare.canonical_caller_cql_hash
    );
    assert!(quoted.text_operand_hashes.is_empty());
}

#[test]
fn wildcard_cql_space_predicates_narrow_the_query_not_authority() {
    let boundary = FixtureSpaces::AllExcept(BTreeSet::new());
    let narrowed = build_fixture_page_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"space = ENG AND title ~ "runbook""#.into(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        narrowed.cql,
        r#"type = page AND ((((type = page)))) AND (space = ENG AND title ~ "runbook")"#
    );
    assert!(boundary.authorizes_value("ROCKET"));
}

#[test]
fn cql_scope_only_and_order_only_keep_space_and_content_constraints() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        let type_name = kind.cql_type();
        for (scope, predicate) in [
            (finite(), "((((space = \"ENG\"))))".to_string()),
            (
                FixtureSpaces::AllExcept(BTreeSet::from(["PRIVATE".into()])),
                format!("((((type = {type_name}) AND NOT (space = \"PRIVATE\"))))"),
            ),
            (
                FixtureSpaces::AllExcept(BTreeSet::new()),
                format!("((((type = {type_name}))))"),
            ),
        ] {
            for (raw, suffix) in [
                ("", ""),
                ("  ", ""),
                ("ORDER BY lastModified DESC", " ORDER BY lastModified DESC"),
            ] {
                let query = build_fixture_search_query(
                    &ConfluenceSearchQueryInput::Cql { value: raw.into() },
                    &scope,
                    &SearchLimitsConfig::default(),
                    kind,
                )
                .unwrap();
                assert_eq!(
                    query.cql,
                    format!("type = {type_name} AND {predicate}{suffix}")
                );
                assert!(query.query_shape["filter"].is_null());
                assert!(query.text_operand_hashes.is_empty());
            }
        }
    }
    assert_eq!(canonical_cql("  ORDER BY title  "), "ORDER BY title ASC");
    assert_eq!(canonical_cql("  "), "");
    assert!(confluence_text_query("", &SearchLimitsConfig::default()).is_err());
    for raw in [
        "ORDER BY",
        "ORDER BY title,",
        "ORDER BY title DESC title",
        "AND title ~ \"x\"",
        "()",
    ] {
        assert_eq!(
            parse_cql_query(raw).unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[test]
fn cql_omitted_spaces_use_authority_and_explicit_spaces_only_narrow() {
    let inputs = parse_search_inputs(&json!({"query":{"type":"cql","value":""}})).unwrap();
    let authority = FixtureSpaces::Finite(BTreeSet::from(["ENG".into(), "OPS".into()]))
        .authority(ConfluenceSearchContentKind::Page);
    let build = |requested| {
        build_containment_search_query(
            &inputs.query,
            &authority,
            &requested,
            &SearchLimitsConfig::default(),
            ConfluenceSearchContentKind::Page,
            "https://example.atlassian.net",
        )
    };
    assert_eq!(
        build(requested_spaces(&inputs).unwrap()).unwrap().cql,
        "type = page AND ((((space = \"ENG\" OR space = \"OPS\"))))"
    );
    assert_eq!(
        build(BTreeSet::from(["ENG".into()])).unwrap().cql,
        "type = page AND ((((space = \"ENG\" OR space = \"OPS\")))) AND (space = \"ENG\")"
    );
    assert_eq!(
        build(BTreeSet::from(["PRIVATE".into()]))
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
}

#[test]
fn cql_discovery_examples_execute_and_blog_fields_match_content_kind() {
    for (name, kind) in [
        ("search", ConfluenceSearchContentKind::Page),
        ("blog.search", ConfluenceSearchContentKind::BlogPost),
    ] {
        let documentation = cql_documentation(kind);
        for example in documentation["cql"]["examples"].as_array().unwrap() {
            let inputs = parse_search_inputs(example).unwrap();
            build_fixture_search_query(
                &inputs.query,
                &finite(),
                &SearchLimitsConfig::default(),
                kind,
            )
            .unwrap();
        }
        assert_eq!(
            documentation["cql"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["name"] == "parent"),
            kind == ConfluenceSearchContentKind::Page
        );
        let descriptor = confluence_descriptor(&confluence_config());
        let action = descriptor
            .actions
            .iter()
            .find(|action| action.action == name)
            .unwrap();
        for (key, value) in documentation.as_object().unwrap() {
            assert_eq!(action.documentation.as_ref().unwrap().get(key), Some(value));
        }
    }
}

#[test]
fn unsupported_space_namespaces_fail_before_query_compilation() {
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    assert!(
        registry
            .typed_selector(
                CONFLUENCE_SPACE_RESOURCE.id(),
                &ResourceSelector::Namespace {
                    value: "engineering".into()
                }
            )
            .is_err()
    );
}
