use super::*;

const SEARCHES: [(&str, ConfluenceSearchContentKind); 2] = [
    ("search", ConfluenceSearchContentKind::Page),
    ("blog.search", ConfluenceSearchContentKind::BlogPost),
];

#[test]
fn text_negation_preserves_quoted_literals_and_canonical_polarity() {
    for (_, kind) in SEARCHES {
        for field in ["title", "text"] {
            for value in [
                "obsolete",
                "",
                "  ",
                "\"release candidate\"",
                "run* ?un",
                "quote \" slash \\ ) AND space = PRIVATE",
                "line\nnext\ttab\rreturn",
                "déjà vu",
            ] {
                let raw = format!("{field} !~ {}", cql_string_literal(value));
                let parsed = parse_cql_query_for_kind(&raw, kind).unwrap();
                assert_eq!(parsed.emit(), raw);
                assert_eq!(
                    parse_cql_query_for_kind(&parsed.emit(), kind).unwrap(),
                    parsed
                );
                assert_eq!(parsed.text_operand_hashes(), [sha256_hex(value.as_bytes())]);
                assert_eq!(parsed.query_shape()["filter"]["operator"], "!~");
                assert_eq!(
                    parsed.query_shape()["filter"]["operand"],
                    json!({"type": "single", "value": {"type": "string"}})
                );
            }
            let parsed =
                parse_cql_query_for_kind(&format!("{} !~ 'obsolete'", field.to_uppercase()), kind)
                    .unwrap();
            assert_eq!(parsed.emit(), format!("{field} !~ \"obsolete\""));
        }
    }
}

#[test]
fn text_negation_rejects_other_fields_and_invalid_operands_without_echoing_values() {
    for (_, kind) in SEARCHES {
        for field in [
            "space",
            "type",
            "id",
            "content.id",
            "label",
            "creator",
            "contributor",
            "mention",
            "ancestor",
            "parent",
            "created",
            "lastModified",
        ] {
            let error = parse_cql_query_for_kind(&format!("{field} !~ \"sensitive-value\""), kind)
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
            assert!(!error.message.contains("sensitive-value"));
        }
        for raw in [
            "title !~",
            "text !~ sensitive-value",
            "title !~ 123",
            "text !~ (\"sensitive-value\")",
            "title !~ currentUser()",
            "title !~ \"sensitive-value",
            "title !~ \"sensitive-value\")",
            "NOT title ~ \"sensitive-value\"",
            "title != \"sensitive-value\"",
            "text IS EMPTY",
        ] {
            let error = parse_cql_query_for_kind(raw, kind).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{raw}");
            assert!(!error.message.contains("sensitive-value"), "{raw}");
        }
        for raw in [
            format!(
                "title !~ \"{}\"",
                "x".repeat(MAX_CONFLUENCE_STRING_LITERAL_BYTES + 1)
            ),
            format!(
                "{}text !~ \"obsolete\"{}",
                "(".repeat(MAX_CONFLUENCE_QUERY_DEPTH + 1),
                ")".repeat(MAX_CONFLUENCE_QUERY_DEPTH + 1)
            ),
            format!(
                "{}title !~ \"obsolete\"",
                " ".repeat(MAX_CONFLUENCE_RAW_QUERY_BYTES)
            ),
        ] {
            assert_eq!(
                parse_cql_query_for_kind(&raw, kind)
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::InputInvalid
            );
        }
    }
}

#[test]
fn text_negation_keeps_positive_type_and_authorized_space_before_grouped_filters() {
    for (_, kind) in SEARCHES {
        for (scope, predicate) in [
            (
                EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
                " AND space IN (ENG)",
            ),
            (
                EffectiveSearchScope::AllExcept(BTreeSet::from(["PRIVATE".to_string()])),
                " AND space NOT IN (PRIVATE)",
            ),
            (EffectiveSearchScope::AllExcept(BTreeSet::new()), ""),
        ] {
            for filter in [
                "title !~ \"obsolete\"",
                "text !~ \"deprecated\"",
                "title !~ \"obsolete\" AND text !~ \"deprecated\"",
                "title !~ \"obsolete\" OR text !~ \"deprecated\"",
                "(title !~ \"obsolete\" AND space != ARCHIVE) OR (text !~ \"deprecated\" AND id NOT IN (12345))",
            ] {
                let raw = format!("{filter} ORDER BY lastModified DESC");
                let built = build_confluence_search_query_for_kind(
                    &ConfluenceSearchQueryInput::Cql { value: raw.clone() },
                    &scope,
                    &SearchLimitsConfig::default(),
                    kind,
                )
                .unwrap();
                assert_eq!(
                    built.cql,
                    format!(
                        "type = {}{predicate} AND ({filter}) ORDER BY lastModified DESC",
                        kind.cql_type()
                    )
                );
                assert_eq!(built.canonical_caller_cql, raw);
                assert_eq!(built.canonical_caller_cql_hash, sha256_hex(raw.as_bytes()));
                assert!(!built.query_shape.to_string().contains("obsolete"));
                assert!(!built.query_shape.to_string().contains("deprecated"));
            }
        }
    }
}

#[test]
fn text_negation_discovery_matches_field_support_and_keeps_text_mode_positive() {
    for (_, kind) in SEARCHES {
        let documentation = cql_documentation(kind);
        for field in documentation["cql"]["fields"].as_array().unwrap() {
            let has_negation = field["operators"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operator| operator == "!~");
            assert_eq!(
                has_negation,
                field["name"] == "title" || field["name"] == "text"
            );
            if has_negation {
                assert_eq!(field["operators"], json!(["~", "!~"]));
            }
        }
        assert!(
            !documentation["cql"]["unsupported"]
                .as_array()
                .unwrap()
                .contains(&json!("!~"))
        );
        let built = build_confluence_search_query_for_kind(
            &ConfluenceSearchQueryInput::Text {
                value: "obsolete".to_string(),
            },
            &EffectiveSearchScope::AllExcept(BTreeSet::new()),
            &SearchLimitsConfig::default(),
            kind,
        )
        .unwrap();
        assert_eq!(built.canonical_caller_cql, "title ~ \"obsolete\"");
    }
}

fn content(kind: ConfluenceSearchContentKind, space: &str, status: &str) -> Value {
    json!({
        "id": "67890",
        "type": kind.cql_type(),
        "status": status,
        "title": "Search result",
        "space": { "key": space },
        "version": { "number": 1 }
    })
}

#[tokio::test]
async fn text_negation_preserves_whole_response_containment_and_hashed_diagnostics() {
    let filter = "title !~ \"obsolete\" AND (text !~ \"deprecated\" OR space = PRIVATE)";
    for (action, kind) in SEARCHES {
        for (scope, predicate) in [
            (
                SearchAuthorizationScope::from_exact_values(vec!["ENG".into()]),
                "space IN (ENG)",
            ),
            (
                SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".into()]),
                "space NOT IN (PRIVATE)",
            ),
        ] {
            for invalid in [None, Some(("PRIVATE", "current")), Some(("ENG", "draft"))] {
                let server = MockServer::start().await;
                let mut results = vec![content(kind, "ENG", "current")];
                if let Some((space, status)) = invalid {
                    results.push(content(kind, space, status));
                }
                Mock::given(method("GET"))
                    .and(path("/wiki/rest/api/content/search"))
                    .and(query_param(
                        "cql",
                        format!("type = {} AND {predicate} AND ({filter})", kind.cql_type()),
                    ))
                    .and(query_param("expand", "space,version,history"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(json!({"results": results})),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                let provider = ConfluenceProvider::with_backend(
                    confluence_config(),
                    ProviderLimits::default(),
                    Arc::new(http_confluence_backend_for_server(&server)),
                );
                let inputs = json!({"query": {"type": "cql", "value": filter}});
                assert!(provider.local_scopes(action, &inputs).unwrap()["space"].is_empty());
                let result = provider
                    .invoke(
                        InvocationBuilder::new("confluence", action)
                            .inputs(inputs)
                            .credential(credential())
                            .search(SearchAuthorization::new("space", scope.clone()))
                            .build(),
                    )
                    .await;
                if invalid.is_some() {
                    let error = result.unwrap_err();
                    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
                    assert!(error.result.is_none());
                    assert!(error.object_ids.is_none());
                } else {
                    let result = result.unwrap();
                    let collection = if action == "search" { "pages" } else { "blogs" };
                    assert_eq!(result.result[collection].as_array().unwrap().len(), 1);
                    assert!(result.result[collection][0].get("body").is_none());
                    let audit = result.audit.as_ref().unwrap();
                    assert_eq!(audit["queryAstVersion"], 3);
                    assert_eq!(
                        audit["textOperandHashes"],
                        json!([sha256_hex(b"obsolete"), sha256_hex(b"deprecated")])
                    );
                    assert_eq!(
                        audit["queryShape"]["filter"]["children"][0]["operator"],
                        "!~"
                    );
                    assert!(!audit.to_string().contains("obsolete"));
                    assert!(!audit.to_string().contains("deprecated"));
                }
                assert_eq!(
                    server.received_requests().await.unwrap().len(),
                    1,
                    "no metadata or body fetches"
                );
            }
        }
    }
}
