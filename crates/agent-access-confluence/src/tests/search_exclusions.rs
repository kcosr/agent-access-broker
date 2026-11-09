use super::*;

const SEARCHES: [(&str, ConfluenceSearchContentKind); 2] = [
    ("search", ConfluenceSearchContentKind::Page),
    ("blog.search", ConfluenceSearchContentKind::BlogPost),
];

#[test]
fn exclusions_preserve_space_keys_content_ids_and_canonical_aliases() {
    for (_, kind) in SEARCHES {
        for (input, canonical) in [
            ("space != ARCHIVE", "space != ARCHIVE"),
            ("space not in (ARCHIVE)", "space NOT IN (ARCHIVE)"),
            (
                "space NOT IN (\"TeamDocs\", '~alice', \"3C\")",
                "space NOT IN (TeamDocs, \"~alice\", 3C)",
            ),
            ("space != \"~Alice\"", "space != \"~Alice\""),
            ("id != 12345", "id != 12345"),
            ("content.id != \"12345\"", "id != 12345"),
            ("id NOT IN (12345)", "id NOT IN (12345)"),
            (
                "content.id not in (12345, '67890')",
                "id NOT IN (12345, 67890)",
            ),
        ] {
            assert_eq!(
                parse_cql_query_for_kind(input, kind).unwrap().emit(),
                canonical,
                "{kind:?}: {input}"
            );
        }
        for input in [
            "space != *",
            "space != \"*\"",
            "space NOT IN (ENG, \"OPS*\")",
            "space NOT IN ()",
            "id != *",
            "content.id != \"*\"",
            "id != 0",
            "content.id NOT IN (12345, 01)",
            "id NOT IN ()",
            "ancestor != 12345",
            "parent NOT IN (12345)",
            "mention != alice",
            "mention NOT IN (alice)",
        ] {
            assert_eq!(
                parse_cql_query_for_kind(input, kind)
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::InputInvalid,
                "{kind:?}: {input}"
            );
        }
        for field in ["space", "id", "content.id"] {
            let value = if field == "space" { "ENG" } else { "12345" };
            let at_cap = std::iter::repeat_n(value, MAX_CONFLUENCE_IN_LIST_VALUES)
                .collect::<Vec<_>>()
                .join(", ");
            parse_cql_query_for_kind(&format!("{field} NOT IN ({at_cap})"), kind).unwrap();
            assert_eq!(
                parse_cql_query_for_kind(&format!("{field} NOT IN ({at_cap}, {value})"), kind)
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::InputInvalid
            );
        }
    }
}

#[test]
fn negative_filters_keep_positive_type_policy_grouping_and_sort_order() {
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
                "space != ARCHIVE",
                "id NOT IN (12345, 67890)",
                "space != ARCHIVE OR id NOT IN (12345, 67890)",
                "space NOT IN (ARCHIVE) AND (id != 12345 OR space = PRIVATE)",
            ] {
                let raw = format!("{filter} ORDER BY lastModified DESC");
                let query = build_confluence_search_query_for_kind(
                    &ConfluenceSearchQueryInput::Cql { value: raw.clone() },
                    &scope,
                    &SearchLimitsConfig::default(),
                    kind,
                )
                .unwrap();
                assert_eq!(
                    query.cql,
                    format!(
                        "type = {}{predicate} AND ({filter}) ORDER BY lastModified DESC",
                        kind.cql_type()
                    )
                );
                assert_eq!(query.canonical_caller_cql, raw);
                assert_eq!(query.canonical_caller_cql_hash, sha256_hex(raw.as_bytes()));
            }
        }
    }
}

#[test]
fn generated_grammar_matches_exclusions_and_unchanged_hierarchy_rules() {
    for (_, kind) in SEARCHES {
        let documentation = cql_documentation(kind);
        let fields = documentation["cql"]["fields"].as_array().unwrap();
        for name in ["space", "id"] {
            let field = fields.iter().find(|field| field["name"] == name).unwrap();
            assert_eq!(field["operators"], json!(["=", "!=", "IN", "NOT IN"]));
        }
        let mention = fields
            .iter()
            .find(|field| field["name"] == "mention")
            .unwrap();
        assert_eq!(mention["operators"], json!(["=", "IN"]));
        for name in ["ancestor", "parent"] {
            let field = fields.iter().find(|field| field["name"] == name);
            if kind == ConfluenceSearchContentKind::Page {
                assert_eq!(field.unwrap()["operators"], json!(["=", "IN"]));
            } else {
                assert!(field.is_none());
            }
        }
    }
}

fn content(kind: ConfluenceSearchContentKind, id: &str, space: &str) -> Value {
    json!({
        "id": id,
        "type": kind.cql_type(),
        "status": "current",
        "title": "Search result",
        "space": { "key": space },
        "version": { "number": 1 }
    })
}

#[tokio::test]
async fn exclusion_searches_check_the_whole_page_against_authorized_spaces() {
    let filter = "space NOT IN (ARCHIVE) AND (content.id != 12345 OR space = PRIVATE)";
    let canonical = "space NOT IN (ARCHIVE) AND (id != 12345 OR space = PRIVATE)";
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
            for include_denied in [false, true] {
                let server = MockServer::start().await;
                let mut results = vec![content(kind, "67890", "ENG")];
                if include_denied {
                    results.push(content(kind, "98765", "PRIVATE"));
                }
                let expected_cql = format!(
                    "type = {} AND {predicate} AND ({canonical})",
                    kind.cql_type()
                );
                Mock::given(method("GET"))
                    .and(path("/wiki/rest/api/content/search"))
                    .and(query_param("cql", &expected_cql))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "results": results
                    })))
                    .expect(1)
                    .mount(&server)
                    .await;
                let provider = ConfluenceProvider::with_backend(
                    confluence_config(),
                    ProviderLimits::default(),
                    Arc::new(http_confluence_backend_for_server(&server)),
                );
                let inputs = json!({ "query": { "type": "cql", "value": filter } });
                // Negative space and ID operands do not request scopes or
                // metadata lookup; the host's authority remains independent.
                assert!(provider.local_scopes(action, &inputs).unwrap()["space"].is_empty());
                let request = InvocationBuilder::new("confluence", action)
                    .inputs(inputs)
                    .credential(credential())
                    .search(SearchAuthorization::new("space", scope.clone()))
                    .build();
                let result = provider.invoke_checked(request).await;
                if include_denied {
                    let error = result.unwrap_err();
                    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
                    assert!(error.result.is_none());
                    assert!(error.object_ids.is_none());
                } else {
                    let result = result.unwrap();
                    let key = if action == "search" { "pages" } else { "blogs" };
                    assert_eq!(result.result[key].as_array().unwrap().len(), 1);
                    assert_eq!(result.result[key][0]["space"], "ENG");
                }
                let sent = server.received_requests().await.unwrap();
                assert_eq!(sent.len(), 1, "no metadata lookup for {action}");
                assert_eq!(sent[0].url.path(), "/wiki/rest/api/content/search");
            }
        }
    }
}

#[tokio::test]
async fn wildcard_keys_stay_invalid_and_text_wildcards_remain_constrained() {
    for (action, kind) in SEARCHES {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/wiki/rest/api/content/search"))
            .and(query_param(
                "cql",
                format!(
                    "type = {} AND space IN (ENG) AND (title ~ \"*\")",
                    kind.cql_type()
                ),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
            .expect(1)
            .mount(&server)
            .await;
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            Arc::new(http_confluence_backend_for_server(&server)),
        );
        for spaces in [json!([]), json!(["*"])] {
            let error = provider
                .invoke_checked(
                    InvocationBuilder::new("confluence", action)
                        .inputs(json!({ "query": { "type": "cql", "value": "id != 12345" }, "spaces": spaces }))
                        .credential(credential())
                        .search(confluence_search_preflight(["ENG"]))
                        .build(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        provider
            .invoke_checked(
                InvocationBuilder::new("confluence", action)
                    .inputs(json!({ "query": { "type": "text", "value": "*" } }))
                    .credential(credential())
                    .search(confluence_search_preflight(["ENG"]))
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[test]
fn documented_composed_cql_examples_match_the_builder() {
    let document = include_str!("../../../../docs/providers-confluence.md");
    let examples = document
        .split("Examples with a finite space scope of `ENG`:")
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(examples.len(), SEARCHES.len());
    for (section, (_, kind)) in examples.into_iter().zip(SEARCHES) {
        let rows = section
            .lines()
            .skip_while(|line| !line.starts_with("| Input |"))
            .skip(2)
            .take_while(|line| line.starts_with("| "));
        let mut checked = 0;
        for row in rows {
            let cells = row
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>();
            assert_eq!(cells.len(), 2, "{row}");
            let input = cells[0].trim_matches('`');
            let expected = cells[1].trim_matches('`');
            let (flag, value) = input.split_once(' ').unwrap();
            let value = value.trim_matches('\'').to_string();
            let query = match flag {
                "--cql" => ConfluenceSearchQueryInput::Cql { value },
                "--text" => ConfluenceSearchQueryInput::Text { value },
                _ => panic!("unsupported documented search input: {input}"),
            };
            let result = build_confluence_search_query_for_kind(
                &query,
                &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
                &SearchLimitsConfig::default(),
                kind,
            )
            .unwrap();
            assert_eq!(result.cql, expected, "{kind:?}: {input}");
            checked += 1;
        }
        assert!(checked >= 3, "missing examples for {kind:?}");
    }
}
