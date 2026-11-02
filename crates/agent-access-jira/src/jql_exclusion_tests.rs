//! Resource exclusions remain filters inside independently admitted search authority.
use super::*;

#[test]
fn resource_exclusion_operators_canonicalize_keys_aliases_and_lists() {
    for (input, expected) in [
        ("PROJECT != 'OPS_TOOLS'", "project != OPS_TOOLS"),
        (
            "project not in ('ARCHIVE', \"IN\")",
            "project NOT IN (ARCHIVE, \"IN\")",
        ),
        ("key != 'PROJ-123'", "key != PROJ-123"),
        (
            "ISSUEKEY not in ('PROJ-123', OPS_TOOLS-456)",
            "key NOT IN (PROJ-123, OPS_TOOLS-456)",
        ),
        ("project NOT IN (ARCHIVE)", "project NOT IN (ARCHIVE)"),
        ("issuekey NOT IN (PROJ-123)", "key NOT IN (PROJ-123)"),
    ] {
        assert_eq!(canonical_jql(input), expected);
        assert_eq!(canonical_jql(expected), expected);
    }
    // The test-only positive-reference collector must not confuse negative
    // operands with requested projects. Production authority comes from the host.
    assert!(projects("project != PRIVATE AND issuekey NOT IN (OTHER-1)").is_empty());
    for field in ["project", "key", "issuekey"] {
        let (canonical, operators) = jql_field_capabilities(field).unwrap();
        assert_eq!(
            canonical,
            if field == "project" { "project" } else { "key" }
        );
        assert_eq!(operators, ["=", "!=", "IN", "NOT IN"]);
    }
}

#[test]
fn resource_exclusions_preserve_operand_and_complexity_limits() {
    for query in [
        "project != *",
        "project != '*'",
        "project NOT IN (PROJ, '*')",
        "project != proj",
        "project NOT IN ()",
        "key != PROJ-0",
        "key != proj-1",
        "key != '*'",
        "issuekey NOT IN (PROJ-1, '*')",
        "issuekey NOT IN ()",
        "project > PROJ",
        "key ~ 'PROJ-1'",
        "NOT project = PROJ",
        "project != PROJ AND key != PROJ-1 OR project != OTHER",
    ] {
        assert_eq!(
            parse_jql_query(query, CredentialMode::Service)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid,
            "{query}"
        );
    }
    for field in ["project", "key", "issuekey"] {
        let values = (1..=MAX_JIRA_IN_LIST_VALUES)
            .map(|index| {
                if field == "project" {
                    format!("PROJ{index}")
                } else {
                    format!("PROJ-{index}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            parse_jql_query(
                &format!("{field} NOT IN ({values})"),
                CredentialMode::Service
            )
            .is_ok()
        );
        let extra = if field == "project" {
            "OTHER"
        } else {
            "OTHER-1"
        };
        assert!(
            parse_jql_query(
                &format!("{field} NOT IN ({values}, {extra})"),
                CredentialMode::Service
            )
            .is_err()
        );
    }
    let deep = format!(
        "{}key != PROJ-1{}",
        "(".repeat(MAX_JIRA_QUERY_DEPTH + 1),
        ")".repeat(MAX_JIRA_QUERY_DEPTH + 1)
    );
    assert!(parse_jql_query(&deep, CredentialMode::Service).is_err());
    let large = format!("project != PROJ{}", " ".repeat(MAX_JIRA_RAW_QUERY_BYTES));
    assert!(parse_jql_query(&large, CredentialMode::Service).is_err());
}

fn invocation(inputs: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::from(per_user_invocation("search", inputs, vec![]))
        .search(SearchAuthorization::new("project", scope))
        .build()
}

fn empty_backend() -> Arc<StubJiraBackend> {
    Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(JiraSearchPage {
            issues: vec![],
            max_results: 50,
            start_at: 0,
            total: Some(0),
            next_page_token: None,
            is_last: Some(true),
        })),
        ..StubJiraBackend::default()
    })
}

#[tokio::test]
async fn exclusion_only_searches_require_finite_effective_scope_before_dispatch() {
    for query in [
        "project != ARCHIVE",
        "project NOT IN (ARCHIVE, SANDBOX)",
        "key != ARCHIVE-1",
        "issuekey NOT IN (ARCHIVE-1, SANDBOX-2)",
        "(project != ARCHIVE OR project NOT IN (PRIVATE, LEGACY)) AND project != SANDBOX",
        "(key != ARCHIVE-1 OR issuekey NOT IN (PRIVATE-1, LEGACY-2)) AND key != SANDBOX-3",
        "project != ARCHIVE AND key NOT IN (PRIVATE-1)",
        "(project != ARCHIVE OR issuekey != PRIVATE-1) AND (key NOT IN (SANDBOX-2) OR project NOT IN (LEGACY)) ORDER BY updated DESC",
        "project != PROJ",
    ] {
        for excluded in [vec![], vec!["PRIVATE".to_string()]] {
            let broad = SearchAuthorizationScope::excluding_exact_values(excluded);
            let backend = empty_backend();
            let provider = JiraProvider::with_backend(
                jira_config(),
                ProviderLimits::default(),
                backend.clone(),
            );
            let inputs = json!({"query":{"type":"jql","value":query}});
            let error = provider
                .invoke(invocation(inputs.clone(), broad.clone()))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{query}");
            assert!(
                error
                    .message
                    .contains("only project or issue-key exclusions")
            );
            for value in ["ARCHIVE", "SANDBOX", "PRIVATE", "PROJ", "LEGACY"] {
                assert!(!error.message.contains(value));
            }
            assert!(backend.credential_observations.lock().unwrap().is_empty());

            // Narrowing either broad authority to explicit projects supplies
            // the bound, even if the caller then excludes that whole selection.
            let mut narrowed = inputs.clone();
            narrowed["projects"] = json!(["PROJ"]);
            let response = provider.invoke(invocation(narrowed, broad)).await.unwrap();
            assert_eq!(response.result["issues"], json!([]));
            let finite = SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]);
            provider.invoke(invocation(inputs, finite)).await.unwrap();
            let observations = backend.credential_observations.lock().unwrap();
            assert_eq!(observations.len(), 2);
            assert!(observations.iter().all(|call| call.operation == "search"));
            let upstream = backend.last_search.lock().unwrap();
            let upstream = upstream.as_ref().unwrap();
            assert!(upstream.jql.contains(" AND project IN (PROJ)"));
            assert_eq!(upstream.projects, vec!["PROJ"]);
        }
    }
}

#[tokio::test]
async fn ordinary_clauses_keep_broad_searches_and_grouped_policy_composition() {
    for query in [
        "project != ARCHIVE AND status = Done",
        "key NOT IN (ARCHIVE-1) OR status != Done",
        "(project != ARCHIVE OR key != PRIVATE-1) AND updated >= -7d",
        "(key != ARCHIVE-1 AND project != LEGACY) OR project = PRIVATE",
        "key != ARCHIVE-1 AND issuekey = PROJ-1",
    ] {
        for (scope, expected) in [
            (
                SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
                format!("({}) AND project IN (PROJ)", canonical_jql(query)),
            ),
            (
                SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".into()]),
                format!("({}) AND project NOT IN (PRIVATE)", canonical_jql(query)),
            ),
            (
                SearchAuthorizationScope::excluding_exact_values(vec![]),
                canonical_jql(query),
            ),
        ] {
            let backend = empty_backend();
            let provider = JiraProvider::with_backend(
                jira_config(),
                ProviderLimits::default(),
                backend.clone(),
            );
            let inputs = json!({"query":{"type":"jql","value":query}});
            // Negative operands (including unauthorized project/issue keys)
            // do not add requested scope and do not trigger resource lookups.
            assert_eq!(
                provider.local_scopes("search", &inputs).unwrap()["project"],
                Vec::<String>::new()
            );
            provider.invoke(invocation(inputs, scope)).await.unwrap();
            assert_eq!(
                backend.last_search.lock().unwrap().as_ref().unwrap().jql,
                expected
            );
            let observations = backend.credential_observations.lock().unwrap();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].operation, "search");
        }
    }
}

#[tokio::test]
async fn exclusion_filters_preserve_full_page_containment_and_current_issue_identity() {
    for (scope, expected_predicate) in [
        (
            SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
            "project IN (PROJ)",
        ),
        (
            SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".into()]),
            "project NOT IN (PRIVATE)",
        ),
    ] {
        for (project, key) in [
            ("PRIVATE", "PRIVATE-9"),
            ("PROJ", "PRIVATE-9"),
            ("PROJ", "invalid"),
        ] {
            let backend = empty_backend();
            let mut denied = visible_issue();
            denied.project = project.into();
            denied.key = key.into();
            denied.summary = Some("private-result-marker".into());
            let mut page = backend.search_page.lock().unwrap().take().unwrap();
            page.issues = vec![visible_issue(), denied];
            page.total = Some(2);
            *backend.search_page.lock().unwrap() = Some(page);
            let provider = JiraProvider::with_backend(
                jira_config(),
                ProviderLimits::default(),
                backend.clone(),
            );
            let error = provider
                .invoke(invocation(
                    json!({"query":{"type":"jql","value":"project != ARCHIVE OR key = PRIVATE-9"}}),
                    scope.clone(),
                ))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
            assert!(error.result.is_none());
            assert!(!format!("{error:?}").contains("private-result-marker"));
            assert!(
                backend
                    .last_search
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .jql
                    .ends_with(expected_predicate)
            );
        }
    }
}

#[tokio::test]
async fn wildcard_text_stays_contained_and_wildcard_project_entries_stay_invalid() {
    let backend = empty_backend();
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    for inputs in [
        json!({"query":{"type":"text","value":"*"},"projects":["*"]}),
        json!({"query":{"type":"text","value":"*"},"projects":[]}),
        json!({"query":{"type":"jql","value":"project = '*'"}}),
        json!({"query":{"type":"jql","value":"*"}}),
    ] {
        assert_eq!(
            provider
                .invoke(invocation(
                    inputs,
                    SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()])
                ))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert!(backend.credential_observations.lock().unwrap().is_empty());
    for query in [
        json!({"type":"text","value":"*"}),
        json!({"type":"jql","value":"text ~ '*'"}),
    ] {
        provider
            .invoke(invocation(
                json!({"query":query}),
                SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
            ))
            .await
            .unwrap();
        assert_eq!(
            backend.last_search.lock().unwrap().as_ref().unwrap().jql,
            "(text ~ \"*\") AND project IN (PROJ)"
        );
    }
}

#[test]
fn documented_exclusion_examples_match_composed_queries() {
    for (query, expected) in [
        (
            "project != ARCHIVE AND text ~ \"deploy\"",
            "(project != ARCHIVE AND text ~ \"deploy\") AND project IN (PROJ)",
        ),
        (
            "project NOT IN (ARCHIVE, SANDBOX)",
            "(project NOT IN (ARCHIVE, SANDBOX)) AND project IN (PROJ)",
        ),
        (
            "issuekey NOT IN (PROJ-123, PROJ-456)",
            "(key NOT IN (PROJ-123, PROJ-456)) AND project IN (PROJ)",
        ),
    ] {
        let built = build_jira_search_query(
            &JiraSearchQueryInput::Jql {
                value: query.into(),
            },
            &EffectiveSearchScope::Finite(set(["PROJ"])),
            &SearchLimitsConfig::default(),
            CredentialMode::Service,
        )
        .unwrap();
        assert_eq!(built.jql, expected);
    }
}
