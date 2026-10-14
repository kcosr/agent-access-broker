use super::*;

const DATE_QUERY: &str =
    "created >= startOfWeek(-1w) AND created <= endOfWeek(-1w) ORDER BY created DESC";

#[test]
fn underscore_project_keys_are_canonical_and_match_discovery_schema() {
    let descriptor = jira_descriptor(&jira_config());
    let action = descriptor
        .actions
        .iter()
        .find(|action| action.action == "issue_type.list")
        .unwrap();
    let pattern = Regex::new(
        action.input_schema["properties"]["project"]["pattern"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    for project in ["OPS_TOOLS", "A_B2", "OPS__TOOLS", "OPS_"] {
        assert!(
            JIRA_PROJECT_RESOURCE.is_canonical_target(project),
            "{project}"
        );
        assert!(pattern.is_match(project), "{project}");
        assert_eq!(validate_project_key(project).unwrap(), project);
        assert!(is_issue_key(&format!("{project}-12345")));
    }
    for project in [
        "_OPS",
        "ops_tools",
        "Ops_TOOLS",
        "1OPS",
        "OPS-TOOLS",
        "OPS.TOOLS",
        "OPS/TOOLS",
        "O",
        "OPS_TOOLS\n",
    ] {
        assert!(
            !JIRA_PROJECT_RESOURCE.is_canonical_target(project),
            "{project:?}"
        );
        assert!(!pattern.is_match(project), "{project:?}");
        assert!(validate_project_key(project).is_err(), "{project:?}");
    }
    for key in [
        "OPS_TOOLS-0",
        "OPS_TOOLS-01",
        "OPS_TOOLS--1",
        "OPS_TOOLS-",
        "OPS_TOOLS-1/other",
        "OPS_TOOLS-1\n",
    ] {
        assert!(!is_issue_key(key), "{key:?}");
    }
}

#[test]
fn underscore_issue_locators_and_jql_preserve_project_identity() {
    let config = jira_config();
    let locator = issue_locator_from_key("OPS_TOOLS-12345").unwrap();
    assert_eq!(locator.candidate_project, "OPS_TOOLS");
    for url in [
        "https://example.atlassian.net/browse/OPS_TOOLS-12345",
        "https://example.atlassian.net/jira/software/c/projects/OPS_TOOLS/issues/OPS_TOOLS-12345",
    ] {
        let locator = issue_locator_from_url(url, &config).unwrap();
        assert_eq!(locator.issue_key, "OPS_TOOLS-12345");
        assert_eq!(locator.candidate_project, "OPS_TOOLS");
    }
    assert!(issue_locator_from_url(
        "https://example.atlassian.net/jira/software/c/projects/OTHER_TOOLS/issues/OPS_TOOLS-12345",
        &config,
    )
    .is_err());
    for query in [
        "project = OPS_TOOLS",
        "project = \"OPS_TOOLS\"",
        "key IN (OPS_TOOLS-12345, OPS_TOOLS-12346)",
        "key = 'OPS_TOOLS-12345'",
    ] {
        assert_eq!(projects(query), set(["OPS_TOOLS"]));
        let canonical = canonical_jql(query);
        assert_eq!(canonical_jql(&canonical), canonical);
        assert_eq!(projects(&canonical), set(["OPS_TOOLS"]));
    }
    let query = build_jira_search_query(
        &JiraSearchQueryInput::Jql {
            value: DATE_QUERY.to_string(),
        },
        &EffectiveSearchScope::Finite(set(["OPS_TOOLS"])),
        &SearchLimitsConfig::default(),
        CredentialMode::PerUser,
    )
    .unwrap();
    assert!(query.jql.contains("project IN (OPS_TOOLS)"));
    assert_eq!(projects(&query.jql), set(["OPS_TOOLS"]));
    let text = build_jira_search_query(
        &JiraSearchQueryInput::Text {
            value: "OPS_TOOLS-12345".to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
        CredentialMode::PerUser,
    )
    .unwrap();
    assert_eq!(text.jql, "key = OPS_TOOLS-12345");
}

#[tokio::test]
async fn finite_search_scope_still_rejects_unauthorized_underscore_projects() {
    let backend = Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(search_page_with_issue("OPS_TOOLS", "OPS_TOOLS-12345"))),
        ..StubJiraBackend::default()
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let finite = |token: Option<&str>| {
        InvocationBuilder::from(search_request(vec![], token))
            .search(SearchAuthorization::new(
                "project".to_string(),
                SearchAuthorizationScope::Finite {
                    values: vec!["PROJ".to_string()],
                },
            ))
            .build()
    };
    let token = continuation_for(&provider, &backend, finite(None), "next-page-fixture").await;
    let error = provider.invoke(finite(Some(&token))).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.internal_diagnostic_code,
        Some("jira_search_project_unauthorized")
    );
    assert_eq!(
        error.audit.as_ref().unwrap()["searchResultValidation"]["issueIndex"],
        8
    );
    assert!(
        backend
            .last_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .jql
            .contains("project IN (PROJ)")
    );
    assert_eq!(
        backend
            .last_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .next_page_token
            .as_deref(),
        Some("next-page-fixture")
    );
}

/// The sealed continuation for Jira's `upstream` token, issued by serving
/// `request` a first page of in-scope issues.
async fn continuation_for(
    provider: &JiraProvider,
    backend: &StubJiraBackend,
    request: ProviderInvocation,
    upstream: &str,
) -> String {
    let mut first_page = search_page_with_issue("PROJ", "PROJ-9");
    first_page.next_page_token = Some(upstream.to_string());
    first_page.is_last = Some(false);
    let next_page = backend.search_page.lock().unwrap().replace(first_page);
    let first = provider.invoke(request).await.unwrap();
    *backend.search_page.lock().unwrap() = next_page;
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert_ne!(token, upstream);
    token.to_string()
}

fn search_request(excluded: Vec<String>, token: Option<&str>) -> ProviderInvocation {
    let mut inputs = json!({"query":{"type":"jql","value":DATE_QUERY},"maxResults":50});
    if let Some(token) = token {
        inputs["nextPageToken"] = json!(token);
    }
    InvocationBuilder::from(per_user_invocation("search", inputs, vec![]))
        .search(SearchAuthorization::new(
            "project".to_string(),
            SearchAuthorizationScope::AllExcept {
                excluded_values: excluded,
            },
        ))
        .build()
}

fn search_page_with_issue(project: &str, key: &str) -> JiraSearchPage {
    let mut issues = (1..=50)
        .map(|number| {
            let mut issue = visible_issue();
            issue.key = format!("PROJ-{number}");
            issue
        })
        .collect::<Vec<_>>();
    issues[8].project = project.to_string();
    issues[8].key = key.to_string();
    JiraSearchPage {
        issues,
        max_results: 50,
        start_at: 0,
        total: None,
        next_page_token: None,
        is_last: Some(true),
    }
}

#[tokio::test]
async fn unrestricted_paginated_search_accepts_underscore_issue_on_continuation() {
    let mut first_page = search_page_with_issue("PROJ", "PROJ-9");
    first_page.next_page_token = Some("next-page-fixture".to_string());
    first_page.is_last = Some(false);
    let backend = Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(first_page)),
        ..StubJiraBackend::default()
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let first = provider.invoke(search_request(vec![], None)).await.unwrap();
    assert_eq!(first.result["issues"].as_array().unwrap().len(), 50);
    assert_eq!(first.result["isLast"], false);
    // The caller receives a sealed continuation, never Jira's token.
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert_ne!(token, "next-page-fixture");
    assert!(!token.contains("next-page-fixture"));
    assert!(token.len() <= provider.search_pages.max_token_bytes());
    assert!(
        backend
            .last_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .next_page_token
            .is_none()
    );
    *backend.search_page.lock().unwrap() =
        Some(search_page_with_issue("OPS_TOOLS", "OPS_TOOLS-12345"));

    let second = provider
        .invoke(search_request(vec![], Some(token)))
        .await
        .unwrap();
    assert_eq!(second.result["issues"].as_array().unwrap().len(), 50);
    assert_eq!(second.result["issues"][8]["key"], "OPS_TOOLS-12345");
    assert_eq!(
        second.result["issues"][8]["webUrl"],
        "https://example.atlassian.net/browse/OPS_TOOLS-12345"
    );
    assert_eq!(second.result["isLast"], true);
    assert!(second.result["nextPageToken"].is_null());
    assert_eq!(
        second.object_ids.as_ref().unwrap()["issueKeys"][8],
        "OPS_TOOLS-12345"
    );
    assert_eq!(
        second.audit.as_ref().unwrap()["injectedScopePredicate"],
        "none"
    );
    assert!(
        second
            .audit
            .as_ref()
            .unwrap()
            .get("searchResultValidation")
            .is_none()
    );
    let search = backend.last_search.lock().unwrap();
    let search = search.as_ref().unwrap();
    assert_eq!(search.jql, DATE_QUERY);
    assert_eq!(search.next_page_token.as_deref(), Some("next-page-fixture"));
    assert_eq!(search.max_results, 50);
    assert_eq!(backend.credential_observations.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn underscore_search_results_still_require_matching_and_authorized_projects() {
    for (project, excluded, code, matches, authorized) in [
        (
            "OPS_TOOLS",
            vec!["OPS_TOOLS".to_string()],
            "jira_search_project_unauthorized",
            true,
            false,
        ),
        (
            "OTHER_TOOLS",
            vec![],
            "jira_search_issue_project_mismatch",
            false,
            true,
        ),
    ] {
        let backend = Arc::new(StubJiraBackend {
            search_page: Mutex::new(Some(search_page_with_issue(project, "OPS_TOOLS-12345"))),
            ..StubJiraBackend::default()
        });
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let token = continuation_for(
            &provider,
            &backend,
            search_request(excluded.clone(), None),
            "next-page-fixture",
        )
        .await;
        let error = provider
            .invoke(search_request(excluded.clone(), Some(&token)))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(error.internal_diagnostic_code, Some(code));
        assert!(error.result.is_none());
        assert!(error.object_ids.is_none());
        let audit = error.audit.unwrap();
        let validation = &audit["searchResultValidation"];
        assert_eq!(validation["issueIndex"], 8);
        assert_eq!(validation["issueKeyValid"], true);
        assert_eq!(validation["keyProjectMatches"], matches);
        assert_eq!(validation["projectAuthorized"], authorized);
        assert_eq!(audit["pageTokenPresent"], true);
        assert_eq!(audit["resultCount"], 50);
        let search = backend.last_search.lock().unwrap();
        assert_eq!(
            search.as_ref().unwrap().next_page_token.as_deref(),
            Some("next-page-fixture")
        );
        let jql = &search.as_ref().unwrap().jql;
        if excluded.is_empty() {
            assert_eq!(jql, DATE_QUERY);
        } else {
            assert!(jql.contains("project NOT IN (OPS_TOOLS)"), "{jql}");
        }
    }
}
