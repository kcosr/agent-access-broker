//! Stable custom-field references share the bounded parser and search authority.
use super::*;

#[test]
fn custom_field_operators_render_canonical_jql_and_preserve_quoted_text() {
    for (input, expected) in [
        ("CF[12345] = 'release'", "cf[12345] = release"),
        ("cf[12345] != Done", "cf[12345] != Done"),
        ("cf[12345] < 10", "cf[12345] < 10"),
        ("cf[12345] <= 10.5", "cf[12345] <= 10.5"),
        ("cf[12345] > 10", "cf[12345] > 10"),
        ("cf[12345] >= '2026-10-01'", "cf[12345] >= 2026-10-01"),
        ("cf[12345] in ('red', blue)", "cf[12345] IN (red, blue)"),
        (
            "cf[12345] not in ('first value', second)",
            "cf[12345] NOT IN (\"first value\", second)",
        ),
        ("cf[12345] is empty", "cf[12345] IS EMPTY"),
        ("cf[12345] is not empty", "cf[12345] IS NOT EMPTY"),
        ("cf[12345] ~ 'EXT-4812'", "cf[12345] ~ \"EXT-4812\""),
        ("cf[12345] = 'OR'", "cf[12345] = \"OR\""),
        (
            "cf[18446744073709551615] = value",
            "cf[18446744073709551615] = value",
        ),
    ] {
        assert_eq!(canonical_jql(input), expected, "{input}");
        assert_eq!(canonical_jql(expected), expected, "round trip: {input}");
    }
    assert_eq!(
        projects("cf[12345] = OTHER-1 AND project = PROJ"),
        set(["PROJ"])
    );
}

#[test]
fn custom_field_discovery_capabilities_match_the_parser_and_documentation() {
    let (reference, operators) = jql_field_capabilities("CF[12345]").unwrap();
    assert_eq!(reference, "cf[12345]");
    assert_eq!(
        operators,
        [
            "=",
            "!=",
            "<",
            "<=",
            ">",
            ">=",
            "IN",
            "NOT IN",
            "IS EMPTY",
            "IS NOT EMPTY",
            "~"
        ]
    );
    assert_eq!(
        jql_documentation()["jql"]["customFields"]["operators"],
        json!(operators)
    );
    for operator in &operators {
        let operand = match *operator {
            "IN" | "NOT IN" => "(value)",
            "IS EMPTY" | "IS NOT EMPTY" => "",
            "~" => "\"value\"",
            _ => "value",
        };
        assert!(
            parse_jql_query(
                &format!("{reference} {operator} {operand}"),
                CredentialMode::Service
            )
            .is_ok()
        );
    }
    assert_eq!(
        jql_field_capabilities("FIXVERSIONS"),
        Some((
            "fixVersion".into(),
            vec!["=", "!=", "IN", "NOT IN", "IS EMPTY", "IS NOT EMPTY"]
        ))
    );
    for unsupported in [
        "External ticket",
        "customfield_12345",
        "cf[0]",
        "cf[01]",
        "cf[-1]",
        "cf[1] OR project",
    ] {
        assert!(
            jql_field_capabilities(unsupported).is_none(),
            "{unsupported}"
        );
    }
}

#[test]
fn custom_field_references_are_strict_bounded_tokens() {
    for reference in [
        "cf[]",
        "cf[0]",
        "cf[00]",
        "cf[01]",
        "cf[-1]",
        "cf[+1]",
        "cf[1.0]",
        "cf[1e2]",
        "cf[ 1]",
        "cf[1 ]",
        "cf [1]",
        "cf[1",
        "cf[[1]]",
        "cf[1]]",
        "cf[1][2]",
        "cf[1]suffix",
        "cf[１２３]",
        "cf[18446744073709551616]",
        "customfield_12345",
        "'cf[12345]'",
        "\"External ticket\"",
    ] {
        let error = parse_jql_query(
            &format!("{reference} = privateValue"),
            CredentialMode::Service,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{reference}");
        assert!(!error.message.contains("privateValue"));
        assert!(!error.message.contains("External ticket"));
    }
    for query in [
        "cf[12345] ~ privateValue",
        "cf[12345] !~ 'privateValue'",
        "cf[12345] WAS privateValue",
        "cf[12345] CHANGED",
        "NOT cf[12345] = privateValue",
        "cf[12345] = now()",
        "cf[12345] = currentUser()",
        "cf[12345] IN (currentUser())",
        "cf[12345] >= startOfDay(-7d)",
        "cf[12345] = privateFunction(privateValue)",
        "ORDER BY cf[12345]",
        "cf[12345] = privateValue ORDER BY cf[12345] DESC",
        "status = cf[12345]",
        "cf[12345] = 'privateValue'; project = OTHER",
        "cf[12345 OR project = OTHER] = privateValue",
        "cf[12345] IN ()",
        "cf[12345] IS NULL",
    ] {
        let error = parse_jql_query(query, CredentialMode::PerUser).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{query}");
        for private in ["privateValue", "privateFunction", "OTHER"] {
            assert!(
                !error.message.contains(private),
                "{query}: {}",
                error.message
            );
        }
    }
}

#[test]
fn custom_fields_preserve_query_caps() {
    let values = (0..MAX_JIRA_IN_LIST_VALUES)
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_jql_query(&format!("cf[12345] IN ({values})"), CredentialMode::Service).is_ok());
    for (query, expected) in [
        (format!("cf[12345] IN ({values},101)"), "item cap"),
        (
            format!(
                "cf[12345] ~ \"{}\"",
                "x".repeat(MAX_JIRA_STRING_LITERAL_BYTES + 1)
            ),
            "string literal byte cap",
        ),
        (
            format!("cf[{}] = x", "1".repeat(MAX_JIRA_RAW_QUERY_BYTES)),
            "byte cap",
        ),
        (
            format!(
                "{}cf[12345] = x{}",
                "(".repeat(MAX_JIRA_QUERY_DEPTH + 1),
                ")".repeat(MAX_JIRA_QUERY_DEPTH + 1)
            ),
            "nesting",
        ),
        (
            vec!["cf[1] = x"; MAX_JIRA_QUERY_TOKENS / 4 + 2].join(" AND "),
            "token cap",
        ),
    ] {
        let error = parse_jql_query(&query, CredentialMode::Service).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(error.message.contains(expected), "{}", error.message);
    }
}

#[test]
fn custom_field_predicates_keep_authorization_and_redacted_shapes() {
    let input = JiraSearchQueryInput::Jql {
        value: "cf[12345] ~ \"privateSearchTerm\" OR project = OTHER".into(),
    };
    for (scope, expected) in [
        (
            EffectiveSearchScope::Finite(set(["PROJ"])),
            "(cf[12345] ~ \"privateSearchTerm\" OR project = OTHER) AND project IN (PROJ)",
        ),
        (
            EffectiveSearchScope::AllExcept(set(["PRIVATE"])),
            "(cf[12345] ~ \"privateSearchTerm\" OR project = OTHER) AND project NOT IN (PRIVATE)",
        ),
        (
            EffectiveSearchScope::AllExcept(BTreeSet::new()),
            "cf[12345] ~ \"privateSearchTerm\" OR project = OTHER",
        ),
    ] {
        let query = build_jira_search_query(
            &input,
            &scope,
            &SearchLimitsConfig::default(),
            CredentialMode::Service,
        )
        .unwrap();
        assert_eq!(query.jql, expected);
        assert_eq!(
            query.text_operand_hashes,
            vec![sha256_hex(b"privateSearchTerm")]
        );
        assert!(!query.query_shape.to_string().contains("privateSearchTerm"));
        assert!(!query.query_shape.to_string().contains("OTHER"));
        assert_eq!(
            query.query_shape["filter"]["children"][0]["field"],
            "cf[12345]"
        );
    }
    // Quotes and backslashes remain data when re-emitted beside the scope.
    let query = canonical_jql(r#"cf[12345] = "value\" OR project = OTHER""#);
    assert_eq!(query, r#"cf[12345] = "value\" OR project = OTHER""#);
}

#[tokio::test]
async fn custom_field_search_continuations_bind_normalized_query_and_current_authority() {
    let backend = Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(page_with_upstream_token("private-upstream-cursor"))),
        ..StubJiraBackend::default()
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let invoke = |query: &str, token: Option<&str>| {
        let mut inputs = json!({"query": {"type": "jql", "value": query}});
        if let Some(token) = token {
            inputs["nextPageToken"] = json!(token);
        }
        per_user_invocation("search", inputs, vec![])
    };
    let first = provider
        .invoke(invoke("CF[12345] ~ 'privateSearchTerm'", None))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap();
    let audit = first.audit.unwrap().to_string();
    for private in ["privateSearchTerm", "private-upstream-cursor", token] {
        assert!(!audit.contains(private));
    }
    provider
        .invoke(invoke("cf[12345] ~ \"privateSearchTerm\"", Some(token)))
        .await
        .unwrap();
    assert_eq!(
        backend
            .last_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .next_page_token
            .as_deref(),
        Some("private-upstream-cursor")
    );
    for changed in [
        "cf[12346] ~ \"privateSearchTerm\"",
        "cf[12345] ~ \"differentTerm\"",
        "cf[12345] = privateSearchTerm",
    ] {
        let error = provider
            .invoke(invoke(changed, Some(token)))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }
    let changed_scope =
        InvocationBuilder::from(invoke("cf[12345] ~ \"privateSearchTerm\"", Some(token)))
            .search(search_preflight(["PROJ", "OTHER"]))
            .build();
    assert!(
        provider
            .invoke(changed_scope)
            .await
            .unwrap_err()
            .message
            .contains("effective Jira project scope changed")
    );

    // Even a custom predicate which names another project cannot release its issues.
    let mut denied = page_with_upstream_token("private-upstream-cursor");
    denied.issues[0].key = "OTHER-1".into();
    denied.issues[0].project = "OTHER".into();
    *backend.search_page.lock().unwrap() = Some(denied);
    let error = provider
        .invoke(invoke("cf[12345] = OTHER OR project = OTHER", None))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.result.is_none());
    assert_eq!(
        backend.last_search.lock().unwrap().as_ref().unwrap().jql,
        "(cf[12345] = OTHER OR project = OTHER) AND project IN (PROJ)"
    );
}
