//! Direct parent references remain predicates over independently authorized children.
use super::*;

#[test]
fn parent_references_canonicalize_keys_ids_and_mixed_lists() {
    for reference in [
        "PROJ-100",
        "OPS_TOOLS-123",
        "10001",
        "184467440737095516160",
    ] {
        for quoted in [
            reference.to_string(),
            format!("'{reference}'"),
            format!("\"{reference}\""),
        ] {
            for operator in ["=", "!=", "IN", "NOT IN"] {
                let (operand, expected) = if operator.contains("IN") {
                    (
                        format!("({quoted}, 'OTHER-2', 10002)"),
                        format!("({reference}, OTHER-2, 10002)"),
                    )
                } else {
                    (quoted.clone(), reference.to_string())
                };
                let input = format!("PARENT {operator} {operand}");
                assert_eq!(
                    canonical_jql(&input),
                    format!("parent {operator} {expected}")
                );
                assert!(projects(&input).is_empty());
                assert!(parse_jql_query(&input, CredentialMode::PerUser).is_ok());
            }
        }
    }
    assert_eq!(
        jql_field_capabilities("PARENT").unwrap(),
        ("parent".into(), vec!["=", "!=", "IN", "NOT IN"])
    );
    assert!(jql_field_capabilities("parentEpic").is_none());
}

#[tokio::test]
async fn invalid_parent_inputs_fail_before_dispatch_without_echoing_values() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let mut invalid = vec![];
    for value in [
        "0",
        "01",
        "-1",
        "+1",
        "1.2",
        "proj-1",
        "PROJ-0",
        "*",
        "",
        "EMPTY",
        "NULL",
        "PRIVATE_MARKER",
        "https://example.invalid/PROJ-1",
        "PROJ-1 OR project = PRIVATE",
    ] {
        for operand in [
            value.to_string(),
            format!("'{value}'"),
            format!("\"{value}\""),
        ] {
            // An unquoted complete second clause is valid JQL, not an operand.
            if operand == "PROJ-1 OR project = PRIVATE" {
                continue;
            }
            invalid.push(format!("parent = {operand}"));
            invalid.push(format!("parent IN (PROJ-1, {operand})"));
        }
    }
    for suffix in [
        "IS EMPTY",
        "IS NOT EMPTY",
        "~ 'PROJ-1'",
        "!~ 'PROJ-1'",
        "> 1",
        ">= 1",
        "< 1",
        "<= 1",
        "= currentUser()",
        "= now()",
        "IN ()",
        "= PROJ-1 ORDER BY parent",
        "WAS PROJ-1",
    ] {
        invalid.push(format!("parent {suffix}"));
    }
    invalid.push("NOT parent = PROJ-1".into());
    for query in invalid {
        let request = InvocationBuilder::from(per_user_invocation(
            "search",
            json!({"query":{"type":"jql","value":query}}),
            vec![],
        ))
        .search(SearchAuthorization::new(
            "project",
            SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
        ))
        .build();
        let error = provider.invoke_checked(request).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{query}");
        assert!(!error.message.contains("PRIVATE_MARKER"));
        assert!(!error.message.contains("example.invalid"));
    }
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[test]
fn parent_filters_keep_shared_query_limits() {
    let values = (1..=100)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(parse_jql_query(&format!("parent IN ({values})"), CredentialMode::Service).is_ok());
    for query in [
        format!("parent IN ({values}, 101)"),
        format!(
            "parent = '{}'",
            "1".repeat(MAX_JIRA_STRING_LITERAL_BYTES + 1)
        ),
        format!("parent = 1{}", " ".repeat(MAX_JIRA_RAW_QUERY_BYTES)),
        format!(
            "{}parent = 1{}",
            "(".repeat(MAX_JIRA_QUERY_DEPTH + 1),
            ")".repeat(MAX_JIRA_QUERY_DEPTH + 1)
        ),
        vec!["parent = 1"; MAX_JIRA_QUERY_TOKENS / 4 + 2].join(" OR "),
    ] {
        assert_eq!(
            parse_jql_query(&query, CredentialMode::Service)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[tokio::test]
async fn parent_search_audit_uses_value_free_shape_and_only_execution_search() {
    let backend = Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(page_with_upstream_token("private-upstream-token"))),
        ..StubJiraBackend::default()
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let inputs = json!({"query":{"type":"jql","value":"parent = PRIVATE-123"}});
    assert!(provider.local_scopes("search", &inputs).unwrap()["project"].is_empty());
    let request = InvocationBuilder::from(per_user_invocation("search", inputs, vec![]))
        .search(SearchAuthorization::new(
            "project",
            SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
        ))
        .build();
    let response = provider.invoke_checked(request).await.unwrap();
    let audit = response.audit.unwrap();
    assert_eq!(audit["queryAstVersion"], 5);
    assert_eq!(audit["queryShape"]["filter"]["field"], "parent");
    assert!(!audit.to_string().contains("PRIVATE-123"));
    assert!(!audit.to_string().contains("private-upstream-token"));
    let observations = backend.credential_observations.lock().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].operation, "search");
}

#[tokio::test]
async fn parent_upstream_rejection_keeps_generic_error_without_lookup() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errorMessages":["privateParentFailure"]})),
        )
        .expect(1)
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let limits = ProviderLimits::default();
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        limits.clone(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let provider = JiraProvider::with_backend(config, limits, Arc::new(backend));
    let request = InvocationBuilder::from(per_user_invocation(
        "search",
        json!({"query":{"type":"jql","value":"parent = PRIVATE-123"}}),
        vec![],
    ))
    .search(SearchAuthorization::new(
        "project",
        SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
    ))
    .build();
    let error = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        provider.invoke_checked(request),
    )
    .await
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
    assert_eq!(
        error.message,
        jira_backend_error(JiraBackendError::HttpStatus(400)).message
    );
    assert!(!format!("{error:?}").contains("privateParentFailure"));
    assert_eq!(api.received_requests().await.unwrap().len(), 1);
}
