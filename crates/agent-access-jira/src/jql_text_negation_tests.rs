//! Text negation uses the bounded grammar and existing search authority.
use super::*;

#[test]
fn text_negation_is_field_specific_and_preserves_canonical_quoted_operands() {
    for (field, canonical) in [
        ("SUMMARY", "summary"),
        ("Description", "description"),
        ("CF[12345]", "cf[12345]"),
    ] {
        for (operand, expected) in [
            ("'obsolete'", "\"obsolete\""),
            ("'OR'", "\"OR\""),
            ("''", "\"\""),
            ("'obsolete*'", "\"obsolete*\""),
            (r#"'"obsolete phrase"'"#, r#""\"obsolete phrase\"""#),
            (r#"'path\\segment'"#, r#""path\\segment""#),
            (r#"'can\'t'"#, r#""can't""#),
            (
                r#""value\" OR project = PRIVATE""#,
                r#""value\" OR project = PRIVATE""#,
            ),
        ] {
            let query = format!("{field} !~ {operand}");
            let expected = format!("{canonical} !~ {expected}");
            assert_eq!(canonical_jql(&query), expected);
            assert_eq!(canonical_jql(&expected), expected);
            assert!(projects(&query).is_empty());
        }
        assert_eq!(
            JqlField::from_input(field).unwrap().operator_names().last(),
            Some(&"!~")
        );
    }
    assert_eq!(JqlField::Text.operator_names(), vec!["~"]);
}

#[test]
fn text_negation_rejects_unsupported_fields_and_operand_shapes_without_values() {
    for field in [
        "text",
        "project",
        "key",
        "issuekey",
        "status",
        "updated",
        "fixVersion",
        "affectedVersion",
        "environment",
        "comment",
    ] {
        let error = parse_jql_query(
            &format!("{field} !~ 'privateSearchMarker*'"),
            CredentialMode::Service,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{field}");
        assert!(!error.message.contains("privateSearchMarker"));
    }
    for field in ["summary", "description", "cf[12345]"] {
        for operand in [
            "",
            "privateSearchMarker",
            "('privateSearchMarker')",
            "('privateSearchMarker', 'another')",
            "privateSearchMarker()",
            "EMPTY",
            "NULL",
            "'privateSearchMarker\\q'",
            "'privateSearchMarker\n'",
            "'privateSearchMarker雪'",
        ] {
            let error = parse_jql_query(&format!("{field} !~ {operand}"), CredentialMode::Service)
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
            assert!(!error.message.contains("privateSearchMarker"));
        }
    }
    for query in [
        "summary != 'privateSearchMarker'",
        "description = 'privateSearchMarker'",
        "description IS EMPTY",
        "summary IN ('privateSearchMarker')",
        "NOT summary ~ 'privateSearchMarker'",
        "summary !~ 'privateSearchMarker' AND description !~ 'other' OR status = Done",
    ] {
        let error = parse_jql_query(query, CredentialMode::Service).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(!error.message.contains("privateSearchMarker"));
    }
    assert!(parse_jql_query("cf[12345] IS EMPTY", CredentialMode::Service).is_ok());
}

#[test]
fn text_negation_preserves_query_limits() {
    for field in ["summary", "description", "cf[12345]"] {
        let bounded = format!("{field} !~ '{}'", "x".repeat(MAX_JIRA_STRING_LITERAL_BYTES));
        assert!(parse_jql_query(&bounded, CredentialMode::Service).is_ok());
        for (query, expected) in [
            (
                format!(
                    "{field} !~ '{}'",
                    "x".repeat(MAX_JIRA_STRING_LITERAL_BYTES + 1)
                ),
                "string literal byte cap",
            ),
            (
                format!("{field} !~ 'x'{}", " ".repeat(MAX_JIRA_RAW_QUERY_BYTES)),
                "byte cap",
            ),
            (
                format!(
                    "{}{field} !~ 'x'{}",
                    "(".repeat(MAX_JIRA_QUERY_DEPTH + 1),
                    ")".repeat(MAX_JIRA_QUERY_DEPTH + 1)
                ),
                "nesting",
            ),
        ] {
            let error = parse_jql_query(&query, CredentialMode::Service).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
            assert!(error.message.contains(expected), "{}", error.message);
        }
    }
    let many_clauses = vec!["summary !~ 'x'"; MAX_JIRA_QUERY_TOKENS / 4 + 2].join(" OR ");
    let error = parse_jql_query(&many_clauses, CredentialMode::Service).unwrap_err();
    assert!(error.message.contains("token cap"));
}

#[test]
fn plain_text_search_keeps_positive_matching_and_issue_key_translation() {
    let limits = SearchLimitsConfig::default();
    assert_eq!(
        jira_text_query("!~ obsolete", &limits).unwrap().emit(),
        "text ~ \"!~ obsolete\""
    );
    assert_eq!(
        jira_text_query("PROJ-1", &limits).unwrap().emit(),
        "key = PROJ-1"
    );
}

fn static_search(inputs: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::new("jira", "search")
        .inputs(inputs)
        .identity(crate::InvocationIdentity::new("agent-one", true))
        .credential_mode(CredentialMode::Service)
        .credential(test_credential())
        .search(SearchAuthorization::new("project", scope))
        .build()
}

#[tokio::test]
async fn text_negation_search_uses_only_execution_search_and_redacts_diagnostics() {
    let backend = Arc::new(StubJiraBackend {
        search_page: Mutex::new(Some(page_with_upstream_token("private-upstream-token"))),
        ..StubJiraBackend::default()
    });
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let query = "summary !~ 'privateSummary' AND description !~ 'privateDescription' AND cf[12345] !~ 'privateCustom'";
    let inputs = json!({"query":{"type":"jql","value":query}});
    assert!(provider.local_scopes("search", &inputs).unwrap()["project"].is_empty());
    let response = provider
        .invoke_checked(static_search(
            inputs,
            SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
        ))
        .await
        .unwrap();
    let observations = backend.credential_observations.lock().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].operation, "search");
    assert_eq!(observations[0].credential, test_credential());
    assert_eq!(
        backend.last_search.lock().unwrap().as_ref().unwrap().jql,
        format!("({}) AND project IN (PROJ)", canonical_jql(query))
    );
    let audit = response.audit.unwrap();
    assert_eq!(audit["queryAstVersion"], 5);
    assert_eq!(
        audit["textOperandHashes"],
        json!([
            sha256_hex(b"privateSummary"),
            sha256_hex(b"privateDescription"),
            sha256_hex(b"privateCustom")
        ])
    );
    let clauses = audit["queryShape"]["filter"]["children"]
        .as_array()
        .unwrap();
    assert_eq!(clauses.len(), 3);
    for clause in clauses {
        assert_eq!(clause["operator"], "!~");
        assert_eq!(clause["operand"]["value"]["type"], "string");
    }
    let audit_text = audit.to_string();
    for private in [
        "privateSummary",
        "privateDescription",
        "privateCustom",
        "private-upstream-token",
    ] {
        assert!(!audit_text.contains(private));
    }
}

#[tokio::test]
async fn incompatible_text_searchers_preserve_http_error_mapping_without_discovery() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errorMessages":["private-upstream-message: incompatible field privateSearchMarker"],
            "errors":{}
        })))
        .expect(2)
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
    let mut errors = vec![];
    for operator in ["~", "!~"] {
        let query = format!("cf[12345] {operator} 'privateSearchMarker'");
        let error = agent_access_provider::host::with_correlation_context(
            crate::CorrelationContext::for_tests(),
            provider.invoke_checked(static_search(
                json!({"query":{"type":"jql","value":query}}),
                SearchAuthorizationScope::from_exact_values(vec!["PROJ".into()]),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
        assert!(!format!("{error:?}").contains("private"));
        errors.push(error.message);
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(
        errors[0],
        jira_backend_error(JiraBackendError::HttpStatus(400)).message
    );
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for (request, operator) in requests.iter().zip(["~", "!~"]) {
        assert_eq!(request.url.path(), "/rest/api/3/search/jql");
        let params = request.url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            params.get("jql").unwrap(),
            &format!("(cf[12345] {operator} \"privateSearchMarker\") AND project IN (PROJ)")
        );
    }
}
