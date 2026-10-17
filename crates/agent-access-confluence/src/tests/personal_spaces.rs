use super::*;

const PERSONAL_KEYS: &[&str] = &[
    "~alice",
    "~Alice.Smith",
    "~alice_notes-team",
    "~alice+notes@example.com",
    "~557058:12345678-abcd-4321-abcd-123456789abc",
];

#[test]
fn personal_space_key_grammar_is_bounded_and_preserves_exact_case() {
    for key in PERSONAL_KEYS
        .iter()
        .copied()
        .chain(["~a", "~0", "ENG", "ENG_2-A"])
    {
        assert_eq!(validate_space_key(key).unwrap(), key);
    }
    for key in [format!("~{}", "a".repeat(254)), "A".repeat(255)] {
        assert_eq!(validate_space_key(&key).unwrap(), key);
    }
    for key in [
        "",
        "A",
        "eng",
        "Eng",
        "~",
        "~~alice",
        "~.alice",
        "~@alice",
        "~alice/bob",
        "~alice\\bob",
        "~alice?x=1",
        "~alice#fragment",
        "~alice&x=1",
        "~alice%40example.com",
        "%7Ealice",
        "~alice\"",
        "~alice'",
        "~alice;",
        "~alice*",
        "~alice ",
        "~alice\n",
        "~álîce",
    ] {
        assert!(validate_space_key(key).is_err(), "accepted {key:?}");
    }
    for key in [format!("~{}", "a".repeat(255)), "A".repeat(256)] {
        assert!(validate_space_key(&key).is_err());
    }
}

#[test]
fn personal_space_url_locators_and_projections_preserve_literal_keys() {
    let config = confluence_config();
    for key in PERSONAL_KEYS {
        let page_url =
            format!("https://example.atlassian.net/wiki/spaces/{key}/pages/123456/Notes");
        let blog_url =
            format!("https://example.atlassian.net/wiki/spaces/{key}/blog/2026/10/15/7777/Notes");
        assert_eq!(
            page_locator_from_url(&page_url, &config)
                .unwrap()
                .candidate_space
                .as_deref(),
            Some(*key)
        );
        assert_eq!(
            blog_locator_from_url(&blog_url, &config)
                .unwrap()
                .candidate_space
                .as_deref(),
            Some(*key)
        );
        for (url, kind, id) in [
            (&page_url, ConfluenceBrowserContentKind::Page, "123456"),
            (&blog_url, ConfluenceBrowserContentKind::Blog, "7777"),
        ] {
            assert_eq!(
                content_browser_url(Some(url), kind, id, key, &config).unwrap(),
                *url
            );
            assert!(content_browser_url(Some(url), kind, id, "~bob", &config).is_err());
        }
        assert_eq!(
            space_browser_url(None, key, &config).unwrap(),
            format!("https://example.atlassian.net/wiki/spaces/{key}")
        );
        let overview = format!("/spaces/{key}/overview");
        assert_eq!(
            space_browser_url(Some(&overview), key, &config).unwrap(),
            format!("https://example.atlassian.net/wiki{overview}")
        );
    }
    // Percent escapes are not aliases for literal resource keys, including a
    // double-encoded escape or an encoded path/query delimiter.
    for key in [
        "%7Ealice",
        "~%61lice",
        "~alice%40example.com",
        "~alice%2Fbob",
        "~alice%3Fx",
        "~alice%252Fbob",
        "~alice%",
        "~alice%GG",
    ] {
        let page_url =
            format!("https://example.atlassian.net/wiki/spaces/{key}/pages/123456/Notes");
        let blog_url = format!("https://example.atlassian.net/wiki/spaces/{key}/blog/7777/Notes");
        assert!(page_locator_from_url(&page_url, &config).is_err(), "{key}");
        assert!(blog_locator_from_url(&blog_url, &config).is_err(), "{key}");
        assert!(
            content_browser_url(
                Some(&page_url),
                ConfluenceBrowserContentKind::Page,
                "123456",
                "~alice",
                &config
            )
            .is_err()
        );
        assert!(space_browser_url(Some(&format!("/spaces/{key}")), "~alice", &config).is_err());
    }
    assert!(space_browser_url(Some("/spaces/~Alice"), "~alice", &config).is_err());
}

#[test]
fn personal_space_cql_quotes_keys_and_keeps_exact_containment() {
    for key in PERSONAL_KEYS {
        let raw = format!("space = \"{key}\"");
        assert_eq!(canonical_cql(&raw), raw);
        assert_eq!(
            parse_cql_spaces(&raw).unwrap(),
            BTreeSet::from([key.to_string()])
        );
        let scope = EffectiveSearchScope::Finite(BTreeSet::from([key.to_string()]));
        assert!(scope.authorizes_value(key));
        assert!(!scope.authorizes_value("~bob"));
        let query = build_confluence_search_query(
            &ConfluenceSearchQueryInput::Cql {
                value: String::new(),
            },
            &scope,
            &SearchLimitsConfig::default(),
        )
        .unwrap();
        assert_eq!(query.cql, format!("space IN (\"{key}\") AND type = page"));
    }
    let excluded = EffectiveSearchScope::AllExcept(BTreeSet::from(["~alice".to_string()]));
    let query = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: String::new(),
        },
        &excluded,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(query.cql, "space NOT IN (\"~alice\") AND type = page");
    assert!(!excluded.authorizes_value("~alice"));
    assert!(excluded.authorizes_value("~Alice"));
    for raw in [
        "space = ~alice",
        "space = \"~alice%40example.com\"",
        "space = \"~alice/bob\"",
        "space = \"~alice\\\" OR space = ENG\"",
    ] {
        assert!(parse_cql_spaces(raw).is_err(), "{raw}");
    }
}

#[tokio::test]
async fn personal_space_http_lookup_encodes_keys_and_parses_authoritative_metadata() {
    let server = MockServer::start().await;
    for key in PERSONAL_KEYS {
        Mock::given(method("GET"))
            .and(path("/wiki/api/v2/spaces"))
            .and(query_param("keys", *key))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"id": "98765", "key": key, "status": "current", "homepageId": "55555"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let backend = http_confluence_backend_for_server(&server);
    for key in PERSONAL_KEYS {
        let response = agent_access_provider::host::with_correlation_context(
            crate::CorrelationContext::for_tests(),
            backend.space_by_key(key, &credential()),
        )
        .await
        .unwrap();
        assert_eq!(response.value.key, *key);
        assert_eq!(response.value.homepage_id.as_deref(), Some("55555"));
        let page = page_from_value(personal_content_json("page", key)).unwrap();
        assert_eq!(page.space, *key);
        let page_result = page_view_result(
            &page,
            &confluence_config().content.page_formats,
            &confluence_config(),
        )
        .unwrap();
        assert_eq!(page_result["space"], *key);
        assert_eq!(
            page_result["spaceUrl"],
            format!("https://example.atlassian.net/wiki/spaces/{key}")
        );
    }
    let requests = server.received_requests().await.unwrap();
    let email_request = requests
        .iter()
        .find(|request| request.url.query().unwrap().contains("%2B"))
        .unwrap();
    assert_eq!(
        email_request
            .url
            .query_pairs()
            .find(|(name, _)| name == "keys")
            .unwrap()
            .1,
        "~alice+notes@example.com"
    );
    for key in ["~alice%40example.com", "~alice/bob", "~"] {
        assert!(page_from_value(personal_content_json("page", key)).is_err());
        assert!(
            search_blog_from_value(
                json!({"results": [personal_content_json("blogpost", key)]}),
                1
            )
            .is_err()
        );
        assert!(space_from_value(json!({"id": "98765", "key": key})).is_err());
    }
}

fn personal_content_json(content_type: &str, key: &str) -> Value {
    json!({
        "id": "123456", "type": content_type, "status": "current", "title": "Notes",
        "space": {"key": key}, "version": {"number": 7},
        "body": {"storage": {"value": "<p>notes</p>"}}
    })
}

fn personal_invocation(action: &str, inputs: Value, key: &str) -> ProviderInvocation {
    InvocationBuilder::from(invocation(action, inputs))
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec![key.to_string()],
        )]))
        .build()
}

#[tokio::test]
async fn personal_space_page_and_blog_reads_and_writes_keep_authorized_space() {
    let mut backend = AttributionStubConfluenceBackend::new();
    backend.page.space = "~alice".to_string();
    backend.blog.space = "~alice".to_string();
    backend.space.key = "~alice".to_string();
    let backend = Arc::new(backend);
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    for (action, inputs) in [
        ("page.view", json!({"pageId": "123456"})),
        ("blog.view", json!({"blogId": "7777"})),
        (
            "page.create",
            json!({"space": "~alice", "title": "Notes", "contentFormat": "storage", "content": "<p>notes</p>"}),
        ),
        (
            "page.update",
            json!({"pageId": "123456", "baseVersion": 7, "contentFormat": "storage", "content": "<p>notes</p>"}),
        ),
        (
            "blog.create",
            json!({"space": "~alice", "title": "Notes", "contentFormat": "storage", "content": "<p>notes</p>"}),
        ),
        (
            "blog.update",
            json!({"blogId": "7777", "baseVersion": 3, "contentFormat": "storage", "content": "<p>notes</p>"}),
        ),
    ] {
        let result = provider
            .invoke(personal_invocation(action, inputs.clone(), "~alice"))
            .await
            .unwrap();
        assert_eq!(result.result["space"], "~alice", "{action}");
        assert_eq!(
            result.result["spaceUrl"], "https://example.atlassian.net/wiki/spaces/~alice",
            "{action}"
        );
        if matches!(action, "page.update" | "blog.update") {
            // Updates receive an already admitted invocation. Their lookup hook
            // supplies the authoritative space for the host's grant decision;
            // a fabricated invocation is not a host authorization test.
            let scopes = provider
                .lookup_scopes(action, &inputs, Some(&credential()))
                .await
                .unwrap();
            assert_eq!(
                scopes,
                ResourceScopes::from([("space".to_string(), vec!["~alice".to_string()])]),
                "{action}"
            );
            continue;
        }
        for other_key in ["~Alice", "~bob"] {
            let error = provider
                .invoke(personal_invocation(action, inputs.clone(), other_key))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved, "{action}");
        }
    }
    assert_eq!(backend.page_create_requests.lock().unwrap().len(), 1);
    assert_eq!(backend.page_update_requests.lock().unwrap().len(), 1);
    assert_eq!(backend.blog_create_requests.lock().unwrap().len(), 1);
    assert_eq!(backend.blog_update_requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn personal_space_page_and_blog_searches_enforce_finite_and_excluded_scopes() {
    for (action, kind, result_field) in [
        ("search", "page", "pages"),
        ("blog.search", "blogpost", "blogs"),
    ] {
        for (returned_key, all_except, allowed) in [
            ("~alice", false, true),
            ("~Alice", false, false),
            ("~bob", false, false),
            ("~alice", true, true),
            ("~bob", true, false),
        ] {
            let server = MockServer::start().await;
            let predicate = if all_except {
                "space NOT IN (\"~bob\")"
            } else {
                "space IN (\"~alice\")"
            };
            Mock::given(method("GET"))
                .and(path("/wiki/rest/api/content/search"))
                .and(query_param("cql", format!("{predicate} AND type = {kind}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        json!({"results": [personal_content_json(kind, returned_key)]}),
                    ),
                )
                .expect(1)
                .mount(&server)
                .await;
            let provider = ConfluenceProvider::with_backend(
                confluence_config(),
                ProviderLimits::default(),
                Arc::new(http_confluence_backend_for_server(&server)),
            );
            let scope = if all_except {
                SearchAuthorizationScope::AllExcept {
                    excluded_values: vec!["~bob".to_string()],
                }
            } else {
                SearchAuthorizationScope::Finite {
                    values: vec!["~alice".to_string()],
                }
            };
            let request = InvocationBuilder::from(invocation(
                action,
                json!({"query": {"type": "cql", "value": ""}}),
            ))
            .search(SearchAuthorization::new("space".to_string(), scope))
            .build();
            let result = agent_access_provider::host::with_correlation_context(
                crate::CorrelationContext::for_tests(),
                provider.invoke(request),
            )
            .await;
            if allowed {
                let result = result.unwrap();
                assert_eq!(result.result[result_field][0]["space"], returned_key);
                assert_eq!(
                    result.result[result_field][0]["spaceUrl"],
                    format!("https://example.atlassian.net/wiki/spaces/{returned_key}")
                );
            } else {
                assert_eq!(
                    result.unwrap_err().reason_code(),
                    ReasonCode::ScopeUnresolved
                );
            }
        }
    }
}

#[test]
fn personal_space_draft_handles_preserve_space_and_reject_other_exact_grants() {
    let continuations = ConfluenceContinuations::new(
        &confluence_config(),
        &ProviderLimits::default(),
        Some(agent_access_provider::test_support::test_signing_key(7)),
    );
    for content_type in [
        ConfluenceDraftContentType::Page,
        ConfluenceDraftContentType::Blog,
    ] {
        let mut content = draft_content("123456", content_type);
        content.space = "~alice".to_string();
        let request = personal_invocation("page.draft.view", json!({}), "~alice");
        let handle =
            ConfluenceDraftHandle::new(content_type, &content, ConfluenceDraftOrigin::New, None);
        let token = continuations
            .seal_draft_handle(request.context(), request.execution(), &handle)
            .unwrap();
        let opened = continuations
            .open_draft_handle(
                request.context(),
                request.execution(),
                content_type,
                "123456",
                &token,
            )
            .unwrap();
        assert_eq!(opened.space, "~alice");
        ensure_authorized_draft_handle(&opened, request.resource_scopes().unwrap()).unwrap();
        ensure_draft_content_matches_handle(&content, &opened).unwrap();
        for other_key in ["~Alice", "~bob"] {
            let request = personal_invocation("page.draft.view", json!({}), other_key);
            assert_invalid_draft_handle(ensure_authorized_draft_handle(
                &opened,
                request.resource_scopes().unwrap(),
            ));
            content.space = other_key.to_string();
            assert_eq!(
                ensure_draft_content_matches_handle(&content, &opened)
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::ScopeUnresolved
            );
        }
    }
}
