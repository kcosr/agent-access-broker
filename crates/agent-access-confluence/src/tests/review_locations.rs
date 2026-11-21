//! HTTP-backed regressions for response, lifecycle and URL-location review fixes.
use super::*;
use agent_access_provider::test_support::ScopeRequestFixture;

fn space(status: &str) -> Value {
    // Deliberately omit currentActiveAlias: only the trusted space webui names it.
    json!({"id":"10","key":"ENG","status":status,"homepageId":"200",
        "_links":{"webui":"/spaces/ALIAS"}})
}

fn page(id: &str) -> Value {
    json!({"id":id,"type":"page","status":"current","spaceId":"10",
        "title":"Fixture","parentId":null,"parentType":null,
        "version":{"number":7},"body":{"storage":{"value":"<p>body</p>"}}})
}

fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("confluence", action)
        .inputs(inputs)
        .resources(ResourceScopes::from([("space".into(), vec!["ENG".into()])]))
        .credential(credential())
        .lookup_credential(credential())
        .build()
}

async fn get(server: &MockServer, route: &str, value: Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .mount(server)
        .await;
}

async fn fixture(status: &str) -> (MockServer, ConfluenceProvider) {
    let server = MockServer::start().await;
    get(&server, "/wiki/api/v2/spaces/10", space(status)).await;
    get(
        &server,
        "/wiki/api/v2/spaces",
        json!({"results":[space(status)]}),
    )
    .await;
    for id in ["123", "200", "300"] {
        get(&server, &format!("/wiki/api/v2/pages/{id}"), page(id)).await;
    }
    get(
        &server,
        "/wiki/api/v2/pages",
        json!({"results":[page("123")]}),
    )
    .await;
    let mut body = page("123");
    body["space"] = json!({"key":"ENG","_links":{"webui":"/spaces/ALIAS"}});
    body["_links"] = json!({"webui":"/spaces/ALIAS/pages/123/Fixture"});
    get(&server, "/wiki/rest/api/content/123", body).await;
    let mut blog = page("700");
    blog["type"] = json!("blogpost");
    blog["_links"] = json!({"webui":"/spaces/ALIAS/blog/700/Fixture"});
    get(&server, "/wiki/api/v2/blogposts/700", blog).await;
    get(
        &server,
        "/wiki/rest/api/content/123/child/attachment",
        json!({"results":[]}),
    )
    .await;
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(http_confluence_backend_for_server(&server)),
    );
    (server, provider)
}

fn update_inputs() -> Value {
    json!({"pageId":"123","baseVersion":7,"contentFormat":"storage","content":"<p>changed</p>"})
}

#[tokio::test]
async fn accepted_update_response_mismatches_are_protocol_errors_with_applied_receipts() {
    for (field, value) in [
        ("/id", json!("999")),
        ("/spaceId", json!("11")),
        ("/status", json!("draft")),
        ("/version/number", json!(9)),
        ("/version/number", Value::Null),
        ("/type", json!("blogpost")),
    ] {
        let (server, provider) = fixture("current").await;
        let mut response = page("123");
        response["version"]["number"] = json!(8);
        *response.pointer_mut(field).unwrap() = value;
        Mock::given(method("PUT"))
            .and(path("/wiki/api/v2/pages/123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let error = provider
            .invoke_fixture(invocation("page.update", update_inputs()))
            .await
            .unwrap_err();
        assert_eq!(error.decision(), Decision::Error, "{field}: {error:?}");
        assert_eq!(
            error.reason_code(),
            ReasonCode::UpstreamProtocolFailed,
            "{field}: {error:?}"
        );
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["mutationStatus"], "applied_unverified", "{field}");
        assert_eq!(result["retrySafe"], false, "{field}");
        assert!(!result.to_string().contains("changed"));
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "PUT")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn current_content_in_archived_spaces_keeps_existing_read_and_update_access() {
    let (server, provider) = fixture("archived").await;
    for (action, inputs) in [
        ("page.view", json!({"pageId":"123"})),
        ("blog.view", json!({"blogId":"700"})),
        ("attachment.list", json!({"pageId":"123"})),
    ] {
        let result = provider
            .invoke_fixture(invocation(action, inputs))
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        let space = if action == "attachment.list" {
            &result.result["page"]["space"]
        } else {
            &result.result["space"]
        };
        assert_eq!(space, "ENG", "{action}");
    }
    let mut response = page("123");
    response["version"]["number"] = json!(8);
    Mock::given(method("PUT"))
        .and(path("/wiki/api/v2/pages/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;
    let result = provider
        .invoke_fixture(invocation("page.update", update_inputs()))
        .await
        .unwrap();
    assert_eq!(result.result["version"], 8);
}

#[tokio::test]
async fn archived_spaces_still_refuse_all_four_creation_paths_before_mutation() {
    for action in [
        "page.create",
        "page.draft.create",
        "blog.create",
        "blog.draft.create",
    ] {
        let (server, provider) = fixture("archived").await;
        let error = provider
            .invoke_fixture(invocation(
                action,
                json!({
                    "space":"ENG","title":"Created","contentFormat":"storage","content":"<p>new</p>"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::ScopeUnresolved,
            "{action}: {error:?}"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn space_listing_rejects_archived_rows_and_requests_current_spaces() {
    let server = MockServer::start().await;
    let mut row = space("archived");
    row["name"] = json!("Fixture");
    row["type"] = json!("global");
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/spaces"))
        .and(query_param("status", "current"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results":[row]})))
        .expect(1)
        .mount(&server)
        .await;
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(http_confluence_backend_for_server(&server)),
    );
    let request = InvocationBuilder::from(invocation("space.list", json!({})))
        .search(confluence_search_preflight(["ENG"]))
        .build();
    let error = provider.invoke_fixture(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn webui_only_space_alias_is_consistent_in_real_locator_resolution_and_reads() {
    let (_server, provider) = fixture("current").await;
    let alias_page = "https://example.atlassian.net/wiki/spaces/ALIAS/pages/123";
    let alias_target = "https://example.atlassian.net/wiki/spaces/ALIAS/pages/300";
    let alias_blog = "https://example.atlassian.net/wiki/spaces/ALIAS/blog/700";
    for (action, inputs) in [
        ("page.view", json!({"url":alias_page})),
        ("attachment.list", json!({"url":alias_page})),
        ("blog.view", json!({"url":alias_blog})),
        (
            "page.create",
            json!({"space":"ENG","title":"Child","parentUrl":alias_page,"contentFormat":"storage","content":"<p>new</p>"}),
        ),
        (
            "page.draft.create",
            json!({"space":"ENG","title":"Child","parentUrl":alias_page,"contentFormat":"storage","content":"<p>new</p>"}),
        ),
        (
            "page.move",
            json!({"url":alias_page,"targetUrl":alias_target,"position":"append"}),
        ),
    ] {
        let scopes = provider
            .fixture_space_lookup(
                action,
                &inputs,
                Some(&AtlassianCredential::from_static(credential())),
            )
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        assert_eq!(scopes["space"], vec!["ENG"]);
        if matches!(action, "page.view" | "blog.view" | "attachment.list") {
            let result = provider
                .invoke_fixture(invocation(action, inputs))
                .await
                .unwrap();
            let space = if action == "attachment.list" {
                &result.result["page"]["space"]
            } else {
                &result.result["space"]
            };
            assert_eq!(space, "ENG");
        }
    }
    for alias in ["alias", "OTHER"] {
        let error = provider.fixture_space_lookup("page.view", &json!({"url":format!("https://example.atlassian.net/wiki/spaces/{alias}/pages/123")}), Some(&AtlassianCredential::from_static(credential()))).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    }
}

#[tokio::test]
async fn space_only_creation_admission_does_not_read_parent_ancestors() {
    for action in ["page.create", "page.draft.create"] {
        let (server, provider) = fixture("current").await;
        let mut child = page("123");
        child["parentId"] = json!("999");
        child["parentType"] = json!("folder");
        Mock::given(method("GET"))
            .and(path("/wiki/api/v2/pages/123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(child))
            .with_priority(1)
            .mount(&server)
            .await;
        let input = json!({"space":"ENG","title":"Child","parent":{"kind":"page","id":"123"},"contentFormat":"storage","content":"<p>new</p>"});
        let fixture = ScopeRequestFixture::new("confluence", action, input)
            .lookup_credential(credential())
            .containment_evidence_level(ContainmentEvidenceLevel::ContainerOnly);
        provider
            .resolve_scopes(fixture.request())
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| matches!(
            r.url.path(),
            "/wiki/api/v2/spaces" | "/wiki/api/v2/pages/123"
        )));
    }
}

#[tokio::test]
async fn move_root_limit_counts_only_roots_in_the_current_space() {
    for (space_key, count, allowed) in [("OPS", 65, true), ("ENG", 64, true), ("ENG", 65, false)] {
        let (server, provider) = fixture("current").await;
        Mock::given(method("GET"))
            .and(wiremock::matchers::path_regex(
                "^/wiki/api/v2/pages/1[0-9]{3}$",
            ))
            .respond_with(|request: &wiremock::Request| {
                let id = request.url.path().rsplit('/').next().unwrap();
                ResponseTemplate::new(200).set_body_json(page(id))
            })
            .mount(&server)
            .await;
        let registry =
            ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
                .unwrap();
        let roots = (1000..1000 + count)
            .map(|id| {
                registry
                    .typed_selector(
                        CONFLUENCE_CONTENT_RESOURCE.id(),
                        &ResourceSelector::Subtree {
                            value: format!(
                                "https://example.atlassian.net/wiki/spaces/{space_key}/pages/{id}"
                            ),
                        },
                    )
                    .unwrap()
            })
            .collect();
        let input = json!({"pageId":"123","targetPageId":"300","position":"append"});
        let fixture = ScopeRequestFixture::new("confluence", "page.move", input)
            .lookup_credential(credential())
            .containment_evidence_level(ContainmentEvidenceLevel::CompleteLineage)
            .containment_roots(roots);
        let result = provider.resolve_scopes(fixture.request()).await;
        if allowed {
            assert!(result.is_ok(), "{space_key}/{count}: {:?}", result.err());
        } else {
            assert_eq!(
                result.err().unwrap().reason_code(),
                ReasonCode::ScopeUnresolved
            );
        }
        let root_reads = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                request
                    .url
                    .path()
                    .rsplit('/')
                    .next()
                    .is_some_and(|id| id.len() == 4)
            })
            .count();
        assert_eq!(root_reads, if space_key == "OPS" { 0 } else { 64 });
    }
}
