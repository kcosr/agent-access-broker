use super::*;
use agent_access_provider::test_support::{InvocationBuilder, TestHost, bearer_credential};
use reqwest::header::{HeaderName, HeaderValue};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(server: &MockServer) -> GitlabProviderConfig {
    serde_json::from_value(json!({"api_base_url":format!("{}/api/v4",server.uri()),"web_base_url":format!("{}/gitlab",server.uri()),"allowed_upstream_hosts":[format!("{}/api/v4/**",server.uri())]})).unwrap()
}
fn scope() -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Namespace {
            value: "team".into(),
        }],
        vec![ResourceSelector::Namespace {
            value: "team/private".into(),
        }],
    )
}
fn invocation(action: &str, input: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::new("gitlab", action)
        .inputs(input)
        .search(SearchAuthorization::new("repository", scope))
        .credential(bearer_credential("execution-only"))
        .build()
}
fn provider(config: GitlabProviderConfig) -> GitlabProvider {
    GitlabProvider::new(config, &TestHost::default().context()).unwrap()
}
fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (key, value) in pairs {
        out.append(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    out
}
fn offset_url(page: u64, size: u32) -> Url {
    Url::parse(&format!("https://gitlab.example/api/v4/search?search=needle&scope=issues&search_type=advanced&page={page}&per_page={size}")).unwrap()
}
fn link(url: &Url, position: u64, relation: &str) -> String {
    let mut url = url.clone();
    let mut fields: Vec<_> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    fields.iter_mut().find(|(key, _)| key == "page").unwrap().1 = position.to_string();
    url.query_pairs_mut().clear().extend_pairs(fields);
    format!("<{url}>; rel=\"{relation}\"")
}
fn issue(project: u64, id: u64) -> Value {
    json!({"project_id":project,"id":1000+id,"iid":id,"title":"authorized title","state":"opened","description":"preview"})
}
async fn project(server: &MockServer, id: u64, path_with_namespace: &str, status: u16) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v4/projects/{id}")))
        .and(header("authorization", "Bearer execution-only"))
        .respond_with(
            ResponseTemplate::new(status)
                .set_body_json(json!({"id":id,"path_with_namespace":path_with_namespace})),
        )
        .mount(server)
        .await;
}
async fn page(server: &MockServer, page: u64, body: Value, next: Option<&str>) {
    let mut response = ResponseTemplate::new(200)
        .insert_header("X-Search-Type", "basic")
        .set_body_json(body);
    if let Some(next) = next {
        response = response.insert_header("X-Next-Page", next);
    }
    Mock::given(method("GET"))
        .and(path("/api/v4/search"))
        .and(query_param("page", page.to_string()))
        .and(query_param("scope", "issues"))
        .and(query_param("search_type", "basic"))
        .and(header("authorization", "Bearer execution-only"))
        .respond_with(response)
        .mount(server)
        .await;
}

#[test]
fn input_validation_and_capability_matrix_are_closed() {
    let config = GitlabSearchConfig::default();
    assert!(parse_inputs("project.search", &json!({}), &config).is_ok());
    assert!(parse_inputs("search.issues", &json!({"search":" needle "}), &config).is_ok());
    for input in [
        json!({"search":""}),
        json!({"search":"  "}),
        json!({"search":"x","maxResults":0}),
        json!({"search":"x","pageToken":"é"}),
        json!({"search":"x","scope":"users"}),
        json!({"search":"x","project":"/team/repo"}),
        json!({"search":"x","engine":"zoekt"}),
        json!({"search":"x","regex":false}),
        json!({"search":"x","project":null}),
    ] {
        assert!(
            parse_inputs("search.issues", &input, &config).is_err(),
            "{input}"
        );
    }
    assert!(parse_inputs("search.code", &json!({"search":"x"}), &config).is_err());
    assert!(
        parse_inputs(
            "search.code",
            &json!({"search":"x","project":"team/repo"}),
            &config
        )
        .is_ok()
    );
    let mut zoekt = config;
    zoekt.engines.zoekt.instance_categories = vec!["code".into()];
    assert_eq!(
        parse_inputs(
            "search.code",
            &json!({"search":"x","engine":"zoekt"}),
            &zoekt
        )
        .unwrap()
        .regex,
        Some(false)
    );
    assert!(
        parse_inputs(
            "search.code",
            &json!({"search":"é".repeat(257),"project":"team/repo"}),
            &zoekt
        )
        .is_err()
    );
}

#[test]
fn configuration_rejects_unknown_duplicate_impossible_and_unusable_defaults() {
    assert!(
        serde_json::from_value::<GitlabSearchConfig>(json!({"engines":{"elastic":{}}})).is_err()
    );
    for patch in [
        json!({"default_engine":"other"}),
        json!({"max_candidate_pages":0}),
        json!({"max_candidate_pages":33}),
        json!({"max_upstream_requests":51}),
        json!({"max_upstream_requests":4097}),
        json!({"max_scan_bytes":1048575}),
        json!({"engines":{"basic":{"instance_categories":["code"]}}}),
        json!({"engines":{"basic":{"project_categories":["issues","issues"]}}}),
        json!({"engines":{"advanced":{"project_categories":["unknown"]}}}),
        json!({"engines":{"zoekt":{"project_categories":["issues"]}}}),
        json!({"default_engine":"advanced"}),
    ] {
        let config: GitlabSearchConfig = serde_json::from_value(patch.clone()).unwrap();
        let mut errors = vec![];
        config.validate(&mut errors);
        assert!(!errors.is_empty(), "{patch}");
    }
    let config: GitlabSearchConfig = serde_json::from_value(
        json!({"engines":{"basic":{"project_categories":[],"instance_categories":[]}}}),
    )
    .unwrap();
    let mut errors = vec![];
    config.validate(&mut errors);
    assert!(errors.is_empty());
}

#[test]
fn offset_pagination_obeys_every_evidence_case() {
    use pagination::Next::*;
    let url = offset_url(1, 10);
    for count in [1, 9, 10] {
        assert_eq!(
            pagination::offset(&HeaderMap::new(), &url, 1, 10, count, false).unwrap(),
            Position(2)
        );
    }
    assert_eq!(
        pagination::offset(&HeaderMap::new(), &url, 1, 10, 0, false).unwrap(),
        End
    );
    assert_eq!(
        pagination::offset(&headers(&[("x-next-page", "")]), &url, 1, 10, 10, false).unwrap(),
        End
    );
    assert_eq!(
        pagination::offset(&headers(&[("x-next-page", "2")]), &url, 1, 10, 0, false).unwrap(),
        Position(2)
    );
    for relation in ["next", "last"] {
        assert_eq!(
            pagination::offset(
                &headers(&[("link", &link(&url, 2, relation))]),
                &url,
                1,
                10,
                0,
                false
            )
            .unwrap(),
            Position(2)
        );
    }
    assert_eq!(
        pagination::offset(
            &headers(&[("link", &link(&url, 1, "last"))]),
            &url,
            1,
            10,
            10,
            false
        )
        .unwrap(),
        End
    );
    assert_eq!(
        pagination::offset(
            &headers(&[("link", "<https://elsewhere.example/help>; rel=\"help\"")]),
            &url,
            1,
            10,
            1,
            false
        )
        .unwrap(),
        Position(2)
    );
    assert_eq!(
        pagination::offset(
            &headers(&[("link", &link(&url, 1, "first"))]),
            &url,
            1,
            10,
            1,
            false
        )
        .unwrap(),
        Position(2)
    );
    // With a numeric header, proxy-generated origin/base/query values are not
    // authority. The scalar page and any supplied page size still must agree.
    assert_eq!(
        pagination::offset(
            &headers(&[
                ("x-next-page", "2"),
                (
                    "link",
                    "<https://proxy.example/other?different=x&page=2&per_page=10>; rel=\"next\""
                )
            ]),
            &url,
            1,
            10,
            10,
            false
        )
        .unwrap(),
        Position(2)
    );
}

#[test]
fn pagination_rejects_skips_duplicates_loops_and_untrusted_link_evidence() {
    let url = offset_url(2, 10);
    for pairs in [
        vec![("x-next-page", "4")],
        vec![("x-next-page", "3"), ("x-next-page", "3")],
        vec![("x-next-page", "+3")],
        vec![("x-next-page", ""), ("link", &link(&url, 3, "last"))],
        vec![("link", &link(&url, 1, "last"))],
        vec![("link", &link(&url, 4, "next"))],
        vec![
            ("x-next-page", "3"),
            ("link", "<https://proxy.example/?page=3&page=3>; rel=next"),
        ],
        vec![
            ("x-next-page", "3"),
            (
                "link",
                "<https://proxy.example/?page=3&per_page=9>; rel=next",
            ),
        ],
        vec![(
            "link",
            "<https://proxy.example/?page=3&per_page=10>; rel=next",
        )],
        vec![(
            "link",
            &format!("{}, {}", link(&url, 3, "next"), link(&url, 3, "next")),
        )],
        vec![("x-next-page", "3"), ("link", "not a link; rel=next")],
    ] {
        assert!(
            pagination::offset(&headers(&pairs), &url, 2, 10, 1, false).is_err(),
            "{pairs:?}"
        );
    }
}

#[test]
fn advanced_window_never_claims_completion_at_ceiling() {
    use pagination::Next::*;
    for count in [0, 1, 100] {
        assert_eq!(
            pagination::offset(
                &headers(&[("x-next-page", "")]),
                &offset_url(100, 100),
                100,
                100,
                count,
                true
            )
            .unwrap(),
            Window
        );
    }
    assert_eq!(
        pagination::offset(
            &headers(&[("x-next-page", "")]),
            &offset_url(133, 75),
            133,
            75,
            75,
            true
        )
        .unwrap(),
        Window
    );
    assert_eq!(
        pagination::offset(
            &headers(&[("x-next-page", "")]),
            &offset_url(133, 75),
            133,
            75,
            1,
            true
        )
        .unwrap(),
        End
    );
    assert_eq!(
        pagination::offset(&HeaderMap::new(), &offset_url(133, 75), 133, 75, 1, true).unwrap(),
        Window
    );
    assert_eq!(
        pagination::offset(&HeaderMap::new(), &offset_url(133, 75), 133, 75, 0, true).unwrap(),
        Window
    );
}

#[test]
fn keyset_validates_complete_page_progress_and_exact_next_id() {
    use pagination::Next::*;
    let url = Url::parse(
        "https://gitlab.example/api/v4/projects?per_page=2&id_after=10&pagination=keyset",
    )
    .unwrap();
    let items = vec![json!({"id":11}), json!({"id":15})];
    assert_eq!(
        pagination::keyset(&HeaderMap::new(), &url, 10, &items).unwrap(),
        Position(15)
    );
    assert_eq!(
        pagination::keyset(&HeaderMap::new(), &url, 10, &[]).unwrap(),
        End
    );
    let next = "<https://gitlab.example/api/v4/projects?per_page=2&id_after=15&pagination=keyset>; rel=next";
    assert_eq!(
        pagination::keyset(&headers(&[("link", next)]), &url, 10, &items).unwrap(),
        Position(15)
    );
    for next in [
        next.replace("id_after=15", "id_after=16"),
        next.replace("gitlab.example", "evil.example"),
        next.replace("per_page=2", "per_page=1"),
    ] {
        assert!(pagination::keyset(&headers(&[("link", &next)]), &url, 10, &items).is_err());
    }
    assert!(pagination::keyset(&headers(&[("link", next)]), &url, 10, &[]).is_err());
    assert!(pagination::keyset(&HeaderMap::new(), &url, 10, &[json!({"id":10})]).is_err());
    assert!(
        pagination::keyset(
            &HeaderMap::new(),
            &url,
            10,
            &[json!({"id":12}), json!({"id":11})]
        )
        .is_err()
    );
}

#[tokio::test]
async fn discovery_filters_live_listing_without_project_lookups_and_resumes_keysets() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    Mock::given(method("GET")).and(path("/api/v4/projects")).and(query_param("simple","false")).and(query_param("pagination","keyset")).and(query_param("order_by","id")).and(query_param("sort","asc")).and(query_param("search_namespaces","true"))
        .respond_with(|req:&wiremock::Request|{
            let after=req.url.query_pairs().find(|(key,_)|key=="id_after").map(|(_,v)|v.into_owned());
            ResponseTemplate::new(200).set_body_json(if after.is_some(){json!([])}else{json!([{"id":1,"path_with_namespace":"hidden/secret","name":"DENIED_NAME","description":"DENIED_BODY","archived":false},{"id":2,"path_with_namespace":"team/new-repository","name":"New","description":"visible","archived":false}])})
        }).expect(2).mount(&server).await;
    let first = provider
        .invoke(invocation(
            "project.search",
            json!({"maxResults":2}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(first.result["count"], 1);
    assert_eq!(first.result["items"][0]["project"], "team/new-repository");
    assert_eq!(first.result["scanStatus"], "more");
    let serialized = format!("{:?}{:?}{:?}", first.result, first.audit, first.object_ids);
    assert!(!serialized.contains("DENIED"));
    assert!(!serialized.contains("hidden/secret"));
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert_eq!(token.len(), 99);
    let second = provider
        .invoke(invocation(
            "project.search",
            json!({"maxResults":2,"pageToken":token}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(second.result["scanStatus"], "exhausted");
    assert!(second.result.get("engine").is_none());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn content_confirms_current_paths_discards_denied_and_unavailable_then_returns_whole_page() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    page(
        &server,
        1,
        json!([issue(1, 1), issue(2, 2), issue(3, 3), issue(4, 4)]),
        Some(""),
    )
    .await;
    project(&server, 1, "outside/moved", 200).await;
    project(&server, 2, "team/private/secret", 200).await;
    project(&server, 3, "team/deleted", 404).await;
    project(&server, 4, "team/reused", 200).await;
    let result = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":4}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    assert_eq!(result.result["items"][0]["iid"], 4);
    assert_eq!(result.result["scanStatus"], "exhausted");
    let all = format!(
        "{:?}{:?}{:?}",
        result.result, result.audit, result.object_ids
    );
    for denied in ["outside/moved", "team/private/secret", "team/deleted"] {
        assert!(!all.contains(denied));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 5);
}

#[tokio::test]
async fn filtered_page_budget_returns_empty_resumable_page_and_missing_headers_need_terminal_probe()
{
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_candidate_pages = 1;
    let provider = provider(cfg);
    page(&server, 1, json!([issue(1, 1)]), None).await;
    project(&server, 1, "outside/hidden", 200).await;
    page(&server, 2, json!([issue(2, 2)]), None).await;
    project(&server, 2, "team/visible", 200).await;
    page(&server, 3, json!([]), None).await;
    let first = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":2}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(first.result["count"], 0);
    assert_eq!(first.result["scanStatus"], "scan_budget");
    let second = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":2,"pageToken":first.result["nextPageToken"]}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(second.result["count"], 1);
    assert_eq!(second.result["scanStatus"], "more");
    let last = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":2,"pageToken":second.result["nextPageToken"]}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(last.result["scanStatus"], "exhausted");
}

#[tokio::test]
async fn every_confirmation_failure_except_candidate_403_404_aborts_without_cursor() {
    for status in [401, 403, 404, 500] {
        let server = MockServer::start().await;
        let provider = provider(config(&server));
        page(&server, 1, json!([issue(1, 1)]), Some("")).await;
        project(&server, 1, "team/repo", status).await;
        let result = provider
            .invoke(invocation(
                "search.issues",
                json!({"search":"needle","maxResults":1}),
                scope(),
            ))
            .await;
        if matches!(status, 403 | 404) {
            assert_eq!(result.unwrap().result["count"], 0);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
    for metadata in [
        json!({"id":0,"path_with_namespace":"team/repo"}),
        json!({"id":2,"path_with_namespace":"team/repo"}),
        json!({"id":1,"path_with_namespace":"bad path/repo"}),
    ] {
        let server = MockServer::start().await;
        let provider = provider(config(&server));
        page(&server, 1, json!([issue(1, 1)]), Some("2")).await;
        Mock::given(path("/api/v4/projects/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&server)
            .await;
        assert!(
            provider
                .invoke(invocation(
                    "search.issues",
                    json!({"search":"needle","maxResults":1}),
                    scope()
                ))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn all_six_categories_use_fixed_scopes_and_allowlisted_projections() {
    let cases = [
        ("issues", "issues", issue(7, 1), "descriptionPreview"),
        (
            "merge_requests",
            "merge_requests",
            json!({"id":12,"iid":2,"project_id":7,"target_project_id":7,"source_project_id":999,"title":"MR","state":"opened","description":"description"}),
            "descriptionPreview",
        ),
        (
            "code",
            "blobs",
            json!({"project_id":7,"path":"src/main.rs","ref":"main","startline":12,"data":"fn main()"}),
            "snippet",
        ),
        (
            "commits",
            "commits",
            json!({"project_id":7,"id":"a".repeat(40),"title":"Commit","message":"message"}),
            "messagePreview",
        ),
        (
            "wiki",
            "wiki_blobs",
            json!({"project_id":7,"group_id":null,"path":"guide.md","title":"Guide","data":"wiki"}),
            "snippet",
        ),
        (
            "comments",
            "notes",
            json!({"project_id":7,"id":123,"noteable_type":"Issue","noteable_iid":4,"noteable_id":999,"body":"comment"}),
            "bodyPreview",
        ),
    ];
    for (category, scope_name, mut hit, preview) in cases {
        let server = MockServer::start().await;
        let mut cfg = config(&server);
        cfg.search.default_engine = "advanced".into();
        cfg.search.engines.advanced.project_categories =
            CATEGORIES.iter().map(|s| (*s).into()).collect();
        cfg.search.engines.advanced.instance_categories =
            CATEGORIES.iter().map(|s| (*s).into()).collect();
        let provider = provider(cfg);
        hit["unexpected_secret"] = json!("DROP_THIS_FIELD");
        Mock::given(method("GET"))
            .and(path("/api/v4/search"))
            .and(query_param("scope", scope_name))
            .and(query_param("search_type", "advanced"))
            .and(query_param("search", "native expression"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Search-Type", "advanced")
                    .insert_header("X-Next-Page", "")
                    .set_body_json(json!([hit])),
            )
            .mount(&server)
            .await;
        project(&server, 7, "team/repo", 200).await;
        let result = provider
            .invoke(invocation(
                &format!("search.{category}"),
                json!({"search":" native expression ","maxResults":1}),
                scope(),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["count"], 1, "{category}");
        assert_eq!(result.result["items"][0]["project"], "team/repo");
        assert!(result.result["items"][0].get(preview).is_some());
        assert!(!result.result.to_string().contains("DROP_THIS_FIELD"));
        assert!(!result.result.to_string().contains("source_project"));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn explicit_project_uses_safe_rename_current_authority_and_numeric_route() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_results = 1;
    cfg.search.max_upstream_requests = 4;
    let provider = provider(cfg);
    Mock::given(path("/api/v4/projects/old%2Frepo"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("Location", "https://untrusted.example/api/v4/projects/7")
                .set_body_string("redirect body"),
        )
        .expect(1)
        .mount(&server)
        .await;
    project(&server, 7, "team/current", 200).await;
    Mock::given(path("/api/v4/projects/7/search")).and(query_param("scope","blobs")).and(query_param("search_type","basic"))
        .respond_with(ResponseTemplate::new(200).insert_header("X-Search-Type","basic").insert_header("X-Next-Page","").set_body_json(json!([{"project_id":7,"path":"lib.rs","ref":"main","startline":1,"data":"needle"}]))).expect(1).mount(&server).await;
    let result = provider
        .invoke(invocation(
            "search.code",
            json!({"search":"needle","project":"old/repo"}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["items"][0]["project"], "team/current");
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn explicit_project_and_collection_403_404_are_errors_and_hit_ownership_is_strict() {
    for status in [403, 404] {
        let server = MockServer::start().await;
        let provider = provider(config(&server));
        Mock::given(path("/api/v4/projects/team%2Frepo"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        assert!(
            provider
                .invoke(invocation(
                    "search.code",
                    json!({"search":"needle","project":"team/repo"}),
                    scope()
                ))
                .await
                .is_err()
        );
        Mock::given(path("/api/v4/search"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        assert!(
            provider
                .invoke(invocation(
                    "search.issues",
                    json!({"search":"needle"}),
                    scope()
                ))
                .await
                .is_err()
        );
    }
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    Mock::given(path("/api/v4/projects/team%2Frepo"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":1,"path_with_namespace":"team/repo"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/v4/projects/1/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Search-Type", "basic")
                .insert_header("X-Next-Page", "")
                .set_body_json(json!([issue(2, 1)])),
        )
        .mount(&server)
        .await;
    assert_eq!(
        provider
            .invoke(invocation(
                "search.issues",
                json!({"search":"needle","project":"team/repo"}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}

#[tokio::test]
async fn headers_and_page_failure_never_return_partially_projected_items() {
    for engine in [None, Some("advanced"), Some("unknown")] {
        let server = MockServer::start().await;
        let provider = provider(config(&server));
        let mut response = ResponseTemplate::new(200).set_body_json(json!([issue(1, 1)]));
        if let Some(engine) = engine {
            response = response.insert_header("X-Search-Type", engine);
        }
        Mock::given(path("/api/v4/search"))
            .respond_with(response)
            .mount(&server)
            .await;
        assert_eq!(
            provider
                .invoke(invocation(
                    "search.issues",
                    json!({"search":"needle"}),
                    scope()
                ))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::UpstreamProtocolFailed
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    page(
        &server,
        1,
        json!([issue(1,1),{"id":88,"project_id":"ambiguous"}]),
        Some("2"),
    )
    .await;
    project(&server, 1, "team/repo", 200).await;
    let error = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":2}),
            scope(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!format!("{error:?}").contains("ambiguous"));
}

#[tokio::test]
async fn unavailable_projects_are_memoized_and_reconfirmed_on_later_operations() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    page(&server, 1, json!([issue(1, 1), issue(1, 2)]), Some("")).await;
    project(&server, 1, "hidden/deleted", 404).await;
    for _ in 0..2 {
        assert_eq!(
            provider
                .invoke(invocation(
                    "search.issues",
                    json!({"search":"needle","maxResults":2}),
                    scope()
                ))
                .await
                .unwrap()
                .result["count"],
            0
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path() == "/api/v4/projects/1")
            .count(),
        2
    );
}

#[tokio::test]
async fn changing_boundaries_inputs_and_explicit_identity_invalidates_continuations() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    page(&server, 1, json!([issue(1, 1)]), Some("2")).await;
    project(&server, 1, "team/repo", 200).await;
    let input = json!({"search":"needle","maxResults":1});
    let first = provider
        .invoke(invocation("search.issues", input.clone(), scope()))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].clone();
    for (query, boundary) in [
        (
            json!({"search":"different","maxResults":1,"pageToken":token}),
            scope(),
        ),
        (
            json!({"search":"needle","maxResults":2,"pageToken":token}),
            scope(),
        ),
        (
            json!({"search":"needle","maxResults":1,"pageToken":token}),
            SearchAuthorizationScope::from_selectors(
                vec![ResourceSelector::Exact {
                    value: "team/repo".into(),
                }],
                vec![],
            ),
        ),
    ] {
        assert_eq!(
            provider
                .invoke(invocation("search.issues", query, boundary))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn request_and_decoded_byte_budgets_fail_before_partial_page_release() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_results = 2;
    cfg.search.max_upstream_requests = 3;
    assert_eq!(
        provider(cfg)
            .invoke(invocation(
                "search.issues",
                json!({"search":"needle"}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    page(&server, 1, json!([issue(1, 1)]), Some("2")).await;
    project(&server, 1, "team/repo", 200).await;
    let mut cfg = config(&server);
    let body = json!([issue(1, 1)]).to_string();
    cfg.search.max_scan_bytes = body.len() as u64 + 5;
    assert_eq!(
        provider(cfg)
            .invoke(invocation(
                "search.issues",
                json!({"search":"needle","maxResults":1}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[test]
fn projections_validate_owned_locators_preview_boundaries_and_comment_parents() {
    let config:GitlabProviderConfig=serde_json::from_value(json!({"api_base_url":"https://gitlab.example/gitlab/api/v4","web_base_url":"https://gitlab.example/gitlab"})).unwrap();
    let project =
        projection::Project::parse(&json!({"id":1,"path_with_namespace":"team/repo"})).unwrap();
    let mut candidate = issue(1, 8);
    candidate["description"] = json!("é".repeat(3000));
    let item = projection::content_item("search.issues", &candidate, &project, &config).unwrap();
    assert_eq!(item["descriptionPreview"].as_str().unwrap().len(), 4096);
    assert_eq!(item["previewTruncated"], true);
    assert_eq!(
        item["webUrl"],
        "https://gitlab.example/gitlab/team/repo/-/issues/8"
    );
    for url in [
        "https://gitlab.example/gitlab/other/repo/-/issues/8",
        "https://gitlab.example/gitlab/team/repo/-/issues/9",
        "https://gitlab.example/team/repo/-/issues/8",
        "https://evil.example/gitlab/team/repo/-/issues/8",
        "https://user:password@gitlab.example/gitlab/team/repo/-/issues/8",
        "https://gitlab.example/gitlab/team/repo/-/issues/8?search=hidden",
        "https://gitlab.example/gitlab/team/repo/-/issues/8#bad",
        "https://gitlab.example/gitlab/team%2Frepo/-/issues/8",
    ] {
        candidate["web_url"] = json!(url);
        assert!(
            projection::content_item("search.issues", &candidate, &project, &config)
                .unwrap()
                .get("webUrl")
                .is_none(),
            "{url}"
        );
    }
    for kind in ["Issue", "MergeRequest", "Snippet", "Commit"] {
        let mut note = json!({"id":11,"project_id":1,"noteable_type":kind,"noteable_id":987,"noteable_iid":4,"body":"preview","commit_id":"a".repeat(40)});
        let item = projection::content_item("search.comments", &note, &project, &config).unwrap();
        assert_eq!(item["parentKind"], kind);
        if kind == "Commit" {
            assert!(item.get("webUrl").is_none());
        } else {
            assert!(item["webUrl"].as_str().unwrap().ends_with("#note_11"));
        }
        note.as_object_mut().unwrap().remove("noteable_iid");
        if matches!(kind, "Issue" | "MergeRequest") {
            assert!(
                projection::content_item("search.comments", &note, &project, &config)
                    .unwrap()
                    .get("webUrl")
                    .is_none()
            );
        }
    }
    assert!(
        projection::owner(
            "search.comments",
            &json!({"project_id":1,"noteable_type":"Epic"})
        )
        .is_err()
    );
    assert_eq!(
        projection::owner(
            "search.comments",
            &json!({"project_id":null,"noteable_type":"Snippet"})
        )
        .unwrap(),
        None
    );
    assert_eq!(
        projection::owner("search.wiki", &json!({"group_id":4,"project_id":null})).unwrap(),
        None
    );
    assert!(projection::owner("search.wiki", &json!({"group_id":4,"project_id":1})).is_err());
    assert!(
        projection::owner(
            "search.merge_requests",
            &json!({"project_id":1,"target_project_id":2})
        )
        .is_err()
    );
    let code = json!({"project_id":1,"path":"src/main.rs","ref":"main","data":"text","web_url":"https://gitlab.example/gitlab/team/repo/-/blob/other/src/main.rs"});
    assert!(
        projection::content_item("search.code", &code, &project, &config)
            .unwrap()
            .get("webUrl")
            .is_none()
    );
}

#[test]
fn descriptors_are_independent_sensitive_reads_with_conditional_project_schemas() {
    let config:GitlabProviderConfig=serde_json::from_value(json!({"api_base_url":"https://gitlab.example/api/v4","web_base_url":"https://gitlab.example"})).unwrap();
    let descriptor = gitlab_descriptor(&config);
    descriptor.validate().unwrap();
    let actions: Vec<_> = descriptor
        .actions
        .iter()
        .filter(|a| is_search_action(&a.action))
        .collect();
    assert_eq!(actions.len(), 7);
    for action in &actions {
        assert!(action.read_only);
        assert_eq!(
            action.native_search,
            Some(NativeSearchEnforcement::ResultFiltered)
        );
        assert_eq!(action.lookup, LookupRequirement::None);
        assert!(action.presentation.is_some());
        assert!(!action.sensitive_output_pointers.is_empty());
        assert_eq!(action.input_schema["additionalProperties"], false);
    }
    let code = actions.iter().find(|a| a.action == "search.code").unwrap();
    assert_eq!(
        code.input_schema["properties"]["engine"]["enum"],
        json!(["basic"])
    );
    assert!(code.input_schema["allOf"].to_string().contains("project"));
    assert!(code.input_schema["properties"].get("regex").is_none());
    let mut disabled = config;
    disabled.search.engines.basic = GitlabSearchEngineConfig::default();
    let descriptor = gitlab_descriptor(&disabled);
    assert_eq!(
        descriptor
            .actions
            .iter()
            .filter(|a| is_search_action(&a.action))
            .count(),
        1
    );
    assert!(
        descriptor
            .actions
            .iter()
            .any(|a| a.action == "project.search")
    );
}

#[tokio::test]
async fn discovery_reapplies_archived_filter_and_rejects_duplicate_current_paths() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_candidate_pages = 1;
    let provider = provider(cfg);
    Mock::given(path("/api/v4/projects"))
        .and(query_param("archived", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id":1,"path_with_namespace":"team/archived","archived":true},
            {"id":2,"path_with_namespace":"team/active","archived":false}
        ])))
        .mount(&server)
        .await;
    let result = provider
        .invoke(invocation(
            "project.search",
            json!({"archived":false,"maxResults":2}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    assert_eq!(result.result["items"][0]["project"], "team/active");
    server.reset().await;
    Mock::given(path("/api/v4/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id":1,"path_with_namespace":"team/same","archived":false},
            {"id":2,"path_with_namespace":"team/same","archived":false}
        ])))
        .mount(&server)
        .await;
    assert_eq!(
        provider
            .invoke(invocation(
                "project.search",
                json!({"maxResults":2}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}

#[tokio::test]
async fn exact_path_grants_do_not_follow_moved_projects_but_reused_paths_are_current_authority() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    page(&server, 1, json!([issue(1, 1), issue(2, 2)]), Some("")).await;
    project(&server, 1, "moved/new-home", 200).await;
    project(&server, 2, "team/old-home", 200).await;
    let exact = SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Exact {
            value: "team/old-home".into(),
        }],
        vec![],
    );
    let result = provider
        .invoke(invocation(
            "search.issues",
            json!({"search":"needle","maxResults":2}),
            exact,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    assert_eq!(result.result["items"][0]["projectId"], 2);
}

#[tokio::test]
async fn any_unsupported_capability_fails_before_a_request_without_engine_fallback() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    for (action, input) in [
        ("search.code", json!({"search":"x"})),
        ("search.commits", json!({"search":"x"})),
        ("search.comments", json!({"search":"x","engine":"advanced"})),
        ("search.issues", json!({"search":"x","engine":"zoekt"})),
        (
            "search.wiki",
            json!({"search":"x","project":"team/repo","regex":false}),
        ),
    ] {
        assert_eq!(
            provider
                .invoke(invocation(action, input, scope()))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn zoekt_sends_explicit_regex_choice_and_never_tries_basic() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.engines.zoekt.instance_categories = vec!["code".into()];
    let provider = provider(cfg);
    Mock::given(path("/api/v4/search"))
        .and(query_param("scope", "blobs"))
        .and(query_param("search_type", "zoekt"))
        .and(query_param("regex", "false"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Search-Type", "zoekt")
                .insert_header("X-Next-Page", "")
                .set_body_json(json!([])),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        provider
            .invoke(invocation(
                "search.code",
                json!({"search":"literal","engine":"zoekt"}),
                scope()
            ))
            .await
            .unwrap()
            .result["engine"],
        "zoekt"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_confidential_payloads_and_binding_changes_make_no_collection_request() {
    let server = MockServer::start().await;
    let provider = provider(config(&server));
    for token in ["a".repeat(99), "a".repeat(100), "bad".into()] {
        assert_eq!(
            provider
                .invoke(invocation(
                    "project.search",
                    json!({"pageToken":token}),
                    scope()
                ))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    for payload in [encode_position(2, 5), encode_position(1, 0)] {
        assert!(decode_position(&payload, 1).is_err());
    }
    let mut payload = encode_position(1, 1);
    payload[31] = 1;
    assert!(decode_position(&payload, 1).is_err());
}

struct Lease {
    target: String,
    version: std::sync::atomic::AtomicUsize,
    recoveries: std::sync::atomic::AtomicUsize,
    rejected: std::sync::Mutex<Vec<String>>,
}
#[async_trait]
impl DelegatedLease for Lease {
    fn access(&self) -> DelegatedAccess {
        let version = self.version.load(Ordering::Acquire);
        DelegatedAccess::new(
            format!("oauth-{version}"),
            self.target.clone(),
            "gitlab",
            format!("v{version}"),
            i64::MAX,
        )
    }
    fn binding_identity(&self) -> DelegatedBindingId {
        agent_access_provider::test_support::delegated_binding_id("search-user")
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Ok(())
    }
    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        self.rejected.lock().unwrap().push(version.to_string());
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        self.recoveries.fetch_add(1, Ordering::AcqRel);
        self.version.fetch_add(1, Ordering::AcqRel);
        Ok(self.access())
    }
}
fn delegated_request(action: &str, input: Value, lease: &Arc<Lease>) -> ProviderInvocation {
    InvocationBuilder::new("gitlab", action)
        .inputs(input)
        .search(SearchAuthorization::new("repository", scope()))
        .credential_mode(CredentialMode::PerUser)
        .delegated(agent_access_provider::host::delegated_credential(
            lease.clone(),
        ))
        .build()
}

#[tokio::test]
async fn one_candidate_page_allows_one_401_replay_and_smallest_budget_covers_rename() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_results = 1;
    cfg.search.max_candidate_pages = 1;
    cfg.search.max_upstream_requests = 4;
    let provider = provider(cfg);
    let lease = Arc::new(Lease {
        target: server.uri(),
        version: std::sync::atomic::AtomicUsize::new(1),
        recoveries: std::sync::atomic::AtomicUsize::new(0),
        rejected: std::sync::Mutex::new(Vec::new()),
    });
    Mock::given(path("/api/v4/projects/old%2Frepo"))
        .and(header("authorization", "Bearer oauth-1"))
        .respond_with(ResponseTemplate::new(401).set_body_string("authentication failed"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/v4/projects/old%2Frepo"))
        .and(header("authorization", "Bearer oauth-2"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("Location", "https://proxy.example/api/v4/projects/7")
                .set_body_string("moved"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/v4/projects/7"))
        .and(header("authorization", "Bearer oauth-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":7,"path_with_namespace":"team/current"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/v4/projects/7/search"))
        .and(header("authorization", "Bearer oauth-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Search-Type", "basic")
                .insert_header("X-Next-Page", "")
                .set_body_json(json!([issue(7, 1)])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = provider
        .invoke(delegated_request(
            "search.issues",
            json!({"search":"needle","project":"old/repo"}),
            &lease,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    assert_eq!(lease.recoveries.load(Ordering::Acquire), 1);
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn collection_replay_consumes_one_page_slot_and_repeated_401_cannot_recover_again() {
    for second_unauthorized in [false, true] {
        let server = MockServer::start().await;
        let mut cfg = config(&server);
        cfg.search.max_results = 1;
        cfg.search.max_candidate_pages = 1;
        cfg.search.max_upstream_requests = 4;
        let provider = provider(cfg);
        let lease = Arc::new(Lease {
            target: server.uri(),
            version: std::sync::atomic::AtomicUsize::new(1),
            recoveries: std::sync::atomic::AtomicUsize::new(0),
            rejected: std::sync::Mutex::new(Vec::new()),
        });
        Mock::given(path("/api/v4/search"))
            .and(header("authorization", "Bearer oauth-1"))
            .respond_with(ResponseTemplate::new(401).set_body_string("401 body"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/api/v4/search"))
            .and(header("authorization", "Bearer oauth-2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Search-Type", "basic")
                    .insert_header("X-Next-Page", "")
                    .set_body_json(json!([issue(1, 1)])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/api/v4/projects/1"))
            .and(header("authorization", "Bearer oauth-2"))
            .respond_with(if second_unauthorized {
                ResponseTemplate::new(401)
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id":1,"path_with_namespace":"team/repo"}))
            })
            .expect(1)
            .mount(&server)
            .await;
        let result = provider
            .invoke(delegated_request(
                "search.issues",
                json!({"search":"needle"}),
                &lease,
            ))
            .await;
        if second_unauthorized {
            assert_eq!(
                result.unwrap_err().reason_code(),
                ReasonCode::CredentialInvalid
            );
        } else {
            assert_eq!(result.unwrap().result["count"], 1);
        }
        assert_eq!(lease.recoveries.load(Ordering::Acquire), 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn consumed_error_body_exhaustion_prevents_authentication_replay() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.search.max_scan_bytes = 8;
    let provider = provider(cfg);
    let lease = Arc::new(Lease {
        target: server.uri(),
        version: std::sync::atomic::AtomicUsize::new(1),
        recoveries: std::sync::atomic::AtomicUsize::new(0),
        rejected: std::sync::Mutex::new(Vec::new()),
    });
    Mock::given(path("/api/v4/search"))
        .respond_with(ResponseTemplate::new(401).set_body_string("too much error body"))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        provider
            .invoke(delegated_request(
                "search.issues",
                json!({"search":"needle"}),
                &lease
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    assert_eq!(lease.recoveries.load(Ordering::Acquire), 0);
    assert_eq!(*lease.rejected.lock().unwrap(), ["v1"]);
}
