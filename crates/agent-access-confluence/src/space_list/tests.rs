use super::*;
use agent_access_provider::test_support::{
    InvocationBuilder, ScopeRequestFixture, basic_credential, bearer_credential,
    credential_with_profile, test_signing_key,
};
use std::time::SystemTime;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(server: &MockServer) -> ConfluenceProviderConfig {
    serde_json::from_value(json!({"tenant_host":"example.atlassian.net","allowed_upstream_hosts":[format!("{}/**",server.uri())]})).unwrap()
}
fn provider(
    server: &MockServer,
    cfg: ConfluenceProviderConfig,
    limits: ProviderLimits,
) -> ConfluenceProvider {
    let backend = HttpConfluenceBackend::new_with_api_base(
        cfg.clone(),
        limits.clone(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    );
    ConfluenceProvider::with_backend_and_signing_key(
        cfg,
        limits,
        Arc::new(backend),
        test_signing_key(41),
    )
}
fn scope() -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::All],
        vec![ResourceSelector::Exact {
            value: "DENIED".into(),
        }],
    )
}
fn invocation(input: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::new("confluence", "space.list")
        .inputs(input)
        .search(SearchAuthorization::new("space", scope))
        .credential(basic_credential("user@example.com", "execution-token"))
        .build()
}
fn space(id: &str, key: &str) -> Value {
    json!({"id":id,"key":key,"name":format!("{key} space"),"type":"global","status":"current","owner":"UNPROJECTED_OWNER"})
}
async fn mount(
    server: &MockServer,
    cursor: Option<&str>,
    size: u32,
    values: Value,
    next: Option<&str>,
) {
    let mut mock = Mock::given(method("GET"))
        .and(path("/wiki/api/v2/spaces"))
        .and(query_param("limit", size.to_string()))
        .and(query_param("status", "current"))
        .and(header(
            "authorization",
            "Basic dXNlckBleGFtcGxlLmNvbTpleGVjdXRpb24tdG9rZW4=",
        ));
    mock = match cursor {
        Some(cursor) => mock.and(query_param("cursor", cursor)),
        None => mock.and(query_param_is_missing("cursor")),
    };
    let mut value = json!({"results":values});
    if let Some(next) = next {
        value["_links"] = json!({"next":format!("/wiki/api/v2/spaces?cursor={next}&limit={size}&status=current")});
    }
    mock.respond_with(ResponseTemplate::new(200).set_body_json(value))
        .mount(server)
        .await;
}

#[tokio::test]
async fn local_validation_and_descriptor_need_no_space_or_lookup() {
    let server = MockServer::start().await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    for input in [
        json!(null),
        json!([]),
        json!({"query":"x"}),
        json!({"space":"ENG"}),
        json!({"maxResults":0}),
        json!({"maxResults":51}),
        json!({"maxResults":1.5}),
        json!({"maxResults":null}),
        json!({"pageToken":null}),
        json!({"pageToken":""}),
    ] {
        assert_eq!(
            p.invoke(invocation(input, scope()))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    p.resolve_scopes(ScopeRequestFixture::new("confluence", "space.list", json!({})).request())
        .await
        .unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
    let action = descriptor(&ConfluenceListingConfig::default());
    assert!(action.read_only);
    assert_eq!(
        action.native_search,
        Some(NativeSearchEnforcement::ResultFiltered)
    );
}

#[tokio::test]
async fn mixed_case_space_keys_survive_full_and_small_pages() {
    let server = MockServer::start().await;
    let values = (1..=50)
        .map(|id| {
            let key = match id {
                45 => "TeamDocs".to_string(),
                46 => "eng".to_string(),
                47 => "7Ops".to_string(),
                48 => "A".to_string(),
                _ => format!("~person{id}"),
            };
            space(&id.to_string(), &key)
        })
        .collect::<Vec<_>>();
    for size in [50, 10, 4] {
        for (page, chunk) in values.chunks(size).enumerate() {
            let start = page * size;
            let end = start + chunk.len();
            let cursor = (start != 0).then(|| format!("offset-{start}"));
            let next = (end < values.len()).then(|| format!("offset-{end}"));
            mount(
                &server,
                cursor.as_deref(),
                size as u32,
                json!(chunk),
                next.as_deref(),
            )
            .await;
        }
    }
    let p = provider(&server, config(&server), ProviderLimits::default());
    let expected_keys = values
        .iter()
        .map(|item| item["key"].clone())
        .collect::<Vec<_>>();
    for size in [50, 10, 4] {
        let mut input = if size == 50 {
            json!({})
        } else {
            json!({"maxResults":size})
        };
        let mut keys = Vec::new();
        for _ in 0..50 {
            let result = p.invoke(invocation(input.clone(), scope())).await.unwrap();
            let items = result.result["items"].as_array().unwrap();
            keys.extend(items.iter().map(|item| item["key"].clone()));
            assert!(items.len() <= size);
            if result.result["scanStatus"] == "exhausted" {
                assert!(result.result.get("nextPageToken").is_none());
                break;
            }
            assert_eq!(result.result["scanStatus"], "more");
            input["pageToken"] = result.result["nextPageToken"].clone();
        }
        assert_eq!(keys, expected_keys, "page size {size}");
    }
}

#[tokio::test]
async fn mixed_case_listing_keys_use_exact_inclusions_and_exclusions() {
    let server = MockServer::start().await;
    mount(
        &server,
        None,
        3,
        json!([space("1", "ENG"), space("2", "eng"), space("3", "Eng")]),
        None,
    )
    .await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let exact = ResourceSelector::Exact {
        value: "Eng".into(),
    };
    for (scope, expected) in [
        (
            SearchAuthorizationScope::from_selectors(vec![exact.clone()], vec![]),
            json!(["Eng"]),
        ),
        (
            SearchAuthorizationScope::from_selectors(vec![ResourceSelector::All], vec![exact]),
            json!(["ENG", "eng"]),
        ),
    ] {
        let result = p
            .invoke(invocation(json!({"maxResults":3}), scope))
            .await
            .unwrap();
        assert_eq!(
            json!(
                result.result["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| item["key"].clone())
                    .collect::<Vec<_>>()
            ),
            expected
        );
    }
}

#[tokio::test]
async fn rejected_space_fields_have_private_fixed_diagnostics() {
    let mut cases = vec![
        (
            json!({"results":null}),
            "confluence_space_list_results_invalid",
        ),
        (
            json!({"results":[space("1", "ENG"), space("1", "OPS")]}),
            "confluence_space_list_duplicate_id",
        ),
        (
            json!({"results":[space("1", "ENG"), space("2", "ENG")]}),
            "confluence_space_list_duplicate_key",
        ),
    ];
    for (field, value, code) in [
        (
            "id",
            json!("PRIVATE_ID"),
            "confluence_space_list_id_invalid",
        ),
        (
            "key",
            json!("PRIVATE/KEY"),
            "confluence_space_list_key_invalid",
        ),
        ("name", json!(null), "confluence_space_list_name_invalid"),
        ("name", json!(""), "confluence_space_list_name_invalid"),
        (
            "type",
            json!("PRIVATE-TYPE"),
            "confluence_space_list_type_invalid",
        ),
        (
            "status",
            json!("PRIVATE_STATUS"),
            "confluence_space_list_status_invalid",
        ),
    ] {
        let mut item = space("1", "ENG");
        item[field] = value;
        cases.push((json!({"results":[item]}), code));
    }
    for (body, code) in cases {
        let server = MockServer::start().await;
        Mock::given(path("/wiki/api/v2/spaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let error = provider(&server, config(&server), ProviderLimits::default())
            .invoke(invocation(json!({}), scope()))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.internal_diagnostic_code, Some(code));
        assert_eq!(
            error.message,
            "Confluence space listing response protocol error"
        );
        assert!(error.result.is_none());
        assert!(error.audit.is_none());
        assert!(error.object_ids.is_none());
    }
}

#[tokio::test]
async fn canonical_keys_filter_before_metadata_and_aliases_only_control_links() {
    let server = MockServer::start().await;
    let mut personal = space("2", "~personal");
    personal["type"] = json!("personal");
    personal["currentActiveAlias"] = json!("personal-home");
    personal["_links"] = json!({"webui":"/wiki/spaces/personal-home/overview"});
    let mut visible = space("3", "ENG");
    visible["name"] = json!("é".repeat(3000));
    visible["_links"] = json!({"webui":"https://evil.example/private"});
    visible["homepageId"] = json!({"unneeded":"malformed"});
    mount(&server,None,3,json!([{"id":"1","key":"DENIED","name":["DENIED_NAME"],"currentActiveAlias":"ENG"},personal,visible]),None).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(json!({"maxResults":3}), scope()))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 2);
    assert_eq!(result.result["scanStatus"], "exhausted");
    assert_eq!(
        result.result["items"][0]["webUrl"],
        "https://example.atlassian.net/wiki/spaces/personal-home/overview"
    );
    assert_eq!(
        result.result["items"][1]["webUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert_eq!(
        result.result["items"][1]["name"].as_str().unwrap().len(),
        4096
    );
    assert_eq!(result.result["items"][1]["previewTruncated"], true);
    for secret in [
        "DENIED_NAME",
        "UNPROJECTED_OWNER",
        "homepageId",
        "currentActiveAlias",
        "evil.example",
    ] {
        assert!(!result.result.to_string().contains(secret));
        assert!(!result.audit.as_ref().unwrap().to_string().contains(secret));
    }
    let alias = SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Exact {
            value: "personal-home".into(),
        }],
        vec![],
    );
    let denied = p
        .invoke(invocation(json!({"maxResults":3}), alias))
        .await
        .unwrap();
    assert_eq!(denied.result["count"], 0);
}

#[tokio::test]
async fn empty_budget_pages_resume_across_instances_without_skipping_candidates() {
    let server = MockServer::start().await;
    mount(&server, None, 1, json!([space("1", "DENIED")]), Some("A")).await;
    mount(&server, Some("A"), 1, json!([]), Some("B")).await;
    mount(&server, Some("B"), 1, json!([space("2", "ENG")]), Some("C")).await;
    mount(&server, Some("C"), 1, json!([]), None).await;
    let mut cfg = config(&server);
    cfg.listing.max_candidate_pages = 1;
    let mut token = None;
    for (status, count) in [
        ("scan_budget", 0),
        ("scan_budget", 0),
        ("more", 1),
        ("exhausted", 0),
    ] {
        let p = provider(&server, cfg.clone(), ProviderLimits::default());
        let mut input = json!({"maxResults":1});
        if let Some(token) = token.take() {
            input["pageToken"] = token;
        }
        let result = p.invoke(invocation(input, scope())).await.unwrap();
        assert_eq!(result.result["scanStatus"], status);
        assert_eq!(result.result["count"], count);
        token = result.result.get("nextPageToken").cloned();
    }
    assert!(token.is_none());
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn both_pagination_carriers_agree_and_echoes_never_change_requests() {
    let server = MockServer::start().await;
    Mock::given(path("/wiki/api/v2/spaces")).and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).insert_header("Link","</wiki/api/v2/spaces?cursor=A&limit=100&status=archived&sort=-id>; rel=\"next\"")
        .set_body_json(json!({"results":[],"_links":{"next":"?cursor=A"}}))).mount(&server).await;
    mount(&server, Some("A"), 2, json!([space("1", "ENG")]), None).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(json!({"maxResults":2}), scope()))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].url.query_pairs().collect::<BTreeMap<_, _>>()["status"],
        "current"
    );
    assert!(!requests[1].url.query_pairs().any(|(key, _)| key == "sort"));
}

#[test]
fn hostile_or_contradictory_next_links_are_rejected_on_site_and_gateway() {
    for root in [
        "https://tenant.example/",
        "https://api.atlassian.com/ex/confluence/11111111-2222-4333-8444-555555555555/",
    ] {
        let site = Url::parse(root).unwrap();
        let current = site
            .join("wiki/api/v2/spaces?limit=2&status=current")
            .unwrap();
        let allowed = vec![format!("{}**", root)];
        let headers = reqwest::header::HeaderMap::new();
        for next in [
            "https://evil.example/wiki/api/v2/spaces?cursor=A",
            "/wiki/api/v2/pages?cursor=A",
            "?cursor=A#fragment",
            "?cursor=A&cursor=A",
            "?cursor=A&limit=2&limit=2",
            "?cursor=A&expand=owner",
            "?limit=2",
            "?cursor=",
            "https://user:pass@tenant.example/wiki/api/v2/spaces?cursor=A",
        ] {
            assert!(
                next_cursor(
                    &current,
                    &site,
                    &json!({"_links":{"next":next}}),
                    &headers,
                    &allowed
                )
                .is_err(),
                "{root}: {next}"
            );
        }
        for next in [
            "?cursor=A",
            "/wiki/api/v2/spaces?cursor=A&status=current&sort=id&limit=2",
        ] {
            assert_eq!(
                next_cursor(
                    &current,
                    &site,
                    &json!({"_links":{"next":next}}),
                    &headers,
                    &allowed
                )
                .unwrap()
                .as_deref(),
                Some("A")
            );
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "link",
            "</wiki/api/v2/spaces?cursor=B>; rel=\"next\""
                .parse()
                .unwrap(),
        );
        assert!(
            next_cursor(
                &current,
                &site,
                &json!({"_links":{"next":"?cursor=A"}}),
                &headers,
                &allowed
            )
            .is_err()
        );
        headers.append(
            "link",
            "</wiki/api/v2/spaces?cursor=B>; rel=\"next\""
                .parse()
                .unwrap(),
        );
        assert!(next_cursor(&current, &site, &json!({}), &headers, &allowed).is_err());
    }
}

#[tokio::test]
async fn cursor_cycles_fail_within_calls_and_across_resumed_pages() {
    for productive in [false, true] {
        let server = MockServer::start().await;
        let items = if productive {
            json!([space("1", "ENG")])
        } else {
            json!([])
        };
        mount(&server, None, 1, items.clone(), Some("A")).await;
        mount(&server, Some("A"), 1, items.clone(), Some("B")).await;
        mount(&server, Some("B"), 1, items, Some("A")).await;
        let p = provider(&server, config(&server), ProviderLimits::default());
        let mut input = json!({"maxResults":1});
        if productive {
            for _ in 0..2 {
                let result = p.invoke(invocation(input, scope())).await.unwrap();
                input = json!({"maxResults":1,"pageToken":result.result["nextPageToken"]});
            }
        }
        assert_eq!(
            p.invoke(invocation(input, scope()))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::UpstreamProtocolFailed
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn continuation_binds_scope_context_route_method_action_and_page_size_before_http() {
    let server = MockServer::start().await;
    mount(&server, None, 1, json!([space("1", "ENG")]), Some("A")).await;
    let mut cfg = config(&server);
    cfg.cloud_id = Some("11111111-2222-4333-8444-555555555555".into());
    let p = provider(&server, cfg.clone(), ProviderLimits::default());
    let first = p
        .invoke(invocation(json!({"maxResults":1}), scope()))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap();
    let request = invocation(json!({"maxResults":1,"pageToken":token}), scope());
    let mut changed = scope();
    changed = changed.intersection(&SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Exact {
            value: "ENG".into(),
        }],
        vec![],
    ));
    let requests = [
        invocation(json!({"maxResults":2,"pageToken":token}), scope()),
        invocation(json!({"maxResults":1,"pageToken":token}), changed),
        InvocationBuilder::from(request.clone())
            .principal("other")
            .build(),
        InvocationBuilder::from(request.clone())
            .execution_context("other")
            .build(),
        InvocationBuilder::from(request.clone())
            .credential(bearer_credential("other"))
            .build(),
        InvocationBuilder::from(request.clone())
            .credential(credential_with_profile(
                basic_credential("u", "t"),
                "atlassian-scoped-api-token",
            ))
            .build(),
    ];
    for request in requests {
        assert_eq!(
            p.invoke(request).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
    for change in 0..3 {
        let mut changed = cfg.clone();
        match change {
            0 => changed.listing.max_scan_bytes += 1,
            1 => changed.tenant_host = "other.atlassian.net".into(),
            _ => changed.cloud_id = Some("99999999-8888-4777-8666-555555555555".into()),
        };
        assert_eq!(
            provider(&server, changed, ProviderLimits::default())
                .invoke(request.clone())
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    let mut tampered = token.as_bytes().to_vec();
    tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        p.invoke(invocation(
            json!({"maxResults":1,"pageToken":String::from_utf8(tampered).unwrap()}),
            scope()
        ))
        .await
        .unwrap_err()
        .reason_code(),
        ReasonCode::InputInvalid
    );
    for foreign in [
        TOKENS,
        ContinuationFamily::new(
            "jira",
            "project-list",
            1,
            ContinuationLifetime::StableWhenConfigured,
            100,
        )
        .confidential()
        .expires_after(Duration::from_secs(900)),
    ] {
        let context = if foreign == TOKENS {
            InvocationBuilder::from(request.clone())
                .action("search")
                .build()
        } else {
            request.clone()
        };
        let binding = listing_binding(
            &p,
            &context,
            1,
            &scope(),
            foreign.with_max_payload_bytes(100),
        )
        .unwrap();
        let token = p
            .listing_signer
            .seal_until(
                &binding,
                &Position {
                    cursor: "A".into(),
                    predecessor: [0; 32],
                }
                .payload(),
                p.listing_signer.deadline(&binding).unwrap(),
            )
            .unwrap();
        assert_eq!(
            p.invoke(invocation(
                json!({"maxResults":1,"pageToken":token}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn resumed_provider_token_keeps_its_original_expiry() {
    let server = MockServer::start().await;
    mount(&server, None, 1, json!([space("1", "ENG")]), Some("A")).await;
    mount(&server, Some("A"), 1, json!([space("2", "OPS")]), Some("B")).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let request = invocation(json!({"maxResults":1}), scope());
    let binding = listing_binding(&p, &request, 1, &scope(), family(&p.limits)).unwrap();
    let first = p.invoke(request).await.unwrap();
    let opened = p
        .listing_signer
        .open_confidential(&binding, first.result["nextPageToken"].as_str().unwrap())
        .unwrap();
    let now = SystemTime::now();
    let expiry = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30;
    let aged = p
        .listing_signer
        .seal_until_at(&binding, opened.payload(), expiry, now)
        .unwrap();
    let resumed = p
        .invoke(invocation(
            json!({"maxResults":1,"pageToken":aged}),
            scope(),
        ))
        .await
        .unwrap();
    let token = resumed.result["nextPageToken"].as_str().unwrap();
    assert_eq!(
        p.listing_signer
            .open_confidential(&binding, token)
            .unwrap()
            .expiry(),
        expiry
    );
    assert!(
        p.listing_signer
            .open_confidential_at(&binding, token, now + Duration::from_secs(31))
            .is_err()
    );
}

#[tokio::test]
async fn request_response_and_scan_byte_limits_are_explicit_and_no_errors_retry() {
    let server = MockServer::start().await;
    mount(&server, None, 1, json!([space("1", "DENIED")]), Some("A")).await;
    mount(&server, Some("A"), 1, json!([space("2", "ENG")]), None).await;
    let mut cfg = config(&server);
    cfg.listing.max_upstream_requests = 1;
    let p = provider(&server, cfg.clone(), ProviderLimits::default());
    let result = p
        .invoke(invocation(json!({"maxResults":1}), scope()))
        .await
        .unwrap();
    assert_eq!(result.result["scanStatus"], "scan_budget");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    cfg.listing.max_scan_bytes = 1;
    assert!(
        provider(&server, cfg, ProviderLimits::default())
            .invoke(invocation(json!({"maxResults":1}), scope()))
            .await
            .is_err()
    );
    for status in [302, 401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        Mock::given(path("/wiki/api/v2/spaces"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Location", "/elsewhere")
                    .set_body_string("PRIVATE_ERROR"),
            )
            .mount(&server)
            .await;
        let p = provider(&server, config(&server), ProviderLimits::default());
        let error = p.invoke(invocation(json!({}), scope())).await.unwrap_err();
        assert!(!error.message.contains("PRIVATE_ERROR"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    let server = MockServer::start().await;
    Mock::given(path("/wiki/api/v2/spaces"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
        .mount(&server)
        .await;
    assert_eq!(
        provider(
            &server,
            config(&server),
            ProviderLimits::default().with_request_timeout_ms(25)
        )
        .invoke(invocation(json!({}), scope()))
        .await
        .unwrap_err()
        .reason_code(),
        ReasonCode::UpstreamTimeout
    );
}

#[tokio::test]
async fn empty_first_page_is_terminal_and_malformed_collections_fail() {
    let server = MockServer::start().await;
    mount(&server, None, 50, json!([]), None).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    assert_eq!(
        p.invoke(invocation(json!({}), scope()))
            .await
            .unwrap()
            .result,
        json!({"items":[],"count":0,"maxResults":50,"scanStatus":"exhausted"})
    );
    for value in [
        json!({}),
        json!({"results":null}),
        json!({"results":[{},{}]}),
        json!({"results":[space("1","ENG"),space("1","OPS")]}),
        json!({"results":[{"id":"1","key":"ENG","name":"x","type":"global","status":"archived"}]}),
    ] {
        let server = MockServer::start().await;
        Mock::given(path("/wiki/api/v2/spaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .mount(&server)
            .await;
        assert!(
            provider(&server, config(&server), ProviderLimits::default())
                .invoke(invocation(json!({"maxResults":1}), scope()))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn all_current_space_types_and_independent_allows_keep_clause_exclusions() {
    let server = MockServer::start().await;
    let values = [
        "global",
        "collaboration",
        "knowledge_base",
        "personal",
        "system",
        "onboarding",
        "xflow_sample_space",
    ]
    .into_iter()
    .enumerate()
    .map(|(n, kind)| {
        let mut value = space(
            &(n + 1).to_string(),
            if n == 0 { "DENIED" } else { "~personal" },
        );
        value["key"] = json!(if n == 0 {
            "DENIED".into()
        } else {
            format!("~personal{n}")
        });
        value["type"] = json!(kind);
        value
    })
    .collect::<Vec<_>>();
    mount(&server, None, 7, json!(values), None).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let excluded = p
        .invoke(invocation(json!({"maxResults":7}), scope()))
        .await
        .unwrap();
    assert_eq!(excluded.result["count"], 6);
    let independent = scope().union(&SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Exact {
            value: "DENIED".into(),
        }],
        vec![],
    ));
    let allowed = p
        .invoke(invocation(json!({"maxResults":7}), independent))
        .await
        .unwrap();
    assert_eq!(allowed.result["count"], 7);
}

#[tokio::test]
async fn response_and_result_byte_caps_do_not_silently_truncate_pages_or_cursors() {
    let server = MockServer::start().await;
    mount(
        &server,
        None,
        1,
        json!([space("1", "ENG")]),
        Some(&"A".repeat(300)),
    )
    .await;
    let mut limits = ProviderLimits::default();
    limits.max_upstream_response_bytes = 512;
    let error = provider(&server, config(&server), limits)
        .invoke(invocation(json!({"maxResults":1}), scope()))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let server = MockServer::start().await;
    let mut value = space("1", "ENG");
    value["name"] = json!("X".repeat(2000));
    mount(&server, None, 1, json!([value]), None).await;
    let mut limits = ProviderLimits::default();
    limits.max_upstream_response_bytes = 512;
    assert!(
        provider(&server, config(&server), limits)
            .invoke(invocation(json!({"maxResults":1}), scope()))
            .await
            .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
