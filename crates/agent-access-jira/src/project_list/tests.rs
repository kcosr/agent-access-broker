use super::*;
use agent_access_provider::test_support::{InvocationBuilder, basic_credential, test_signing_key};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(server: &MockServer) -> JiraProviderConfig {
    serde_json::from_value(json!({"tenant_host":"example.atlassian.net", "allowed_upstream_hosts":[format!("{}/**", server.uri())]})).unwrap()
}
fn provider(
    server: &MockServer,
    config: JiraProviderConfig,
    limits: ProviderLimits,
) -> JiraProvider {
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        limits.clone(),
        Url::parse(&format!("{}/rest/api/3/", server.uri())).unwrap(),
    );
    let mut provider = JiraProvider::from_backend(config, limits, Arc::new(backend));
    provider.listing_signer = ContinuationSigner::new(Some(test_signing_key(37)));
    provider
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
    InvocationBuilder::new("jira", "project.list")
        .inputs(input)
        .search(SearchAuthorization::new("project", scope))
        .credential(basic_credential("user@example.com", "execution-token"))
        .build()
}
fn project(id: &str, key: &str) -> Value {
    json!({"id":id, "key":key, "name":format!("{key} project"), "projectTypeKey":"software", "owner":"UNPROJECTED_OWNER"})
}
async fn mount(server: &MockServer, offset: u64, size: u32, last: bool, values: Value) {
    Mock::given(method("GET")).and(path("/rest/api/3/project/search"))
        .and(query_param("startAt", offset.to_string())).and(query_param("maxResults", size.to_string()))
        .and(query_param("orderBy", "key")).and(query_param("status", "live"))
        .and(header("authorization", "Basic dXNlckBleGFtcGxlLmNvbTpleGVjdXRpb24tdG9rZW4="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"startAt":offset,"maxResults":size,"isLast":last,"values":values,"total":999999})))
        .mount(server).await;
}

#[test]
fn inputs_and_page_protocol_are_strict() {
    for value in [
        json!(null),
        json!([]),
        json!({"query":"x"}),
        json!({"project":"ENG"}),
        json!({"maxResults":null}),
        json!({"maxResults":0}),
        json!({"maxResults":51}),
        json!({"maxResults":1.5}),
        json!({"pageToken":null}),
        json!({"pageToken":""}),
        json!({"pageToken":"a".repeat(TOKENS.max_token_bytes()+1)}),
    ] {
        assert!(
            parse_inputs(&value, &JiraListingConfig::default()).is_err(),
            "{value}"
        );
    }
    let valid = json!({"startAt":0,"maxResults":2,"isLast":false,"values":[project("1","ENG")],"nextPage":"https://another-gateway.example/anything?unrelated=true&startAt=1"});
    assert_eq!(page(&valid, 0, 2).unwrap().1, Some(1));
    for (field, bad) in [
        ("startAt", json!(1)),
        ("maxResults", json!(0)),
        ("maxResults", json!(3)),
        ("isLast", json!(null)),
        ("values", json!([])),
        ("values", json!([{}, {}, {}])),
        ("nextPage", json!("?startAt=2")),
        ("nextPage", json!("?startAt=1&startAt=1")),
    ] {
        let mut value = valid.clone();
        value[field] = bad;
        assert!(page(&value, 0, 2).is_err(), "{value}");
    }
    for link in [
        "https://other.example/?foo=bar",
        "?startAt=1",
        "http://[bad",
        "/rest/api/3/project/search?startAt=1&status=archived",
    ] {
        let mut value = valid.clone();
        value["nextPage"] = json!(link);
        assert!(page(&value, 0, 2).is_ok());
    }
    let overflow =
        json!({"startAt":u64::MAX,"maxResults":1,"isLast":false,"values":[project("1","ENG")]});
    assert!(page(&overflow, u64::MAX, 1).is_err());
}

#[tokio::test]
async fn current_keys_are_filtered_before_metadata_and_empty_pages_resume() {
    let server = MockServer::start().await;
    let mut cfg = config(&server);
    cfg.listing.max_candidate_pages = 1;
    let p = provider(&server, cfg.clone(), ProviderLimits::default());
    // A denied candidate has malformed display metadata: none may be projected.
    mount(
        &server,
        0,
        2,
        false,
        json!([{"id":"99","key":"DENIED","name":{"DENIED_NAME":"hidden"}}]),
    )
    .await;
    mount(
        &server,
        1,
        2,
        false,
        json!([project("10", "ENG"), project("99", "DENIED")]),
    )
    .await;
    mount(&server, 3, 2, true, json!([project("20", "OPS")])).await;
    let first = p
        .invoke(invocation(json!({"maxResults":2}), scope()))
        .await
        .unwrap();
    assert_eq!(first.result["items"], json!([]));
    assert_eq!(first.result["scanStatus"], "scan_budget");
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert_eq!(token.len(), TOKENS.max_token_bytes());
    // A rebuild with the same stable key keeps the token usable.
    let p = provider(&server, cfg, ProviderLimits::default());
    let second = p
        .invoke(invocation(
            json!({"maxResults":2,"pageToken":token}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(second.result["count"], 1);
    assert_eq!(second.result["scanStatus"], "more");
    assert_eq!(
        second.result["items"][0],
        json!({"id":"10","key":"ENG","name":"ENG project","projectTypeKey":"software","webUrl":"https://example.atlassian.net/browse/ENG"})
    );
    let third = p
        .invoke(invocation(
            json!({"maxResults":2,"pageToken":second.result["nextPageToken"]}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(third.result["scanStatus"], "exhausted");
    assert!(third.result.get("nextPageToken").is_none());
    for result in [&first, &second, &third] {
        let public = format!("{:?}", result);
        for hidden in ["DENIED", "UNPROJECTED_OWNER", "999999", "execution-token"] {
            assert!(!public.contains(hidden), "{public}");
        }
        assert_eq!(
            result.result.as_object().unwrap().len(),
            if result.result.get("nextPageToken").is_some() {
                5
            } else {
                4
            }
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|request| request.url.query_pairs().count() == 4)
    );
}

#[tokio::test]
async fn independent_allow_preserves_an_excluded_project_and_previews_are_bounded() {
    let server = MockServer::start().await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let mut candidate = project("99", "DENIED");
    candidate["name"] = json!("界".repeat(2000));
    mount(&server, 0, 50, true, json!([candidate])).await;
    let authority = scope().union(&SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::Exact {
            value: "DENIED".into(),
        }],
        vec![],
    ));
    let result = p.invoke(invocation(json!({}), authority)).await.unwrap();
    assert_eq!(result.result["count"], 1);
    assert!(result.result["items"][0]["name"].as_str().unwrap().len() <= 4096);
    assert_eq!(result.result["items"][0]["previewTruncated"], true);
}

#[tokio::test]
async fn continuations_reject_changed_authority_inputs_config_and_identity_before_http() {
    let server = MockServer::start().await;
    mount(&server, 0, 2, false, json!([project("1", "ENG")])).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let first = p
        .invoke(invocation(json!({"maxResults":2}), scope()))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap();
    let base = invocation(json!({"maxResults":2,"pageToken":token}), scope());
    let mut tampered = token.as_bytes().to_vec();
    tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
    let variants = [
        invocation(json!({"maxResults":1,"pageToken":token}), scope()),
        invocation(
            json!({"maxResults":2,"pageToken":token}),
            SearchAuthorizationScope::from_selectors(vec![ResourceSelector::All], vec![]),
        ),
        InvocationBuilder::from(base.clone())
            .principal("another")
            .build(),
        InvocationBuilder::from(base.clone())
            .execution_context("another")
            .build(),
        invocation(
            json!({"maxResults":2,"pageToken":String::from_utf8(tampered).unwrap()}),
            scope(),
        ),
    ];
    for request in variants {
        assert_eq!(
            p.invoke(request).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
    let mut cfg = config(&server);
    cfg.listing.max_scan_bytes += 1;
    assert_eq!(
        provider(&server, cfg, ProviderLimits::default())
            .invoke(base.clone())
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );
    let mut restarted = provider(&server, config(&server), ProviderLimits::default());
    restarted.listing_signer = ContinuationSigner::new(None);
    assert_eq!(
        restarted.invoke(base).await.unwrap_err().reason_code(),
        ReasonCode::InputInvalid
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn failure_statuses_and_byte_limits_never_become_exhaustion_or_hidden_retries() {
    for status in [401, 403, 404, 429, 500, 302] {
        let server = MockServer::start().await;
        Mock::given(path("/rest/api/3/project/search"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", "1")
                    .set_body_string("DENIED_ERROR_DETAIL"),
            )
            .mount(&server)
            .await;
        let p = provider(&server, config(&server), ProviderLimits::default());
        let error = p.invoke(invocation(json!({}), scope())).await.unwrap_err();
        assert!(!error.message.contains("DENIED_ERROR_DETAIL"));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "{status}"
        );
    }
    for response_cap in [false, true] {
        let server = MockServer::start().await;
        mount(&server, 0, 50, true, json!([project("1", "ENG")])).await;
        let mut cfg = config(&server);
        let mut limits = ProviderLimits::default();
        if response_cap {
            limits.max_upstream_response_bytes = 32;
        } else {
            cfg.listing.max_scan_bytes = 32;
        }
        assert!(
            provider(&server, cfg, limits)
                .invoke(invocation(json!({}), scope()))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn http_attempt_and_cumulative_body_budgets_bound_denied_scanning() {
    for byte_budget in [false, true] {
        let server = MockServer::start().await;
        mount(&server, 0, 1, false, json!([project("99", "DENIED")])).await;
        mount(&server, 1, 1, true, json!([project("10", "ENG")])).await;
        let mut cfg = config(&server);
        if byte_budget {
            cfg.listing.max_scan_bytes = 300;
        } else {
            cfg.listing.max_upstream_requests = 1;
        }
        let result = provider(&server, cfg, ProviderLimits::default())
            .invoke(invocation(json!({"maxResults":1}), scope()))
            .await;
        if byte_budget {
            assert!(result.is_err());
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        } else {
            let result = result.unwrap();
            assert_eq!(result.result["scanStatus"], "scan_budget");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}

#[test]
fn confidential_resume_preserves_the_original_expiry() {
    let signer = ContinuationSigner::new(Some(test_signing_key(37)));
    let request = invocation(json!({}), scope());
    let binding = TOKENS.bind(request.context(), b"config");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let expiry = signer.deadline_at(&binding, start).unwrap();
    let token = signer
        .seal_until_at(&binding, &1u64.to_be_bytes(), expiry, start)
        .unwrap();
    let later = start + Duration::from_secs(800);
    let opened = signer
        .open_confidential_at(&binding, &token, later)
        .unwrap();
    let resumed = signer
        .seal_resumed_at(&binding, &2u64.to_be_bytes(), &opened, later)
        .unwrap();
    assert_eq!(
        signer
            .open_confidential_at(&binding, &resumed, later)
            .unwrap()
            .expiry(),
        expiry
    );
    assert!(
        signer
            .open_confidential_at(&binding, &resumed, start + Duration::from_secs(900))
            .is_err()
    );
}

#[tokio::test]
async fn offset_pages_tolerate_repeated_denied_candidates_after_concurrent_changes() {
    let server = MockServer::start().await;
    mount(&server, 0, 2, false, json!([project("9", "DENIED")])).await;
    mount(
        &server,
        1,
        2,
        true,
        json!([project("9", "DENIED"), project("10", "ENG")]),
    )
    .await;
    let result = provider(&server, config(&server), ProviderLimits::default())
        .invoke(invocation(json!({"maxResults":2}), scope()))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 1);
    assert_eq!(result.result["items"][0]["key"], "ENG");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn first_page_exhaustion_timeout_and_result_byte_overflow_are_distinct() {
    let server = MockServer::start().await;
    mount(&server, 0, 50, true, json!([])).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let result = p.invoke(invocation(json!({}), scope())).await.unwrap();
    assert_eq!(
        result.result,
        json!({"items":[],"count":0,"maxResults":50,"scanStatus":"exhausted"})
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let server = MockServer::start().await;
    Mock::given(path("/rest/api/3/project/search"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
        .mount(&server)
        .await;
    let p = provider(
        &server,
        config(&server),
        ProviderLimits::default().with_request_timeout_ms(25),
    );
    assert_eq!(
        p.invoke(invocation(json!({}), scope()))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamTimeout
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let server = MockServer::start().await;
    mount(
        &server,
        0,
        50,
        true,
        json!([{"id":"1","key":"ENG","name":"Visible"}]),
    )
    .await;
    let mut limits = ProviderLimits::default();
    limits.max_upstream_response_bytes = 150;
    let error = provider(&server, config(&server), limits)
        .invoke(invocation(json!({}), scope()))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "provider response exceeded the configured byte cap"
    );
}

#[tokio::test]
async fn provider_resume_preserves_an_aged_tokens_original_expiry() {
    let server = MockServer::start().await;
    mount(&server, 0, 1, false, json!([project("1", "ENG")])).await;
    mount(&server, 1, 1, false, json!([project("2", "OPS")])).await;
    let p = provider(&server, config(&server), ProviderLimits::default());
    let request = invocation(json!({"maxResults":1}), scope());
    let binding = listing_binding(&p, &request, 1, &scope(), TOKENS).unwrap();
    let first = p.invoke(request).await.unwrap();
    let opened = p
        .listing_signer
        .open_confidential(&binding, first.result["nextPageToken"].as_str().unwrap())
        .unwrap();
    // Age the genuine provider payload without sleeping or renewing its binding.
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
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn credential_route_changes_and_foreign_actions_or_families_reject_before_http() {
    use agent_access_provider::test_support::{bearer_credential, credential_with_profile};
    let server = MockServer::start().await;
    mount(&server, 0, 1, false, json!([project("1", "ENG")])).await;
    let mut cfg = config(&server);
    cfg.cloud_id = Some("11111111-2222-4333-8444-555555555555".into());
    let p = provider(&server, cfg, ProviderLimits::default());
    let request = invocation(json!({"maxResults":1}), scope());
    let first = p.invoke(request.clone()).await.unwrap();
    let base = invocation(
        json!({"maxResults":1,"pageToken":first.result["nextPageToken"]}),
        scope(),
    );
    for credential in [
        credential_with_profile(
            basic_credential("user@example.com", "execution-token"),
            "atlassian-scoped-api-token",
        ),
        bearer_credential("execution-token"),
    ] {
        let request = InvocationBuilder::from(base.clone())
            .credential(credential)
            .build();
        assert_eq!(
            p.invoke(request).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
    for family in [
        ContinuationFamily::new(
            "jira",
            "search-page",
            1,
            ContinuationLifetime::StableWhenConfigured,
            8,
        )
        .confidential()
        .expires_after(Duration::from_secs(900)),
        ContinuationFamily::new(
            "gitlab",
            "native-search",
            1,
            ContinuationLifetime::StableWhenConfigured,
            8,
        )
        .confidential()
        .expires_after(Duration::from_secs(900)),
    ] {
        let binding = listing_binding(&p, &request, 1, &scope(), family).unwrap();
        let token = p
            .listing_signer
            .seal_until(
                &binding,
                &1u64.to_be_bytes(),
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
    let other = InvocationBuilder::new("jira", "search")
        .credential(basic_credential("user@example.com", "execution-token"))
        .search(SearchAuthorization::new("project", scope()))
        .build();
    let binding = listing_binding(&p, &other, 1, &scope(), TOKENS).unwrap();
    let token = p
        .listing_signer
        .seal_until(
            &binding,
            &1u64.to_be_bytes(),
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
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
