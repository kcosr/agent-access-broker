use super::*;
use agent_access_provider::test_support::{
    InvocationBuilder, basic_credential, bearer_credential, credential_with_profile,
    test_signing_key,
};
use agent_access_provider::{CredentialMode, SearchAuthorization};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

fn config(server: &MockServer) -> CloudbeesCiProviderConfig {
    CloudbeesCiProviderConfig {
        listing: Default::default(),
        max_log_scan_bytes: logs::default_scan_limit(),
        controllers: BTreeMap::from([(
            "ci".into(),
            CloudbeesCiControllerConfig {
                base_url: format!("{}/ci/", server.uri()),
                web_base_url: None,
            },
        )]),
        egress_proxy: None,
        allowed_upstream_hosts: vec![format!("{}/ci/**", server.uri())],
    }
}
fn provider(cfg: CloudbeesCiProviderConfig, limits: ProviderLimits) -> CloudbeesCiProvider {
    let mut provider = CloudbeesCiProvider::for_tests(cfg, limits).unwrap();
    provider.listing_signer =
        agent_access_provider::ContinuationSigner::new(Some(test_signing_key(43)));
    provider
}
fn scope() -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_selectors(vec![ResourceSelector::All], vec![])
}
fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}
fn namespace(value: &str) -> ResourceSelector {
    ResourceSelector::Namespace {
        value: value.into(),
    }
}
fn invocation(input: Value, scope: SearchAuthorizationScope) -> ProviderInvocation {
    InvocationBuilder::new("cloudbees_ci", "job.list")
        .inputs(input)
        .search(SearchAuthorization::new("job", scope))
        .credential(basic_credential("u", "t"))
        .build()
}
fn child(parent: &str, name: &str, container: bool) -> Value {
    let job = if parent.is_empty() {
        name.into()
    } else {
        format!("{parent}/{name}")
    };
    let mut value = json!({"name":name,"fullName":job,"displayName":format!("{name} display"),"_class":"DO_NOT_RELEASE_CLASS","builds":[{"secret":"DO_NOT_RELEASE_BUILD"}],"url":"https://evil.invalid/job/x"});
    if container {
        value["jobs"] = json!([]);
    }
    value
}
fn route(job: &str) -> String {
    if job.is_empty() {
        "/ci/api/json".into()
    } else {
        CloudbeesCiProvider::append(
            CloudbeesCiProvider::job_url(&Url::parse("http://example.invalid/ci/").unwrap(), job),
            &["api", "json"],
        )
        .path()
        .into()
    }
}
async fn mount(server: &MockServer, job: &str, offset: u32, size: u32, values: Value) {
    let tree = format!(
        "jobs[name,fullName,displayName,url,_class,jobs[name]{{0,0}}]{{{offset},{}}}",
        offset + size
    );
    Mock::given(method("GET"))
        .and(path(route(job)))
        .and(query_param("tree", tree))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jobs":values})))
        .mount(server)
        .await;
}
fn resources(result: &ProviderResult) -> Vec<String> {
    result.result["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["resource"].as_str().unwrap().into())
        .collect()
}

#[tokio::test]
async fn validates_config_and_local_inputs_without_http() {
    assert_eq!(MIN_RESULT_BYTES, 11491);
    let server = MockServer::start().await;
    let p = provider(config(&server), ProviderLimits::default());
    let descriptor = descriptor(&p.listing);
    assert_eq!(descriptor.input_schema["required"], json!(["controller"]));
    assert!(
        p.local_scopes("job.list", &json!({"controller":"ci"}))
            .unwrap()
            .is_empty()
    );
    for bad in [
        json!({}),
        json!({"controller":"unknown"}),
        json!({"controller":"ci","folder":""}),
        json!({"controller":"ci","folder":"../secret"}),
        json!({"controller":"ci","folder":"A//B"}),
        json!({"controller":"ci","job":"A"}),
        json!({"controller":"ci","query":"A"}),
        json!({"controller":"ci","maxResults":0}),
        json!({"controller":"ci","maxResults":51}),
        json!({"controller":"ci","maxResults":null}),
        json!({"controller":"ci","pageToken":""}),
    ] {
        assert_eq!(
            p.invoke(invocation(bad, scope()))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    for change in 0..5 {
        let mut listing = p.listing.clone();
        let mut limits = ProviderLimits::default();
        match change {
            0 => listing.max_results = 101,
            1 => listing.max_candidate_pages = 0,
            2 => listing.max_upstream_requests = 0,
            3 => listing.max_scan_bytes = 0,
            _ => limits.max_upstream_response_bytes = MIN_RESULT_BYTES - 1,
        }
        let mut errors = vec![];
        listing.validate(&limits, &mut errors);
        assert!(!errors.is_empty());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn traverses_denied_parents_and_reuses_parent_page_within_call() {
    let server = MockServer::start().await;
    let mut hidden = child("", "HIDDEN", true);
    hidden["displayName"] = json!({"denied":"metadata"});
    mount(
        &server,
        "",
        0,
        10,
        json!([hidden, child("", "SECOND", true), child("", "ROOT", false)]),
    )
    .await;
    mount(
        &server,
        "HIDDEN",
        0,
        10,
        json!([child("HIDDEN", "DENIED", false)]),
    )
    .await;
    mount(
        &server,
        "SECOND",
        0,
        10,
        json!([child("SECOND", "OK", false)]),
    )
    .await;
    let allowed = SearchAuthorizationScope::from_selectors(
        vec![
            namespace("ci/SECOND"),
            exact("ci/ROOT"),
            exact("ci/HIDDEN/MISSING"),
        ],
        vec![],
    );
    let p = provider(config(&server), ProviderLimits::default());
    let first = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":10}),
            allowed.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&first), ["ci/SECOND/OK"]);
    assert_eq!(first.result["scanStatus"], "more");
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls
            .iter()
            .filter(|r| r.url.path() == "/ci/api/json")
            .count(),
        1
    );
    let serialized = serde_json::to_string(&first).unwrap();
    for hidden in ["HIDDEN", "DENIED", "DO_NOT_RELEASE", "evil.invalid"] {
        assert!(!serialized.contains(hidden), "{serialized}");
    }
    // Across invocations, only the next offset survives, so the parent is read at offset two.
    mount(&server, "", 2, 10, json!([child("", "ROOT", false)])).await;
    let second = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":10,"pageToken":first.result["nextPageToken"]}),
            allowed,
        ))
        .await
        .unwrap();
    assert_eq!(resources(&second), ["ci/ROOT"]);
    assert_eq!(second.result["scanStatus"], "exhausted");
}

#[tokio::test]
async fn namespace_exclusions_and_independent_allows_control_descent() {
    let server = MockServer::start().await;
    mount(
        &server,
        "",
        0,
        10,
        json!([
            child("", "DENIED", true),
            child("", "BLOCKED", true),
            child("", "OPEN", false)
        ]),
    )
    .await;
    mount(
        &server,
        "DENIED",
        0,
        10,
        json!([
            child("DENIED", "OK", false),
            child("DENIED", "HIDDEN", false)
        ]),
    )
    .await;
    let base = SearchAuthorizationScope::from_selectors(
        vec![ResourceSelector::All],
        vec![
            namespace("ci/DENIED"),
            exact("ci/DENIED"),
            namespace("ci/BLOCKED"),
            exact("ci/BLOCKED"),
        ],
    );
    let allowed = base.union(&SearchAuthorizationScope::from_selectors(
        vec![exact("ci/DENIED/OK")],
        vec![],
    ));
    let p = provider(config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":10}),
            allowed,
        ))
        .await
        .unwrap();
    assert_eq!(resources(&result), ["ci/DENIED/OK"]);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    for root in ["DENIED", "MISSING"] {
        let result = p
            .invoke(invocation(
                json!({"controller":"ci","folder":root}),
                SearchAuthorizationScope::from_selectors(
                    vec![exact(&format!("ci/{root}"))],
                    vec![],
                ),
            ))
            .await
            .unwrap_err();
        assert_eq!(result.reason_code(), ReasonCode::ServiceActionDenied);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn empty_budget_pages_resume_after_restart_without_skipping_jobs() {
    let server = MockServer::start().await;
    mount(&server, "", 0, 1, json!([child("", "SECRET_PARENT", true)])).await;
    mount(
        &server,
        "SECRET_PARENT",
        0,
        1,
        json!([child("SECRET_PARENT", "A", false)]),
    )
    .await;
    mount(&server, "SECRET_PARENT", 1, 1, json!([])).await;
    mount(&server, "", 1, 1, json!([child("", "B", false)])).await;
    mount(&server, "", 2, 1, json!([])).await;
    let mut cfg = config(&server);
    cfg.listing.max_candidate_pages = 1;
    let allowed = SearchAuthorizationScope::from_selectors(
        vec![exact("ci/SECRET_PARENT/A"), exact("ci/B")],
        vec![],
    );
    let mut input = json!({"controller":"ci","maxResults":1});
    let mut seen = vec![];
    let mut empty = 0;
    for index in 0..8 {
        let p = provider(cfg.clone(), ProviderLimits::default());
        let result = p
            .invoke(invocation(input.clone(), allowed.clone()))
            .await
            .unwrap();
        seen.extend(resources(&result));
        if result.result["count"] == 0 && result.result["scanStatus"] == "scan_budget" {
            empty += 1;
        }
        if index == 0 {
            assert_eq!(result.result["scanStatus"], "scan_budget");
            assert_eq!(result.result["count"], 0);
        }
        if let Some(token) = result.result.get("nextPageToken") {
            assert_eq!(token.as_str().unwrap().len(), TOKENS.max_token_bytes());
            assert!(!token.as_str().unwrap().contains("SECRET_PARENT"));
            input["pageToken"] = token.clone();
        } else {
            assert_eq!(result.result["scanStatus"], "exhausted");
            break;
        }
    }
    assert_eq!(seen, ["ci/SECRET_PARENT/A", "ci/B"]);
    assert!(empty >= 2);
    assert_eq!(server.received_requests().await.unwrap().len(), 5);
}

#[tokio::test]
async fn result_byte_boundary_resumes_at_first_unconsumed_child() {
    let server = MockServer::start().await;
    let children: Vec<_> = (0..3)
        .map(|i| {
            let mut v = child("", &format!("J{i}"), false);
            v["displayName"] = json!("é".repeat(2100));
            v
        })
        .collect();
    for offset in 0..3 {
        mount(&server, "", offset, 4, json!(&children[offset as usize..])).await;
    }
    let p = provider(config(&server), {
        let mut limits = ProviderLimits::default();
        limits.max_upstream_response_bytes = 16000;
        limits
    });
    let mut input = json!({"controller":"ci","maxResults":4});
    let mut seen = vec![];
    for _ in 0..3 {
        let result = p.invoke(invocation(input.clone(), scope())).await.unwrap();
        seen.extend(resources(&result));
        assert_eq!(result.result["count"], 1);
        assert_eq!(result.result["items"][0]["previewTruncated"], true);
        assert_eq!(
            result.result["items"][0]["displayName"]
                .as_str()
                .unwrap()
                .len(),
            4096
        );
        if let Some(token) = result.result.get("nextPageToken") {
            input["pageToken"] = token.clone();
        } else {
            assert_eq!(result.result["scanStatus"], "exhausted");
        }
    }
    assert_eq!(seen, ["ci/J0", "ci/J1", "ci/J2"]);
}

#[tokio::test]
async fn container_markers_identity_and_page_shapes_are_strict() {
    let mut bad_marker = child("", "F", true);
    bad_marker["jobs"] = json!({});
    let mut bad_parent = child("OTHER", "F", false);
    bad_parent["displayName"] = json!("secret");
    let bad_pages = vec![
        json!([bad_marker]),
        json!([bad_parent]),
        json!([child("", "A", false), child("", "A", false)]),
        json!([child("", "../escape", false)]),
        json!([
            child("", "A", false),
            child("", "B", false),
            child("", "C", false)
        ]),
    ];
    for page in bad_pages {
        let server = MockServer::start().await;
        mount(&server, "", 0, 2, page).await;
        let p = provider(config(&server), ProviderLimits::default());
        assert_eq!(
            p.invoke(invocation(
                json!({"controller":"ci","maxResults":2}),
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
    mount(
        &server,
        "",
        0,
        10,
        json!([child("", "EMPTY", true), child("", "MB", true)]),
    )
    .await;
    mount(&server, "EMPTY", 0, 10, json!([])).await;
    mount(
        &server,
        "MB",
        0,
        10,
        json!([child("MB", "feature%2Fbranch", false)]),
    )
    .await;
    let p = provider(config(&server), ProviderLimits::default());
    // The folder itself is excluded by namespace semantics; the percent-encoded branch is literal.
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","folder":"MB","maxResults":10}),
            SearchAuthorizationScope::from_selectors(vec![namespace("ci/MB")], vec![]),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&result), ["ci/MB/feature%2Fbranch"]);
    assert_eq!(result.result["items"][0]["kind"], "job");
    assert!(result.result["items"][0].get("webUrl").is_none());
}

#[tokio::test]
async fn errors_are_bounded_single_attempt_and_never_echo_paths_or_bodies() {
    for (status, reason) in [
        (401, ReasonCode::UpstreamUnauthorized),
        (403, ReasonCode::UpstreamForbidden),
        (404, ReasonCode::UpstreamFailed),
        (429, ReasonCode::UpstreamRateLimited),
        (503, ReasonCode::UpstreamFailed),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_string("SECRET_ERROR_BODY"))
            .mount(&server)
            .await;
        let p = provider(config(&server), ProviderLimits::default());
        let error = p
            .invoke(invocation(
                json!({"controller":"ci","folder":"SECRET_ROOT"}),
                scope(),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), reason);
        let text = format!("{error:?}");
        assert!(!text.contains("SECRET_"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    let server = MockServer::start().await;
    mount(&server, "", 0, 50, json!([child("", "A", false)])).await;
    let mut cfg = config(&server);
    cfg.listing.max_scan_bytes = 10;
    let error = provider(cfg, ProviderLimits::default())
        .invoke(invocation(json!({"controller":"ci"}), scope()))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(format!("{error:?}").contains("smaller maxResults"));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({"jobs":[]})),
        )
        .mount(&server)
        .await;
    let p = provider(config(&server), {
        let mut limits = ProviderLimits::default();
        limits.request_timeout_ms = 20;
        limits
    });
    assert_eq!(
        p.invoke(invocation(json!({"controller":"ci"}), scope()))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamTimeout
    );
}

#[tokio::test]
async fn continuation_rejects_changed_context_inputs_scope_method_and_configuration() {
    let server = MockServer::start().await;
    mount(&server, "", 0, 1, json!([child("", "A", false)])).await;
    let mut cfg = config(&server);
    cfg.controllers
        .insert("other".into(), cfg.controllers["ci"].clone());
    let p = provider(cfg.clone(), ProviderLimits::default());
    let first = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1}),
            scope(),
        ))
        .await
        .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap();
    let input = json!({"controller":"ci","maxResults":1,"pageToken":token});
    let request = invocation(input.clone(), scope());
    let altered = [
        invocation(
            json!({"controller":"other","maxResults":1,"pageToken":token}),
            scope(),
        ),
        invocation(
            json!({"controller":"ci","maxResults":2,"pageToken":token}),
            scope(),
        ),
        invocation(
            json!({"controller":"ci","folder":"A","maxResults":1,"pageToken":token}),
            scope(),
        ),
        invocation(
            input.clone(),
            SearchAuthorizationScope::from_selectors(vec![exact("ci/A")], vec![]),
        ),
        InvocationBuilder::from(request.clone())
            .principal("other")
            .build(),
        InvocationBuilder::from(request.clone())
            .execution_context("other")
            .build(),
        InvocationBuilder::from(request.clone())
            .credential_mode(CredentialMode::PerUser)
            .build(),
        InvocationBuilder::from(request.clone())
            .credential(bearer_credential("other"))
            .build(),
        InvocationBuilder::from(request.clone())
            .credential(credential_with_profile(
                basic_credential("u", "t"),
                "cloudbees-ci-api-token",
            ))
            .build(),
    ];
    for request in altered {
        assert_eq!(
            p.invoke(request).await.unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
    for change in 0..3 {
        let mut cfg = cfg.clone();
        match change {
            0 => cfg.listing.max_scan_bytes += 1,
            1 => {
                cfg.controllers.get_mut("ci").unwrap().web_base_url =
                    Some("https://other.invalid/".into())
            }
            _ => cfg
                .allowed_upstream_hosts
                .push("https://other.invalid/**".into()),
        }
        assert_eq!(
            provider(cfg, ProviderLimits::default())
                .invoke(request.clone())
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    let mut tampered = token.as_bytes().to_vec();
    tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
    assert_eq!(p.invoke(invocation(json!({"controller":"ci","maxResults":1,"pageToken":String::from_utf8(tampered).unwrap()}),scope())).await.unwrap_err().reason_code(),ReasonCode::InputInvalid);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn traversal_payload_validates_offsets_components_padding_and_depth() {
    let frames = vec![
        Frame::new(String::new()),
        Frame {
            component: "folder%2Fbranch".into(),
            offset: 19,
            page: None,
        },
    ];
    let encoded = encode(&frames).unwrap();
    assert_eq!(encoded.len(), PAYLOAD_BYTES);
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded[1].component, "folder%2Fbranch");
    assert_eq!(decoded[1].offset, 19);
    for index in [0, 1, 2, 8, PAYLOAD_BYTES - 1] {
        let mut bad = encoded.clone();
        bad[index] = 255;
        assert!(decode(&bad).is_err(), "{index}");
    }
    let mut too_deep = vec![Frame::new(String::new())];
    for _ in 0..MAX_DEPTH {
        too_deep.push(Frame::new("F".into()));
    }
    assert!(encode(&too_deep).is_some());
    too_deep.push(Frame::new("F".into()));
    assert!(encode(&too_deep).is_none());
    assert!(
        encode(&[
            Frame::new(String::new()),
            Frame::new("F".repeat(PAYLOAD_BYTES))
        ])
        .is_none()
    );
}

#[tokio::test]
async fn required_descent_beyond_payload_or_depth_is_terminal_incomplete() {
    let server = MockServer::start().await;
    let name = "F".repeat(PAYLOAD_BYTES);
    mount(&server, "", 0, 1, json!([child("", &name, true)])).await;
    let p = provider(config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["scanStatus"], "upstream_window");
    assert_eq!(result.result["count"], 1);
    assert!(result.result.get("nextPageToken").is_none());
    let server = MockServer::start().await;
    let mut parent = String::new();
    for _ in 0..=MAX_DEPTH {
        mount(&server, &parent, 0, 1, json!([child(&parent, "F", true)])).await;
        if !parent.is_empty() {
            parent.push('/');
        }
        parent.push('F');
    }
    let mut cfg = config(&server);
    cfg.listing.max_candidate_pages = 100;
    cfg.listing.max_upstream_requests = 100;
    let p = provider(cfg, ProviderLimits::default());
    let allowed = SearchAuthorizationScope::from_selectors(
        vec![exact(&format!("ci/{parent}/UNREACHABLE"))],
        vec![],
    );
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1}),
            allowed,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["scanStatus"], "upstream_window");
    assert_eq!(result.result["count"], 0);
    assert!(result.result.get("nextPageToken").is_none());
    assert_eq!(server.received_requests().await.unwrap().len(), 65);
}

#[tokio::test]
async fn continuations_preserve_original_expiry_and_enforce_range_windows_before_http() {
    use std::time::SystemTime;
    let server = MockServer::start().await;
    mount(&server, "", 0, 1, json!([child("", "A", false)])).await;
    mount(&server, "", 1, 1, json!([child("", "B", false)])).await;
    let p = provider(config(&server), ProviderLimits::default());
    let request = invocation(json!({"controller":"ci","maxResults":1}), scope());
    let input = parse_inputs(&p, request.inputs()).unwrap();
    let binding = listing_binding(&p, &request, &input, &scope()).unwrap();
    assert!(
        p.listing_signer
            .seal_until(
                &binding,
                &[0; 16],
                p.listing_signer.deadline(&binding).unwrap()
            )
            .is_err()
    );
    let first = p.invoke(request.clone()).await.unwrap();
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
            json!({"controller":"ci","maxResults":1,"pageToken":aged}),
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
    let expired = p
        .listing_signer
        .seal_until_at(
            &binding,
            opened.payload(),
            expiry - 60,
            now - Duration::from_secs(90),
        )
        .unwrap();
    assert_eq!(
        p.invoke(invocation(
            json!({"controller":"ci","maxResults":1,"pageToken":expired}),
            scope()
        ))
        .await
        .unwrap_err()
        .reason_code(),
        ReasonCode::InputInvalid
    );
    let payload = encode(&[Frame {
        component: String::new(),
        offset: i32::MAX as u32,
        page: None,
    }])
    .unwrap();
    let token = p
        .listing_signer
        .seal_until(
            &binding,
            &payload,
            p.listing_signer.deadline(&binding).unwrap(),
        )
        .unwrap();
    let window = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1,"pageToken":token}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(window.result["scanStatus"], "upstream_window");
    assert!(window.result.get("nextPageToken").is_none());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    for action in ["job.view", "build.list"] {
        let other = InvocationBuilder::new("cloudbees_ci", action)
            .inputs(json!({"controller":"ci","maxResults":1}))
            .search(SearchAuthorization::new("job", scope()))
            .credential(basic_credential("u", "t"))
            .build();
        let other_binding = listing_binding(&p, &other, &input, &scope()).unwrap();
        let token = p
            .listing_signer
            .seal_until(
                &other_binding,
                opened.payload(),
                p.listing_signer.deadline(&other_binding).unwrap(),
            )
            .unwrap();
        assert_eq!(
            p.invoke(invocation(
                json!({"controller":"ci","maxResults":1,"pageToken":token}),
                scope()
            ))
            .await
            .unwrap_err()
            .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    let other_family = ContinuationFamily::new(
        "cloudbees_ci",
        "other-list",
        1,
        ContinuationLifetime::StableWhenConfigured,
        PAYLOAD_BYTES,
    )
    .confidential()
    .expires_after(Duration::from_secs(900));
    let other_binding = other_family.bind(request.context(), &p.listing_fingerprint);
    let token = p
        .listing_signer
        .seal_until(
            &other_binding,
            opened.payload(),
            p.listing_signer.deadline(&other_binding).unwrap(),
        )
        .unwrap();
    assert_eq!(
        p.invoke(invocation(
            json!({"controller":"ci","maxResults":1,"pageToken":token}),
            scope()
        ))
        .await
        .unwrap_err()
        .reason_code(),
        ReasonCode::InputInvalid
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn full_result_cannot_skip_a_reachable_container_and_percent_names_encode_once_as_components()
{
    let server = MockServer::start().await;
    mount(
        &server,
        "",
        0,
        1,
        json!([child("", "feature%2Fbranch", true)]),
    )
    .await;
    mount(
        &server,
        "feature%2Fbranch",
        0,
        1,
        json!([child("feature%2Fbranch", "A", false)]),
    )
    .await;
    let p = provider(config(&server), ProviderLimits::default());
    let first = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(first.result["items"][0]["kind"], "container");
    let second = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1,"pageToken":first.result["nextPageToken"]}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&second), ["ci/feature%2Fbranch/A"]);
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].url.path(), "/ci/job/feature%252Fbranch/api/json");
}

#[tokio::test]
async fn empty_containers_are_listed_by_marker_and_web_urls_require_exact_configured_paths() {
    let server = MockServer::start().await;
    let mut empty = child("", "EMPTY", true);
    empty["_class"] = json!("UnknownPluginClass");
    empty["url"] = json!(format!("{}/ci/job/EMPTY/", server.uri()));
    mount(&server, "", 0, 10, json!([empty])).await;
    mount(&server, "EMPTY", 0, 10, json!([])).await;
    let p = provider(config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":10}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&result), ["ci/EMPTY"]);
    assert_eq!(result.result["items"][0]["kind"], "container");
    assert_eq!(result.result["scanStatus"], "exhausted");
    assert_eq!(
        result.result["items"][0]["webUrl"],
        format!("{}/ci/job/EMPTY/", server.uri())
    );
    let server = MockServer::start().await;
    let mut leaf = child("", "LEAF", false);
    leaf["_class"] = json!("com.cloudbees.hudson.plugins.folder.Folder");
    leaf["url"] = json!(format!("{}/ci/job/OTHER/", server.uri()));
    mount(&server, "", 0, 10, json!([leaf])).await;
    let p = provider(config(&server), ProviderLimits::default());
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":10}),
            scope(),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["items"][0]["kind"], "job");
    assert!(result.result["items"][0].get("webUrl").is_none());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn request_budget_yields_an_empty_page_and_stalled_bodies_keep_timeout_classification() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = MockServer::start().await;
    mount(&server, "", 0, 1, json!([child("", "DENIED", false)])).await;
    let mut cfg = config(&server);
    cfg.listing.max_upstream_requests = 1;
    let p = provider(cfg, ProviderLimits::default());
    let allowed = SearchAuthorizationScope::from_selectors(vec![exact("ci/LATER")], vec![]);
    let result = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":1}),
            allowed,
        ))
        .await
        .unwrap();
    assert_eq!(result.result["scanStatus"], "scan_budget");
    assert_eq!(result.result["count"], 0);
    assert!(result.result.get("nextPageToken").is_some());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        result.audit.as_ref().unwrap()["cloudbees_ci"]["egressProxy"],
        agent_access_provider::EgressRoute::direct().audit_value()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        assert!(socket.read(&mut buf).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let mut cfg = config(&server);
    cfg.controllers.get_mut("ci").unwrap().base_url = format!("http://{address}/ci/");
    cfg.allowed_upstream_hosts = vec![format!("http://{address}/ci/**")];
    let p = provider(cfg, ProviderLimits::default().with_request_timeout_ms(50));
    assert_eq!(
        p.invoke(invocation(json!({"controller":"ci"}), scope()))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamTimeout
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn controller_namespaces_do_not_cross_alias_boundaries() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    mount(&a, "", 0, 50, json!([child("", "A", false)])).await;
    mount(&b, "", 0, 50, json!([child("", "B", false)])).await;
    let mut cfg = config(&a);
    cfg.controllers
        .insert("ci2".into(), config(&b).controllers["ci"].clone());
    cfg.allowed_upstream_hosts
        .extend(config(&b).allowed_upstream_hosts);
    let p = provider(cfg, ProviderLimits::default());
    let allowed = SearchAuthorizationScope::from_selectors(vec![namespace("ci")], vec![]);
    assert_eq!(
        p.invoke(invocation(json!({"controller":"ci2"}), allowed.clone()))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
    let result = p
        .invoke(invocation(json!({"controller":"ci"}), allowed))
        .await
        .unwrap();
    assert_eq!(resources(&result), ["ci/A"]);
    assert_eq!(a.received_requests().await.unwrap().len(), 1);
    assert!(b.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn result_capacity_in_child_page_resumes_its_first_unconsumed_item() {
    let server = MockServer::start().await;
    mount(
        &server,
        "",
        0,
        2,
        json!([child("", "J", false), child("", "F", true)]),
    )
    .await;
    mount(
        &server,
        "F",
        0,
        2,
        json!([child("F", "x", false), child("F", "y", false)]),
    )
    .await;
    mount(&server, "F", 1, 2, json!([child("F", "y", false)])).await;
    mount(&server, "", 2, 2, json!([])).await;
    let p = provider(config(&server), ProviderLimits::default());
    let allowed =
        SearchAuthorizationScope::from_selectors(vec![exact("ci/J"), namespace("ci/F")], vec![]);
    let first = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":2}),
            allowed.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&first), ["ci/J", "ci/F/x"]);
    assert_eq!(first.result["scanStatus"], "more");
    let second = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":2,"pageToken":first.result["nextPageToken"]}),
            allowed.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(resources(&second), ["ci/F/y"]);
    assert_eq!(second.result["scanStatus"], "more");
    let third = p
        .invoke(invocation(
            json!({"controller":"ci","maxResults":2,"pageToken":second.result["nextPageToken"]}),
            allowed,
        ))
        .await
        .unwrap();
    assert!(resources(&third).is_empty());
    assert_eq!(third.result["scanStatus"], "exhausted");
    assert!(third.result.get("nextPageToken").is_none());
    let requests = server.received_requests().await.unwrap();
    let actual: Vec<_> = requests
        .iter()
        .map(|r| {
            (
                r.url.path().to_owned(),
                r.url
                    .query_pairs()
                    .find(|(k, _)| k == "tree")
                    .unwrap()
                    .1
                    .into_owned(),
            )
        })
        .collect();
    let expected: Vec<_> = [("", 0), ("F", 0), ("F", 1), ("", 2)]
        .into_iter()
        .map(|(job, offset)| {
            (
                route(job),
                format!(
                    "jobs[name,fullName,displayName,url,_class,jobs[name]{{0,0}}]{{{offset},{}}}",
                    offset + 2
                ),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn oversized_success_and_error_bodies_and_truncated_transport_keep_safe_errors() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (status, reason) in [
        (200, ReasonCode::UpstreamProtocolFailed),
        (401, ReasonCode::UpstreamUnauthorized),
        (403, ReasonCode::UpstreamForbidden),
        (404, ReasonCode::UpstreamFailed),
        (429, ReasonCode::UpstreamRateLimited),
        (503, ReasonCode::UpstreamFailed),
    ] {
        for scan_budget in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Retry-After", "17")
                        .set_body_string("SECRET".repeat(3000)),
                )
                .mount(&server)
                .await;
            let mut cfg = config(&server);
            let mut limits = ProviderLimits::default();
            if scan_budget {
                cfg.listing.max_scan_bytes = 10;
            } else {
                limits.max_upstream_response_bytes = MIN_RESULT_BYTES;
            }
            let error = provider(cfg, limits)
                .invoke(invocation(
                    json!({"controller":"ci","folder":"SECRET_ROOT"}),
                    scope(),
                ))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), reason);
            let message = format!("{error:?}");
            assert_eq!(message.contains("smaller maxResults"), status == 200);
            if status == 429 {
                assert_eq!(error.result.as_deref().unwrap()["retryAfterSeconds"], 17);
            }
            assert!(!message.contains("SECRET"));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
    let server = MockServer::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        assert!(socket.read(&mut buf).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut cfg = config(&server);
    cfg.controllers.get_mut("ci").unwrap().base_url = format!("http://{address}/ci/");
    cfg.allowed_upstream_hosts = vec![format!("http://{address}/ci/**")];
    let error = provider(cfg, ProviderLimits::default())
        .invoke(invocation(
            json!({"controller":"ci","folder":"SECRET_ROOT"}),
            scope(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamConnectionFailed);
    assert!(!format!("{error:?}").contains("SECRET"));
    task.await.unwrap();
}
