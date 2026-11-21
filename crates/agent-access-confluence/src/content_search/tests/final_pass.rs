//! An error in a started proof withholds the whole page, including an earlier
//! retained/final-checked candidate and an upstream continuation.
use super::*;

fn two_candidates() -> Arc<Backend> {
    Backend::new(vec![results(
        vec![page("101", "ENG"), page("102", "ENG")],
        Some("private-next-cursor"),
    )])
}

fn two_exact(kind: ConfluenceSearchContentKind) -> ContainmentCollectionAuthorization {
    authority(
        kind,
        vec![content(kind, "101", false), content(kind, "102", false)],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'a',
    )
}

fn assert_whole_page_failure(error: &ProviderError, reason: ReasonCode, final_pass: bool) {
    assert_eq!(error.reason_code(), reason, "{error:?}");
    assert!(
        error.result.is_none(),
        "failed proofs return neither rows nor nextPageToken"
    );
    assert!(
        error.object_ids.is_none(),
        "earlier checked IDs must not escape"
    );
    assert!(!error.message.contains("private-next-cursor"));
    assert!(
        error
            .audit
            .as_ref()
            .and_then(|value| value.get("observedSpaces"))
            .is_none()
    );
    if final_pass {
        assert_eq!(
            error.audit.as_ref().unwrap()["locationProof"]["finalCheck"],
            "unresolved"
        );
    }
}

#[tokio::test]
async fn provider_classified_failures_withhold_two_candidates_in_initial_and_final_passes() {
    for (kind, failure) in [
        (ConfluenceSearchContentKind::Page, "noncurrent"),
        (ConfluenceSearchContentKind::BlogPost, "noncurrent"),
        (ConfluenceSearchContentKind::Page, "wrong_kind"),
        (ConfluenceSearchContentKind::Page, "unreadable_space"),
        (ConfluenceSearchContentKind::BlogPost, "unreadable_space"),
        (ConfluenceSearchContentKind::Page, "hidden_ancestor"),
    ] {
        for final_pass in [false, true] {
            let backend = two_candidates();
            let lineage = failure == "hidden_ancestor";
            for id in ["101", "102"] {
                if lineage {
                    backend.rooted(id);
                } else {
                    backend.set_nodes(id, vec![node(id, "1", None)]);
                }
            }
            match failure {
                "noncurrent" | "wrong_kind" => {
                    let mut invalid = node("102", "1", None);
                    if failure == "noncurrent" {
                        invalid.status = ConfluenceContentStatus::Draft;
                    } else {
                        invalid.kind = ConfluenceNodeKind::Folder;
                    }
                    backend.set_nodes(
                        "102",
                        if final_pass {
                            vec![node("102", "1", None), invalid]
                        } else {
                            vec![invalid]
                        },
                    );
                }
                "unreadable_space" | "hidden_ancestor" => {
                    let label = if lineage { "node:100" } else { "space:1" };
                    // Each candidate/pass has its own numeric-space/ancestor
                    // observation. The second candidate is the one that fails.
                    let successes = if final_pass { 3 } else { 1 };
                    let mut observations = vec![None; successes];
                    observations.push(Some(ConfluenceBackendError::Forbidden));
                    backend
                        .failures
                        .lock()
                        .unwrap()
                        .insert(label.into(), observations.into());
                }
                _ => unreachable!(),
            }
            let selected = if lineage {
                tree_authority()
            } else {
                two_exact(kind)
            };
            let error = provider(backend.clone(), config())
                .invoke_content_search(invocation(kind, selected, inputs()), kind)
                .await
                .unwrap_err();
            let reason = if failure == "wrong_kind" {
                ReasonCode::UpstreamProtocolFailed
            } else {
                ReasonCode::ScopeUnresolved
            };
            assert_whole_page_failure(&error, reason, final_pass);
            let reads = backend.reads.lock().unwrap();
            let prefix = if kind == ConfluenceSearchContentKind::Page {
                "node"
            } else {
                "blog"
            };
            for id in ["101", "102"] {
                assert_eq!(
                    reads
                        .iter()
                        .filter(|read| **read == format!("{prefix}:{id}"))
                        .count(),
                    if final_pass { 2 } else { 1 },
                    "{failure}, final={final_pass}"
                );
            }
            if final_pass {
                // This prefix proves both initial proofs and the first final
                // proof completed before the second candidate's failure.
                let expected = if lineage {
                    vec![
                        "node:101", "space:1", "node:100", "node:102", "space:1", "node:100",
                        "node:101", "space:1", "node:100",
                    ]
                } else if kind == ConfluenceSearchContentKind::Page {
                    vec![
                        "node:101", "space:1", "node:102", "space:1", "node:101", "space:1",
                    ]
                } else {
                    vec![
                        "blog:101", "space:1", "blog:102", "space:1", "blog:101", "space:1",
                    ]
                };
                assert!(
                    reads
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .starts_with(&expected)
                );
            }
            assert_eq!(backend.requests.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn actual_request_and_byte_exhaustion_are_whole_page_errors_in_either_pass() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        for final_pass in [false, true] {
            for exhausted in ["requests", "bytes"] {
                let backend = two_candidates();
                for id in ["101", "102"] {
                    backend.set_nodes(id, vec![node(id, "1", None)]);
                }
                let mut limits = config();
                limits.content_access.max_metadata_requests = 8;
                if exhausted == "bytes" {
                    // Initial failure starts the second proof after retaining one
                    // candidate. Final failure follows both initial proofs and
                    // the first candidate's complete final proof.
                    limits.content_access.max_metadata_bytes = if final_pass { 416 } else { 160 };
                } else {
                    let prefix = if kind == ConfluenceSearchContentKind::Page {
                        "node"
                    } else {
                        "blog"
                    };
                    // Nominal per-pass reservations already cover the adapter's
                    // bounded requests/recovery. Deliberately charge extra work
                    // through the real budget here to test its refusal path;
                    // this is not a claim that valid HTTP retries exceed that bound.
                    let charges = if final_pass {
                        vec![(1, 64), (3, 64)]
                    } else {
                        vec![(7, 64)]
                    };
                    backend
                        .metadata_charges
                        .lock()
                        .unwrap()
                        .insert(format!("{prefix}:102"), charges.into());
                }
                let error = provider(backend.clone(), limits)
                    .invoke_content_search(invocation(kind, two_exact(kind), inputs()), kind)
                    .await
                    .unwrap_err();
                assert_whole_page_failure(&error, ReasonCode::ScopeUnresolved, final_pass);
                let budget = backend
                    .last_metadata_budget
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap();
                assert!(
                    budget.exhausted(),
                    "actual shared counters must affirm exhaustion"
                );
                let usage = budget.usage().unwrap();
                if exhausted == "requests" {
                    assert_eq!(usage.0, 8);
                } else {
                    assert_eq!(usage, if final_pass { (7, 384) } else { (3, 128) });
                }
                assert_eq!(backend.requests.lock().unwrap().len(), 1);
            }
        }
    }
    // The same two-candidate fixture stopping BEFORE an unaffordable proof is a
    // successful scan_budget response, with a final-checked row and resumable
    // cursor. It neither exhausts the real counters nor returns an unresolved error.
    let kind = ConfluenceSearchContentKind::Page;
    let backend = two_candidates();
    for id in ["101", "102"] {
        backend.set_nodes(id, vec![node(id, "1", None)]);
    }
    let mut limits = config();
    limits.content_access.max_metadata_requests = 7;
    let result = provider(backend.clone(), limits)
        .invoke_content_search(invocation(kind, two_exact(kind), inputs()), kind)
        .await
        .unwrap();
    assert_eq!(result.result["pages"].as_array().unwrap().len(), 1);
    assert_eq!(result.result["pages"][0]["id"], "101");
    assert_eq!(result.result["scanStatus"], "scan_budget");
    assert!(result.result["nextPageToken"].is_string());
    assert_eq!(
        result.audit.as_ref().unwrap()["locationProof"]["finalCheck"],
        "matched"
    );
    let budget = backend
        .last_metadata_budget
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert!(!budget.exhausted());
    assert_eq!(budget.usage().unwrap(), (4, 256));
}

#[tokio::test]
async fn metadata_http_deadline_withholds_two_candidate_page_in_either_pass() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for final_pass in [false, true] {
        let server = MockServer::start().await;
        let content = |id| {
            json!({"id":id,"type":"page","title":format!("Record {id}"),
            "space":{"key":"ENG"},"status":"current","version":{"number":1}})
        };
        Mock::given(method("GET"))
            .and(path("/wiki/rest/api/content/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results":[content("101"),content("102")],
                "_links":{"next":"/wiki/rest/api/content/search?cursor=private-next-cursor"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let observed = |id| {
            json!({"id":id,"type":"page","spaceId":"1","status":"current",
            "parentId":null,"parentType":null,"version":{"number":1}})
        };
        Mock::given(method("GET"))
            .and(path("/wiki/api/v2/pages/101"))
            .respond_with(ResponseTemplate::new(200).set_body_json(observed("101")))
            .expect(if final_pass { 2 } else { 1 })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/wiki/api/v2/spaces/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id":"1","key":"ENG","status":"current"
            })))
            .expect(if final_pass { 3 } else { 1 })
            .mount(&server)
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let node_calls = calls.clone();
        let node_value = observed("102");
        Mock::given(method("GET"))
            .and(path("/wiki/api/v2/pages/102"))
            .respond_with(move |_: &wiremock::Request| {
                let reply = ResponseTemplate::new(200).set_body_json(node_value.clone());
                if node_calls.fetch_add(1, Ordering::SeqCst) == 0 && final_pass {
                    reply
                } else {
                    reply.set_delay(Duration::from_secs(5))
                }
            })
            .expect(if final_pass { 2 } else { 1 })
            .mount(&server)
            .await;
        let mut settings = config();
        settings.allowed_upstream_hosts = vec![format!("{}/**", server.uri())];
        let limits = ProviderLimits::default().with_request_timeout_ms(1_000);
        let backend = HttpConfluenceBackend::new_with_api_base(
            settings.clone(),
            limits.clone(),
            url::Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
        );
        let provider = ConfluenceProvider::with_backend_and_signing_key(
            settings,
            limits,
            Arc::new(backend),
            test_signing_key(9),
        );
        let kind = ConfluenceSearchContentKind::Page;
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            provider.invoke_content_search(invocation(kind, two_exact(kind), inputs()), kind),
        )
        .await
        .expect("the HTTP client's own deadline must end the proof")
        .unwrap_err();
        assert_whole_page_failure(&error, ReasonCode::UpstreamTimeout, final_pass);
        assert_eq!(calls.load(Ordering::SeqCst), if final_pass { 2 } else { 1 });
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.url.path())
                .collect::<Vec<_>>(),
            if final_pass {
                vec![
                    "/wiki/rest/api/content/search",
                    "/wiki/api/v2/pages/101",
                    "/wiki/api/v2/spaces/1",
                    "/wiki/api/v2/pages/102",
                    "/wiki/api/v2/spaces/1",
                    "/wiki/api/v2/pages/101",
                    "/wiki/api/v2/spaces/1",
                    "/wiki/api/v2/pages/102",
                ]
            } else {
                vec![
                    "/wiki/rest/api/content/search",
                    "/wiki/api/v2/pages/101",
                    "/wiki/api/v2/spaces/1",
                    "/wiki/api/v2/pages/102",
                ]
            }
        );
    }
}
