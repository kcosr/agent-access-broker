use super::*;
use futures_util::StreamExt;

#[tokio::test]
async fn openapi_gateway_early_upstream_reply_does_not_wait_for_an_unfinished_upload() {
    let upstream = Upstream::raw(RawReply::EarlyRejection).await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["upload_bytes"]).await;
    let chunks =
        futures_util::stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"first")) })
            .chain(futures_util::stream::pending());
    tokio::time::timeout(Duration::from_secs(2), async {
        let response = fixture
            .gateway(Method::POST, "/upload", "early-upstream-reply")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::Body::wrap_stream(chunks))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.text().await.unwrap(),
            "synthetic early rejection\n"
        );
    })
    .await
    .expect("the complete early response arrives before upload disposal finishes");
    // Joined terminal audit waits for bounded disposal of the unfinished input.
    // Its deadline must include the production linger period, not race it.
    let terminal = fixture
        .terminal_within(
            "early-upstream-reply",
            crate::ingress::lingering_close::LINGER_TIMEOUT + Duration::from_secs(2),
        )
        .await;
    assert_eq!(terminal["upstreamStatus"], 413);
    assert_eq!(upstream.api_requests().len(), 1);
    assert_eq!(upstream.writes(), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_late_upload_failure_records_started_upstream_work_without_retry() {
    for cap_exceeded in [false, true] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready_with(
            &upstream,
            UpstreamAuth::Anonymous,
            &["upload_bytes"],
            |config| {
                if cap_exceeded {
                    config
                        .imports
                        .gateway_bindings
                        .get_mut(SERVICE)
                        .unwrap()
                        .request_body_max_bytes = Some(8);
                }
            },
        )
        .await;
        let started = upstream.upload_started();
        let chunks =
            futures_util::stream::unfold((0, started), move |(step, started)| async move {
                match step {
                    0 => Some((Ok(Bytes::from_static(b"first")), (1, started))),
                    1 => {
                        started.notified().await;
                        let frame = if cap_exceeded {
                            Ok(Bytes::from_static(b"later"))
                        } else {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "synthetic upload interruption",
                            ))
                        };
                        Some((frame, (2, started)))
                    }
                    _ => None,
                }
            });
        let id = if cap_exceeded {
            "late-upload-cap"
        } else {
            "late-upload-failure"
        };
        let reason = if cap_exceeded {
            "gateway_request_cap_exceeded"
        } else {
            "gateway_request_body_denied"
        };
        let response = fixture
            .gateway(Method::POST, "/upload", id)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::Body::wrap_stream(chunks))
            .send()
            .await;
        if cap_exceeded {
            assert!(
                response.is_ok(),
                "valid client body receives the postdispatch cap failure"
            );
        }
        // The read-error client can terminate its own transport before it reads
        // a response. Any delivered response must preserve execution uncertainty.
        if let Ok(response) = response {
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(response.headers()[REASON_CODE_HEADER], reason);
            assert!(
                response
                    .text()
                    .await
                    .unwrap()
                    .contains("upstream execution may be partial or uncertain")
            );
        }
        let terminal = fixture.terminal(id).await;
        assert_eq!(terminal["decision"], "error");
        assert_eq!(terminal["reasonCode"], reason);
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
        assert_eq!(terminal["providerAudit"]["gateway"]["requestBytes"], 5);
        assert!(
            terminal["providerAudit"]["gateway"]["message"]
                .as_str()
                .is_some_and(
                    |message| message.contains("upstream execution may be partial or uncertain")
                )
        );
        let records =
            read_audit_records(Path::new(&fixture.seed.config.audit.as_ref().unwrap().path));
        let records = records
            .iter()
            .filter(|record| record["agentRequestId"] == id)
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| record["providerAudit"]["gateway"]["phase"] == "started")
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["providerAudit"]["gateway"]["phase"] == "failed")
                .count(),
            1
        );
        assert_eq!(upstream.writes(), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while upstream.api_requests().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("upstream observes the interrupted upload");
        assert_eq!(
            upstream.api_requests().len(),
            1,
            "failed upload must not replay"
        );
        assert_eq!(upstream.api_requests()[0].body, b"first");
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_fragmented_known_length_upload_is_denied_before_upstream_dispatch() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["upload_bytes"],
        |config| {
            config
                .imports
                .gateway_bindings
                .get_mut(SERVICE)
                .unwrap()
                .request_body_max_bytes = Some(8);
        },
    )
    .await;
    let chunks = futures_util::stream::iter(
        [b"aaaa", b"bbbb", b"cccc"].map(|chunk| Ok::<_, std::io::Error>(Bytes::from_static(chunk))),
    );
    let response = fixture
        .gateway(Method::POST, "/upload", "known-fragmented-cap")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, 12)
        .body(reqwest::Body::wrap_stream(chunks))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_request_cap_exceeded"
    );
    response.bytes().await.unwrap();
    assert!(upstream.api_requests().is_empty());
    assert_eq!(upstream.writes(), 0);
    let terminal = fixture.terminal("known-fragmented-cap").await;
    assert_eq!(terminal["decision"], "deny");
    assert_eq!(terminal["reasonCode"], "gateway_request_cap_exceeded");
    assert_ne!(terminal["providerAudit"]["gateway"]["phase"], "started");
    let records = read_audit_records(Path::new(&fixture.seed.config.audit.as_ref().unwrap().path));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["agentRequestId"] == "known-fragmented-cap")
            .count(),
        1
    );
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_known_length_request_and_response_caps_are_enforced() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["upload_bytes", "download_blob"],
        |config| {
            let binding = config.imports.gateway_bindings.get_mut(SERVICE).unwrap();
            binding.request_body_max_bytes = Some(8);
            binding.response_body_max_bytes = Some(8);
        },
    )
    .await;
    let response = fixture
        .gateway(Method::POST, "/upload", "known-upload-cap")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(BLOB.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(upstream.api_requests().is_empty());
    let response = fixture
        .gateway(Method::GET, "/blob", "known-download-cap")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    let terminal = fixture.terminal("known-download-cap").await;
    assert_eq!(terminal["decision"], "error");
    assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 0);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_classifier_denials_do_not_spend_the_operation_rate_allowance() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item"],
        |config| {
            config.limits.invocations.default = Some(agent_access_core::InvocationLimitConfig {
                requests: 1,
                window: "60s".into(),
                max_wait: Some("0s".into()),
            });
        },
    )
    .await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "unaccepted-before-rate")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(upstream.api_requests().is_empty());
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "charged-once")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let response = fixture
        .gateway(Method::GET, "/items/beta", "rate-refusal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_ambiguous_write_disconnect_and_partial_download_are_never_replayed() {
    let upstream = Upstream::raw(RawReply::CloseBeforeHeaders).await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["update_item"]).await;
    let payload = b"{\"effect\":true}";
    let response = fixture
        .gateway(Method::POST, "/items/alpha", "write-disconnected")
        .header(CONTENT_TYPE, "application/json")
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    response.bytes().await.unwrap();
    let terminal = fixture.terminal("write-disconnected").await;
    assert_eq!(terminal["decision"], "error");
    assert_eq!(upstream.writes(), 1);
    assert_eq!(upstream.api_requests().len(), 1);
    assert_eq!(upstream.api_requests()[0].body, payload);
    fixture.stop().await;

    let upstream = Upstream::raw(RawReply::TruncatedLength).await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["download_blob"]).await;
    match fixture
        .gateway(Method::GET, "/blob", "truncated-download")
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::OK => {
            assert!(response.bytes().await.is_err())
        }
        Ok(response) => assert_eq!(response.status(), StatusCode::BAD_GATEWAY),
        Err(_) => {}
    }
    let terminal = fixture.terminal("truncated-download").await;
    assert_eq!(terminal["decision"], "error");
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
    assert!(
        terminal["providerAudit"]["gateway"]["responseBytes"]
            .as_u64()
            .unwrap()
            <= 5
    );
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_unknown_length_response_cap_and_idle_timeout_fail_after_stream_start() {
    for idle in [false, true] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready_with(
            &upstream,
            UpstreamAuth::Anonymous,
            &["stream_blob"],
            |config| {
                let binding = config.imports.gateway_bindings.get_mut(SERVICE).unwrap();
                if idle {
                    binding.streaming_idle_timeout_ms = Some(100);
                } else {
                    binding.response_body_max_bytes = Some(15);
                }
            },
        )
        .await;
        let mut response = fixture
            .gateway(Method::GET, "/stream", "bounded-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            &response.chunk().await.unwrap().unwrap()[..],
            b"first-chunk"
        );
        if !idle {
            upstream.release_stream();
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(5), response.bytes())
                .await
                .unwrap()
                .is_err()
        );
        let terminal = fixture.terminal("bounded-stream").await;
        assert_eq!(terminal["decision"], "error");
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
        assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 11);
        assert_eq!(upstream.api_requests().len(), 1);
        upstream.release_stream();
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_client_disconnect_finalizes_audit_and_releases_transfer_capacity() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["stream_blob", "download_blob"],
        |config| {
            config.limits.max_concurrent_requests_per_principal = 1;
        },
    )
    .await;
    let mut response = fixture
        .gateway(Method::GET, "/stream", "cancelled-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &response.chunk().await.unwrap().unwrap()[..],
        b"first-chunk"
    );
    let blocked = fixture
        .gateway(Method::GET, "/blob", "capacity-held")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    blocked.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    drop(response);
    let terminal = fixture.terminal("cancelled-stream").await;
    assert_eq!(terminal["decision"], "error");
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "canceled");
    assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 11);
    let response = fixture
        .gateway(Method::GET, "/blob", "capacity-released")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), BLOB);
    assert_eq!(upstream.api_requests().len(), 2);
    upstream.release_stream();
    fixture.stop().await;
}
