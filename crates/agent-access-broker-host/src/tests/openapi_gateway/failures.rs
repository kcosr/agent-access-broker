use super::*;
use futures_util::StreamExt;

#[tokio::test]
async fn openapi_gateway_early_upstream_reply_does_not_wait_for_an_unfinished_upload() {
    let upstream = Upstream::raw(RawReply::EarlyRejection).await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["upload_bytes"]).await;
    let chunks =
        futures_util::stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"first")) })
            .chain(futures_util::stream::pending());
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
    let terminal = fixture.terminal("early-upstream-reply").await;
    assert_eq!(terminal["upstreamStatus"], 413);
    assert_eq!(upstream.api_requests().len(), 1);
    assert_eq!(upstream.writes(), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_late_upload_failure_records_started_upstream_work_without_retry() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["upload_bytes"]).await;
    let started = upstream.upload_started();
    let chunks = futures_util::stream::unfold((0, started), |(step, started)| async move {
        match step {
            0 => Some((Ok(Bytes::from_static(b"first")), (1, started))),
            1 => {
                started.notified().await;
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "synthetic upload interruption",
                    )),
                    (2, started),
                ))
            }
            _ => None,
        }
    });
    if let Ok(response) = fixture
        .gateway(Method::POST, "/upload", "late-upload-failure")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(reqwest::Body::wrap_stream(chunks))
        .send()
        .await
    {
        assert!(!response.status().is_success());
    }
    let terminal = fixture.terminal("late-upload-failure").await;
    assert_eq!(terminal["decision"], "error");
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
    assert_eq!(upstream.writes(), 1);
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
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
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
