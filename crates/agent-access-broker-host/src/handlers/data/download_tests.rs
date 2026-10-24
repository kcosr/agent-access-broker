use super::*;
use agent_access_provider::ProviderResultStream;
use agent_access_provider::test_support::install_trace_capture;
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicBool, Ordering};

fn response(result: Value, stream: ProviderResultStream) -> BrokerResponse<Value> {
    BrokerResponse {
        status: 200,
        retry_after_seconds: None,
        envelope: ResponseEnvelope {
            agent_request_id: "download-agent".into(),
            broker_request_id: "download-broker".into(),
            service: "reports".into(),
            action: "download".into(),
            decision: Decision::Allow,
            resource_scopes: ResourceScopes::new(),
            reason_code: None,
            reason: None,
            result: Some(result),
            error: None,
        },
        stream: Some(stream),
    }
}

#[test]
fn metadata_serialization_enforces_the_encoded_header_boundary() {
    let fits = Value::String("x".repeat(RAW_METADATA_JSON_LIMIT - 2));
    let bytes = bounded_metadata(&fits, RAW_METADATA_JSON_LIMIT).unwrap();
    assert_eq!(BASE64.encode(bytes).len(), RAW_METADATA_HEADER_LIMIT);
    let exceeds = Value::String("x".repeat(RAW_METADATA_JSON_LIMIT - 1));
    assert!(bounded_metadata(&exceeds, RAW_METADATA_JSON_LIMIT).is_err());
}

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn oversized_metadata_drops_transfer_and_preserves_only_bounded_write_evidence() {
    let capture = install_trace_capture().start();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(Arc::clone(&dropped));
    let stream = ProviderResultStream::from_stream(
        RAW_RESULT_MIME,
        futures_util::stream::once(async move {
            let _guard = guard;
            Ok(Bytes::from_static(b"private-file-bytes"))
        }),
    );
    let result = json!({
        "upstreamCommand": {"private": "private-metadata".repeat(RAW_METADATA_JSON_LIMIT)},
        "mutationStatus": "applied_unverified", "retrySafe": false,
        "safeLocators": {"report": "REPORT-42"}
    });
    let response = capture
        .run(raw_result_response(response(result, stream), None, true))
        .await;
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(RESULT_METADATA_HEADER));
    let body = axum::body::to_bytes(response.into_body(), 32_768)
        .await
        .unwrap();
    let envelope: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope["reasonCode"], "operation_failed");
    assert_eq!(envelope["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(envelope["result"]["safeLocators"]["report"], "REPORT-42");
    assert!(envelope["result"].get("upstreamCommand").is_none());
    let events = capture.take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "raw_download_metadata_refused");
    assert_eq!(events[0]["category"], "serialization_limit");
    assert_eq!(events[0]["agentRequestId"], "download-agent");
    assert_eq!(events[0]["brokerRequestId"], "download-broker");
    assert!(
        events[0]["encodedLengthLowerBound"].as_u64().unwrap() > RAW_METADATA_HEADER_LIMIT as u64
    );
    assert!(!String::from_utf8_lossy(&body).contains("private-"));
    assert!(!serde_json::to_string(&events).unwrap().contains("private-"));
}

#[tokio::test]
async fn raw_body_and_yielded_bytes_keep_global_and_principal_admission() {
    for streaming in [false, true] {
        let guards = Arc::new(crate::ingress::guards::IngressGuards::new());
        let permits = RequestPermits {
            _global: guards.try_global_concurrency(1).unwrap(),
            _principal: guards
                .try_principal_concurrency("download-user", 1)
                .unwrap(),
        };
        let data = vec![42; 1024];
        let stream = if streaming {
            ProviderResultStream::from_stream(
                RAW_RESULT_MIME,
                futures_util::stream::iter([Ok(Bytes::from(data))]),
            )
        } else {
            ProviderResultStream::from_bytes(RAW_RESULT_MIME, data)
        };
        let response =
            raw_result_response(response(json!({"size":1024}), stream), Some(permits), true).await;
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let encoded = response.headers()[RESULT_METADATA_HEADER].to_str().unwrap();
        let metadata: Value = serde_json::from_slice(&BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(metadata["result"]["size"], 1024);
        let mut body = response.into_body();
        assert!(guards.try_global_concurrency(1).is_err());
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(body.frame().await.is_none());
        drop(body);
        let slice = bytes.slice(0..1);
        drop(bytes);
        assert!(guards.try_global_concurrency(1).is_err());
        assert!(
            guards
                .try_principal_concurrency("download-user", 1)
                .is_err()
        );
        drop(slice);
        assert!(guards.try_global_concurrency(1).is_ok());
        assert!(guards.try_principal_concurrency("download-user", 1).is_ok());
    }
}
