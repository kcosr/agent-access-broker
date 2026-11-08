use super::*;
use agent_access_provider::{
    GatewayBodyFrame, GatewayClassification, GatewayManagedAction, GatewayManagedInput,
    GatewayProtocol, GatewayServiceContext, GatewayVersionedData, ReasonCode, test_support,
};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};

fn plan(method: &str, path: &str, source: &str) -> Value {
    let parameters = if path.contains("{id}") {
        json!([{"name":"id","location":"path","required":true,"style":"simple","explode":false,"schema":{"type":"string","maxLength":64}}])
    } else {
        json!([])
    };
    json!({
        "version": 1,
        "source": {"operationId":source},
        "method": method, "path": path,
        "security": {"kind":"anonymous"},
        "parameters": parameters,
        "responses": {"200":{"headers":[],"contentTypes":["application/json"]}},
    })
}

fn input(plan: Value) -> GatewayManagedInput {
    let method = plan["method"].as_str().unwrap().to_owned();
    let path = plan["path"].as_str().unwrap().to_owned();
    GatewayManagedInput::new(
        GatewayVersionedData::new(1, json!({
            "version": 1,
            "paths": {(path): {"methods": {(method): {"source":plan["source"],"current":true,"supported":true}}}},
        })),
        vec![GatewayManagedAction::new("items.read", 1, "a".repeat(64), true, GatewayVersionedData::new(1, plan))],
    ).with_manifest_revision(1, "b".repeat(64))
}

fn build(
    input: &GatewayManagedInput,
) -> Result<Arc<dyn GatewayProtocol>, agent_access_provider::ProviderBuildError> {
    registration().managed_builder().unwrap()(
        &GatewayServiceContext::new(
            "inventory",
            "Inventory",
            "https://inventory.example.com/api",
        ),
        input,
    )
}

fn classify(
    protocol: &dyn GatewayProtocol,
    method: &Method,
    target: &str,
    headers: &HeaderMap,
) -> Result<GatewayClassification, agent_access_provider::ProviderError> {
    protocol.classify(test_support::synthetic_gateway_request_head(
        method, target, headers,
    ))
}

fn body(data: &'static [u8]) -> agent_access_provider::GatewayBody {
    let frames = if data.is_empty() {
        vec![]
    } else {
        vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(data)))]
    };
    test_support::synthetic_gateway_body(frames, 1024)
}

#[test]
fn registration_is_managed_only_counted_and_has_no_verification() {
    assert_eq!(registration().kind(), "openapi_gateway");
    assert_eq!(registration().counted("request"), Some(true));
    assert_eq!(registration().counted("discovery"), None);
    assert!(
        registration()
            .parse_config(toml::Table::new().into())
            .is_err()
    );
    let protocol = build(&input(plan("GET", "/items", "list"))).unwrap();
    assert!(protocol.verification(None).unwrap().is_none());
}

#[test]
fn complete_route_universe_blocks_literal_method_and_inactive_fallbacks() {
    let mut candidate = input(plan("GET", "/items/{id}", "get"));
    candidate.manifest.data["paths"]["/items/admin"] = json!({"methods": {
        "POST":{"source":{"operationId":"admin"},"current":true,"supported":false}
    }});
    candidate.manifest.data["paths"]["/items/removed"] = json!({"methods": {
        "GET":{"source":{"operationId":"removed"},"current":false,"supported":true}
    }});
    let protocol = build(&candidate).unwrap();
    for (method, target) in [
        (Method::GET, "/items/admin"),
        (Method::POST, "/items/admin"),
        (Method::GET, "/items/removed"),
        (Method::HEAD, "/items/ordinary"),
        (Method::OPTIONS, "/items/ordinary"),
        (Method::GET, "/absent"),
    ] {
        let error = classify(protocol.as_ref(), &method, target, &HeaderMap::new()).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRuleNotFound);
        assert_eq!(error.message, "gateway route was not found");
    }
    let active = classify(
        protocol.as_ref(),
        &Method::GET,
        "/items/ordinary",
        &HeaderMap::new(),
    )
    .unwrap();
    assert_eq!(active.action(), "items.read");
    assert!(active.scopes().is_empty());
    assert_eq!(active.request_kind(), "request");
}

#[test]
fn inactive_accepted_action_is_not_routable() {
    let mut candidate = input(plan("GET", "/items/{id}", "get"));
    candidate.actions[0].dispatchable = false;
    let protocol = build(&candidate).unwrap();
    assert_eq!(
        classify(
            protocol.as_ref(),
            &Method::GET,
            "/items/value",
            &HeaderMap::new()
        )
        .unwrap_err()
        .reason_code(),
        ReasonCode::GatewayRuleNotFound
    );
}

#[test]
fn malformed_target_never_becomes_a_different_route() {
    let protocol = build(&input(plan("GET", "/items/{id}", "get"))).unwrap();
    for path in [
        "/items/a%2Fb",
        "/items/a%5Cb",
        "/items/%252F",
        "/items/%2e%2e",
        "/items/%",
        "/items/a\\b",
        "/items/..",
    ] {
        assert_eq!(
            classify(protocol.as_ref(), &Method::GET, path, &HeaderMap::new())
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid,
            "{path}"
        );
    }
}

#[test]
fn builder_refuses_incoherent_and_unknown_records() {
    let good = input(plan("GET", "/items", "list"));
    let mut candidates = Vec::new();
    let mut bad = good.clone();
    bad.manifest.version = 2;
    candidates.push(bad);
    let mut bad = good.clone();
    bad.manifest_generation = 0;
    candidates.push(bad);
    let mut bad = good.clone();
    bad.manifest_hash = "invalid".into();
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].plan.version = 2;
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].version = 0;
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].accepted_hash.clear();
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].action = "Not an action".into();
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions.push(bad.actions[0].clone());
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].plan.data["source"] = json!({"operationId":"replacement"});
    candidates.push(bad);
    let mut bad = good.clone();
    bad.actions[0].plan.data["unexpected"] = json!(true);
    candidates.push(bad);
    let mut bad = good.clone();
    bad.manifest.data["paths"]["/items"]["methods"]["GET"]["current"] = json!(false);
    candidates.push(bad);
    for candidate in candidates {
        assert!(build(&candidate).is_err());
    }
}

#[tokio::test]
async fn parameter_denial_is_deferred_until_preflight() {
    let protocol = build(&input(plan("GET", "/items/{id}", "get"))).unwrap();
    let classified = classify(
        protocol.as_ref(),
        &Method::GET,
        "/items/a?undeclared=SECRET",
        &HeaderMap::new(),
    )
    .unwrap();
    let error = classified
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        error.message,
        "gateway request has an undeclared query parameter"
    );
    assert!(!format!("{error:?}").contains("SECRET"));
}

#[tokio::test]
async fn opaque_upload_replays_inspected_prefix_and_drops_identity_headers() {
    let mut operation = plan("POST", "/items/{id}", "write");
    operation["requestBody"] = json!({"required":true,"mediaTypes":["application/octet-stream"]});
    let protocol = build(&input(operation)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("authorization", HeaderValue::from_static("Bearer SECRET"));
    headers.insert("cookie", HeaderValue::from_static("SECRET"));
    headers.insert("x-api-key", HeaderValue::from_static("SECRET"));
    headers.insert("accept-encoding", HeaderValue::from_static("gzip"));
    let classified = classify(protocol.as_ref(), &Method::POST, "/items/SECRET", &headers).unwrap();
    let frames = vec![
        Ok(GatewayBodyFrame::Data(Bytes::from_static(b"\x00prefix"))),
        Ok(GatewayBodyFrame::Data(Bytes::from_static(b"\xffsuffix"))),
    ];
    let forwarded = classified
        .into_request()
        .preflight(test_support::synthetic_gateway_body(frames, 1024))
        .await
        .unwrap();
    assert_eq!(forwarded.relative_target, "/items/SECRET");
    assert_eq!(forwarded.headers.len(), 2);
    assert_eq!(forwarded.headers["accept-encoding"], "identity");
    assert_eq!(
        forwarded.headers["content-type"],
        "application/octet-stream"
    );
    assert!(
        !forwarded
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("SECRET")
    );
    assert_eq!(forwarded.audit_target.as_deref(), Some("/items/{id}"));
    let frames: Vec<_> = test_support::replay_gateway_body(forwarded.body)
        .collect()
        .await;
    let mut bytes = Vec::new();
    for frame in frames {
        if let GatewayBodyFrame::Data(data) = frame.unwrap() {
            bytes.extend(data);
        }
    }
    assert_eq!(bytes, b"\x00prefix\xffsuffix");
}

#[tokio::test]
async fn body_presence_media_and_trailers_are_checked_before_forwarding() {
    let mut operation = plan("POST", "/items", "write");
    operation["requestBody"] = json!({"required":true,"mediaTypes":["application/json"]});
    let protocol = build(&input(operation)).unwrap();
    for (content_type, payload) in [
        (Some("application/json"), &b""[..]),
        (None, &b"{}"[..]),
        (Some("text/plain"), &b"{}"[..]),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert("content-type", HeaderValue::from_static(content_type));
        }
        let classified = classify(protocol.as_ref(), &Method::POST, "/items", &headers).unwrap();
        assert_eq!(
            classified
                .into_request()
                .preflight(body(payload))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::GatewayRequestBodyDenied
        );
    }
    let get = build(&input(plan("GET", "/items", "list"))).unwrap();
    for frames in [
        vec![Ok(GatewayBodyFrame::Trailers)],
        vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(
            b"unexpected",
        )))],
    ] {
        let classified = classify(get.as_ref(), &Method::GET, "/items", &HeaderMap::new()).unwrap();
        assert_eq!(
            classified
                .into_request()
                .preflight(test_support::synthetic_gateway_body(frames, 1024))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::GatewayRequestBodyDenied
        );
    }
}

#[tokio::test]
async fn query_arrays_are_encoded_and_audit_contains_names_only() {
    let mut operation = plan("GET", "/items", "list");
    operation["parameters"] = json!([{"name":"tag","location":"query","required":false,"style":"form","explode":true,"schema":{"type":"array","maxItems":3,"items":{"type":"string"}}}]);
    let protocol = build(&input(operation)).unwrap();
    let classified = classify(
        protocol.as_ref(),
        &Method::GET,
        "/items?tag=SECRET%26next%3Devil&tag=second",
        &HeaderMap::new(),
    )
    .unwrap();
    let plan = classified
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap();
    assert_eq!(
        plan.relative_target,
        "/items?tag=SECRET%26next%3Devil&tag=second"
    );
    assert_eq!(
        plan.audit.as_ref().unwrap()["parametersPresent"],
        json!(["tag"])
    );
    assert!(!plan.audit.unwrap().to_string().contains("SECRET"));
}

#[tokio::test]
async fn response_validator_uses_exact_class_default_and_never_returns_reserved_headers() {
    let mut operation = plan("GET", "/items", "list");
    operation["responses"] = json!({
        "200":{"headers":[{"name":"X-Api-Version","schema":{"type":"integer","minimum":1}}],"contentTypes":[]},
        "2XX":{"headers":[{"name":"X-Class","schema":{"type":"string"}}],"contentTypes":[]},
        "default":{"headers":[{"name":"X-Default","schema":{"type":"string"}}],"contentTypes":[]},
    });
    let protocol = build(&input(operation)).unwrap();
    let forwarded = classify(protocol.as_ref(), &Method::GET, "/items", &HeaderMap::new())
        .unwrap()
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap();
    assert!(forwarded.response.translate_unauthorized);
    assert!(forwarded.response.reject_redirects);
    assert!(forwarded.response.preserve_content_length);
    assert!(matches!(
        forwarded.replay,
        agent_access_provider::GatewayReplayProfile::ConfirmedUnprocessed
    ));
    let validator = forwarded.response.validator.as_ref().unwrap();
    let mut upstream = HeaderMap::new();
    for (name, value) in [
        ("x-api-version", "2"),
        ("x-class", "class"),
        ("x-default", "default"),
        ("content-type", "application/json"),
        ("set-cookie", "SECRET"),
        ("www-authenticate", "SECRET"),
        ("content-length", "42"),
        ("location", "https://private.example.com"),
        ("x-unlisted", "SECRET"),
    ] {
        upstream.insert(name, HeaderValue::from_static(value));
    }
    for (status, selected) in [(200, "x-api-version"), (201, "x-class"), (404, "x-default")] {
        let headers = validator.validate(status, &upstream).unwrap();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("content-type"));
        assert!(headers.contains_key(selected));
    }
    upstream.insert("x-api-version", HeaderValue::from_static("SECRET"));
    let headers = validator.validate(200, &upstream).unwrap();
    assert_eq!(headers.len(), 1);
    assert!(headers.contains_key("content-type"));
    // Invalid optional values are omitted. Ambiguous repeated fields remain errors.
    upstream.append("x-api-version", HeaderValue::from_static("2"));
    let error = validator.validate(200, &upstream).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!error.message.contains("SECRET"));
    assert!(
        registration()
            .check_failure(agent_access_provider::GatewayHookPhase::Response, &error)
            .is_ok()
    );
    // A declaration for an unselected status cannot restrict an unrelated response.
    assert!(validator.validate(201, &upstream).is_ok());
}

#[tokio::test]
async fn restored_response_media_ranges_do_not_filter_upstream_content_type() {
    for media in [
        json!(["*/*"]),
        json!(["application/*", "application/octet-stream", "*/*"]),
        json!(["text/*"]),
    ] {
        let mut operation = plan("GET", "/items", "list");
        operation["responses"]["200"]["contentTypes"] = media;
        let serialized = serde_json::to_vec(&operation).unwrap();
        let restored = serde_json::from_slice(&serialized).unwrap();
        let protocol = build(&input(restored)).unwrap();
        let forwarded = classify(protocol.as_ref(), &Method::GET, "/items", &HeaderMap::new())
            .unwrap()
            .into_request()
            .preflight(body(b""))
            .await
            .unwrap();
        let mut upstream = HeaderMap::new();
        upstream.insert(
            "content-type",
            HeaderValue::from_static("application/x-gzip"),
        );
        let selected = forwarded
            .response
            .validator
            .as_ref()
            .unwrap()
            .validate(200, &upstream)
            .unwrap();
        assert_eq!(selected["content-type"], "application/x-gzip");
    }
}

#[tokio::test]
async fn response_validator_preserves_encoding_and_leaves_retry_after_to_host() {
    let mut operation = plan("GET", "/items", "list");
    operation["responses"] = json!({
        "429":{"headers":[{"name":"Retry-After","schema":{"type":"string"}}],"contentTypes":[]}
    });
    let protocol = build(&input(operation)).unwrap();
    let forwarded = classify(protocol.as_ref(), &Method::GET, "/items", &HeaderMap::new())
        .unwrap()
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap();
    let validator = forwarded.response.validator.as_ref().unwrap();
    assert!(forwarded.response.bounded_retry_after);
    assert!(
        !forwarded
            .response
            .headers
            .iter()
            .any(|name| name == "retry-after")
    );
    assert!(
        forwarded
            .response
            .status_headers
            .iter()
            .all(|status| !status.headers.iter().any(|name| name == "retry-after"))
    );
    let mut upstream = HeaderMap::new();
    upstream.insert("content-encoding", HeaderValue::from_static("gzip"));
    upstream.insert("retry-after", HeaderValue::from_static("15"));
    let headers = validator.validate(429, &upstream).unwrap();
    assert_eq!(headers["content-encoding"], "gzip");
    assert!(!headers.contains_key("retry-after"));
    upstream.append("retry-after", HeaderValue::from_static("30"));
    for status in [200, 429, 503] {
        let headers = validator.validate(status, &upstream).unwrap();
        assert_eq!(headers.len(), 1);
        assert!(!headers.contains_key("retry-after"));
    }
    upstream.insert("retry-after", HeaderValue::from_static("SECRET"));
    let headers = validator.validate(429, &upstream).unwrap();
    assert_eq!(headers.len(), 1);
    assert!(headers.contains_key("content-encoding"));
    upstream.append("content-encoding", HeaderValue::from_static("br"));
    assert_eq!(
        validator
            .validate(429, &upstream)
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}

#[tokio::test]
async fn optional_nontext_metadata_does_not_discard_success_or_error_response() {
    let mut operation = plan("GET", "/items", "list");
    operation["responses"] = json!({
        "default":{"headers":[{"name":"X-Api-Version","schema":{"type":"string"}}],"contentTypes":[]}
    });
    let protocol = build(&input(operation)).unwrap();
    let forwarded = classify(protocol.as_ref(), &Method::GET, "/items", &HeaderMap::new())
        .unwrap()
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap();
    let mut upstream = HeaderMap::new();
    upstream.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    upstream.insert(
        "content-disposition",
        HeaderValue::from_bytes(b"attachment; filename=\"r\xe9sum\xe9.pdf\"").unwrap(),
    );
    upstream.insert("x-api-version", HeaderValue::from_bytes(b"v\xff").unwrap());
    let validator = forwarded.response.validator.as_ref().unwrap();
    for status in [200, 404, 500] {
        let selected = validator.validate(status, &upstream).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected["content-type"], "application/octet-stream");
    }
}

#[tokio::test]
async fn compiled_routes_preserve_literal_custom_verbs_and_encode_parameter_values() {
    let protocol = build(&input(plan("POST", "/jobs/{id}/action:run", "run"))).unwrap();
    let target = "/jobs/a@b+c=d/action:run";
    let forwarded = classify(protocol.as_ref(), &Method::POST, target, &HeaderMap::new())
        .unwrap()
        .into_request()
        .preflight(body(b""))
        .await
        .unwrap();
    assert_eq!(forwarded.relative_target, "/jobs/a%40b%2Bc%3Dd/action:run");
}

#[test]
fn path_parameters_cannot_bypass_literal_guards_with_semicolon_suffixes() {
    let mut candidate = input(plan("GET", "/items/{id}", "get"));
    candidate.manifest.data["paths"]["/items/admin"] = json!({"methods": {
        "GET":{"source":{"operationId":"admin"},"current":true,"supported":true}
    }});
    let protocol = build(&candidate).unwrap();
    for path in [
        "/items/admin;x",
        "/items/admin%3Bx",
        "/items/..;",
        "/items/%2E%2E%3B",
        "/other/foo;x",
        "/absent/foo%3Bx",
        "/unknown/..;/comments",
    ] {
        let error = classify(protocol.as_ref(), &Method::GET, path, &HeaderMap::new()).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.message, "gateway request target is invalid");
    }
}

#[tokio::test]
async fn raw_json_is_forwarded_without_claiming_body_schema_validation() {
    let mut operation = plan("POST", "/items", "write");
    operation["requestBody"] = json!({"required":true,"mediaTypes":["application/json"]});
    let protocol = build(&input(operation)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    let forwarded = classify(protocol.as_ref(), &Method::POST, "/items", &headers)
        .unwrap()
        .into_request()
        .preflight(body(b"opaque non-JSON bytes"))
        .await
        .unwrap();
    let frames: Vec<_> = test_support::replay_gateway_body(forwarded.body)
        .collect()
        .await;
    assert!(
        matches!(&frames[..], [Ok(GatewayBodyFrame::Data(bytes))] if bytes.as_ref() == b"opaque non-JSON bytes")
    );
}

#[tokio::test]
async fn body_presence_inspection_has_an_empty_frame_budget() {
    let protocol = build(&input(plan("GET", "/items", "list"))).unwrap();
    let classified =
        classify(protocol.as_ref(), &Method::GET, "/items", &HeaderMap::new()).unwrap();
    let frames = (0..33)
        .map(|_| Ok(GatewayBodyFrame::Data(Bytes::new())))
        .collect();
    let error = classified
        .into_request()
        .preflight(test_support::synthetic_gateway_body(frames, 1))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);
    assert_eq!(error.message, "gateway request body could not be read");
}

#[test]
fn corrupt_retained_plan_does_not_publish_a_partial_service() {
    let mut candidate = input(plan("GET", "/items", "list"));
    candidate.actions.push(GatewayManagedAction::new(
        "retained.read",
        1,
        "c".repeat(64),
        false,
        GatewayVersionedData::new(1, json!({})),
    ));
    assert!(build(&candidate).is_err());
}
