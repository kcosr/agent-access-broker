use super::*;

#[tokio::test]
async fn openapi_gateway_classifier_audit_records_only_bounded_method_and_safe_identity() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let mut public_denial = None;
    for (method, path, id) in [
        (
            Method::GET,
            "/missing-private-path?secret=private-query",
            "classify-missing",
        ),
        (Method::GET, "/items/private", "classify-unaccepted"),
        (Method::POST, "/items/private", "classify-missing-method"),
    ] {
        let response = fixture
            .gateway(method.clone(), path, id)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found"
        );
        assert!(response.headers().get("allow").is_none());
        let body = response.text().await.unwrap();
        if let Some(expected) = &public_denial {
            assert_eq!(&body, expected);
        } else {
            public_denial = Some(body);
        }
        let audit = fixture.terminal(id).await;
        assert_eq!(audit["action"], "gateway.classify");
        assert_eq!(audit["providerAudit"]["gateway"]["method"], method.as_str());
        let encoded = audit.to_string();
        for forbidden in [
            path,
            "missing-private-path",
            "private-query",
            "private_item",
            "/items/private",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "classifier audit exposed {forbidden}"
            );
        }
    }
    assert!(upstream.api_requests().is_empty());
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_request_value_sentinels_never_reach_persisted_audit_or_local_errors() {
    const PATH_VALUE: &str = "path-secret-sentinel";
    const QUERY_VALUE: &str = "query-secret-sentinel";
    const HEADER_VALUE: &str = "header-secret-sentinel";
    const BODY_VALUE: &str = "body-secret-sentinel";
    const DESCRIPTION: &str = "source-description-secret-sentinel";
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let mut source = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    let operation = &mut source["paths"]["/items/{id}"]["post"];
    operation["description"] = json!(DESCRIPTION);
    operation["parameters"].as_array_mut().unwrap().extend([
        json!({"name":"label","in":"query","schema":{"type":"string","maxLength":128}}),
        json!({"name":"X-Tag","in":"header","schema":{"type":"string","maxLength":128}}),
    ]);
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &source)
        .await;
    fixture.accept(&preview, &["update_item"]).await;
    fixture.enable().await;
    fixture.grant(&["update_item"]).await;
    let target = format!("/items/{PATH_VALUE}?label={QUERY_VALUE}");
    let response = fixture
        .gateway(Method::POST, &target, "sentinel-success")
        .header("X-Tag", HEADER_VALUE)
        .header(CONTENT_TYPE, "application/json")
        .body(json!({"value":BODY_VALUE}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let audit = fixture.terminal("sentinel-success").await;
    assert_eq!(audit["action"], "update_item");
    let seen = upstream.api_requests();
    assert!(seen[0].path.contains(PATH_VALUE));
    assert!(seen[0].query.contains(QUERY_VALUE));
    assert_eq!(seen[0].headers["x-tag"], HEADER_VALUE);
    assert!(String::from_utf8_lossy(&seen[0].body).contains(BODY_VALUE));
    let response = fixture
        .gateway(
            Method::POST,
            &format!("{target}&unknown={QUERY_VALUE}"),
            "sentinel-error",
        )
        .header("X-Tag", HEADER_VALUE)
        .header(CONTENT_TYPE, "application/json")
        .body(json!({"value":BODY_VALUE}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = response.text().await.unwrap();
    fixture.terminal("sentinel-error").await;

    // Exercise the same gateway router under a scoped trace capture. The
    // socket requests above cover real ingress; an in-process router call
    // carries the capture span into the host's operation owner.
    let captured = install_trace_capture().start();
    let trace_response = captured
        .run(async {
            let response = fixture
                .broker
                .gateway_app()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(&target)
                        .extension(ConnectInfo(
                            "127.0.0.1:43123".parse::<SocketAddr>().unwrap(),
                        ))
                        .header(HOST, GATEWAY_HOST)
                        .header(AUTHORIZATION, format!("Bearer {}", fixture.agent))
                        .header(REQUEST_ID_HEADER, "sentinel-trace")
                        .header("X-Tag", HEADER_VALUE)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(json!({"value":BODY_VALUE}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            status
        })
        .await;
    assert_eq!(trace_response, StatusCode::OK);
    fixture.terminal("sentinel-trace").await;
    let events = captured.take_events();
    assert!(
        events
            .iter()
            .any(|event| event["agentRequestId"] == "sentinel-trace"),
        "{events:?}"
    );
    let trace = serde_json::to_string(&events).unwrap();
    let persisted =
        std::fs::read_to_string(&fixture.seed.config.audit.as_ref().unwrap().path).unwrap();
    for secret in [
        PATH_VALUE,
        QUERY_VALUE,
        HEADER_VALUE,
        BODY_VALUE,
        DESCRIPTION,
    ] {
        assert!(!persisted.contains(secret), "audit exposed {secret}");
        assert!(!error.contains(secret), "local error exposed {secret}");
        assert!(!trace.contains(secret), "trace exposed {secret}");
    }
    for secret in [fixture.agent.as_str(), UPSTREAM_TOKEN] {
        assert!(
            !persisted.contains(secret),
            "audit exposed an authorization secret"
        );
        assert!(
            !trace.contains(secret),
            "trace exposed an authorization secret"
        );
    }
    assert_eq!(upstream.api_requests().len(), 2);
    fixture.stop().await;
}
