use super::*;

#[tokio::test]
async fn openapi_gateway_operator_guide_document_runs_through_upload_acceptance_and_native_http() {
    // Read the shipped guide rather than maintaining a second example that
    // could pass after the documented document has stopped working.
    let guide = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/http-gateway-setup.md"),
    )
    .unwrap();
    let (_, marked) = guide
        .split_once("<!-- gateway-setup-document:start -->")
        .unwrap();
    let (marked, _) = marked
        .split_once("<!-- gateway-setup-document:end -->")
        .unwrap();
    let (_, fenced) = marked.split_once("```json\n").unwrap();
    let (source, _) = fenced.split_once("\n```").unwrap();
    let mut document: Value = serde_json::from_str(source).unwrap();
    assert_eq!(
        document["servers"],
        json!([{"url":"https://inventory.example.com/api"}])
    );
    let upstream = Upstream::start().await;
    // Only the deployment placeholder changes: operation paths, methods,
    // parameters, body schemas, security and headers come from the guide.
    document["servers"][0]["url"] = json!(upstream.endpoint());
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &document)
        .await;
    let accepted = [
        "get_item",
        "update_item",
        "download_artifact",
        "artifact_metadata",
    ];
    fixture.accept(&preview, &accepted).await;
    fixture.enable().await;
    fixture.grant(&accepted).await;

    let response = fixture
        .gateway(Method::GET, "/items/widget?view=summary", "guide-get")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["path"], "/api/items/widget");
    assert_eq!(body["query"], "view=summary");
    let response = fixture
        .gateway(Method::GET, "/items/admin", "guide-guard")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert_eq!(upstream.api_requests().len(), 1);

    // The guide explicitly states that body schemas are documentation: this
    // payload omits the required name and must still pass through unchanged.
    let raw = br#"{ "unexpected":true, "number":1e2 }"#;
    let response = fixture
        .gateway(Method::PUT, "/items/widget", "guide-put")
        .header(CONTENT_TYPE, "application/json")
        .body(raw.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.bytes().await.unwrap().is_empty());
    assert_eq!(upstream.api_requests()[1].body, raw);

    for (method, id) in [
        (Method::GET, "guide-download"),
        (Method::HEAD, "guide-head"),
    ] {
        let response = fixture
            .gateway(method.clone(), "/artifacts/build-123", id)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_LENGTH], BLOB.len().to_string());
        assert_eq!(response.headers()["x-api-version"], "1");
        let received = response.bytes().await.unwrap();
        assert_eq!(
            received.as_ref(),
            if method == Method::HEAD { b"" } else { BLOB }
        );
        assert_eq!(
            fixture.terminal(id).await["providerAudit"]["gateway"]["phase"],
            "completed"
        );
    }
    assert_eq!(upstream.api_requests().len(), 4);
    fixture.stop().await;
}
