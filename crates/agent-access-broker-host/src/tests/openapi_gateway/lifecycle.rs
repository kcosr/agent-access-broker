use super::*;

#[tokio::test]
async fn openapi_gateway_missing_linked_protocol_preserves_import_and_reserved_host_on_restart() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let before = fixture.detail().await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "before-module-removal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let fixture = fixture.restart_without_gateway().await;
    let after = fixture.detail().await;
    assert_eq!(after["catalogRevision"], before["catalogRevision"]);
    assert_eq!(after["service"]["actions"], before["service"]["actions"]);
    assert_eq!(after["service"]["status"], "enabled");
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "missing-linked-module")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_new_unaccepted_literal_narrows_template_without_quarantining_it() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let mut original = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    original["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/private");
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &original)
        .await;
    fixture.accept(&preview, &["read_item"]).await;
    fixture.enable().await;
    fixture.grant(&["read_item"]).await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "template-before-literal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let expanded = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    let preview = fixture.upload(&expanded).await;
    assert!(
        preview["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["definition"]["action"] == "read_item"
                && action["status"] == "enabled")
    );
    for (label, document) in [("new-literal", expanded), ("removed-literal", original)] {
        if label == "removed-literal" {
            fixture.upload(&document).await;
        }
        let before = upstream.api_requests().len();
        let response = fixture
            .gateway(Method::GET, "/items/private", label)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found"
        );
        assert_eq!(upstream.api_requests().len(), before);
        let response = fixture
            .gateway(Method::GET, "/items/ordinary", &format!("{label}-template"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), before + 1);
    }
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_operator_binding_reserves_a_host_before_an_import_is_created() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "reserved-empty-binding")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert!(upstream.api_requests().is_empty());
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_refresh_keeps_unaccepted_removed_and_retired_routes_as_denial_guards() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item", "private_item"],
    )
    .await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "literal-enabled")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let mut changed = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    changed["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/private");
    changed["paths"]["/items/new"] =
        json!({"get":{"operationId":"new_item","responses":{"200":{"description":"New"}}}});
    let preview = fixture.upload(&changed).await;
    assert!(
        preview["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["definition"]["action"] == "private_item"
                && action["status"] == "quarantined")
    );
    fixture.accept(&preview, &["read_item"]).await;
    let before = upstream.api_requests().len();
    for path in ["/items/private", "/items/new"] {
        let response = fixture
            .gateway(Method::GET, path, "retained-guard")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found"
        );
    }
    assert_eq!(upstream.api_requests().len(), before);
    let response = fixture
        .gateway(Method::GET, "/items/ordinary", "template-still-enabled")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();

    let mut retired = versions(&fixture.detail().await);
    retired["status"] = json!("retired");
    retired["confirm"] = json!(true);
    fixture
        .admin_ok(
            Method::POST,
            "/v1/admin/imports/inventory/actions/private_item/status",
            Some(retired),
        )
        .await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "retired-literal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(upstream.api_requests().len(), before + 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_changed_operation_is_quarantined_until_explicit_reacceptance() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let mut changed = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    changed["paths"]["/items/{id}"]["get"]["parameters"].as_array_mut().unwrap().push(
        json!({"name":"revision","in":"query","required":true,"schema":{"type":"integer","minimum":1}}));
    let preview = fixture.upload(&changed).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha?revision=1", "quarantined")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(upstream.api_requests().is_empty());
    fixture.accept(&preview, &["read_item"]).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "missing-new-required")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = fixture
        .gateway(Method::GET, "/items/alpha?revision=1", "reaccepted")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}
