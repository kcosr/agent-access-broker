//! Native HTTP acceptance through the real import lifecycle and bound listeners.
//! The upstream is synthetic; Broker management, routing, grants, credentials,
//! streaming and audit all use production paths.
use super::*;
use axum::http::header::{CONTENT_LENGTH, HOST};
use axum::http::{HeaderMap, HeaderValue};

mod accounting;
mod credentials;
mod failures;
mod fixture;
mod guide;
mod lifecycle;
mod privacy;
mod races;
mod transfers;
mod trusted_identity;

use fixture::*;

#[tokio::test]
async fn openapi_gateway_uploaded_and_remote_documents_drive_native_http_without_invoke_tools() {
    for (dialect, source) in [
        (Dialect::OpenApi31, DefinitionSource::Upload),
        (Dialect::Swagger2, DefinitionSource::Url),
    ] {
        let upstream = Upstream::start().await;
        let document = document(dialect, UpstreamAuth::Anonymous, &upstream.endpoint());
        upstream.document(document.clone());
        let fixture = Fixture::start(&upstream, |_| {}).await;
        let preview = fixture
            .create_and_discover(source, UpstreamAuth::Anonymous, &document)
            .await;
        fixture
            .accept(&preview, &["read_item", "update_item"])
            .await;
        fixture.enable().await;

        let before_grant = fixture
            .gateway(Method::GET, "/items/alpha?count=2", "before-grant")
            .send()
            .await
            .unwrap();
        assert_eq!(before_grant.status(), StatusCode::FORBIDDEN);
        assert!(upstream.api_requests().is_empty());
        fixture.grant(&["read_item", "update_item"]).await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha?count=2", "native-read")
            .header("X-Revision", "3")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["path"], "/api/items/alpha");
        assert_eq!(body["query"], "count=2");
        assert_eq!(upstream.api_requests().last().unwrap().method, Method::GET);
        assert_eq!(
            upstream
                .api_requests()
                .last()
                .unwrap()
                .headers
                .get("x-revision")
                .unwrap(),
            "3"
        );
        assert!(
            !upstream
                .api_requests()
                .last()
                .unwrap()
                .headers
                .contains_key("authorization")
        );

        // Body schemas are documentation only: bytes remain exactly as supplied.
        let payload = b"{ \"field\": [ 1, 2 ], \"opaque\": true }\n";
        let response = fixture
            .gateway(Method::POST, "/items/alpha", "native-write")
            .header(CONTENT_TYPE, "application/json")
            .body(payload.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().last().unwrap().body, payload);
        assert_eq!(upstream.writes(), 1);

        let before = upstream.api_requests().len();
        for (method, path) in [
            (Method::GET, "/items/private"),
            (Method::POST, "/items/private"),
            (Method::GET, "/missing"),
            (Method::DELETE, "/items/alpha"),
        ] {
            let response = fixture
                .gateway(method, path, "unaccepted-route")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response.headers().get("allow").is_none());
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                "gateway_rule_not_found"
            );
            assert!(!response.text().await.unwrap().contains("private_item"));
        }
        assert_eq!(upstream.api_requests().len(), before);

        let response = fixture
            .public(Method::GET, "/v1/services")
            .bearer_auth(&fixture.agent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let services: Value = response.json().await.unwrap();
        assert!(
            services
                .as_array()
                .unwrap()
                .iter()
                .all(|service| service["service"] != SERVICE)
        );
        let response = fixture
            .public(Method::GET, "/v1/spec/catalog")
            .bearer_auth(&fixture.agent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let catalog: Value = response.json().await.unwrap();
        assert!(
            catalog["services"]
                .as_array()
                .unwrap()
                .iter()
                .all(|service| service["service"] != SERVICE)
        );
        let response = fixture
            .public(Method::POST, "/v1/invoke/inventory/read_item")
            .bearer_auth(&fixture.agent)
            .json(&json!({"inputs":{}}))
            .send()
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        assert_eq!(upstream.api_requests().len(), before);
        fixture.terminal("native-read").await;
        fixture.terminal("native-write").await;
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_parameter_body_identity_and_read_only_denials_never_dispatch() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item", "update_item", "upload_bytes"],
    )
    .await;
    for (method, path, body, content_type) in [
        (Method::GET, "/items/alpha?unknown=1", None, None),
        (Method::GET, "/items/alpha?count=0", None, None),
        (Method::GET, "/items/alpha?count=1&count=2", None, None),
        (
            Method::GET,
            "/items/alpha",
            Some("unexpected"),
            Some("application/json"),
        ),
        (Method::POST, "/items/alpha", None, None),
        (
            Method::POST,
            "/items/alpha",
            Some("text"),
            Some("text/plain"),
        ),
    ] {
        let mut request = fixture.gateway(method, path, "invalid-profile");
        if let Some(body) = body {
            request = request.body(body);
        }
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        fixture
            .gateway(Method::GET, "/items/alpha", "invalid-parameter")
            .header("X-Revision", "not-an-integer")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let read_only = fixture.issue_agent(true);
    let response = fixture
        .gateway_as(&read_only, Method::POST, "/items/alpha", "read-only-write")
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .gateway_as(
            "invalid-broker-token",
            Method::GET,
            "/items/alpha",
            "invalid-token",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(upstream.api_requests().is_empty());
    fixture.stop().await;
}
