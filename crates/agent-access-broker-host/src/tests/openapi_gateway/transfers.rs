use super::*;

#[tokio::test]
async fn openapi_gateway_basic_broker_auth_is_consumed_before_anonymous_upstream_dispatch() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let response = fixture
        .client
        .get(format!(
            "http://{}/items/alpha",
            fixture.broker.running().gateway_addr().unwrap()
        ))
        .header(HOST, GATEWAY_HOST)
        .header(REQUEST_ID_HEADER, "basic-ingress")
        .basic_auth("agent-access", Some(&fixture.agent))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    assert!(
        !upstream.api_requests()[0]
            .headers
            .contains_key(AUTHORIZATION)
    );
    assert_eq!(fixture.terminal("basic-ingress").await["decision"], "allow");
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_static_credentials_replace_broker_auth_and_drop_private_headers() {
    for auth in [
        UpstreamAuth::Bearer,
        UpstreamAuth::Basic,
        UpstreamAuth::Header,
    ] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready(&upstream, auth, &["read_item"]).await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "static-auth")
            .header("Cookie", "private-client-cookie")
            .header("X-Undeclared-Client", "must-not-pass")
            .header("X-Inventory-Key", "caller-controlled-spoof")
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("set-cookie").is_none());
        assert!(response.headers().get("x-backend-private").is_none());
        response.bytes().await.unwrap();
        let requests = upstream.api_requests();
        assert_eq!(requests.len(), 1);
        let headers = &requests[0].headers;
        let expected = match auth {
            UpstreamAuth::Bearer => format!("Bearer {UPSTREAM_TOKEN}"),
            UpstreamAuth::Basic => format!(
                "Basic {}",
                BASE64.encode(format!("synthetic-upstream-user:{UPSTREAM_TOKEN}"))
            ),
            UpstreamAuth::Header => UPSTREAM_TOKEN.into(),
            UpstreamAuth::Anonymous => unreachable!(),
        };
        let carrier = if auth == UpstreamAuth::Header {
            "x-inventory-key"
        } else {
            "authorization"
        };
        assert_eq!(headers[carrier], expected);
        assert!(!headers.values().any(|value| {
            value
                .as_bytes()
                .windows(fixture.agent.len())
                .any(|slice| slice == fixture.agent.as_bytes())
        }));
        for absent in [
            "cookie",
            "x-undeclared-client",
            "x-aw-identity-token-sha256",
            "x-aw-caller-credential",
        ] {
            assert!(!headers.contains_key(absent), "{absent}");
        }
        assert_eq!(headers["accept-encoding"], "identity");
        if auth == UpstreamAuth::Header {
            assert!(!headers.contains_key("authorization"));
        }
        let terminal = fixture.terminal("static-auth").await;
        assert_eq!(terminal["decision"], "allow");
        assert!(!terminal.to_string().contains(UPSTREAM_TOKEN));
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_binary_range_head_and_bodyless_replies_complete_once() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(
        &upstream,
        UpstreamAuth::Anonymous,
        &[
            "download_blob",
            "head_blob",
            "empty_result",
            "conditional",
            "upload_bytes",
        ],
    )
    .await;
    let response = fixture
        .gateway(Method::GET, "/blob", "binary-download")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/octet-stream");
    assert_eq!(response.headers()[CONTENT_LENGTH], BLOB.len().to_string());
    assert_eq!(response.headers()["x-checksum"], "synthetic-checksum");
    assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
    assert_eq!(response.bytes().await.unwrap().as_ref(), BLOB);
    let audit = fixture.terminal("binary-download").await;
    assert_eq!(audit["providerAudit"]["gateway"]["phase"], "completed");
    assert_eq!(
        audit["providerAudit"]["gateway"]["responseBytes"],
        BLOB.len()
    );

    let mut response = fixture
        .gateway(Method::GET, "/blob", "length-framing-completion")
        .send()
        .await
        .unwrap();
    let mut bytes = Vec::new();
    while bytes.len() < BLOB.len() {
        bytes.extend_from_slice(&response.chunk().await.unwrap().unwrap());
    }
    assert_eq!(bytes, BLOB);
    // Stop exactly at Content-Length; completion must not depend on an extra poll.
    assert_eq!(
        fixture.terminal("length-framing-completion").await["providerAudit"]["gateway"]["phase"],
        "completed"
    );
    drop(response);

    let response = fixture
        .gateway(Method::GET, "/blob", "binary-range")
        .header("Range", "bytes=2-5")
        .header("If-Range", "\"synthetic-v1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers()["content-range"],
        format!("bytes 2-5/{}", BLOB.len())
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), &BLOB[2..6]);
    assert_eq!(
        fixture.terminal("binary-range").await["providerAudit"]["gateway"]["responseBytes"],
        4
    );

    for (method, path, id, status) in [
        (Method::HEAD, "/blob", "head-completion", StatusCode::OK),
        (
            Method::GET,
            "/empty",
            "empty-completion",
            StatusCode::NO_CONTENT,
        ),
        (
            Method::GET,
            "/conditional",
            "conditional-completion",
            StatusCode::NOT_MODIFIED,
        ),
    ] {
        let response = fixture
            .gateway(method, path, id)
            .header("If-None-Match", "\"synthetic-v1\"")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if id == "head-completion" {
            assert_eq!(response.headers()[CONTENT_LENGTH], BLOB.len().to_string());
        }
        // A framing-complete body must finalize without requiring a consumer poll.
        let terminal = fixture.terminal(id).await;
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "completed");
        assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 0);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let response = fixture
        .gateway(Method::POST, "/upload", "binary-upload")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(BLOB.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().last().unwrap().body, BLOB);
    assert_eq!(upstream.writes(), 1);
    fixture.terminal("binary-upload").await;
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_unknown_length_download_streams_before_upstream_completion() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["stream_blob"]).await;
    let mut response = fixture
        .gateway(Method::GET, "/stream", "progressive-download")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(CONTENT_LENGTH).is_none());
    let first = tokio::time::timeout(Duration::from_secs(2), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&first[..], b"first-chunk");
    upstream.release_stream();
    let last = response.bytes().await.unwrap();
    assert_eq!(&last[..], b"last-chunk");
    let terminal = fixture.terminal("progressive-download").await;
    assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 21);
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "completed");
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_preserves_upstream_errors_but_translates_auth_and_rejects_redirects() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["error_status"]).await;
    for status in [403, 404, 429, 500, 503] {
        let id = format!("upstream-{status}");
        let response = fixture
            .gateway(Method::GET, &format!("/errors/{status}"), &id)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert!(response.headers().get("www-authenticate").is_none());
        assert!(response.headers().get("set-cookie").is_none());
        if status == 429 {
            assert_eq!(response.headers()["retry-after"], "7");
        }
        assert_eq!(
            response.text().await.unwrap(),
            format!("synthetic backend {status}\n")
        );
        let terminal = fixture.terminal(&id).await;
        assert_eq!(terminal["upstreamStatus"], status);
        if status == 429 {
            assert_eq!(terminal["reasonCode"], "upstream_rate_limited");
        }
    }
    let response = fixture
        .gateway(Method::GET, "/errors/401", "upstream-auth")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FAILED_DEPENDENCY);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "upstream_unauthorized"
    );
    assert!(response.headers().get("www-authenticate").is_none());
    assert!(
        !response
            .text()
            .await
            .unwrap()
            .contains("synthetic backend 401")
    );
    let response = fixture
        .gateway(Method::GET, "/errors/302", "upstream-redirect")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(response.headers().get("location").is_none());
    assert!(
        !response
            .text()
            .await
            .unwrap()
            .contains("bypass.example.test")
    );
    assert_eq!(
        upstream.api_requests().len(),
        7,
        "no automatic status retry or redirect follow"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_preserves_encoded_response_bytes_and_raw_form_uploads() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(
        &upstream,
        UpstreamAuth::Anonymous,
        &["encoded_blob", "upload_form"],
    )
    .await;
    let response = fixture
        .gateway(Method::GET, "/encoded", "encoded-response")
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_ENCODING], "gzip");
    assert_eq!(
        response.headers()[CONTENT_LENGTH],
        ENCODED_BLOB.len().to_string()
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), ENCODED_BLOB);
    let terminal = fixture.terminal("encoded-response").await;
    assert_eq!(
        terminal["providerAudit"]["gateway"]["responseBytes"],
        ENCODED_BLOB.len()
    );
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "completed");
    assert_eq!(
        upstream.api_requests()[0].headers["accept-encoding"],
        "identity"
    );

    let form = b"name=a%2Bb&name=c+d&opaque=%00%ff&empty=&extra=%252F";
    let response = fixture
        .gateway(Method::POST, "/form", "raw-form")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let seen = upstream.api_requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].body, form);
    assert_eq!(
        seen[1].headers[CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(upstream.writes(), 1);
    assert_eq!(fixture.terminal("raw-form").await["decision"], "allow");
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_authenticated_upstream_401_is_translated_for_each_static_credential_carrier()
 {
    for auth in [
        UpstreamAuth::Bearer,
        UpstreamAuth::Basic,
        UpstreamAuth::Header,
    ] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready(&upstream, auth, &["error_status"]).await;
        let response = fixture
            .gateway(Method::GET, "/errors/401", "static-upstream-401")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FAILED_DEPENDENCY);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "upstream_unauthorized"
        );
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
        assert!(response.headers().get("set-cookie").is_none());
        let body = response.text().await.unwrap();
        for secret in [
            "synthetic backend 401",
            "private-upstream",
            UPSTREAM_TOKEN,
            fixture.agent.as_str(),
        ] {
            assert!(!body.contains(secret));
        }
        let seen = upstream.api_requests();
        assert_eq!(seen.len(), 1, "401 must not cause replay");
        let carrier = if auth == UpstreamAuth::Header {
            "x-inventory-key"
        } else {
            "authorization"
        };
        assert!(seen[0].headers.contains_key(carrier));
        let terminal = fixture.terminal("static-upstream-401").await;
        assert_eq!(terminal["upstreamStatus"], 401);
        assert_eq!(terminal["reasonCode"], "upstream_unauthorized");
        assert_eq!(terminal["decision"], "error");
        fixture.stop().await;
    }
}
