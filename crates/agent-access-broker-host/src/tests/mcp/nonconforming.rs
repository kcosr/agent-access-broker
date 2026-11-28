use super::*;

#[tokio::test]
async fn http_media_types_match_exactly_without_case_sensitivity() {
    let fixture = Fixture::new(|_| {}).await;
    let session = fixture.initialize_version(TOKEN_A, VERSION).await;
    for (header, value, expected) in [
        (
            CONTENT_TYPE,
            "Application/JSON; charset=UTF-8",
            StatusCode::OK,
        ),
        (
            CONTENT_TYPE,
            "application/json-rpc",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            ACCEPT,
            "APPLICATION/JSON, TEXT/EVENT-STREAM",
            StatusCode::OK,
        ),
        (
            ACCEPT,
            "text/application/json, text/event-stream",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            ACCEPT,
            "application/json, text/event-stream-extra",
            StatusCode::NOT_ACCEPTABLE,
        ),
    ] {
        let mut message = request(
            Method::POST,
            Some(TOKEN_A),
            Some(&session),
            Some(json!({"jsonrpc":"2.0","id":900,"method":"ping"})),
        );
        message
            .headers_mut()
            .insert(header, HeaderValue::from_static(value));
        let response = fixture.send(message).await;
        assert_eq!(response.status(), expected, "{value}");
        if expected == StatusCode::OK {
            assert_eq!(rpc_body(response).await["result"], json!({}));
        }
    }
}

#[tokio::test]
async fn http_method_with_result_or_error_is_rejected_even_when_null() {
    let fixture = Fixture::new(|_| {}).await;
    let session = fixture.initialize_version(TOKEN_A, VERSION).await;
    for field in ["result", "error"] {
        for value in [Value::Null, json!({"secret":"must-not-be-echoed"})] {
            let mut message = json!({"jsonrpc":"2.0","id":900,"method":"ping"});
            message[field] = value;
            let response = fixture
                .send(request(
                    Method::POST,
                    Some(TOKEN_A),
                    Some(&session),
                    Some(message),
                ))
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = rpc_body(response).await;
            assert_eq!(body["id"], 900);
            assert_eq!(body["error"]["code"], -32602);
            assert_eq!(body["error"]["message"], "Invalid MCP method parameters");
            assert!(!body.to_string().contains("must-not-be-echoed"));
        }
    }
}
