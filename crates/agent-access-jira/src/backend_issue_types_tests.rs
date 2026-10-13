use super::*;
use agent_access_provider::test_support::{basic_credential, bearer_credential};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn credential() -> ExecutionCredential {
    basic_credential("service@example.com", "token")
}

fn backend(api: &MockServer, limits: ProviderLimits) -> HttpJiraBackend {
    let config = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "allowed_upstream_hosts": [format!("{}/**", api.uri())]
    }))
    .unwrap();
    HttpJiraBackend::new_with_api_base(
        config,
        limits,
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    )
}

fn request(start_at: u32, max_results: u32) -> JiraIssueTypeListRequest {
    JiraIssueTypeListRequest {
        start_at,
        max_results,
    }
}

fn page() -> Value {
    json!({
        "startAt": 0, "maxResults": 2, "total": 2,
        "issueTypes": [
            {"id": "10001", "name": "Task", "description": "A task", "subtask": false},
            {"id": "10002", "name": "Subtask", "description": "A child task", "subtask": true}
        ]
    })
}

#[tokio::test]
async fn issue_types_uses_selected_auth_and_gateway_and_requests_one_page() {
    let api = MockServer::start().await;
    let mut backend = backend(&api, ProviderLimits::default());
    backend.gateway_clients.as_mut().unwrap().api_base =
        Url::parse(&format!("{}/ex/jira/cloud/rest/api/3/", api.uri())).unwrap();
    let mut response = page();
    response["startAt"] = json!(2);
    response["total"] = json!(5);
    for (base, auth) in [
        ("/rest/api/3", "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg=="),
        ("/ex/jira/cloud/rest/api/3", "Bearer selected-token"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{base}/issue/createmeta/PROJ/issuetypes")))
            .and(query_param("startAt", "2"))
            .and(query_param("maxResults", "2"))
            .and(header("Authorization", auth))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
            .expect(1)
            .mount(&api)
            .await;
    }
    for credential in [credential(), bearer_credential("selected-token")] {
        let result = backend
            .issue_types("PROJ", request(2, 2), &credential)
            .await
            .unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.value.start_at, 2);
        assert_eq!(result.value.total, 5);
        assert_eq!(result.value.issue_types[0].id, "10001");
        assert_eq!(result.value.issue_types[0].description, "A task");
        assert!(result.value.issue_types[1].subtask);
    }
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.body.is_empty()));
}

#[tokio::test]
async fn issue_types_rejects_malformed_wire_shapes_and_invalid_pagination() {
    let api = MockServer::start().await;
    let backend = backend(&api, ProviderLimits::default());
    let mut invalid_pages = vec![Value::Null, json!({})];
    for (pointer, invalid) in [
        ("/issueTypes/0/id", json!(10001)),
        ("/issueTypes/0/id", json!("secret-value")),
        ("/issueTypes/0/id", json!("")),
        ("/issueTypes/0/name", json!(" \n ")),
        ("/issueTypes/0/name", json!(false)),
        ("/issueTypes/0/description", Value::Null),
        (
            "/issueTypes/0/description",
            json!({"secret-value": "secret-value"}),
        ),
        ("/issueTypes/0/subtask", json!("false")),
        ("/issueTypes/1/id", json!("10001")),
        ("/startAt", json!(1)),
        ("/startAt", json!(-1)),
        ("/startAt", json!(4294967296_u64)),
        ("/maxResults", json!(0)),
        ("/maxResults", json!(1)),
        ("/maxResults", json!(3)),
        ("/total", json!(1)),
        ("/total", json!("2")),
        ("/issueTypes", json!([])),
    ] {
        let mut value = page();
        *value.pointer_mut(pointer).unwrap() = invalid;
        invalid_pages.push(value);
    }
    for field in ["id", "name", "subtask"] {
        let mut value = page();
        value["issueTypes"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        invalid_pages.push(value);
    }
    let mut legacy_shape = page();
    let entries = legacy_shape
        .as_object_mut()
        .unwrap()
        .remove("issueTypes")
        .unwrap();
    legacy_shape["values"] = entries;
    invalid_pages.push(legacy_shape);
    for value in invalid_pages {
        api.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .expect(1)
            .mount(&api)
            .await;
        let error = backend
            .issue_types("PROJ", request(0, 2), &credential())
            .await
            .unwrap_err();
        assert!(matches!(error, JiraBackendError::Protocol(_)), "{error:?}");
        assert!(!format!("{error:?}").contains("secret-value"));
    }
}

#[tokio::test]
async fn issue_types_preserves_optional_description_and_empty_end_pages() {
    let api = MockServer::start().await;
    let backend = backend(&api, ProviderLimits::default());
    let mut missing_description = page();
    missing_description["issueTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("description");
    for (value, start_at) in [
        (missing_description, 0),
        (
            json!({"issueTypes": [], "startAt": 2, "maxResults": 2, "total": 2}),
            2,
        ),
        (
            json!({"issueTypes": [], "startAt": 3, "maxResults": 2, "total": 2}),
            3,
        ),
    ] {
        api.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .mount(&api)
            .await;
        let result = backend
            .issue_types("PROJ", request(start_at, 2), &credential())
            .await
            .unwrap();
        if start_at == 0 {
            assert_eq!(result.value.issue_types[0].description, "");
        } else {
            assert!(result.value.issue_types.is_empty());
        }
    }
    let mut overflow: JiraIssueTypePage = serde_json::from_value(page()).unwrap();
    overflow.start_at = u32::MAX;
    overflow.total = u32::MAX;
    assert!(validate_issue_type_page(&overflow, &request(u32::MAX, 2)).is_err());
}

#[tokio::test]
async fn issue_types_bounds_response_and_sanitizes_upstream_failures() {
    let api = MockServer::start().await;
    let backend = backend(
        &api,
        ProviderLimits {
            max_upstream_response_bytes: 64,
            ..ProviderLimits::default()
        },
    );
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page()))
        .mount(&api)
        .await;
    assert_eq!(
        backend
            .issue_types("PROJ", request(0, 2), &credential())
            .await
            .unwrap_err(),
        JiraBackendError::ResponseTooLarge
    );
    for (status, expected) in [
        (400, JiraBackendError::HttpStatus(400)),
        (401, JiraBackendError::Unauthorized),
        (403, JiraBackendError::Forbidden),
        (404, JiraBackendError::NotFound),
        (429, JiraBackendError::RateLimited(None)),
        (500, JiraBackendError::HttpStatus(500)),
    ] {
        api.reset().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"errors": {"description": "secret-value"}})),
            )
            .expect(1)
            .mount(&api)
            .await;
        let error = backend
            .issue_types("PROJ", request(0, 2), &credential())
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!jira_backend_error(error).message.contains("secret-value"));
    }
}

#[tokio::test]
async fn issue_types_rejects_invalid_json_and_does_not_follow_redirects() {
    let api = MockServer::start().await;
    let destination = MockServer::start().await;
    let backend = backend(&api, ProviderLimits::default());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not JSON secret-value"))
        .mount(&api)
        .await;
    let error = backend
        .issue_types("PROJ", request(0, 2), &credential())
        .await
        .unwrap_err();
    assert_eq!(
        jira_backend_error(error).reason_code,
        ReasonCode::UpstreamProtocolFailed
    );
    api.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", destination.uri()))
        .expect(1)
        .mount(&api)
        .await;
    assert!(
        backend
            .issue_types("PROJ", request(0, 2), &credential())
            .await
            .is_err()
    );
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn issue_types_enforces_upstream_allowlist_before_dispatch() {
    let api = MockServer::start().await;
    let config = serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "allowed_upstream_hosts": [format!("{}/rest/api/3/issue/PROJ-1", api.uri())]
    }))
    .unwrap();
    let backend = HttpJiraBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let error = backend
        .issue_types("PROJ", request(0, 2), &credential())
        .await
        .unwrap_err();
    assert!(matches!(error, JiraBackendError::Protocol(_)));
    assert!(api.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn issue_types_traces_semantic_protocol_failure_without_response_text() {
    let api = MockServer::start().await;
    let backend = backend(&api, ProviderLimits::default());
    let mut value = page();
    value["issueTypes"][0]["id"] = json!("secret-value");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .mount(&api)
        .await;
    let capture = agent_access_provider::test_support::install_trace_capture().start();
    let credential = credential();
    let error = capture
        .run(with_provider_context(
            CorrelationContext::for_tests(),
            "jira".to_string(),
            "issue_type.list".to_string(),
            backend.issue_types("PROJ", request(0, 2), &credential),
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, JiraBackendError::Protocol(_)));
    let events = capture.take_upstream_requests();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["upstreamOperation"], "issue_type.list");
    assert_eq!(events[0]["http.statusCode"], 200);
    assert_eq!(events[0]["reasonCode"], "upstream_protocol_failed");
    assert!(!format!("{events:?}").contains("secret-value"));
}
