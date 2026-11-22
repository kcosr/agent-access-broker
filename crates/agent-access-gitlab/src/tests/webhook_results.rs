//! Webhook results through the HTTP backend, checked strictly against the
//! published result schemas.
use super::*;
use agent_access_provider::test_support::TestHost;

fn webhook_provider(
    server: &MockServer,
    change: impl FnOnce(&mut GitlabProviderConfig),
) -> GitlabProvider {
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    config.webhooks.allowed_destinations = vec!["https://hooks.example.com/**".to_string()];
    change(&mut config);
    GitlabProvider::new(config, &TestHost::default().context()).unwrap()
}

async fn mount_project_and_hook(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":42,"path_with_namespace":"sip/service"})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/hooks/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":7, "project_id":42, "url":"https://hooks.example.com/old",
            "push_events":true, "enable_ssl_verification":true, "token_present":true,
            "custom_headers":[{"key":"X-Delivery-Secret"}], "url_variables":[{"key":"tenant"}]
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn url_change_without_confirmation_reports_the_secrets_it_would_reset() {
    let server = MockServer::start().await;
    let provider = webhook_provider(&server, |_| {});
    mount_project_and_hook(&server).await;
    let error = provider
        .invoke_strict(test_invocation(
            "webhook.update",
            json!({"project":"sip/service","webhookId":7,"url":"https://hooks.example.com/new","clearToken":true}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        error.result.as_deref(),
        Some(
            &json!({"resetConfiguration":{"customHeaders":["X-Delivery-Secret"],"urlVariables":["tenant"]}})
        )
    );
    // Nothing was written.
    assert_eq!(
        received_requests(&server).await,
        [
            "GET /api/v4/projects/sip%2Fservice",
            "GET /api/v4/projects/sip%2Fservice",
            "GET /api/v4/projects/42/hooks/7",
        ]
    );
}

#[tokio::test]
async fn delivery_events_keep_opaque_payloads_and_report_truncation() {
    let server = MockServer::start().await;
    let provider = webhook_provider(&server, |config| config.content.max_body_bytes = 256);
    mount_project_and_hook(&server).await;
    let oversized = "x".repeat(512);
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/hooks/7/events"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Next-Page", "2")
                .set_body_json(json!([
                    {
                        "id":1, "trigger":"push_hooks", "created_at":"2026-11-01T00:00:00Z",
                        "execution_duration":0.25, "response_status":"200",
                        "request_headers":{"X-Gitlab-Event":"Push Hook","X-Delivery-Secret":"value"},
                        "request_data":{"object_kind":"push","commits":[]},
                        "response_headers":{"Content-Type":"text/plain"}, "response_body":"ok"
                    },
                    {
                        "id":2, "trigger":"push_hooks", "response_status":"internal error",
                        "request_data":{"blob":oversized}, "response_body":oversized
                    }
                ])),
        )
        .mount(&server)
        .await;
    let result = provider
        .invoke_strict(test_invocation(
            "webhook.event.list",
            json!({"project":"sip/service","webhookId":7}),
        ))
        .await
        .unwrap()
        .result;
    let events = &result["events"];
    assert_eq!(events[0]["requestData"]["object_kind"], "push");
    assert_eq!(
        events[0]["requestHeaders"]["X-Delivery-Secret"],
        "[REDACTED]"
    );
    assert_eq!(events[1]["requestData"], Value::Null);
    assert_eq!(events[1]["requestDataTruncated"], true);
    assert_eq!(events[1]["responseBodyTruncated"], true);
    assert_eq!(events[1]["executionDuration"], Value::Null);
    assert_eq!(result["isLast"], false);
    assert!(result["nextPageToken"].is_string());
}
