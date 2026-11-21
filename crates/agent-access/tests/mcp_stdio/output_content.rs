//! Client validation requires deliberately malformed Broker responses, so these
//! tests use synthetic HTTP while running the actual stdio command.
use super::McpProcess;
use serde_json::{Value, json};
use std::path::Path;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

fn catalog() -> Value {
    let mut catalog = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
    catalog["services"] = json!([{"service":"jira","displayName":"Jira","surface":"invoke","scopedMcpReady":true,"scopeTypes":[],"actions":[{
        "action":"issue.view","scopedMcpName":"issue.view","description":"Read an issue","readOnly":true,
        "requiredScopeTypes":[],"credentialModes":[],"inputSchema":{"type":"object"},
        "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision",
        "outputContentFormats":["markdown","text"],"nativeOutputContentFormat":"markdown","defaultOutputContentFormat":"markdown",
        "bodyFields":[{"ownerPath":"/result","field":"description","optionalOwnerPrefixes":[],"nullableOwnerPrefixes":[],"optional":true,"nullable":true}]
    }]}]);
    catalog
}

fn configure(config: &Path, broker: &MockServer, defaults: &str) {
    std::fs::write(
        config,
        format!(
            "[service]\nurl={:?}\n[identity]\ndisabled=true\n[defaults]\n{defaults}\n",
            broker.uri()
        ),
    )
    .unwrap();
}

async fn serve_catalog(broker: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
        .mount(broker)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_selected_content_returns_structured_completion_receipt_without_file_or_replay() {
    for file in [false, true] {
        let broker = MockServer::start().await;
        serve_catalog(&broker).await;
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","service":"jira","action":"issue.view",
                "result":{"description":{"format":"markdown","value":42},"mutationStatus":"applied","retrySafe":false,"safeLocators":{"issueId":"42"},"private":"PRIVATE BODY"}
            })))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("client.toml");
        configure(&config, &broker, "");
        let destination = directory.path().join("result.json");
        std::fs::write(&destination, "original").unwrap();
        let mut process = McpProcess::start(&config);
        process.initialize().await;
        let mut arguments = json!({"inputs":{},"outputContentFormat":"markdown"});
        if file {
            arguments["outputPath"] = json!(destination);
        }
        let response = process
            .request(
                "tools/call",
                json!({"name":"jira_issue_view","arguments":arguments}),
            )
            .await;
        assert!(response.get("error").is_none(), "{response}");
        let result = &response["result"];
        assert_eq!(result["isError"], true, "{response}");
        let receipt = &result["structuredContent"];
        assert_eq!(receipt["reasonCode"], "response_content_invalid");
        assert_eq!(receipt["operationStatus"], "succeeded");
        assert_eq!(receipt["mutationStatus"], "applied");
        assert_eq!(receipt["retrySafe"], false);
        assert_eq!(receipt["brokerRequestId"], "broker");
        assert!(receipt.get("output").is_none());
        assert!(!response.to_string().contains("PRIVATE BODY"));
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            *receipt
        );
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "original");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
        process.finish().await;
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_client_preference_reload_survives_retired_key_and_accepts_new_native_output() {
    let broker = MockServer::start().await;
    serve_catalog(&broker).await;
    for preferred in ["text", "adf"] {
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.view"))
            .and(body_json(json!({"inputs":{},"preferredOutputContentFormat":preferred})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","service":"jira","action":"issue.view",
                "result":{"description":{"format":"adf","value":{"type":"doc","version":1,"content":[]}}}
            })))
            .expect(1)
            .mount(&broker)
            .await;
    }
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    configure(&config, &broker, "preferred_output_content_format=\"text\"");
    let mut process = McpProcess::start(&config);
    process.initialize().await;
    let request = json!({"name":"jira_issue_view","arguments":{"inputs":{}}});
    let first = process.request("tools/call", request.clone()).await;
    assert_eq!(first["result"]["isError"], false, "{first}");
    assert_eq!(
        first["result"]["structuredContent"]["result"]["description"]["format"],
        "adf"
    );
    configure(&config, &broker, "read_content_format=\"native\"");
    let invalid = process.request("tools/call", request.clone()).await;
    assert_eq!(invalid["result"]["isError"], true, "{invalid}");
    configure(&config, &broker, "preferred_output_content_format=\"adf\"");
    let recovered = process.request("tools/call", request).await;
    assert_eq!(recovered["result"]["isError"], false, "{recovered}");
    assert_eq!(
        recovered["result"]["structuredContent"]["result"]["description"]["format"],
        "adf"
    );
    process.finish().await;
    broker.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compact_allow_outcomes_keep_original_status_and_reason_without_success_bodies() {
    for (mutation, retry_safe) in [
        ("unknown", false),
        ("not_applied", true),
        ("applied", false),
    ] {
        let broker = MockServer::start().await;
        let mut required_body = catalog();
        required_body["services"][0]["actions"][0]["bodyFields"][0]["optional"] = json!(false);
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(required_body))
            .mount(&broker)
            .await;
        let receipt = json!({"agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","reasonCode":"verification_mismatch","reason":"Original provider outcome","result":{"mutationStatus":mutation,"retrySafe":retry_safe}});
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(receipt.clone()))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("client.toml");
        configure(&config, &broker, "");
        let mut process = McpProcess::start(&config);
        process.initialize().await;
        let response = process
            .request("tools/call", json!({"name":"jira_issue_view","arguments":{"inputs":{},"outputContentFormat":"markdown"}}))
            .await;
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], false, "{response}");
        assert_eq!(response["result"]["structuredContent"], receipt);
        assert_eq!(
            serde_json::from_str::<Value>(
                response["result"]["content"][0]["text"].as_str().unwrap()
            )
            .unwrap(),
            receipt
        );
        process.finish().await;
        broker.verify().await;
    }
}
