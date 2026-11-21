//! Exercise startup presentation controls through the actual stdio subprocess.
//! Synthetic Broker responses cover payloads that native fixtures do not emit.
use super::McpProcess;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

fn catalog() -> Value {
    let mut catalog = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
    catalog["services"] = json!([{"service":"example","displayName":"Example","surface":"invoke","scopedMcpReady":true,"scopeTypes":[],"actions":[{
        "action":"read","scopedMcpName":"read","description":"Read a result","readOnly":true,
        "requiredScopeTypes":[],"credentialModes":[],"inputSchema":{"type":"object"},
        "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision",
        "sensitiveOutputPointers":["/result"]
    }]}]);
    catalog
}

fn assert_copy(result: &Value, include_text_copy: bool) {
    assert!(result.get("structuredContent").is_some(), "{result}");
    if include_text_copy {
        assert_eq!(result["content"].as_array().unwrap().len(), 1);
    } else {
        assert_eq!(result["content"], json!([]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_copy_mode_preserves_results_errors_files_and_discovery_in_each_view() {
    let broker = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
        .mount(&broker)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&broker)
        .await;
    let success = json!({
        "agentRequestId":"agent","decision":"allow","service":"example","action":"read","brokerRequestId":"success",
        "result":{"upstreamMcp":{"content":[{"type":"text","text":"nested text must remain"}],"structuredContent":{"answer":42}},"description":{"format":"markdown","value":"**complete body**"}}
    });
    let failure = json!({
        "agentRequestId":"agent","decision":"error","service":"example","action":"read","brokerRequestId":"failure",
        "reasonCode":"upstream_rate_limited","reason":"Retry after 12s.","error":{"message":"Retry after 12s."},
        "result":{"retryAfterSeconds":12,"mutationStatus":"not_applied","retrySafe":true}
    });
    for (outcome, status, value) in [("success", 200, &success), ("failure", 429, &failure)] {
        Mock::given(method("POST"))
            .and(path("/v1/invoke/example/read"))
            .and(body_json(json!({"inputs":{"outcome":outcome}})))
            .respond_with(ResponseTemplate::new(status).set_body_json(value))
            .mount(&broker)
            .await;
    }
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    let config_text = format!(
        "[service]\nurl={:?}\n[identity]\ndisabled=true\n",
        broker.uri()
    );
    std::fs::write(&config, &config_text).unwrap();
    for service in [None, Some("example")] {
        let mut baseline_tools = None;
        for setting in [None, Some(true), Some(false)] {
            let include_text_copy = setting.unwrap_or(true);
            let mut process = McpProcess::start_with_text_copy(&config, service, setting);
            process.initialize().await;
            let tools = process.request("tools/list", json!({})).await;
            assert!(tools.get("error").is_none(), "{tools}");
            if let Some(baseline) = &baseline_tools {
                assert_eq!(&tools["result"], baseline);
            } else {
                baseline_tools = Some(tools["result"].clone());
            }
            let name = if service.is_some() {
                "read"
            } else {
                "example_read"
            };
            for (outcome, expected, is_error) in
                [("success", &success, false), ("failure", &failure, true)]
            {
                let response = process
                    .request(
                        "tools/call",
                        json!({"name":name,"arguments":{"inputs":{"outcome":outcome}}}),
                    )
                    .await;
                assert!(response.get("error").is_none(), "{response}");
                let result = &response["result"];
                assert_copy(result, include_text_copy);
                assert_eq!(&result["structuredContent"], expected);
                assert_eq!(result["isError"], is_error);
                assert_eq!(
                    result["_meta"],
                    json!({"agent-access/sensitive-output-pointers":["/result"]})
                );
            }
            if service.is_none() {
                let helper = process
                    .request("tools/call", json!({"name":"services_list","arguments":{}}))
                    .await;
                assert_copy(&helper["result"], include_text_copy);
                assert_eq!(
                    helper["result"]["structuredContent"],
                    json!({"services":[]})
                );
            }
            let destination = directory.path().join("saved.json");
            let saved = process.request("tools/call", json!({"name":name,"arguments":{"inputs":{"outcome":"success"},"outputPath":destination}})).await;
            assert_copy(&saved["result"], include_text_copy);
            assert_eq!(saved["result"]["isError"], false, "{saved}");
            assert_eq!(
                saved["result"]["structuredContent"]["brokerRequestId"],
                "success"
            );
            assert_eq!(
                saved["result"]["structuredContent"]["output"]["sensitive"],
                true
            );
            assert!(saved["result"]["structuredContent"].get("result").is_none());
            assert!(saved["result"].get("_meta").is_none());
            assert_eq!(
                serde_json::from_slice::<Value>(&std::fs::read(&destination).unwrap()).unwrap(),
                success
            );
            let invalid = process
                .request("tools/call", json!({"name":name,"arguments":{"inputs":[]}}))
                .await;
            assert_copy(&invalid["result"], include_text_copy);
            assert_eq!(invalid["result"]["isError"], true);
            assert_eq!(
                invalid["result"]["structuredContent"]["error"]["message"],
                "action inputs must be a JSON object"
            );
            let unknown = process
                .request("tools/call", json!({"name":"missing","arguments":{}}))
                .await;
            assert_eq!(unknown["error"]["code"], -32602);
            assert!(unknown.get("result").is_none());
            std::fs::write(&config, "invalid = [").unwrap();
            let invalid_config = process
                .request("tools/call", json!({"name":name,"arguments":{"inputs":{}}}))
                .await;
            assert_copy(&invalid_config["result"], include_text_copy);
            assert_eq!(invalid_config["result"]["isError"], true);
            assert!(
                invalid_config["result"]["structuredContent"]["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("Cannot resolve broker configuration")
            );
            std::fs::write(&config, &config_text).unwrap();
            process.finish().await;
        }
    }
}
