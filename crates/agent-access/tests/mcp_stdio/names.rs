//! Exercise naming failures through the real stdio command and a changing broker catalog.
use super::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn action(name: &str) -> Value {
    json!({
        "action":name,"scopedMcpName":name,"description":"Synthetic naming action","readOnly":true,
        "requiredScopeTypes":[],"credentialModes":[],"lookupRequired":false,
        "inputSchema":{"type":"object","additionalProperties":false},
        "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision"
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_names_omit_conflicts_preserve_helpers_and_refresh_without_reconnecting() {
    let server = MockServer::start().await;
    let overlong = "a".repeat(124);
    let mut catalog = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
    catalog["services"] = json!([
        {"service":"fake","displayName":"Naming fixture","surface":"invoke","scopedMcpReady":true,"availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":[],
         "actions":[action("echo"),action("item.read"),action("item_read"),action(&overlong)]},
        {"service":"services","displayName":"Helper conflict fixture","surface":"invoke","scopedMcpReady":true,"availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":[],
         "actions":[action("list")]}
    ]);
    let current = Arc::new(Mutex::new(catalog));
    let response = current.clone();
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(response.lock().unwrap().clone())
        })
        .mount(&server)
        .await;
    for service in ["fake", "services"] {
        let response = current.clone();
        Mock::given(method("GET"))
            .and(path(format!("/v1/services/{service}")))
            .respond_with(move |_: &wiremock::Request| {
                let catalog = response.lock().unwrap();
                let definition = catalog["services"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|value| value["service"] == service)
                    .unwrap();
                ResponseTemplate::new(200).set_body_json(definition)
            })
            .mount(&server)
            .await;
    }
    let response = current.clone();
    Mock::given(method("GET"))
        .and(path("/v1/services"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(response.lock().unwrap()["services"].clone())
        })
        .expect(1)
        .mount(&server)
        .await;
    for action in ["echo", "item.read"] {
        Mock::given(method("POST")).and(path(format!("/v1/invoke/fake/{action}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","result":{"action":action}})))
            .expect(1).mount(&server).await;
    }

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    std::fs::write(
        &config,
        format!(
            "[service]\nurl = {:?}\n[identity]\ndisabled = true\n",
            server.uri()
        ),
    )
    .unwrap();
    let mut process = McpProcess::start(&config);
    process.initialize().await;
    let listed = process.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6, "{listed}");
    assert!(tools.iter().any(|tool| tool["name"] == "fake_echo"));
    assert_eq!(
        tools
            .iter()
            .filter(|tool| tool["name"] == "services_list")
            .count(),
        1
    );
    for name in [
        "fake_item_read".to_owned(),
        format!("fake_{overlong}"),
        "fake_echo_245a0744f1fbd877".to_owned(),
    ] {
        let rejected = process
            .request("tools/call", json!({"name":name,"arguments":{"inputs":{}}}))
            .await;
        assert_eq!(rejected["error"]["code"], -32602, "{rejected}");
    }
    for (service, action, code) in [
        ("fake", "item.read", "name_conflict"),
        ("fake", "item_read", "name_conflict"),
        ("fake", overlong.as_str(), "name_too_long"),
        ("services", "list", "reserved_name"),
    ] {
        let result = process
            .request(
                "tools/call",
                json!({"name":"actions_describe","arguments":{"service":service,"action":action}}),
            )
            .await;
        assert_eq!(result["result"]["isError"], false, "{result}");
        let detail = &result["result"]["structuredContent"];
        assert_eq!(detail["action"], action);
        assert!(detail.get("mcpTool").is_none());
        assert_eq!(detail["mcpToolUnavailable"], code);
    }
    let helper = process
        .request("tools/call", json!({"name":"services_list","arguments":{}}))
        .await;
    assert_eq!(helper["result"]["isError"], false, "{helper}");
    let allowed = process
        .request(
            "tools/call",
            json!({"name":"fake_echo","arguments":{"inputs":{}}}),
        )
        .await;
    assert_eq!(allowed["result"]["structuredContent"]["decision"], "allow");

    current.lock().unwrap()["services"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .retain(|action| action["action"] != "item_read");
    let refreshed = process.request("tools/list", json!({})).await;
    assert!(
        refreshed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "fake_item_read")
    );
    let detail = process
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"fake","action":"item.read"}}),
        )
        .await;
    assert_eq!(
        detail["result"]["structuredContent"]["mcpTool"]["name"],
        "fake_item_read"
    );
    assert!(
        detail["result"]["structuredContent"]
            .get("mcpToolUnavailable")
            .is_none()
    );
    let allowed = process
        .request(
            "tools/call",
            json!({"name":"fake_item_read","arguments":{"inputs":{}}}),
        )
        .await;
    assert_eq!(allowed["result"]["structuredContent"]["decision"], "allow");
    process.finish().await;
    server.verify().await;
}
