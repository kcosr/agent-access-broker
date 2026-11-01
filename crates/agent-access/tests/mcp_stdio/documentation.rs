//! Extended documentation through real Broker discovery and the stdio process.
use super::*;
use agent_access_broker_host::test_support::ProviderFixture;
use agent_access_provider::{
    Provider, ProviderError, ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution,
    ServiceProvider,
};

struct DiscoveryOnly;

#[async_trait::async_trait]
impl Provider for DiscoveryOnly {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        panic!("documentation discovery must not resolve upstream scopes")
    }

    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("documentation discovery must not invoke an upstream")
    }
}

fn client_config(directory: &FixtureDir, base: &str, token: &Path) -> std::path::PathBuf {
    let client = directory.join("client.toml");
    std::fs::write(&client, format!(
        "[service]\nurl={}\n[identity]\nheader=\"Authorization\"\nscheme=\"Bearer\"\ntoken_file={}\n",
        toml_string(base), toml_string(token.display())
    )).unwrap();
    client
}

async fn get(client: &reqwest::Client, base: &str, token: &str, path: &str) -> Value {
    let response = client
        .get(format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Agent-Access-Request-Id", "documentation-get")
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{path}: {}",
        response.status()
    );
    response.json().await.unwrap()
}

fn assert_detail(response: &Value, documentation: &Value) {
    assert_eq!(response["result"]["isError"], false, "{response}");
    let detail = &response["result"]["structuredContent"];
    assert_eq!(detail["documentation"], *documentation);
    assert_eq!(
        serde_json::from_str::<Value>(response["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap(),
        *detail
    );
    assert!(detail["mcpTool"].get("documentation").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_documentation_survives_real_stdio_and_stays_out_of_tool_lists() {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let token = "documentation-reader";
    let first = directory.secret_file("one.token", token).unwrap();
    let second = directory
        .secret_file("two.token", "other-documentation-reader")
        .unwrap();
    let upstream = directory
        .secret_file("upstream.token", "synthetic-upstream-token")
        .unwrap();
    let mut document: toml::Value =
        toml::from_str(&fake_document(&directory, &first, &second)).unwrap();
    document["identity"]["sources"][0]["header"] = toml::Value::from("Authorization");
    document["identity"]["sources"][0]["scheme"] = toml::Value::from("Bearer");
    document["credentials"]["service"]["fake"]["token_ref"] =
        toml::Value::from(format!("file:{}", upstream.display()));
    let documentation = json!({"usage":"DOC_SENTINEL", "inputExamples":[{
        "label":"Nested example with escaped text", "inputs":{"project":"TEST", "message":"A \"quote\" and C:\\work\nnext line", "nested":{"items":["é"]}}
    }]});
    let mut descriptor = agent_access_fake::fake_descriptor();
    descriptor.actions[0].documentation = Some(documentation.clone());
    descriptor.actions[0].input_schema["properties"]["message"]["x-agent-access-sensitive"] =
        json!(true);
    let broker = application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "fake",
            ProviderFixture::instance(ServiceProvider::new(descriptor, Arc::new(DiscoveryOnly))),
        )
        .start()
        .await
        .unwrap();
    let base = broker.public_url();
    let client = reqwest::Client::new();
    let catalog = get(&client, &base, token, "/v1/spec/catalog").await;
    let service = get(&client, &base, token, "/v1/services/fake").await;
    assert_eq!(
        catalog["services"][0]["actions"][0]["documentation"],
        documentation
    );
    assert_eq!(service["actions"][0]["documentation"], documentation);
    let config = client_config(&directory, &base, &first);
    for view in [None, Some("fake")] {
        let mut process = McpProcess::start_view(&config, view);
        process.initialize().await;
        let listed = process.request("tools/list", json!({})).await;
        assert!(listed.get("error").is_none(), "{listed}");
        assert!(!listed.to_string().contains("DOC_SENTINEL"));
        let provider = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == "echo")
            .unwrap();
        assert!(
            provider["inputSchema"]["properties"]
                .get("secretSources")
                .is_some()
        );
        let described = process
            .request(
                "tools/call",
                json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
            )
            .await;
        assert_detail(&described, &documentation);
        assert!(
            !described["result"]["structuredContent"]["mcpTool"]
                .to_string()
                .contains("DOC_SENTINEL")
        );
        process.finish().await;
    }
    stop(broker).await;
}

async fn rpc_response(response: reqwest::Response) -> Value {
    assert!(response.status().is_success(), "{}", response.status());
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let text = tokio::time::timeout(RPC_TIMEOUT, response.text())
        .await
        .unwrap()
        .unwrap();
    if content_type.starts_with("application/json") {
        return serde_json::from_str(&text).unwrap();
    }
    assert!(content_type.starts_with("text/event-stream"));
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|message| message.get("id").is_some())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn largest_jira_documentation_survives_both_real_mcp_transports_at_minimum_http_budget() {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let token = "native-documentation-reader";
    let first = directory.secret_file("one.token", token).unwrap();
    let second = directory
        .secret_file("two.token", "other-documentation-reader")
        .unwrap();
    let upstream = directory
        .secret_file("upstream.token", "synthetic-upstream-token")
        .unwrap();
    let mut document: toml::Value =
        toml::from_str(&fake_document(&directory, &first, &second)).unwrap();
    document["deployment"]["enable_fake_service"] = toml::Value::from(false);
    document["identity"]["sources"][0]["header"] = toml::Value::from("Authorization");
    document["identity"]["sources"][0]["scheme"] = toml::Value::from("Bearer");
    document["providers"] = toml::from_str(
        r#"
[jira]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/**"]
[jira.content]
comment_formats = ["adf"]
[jira.attachments]
media_types = ["text/plain", "application/json"]
[jira.comments]
allowed_visibility = [{ type = "role", value = "Developers" }]
"#,
    )
    .unwrap();
    let jira_config: agent_access_jira::JiraProviderConfig =
        document["providers"]["jira"].clone().try_into().unwrap();
    let descriptor = agent_access_jira::jira_descriptor(&jira_config);
    document["credentials"] = toml::from_str(&format!(
        r#"
[service.jira]
type = "basic_api_token"
username_ref = {credential}
token_ref = {credential}
[lookup.jira]
type = "basic_api_token"
username_ref = {credential}
token_ref = {credential}
read_only = true
"#,
        credential = toml_string(format_args!("file:{}", upstream.display()))
    ))
    .unwrap();
    document["policy"]["grants"][0]["service"] = toml::Value::from("jira");
    document["policy"]["grants"][0]["actions"] = toml::Value::try_from(
        descriptor
            .actions
            .iter()
            .map(|action| action.action.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for resource in document["policy"]["resources"].as_array_mut().unwrap() {
        resource["resource_type"] =
            toml::Value::from(agent_access_jira::JIRA_PROJECT_RESOURCE.id().as_str());
    }
    document.as_table_mut().unwrap().insert(
        "mcp".into(),
        toml::from_str(&format!(
            "enabled=true\npublic_url={}\nmax_response_bytes=65536\n",
            toml_string(format!("{}/mcp", application.public_url()))
        ))
        .unwrap(),
    );
    let broker = application
        .config_document(toml::to_string(&document).unwrap())
        .start()
        .await
        .unwrap();
    let base = broker.public_url();
    let client = reqwest::Client::new();
    let catalog = get(&client, &base, token, "/v1/spec/catalog").await;
    let jira = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .unwrap();
    let longest = jira["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|action| action.get("documentation").is_some())
        .max_by_key(|action| serde_json::to_vec(&action["documentation"]).unwrap().len())
        .unwrap();
    let action = longest["action"].as_str().unwrap();
    let documentation = &longest["documentation"];
    assert_eq!(
        descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == action)
            .unwrap()
            .documentation
            .as_ref(),
        Some(documentation)
    );
    let config = client_config(&directory, &base, &first);
    for service in [None, Some("jira")] {
        let mut process = McpProcess::start_view(&config, service);
        process.initialize().await;
        let described = process
            .request(
                "tools/call",
                json!({"name":"actions_describe","arguments":{"service":"jira","action":action}}),
            )
            .await;
        assert_detail(&described, documentation);
        process.finish().await;
    }
    for path in ["/mcp", "/mcp/jira"] {
        let request = |body: Value| {
            client
                .post(format!("{base}{path}"))
                .bearer_auth(token)
                .header("accept", "application/json, text/event-stream")
                .json(&body)
        };
        let initialized = request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"documentation-test","version":"1"}}})).send().await.unwrap();
        let session = initialized.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            rpc_response(initialized).await["result"]["protocolVersion"],
            "2025-11-25"
        );
        let notification = request(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap();
        assert!(notification.status().is_success());
        let described = rpc_response(request(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"actions_describe","arguments":{"service":"jira","action":action}}})).header("mcp-session-id", &session).header("mcp-protocol-version", "2025-11-25").send().await.unwrap()).await;
        assert_detail(&described, documentation);
        assert!(serde_json::to_vec(&described).unwrap().len() < 65_536);
        let closed = client
            .delete(format!("{base}{path}"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap();
        assert!(closed.status().is_success());
    }
    stop(broker).await;
}
