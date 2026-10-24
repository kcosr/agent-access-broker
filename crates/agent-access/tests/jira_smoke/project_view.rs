//! Real Broker and CLI with production Jira HTTP transport; only Jira is synthetic.
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[path = "../common/list_mcp.rs"]
mod list_mcp;

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const API: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3";
const QUERY: &str = r#"cf[12345] ~ "EXT-4812" AND fixVersion = "2.4""#;
const CONSTRAINED_QUERY: &str =
    r#"(cf[12345] ~ "EXT-4812" AND fixVersion = 2.4) AND project IN (PROJ)"#;

async fn start(server: &MockServer, access: JiraAccess, actions: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value =
        toml::from_str(&jira_document(application.directory(), access)).unwrap();
    document["identity"]["sources"][0]["header"] = "Authorization".into();
    document["identity"]["sources"][0]["scheme"] = "Bearer".into();
    document.as_table_mut().unwrap().insert(
        "mcp".into(),
        toml::Value::try_from(
            json!({"enabled":true,"public_url":format!("{}/mcp", application.public_url())}),
        )
        .unwrap(),
    );
    document["providers"]["jira"]["allowed_upstream_hosts"] = toml::Value::try_from(vec![
        "https://api.atlassian.com/ex/jira/**",
        "https://example.atlassian.net/rest/api/3/**",
    ])
    .unwrap();
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["credentials"]["service"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("profile".into(), "atlassian-scoped-api-token".into());
    // Project views and JQL searches must use the selected execution credential.
    document["credentials"]
        .as_table_mut()
        .unwrap()
        .remove("lookup");
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        grant["actions"] = toml::Value::try_from(actions).unwrap();
        grant["resources"] =
            toml::Value::try_from(BTreeMap::from([("resource_ids", vec!["project-proj"])]))
                .unwrap();
    }
    if matches!(access, JiraAccess::AgentPerUser) {
        let file = application.directory().join("jira-per-user-store.json");
        let mut store: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        store["credentials"][0]["type"] = json!("bearer_token");
        store["credentials"][0]
            .as_object_mut()
            .unwrap()
            .remove("username_ref");
        std::fs::write(file, serde_json::to_vec(&store).unwrap()).unwrap();
    }
    let mut config: agent_access_jira::JiraProviderConfig =
        document["providers"]["jira"].clone().try_into().unwrap();
    config
        .allowed_upstream_hosts
        .push(format!("{}/**", server.uri()));
    let gateway = server.uri();
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "jira",
            ProviderFixture::factory(move |context| {
                agent_access_jira::test_support::provider_with_gateway(
                    config.clone(),
                    context.build_context(),
                    &gateway,
                )
                .unwrap()
            }),
        )
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#?}"))
}

async fn mount(server: &MockServer) {
    for (verb, route, body) in [
        (
            "GET",
            "project/PROJ",
            json!({
                "id":"10001", "key":"PROJ", "name":"Visible project",
                "description":"Synthetic project for discovery",
                "lead":{"displayName":"UNPROJECTED_LEAD"},
                "versions":[{"id":"20001","name":"2.4","description":"Release","released":false,"archived":false}],
                "components":[{"id":"30001","name":"API","description":"Public API","lead":{"displayName":"UNPROJECTED_COMPONENT_LEAD"}}],
                "issueTypes":[{"id":"40001","name":"Task","description":"Work to complete","subtask":false}]
            }),
        ),
        (
            "POST",
            "jql/autocompletedata",
            json!({
                "visibleFieldNames":[
                    {"value":"External ticket number","displayName":"External ticket number","cfid":"cf[12345]","searchable":"true","operators":["~","!~"],"types":["java.lang.String"]},
                    {"value":"fixVersion","displayName":"Fix version","searchable":"true","operators":["=","in"],"types":["com.atlassian.jira.project.version.Version"]},
                    {"value":"UNSUPPORTED_FIELD","displayName":"UNPROJECTED_FIELD","searchable":"true","operators":["~"],"types":["java.lang.String"]}
                ],
                "visibleFunctionNames":[{"value":"UNPROJECTED_FUNCTION()"}]
            }),
        ),
        (
            "GET",
            "project/10001/statuses",
            json!([
                {"id":"40001","name":"Task","statuses":[{"id":"50001","name":"Open","description":"Ready","statusCategory":{"id":2,"key":"new","name":"To Do"}}]},
                {"id":"40002","name":"Bug","statuses":[{"id":"50001","name":"Open","description":"Ready","statusCategory":{"id":2,"key":"new","name":"To Do"}}]}
            ]),
        ),
        (
            "GET",
            "search/jql",
            json!({"isLast":true,"issues":[{
                "id":"60001","key":"PROJ-1","fields":{"project":{"key":"PROJ"},"summary":"External ticket result","issuetype":{"name":"Task"},"status":{"name":"Open"}}
            }]}),
        ),
    ] {
        Mock::given(method(verb))
            .and(path(format!("{API}/{route}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
}

fn cli(base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base,
        "--token-value",
        "agent-token",
        "--identity-header",
        "Authorization",
        "--identity-scheme",
        "Bearer",
    ]);
    command
}

fn run(base: &str, arguments: &[&str]) -> Value {
    let output = cli(base).args(arguments).output().unwrap();
    assert_success("project discovery", &output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn action<'a>(catalog: &'a Value, name: &str) -> &'a Value {
    catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == name)
        .unwrap()
}

fn tool(listing: &Value) -> &Value {
    listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "project.view")
        .unwrap()
}

async fn rpc_body(response: reqwest::Response) -> Value {
    assert!(response.status().is_success(), "{}", response.status());
    let body = response.text().await.unwrap();
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(&body).unwrap();
    }
    let responses = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|value| value.get("id").is_some())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 1, "{body}");
    responses.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_project_view_discovers_then_searches_across_cli_http_and_mcp() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let server = MockServer::start().await;
        mount(&server).await;
        let broker = start(&server, access, &["project.view", "search"]).await;
        let base = broker.public_url();
        let catalog = run(&base, &["spec", "catalog"]);
        let view = action(&catalog, "project.view");
        assert_eq!(view["readOnly"], true);
        assert_eq!(view["lookupRequired"], false);
        assert_eq!(view["requiredScopeTypes"], json!(["project"]));
        assert_eq!(view["inputSchema"]["required"], json!(["project"]));
        assert!(view["documentation"].is_object());
        let detail = run(
            &base,
            &["actions", "describe", "--service", "jira", "project.view"],
        );
        assert_eq!(detail["documentation"], view["documentation"]);
        let openapi = run(&base, &["spec", "openapi"]);
        let operation = &openapi["paths"]["/v1/invoke/jira/project.view"]["post"];
        assert_eq!(operation["x-agent-access-read-only"], true);
        assert_eq!(
            operation["x-agent-access-documentation"],
            view["documentation"]
        );
        let schema = run(&base, &["spec", "send-schema"]);
        let send_variant = schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["service"]["const"] == "jira"
                    && variant["properties"]["action"]["const"] == "project.view"
            })
            .unwrap();
        assert_eq!(send_variant["x-agent-access-read-only"], true);
        assert_eq!(
            send_variant["x-agent-access-documentation"],
            view["documentation"]
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        let viewed = run(&base, &["jira", "project", "view", "PROJ"]);
        assert_eq!(viewed["decision"], "allow", "{viewed}");
        let result = &viewed["result"];
        assert_eq!(result["operation"], "project.view");
        assert_eq!(result["project"]["id"], "10001");
        assert_eq!(result["project"]["key"], "PROJ");
        assert_eq!(result["project"]["name"], "Visible project");
        assert_eq!(result["fields"]["count"], 2);
        assert_eq!(result["fields"]["truncated"], false);
        let custom = result["fields"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["id"] == "customfield_12345")
            .unwrap();
        assert_eq!(custom["name"], "External ticket number");
        assert_eq!(custom["jqlReference"], "cf[12345]");
        assert_eq!(custom["operators"], json!(["~"]));
        for section in ["versions", "components", "issueTypes", "statuses"] {
            assert!(result.get(section).is_none(), "{result}");
        }
        let initial_requests = server.received_requests().await.unwrap();
        assert_eq!(initial_requests.len(), 2);
        assert_eq!(
            initial_requests[0].url.path(),
            format!("{API}/project/PROJ")
        );
        assert_eq!(
            initial_requests[1].url.path(),
            format!("{API}/jql/autocompletedata")
        );

        let filtered = run(
            &base,
            &["jira", "project", "view", "PROJ", "--query", "external"],
        );
        assert_eq!(filtered["result"]["fields"]["items"], json!([custom]));
        let all = run(
            &base,
            &[
                "jira",
                "project",
                "view",
                "PROJ",
                "--include",
                "fields,versions,components,issueTypes,statuses",
            ],
        );
        for (section, name) in [
            ("versions", "2.4"),
            ("components", "API"),
            ("issueTypes", "Task"),
            ("statuses", "Open"),
        ] {
            assert_eq!(all["result"][section]["count"], 1, "{all}");
            assert_eq!(all["result"][section]["items"][0]["name"], name);
            assert_eq!(all["result"][section]["truncated"], false);
        }
        let before_identity = server.received_requests().await.unwrap().len();
        let identity = run(&base, &["jira", "project", "view", "PROJ", "--include"]);
        assert_eq!(identity["result"]["project"], result["project"]);
        assert!(identity["result"].get("fields").is_none());
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            before_identity + 1
        );
        let markdown = cli(&base)
            .args([
                "jira",
                "project",
                "view",
                "PROJ",
                "--output-format",
                "markdown",
            ])
            .output()
            .unwrap();
        assert_success("project Markdown", &markdown);
        let markdown = String::from_utf8(markdown.stdout).unwrap();
        assert!(
            markdown.contains("Visible project") && markdown.contains("cf[12345]"),
            "{markdown}"
        );
        let inputs = json!({"project":"PROJ"});
        let invoked = run(
            &base,
            &[
                "invoke",
                "jira.project.view",
                "--input-json",
                &inputs.to_string(),
            ],
        );
        assert_eq!(invoked["result"], *result);
        let request = json!({"version":"agent-access.send.v1", "kind":"invoke", "service":"jira", "action":"project.view", "inputs":inputs});
        let sent = run(&base, &["send", "--request-json", &request.to_string()]);
        assert_eq!(sent["result"], *result);
        let client = reqwest::Client::new();
        let http = client
            .post(format!("{base}/v1/invoke/jira/project.view"))
            .bearer_auth("agent-token")
            .header(REQUEST_ID_HEADER, "jira-project-view-http")
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap();
        assert!(http.status().is_success(), "{}", http.status());
        assert_eq!(http.json::<Value>().await.unwrap()["result"], *result);

        let mut mcp = list_mcp::StdioMcp::start(cli(&base));
        let initialize = json!({"protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"jira-discovery-smoke", "version":"1"}});
        mcp.request("initialize", initialize.clone()).await;
        mcp.notify("notifications/initialized", json!({}));
        let before_list = server.received_requests().await.unwrap().len();
        let listing = mcp.request("tools/list", json!({})).await;
        assert_eq!(server.received_requests().await.unwrap().len(), before_list);
        let definition = tool(&listing);
        assert!(definition.get("documentation").is_none());
        assert_eq!(
            definition["inputSchema"]["properties"]["inputs"]["required"],
            json!(["project"])
        );
        let called = mcp
            .request(
                "tools/call",
                json!({"name":definition["name"], "arguments":{"inputs":inputs}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(called["result"]["structuredContent"]["result"], *result);
        mcp.finish().await;

        let endpoint = format!("{base}/mcp");
        let rpc = |message: Value, session: Option<&str>| {
            let mut request = client
                .post(&endpoint)
                .bearer_auth("agent-token")
                .header("Accept", "application/json, text/event-stream")
                .json(&message);
            if let Some(session) = session {
                request = request
                    .header("mcp-session-id", session)
                    .header("mcp-protocol-version", "2025-11-25");
            }
            request
        };
        let initialized = rpc(
            json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":initialize}),
            None,
        )
        .send()
        .await
        .unwrap();
        assert!(
            initialized.status().is_success(),
            "{}",
            initialized.status()
        );
        let session = initialized.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            rpc_body(initialized).await["result"]["protocolVersion"],
            "2025-11-25"
        );
        assert!(
            rpc(
                json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
                Some(&session)
            )
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
        );
        let before_list = server.received_requests().await.unwrap().len();
        let http_listing = rpc_body(
            rpc(
                json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
                Some(&session),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(server.received_requests().await.unwrap().len(), before_list);
        let http_tool = tool(&http_listing);
        assert_eq!(http_tool["name"], definition["name"]);
        let http_called = rpc_body(rpc(json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":http_tool["name"], "arguments":{"inputs":inputs}}}), Some(&session)).send().await.unwrap()).await;
        assert_eq!(http_called["result"]["isError"], false, "{http_called}");
        assert_eq!(
            http_called["result"]["structuredContent"]["result"],
            *result
        );
        assert!(
            client
                .delete(&endpoint)
                .bearer_auth("agent-token")
                .header("mcp-session-id", &session)
                .header("mcp-protocol-version", "2025-11-25")
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );

        let searched = run(&base, &["jira", "issue", "search", "--jql", QUERY]);
        assert_eq!(searched["decision"], "allow", "{searched}");
        assert_eq!(searched["result"]["issues"][0]["key"], "PROJ-1");
        let expected_auth = match access {
            JiraAccess::AgentPerUser => "Bearer jira-per-user-token".to_owned(),
            _ => format!("Basic {}", BASE64.encode("service@example.com:jira-token")),
        };
        let requests = server.received_requests().await.unwrap();
        for request in &requests {
            assert_eq!(request.headers["authorization"], expected_auth);
            let route = request.url.path().strip_prefix(API).unwrap();
            match route {
                "/project/PROJ" => {
                    let expand = request
                        .url
                        .query_pairs()
                        .find(|(name, _)| name == "expand")
                        .unwrap()
                        .1;
                    assert!(expand == "description" || expand == "description,issueTypes");
                }
                "/jql/autocompletedata" => assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!({"projectIds":[10001], "includeCollapsedFields":false})
                ),
                "/project/10001/statuses" => {}
                "/search/jql" => assert_eq!(
                    request
                        .url
                        .query_pairs()
                        .find(|(name, _)| name == "jql")
                        .unwrap()
                        .1,
                    CONSTRAINED_QUERY
                ),
                other => panic!("unexpected Jira route: {other}"),
            }
        }
        let audit = broker.audit().unwrap();
        audit.require_action("jira", "project.view");
        audit.require_action("jira", "search");
        for output in [
            viewed.to_string(),
            all.to_string(),
            markdown,
            called.to_string(),
            http_called.to_string(),
            audit.text().to_owned(),
        ] {
            for withheld in [
                "UNPROJECTED_",
                "jira-token",
                "jira-per-user-token",
                "jira-lookup-token",
            ] {
                assert!(!output.contains(withheld), "{withheld}: {output}");
            }
        }
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_project_view_denies_before_upstream_and_never_falls_back_from_personal_access() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let server = MockServer::start().await;
        mount(&server).await;
        let broker = start(&server, access, &["project.view"]).await;
        let base = broker.public_url();
        for arguments in [
            vec!["jira", "project", "view", "HIDDEN"],
            vec!["jira", "issue", "search", "--jql", QUERY],
        ] {
            let denied = cli(&base).args(arguments).output().unwrap();
            assert!(!denied.status.success());
            assert!(server.received_requests().await.unwrap().is_empty());
        }
        assert_eq!(
            run(&base, &["jira", "project", "view", "PROJ"])["decision"],
            "allow"
        );
        match access {
            JiraAccess::AgentPerUser => std::fs::write(
                broker.directory().join("jira-per-user-store.json"),
                b"{\"credentials\":[]}",
            )
            .unwrap(),
            _ => std::fs::remove_file(broker.directory().join("jira-token.txt")).unwrap(),
        }
        let before = server.received_requests().await.unwrap().len();
        let catalog = run(&base, &["spec", "catalog"]);
        assert!(!catalog.to_string().contains("project.view"));
        let denied = cli(&base)
            .args(["jira", "project", "view", "PROJ"])
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            before,
            "{access:?}: missing selected credential reached Jira"
        );
        stop(broker).await;
    }
}
