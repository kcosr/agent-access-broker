//! Production Jira transport behind the real broker and CLI; only Jira is synthetic.
use super::list_mcp;
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const ROUTE: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3/project/search";

async fn start(server: &MockServer, access: JiraAccess, actions: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value =
        toml::from_str(&jira_document(application.directory(), access)).unwrap();
    document.as_table_mut().unwrap().insert(
        "execution_context".into(),
        toml::from_str(
            "allowed_values = [\"default\", \"internal\"]\ndefault_context = \"default\"",
        )
        .unwrap(),
    );
    document["providers"]["jira"]["allowed_upstream_hosts"] = toml::Value::try_from(vec![
        "https://api.atlassian.com/ex/jira/**".to_string(),
        "https://example.atlassian.net/rest/api/3/**".to_string(),
    ])
    .unwrap();
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert(
            "listing".into(),
            toml::Value::try_from(BTreeMap::from([("max_candidate_pages", 1)])).unwrap(),
        );
    document["credentials"]["service"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("profile".into(), "atlassian-scoped-api-token".into());
    // Native listing never acquires lookup credentials.
    document["credentials"]
        .as_table_mut()
        .unwrap()
        .remove("lookup");
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        grant["actions"] = toml::Value::try_from(actions).unwrap();
        grant.as_table_mut().unwrap().insert(
            "execution_contexts".into(),
            toml::Value::try_from(vec!["default"]).unwrap(),
        );
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
    let mut cfg: agent_access_jira::JiraProviderConfig =
        document["providers"]["jira"].clone().try_into().unwrap();
    cfg.allowed_upstream_hosts
        .push(format!("{}/**", server.uri()));
    let gateway = server.uri();
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "jira",
            ProviderFixture::factory(move |context| {
                agent_access_jira::test_support::provider_with_gateway(
                    cfg.clone(),
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
async fn mount(server: &MockServer, offset: u64, last: bool, values: Value) {
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .and(query_param("startAt", offset.to_string()))
        .and(query_param("maxResults", "2"))
        .and(query_param("status", "live"))
        .and(query_param("orderBy", "key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"startAt":offset,"maxResults":2,"isLast":last,"values":values,"total":989898}),
        ))
        .mount(server)
        .await;
}
fn checked(output: std::process::Output) -> Value {
    assert_success("project listing", &output);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "allow", "{value}");
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_project_list_service_personal_cli_send_http_and_mcp() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let server = MockServer::start().await;
        mount(
            &server,
            0,
            false,
            json!([{"id":"9","key":"HIDDEN","name":"DENIED_PROJECT_NAME"}]),
        )
        .await;
        mount(&server,1,true,json!([{"id":"1","key":"PROJ","name":"Visible project","projectTypeKey":"software","owner":"UNPROJECTED_OWNER"}])).await;
        let broker = start(&server, access, &["project.list"]).await;
        let base = broker.public_url();
        let output = authenticated_jira_cli(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("catalog", &output);
        let catalog: Value = serde_json::from_slice(&output.stdout).unwrap();
        let actions = catalog["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|service| service["service"] == "jira")
            .unwrap()["actions"]
            .as_array()
            .unwrap();
        assert_eq!(actions.len(), 1, "{access:?}: {catalog}");
        assert_eq!(actions[0]["action"], "project.list");
        assert_eq!(actions[0]["readOnly"], true);
        assert_eq!(actions[0]["lookupRequired"], false);
        assert!(server.received_requests().await.unwrap().is_empty());
        let first = checked(
            authenticated_jira_cli(&base)
                .args(["jira", "project", "list", "--max-results", "2"])
                .output()
                .unwrap(),
        );
        assert_eq!(first["result"]["scanStatus"], "scan_budget");
        assert_eq!(first["result"]["count"], 0);
        let token = first["result"]["nextPageToken"].as_str().unwrap();
        let second = checked(
            authenticated_jira_cli(&base)
                .args([
                    "jira",
                    "project",
                    "list",
                    "--max-results",
                    "2",
                    "--page-token",
                    token,
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(second["result"]["items"][0]["key"], "PROJ");
        assert_eq!(second["result"]["scanStatus"], "exhausted");
        let markdown = authenticated_jira_cli(&base)
            .args([
                "jira",
                "project",
                "list",
                "--max-results",
                "2",
                "--page-token",
                token,
                "--output-format",
                "markdown",
            ])
            .output()
            .unwrap();
        assert_success("Markdown listing", &markdown);
        let markdown = String::from_utf8(markdown.stdout).unwrap();
        assert!(
            markdown.contains("Jira projects")
                && markdown.contains("Visible project")
                && markdown.contains("exhausted")
        );
        let send=json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"project.list","inputs":{"maxResults":2,"pageToken":token}}).to_string();
        let sent = checked(
            authenticated_jira_cli(&base)
                .args(["send", "--request-json", &send])
                .output()
                .unwrap(),
        );
        assert_eq!(sent["result"], second["result"]);
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/jira/project.list"))
            .header("X-Agent-Access-Identity-Token", "agent-token")
            .header(REQUEST_ID_HEADER, "jira-project-http")
            .json(&json!({"inputs":{"maxResults":2,"pageToken":token}}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let http: Value = response.json().await.unwrap();
        assert_eq!(http["result"], second["result"]);
        let mut mcp = list_mcp::StdioMcp::start(authenticated_jira_cli(&base));
        mcp.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"jira-list-smoke","version":"1"}})).await;
        mcp.notify("notifications/initialized", json!({}));
        let before = server.received_requests().await.unwrap().len();
        let tools = mcp.request("tools/list", json!({})).await;
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        let tool = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == "project.list")
            .unwrap();
        let called=mcp.request("tools/call",json!({"name":tool["name"],"arguments":{"inputs":{"maxResults":2,"pageToken":token}}})).await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["result"],
            second["result"]
        );
        mcp.finish().await;
        let expected = match access {
            JiraAccess::AgentPerUser => "Bearer jira-per-user-token".to_string(),
            _ => format!("Basic {}", BASE64.encode("service@example.com:jira-token")),
        };
        for request in server.received_requests().await.unwrap() {
            assert_eq!(request.headers["authorization"], expected);
            assert_eq!(request.url.path(), ROUTE);
        }
        let audit = broker.audit().unwrap();
        audit.require_action("jira", "project.list");
        for output in [
            first.to_string(),
            second.to_string(),
            markdown,
            called.to_string(),
            audit.text().to_string(),
        ] {
            for denied in [
                "HIDDEN",
                "DENIED_PROJECT_NAME",
                "UNPROJECTED_OWNER",
                "989898",
                "jira-token",
                "jira-per-user-token",
            ] {
                assert!(!output.contains(denied), "{denied}: {output}");
            }
        }
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_project_listing_permission_is_independent_and_missing_credentials_hide_it() {
    let server = MockServer::start().await;
    let broker = start(&server, JiraAccess::AgentService, &["search"]).await;
    let base = broker.public_url();
    let denied = authenticated_jira_cli(&base)
        .args(["jira", "project", "list"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
    let broker = start(&server, JiraAccess::AgentService, &["project.list"]).await;
    let base = broker.public_url();
    let before = authenticated_jira_cli(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog before credential removal", &before);
    assert!(
        String::from_utf8(before.stdout)
            .unwrap()
            .contains("project.list")
    );
    std::fs::remove_file(broker.directory().join("jira-token.txt")).unwrap();
    let after = authenticated_jira_cli(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog after credential removal", &after);
    assert!(
        !String::from_utf8(after.stdout)
            .unwrap()
            .contains("project.list")
    );
    let denied = authenticated_jira_cli(&base)
        .args(["jira", "project", "list"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_project_listing_rechecks_subjects_contexts_and_winning_credential_modes() {
    let server = MockServer::start().await;
    mount(
        &server,
        0,
        true,
        json!([{"id":"1","key":"PROJ","name":"Visible"}]),
    )
    .await;
    let broker = start(&server, JiraAccess::AgentPerUser, &["project.list"]).await;
    let base = broker.public_url();
    let original: toml::Value =
        toml::from_str(&std::fs::read_to_string(broker.config_path()).unwrap()).unwrap();
    for mode in ["subject", "context", "mixed"] {
        let positive = checked(
            authenticated_jira_cli(&base)
                .args(["jira", "project", "list", "--max-results", "2"])
                .output()
                .unwrap(),
        );
        assert_eq!(positive["result"]["count"], 1);
        let mut changed = original.clone();
        match mode {
            "subject" => {
                changed["policy"]["grants"]
                    .as_array_mut()
                    .unwrap()
                    .truncate(1);
                for grant in changed["policy"]["grants"].as_array_mut().unwrap() {
                    grant["subjects"] = toml::Value::try_from(vec!["group:anonymous"]).unwrap();
                }
            }
            "context" => {
                for resource in changed["policy"]["resources"].as_array_mut().unwrap() {
                    resource["allowed_execution_contexts"] =
                        toml::Value::try_from(vec!["internal"]).unwrap();
                }
            }
            "mixed" => {
                let mut other = changed["policy"]["resources"][0].clone();
                other["id"] = "project-ops".into();
                other["selector"]["value"] = "OPS".into();
                changed["policy"]["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(other);
                changed["policy"]["grants"][0]["subjects"] =
                    toml::Value::try_from(vec!["user:agent-one"]).unwrap();
                changed["policy"]["grants"][0]["resources"]["resource_ids"] =
                    toml::Value::try_from(vec!["project-ops"]).unwrap();
            }
            _ => unreachable!(),
        }
        broker
            .rewrite_config(toml::to_string(&changed).unwrap())
            .unwrap();
        let reloaded = broker.reload().await.unwrap();
        assert!(reloaded.is_success(), "{mode}: {reloaded:?}");
        let before = server.received_requests().await.unwrap().len();
        let catalog = authenticated_jira_cli(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("catalog", &catalog);
        assert!(
            !String::from_utf8(catalog.stdout)
                .unwrap()
                .contains("project.list"),
            "{mode}"
        );
        let denied = authenticated_jira_cli(&base)
            .args(["jira", "project", "list", "--max-results", "2"])
            .output()
            .unwrap();
        assert!(!denied.status.success(), "{mode}");
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        broker
            .rewrite_config(toml::to_string(&original).unwrap())
            .unwrap();
        let reloaded = broker.reload().await.unwrap();
        assert!(reloaded.is_success(), "{mode}: {reloaded:?}");
    }
    let positive = checked(
        authenticated_jira_cli(&base)
            .args(["jira", "project", "list", "--max-results", "2"])
            .output()
            .unwrap(),
    );
    assert_eq!(positive["result"]["count"], 1);
    let before = server.received_requests().await.unwrap().len();
    std::fs::write(
        broker.directory().join("jira-per-user-store.json"),
        b"{\"credentials\":[]}",
    )
    .unwrap();
    let denied = authenticated_jira_cli(&base)
        .args(["jira", "project", "list", "--max-results", "2"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        before,
        "missing winning personal access fell back to service access"
    );
    stop(broker).await;
}
