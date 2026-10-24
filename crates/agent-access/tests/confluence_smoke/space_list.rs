//! Production Confluence transport behind the real broker and CLI; only Confluence is synthetic.
use super::*;
use agent_access_provider::REQUEST_ID_HEADER;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};
#[path = "../common/list_mcp.rs"]
mod list_mcp;

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const ROUTE: &str = "/ex/confluence/11111111-2222-4333-8444-555555555555/wiki/api/v2/spaces";

async fn start(server: &MockServer, access: ConfluenceAccess, actions: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value =
        toml::from_str(&listing_document(application.directory(), access)).unwrap();
    document.as_table_mut().unwrap().insert(
        "execution_context".into(),
        toml::from_str(
            "allowed_values = [\"default\", \"internal\"]\ndefault_context = \"default\"",
        )
        .unwrap(),
    );
    document["providers"]["confluence"]["allowed_upstream_hosts"] = toml::Value::try_from(vec![
        "https://api.atlassian.com/ex/confluence/**".to_string(),
        "https://example.atlassian.net/wiki/**".to_string(),
    ])
    .unwrap();
    document["providers"]["confluence"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["providers"]["confluence"]
        .as_table_mut()
        .unwrap()
        .insert(
            "listing".into(),
            toml::Value::try_from(BTreeMap::from([("max_candidate_pages", 1)])).unwrap(),
        );
    document["credentials"]["service"]["confluence"]
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
    }
    if matches!(access, ConfluenceAccess::AgentPerUser) {
        let file = application
            .directory()
            .join("confluence-per-user-store.json");
        let mut store: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        store["credentials"][0]["type"] = json!("bearer_token");
        store["credentials"][0]
            .as_object_mut()
            .unwrap()
            .remove("username_ref");
        std::fs::write(file, serde_json::to_vec(&store).unwrap()).unwrap();
    }
    let mut cfg: agent_access_confluence::ConfluenceProviderConfig =
        document["providers"]["confluence"]
            .clone()
            .try_into()
            .unwrap();
    cfg.allowed_upstream_hosts
        .push(format!("{}/**", server.uri()));
    let gateway = server.uri();
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "confluence",
            ProviderFixture::factory(move |context| {
                agent_access_confluence::test_support::provider_with_gateway(
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
async fn mount(server: &MockServer, offset: u64, last: bool, mut values: Value) {
    for item in values.as_array_mut().unwrap() {
        item["type"] = json!("global");
        item["status"] = json!("current");
    }
    let mut mock = Mock::given(method("GET"))
        .and(path(ROUTE))
        .and(query_param("limit", "2"))
        .and(query_param("status", "current"));
    mock = if offset == 0 {
        mock.and(wiremock::matchers::query_param_is_missing("cursor"))
    } else {
        mock.and(query_param("cursor", "A"))
    };
    let mut body = json!({"results":values});
    if !last {
        body["_links"] = json!({"next":"/wiki/api/v2/spaces?cursor=A&limit=2&status=current"});
    }
    mock.respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}
fn checked(output: std::process::Output) -> Value {
    assert_success("space listing", &output);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "allow", "{value}");
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_space_list_service_personal_cli_send_http_and_mcp() {
    for access in [
        ConfluenceAccess::AgentService,
        ConfluenceAccess::AgentPerUser,
    ] {
        let server = MockServer::start().await;
        mount(
            &server,
            0,
            false,
            json!([{"id":"9","key":"HIDDEN","name":"DENIED_SPACE_NAME"},{"id":"8","key":"EXCLUDED","name":"EXCLUDED_SPACE_NAME"}]),
        )
        .await;
        mount(&server,1,true,json!([{"id":"1","key":"ENG","name":"Visible space","owner":"UNPROJECTED_OWNER"},{"id":"2","key":"TeamDocs","name":"Unregistered space"}])).await;
        let broker = start(&server, access, &["space.list"]).await;
        let base = broker.public_url();
        let output = authenticated_confluence_cli(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("catalog", &output);
        let catalog: Value = serde_json::from_slice(&output.stdout).unwrap();
        let actions = catalog["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|service| service["service"] == "confluence")
            .unwrap()["actions"]
            .as_array()
            .unwrap();
        assert_eq!(actions.len(), 1, "{access:?}: {catalog}");
        assert_eq!(actions[0]["action"], "space.list");
        assert_eq!(actions[0]["readOnly"], true);
        assert_eq!(actions[0]["lookupRequired"], false);
        assert!(server.received_requests().await.unwrap().is_empty());
        let first = checked(
            authenticated_confluence_cli(&base)
                .args(["confluence", "space", "list", "--max-results", "2"])
                .output()
                .unwrap(),
        );
        assert_eq!(first["result"]["scanStatus"], "scan_budget");
        assert_eq!(first["result"]["count"], 0);
        let token = first["result"]["nextPageToken"].as_str().unwrap();
        let second = checked(
            authenticated_confluence_cli(&base)
                .args([
                    "confluence",
                    "space",
                    "list",
                    "--max-results",
                    "2",
                    "--page-token",
                    token,
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(second["result"]["items"][0]["key"], "ENG");
        if matches!(access, ConfluenceAccess::AgentPerUser) {
            assert_eq!(second["result"]["count"], 2);
            assert_eq!(second["result"]["items"][1]["key"], "TeamDocs");
        } else {
            assert_eq!(second["result"]["count"], 1);
        }
        assert_eq!(second["result"]["scanStatus"], "exhausted");
        let markdown = authenticated_confluence_cli(&base)
            .args([
                "confluence",
                "space",
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
            markdown.contains("Confluence spaces")
                && markdown.contains("Visible space")
                && markdown.contains("exhausted")
        );
        let send=json!({"version":"agent-access.send.v1","kind":"invoke","service":"confluence","action":"space.list","inputs":{"maxResults":2,"pageToken":token}}).to_string();
        let sent = checked(
            authenticated_confluence_cli(&base)
                .args(["send", "--request-json", &send])
                .output()
                .unwrap(),
        );
        assert_eq!(sent["result"], second["result"]);
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/confluence/space.list"))
            .header("X-Agent-Access-Identity-Token", "agent-token")
            .header(REQUEST_ID_HEADER, "confluence-space-http")
            .json(&json!({"inputs":{"maxResults":2,"pageToken":token}}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let http: Value = response.json().await.unwrap();
        assert_eq!(http["result"], second["result"]);
        let mut mcp = list_mcp::StdioMcp::start(authenticated_confluence_cli(&base));
        mcp.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"confluence-list-smoke","version":"1"}})).await;
        mcp.notify("notifications/initialized", json!({}));
        let before = server.received_requests().await.unwrap().len();
        let tools = mcp.request("tools/list", json!({})).await;
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        let tool = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == "space.list")
            .unwrap();
        let called=mcp.request("tools/call",json!({"name":tool["name"],"arguments":{"inputs":{"maxResults":2,"pageToken":token}}})).await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["result"],
            second["result"]
        );
        mcp.finish().await;
        let expected = match access {
            ConfluenceAccess::AgentPerUser => "Bearer confluence-per-user-token".to_string(),
            _ => format!(
                "Basic {}",
                BASE64.encode("service@example.com:confluence-token")
            ),
        };
        for request in server.received_requests().await.unwrap() {
            assert_eq!(request.headers["authorization"], expected);
            assert_eq!(request.url.path(), ROUTE);
        }
        let audit = broker.audit().unwrap();
        audit.require_action("confluence", "space.list");
        for output in [
            first.to_string(),
            second.to_string(),
            markdown,
            called.to_string(),
            audit
                .text()
                .lines()
                .map(|line| {
                    let event: Value = serde_json::from_str(line).unwrap();
                    event["providerAudit"]
                        .get("confluence")
                        .expect("Confluence provider audit")
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ] {
            for denied in [
                "HIDDEN",
                "EXCLUDED",
                "EXCLUDED_SPACE_NAME",
                "DENIED_SPACE_NAME",
                "UNPROJECTED_OWNER",
                "989898",
                "confluence-token",
                "confluence-per-user-token",
            ] {
                assert!(!output.contains(denied), "{denied}: {output}");
            }
        }
        // Host audit records configured exclusion keys as authority. Upstream
        // denied metadata must never appear anywhere in that record.
        for secret in [
            "EXCLUDED_SPACE_NAME",
            "DENIED_SPACE_NAME",
            "UNPROJECTED_OWNER",
            "confluence-token",
            "confluence-per-user-token",
        ] {
            assert!(!audit.text().contains(secret), "{secret}");
        }
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_space_listing_permission_is_independent_and_missing_credentials_hide_it() {
    let server = MockServer::start().await;
    let broker = start(&server, ConfluenceAccess::AgentService, &["search"]).await;
    let base = broker.public_url();
    let denied = authenticated_confluence_cli(&base)
        .args(["confluence", "space", "list"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
    let broker = start(&server, ConfluenceAccess::AgentService, &["space.list"]).await;
    let base = broker.public_url();
    let before = authenticated_confluence_cli(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog before credential removal", &before);
    assert!(
        String::from_utf8(before.stdout)
            .unwrap()
            .contains("space.list")
    );
    std::fs::remove_file(broker.directory().join("confluence-token.txt")).unwrap();
    let after = authenticated_confluence_cli(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog after credential removal", &after);
    assert!(
        !String::from_utf8(after.stdout)
            .unwrap()
            .contains("space.list")
    );
    let denied = authenticated_confluence_cli(&base)
        .args(["confluence", "space", "list"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_space_listing_rechecks_subjects_contexts_and_winning_credential_modes() {
    let server = MockServer::start().await;
    mount(
        &server,
        0,
        true,
        json!([{"id":"1","key":"ENG","name":"Visible"}]),
    )
    .await;
    let broker = start(&server, ConfluenceAccess::AgentPerUser, &["space.list"]).await;
    let base = broker.public_url();
    let original: toml::Value =
        toml::from_str(&std::fs::read_to_string(broker.config_path()).unwrap()).unwrap();
    for mode in ["subject", "context", "mixed"] {
        let positive = checked(
            authenticated_confluence_cli(&base)
                .args(["confluence", "space", "list", "--max-results", "2"])
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
                other["id"] = "space-ops".into();
                other["selector"]["value"] = "OPS".into();
                changed["policy"]["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(other);
                changed["policy"]["grants"][0]["subjects"] =
                    toml::Value::try_from(vec!["user:agent-one"]).unwrap();
                changed["policy"]["grants"][0]["resources"]["resource_ids"] =
                    toml::Value::try_from(vec!["space-ops"]).unwrap();
                // Disjoint winning regions are valid configuration but listing
                // must reject their mixed execution modes without a fallback.
                changed["policy"]["grants"][1]["resources"] =
                    toml::Value::try_from(BTreeMap::from([("resource_ids", vec!["space-eng"])]))
                        .unwrap();
            }
            _ => unreachable!(),
        }
        broker
            .rewrite_config(toml::to_string(&changed).unwrap())
            .unwrap();
        let reloaded = broker.reload().await.unwrap();
        assert!(reloaded.is_success(), "{mode}: {reloaded:?}");
        let before = server.received_requests().await.unwrap().len();
        let catalog = authenticated_confluence_cli(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("catalog", &catalog);
        assert!(
            !String::from_utf8(catalog.stdout)
                .unwrap()
                .contains("space.list"),
            "{mode}"
        );
        let denied = authenticated_confluence_cli(&base)
            .args(["confluence", "space", "list", "--max-results", "2"])
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
        authenticated_confluence_cli(&base)
            .args(["confluence", "space", "list", "--max-results", "2"])
            .output()
            .unwrap(),
    );
    assert_eq!(positive["result"]["count"], 1);
    let before = server.received_requests().await.unwrap().len();
    std::fs::write(
        broker.directory().join("confluence-per-user-store.json"),
        b"{\"credentials\":[]}",
    )
    .unwrap();
    let denied = authenticated_confluence_cli(&base)
        .args(["confluence", "space", "list", "--max-results", "2"])
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

#[derive(Clone, Copy, Debug)]
enum ConfluenceAccess {
    AgentService,
    AgentPerUser,
}
fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn authenticated_confluence_cli(base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base,
        "--token-value",
        "agent-token",
        "--identity-header",
        "X-Agent-Access-Identity-Token",
        "--identity-scheme",
        "raw",
    ]);
    command
}
fn listing_document(directory: &FixtureDir, access: ConfluenceAccess) -> String {
    let mut doc: toml::Value =
        toml::from_str(&confluence_document(directory, &["space.list"])).unwrap();
    doc["identity"] = toml::from_str(&format!(
        r#"
mode = "required"
authority = "toml"
[[sources]]
name = "local"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"
[[sources.principals]]
principal = "agent-one"
token_refs = [{}]
[[groups]]
id = "agents"
status = "active"
members = ["agent-one"]
"#,
        secret_ref(directory, "agent-token.txt", "agent-token")
    ))
    .unwrap();
    doc["policy"]["grants"][0]["subjects"] = toml::Value::try_from(vec!["group:agents"]).unwrap();
    let all = toml::from_str(
        r#"id="all-spaces"
resource_type="confluence_space"
selector={kind="all"}
allowed_execution_contexts=["default"]"#,
    )
    .unwrap();
    doc["policy"]["resources"].as_array_mut().unwrap().push(all);
    for (id, key) in [("space-hidden", "HIDDEN"), ("space-excluded", "EXCLUDED")] {
        let resource: toml::Value = toml::from_str(&format!(
            "id={id:?}\nresource_type=\"confluence_space\"\nselector={{kind=\"exact\",value={key:?}}}\nallowed_execution_contexts=[\"default\"]\nenabled=false"
        )).unwrap();
        doc["policy"]["resources"]
            .as_array_mut()
            .unwrap()
            .push(resource);
    }
    doc["policy"].as_table_mut().unwrap().insert(
        "resource_groups".into(),
        toml::Value::try_from(vec![
            toml::from_str::<toml::Value>(
                r#"
id="allowed-spaces"
name="Spaces with exclusions"
included_resource_ids=["all-spaces"]
excluded_resource_ids=["space-hidden","space-excluded"]
"#,
            )
            .unwrap(),
        ])
        .unwrap(),
    );

    if matches!(access, ConfluenceAccess::AgentPerUser) {
        let token = directory
            .secret_file("confluence-per-user-token.txt", "confluence-per-user-token")
            .unwrap();
        let store=directory.secret_file("confluence-per-user-store.json",json!({"credentials":[{"principal":"agent-one","type":"bearer_token","token_ref":format!("file:{}",token.display())}]}).to_string()).unwrap();
        doc["credentials"].as_table_mut().unwrap().insert(
            "per_user".into(),
            toml::from_str(&format!(
                "[confluence]\ntype=\"secret_store\"\nprovider=\"local_file\"\npath={}",
                toml_string(store.display())
            ))
            .unwrap(),
        );
        let mut grant = doc["policy"]["grants"][0].clone();
        grant["subjects"] = toml::Value::try_from(vec!["user:agent-one"]).unwrap();
        grant["resources"] = toml::Value::try_from(BTreeMap::from([(
            "resource_group_ids",
            vec!["allowed-spaces"],
        )]))
        .unwrap();
        grant["credential_mode"] = "per_user".into();
        doc["policy"]["grants"].as_array_mut().unwrap().push(grant);
    }
    toml::to_string(&doc).unwrap()
}
