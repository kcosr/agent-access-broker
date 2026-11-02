//! Real Broker, CLI and Jira HTTP provider; only the upstream Jira server is synthetic.
use super::search_access::{self as access, GrantShape, Tokens};
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const ROUTE: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3/search/jql";
const QUERY: &str = "project != PRIVATE AND project NOT IN (ARCHIVE, SANDBOX) AND key != PRIVATE-1 AND issuekey NOT IN (PRIVATE-2, OTHER-2) AND summary !~ \"obsolete\" AND description !~ \"deprecated\" AND cf[12345] !~ \"privateValue\"";
const CANONICAL: &str = "project != PRIVATE AND project NOT IN (ARCHIVE, SANDBOX) AND key != PRIVATE-1 AND key NOT IN (PRIVATE-2, OTHER-2) AND summary !~ \"obsolete\" AND description !~ \"deprecated\" AND cf[12345] !~ \"privateValue\"";

async fn start(server: &MockServer, shape: GrantShape) -> (RunningBroker, Tokens) {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value = toml::from_str(&jira_document(
        application.directory(),
        JiraAccess::AnonymousService,
    ))
    .unwrap();
    let tokens = access::configure(
        &application,
        &mut document,
        "jira",
        JIRA_PROJECT_RESOURCE.id().as_str(),
        ["PROJ", "OTHER"],
        &["search"],
        shape,
    );
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["providers"]["jira"]["allowed_upstream_hosts"] =
        toml::Value::try_from(vec!["https://api.atlassian.com/ex/jira/**"]).unwrap();
    document["credentials"]["service"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert("profile".into(), "atlassian-scoped-api-token".into());
    let mut config: JiraProviderConfig = document["providers"]["jira"].clone().try_into().unwrap();
    config
        .allowed_upstream_hosts
        .push(format!("{}/**", server.uri()));
    let gateway = server.uri();
    let broker = application
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
        .unwrap();
    (broker, tokens)
}

async fn mount(server: &MockServer) -> Arc<Mutex<String>> {
    let project = Arc::new(Mutex::new("PROJ".to_string()));
    let returned = project.clone();
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(move |_: &wiremock::Request| {
            let project = returned.lock().unwrap().clone();
            let mut issues = vec![json!({
                "id":"60001","key":"PROJ-1","fields":{"project":{"key":"PROJ"},
                "summary":"Visible result"}
            })];
            if project != "PROJ" {
                issues.push(json!({
                    "id":"60002","key":format!("{project}-2"),
                    "fields":{"project":{"key":project},"summary":"DENIED_CONTENT"}
                }));
            }
            ResponseTemplate::new(200).set_body_json(json!({"isLast":true,"issues":issues}))
        })
        .mount(server)
        .await;
    project
}

fn inputs(query: &str) -> Value {
    json!({"query":{"type":"jql","value":query}})
}

fn allowed(value: &Value) {
    assert_eq!(value["decision"], "allow", "{value}");
    assert_eq!(value["result"]["issues"][0]["key"], "PROJ-1", "{value}");
}

async fn last_query(server: &MockServer, expected: &str) {
    let requests = server.received_requests().await.unwrap();
    let request = requests.last().unwrap();
    assert_eq!(request.url.path(), ROUTE);
    assert_eq!(
        request
            .url
            .query_pairs()
            .find(|(key, _)| key == "jql")
            .unwrap()
            .1,
        expected
    );
    assert!(
        requests.iter().all(|request| request.url.path() == ROUTE),
        "negative operands must not cause lookups"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_exclusions_keep_token_scope_across_cli_send_http_and_mcp() {
    let server = MockServer::start().await;
    let returned = mount(&server).await;
    let (broker, tokens) = start(&server, GrantShape::Finite).await;
    let documentation = access::documentation(
        &broker,
        &tokens.narrowed,
        "jira",
        "search",
        &["project", "key"],
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    let expected = format!("({CANONICAL}) AND project IN (PROJ)");
    for value in [
        access::run(
            &broker,
            &tokens.narrowed,
            &["jira", "issue", "search", "--jql", QUERY],
            true,
        ),
        access::invoke(
            &broker,
            &tokens.narrowed,
            "jira.search",
            &inputs(QUERY),
            true,
        ),
        access::send(&broker, &tokens.narrowed, "jira", "search", &inputs(QUERY)),
        access::http(&broker, &tokens.narrowed, "jira", "search", &inputs(QUERY)).await,
    ] {
        allowed(&value);
    }
    let mut mcp = list_mcp::StdioMcp::start(access::cli(&broker, &tokens.narrowed));
    mcp.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"jira-exclusions","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let listing = mcp.request("tools/list", json!({})).await;
    let tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "search")
        .unwrap();
    assert!(tool.get("documentation").is_none());
    assert!(
        tool["description"]
            .as_str()
            .unwrap()
            .contains("text negation")
    );
    assert!(tool["inputSchema"]["properties"]["inputs"]["properties"]["query"]["properties"]["value"]["description"]
        .as_str().unwrap().contains("text negation"));
    let described = mcp
        .request(
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"jira","action":"search"}}),
        )
        .await;
    assert_eq!(
        described["result"]["structuredContent"]["documentation"],
        documentation
    );
    let called = mcp
        .request(
            "tools/call",
            json!({"name":tool["name"],"arguments":{"inputs":inputs(QUERY)}}),
        )
        .await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    allowed(&called["result"]["structuredContent"]);
    let invalid = mcp.request("tools/call",json!({"name":tool["name"],"arguments":{"inputs":{"query":{"type":"jql","value":QUERY},"projects":["*"]}}})).await;
    access::denied(&invalid["result"]["structuredContent"], "input_invalid");
    mcp.finish().await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 5);
    for request in requests {
        assert_eq!(request.url.path(), ROUTE);
        assert_eq!(
            request
                .url
                .query_pairs()
                .find(|(key, _)| key == "jql")
                .unwrap()
                .1,
            expected
        );
    }
    access::negation_audit(
        &broker,
        "jira",
        "search",
        &inputs(QUERY)["query"],
        4,
        &[
            ("summary", "obsolete"),
            ("description", "deprecated"),
            ("cf[12345]", "privateValue"),
        ],
    );

    let grouped = "project = PRIVATE OR (summary !~ \"obsolete\" AND key != PRIVATE-1)";
    allowed(&access::invoke(
        &broker,
        &tokens.narrowed,
        "jira.search",
        &inputs(grouped),
        true,
    ));
    last_query(&server, &format!("({grouped}) AND project IN (PROJ)")).await;
    allowed(&access::invoke(
        &broker,
        &tokens.narrowed,
        "jira.search",
        &json!({"query":{"type":"text","value":"*"}}),
        true,
    ));
    last_query(&server, "(text ~ \"*\") AND project IN (PROJ)").await;
    allowed(&access::invoke(
        &broker,
        &tokens.unrestricted,
        "jira.search",
        &inputs(QUERY),
        true,
    ));
    last_query(
        &server,
        &format!("({CANONICAL}) AND project IN (OTHER, PROJ)"),
    )
    .await;

    let before = server.received_requests().await.unwrap().len();
    for invalid in [
        json!({"query":{"type":"jql","value":QUERY},"projects":["*"]}),
        json!({"query":{"type":"jql","value":QUERY},"projects":[]}),
        inputs("project = \"*\""),
        inputs("project = *"),
        inputs("key != \"*\""),
        inputs("text !~ \"PRIVATE_LITERAL\""),
        inputs("status !~ \"PRIVATE_LITERAL\""),
        inputs("cf[12345] !~ PRIVATE_LITERAL"),
    ] {
        access::denied(
            &access::http(&broker, &tokens.narrowed, "jira", "search", &invalid).await,
            "input_invalid",
        );
    }
    for token in [&tokens.disjoint, &tokens.ungranted] {
        access::denied(
            &access::http(&broker, token, "jira", "search", &inputs(QUERY)).await,
            "service_action_denied",
        );
    }
    for project in ["PRIVATE", "OTHER"] {
        access::denied(
            &access::http(
                &broker,
                &tokens.narrowed,
                "jira",
                "search",
                &json!({"query":{"type":"jql","value":QUERY},"projects":[project]}),
            )
            .await,
            "service_action_denied",
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), before);

    *returned.lock().unwrap() = "OTHER".into();
    access::denied(
        &access::invoke(
            &broker,
            &tokens.narrowed,
            "jira.search",
            &inputs(QUERY),
            false,
        ),
        "scope_unresolved",
    );
    assert_eq!(server.received_requests().await.unwrap().len(), before + 1);
    let audit = broker
        .audit()
        .unwrap()
        .records()
        .into_iter()
        .map(|record| record.to_string())
        .collect::<String>();
    assert!(!audit.contains("DENIED_CONTENT"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_exclusions_keep_all_except_policy_and_reject_unbounded_dispatch() {
    let server = MockServer::start().await;
    let returned = mount(&server).await;
    let (broker, tokens) = start(&server, GrantShape::AllExcept).await;
    // Naming/excluding PRIVATE is a filter, not a request to acquire PRIVATE authority.
    let query = "project = PRIVATE OR (summary !~ \"obsolete\" AND status = Done)";
    allowed(&access::invoke(
        &broker,
        &tokens.unrestricted,
        "jira.search",
        &inputs(query),
        true,
    ));
    last_query(&server, &format!("({query}) AND project NOT IN (PRIVATE)")).await;
    let before = server.received_requests().await.unwrap().len();
    for query in [
        "project != PRIVATE",
        "issuekey NOT IN (PRIVATE-1)",
        "project != PRIVATE OR (key != OTHER-1 AND project NOT IN (ARCHIVE))",
        "summary !~ \"obsolete\"",
        "description !~ \"deprecated\" AND cf[12345] !~ \"privateValue\"",
        "summary !~ \"obsolete\" OR (key != OTHER-1 AND description !~ \"deprecated\")",
    ] {
        access::denied(
            &access::invoke(
                &broker,
                &tokens.unrestricted,
                "jira.search",
                &inputs(query),
                false,
            ),
            "input_invalid",
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    allowed(&access::invoke(
        &broker,
        &tokens.narrowed,
        "jira.search",
        &inputs(QUERY),
        true,
    ));
    last_query(&server, &format!("({CANONICAL}) AND project IN (PROJ)")).await;
    *returned.lock().unwrap() = "PRIVATE".into();
    access::denied(
        &access::http(
            &broker,
            &tokens.unrestricted,
            "jira",
            "search",
            &inputs(query),
        )
        .await,
        "scope_unresolved",
    );
    stop(broker).await;
}
