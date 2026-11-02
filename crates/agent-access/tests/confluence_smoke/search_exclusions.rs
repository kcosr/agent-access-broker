//! Real Broker, CLI and Confluence HTTP provider with synthetic page/blog responses.
use super::search_access::{self as access, GrantShape, Tokens};
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const ROUTE: &str =
    "/ex/confluence/11111111-2222-4333-8444-555555555555/wiki/rest/api/content/search";
const QUERY: &str = "space != PRIVATE AND space NOT IN (ARCHIVE, SANDBOX) AND id != 999 AND content.id NOT IN (888, 777)";
const CANONICAL: &str =
    "space != PRIVATE AND space NOT IN (ARCHIVE, SANDBOX) AND id != 999 AND id NOT IN (888, 777)";

async fn start(server: &MockServer, shape: GrantShape) -> (RunningBroker, Tokens) {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value = toml::from_str(&confluence_document(
        application.directory(),
        &["search", "blog.search"],
    ))
    .unwrap();
    let tokens = access::configure(
        &application,
        &mut document,
        "confluence",
        CONFLUENCE_SPACE_RESOURCE.id().as_str(),
        ["ENG", "OPS"],
        &["search", "blog.search"],
        shape,
    );
    document["providers"]["confluence"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["providers"]["confluence"]["allowed_upstream_hosts"] =
        toml::Value::try_from(vec!["https://api.atlassian.com/ex/confluence/**"]).unwrap();
    document["credentials"]["service"]["confluence"]
        .as_table_mut()
        .unwrap()
        .insert("profile".into(), "atlassian-scoped-api-token".into());
    let mut config: ConfluenceProviderConfig = document["providers"]["confluence"]
        .clone()
        .try_into()
        .unwrap();
    config
        .allowed_upstream_hosts
        .push(format!("{}/**", server.uri()));
    let gateway = server.uri();
    let broker = application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "confluence",
            ProviderFixture::factory(move |context| {
                agent_access_confluence::test_support::provider_with_gateway(
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
    let space = Arc::new(Mutex::new("ENG".to_string()));
    let returned = space.clone();
    Mock::given(method("GET")).and(path(ROUTE)).respond_with(move |request: &wiremock::Request| {
        let space = returned.lock().unwrap().clone();
        let cql = request.url.query_pairs().find(|(key,_)|key=="cql").unwrap().1;
        let kind = if cql.contains("type = blogpost") {"blogpost"} else {"page"};
        ResponseTemplate::new(200).set_body_json(json!({"results":[{
            "id":"123456","type":kind,"status":"current","space":{"key":space},
            "title":if space=="ENG" {"Visible result"} else {"DENIED_CONTENT"},"version":{"number":1}
        }]}))
    }).mount(server).await;
    space
}

fn inputs(query: &str) -> Value {
    json!({"query":{"type":"cql","value":query}})
}

fn allowed(value: &Value, action: &str) {
    assert_eq!(value["decision"], "allow", "{value}");
    let collection = if action == "search" { "pages" } else { "blogs" };
    assert_eq!(value["result"][collection][0]["id"], "123456", "{value}");
}

async fn last_query(server: &MockServer, expected: &str) {
    let requests = server.received_requests().await.unwrap();
    let request = requests.last().unwrap();
    assert_eq!(request.url.path(), ROUTE);
    assert_eq!(
        request
            .url
            .query_pairs()
            .find(|(key, _)| key == "cql")
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
async fn confluence_exclusions_keep_token_scope_across_cli_send_http_and_mcp() {
    let server = MockServer::start().await;
    let returned = mount(&server).await;
    let (broker, tokens) = start(&server, GrantShape::Finite).await;
    for (action, command, kind) in [
        ("search", "page", "page"),
        ("blog.search", "blog", "blogpost"),
    ] {
        let before = server.received_requests().await.unwrap().len();
        let documentation = access::documentation(
            &broker,
            &tokens.narrowed,
            "confluence",
            action,
            &["space", "id"],
        );
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        let qualified = format!("confluence.{action}");
        let expected = format!("type = {kind} AND space IN (ENG) AND ({CANONICAL})");
        for value in [
            access::run(
                &broker,
                &tokens.narrowed,
                &["confluence", command, "search", "--cql", QUERY],
                true,
            ),
            access::invoke(&broker, &tokens.narrowed, &qualified, &inputs(QUERY), true),
            access::send(
                &broker,
                &tokens.narrowed,
                "confluence",
                action,
                &inputs(QUERY),
            ),
            access::http(
                &broker,
                &tokens.narrowed,
                "confluence",
                action,
                &inputs(QUERY),
            )
            .await,
        ] {
            allowed(&value, action);
        }
        let mut mcp = list_mcp::StdioMcp::start(access::cli(&broker, &tokens.narrowed));
        mcp.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"confluence-exclusions","version":"1"}})).await;
        mcp.notify("notifications/initialized", json!({}));
        let listing = mcp.request("tools/list", json!({})).await;
        let tool = listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == action)
            .unwrap();
        assert!(tool.get("documentation").is_none());
        let described = mcp.request("tools/call",json!({"name":"actions_describe","arguments":{"service":"confluence","action":action}})).await;
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
        allowed(&called["result"]["structuredContent"], action);
        let invalid = mcp.request("tools/call",json!({"name":tool["name"],"arguments":{"inputs":{"query":{"type":"cql","value":QUERY},"spaces":["*"]}}})).await;
        access::denied(&invalid["result"]["structuredContent"], "input_invalid");
        mcp.finish().await;
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), before + 5);
        for request in &requests[before..] {
            assert_eq!(request.url.path(), ROUTE);
            assert_eq!(
                request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "cql")
                    .unwrap()
                    .1,
                expected
            );
        }

        let grouped = "space = PRIVATE OR (space != ARCHIVE AND id != 999)";
        allowed(
            &access::invoke(
                &broker,
                &tokens.narrowed,
                &qualified,
                &inputs(grouped),
                true,
            ),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space IN (ENG) AND ({grouped})"),
        )
        .await;
        allowed(
            &access::invoke(
                &broker,
                &tokens.narrowed,
                &qualified,
                &json!({"query":{"type":"text","value":"*"}}),
                true,
            ),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space IN (ENG) AND (title ~ \"*\")"),
        )
        .await;
        allowed(
            &access::invoke(
                &broker,
                &tokens.unrestricted,
                &qualified,
                &inputs(QUERY),
                true,
            ),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space IN (ENG, OPS) AND ({CANONICAL})"),
        )
        .await;

        let before = server.received_requests().await.unwrap().len();
        for invalid in [
            json!({"query":{"type":"cql","value":QUERY},"spaces":["*"]}),
            json!({"query":{"type":"cql","value":QUERY},"spaces":[]}),
            inputs("space = \"*\""),
            inputs("space = *"),
            inputs("id != \"*\""),
        ] {
            access::denied(
                &access::http(&broker, &tokens.narrowed, "confluence", action, &invalid).await,
                "input_invalid",
            );
        }
        for token in [&tokens.disjoint, &tokens.ungranted] {
            access::denied(
                &access::http(&broker, token, "confluence", action, &inputs(QUERY)).await,
                "service_action_denied",
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        *returned.lock().unwrap() = "OPS".into();
        access::denied(
            &access::invoke(&broker, &tokens.narrowed, &qualified, &inputs(QUERY), false),
            "scope_unresolved",
        );
        assert_eq!(server.received_requests().await.unwrap().len(), before + 1);
        *returned.lock().unwrap() = "ENG".into();
    }
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
async fn confluence_exclusions_keep_all_except_policy_for_pages_and_blogs() {
    let server = MockServer::start().await;
    let returned = mount(&server).await;
    let (broker, tokens) = start(&server, GrantShape::AllExcept).await;
    for (action, kind) in [("search", "page"), ("blog.search", "blogpost")] {
        let qualified = format!("confluence.{action}");
        allowed(
            &access::invoke(
                &broker,
                &tokens.unrestricted,
                &qualified,
                &inputs(QUERY),
                true,
            ),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space NOT IN (PRIVATE) AND ({CANONICAL})"),
        )
        .await;
        let grouped = "space = PRIVATE OR (space != ARCHIVE AND id != 999)";
        allowed(
            &access::invoke(
                &broker,
                &tokens.unrestricted,
                &qualified,
                &inputs(grouped),
                true,
            ),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space NOT IN (PRIVATE) AND ({grouped})"),
        )
        .await;
        allowed(
            &access::invoke(&broker, &tokens.narrowed, &qualified, &inputs(QUERY), true),
            action,
        );
        last_query(
            &server,
            &format!("type = {kind} AND space IN (ENG) AND ({CANONICAL})"),
        )
        .await;
        *returned.lock().unwrap() = "PRIVATE".into();
        access::denied(
            &access::http(
                &broker,
                &tokens.unrestricted,
                "confluence",
                action,
                &inputs(QUERY),
            )
            .await,
            "scope_unresolved",
        );
        *returned.lock().unwrap() = "ENG".into();
    }
    stop(broker).await;
}
