//! Real CLI/Broker acceptance against the production Jira HTTP adapter.
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const API: &str = "/ex/jira/11111111-2222-4333-8444-555555555555/rest/api/3";
const ISSUE_BODY: &str = "private-batch-issue-description";
const COMMENT_BODY: &str = "private-batch-comment-body";
const READ_ACTIONS: &[&str] = &["issue.view", "comment.list", "comment.view"];

async fn start(
    server: &MockServer,
    actions: &[&str],
    personal_actions: Option<&[&str]>,
) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let access = if personal_actions.is_some() {
        JiraAccess::AgentPerUser
    } else {
        JiraAccess::AgentService
    };
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
    for kind in ["service", "lookup"] {
        document["credentials"][kind]["jira"]
            .as_table_mut()
            .unwrap()
            .insert("profile".into(), "atlassian-scoped-api-token".into());
    }
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        let selected = if grant["credential_mode"].as_str() == Some("per_user") {
            personal_actions.unwrap()
        } else {
            actions
        };
        grant["actions"] = toml::Value::try_from(selected).unwrap();
        grant["resources"] =
            toml::Value::try_from(BTreeMap::from([("resource_ids", vec!["project-proj"])]))
                .unwrap();
    }
    if personal_actions.is_some() {
        let file = application.directory().join("jira-per-user-store.json");
        let mut store: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        store["credentials"][0]["type"] = json!("bearer_token");
        store["credentials"][0]
            .as_object_mut()
            .unwrap()
            .remove("username_ref");
        std::fs::write(file, serde_json::to_vec(&store).unwrap()).unwrap();
    }
    let mut config: JiraProviderConfig = document["providers"]["jira"].clone().try_into().unwrap();
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
        .unwrap()
}

fn comment(index: u32) -> Value {
    let mut comment = json!({
        "id":(10000 + index).to_string(),
        "body":jira_adf_text(&format!("{COMMENT_BODY}-{index}")),
        "author":{"accountId":"synthetic-author", "displayName":"Example Author"},
        "created":format!("2026-06-{:02}T10:00:00.000+0000", index + 1),
        "updated":format!("2026-06-{:02}T10:00:00.000+0000", index + 1)
    });
    if index > 0 {
        comment["parentId"] = json!(10000);
    }
    comment
}

async fn mount(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{API}/issue/PROJ-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"20001", "key":"PROJ-1", "names":{}, "schema":{},
            "fields":{
                "project":{"key":"PROJ"}, "summary":"Batch comments",
                "issuetype":{"name":"Task"}, "status":{"name":"Open"},
                "description":jira_adf_text(ISSUE_BODY)
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/issue/PROJ-1/comment")))
        .respond_with(|request: &Request| {
            let parameters = request.url.query_pairs().collect::<BTreeMap<_, _>>();
            let start_at = parameters["startAt"].parse::<u32>().unwrap();
            let maximum = parameters["maxResults"].parse::<u32>().unwrap();
            let mut comments = (0..23).map(comment).collect::<Vec<_>>();
            if parameters.get("orderBy").map(|value| value.as_ref()) == Some("-created") {
                comments.reverse();
            }
            let comments = comments
                .into_iter()
                .skip(start_at as usize)
                .take(maximum as usize)
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(json!({
                "startAt":start_at, "maxResults":maximum, "total":23, "comments":comments
            }))
        })
        .mount(server)
        .await;
    for index in [2, 22] {
        Mock::given(method("GET"))
            .and(path(format!(
                "{API}/issue/PROJ-1/comment/{}",
                10000 + index
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(comment(index)))
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
    assert_success("comment body collection", &output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn tool<'a>(listing: &'a Value, action: &str) -> &'a Value {
    listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == action)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_comment_pages_accept_zero_upstream_maximum_across_read_modes() {
    let server = MockServer::start().await;
    mount(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("{API}/issue/PROJ-1/comment")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "startAt":0, "maxResults":0, "total":0, "comments":[]
        })))
        .with_priority(1)
        .expect(3)
        .mount(&server)
        .await;
    let broker = start(&server, READ_ACTIONS, None).await;
    let base = broker.public_url();

    for (arguments, embedded, include_bodies, requested_maximum) in [
        (
            vec!["jira", "issue", "comment", "list", "--issue", "PROJ-1"],
            false,
            false,
            "50",
        ),
        (
            vec![
                "jira",
                "issue",
                "comment",
                "list",
                "--issue",
                "PROJ-1",
                "--include-bodies",
                "--read-content-format",
                "text",
            ],
            false,
            true,
            "20",
        ),
        (
            vec![
                "jira",
                "issue",
                "view",
                "PROJ-1",
                "--include-comments",
                "--read-content-format",
                "text",
            ],
            true,
            true,
            "20",
        ),
    ] {
        let before = server.received_requests().await.unwrap().len();
        let result = run(&base, &arguments);
        let page = if embedded {
            &result["result"]["commentPage"]
        } else {
            &result["result"]
        };
        assert_eq!(page["comments"], json!([]));
        assert_eq!(page["startAt"], 0);
        assert_eq!(page["maxResults"], 0);
        assert_eq!(page["count"], 0);
        assert_eq!(page["total"], 0);
        assert_eq!(page["isLast"], true);
        assert!(page["nextStartAt"].is_null());
        assert_eq!(page["includeBodies"], include_bodies);
        assert_eq!(page["orderBy"], "+created");
        assert!(page.get("limitedBy").is_none());

        let requests = server.received_requests().await.unwrap();
        let collections = requests[before..]
            .iter()
            .filter(|request| request.url.path().ends_with("/comment"))
            .collect::<Vec<_>>();
        assert_eq!(collections.len(), 1);
        let parameters = collections[0].url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(parameters["startAt"], "0");
        assert_eq!(parameters["maxResults"], requested_maximum);
        assert_eq!(parameters["orderBy"], "+created");
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_bodies_are_opt_in_and_continue_in_batches_across_cli_and_mcp() {
    let server = MockServer::start().await;
    mount(&server).await;
    let broker = start(&server, READ_ACTIONS, None).await;
    let base = broker.public_url();

    let ordinary = run(&base, &["jira", "issue", "view", "PROJ-1"]);
    assert!(ordinary["result"].get("commentPage").is_none());
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| { !request.url.path().contains("/comment") })
    );

    let before = server.received_requests().await.unwrap().len();
    let embedded = run(
        &base,
        &[
            "jira",
            "issue",
            "view",
            "PROJ-1",
            "--include-comments",
            "--read-content-format",
            "text",
        ],
    );
    let page = &embedded["result"]["commentPage"];
    assert_eq!(page["count"], 20);
    assert_eq!(page["total"], 23);
    assert_eq!(page["isLast"], false);
    assert_eq!(page["nextStartAt"], 20);
    assert_eq!(page["orderBy"], "+created");
    assert_eq!(page["includeBodies"], true);
    assert_eq!(page["comments"][0]["commentId"], "10000");
    assert_eq!(page["comments"][1]["parentCommentId"], "10000");
    assert_eq!(
        page["comments"][0]["renderedBody"],
        json!({"format":"text", "value":format!("{COMMENT_BODY}-0")})
    );
    let requests = server.received_requests().await.unwrap();
    let collection = requests[before..]
        .iter()
        .filter(|request| request.url.path().ends_with("/comment"))
        .collect::<Vec<_>>();
    assert_eq!(
        collection.len(),
        1,
        "combined read must fetch one collection page"
    );
    let parameters = collection[0].url.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(parameters["startAt"], "0");
    assert_eq!(parameters["maxResults"], "20");
    assert_eq!(parameters["orderBy"], "+created");

    let metadata = run(
        &base,
        &["jira", "issue", "comment", "list", "--issue", "PROJ-1"],
    );
    assert_eq!(metadata["result"]["includeBodies"], false);
    assert_eq!(metadata["result"]["orderBy"], "+created");
    assert!(!metadata.to_string().contains(COMMENT_BODY));
    assert!(
        metadata["result"]["comments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item.get("body").is_none())
    );

    let next_offset = page["nextStartAt"].to_string();
    let continued = run(
        &base,
        &[
            "jira",
            "issue",
            "comment",
            "list",
            "--issue",
            "PROJ-1",
            "--include-bodies",
            "--start-at",
            &next_offset,
            "--read-content-format",
            "text",
        ],
    );
    assert_eq!(continued["result"]["count"], 3);
    assert_eq!(continued["result"]["isLast"], true);
    assert!(continued["result"]["nextStartAt"].is_null());
    assert_eq!(continued["result"]["comments"][0]["commentId"], "10020");
    assert_eq!(
        continued["result"]["comments"][0]["parentCommentId"],
        "10000"
    );
    assert_eq!(
        continued["result"]["comments"][2]["renderedBody"]["value"],
        format!("{COMMENT_BODY}-22")
    );

    for arguments in [
        vec![
            "jira",
            "issue",
            "view",
            "PROJ-1",
            "--include-comments",
            "--output-format",
            "markdown",
        ],
        vec![
            "jira",
            "issue",
            "comment",
            "list",
            "--issue",
            "PROJ-1",
            "--include-bodies",
            "--output-format",
            "markdown",
        ],
    ] {
        let output = cli(&base).args(arguments).output().unwrap();
        assert_success("comment body Markdown", &output);
        let markdown = String::from_utf8(output.stdout).unwrap();
        assert!(
            markdown.contains(&format!("{COMMENT_BODY}-0").replace('-', "\\-")),
            "{markdown}"
        );
        assert!(markdown.contains("10000"), "{markdown}");
        assert!(markdown.contains("20"), "{markdown}");
    }

    for (action, inputs) in [
        (
            "issue.view",
            json!({"issue":"PROJ-1", "includeComments":false}),
        ),
        (
            "comment.list",
            json!({"issue":"PROJ-1", "includeBodies":false}),
        ),
    ] {
        let request = json!({
            "version":"agent-access.send.v1", "kind":"invoke", "service":"jira",
            "action":action, "inputs":inputs, "readContentFormat":"text"
        });
        let result = run(&base, &["send", "--request-json", &request.to_string()]);
        assert!(!result.to_string().contains(COMMENT_BODY));
        if action == "issue.view" {
            assert!(result["result"].get("commentPage").is_none());
        }
    }

    let mut mcp = list_mcp::StdioMcp::start(cli(&base));
    mcp.request(
        "initialize",
        json!({
            "protocolVersion":"2025-11-25", "capabilities":{},
            "clientInfo":{"name":"jira-comments-smoke", "version":"1"}
        }),
    )
    .await;
    mcp.notify("notifications/initialized", json!({}));
    let before_list = server.received_requests().await.unwrap().len();
    let listing = mcp.request("tools/list", json!({})).await;
    assert_eq!(server.received_requests().await.unwrap().len(), before_list);
    for (action, flag) in [
        ("issue.view", "includeComments"),
        ("comment.list", "includeBodies"),
    ] {
        assert_eq!(
            tool(&listing, action)["inputSchema"]["properties"]["inputs"]["properties"][flag]["type"],
            "boolean"
        );
    }
    let called = mcp.request("tools/call", json!({
        "name":tool(&listing, "comment.list")["name"],
        "arguments":{"inputs":{"issue":"PROJ-1", "includeBodies":true, "startAt":20}, "readContentFormat":"text"}
    })).await;
    assert_eq!(called["result"]["isError"], false, "{called}");
    assert_eq!(
        called["result"]["structuredContent"]["result"],
        continued["result"]
    );
    mcp.finish().await;

    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| { !request.url.path().contains("/comment/") }),
        "batch reads must not fan out to individual comments"
    );

    // Metadata selection can still be followed by exact body reads in any order.
    for index in [22, 2] {
        let selected = run(
            &base,
            &[
                "jira",
                "issue",
                "comment",
                "view",
                &(10000 + index).to_string(),
                "--issue",
                "PROJ-1",
                "--read-content-format",
                "text",
            ],
        );
        assert_eq!(
            selected["result"]["comment"]["renderedBody"]["value"],
            format!("{COMMENT_BODY}-{index}")
        );
    }
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("includeComments"));
    assert!(audit.contains("includeBodies"));
    assert!(!audit.contains(COMMENT_BODY));
    assert!(!audit.contains(ISSUE_BODY));
    stop(broker).await;
}

async fn assert_denied_before_content(server: &MockServer, base: &str, arguments: &[&str]) {
    let before = server.received_requests().await.unwrap().len();
    let output = cli(base).args(arguments).output().unwrap();
    assert!(
        !output.status.success(),
        "body request unexpectedly succeeded"
    );
    let denied: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert_eq!(denied["reasonCode"], "service_action_denied", "{denied}");
    assert!(!denied.to_string().contains(COMMENT_BODY));
    for request in &server.received_requests().await.unwrap()[before..] {
        assert_eq!(request.url.path(), format!("{API}/issue/PROJ-1"));
        let parameters = request.url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            parameters["fields"], "project",
            "only scope resolution may precede denial"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_body_flags_preserve_independent_metadata_and_exact_read_grants() {
    for actions in [
        &["issue.view"][..],
        &["comment.list"][..],
        &["issue.view", "comment.list"][..],
        &["issue.view", "comment.view"][..],
    ] {
        let server = MockServer::start().await;
        mount(&server).await;
        let broker = start(&server, actions, None).await;
        let base = broker.public_url();
        if actions.contains(&"issue.view") {
            assert!(
                run(&base, &["jira", "issue", "view", "PROJ-1"])["result"]
                    .get("commentPage")
                    .is_none()
            );
            assert_denied_before_content(
                &server,
                &base,
                &["jira", "issue", "view", "PROJ-1", "--include-comments"],
            )
            .await;
        }
        if actions.contains(&"comment.list") {
            let metadata = run(
                &base,
                &["jira", "issue", "comment", "list", "--issue", "PROJ-1"],
            );
            assert!(!metadata.to_string().contains(COMMENT_BODY));
            assert_denied_before_content(
                &server,
                &base,
                &[
                    "jira",
                    "issue",
                    "comment",
                    "list",
                    "--issue",
                    "PROJ-1",
                    "--include-bodies",
                ],
            )
            .await;
        }
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_body_flags_do_not_fall_back_from_the_winning_personal_grant() {
    let server = MockServer::start().await;
    mount(&server).await;
    // A lower group grant permits every action as service, but the direct user's
    // exact body read wins in personal mode. It cannot authorize service-mode batches.
    let broker = start(&server, READ_ACTIONS, Some(&["comment.view"])).await;
    let base = broker.public_url();
    run(&base, &["jira", "issue", "view", "PROJ-1"]);
    run(
        &base,
        &["jira", "issue", "comment", "list", "--issue", "PROJ-1"],
    );
    assert_denied_before_content(
        &server,
        &base,
        &["jira", "issue", "view", "PROJ-1", "--include-comments"],
    )
    .await;
    assert_denied_before_content(
        &server,
        &base,
        &[
            "jira",
            "issue",
            "comment",
            "list",
            "--issue",
            "PROJ-1",
            "--include-bodies",
        ],
    )
    .await;
    let selected = run(
        &base,
        &[
            "jira",
            "issue",
            "comment",
            "view",
            "10022",
            "--issue",
            "PROJ-1",
            "--read-content-format",
            "text",
        ],
    );
    assert_eq!(
        selected["result"]["comment"]["renderedBody"]["value"],
        format!("{COMMENT_BODY}-22")
    );
    let requests = server.received_requests().await.unwrap();
    let exact = requests
        .iter()
        .find(|request| request.url.path().ends_with("/comment/10022"))
        .unwrap();
    assert_eq!(exact.headers["authorization"], "Bearer jira-per-user-token");
    stop(broker).await;
}
