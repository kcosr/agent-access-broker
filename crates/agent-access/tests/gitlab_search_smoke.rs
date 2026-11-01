//! Independent acceptance of repository discovery and native content search.
//! Real CLI and HTTP MCP clients exercise the production Broker/GitLab assembly;
//! only GitLab's HTTP responses and credentials are synthetic.
#[path = "gitlab_search_smoke/fixture.rs"]
mod fixture;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fixture::{
    ACTIONS, CATEGORIES, Credentials, FIRST_PROJECT, FORBIDDEN, Fixture, QUERY, SECOND_PROJECT,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

fn action_inputs(action: &str) -> Value {
    if matches!(action, "project.list" | "project.search") {
        json!({"maxResults":4})
    } else {
        json!({"search":QUERY,"maxResults":4})
    }
}

fn successful_cli(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "allow", "{value}");
    assert_private(&String::from_utf8_lossy(&output.stdout));
    assert_private(&String::from_utf8_lossy(&output.stderr));
    value
}

fn assert_private(text: &str) {
    for forbidden in FORBIDDEN.into_iter().chain([
        "search-service-token",
        "search-personal-token",
        "search-oauth-access-",
        "search-oauth-refresh-",
        "synthetic-oauth-client-secret",
    ]) {
        assert!(
            !text.contains(forbidden),
            "search output disclosed a forbidden fixture marker: {forbidden}"
        );
    }
}

fn assert_no_hidden_ids(value: &Value) {
    for component in value
        .to_string()
        .split(|character: char| !character.is_ascii_digit())
    {
        assert!(
            !matches!(component, "9901" | "9902" | "9903" | "9904" | "9905"),
            "a discarded candidate ID reached public metadata"
        );
    }
}

fn assert_projects(result: &Value, expected: &[&str]) {
    let items = result["items"].as_array().unwrap();
    let projects: Vec<_> = items
        .iter()
        .map(|item| item["project"].as_str().unwrap())
        .collect();
    assert_eq!(projects, expected);
    assert_eq!(result["count"].as_u64().unwrap(), items.len() as u64);
    assert_eq!(result["maxResults"], 4);
    for removed in [
        "total",
        "totalPages",
        "scannedCount",
        "excludedCount",
        "hasMoreResults",
    ] {
        assert!(result.get(removed).is_none(), "{removed} was disclosed");
    }
    for item in items {
        for key in ["id", "projectId", "sourceProjectId", "targetProjectId"] {
            assert!(
                !item[key].as_u64().is_some_and(|id| id >= 9900),
                "unauthorized ownership reached {key}"
            );
        }
    }
    assert_private(&result.to_string());
}

/// The public envelope has a fixed header and encrypted fixed-size payload.
/// Cryptographic vectors live in the SDK tests; this verifies the public wire
/// observed by a client has neither plaintext search state nor candidate data.
fn confidential_token(result: &Value) -> (String, Vec<u8>) {
    let token = result["nextPageToken"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 99);
    let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(decoded.len(), 74);
    assert_eq!(&decoded[..4], b"AACE");
    for text in [
        QUERY,
        "empty-page-query",
        FIRST_PROJECT,
        SECOND_PROJECT,
        FORBIDDEN[0],
        "search-service-token",
    ] {
        assert!(
            !decoded
                .windows(text.len())
                .any(|window| window == text.as_bytes())
        );
    }
    assert!(
        !decoded[26..].windows(23).any(|window| window == [0; 23]),
        "plaintext padding exposed"
    );
    (token, decoded)
}

async fn mcp_json(response: reqwest::Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_private(&body);
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(&body).unwrap();
    }
    let messages: Vec<Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|value| value.get("id").is_some())
        .collect();
    assert_eq!(messages.len(), 1);
    messages.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_collections_and_all_six_categories_use_service_credentials_through_cli_and_http_mcp()
 {
    assert_project_collections_and_categories(Credentials::Service).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_collections_and_all_six_categories_use_personal_credentials_through_cli_and_http_mcp()
 {
    assert_project_collections_and_categories(Credentials::Personal).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_collections_and_all_six_categories_use_oauth_credentials_through_cli_and_http_mcp()
{
    assert_project_collections_and_categories(Credentials::OAuth).await;
}

async fn assert_project_collections_and_categories(credentials: Credentials) {
    let fixture = Fixture::start(credentials, &ACTIONS).await;
    for command in ["search", "list"] {
        let before = fixture.requests().await.len();
        let discovery =
            successful_cli(fixture.cli(&["gitlab", "project", command, "--max-results", "4"]));
        assert_projects(&discovery["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
        // The nested project has no exact resource entry: the namespace discovers it.
        assert_eq!(discovery["resourceScopes"]["repository"], json!(["*"]));
        assert_eq!(discovery["result"]["scanStatus"], "more");
        let discovery_token = confidential_token(&discovery["result"]).0;
        let requests = fixture.requests().await;
        assert_eq!(
            requests.len() - before,
            1,
            "discovery redundantly confirmed project IDs"
        );
        assert_eq!(requests[before].url.path(), "/api/v4/projects");
        let terminal = successful_cli(fixture.cli(&[
            "gitlab",
            "project",
            command,
            "--max-results",
            "4",
            "--page-token",
            &discovery_token,
        ]));
        assert_projects(&terminal["result"], &[]);
        assert_eq!(terminal["result"]["scanStatus"], "exhausted");
        assert!(terminal["result"].get("nextPageToken").is_none());
        assert_eq!(fixture.requests().await.len() - before, 2);
    }

    let listing_markdown = fixture.cli(&[
        "gitlab",
        "project",
        "list",
        "--max-results",
        "4",
        "--output-format",
        "markdown",
    ]);
    assert!(listing_markdown.status.success());
    let listing_markdown = String::from_utf8(listing_markdown.stdout).unwrap();
    for marker in [
        "GitLab projects",
        "Scan status",
        "more",
        "Continuation",
        FIRST_PROJECT,
        SECOND_PROJECT,
    ] {
        assert!(listing_markdown.contains(marker), "missing {marker}");
    }
    assert_private(&listing_markdown);

    for (command, _) in CATEGORIES {
        let response = successful_cli(fixture.cli(&[
            "gitlab",
            "search",
            command,
            "--search",
            QUERY,
            "--engine",
            "advanced",
            "--max-results",
            "4",
        ]));
        assert_projects(&response["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
        assert_eq!(response["result"]["engine"], "advanced");
        assert_eq!(response["result"]["scanStatus"], "exhausted");
        assert!(response["result"].get("nextPageToken").is_none());
    }
    let rendered = fixture.cli(&[
        "gitlab",
        "search",
        "code",
        "--search",
        QUERY,
        "--max-results",
        "4",
        "--output-format",
        "markdown",
    ]);
    assert!(rendered.status.success());
    let rendered = String::from_utf8(rendered.stdout).unwrap();
    assert_private(&rendered);
    assert!(rendered.contains(FIRST_PROJECT));
    assert!(rendered.contains(SECOND_PROJECT));

    let initialize = fixture.mcp_request(None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"gitlab-search-smoke","version":"1"}
        }})).await;
    assert_eq!(initialize.status(), StatusCode::OK);
    let session = initialize.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp_json(initialize).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    let initialized = fixture
        .mcp_request(
            Some(&session),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    let before_listing = fixture.requests().await.len();
    let listing = mcp_json(
        fixture
            .mcp_request(
                Some(&session),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            )
            .await,
    )
    .await;
    assert_eq!(
        fixture.requests().await.len(),
        before_listing,
        "MCP discovery contacted GitLab"
    );
    let tools = listing["result"]["tools"].as_array().unwrap();
    for (index, action) in ACTIONS.iter().enumerate() {
        let tool = tools
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == *action)
            .unwrap_or_else(|| panic!("missing {action}"));
        let inputs = action_inputs(action);
        let called = mcp_json(
            fixture
                .mcp_request(
                    Some(&session),
                    json!({"jsonrpc":"2.0","id":10+index,"method":"tools/call","params":{
                        "name":tool["name"],"arguments":{"inputs":inputs}
                    }}),
                )
                .await,
        )
        .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_projects(
            &called["result"]["structuredContent"]["result"],
            &[FIRST_PROJECT, SECOND_PROJECT],
        );
    }
    assert!(
        !tools
            .iter()
            .any(|tool| tool["_meta"]["agent-access/action"] == "file.view")
    );
    fixture.close_mcp(&session).await;

    for request in fixture
        .requests()
        .await
        .iter()
        .filter(|request| request.url.path().starts_with("/api/v4/"))
    {
        assert_eq!(
            request
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            credentials.authorization()
        );
    }
    let audit = fixture.broker.audit().unwrap();
    for action in ACTIONS {
        audit.require_action("gitlab", action);
    }
    for record in audit.records() {
        assert_no_hidden_ids(&record["objectIds"]);
        assert_no_hidden_ids(&record["providerAudit"]);
    }
    assert_private(&audit.text());
    // The query is a declared audit input of every content search.
    let recorded_query = json!({"input":"search","label":"Search","value":QUERY});
    for action in ACTIONS
        .iter()
        .filter(|action| action.starts_with("search."))
    {
        for record in audit.require_action("gitlab", action) {
            assert!(
                record["auditInputs"]
                    .as_array()
                    .is_some_and(|inputs| inputs.contains(&recorded_query)),
                "{action} did not record its query: {record}"
            );
        }
    }
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namespace_holes_token_restrictions_and_action_grants_are_independent() {
    let fixture = Fixture::start(Credentials::Service, &ACTIONS).await;
    for action in ACTIONS {
        let inputs = action_inputs(action);
        let (status, response) = fixture.invoke(&fixture.narrow_token, action, inputs).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_projects(&response["result"], &[FIRST_PROJECT]);
        assert_eq!(
            response["resourceScopes"]["repository"],
            json!([FIRST_PROJECT])
        );
    }
    let before = fixture.requests().await.len();
    for action in &ACTIONS[1..] {
        let (status, response) = fixture
            .invoke(&fixture.discovery_token, action, action_inputs(action))
            .await;
        assert!(!status.is_success(), "{response}");
        assert_ne!(response["decision"], "allow");
        assert_private(&response.to_string());
    }
    assert_eq!(
        fixture.requests().await.len(),
        before,
        "a token-denied search reached GitLab"
    );
    // Each action grant stands alone, independently of the token's action set.
    let original = std::fs::read_to_string(fixture.broker.config_path()).unwrap();
    let all_actions = format!("actions = {}", serde_json::to_string(&ACTIONS).unwrap());
    for granted in ACTIONS {
        let document = original.replace(&all_actions, &format!("actions = [\"{granted}\"]"));
        assert_ne!(document, original);
        std::fs::write(fixture.broker.config_path(), document).unwrap();
        assert!(fixture.broker.reload().await.unwrap().is_success());
        let inputs = action_inputs(granted);
        let (status, response) = fixture.invoke(&fixture.token, granted, inputs).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_projects(&response["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
        let before = fixture.requests().await.len();
        for denied in ACTIONS.into_iter().filter(|action| *action != granted) {
            let inputs = action_inputs(denied);
            let (status, response) = fixture.invoke(&fixture.token, denied, inputs).await;
            assert!(
                !status.is_success(),
                "{granted} authorized {denied}: {response}"
            );
        }
        assert_eq!(fixture.requests().await.len(), before);
    }
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "file.view",
            json!({"project":FIRST_PROJECT,"path":"src/rotation.rs","ref":"main"}),
        )
        .await;
    assert!(
        !status.is_success(),
        "search grant authorized an ordinary read: {response}"
    );
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confidential_empty_pages_resume_without_losing_hits_and_reject_stale_authority() {
    let fixture = Fixture::start(Credentials::Service, &ACTIONS).await;
    let inputs = json!({"search":"empty-page-query","maxResults":4});
    let (status, first) = fixture
        .invoke(&fixture.token, "search.issues", inputs.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_projects(&first["result"], &[]);
    assert_eq!(first["result"]["scanStatus"], "scan_budget");
    let (first_token, first_bytes) = confidential_token(&first["result"]);
    let markdown = fixture.cli(&[
        "gitlab",
        "search",
        "issues",
        "--search",
        "empty-page-query",
        "--max-results",
        "4",
        "--output-format",
        "markdown",
    ]);
    assert!(markdown.status.success());
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.contains("No matching authorized items in this page; continue the search."));
    assert_private(&markdown);

    let (status, second) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":first_token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_projects(&second["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
    assert_eq!(second["result"]["scanStatus"], "more");
    let (second_token, second_bytes) = confidential_token(&second["result"]);
    assert_eq!(
        &first_bytes[6..14],
        &second_bytes[6..14],
        "continuation extended its original deadline"
    );
    assert_ne!(first_token, second_token);
    let (status, final_page) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":second_token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_projects(&final_page["result"], &[]);
    assert_eq!(final_page["result"]["scanStatus"], "exhausted");
    assert!(final_page["result"].get("nextPageToken").is_none());

    let mut tampered = first_token.as_bytes().to_vec();
    tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    let before = fixture.requests().await.len();
    for (action, search, token) in [
        ("search.issues", "empty-page-query", tampered.as_str()),
        ("search.issues", "different-query", first_token.as_str()),
        ("search.code", "empty-page-query", first_token.as_str()),
    ] {
        let (status, response) = fixture
            .invoke(
                &fixture.token,
                action,
                json!({"search":search,"maxResults":4,"pageToken":token}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["reasonCode"], "input_invalid");
        assert!(!response.to_string().contains(token));
    }
    assert_eq!(
        fixture.requests().await.len(),
        before,
        "invalid continuation reached GitLab"
    );
    let document = std::fs::read_to_string(fixture.broker.config_path()).unwrap();
    let narrowed = document.replace(
        "resources = { resource_group_ids = [\"engineering\"] }",
        "resources = { resource_ids = [\"api\"] }",
    );
    assert_ne!(document, narrowed);
    std::fs::write(fixture.broker.config_path(), narrowed).unwrap();
    assert!(fixture.broker.reload().await.unwrap().is_success());
    let (status, denied) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":first_token}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["reasonCode"], "input_invalid");
    assert_eq!(fixture.requests().await.len(), before);
    let (status, fresh) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":QUERY,"maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_projects(&fresh["result"], &[FIRST_PROJECT]);
    let audit_store = fixture.broker.audit().unwrap();
    let audit = audit_store.text();
    assert_private(&audit);
    // The search text is a declared audit input; continuation tokens are not.
    assert!(
        audit_store
            .require_action("gitlab", "search.issues")
            .iter()
            .any(|record| record["auditInputs"]
                == json!([{"input":"search","label":"Search","value":"empty-page-query"}]))
    );
    for private in [first_token.as_str(), second_token.as_str()] {
        assert!(!audit.contains(private));
    }
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_project_identity_and_confirmed_ownership_control_release() {
    let fixture = Fixture::start(Credentials::Service, &ACTIONS).await;
    let explicit = json!({"search":"move-query","project":FIRST_PROJECT,"maxResults":4});
    let (status, broad) = fixture
        .invoke(&fixture.token, "search.issues", explicit.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{broad}");
    let (status, narrow) = fixture
        .invoke(&fixture.narrow_token, "search.issues", explicit.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{narrow}");
    let broad_token = confidential_token(&broad["result"]).0;
    let narrow_token = confidential_token(&narrow["result"]).0;
    fixture.state.lock().unwrap().first_path = "engineering/renamed".into();
    for (token, continuation) in [
        (&fixture.token, broad_token),
        (&fixture.narrow_token, narrow_token),
    ] {
        let mut resumed = explicit.clone();
        resumed["pageToken"] = json!(continuation);
        let (status, response) = fixture.invoke(token, "search.issues", resumed).await;
        assert!(
            !status.is_success(),
            "a moved project reused stale authority: {response}"
        );
        assert!(response.get("result").is_none());
    }
    let (status, fresh) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":QUERY,"maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_projects(&fresh["result"], &["engineering/renamed", SECOND_PROJECT]);
    assert!(
        !fresh["result"].to_string().contains(FIRST_PROJECT),
        "stale indexed path was released"
    );
    let (status, narrowed) = fixture
        .invoke(
            &fixture.narrow_token,
            "search.issues",
            json!({"search":QUERY,"maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_projects(&narrowed["result"], &[]);

    let before = fixture.requests().await.len();
    let (status, unavailable) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"unavailable-query","maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{unavailable}");
    assert_projects(&unavailable["result"], &["engineering/renamed"]);
    assert_eq!(
        fixture.requests().await[before..]
            .iter()
            .filter(|request| request.url.path() == "/api/v4/projects/9903")
            .count(),
        1,
        "unavailable confirmation was not memoized"
    );
    for (action, search, project) in [
        ("search.issues", "wrong-owner-query", Some(FIRST_PROJECT)),
        ("search.merge_requests", "contradictory-mr-query", None),
        ("search.comments", "unknown-parent-query", None),
        ("search.issues", "missing-header-query", None),
        ("search.issues", "wrong-header-query", None),
    ] {
        let mut inputs = json!({"search":search,"maxResults":4});
        if let Some(project) = project {
            inputs["project"] = json!(project);
        }
        let (status, response) = fixture.invoke(&fixture.token, action, inputs).await;
        assert!(!status.is_success(), "{search}: {response}");
        assert_eq!(
            response["reasonCode"], "upstream_protocol_failed",
            "{response}"
        );
        assert!(response.get("result").is_none());
        assert_private(&response.to_string());
    }
    assert_private(&fixture.broker.audit().unwrap().text());
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supported_comment_parents_and_project_wikis_have_honest_locators() {
    let fixture = Fixture::start(Credentials::Service, &ACTIONS).await;
    let (status, comments) = fixture
        .invoke(
            &fixture.token,
            "search.comments",
            json!({"search":"comment-parents-query","maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{comments}");
    assert_projects(
        &comments["result"],
        &[FIRST_PROJECT, SECOND_PROJECT, FIRST_PROJECT, SECOND_PROJECT],
    );
    let items = comments["result"]["items"].as_array().unwrap();
    let kinds: Vec<_> = items
        .iter()
        .map(|item| item["parentKind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["Issue", "MergeRequest", "Commit", "Snippet"]);
    assert!(
        items[2].get("webUrl").is_none(),
        "numeric noteable_id was treated as a commit SHA"
    );
    let (status, wikis) = fixture
        .invoke(
            &fixture.token,
            "search.wiki",
            json!({"search":"wiki-kinds-query","maxResults":4}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{wikis}");
    assert_projects(&wikis["result"], &[FIRST_PROJECT]);
    assert_private(&fixture.broker.audit().unwrap().text());
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_refresh_preserves_continuation_but_reconnection_and_token_revocation_do_not() {
    let fixture = Fixture::start(Credentials::OAuth, &ACTIONS).await;
    let inputs = json!({"search":"empty-page-query","maxResults":4});
    let (status, first) = fixture
        .invoke(&fixture.token, "search.issues", inputs.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (token, first_bytes) = confidential_token(&first["result"]);
    fixture.state.lock().unwrap().reject_first_access = true;
    let before = fixture.requests().await.len();
    let (status, resumed) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_projects(&resumed["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
    let (_, resumed_bytes) = confidential_token(&resumed["result"]);
    assert_eq!(&first_bytes[6..14], &resumed_bytes[6..14]);
    assert_eq!(fixture.state.lock().unwrap().refreshes, 1);
    let attempts = fixture.requests().await;
    let attempts: Vec<_> = attempts[before..]
        .iter()
        .filter(|request| request.url.path() == "/api/v4/search")
        .collect();
    assert_eq!(
        attempts.len(),
        2,
        "one candidate-page slot must permit the single authentication replay"
    );
    assert_eq!(
        attempts[0].headers.get("authorization").unwrap(),
        "Bearer search-oauth-access-1"
    );
    assert_eq!(
        attempts[1].headers.get("authorization").unwrap(),
        "Bearer search-oauth-access-2"
    );

    fixture.connect("reconnect").await;
    // Remote revocation of the old OAuth family is independent background work.
    // Rejecting a cursor must prevent GitLab resource reads, not that cleanup.
    let before = fixture.resource_request_count().await;
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":token}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["reasonCode"], "input_invalid");
    assert_eq!(fixture.resource_request_count().await, before);
    let (status, fresh) = fixture
        .invoke(&fixture.token, "search.issues", inputs)
        .await;
    assert_eq!(status, StatusCode::OK, "{fresh}");
    let fresh_token = confidential_token(&fresh["result"]).0;
    let revoked = fixture
        .browser(
            Method::DELETE,
            &format!("/v1/tokens/{}", fixture.token_id),
            None,
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let before = fixture.resource_request_count().await;
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "search.issues",
            json!({"search":"empty-page-query","maxResults":4,"pageToken":fresh_token}),
        )
        .await;
    assert!(
        !status.is_success(),
        "revoked token resumed search: {response}"
    );
    assert_eq!(fixture.resource_request_count().await, before);
    assert_private(&fixture.broker.audit().unwrap().text());
    fixture.stop().await;
}

async fn reload_document(fixture: &Fixture, document: &str) {
    std::fs::write(fixture.broker.config_path(), document).unwrap();
    let outcome = fixture.broker.reload().await.unwrap();
    assert!(
        outcome.is_success(),
        "reload failed: {:?}: {:?}",
        outcome.reason_code(),
        outcome.message()
    );
}

async fn assert_list_discovery_without_upstream(fixture: &Fixture, expected: bool) {
    let before = fixture.requests().await.len();
    let catalog = reqwest::Client::new()
        .get(format!("{}/v1/spec/catalog", fixture.broker.public_url()))
        .header(
            agent_access_provider::REQUEST_ID_HEADER,
            uuid::Uuid::new_v4().to_string(),
        )
        .bearer_auth(&fixture.token)
        .send()
        .await
        .unwrap();
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog: Value = catalog.json().await.unwrap();
    let catalog_has_list = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|service| service["service"] == "gitlab")
        .flat_map(|service| service["actions"].as_array().unwrap())
        .any(|action| action["action"] == "project.list");
    assert_eq!(catalog_has_list, expected, "{catalog}");
    let initialize = fixture.mcp_request(None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"list-admission","version":"1"}
    }})).await;
    assert_eq!(initialize.status(), StatusCode::OK);
    let session = initialize.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp_json(initialize).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    assert_eq!(
        fixture
            .mcp_request(
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let tools = mcp_json(
        fixture
            .mcp_request(
                Some(&session),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            )
            .await,
    )
    .await;
    let mcp_has_list = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| {
            tool["_meta"]["agent-access/service"] == "gitlab"
                && tool["_meta"]["agent-access/action"] == "project.list"
        });
    assert_eq!(mcp_has_list, expected, "{tools}");
    fixture.close_mcp(&session).await;
    assert_eq!(
        fixture.requests().await.len(),
        before,
        "local availability discovery contacted GitLab"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_list_discovery_requires_the_selected_locally_available_credential() {
    for mode in [Credentials::Service, Credentials::Personal] {
        let fixture = Fixture::start(mode, &["project.list"]).await;
        assert_list_discovery_without_upstream(&fixture, true).await;
        let original = std::fs::read_to_string(fixture.broker.config_path()).unwrap();
        let config: toml::Value = toml::from_str(&original).unwrap();
        match mode {
            Credentials::Service => {
                let reference = config["credentials"]["service"]["gitlab"]["token_ref"]
                    .as_str()
                    .unwrap();
                std::fs::remove_file(reference.strip_prefix("file:").unwrap()).unwrap();
            }
            Credentials::Personal => {
                let path = config["credentials"]["per_user"]["gitlab"]["path"]
                    .as_str()
                    .unwrap();
                std::fs::write(path, r#"{"credentials":[]}"#).unwrap();
            }
            Credentials::OAuth => unreachable!(),
        }
        assert_list_discovery_without_upstream(&fixture, false).await;
        let before = fixture.requests().await.len();
        let (status, response) = fixture
            .invoke(
                &fixture.token,
                "project.list",
                action_inputs("project.list"),
            )
            .await;
        assert!(!status.is_success(), "{response}");
        assert_private(&response.to_string());
        assert_eq!(fixture.requests().await.len(), before);
        fixture.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_list_preserves_modes_precedence_subjects_groups_and_execution_contexts() {
    let fixture = Fixture::start(Credentials::Personal, &["project.list"]).await;
    assert_list_discovery_without_upstream(&fixture, true).await;
    let original = std::fs::read_to_string(fixture.broker.config_path()).unwrap();
    let mut config: toml::Value = toml::from_str(&original).unwrap();
    let mut other = config["policy"]["resources"][2].clone();
    other["id"] = toml::Value::String("other".into());
    other["selector"]["value"] = toml::Value::String("labs/other".into());
    config["policy"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(other);
    let mut second = config["policy"]["grants"][0].clone();
    second["credential_mode"] = toml::Value::String("service".into());
    second["resources"] = toml::from_str::<toml::Value>("resource_ids = [\"other\"]").unwrap();
    config["policy"]["grants"]
        .as_array_mut()
        .unwrap()
        .push(second);
    reload_document(&fixture, &toml::to_string(&config).unwrap()).await;
    assert_list_discovery_without_upstream(&fixture, false).await;
    let before = fixture.requests().await.len();
    let (status, denied) = fixture
        .invoke(
            &fixture.token,
            "project.list",
            action_inputs("project.list"),
        )
        .await;
    assert!(!status.is_success(), "{denied}");
    assert_eq!(denied["reasonCode"], "service_action_denied");
    assert_eq!(fixture.requests().await.len(), before);

    config["policy"]["grants"][1]
        .as_table_mut()
        .unwrap()
        .insert("priority".into(), toml::Value::Integer(10));
    config["policy"]["grants"][1]["resources"] =
        toml::from_str("resource_ids = [\"api\"]").unwrap();
    reload_document(&fixture, &toml::to_string(&config).unwrap()).await;
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "project.list",
            action_inputs("project.list"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_projects(&response["result"], &[FIRST_PROJECT]);
    assert_eq!(
        fixture.requests().await.last().unwrap().headers["authorization"],
        "Bearer search-service-token"
    );

    // Direct-user authority outranks even a higher-priority group grant.
    config["policy"]["grants"][1]["subjects"] =
        toml::Value::Array(vec![toml::Value::String("group:list-members".into())]);
    reload_document(&fixture, &toml::to_string(&config).unwrap()).await;
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "project.list",
            action_inputs("project.list"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_projects(&response["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
    assert_eq!(
        fixture.requests().await.last().unwrap().headers["authorization"],
        "Bearer search-personal-token"
    );

    for subject in ["user:admin", "group:list-nonmembers", "group:list-members"] {
        reload_document(&fixture, &original).await;
        assert_list_discovery_without_upstream(&fixture, true).await;
        let document = original.replace(
            "subjects = [\"user:alice\"]",
            &format!("subjects = [\"{subject}\"]"),
        );
        reload_document(&fixture, &document).await;
        let before = fixture.requests().await.len();
        let (status, response) = fixture
            .invoke(
                &fixture.token,
                "project.list",
                action_inputs("project.list"),
            )
            .await;
        if subject == "group:list-members" {
            assert_list_discovery_without_upstream(&fixture, true).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            assert_projects(&response["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
        } else {
            assert!(!status.is_success(), "{response}");
            assert_eq!(fixture.requests().await.len(), before);
            assert_list_discovery_without_upstream(&fixture, false).await;
        }
    }
    let mut config: toml::Value = toml::from_str(&original).unwrap();
    config.as_table_mut().unwrap().insert(
        "execution_context".into(),
        toml::from_str(
            "allowed_values = [\"default\", \"external\"]\ndefault_context = \"default\"",
        )
        .unwrap(),
    );
    reload_document(&fixture, &toml::to_string(&config).unwrap()).await;
    assert_list_discovery_without_upstream(&fixture, true).await;
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "project.list",
            action_inputs("project.list"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_projects(&response["result"], &[FIRST_PROJECT, SECOND_PROJECT]);
    config["policy"]["grants"][0]["execution_contexts"] =
        toml::Value::Array(vec![toml::Value::String("external".into())]);
    reload_document(&fixture, &toml::to_string(&config).unwrap()).await;
    let before = fixture.requests().await.len();
    let (status, response) = fixture
        .invoke(
            &fixture.token,
            "project.list",
            action_inputs("project.list"),
        )
        .await;
    assert!(!status.is_success(), "{response}");
    assert_eq!(fixture.requests().await.len(), before);
    assert_list_discovery_without_upstream(&fixture, false).await;
    fixture.stop().await;
}
