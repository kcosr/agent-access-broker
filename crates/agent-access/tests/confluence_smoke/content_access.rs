//! Production Broker, Confluence HTTP adapter and CLI/MCP against a synthetic
//! mixed tree. These tests establish transport enforcement, not live Cloud shapes.
use super::search_access::{self as access, GrantShape, Tokens};
use super::*;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path_regex};

const CLOUD: &str = "11111111-2222-4333-8444-555555555555";
const PREFIX: &str = "/ex/confluence/11111111-2222-4333-8444-555555555555/wiki";
const FOLDER: &str = "https://example.atlassian.net/wiki/spaces/ENG/folder/10";
const ACTIONS: &[&str] = &["page.view", "page.update", "page.create", "search"];

async fn start(server: &MockServer, grant_folder: bool) -> (RunningBroker, Tokens) {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value =
        toml::from_str(&confluence_document(application.directory(), ACTIONS)).unwrap();
    let lookup = document["credentials"]["lookup"].clone();
    let tokens = access::configure(
        &application,
        &mut document,
        "confluence",
        "confluence_space",
        ["ENG", "OPS"],
        ACTIONS,
        GrantShape::Finite,
    );
    // The issued tokens retain live resource references. Change the first
    // reference into a folder ceiling, while the grant can remain space-wide.
    document["policy"]["resources"][0]["resource_type"] = "confluence_content".into();
    document["policy"]["resources"][0]["selector"] =
        toml::Value::try_from(json!({"kind":"subtree","value":FOLDER})).unwrap();
    document["policy"]["resources"][1]["selector"] =
        toml::Value::try_from(json!({"kind":"exact","value":"ENG"})).unwrap();
    document["policy"]["grants"][0]["resources"] = toml::Value::try_from(
        json!({"resource_ids":[if grant_folder { "first" } else { "second" }]}),
    )
    .unwrap();
    document["credentials"]
        .as_table_mut()
        .unwrap()
        .insert("lookup".into(), lookup);
    document["providers"]["confluence"]
        .as_table_mut()
        .unwrap()
        .insert("cloud_id".into(), CLOUD.into());
    document["providers"]["confluence"]["allowed_upstream_hosts"] =
        toml::Value::try_from(vec!["https://api.atlassian.com/ex/confluence/**"]).unwrap();
    for kind in ["lookup", "service"] {
        document["credentials"][kind]["confluence"]
            .as_table_mut()
            .unwrap()
            .insert("profile".into(), "atlassian-scoped-api-token".into());
    }
    document.as_table_mut().unwrap().insert(
        "mcp".into(),
        toml::Value::try_from(
            json!({"enabled":true,"public_url":format!("{}/mcp",application.public_url())}),
        )
        .unwrap(),
    );
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

#[derive(Default)]
struct Upstream {
    versions: BTreeMap<String, u64>,
    writes: Vec<Value>,
    creations: Vec<Value>,
    corrupt_creation_parent: bool,
    move_root_for_execution: bool,
    hide_root_for_execution: bool,
}

fn node(id: &str, version: u64) -> Value {
    let (kind, parent_id, parent_type) = match id {
        "10" | "20" => ("folder", Value::Null, Value::Null),
        "101" => ("page", json!("10"), json!("folder")),
        "102" => ("page", json!("20"), json!("folder")),
        "103" => ("page", json!("101"), json!("page")),
        _ => panic!("unknown synthetic node"),
    };
    json!({"id":id,"type":kind,"spaceId":"1","status":"current","title":"Runbook",
        "parentId":parent_id,"parentType":parent_type,"version":{"number":version},
        "body":{"storage":{"value":"<p>Allowed body</p>","representation":"storage"}}})
}

async fn mount(server: &MockServer) -> Arc<Mutex<Upstream>> {
    let state = Arc::new(Mutex::new(Upstream::default()));
    let served = state.clone();
    let service_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("service@example.com:confluence-token")
    );
    Mock::given(path_regex(format!("^{PREFIX}/")))
        .respond_with(move |request: &wiremock::Request| {
            let mut state = served.lock().unwrap();
            let path = request.url.path().strip_prefix(PREFIX).unwrap();
            let execution = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                == Some(service_auth.as_str());
            if request.method == "GET" {
                if path == "/api/v2/spaces" {
                    assert!(
                        request
                            .url
                            .query_pairs()
                            .any(|(key, value)| key == "keys" && value == "ENG")
                    );
                    return ResponseTemplate::new(200).set_body_json(json!({"results":[
                        {"id":"1","key":"ENG","status":"current","homepageId":"101"}
                    ]}));
                }
                if path == "/api/v2/spaces/1" {
                    return ResponseTemplate::new(200).set_body_json(
                        json!({"id":"1","key":"ENG","status":"current","homepageId":"101"}),
                    );
                }
                if path == "/api/v2/pages" {
                    let id = request
                        .url
                        .query_pairs()
                        .find(|(key, _)| key == "id")
                        .unwrap()
                        .1
                        .into_owned();
                    let value = node(&id, *state.versions.get(&id).unwrap_or(&1));
                    return ResponseTemplate::new(200).set_body_json(json!({"results":[value]}));
                }
                if path == "/rest/api/content/search" {
                    let results = ["101", "102"].map(|id| {
                        let mut value = node(id, *state.versions.get(id).unwrap_or(&1));
                        value["space"] = json!({"id":"1","key":"ENG"});
                        value.as_object_mut().unwrap().remove("body");
                        value
                    });
                    return ResponseTemplate::new(200).set_body_json(json!({"results":results}));
                }
                for prefix in ["/api/v2/pages/", "/api/v2/folders/", "/rest/api/content/"] {
                    if let Some(id) = path.strip_prefix(prefix) {
                        if !["10", "20", "101", "102", "103"].contains(&id) {
                            return ResponseTemplate::new(404);
                        }
                        if id == "10" && execution && state.hide_root_for_execution {
                            return ResponseTemplate::new(403);
                        }
                        let mut value = node(id, *state.versions.get(id).unwrap_or(&1));
                        if id == "10" && execution && state.move_root_for_execution {
                            value["parentId"] = json!("20");
                            value["parentType"] = json!("folder");
                        }
                        if prefix == "/rest/api/content/" {
                            value["space"] = json!({"id":"1","key":"ENG"});
                        }
                        return ResponseTemplate::new(200).set_body_json(value);
                    }
                }
            }
            if request.method == "POST" && path == "/api/v2/pages" {
                assert!(
                    request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "root-level" && value == "false")
                );
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = (201 + state.creations.len()).to_string();
                let value = json!({"id":id,"type":"page","spaceId":body["spaceId"],
                    "status":"current","title":body["title"],"parentId":body["parentId"],
                    "parentType":if state.corrupt_creation_parent {"page"} else {"folder"},
                    "version":{"number":1},"body":{"storage":body["body"]}});
                state.creations.push(body);
                return ResponseTemplate::new(201).set_body_json(value);
            }
            if request.method == "PUT" && path.starts_with("/api/v2/pages/") {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["id"].as_str().unwrap();
                let version = body["version"]["number"].as_u64().unwrap();
                state.versions.insert(id.into(), version);
                let mut value = node(id, version);
                value["title"] = body["title"].clone();
                state.writes.push(body);
                return ResponseTemplate::new(200).set_body_json(value);
            }
            ResponseTemplate::new(404)
        })
        .mount(server)
        .await;
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_folder_creation_preserves_typed_parent_across_cli_invoke_send_and_receipts() {
    let server = MockServer::start().await;
    let state = mount(&server).await;
    let (broker, tokens) = start(&server, true).await;
    let parent = json!({"kind":"folder","id":"10"});
    let content = "<p>folder creation private content</p>";
    let body_path = broker.directory().join("folder-create.html");
    std::fs::write(&body_path, content).unwrap();
    let inputs = json!({"space":"ENG","title":"Folder child","parent":parent,
        "contentFormat":"storage","content":content});
    let send_path = broker.directory().join("folder-create.send.json");
    std::fs::write(
        &send_path,
        json!({"version":"agent-access.send.v1","kind":"invoke",
        "service":"confluence","action":"page.create","inputs":inputs})
        .to_string(),
    )
    .unwrap();
    for unreadable in [false, true] {
        state.lock().unwrap().corrupt_creation_parent = unreadable;
        let expected_success = !unreadable;
        let responses = [
            access::run(
                &broker,
                &tokens.narrowed,
                &[
                    "confluence",
                    "page",
                    "create",
                    "--space",
                    "ENG",
                    "--title",
                    "Folder child",
                    "--parent-kind",
                    "folder",
                    "--parent-id",
                    "10",
                    "--content-format",
                    "storage",
                    "--content-file",
                    body_path.to_str().unwrap(),
                ],
                expected_success,
            ),
            access::invoke(
                &broker,
                &tokens.narrowed,
                "confluence.page.create",
                &inputs,
                expected_success,
            ),
            access::run(
                &broker,
                &tokens.narrowed,
                &["send", "--request-file", send_path.to_str().unwrap()],
                expected_success,
            ),
        ];
        for (index, response) in responses.into_iter().enumerate() {
            assert!(!response.to_string().contains("parentPageId"), "{response}");
            assert!(!response.to_string().contains(content), "{response}");
            if unreadable {
                assert_eq!(
                    response["result"]["mutationStatus"], "applied_unverified",
                    "{response}"
                );
                assert_eq!(response["result"]["retrySafe"], false);
                assert_eq!(response["result"]["verificationStage"], "mutation_response");
                assert_eq!(
                    response["result"]["safeLocators"],
                    json!({"space":"ENG","parent":parent})
                );
            } else {
                assert_eq!(response["decision"], "allow", "{response}");
                assert_eq!(response["result"]["pageId"], (201 + index).to_string());
                assert_eq!(response["result"]["parent"], parent);
                assert_eq!(response["result"]["placement"], "requested_parent");
            }
        }
    }
    {
        let state = state.lock().unwrap();
        assert_eq!(
            state.creations.len(),
            6,
            "each requested mutation is sent exactly once, including accepted unreadable responses"
        );
        for body in &state.creations {
            assert_eq!(body["parentId"], "10");
            assert_eq!(body["spaceId"], "1");
            assert_eq!(body["status"], "current");
            assert_eq!(body["body"]["value"], content);
            assert_eq!(
                body.as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                ["body", "parentId", "spaceId", "status", "title"]
                    .into_iter()
                    .collect()
            );
        }
    }
    let audit = broker.audit().unwrap();
    let records = audit.require_action("confluence", "page.create");
    assert_eq!(records.len(), 6);
    for (index, record) in records.iter().enumerate() {
        assert!(
            record["auditInputs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|input| input["input"] == "parent" && input["value"] == parent),
            "{record}"
        );
        assert!(!record.to_string().contains("parentPageId"), "{record}");
        if index < 3 {
            assert_eq!(record["objectIds"]["parent"], parent);
            assert_eq!(record["providerAudit"]["parent"], parent);
        }
    }
    assert!(!audit.text().contains(content));
    stop(broker).await;
}

fn allowed(value: &Value, id: &str) {
    assert_eq!(value["decision"], "allow", "{value}");
    assert_eq!(value["result"]["id"], id, "{value}");
}

fn allowed_search(value: &Value) {
    assert_eq!(value["decision"], "allow", "{value}");
    let pages = value["result"]["pages"].as_array().unwrap();
    assert_eq!(pages.len(), 1, "{value}");
    assert_eq!(pages[0]["id"], "101", "{value}");
    assert!(value["result"]["nextPageToken"].is_null(), "{value}");
    assert_eq!(value["result"]["scanStatus"], "exhausted", "{value}");
    assert!(!value.to_string().contains("/pages/102"));
}

fn denied(value: &Value) {
    assert_eq!(value["decision"], "deny", "{value}");
    assert!(value.get("result").is_none(), "{value}");
    assert!(
        value["resourceScopes"]
            .as_object()
            .is_none_or(|scopes| scopes.is_empty()),
        "{value}"
    );
    assert!(!value.to_string().contains("Allowed body"));
}

async fn rpc_body(response: reqwest::Response) -> Value {
    assert!(response.status().is_success());
    let text = response.text().await.unwrap();
    if text.trim_start().starts_with('{') {
        return serde_json::from_str(&text).unwrap();
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|v| v.get("id").is_some())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_folder_ceiling_matches_cli_send_http_and_both_mcp_transports() {
    let server = MockServer::start().await;
    let state = mount(&server).await;
    let (broker, tokens) = start(&server, false).await;
    let token = &tokens.narrowed;
    // The subtree includes both a direct child and a deeper descendant, but a
    // sibling under another folder remains outside even with the broad grant.
    for id in ["101", "103"] {
        let inputs = json!({"pageId":id});
        for value in [
            access::run(&broker, token, &["confluence", "page", "view", id], true),
            access::invoke(&broker, token, "confluence.page.view", &inputs, true),
            access::send(&broker, token, "confluence", "page.view", &inputs),
            access::http(&broker, token, "confluence", "page.view", &inputs).await,
        ] {
            allowed(&value, id);
        }
    }
    denied(&access::invoke(
        &broker,
        token,
        "confluence.page.view",
        &json!({"pageId":"102"}),
        false,
    ));
    denied(
        &access::http(
            &broker,
            token,
            "confluence",
            "page.view",
            &json!({"pageId":"102"}),
        )
        .await,
    );
    let search = json!({"query":{"type":"text","value":"Runbook"}});
    // The synthetic search deliberately returns a sibling outside the indexed
    // subtree. Current metadata must remove it before any transport can release it.
    for value in [
        access::run(
            &broker,
            token,
            &["confluence", "page", "search", "--text", "Runbook"],
            true,
        ),
        access::invoke(&broker, token, "confluence.search", &search, true),
        access::send(&broker, token, "confluence", "search", &search),
        access::http(&broker, token, "confluence", "search", &search).await,
    ] {
        allowed_search(&value);
    }
    for request in server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path().ends_with("/rest/api/content/search"))
    {
        let cql = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "cql")
            .unwrap()
            .1;
        assert!(cql.contains("ancestor = 10"), "{cql}");
        assert!(cql.contains("space = \"ENG\""), "{cql}");
        assert!(cql.contains("AND (title ~ \"Runbook\")"), "{cql}");
    }
    let initialize = json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"content-grants","version":"1"}});
    let mut stdio = list_mcp::StdioMcp::start(access::cli(&broker, token));
    assert!(
        stdio
            .request("initialize", initialize.clone())
            .await
            .get("error")
            .is_none()
    );
    stdio.notify("notifications/initialized", json!({}));
    let client = reqwest::Client::new();
    let endpoint = format!("{}/mcp", broker.public_url());
    let rpc = |message: Value, session: Option<&str>| {
        let mut request = client
            .post(&endpoint)
            .bearer_auth(token)
            .header("Accept", "application/json, text/event-stream")
            .json(&message);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        request
    };
    let response = rpc(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":initialize}),
        None,
    )
    .send()
    .await
    .unwrap();
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(rpc_body(response).await.get("error").is_none());
    assert!(
        rpc(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            Some(&session)
        )
        .send()
        .await
        .unwrap()
        .status()
        .is_success()
    );
    for (index, id) in ["101", "102"].into_iter().enumerate() {
        let params = json!({"name":agent_access_core::mcp::tool_name("confluence","page.view"),"arguments":{"inputs":{"pageId":id}}});
        let local = stdio.request("tools/call", params.clone()).await;
        let remote = rpc_body(
            rpc(
                json!({"jsonrpc":"2.0","id":index+2,"method":"tools/call","params":params}),
                Some(&session),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        for response in [local, remote] {
            if id == "101" {
                allowed(&response["result"]["structuredContent"], id);
            } else {
                denied(&response["result"]["structuredContent"]);
            }
        }
    }
    let params = json!({"name":agent_access_core::mcp::tool_name("confluence","search"),"arguments":{"inputs":search}});
    let local = stdio.request("tools/call", params.clone()).await;
    let remote = rpc_body(
        rpc(
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":params}),
            Some(&session),
        )
        .send()
        .await
        .unwrap(),
    )
    .await;
    for response in [local, remote] {
        allowed_search(&response["result"]["structuredContent"]);
    }
    stdio.finish().await;
    let writes_before = state.lock().unwrap().writes.len();
    denied(&access::http(&broker,token,"confluence","page.update",&json!({"pageId":"102","baseVersion":1,"contentFormat":"storage","content":"<p>Forbidden</p>"})).await);
    assert_eq!(
        state.lock().unwrap().writes.len(),
        writes_before,
        "outside token boundary must send no PUT"
    );
    // Ordinary discovery stays offline and reveals only the positive folder.
    let before = server.received_requests().await.unwrap().len();
    let discovery = access::run(
        &broker,
        token,
        &[
            "resource-access",
            "describe",
            "--service",
            "confluence",
            "--action",
            "page.view",
        ],
        true,
    );
    assert!(discovery.to_string().contains("location"));
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_grant_denies_sibling_and_execution_move_or_hidden_ancestor_before_put() {
    for (moved, hidden) in [(false, false), (true, false), (false, true)] {
        let server = MockServer::start().await;
        let state = mount(&server).await;
        let (broker, tokens) = start(&server, true).await;
        let token = &tokens.unrestricted;
        denied(
            &access::http(
                &broker,
                token,
                "confluence",
                "page.view",
                &json!({"pageId":"102"}),
            )
            .await,
        );
        state.lock().unwrap().move_root_for_execution = moved;
        state.lock().unwrap().hide_root_for_execution = hidden;
        let result=access::http(&broker,token,"confluence","page.update",&json!({"pageId":"101","baseVersion":1,"contentFormat":"storage","content":"<p>Approved update</p>"})).await;
        if moved || hidden {
            assert_eq!(result["decision"], "deny", "{result}");
            assert_eq!(result["reasonCode"], "scope_unresolved", "{result}");
            assert!(result.get("result").is_none(), "{result}");
            assert_eq!(
                result["resourceScopes"],
                json!({"page_location":["https://example.atlassian.net/wiki/spaces/ENG/pages/101"]}),
                "final denial keeps only the admitted operation location: {result}"
            );
            assert!(!result.to_string().contains("Allowed body"));
            assert!(!result.to_string().contains("/folder/20"));
            assert!(
                state.lock().unwrap().writes.is_empty(),
                "changed or hidden ancestry must prevent the write"
            );
        } else {
            assert_eq!(result["decision"], "allow", "{result}");
            assert_eq!(result["result"]["pageId"], "101", "{result}");
            let state = state.lock().unwrap();
            assert_eq!(state.writes.len(), 1);
            let fields = state.writes[0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                fields,
                ["body", "id", "status", "title", "version"]
                    .into_iter()
                    .collect()
            );
            assert_eq!(state.writes[0]["version"]["number"], 2);
        }
        stop(broker).await;
    }
}
