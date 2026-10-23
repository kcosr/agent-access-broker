//! Real Broker admission and production CloudBees transport across caller surfaces.
use super::*;
use std::collections::BTreeMap;
#[path = "../common/list_mcp.rs"]
mod list_mcp;

async fn start(server: &MockServer, personal: bool, actions: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let settings = Cloudbees {
        http_mcp: true,
        callers: Callers::Principal {
            header: "Authorization",
            scheme: "Bearer",
            token: "ci-principal-token",
        },
        ..Cloudbees::ci_agent(server)
    };
    let mut doc: toml::Value =
        toml::from_str(&settings.document(application.directory(), &application.public_url()))
            .unwrap();
    doc.as_table_mut().unwrap().insert(
        "execution_context".into(),
        toml::from_str("allowed_values=[\"default\",\"internal\"]\ndefault_context=\"default\"")
            .unwrap(),
    );
    doc["identity"].as_table_mut().unwrap().insert(
        "groups".into(),
        toml::Value::try_from(vec![
            toml::from_str::<toml::Value>(
                "id=\"agents\"\nstatus=\"active\"\nmembers=[\"ci-agent\"]",
            )
            .unwrap(),
        ])
        .unwrap(),
    );
    doc["providers"]["cloudbees_ci"]
        .as_table_mut()
        .unwrap()
        .insert(
            "listing".into(),
            toml::Value::try_from(BTreeMap::from([("max_candidate_pages", 1)])).unwrap(),
        );
    doc["policy"]["grants"][0]["subjects"] = toml::Value::try_from(vec!["group:agents"]).unwrap();
    doc["policy"]["grants"][0]["actions"] = toml::Value::try_from(actions).unwrap();
    doc["policy"]["grants"][0].as_table_mut().unwrap().insert(
        "execution_contexts".into(),
        toml::Value::try_from(vec!["default"]).unwrap(),
    );
    doc["policy"]["resources"].as_array_mut().unwrap().push(toml::from_str("id=\"all-jobs\"\nresource_type=\"cloudbees_ci_job\"\nselector={kind=\"all\"}\nallowed_execution_contexts=[\"default\"]").unwrap());
    for name in ["HIDDEN", "EXCLUDED", "BLOCKED"] {
        doc["policy"]["resources"].as_array_mut().unwrap().push(toml::from_str(&format!("id={name:?}\nresource_type=\"cloudbees_ci_job\"\nselector={{kind=\"exact\",value=\"team-ci/payments/{name}\"}}\nenabled=false\nallowed_execution_contexts=[\"internal\"]")).unwrap());
    }
    doc["policy"].as_table_mut().unwrap().insert("resource_groups".into(),toml::Value::try_from(vec![toml::from_str::<toml::Value>("id=\"allowed-jobs\"\nname=\"Jobs with exclusions\"\nincluded_resource_ids=[\"all-jobs\"]\nexcluded_resource_ids=[\"HIDDEN\",\"EXCLUDED\",\"BLOCKED\"]").unwrap()]).unwrap());
    if personal {
        let directory = application.directory();
        let username = directory
            .secret_file("personal-username", "personal-user")
            .unwrap();
        let token = directory
            .secret_file("personal-token", "personal-token-value")
            .unwrap();
        let store=directory.secret_file("personal-store.json",json!({"credentials":[{"principal":"ci-agent","type":"basic_api_token","username_ref":format!("file:{}",username.display()),"token_ref":format!("file:{}",token.display())}]}).to_string()).unwrap();
        doc["credentials"].as_table_mut().unwrap().insert(
            "per_user".into(),
            toml::from_str(&format!(
                "[cloudbees_ci]\ntype=\"secret_store\"\nprovider=\"local_file\"\npath={}",
                toml_string(store.display())
            ))
            .unwrap(),
        );
        let mut grant = doc["policy"]["grants"][0].clone();
        grant["subjects"] = toml::Value::try_from(vec!["user:ci-agent"]).unwrap();
        grant["resources"] = toml::Value::try_from(BTreeMap::from([(
            "resource_group_ids",
            vec!["allowed-jobs"],
        )]))
        .unwrap();
        grant["credential_mode"] = "per_user".into();
        doc["policy"]["grants"].as_array_mut().unwrap().push(grant);
    }
    let document = toml::to_string(&doc).unwrap();
    let registry = std::sync::Arc::new(
        agent_access_core::BackendRegistry::new([&agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND])
            .unwrap(),
    );
    let parsed =
        agent_access_core::parse_broker_config_raw("listing fixture", &document, &registry)
            .unwrap();
    agent_access_core::validate_broker_config(&parsed).unwrap();
    application.config_document(document).start().await.unwrap()
}
fn authenticated(base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base,
        "--token-value",
        "ci-principal-token",
        "--identity-header",
        "Authorization",
        "--identity-scheme",
        "Bearer",
    ]);
    command
}
fn checked(output: std::process::Output) -> Value {
    assert_success("job listing", &output);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["decision"], "allow", "{result}");
    result
}
fn typed(base: &str) -> Command {
    let mut command = authenticated(base);
    command.args([
        "cloudbees-ci",
        "job",
        "list",
        "team-ci",
        "--folder",
        "payments",
        "--max-results",
        "3",
    ]);
    command
}
async fn mount(server: &MockServer) {
    for (offset, names) in [
        (0, vec!["HIDDEN", "EXCLUDED", "BLOCKED"]),
        (3, vec!["build-api", "NEW"]),
    ] {
        let values:Vec<_>=names.into_iter().map(|name|json!({"name":name,"fullName":format!("payments/{name}"),"displayName":if ["HIDDEN","EXCLUDED","BLOCKED"].contains(&name){"DENIED_DISPLAY"}else{"Visible job"},"_class":"UNPROJECTED_CLASS","builds":[{"secret":"UNPROJECTED_BUILD"}]})).collect();
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/api/json"))
            .and(query_param(
                "tree",
                format!(
                    "jobs[name,fullName,displayName,url,_class,jobs[name]{{0,0}}]{{{offset},{}}}",
                    offset + 3
                ),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jobs":values})))
            .mount(server)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn job_list_service_personal_cli_send_http_and_mcp_filter_current_inventory() {
    for personal in [false, true] {
        let server = MockServer::start().await;
        mount(&server).await;
        let broker = start(&server, personal, &["job.list"]).await;
        let base = broker.public_url();
        let catalog = authenticated(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("catalog", &catalog);
        let catalog: Value = serde_json::from_slice(&catalog.stdout).unwrap();
        let actions = catalog["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["service"] == "cloudbees_ci")
            .unwrap()["actions"]
            .as_array()
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["action"], "job.list");
        assert_eq!(actions[0]["readOnly"], true);
        assert_eq!(actions[0]["lookupRequired"], false);
        assert!(server.received_requests().await.unwrap().is_empty());
        let first = checked(typed(&base).output().unwrap());
        assert_eq!(first["result"]["count"], 0);
        assert_eq!(first["result"]["scanStatus"], "scan_budget");
        let token = first["result"]["nextPageToken"].as_str().unwrap();
        let second = checked(typed(&base).args(["--page-token", token]).output().unwrap());
        assert_eq!(second["result"]["count"], if personal { 2 } else { 1 });
        assert_eq!(
            second["result"]["items"][0]["resource"],
            "team-ci/payments/build-api"
        );
        if personal {
            assert_eq!(
                second["result"]["items"][1]["resource"],
                "team-ci/payments/NEW"
            );
        }
        assert_eq!(second["result"]["scanStatus"], "exhausted");
        let inputs =
            json!({"controller":"team-ci","folder":"payments","maxResults":3,"pageToken":token});
        let send = json!({"version":"agent-access.send.v1","kind":"invoke","service":"cloudbees_ci","action":"job.list","inputs":inputs});
        let sent = checked(
            authenticated(&base)
                .args(["send", "--request-json", &send.to_string()])
                .output()
                .unwrap(),
        );
        assert_eq!(sent["result"], second["result"]);
        let invoked = checked(
            authenticated(&base)
                .args([
                    "invoke",
                    "cloudbees_ci.job.list",
                    "--input-json",
                    &inputs.to_string(),
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(invoked["result"], second["result"]);
        let http: Value = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/cloudbees_ci/job.list"))
            .header("Authorization", "Bearer ci-principal-token")
            .header("X-Agent-Access-Request-Id", "cloudbees-list-http")
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(http["result"], second["result"]);
        let mut mcp = list_mcp::StdioMcp::start(authenticated(&base));
        mcp.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cloudbees-list","version":"1"}})).await;
        mcp.notify("notifications/initialized", json!({}));
        let before = server.received_requests().await.unwrap().len();
        let tools = mcp.request("tools/list", json!({})).await;
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        let tool = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["_meta"]["agent-access/action"] == "job.list")
            .unwrap();
        let called = mcp
            .request(
                "tools/call",
                json!({"name":tool["name"],"arguments":{"inputs":inputs}}),
            )
            .await;
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["result"],
            second["result"]
        );
        mcp.finish().await;
        let client = reqwest::Client::new();
        let endpoint = format!("{base}/mcp");
        let initialize=client.post(&endpoint).header("Authorization","Bearer ci-principal-token").header("accept","application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cloudbees-list-http","version":"1"}}})).send().await.unwrap();
        assert!(initialize.status().is_success(), "{}", initialize.status());
        let session = initialize.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let initialized = mcp_http_body(initialize).await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        let notified = client
            .post(&endpoint)
            .header("Authorization", "Bearer ci-principal-token")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await
            .unwrap();
        assert!(notified.status().is_success());
        let called_http=client.post(&endpoint).header("Authorization","Bearer ci-principal-token").header("accept","application/json, text/event-stream").header("mcp-session-id",&session).header("mcp-protocol-version","2025-11-25")
            .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool["name"],"arguments":{"inputs":inputs}}})).send().await.unwrap();
        let called_http = mcp_http_body(called_http).await;
        assert_eq!(called_http["result"]["isError"], false, "{called_http}");
        assert_eq!(
            called_http["result"]["structuredContent"]["result"],
            second["result"]
        );
        let expected = if personal {
            "personal-user:personal-token-value"
        } else {
            "automation:basic-secret"
        };
        for request in server.received_requests().await.unwrap() {
            assert_eq!(
                request.headers["authorization"],
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(expected)
                )
            );
            assert_eq!(request.url.path(), "/team-ci/job/payments/api/json");
        }
        let audit = broker.audit().unwrap();
        audit.require_action("cloudbees_ci", "job.list");
        let provider_audit = audit
            .text()
            .lines()
            .map(|line| {
                let event: Value = serde_json::from_str(line).unwrap();
                event["providerAudit"]
                    .get("cloudbees_ci")
                    .expect("CloudBees provider audit")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for output in [
            first.to_string(),
            second.to_string(),
            called.to_string(),
            called_http.to_string(),
            provider_audit,
        ] {
            for secret in [
                "HIDDEN",
                "EXCLUDED",
                "BLOCKED",
                "DENIED_DISPLAY",
                "UNPROJECTED_CLASS",
                "UNPROJECTED_BUILD",
                "basic-secret",
                "personal-token-value",
            ] {
                assert!(!output.contains(secret), "{secret}: {output}");
            }
        }
        for secret in [
            "DENIED_DISPLAY",
            "UNPROJECTED_CLASS",
            "UNPROJECTED_BUILD",
            "basic-secret",
            "personal-token-value",
        ] {
            assert!(!audit.text().contains(secret));
        }
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_permission_is_independent_and_unavailable_credentials_hide_it() {
    let server = MockServer::start().await;
    let broker = start(&server, false, &["job.view"]).await;
    assert!(
        !typed(&broker.public_url())
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
    let broker = start(&server, false, &["job.list"]).await;
    let base = broker.public_url();
    let before = authenticated(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog before", &before);
    assert!(
        String::from_utf8(before.stdout)
            .unwrap()
            .contains("job.list")
    );
    std::fs::remove_file(broker.directory().join("token")).unwrap();
    let after = authenticated(&base)
        .args(["spec", "catalog"])
        .output()
        .unwrap();
    assert_success("catalog after", &after);
    assert!(
        !String::from_utf8(after.stdout)
            .unwrap()
            .contains("job.list")
    );
    assert!(!typed(&base).output().unwrap().status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_admission_honors_subject_context_mode_and_never_falls_back() {
    let server = MockServer::start().await;
    mount(&server).await;
    let broker = start(&server, true, &["job.list"]).await;
    let base = broker.public_url();
    let original: toml::Value =
        toml::from_str(&std::fs::read_to_string(broker.config_path()).unwrap()).unwrap();
    for mode in ["subject", "context", "mixed"] {
        let positive = checked(typed(&base).output().unwrap());
        assert_eq!(positive["result"]["scanStatus"], "scan_budget");
        let mut changed = original.clone();
        match mode {
            "subject" => {
                changed["policy"]["grants"]
                    .as_array_mut()
                    .unwrap()
                    .truncate(1);
                changed["policy"]["grants"][0]["subjects"] =
                    toml::Value::try_from(vec!["group:anonymous"]).unwrap();
            }
            "context" => {
                for r in changed["policy"]["resources"].as_array_mut().unwrap() {
                    r["allowed_execution_contexts"] =
                        toml::Value::try_from(vec!["internal"]).unwrap();
                }
            }
            _ => {
                let mut other = changed["policy"]["resources"][0].clone();
                other["id"] = "other-job".into();
                other["selector"]["value"] = "team-ci/payments/OTHER".into();
                changed["policy"]["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(other);
                changed["policy"]["grants"][0]["subjects"] =
                    toml::Value::try_from(vec!["user:ci-agent"]).unwrap();
                changed["policy"]["grants"][0]["resources"]["resource_ids"] =
                    toml::Value::try_from(vec!["other-job"]).unwrap();
                changed["policy"]["grants"][1]["resources"] =
                    toml::Value::try_from(BTreeMap::from([("resource_ids", vec!["payments-job"])]))
                        .unwrap();
            }
        }
        broker
            .rewrite_config(toml::to_string(&changed).unwrap())
            .unwrap();
        assert!(broker.reload().await.unwrap().is_success());
        let before = server.received_requests().await.unwrap().len();
        let catalog = authenticated(&base)
            .args(["spec", "catalog"])
            .output()
            .unwrap();
        assert_success("restricted catalog", &catalog);
        assert!(
            !String::from_utf8(catalog.stdout)
                .unwrap()
                .contains("job.list"),
            "{mode}"
        );
        assert!(!typed(&base).output().unwrap().status.success(), "{mode}");
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        broker
            .rewrite_config(toml::to_string(&original).unwrap())
            .unwrap();
        assert!(broker.reload().await.unwrap().is_success());
    }
    checked(typed(&base).output().unwrap());
    let before = server.received_requests().await.unwrap().len();
    std::fs::write(
        broker.directory().join("personal-store.json"),
        b"{\"credentials\":[]}",
    )
    .unwrap();
    assert!(!typed(&base).output().unwrap().status.success());
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        before,
        "missing winning personal credential fell back to service"
    );
    stop(broker).await;
}
