//! Real Broker and CLI/MCP contracts with a synthetic Jira backend.
use super::*;
use serde_json::{Value, json};

const LIST: &str = "issue.transition.list";
const APPLY: &str = "issue.transition.apply";

async fn start(access: JiraAccess, actions: &[&str]) -> (RunningBroker, Arc<StubJiraBackend>) {
    let (broker, backend, ()) = start_configured(access, actions, |_, _| ()).await;
    (broker, backend)
}

async fn start_configured<T>(
    access: JiraAccess,
    actions: &[&str],
    configure: impl FnOnce(&IsolatedBroker, &mut toml::Value) -> T,
) -> (RunningBroker, Arc<StubJiraBackend>, T) {
    let backend = Arc::new(StubJiraBackend {
        issues: [("PROJ-1", "10001", "PROJ"), ("OTHER-1", "10002", "OTHER")]
            .into_iter()
            .map(|(key, id, project)| {
                (
                    key.into(),
                    serde_json::from_value(json!({"id":id,"key":key,"project":project})).unwrap(),
                )
            })
            .collect(),
        ..Default::default()
    });
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
            json!({"enabled":true,"public_url":format!("{}/mcp",application.public_url())}),
        )
        .unwrap(),
    );
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        grant["actions"] = toml::Value::try_from(actions).unwrap();
    }
    let extra = configure(&application, &mut document);
    let config = document["providers"]["jira"].clone().try_into().unwrap();
    let broker = application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "jira",
            ProviderFixture::instance(jira_service(config, Default::default(), backend.clone())),
        )
        .start()
        .await
        .unwrap();
    (broker, backend, extra)
}

fn command(base: &str) -> Command {
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

fn run(base: &str, args: &[&str]) -> Value {
    let output = command(base).args(args).output().unwrap();
    assert_success("transition CLI", &output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn inputs() -> Value {
    json!({"issue":"PROJ-1","transitionId":"31","toStatusId":"10002","expectedIssueId":"10001","resolutionId":"1"})
}

fn applied(value: &Value) {
    assert_eq!(value["decision"], "allow", "{value}");
    assert_eq!(value["result"]["status"], "transitioned", "{value}");
    assert_eq!(value["result"]["verification"]["status"], "matched");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_transitions_typed_invoke_send_and_http_use_selected_execution_credentials() {
    for access in [JiraAccess::AgentService, JiraAccess::AgentPerUser] {
        let (broker, backend) = start(access, &[LIST, APPLY]).await;
        let base = broker.public_url();
        let listed = run(
            &base,
            &[
                "jira",
                "issue",
                "transition",
                "list",
                "PROJ-1",
                "--include-fields",
            ],
        );
        assert_eq!(listed["result"]["transitions"][0]["to"]["name"], "Stalled");
        let typed = run(
            &base,
            &[
                "jira",
                "issue",
                "transition",
                "apply",
                "--issue-url",
                "https://example.atlassian.net/browse/PROJ-1",
                "--transition-id",
                "31",
                "--to-status-id",
                "10002",
                "--expected-issue-id",
                "10001",
                "--expected-status-id",
                "10000",
                "--resolution-id",
                "1",
            ],
        );
        applied(&typed);
        applied(&run(
            &base,
            &[
                "invoke",
                "jira.issue.transition.apply",
                "--input-json",
                &inputs().to_string(),
            ],
        ));
        applied(&run(&base, &["send","--request-json",&json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":APPLY,"inputs":inputs()}).to_string()]));
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/jira/{APPLY}"))
            .header(REQUEST_ID_HEADER, uuid::Uuid::new_v4().to_string())
            .bearer_auth("agent-token")
            .json(&json!({"inputs": inputs()}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.json::<Value>().await.unwrap();
        assert!(status.is_success(), "{status}: {body}");
        applied(&body);
        assert_eq!(
            *backend.transition_writes.lock().unwrap(),
            vec![("10001".into(), "31".into(), Some("1".into())); 4]
        );
        let execution = if matches!(access, JiraAccess::AgentPerUser) {
            "jira-per-user-token"
        } else {
            "jira-token"
        };
        let observations = backend
            .credential_observations
            .lock()
            .unwrap()
            .iter()
            .map(|o| {
                (
                    o.operation.clone(),
                    if o.operation == "issue_metadata" && matches!(access, JiraAccess::AgentService)
                    {
                        "jira-lookup-token"
                    } else {
                        execution
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_credential_observations(
            &backend,
            &observations
                .iter()
                .map(|(op, token)| (op.as_str(), *token))
                .collect::<Vec<_>>(),
        );
        let audit = broker.audit().unwrap().text();
        assert!(audit.contains(APPLY));
        assert!(!audit.contains("Stalled"));
        assert!(!audit.contains("Stall work"));
        stop(broker).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_transition_grants_are_independent_and_project_denial_does_not_execute() {
    for actions in [vec![LIST], vec![APPLY], vec!["issue.update"]] {
        let (broker, backend) = start(JiraAccess::AgentService, &actions).await;
        let base = broker.public_url();
        let denied = if actions.contains(&LIST) { APPLY } else { LIST };
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/jira/{denied}"))
            .header(REQUEST_ID_HEADER, uuid::Uuid::new_v4().to_string())
            .bearer_auth("agent-token")
            .json(&json!({"inputs": if denied == APPLY { inputs() } else { json!({"issue":"PROJ-1"}) }}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(response["decision"], "deny", "{response}");
        assert_eq!(response["reasonCode"], "scope_unresolved", "{response}");
        assert!(backend.transition_writes.lock().unwrap().is_empty());
        assert!(
            backend
                .credential_observations
                .lock()
                .unwrap()
                .iter()
                .all(|o| o.operation == "issue_metadata")
        );
        let allowed = actions[0];
        let denied_project = if allowed == APPLY {
            let mut v = inputs();
            v["issue"] = json!("OTHER-1");
            v
        } else if allowed == LIST {
            json!({"issue":"OTHER-1"})
        } else {
            json!({"issue":"OTHER-1","summary":"Updated"})
        };
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/invoke/jira/{allowed}"))
            .header(REQUEST_ID_HEADER, uuid::Uuid::new_v4().to_string())
            .bearer_auth("agent-token")
            .json(&json!({"inputs": denied_project}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(response["decision"], "deny", "{response}");
        assert_eq!(response["reasonCode"], "scope_unresolved", "{response}");
        assert!(backend.transition_writes.lock().unwrap().is_empty());
        assert!(
            backend
                .credential_observations
                .lock()
                .unwrap()
                .iter()
                .all(|o| o.operation == "issue_metadata")
        );
        if actions.contains(&APPLY) {
            applied(&run(
                &base,
                &[
                    "invoke",
                    "jira.issue.transition.apply",
                    "--input-json",
                    &inputs().to_string(),
                ],
            ));
        }
        stop(broker).await;
    }
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
async fn jira_transitions_run_through_both_mcp_transports() {
    let (broker, backend) = start(JiraAccess::AgentService, &[LIST, APPLY]).await;
    let base = broker.public_url();
    let initialize = json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"transition-smoke","version":"1"}});
    let mut stdio = list_mcp::StdioMcp::start(command(&base));
    assert!(
        stdio
            .request("initialize", initialize.clone())
            .await
            .get("error")
            .is_none()
    );
    stdio.notify("notifications/initialized", json!({}));
    let client = reqwest::Client::new();
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
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":initialize}),
        None,
    )
    .send()
    .await
    .unwrap();
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(rpc_body(initialized).await.get("error").is_none());
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
    for (index, action) in [LIST, APPLY].into_iter().enumerate() {
        let arguments = if action == APPLY {
            inputs()
        } else {
            json!({"issue":"PROJ-1","includeFields":true})
        };
        let params = json!({"name":agent_access_core::mcp::tool_name("jira",action),"arguments":{"inputs":arguments}});
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
            assert_eq!(response["result"]["isError"], false, "{response}");
            let result = &response["result"]["structuredContent"];
            if action == APPLY {
                applied(result);
            } else {
                assert_eq!(result["result"]["transitions"][0]["id"], "31");
            }
        }
    }
    assert_eq!(backend.transition_writes.lock().unwrap().len(), 2);
    stdio.finish().await;
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_read_only_token_lists_but_refuses_transition_before_upstream_work() {
    use agent_access_core::{
        BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
        ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole,
        PrincipalWriteRequest,
    };
    let (broker, backend, token) = start_configured(JiraAccess::AgentService, &[LIST, APPLY], |application, document| {
        let key = application.directory().secret_file("transition-token-key", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([41_u8;32])).unwrap();
        let path = application.directory().join("transition-tokens.sqlite");
        for (name, value) in [
            ("identity",json!({"mode":"required","authority":"managed","sources":[{"name":"broker","type":"broker_tokens","header":"Authorization","scheme":"Bearer"}]})),
            ("managed_store",json!({"type":"sqlite","path":path,"auto_migrate":true})),
            ("broker_tokens",json!({"hash_key_ref":format!("file:{}",key.display())})),
            ("credential_encryption",json!({"active_key":"fixture","keys":[{"id":"fixture","provider":"file","path":key}]})),
            ("execution_context",json!({"allowed_values":["default"],"default_context":"default"})),
        ] { document.as_table_mut().unwrap().insert(name.into(),toml::Value::try_from(value).unwrap()); }
        document["policy"]["grants"][0]["subjects"] = toml::Value::try_from(vec!["user:agent-one"]).unwrap();
        document["policy"]["grants"][0].as_table_mut().unwrap().insert("execution_contexts".into(),toml::Value::try_from(vec!["default"]).unwrap());
        let contexts = agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap();
        let store = ManagedStore::open(&ManagedStoreConfig {
            kind:"sqlite".into(),path:path.display().to_string(),auto_migrate:true,
            require_registered_principal_for_invocation:false,
        }, &contexts, ManagedStoreOpenMode::Startup).unwrap();
        store.create_principal(PrincipalWriteRequest {
            agent_token_issuance:Default::default(),principal_id:"agent-one".into(),kind:"user".into(),
            role:PrincipalRole::User,display_name:None,email:None,external_subject:None,
            self_service_enabled:None,created_by:"test".into(),
        }, &contexts).unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {hash_key_ref:format!("file:{}",key.display()),..Default::default()}).unwrap();
        store.issue_broker_token_with_catalog(&hasher,BrokerTokenIssueRequest {
            principal_id:"agent-one".into(),name:"read-only transitions".into(),token_class:BrokerTokenClass::AgentInvoke,
            scopes:json!({"readOnly":true,"allowedServices":["jira"],"allowedExecutionContexts":["default"]}),
            expires_at:None,created_by:"test".into(),
        },None).unwrap().token
    }).await;
    let client = reqwest::Client::new();
    let base = broker.public_url();
    let listed = client
        .post(format!("{base}/v1/invoke/jira/{LIST}"))
        .header(REQUEST_ID_HEADER, uuid::Uuid::new_v4().to_string())
        .bearer_auth(&token)
        .json(&json!({"inputs":{"issue":"PROJ-1"}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(listed["decision"], "allow", "{listed}");
    backend.credential_observations.lock().unwrap().clear();
    let refused = client
        .post(format!("{base}/v1/invoke/jira/{APPLY}"))
        .header(REQUEST_ID_HEADER, uuid::Uuid::new_v4().to_string())
        .bearer_auth(&token)
        .json(&json!({"inputs": inputs()}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(refused["decision"], "deny", "{refused}");
    assert_eq!(refused["reasonCode"], "service_action_denied", "{refused}");
    assert_eq!(refused["reason"], "broker token is read-only");
    assert!(backend.credential_observations.lock().unwrap().is_empty());
    assert!(backend.transition_writes.lock().unwrap().is_empty());
    stop(broker).await;
}
