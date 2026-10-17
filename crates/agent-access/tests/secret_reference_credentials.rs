//! A real GitLab producer across every invocation transport, CLI handoff,
//! encrypted credential connection, and subsequent provider call.
use agent_access_broker_host::test_support::{IsolatedBroker, ProviderFixture};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole, PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, Output, Stdio},
    time::Duration,
};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUED: &str = "issued-secret-reference-workflow-token";
const CONSUMER_ACTION: &str = "webhook.custom_header.set";

fn cli_command(url: &str, token: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(name);
        }
    }
    command.env("SECRET_REFERENCE_TEST_BROKER_TOKEN", token);
    command.args([
        "--config",
        "/dev/null",
        "--url",
        url,
        "--token-env",
        "SECRET_REFERENCE_TEST_BROKER_TOKEN",
        "--identity-header",
        "Authorization",
        "--identity-scheme",
        "Bearer",
    ]);
    command
}

fn cli(url: &str, token: &str, args: &[&str]) -> Output {
    cli_command(url, token).args(args).output().unwrap()
}

fn result(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ISSUED));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(ISSUED));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn issued_reference(envelope: &Value) -> String {
    assert_eq!(envelope["decision"], "allow", "{envelope}");
    assert!(!envelope.to_string().contains(ISSUED));
    let issued = &envelope["result"]["issuedToken"];
    assert!(issued["expiresAt"].is_string(), "{envelope}");
    let reference = issued["secretRef"].as_str().unwrap();
    assert!(reference.starts_with("sr_"));
    reference.to_owned()
}

fn action_tool<'a>(listing: &'a Value, action: &str) -> &'a Value {
    listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| {
            tool["_meta"]["agent-access/service"] == "gitlab"
                && tool["_meta"]["agent-access/action"] == action
        })
        .unwrap()
}

fn issuance_tool(listing: &Value) -> &str {
    let tool = action_tool(listing, "project.access_token.create");
    assert_eq!(
        tool["_meta"]["agent-access/secret-output-mode"],
        "reference"
    );
    tool["name"].as_str().unwrap()
}

fn mcp_issued_reference(response: &Value) -> String {
    assert!(!response.to_string().contains(ISSUED));
    assert_eq!(response["result"]["isError"], false, "{response}");
    issued_reference(&response["result"]["structuredContent"])
}

async fn mcp_post(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    session: Option<&str>,
    body: Value,
) -> reqwest::Response {
    let mut request = client
        .post(endpoint)
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream");
    if let Some(session) = session {
        request = request
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25");
    }
    request.json(&body).send().await.unwrap()
}

async fn mcp_http_body(response: reqwest::Response) -> Value {
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let wire = response.text().await.unwrap();
    assert!(!wire.contains(ISSUED));
    if wire.trim_start().starts_with('{') {
        return serde_json::from_str(&wire).unwrap();
    }
    let responses = wire
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|value| value.get("id").is_some())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 1, "{wire}");
    responses.into_iter().next().unwrap()
}

struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: tokio::sync::mpsc::UnboundedReceiver<String>,
    stderr: Option<std::thread::JoinHandle<String>>,
    next_id: u64,
}

impl StdioMcp {
    fn start(url: &str, token: &str) -> Self {
        let mut child = cli_command(url, token)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, responses) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Some(std::thread::spawn(move || {
            let mut text = String::new();
            stderr.take(65536).read_to_string(&mut text).unwrap();
            text
        }));
        Self {
            child,
            stdin,
            responses,
            stderr,
            next_id: 1,
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let line = self.responses.recv().await.expect("stdio MCP closed");
                assert!(!line.contains(ISSUED));
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["id"] == id {
                    return value;
                }
                assert!(value.get("id").is_none(), "{value}");
            }
        })
        .await
        .expect("stdio MCP response timed out")
    }

    async fn finish(mut self) {
        self.stdin.take();
        let status = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stdio MCP did not exit");
        let stderr = self.stderr.take().unwrap().join().unwrap();
        assert!(!stderr.contains(ISSUED));
        assert!(status.success(), "stdio MCP failed: {stderr}");
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_references_cross_all_transports_and_import_without_plaintext_roundtrip() {
    let upstream = MockServer::start().await;
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let hash_key = directory
        .secret_file("token-hash-key", URL_SAFE_NO_PAD.encode([31u8; 32]))
        .unwrap();
    let encryption_key = directory
        .secret_file("encryption-key", URL_SAFE_NO_PAD.encode([32u8; 32]))
        .unwrap();
    let service_token = directory
        .secret_file("service-token", "issuer-service-token")
        .unwrap();
    let lookup_token = directory
        .secret_file("lookup-token", "lookup-service-token")
        .unwrap();
    let store_path = directory.join("managed.sqlite");
    let audit_path = directory.join("audit.jsonl");
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: true,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for (principal, kind, role) in [
        ("issuer", "user", PrincipalRole::User),
        ("admin", "user", PrincipalRole::Admin),
        ("robot", "service_account", PrincipalRole::User),
    ] {
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: principal.into(),
                kind: kind.into(),
                role,
                self_service_enabled: None,
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "fixture".into(),
            })
            .unwrap();
    }
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    })
    .unwrap();
    let issue = |principal: &str, token_class: BrokerTokenClass| {
        store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "fixture".into(),
                    token_class,
                    scopes: json!({"allowedExecutionContexts":["default"]}),
                    expires_at: None,
                    created_by: "fixture".into(),
                },
            )
            .unwrap()
            .token
    };
    let issuer = issue("issuer", BrokerTokenClass::AgentInvoke);
    let administrator = issue("admin", BrokerTokenClass::Admin);
    let robot = issue("robot", BrokerTokenClass::AgentInvoke);
    let q = |value: String| serde_json::to_string(&value).unwrap();
    let config = format!(
        r#"
[deployment]
environment = "test"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[broker_tokens]
hash_key_ref = {hash_key}
[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
require_registered_principal_for_invocation = true
[credential_encryption]
active_key = "fixture"
[[credential_encryption.keys]]
id = "fixture"
provider = "file"
path = {encryption_key}
[management]
enabled = true
[management.initial_admin]
mode = "disabled"
[mcp]
enabled = true
public_url = {mcp_url}
[secret_outputs]
mode = "reference"
[credentials.service.gitlab]
type = "bearer_token"
token_ref = {service_token}
[credentials.lookup.gitlab]
type = "bearer_token"
token_ref = {lookup_token}
read_only = true
[credentials.connections.gitlab]
token_profile = "gitlab-access-token"
[credentials.per_user.gitlab]
type = "connection"
connection = "gitlab"
[providers.gitlab]
api_base_url = {api_url}
web_base_url = {web_url}
allowed_upstream_hosts = [{allowed_url}]
[providers.gitlab.provisioning]
enabled = true
[audit]
type = "jsonl"
path = {audit}
[limits]
upload_spool_dir = {spool}
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "project"
resource_type = {resource_type}
selector = {{kind = "exact", value = "acme/portal"}}
allowed_execution_contexts = ["default"]
[[policy.grants]]
subjects = ["user:issuer"]
service = "gitlab"
actions = ["project.access_token.create", "project.member.view", "webhook.custom_header.set"]
resources = {{resource_ids = ["project"]}}
credential_mode = "service"
[[policy.grants]]
subjects = ["user:robot"]
service = "gitlab"
actions = ["project.view"]
resources = {{resource_ids = ["project"]}}
credential_mode = "per_user"
"#,
        hash_key = q(format!("file:{}", hash_key.display())),
        store = q(store_path.display().to_string()),
        encryption_key = q(encryption_key.display().to_string()),
        service_token = q(format!("file:{}", service_token.display())),
        lookup_token = q(format!("file:{}", lookup_token.display())),
        mcp_url = q(format!("{}/mcp", application.public_url())),
        api_url = q(format!("{}/api/v4", upstream.uri())),
        web_url = q(upstream.uri()),
        allowed_url = q(format!("{}/api/v4/**", upstream.uri())),
        audit = q(audit_path.display().to_string()),
        spool = q(directory.join("upload-spool").display().to_string()),
        resource_type = q(agent_access_provider::GIT_REPOSITORY_RESOURCE
            .id()
            .to_string()),
    );
    let project = json!({"id":42,"path_with_namespace":"acme/portal","name":"portal"});
    for token in ["lookup-service-token", "issuer-service-token"] {
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/acme%2Fportal"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(project.clone()))
            .mount(&upstream)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/acme%2Fportal"))
        .and(header("authorization", format!("Bearer {ISSUED}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(project))
        // Scope resolution, invocation lookup, and the actual project read all
        // use the installed per-user credential.
        .expect(3)
        .mount(&upstream)
        .await;
    let expiry = (chrono::Utc::now().date_naive() + chrono::Duration::days(7)).to_string();
    for name in [
        "typed-reviewer",
        "invoke-reviewer",
        "send-reviewer",
        "http-mcp-reviewer",
        "stdio-mcp-reviewer",
    ] {
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/42/access_tokens"))
            .and(header("authorization", "Bearer issuer-service-token"))
            .and(body_json(json!({
                "name":name, "scopes":["read_api"],
                "access_level":30, "expires_at":expiry,
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id":10,"user_id":70,"name":name,"scopes":["read_api"],
                "access_level":30,"expires_at":expiry,"active":true,"revoked":false,"token":ISSUED,
            })))
            .expect(1)
            .mount(&upstream)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/members/70"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":70,"username":"project_42_bot_fixture","name":"reviewer","access_level":30,
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let header_keys = ["X-Send-Reference", "X-Stdio-Reference"];
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/hooks/9"))
        .and(header("authorization", "Bearer issuer-service-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":9, "project_id":42, "url":"https://hooks.example.test/events",
            "custom_headers":header_keys.map(|key| json!({"key":key})),
        })))
        .expect(4)
        .mount(&upstream)
        .await;
    for key in header_keys {
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/v4/projects/42/hooks/9/custom_headers/{key}"
            )))
            .and(header("authorization", "Bearer issuer-service-token"))
            .and(body_json(json!({"value":ISSUED})))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&upstream)
            .await;
    }
    let broker = application
        .config_document(config)
        .provider_fixture(
            "gitlab",
            ProviderFixture::factory(|context| {
                // Exercise a declared secret consumer with the real native
                // GitLab implementation and real upstream HTTP, while keeping
                // this test-only declaration out of the production catalog.
                let mut service = context.registered_provider().unwrap();
                let action = service
                    .descriptor
                    .actions
                    .iter_mut()
                    .find(|action| action.action == CONSUMER_ACTION)
                    .unwrap();
                action.input_schema["properties"]["value"]["writeOnly"] = json!(true);
                action
                    .secret_inputs
                    .push(agent_access_provider::SecretInputDescriptor::new(
                        "/inputs/value",
                    ));
                service
            }),
        )
        .start()
        .await
        .unwrap();
    let url = broker.public_url();
    let issued = result(cli(
        &url,
        &issuer,
        &[
            "gitlab",
            "project",
            "access-token",
            "create",
            "acme/portal",
            "--name",
            "typed-reviewer",
            "--access-level",
            "30",
            "--scopes",
            "read_api",
            "--expires-at",
            &expiry,
        ],
    ));
    let reference = issued_reference(&issued);
    let mut references = vec![reference.clone()];
    let inputs = |name: &str| {
        json!({
            "project":"acme/portal", "name":name, "scopes":["read_api"],
            "accessLevel":30, "expiresAt":expiry,
        })
    };
    let invoked = result(cli(
        &url,
        &issuer,
        &[
            "invoke",
            "gitlab.project.access_token.create",
            "--input-json",
            &inputs("invoke-reviewer").to_string(),
        ],
    ));
    references.push(issued_reference(&invoked));
    let sent = result(cli(
        &url,
        &issuer,
        &[
            "send",
            "--request-json",
            &json!({
                "version":"agent-access.send.v1", "kind":"invoke",
                "service":"gitlab", "action":"project.access_token.create",
                "inputs":inputs("send-reviewer"),
            })
            .to_string(),
        ],
    ));
    references.push(issued_reference(&sent));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let endpoint = format!("{url}/mcp");
    let initialize_params = json!({
        "protocolVersion":"2025-11-25", "capabilities":{},
        "clientInfo":{"name":"secret-reference-workflow", "version":"1"},
    });
    let initialized = mcp_post(
        &client,
        &endpoint,
        &issuer,
        None,
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":initialize_params}),
    )
    .await;
    assert_eq!(initialized.status(), reqwest::StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp_http_body(initialized).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    let notification = mcp_post(
        &client,
        &endpoint,
        &issuer,
        Some(&session),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(notification.status(), reqwest::StatusCode::ACCEPTED);
    let listing = mcp_http_body(
        mcp_post(
            &client,
            &endpoint,
            &issuer,
            Some(&session),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
        )
        .await,
    )
    .await;
    let called = mcp_http_body(
        mcp_post(
            &client,
            &endpoint,
            &issuer,
            Some(&session),
            json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{
                "name":issuance_tool(&listing),
                "arguments":{"inputs":inputs("http-mcp-reviewer")},
            }}),
        )
        .await,
    )
    .await;
    references.push(mcp_issued_reference(&called));
    let deleted = client
        .delete(&endpoint)
        .bearer_auth(&issuer)
        .header("mcp-session-id", session)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await
        .unwrap();
    assert!(deleted.status().is_success());

    let mut stdio = StdioMcp::start(&url, &issuer);
    let initialized = stdio.request("initialize", initialize_params).await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    stdio.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
    let listing = stdio.request("tools/list", json!({})).await;
    let called = stdio
        .request(
            "tools/call",
            json!({
                "name":issuance_tool(&listing),
                "arguments":{"inputs":inputs("stdio-mcp-reviewer")},
            }),
        )
        .await;
    references.push(mcp_issued_reference(&called));
    let consumer = action_tool(&listing, CONSUMER_ACTION);
    assert_eq!(
        consumer["_meta"]["agent-access/secret-input-pointers"],
        json!(["/inputs/value"])
    );
    let consume = |key: &str, value: Value| json!({"project":"acme/portal", "webhookId":9, "key":key, "value":value});
    let send_consumer = |inputs: Value| {
        cli(
            &url,
            &issuer,
            &[
                "send",
                "--request-json",
                &json!({
                    "version":"agent-access.send.v1", "kind":"invoke", "service":"gitlab",
                    "action":CONSUMER_ACTION, "inputs":inputs,
                })
                .to_string(),
            ],
        )
    };
    let protected = issued["result"]["issuedToken"].clone();
    let consumed = result(send_consumer(consume(
        "X-Send-Reference",
        protected.clone(),
    )));
    assert_eq!(consumed["decision"], "allow");
    assert_eq!(consumed["result"]["mutationStatus"], "applied");
    assert!(!consumed.to_string().contains(&reference));
    let consumed = stdio
        .request(
            "tools/call",
            json!({
                "name":consumer["name"],
                "arguments":{"inputs":consume("X-Stdio-Reference", protected.clone())},
            }),
        )
        .await;
    assert_eq!(consumed["result"]["isError"], false, "{consumed}");
    assert_eq!(
        consumed["result"]["structuredContent"]["result"]["mutationStatus"],
        "applied"
    );
    assert!(!consumed.to_string().contains(&reference));

    let mut undeclared = consume("X-Send-Reference", protected.clone());
    undeclared["key"] = protected.clone();
    for inputs in [
        consume("X-Send-Reference", json!(ISSUED)),
        consume("X-Send-Reference", json!(reference)),
        consume(&reference, protected.clone()),
        consume(&format!("TOKEN={reference}"), protected.clone()),
        consume("X-Send-Reference", json!(format!("Bearer {reference}"))),
        consume(
            "X-Send-Reference",
            json!({"secretRef":reference,"extra":true}),
        ),
        undeclared,
    ] {
        let upstream_calls = upstream.received_requests().await.unwrap().len();
        let denied = send_consumer(inputs.clone());
        assert!(!denied.status.success());
        for bytes in [&denied.stdout, &denied.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(ISSUED));
            assert!(!text.contains(&reference));
        }
        let denied = stdio
            .request(
                "tools/call",
                json!({"name":consumer["name"], "arguments":{"inputs":inputs}}),
            )
            .await;
        assert_eq!(denied["result"]["isError"], true, "{denied}");
        assert!(!denied.to_string().contains(&reference));
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            upstream_calls,
            "invalid inline capabilities must be rejected before any upstream request"
        );
    }

    let unavailable_reference = format!("sr_{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
    assert!(!references.contains(&unavailable_reference));
    let unavailable = json!({"secretRef":unavailable_reference});
    let denied = send_consumer(consume("X-Send-Reference", unavailable.clone()));
    assert!(!denied.status.success());
    let denied: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied["reasonCode"], "secret_reference_not_found");
    let denied = stdio
        .request(
            "tools/call",
            json!({
                "name":consumer["name"],
                "arguments":{"inputs":consume("X-Stdio-Reference", unavailable)},
            }),
        )
        .await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    assert_eq!(
        denied["result"]["structuredContent"]["reasonCode"],
        "secret_reference_not_found"
    );
    stdio.finish().await;
    assert_eq!(
        references
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        5,
        "each issuance must have its own reference"
    );
    let member = result(cli(
        &url,
        &issuer,
        &["gitlab", "project", "member", "view", "acme/portal", "70"],
    ));
    assert_eq!(
        member["result"]["member"]["username"],
        "project_42_bot_fixture"
    );
    let stored = result(cli(
        &url,
        &administrator,
        &[
            "admin",
            "credentials",
            "put",
            "robot",
            "gitlab",
            "--field-ref",
            &format!("token={reference}"),
        ],
    ));
    assert_eq!(stored["result"]["ownerPrincipal"], "robot");
    assert!(!stored.to_string().contains(&reference));
    let view = result(cli(
        &url,
        &robot,
        &["gitlab", "project", "view", "acme/portal"],
    ));
    assert_eq!(view["result"]["project"]["id"], 42);
    let mut issuance_names = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| {
            request.method == "POST" && request.url.path() == "/api/v4/projects/42/access_tokens"
        })
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["name"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    issuance_names.sort();
    assert_eq!(
        issuance_names,
        [
            "http-mcp-reviewer",
            "invoke-reviewer",
            "send-reviewer",
            "stdio-mcp-reviewer",
            "typed-reviewer",
        ],
        "each transport must dispatch its own issuance exactly once"
    );
    broker.shutdown();
    broker.join().await.unwrap();
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(!audit.contains(ISSUED));
    for reference in &references {
        assert!(!audit.contains(reference));
    }
    assert!(audit.contains("secretReferences"));
}
