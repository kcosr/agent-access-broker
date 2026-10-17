//! Builtin local administration through the real host, CLI and both MCP transports.
use super::{McpProcess, isolated_broker, stop, toml_string};
use agent_access_broker_host::test_support::{FixtureDir, RunningBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    GroupWriteRequest, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole,
    PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

const SERVICE: &str = "broker_management";
const ISSUED_GITLAB_TOKEN: &str = "synthetic-local-admin-issued-gitlab-token";
const MODES: [&str; 4] = ["http", "cli", "http-mcp", "stdio-mcp"];
const ACTIONS: [&str; 14] = [
    "principal.create",
    "principal.view",
    "group.view",
    "group.member.view",
    "group.member.add",
    "group.member.remove",
    "grant.view",
    "grant.subject.view",
    "grant.subject.add",
    "grant.subject.remove",
    "credential.view",
    "credential.install",
    "token.create",
    "token.view",
];

struct Fixture {
    broker: RunningBroker,
    client: reqwest::Client,
    base: String,
    token: String,
    config: PathBuf,
    upstream: MockServer,
    expiry: String,
    references: Vec<String>,
}

impl Fixture {
    async fn new() -> Self {
        let upstream = MockServer::start().await;
        let application = isolated_broker();
        let directory = application.directory().clone();
        let base = application.public_url();
        let hash = directory
            .secret_file("hash", URL_SAFE_NO_PAD.encode([17; 32]))
            .unwrap();
        directory
            .secret_file("key", URL_SAFE_NO_PAD.encode([18; 32]))
            .unwrap();
        directory
            .secret_file("gitlab-service", "synthetic-issuer-service-token")
            .unwrap();
        directory
            .secret_file("gitlab-lookup", "synthetic-issuer-lookup-token")
            .unwrap();
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: directory.join("store.sqlite").display().to_string(),
                auto_migrate: true,
                require_registered_principal_for_invocation: true,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        for (principal_id, kind, role) in [
            ("administrator", "user", PrincipalRole::Admin),
            ("operator", "user", PrincipalRole::User),
            ("seed-worker", "service_account", PrincipalRole::User),
        ] {
            store
                .create_principal(PrincipalWriteRequest {
                    principal_id: principal_id.into(),
                    kind: kind.into(),
                    role,
                    self_service_enabled: Some(false),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "fixture".into(),
                })
                .unwrap();
        }
        store
            .create_group(GroupWriteRequest {
                group_id: "workers".into(),
                display_name: Some("Workers".into()),
                description: None,
                created_by: "fixture".into(),
            })
            .unwrap();
        let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash.display()),
            ..Default::default()
        })
        .unwrap();
        let issue = |principal: &str, token_class, scopes| {
            store
                .issue_broker_token(
                    &hasher,
                    BrokerTokenIssueRequest {
                        principal_id: principal.into(),
                        name: "transport fixture".into(),
                        token_class,
                        scopes,
                        expires_at: None,
                        created_by: "fixture".into(),
                    },
                )
                .unwrap()
                .token
        };
        let administrator = issue("administrator", BrokerTokenClass::Admin, json!({}));
        let token = issue(
            "operator",
            BrokerTokenClass::AgentInvoke,
            json!({"allowedServices":[SERVICE,"gitlab"],"allowedExecutionContexts":["default"]}),
        );
        drop(store);
        let token_path = directory.secret_file("client.token", &token).unwrap();
        let config = directory.join("client.toml");
        std::fs::write(&config, format!(
            "[service]\nurl={}\n[identity]\nheader=\"Authorization\"\nscheme=\"Bearer\"\ndisabled=false\ntoken_file={}\n",
            toml_string(&base), toml_string(token_path.display()),
        )).unwrap();
        let broker = application
            .config_document(document(&directory, &base, &upstream.uri()))
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let expiry = (chrono::Utc::now().date_naive() + chrono::Duration::days(7)).to_string();
        let fixture = Self {
            broker,
            client,
            base,
            token,
            config,
            upstream,
            expiry,
            references: vec![],
        };

        let mut managed_resources = vec![];
        for mode in MODES {
            let id = format!("worker-{mode}");
            fixture.admin(&administrator, "/v1/admin/policy/resources", json!({
                "id":id,"resourceType":"broker_principal","selector":{"kind":"exact","value":id},
                "allowedExecutionContexts":["default"]
            })).await;
            managed_resources.push(id);
        }
        for (id, resource_type, value) in [
            ("workers", "broker_group", "workers"),
            ("service-access", "broker_grant", "service-access"),
            ("gitlab-connection", "broker_connection", "gitlab"),
            ("project", "git_repository", "acme/portal"),
            ("fake-project", "fake_project", "TEST"),
        ] {
            fixture.admin(&administrator, "/v1/admin/policy/resources", json!({
                "id":id,"resourceType":resource_type,"selector":{"kind":"exact","value":value},
                "allowedExecutionContexts":["default"]
            })).await;
            if resource_type.starts_with("broker_") {
                managed_resources.push(id.into());
            }
        }
        for (grant_id, subjects, service, actions, resources) in [
            (
                "service-access",
                vec!["user:seed-worker"],
                "fake",
                vec!["echo"],
                vec!["fake-project".to_owned()],
            ),
            (
                "producer",
                vec!["user:operator"],
                "gitlab",
                vec!["project.access_token.create"],
                vec!["project".to_owned()],
            ),
            (
                "provision",
                vec!["user:operator"],
                SERVICE,
                ACTIONS.to_vec(),
                managed_resources,
            ),
        ] {
            fixture.admin(&administrator, "/v1/admin/policy/grants", json!({
                "grantId":grant_id,"subjects":subjects,"executionContexts":["default"],
                "service":service,"actions":actions,"resources":{"resourceIds":resources},"credentialMode":"service"
            })).await;
        }
        for token in [
            "synthetic-issuer-service-token",
            "synthetic-issuer-lookup-token",
        ] {
            Mock::given(method("GET"))
                .and(path("/api/v4/projects/acme%2Fportal"))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id":42,"path_with_namespace":"acme/portal","name":"portal"
                })))
                .mount(&fixture.upstream)
                .await;
        }
        for mode in MODES {
            Mock::given(method("POST")).and(path("/api/v4/projects/42/access_tokens"))
                .and(header("authorization", "Bearer synthetic-issuer-service-token"))
                .and(body_json(json!({"name":mode,"scopes":["read_api"],"access_level":30,"expires_at":fixture.expiry})))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "id":10,"user_id":70,"name":mode,"scopes":["read_api"],"access_level":30,
                    "expires_at":fixture.expiry,"active":true,"revoked":false,"token":ISSUED_GITLAB_TOKEN
                }))).expect(1).mount(&fixture.upstream).await;
        }
        fixture
    }

    async fn admin(&self, token: &str, route: &str, body: Value) -> Value {
        let response = self
            .client
            .post(format!("{}{route}", self.base))
            .bearer_auth(token)
            .header(
                "X-Agent-Access-Request-Id",
                uuid::Uuid::new_v4().to_string(),
            )
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let value: Value = response.json().await.unwrap();
        assert!(status.is_success(), "{route}: {value}");
        value
    }

    async fn http(&self, service: &str, action: &str, inputs: Value) -> Value {
        let response = self
            .client
            .post(format!("{}/v1/invoke/{service}/{action}", self.base))
            .bearer_auth(&self.token)
            .header(
                "X-Agent-Access-Request-Id",
                uuid::Uuid::new_v4().to_string(),
            )
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap();
        if matches!(action, "token.create" | "project.access_token.create") {
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let value = response.json().await.unwrap();
        safe(&value);
        value
    }

    fn cli(&self, args: &[&str]) -> Value {
        self.cli_expect(args, true)
    }

    fn cli_expect(&self, args: &[&str], success: bool) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        let output = command
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains(ISSUED_GITLAB_TOKEN));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(ISSUED_GITLAB_TOKEN));
        assert_eq!(
            output.status.success(),
            success,
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    async fn actions(&self, targets: Value) -> Value {
        let response = self
            .client
            .get(format!("{}/v1/services/{SERVICE}/actions", self.base))
            .bearer_auth(&self.token)
            .header(
                "X-Agent-Access-Request-Id",
                uuid::Uuid::new_v4().to_string(),
            )
            .query(&[("targets", targets.to_string())])
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        response.json().await.unwrap()
    }

    async fn rpc(&self, session: Option<&str>, body: Value) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.base))
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream");
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        request.json(&body).send().await.unwrap()
    }
}

fn safe(value: &Value) {
    assert!(!value.to_string().contains(ISSUED_GITLAB_TOKEN));
}

fn allowed(value: &Value) -> &Value {
    safe(value);
    assert_eq!(value["decision"], "allow", "{value}");
    assert!(value["result"].is_object(), "{value}");
    &value["result"]
}

fn settled_conflict(value: &Value) {
    safe(value);
    assert_eq!(value["decision"], "deny", "{value}");
    assert_eq!(
        value["reasonCode"], "access_management_target_exists",
        "{value}"
    );
    assert_eq!(
        value["result"]["executionState"], "not_committed",
        "{value}"
    );
    assert_eq!(value["result"]["retrySafe"], false, "{value}");
}

fn tool_names(listing: &Value) -> BTreeMap<String, String> {
    listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tool| tool["_meta"]["agent-access/service"] == SERVICE)
        .map(|tool| {
            (
                tool["_meta"]["agent-access/action"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                tool["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

async fn rpc_body(response: reqwest::Response) -> Value {
    assert!(response.status().is_success());
    assert_eq!(response.headers()["cache-control"], "no-store");
    let text = response.text().await.unwrap();
    assert!(!text.contains(ISSUED_GITLAB_TOKEN));
    if text.trim_start().starts_with('{') {
        return serde_json::from_str(&text).unwrap();
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|value| value.get("id").is_some())
        .unwrap()
}

struct McpClients {
    session: String,
    http_names: BTreeMap<String, String>,
    stdio: McpProcess,
    stdio_names: BTreeMap<String, String>,
    next_id: u64,
}

impl McpClients {
    async fn new(fixture: &Fixture) -> Self {
        let initialized = fixture.rpc(None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local-admin-test","version":"1"}
        }})).await;
        let session = initialized.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(rpc_body(initialized).await.get("error").is_none());
        let notification = fixture
            .rpc(
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await;
        assert_eq!(notification.status(), reqwest::StatusCode::ACCEPTED);
        let listing = rpc_body(
            fixture
                .rpc(
                    Some(&session),
                    json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
                )
                .await,
        )
        .await;
        let http_names = tool_names(&listing);
        let mut stdio = McpProcess::start(&fixture.config);
        stdio.initialize().await;
        let stdio_names = tool_names(&stdio.request("tools/list", json!({})).await);
        assert_eq!(http_names.len(), ACTIONS.len());
        assert_eq!(stdio_names.len(), ACTIONS.len());
        Self {
            session,
            http_names,
            stdio,
            stdio_names,
            next_id: 3,
        }
    }

    async fn call(&mut self, fixture: &Fixture, mode: &str, name: &str, inputs: Value) -> Value {
        self.call_expect(fixture, mode, name, inputs, true).await
    }

    async fn call_expect(
        &mut self,
        fixture: &Fixture,
        mode: &str,
        name: &str,
        inputs: Value,
        success: bool,
    ) -> Value {
        match mode {
            "http" => fixture.http(SERVICE, name, inputs).await,
            "cli" => fixture.cli_expect(
                &[
                    "invoke",
                    &format!("{SERVICE}.{name}"),
                    "--input-json",
                    &inputs.to_string(),
                ],
                success,
            ),
            "http-mcp" | "stdio-mcp" => {
                let response = if mode == "http-mcp" {
                    self.next_id += 1;
                    rpc_body(fixture.rpc(Some(&self.session), json!({"jsonrpc":"2.0","id":self.next_id,"method":"tools/call","params":{
                        "name":self.http_names[name],"arguments":{"inputs":inputs}
                    }})).await).await
                } else {
                    self.stdio
                        .request(
                            "tools/call",
                            json!({"name":self.stdio_names[name],"arguments":{"inputs":inputs}}),
                        )
                        .await
                };
                assert_eq!(response["result"]["isError"], !success, "{response}");
                response["result"]["structuredContent"].clone()
            }
            _ => unreachable!(),
        }
    }

    async fn finish(self, fixture: &Fixture) {
        self.stdio.finish().await;
        let response = fixture
            .client
            .delete(format!("{}/mcp", fixture.base))
            .bearer_auth(&fixture.token)
            .header("mcp-session-id", self.session)
            .header("mcp-protocol-version", "2025-11-25")
            .header("accept", "application/json, text/event-stream")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn builtin_management_uses_real_http_cli_and_mcp_without_plaintext_or_admin_authority() {
    let mut fixture = Fixture::new().await;
    let mut mcp = McpClients::new(&fixture).await;
    let description = fixture.cli(&["services", "describe", SERVICE]);
    assert_eq!(
        description["availability"]["state"], "available",
        "{description}"
    );
    assert_eq!(description["availability"]["requirements"], json!([]));
    for action in description["actions"].as_array().unwrap() {
        assert!(action["requiredScopes"].is_object());
    }
    for mode in MODES {
        let worker = format!("worker-{mode}");
        // Discovery proves policy on an exact tuple before the object exists.
        let targets = json!({"principal":[worker],"group":["workers"]});
        let before = fixture.actions(targets.clone()).await;
        assert_eq!(before["matchKind"], "complete_targets");
        assert!(before["policyGeneration"].is_u64());
        assert_eq!(
            before["actions"],
            json!([
                "group.member.add",
                "group.member.remove",
                "group.member.view"
            ])
        );
        assert!(before.get("resource").is_none());
        let cli_actions = fixture.cli(&[
            "actions",
            "list",
            "--service",
            SERVICE,
            "--targets-json",
            &targets.to_string(),
        ]);
        assert_eq!(cli_actions["actions"], before["actions"]);
        for transport in ["http-mcp", "stdio-mcp"] {
            let args = json!({"service":SERVICE,"targets":targets});
            let result = if transport == "http-mcp" {
                mcp.next_id += 1;
                rpc_body(
                    fixture
                        .rpc(
                            Some(&mcp.session),
                            json!({"jsonrpc":"2.0","id":mcp.next_id,"method":"tools/call","params":{
                                "name":"actions_list","arguments":args
                            }}),
                        )
                        .await,
                )
                .await
            } else {
                mcp.stdio
                    .request(
                        "tools/call",
                        json!({"name":"actions_list","arguments":args}),
                    )
                    .await
            };
            assert_eq!(
                result["result"]["structuredContent"]["actions"], before["actions"],
                "{result}"
            );
            assert_eq!(
                result["result"]["structuredContent"]["matchKind"],
                "complete_targets"
            );
        }

        let created = mcp
            .call(
                &fixture,
                mode,
                "principal.create",
                json!({"principalId":worker,"displayName":"Transport worker"}),
            )
            .await;
        let principal = allowed(&created);
        assert_eq!(principal["principalId"], worker);
        assert_eq!(principal["kind"], "service_account");
        assert_eq!(principal["role"], "user");
        assert_eq!(principal["selfServiceEnabled"], false);
        for field in ["groups", "email", "externalSubject", "createdBy"] {
            assert!(principal.get(field).is_none());
        }
        // This reaches the local transaction and rolls back; its receipt is
        // preserved as an error across every generic invocation transport.
        let conflict = mcp
            .call_expect(
                &fixture,
                mode,
                "principal.create",
                json!({"principalId":worker,"displayName":"Must not replace the worker"}),
                false,
            )
            .await;
        settled_conflict(&conflict);
        if mode == "cli" {
            let request = json!({"version":"agent-access.send.v1","kind":"invoke",
                "service":SERVICE,"action":"principal.create","inputs":{"principalId":worker}});
            settled_conflict(
                &fixture.cli_expect(&["send", "--request-json", &request.to_string()], false),
            );
        }
        let viewed = mcp
            .call(
                &fixture,
                mode,
                "principal.view",
                json!({"principalId":worker}),
            )
            .await;
        assert_eq!(allowed(&viewed), principal);
        assert_eq!(fixture.actions(targets).await["actions"], before["actions"]);

        let group = mcp
            .call(&fixture, mode, "group.view", json!({"groupId":"workers"}))
            .await;
        assert_eq!(allowed(&group)["livePolicy"], true);
        assert!(allowed(&group).get("members").is_none());
        let added = mcp
            .call(
                &fixture,
                mode,
                "group.member.add",
                json!({"groupId":"workers","principalId":worker}),
            )
            .await;
        assert_eq!(allowed(&added)["changed"], true);
        let membership = mcp
            .call(
                &fixture,
                mode,
                "group.member.view",
                json!({"groupId":"workers","principalId":worker}),
            )
            .await;
        assert_eq!(allowed(&membership)["effectiveMember"], true);
        let removed = mcp
            .call(
                &fixture,
                mode,
                "group.member.remove",
                json!({"groupId":"workers","principalId":worker}),
            )
            .await;
        assert_eq!(allowed(&removed)["effectiveMember"], false);

        let grant = mcp
            .call(
                &fixture,
                mode,
                "grant.view",
                json!({"grantId":"service-access"}),
            )
            .await;
        let grant = allowed(&grant);
        assert_eq!(grant["service"], "fake");
        assert!(grant.get("subjects").is_none());
        let linked = mcp.call(&fixture, mode, "grant.subject.add", json!({"grantId":"service-access","principalId":worker,"expectedVersion":grant["version"]})).await;
        let version = allowed(&linked)["version"].as_i64().unwrap();
        assert_eq!(allowed(&linked)["directSubject"], true);
        let edge = mcp
            .call(
                &fixture,
                mode,
                "grant.subject.view",
                json!({"grantId":"service-access","principalId":worker}),
            )
            .await;
        assert_eq!(allowed(&edge)["directSubject"], true);

        let producer = fixture.http("gitlab", "project.access_token.create", json!({
            "project":"acme/portal","name":mode,"role":"developer","scopes":["read_api"],"expiresAt":fixture.expiry
        })).await;
        let issued = allowed(&producer)["issuedToken"].clone();
        let reference = issued["secretRef"].as_str().unwrap().to_owned();
        assert!(reference.starts_with("sr_"));
        fixture.references.push(reference);
        let installed = mcp
            .call(
                &fixture,
                mode,
                "credential.install",
                json!({"principalId":worker,"connectionId":"gitlab","token":issued}),
            )
            .await;
        assert_eq!(allowed(&installed)["present"], true);
        assert_eq!(allowed(&installed)["profile"], "gitlab-access-token");
        assert!(allowed(&installed).get("token").is_none());
        let credential = mcp
            .call(
                &fixture,
                mode,
                "credential.view",
                json!({"principalId":worker,"connectionId":"gitlab"}),
            )
            .await;
        assert_eq!(allowed(&credential), allowed(&installed));
        for field in ["token", "secret", "secretRef", "username"] {
            assert!(allowed(&credential).get(field).is_none());
        }

        let token_id = uuid::Uuid::new_v4().to_string();
        let issuance = json!({"principalId":worker,"grantId":"service-access","expectedVersion":version,
            "tokenId":token_id,"name":"bounded worker","allowedExecutionContexts":["default"],"ttlSeconds":28800});
        let token = mcp
            .call(&fixture, mode, "token.create", issuance.clone())
            .await;
        let token = allowed(&token);
        assert_eq!(token["tokenId"], token_id);
        assert_eq!(token["scopes"]["allowedServices"], json!(["fake"]));
        assert_eq!(
            token["scopes"]["serviceRestrictions"]["fake"]["actions"],
            json!(["echo"])
        );
        assert!(token.get("token").is_none());
        fixture.references.push(
            token["issuedToken"]["secretRef"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        let viewed = mcp
            .call(
                &fixture,
                mode,
                "token.view",
                json!({"principalId":worker,"tokenId":token_id}),
            )
            .await;
        assert_eq!(allowed(&viewed)["tokenId"], token_id);
        assert!(allowed(&viewed).get("issuedToken").is_none());
        let repeated = fixture.http(SERVICE, "token.create", issuance).await;
        assert_eq!(repeated["reasonCode"], "access_management_target_exists");
        assert!(!repeated.to_string().contains("sr_"));
        let unlinked = mcp
            .call(
                &fixture,
                mode,
                "grant.subject.remove",
                json!({"grantId":"service-access","principalId":worker,"expectedVersion":version}),
            )
            .await;
        assert_eq!(allowed(&unlinked)["directSubject"], false);
    }
    let invalid = fixture.http(SERVICE,"credential.install",json!({"principalId":"worker-http","connectionId":"gitlab","token":"literal-secret-must-not-be-installed"})).await;
    assert_eq!(invalid["reasonCode"], "input_invalid");
    assert!(
        !invalid
            .to_string()
            .contains("literal-secret-must-not-be-installed")
    );
    let forbidden = fixture
        .http(
            SERVICE,
            "principal.create",
            json!({"principalId":"worker-http","role":"admin"}),
        )
        .await;
    assert_eq!(forbidden["reasonCode"], "input_invalid");
    let hidden = fixture
        .actions(json!({"principal":["out-of-grant"],"group":["workers"]}))
        .await;
    assert_eq!(hidden["actions"], json!([]));
    let requests = fixture.upstream.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        MODES.len()
    );
    mcp.finish(&fixture).await;
    let audit = fixture.broker.audit().unwrap();
    stop(fixture.broker).await;
    let text = audit.text();
    assert!(!text.contains(ISSUED_GITLAB_TOKEN));
    for reference in fixture.references {
        assert!(!text.contains(&reference));
    }
}

fn document(directory: &FixtureDir, base: &str, upstream: &str) -> String {
    format!(
        r#"
[deployment]
environment = "test"
enable_fake_service = true
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
require_registered_principal_for_invocation = true
[broker_tokens]
hash_key_ref = {hash}
[credential_encryption]
active_key = "fixture"
[[credential_encryption.keys]]
id = "fixture"
provider = "file"
path = {key}
[management]
enabled = true
[management.initial_admin]
mode = "disabled"
[policy]
authority = "managed"
default_decision = "deny"
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
[providers.fake]
[providers.gitlab]
api_base_url = {api_url}
web_base_url = {web_url}
allowed_upstream_hosts = [{allowed_url}]
[providers.gitlab.provisioning]
enabled = true
[mcp]
enabled = true
public_url = {mcp_url}
[audit]
type = "jsonl"
path = {audit}
[limits]
upload_spool_dir = {spool}
"#,
        store = toml_string(directory.join("store.sqlite").display()),
        hash = toml_string(format!("file:{}", directory.join("hash").display())),
        key = toml_string(directory.join("key").display()),
        service_token = toml_string(format!(
            "file:{}",
            directory.join("gitlab-service").display()
        )),
        lookup_token = toml_string(format!(
            "file:{}",
            directory.join("gitlab-lookup").display()
        )),
        api_url = toml_string(format!("{upstream}/api/v4")),
        web_url = toml_string(upstream),
        allowed_url = toml_string(format!("{upstream}/api/v4/**")),
        mcp_url = toml_string(format!("{base}/mcp")),
        audit = toml_string(directory.join("audit.jsonl").display()),
        spool = toml_string(directory.join("spool").display()),
    )
}
