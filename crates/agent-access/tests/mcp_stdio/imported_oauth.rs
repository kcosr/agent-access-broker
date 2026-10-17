//! Personal imported OAuth through real scoped HTTP and stdio MCP connections.
use super::{McpProcess, isolated_broker, stop};
use agent_access_broker_host::test_support::{FixtureDir, RunningBroker};
use agent_access_core::imports::{
    ImportedActionDefinition, ImportedAuthMechanism, ImportedBindingStatus,
    ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
    ImportedCredentialPurpose, ImportedDiscoveryCredential, ImportedServiceDefinition,
};
use agent_access_core::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ACCESS: &str = "synthetic-personal-mcp-access";
const DISCOVERY: &str = "synthetic-discovery-only-access";
const SHARED: &str = "shared-execution-fallback-must-not-be-used";
const PROTOCOL: &str = "2025-11-25";
const CURRENT_PROTOCOL: &str = "2026-07-28";
const STALLED_RESPONSE: Duration = Duration::from_millis(1_500);

async fn write_policy_grant(
    client: &reqwest::Client,
    base: &str,
    admin_token: &str,
    route: &str,
    body: Value,
) {
    let response = client
        .post(format!("{base}{route}"))
        .bearer_auth(admin_token)
        .header(
            "X-Agent-Access-Request-Id",
            uuid::Uuid::new_v4().to_string(),
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let result = response.json::<Value>().await.unwrap();
    assert!(status.is_success(), "{route}: {result}");
}

#[derive(Clone, Copy)]
enum DeadlineCase {
    SuccessfulWrite,
    ToolError,
    InFlightWrite,
}

#[derive(Default)]
struct FixtureOptions {
    use_stdio: bool,
    server_default: bool,
    switch_to_legacy: bool,
    group_grant: bool,
    deadline_case: Option<DeadlineCase>,
}

struct UpstreamSession {
    authorization: String,
    probe: bool,
    initialized: bool,
    used: bool,
    deleted: bool,
}

#[derive(Default)]
struct Upstream {
    legacy: bool,
    deny_write: bool,
    reject_cleanup: bool,
    calls: usize,
    lists: usize,
    deadline_case: Option<DeadlineCase>,
    sessions: BTreeMap<String, UpstreamSession>,
}

impl Upstream {
    fn create_session(&mut self, authorization: &str, probe: bool) -> String {
        let id = format!("private-upstream-session-{}", self.sessions.len());
        self.sessions.insert(
            id.clone(),
            UpstreamSession {
                authorization: authorization.into(),
                probe,
                initialized: false,
                used: false,
                deleted: false,
            },
        );
        id
    }

    fn session(
        &mut self,
        request: &wiremock::Request,
        authorization: &str,
    ) -> &mut UpstreamSession {
        assert_eq!(request.headers["mcp-protocol-version"], PROTOCOL);
        let id = request.headers["mcp-session-id"].to_str().unwrap();
        let session = self.sessions.get_mut(id).expect("issued session");
        assert_eq!(session.authorization, authorization, "credential isolation");
        assert!(!session.deleted, "a terminated session cannot be reused");
        session
    }

    fn respond(&mut self, request: &wiremock::Request) -> ResponseTemplate {
        let authorization = request.headers["authorization"].to_str().unwrap();
        assert!(
            [format!("Bearer {ACCESS}"), format!("Bearer {DISCOVERY}")]
                .contains(&authorization.to_owned()),
            "neither shared execution nor personal PAT is a fallback"
        );
        if request.method.as_str() == "DELETE" {
            assert!(self.legacy);
            assert!(request.body.is_empty());
            let session = self.session(request, authorization);
            assert!(session.probe || (session.initialized && session.used));
            session.deleted = true;
            let response = ResponseTemplate::new(if self.reject_cleanup { 401 } else { 204 });
            return if self.deadline_case.is_some() {
                response.set_delay(STALLED_RESPONSE)
            } else {
                response
            };
        }
        assert_eq!(request.method.as_str(), "POST");
        let rpc: Value = serde_json::from_slice(&request.body).unwrap();
        let method = rpc["method"].as_str().unwrap();
        if self.legacy && method != "server/discover" {
            for header in [
                "mcp-method",
                "mcp-name",
                "mcp-client-info",
                "mcp-client-capabilities",
            ] {
                assert!(
                    !request.headers.contains_key(header),
                    "legacy header {header}"
                );
            }
            assert!(
                request
                    .headers
                    .keys()
                    .all(|name| !name.as_str().starts_with("mcp-param-"))
            );
            assert!(rpc["params"].get("_meta").is_none());
        }
        let result = match method {
            "server/discover" => {
                assert!(!request.headers.contains_key("mcp-session-id"));
                assert_eq!(request.headers["mcp-protocol-version"], CURRENT_PROTOCOL);
                assert!(rpc["params"].get("name").is_none());
                assert!(rpc["params"].get("arguments").is_none());
                if self.legacy {
                    // Stateful middleware may mint a session before rejecting the
                    // modern probe. It is cleanup-only, never the initialized session.
                    let session = self.create_session(authorization, true);
                    return ResponseTemplate::new(400)
                        .insert_header("Mcp-Session-Id", session)
                        .set_body_json(json!({"jsonrpc":"2.0","id":"server-error",
                            "error":{"code":-32600,"message":"synthetic legacy startup required"}}));
                }
                json!({"supportedVersions":[CURRENT_PROTOCOL],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})
            }
            "initialize" => {
                assert!(self.legacy);
                assert!(!request.headers.contains_key("mcp-session-id"));
                assert!(!request.headers.contains_key("mcp-protocol-version"));
                assert_eq!(rpc["params"]["protocolVersion"], PROTOCOL);
                assert_eq!(rpc["params"]["capabilities"], json!({}));
                assert!(rpc["params"]["clientInfo"]["name"].is_string());
                let session = self.create_session(authorization, false);
                return ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", session)
                    .set_body_json(json!({"jsonrpc":"2.0","id":rpc["id"],"result":{
                        "protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                        "serverInfo":{"name":"legacy-metrics-fixture","version":"1","title":"Legacy metrics"},
                        "instructions":"private-upstream-instructions"}}));
            }
            "notifications/initialized" => {
                assert!(self.legacy);
                assert!(rpc.get("id").is_none());
                let session = self.session(request, authorization);
                assert!(!session.probe && !session.initialized && !session.used);
                session.initialized = true;
                return ResponseTemplate::new(202);
            }
            "tools/list" => {
                assert_eq!(authorization, format!("Bearer {DISCOVERY}"));
                let session = self.session(request, authorization);
                assert!(!session.probe && session.initialized && !session.used);
                session.used = true;
                self.lists += 1;
                json!({"tools":[
                    {"name":"Original.Read","description":"Delegated fixture action","inputSchema":{"type":"object","additionalProperties":false}},
                    {"name":"Original.Write","description":"Delegated fixture action","inputSchema":{"type":"object","additionalProperties":false}}
                ]})
            }
            "tools/call" => {
                assert_eq!(authorization, format!("Bearer {ACCESS}"));
                if self.legacy {
                    let session = self.session(request, authorization);
                    assert!(!session.probe && session.initialized && !session.used);
                    session.used = true;
                } else {
                    assert!(!request.headers.contains_key("mcp-session-id"));
                    assert_eq!(request.headers["mcp-protocol-version"], CURRENT_PROTOCOL);
                }
                assert_eq!(rpc["params"]["arguments"], json!({}));
                assert!(
                    ["Original.Read", "Original.Write"]
                        .contains(&rpc["params"]["name"].as_str().unwrap())
                );
                self.calls += 1;
                if rpc["params"]["name"] == "Original.Write" && self.deny_write {
                    return ResponseTemplate::new(401)
                        .set_body_json(json!({"error":"unauthorized"}));
                }
                if matches!(self.deadline_case, Some(DeadlineCase::ToolError)) {
                    json!({"content":[{"type":"text","text":"synthetic tool failure"}],"isError":true})
                } else {
                    json!({"content":[{"type":"text","text":"personal result"}]})
                }
            }
            other => panic!("unexpected upstream method {other}"),
        };
        let response = ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc":"2.0","id":rpc["id"],"result":result}));
        let response = if self.legacy {
            // Normal response echoes must not create a new session or disrupt a call.
            response.insert_header("Mcp-Session-Id", request.headers["mcp-session-id"].clone())
        } else {
            response
        };
        if method == "tools/call" && matches!(self.deadline_case, Some(DeadlineCase::InFlightWrite))
        {
            response.set_delay(STALLED_RESPONSE)
        } else {
            response
        }
    }
}

async fn rpc_body(response: reqwest::Response) -> Value {
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {text}");
    serde_json::from_str(&text).unwrap_or_else(|_| {
        text.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
            .find(|message| message.get("id").is_some())
            .unwrap()
    })
}
struct HttpMcp {
    client: reqwest::Client,
    url: String,
    token: String,
    session: String,
    next_id: u64,
}
impl HttpMcp {
    async fn start(base: &str, token: &str) -> Self {
        let mut this = Self {
            client: reqwest::Client::new(),
            url: format!("{base}/mcp/metrics"),
            token: token.into(),
            session: String::new(),
            next_id: 2,
        };
        let response = this.client.post(&this.url).bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"oauth-scoped-fixture","version":"1"}}}))
            .send().await.unwrap();
        this.session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .into();
        assert_eq!(
            rpc_body(response).await["result"]["serverInfo"]["name"],
            "metrics"
        );
        let response = this
            .client
            .post(&this.url)
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &this.session)
            .header("mcp-protocol-version", PROTOCOL)
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        this
    }
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        rpc_body(
            self.client
                .post(&self.url)
                .bearer_auth(&self.token)
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &self.session)
                .header("mcp-protocol-version", PROTOCOL)
                .json(&json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params}))
                .send()
                .await
                .unwrap(),
        )
        .await
    }
}

enum Client {
    Stdio(McpProcess),
    Http(HttpMcp),
}
impl Client {
    async fn request(&mut self, method: &str, params: Value) -> Value {
        match self {
            Self::Stdio(client) => client.request(method, params).await,
            Self::Http(client) => client.request(method, params).await,
        }
    }

    async fn assert_discovery(&mut self, available: bool) {
        let tools = self.request("tools/list", json!({})).await;
        let tools = tools["result"]["tools"].as_array().expect("tool list");
        assert_eq!(
            tools.iter().any(|tool| tool["name"] == "Original.Read"),
            available
        );
        if !available {
            assert_eq!(tools.len(), 5, "only discovery helpers remain");
        }
        let summary = self
            .request("tools/call", json!({"name":"services_list","arguments":{}}))
            .await;
        let service = &summary["result"]["structuredContent"]["services"][0];
        assert_eq!(service["service"], "metrics", "{summary}");
        assert_eq!(
            service["availability"]["state"],
            if available {
                "available"
            } else {
                "unavailable"
            }
        );
        assert_eq!(
            service["actions"].as_array().unwrap().is_empty(),
            !available
        );
        if !available {
            let detail = self.request("tools/call", json!({"name":"actions_describe","arguments":{"service":"metrics","action":"item.read"}})).await;
            assert_eq!(detail["result"]["isError"], true, "{detail}");
            assert!(!detail.to_string().contains("inputSchema"));
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_stdio_personal_oauth_never_falls_back_or_replays_writes() {
    exercise_oauth(true, false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_personal_oauth_never_falls_back_or_replays_writes() {
    exercise_oauth(false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_group_grant_allows_ordinary_personal_oauth_without_rights() {
    exercise_oauth_fixture(FixtureOptions {
        group_grant: true,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_stdio_server_default_oauth_never_falls_back_or_replays_writes() {
    exercise_oauth(true, true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_server_default_oauth_never_falls_back_or_replays_writes() {
    exercise_oauth(false, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_stdio_personal_oauth_survives_legacy_upstream_switch() {
    exercise_oauth(true, false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_personal_oauth_survives_legacy_upstream_switch() {
    exercise_oauth(false, false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_stdio_server_default_oauth_survives_legacy_upstream_switch() {
    exercise_oauth(true, true, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_server_default_oauth_survives_legacy_upstream_switch() {
    exercise_oauth(false, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_oauth_cleanup_deadline_preserves_successful_write() {
    exercise_oauth_fixture(FixtureOptions {
        deadline_case: Some(DeadlineCase::SuccessfulWrite),
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_oauth_cleanup_deadline_preserves_known_tool_error() {
    exercise_oauth_fixture(FixtureOptions {
        deadline_case: Some(DeadlineCase::ToolError),
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_http_oauth_in_flight_write_deadline_stays_unknown() {
    exercise_oauth_fixture(FixtureOptions {
        deadline_case: Some(DeadlineCase::InFlightWrite),
        ..Default::default()
    })
    .await;
}

async fn exercise_oauth(use_stdio: bool, server_default: bool, switch_to_legacy: bool) {
    exercise_oauth_fixture(FixtureOptions {
        use_stdio,
        server_default,
        switch_to_legacy,
        ..Default::default()
    })
    .await;
}

async fn exercise_oauth_fixture(options: FixtureOptions) {
    let FixtureOptions {
        use_stdio,
        server_default,
        switch_to_legacy,
        group_grant,
        deadline_case,
    } = options;
    let issuer = MockServer::start().await;
    let endpoint = format!("{}/mcp", issuer.uri());
    let application = isolated_broker();
    let directory = application.directory().clone();
    // The listener is already bound, so the configuration can name it.
    let base = application.public_url();
    let key = directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([75u8; 32]))
        .unwrap();
    let key_ref = format!("file:{}", key.display());
    let store_path = directory.join("store.sqlite").display().to_string();
    let document = oauth_document(
        &directory,
        &base,
        &issuer.uri(),
        server_default,
        deadline_case.is_some(),
    );
    // Seed the managed store before the broker opens and locks it.
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: store_path,
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "alice".into(),
        })
        .unwrap();
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "alice".into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "alice".into(),
        })
        .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: PrincipalRole::Admin,
            self_service_enabled: None,
            principal_id: "admin".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "alice".into(),
        })
        .unwrap();
    let definition = ImportedServiceDefinition {
        service: "metrics".into(),
        display_name: "Personal metrics".into(),
        adapter_kind: "mcp_http".into(),
        endpoint: endpoint.clone(),
        connection_settings: BTreeMap::new(),
        execution_bindings: vec![
            ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            ),
            ImportedCredentialBinding {
                owner_mode: ImportedCredentialMode::PerUser,
                mechanism: ImportedAuthMechanism::Oauth,
                delivery: ImportedCredentialDelivery::Bearer,
                status: ImportedBindingStatus::Configured,
                adapter_id: Some("mcp_oauth".into()),
                registration_id: Some("personal".into()),
                profile: Some("access".into()),
            },
        ],
        discovery: ImportedDiscoveryCredential::Slot,
        transport_auth: false,
        invocation_limit: None,
    };
    let mut catalog = store
        .create_imported_service(definition, "alice", |_| Ok(()))
        .unwrap()
        .catalog;
    let ring = CredentialKeyRing::load(&CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            env: None,
            path: Some(key.display().to_string()),
        }],
    })
    .unwrap();
    for (purpose, token) in [
        (ImportedCredentialPurpose::Execution, SHARED),
        (ImportedCredentialPurpose::Discovery, DISCOVERY),
    ] {
        catalog = store
            .write_imported_secret(
                ImportedSecretWriteRequest {
                    service: "metrics".into(),
                    purpose,
                    expected_version: catalog.service("metrics").unwrap().version,
                    expected_catalog_revision: catalog.revision,
                    token: token.into(),
                    username: None,
                    actor: "alice".into(),
                },
                &ring,
                |_, _| Ok(()),
            )
            .unwrap()
            .catalog;
    }
    let record = catalog.service("metrics").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: record.definition.clone(),
                status: ImportedServiceStatus::Enabled,
                actions: [
                    ("item.read", "Original.Read", true),
                    ("item.write", "Original.Write", false),
                ]
                .into_iter()
                .map(|(action, name, read_only)| ImportedActionWrite {
                    definition: ImportedActionDefinition {
                        action: action.into(),
                        source: json!({"toolName":name}),
                        label: None,
                        description: "Delegated fixture action".into(),
                        input_schema: json!({"type":"object","additionalProperties":false}),
                        output_schema: None,
                        annotations: json!({"toolAnnotations":{},"execution":null}),
                        read_only,
                    },
                    status: ImportedActionStatus::Enabled,
                })
                .collect(),
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                accepted_preview: None,
                actor: "alice".into(),
            },
            |_| Ok(()),
        )
        .unwrap();
    // A second service shares this owner's registration. Its empty target must
    // stay hidden until it has its own setup grant; cleanup is registration-wide.
    let current = store.imported_catalog().unwrap();
    let primary = current.service("metrics").unwrap();
    let mut secondary = primary.definition.clone();
    secondary.service = "metrics_secondary".into();
    secondary.display_name = "Secondary personal metrics".into();
    let secondary_actions = primary
        .actions
        .iter()
        .map(|action| ImportedActionWrite {
            definition: action.definition.clone(),
            status: action.status,
        })
        .collect();
    let current = store
        .create_imported_service(secondary, "alice", |_| Ok(()))
        .unwrap()
        .catalog;
    let secondary = current.service("metrics_secondary").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: secondary.definition.clone(),
                status: ImportedServiceStatus::Enabled,
                actions: secondary_actions,
                expected_version: secondary.version,
                expected_catalog_revision: current.revision,
                accepted_preview: None,
                actor: "alice".into(),
            },
            |_| Ok(()),
        )
        .unwrap();
    // Even a stored personal PAT must not satisfy a selected OAuth binding.
    store
        .upsert_user_credential(
            &ring,
            CredentialWriteRequest {
                owner_principal_id: "alice".into(),
                service: "metrics".into(),
                name: "default".into(),
                profile: "token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token":"personal-PAT-fallback-must-not-be-used"}),
                metadata: json!({}),
                actor: "alice".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    if group_grant {
        store
            .create_group(GroupWriteRequest {
                group_id: "metrics-readers".into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
        store
            .add_group("alice", "metrics-readers", "admin")
            .unwrap();
    }
    if !switch_to_legacy {
        // The regular setup/invocation cases exercise an ordinary human. The
        // protocol-switch cases retain administrator discovery coverage below.
        store
            .patch_principal_access(PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: Some(PrincipalRole::User),
                self_service_enabled: None,
                actor: "admin".into(),
            })
            .unwrap();
    }
    store
        .enable_local_password(
            &LocalPasswordHasher::load("browser_auth.local_password.pepper_ref", &key_ref).unwrap(),
            LocalPasswordWriteRequest {
                principal_id: "alice".into(),
                password: "fixture-password".into(),
                min_password_length: 8,
                password_change_required: false,
                actor: "alice".into(),
            },
        )
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: key_ref.clone(),
        ..Default::default()
    })
    .unwrap();
    let agent = store.issue_broker_token(&hasher,BrokerTokenIssueRequest {
        principal_id:"alice".into(),name:"personal scoped MCP".into(),token_class:BrokerTokenClass::AgentInvoke,scopes:json!({"allowedServices":["metrics"],"allowedExecutionContexts":["default"]}),expires_at:None,created_by:"alice".into(),
    }).unwrap().token;
    let admin_token = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "current runtime policy management".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    drop(store);
    let broker = application.config_document(document).start().await.unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // The administrator grants alice personal access through the running
    // broker's management API.
    write_policy_grant(
        &client,
        &base,
        &admin_token,
        "/v1/admin/policy/grants",
        json!({
            "grantId":"personal-metrics",
            "subjects":[if group_grant { "group:metrics-readers" } else { "user:alice" }],
            "executionContexts":["default"], "service":"metrics",
            "actions":["item.read","item.write"],
            "resources":{"resourceIds":[],"resourceGroupIds":[]},
            "credentialMode":"per_user"
        }),
    )
    .await;
    let login = client
        .post(format!("{base}/v1/auth/local/login"))
        .header("origin", &base)
        .json(&json!({"principalId":"alice","password":"fixture-password"}))
        .send()
        .await
        .unwrap();
    assert!(login.status().is_success());
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = login.json::<Value>().await.unwrap()["result"]["csrfToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let browser = |method: reqwest::Method, route: &str| {
        client
            .request(method, format!("{base}{route}"))
            .header("origin", &base)
            .header("cookie", &cookie)
            .header("X-Agent-Access-CSRF", &csrf)
            .header(
                "X-Agent-Access-Request-Id",
                uuid::Uuid::new_v4().to_string(),
            )
    };
    let config_path = directory.path().join("client.toml");
    let token_path = directory.path().join("agent.token");
    std::fs::write(&token_path, &agent).unwrap();
    std::fs::write(&config_path,format!("[service]\nurl={base:?}\n[identity]\nheader=\"Authorization\"\nscheme=\"Bearer\"\ntoken_file={:?}\n",token_path.display().to_string())).unwrap();
    let mut connection = if use_stdio {
        let mut stdio = McpProcess::start_scoped(&config_path, "metrics");
        stdio.initialize().await;
        Client::Stdio(stdio)
    } else {
        Client::Http(HttpMcp::start(&base, &agent).await)
    };
    let read = json!({"name":"Original.Read","arguments":{"inputs":{}}});
    connection.assert_discovery(false).await;
    {
        let response = connection.request("tools/call", read.clone()).await;
        assert_eq!(response["error"]["code"], -32602, "{response}");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("services_describe"),
            "cached tool failures must point callers to availability: {response}"
        );
    }
    // Native name rejection is separate from invocation's credential checks.
    let denied = client
        .post(format!("{base}/v1/invoke/metrics/item.read"))
        .bearer_auth(&agent)
        .header("X-Agent-Access-Request-Id", "missing-oauth-direct")
        .json(&json!({"inputs":{}}))
        .send()
        .await
        .unwrap();
    assert!(!denied.status().is_success());
    let denied = denied.json::<Value>().await.unwrap();
    assert_eq!(denied["reasonCode"], "credential_invalid", "{denied}");
    assert_eq!(denied["reason"], "oauth_reconnect_required", "{denied}");
    for document in ["catalog", "openapi.json", "send-schema.json"] {
        let result = client
            .get(format!("{base}/v1/spec/{document}"))
            .bearer_auth(&agent)
            .header(
                "X-Agent-Access-Request-Id",
                format!("missing-oauth-{document}"),
            )
            .send()
            .await
            .unwrap();
        assert!(
            result.status().is_success(),
            "{document}: {}",
            result.status()
        );
        let result = result.json::<Value>().await.unwrap();
        assert!(
            !result.to_string().contains("item.read"),
            "{document} exposes unavailable action"
        );
    }
    assert!(
        issuer.received_requests().await.unwrap().is_empty(),
        "missing OAuth must never use any stored fallback"
    );
    Mock::given(method("GET")).and(path("/resource-metadata")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"resource":endpoint,"authorization_servers":[issuer.uri()],"bearer_methods_supported":["header"]}))).mount(&issuer).await;
    Mock::given(method("GET")).and(path("/issuer-metadata")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer":issuer.uri(),"authorization_endpoint":format!("{}/authorize",issuer.uri()),"token_endpoint":format!("{}/token",issuer.uri()),"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"authorization_response_iss_parameter_supported":true}))).mount(&issuer).await;
    let connected = browser(reqwest::Method::POST, "/v1/oauth/connect")
        .json(&json!({"registration":"personal","intent":"connect"}))
        .send()
        .await
        .unwrap();
    let status = connected.status();
    let connected = connected.json::<Value>().await.unwrap();
    assert!(status.is_success(), "{connected}");
    let authorization =
        url::Url::parse(connected["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
    let query: BTreeMap<String, String> = authorization.query_pairs().into_owned().collect();
    assert_eq!(query["resource"], endpoint);
    assert_eq!(query["code_challenge_method"], "S256");
    if server_default {
        assert!(!query.contains_key("scope"));
    } else {
        assert_eq!(query["scope"], "metrics.read metrics.write");
    }
    let challenge = query["code_challenge"].clone();
    let expected_resource = endpoint.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |request: &wiremock::Request| {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            assert_eq!(form["resource"], expected_resource);
            if server_default {
                assert!(!form.contains_key("scope"));
            } else {
                assert_eq!(form["scope"], "metrics.read metrics.write");
            }
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
                challenge
            );
            let mut token = json!({"access_token":ACCESS,"token_type":"Bearer","expires_in":3600});
            if !server_default {
                token["scope"] = json!("metrics.read metrics.write");
            }
            ResponseTemplate::new(200).set_body_json(token)
        })
        .expect(1)
        .mount(&issuer)
        .await;
    let callback = format!(
        "/v1/oauth/callback/personal?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &query["state"])
            .append_pair("code", "one-use-code")
            .append_pair("iss", &issuer.uri())
            .finish()
    );
    let callback = browser(reqwest::Method::GET, &callback)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), reqwest::StatusCode::OK);
    assert!(callback.headers().get("location").is_none());
    assert_eq!(
        callback.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    assert!(
        callback
            .text()
            .await
            .unwrap()
            .contains("<h1>Authorized</h1>")
    );
    let metadata = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        metadata["result"].as_array().unwrap().len(),
        1,
        "the shared registration has one row"
    );
    let row = metadata["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["registration"] == "personal")
        .unwrap();
    assert_eq!(
        row["scopeMode"],
        if server_default {
            "server_default"
        } else {
            "explicit"
        }
    );
    assert_eq!(
        row["requestedScopes"],
        if server_default {
            json!([])
        } else {
            json!(["metrics.read", "metrics.write"])
        }
    );
    assert_eq!(row["connection"]["status"], "ready");
    let original_connection = row["connection"].clone();
    connection.assert_discovery(true).await;
    let upstream = Arc::new(Mutex::new(Upstream::default()));
    let handler = upstream.clone();
    Mock::given(path("/mcp"))
        .respond_with(move |request: &wiremock::Request| handler.lock().unwrap().respond(request))
        .mount(&issuer)
        .await;
    if let Some(case) = deadline_case {
        {
            let mut upstream = upstream.lock().unwrap();
            upstream.legacy = true;
            upstream.deadline_case = Some(case);
        }
        exercise_deadline_case(case, &mut connection, &upstream, &issuer, broker).await;
        return;
    }
    {
        let response = connection.request("tools/call", read.clone()).await;
        assert_ne!(response["result"]["isError"], true, "{response}");
        assert!(response.to_string().contains("personal result"));
    }
    assert_eq!(upstream.lock().unwrap().calls, 1);
    if switch_to_legacy {
        // The endpoint and accepted service stay fixed. A later upstream release
        // can change its protocol without changing OAuth consent or action IDs.
        upstream.lock().unwrap().legacy = true;
        let original = browser(reqwest::Method::GET, "/v1/admin/imports/metrics")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let discovered = browser(reqwest::Method::POST, "/v1/admin/imports/metrics/discover")
            .json(&json!({
                "expectedVersion":original["result"]["service"]["version"],
                "expectedCatalogRevision":original["result"]["catalogRevision"]
            }))
            .send()
            .await
            .unwrap();
        let status = discovered.status();
        let discovered = discovered.json::<Value>().await.unwrap();
        assert!(status.is_success(), "{discovered}");
        let manifest = &discovered["result"]["preview"]["manifest"];
        assert_eq!(manifest["protocolVersion"], PROTOCOL);
        assert_eq!(
            manifest["metadata"]["serverInfo"],
            json!({
                "name":"legacy-metrics-fixture","version":"1","title":"Legacy metrics"
            })
        );
        assert_eq!(manifest["tools"].as_array().unwrap().len(), 2);
        assert!(
            !discovered
                .to_string()
                .contains("private-upstream-instructions")
        );
        assert_eq!(
            discovered["result"]["service"]["actions"], original["result"]["service"]["actions"],
            "protocol changes alone must not quarantine or replace accepted actions"
        );
        assert_eq!(upstream.lock().unwrap().lists, 1);
        // Even a cleanup 401 is outside the operation outcome and cannot reject
        // the personal access version. The next independent call must still work.
        upstream.lock().unwrap().reject_cleanup = true;
        for _ in 0..2 {
            let response = connection.request("tools/call", read.clone()).await;
            assert_ne!(response["result"]["isError"], true, "{response}");
            assert!(response.to_string().contains("personal result"));
            assert!(!response.to_string().contains("private-upstream-session-"));
            let current = browser(reqwest::Method::GET, "/v1/oauth/connections")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            let current = current["result"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["registration"] == "personal")
                .unwrap();
            assert_eq!(
                current["connection"], original_connection,
                "negotiation and cleanup must preserve the existing personal connection"
            );
            upstream.lock().unwrap().reject_cleanup = false;
        }
        assert_eq!(upstream.lock().unwrap().calls, 3);
    }
    upstream.lock().unwrap().deny_write = true;
    let write = json!({"name":"Original.Write","arguments":{"inputs":{}}});
    {
        let response = connection.request("tools/call", write).await;
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert_eq!(
            response["result"]["structuredContent"]["result"]["mutationStatus"], "unknown",
            "{response}"
        );
        assert_eq!(
            response["result"]["structuredContent"]["result"]["retrySafe"], false,
            "{response}"
        );
    }
    assert_eq!(
        upstream.lock().unwrap().calls,
        if switch_to_legacy { 4 } else { 2 },
        "the uncertain write is attempted once"
    );
    let before = issuer.received_requests().await.unwrap().len();
    connection.assert_discovery(false).await;
    let response = connection.request("tools/call", read.clone()).await;
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert_eq!(
        issuer.received_requests().await.unwrap().len(),
        before,
        "a normal-operation 401 rejects the sent access version without replay or fallback"
    );
    let rejected = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let rejected = rejected["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["registration"] == "personal")
        .unwrap();
    assert_eq!(
        rejected["connection"]["connectionId"],
        original_connection["connectionId"]
    );
    assert_eq!(rejected["connection"]["status"], "reconnect_required");
    // Discovery can publish a replacement runtime. Mutate policy through the
    // active HTTP state.
    write_policy_grant(
        &client,
        &base,
        &admin_token,
        "/v1/admin/policy/grants",
        json!({
            "grantId":"secondary-metrics", "subjects":["user:alice"],
            "executionContexts":["default"], "service":"metrics_secondary",
            "actions":["item.read"], "resources":{"resourceIds":[],"resourceGroupIds":[]},
            "credentialMode":"per_user"
        }),
    )
    .await;
    let rows = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["result"]
        .clone();
    assert_eq!(
        rows.as_array().unwrap().len(),
        1,
        "a registration shared by two services has one row"
    );
    assert_eq!(
        consumer_services(&rows[0]),
        ["metrics", "metrics_secondary"],
        "the row names every entitled consumer"
    );
    assert_eq!(rows[0]["otherConsumers"], 0);
    assert_eq!(rows[0]["canConnect"], true);
    write_policy_grant(
        &client,
        &base,
        &admin_token,
        "/v1/admin/policy/grants/personal-metrics/disable",
        json!({"expectedVersion":1}),
    )
    .await;
    let rows = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["result"]
        .clone();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["registration"], "personal");
    assert_eq!(consumer_services(&rows[0]), ["metrics_secondary"]);
    assert_eq!(rows[0]["otherConsumers"], 1);
    assert_eq!(rows[0]["canConnect"], true);
    write_policy_grant(
        &client,
        &base,
        &admin_token,
        "/v1/admin/policy/grants/secondary-metrics/disable",
        json!({"expectedVersion":1}),
    )
    .await;
    let rows = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["result"]
        .clone();
    assert_eq!(
        rows.as_array().unwrap().len(),
        1,
        "one cleanup row represents the shared owned connection"
    );
    assert_eq!(rows[0]["registration"], "personal");
    assert!(consumer_services(&rows[0]).is_empty());
    assert_eq!(rows[0]["otherConsumers"], 2);
    assert_eq!(rows[0]["canConnect"], false);
    assert_eq!(rows[0]["canDisconnect"], true);
    assert_eq!(rows[0]["connectUnavailableReason"], "no_personal_access");
    let before = issuer.received_requests().await.unwrap().len();
    let response = connection.request("tools/call", read.clone()).await;
    if use_stdio {
        assert_eq!(response["result"]["isError"], true, "{response}");
    } else {
        assert_eq!(
            response["error"]["message"], "Service MCP view is unavailable",
            "{response}"
        );
    }
    assert_eq!(
        issuer.received_requests().await.unwrap().len(),
        before,
        "withdrawn grants stop invocation before contacting upstream"
    );
    let denied = browser(reqwest::Method::POST, "/v1/oauth/connect")
        .json(&json!({"registration":"personal","intent":"reconnect"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    let denied = denied.json::<Value>().await.unwrap();
    assert_eq!(denied["reasonCode"], "service_action_denied");
    assert_eq!(denied["error"]["message"], "oauth_setup_denied");
    let response = browser(reqwest::Method::DELETE, "/v1/oauth/connections/personal")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let rows = browser(reqwest::Method::GET, "/v1/oauth/connections")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        rows["result"],
        json!([]),
        "disconnected empty targets are hidden"
    );
    // Restore invocation entitlement independently of the removed connection:
    // the call must now fail for missing OAuth without borrowing other tokens.
    write_policy_grant(
        &client,
        &base,
        &admin_token,
        "/v1/admin/policy/grants/personal-metrics/enable",
        json!({"expectedVersion":2}),
    )
    .await;
    let before = issuer.received_requests().await.unwrap().len();
    connection.assert_discovery(false).await;
    let response = connection.request("tools/call", read).await;
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert_eq!(
        issuer.received_requests().await.unwrap().len(),
        before,
        "revoked connections never fall back or reach upstream"
    );
    {
        let upstream = upstream.lock().unwrap();
        if switch_to_legacy {
            assert_eq!(
                upstream.sessions.len(),
                8,
                "fresh probe and initialize sessions for each operation"
            );
            assert_eq!(
                upstream.sessions.values().filter(|s| s.deleted).count(),
                6,
                "cleanup covers discovery and successful calls, but skips the normal 401"
            );
            assert_eq!(
                upstream
                    .sessions
                    .values()
                    .filter(|s| s.authorization == format!("Bearer {DISCOVERY}"))
                    .count(),
                2,
                "discovery sessions never cross into personal execution"
            );
            for session in upstream.sessions.values() {
                assert_eq!(session.initialized, !session.probe);
                assert_eq!(session.used, !session.probe);
            }
        } else {
            assert!(upstream.sessions.is_empty());
            assert_eq!(upstream.lists, 0);
        }
    }
    let audit = broker.audit().unwrap();
    stop(broker).await;
    let audit = audit.text();
    for private in [
        ACCESS,
        DISCOVERY,
        SHARED,
        "private-upstream-session-",
        "private-upstream-instructions",
        "personal result",
    ] {
        assert!(
            !audit.contains(private),
            "private upstream data must not reach audit"
        );
    }
    let invocations = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["providerAudit"]["toolDispatched"] == true)
        .collect::<Vec<_>>();
    assert_eq!(invocations.len(), if switch_to_legacy { 4 } else { 2 });
    assert_eq!(
        invocations[0]["providerAudit"]["protocolVersion"],
        CURRENT_PROTOCOL
    );
    for entry in &invocations[1..] {
        assert_eq!(
            entry["providerAudit"]["protocolVersion"],
            if switch_to_legacy {
                PROTOCOL
            } else {
                CURRENT_PROTOCOL
            }
        );
    }
    issuer.verify().await;
}

/// The services an OAuth connections row lists as entitled consumers.
fn consumer_services(row: &Value) -> Vec<String> {
    row["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|consumer| consumer["service"].as_str().unwrap().to_string())
        .collect()
}

/// Managed identity, policy and store, browser login, JSONL audit, MCP
/// imports of `{issuer}/mcp` and HTTP MCP at `base`, with the `personal`
/// OAuth registration at `issuer`. The deadline cases shorten the MCP
/// operation timeout under the request timeout.
fn oauth_document(
    directory: &FixtureDir,
    base: &str,
    issuer: &str,
    server_default: bool,
    shortened_deadline: bool,
) -> String {
    let endpoint = format!("{issuer}/mcp");
    let key = directory.join("key");
    let key_ref = format!("file:{}", key.display());
    // Only the focused deadline cases shorten the outer supervisor deadline.
    let (mcp_timeouts, limits_timeouts) = if shortened_deadline {
        ("operation_timeout_ms=500\n", "request_timeout_ms=5000\n")
    } else {
        ("", "")
    };
    format!(
        r#"
[deployment]
environment="development"
[identity]
mode="required"
authority="managed"
[[identity.sources]]
name="broker"
type="broker_tokens"
header="Authorization"
scheme="Bearer"
[managed_store]
type="sqlite"
path={store:?}
auto_migrate=true
[credential_encryption]
active_key="test"
[[credential_encryption.keys]]
id="test"
provider="file"
path={key:?}
[broker_tokens]
hash_key_ref={key_ref:?}
[browser_auth]
enabled=true
public_origin={base:?}
csrf_key_ref={key_ref:?}
[browser_auth.local_password]
enabled=true
pepper_ref={key_ref:?}
[management]
enabled=true
[audit]
type="jsonl"
path={audit:?}
[policy]
authority="managed"
default_decision="deny"
[imports]
enabled=true
allowed_kinds=["mcp_http"]
allowed_endpoints=[{endpoint:?}]
[mcp]
enabled=true
public_url={mcp_url:?}
{mcp_timeouts}[oauth.registrations.personal]
adapter="mcp_oauth"
base_url={issuer_url:?}
redirect_uri={redirect:?}
client_id="scoped-oauth-fixture"
client_auth="none"
allow_insecure_loopback=true
[oauth.registrations.personal.adapter_settings]
resource={endpoint:?}
protected_resource_metadata_url={resource_meta:?}
authorization_server_metadata_url={issuer_meta:?}
authorization_endpoint={authorize:?}
token_endpoint={token_url:?}
[oauth.registrations.personal.permission_profiles.access]
{permission_settings}
audience={endpoint:?}
target={endpoint:?}
[limits]
upload_spool_dir={spool:?}
{limits_timeouts}"#,
        store = directory.join("store.sqlite").display().to_string(),
        audit = directory.join("audit.jsonl").display().to_string(),
        key = key.display().to_string(),
        mcp_url = format!("{base}/mcp"),
        issuer_url = issuer,
        redirect = format!("{base}/v1/oauth/callback/personal"),
        resource_meta = format!("{issuer}/resource-metadata"),
        issuer_meta = format!("{issuer}/issuer-metadata"),
        authorize = format!("{issuer}/authorize"),
        token_url = format!("{issuer}/token"),
        permission_settings = if server_default {
            "scope_mode=\"server_default\""
        } else {
            "scopes=[\"metrics.read\",\"metrics.write\"]"
        },
        spool = directory.join("spool").display().to_string()
    )
}

async fn exercise_deadline_case(
    case: DeadlineCase,
    connection: &mut Client,
    upstream: &Arc<Mutex<Upstream>>,
    issuer: &MockServer,
    broker: RunningBroker,
) {
    let response = connection
        .request(
            "tools/call",
            json!({"name":"Original.Write","arguments":{"inputs":{}}}),
        )
        .await;
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(envelope["action"], "item.write", "{response}");
    assert_eq!(envelope["result"]["retrySafe"], false, "{response}");
    match case {
        DeadlineCase::SuccessfulWrite => {
            assert_eq!(response["result"]["isError"], false, "{response}");
            assert_eq!(envelope["decision"], "allow");
            assert_eq!(envelope["reasonCode"], Value::Null);
            assert_eq!(envelope["result"]["mutationStatus"], "applied_unverified");
            assert_eq!(envelope["result"]["upstreamMcp"]["isError"], false);
            assert_eq!(
                envelope["result"]["upstreamMcp"]["content"],
                json!([{"type":"text","text":"personal result"}])
            );
        }
        DeadlineCase::ToolError => {
            assert_eq!(response["result"]["isError"], true, "{response}");
            assert_eq!(envelope["reasonCode"], "upstream_failed", "{response}");
            assert_eq!(envelope["result"]["mutationStatus"], "unknown");
            assert_eq!(envelope["result"]["toolDispatched"], true);
            assert_eq!(envelope["result"]["upstreamMcp"]["isError"], true);
            assert_eq!(
                envelope["result"]["upstreamMcp"]["content"],
                json!([{"type":"text","text":"synthetic tool failure"}])
            );
        }
        DeadlineCase::InFlightWrite => {
            assert_eq!(response["result"]["isError"], true, "{response}");
            assert_eq!(envelope["reasonCode"], "operation_timeout", "{response}");
            assert_eq!(envelope["result"]["executionState"], "unknown");
            assert_eq!(envelope["result"]["upstreamMcp"], Value::Null);
        }
    }
    {
        let upstream = upstream.lock().unwrap();
        assert_eq!(upstream.calls, 1, "exactly one upstream write");
        assert_eq!(
            upstream.sessions.len(),
            2,
            "one probe and one initialized session"
        );
        let session = upstream.sessions.values().find(|s| !s.probe).unwrap();
        let probe = upstream.sessions.values().find(|s| s.probe).unwrap();
        assert!(session.initialized && session.used);
        assert!(!probe.initialized && !probe.used && !probe.deleted);
        assert_eq!(
            session.deleted,
            !matches!(case, DeadlineCase::InFlightWrite),
            "known outcomes started cleanup; unfinished calls never start cleanup"
        );
    }
    let requests = issuer.received_requests().await.unwrap().len();
    // Let the delayed upstream response become available after the operation's
    // deadline. It must not cause a replay, a second DELETE, or a second outcome.
    tokio::time::sleep(STALLED_RESPONSE + Duration::from_millis(50)).await;
    assert_eq!(
        issuer.received_requests().await.unwrap().len(),
        requests,
        "no upstream work may resume after the operation deadline"
    );
    assert_eq!(upstream.lock().unwrap().calls, 1);
    let audit = broker.audit().unwrap();
    stop(broker).await;
    let audit = audit.text();
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["service"] == "metrics" && entry["action"] == "item.write")
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "one terminal audit for the write");
    let record = &records[0];
    assert_eq!(record["brokerRequestId"], envelope["brokerRequestId"]);
    assert_eq!(record["decision"], envelope["decision"]);
    assert_eq!(record["reasonCode"], envelope["reasonCode"]);
    if matches!(case, DeadlineCase::InFlightWrite) {
        assert_eq!(record["providerAudit"]["executionState"], "unknown");
        assert_eq!(record["providerAudit"]["retrySafe"], false);
    } else {
        assert_eq!(record["upstreamStatus"], 200);
        assert_eq!(record["providerAudit"]["protocolVersion"], PROTOCOL);
        assert_eq!(record["providerAudit"]["toolDispatched"], true);
        assert_eq!(record["providerAudit"]["upstreamTool"], "Original.Write");
    }
    for private in [
        ACCESS,
        DISCOVERY,
        SHARED,
        "private-upstream-session-",
        "private-upstream-instructions",
        "personal result",
        "synthetic tool failure",
    ] {
        assert!(
            !audit.contains(private),
            "private upstream data must not reach audit"
        );
    }
    issuer.verify().await;
}
