//! Read-only identity access paths over HTTP MCP and REST. One person has
//! grants on reads and writes; a read-only path lists and executes only the
//! reads, refuses writes before any provider work, and the same person's
//! full-access paths keep every action.
use super::mcp::{rpc_body, structured};
use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ManagedPolicyGrantCreateRequest, ManagedStoreConfig, PrincipalRole, TrustedCallerConfig,
    TrustedCallerContextMode, TrustedCallerCredentialTransport,
};
use agent_access_provider::ServiceProvider;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

const RELAY: &str = "synthetic-path-relay-0123456789";
const USER: &str = "x-agent-access-user";
const CALLER: &str = "x-agent-access-caller-authorization";
const FINGERPRINT: &str = "x-aw-identity-token-sha256";
const NOTICE: &str =
    "This connection is read-only: only actions classified as reads are listed or executable.";
const HELPERS: [&str; 5] = [
    "actions_describe",
    "actions_list",
    "resources_list",
    "services_describe",
    "services_list",
];

/// The fake service with one reviewed read and unreviewed writes of every
/// I/O kind, counting scope resolutions and dispatches.
#[derive(Default)]
struct PathProvider {
    scope_resolutions: AtomicUsize,
    invocations: AtomicUsize,
}

impl PathProvider {
    fn work(&self) -> (usize, usize) {
        (
            self.scope_resolutions.load(Ordering::SeqCst),
            self.invocations.load(Ordering::SeqCst),
        )
    }
}

fn project_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "message"],
        "properties": {
            "project": { "type": "string" },
            "message": { "type": "string" }
        },
        "additionalProperties": false
    })
}

impl agent_access_provider::test_support::DescribedProvider for PathProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        let echo = descriptor.actions[0].clone();
        assert!(echo.read_only);
        let locator = json!({
            "type": "object",
            "required": ["project"],
            "properties": { "project": { "type": "string" } },
            "additionalProperties": false
        });
        let upload = json!({
            "type": "object",
            "required": ["project", "attachments"],
            "properties": {
                "project": { "type": "string" },
                "attachments": { "type": "array", "items": { "type": "object" } }
            },
            "additionalProperties": false
        });
        descriptor.actions = vec![
            echo,
            ActionDescriptor::new("note.write", "Write a project note", project_schema())
                .scope("project")
                .credential_modes(["service"]),
            ActionDescriptor::new("file.upload", "Upload a project file", upload)
                .scope("project")
                .credential_modes(["service"])
                .multipart_upload(attachment_upload_plan(&["project"], None)),
            ActionDescriptor::new("file.export", "Export a project file", locator)
                .scope("project")
                .credential_modes(["service"])
                .raw_download(),
        ];
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for PathProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        let project = request
            .inputs()
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ScopeResolution::resources(ResourceScopes::from([(
            "project".to_owned(),
            vec![project.to_owned()],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderResult::new(json!({
            "action": request.action(),
            "principal": request.identity().principal,
        })))
    }
}

/// A service whose only action is an unreviewed write.
struct WriteOnlyJira;

impl agent_access_provider::test_support::DescribedProvider for WriteOnlyJira {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Write-only Jira")
            .with_resource_scopes(fixture_scope_capabilities("project"))
            .with_actions(vec![
                ActionDescriptor::new(
                    "issue.comment.add",
                    "Comment on a project",
                    project_schema(),
                )
                .scope("project")
                .credential_modes(["service"]),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
    }
}

#[async_trait::async_trait]
impl Provider for WriteOnlyJira {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        panic!("a read-only path never resolves a write's scopes")
    }

    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("a read-only path never dispatches a write")
    }
}

/// Which of alice's trusted-identity paths a request uses.
#[derive(Clone, Copy, Debug)]
enum Via {
    Username,
    Fingerprint,
}

struct Fixture {
    _dir: tempfile::TempDir,
    _broker: TestBroker,
    app: Router,
    provider: Arc<PathProvider>,
    fingerprint: String,
    agent_token: String,
    admin_token: String,
    audit_path: PathBuf,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    create_private_dir(dir.path());
    let key = dir.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([47_u8; 32])).unwrap();
    let relay = dir.path().join("relay");
    std::fs::write(&relay, RELAY).unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    // One relay forwards both of alice's paths: username assertions and
    // identity-token fingerprints.
    config.identity.trusted_callers.insert(
        "relay".into(),
        TrustedCallerConfig {
            credential_ref: format!("file:{}", relay.display()),
            credential_transport: TrustedCallerCredentialTransport::CallerAuthorization,
            username_namespace: Some("linux".into()),
            context_mode: TrustedCallerContextMode::Fixed,
            execution_context: Some("default".into()),
            allowed_execution_contexts: None,
            allow_forwarded_identity: true,
        },
    );
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: dir.path().join("managed.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    });
    config.management.enabled = true;
    config.mcp.enabled = true;
    config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    config.mcp.max_sessions_per_principal = 64;
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.credentials.service.insert(
        "jira".into(),
        CredentialConfig {
            kind: "basic_api_token".into(),
            username_ref: Some("env:PATH_CONTROLS_JIRA_USERNAME".into()),
            token_ref: Some("env:PATH_CONTROLS_JIRA_TOKEN".into()),
            provider: None,
            path: None,
            read_only: None,
            connection: None,
        },
    );
    // Grants name the provider fixture's actions, so they are created
    // against the running catalog below.
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();

    let bootstrap = BrokerRuntime::new(config.clone()).unwrap();
    let store = bootstrap.managed_store().unwrap().clone();
    for (principal, role) in [
        ("alice", PrincipalRole::User),
        ("admin", PrincipalRole::Admin),
    ] {
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: principal.into(),
                kind: "user".into(),
                role,
                self_service_enabled: None,
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "fixture".into(),
            })
            .unwrap();
    }
    store
        .create_username_binding("alice", "linux", "alice", false, "fixture")
        .unwrap();
    seed_managed_fixture_resources(&store);
    let secret = store
        .reveal_identity_token("alice", bootstrap.credential_key_ring().unwrap())
        .unwrap();
    let fingerprint = format!("sha256:{:x}", Sha256::digest(secret.as_bytes()));
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: BrokerTokenClass, scopes: Value| {
        store
            .issue_broker_token(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "fixture".into(),
                    token_class,
                    scopes,
                    expires_at: None,
                    created_by: "fixture".into(),
                },
            )
            .unwrap()
            .token
    };
    let agent_token = issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts": ["default"]}),
    );
    let admin_token = issue("admin", BrokerTokenClass::Admin, json!({}));
    drop(bootstrap);

    let provider = Arc::new(PathProvider::default());
    let broker = TestBroker::start_with(with_provider_instances(
        TestBroker::config_builder(&config),
        [
            ServiceProvider::from(Arc::clone(&provider)),
            ServiceProvider::from(Arc::new(WriteOnlyJira)),
        ],
    ))
    .await;
    let runtime = broker.runtime();
    for (service, actions, resources) in [
        (
            "fake",
            &["echo", "note.write", "file.upload", "file.export"][..],
            &["project-test", "project-proj"][..],
        ),
        (
            "jira",
            &["issue.comment.add"][..],
            &["jira-project-test"][..],
        ),
    ] {
        runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: None,
                subjects: vec!["user:alice".into()],
                execution_contexts: vec!["default".into()],
                service: service.into(),
                actions: actions.iter().map(|action| (*action).into()).collect(),
                resources: ResourceSelection {
                    resource_ids: resources.iter().map(|id| (*id).into()).collect(),
                    resource_group_ids: vec![],
                },
                credential_mode: "service".into(),
                priority: None,
                status: None,
                description: None,
                created_by: "fixture".into(),
            })
            .unwrap();
    }
    Fixture {
        _dir: dir,
        app: broker.app(),
        _broker: broker,
        provider,
        fingerprint,
        agent_token,
        admin_token,
        audit_path,
    }
}

impl Fixture {
    fn path_headers(&self, via: Via) -> Vec<(&'static str, String)> {
        let mut headers = vec![(CALLER, format!("Bearer {RELAY}"))];
        headers.push(match via {
            Via::Username => (USER, "alice".to_owned()),
            Via::Fingerprint => (FINGERPRINT, self.fingerprint.clone()),
        });
        headers
    }

    /// An administrator request to alice's identity administration.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let mut headers = vec![("authorization", format!("Bearer {}", self.admin_token))];
        if body.is_some() {
            headers.push((CONTENT_TYPE.as_str(), "application/json".into()));
        }
        let response = self
            .rest(
                method,
                &format!("/v1/admin/principals/alice/{path}"),
                &headers,
                body.map_or_else(Body::empty, |body| Body::from(body.to_string())),
            )
            .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body["result"].clone()
    }

    /// Changes one of alice's paths' settings through its management PATCH,
    /// fenced by the current version or revision.
    async fn update_path(&self, via: Via, enabled: Option<bool>, read_only: Option<bool>) {
        let mut body = serde_json::Map::new();
        if let Some(enabled) = enabled {
            body.insert("enabled".into(), json!(enabled));
        }
        if let Some(read_only) = read_only {
            body.insert("readOnly".into(), json!(read_only));
        }
        let (path, current) = match via {
            Via::Username => {
                let binding =
                    self.admin(Method::GET, "identity-bindings", None).await["bindings"][0].clone();
                body.insert("expectedVersion".into(), binding["version"].clone());
                (
                    format!(
                        "identity-bindings/{}",
                        binding["bindingId"].as_str().unwrap()
                    ),
                    binding,
                )
            }
            Via::Fingerprint => {
                let inventory = self.admin(Method::GET, "identity-token", None).await;
                body.insert("expectedRevision".into(), inventory["revision"].clone());
                ("identity-token".to_owned(), inventory)
            }
        };
        let updated = self
            .admin(Method::PATCH, &path, Some(Value::Object(body)))
            .await;
        for (field, value) in [("enabled", enabled), ("readOnly", read_only)] {
            let expected = value.map_or_else(|| current[field].clone(), |value| json!(value));
            assert_eq!(updated[field], expected, "{via:?}: {updated}");
        }
    }

    async fn set_read_only(&self, via: Via, read_only: bool) {
        self.update_path(via, None, Some(read_only)).await;
    }

    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        tokio::time::timeout(Duration::from_secs(10), self.app.clone().oneshot(request))
            .await
            .expect("request timed out")
            .unwrap()
    }

    async fn mcp(
        &self,
        path: &str,
        via: Via,
        session: Option<&str>,
        message: Value,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:47100".parse::<SocketAddr>().unwrap(),
            ))
            .header("host", "broker.example.test")
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json");
        for (name, value) in self.path_headers(via) {
            builder = builder.header(name, value);
        }
        if let Some(session) = session {
            builder = builder
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        self.send(builder.body(Body::from(message.to_string())).unwrap())
            .await
    }

    /// An initialized session on `path` and its server instructions.
    async fn initialize(&self, path: &str, via: Via) -> (String, String) {
        let response = self
            .mcp(
                path,
                via,
                None,
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"identity-path-controls","version":"1"}
                }}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path} {via:?}");
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = rpc_body(response).await;
        // The SDK's negotiation and server info are unchanged by the override.
        assert_eq!(body["result"]["protocolVersion"], "2025-11-25", "{body}");
        assert!(body["result"]["serverInfo"]["name"].is_string(), "{body}");
        assert!(
            body["result"]["capabilities"]["tools"].is_object(),
            "{body}"
        );
        let instructions = body["result"]["instructions"].as_str().unwrap().to_owned();
        let initialized = self
            .mcp(
                path,
                via,
                Some(&session),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await;
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);
        (session, instructions)
    }

    async fn rpc(&self, path: &str, via: Via, session: &str, method: &str, params: Value) -> Value {
        let response = self
            .mcp(
                path,
                via,
                Some(session),
                json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        rpc_body(response).await
    }

    async fn tool_names(&self, path: &str, via: Via, session: &str) -> BTreeSet<String> {
        let listing = self.rpc(path, via, session, "tools/list", json!({})).await;
        listing["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("{listing}"))
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn helper(&self, via: Via, session: &str, name: &str, arguments: Value) -> Value {
        let result = self
            .rpc(
                "/mcp",
                via,
                session,
                "tools/call",
                json!({"name": name, "arguments": arguments}),
            )
            .await;
        structured(&result).clone()
    }

    async fn rest(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, String)],
        body: Body,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:47101".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, "identity-path-controls");
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        self.send(builder.body(body).unwrap()).await
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let response = self
            .rest(
                Method::GET,
                path,
                &self.path_headers(Via::Fingerprint),
                Body::empty(),
            )
            .await;
        let status = response.status();
        (status, response_json(response).await)
    }

    async fn invoke(
        &self,
        action: &str,
        headers: &[(&str, String)],
        inputs: Value,
    ) -> (StatusCode, Value) {
        let mut headers = headers.to_vec();
        headers.push((CONTENT_TYPE.as_str(), "application/json".into()));
        let response = self
            .rest(
                Method::POST,
                &format!("/v1/invoke/{action}"),
                &headers,
                Body::from(json!({"inputs": inputs}).to_string()),
            )
            .await;
        let status = response.status();
        (status, response_json(response).await)
    }
}

fn note() -> Value {
    json!({"project": "TEST", "message": "synthetic path control"})
}

fn assert_read_only_denial(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "service_action_denied", "{body}");
    assert_eq!(body["reason"], "identity access is read-only", "{body}");
    assert_eq!(body["resourceScopes"], json!({}), "{body}");
}

fn service_actions(services: &Value, service: &str) -> Option<Vec<String>> {
    services
        .as_array()
        .unwrap_or_else(|| panic!("{services}"))
        .iter()
        .find(|entry| entry["service"] == service)
        .map(|entry| {
            let mut actions = entry["actions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|action| {
                    action
                        .as_str()
                        .or_else(|| action["action"].as_str())
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>();
            actions.sort();
            actions
        })
}

fn all_fake_actions() -> Vec<String> {
    ["echo", "file.export", "file.upload", "note.write"]
        .map(str::to_owned)
        .to_vec()
}

#[tokio::test]
async fn http_mcp_read_only_paths_announce_list_and_call_only_reads() {
    let f = fixture().await;
    let echo = agent_access_core::mcp::tool_name("fake", "echo");
    let write = agent_access_core::mcp::tool_name("fake", "note.write");
    let comment = agent_access_core::mcp::tool_name("jira", "issue.comment.add");
    for via in [Via::Username, Via::Fingerprint] {
        let mut full_instructions = BTreeMap::new();
        for read_only in [false, true] {
            f.set_read_only(via, read_only).await;
            let case = format!("{via:?} read_only={read_only}");

            // initialize: the notice is appended to both views' instructions.
            for path in ["/mcp", "/mcp/fake"] {
                let (session, instructions) = f.initialize(path, via).await;
                // In-session discovery reports the same instructions.
                let discovered = f
                    .rpc(
                        path,
                        via,
                        &session,
                        "server/discover",
                        json!({"_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                            "io.modelcontextprotocol/clientCapabilities": {}
                        }}),
                    )
                    .await;
                assert_eq!(
                    discovered["result"]["instructions"], instructions,
                    "{case} {path}: {discovered}"
                );
                if read_only {
                    assert_eq!(
                        instructions,
                        format!("{} {NOTICE}", full_instructions[path]),
                        "{case} {path}"
                    );
                } else {
                    assert!(!instructions.contains(NOTICE), "{case} {path}");
                    full_instructions.insert(path, instructions);
                }
            }

            // tools/list, aggregate and scoped.
            let (session, _) = f.initialize("/mcp", via).await;
            let mut expected = HELPERS.map(str::to_owned).to_vec();
            expected.push(echo.clone());
            if !read_only {
                expected.extend([write.clone(), comment.clone()]);
            }
            assert_eq!(
                f.tool_names("/mcp", via, &session).await,
                expected.into_iter().collect::<BTreeSet<_>>(),
                "{case}"
            );
            let (scoped, _) = f.initialize("/mcp/fake", via).await;
            let mut expected = HELPERS.map(str::to_owned).to_vec();
            expected.push("echo".into());
            if !read_only {
                expected.push("note.write".into());
            }
            assert_eq!(
                f.tool_names("/mcp/fake", via, &scoped).await,
                expected.into_iter().collect::<BTreeSet<_>>(),
                "{case}"
            );
            // A service with no remaining action has no scoped view.
            let jira = f
                .mcp(
                    "/mcp/jira",
                    via,
                    None,
                    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                        "protocolVersion":"2025-11-25","capabilities":{},
                        "clientInfo":{"name":"identity-path-controls","version":"1"}
                    }}),
                )
                .await;
            if read_only {
                assert_eq!(jira.status(), StatusCode::NOT_FOUND, "{case}");
                assert_eq!(
                    response_json(jira).await["error"],
                    "Service MCP view is unavailable"
                );
            } else {
                assert_eq!(jira.status(), StatusCode::OK, "{case}");
            }

            // The five helpers report only the filtered catalog.
            let services = f.helper(via, &session, "services_list", json!({})).await;
            assert_eq!(
                service_actions(&services["services"], "fake"),
                Some(if read_only {
                    vec!["echo".into()]
                } else {
                    all_fake_actions()
                }),
                "{case}"
            );
            assert_eq!(
                service_actions(&services["services"], "jira").is_some(),
                !read_only,
                "{case}"
            );
            let described = f
                .helper(
                    via,
                    &session,
                    "services_describe",
                    json!({"service": "fake"}),
                )
                .await;
            assert_eq!(
                service_actions(&json!([described]), "fake"),
                Some(if read_only {
                    vec!["echo".into()]
                } else {
                    all_fake_actions()
                }),
                "{case}"
            );
            let jira = f
                .helper(
                    via,
                    &session,
                    "services_describe",
                    json!({"service": "jira"}),
                )
                .await;
            assert_eq!(jira.get("error").is_some(), read_only, "{case}: {jira}");
            let actions = f
                .helper(
                    via,
                    &session,
                    "actions_list",
                    json!({"service": "fake", "resource": "TEST"}),
                )
                .await;
            assert_eq!(
                actions["actions"],
                if read_only {
                    json!(["echo"])
                } else {
                    json!(all_fake_actions())
                },
                "{case}"
            );
            let detail = f
                .helper(
                    via,
                    &session,
                    "actions_describe",
                    json!({"service": "fake", "action": "note.write"}),
                )
                .await;
            if read_only {
                assert_eq!(
                    detail["error"]["message"], "Action is not visible or does not exist",
                    "{case}"
                );
            } else {
                assert_eq!(detail["action"], "note.write", "{case}: {detail}");
            }
            let resources = f
                .helper(via, &session, "resources_list", json!({"service": "fake"}))
                .await;
            assert_eq!(
                resources["resources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|resource| resource["value"].clone())
                    .collect::<Vec<_>>(),
                [json!("PROJ"), json!("TEST")],
                "{case}"
            );

            // A hidden write tool fails registry resolution, before dispatch.
            let before = f.provider.work();
            let called = f
                .rpc(
                    "/mcp",
                    via,
                    &session,
                    "tools/call",
                    json!({"name": write, "arguments": {"inputs": note()}}),
                )
                .await;
            if read_only {
                assert_eq!(called["error"]["code"], -32602, "{case}: {called}");
                assert!(
                    called["error"]["message"]
                        .as_str()
                        .unwrap()
                        .starts_with("Unknown or unavailable HTTP MCP tool"),
                    "{called}"
                );
                assert_eq!(f.provider.work(), before, "{case}");
            } else {
                assert_eq!(structured(&called)["decision"], "allow", "{case}: {called}");
                assert_eq!(f.provider.work(), (before.0 + 1, before.1 + 1), "{case}");
            }
            let read = f
                .rpc(
                    "/mcp",
                    via,
                    &session,
                    "tools/call",
                    json!({"name": echo, "arguments": {"inputs": note()}}),
                )
                .await;
            assert_eq!(structured(&read)["decision"], "allow", "{case}: {read}");
        }
        f.set_read_only(via, false).await;
    }

    // Both paths' invocation audit records carry their path setting.
    let records = read_audit_records(&f.audit_path);
    for (kind, header) in [
        ("trusted_user", "x-agent-access-user"),
        ("forwarded_identity", "x-aw-identity-token-sha256"),
    ] {
        let settings = records
            .iter()
            .filter(|record| {
                record["action"] == "echo"
                    && record["decision"] == "allow"
                    && record["identitySource"]["type"] == kind
            })
            .map(|record| {
                assert_eq!(record["identitySource"]["tokenHeader"], header);
                record["identitySource"]["readOnlyAccess"].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(settings, [json!(false), json!(true)], "{kind}");
    }
}

#[tokio::test]
async fn fingerprint_rest_read_only_path_filters_specs_and_denies_writes_before_provider_work() {
    let f = fixture().await;
    let send_request = |action: &str| {
        json!({
            "version": "agent-access.send.v1", "kind": "invoke",
            "service": "fake", "action": action,
            "inputs": {"project": "TEST", "message": "synthetic"}
        })
    };
    for read_only in [false, true] {
        f.set_read_only(Via::Fingerprint, read_only).await;
        let case = format!("read_only={read_only}");
        let fake_actions = if read_only {
            vec!["echo".to_owned()]
        } else {
            all_fake_actions()
        };

        let (status, me) = f.get("/v1/me").await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["principal"], "alice");
        assert_eq!(me["readOnlyAccess"], read_only, "{me}");

        let (_, capabilities) = f.get("/v1/capabilities").await;
        assert_eq!(capabilities["identity"]["readOnlyAccess"], read_only);
        assert_eq!(
            service_actions(&capabilities["services"], "fake"),
            Some(fake_actions.clone()),
            "{case}"
        );
        assert_eq!(
            service_actions(&capabilities["services"], "jira").is_some(),
            !read_only
        );

        let (_, catalog) = f.get("/v1/spec/catalog").await;
        assert_eq!(catalog["identity"]["readOnlyAccess"], read_only);
        assert_eq!(
            service_actions(&catalog["services"], "fake"),
            Some(fake_actions.clone()),
            "{case}"
        );
        assert_eq!(
            service_actions(&catalog["services"], "jira").is_some(),
            !read_only
        );

        let (_, openapi) = f.get("/v1/spec/openapi.json").await;
        for (route, listed) in [
            ("/v1/invoke/fake/echo", true),
            ("/v1/invoke/fake/note.write", !read_only),
            ("/v1/invoke/fake/file.upload", !read_only),
            ("/v1/invoke/fake/file.export", !read_only),
            ("/v1/invoke/jira/issue.comment.add", !read_only),
        ] {
            assert_eq!(
                openapi["paths"].get(route).is_some(),
                listed,
                "{case} {route}"
            );
        }

        let (_, send_schema) = f.get("/v1/spec/send-schema.json").await;
        let send = jsonschema::validator_for(&send_schema).unwrap();
        assert!(send.is_valid(&send_request("echo")), "{case}");
        assert_eq!(
            send.is_valid(&send_request("note.write")),
            !read_only,
            "{case}"
        );

        let (_, services) = f.get("/v1/services").await;
        let listed = services
            .as_array()
            .unwrap_or_else(|| panic!("{services}"))
            .iter()
            .map(|service| service["service"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let mut expected = BTreeSet::from(["fake".to_owned()]);
        if !read_only {
            expected.insert("jira".to_owned());
        }
        assert_eq!(listed, expected, "{case}");
        let (_, fake) = f.get("/v1/services/fake").await;
        assert_eq!(
            service_actions(&json!([fake]), "fake"),
            Some(fake_actions.clone())
        );
        let (status, _) = f.get("/v1/services/jira").await;
        assert_eq!(status == StatusCode::OK, !read_only, "{case}: {status}");
        let (_, actions) = f.get("/v1/services/fake/actions?resource=TEST").await;
        assert_eq!(actions["actions"], json!(fake_actions), "{case}");
        let (_, resources) = f.get("/v1/services/fake/resources").await;
        assert_eq!(
            resources["resources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|resource| resource["value"].clone())
                .collect::<Vec<_>>(),
            [json!("PROJ"), json!("TEST")],
            "{case}"
        );
    }

    // Writes are refused on every REST invocation shape before scope
    // resolution or dispatch; the read still works.
    let headers = f.path_headers(Via::Fingerprint);
    let before = f.provider.work();
    let (status, body) = f.invoke("fake/note.write", &headers, note()).await;
    assert_read_only_denial(status, &body);
    let (status, body) = f.invoke("jira/issue.comment.add", &headers, note()).await;
    assert_read_only_denial(status, &body);
    let mut raw_headers = headers.clone();
    raw_headers.push((ACCEPT.as_str(), RAW_RESULT_MIME.into()));
    let (status, body) = f
        .invoke("fake/file.export", &raw_headers, json!({"project": "TEST"}))
        .await;
    assert_read_only_denial(status, &body);
    let boundary = "path-controls-boundary";
    let mut multipart_headers = headers.clone();
    multipart_headers.push((
        CONTENT_TYPE.as_str(),
        format!("multipart/form-data; boundary={boundary}"),
    ));
    let multipart = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"TEST\",\"attachments\":[{{\"field\":\"file\",\"filename\":\"notes.txt\",\"contentType\":\"text/plain\",\"size\":5,\"sha256\":\"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"}}]}}}}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         hello\r\n\
         --{boundary}--\r\n"
    );
    let response = f
        .rest(
            Method::POST,
            "/v1/invoke/fake/file.upload",
            &multipart_headers,
            Body::from(multipart),
        )
        .await;
    let status = response.status();
    assert_read_only_denial(status, &response_json(response).await);
    assert_eq!(f.provider.work(), before);
    let (status, body) = f.invoke("fake/echo", &headers, note()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(f.provider.work(), (before.0 + 1, before.1 + 1));

    // The username header stays rejected on REST routes.
    let username = f.path_headers(Via::Username);
    for path in ["/v1/me", "/v1/spec/catalog", "/v1/services"] {
        let response = f.rest(Method::GET, path, &username, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            response_json(response).await["reasonCode"],
            "identity_assertion_unsupported"
        );
    }

    // The full-access path and an issued Broker token still write.
    f.set_read_only(Via::Fingerprint, false).await;
    let (status, body) = f.invoke("fake/note.write", &headers, note()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bearer = [(AUTHORIZATION.as_str(), format!("Bearer {}", f.agent_token))];
    let (status, body) = f.invoke("fake/note.write", &bearer, note()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let records = read_audit_records(&f.audit_path);
    let invocations = records
        .iter()
        .filter(|record| record["service"] != "broker" && record.get("decision").is_some())
        .filter(|record| record["identitySource"].is_object())
        .collect::<Vec<_>>();
    let denials = invocations
        .iter()
        .filter(|record| record["reasonCode"] == "service_action_denied")
        .collect::<Vec<_>>();
    assert_eq!(denials.len(), 4, "{denials:?}");
    for denial in &denials {
        assert_eq!(denial["providerAudit"]["identityAccess"]["readOnly"], true);
        assert_eq!(
            denial["providerAudit"]["identityAccess"]["requestedAction"],
            denial["action"]
        );
        assert_eq!(denial["identitySource"]["readOnlyAccess"], true);
        assert_eq!(denial["identitySource"]["type"], "forwarded_identity");
        assert!(denial.get("matchedGrant").is_none(), "{denial}");
        let encoded = denial.to_string();
        assert!(!encoded.contains(&f.fingerprint), "{encoded}");
    }
    let allowed = |action: &str| {
        invocations
            .iter()
            .filter(|record| record["action"] == action && record["decision"] == "allow")
            .map(|record| record["identitySource"].clone())
            .collect::<Vec<_>>()
    };
    let reads = allowed("echo");
    assert_eq!(reads.last().unwrap()["readOnlyAccess"], true);
    let writes = allowed("note.write");
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0]["readOnlyAccess"], false);
    assert_eq!(writes[1]["type"], "broker_tokens");
    assert!(writes[1].get("readOnlyAccess").is_none(), "{}", writes[1]);
}

#[tokio::test]
async fn resource_discovery_cursors_do_not_survive_a_read_only_toggle() {
    let f = fixture().await;
    let (status, page) = f.get("/v1/services/fake/resources?limit=1").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let cursor = page["nextCursor"].as_str().unwrap().to_owned();
    let next = format!("/v1/services/fake/resources?limit=1&cursor={cursor}");
    let (status, _) = f.get(&next).await;
    assert_eq!(status, StatusCode::OK);
    f.set_read_only(Via::Fingerprint, true).await;
    let (status, body) = f.get(&next).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn disabled_identity_token_resolves_as_an_unknown_fingerprint_until_reenabled() {
    let f = fixture().await;
    let unknown = format!("sha256:{}", "0".repeat(64));
    let fixture = &f;
    let me = |fingerprint: String| async move {
        let headers = [
            (CALLER, format!("Bearer {RELAY}")),
            (FINGERPRINT, fingerprint),
        ];
        let response = fixture
            .rest(Method::GET, "/v1/me", &headers, Body::empty())
            .await;
        let status = response.status();
        (status, response_json(response).await)
    };
    let (status, unknown_body) = me(unknown).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = me(f.fingerprint.clone()).await;
    assert_eq!(status, StatusCode::OK);

    f.update_path(Via::Fingerprint, Some(false), None).await;
    let (status, body) = me(f.fingerprint.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["reasonCode"], unknown_body["reasonCode"], "{body}");
    assert_eq!(body["reason"], unknown_body["reason"], "{body}");
    let response = f
        .mcp(
            "/mcp",
            Via::Fingerprint,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"identity-path-controls","version":"1"}
            }}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The username path is a separate path and is unaffected.
    f.initialize("/mcp", Via::Username).await;

    f.update_path(Via::Fingerprint, Some(true), None).await;
    let (status, body) = me(f.fingerprint.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    f.initialize("/mcp", Via::Fingerprint).await;
}
