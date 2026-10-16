use super::*;
use agent_access_provider::{
    Provider, ProviderError, ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution,
};
use async_trait::async_trait;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

const IDENTITY: AssemblyIdentity = AssemblyIdentity::new("isolated-test-broker", "1.2.3");

fn composition() -> BrokerComposition {
    BrokerComposition::from_registry(crate::backend_registry())
}

fn quoted(path: &Path) -> String {
    serde_json::to_string(&path.display().to_string()).unwrap()
}

/// Anonymous callers may echo to the fake project `project`; audit is JSONL.
fn fake_document(directory: &FixtureDir, project: &str) -> String {
    let token = directory
        .secret_file("fake-service-token", "synthetic-fake-token")
        .unwrap();
    let spool = directory.private_dir("spool").unwrap();
    format!(
        r#"
[deployment]
environment = "development"
enable_fake_service = true

[identity]
mode = "anonymous"
authority = "toml"

[providers.fake]

[credentials.service.fake]
type = "bearer_token"
token_ref = {token}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "project"
resource_type = "fake_project"
selector = {{ kind = "exact", value = "{project}" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:anonymous"]
service = "fake"
actions = ["echo"]
resources = {{ resource_ids = ["project"] }}
credential_mode = "service"

[limits]
upload_spool_dir = {spool}

[audit]
type = "jsonl"
path = {audit}
"#,
        token = quoted(&PathBuf::from(format!("file:{}", token.display()))),
        spool = quoted(&spool),
        audit = quoted(&directory.join("audit.jsonl")),
    )
}

async fn echo(broker: &RunningBroker, request_id: &str, project: &str) -> (u16, Value) {
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/invoke/fake/echo", broker.public_url()))
        .header("x-agent-access-request-id", request_id)
        .json(&json!({"inputs": {"project": project, "message": "isolated"}}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

#[tokio::test]
async fn an_isolated_broker_serves_reloads_and_releases_its_locks_on_join() {
    let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let document = fake_document(application.directory(), "TEST");
    let broker = application.config_document(document).start().await.unwrap();
    assert!(broker.public_addr().ip().is_loopback());
    assert_ne!(broker.public_addr().port(), 0);
    assert_eq!(broker.gateway_addr(), None);
    assert_eq!(broker.config_generation(), 1);
    assert_eq!(
        broker.config_path(),
        broker.directory().join("broker.toml").as_path()
    );

    let (status, envelope) = echo(&broker, "isolated-before-reload", "TEST").await;
    assert_eq!(status, 200, "{envelope}");
    assert_eq!(envelope["result"]["project"], "TEST");

    // A second broker on the same state cannot start while the first owns it.
    let contender = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .in_directory(broker.directory().clone())
        .config_path(broker.config_path())
        .start()
        .await
        .unwrap_err();
    assert!(
        format!("{contender:#}").contains("state lock is held"),
        "{contender:#}"
    );

    broker
        .rewrite_config(fake_document(broker.directory(), "NEXT"))
        .unwrap();
    let reload = broker.reload().await.unwrap();
    assert!(reload.is_success(), "{reload:?}");
    assert_eq!(reload.decision(), "allow");
    assert_eq!(reload.result()["generation"], 2);
    assert_eq!(broker.config_generation(), 2);
    assert_eq!(echo(&broker, "isolated-old-project", "TEST").await.0, 403);
    assert_eq!(echo(&broker, "isolated-new-project", "NEXT").await.0, 200);

    broker.rewrite_config("not toml =").unwrap();
    let failed = broker.reload().await.unwrap();
    assert!(!failed.is_success());
    assert_eq!(failed.decision(), "deny");
    assert_eq!(failed.reason_code(), Some("config_parse_failed"));
    assert_eq!(broker.config_generation(), 2);

    let audit = broker.audit().unwrap();
    assert_eq!(audit.kind(), "jsonl");
    let records = audit.records();
    assert!(records.iter().any(|record| {
        record["service"] == "broker"
            && record["action"] == "config.reload"
            && record["decision"] == "allow"
            && record["principal"] == "system"
    }));
    assert!(audit.text().contains("isolated-new-project"));

    let directory = broker.directory().clone();
    let config_path = broker.config_path().to_path_buf();
    broker.shutdown();
    let report = broker.join().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(
        audit.records().len(),
        records.len(),
        "the audit view outlives the broker"
    );

    // Every lock is released, so a restart on the same state succeeds.
    std::fs::write(&config_path, fake_document(&directory, "TEST")).unwrap();
    let restarted = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .in_directory(directory)
        .config_path(config_path)
        .start()
        .await
        .unwrap();
    assert_eq!(echo(&restarted, "isolated-restarted", "TEST").await.0, 200);
    restarted.shutdown();
    restarted.join().await.unwrap();
}

/// A command supervisor stand-in that ignores kill requests, holding its
/// permit until the test releases it.
#[derive(Default)]
struct StuckCommandProcess {
    kills: AtomicUsize,
}

impl agent_access_core::imports::CommandProcessControl for StuckCommandProcess {
    fn request_kill(&self) {
        self.kills.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn shutdown_reports_unreaped_command_processes_and_a_restart_has_full_budgets() {
    let application = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .shutdown_timeout(Duration::from_millis(500));
    let document = fake_document(application.directory(), "TEST");
    let broker = application.config_document(document).start().await.unwrap();
    let registry = broker
        .reloadable_state()
        .current()
        .runtime
        .command_registry()
        .clone();
    assert!(broker.reload().await.unwrap().is_success());
    assert!(
        registry.ptr_eq(
            broker
                .reloadable_state()
                .current()
                .runtime
                .command_registry()
        ),
        "a reload keeps the command budgets"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let stuck = Arc::new(StuckCommandProcess::default());
    let live = registry
        .acquire("ticketing", 1, deadline)
        .await
        .unwrap()
        .register(stuck.clone())
        .unwrap();

    let directory = broker.directory().clone();
    let config_path = broker.config_path().to_path_buf();
    broker.shutdown();
    let report = broker.join().await.unwrap();
    assert_eq!(report.unfinished_command_processes(), 1);
    assert!(!report.is_clean(), "{report:?}");
    assert_eq!(stuck.kills.load(Ordering::SeqCst), 1);
    assert!(registry.is_closed());
    drop(live);
    assert_eq!(registry.in_use("ticketing"), 0);

    // Another broker on the same runtime starts with its own, full budgets.
    let restarted = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .in_directory(directory)
        .config_path(config_path)
        .start()
        .await
        .unwrap();
    let fresh = restarted
        .reloadable_state()
        .current()
        .runtime
        .command_registry()
        .clone();
    assert!(!fresh.ptr_eq(&registry));
    assert!(!fresh.is_closed());
    drop(fresh.acquire("ticketing", 1, deadline).await.unwrap());
    restarted.shutdown();
    let report = restarted.join().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.unfinished_command_processes(), 0);
}

#[tokio::test]
async fn reload_and_shutdown_fail_once_the_broker_has_stopped() {
    let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let document = fake_document(application.directory(), "TEST");
    let broker = application.config_document(document).start().await.unwrap();
    let reload = broker.reload.clone();
    broker.shutdown();
    broker.shutdown();
    broker.join().await.unwrap();
    let (outcome, _received) = oneshot::channel();
    assert!(
        reload
            .send(ReloadRequest {
                outcome: Some(outcome)
            })
            .is_err()
    );
}

#[tokio::test]
async fn startup_failures_are_reported_as_the_process_reports_them() {
    let missing = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .start()
        .await
        .unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("configuration document or path")
    );

    let invalid = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .config_document("[identity]\nmode = \"anonymous\"\n")
        .start()
        .await
        .unwrap_err();
    assert!(
        invalid
            .chain()
            .any(|cause| cause.is::<agent_access_core::ConfigError>()),
        "{invalid:#}"
    );
}

struct CountingFake {
    generation: usize,
    invocations: Arc<Mutex<Vec<usize>>>,
}

#[async_trait]
impl Provider for CountingFake {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .resolve_scopes(request)
            .await
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.lock().unwrap().push(self.generation);
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

#[tokio::test]
async fn provider_fixtures_serve_every_generation_under_normal_admission() {
    let builds = Arc::new(AtomicUsize::new(0));
    let invocations = Arc::new(Mutex::new(Vec::new()));
    let fixture = ProviderFixture::factory({
        let builds = Arc::clone(&builds);
        let invocations = Arc::clone(&invocations);
        move |context| {
            let generation = builds.fetch_add(1, Ordering::SeqCst) + 1;
            ServiceProvider::new(
                context.descriptor().clone(),
                Arc::new(CountingFake {
                    generation,
                    invocations: Arc::clone(&invocations),
                }),
            )
        }
    });
    let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let document = fake_document(application.directory(), "TEST");
    let broker = application
        .config_document(document)
        .provider_fixture("fake", fixture)
        .start()
        .await
        .unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_eq!(echo(&broker, "fixture-first", "TEST").await.0, 200);
    // Policy still applies to the injected provider.
    assert_eq!(echo(&broker, "fixture-denied", "OTHER").await.0, 403);

    assert!(broker.reload().await.unwrap().is_success());
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert_eq!(echo(&broker, "fixture-second", "TEST").await.0, 200);
    assert_eq!(*invocations.lock().unwrap(), [1, 2]);
    broker.shutdown();
    broker.join().await.unwrap();
}

#[tokio::test]
async fn provider_fixtures_must_name_a_configured_selected_kind_once() {
    let instance = || ProviderFixture::instance(agent_access_fake::fake_service_provider());
    let start = |kinds: &[&str]| {
        let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
        let document = fake_document(application.directory(), "TEST");
        let application = kinds.iter().fold(
            application.config_document(document),
            |application, kind| application.provider_fixture(*kind, instance()),
        );
        application.start()
    };
    let unconfigured = start(&["jira"]).await.unwrap_err();
    assert!(
        format!("{unconfigured:#}")
            .contains("provider fixture jira has no [providers.jira] configuration"),
        "{unconfigured:#}"
    );
    let unselected = start(&["unselected"]).await.unwrap_err();
    assert!(
        format!("{unselected:#}")
            .contains("provider fixture unselected names no selected native provider"),
        "{unselected:#}"
    );
    let duplicate = start(&["fake", "fake"]).await.unwrap_err();
    assert_eq!(
        duplicate.to_string(),
        "provider fixture fake is supplied more than once"
    );
    let impersonating = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let document = fake_document(impersonating.directory(), "TEST");
    let error = impersonating
        .config_document(document)
        .provider_fixture(
            "fake",
            ProviderFixture::factory(|context| {
                let mut descriptor = context.descriptor().clone();
                descriptor.service = "jira".into();
                ServiceProvider::new(descriptor, Arc::new(agent_access_fake::FakeProvider))
            }),
        )
        .start()
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("provider fixture fake serves service jira"),
        "{error:#}"
    );
}

#[test]
fn fixture_directories_are_private_and_contain_their_paths() {
    let directory = FixtureDir::new().unwrap();
    let secret = directory.secret_file("nested/secret", "value").unwrap();
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "value");
    let replaced = directory.secret_file("nested/secret", "other").unwrap();
    assert_eq!(std::fs::read_to_string(replaced).unwrap(), "other");
    let state = directory.private_dir("state/deeper").unwrap();
    assert!(state.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(directory.path()), 0o700);
        assert_eq!(mode(&directory.join("nested")), 0o700);
        assert_eq!(mode(&secret), 0o600);
        assert_eq!(mode(&directory.join("state")), 0o700);
        assert_eq!(mode(&state), 0o700);
    }
    for escaping in ["../outside", "/absolute", "", "a/../../b"] {
        assert_eq!(
            directory.secret_file(escaping, "x").unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{escaping}"
        );
    }
    let clone = directory.clone();
    let path = directory.path().to_path_buf();
    drop(directory);
    assert!(path.exists(), "clones share the directory");
    drop(clone);
    assert!(!path.exists());
}

#[tokio::test]
async fn host_tests_reach_the_served_routers_and_state_in_process() {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;

    let application = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .gateway_listener()
        .unwrap();
    let document = fake_document(application.directory(), "TEST");
    let (public_addr, bound_gateway) = (application.public_addr(), application.gateway_addr());
    let broker = application.config_document(document).start().await.unwrap();
    // The listeners bound before startup are the ones that serve.
    assert_eq!(broker.public_addr(), public_addr);
    assert_eq!(broker.gateway_addr(), bound_gateway);
    let gateway_addr = broker.gateway_addr().unwrap();
    assert!(gateway_addr.ip().is_loopback());
    assert_ne!(gateway_addr, broker.public_addr());
    let state = broker.reloadable_state();
    assert_eq!(state.current().generation, 1);
    assert_eq!(state.config_path, broker.config_path());
    drop(state);

    let in_process = |app: axum::Router, uri: &'static str| async move {
        app.oneshot(
            Request::get(uri)
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41000))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
        .as_u16()
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let over_tcp = |url: String| {
        let client = client.clone();
        async move { client.get(url).send().await.unwrap().status().as_u16() }
    };
    assert_eq!(in_process(broker.public_app(), "/v1/healthz").await, 200);
    assert_eq!(
        over_tcp(format!("{}/v1/healthz", broker.public_url())).await,
        200
    );
    let gateway_path = "/group/repo.git/info/refs?service=git-upload-pack";
    assert_eq!(
        in_process(broker.gateway_app(), gateway_path).await,
        over_tcp(format!("http://{gateway_addr}{gateway_path}")).await
    );
    broker.shutdown();
    broker.join().await.unwrap();
}

#[tokio::test]
async fn join_ends_http_mcp_sessions_left_open() {
    let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let token = application
        .directory()
        .secret_file("mcp-token", "synthetic-mcp-token")
        .unwrap();
    // HTTP MCP needs Bearer identity rather than anonymous callers.
    let document = fake_document(application.directory(), "TEST").replace(
        "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n",
        &format!(
            "[identity]\nmode = \"optional\"\nauthority = \"toml\"\n\
             [[identity.sources]]\nname = \"mcp\"\ntype = \"static_principals\"\n\
             header = \"Authorization\"\nscheme = \"Bearer\"\n\
             [[identity.sources.principals]]\nprincipal = \"mcp-user\"\ntoken_refs = [{}]\n",
            quoted(&PathBuf::from(format!("file:{}", token.display())))
        ),
    );
    let mcp_url = format!("{}/mcp", application.public_url());
    let document = format!(
        "{document}\n[mcp]\nenabled = true\npublic_url = {}\n",
        serde_json::to_string(&mcp_url).unwrap()
    );
    let broker = application
        .config_document(document)
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    let initialized = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&mcp_url)
        .header("x-agent-access-request-id", "join-open-session")
        .bearer_auth("synthetic-mcp-token")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "join-test", "version": "1"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(initialized.status().is_success(), "{initialized:?}");
    assert!(initialized.headers().contains_key("mcp-session-id"));
    drop(initialized);
    broker.shutdown();
    let report = tokio::time::timeout(Duration::from_secs(10), broker.join())
        .await
        .expect("an open MCP session must not hold the state locks")
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
}

#[tokio::test]
async fn join_cuts_off_connections_still_open_at_the_shutdown_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let application = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .shutdown_timeout(Duration::from_millis(500));
    let document = fake_document(application.directory(), "TEST");
    let broker = application.config_document(document).start().await.unwrap();
    // A request whose body never finishes: the broker's 100 Continue shows
    // that the request is being served and its body is being read.
    let mut client = tokio::net::TcpStream::connect(broker.public_addr())
        .await
        .unwrap();
    client
        .write_all(
            b"POST /v1/invoke/fake/echo HTTP/1.1\r\n\
              host: 127.0.0.1\r\n\
              content-type: application/json\r\n\
              x-agent-access-request-id: partial-body\r\n\
              expect: 100-continue\r\n\
              content-length: 1000\r\n\r\n",
        )
        .await
        .unwrap();
    let mut interim = Vec::new();
    while !interim.ends_with(b"\r\n\r\n") {
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), client.read(&mut byte))
            .await
            .expect("the broker reads the request body")
            .unwrap();
        assert_eq!(read, 1, "{}", String::from_utf8_lossy(&interim));
        interim.push(byte[0]);
    }
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "{}",
        String::from_utf8_lossy(&interim)
    );
    client.write_all(br#"{"inputs":"#).await.unwrap();

    let directory = broker.directory().clone();
    let config_path = broker.config_path().to_path_buf();
    broker.shutdown();
    let report = tokio::time::timeout(Duration::from_secs(4), broker.join())
        .await
        .expect("a connection left open must not outlive the shutdown deadline")
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert!(report.was_forced(), "{report:?}");
    // The broker closed the connection without answering the request.
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut rest))
        .await
        .expect("the broker closed the connection");
    if let Ok(read) = closed {
        assert_eq!(read, 0, "{}", String::from_utf8_lossy(&rest));
    }

    // Every lock is released, so a restart on the same state succeeds at once.
    let restarted = IsolatedBroker::new(composition(), IDENTITY)
        .unwrap()
        .in_directory(directory)
        .config_path(config_path)
        .start()
        .await
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(echo(&restarted, "cut-off-restarted", "TEST").await.0, 200);
    restarted.shutdown();
    restarted.join().await.unwrap();
}

#[tokio::test]
async fn audit_views_keep_the_fixture_directory_after_join() {
    let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
    let document = fake_document(application.directory(), "TEST");
    let directory = application.directory().path().to_path_buf();
    let broker = application.config_document(document).start().await.unwrap();
    assert_eq!(echo(&broker, "audit-view-after-join", "TEST").await.0, 200);
    let audit = broker.audit().unwrap();
    broker.shutdown();
    broker.join().await.unwrap();

    // The view is the only holder of the fixture directory now.
    assert!(audit.path().starts_with(&directory));
    let records = audit.records();
    assert!(
        records
            .iter()
            .any(|record| record["agentRequestId"] == "audit-view-after-join"),
        "{records:?}"
    );
    assert!(audit.text().contains("audit-view-after-join"));
    let clone = audit.clone();
    drop(audit);
    assert!(directory.exists(), "clones keep the directory");
    drop(clone);
    assert!(!directory.exists());
}

/// Records the `event` field of events and the `agentRequestId` recorded
/// on spans.
#[derive(Clone, Default)]
struct CapturedFields(Arc<Mutex<Vec<String>>>);

impl CapturedFields {
    fn contains(&self, entry: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|captured| captured == entry)
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedFields {
    fn on_record(
        &self,
        _span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        values.record(&mut FieldVisitor {
            name: "agentRequestId",
            captured: self,
        });
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        event.record(&mut FieldVisitor {
            name: "event",
            captured: self,
        });
    }
}

struct FieldVisitor<'a> {
    name: &'static str,
    captured: &'a CapturedFields,
}

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == self.name {
            self.captured
                .0
                .lock()
                .unwrap()
                .push(format!("{}={value}", self.name));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == self.name {
            self.record_str(field, &format!("{value:?}"));
        }
    }
}

#[tokio::test]
async fn lifecycle_and_connection_events_reach_the_starting_task_s_dispatcher() {
    use tracing_subscriber::layer::SubscriberExt;

    let _capture_guard = crate::observability::tracing_capture_test_lock()
        .lock()
        .await;
    // As in the other capture tests: a second live dispatcher makes callsite
    // registration consult every subscriber rather than whichever thread
    // registers first, and the rebuild covers callsites registered earlier.
    let _registration_guard = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let captured = CapturedFields::default();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(captured.clone()));
    tracing_core::callsite::rebuild_interest_cache();
    async {
        let application = IsolatedBroker::new(composition(), IDENTITY).unwrap();
        let document = fake_document(application.directory(), "TEST");
        let broker = application.config_document(document).start().await.unwrap();
        // Served over TCP by a connection task of the broker's listener.
        assert_eq!(echo(&broker, "scoped-dispatcher", "TEST").await.0, 200);
        // Published by the broker's reload task.
        assert!(broker.reload().await.unwrap().is_success());
        broker.shutdown();
        broker.join().await.unwrap();
    }
    .with_subscriber(dispatch)
    .await;
    assert!(
        captured.contains("agentRequestId=scoped-dispatcher"),
        "{:?}",
        captured.0.lock().unwrap()
    );
    assert!(
        captured.contains("event=config_reload_completed"),
        "{:?}",
        captured.0.lock().unwrap()
    );
}
