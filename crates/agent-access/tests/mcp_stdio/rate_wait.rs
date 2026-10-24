use super::*;
use agent_access_broker_host::test_support::ProviderFixture;
use agent_access_provider::{
    Provider, ProviderError, ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution,
    ServiceProvider,
};

struct CountingFake {
    calls: Arc<Mutex<Vec<String>>>,
    release_queued: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
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
        self.calls
            .lock()
            .unwrap()
            .push(request.inputs()["message"].as_str().unwrap().to_owned());
        if request.inputs()["message"] == "queued-cli" {
            self.release_queued.notified().await;
        }
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

struct Fixture {
    broker: RunningBroker,
    directory: FixtureDir,
    client: std::path::PathBuf,
    token: String,
    calls: Arc<Mutex<Vec<String>>>,
    release_queued: Arc<tokio::sync::Notify>,
}

async fn fixture() -> Fixture {
    let application = isolated_broker();
    let directory = application.directory().clone();
    let token = "rate-wait-agent-one".to_owned();
    let first = directory.secret_file("one.token", &token).unwrap();
    let second = directory
        .secret_file("two.token", "rate-wait-agent-two")
        .unwrap();
    let credential = directory
        .secret_file("fake-credential", "fake-service-credential")
        .unwrap();
    let document = fake_document(&directory, &first, &second).replace(
        "\"env:FAKE_SERVICE_TOKEN\"",
        &toml_string(format_args!("file:{}", credential.display())),
    ) + "\nmax_concurrent_requests = 1\nmax_concurrent_requests_per_principal = 1\n\n[limits.invocations]\ndefault = { requests = 1, window = '1s', max_wait = '5s' }\n";
    let calls = Arc::new(Mutex::new(Vec::new()));
    let release_queued = Arc::new(tokio::sync::Notify::new());
    let broker = application
        .provider_fixture(
            "fake",
            ProviderFixture::instance(ServiceProvider::new(
                agent_access_fake::fake_descriptor(),
                Arc::new(CountingFake {
                    calls: calls.clone(),
                    release_queued: release_queued.clone(),
                }),
            )),
        )
        .config_document(document)
        .start()
        .await
        .unwrap();
    let client = directory.join("client.toml");
    std::fs::write(
        &client,
        format!(
            "[service]\nurl={}\nrequest_timeout_ms=5000\n[identity]\ntoken_file={}\n",
            toml_string(broker.public_url()),
            toml_string(first.display()),
        ),
    )
    .unwrap();
    Fixture {
        broker,
        directory,
        client,
        token,
        calls,
        release_queued,
    }
}

fn cli(config: &Path, arguments: &[&str]) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(name);
        }
    }
    command
        .arg("--config")
        .arg(config)
        .args(arguments)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

async fn invoke(config: &Path, message: &str) -> std::process::Output {
    cli(
        config,
        &[
            "invoke",
            "fake.echo",
            "--input-json",
            &json!({"project":"TEST","message":message}).to_string(),
        ],
    )
    .output()
    .await
    .unwrap()
}

fn successful(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn detail(fixture: &Fixture) -> Value {
    let response = reqwest::Client::new()
        .get(format!("{}/v1/services/fake", fixture.broker.public_url()))
        .header("X-Agent-Access-Identity-Token", &fixture.token)
        .header(
            agent_access_provider::REQUEST_ID_HEADER,
            uuid::Uuid::new_v4().to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert!(status.is_success(), "detail returned {status}: {value}");
    value
}

fn assert_limits(value: &Value) {
    let limits = &value["limits"];
    assert_eq!(value["scopedMcpReady"], true);
    assert_eq!(limits["scope"], "principal_service");
    assert_eq!(limits["stateScope"], "broker_process");
    assert!(limits["instanceId"].is_string());
    assert!(limits["observedAt"].is_string());
    assert_eq!(limits["invocations"]["requests"], 1);
    assert_eq!(limits["invocations"]["windowSeconds"], 1);
    assert_eq!(limits["invocations"]["maxWaitSeconds"], 5);
    assert_eq!(limits["capacity"]["maxConcurrentRequests"], 1);
    assert_eq!(limits["capacity"]["maxConcurrentRequestsPerPrincipal"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_wait_cli_and_both_stdio_views_describe_while_shared_capacity_is_full() {
    let fixture = fixture().await;
    let mut aggregate = McpProcess::start(&fixture.client);
    let mut scoped = McpProcess::start_scoped(&fixture.client, "fake");
    aggregate.initialize().await;
    scoped.initialize().await;
    assert_eq!(
        successful(&invoke(&fixture.client, "first").await)["decision"],
        "allow"
    );
    let queued = cli(
        &fixture.client,
        &[
            "invoke",
            "fake.echo",
            "--input-json",
            r#"{"project":"TEST","message":"queued-cli"}"#,
        ],
    )
    .spawn()
    .unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let value = detail(&fixture).await;
            if value["limits"]["invocations"]["queuedRequests"] == 1 {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("CLI invocation never entered rate waiting");
    assert_limits(&observed);
    assert_eq!(
        observed["limits"]["capacity"]["principalInFlightRequests"],
        1
    );
    assert_eq!(&*fixture.calls.lock().unwrap(), &["first"]);
    let describe_args = json!({"name":"services_describe","arguments":{"service":"fake"}});
    // The independent detail pool also has capacity one, so exercise these
    // calls serially rather than deliberately saturating that control pool.
    let console = successful(
        &cli(&fixture.client, &["services", "describe", "fake"])
            .output()
            .await
            .unwrap(),
    );
    assert_limits(&console);
    assert_eq!(
        console["limits"]["capacity"]["principalInFlightRequests"],
        1
    );
    let aggregate_detail = aggregate.request("tools/call", describe_args.clone()).await;
    let scoped_detail = scoped.request("tools/call", describe_args).await;
    for response in [aggregate_detail, scoped_detail] {
        assert_eq!(response["result"]["isError"], false, "{response}");
        let description = &response["result"]["structuredContent"];
        assert_limits(description);
        assert_eq!(
            description["limits"]["capacity"]["principalInFlightRequests"],
            1
        );
        assert_eq!(
            description["limits"]["instanceId"],
            observed["limits"]["instanceId"]
        );
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(&text, description);
    }
    fixture.release_queued.notify_one();
    let completed = tokio::time::timeout(Duration::from_secs(6), queued.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(successful(&completed)["result"]["message"], "queued-cli");
    let mcp_result = aggregate.request("tools/call", json!({"name":"fake_echo","arguments":{"inputs":{"project":"TEST","message":"queued-stdio"}}})).await;
    assert_eq!(mcp_result["result"]["isError"], false, "{mcp_result}");
    assert_eq!(
        &*fixture.calls.lock().unwrap(),
        &["first", "queued-cli", "queued-stdio"]
    );
    aggregate.finish().await;
    scoped.finish().await;
    stop(fixture.broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_wait_short_cli_and_stdio_timeouts_report_uncertainty_without_automatic_retry() {
    let fixture = fixture().await;
    let short_config = fixture.directory.join("short-client.toml");
    let document = std::fs::read_to_string(&fixture.client)
        .unwrap()
        .replace("request_timeout_ms=5000", "request_timeout_ms=150");
    std::fs::write(&short_config, document).unwrap();
    let mut stdio = McpProcess::start(&short_config);
    stdio.initialize().await;
    successful(&invoke(&fixture.client, "first").await);
    let output = invoke(&short_config, "client-timeout").await;
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(
        message.contains("may still be queued or executing"),
        "{message}"
    );
    assert!(
        message.contains("do not resubmit a mutation without reconciling its outcome"),
        "{message}"
    );
    // A direct HTTP/1.1 peer close may be detected late. The timeout is not a
    // claim of cancellation; either detection removes the pending call or the
    // original call may dispatch once. No client retry may create another call.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if detail(&fixture).await["limits"]["invocations"]["queuedRequests"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    successful(&invoke(&fixture.client, "before-stdio-timeout").await);
    let response = stdio.request("tools/call", json!({"name":"fake_echo","arguments":{"inputs":{"project":"TEST","message":"stdio-timeout"}}})).await;
    assert_eq!(response["result"]["isError"], true, "{response}");
    let message = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        message.contains("may still be queued or executing"),
        "{message}"
    );
    assert!(
        message.contains("do not resubmit a mutation without reconciling its outcome"),
        "{message}"
    );
    stdio.finish().await;
    stop(fixture.broker).await;
    for timed_out in ["client-timeout", "stdio-timeout"] {
        assert!(
            fixture
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|message| message.as_str() == timed_out)
                .count()
                <= 1
        );
    }
}
