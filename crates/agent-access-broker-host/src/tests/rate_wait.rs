//! Rate waiting through the production router, including body ownership,
//! independently admitted discovery, managed updates and reload finalization.
//! Exact timer boundaries are tested in the scheduler; these tests use real
//! short windows and observe queue transitions before asserting transport work.
use super::*;
use agent_access_core::{InvocationLimitConfig, InvocationLimitsConfig};
use std::sync::Mutex;

const ALICE: &str = "rate-wait-alice";
const ALICE_OTHER_TOKEN: &str = "rate-wait-alice-other";
const BOB: &str = "rate-wait-bob";
const WAIT_BOUND: Duration = Duration::from_secs(10);

#[derive(Default)]
struct RecordingProvider {
    scope_resolutions: AtomicUsize,
    calls: Mutex<Vec<String>>,
}

impl agent_access_provider::test_support::DescribedProvider for RecordingProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        // Keep the fake_project resource type and read classification used by
        // fake_config's grants; only execution is replaced by this recorder.
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for RecordingProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(ScopeResolution::resources(ResourceScopes::from([(
            "project".into(),
            vec![request.inputs()["project"].as_str().unwrap().to_owned()],
        )])))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let message = request.inputs()["message"].as_str().unwrap().to_owned();
        self.calls.lock().unwrap().push(message.clone());
        Ok(ProviderResult::new(json!({"message": message})))
    }
}

struct WaitFixture {
    broker: TestBroker,
    app: Router,
    state: Arc<ReloadableState>,
    provider: Arc<RecordingProvider>,
    audit_path: PathBuf,
    _directory: tempfile::TempDir,
}

fn waiting_limit(requests: u64, window: &str, max_wait: &str) -> InvocationLimitConfig {
    InvocationLimitConfig {
        requests,
        window: window.into(),
        max_wait: Some(max_wait.into()),
    }
}

async fn fixture(
    window: &str,
    max_wait: &str,
    configure: impl FnOnce(&mut BrokerConfig),
) -> WaitFixture {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let audit_path = directory.path().join("audit.jsonl");
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
    config.limits.request_body_timeout_ms = 30_000;
    config
        .limits
        .invocations
        .services
        .insert("fake".into(), waiting_limit(1, window, max_wait));
    let mut principals = Vec::new();
    for (principal, tokens) in [
        ("alice", vec![ALICE, ALICE_OTHER_TOKEN]),
        ("bob", vec![BOB]),
    ] {
        let token_refs = tokens
            .into_iter()
            .enumerate()
            .map(|(index, token)| {
                let path = directory.path().join(format!("{principal}-{index}"));
                std::fs::write(&path, token).unwrap();
                format!("file:{}", path.display())
            })
            .collect();
        principals.push(StaticPrincipalConfig {
            principal: principal.into(),
            token_refs,
        });
    }
    config.identity.mode = "required".into();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "rate-wait-fixture".into(),
        kind: "static_principals".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals,
    }];
    config.policy.grants[0].subjects = vec!["user:alice".into(), "user:bob".into()];
    let upstream_token = directory.path().join("provider-token");
    std::fs::write(&upstream_token, "synthetic-provider-token").unwrap();
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", upstream_token.display()));
    configure(&mut config);
    let provider = Arc::new(RecordingProvider::default());
    let broker = TestBroker::start_with_providers(&config, [provider.clone()]).await;
    WaitFixture {
        app: broker.app(),
        state: broker.state(),
        broker,
        provider,
        audit_path,
        _directory: directory,
    }
}

fn invoke_request(request_id: &str, token: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/fake/echo")
        .extension(ConnectInfo(
            "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, request_id)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

fn counted_body(message: &str) -> (Body, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    let mut payload = Some(Bytes::from(
        json!({
            "inputs": {"project": "TEST", "message": message}
        })
        .to_string(),
    ));
    let body = Body::from_stream(stream::poll_fn(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(payload.take().map(Ok::<_, std::io::Error>))
    }));
    (body, polls)
}

type Call = tokio::task::JoinHandle<Result<axum::response::Response, std::convert::Infallible>>;

fn pending(app: &Router, request_id: &str, token: &str) -> (Call, Arc<AtomicUsize>) {
    let (body, polls) = counted_body(request_id);
    (
        tokio::spawn(app.clone().oneshot(invoke_request(request_id, token, body))),
        polls,
    )
}

async fn complete(call: Call) -> Value {
    let response = tokio::time::timeout(WAIT_BOUND, call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

async fn detail_response(app: &Router, header: &str, token: &str) -> axum::response::Response {
    authed_json_request(
        app.clone(),
        Method::GET,
        "/v1/services/fake",
        "rate-wait-describe",
        header,
        format!("Bearer {token}"),
        None,
    )
    .await
}

async fn detail(app: &Router, header: &str, token: &str) -> Value {
    let response = detail_response(app, header, token).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    response_json(response).await
}

async fn queued(app: &Router, header: &str, token: &str, expected: u64) -> Value {
    tokio::time::timeout(WAIT_BOUND, async {
        loop {
            let value = detail(app, header, token).await;
            if value["limits"]["invocations"]["queuedRequests"] == expected {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("queue did not reach {expected} pending requests"))
}

async fn terminal_audit(fixture: &WaitFixture, request_id: &str) -> Value {
    tokio::time::timeout(WAIT_BOUND, async {
        loop {
            let records = read_audit_records(&fixture.audit_path)
                .into_iter()
                .filter(|record| record["agentRequestId"] == request_id)
                .collect::<Vec<_>>();
            if !records.is_empty() {
                assert_eq!(records.len(), 1, "one terminal record per request");
                return records.into_iter().next().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pending admission must finalize its audit")
}

#[tokio::test]
async fn rest_waits_fifo_across_tokens_without_reading_bodies_or_preparing_providers() {
    let fixture = fixture("1s", "2s", |_| {}).await;
    complete(pending(&fixture.app, "fifo-seed", ALICE).0).await;
    let (first, first_polls) = pending(&fixture.app, "fifo-first", ALICE_OTHER_TOKEN);
    queued(&fixture.app, "Authorization", ALICE, 1).await;
    let (second, second_polls) = pending(&fixture.app, "fifo-second", ALICE);
    let observed = queued(&fixture.app, "Authorization", ALICE_OTHER_TOKEN, 2).await;
    assert_eq!(observed["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(observed["limits"]["invocations"]["availableImmediately"], 0);
    assert_eq!(first_polls.load(Ordering::SeqCst), 0);
    assert_eq!(second_polls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(*fixture.provider.calls.lock().unwrap(), ["fifo-seed"]);

    // The rejection forecasts after both accepted tickets and never reads its body.
    let (body, rejected_polls) = counted_body("fifo-rejected");
    let rejected = fixture
        .app
        .clone()
        .oneshot(invoke_request("fifo-rejected", ALICE, body))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = rejected.headers()[RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        retry_after >= 2,
        "tail projection must honor existing reservations"
    );
    let rejected = response_json(rejected).await;
    assert_eq!(rejected["reasonCode"], "rate_limited");
    let message = rejected["error"]["message"].as_str().unwrap();
    assert!(message.contains("not queued or executed"), "{message}");
    assert!(message.contains("pending"), "{message}");
    assert!(message.contains("Do not resubmit"), "{message}");
    assert_eq!(rejected_polls.load(Ordering::SeqCst), 0);
    assert!(!first.is_finished());
    assert!(!second.is_finished());

    // A different principal progresses while Alice's FIFO remains pending.
    complete(pending(&fixture.app, "fifo-bob", BOB).0).await;
    complete(first).await;
    complete(second).await;
    assert!(first_polls.load(Ordering::SeqCst) > 0);
    assert!(second_polls.load(Ordering::SeqCst) > 0);
    assert_eq!(
        *fixture.provider.calls.lock().unwrap(),
        ["fifo-seed", "fifo-bob", "fifo-first", "fifo-second"]
    );
    for id in ["fifo-first", "fifo-second"] {
        assert_eq!(terminal_audit(&fixture, id).await["decision"], "allow");
    }
}

#[tokio::test]
async fn dropping_queued_rest_request_removes_it_without_body_dispatch_or_charge() {
    let fixture = fixture("1s", "2s", |_| {}).await;
    complete(pending(&fixture.app, "cancel-seed", ALICE).0).await;
    let (abandoned, abandoned_polls) = pending(&fixture.app, "cancel-abandoned", ALICE);
    queued(&fixture.app, "Authorization", ALICE, 1).await;
    let (successor, _) = pending(&fixture.app, "cancel-successor", ALICE_OTHER_TOKEN);
    queued(&fixture.app, "Authorization", ALICE, 2).await;
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    let observed = queued(&fixture.app, "Authorization", ALICE, 1).await;
    assert_eq!(observed["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(abandoned_polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        terminal_audit(&fixture, "cancel-abandoned").await["reasonCode"],
        "operation_cancelled"
    );
    complete(successor).await;
    assert_eq!(
        *fixture.provider.calls.lock().unwrap(),
        ["cancel-seed", "cancel-successor"]
    );
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(
        terminal_audit(&fixture, "cancel-abandoned").await["reasonCode"],
        "operation_cancelled"
    );
}

#[tokio::test]
async fn live_detail_is_pure_and_has_bounded_capacity_when_invocation_slots_are_full() {
    let fixture = fixture("1s", "3s", |config| {
        config.limits.max_concurrent_requests = 1;
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    for _ in 0..3 {
        let empty = detail(&fixture.app, "Authorization", ALICE).await;
        assert_eq!(empty["limits"]["scope"], "principal_service");
        assert_eq!(empty["limits"]["stateScope"], "broker_process");
        assert_eq!(empty["limits"]["invocations"]["countedRequests"], 0);
        assert_eq!(empty["limits"]["capacity"]["principalInFlightRequests"], 0);
    }
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 0);
    complete(pending(&fixture.app, "capacity-seed", ALICE).0).await;
    let (waiting, _) = pending(&fixture.app, "capacity-waiting", ALICE);
    let observed = queued(&fixture.app, "Authorization", ALICE, 1).await;
    assert_eq!(
        observed["limits"]["capacity"]["principalInFlightRequests"],
        1
    );
    let history = fixture.state.shared_invocations.state_for_test();
    for _ in 0..3 {
        detail(&fixture.app, "Authorization", ALICE).await;
    }
    assert_eq!(fixture.state.shared_invocations.state_for_test(), history);
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 1);

    for path in ["/v1/services", "/v1/services/fake/actions"] {
        let denied = authed_json_request(
            fixture.app.clone(),
            Method::GET,
            path,
            "capacity-lookalike",
            "Authorization",
            format!("Bearer {ALICE}"),
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert!(denied.headers().get(RETRY_AFTER).is_none());
        assert_eq!(
            response_json(denied).await["reasonCode"],
            "concurrency_limited"
        );
    }

    // Detail's delivery lease is independent, bounded, and released by body drop.
    let held_detail = detail_response(&fixture.app, "Authorization", ALICE).await;
    assert_eq!(held_detail.status(), StatusCode::OK);
    let denied = detail_response(&fixture.app, "Authorization", ALICE).await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(denied.headers().get(RETRY_AFTER).is_none());
    let denied = response_json(denied).await;
    assert_eq!(denied["reasonCode"], "concurrency_limited");
    assert!(
        denied["error"]["message"]
            .as_str()
            .unwrap()
            .contains("service-detail")
    );
    drop(held_detail);
    detail(&fixture.app, "Authorization", ALICE).await;
    let head = authed_json_request(
        fixture.app.clone(),
        Method::HEAD,
        "/v1/services/fake",
        "capacity-detail-head",
        "Authorization",
        format!("Bearer {ALICE}"),
        None,
    )
    .await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()[CACHE_CONTROL], "no-store");
    assert!(
        axum::body::to_bytes(head.into_body(), 4096)
            .await
            .unwrap()
            .is_empty()
    );
    detail(&fixture.app, "Authorization", ALICE).await;
    complete(waiting).await;
}

#[tokio::test]
async fn insufficient_body_deadline_refuses_without_polling_or_spending_another_rate_unit() {
    let fixture = fixture("10s", "20s", |config| {
        config.limits.request_body_timeout_ms = 500;
    })
    .await;
    complete(pending(&fixture.app, "deadline-seed", ALICE).0).await;
    let (waiting, polls) = pending(&fixture.app, "deadline-waiting", ALICE);
    let response = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .expect("body budget cannot accommodate the ten-second opportunity")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(RETRY_AFTER));
    let value = response_json(response).await;
    assert_eq!(value["service"], "broker");
    assert_eq!(value["action"], "request.admit");
    assert_eq!(value["reasonCode"], "rate_limited");
    assert!(value.get("result").is_none());
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains("body deadline"), "{message}");
    assert!(message.contains("not queued or executed"), "{message}");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(*fixture.provider.calls.lock().unwrap(), ["deadline-seed"]);
    let after = queued(&fixture.app, "Authorization", ALICE, 0).await;
    assert_eq!(after["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(
        terminal_audit(&fixture, "deadline-waiting").await["reasonCode"],
        "rate_limited"
    );
}

#[tokio::test]
async fn runtime_publication_cancels_pending_requests_once_and_preserves_history() {
    let fixture = fixture("10s", "20s", |_| {}).await;
    complete(pending(&fixture.app, "reload-seed", ALICE).0).await;
    let (waiting, polls) = pending(&fixture.app, "reload-waiting", ALICE);
    let before = queued(&fixture.app, "Authorization", ALICE, 1).await;
    let history = fixture.state.shared_invocations.state_for_test();
    let mut config = fixture.state.current().runtime.config().clone();
    config.limits.max_concurrent_requests += 1;
    fixture.broker.reload_config(&config).await;
    let response = tokio::time::timeout(WAIT_BOUND, waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "operation_cancelled", "{value}");
    assert_eq!(value["service"], "fake");
    assert_eq!(value["action"], "echo");
    assert_eq!(
        value["result"]["executionState"], "not_dispatched",
        "{value}"
    );
    assert_eq!(value["result"]["retrySafe"], true, "{value}");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(*fixture.provider.calls.lock().unwrap(), ["reload-seed"]);
    assert_eq!(fixture.state.shared_invocations.state_for_test(), history);
    let after = queued(&fixture.app, "Authorization", ALICE, 0).await;
    assert_eq!(
        before["limits"]["instanceId"],
        after["limits"]["instanceId"]
    );
    assert_eq!(
        terminal_audit(&fixture, "reload-waiting").await["reasonCode"],
        "operation_cancelled"
    );
}

#[tokio::test]
async fn managed_limit_change_wakes_queued_requests_without_waiting_for_window_expiry() {
    let fixture = browser_rate_fixture(LimitsConfig {
        invocations: InvocationLimitsConfig {
            services: BTreeMap::from([("fake".into(), waiting_limit(1, "10s", "20s"))]),
            ..Default::default()
        },
        ..test_limits()
    })
    .await;
    let response = fixture
        .token_invoke("managed-wait-seed", &fixture.agent_tokens[0])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    let app = fixture.app.clone();
    let token = fixture.agent_tokens[1].clone();
    let waiting = tokio::spawn(async move {
        authed_json_request(
            app,
            Method::POST,
            "/v1/invoke/fake/echo",
            "managed-wait-queued",
            "X-Agent-Token",
            format!("Bearer {token}"),
            Some(r#"{"inputs":{"project":"TEST","message":"managed"}}"#),
        )
        .await
    });
    let before = queued(&fixture.app, "X-Agent-Token", &fixture.agent_tokens[0], 1).await;
    assert_eq!(before["limits"]["invocations"]["countedRequests"], 1);
    let invalid = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/service-limits/fake",
        "managed-wait-invalid",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some(r#"{"requests":0,"windowSeconds":10}"#),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    drop(invalid);
    let unchanged = queued(&fixture.app, "X-Agent-Token", &fixture.agent_tokens[0], 1).await;
    assert_eq!(unchanged["limits"]["invocations"]["requests"], 1);
    assert_eq!(unchanged["limits"]["invocations"]["countedRequests"], 1);
    let response = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/principals/alice/service-limits/fake",
        "managed-wait-raise",
        "X-Agent-Token",
        format!("Bearer {}", fixture.admin_token),
        Some(r#"{"requests":2,"windowSeconds":10}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    let response = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .expect("managed update must wake the queue before the ten-second window expires")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    let after = detail(&fixture.app, "X-Agent-Token", &fixture.agent_tokens[0]).await;
    assert_eq!(after["limits"]["invocations"]["requests"], 2);
    assert_eq!(after["limits"]["invocations"]["maxWaitSeconds"], 20);
    assert_eq!(after["limits"]["invocations"]["countedRequests"], 2);
    assert_eq!(after["limits"]["invocations"]["queuedRequests"], 0);
    let records = require_audit_request(&fixture.audit_path, "managed-wait-queued", "fake", "echo");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "allow");
}

#[tokio::test]
async fn anonymous_detail_omits_live_limits_without_allocating_rate_state() {
    let fixture = fixture("1s", "2s", |config| {
        config.identity.mode = "anonymous".into();
        config.identity.sources.clear();
        config.policy.grants[0].subjects = vec!["group:anonymous".into()];
    })
    .await;
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/services/fake")
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "anonymous-live-limits")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_json(response).await.get("limits").is_none());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.provider.calls.lock().unwrap().is_empty());
}
