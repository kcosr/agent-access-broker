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
    let status = response.status();
    let envelope = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {envelope}");
    envelope
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
    // The accepted tickets project to 2s and 4s, while the next projects to
    // 6s. A 5s budget leaves real-timer scheduling slack for the second ticket
    // without admitting the third; exact boundaries use the scheduler clock.
    let fixture = fixture("2s", "5s", |_| {}).await;
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
    // Ignoring the queued reservations would report at most the first 2s
    // window. The tail must remain beyond that window while both are pending.
    assert!(
        retry_after >= 4,
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

async fn git_revocation_during_rate_wait(exhaust_auth_budget: bool) {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.limits.auth_requests_per_source_per_minute = 1;
        config.limits.request_body_timeout_ms = 10_000;
        config
            .limits
            .invocations
            .services
            .insert("gitlab_git".into(), waiting_limit(1, "2s", "5s"));
    })
    .await;
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    let pack = |request_id: &'static str, body: Body| {
        let app = fixture.app.clone();
        let basic = basic.clone();
        async move {
            gateway_request(GatewayRequestSpec {
                app,
                method: Method::POST,
                uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
                host: Some("git.example.test"),
                request_id: Some(request_id),
                authorization: Some(&basic),
                headers: &[(
                    CONTENT_TYPE.as_str(),
                    "application/x-git-upload-pack-request",
                )],
                body,
            })
            .await
        }
    };
    let seed = pack("git-revocation-seed", Body::from("0000")).await;
    assert_eq!(seed.status(), StatusCode::BAD_GATEWAY);
    drop(seed);
    let (body, polls) = counted_body("git-revocation-waiting");
    let waiting = tokio::spawn(pack("git-revocation-waiting", body));
    let public = fixture._broker.app();
    tokio::time::timeout(WAIT_BOUND, async {
        loop {
            let response = authed_json_request(
                public.clone(),
                Method::GET,
                "/v1/services/gitlab_git",
                "git-revocation-observe",
                "Authorization",
                format!("Bearer {}", fixture.agent_token),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            if response_json(response).await["limits"]["invocations"]["queuedRequests"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Git pack request must queue before revocation");
    let runtime = fixture._broker.runtime();
    let store = runtime.managed_store().unwrap();
    let tokens = store
        .list_broker_tokens_for_principal("gateway-user")
        .unwrap();
    assert_eq!(tokens.len(), 1);
    store
        .revoke_broker_token(&tokens[0].token_id, "test")
        .unwrap();
    if exhaust_auth_budget {
        let invalid = gateway_get(
            fixture.app.clone(),
            "/sip/service.git/info/refs?service=git-upload-pack",
            "git.example.test",
            "git-revocation-budget-seed",
            Some(&basic),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    }
    let response = tokio::time::timeout(WAIT_BOUND, waiting)
        .await
        .expect("queued Git revalidation must finish")
        .unwrap();
    let expected_reason = if exhaust_auth_budget {
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
        "rate_limited"
    } else {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE],
            r#"Basic realm="Agent Access Broker""#
        );
        "gateway_auth_invalid"
    };
    assert_eq!(response.headers()[REASON_CODE_HEADER], expected_reason);
    assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(response);
    let records = require_audit_request(
        &fixture.audit_path,
        "git-revocation-waiting",
        "gitlab_git",
        "repo.fetch",
    );
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["principal"], "anonymous");
    assert_eq!(record["reasonCode"], expected_reason);
    assert_eq!(record["providerAudit"]["admission"]["waited"], true);
    assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
    assert!(
        record["providerAudit"]["admission"]["waitedMilliseconds"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(record.get("matchedGrant").is_none());
    assert!(record.get("tokenId").is_none());

    // The failed post-grant identity check used the same source budget as an
    // ordinary Git authentication failure, even though it already paid quota.
    let next = gateway_get(
        fixture.app.clone(),
        "/sip/service.git/info/refs?service=git-upload-pack",
        "git.example.test",
        "git-revocation-next-invalid",
        Some(&basic),
    )
    .await;
    assert_eq!(next.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(next.headers()[REASON_CODE_HEADER], "rate_limited");
}

#[tokio::test]
async fn git_token_revoked_while_queued_keeps_identity_failure_contract_and_admission_audit() {
    git_revocation_during_rate_wait(false).await;
}

#[tokio::test]
async fn git_post_grant_auth_budget_rejection_keeps_anonymous_admission_audit() {
    git_revocation_during_rate_wait(true).await;
}

async fn disconnected_http1_body_wait(expect_continue: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body_budget = Duration::from_secs(3);
    let fixture = fixture("2s", "5s", |config| {
        config.limits.request_body_timeout_ms = body_budget.as_millis() as u64;
    })
    .await;
    complete(pending(&fixture.app, "socket-seed", ALICE).0).await;
    let request_id = if expect_continue {
        "socket-expect-continue"
    } else {
        "socket-unread-body"
    };
    let mut client = tokio::net::TcpStream::connect(fixture.broker.running().public_addr())
        .await
        .unwrap();
    let expect = if expect_continue {
        "Expect: 100-continue\r\n"
    } else {
        ""
    };
    let headers = format!(
        "POST /v1/invoke/fake/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {ALICE}\r\n{REQUEST_ID_HEADER}: {request_id}\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n{expect}\r\n"
    );
    let began = tokio::time::Instant::now();
    client.write_all(headers.as_bytes()).await.unwrap();
    if !expect_continue {
        // Hyper may buffer this prefix, but the rate waiter must not read it.
        // The declared body remains incomplete, so no provider can dispatch.
        client.write_all(b"{\"inputs\":").await.unwrap();
    }
    queued(&fixture.app, "Authorization", ALICE, 1).await;
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(*fixture.provider.calls.lock().unwrap(), ["socket-seed"]);
    if expect_continue {
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.read(&mut byte))
                .await
                .is_err(),
            "100 Continue must wait until admission starts reading the body"
        );
    }
    drop(client);
    let record = tokio::time::timeout_at(
        began + body_budget + Duration::from_secs(2),
        terminal_audit(&fixture, request_id),
    )
    .await
    .expect("disconnect detection or the original body deadline must bound request lifetime");
    let admission = &record["providerAudit"]["admission"];
    assert_eq!(admission["waited"], true);
    let after = queued(&fixture.app, "Authorization", ALICE, 0).await;
    match admission["outcome"].as_str().unwrap() {
        "cancelled" => {
            assert_eq!(record["reasonCode"], "operation_cancelled");
            assert_eq!(record["providerAudit"]["executionState"], "not_dispatched");
            assert_eq!(
                fixture.state.shared_invocations.state_for_test(),
                vec![("alice".into(), "fake".into(), 1)]
            );
        }
        "rejected" => {
            assert_eq!(record["reasonCode"], "rate_limited");
            assert_eq!(record["providerAudit"]["rateLimit"]["deadlineKind"], "body");
            assert_eq!(
                fixture.state.shared_invocations.state_for_test(),
                vec![("alice".into(), "fake".into(), 1)]
            );
        }
        "admitted" => {
            // An unread HTTP/1 body can hide a disconnect until after the
            // grant. That grant is retained, and the incomplete body fails
            // before scope resolution or provider execution.
            assert!(matches!(
                record["reasonCode"].as_str(),
                Some("body_malformed" | "operation_cancelled")
            ));
            assert_eq!(after["limits"]["invocations"]["countedRequests"], 1);
        }
        outcome => panic!("unexpected disconnect admission outcome: {outcome}"),
    }
    tokio::time::timeout_at(began + body_budget + Duration::from_secs(2), async {
        loop {
            let value = detail(&fixture.app, "Authorization", ALICE).await;
            if value["limits"]["capacity"]["principalInFlightRequests"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the disconnected request must release its permits within the body deadline bound");
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(*fixture.provider.calls.lock().unwrap(), ["socket-seed"]);
    assert_eq!(
        read_audit_records(&fixture.audit_path)
            .into_iter()
            .filter(|record| record["agentRequestId"] == request_id)
            .count(),
        1
    );
    eprintln!(
        "{request_id}: admission={}, reason={}, elapsed_ms={}",
        admission["outcome"],
        record["reasonCode"],
        began.elapsed().as_millis()
    );
}

#[tokio::test]
async fn http1_disconnect_with_unread_declared_body_has_bounded_admission_lifetime() {
    disconnected_http1_body_wait(false).await;
}

#[tokio::test]
async fn http1_disconnect_with_expect_continue_has_bounded_admission_lifetime() {
    disconnected_http1_body_wait(true).await;
}

fn assert_initial_settings_deadline_audit(record: &Value, reason: &str) {
    assert_eq!(record["reasonCode"], reason);
    assert_eq!(record["providerAudit"]["executionState"], "not_dispatched");
    assert_eq!(record["providerAudit"]["retrySafe"], true);
    assert_eq!(record["providerAudit"]["deadlineKind"], "body");
    assert_eq!(
        record["providerAudit"]["admission"],
        json!({"waited": false, "waitedMilliseconds": 0, "outcome": "rejected"})
    );
    assert!(record.get("matchedGrant").is_none());
}

#[tokio::test]
async fn initial_settings_deadline_keeps_rest_body_response_and_proves_no_dispatch() {
    let fixture = fixture("1s", "3s", |config| {
        config.limits.request_body_timeout_ms = 250;
    })
    .await;
    // A real managed-update fence prevents settings resolution until after
    // the original body budget. No rate history or queued ticket is needed.
    let write = fixture
        .state
        .shared_invocations
        .begin_update("alice", "fake");
    let (waiting, polls) = pending(&fixture.app, "initial-settings-rest", ALICE);
    let response = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .expect("initial settings resolution must respect the original body deadline")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(RETRY_AFTER));
    let value = response_json(response).await;
    assert_eq!(value["service"], "fake");
    assert_eq!(value["action"], "echo");
    assert_eq!(value["reasonCode"], "body_malformed");
    assert_eq!(
        value["error"]["message"],
        "request body receive deadline exceeded"
    );
    assert_eq!(
        value["result"],
        json!({
            "executionState": "not_dispatched", "retrySafe": true, "deadlineKind": "body"
        })
    );
    assert_initial_settings_deadline_audit(
        &terminal_audit(&fixture, "initial-settings-rest").await,
        "body_malformed",
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.provider.calls.lock().unwrap().is_empty());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    write.finish(false);
    let observed = queued(&fixture.app, "Authorization", ALICE, 0).await;
    assert_eq!(observed["limits"]["invocations"]["countedRequests"], 0);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}

#[tokio::test]
async fn initial_settings_deadline_keeps_git_body_response_and_proves_no_dispatch() {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config.limits.request_body_timeout_ms = 250;
        config
            .limits
            .invocations
            .services
            .insert("gitlab_git".into(), waiting_limit(1, "1s", "3s"));
    })
    .await;
    let state = fixture._broker.state();
    let write = state
        .shared_invocations
        .begin_update("gateway-user", "gitlab_git");
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    let (body, polls) = counted_body("initial-settings-git");
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        gateway_request(GatewayRequestSpec {
            app: fixture.app.clone(),
            method: Method::POST,
            uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
            host: Some("git.example.test"),
            request_id: Some("initial-settings-git"),
            authorization: Some(&basic),
            headers: &[(
                CONTENT_TYPE.as_str(),
                "application/x-git-upload-pack-request",
            )],
            body,
        }),
    )
    .await
    .expect("Git initial settings resolution must respect the original body deadline");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_request_body_denied"
    );
    assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
    assert!(
        response.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    assert!(!response.headers().contains_key(RETRY_AFTER));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
        "gateway request body read timed out\n"
    );
    let records = require_audit_request(
        &fixture.audit_path,
        "initial-settings-git",
        "gitlab_git",
        "repo.fetch",
    );
    assert_eq!(records.len(), 1);
    assert_initial_settings_deadline_audit(&records[0], "gateway_request_body_denied");
    assert_eq!(records[0]["principal"], "gateway-user");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(state.shared_invocations.key_count(), 0);
    write.finish(false);
    tokio::task::yield_now().await;
    assert_eq!(state.shared_invocations.key_count(), 0);
    assert_eq!(read_audit_records(&fixture.audit_path).len(), 1);
}
