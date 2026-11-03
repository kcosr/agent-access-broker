//! Native MCP keeps transport, rate admission, and operation ownership distinct.
use super::*;

async fn waiting_fixture(
    provider: Arc<ControlledProvider>,
    configure: impl FnOnce(&mut BrokerConfig),
) -> Fixture {
    controlled_fixture_with(provider, |config| {
        config.limits.invocations.services.insert(
            "fake".into(),
            agent_access_core::InvocationLimitConfig {
                requests: 1,
                window: "1s".into(),
                max_wait: Some("3s".into()),
            },
        );
        configure(config);
    })
    .await
}

async fn seed(fixture: &Fixture, provider: &ControlledProvider, session: &str) {
    provider.release.add_permits(1);
    let response = start_controlled_call(fixture, session, 201).await;
    provider.wait_entered().await;
    assert_eq!(structured(&rpc_body(response).await)["decision"], "allow");
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
}

async fn queue_size(fixture: &Fixture, session: &str, expected: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut id = 300;
        loop {
            let described = fixture
                .call(session, id, "services_describe", json!({"service":"fake"}))
                .await;
            let detail = structured(&described);
            if detail["limits"]["invocations"]["queuedRequests"] == expected {
                return detail.clone();
            }
            id += 1;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("MCP admission did not reach the expected queue state")
}

async fn terminal_audit(fixture: &Fixture, reason: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let records = read_audit_records(&fixture.audit_path);
            if let Some(record) = records.iter().find(|record| record["reasonCode"] == reason) {
                assert_eq!(records.len(), 2, "one terminal record per native call");
                return record.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("MCP pending admission must finalize its terminal audit")
}

fn assert_cancelled(record: &Value) {
    assert_eq!(record["providerAudit"]["executionState"], "not_dispatched");
    assert_eq!(record["providerAudit"]["retrySafe"], true);
    assert_eq!(record["providerAudit"]["admission"]["waited"], true);
    assert_eq!(record["providerAudit"]["admission"]["outcome"], "cancelled");
}

#[tokio::test]
async fn native_mcp_shares_rest_service_capacity_and_reports_the_callers_joint_eligibility() {
    let fixture = Fixture::new(|config| {
        let peer_tokens = config.identity.sources[0].principals[0]
            .token_refs
            .split_off(1);
        config.identity.sources[0]
            .principals
            .push(StaticPrincipalConfig {
                principal: "mcp-peer".into(),
                token_refs: peer_tokens,
            });
        config.policy.grants[0]
            .subjects
            .push("user:mcp-peer".into());
        config.limits.invocations.aggregate.insert(
            "fake".into(),
            crate::tests::aggregate_limits::aggregate(1, "1m"),
        );
    })
    .await;
    let seeded = invoke_fake_project_with_token(
        fixture.app.clone(),
        "mcp-shared-rest-seed",
        TOKEN_A,
        "TEST",
    )
    .await;
    assert_eq!(seeded.status(), StatusCode::OK);
    drop(seeded);
    let session = fixture.initialize_version(TOKEN_B, VERSION).await;
    let native = agent_access_core::mcp::tool_name("fake", "echo");
    let response = fixture.send(request(Method::POST, Some(TOKEN_B), Some(&session), Some(json!({
        "jsonrpc":"2.0","id":991,"method":"tools/call",
        "params":{"name":native,"arguments":{"inputs":{"project":"TEST","message":"shared MCP refused"}}}
    })))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let limited = rpc_body(response).await;
    assert_eq!(limited["result"]["isError"], true);
    assert!(limited.get("error").is_none(), "{limited}");
    // Rate refusals carry the complete human message as MCP text; their
    // structured content still carries the ordinary admission envelope.
    let envelope = &limited["result"]["structuredContent"];
    assert_eq!(
        limited["result"]["content"][0]["text"],
        envelope["error"]["message"]
    );
    assert_eq!(envelope["reasonCode"], "rate_limited");
    assert_eq!(envelope["service"], "broker");
    assert_eq!(envelope["action"], "request.admit");
    assert!(envelope.get("result").is_none());
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Shared rate limit")
    );

    let response = fixture
        .send(request(
            Method::POST,
            Some(TOKEN_B),
            Some(&session),
            Some(json!({
                "jsonrpc":"2.0","id":992,"method":"tools/call",
                "params":{"name":"services_describe","arguments":{"service":"fake"}}
            })),
        ))
        .await;
    let described = rpc_body(response).await;
    let detail = structured(&described);
    assert_eq!(
        detail["limits"]["aggregate"],
        json!({"requests":1,"windowSeconds":60})
    );
    assert_eq!(detail["limits"]["invocations"]["countedRequests"], 0);
    assert_eq!(detail["limits"]["invocations"]["blockingScope"], "service");
    assert_eq!(detail["limits"]["invocations"]["availableImmediately"], 0);
    let records = read_audit_records(&fixture.audit_path);
    let limited = records
        .iter()
        .find(|record| record["reasonCode"] == "rate_limited")
        .unwrap();
    assert_eq!(limited["principal"], "mcp-peer");
    assert_eq!(
        limited["providerAudit"]["rateLimit"]["limitScope"],
        "service"
    );
}

#[tokio::test]
async fn queued_native_cancellation_releases_permits_without_charge_or_execution() {
    let provider = ControlledProvider::new(false);
    let fixture = waiting_fixture(provider.clone(), |_| {}).await;
    let session = fixture.initialize().await;
    seed(&fixture, &provider, &session).await;
    let response = start_controlled_call(&fixture, &session, 202).await;
    let detail = queue_size(&fixture, &session, 1).await;
    assert_eq!(detail["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(detail["limits"]["capacity"]["principalInFlightRequests"], 1);
    cancel_controlled_call(&fixture, &session, 202).await;
    assert_cancelled(&terminal_audit(&fixture, "operation_cancelled").await);
    drop(response);
    let detail = queue_size(&fixture, &session, 0).await;
    assert_eq!(detail["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .state
            .shared_ingress
            .try_global_concurrency(1)
            .is_ok()
    );
}

#[tokio::test]
async fn dropping_queued_native_sse_cancels_admission_without_provider_execution() {
    let provider = ControlledProvider::new(false);
    let fixture = waiting_fixture(provider.clone(), |_| {}).await;
    let session = fixture.initialize().await;
    seed(&fixture, &provider, &session).await;
    let response = start_controlled_call(&fixture, &session, 203).await;
    assert!(
        response.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    queue_size(&fixture, &session, 1).await;
    // Opening SSE preserved the owner above; dropping it ends only pending work.
    drop(response);
    assert_cancelled(&terminal_audit(&fixture, "operation_cancelled").await);
    let detail = queue_size(&fixture, &session, 0).await;
    assert_eq!(detail["limits"]["invocations"]["countedRequests"], 1);
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .state
            .shared_ingress
            .try_global_concurrency(1)
            .is_ok()
    );
}

#[tokio::test]
async fn native_rate_wait_and_execution_share_one_absolute_operation_deadline() {
    let provider = ControlledProvider::new(false);
    let fixture = waiting_fixture(provider.clone(), |config| {
        config.mcp.protocol_timeout_ms = 500;
        config.mcp.operation_timeout_ms = 1500;
    })
    .await;
    let session = fixture.initialize().await;
    seed(&fixture, &provider, &session).await;
    let response = start_controlled_call(&fixture, &session, 204).await;
    queue_size(&fixture, &session, 1).await;
    // The rate window outlasts the protocol timeout, yet the operation proceeds.
    provider.wait_entered().await;
    assert_eq!(provider.executions.load(Ordering::SeqCst), 2);
    // About one second was already spent waiting. A fresh 1500ms execution
    // timer would fail this bound; the original timer leaves about 500ms.
    let result = tokio::time::timeout(Duration::from_millis(1100), rpc_body(response))
        .await
        .expect("rate waiting must consume the original operation deadline");
    assert_eq!(
        result["result"]["structuredContent"]["reasonCode"],
        "operation_timeout"
    );
    let record = terminal_audit(&fixture, "operation_timeout").await;
    assert_eq!(record["providerAudit"]["executionState"], "unknown");
    assert_eq!(record["providerAudit"]["admission"]["waited"], true);
    assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
    assert!(
        record["providerAudit"]["admission"]["waitedMilliseconds"]
            .as_u64()
            .unwrap()
            > 500
    );
}

#[tokio::test]
async fn initial_settings_deadline_returns_mcp_timeout_with_proven_no_dispatch() {
    let provider = ControlledProvider::new(false);
    let fixture = waiting_fixture(provider.clone(), |config| {
        config.mcp.operation_timeout_ms = 250;
        config.mcp.protocol_timeout_ms = 5_000;
    })
    .await;
    let session = fixture.initialize().await;
    let write = fixture
        .state
        .shared_invocations
        .begin_update("mcp-user", "fake");
    let response = start_controlled_call(&fixture, &session, 205).await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = tokio::time::timeout(Duration::from_secs(3), rpc_body(response))
        .await
        .expect("initial settings resolution must respect the original MCP operation deadline");
    assert_eq!(result["result"]["isError"], true);
    let envelope = structured(&result);
    assert_eq!(envelope["reasonCode"], "operation_timeout");
    assert_eq!(
        envelope["result"],
        json!({
            "executionState": "not_dispatched", "retrySafe": true, "deadlineKind": "operation"
        })
    );
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["reasonCode"], "operation_timeout");
    assert_eq!(record["providerAudit"]["executionState"], "not_dispatched");
    assert_eq!(record["providerAudit"]["retrySafe"], true);
    assert_eq!(record["providerAudit"]["deadlineKind"], "operation");
    assert_eq!(
        record["providerAudit"]["admission"],
        json!({
            "waited": false, "waitedMilliseconds": 0, "outcome": "rejected"
        })
    );
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    write.finish(false);
    let observed = queue_size(&fixture, &session, 0).await;
    assert_eq!(observed["limits"]["invocations"]["countedRequests"], 0);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}
