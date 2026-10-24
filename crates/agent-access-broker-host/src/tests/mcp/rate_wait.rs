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
