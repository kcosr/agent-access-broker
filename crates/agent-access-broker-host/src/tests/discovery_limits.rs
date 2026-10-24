//! Live service detail is caller-only and remains independently bounded.
use super::invocation_limits::{ALICE, BOB, LimitFixture, limit_fixture, set_fake_limit};
use super::*;

async fn detail(fixture: &LimitFixture, token: &str) -> axum::response::Response {
    authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services/fake",
        "live-detail",
        "Authorization",
        format!("Bearer {token}"),
        None,
    )
    .await
}

struct ReleaseContextWorker(Arc<crate::state::McpBlockingBarrier>);

impl Drop for ReleaseContextWorker {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn live_detail_is_private_nonmutating_and_separate_from_static_discovery() {
    let fixture = limit_fixture(|config| set_fake_limit(config, 2, "10s")).await;
    let first = detail(&fixture, ALICE).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first = response_json(first).await;
    let limits = &first["limits"];
    assert_eq!(limits["scope"], "principal_service");
    assert_eq!(limits["stateScope"], "broker_process");
    assert!(
        limits["instanceId"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(limits["invocations"]["requests"], 2);
    assert_eq!(limits["invocations"]["windowSeconds"], 10);
    assert_eq!(limits["invocations"]["countedRequests"], 0);
    assert_eq!(limits["invocations"]["queuedRequests"], 0);
    assert_eq!(limits["invocations"]["availableImmediately"], 2);
    assert_eq!(limits["invocations"]["nextAdmissionAfterSeconds"], 0);
    assert_eq!(limits["capacity"]["principalInFlightRequests"], 0);
    assert!(limits["capacity"].get("globalInFlightRequests").is_none());
    assert!(limits.get("principal").is_none());
    assert!(limits["invocations"].get("resetAt").is_none());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    let invoked = fixture.invoke("live-detail-invoke", ALICE).await;
    assert_eq!(invoked.status(), StatusCode::OK);
    let _ = response_json(invoked).await;
    for _ in 0..3 {
        let own = response_json(detail(&fixture, ALICE).await).await;
        assert_eq!(own["limits"]["invocations"]["countedRequests"], 1);
        assert_eq!(own["limits"]["invocations"]["availableImmediately"], 1);
        assert_eq!(own["limits"]["instanceId"], limits["instanceId"]);
        let other = response_json(detail(&fixture, BOB).await).await;
        assert_eq!(other["limits"]["invocations"]["countedRequests"], 0);
        assert_eq!(other["limits"]["invocations"]["availableImmediately"], 2);
    }
    assert_eq!(fixture.state.shared_invocations.key_count(), 1);
    let list = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services",
        "static-list",
        "Authorization",
        format!("Bearer {ALICE}"),
        None,
    )
    .await;
    let list = response_json(list).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|service| service.get("limits").is_none())
    );
    fixture.publish(2, |_| {}).await;
    let after_reload = response_json(detail(&fixture, ALICE).await).await;
    assert_eq!(after_reload["limits"]["instanceId"], limits["instanceId"]);
    assert_eq!(after_reload["limits"]["invocations"]["countedRequests"], 1);
}

#[tokio::test]
async fn live_detail_principal_control_capacity_is_separate_and_released() {
    let fixture = limit_fixture(|config| {
        config.limits.max_concurrent_requests = 2;
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    let permit = fixture
        .state
        .service_detail_ingress
        .try_service_detail_principal_concurrency("alice", 1)
        .unwrap();
    let rejected = detail(&fixture, ALICE).await;
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    let rejected = response_json(rejected).await;
    assert_eq!(rejected["reasonCode"], "concurrency_limited");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("service-detail")
    );
    assert_eq!(detail(&fixture, BOB).await.status(), StatusCode::OK);
    drop(permit);
    assert_eq!(detail(&fixture, ALICE).await.status(), StatusCode::OK);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}

#[tokio::test]
async fn live_detail_deadline_keeps_noncancelable_work_bounded_and_uncharged() {
    let fixture = limit_fixture(|config| {
        config.limits.request_body_timeout_ms = 150;
        config.limits.max_concurrent_requests = 1;
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    let barrier = Arc::new(crate::state::McpAdmissionBarrier {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    *fixture.state.service_detail_limit_barrier.lock().unwrap() = Some(barrier.clone());
    let app = fixture.app.clone();
    let request = tokio::spawn(async move {
        authed_json_request(
            app,
            Method::GET,
            "/v1/services/fake",
            "detail-deadline",
            "Authorization",
            format!("Bearer {ALICE}"),
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), barrier.reached.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = response_json(response).await;
    assert_eq!(value["decision"], "error");
    assert_eq!(
        value["error"]["message"],
        "local discovery could not complete"
    );
    assert!(value.get("reasonCode").is_none());
    assert!(value.get("result").is_none());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    assert_eq!(
        fixture
            .state
            .service_detail_ingress
            .principal_in_flight_requests("alice"),
        1
    );
    assert_eq!(
        detail(&fixture, ALICE).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    *fixture.state.service_detail_limit_barrier.lock().unwrap() = None;
    barrier.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture
            .state
            .service_detail_ingress
            .principal_in_flight_requests("alice")
            != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(detail(&fixture, ALICE).await.status(), StatusCode::OK);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}

#[tokio::test]
async fn live_detail_rejects_runtime_replacement_during_async_assembly() {
    let fixture = limit_fixture(|_| {}).await;
    let barrier = Arc::new(crate::state::McpAdmissionBarrier {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    *fixture.state.service_detail_limit_barrier.lock().unwrap() = Some(barrier.clone());
    let app = fixture.app.clone();
    let request = tokio::spawn(async move {
        authed_json_request(
            app,
            Method::GET,
            "/v1/services/fake",
            "detail-publication",
            "Authorization",
            format!("Bearer {ALICE}"),
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), barrier.reached.notified())
        .await
        .unwrap();
    fixture.publish(2, |_| {}).await;
    *fixture.state.service_detail_limit_barrier.lock().unwrap() = None;
    barrier.release.add_permits(1);
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = response_json(response).await;
    assert_eq!(
        value["error"]["message"],
        "local discovery could not complete"
    );
    assert!(value.get("limits").is_none());
    assert!(value.get("result").is_none());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}

#[tokio::test]
async fn live_detail_context_timeout_retains_transport_capacity_until_worker_finishes() {
    let fixture = limit_fixture(|config| {
        config.limits.request_body_timeout_ms = 150;
        config.limits.max_concurrent_requests = 1;
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    let barrier = Arc::new(crate::state::McpBlockingBarrier::default());
    let _release_on_failure = ReleaseContextWorker(barrier.clone());
    *fixture.state.service_detail_context_barrier.lock().unwrap() = Some(barrier.clone());
    let app = fixture.app.clone();
    let request = tokio::spawn(async move {
        authed_json_request(
            app,
            Method::GET,
            "/v1/services/fake",
            "detail-context-deadline",
            "Authorization",
            format!("Bearer {ALICE}"),
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), barrier.reached.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(
        body["error"]["message"],
        "local discovery could not complete"
    );
    assert!(body.get("result").is_none());
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    // No identity permit exists yet. The independently owned lookup must still
    // keep the transport global permit after the timeout response is consumed.
    assert_eq!(
        fixture
            .state
            .service_detail_ingress
            .principal_in_flight_requests("alice"),
        0
    );
    assert!(
        fixture
            .state
            .service_detail_ingress
            .try_service_detail_global_concurrency(1)
            .is_err()
    );
    *fixture.state.service_detail_context_barrier.lock().unwrap() = None;
    barrier.release();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(permit) = fixture
                .state
                .service_detail_ingress
                .try_service_detail_global_concurrency(1)
            {
                drop(permit);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(detail(&fixture, ALICE).await.status(), StatusCode::OK);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
}
