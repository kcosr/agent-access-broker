use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;

struct Cancellation(CancellationToken);
impl AdmissionCancellation for Cancellation {
    fn reason(&self) -> Option<AdmissionCancellationReason> {
        self.0
            .is_cancelled()
            .then_some(AdmissionCancellationReason::ExplicitCancellation)
    }
    fn cancelled(&self) -> BoxFuture<'_, AdmissionCancellationReason> {
        Box::pin(async {
            self.0.cancelled().await;
            AdmissionCancellationReason::ExplicitCancellation
        })
    }
}
fn resolver(limit: InvocationLimit) -> InvocationLimitResolver {
    Arc::new(move || Box::pin(async move { Ok(limit) }))
}
fn request(
    limiter: &InvocationLimiter,
    limit: InvocationLimit,
    max_wait: u64,
) -> InvocationAdmissionRequest {
    InvocationAdmissionRequest {
        epoch: limiter.runtime_epoch(|| true).unwrap(),
        principal: "alice".into(),
        service: "jira".into(),
        max_wait: Duration::from_secs(max_wait),
        hard_deadline: None,
        cancellation: Arc::new(Cancellation(CancellationToken::new())),
        resolve_limit: resolver(limit),
    }
}
fn spawn(
    limiter: &Arc<InvocationLimiter>,
    request: InvocationAdmissionRequest,
) -> tokio::task::JoinHandle<Result<InvocationAdmissionGrant, InvocationAdmissionError>> {
    let limiter = limiter.clone();
    tokio::spawn(async move { limiter.admit(request).await })
}
async fn queued(limiter: &InvocationLimiter, count: usize) {
    for _ in 0..50 {
        let actual = limiter
            .state
            .lock()
            .unwrap()
            .scheduler
            .queues
            .values()
            .map(|queue| queue.entries.len())
            .sum::<usize>();
        if actual == count {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("queue did not reach {count} entries");
}
fn limit(requests: u64, window: u64) -> InvocationLimit {
    InvocationLimit::new(requests, window).unwrap()
}

#[tokio::test(start_paused = true)]
async fn fifo_forecasts_include_accepted_tickets_and_late_batch_charges_actual_time() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(2, 10);
    for _ in 0..2 {
        limiter.admit(request(&limiter, rate, 10)).await.unwrap();
    }
    let one = spawn(&limiter, request(&limiter, rate, 10));
    queued(&limiter, 1).await;
    let two = spawn(&limiter, request(&limiter, rate, 10));
    queued(&limiter, 2).await;
    let Err(InvocationAdmissionError::RateLimited(rejection)) =
        limiter.admit(request(&limiter, rate, 10)).await
    else {
        panic!("third waiter must be refused");
    };
    assert_eq!(rejection.retry_after_seconds, 20);
    assert_eq!(rejection.queued_requests, 2);
    assert!(!rejection.was_queued);
    let observed = limiter
        .observe(0, "alice", "jira", Duration::from_secs(10), resolver(rate))
        .await
        .unwrap();
    assert_eq!(observed.invocations.counted_requests, 2);
    assert_eq!(observed.invocations.queued_requests, 2);
    assert_eq!(observed.invocations.next_admission_after_seconds, 20);
    assert_eq!(observed.invocations.available_immediately, 0);
    tokio::time::advance(Duration::from_micros(10_000_500)).await;
    assert!(one.await.unwrap().unwrap().waited);
    assert!(two.await.unwrap().unwrap().waited);
    {
        let state = limiter.state.lock().unwrap();
        let window = &state.keys["alice"]["jira"];
        assert_eq!(window.total, 2);
        assert_eq!(window.buckets.back().unwrap().last_ns, 10_000_500_000);
    }
    tokio::time::advance(Duration::from_micros(9_999_500)).await;
    assert!(matches!(
        limiter.admit(request(&limiter, rate, 0)).await,
        Err(InvocationAdmissionError::RateLimited(_))
    ));
    tokio::time::advance(Duration::from_micros(500)).await;
    assert!(
        !limiter
            .admit(request(&limiter, rate, 0))
            .await
            .unwrap()
            .waited
    );
}

#[tokio::test(start_paused = true)]
async fn late_rate_opportunity_cannot_cross_strict_body_deadline() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 10)).await.unwrap();
    let mut waiting = request(&limiter, rate, 10);
    waiting.hard_deadline = Some(AdmissionDeadline {
        at: Instant::now() + Duration::from_micros(10_000_250),
        kind: InvocationDeadlineKind::Body,
    });
    let waiter = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    tokio::time::advance(Duration::from_micros(10_000_500)).await;
    let Err(InvocationAdmissionError::RateLimited(rejection)) = waiter.await.unwrap() else {
        panic!("strict body deadline must win");
    };
    assert!(rejection.was_queued);
    // The original configured rate deadline is earlier, but an otherwise valid
    // due opportunity was removed by the actual body deadline.
    assert_eq!(rejection.deadline_kind, InvocationDeadlineKind::Body);
    assert_eq!(limiter.state_for_test()[0].2, 1);
}

#[tokio::test(start_paused = true)]
async fn cancellation_releases_fifo_reservation_without_charging() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 30)).await.unwrap();
    let token = CancellationToken::new();
    let mut waiting = request(&limiter, rate, 30);
    waiting.cancellation = Arc::new(Cancellation(token.clone()));
    let first = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    let second = spawn(&limiter, request(&limiter, rate, 30));
    queued(&limiter, 2).await;
    token.cancel();
    let Err(InvocationAdmissionError::Cancelled(removal)) = first.await.unwrap() else {
        panic!("cancelled ticket must be removed");
    };
    assert_eq!(
        removal.reason(),
        AdmissionCancellationReason::ExplicitCancellation
    );
    assert_eq!(
        removal.into_provider_error().result.unwrap()["retrySafe"],
        true
    );
    queued(&limiter, 1).await;
    assert_eq!(limiter.state_for_test()[0].2, 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(second.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn publication_fences_initial_reads_and_preserves_admitted_history() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 20)).await.unwrap();
    let waiter = spawn(&limiter, request(&limiter, rate, 20));
    queued(&limiter, 1).await;
    let stale = request(&limiter, rate, 0);
    limiter.publish_runtime(|epoch| assert_eq!(epoch, 1));
    for result in [waiter.await.unwrap(), limiter.admit(stale).await] {
        let Err(InvocationAdmissionError::Cancelled(removal)) = result else {
            panic!("old snapshot cannot admit");
        };
        assert_eq!(
            removal.reason(),
            AdmissionCancellationReason::RuntimePublished
        );
    }
    assert_eq!(
        limiter.state_for_test(),
        [("alice".into(), "jira".into(), 1)]
    );
    assert!(matches!(
        limiter.admit(request(&limiter, rate, 0)).await,
        Err(InvocationAdmissionError::RateLimited(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn shutdown_and_abandoned_future_remove_pending_without_a_charge() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 20)).await.unwrap();
    let abandoned = spawn(&limiter, request(&limiter, rate, 20));
    queued(&limiter, 1).await;
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    queued(&limiter, 0).await;
    let pending = spawn(&limiter, request(&limiter, rate, 20));
    queued(&limiter, 1).await;
    limiter.close();
    let Err(InvocationAdmissionError::Cancelled(removal)) = pending.await.unwrap() else {
        panic!("shutdown must remove pending ticket");
    };
    assert_eq!(removal.reason(), AdmissionCancellationReason::Shutdown);
    assert_eq!(limiter.state_for_test()[0].2, 1);
    assert!(matches!(
        limiter.admit(request_after_close(&limiter, rate)).await,
        Err(InvocationAdmissionError::Cancelled(_))
    ));
}
fn request_after_close(
    _limiter: &InvocationLimiter,
    rate: InvocationLimit,
) -> InvocationAdmissionRequest {
    InvocationAdmissionRequest {
        epoch: 0,
        principal: "alice".into(),
        service: "jira".into(),
        max_wait: Duration::ZERO,
        hard_deadline: None,
        cancellation: Arc::new(Cancellation(CancellationToken::new())),
        resolve_limit: resolver(rate),
    }
}

#[tokio::test(start_paused = true)]
async fn observations_are_pure_even_when_opportunities_are_due() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(2, 10);
    let empty = limiter
        .observe(0, "unseen", "jira", Duration::from_secs(10), resolver(rate))
        .await
        .unwrap();
    assert_eq!(empty.invocations.available_immediately, 2);
    assert_eq!(empty.invocations.next_admission_after_seconds, 0);
    assert_eq!(limiter.key_count(), 0);
    for _ in 0..2 {
        limiter.admit(request(&limiter, rate, 10)).await.unwrap();
    }
    let first = spawn(&limiter, request(&limiter, rate, 10));
    queued(&limiter, 1).await;
    let second = spawn(&limiter, request(&limiter, rate, 10));
    queued(&limiter, 2).await;
    // Pure projection with a future clock value exercises due opportunities
    // without letting the real scheduler process them.
    {
        let state = limiter.state.lock().unwrap();
        let future = Instant::now() + Duration::from_micros(10_000_500);
        let projection = project(
            &state,
            &("alice".into(), "jira".into()),
            rate,
            future,
            10_000_500_000,
        );
        assert_eq!(projection.counted, 0);
        assert_eq!(projection.queued, 2);
        assert_eq!(projection.next_ns, 20_000_500_000);
        assert_eq!(state.keys["alice"]["jira"].total, 2);
        assert_eq!(
            state
                .scheduler
                .queues
                .values()
                .next()
                .unwrap()
                .entries
                .len(),
            2
        );
    }
    limiter.close();
    assert!(first.await.unwrap().is_err());
    assert!(second.await.unwrap().is_err());
}

#[tokio::test(start_paused = true)]
async fn successful_key_updates_refresh_only_that_key_and_failed_updates_keep_opportunities() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = Arc::new(Mutex::new(limit(1, 10)));
    let reads = Arc::new(AtomicUsize::new(0));
    let dynamic: InvocationLimitResolver = {
        let rate = rate.clone();
        let reads = reads.clone();
        Arc::new(move || {
            let value = *rate.lock().unwrap();
            reads.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(value) })
        })
    };
    let mut initial = request(&limiter, limit(1, 10), 10);
    initial.resolve_limit = dynamic.clone();
    limiter.admit(initial).await.unwrap();
    let mut pending = request(&limiter, limit(1, 10), 10);
    pending.resolve_limit = dynamic.clone();
    let waiter = spawn(&limiter, pending);
    queued(&limiter, 1).await;
    limiter.begin_update("bob", "jira").finish(true);
    limiter.begin_update("alice", "jira").finish(false);
    tokio::time::advance(Duration::from_micros(10_000_500)).await;
    assert!(waiter.await.unwrap().is_ok());
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "unrelated and failed writes must retain cached settings"
    );
    let guard = limiter.begin_update("alice", "jira");
    *rate.lock().unwrap() = limit(2, 10);
    guard.finish(true);
    let mut next = request(&limiter, limit(2, 10), 0);
    next.resolve_limit = dynamic;
    assert!(limiter.admit(next).await.is_ok());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(limiter.state_for_test()[0].2, 2);
}

#[tokio::test(start_paused = true)]
async fn stale_store_read_cannot_reset_a_newer_window() {
    let limiter = Arc::new(InvocationLimiter::new());
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let reads = Arc::new(AtomicUsize::new(0));
    let dynamic: InvocationLimitResolver = {
        let started = started.clone();
        let release = release.clone();
        let reads = reads.clone();
        Arc::new(move || {
            let started = started.clone();
            let release = release.clone();
            let reads = reads.clone();
            Box::pin(async move {
                if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    started.notify_one();
                    release.notified().await;
                    Ok(limit(1, 60))
                } else {
                    Ok(limit(2, 10))
                }
            })
        })
    };
    let mut stale = request(&limiter, limit(1, 60), 0);
    stale.resolve_limit = dynamic;
    let pending = spawn(&limiter, stale);
    started.notified().await;
    limiter.begin_update("alice", "jira").finish(true);
    limiter
        .admit(request(&limiter, limit(2, 10), 0))
        .await
        .unwrap();
    release.notify_one();
    pending.await.unwrap().unwrap();
    let state = limiter.state.lock().unwrap();
    assert_eq!(state.keys["alice"]["jira"].window_ns, 10 * NANOS_PER_SECOND);
    assert_eq!(state.keys["alice"]["jira"].total, 2);
}

#[tokio::test(start_paused = true)]
async fn hard_deadline_removes_a_ticket_while_its_settings_write_is_in_progress() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 20)).await.unwrap();
    let mut waiting = request(&limiter, rate, 20);
    waiting.hard_deadline = Some(AdmissionDeadline {
        at: Instant::now() + Duration::from_secs(15),
        kind: InvocationDeadlineKind::Operation,
    });
    let pending = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    let write = limiter.begin_update("alice", "jira");
    tokio::time::advance(Duration::from_secs(15)).await;
    let Err(InvocationAdmissionError::RateLimited(rejection)) = pending.await.unwrap() else {
        panic!("hard bound cannot wait for a database mutation");
    };
    assert_eq!(rejection.deadline_kind, InvocationDeadlineKind::Operation);
    assert_eq!(rejection.waited_milliseconds, 15_000);
    assert_eq!(limiter.state_for_test()[0].2, 1);
    write.finish(false);
}

#[tokio::test(start_paused = true)]
async fn changed_window_resets_history_once_and_reforecasts_pending_fifo() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = Arc::new(Mutex::new(limit(1, 10)));
    let dynamic: InvocationLimitResolver = {
        let rate = rate.clone();
        Arc::new(move || {
            let value = *rate.lock().unwrap();
            Box::pin(async move { Ok(value) })
        })
    };
    let mut initial = request(&limiter, limit(1, 10), 20);
    initial.resolve_limit = dynamic.clone();
    limiter.admit(initial).await.unwrap();
    let mut waiting = request(&limiter, limit(1, 10), 20);
    waiting.resolve_limit = dynamic.clone();
    let first = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    let mut waiting = request(&limiter, limit(1, 10), 20);
    waiting.resolve_limit = dynamic;
    let second = spawn(&limiter, waiting);
    queued(&limiter, 2).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let write = limiter.begin_update("alice", "jira");
    *rate.lock().unwrap() = limit(1, 5);
    write.finish(true);
    assert!(first.await.unwrap().is_ok());
    queued(&limiter, 1).await;
    assert!(!second.is_finished());
    {
        let state = limiter.state.lock().unwrap();
        let window = &state.keys["alice"]["jira"];
        assert_eq!(window.window_ns, 5 * NANOS_PER_SECOND);
        assert_eq!(window.total, 1);
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(second.await.unwrap().is_ok());
    assert_eq!(limiter.state_for_test()[0].2, 1);
}

#[tokio::test(start_paused = true)]
async fn lower_request_count_keeps_history_and_refuses_a_now_infeasible_tail() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = Arc::new(Mutex::new(limit(2, 10)));
    let dynamic: InvocationLimitResolver = {
        let rate = rate.clone();
        Arc::new(move || {
            let value = *rate.lock().unwrap();
            Box::pin(async move { Ok(value) })
        })
    };
    for _ in 0..2 {
        let mut initial = request(&limiter, limit(2, 10), 10);
        initial.resolve_limit = dynamic.clone();
        limiter.admit(initial).await.unwrap();
    }
    let mut waiting = request(&limiter, limit(2, 10), 10);
    waiting.resolve_limit = dynamic.clone();
    let first = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    let mut waiting = request(&limiter, limit(2, 10), 10);
    waiting.resolve_limit = dynamic;
    let second = spawn(&limiter, waiting);
    queued(&limiter, 2).await;
    let write = limiter.begin_update("alice", "jira");
    *rate.lock().unwrap() = limit(1, 10);
    write.finish(true);
    let Err(InvocationAdmissionError::RateLimited(rejection)) = second.await.unwrap() else {
        panic!("tail no longer fits unchanged deadline");
    };
    assert_eq!(rejection.limit.requests(), 1);
    assert_eq!(rejection.queued_requests, 1);
    assert_eq!(rejection.retry_after_seconds, 20);
    assert_eq!(limiter.state_for_test()[0].2, 2);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(first.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn cancellation_before_enqueue_and_after_grant_have_distinct_charge_outcomes() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    let token = CancellationToken::new();
    token.cancel();
    let mut cancelled = request(&limiter, rate, 20);
    cancelled.cancellation = Arc::new(Cancellation(token));
    assert!(matches!(
        limiter.admit(cancelled).await,
        Err(InvocationAdmissionError::Cancelled(_))
    ));
    assert_eq!(limiter.key_count(), 0);
    limiter.admit(request(&limiter, rate, 20)).await.unwrap();
    let token = CancellationToken::new();
    let mut pending = request(&limiter, rate, 20);
    pending.cancellation = Arc::new(Cancellation(token.clone()));
    let pending = spawn(&limiter, pending);
    queued(&limiter, 1).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    queued(&limiter, 0).await;
    token.cancel();
    assert!(
        pending.await.unwrap().is_ok(),
        "committed grant wins later cancellation"
    );
    assert_eq!(limiter.state_for_test()[0].2, 1);
}

#[tokio::test(start_paused = true)]
async fn failed_and_abandoned_observation_reads_leave_no_unseen_key_metadata() {
    let limiter = Arc::new(InvocationLimiter::new());
    let failure: InvocationLimitResolver = Arc::new(|| {
        Box::pin(async {
            Err(ProviderError::error(
                ReasonCode::RateLimited,
                "synthetic settings failure",
            ))
        })
    });
    assert!(matches!(
        limiter
            .observe(0, "unseen", "jira", Duration::ZERO, failure)
            .await,
        Err(InvocationObservationError::Resolution(_))
    ));
    assert!(limiter.state.lock().unwrap().scheduler.settings.is_empty());
    let started = Arc::new(Notify::new());
    let blocked: InvocationLimitResolver = {
        let started = started.clone();
        Arc::new(move || {
            let started = started.clone();
            Box::pin(async move {
                started.notify_one();
                std::future::pending().await
            })
        })
    };
    let task = {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            limiter
                .observe(0, "unseen", "jira", Duration::ZERO, blocked)
                .await
        })
    };
    started.notified().await;
    assert_eq!(limiter.state.lock().unwrap().scheduler.settings.len(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(limiter.state.lock().unwrap().scheduler.settings.is_empty());
    assert_eq!(limiter.key_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn publication_during_observation_preserves_read_fence_then_cleans_it() {
    let limiter = Arc::new(InvocationLimiter::new());
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let blocked: InvocationLimitResolver = {
        let started = started.clone();
        let release = release.clone();
        Arc::new(move || {
            let started = started.clone();
            let release = release.clone();
            Box::pin(async move {
                started.notify_one();
                release.notified().await;
                Ok(limit(1, 10))
            })
        })
    };
    let task = {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            limiter
                .observe(0, "unseen", "jira", Duration::ZERO, blocked)
                .await
        })
    };
    started.notified().await;
    limiter.publish_runtime(|_| {});
    assert_eq!(
        limiter.state.lock().unwrap().scheduler.settings.len(),
        1,
        "active reader must retain its fence"
    );
    release.notify_one();
    assert!(matches!(
        task.await.unwrap(),
        Err(InvocationObservationError::RuntimePublished)
    ));
    assert!(limiter.state.lock().unwrap().scheduler.settings.is_empty());
    assert_eq!(limiter.key_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn cancelled_ticket_keeps_its_non_cancelable_settings_read_owned_until_completion() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 20)).await.unwrap();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let keepalive = Arc::new(());
    let weak = Arc::downgrade(&keepalive);
    let blocked: InvocationLimitResolver = {
        let started = started.clone();
        let release = release.clone();
        Arc::new(move || {
            let started = started.clone();
            let release = release.clone();
            let keepalive = keepalive.clone();
            Box::pin(async move {
                let _keepalive = keepalive;
                started.notify_one();
                release.notified().await;
                Ok(rate)
            })
        })
    };
    let token = CancellationToken::new();
    let mut waiting = request(&limiter, rate, 20);
    waiting.resolve_limit = blocked;
    waiting.cancellation = Arc::new(Cancellation(token.clone()));
    let pending = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    limiter.begin_update("alice", "jira").finish(true);
    started.notified().await;
    token.cancel();
    assert!(matches!(
        pending.await.unwrap(),
        Err(InvocationAdmissionError::Cancelled(_))
    ));
    assert!(
        weak.upgrade().is_some(),
        "the settings worker retains its request ownership after removal"
    );
    release.notify_one();
    for _ in 0..50 {
        if weak.upgrade().is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        weak.upgrade().is_none(),
        "drained settings work releases its owner"
    );
    assert_eq!(limiter.state_for_test()[0].2, 1);
}

#[tokio::test(start_paused = true)]
async fn final_write_fence_cleans_an_observation_abandoned_during_mutation() {
    let limiter = Arc::new(InvocationLimiter::new());
    let write = limiter.begin_update("unseen", "jira");
    let task = {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            limiter
                .observe(0, "unseen", "jira", Duration::ZERO, resolver(limit(1, 10)))
                .await
        })
    };
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(limiter.state.lock().unwrap().scheduler.settings.len(), 1);
    write.finish(false);
    assert!(limiter.state.lock().unwrap().scheduler.settings.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pure_projection_and_scheduler_share_removal_invalidation_rules() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(2, 10);
    for _ in 0..2 {
        limiter.admit(request(&limiter, rate, 10)).await.unwrap();
    }
    let first = spawn(&limiter, request(&limiter, rate, 10));
    queued(&limiter, 1).await;
    let token = CancellationToken::new();
    let mut waiting = request(&limiter, rate, 10);
    waiting.cancellation = Arc::new(Cancellation(token.clone()));
    let second = spawn(&limiter, waiting);
    queued(&limiter, 2).await;
    token.cancel();
    {
        let mut state = limiter.state.lock().unwrap();
        let key = ("alice".into(), "jira".into());
        let now = Instant::now() + Duration::from_micros(10_000_500);
        let now_ns = 10_000_500_000;
        let before = project(&state, &key, rate, now, now_ns);
        assert_eq!(
            before.queued, 0,
            "removal invalidates old opportunities before projection walks any position"
        );
        limiter.process(&mut state, &key, rate, 0, now, now_ns);
        let after = project(&state, &key, rate, now, now_ns);
        assert_eq!(before.next_ns, after.next_ns);
        assert_eq!(before.available, after.available);
        assert!(state.scheduler.queues.is_empty());
    }
    assert!(matches!(
        first.await.unwrap(),
        Err(InvocationAdmissionError::RateLimited(_))
    ));
    assert!(matches!(
        second.await.unwrap(),
        Err(InvocationAdmissionError::Cancelled(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn granted_head_does_not_keep_its_permits_while_the_driver_waits_for_a_successor() {
    let limiter = Arc::new(InvocationLimiter::new());
    let rate = limit(1, 10);
    limiter.admit(request(&limiter, rate, 30)).await.unwrap();
    let keepalive = Arc::new(());
    let weak = Arc::downgrade(&keepalive);
    let mut waiting = request(&limiter, rate, 30);
    waiting.resolve_limit = Arc::new(move || {
        let keepalive = keepalive.clone();
        Box::pin(async move {
            let _keepalive = keepalive;
            Ok(rate)
        })
    });
    let first = spawn(&limiter, waiting);
    queued(&limiter, 1).await;
    let second = spawn(&limiter, request(&limiter, rate, 30));
    queued(&limiter, 2).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    first.await.unwrap().unwrap();
    queued(&limiter, 1).await;
    assert!(
        weak.upgrade().is_none(),
        "completed head no longer owns capacity through its scheduler driver"
    );
    limiter.close();
    assert!(second.await.unwrap().is_err());
}
