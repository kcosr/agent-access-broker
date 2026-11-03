use super::*;

fn capped(rate: InvocationLimit) -> Arc<InvocationLimiter> {
    Arc::new(InvocationLimiter::new(&BTreeMap::from([(
        "jira".into(),
        rate,
    )])))
}

fn named(
    limiter: &InvocationLimiter,
    principal: &str,
    rate: InvocationLimit,
    wait: u64,
) -> InvocationAdmissionRequest {
    let mut value = request(limiter, rate, wait);
    value.principal = principal.into();
    value
}

fn shared_count(limiter: &InvocationLimiter) -> u64 {
    limiter
        .state
        .lock()
        .unwrap()
        .aggregate_windows
        .get("jira")
        .map_or(0, |window| window.total)
}

fn opportunities(limiter: &InvocationLimiter) -> Vec<(String, Vec<u64>)> {
    let state = limiter.state.lock().unwrap();
    let mut result = state
        .scheduler
        .queues
        .iter()
        .map(|((principal, _), queue)| {
            (
                principal.clone(),
                queue
                    .entries
                    .iter()
                    .map(|entry| entry.opportunity_ns)
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    result.sort();
    result
}

async fn settle_tasks() {
    for _ in 0..30 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_principals_debit_both_histories_or_neither() {
    let limiter = capped(limit(3, 10));
    let mut calls = Vec::new();
    for index in 0..20 {
        calls.push(spawn(
            &limiter,
            named(&limiter, &format!("person-{index}"), limit(2, 6), 0),
        ));
    }
    let mut admitted = 0;
    for call in calls {
        match call.await.unwrap() {
            Ok(_) => admitted += 1,
            Err(InvocationAdmissionError::RateLimited(rejection)) => {
                assert_eq!(rejection.scope, InvocationLimitScope::Service);
                assert_eq!(rejection.limit, limit(3, 10));
            }
            outcome => panic!("unexpected admission: {outcome:?}"),
        }
    }
    assert_eq!(admitted, 3);
    assert_eq!(shared_count(&limiter), 3);
    assert_eq!(
        limiter
            .state_for_test()
            .iter()
            .map(|entry| entry.2)
            .sum::<u64>(),
        3
    );
    assert_eq!(limiter.key_count(), 3);
    let mut other = named(&limiter, "other", limit(1, 10), 0);
    other.service = "gitlab".into();
    limiter.admit(other).await.unwrap();
    assert_eq!(shared_count(&limiter), 3);
}

#[tokio::test(start_paused = true)]
async fn unequal_personal_and_shared_windows_hold_for_every_trailing_interval() {
    let limiter = capped(limit(5, 10));
    let rates = [limit(2, 6), limit(4, 9), limit(3, 7)];
    let start = Instant::now();
    let mut admissions = Vec::new();
    for index in 0..500 {
        tokio::time::advance(Duration::from_millis(97 + index % 13)).await;
        let principal = index as usize % rates.len();
        if limiter
            .admit(named(
                &limiter,
                &format!("p{principal}"),
                rates[principal],
                0,
            ))
            .await
            .is_ok()
        {
            admissions.push((Instant::now() - start, principal));
        }
    }
    assert!(admissions.len() > 20);
    for (end, principal) in &admissions {
        assert!(
            admissions
                .iter()
                .filter(|(at, _)| at <= end && *end - *at < Duration::from_secs(10))
                .count()
                <= 5
        );
        let rate = rates[*principal];
        assert!(
            admissions
                .iter()
                .filter(|(at, owner)| owner == principal
                    && at <= end
                    && *end - *at < Duration::from_secs(u64::from(rate.window_seconds())))
                .count()
                <= rate.requests() as usize
        );
    }
}

#[tokio::test(start_paused = true)]
async fn scope_distinguishes_shared_delay_ties_and_personal_only_exhaustion() {
    for (shared, personal, expected, opening) in [
        (
            limit(1, 10),
            limit(1, 10),
            InvocationLimitScope::Service,
            10,
        ),
        (
            limit(10, 10),
            limit(1, 10),
            InvocationLimitScope::Principal,
            10,
        ),
        (
            limit(1, 20),
            limit(1, 10),
            InvocationLimitScope::Service,
            20,
        ),
        // Both allowances are empty, but only the personal allowance delays
        // the next call beyond the shared window's opening at ten seconds.
        (
            limit(1, 10),
            limit(1, 20),
            InvocationLimitScope::Principal,
            20,
        ),
    ] {
        let limiter = capped(shared);
        let empty = limiter
            .observe(0, "alice", "jira", Duration::ZERO, resolver(personal))
            .await
            .unwrap();
        assert_eq!(empty.invocations.blocking_scope, None);
        assert_eq!(
            empty.invocations.available_immediately,
            shared.requests().min(personal.requests())
        );
        limiter
            .admit(named(&limiter, "alice", personal, 0))
            .await
            .unwrap();
        let observed = limiter
            .observe(0, "alice", "jira", Duration::ZERO, resolver(personal))
            .await
            .unwrap();
        assert_eq!(observed.invocations.blocking_scope, Some(expected));
        assert_eq!(observed.invocations.next_admission_after_seconds, opening);
        assert_eq!(
            serde_json::to_value(&observed.invocations).unwrap()["blockingScope"],
            expected.as_str()
        );
        let Err(InvocationAdmissionError::RateLimited(rejected)) =
            limiter.admit(named(&limiter, "alice", personal, 0)).await
        else {
            panic!("expected rejection")
        };
        assert_eq!(rejected.scope, expected);
        assert_eq!(rejected.retry_after_seconds, opening);
        assert_eq!(
            rejected.limit,
            if expected == InvocationLimitScope::Service {
                shared
            } else {
                personal
            }
        );
        assert_eq!(rejected.result()["limitScope"], expected.as_str());
        assert_eq!(
            rejected.result()["windowSeconds"],
            rejected.limit.window_seconds()
        );
        assert_eq!(
            rejected.audit()["rateLimit"]["limitScope"],
            expected.as_str()
        );
        assert_eq!(
            rejected.audit()["rateLimit"]["windowSeconds"],
            rejected.limit.window_seconds()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn scope_tie_uses_the_callers_shared_turn_with_existing_peer_contention() {
    let shared = limit(1, 10);
    let personal = limit(1, 20);
    let limiter = capped(shared);
    limiter
        .admit(named(&limiter, "alice", personal, 0))
        .await
        .unwrap();
    let bob = spawn(&limiter, named(&limiter, "bob", limit(10, 60), 50));
    queued(&limiter, 1).await;
    // Bob takes the shared opening at ten seconds. Alice's shared turn and
    // personal opening now really coincide at twenty seconds, despite the
    // different configured window lengths.
    let observed = limiter
        .observe(0, "alice", "jira", Duration::ZERO, resolver(personal))
        .await
        .unwrap();
    assert_eq!(observed.invocations.next_admission_after_seconds, 20);
    assert_eq!(
        observed.invocations.blocking_scope,
        Some(InvocationLimitScope::Service)
    );
    let Err(InvocationAdmissionError::RateLimited(rejected)) =
        limiter.admit(named(&limiter, "alice", personal, 0)).await
    else {
        panic!("expected the shared-turn tie to reject");
    };
    assert_eq!(rejected.limit, shared);
    assert_eq!(rejected.retry_after_seconds, 20);
    assert_eq!(rejected.result()["limitScope"], "service");
    assert_eq!(rejected.audit()["rateLimit"]["limitScope"], "service");
    limiter.close();
    assert!(bob.await.unwrap().is_err());
}

#[tokio::test(start_paused = true)]
async fn personal_fifo_can_open_later_than_its_shared_turn_despite_both_empty_allowances() {
    let personal = limit(1, 20);
    let limiter = capped(limit(1, 10));
    limiter
        .admit(named(&limiter, "alice", personal, 0))
        .await
        .unwrap();
    let alice = spawn(&limiter, named(&limiter, "alice", personal, 50));
    queued(&limiter, 1).await;
    let bob = spawn(&limiter, named(&limiter, "bob", limit(10, 60), 50));
    queued(&limiter, 2).await;
    // With personal enforcement, the queued Alice request runs at twenty
    // seconds and her next call at forty. Without that personal constraint,
    // the same ring would run Alice/Bob/Alice at ten/twenty/thirty seconds.
    let observed = limiter
        .observe(0, "alice", "jira", Duration::ZERO, resolver(personal))
        .await
        .unwrap();
    assert_eq!(observed.invocations.next_admission_after_seconds, 40);
    assert_eq!(
        observed.invocations.blocking_scope,
        Some(InvocationLimitScope::Principal)
    );
    let Err(InvocationAdmissionError::RateLimited(rejected)) =
        limiter.admit(named(&limiter, "alice", personal, 0)).await
    else {
        panic!("expected the personal FIFO to reject");
    };
    assert_eq!(rejected.limit, personal);
    assert_eq!(rejected.retry_after_seconds, 40);
    assert_eq!(rejected.result()["limitScope"], "principal");
    assert_eq!(rejected.audit()["rateLimit"]["limitScope"], "principal");
    limiter.close();
    assert!(alice.await.unwrap().is_err());
    assert!(bob.await.unwrap().is_err());
}

#[tokio::test(start_paused = true)]
async fn service_ring_preserves_fifo_and_rotates_eligible_principals() {
    let limiter = capped(limit(1, 10));
    let personal = limit(100, 60);
    limiter
        .admit(named(&limiter, "seed", personal, 0))
        .await
        .unwrap();
    let a1 = spawn(&limiter, named(&limiter, "alice", personal, 60));
    queued(&limiter, 1).await;
    let a2 = spawn(&limiter, named(&limiter, "alice", personal, 60));
    queued(&limiter, 2).await;
    let b1 = spawn(&limiter, named(&limiter, "bob", personal, 60));
    queued(&limiter, 3).await;
    let b2 = spawn(&limiter, named(&limiter, "bob", personal, 60));
    queued(&limiter, 4).await;
    assert_eq!(
        opportunities(&limiter),
        vec![
            ("alice".into(), vec![10_000_000_000, 30_000_000_000]),
            ("bob".into(), vec![20_000_000_000, 40_000_000_000])
        ]
    );
    for expected in [&a1, &b1, &a2, &b2] {
        tokio::time::advance(Duration::from_secs(10)).await;
        settle_tasks().await;
        assert!(expected.is_finished());
    }
    for call in [a1, b1, a2, b2] {
        assert!(call.await.unwrap().unwrap().waited);
    }
    assert_eq!(shared_count(&limiter), 1);
}

#[tokio::test(start_paused = true)]
async fn personally_throttled_head_does_not_reserve_shared_capacity() {
    let limiter = capped(limit(2, 10));
    limiter
        .admit(named(&limiter, "alice", limit(1, 30), 0))
        .await
        .unwrap();
    let a = spawn(&limiter, named(&limiter, "alice", limit(1, 30), 40));
    queued(&limiter, 1).await;
    limiter
        .admit(named(&limiter, "bob", limit(10, 10), 0))
        .await
        .unwrap();
    assert!(!a.is_finished());
    tokio::time::advance(Duration::from_secs(10)).await;
    limiter
        .admit(named(&limiter, "carol", limit(10, 10), 0))
        .await
        .unwrap();
    assert!(!a.is_finished());
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(a.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn only_an_accepted_newcomer_can_displace_existing_peers() {
    let limiter = capped(limit(1, 10));
    let rate = limit(100, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let a1 = spawn(&limiter, named(&limiter, "alice", rate, 35));
    queued(&limiter, 1).await;
    let a2 = spawn(&limiter, named(&limiter, "alice", rate, 35));
    queued(&limiter, 2).await;
    let b1 = spawn(&limiter, named(&limiter, "bob", rate, 35));
    queued(&limiter, 3).await;
    let before = opportunities(&limiter);
    assert_eq!(before[0].1, vec![10_000_000_000, 30_000_000_000]);
    let Err(InvocationAdmissionError::RateLimited(rejected)) =
        limiter.admit(named(&limiter, "carol", rate, 15)).await
    else {
        panic!("newcomer cannot fit")
    };
    assert_eq!(rejected.scope, InvocationLimitScope::Service);
    assert_eq!(opportunities(&limiter), before);
    assert!(!a2.is_finished());
    let c1 = spawn(&limiter, named(&limiter, "carol", rate, 35));
    settle_tasks().await;
    let Err(InvocationAdmissionError::RateLimited(displaced)) = a2.await.unwrap() else {
        panic!("A2 no longer fits")
    };
    assert!(displaced.was_queued);
    assert_eq!(displaced.scope, InvocationLimitScope::Service);
    assert_eq!(displaced.queued_requests, 1);
    assert_eq!(
        opportunities(&limiter),
        vec![
            ("alice".into(), vec![10_000_000_000]),
            ("bob".into(), vec![20_000_000_000]),
            ("carol".into(), vec![30_000_000_000])
        ]
    );
    assert_eq!(
        limiter.state_for_test(),
        [("seed".into(), "jira".into(), 1)]
    );
    for call in [a1, b1, c1] {
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(call.await.unwrap().is_ok());
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_shared_waiter_spends_neither_allowance() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let token = CancellationToken::new();
    let mut pending = named(&limiter, "alice", rate, 30);
    pending.cancellation = Arc::new(Cancellation(token.clone()));
    let a = spawn(&limiter, pending);
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 30));
    queued(&limiter, 2).await;
    token.cancel();
    assert!(matches!(
        a.await.unwrap(),
        Err(InvocationAdmissionError::Cancelled(_))
    ));
    assert_eq!(shared_count(&limiter), 1);
    assert_eq!(
        limiter.state_for_test(),
        [("seed".into(), "jira".into(), 1)]
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(b.await.unwrap().is_ok());
    assert!(
        !limiter
            .state_for_test()
            .iter()
            .any(|entry| entry.0 == "alice")
    );
}

#[tokio::test(start_paused = true)]
async fn late_wake_does_not_replay_missed_shared_windows() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let a = spawn(&limiter, named(&limiter, "alice", rate, 30));
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 30));
    queued(&limiter, 2).await;
    tokio::time::advance(Duration::from_secs(25)).await;
    settle_tasks().await;
    assert!(a.await.unwrap().is_ok());
    let Err(InvocationAdmissionError::RateLimited(rejected)) = b.await.unwrap() else {
        panic!("no second actual capacity at 25s")
    };
    assert_eq!(rejected.scope, InvocationLimitScope::Service);
    let state = limiter.state.lock().unwrap();
    assert_eq!(state.aggregate_windows["jira"].total, 1);
    assert_eq!(
        state.aggregate_windows["jira"].buckets[0].last_ns,
        25_000_000_000
    );
    assert!(!state.keys.contains_key("bob"));
}

#[tokio::test(start_paused = true)]
async fn shared_policy_publication_preserves_counts_and_has_explicit_reset_boundaries() {
    let limiter = capped(limit(2, 10));
    let rate = limit(100, 60);
    for _ in 0..2 {
        limiter
            .admit(named(&limiter, "alice", rate, 0))
            .await
            .unwrap();
    }
    limiter.publish_runtime(&BTreeMap::from([("jira".into(), limit(3, 10))]), |_| {});
    assert_eq!(shared_count(&limiter), 2);
    limiter
        .admit(named(&limiter, "alice", rate, 0))
        .await
        .unwrap();
    limiter.publish_runtime(&BTreeMap::from([("jira".into(), limit(1, 10))]), |_| {});
    assert_eq!(shared_count(&limiter), 3);
    assert!(matches!(
        limiter.admit(named(&limiter, "bob", rate, 0)).await,
        Err(InvocationAdmissionError::RateLimited(_))
    ));
    limiter.publish_runtime(&BTreeMap::from([("jira".into(), limit(1, 5))]), |_| {});
    assert_eq!(shared_count(&limiter), 0);
    limiter
        .admit(named(&limiter, "alice", rate, 0))
        .await
        .unwrap();
    limiter.publish_runtime(&BTreeMap::new(), |_| {});
    assert_eq!(shared_count(&limiter), 0);
    for _ in 0..3 {
        limiter
            .admit(named(&limiter, "alice", rate, 0))
            .await
            .unwrap();
    }
    limiter.publish_runtime(&BTreeMap::from([("jira".into(), limit(1, 5))]), |_| {});
    limiter
        .admit(named(&limiter, "bob", rate, 0))
        .await
        .unwrap();
    assert_eq!(shared_count(&limiter), 1);
    let pending = spawn(&limiter, named(&limiter, "carol", rate, 10));
    queued(&limiter, 1).await;
    limiter.publish_runtime(&BTreeMap::from([("jira".into(), limit(1, 5))]), |_| {});
    assert!(matches!(
        pending.await.unwrap(),
        Err(InvocationAdmissionError::Cancelled(_))
    ));
    assert_eq!(shared_count(&limiter), 1);
}

#[tokio::test(start_paused = true)]
async fn an_unresolved_person_does_not_block_peer_grants_or_hard_deadlines() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
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
                if reads.fetch_add(1, Ordering::SeqCst) > 0 {
                    started.notify_one();
                    release.notified().await;
                }
                Ok(rate)
            })
        })
    };
    let mut a = named(&limiter, "alice", rate, 50);
    a.resolve_limit = dynamic;
    a.hard_deadline = Some(AdmissionDeadline {
        at: Instant::now() + Duration::from_secs(15),
        kind: InvocationDeadlineKind::Operation,
    });
    let a = spawn(&limiter, a);
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 50));
    queued(&limiter, 2).await;
    limiter.begin_update("alice", "jira").finish(true);
    started.notified().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    settle_tasks().await;
    assert!(
        b.is_finished(),
        "Bob must progress while Alice's store read is blocked"
    );
    assert!(b.await.unwrap().is_ok());
    assert!(!a.is_finished());
    tokio::time::advance(Duration::from_secs(5)).await;
    let Err(InvocationAdmissionError::RateLimited(rejected)) = a.await.unwrap() else {
        panic!("hard deadline must remove the unresolved waiter")
    };
    assert_eq!(rejected.deadline_kind, InvocationDeadlineKind::Operation);
    assert_eq!(rejected.scope, InvocationLimitScope::Service);
    assert_eq!(rejected.waited_milliseconds, 15_000);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    release.notify_one();
    settle_tasks().await;
    assert!(
        !limiter
            .state_for_test()
            .iter()
            .any(|entry| entry.0 == "alice")
    );
    assert!(limiter.state.lock().unwrap().scheduler.queues.is_empty());
}

#[tokio::test(start_paused = true)]
async fn queued_settings_failure_is_local_to_one_principal() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut a = named(&limiter, "alice", rate, 30);
    a.resolve_limit = Arc::new(move || {
        let failed = reads.fetch_add(1, Ordering::SeqCst) > 0;
        Box::pin(async move {
            if failed {
                Err(ProviderError::error(
                    ReasonCode::ManagedStoreUnavailable,
                    "synthetic failed refresh",
                ))
            } else {
                Ok(rate)
            }
        })
    });
    let a = spawn(&limiter, a);
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 30));
    queued(&limiter, 2).await;
    limiter.begin_update("alice", "jira").finish(true);
    assert!(matches!(
        a.await.unwrap(),
        Err(InvocationAdmissionError::Resolution { waited: true, .. })
    ));
    assert!(!b.is_finished());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(b.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn observed_forecast_matches_grants_with_unequal_windows_and_conservative_buckets() {
    let limiter = capped(limit(2, 10));
    limiter
        .admit(named(&limiter, "seed", limit(100, 60), 0))
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(150)).await;
    limiter
        .admit(named(&limiter, "seed", limit(100, 60), 0))
        .await
        .unwrap();
    let mut calls = Vec::new();
    for (principal, rate) in [
        ("alice", limit(1, 6)),
        ("bob", limit(2, 15)),
        ("alice", limit(1, 6)),
        ("carol", limit(2, 7)),
        ("bob", limit(2, 15)),
    ] {
        calls.push(spawn(&limiter, named(&limiter, principal, rate, 60)));
        queued(&limiter, calls.len()).await;
    }
    let plan = {
        let state = limiter.state.lock().unwrap();
        forecast_existing(
            &state,
            "jira",
            Instant::now(),
            duration_ns(limiter.clock.monotonic()),
        )
        .opportunities
    };
    let mut ordered = plan.values().copied().collect::<Vec<_>>();
    ordered.sort_unstable();
    ordered.dedup();
    for at in ordered {
        let now = duration_ns(limiter.clock.monotonic());
        tokio::time::advance(Duration::from_nanos(at - now)).await;
        settle_tasks().await;
        for (index, call) in calls.iter().enumerate() {
            assert_eq!(
                call.is_finished(),
                plan[&(index as u64 + 1)] <= at,
                "ticket {} at {at}",
                index + 1
            );
        }
    }
    for call in calls {
        assert!(call.await.unwrap().is_ok());
    }
}

#[tokio::test(start_paused = true)]
async fn due_work_is_observed_without_grants_or_unseen_observer_metadata() {
    let clock = crate::ingress::invocation_limits::tests::ManualClock::new();
    let mut controlled = InvocationLimiter::with_clock(clock.clone());
    controlled.initialize_aggregate_limits(&BTreeMap::from([("jira".into(), limit(2, 10))]));
    let limiter = Arc::new(controlled);
    let rate = limit(10, 60);
    for _ in 0..2 {
        limiter
            .admit(named(&limiter, "seed", rate, 0))
            .await
            .unwrap();
    }
    let a = spawn(&limiter, named(&limiter, "alice", rate, 20));
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 20));
    queued(&limiter, 2).await;
    settle_tasks().await;
    let before = opportunities(&limiter);
    let ring = limiter.state.lock().unwrap().scheduler.services["jira"]
        .ring
        .clone();
    clock.advance(Duration::from_millis(10_500));
    for _ in 0..3 {
        let observed = limiter
            .observe(0, "unseen", "jira", Duration::ZERO, resolver(rate))
            .await
            .unwrap();
        assert_eq!(observed.invocations.counted_requests, 0);
        assert_eq!(observed.invocations.queued_requests, 0);
        assert_eq!(observed.invocations.available_immediately, 0);
        assert_eq!(observed.invocations.next_admission_after_seconds, 10);
        assert_eq!(
            observed.invocations.blocking_scope,
            Some(InvocationLimitScope::Service)
        );
        assert_eq!(opportunities(&limiter), before);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.scheduler.services["jira"].ring, ring);
        assert_eq!(state.aggregate_windows["jira"].total, 2);
        assert_eq!(state.aggregate_windows["jira"].buckets[0].last_ns, 0);
        assert!(
            !state
                .scheduler
                .settings
                .contains_key(&("unseen".into(), "jira".into()))
        );
        assert!(!state.keys.contains_key("unseen"));
    }
    assert!(!a.is_finished() && !b.is_finished());
    limiter.close();
    assert!(a.await.unwrap().is_err());
    assert!(b.await.unwrap().is_err());
}

#[tokio::test(start_paused = true)]
async fn zero_wait_newcomer_cannot_overtake_an_existing_due_head() {
    let clock = crate::ingress::invocation_limits::tests::ManualClock::new();
    let mut controlled = InvocationLimiter::with_clock(clock.clone());
    controlled.initialize_aggregate_limits(&BTreeMap::from([("jira".into(), limit(1, 10))]));
    let limiter = Arc::new(controlled);
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let a = spawn(&limiter, named(&limiter, "alice", rate, 20));
    queued(&limiter, 1).await;
    settle_tasks().await;
    clock.advance(Duration::from_secs(10));
    let Err(InvocationAdmissionError::RateLimited(rejected)) =
        limiter.admit(named(&limiter, "bob", rate, 0)).await
    else {
        panic!("the already due Alice request must receive the shared unit");
    };
    assert_eq!(rejected.scope, InvocationLimitScope::Service);
    assert!(a.await.unwrap().is_ok());
    let state = limiter.state.lock().unwrap();
    assert!(!state.keys.contains_key("bob"));
    assert_eq!(state.keys["alice"]["jira"].total, 1);
    assert_eq!(state.aggregate_windows["jira"].total, 1);
    assert_eq!(state.scheduler.next_ticket, 1);
}

#[tokio::test(start_paused = true)]
async fn an_old_refresh_cannot_act_on_a_recreated_personal_or_service_queue() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old_reads = Arc::new(AtomicUsize::new(0));
    let keepalive = Arc::new(());
    let weak = Arc::downgrade(&keepalive);
    let mut old = named(&limiter, "alice", rate, 30);
    old.resolve_limit = {
        let started = started.clone();
        let release = release.clone();
        let reads = old_reads.clone();
        Arc::new(move || {
            let started = started.clone();
            let release = release.clone();
            let reads = reads.clone();
            let keepalive = keepalive.clone();
            Box::pin(async move {
                let _keepalive = keepalive;
                if reads.fetch_add(1, Ordering::SeqCst) > 0 {
                    started.notify_one();
                    release.notified().await;
                }
                Ok(rate)
            })
        })
    };
    let cancellation = CancellationToken::new();
    old.cancellation = Arc::new(Cancellation(cancellation.clone()));
    let old = spawn(&limiter, old);
    queued(&limiter, 1).await;
    let old_generation = limiter.state.lock().unwrap().scheduler.services["jira"].driver_id;
    limiter.begin_update("alice", "jira").finish(true);
    started.notified().await;
    cancellation.cancel();
    assert!(matches!(
        old.await.unwrap(),
        Err(InvocationAdmissionError::Cancelled(_))
    ));
    assert!(
        weak.upgrade().is_some(),
        "the started read retains its owner"
    );
    assert!(limiter.state.lock().unwrap().scheduler.services.is_empty());
    let new_reads = Arc::new(AtomicUsize::new(0));
    let mut new = named(&limiter, "alice", rate, 30);
    new.resolve_limit = {
        let reads = new_reads.clone();
        Arc::new(move || {
            reads.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(rate) })
        })
    };
    let new = spawn(&limiter, new);
    queued(&limiter, 1).await;
    assert_ne!(
        limiter.state.lock().unwrap().scheduler.services["jira"].driver_id,
        old_generation
    );
    limiter.begin_update("alice", "jira").finish(true);
    settle_tasks().await;
    assert_eq!(
        new_reads.load(Ordering::SeqCst),
        1,
        "the new queue waits for the old key's refresh owner"
    );
    release.notify_one();
    settle_tasks().await;
    assert!(weak.upgrade().is_none());
    assert_eq!(old_reads.load(Ordering::SeqCst), 2);
    assert_eq!(new_reads.load(Ordering::SeqCst), 2);
    assert!(!new.is_finished());
    assert_eq!(shared_count(&limiter), 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(new.await.unwrap().is_ok());
    assert_eq!(shared_count(&limiter), 1);
}

#[tokio::test(start_paused = true)]
async fn peer_write_fence_moves_estimates_without_extending_any_deadline() {
    let limiter = capped(limit(1, 10));
    let rate = limit(10, 60);
    limiter
        .admit(named(&limiter, "seed", rate, 0))
        .await
        .unwrap();
    let a = spawn(&limiter, named(&limiter, "alice", rate, 60));
    queued(&limiter, 1).await;
    let b = spawn(&limiter, named(&limiter, "bob", rate, 60));
    queued(&limiter, 2).await;
    let deadline = limiter.state.lock().unwrap().scheduler.queues[&("bob".into(), "jira".into())]
        .entries[0]
        .ticket
        .rate_deadline;
    let before = limiter
        .observe(0, "bob", "jira", Duration::from_secs(60), resolver(rate))
        .await
        .unwrap();
    assert_eq!(before.invocations.next_admission_after_seconds, 30);
    let write = limiter.begin_update("alice", "jira");
    settle_tasks().await;
    let during = limiter
        .observe(0, "bob", "jira", Duration::from_secs(60), resolver(rate))
        .await
        .unwrap();
    assert_eq!(during.invocations.next_admission_after_seconds, 20);
    write.finish(false);
    settle_tasks().await;
    let after = limiter
        .observe(0, "bob", "jira", Duration::from_secs(60), resolver(rate))
        .await
        .unwrap();
    assert_eq!(after.invocations.next_admission_after_seconds, 30);
    assert_eq!(
        limiter.state.lock().unwrap().scheduler.queues[&("bob".into(), "jira".into())].entries[0]
            .ticket
            .rate_deadline,
        deadline
    );
    limiter.close();
    assert!(a.await.unwrap().is_err());
    assert!(b.await.unwrap().is_err());
}
