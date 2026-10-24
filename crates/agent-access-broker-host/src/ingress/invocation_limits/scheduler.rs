//! FIFO admission and pure observations share the rolling-history lock. Database
//! reads and timers always run outside it; publication and managed writes fence
//! the settings used by each atomic admission.
use super::*;
use agent_access_core::{InvocationDeadlineKind, format_retry_at};
use agent_access_provider::{ProviderError, ReasonCode};
use futures_util::future::BoxFuture;
use serde::Serialize;
use serde_json::json;
use tokio::sync::Notify;

type Key = (String, String);
pub(crate) type InvocationLimitResolver =
    Arc<dyn Fn() -> BoxFuture<'static, Result<InvocationLimit, ProviderError>> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionCancellationReason {
    ExplicitCancellation,
    OwnerAbandoned,
    RuntimePublished,
    Shutdown,
}

pub(crate) trait AdmissionCancellation: Send + Sync {
    fn reason(&self) -> Option<AdmissionCancellationReason>;
    fn cancelled(&self) -> BoxFuture<'_, AdmissionCancellationReason>;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionDeadline {
    pub at: Instant,
    pub kind: InvocationDeadlineKind,
}

pub(crate) struct InvocationAdmissionRequest {
    pub epoch: u64,
    pub principal: String,
    pub service: String,
    pub max_wait: Duration,
    pub hard_deadline: Option<AdmissionDeadline>,
    pub cancellation: Arc<dyn AdmissionCancellation>,
    pub resolve_limit: InvocationLimitResolver,
}

#[derive(Debug)]
pub(crate) struct InvocationAdmissionGrant {
    pub waited: bool,
    pub waited_milliseconds: u64,
}

#[derive(Debug)]
pub(crate) enum InvocationAdmissionError {
    RateLimited(InvocationRateLimited),
    Cancelled(AdmissionRemoval),
    Resolution {
        error: ProviderError,
        waited: bool,
        waited_milliseconds: u64,
    },
}

/// Only the scheduler can construct proof of removal before quota admission.
#[derive(Debug)]
pub(crate) struct AdmissionRemoval {
    reason: AdmissionCancellationReason,
    waited: bool,
    waited_milliseconds: u64,
}

impl AdmissionRemoval {
    pub(crate) fn reason(&self) -> AdmissionCancellationReason {
        self.reason
    }

    pub(crate) fn waited(&self) -> bool {
        self.waited
    }

    pub(crate) fn waited_milliseconds(&self) -> u64 {
        self.waited_milliseconds
    }

    pub(crate) fn into_provider_error(self) -> ProviderError {
        let cause = match self.reason() {
            AdmissionCancellationReason::ExplicitCancellation => "explicitly cancelled",
            AdmissionCancellationReason::OwnerAbandoned => "abandoned by its transport owner",
            AdmissionCancellationReason::RuntimePublished => {
                "cancelled because the broker configuration changed"
            }
            AdmissionCancellationReason::Shutdown => {
                "cancelled because the broker is shutting down"
            }
        };
        ProviderError::error(ReasonCode::OperationCancelled, format!(
            "Request {cause} before rate admission. It is no longer queued and did not execute. Resubmission cannot duplicate this request's effects."
        )).with_result(json!({"executionState":"not_dispatched", "retrySafe":true}))
          .with_audit(json!({"executionState":"not_dispatched", "retrySafe":true}))
    }
}

#[derive(Debug)]
pub(crate) enum InvocationObservationError {
    RuntimePublished,
    Resolution(ProviderError),
}

#[derive(Debug)]
pub(crate) struct InvocationObservation {
    pub instance_id: String,
    pub observed_at: String,
    pub invocations: InvocationObservationValues,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InvocationObservationValues {
    pub requests: u32,
    pub window_seconds: u32,
    pub max_wait_seconds: u64,
    pub counted_requests: u64,
    pub queued_requests: u64,
    pub available_immediately: u32,
    pub next_admission_after_seconds: u64,
    pub next_admission_at: String,
}

#[derive(Default)]
pub(super) struct SchedulerState {
    epoch: u64,
    closed: bool,
    next_ticket: u64,
    settings: HashMap<Key, Settings>,
    queues: HashMap<Key, Queue>,
}

impl SchedulerState {
    pub(super) fn prune_settings(&mut self, history: &HashMap<String, HashMap<String, KeyWindow>>) {
        self.settings.retain(|key, settings| {
            settings.changing != 0
                || Arc::strong_count(&settings.identity) > 1
                || self.queues.contains_key(key)
                || history
                    .get(&key.0)
                    .is_some_and(|services| services.contains_key(&key.1))
        });
    }
}

struct Settings {
    identity: Arc<()>,
    revision: u64,
    changing: usize,
    cached: Option<(u64, InvocationLimit)>,
    notify: Arc<Notify>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            identity: Arc::new(()),
            revision: 0,
            changing: 0,
            cached: None,
            notify: Arc::new(Notify::new()),
        }
    }
}

struct Queue {
    entries: VecDeque<Queued>,
    revision: u64,
    dirty: bool,
    driver_id: u64,
    limit: InvocationLimit,
}

#[derive(Clone)]
struct Queued {
    ticket: Arc<Ticket>,
    opportunity_ns: u64,
}

struct Ticket {
    id: u64,
    epoch: u64,
    service: String,
    enqueued: Instant,
    rate_deadline: Instant,
    max_wait: Duration,
    hard_deadline: Option<AdmissionDeadline>,
    cancellation: Arc<dyn AdmissionCancellation>,
    resolver: InvocationLimitResolver,
    outcome: Mutex<Option<Result<InvocationAdmissionGrant, InvocationAdmissionError>>>,
    notify: Notify,
}

impl Ticket {
    fn finish(&self, result: Result<InvocationAdmissionGrant, InvocationAdmissionError>) {
        let mut outcome = self.outcome.lock().unwrap();
        debug_assert!(outcome.is_none(), "admission finalized twice");
        *outcome = Some(result);
        self.notify.notify_one();
    }

    fn removal(&self, reason: AdmissionCancellationReason) -> AdmissionRemoval {
        AdmissionRemoval {
            reason,
            waited: true,
            waited_milliseconds: milliseconds(self.enqueued.elapsed()),
        }
    }
}

struct Resolved<'a> {
    limit: InvocationLimit,
    revision: u64,
    lease: SettingsReadLease<'a>,
}

/// A read retains its identity until commit or cancellation. Cleanup runs for
/// successful, failed and dropped futures, without allowing revision ABA.
struct SettingsReadLease<'a> {
    limiter: &'a InvocationLimiter,
    key: Key,
    identity: Arc<()>,
}

impl Drop for SettingsReadLease<'_> {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock().unwrap();
        if !state
            .keys
            .get(&self.key.0)
            .is_some_and(|services| services.contains_key(&self.key.1))
            && !state.scheduler.queues.contains_key(&self.key)
            && state
                .scheduler
                .settings
                .get(&self.key)
                .is_some_and(|settings| {
                    settings.changing == 0
                        && Arc::ptr_eq(&settings.identity, &self.identity)
                        && Arc::strong_count(&settings.identity) == 2
                })
        {
            state.scheduler.settings.remove(&self.key);
        }
    }
}

impl InvocationLimiter {
    pub(crate) fn runtime_epoch<F: FnOnce() -> bool>(
        &self,
        check_current: F,
    ) -> Result<u64, AdmissionRemoval> {
        let state = self.state.lock().unwrap();
        let reason = if state.scheduler.closed {
            Some(AdmissionCancellationReason::Shutdown)
        } else if !check_current() {
            Some(AdmissionCancellationReason::RuntimePublished)
        } else {
            None
        };
        match reason {
            Some(reason) => Err(AdmissionRemoval {
                reason,
                waited: false,
                waited_milliseconds: 0,
            }),
            None => Ok(state.scheduler.epoch),
        }
    }

    pub(crate) fn publish_runtime<F: FnOnce(u64)>(&self, publish: F) {
        let mut state = self.state.lock().unwrap();
        state.scheduler.epoch = state
            .scheduler
            .epoch
            .checked_add(1)
            .expect("runtime generation exhausted");
        publish(state.scheduler.epoch);
        invalidate_pending(
            &mut state.scheduler,
            AdmissionCancellationReason::RuntimePublished,
        );
        for settings in state.scheduler.settings.values_mut() {
            settings.cached = None;
            settings.notify.notify_waiters();
        }
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.scheduler.closed = true;
        invalidate_pending(&mut state.scheduler, AdmissionCancellationReason::Shutdown);
        for settings in state.scheduler.settings.values() {
            settings.notify.notify_waiters();
        }
    }

    pub(crate) fn begin_update(
        self: &Arc<Self>,
        principal: &str,
        service: &str,
    ) -> InvocationLimitUpdate {
        let key = (principal.to_owned(), service.to_owned());
        let mut state = self.state.lock().unwrap();
        state
            .scheduler
            .settings
            .entry(key.clone())
            .or_default()
            .changing += 1;
        InvocationLimitUpdate {
            limiter: self.clone(),
            key,
            finished: false,
        }
    }

    async fn resolve(
        &self,
        epoch: u64,
        key: &Key,
        resolver: &InvocationLimitResolver,
    ) -> Result<Resolved<'_>, InvocationAdmissionError> {
        loop {
            let (identity, revision, changing, cached, notify) = {
                let mut state = self.state.lock().unwrap();
                check_epoch(&state.scheduler, epoch)?;
                let settings = state.scheduler.settings.entry(key.clone()).or_default();
                (
                    settings.identity.clone(),
                    settings.revision,
                    settings.changing != 0,
                    settings
                        .cached
                        .filter(|(cached_epoch, _)| *cached_epoch == epoch)
                        .map(|(_, limit)| limit),
                    settings.notify.clone(),
                )
            };
            let lease = SettingsReadLease {
                limiter: self,
                key: key.clone(),
                identity,
            };
            // Enable the waiter before checking the revision again: notifications
            // cannot be lost between clearing a write fence and awaiting it.
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if changing {
                let still_changing = {
                    let state = self.state.lock().unwrap();
                    check_epoch(&state.scheduler, epoch)?;
                    state
                        .scheduler
                        .settings
                        .get(key)
                        .is_some_and(|s| s.changing != 0)
                };
                if still_changing {
                    changed.await;
                }
                continue;
            }
            if let Some(limit) = cached {
                return Ok(Resolved {
                    limit,
                    revision,
                    lease,
                });
            }
            let result = resolver().await;
            let mut state = self.state.lock().unwrap();
            check_epoch(&state.scheduler, epoch)?;
            let settings = state
                .scheduler
                .settings
                .get_mut(key)
                .expect("active settings read retains its fence");
            if !Arc::ptr_eq(&settings.identity, &lease.identity)
                || settings.revision != revision
                || settings.changing != 0
            {
                continue;
            }
            let limit = result.map_err(|error| InvocationAdmissionError::Resolution {
                error,
                waited: false,
                waited_milliseconds: 0,
            })?;
            settings.cached = Some((epoch, limit));
            return Ok(Resolved {
                limit,
                revision,
                lease,
            });
        }
    }

    pub(crate) async fn admit(
        self: &Arc<Self>,
        request: InvocationAdmissionRequest,
    ) -> Result<InvocationAdmissionGrant, InvocationAdmissionError> {
        let key = (request.principal.clone(), request.service.clone());
        loop {
            if let Some(reason) = request.cancellation.reason() {
                return Err(cancelled(reason));
            }
            let resolved = self
                .resolve(request.epoch, &key, &request.resolve_limit)
                .await?;
            let ticket = {
                let mut state = self.state.lock().unwrap();
                check_epoch(&state.scheduler, request.epoch)?;
                if let Some(reason) = request.cancellation.reason() {
                    return Err(cancelled(reason));
                }
                if !settings_current(&state.scheduler, &key, &resolved) {
                    continue;
                }
                let now = Instant::now();
                let now_ns = duration_ns(self.clock.monotonic());
                self.process(
                    &mut state,
                    &key,
                    resolved.limit,
                    resolved.revision,
                    now,
                    now_ns,
                );
                let projection = project(&state, &key, resolved.limit, now, now_ns);
                let deadline = request.hard_deadline;
                if projection.next_ns == now_ns && deadline.is_none_or(|bound| now < bound.at) {
                    record(&mut state, &key, resolved.limit, now_ns);
                    return Ok(InvocationAdmissionGrant {
                        waited: false,
                        waited_milliseconds: 0,
                    });
                }
                let rate_deadline = now
                    .checked_add(request.max_wait)
                    .expect("validated max_wait deadline");
                let opportunity = instant_for(now, now_ns, projection.next_ns);
                if request.max_wait.is_zero()
                    || opportunity > rate_deadline
                    || deadline.is_some_and(|bound| opportunity >= bound.at || now >= bound.at)
                {
                    return Err(InvocationAdmissionError::RateLimited(self.rejection(
                        &request.service,
                        resolved.limit,
                        request.max_wait,
                        now,
                        rate_deadline,
                        deadline,
                        false,
                        projection.queued,
                        projection.next_ns,
                        now,
                        now_ns,
                    )));
                }
                state.scheduler.next_ticket = state
                    .scheduler
                    .next_ticket
                    .checked_add(1)
                    .expect("ticket sequence exhausted");
                let ticket = Arc::new(Ticket {
                    id: state.scheduler.next_ticket,
                    epoch: request.epoch,
                    service: request.service.clone(),
                    enqueued: now,
                    rate_deadline,
                    max_wait: request.max_wait,
                    hard_deadline: deadline,
                    cancellation: request.cancellation.clone(),
                    resolver: request.resolve_limit.clone(),
                    outcome: Mutex::new(None),
                    notify: Notify::new(),
                });
                let start_driver = !state.scheduler.queues.contains_key(&key);
                state
                    .scheduler
                    .queues
                    .entry(key.clone())
                    .or_insert_with(|| Queue {
                        entries: VecDeque::new(),
                        revision: resolved.revision,
                        dirty: false,
                        driver_id: ticket.id,
                        limit: resolved.limit,
                    })
                    .entries
                    .push_back(Queued {
                        ticket: ticket.clone(),
                        opportunity_ns: projection.next_ns,
                    });
                let notify = state.scheduler.settings[&key].notify.clone();
                notify.notify_waiters();
                if start_driver {
                    let limiter = self.clone();
                    let driver_key = key.clone();
                    let driver_id = ticket.id;
                    tokio::spawn(async move {
                        limiter.drive(driver_key, notify, driver_id).await;
                    });
                }
                ticket
            };
            let _guard = PendingGuard {
                limiter: self.clone(),
                key: key.clone(),
                id: ticket.id,
            };
            loop {
                if let Some(outcome) = ticket.outcome.lock().unwrap().take() {
                    return outcome;
                }
                tokio::select! {
                    _ = ticket.notify.notified() => {}
                    reason = request.cancellation.cancelled() => { self.remove(&key, ticket.id, reason); }
                }
            }
        }
    }

    async fn drive(self: Arc<Self>, key: Key, notify: Arc<Notify>, driver_id: u64) {
        loop {
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let pending = {
                let state = self.state.lock().unwrap();
                state
                    .scheduler
                    .queues
                    .get(&key)
                    .filter(|queue| queue.driver_id == driver_id)
                    .and_then(|queue| {
                        queue.entries.front().map(|entry| {
                            (
                                entry.ticket.clone(),
                                queue
                                    .entries
                                    .iter()
                                    .filter_map(|entry| {
                                        entry.ticket.hard_deadline.map(|bound| bound.at)
                                    })
                                    .min(),
                            )
                        })
                    })
            };
            let resolved = {
                let Some((first, mut hard_deadline)) = pending else {
                    return;
                };
                let resolving = self.resolve(first.epoch, &key, &first.resolver);
                tokio::pin!(resolving);
                // A managed read may own a noncancelable blocking worker. Keep its
                // resolver (and request-permit keepalive) until that read returns,
                // while still delivering queue cancellation/deadline outcomes.
                loop {
                    tokio::select! {
                        result = &mut resolving => break result,
                        _ = &mut changed => {},
                        _ = async { match hard_deadline { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending::<()>().await } } => {
                            self.expire_hard_deadlines(&key, driver_id);
                        }
                    }
                    changed.set(notify.notified());
                    changed.as_mut().enable();
                    hard_deadline = self
                        .state
                        .lock()
                        .unwrap()
                        .scheduler
                        .queues
                        .get(&key)
                        .filter(|queue| queue.driver_id == driver_id)
                        .and_then(|queue| {
                            queue
                                .entries
                                .iter()
                                .filter_map(|entry| {
                                    entry.ticket.hard_deadline.map(|bound| bound.at)
                                })
                                .min()
                        });
                }
            };
            let resolved = match resolved {
                Ok(resolved) => resolved,
                Err(error) => {
                    let mut state = self.state.lock().unwrap();
                    if !state
                        .scheduler
                        .queues
                        .get(&key)
                        .is_some_and(|queue| queue.driver_id == driver_id)
                    {
                        return;
                    }
                    if let Some(queue) = state.scheduler.queues.remove(&key) {
                        // Resolution errors are cloned as the provider type is cloneable.
                        for entry in queue.entries {
                            let error = match &error {
                                InvocationAdmissionError::Resolution { error, .. } => {
                                    InvocationAdmissionError::Resolution {
                                        error: error.clone(),
                                        waited: true,
                                        waited_milliseconds: milliseconds(
                                            entry.ticket.enqueued.elapsed(),
                                        ),
                                    }
                                }
                                InvocationAdmissionError::Cancelled(removal) => {
                                    InvocationAdmissionError::Cancelled(
                                        entry.ticket.removal(removal.reason),
                                    )
                                }
                                InvocationAdmissionError::RateLimited(_) => unreachable!(),
                            };
                            entry.ticket.finish(Err(error));
                        }
                    }
                    return;
                }
            };
            let wake = {
                let mut state = self.state.lock().unwrap();
                if !state
                    .scheduler
                    .queues
                    .get(&key)
                    .is_some_and(|queue| queue.driver_id == driver_id)
                {
                    return;
                }
                if !settings_current(&state.scheduler, &key, &resolved) {
                    continue;
                }
                let now = Instant::now();
                let now_ns = duration_ns(self.clock.monotonic());
                self.process(
                    &mut state,
                    &key,
                    resolved.limit,
                    resolved.revision,
                    now,
                    now_ns,
                );
                let Some(queue) = state.scheduler.queues.get(&key) else {
                    return;
                };
                queue
                    .entries
                    .iter()
                    .map(|entry| {
                        let opportunity = instant_for(now, now_ns, entry.opportunity_ns);
                        entry
                            .ticket
                            .hard_deadline
                            .map_or(opportunity, |bound| opportunity.min(bound.at))
                    })
                    .min()
                    .expect("nonempty active queue")
            };
            tokio::select! { _ = &mut changed => {}, _ = tokio::time::sleep_until(wake) => {} }
        }
    }

    fn remove(&self, key: &Key, id: u64, reason: AdmissionCancellationReason) {
        let mut state = self.state.lock().unwrap();
        let Some(queue) = state.scheduler.queues.get_mut(key) else {
            return;
        };
        if let Some(index) = queue.entries.iter().position(|entry| entry.ticket.id == id) {
            let entry = queue.entries.remove(index).unwrap();
            queue.dirty = true;
            entry.ticket.finish(Err(InvocationAdmissionError::Cancelled(
                entry.ticket.removal(reason),
            )));
            if queue.entries.is_empty() {
                state.scheduler.queues.remove(key);
            }
            state.scheduler.settings[key].notify.notify_waiters();
        }
    }

    /// A database read/write fence may delay refreshed rate settings, but it
    /// cannot extend a request's absolute transport deadline.
    fn expire_hard_deadlines(&self, key: &Key, driver_id: u64) {
        let mut state = self.state.lock().unwrap();
        if !state
            .scheduler
            .queues
            .get(key)
            .is_some_and(|queue| queue.driver_id == driver_id)
        {
            return;
        }
        let mut queue = state.scheduler.queues.remove(key).unwrap();
        let now = Instant::now();
        let now_ns = duration_ns(self.clock.monotonic());
        let limit = queue.limit;
        let mut expired = Vec::new();
        queue.entries.retain(|entry| {
            if entry
                .ticket
                .hard_deadline
                .is_some_and(|bound| now >= bound.at)
            {
                expired.push(entry.ticket.clone());
                false
            } else {
                true
            }
        });
        queue.dirty |= !expired.is_empty();
        if !queue.entries.is_empty() {
            state.scheduler.queues.insert(key.clone(), queue);
        }
        let projection = project(&state, key, limit, now, now_ns);
        for ticket in expired {
            let rejection = self.rejection(
                &ticket.service,
                limit,
                ticket.max_wait,
                ticket.enqueued,
                ticket.rate_deadline,
                ticket.hard_deadline,
                true,
                projection.queued,
                projection.next_ns,
                now,
                now_ns,
            );
            ticket.finish(Err(InvocationAdmissionError::RateLimited(rejection)));
        }
    }

    fn process(
        &self,
        state: &mut LimiterState,
        key: &Key,
        limit: InvocationLimit,
        revision: u64,
        now: Instant,
        now_ns: u64,
    ) {
        let Some(mut queue) = state.scheduler.queues.remove(key) else {
            return;
        };
        queue.limit = limit;
        if queue.revision != revision {
            queue.dirty = true;
            queue.revision = revision;
        }
        let mut refused = Vec::new();
        queue.entries.retain(|entry| {
            if let Some(reason) = entry.ticket.cancellation.reason() {
                entry.ticket.finish(Err(InvocationAdmissionError::Cancelled(
                    entry.ticket.removal(reason),
                )));
                queue.dirty = true;
                false
            } else if entry
                .ticket
                .hard_deadline
                .is_some_and(|bound| now >= bound.at)
            {
                refused.push(entry.ticket.clone());
                queue.dirty = true;
                false
            } else {
                true
            }
        });
        if queue.dirty {
            reforecast(state, key, &mut queue, limit, now, now_ns, &mut refused);
        }
        // Preserve every pre-batch opportunity until ALL due FIFO heads have
        // been evaluated. A late first grant must not invalidate its siblings.
        let mut granted = false;
        while queue
            .entries
            .front()
            .is_some_and(|entry| entry.opportunity_ns <= now_ns)
        {
            let window = window_copy(state, key, limit, now_ns);
            if window.total >= u64::from(limit.requests()) {
                break;
            }
            let entry = queue.entries.pop_front().unwrap();
            // Cancellation can arrive concurrently with the preceding checks.
            if let Some(reason) = entry.ticket.cancellation.reason() {
                entry.ticket.finish(Err(InvocationAdmissionError::Cancelled(
                    entry.ticket.removal(reason),
                )));
                queue.dirty = true;
                break;
            }
            if entry
                .ticket
                .hard_deadline
                .is_some_and(|bound| Instant::now() >= bound.at)
            {
                refused.push(entry.ticket);
                queue.dirty = true;
                break;
            }
            let actual_ns = duration_ns(self.clock.monotonic());
            record(state, key, limit, actual_ns);
            entry.ticket.finish(Ok(InvocationAdmissionGrant {
                waited: true,
                waited_milliseconds: milliseconds(entry.ticket.enqueued.elapsed()),
            }));
            granted = true;
        }
        if granted || queue.dirty {
            let actual_now = Instant::now();
            let actual_ns = duration_ns(self.clock.monotonic());
            reforecast(
                state,
                key,
                &mut queue,
                limit,
                actual_now,
                actual_ns,
                &mut refused,
            );
        }
        if !queue.entries.is_empty() {
            state.scheduler.queues.insert(key.clone(), queue);
        }
        let projection = project(state, key, limit, now, now_ns);
        for ticket in refused {
            let rejection = self.rejection(
                &ticket.service,
                limit,
                ticket.max_wait,
                ticket.enqueued,
                ticket.rate_deadline,
                ticket.hard_deadline,
                true,
                projection.queued,
                projection.next_ns,
                now,
                now_ns,
            );
            ticket.finish(Err(InvocationAdmissionError::RateLimited(rejection)));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rejection(
        &self,
        service: &str,
        limit: InvocationLimit,
        max_wait: Duration,
        enqueued: Instant,
        rate_deadline: Instant,
        hard_deadline: Option<AdmissionDeadline>,
        was_queued: bool,
        queued: u64,
        next_ns: u64,
        now: Instant,
        now_ns: u64,
    ) -> InvocationRateLimited {
        let bound = hard_deadline
            .filter(|bound| bound.at <= rate_deadline || (was_queued && now >= bound.at))
            .unwrap_or(AdmissionDeadline {
                at: rate_deadline,
                kind: InvocationDeadlineKind::RateWait,
            });
        let seconds = next_ns
            .saturating_sub(now_ns)
            .div_ceil(NANOS_PER_SECOND)
            .max(1);
        InvocationRateLimited {
            service: service.to_owned(),
            limit,
            retry_after_seconds: seconds,
            retry_at: retry_at(self.clock.wall(), seconds),
            max_wait_seconds: max_wait.as_secs(),
            queued_requests: queued,
            deadline_kind: bound.kind,
            waited_milliseconds: milliseconds(now.saturating_duration_since(enqueued)),
            remaining_wait_milliseconds: milliseconds(bound.at.saturating_duration_since(now)),
            was_queued,
        }
    }

    pub(crate) async fn observe(
        &self,
        epoch: u64,
        principal: &str,
        service: &str,
        max_wait: Duration,
        resolver: InvocationLimitResolver,
    ) -> Result<InvocationObservation, InvocationObservationError> {
        let key = (principal.to_owned(), service.to_owned());
        loop {
            let resolved =
                self.resolve(epoch, &key, &resolver)
                    .await
                    .map_err(|error| match error {
                        InvocationAdmissionError::Resolution { error, .. } => {
                            InvocationObservationError::Resolution(error)
                        }
                        _ => InvocationObservationError::RuntimePublished,
                    })?;
            let state = self.state.lock().unwrap();
            check_epoch(&state.scheduler, epoch)
                .map_err(|_| InvocationObservationError::RuntimePublished)?;
            if !settings_current(&state.scheduler, &key, &resolved) {
                continue;
            }
            let now = Instant::now();
            let now_ns = duration_ns(self.clock.monotonic());
            let wall = self.clock.wall();
            let projection = project(&state, &key, resolved.limit, now, now_ns);
            let seconds = projection
                .next_ns
                .saturating_sub(now_ns)
                .div_ceil(NANOS_PER_SECOND);
            let observation = InvocationObservation {
                instance_id: self.instance_id.clone(),
                observed_at: wall.to_rfc3339(),
                invocations: InvocationObservationValues {
                    requests: resolved.limit.requests(),
                    window_seconds: resolved.limit.window_seconds(),
                    max_wait_seconds: max_wait.as_secs(),
                    counted_requests: projection.counted,
                    queued_requests: projection.queued,
                    available_immediately: projection.available,
                    next_admission_after_seconds: seconds,
                    next_admission_at: if seconds == 0 {
                        wall.to_rfc3339()
                    } else {
                        format_retry_at(retry_at(wall, seconds))
                    },
                },
            };
            drop(state);
            return Ok(observation);
        }
    }
}

pub(crate) struct InvocationLimitUpdate {
    limiter: Arc<InvocationLimiter>,
    key: Key,
    finished: bool,
}
impl InvocationLimitUpdate {
    pub(crate) fn finish(mut self, success: bool) {
        self.complete(success);
    }
    fn complete(&mut self, success: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut state = self.limiter.state.lock().unwrap();
        let settings = state
            .scheduler
            .settings
            .get_mut(&self.key)
            .expect("write fence exists");
        settings.changing -= 1;
        if success {
            settings.revision = settings
                .revision
                .checked_add(1)
                .expect("settings revision exhausted");
            settings.cached = None;
        }
        settings.notify.notify_waiters();
        // A read may have been abandoned while this write kept its fence
        // alive. The final writer also retires an otherwise unused key.
        if !state
            .keys
            .get(&self.key.0)
            .is_some_and(|services| services.contains_key(&self.key.1))
            && !state.scheduler.queues.contains_key(&self.key)
            && state
                .scheduler
                .settings
                .get(&self.key)
                .is_some_and(|settings| {
                    settings.changing == 0 && Arc::strong_count(&settings.identity) == 1
                })
        {
            state.scheduler.settings.remove(&self.key);
        }
    }
}
impl Drop for InvocationLimitUpdate {
    fn drop(&mut self) {
        self.complete(false);
    }
}
struct PendingGuard {
    limiter: Arc<InvocationLimiter>,
    key: Key,
    id: u64,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.limiter.remove(
            &self.key,
            self.id,
            AdmissionCancellationReason::OwnerAbandoned,
        );
    }
}

fn check_epoch(state: &SchedulerState, epoch: u64) -> Result<(), InvocationAdmissionError> {
    if state.closed {
        Err(cancelled(AdmissionCancellationReason::Shutdown))
    } else if state.epoch != epoch {
        Err(cancelled(AdmissionCancellationReason::RuntimePublished))
    } else {
        Ok(())
    }
}
fn cancelled(reason: AdmissionCancellationReason) -> InvocationAdmissionError {
    InvocationAdmissionError::Cancelled(AdmissionRemoval {
        reason,
        waited: false,
        waited_milliseconds: 0,
    })
}
fn settings_current(state: &SchedulerState, key: &Key, resolved: &Resolved) -> bool {
    state.settings.get(key).is_some_and(|s| {
        s.changing == 0
            && s.revision == resolved.revision
            && Arc::ptr_eq(&s.identity, &resolved.lease.identity)
    })
}
fn invalidate_pending(state: &mut SchedulerState, reason: AdmissionCancellationReason) {
    for (_, queue) in state.queues.drain() {
        for entry in queue.entries {
            entry.ticket.finish(Err(InvocationAdmissionError::Cancelled(
                entry.ticket.removal(reason),
            )));
        }
    }
}
fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
fn instant_for(now: Instant, now_ns: u64, at_ns: u64) -> Instant {
    now + Duration::from_nanos(at_ns.saturating_sub(now_ns))
}
fn window_copy(state: &LimiterState, key: &Key, limit: InvocationLimit, now_ns: u64) -> KeyWindow {
    let window_ns = u64::from(limit.window_seconds()) * NANOS_PER_SECOND;
    let mut window = state
        .keys
        .get(&key.0)
        .and_then(|services| services.get(&key.1))
        .filter(|window| window.window_ns == window_ns)
        .cloned()
        .unwrap_or_else(|| KeyWindow::new(window_ns));
    window.expire(now_ns);
    window
}
fn record(state: &mut LimiterState, key: &Key, limit: InvocationLimit, now_ns: u64) {
    state.maybe_sweep(now_ns);
    let window_ns = u64::from(limit.window_seconds()) * NANOS_PER_SECOND;
    let window = state.window_mut(&key.0, &key.1, window_ns);
    if window.window_ns != window_ns {
        *window = KeyWindow::new(window_ns);
    }
    window.expire(now_ns);
    window.record(now_ns);
}
fn next_capacity(window: &mut KeyWindow, requests: u32, cursor: u64) -> u64 {
    window.expire(cursor);
    if window.total < u64::from(requests) {
        cursor
    } else {
        cursor.saturating_add(window.wait_ns(requests, cursor))
    }
}
fn fits(ticket: &Ticket, opportunity: Instant, now: Instant) -> bool {
    opportunity <= ticket.rate_deadline
        && ticket
            .hard_deadline
            .is_none_or(|bound| opportunity < bound.at && now < bound.at)
}
fn reforecast(
    state: &LimiterState,
    key: &Key,
    queue: &mut Queue,
    limit: InvocationLimit,
    now: Instant,
    now_ns: u64,
    refused: &mut Vec<Arc<Ticket>>,
) {
    let mut window = window_copy(state, key, limit, now_ns);
    let mut cursor = now_ns;
    queue.entries.retain_mut(|entry| {
        let opportunity_ns = next_capacity(&mut window, limit.requests(), cursor);
        if !fits(&entry.ticket, instant_for(now, now_ns, opportunity_ns), now) {
            refused.push(entry.ticket.clone());
            return false;
        }
        entry.opportunity_ns = opportunity_ns;
        window.expire(opportunity_ns);
        window.record(opportunity_ns);
        cursor = opportunity_ns;
        true
    });
    queue.dirty = false;
}
struct Projection {
    counted: u64,
    queued: u64,
    available: u32,
    next_ns: u64,
}
fn project(
    state: &LimiterState,
    key: &Key,
    limit: InvocationLimit,
    now: Instant,
    now_ns: u64,
) -> Projection {
    let mut window = window_copy(state, key, limit, now_ns);
    let counted = window.total;
    let mut cursor = now_ns;
    let mut queued = 0;
    if let Some(queue) = state.scheduler.queues.get(key) {
        let mut invalidated = queue.dirty
            || state
                .scheduler
                .settings
                .get(key)
                .is_some_and(|settings| settings.revision != queue.revision)
            || queue.entries.iter().any(|entry| {
                entry.ticket.cancellation.reason().is_some()
                    || entry
                        .ticket
                        .hard_deadline
                        .is_some_and(|bound| now >= bound.at)
            });
        for entry in &queue.entries {
            if entry.ticket.cancellation.reason().is_some()
                || entry
                    .ticket
                    .hard_deadline
                    .is_some_and(|bound| now >= bound.at)
            {
                invalidated = true;
                continue;
            }
            let at_ns = next_capacity(&mut window, limit.requests(), cursor);
            let valid_due = !invalidated && entry.opportunity_ns <= now_ns && at_ns == now_ns;
            if !valid_due && !fits(&entry.ticket, instant_for(now, now_ns, at_ns), now) {
                invalidated = true;
                continue;
            }
            window.expire(at_ns);
            window.record(at_ns);
            cursor = at_ns;
            queued += 1;
        }
    }
    let available = if cursor == now_ns {
        u64::from(limit.requests()).saturating_sub(window.total) as u32
    } else {
        0
    };
    let next_ns = next_capacity(&mut window, limit.requests(), cursor);
    Projection {
        counted,
        queued,
        available,
        next_ns,
    }
}

#[cfg(test)]
mod tests;
