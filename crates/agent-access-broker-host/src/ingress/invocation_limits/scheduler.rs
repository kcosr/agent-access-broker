//! FIFO admission and pure observations share the rolling-history lock. Database
//! reads and timers always run outside it; publication and managed writes fence
//! the settings used by each atomic admission.
use super::*;
use agent_access_core::{InvocationDeadlineKind, format_retry_at};

mod driver;
mod forecast;
mod settings;
use agent_access_provider::{ProviderError, ReasonCode};
use forecast::{Projection, forecast_existing, project};
use futures_util::future::BoxFuture;
use serde::Serialize;
use serde_json::json;
pub(crate) use settings::InvocationLimitUpdate;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

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
    /// The request expired before its effective rate was resolved. No rate
    /// pair or queue forecast is available for a rate-limited response.
    Deadline(InvocationDeadlineKind),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_scope: Option<InvocationLimitScope>,
}

#[derive(Default)]
pub(super) struct SchedulerState {
    epoch: u64,
    closed: bool,
    next_ticket: u64,
    settings: HashMap<Key, Settings>,
    queues: HashMap<Key, Queue>,
    services: HashMap<String, ServiceQueue>,
}

impl SchedulerState {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    pub(super) fn prune_settings(&mut self, history: &HashMap<String, HashMap<String, KeyWindow>>) {
        self.settings.retain(|key, settings| {
            settings.changing != 0
                || Arc::strong_count(&settings.identity) > 1
                || settings.refreshing.is_some()
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
    refreshing: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            identity: Arc::new(()),
            revision: 0,
            changing: 0,
            cached: None,
            notify: Arc::new(Notify::new()),
            refreshing: None,
        }
    }
}

struct ServiceQueue {
    ring: VecDeque<String>,
    driver_id: u64,
    notify: Arc<Notify>,
}

struct Queue {
    entries: VecDeque<Queued>,
    revision: u64,
    driver_id: u64,
    limit: InvocationLimit,
    refresh_stop: CancellationToken,
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

struct Resolved {
    limit: InvocationLimit,
    revision: u64,
    lease: SettingsReadLease,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResolutionPurpose {
    NewAdmission,
    Observation,
    QueueWake,
}

/// A read retains its identity until commit or cancellation. Cleanup runs for
/// successful, failed and dropped futures, without allowing revision ABA.
struct SettingsReadLease {
    limiter: Arc<InvocationLimiter>,
    key: Key,
    identity: Arc<()>,
}

impl Drop for SettingsReadLease {
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
                        && settings.refreshing.is_none()
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

    pub(crate) fn publish_runtime<F: FnOnce(u64)>(
        &self,
        aggregate: &BTreeMap<String, InvocationLimit>,
        publish: F,
    ) {
        let mut state = self.state.lock().unwrap();
        state.scheduler.epoch = state
            .scheduler
            .epoch
            .checked_add(1)
            .expect("runtime generation exhausted");
        state.install_aggregate_limits(aggregate);
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
        notify_service(&state.scheduler, service);
        InvocationLimitUpdate {
            limiter: self.clone(),
            key,
            finished: false,
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
            if let Some(deadline) = request.hard_deadline
                && Instant::now() >= deadline.at
            {
                return Err(InvocationAdmissionError::Deadline(deadline.kind));
            }
            let resolved = self.resolve_initial(&key, &request).await?;
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
                if let Some(deadline) = request.hard_deadline
                    && now >= deadline.at
                {
                    return Err(InvocationAdmissionError::Deadline(deadline.kind));
                }
                // Previously accepted due work wins before a newcomer joins
                // the ring, including a newcomer with zero waiting budget.
                // Time/cancellation may advance during a projection; commit
                // its simulated settlement before deciding the new request.
                let (now, now_ns, projection) = loop {
                    self.process_service(
                        &mut state,
                        &key.1,
                        Instant::now(),
                        duration_ns(self.clock.monotonic()),
                    );
                    let now = Instant::now();
                    let now_ns = duration_ns(self.clock.monotonic());
                    let projection = project(&state, &key, resolved.limit, now, now_ns);
                    if !projection.requires_settlement {
                        break (now, now_ns, projection);
                    }
                };
                let rate_deadline = now
                    .checked_add(request.max_wait)
                    .expect("validated max_wait deadline");
                let opportunity = instant_for(now, now_ns, projection.next_ns);
                if let Some(reason) = request.cancellation.reason() {
                    return Err(cancelled(reason));
                }
                if let Some(deadline) = request.hard_deadline
                    && Instant::now() >= deadline.at
                {
                    return Err(InvocationAdmissionError::Deadline(deadline.kind));
                }
                if projection.next_ns == now_ns {
                    // The trial used the same FIFO/ring arbitration as the
                    // driver. It cannot evict any peer unless accepted here.
                    record(&mut state, &key, resolved.limit, now_ns);
                    self.process_service(
                        &mut state,
                        &key.1,
                        Instant::now(),
                        duration_ns(self.clock.monotonic()),
                    );
                    return Ok(InvocationAdmissionGrant {
                        waited: false,
                        waited_milliseconds: 0,
                    });
                }
                if request.max_wait.is_zero()
                    || opportunity > rate_deadline
                    || request
                        .hard_deadline
                        .is_some_and(|bound| opportunity >= bound.at)
                {
                    return Err(InvocationAdmissionError::RateLimited(self.rejection(
                        &key.1,
                        &projection,
                        request.max_wait,
                        now,
                        rate_deadline,
                        request.hard_deadline,
                        false,
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
                    service: key.1.clone(),
                    enqueued: now,
                    rate_deadline,
                    max_wait: request.max_wait,
                    hard_deadline: request.hard_deadline,
                    cancellation: request.cancellation.clone(),
                    resolver: request.resolve_limit.clone(),
                    outcome: Mutex::new(None),
                    notify: Notify::new(),
                });
                let start_key = !state.scheduler.queues.contains_key(&key);
                let start_service = !state.scheduler.services.contains_key(&key.1);
                if start_key {
                    state
                        .scheduler
                        .services
                        .entry(key.1.clone())
                        .or_insert_with(|| ServiceQueue {
                            ring: VecDeque::new(),
                            driver_id: ticket.id,
                            notify: Arc::new(Notify::new()),
                        })
                        .ring
                        .push_back(key.0.clone());
                }
                state
                    .scheduler
                    .queues
                    .entry(key.clone())
                    .or_insert_with(|| Queue {
                        entries: VecDeque::new(),
                        revision: resolved.revision,
                        driver_id: ticket.id,
                        limit: resolved.limit,
                        refresh_stop: CancellationToken::new(),
                    })
                    .entries
                    .push_back(Queued {
                        ticket: ticket.clone(),
                        opportunity_ns: projection.next_ns,
                    });
                // Commit acceptance and any resulting peer displacement in
                // this same critical section. An infeasible trial never gets
                // here and therefore never removes an accepted peer.
                self.process_service(&mut state, &key.1, now, now_ns);
                if start_key && state.scheduler.queues.contains_key(&key) {
                    let limiter = self.clone();
                    let driver_key = key.clone();
                    let driver_id = ticket.id;
                    let notify = state.scheduler.settings[&key].notify.clone();
                    tokio::spawn(async move {
                        limiter.refresh_key(driver_key, notify, driver_id).await;
                    });
                }
                if start_service && let Some(service) = state.scheduler.services.get(&key.1) {
                    let limiter = self.clone();
                    let name = key.1.clone();
                    let notify = service.notify.clone();
                    let driver_id = service.driver_id;
                    tokio::spawn(async move {
                        limiter.drive_service(name, notify, driver_id).await;
                    });
                }
                notify_service(&state.scheduler, &key.1);
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
                    _ = ticket.notify.notified() => {},
                    reason = request.cancellation.cancelled() => {
                        self.remove(&key, ticket.id, reason);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rejection(
        &self,
        service: &str,
        projection: &Projection,
        max_wait: Duration,
        enqueued: Instant,
        rate_deadline: Instant,
        hard_deadline: Option<AdmissionDeadline>,
        was_queued: bool,
        now: Instant,
        now_ns: u64,
    ) -> InvocationRateLimited {
        let bound = hard_deadline
            .filter(|bound| bound.at <= rate_deadline || (was_queued && now >= bound.at))
            .unwrap_or(AdmissionDeadline {
                at: rate_deadline,
                kind: InvocationDeadlineKind::RateWait,
            });
        let seconds = projection
            .next_ns
            .saturating_sub(now_ns)
            .div_ceil(NANOS_PER_SECOND)
            .max(1);
        InvocationRateLimited {
            scope: projection.scope,
            service: service.to_owned(),
            limit: projection.limiting_limit,
            retry_after_seconds: seconds,
            retry_at: retry_at(self.clock.wall(), seconds),
            max_wait_seconds: max_wait.as_secs(),
            queued_requests: projection.queued,
            deadline_kind: bound.kind,
            waited_milliseconds: milliseconds(now.saturating_duration_since(enqueued)),
            remaining_wait_milliseconds: milliseconds(bound.at.saturating_duration_since(now)),
            was_queued,
        }
    }

    pub(crate) async fn observe(
        self: &Arc<Self>,
        epoch: u64,
        principal: &str,
        service: &str,
        max_wait: Duration,
        resolver: InvocationLimitResolver,
    ) -> Result<InvocationObservation, InvocationObservationError> {
        let key = (principal.to_owned(), service.to_owned());
        loop {
            let resolved = self
                .resolve(epoch, &key, &resolver, ResolutionPurpose::Observation, None)
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
            return Ok(InvocationObservation {
                instance_id: self.instance_id.clone(),
                observed_at: format_retry_at(wall),
                invocations: InvocationObservationValues {
                    requests: resolved.limit.requests(),
                    window_seconds: resolved.limit.window_seconds(),
                    max_wait_seconds: max_wait.as_secs(),
                    counted_requests: projection.counted,
                    queued_requests: projection.queued,
                    available_immediately: projection.available,
                    next_admission_after_seconds: seconds,
                    next_admission_at: if seconds == 0 {
                        format_retry_at(wall)
                    } else {
                        format_retry_at(retry_at(wall, seconds))
                    },
                    blocking_scope: (projection.available == 0).then_some(projection.scope),
                },
            });
        }
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

fn cached_limit(state: &SchedulerState, key: &Key) -> Option<InvocationLimit> {
    let settings = state.settings.get(key)?;
    (settings.changing == 0).then_some(())?;
    settings
        .cached
        .filter(|(epoch, _)| *epoch == state.epoch)
        .map(|(_, limit)| limit)
}

fn queue_usable(state: &SchedulerState, key: &Key) -> bool {
    let Some(queue) = state.queues.get(key) else {
        return false;
    };
    cached_limit(state, key)
        .is_some_and(|limit| limit == queue.limit && state.settings[key].revision == queue.revision)
}

fn service_keys(state: &SchedulerState, service: &str) -> Vec<Key> {
    state
        .services
        .get(service)
        .map(|queue| {
            queue
                .ring
                .iter()
                .map(|principal| (principal.clone(), service.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn notify_service(state: &SchedulerState, service: &str) {
    if let Some(queue) = state.services.get(service) {
        queue.notify.notify_waiters();
    }
}
fn invalidate_pending(state: &mut SchedulerState, reason: AdmissionCancellationReason) {
    for (_, service) in state.services.drain() {
        service.notify.notify_waiters();
    }
    for (_, queue) in state.queues.drain() {
        queue.refresh_stop.cancel();
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

fn aggregate_window_copy(
    state: &LimiterState,
    service: &str,
    limit: InvocationLimit,
    now_ns: u64,
) -> KeyWindow {
    let window_ns = u64::from(limit.window_seconds()) * NANOS_PER_SECOND;
    let mut window = state
        .aggregate_windows
        .get(service)
        .filter(|window| window.window_ns == window_ns)
        .cloned()
        .unwrap_or_else(|| KeyWindow::new(window_ns));
    window.expire(now_ns);
    window
}

fn capacity_available(
    state: &LimiterState,
    key: &Key,
    limit: InvocationLimit,
    now_ns: u64,
) -> bool {
    window_copy(state, key, limit, now_ns).total < u64::from(limit.requests())
        && state.aggregate_limits.get(&key.1).is_none_or(|shared| {
            aggregate_window_copy(state, &key.1, *shared, now_ns).total
                < u64::from(shared.requests())
        })
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
    if let Some(aggregate) = state.aggregate_limits.get(&key.1).copied() {
        let window_ns = u64::from(aggregate.window_seconds()) * NANOS_PER_SECOND;
        let shared = state
            .aggregate_windows
            .entry(key.1.clone())
            .or_insert_with(|| KeyWindow::new(window_ns));
        shared.expire(now_ns);
        shared.record(now_ns);
    }
}
fn next_capacity(window: &mut KeyWindow, requests: u32, cursor: u64) -> u64 {
    window.expire(cursor);
    if window.total < u64::from(requests) {
        cursor
    } else {
        cursor.saturating_add(window.wait_ns(requests, cursor))
    }
}

#[cfg(test)]
mod tests;
