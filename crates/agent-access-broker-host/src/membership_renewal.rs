//! Microsoft membership renewal (design §8): admission of the requests that
//! need one, the process-wide flight registry and provider throttle, one
//! renewal's durable attempt start, audit preflight, redemption, ID-token
//! validation, fenced outcome write and audit, and the shutdown drain.
//!
//! Identity resolution reads a [`MembershipRenewalHint`] with the person's
//! membership. A request whose evidence expired waits, at most once and for
//! at most [`RENEWAL_WAIT`], for a renewal of its login method and then
//! checks its identity again; one whose evidence is within `ttl / 4` of
//! expiry starts a renewal only when a permit is free and proceeds at once.
//! Each renewal runs in its own tracked task, so a waiter's cancellation
//! never aborts it.
use crate::handlers::management::audit_actions;
use crate::oidc_id_token::{IdTokenReference, IdTokenRejection, validate_microsoft_id_token};
use crate::state::{ReloadableState, RuntimeSnapshot};
use agent_access_core::microsoft_oidc::renewal::{
    MembershipRenewalClassification, TokenEndpointClass, TokenEndpointDiagnostics,
    classify_token_endpoint_response, membership_renewal_issued_at_stale,
    membership_renewal_next_attempt, microsoft_oidc_throttle_until,
    microsoft_refresh_token_request,
};
use agent_access_core::microsoft_oidc::{
    MICROSOFT_OIDC_MAX_REFRESH_TOKEN_BYTES, MicrosoftGroupClaimClassification,
};
use agent_access_core::{
    AuditRecord, ManagedStoreError, MembershipRenewalHint, OidcMembershipEvidence,
    OidcMembershipRenewalAttempt, OidcMembershipRenewalAttemptRequest, OidcMembershipRenewalCommit,
    OidcMembershipRenewalCommitRequest, OidcMembershipRenewalCommitted,
    OidcMembershipRenewalEndedReason, OidcMembershipRenewalFailureCode,
    OidcMembershipRenewalResult, OidcMembershipRenewalRotation, OidcMembershipRenewalStart,
    OidcMembershipRenewalState, SourceContext, new_broker_request_id,
};
use agent_access_provider::{Decision, REQUEST_ID_HEADER, ReasonCode, ResourceScopes};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use openidconnect::AccessToken;
use rand::Rng;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;

/// How long a request waits for the renewal of expired evidence.
pub(crate) const RENEWAL_WAIT: Duration = Duration::from_secs(15);
/// At most this many redemptions run at once across the process.
const MAX_CONCURRENT_REDEMPTIONS: usize = 8;
/// At most this many waiting flights queue for a permit.
const MAX_QUEUED_FLIGHTS: usize = 256;
/// A full queue is logged at most this often.
const QUEUE_FULL_WARNING_INTERVAL: Duration = Duration::from_secs(60);

tokio::task_local! {
    static REQUEST_RENEWAL: Arc<RenewalContext>;
}

/// One request's renewal context (design §8.3): the absolute deadline of
/// its one wait, once it waited. Later admissions in the same request only
/// make the non-blocking checks. Every request gets one at ingress; a
/// request-less caller gets a fresh one.
#[derive(Debug, Default)]
pub(crate) struct RenewalContext {
    deadline: Mutex<Option<tokio::time::Instant>>,
}

impl RenewalContext {
    fn current() -> Arc<Self> {
        REQUEST_RENEWAL.try_with(Arc::clone).unwrap_or_default()
    }

    fn waited(&self) -> bool {
        self.deadline.lock().unwrap().is_some()
    }

    fn record_wait(&self, deadline: tokio::time::Instant) {
        self.deadline.lock().unwrap().get_or_insert(deadline);
    }
}

/// Ingress middleware giving each request its [`RenewalContext`].
pub(crate) async fn scope_request_renewal(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_RENEWAL
        .scope(Arc::new(RenewalContext::default()), next.run(request))
        .await
}

/// What admission did for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenewalAdmission {
    /// The request proceeds with the identity it resolved.
    Proceed,
    /// The request waited for a renewal: its entry point performs one
    /// current identity check before continuing.
    Waited,
}

/// Why a renewal ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    Expired,
    Ahead,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Ahead => "ahead",
        }
    }
}

/// Admits membership renewal for the identity a request resolved, with the
/// hint read with it (design §8.2).
pub(crate) async fn admit_membership_renewal(
    state: &Arc<ReloadableState>,
    snapshot: &RuntimeSnapshot,
    hint: Option<&MembershipRenewalHint>,
    headers: &HeaderMap,
) -> RenewalAdmission {
    let Some(hint) = hint else {
        return RenewalAdmission::Proceed;
    };
    let Some(provider) = snapshot.microsoft_oidc.as_ref() else {
        return RenewalAdmission::Proceed;
    };
    if !provider.config().membership_renewal()
        || provider.provider_generation() == 0
        || hint.state == OidcMembershipRenewalState::Ended
    {
        return RenewalAdmission::Proceed;
    }
    let now = provider.clock().now();
    let ahead = ChronoDuration::seconds(
        i64::try_from(provider.config().external_membership_ttl_seconds() / 4).unwrap_or(i64::MAX),
    );
    let remaining = hint
        .valid_until
        .as_deref()
        .and_then(parse_time)
        .map(|valid_until| valid_until - now);
    let trigger = match remaining {
        Some(remaining) if remaining > ahead => return RenewalAdmission::Proceed,
        Some(remaining) if remaining > ChronoDuration::zero() => Trigger::Ahead,
        _ => Trigger::Expired,
    };
    let context = RenewalContext::current();
    // Expired evidence waits once per request; a later expired admission
    // in the same request only makes the non-blocking checks.
    let wait = trigger == Trigger::Expired && !context.waited();
    state
        .membership_renewals
        .admit(Admission {
            state,
            hint,
            trigger,
            wait: wait.then_some(&*context),
            now,
            request_id: request_id(headers),
        })
        .await
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// The request's agent request ID, when it supplied a valid one.
fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        })
        .map(str::to_owned)
}

struct Admission<'a> {
    state: &'a Arc<ReloadableState>,
    hint: &'a MembershipRenewalHint,
    trigger: Trigger,
    /// The request's context when it waits.
    wait: Option<&'a RenewalContext>,
    now: DateTime<Utc>,
    request_id: Option<String>,
}

/// A flight's phase, which forced shutdown reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Queued,
    Starting,
    Redeeming,
    /// The outcome write was submitted; it runs to completion.
    Committing,
    Auditing,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Starting => "starting",
            Self::Redeeming => "redeeming",
            Self::Committing => "committing",
            Self::Auditing => "auditing",
        }
    }
}

/// One in-flight renewal of one login method.
struct Flight {
    login_method_id: String,
    trigger: Trigger,
    request_id: Option<String>,
    broker_request_id: String,
    phase: Mutex<Phase>,
    cancel: CancellationToken,
    done: watch::Sender<bool>,
}

impl Flight {
    fn phase(&self) -> Phase {
        *self.phase.lock().unwrap()
    }

    fn enter(&self, phase: Phase) {
        *self.phase.lock().unwrap() = phase;
    }

    /// Cancels the flight unless its outcome write was submitted.
    fn cancel_unsubmitted(&self) {
        let phase = self.phase.lock().unwrap();
        if *phase < Phase::Committing {
            self.cancel.cancel();
        }
    }

    /// Submits the outcome write unless the flight was cancelled first.
    fn submit(&self) -> bool {
        let mut phase = self.phase.lock().unwrap();
        if self.cancel.is_cancelled() {
            return false;
        }
        *phase = Phase::Committing;
        true
    }

    fn finish(&self) {
        self.done.send_replace(true);
    }

    async fn wait(&self, deadline: tokio::time::Instant) {
        let mut done = self.done.subscribe();
        let _ = tokio::time::timeout_at(deadline, done.wait_for(|done| *done)).await;
    }
}

/// How a flight gets its redemption permit.
enum Permit {
    Held(OwnedSemaphorePermit),
    /// A waiting flight queues until its request's deadline.
    Queue(tokio::time::Instant),
}

/// The flights, permits, queue and provider throttle every generation
/// shares, and the tracked tasks that run renewals.
pub(crate) struct MembershipRenewals {
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    permits: Arc<Semaphore>,
    queued: AtomicUsize,
    throttled_until: Mutex<Option<DateTime<Utc>>>,
    /// When a full queue was last logged.
    queue_full_warned: Mutex<Option<Instant>>,
    tracker: TaskTracker,
    closed: AtomicBool,
    #[cfg(test)]
    pub(crate) test: TestHooks,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    /// Replaces [`RENEWAL_WAIT`].
    pub(crate) wait: Mutex<Option<Duration>>,
    /// Blocks the next outcome write inside its blocking store call.
    pub(crate) commit_gate: Mutex<Option<Arc<crate::state::McpBlockingBarrier>>>,
}

impl MembershipRenewals {
    pub(crate) fn new() -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REDEMPTIONS)),
            queued: AtomicUsize::new(0),
            throttled_until: Mutex::new(None),
            queue_full_warned: Mutex::new(None),
            tracker: TaskTracker::new(),
            closed: AtomicBool::new(false),
            #[cfg(test)]
            test: TestHooks::default(),
        }
    }

    fn wait_budget(&self) -> Duration {
        #[cfg(test)]
        if let Some(wait) = *self.test.wait.lock().unwrap() {
            return wait;
        }
        RENEWAL_WAIT
    }

    fn throttle_active(&self, now: DateTime<Utc>) -> bool {
        self.throttled_until
            .lock()
            .unwrap()
            .is_some_and(|until| until > now)
    }

    /// Raises the provider throttle to `until`; a later, shorter value never
    /// shortens it. Returns whether it activated or extended the throttle.
    fn record_throttle(&self, until: DateTime<Utc>) -> bool {
        let mut throttled_until = self.throttled_until.lock().unwrap();
        if throttled_until.is_some_and(|current| current >= until) {
            return false;
        }
        *throttled_until = Some(until);
        true
    }

    /// Logs a full queue at most once a minute: every waiting request meets
    /// it while it lasts.
    fn warn_queue_full(&self) {
        let mut warned = self.queue_full_warned.lock().unwrap();
        if warned.is_some_and(|at| at.elapsed() < QUEUE_FULL_WARNING_INTERVAL) {
            return;
        }
        *warned = Some(Instant::now());
        tracing::warn!(
            event = "oidc_membership_renewal_queue_full",
            maxQueuedFlights = MAX_QUEUED_FLIGHTS,
            maxConcurrentRedemptions = MAX_CONCURRENT_REDEMPTIONS,
            "Microsoft membership renewals are at capacity; requests with expired evidence proceed without renewal"
        );
    }

    #[cfg(test)]
    pub(crate) fn throttled_until(&self) -> Option<DateTime<Utc>> {
        *self.throttled_until.lock().unwrap()
    }

    #[cfg(test)]
    pub(crate) fn queued_flights(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }

    /// Waits until no renewal is in flight.
    #[cfg(test)]
    pub(crate) async fn wait_idle(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.flights.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "membership renewals stay busy");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Joins a flight, or starts one under the start rules (design §8.4),
    /// then waits for it when the request waits.
    async fn admit(self: &Arc<Self>, admission: Admission<'_>) -> RenewalAdmission {
        let Admission {
            state,
            hint,
            trigger,
            wait,
            now,
            request_id,
        } = admission;
        let deadline = wait.map(|_| tokio::time::Instant::now() + self.wait_budget());
        let flight = {
            let mut flights = self.flights.lock().unwrap();
            if let Some(flight) = flights.get(&hint.login_method_id) {
                Some(Arc::clone(flight))
            } else {
                match self.start_refusal(hint, now) {
                    Some(reason) => {
                        log_skipped(&hint.login_method_id, trigger, reason);
                        None
                    }
                    None => match self.permit_for(deadline) {
                        Some(permit) => {
                            let flight = Arc::new(Flight {
                                login_method_id: hint.login_method_id.clone(),
                                trigger,
                                request_id,
                                broker_request_id: new_broker_request_id(),
                                phase: Mutex::new(Phase::Queued),
                                cancel: CancellationToken::new(),
                                done: watch::channel(false).0,
                            });
                            flights.insert(hint.login_method_id.clone(), Arc::clone(&flight));
                            let registry = Arc::clone(self);
                            let task_state = Arc::clone(state);
                            let task_flight = Arc::clone(&flight);
                            // The renewal keeps the triggering request's span
                            // for log correlation, and outlives the request.
                            self.tracker.spawn(
                                async move {
                                    registry.run(task_state, task_flight, permit).await;
                                }
                                .in_current_span()
                                .with_current_subscriber(),
                            );
                            Some(flight)
                        }
                        None => {
                            if deadline.is_some() {
                                self.warn_queue_full();
                            }
                            log_skipped(&hint.login_method_id, trigger, "capacity");
                            None
                        }
                    },
                }
            }
        };
        match (flight, wait, deadline) {
            (Some(flight), Some(context), Some(deadline)) => {
                context.record_wait(deadline);
                flight.wait(deadline).await;
                RenewalAdmission::Waited
            }
            _ => RenewalAdmission::Proceed,
        }
    }

    /// Why no flight may start now, if one may not.
    fn start_refusal(
        &self,
        hint: &MembershipRenewalHint,
        now: DateTime<Utc>,
    ) -> Option<&'static str> {
        if self.closed.load(Ordering::SeqCst) {
            return Some("shutdown");
        }
        if self.throttle_active(now) {
            return Some("throttled");
        }
        if hint
            .next_attempt_after
            .as_deref()
            .and_then(parse_time)
            .is_some_and(|next| next > now)
        {
            return Some("not_due");
        }
        None
    }

    /// A free permit; or, for a waiting flight, a place in the bounded
    /// queue until `deadline`.
    fn permit_for(&self, deadline: Option<tokio::time::Instant>) -> Option<Permit> {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(Permit::Held(permit));
        }
        let deadline = deadline?;
        self.queued
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |queued| {
                (queued < MAX_QUEUED_FLIGHTS).then_some(queued + 1)
            })
            .ok()
            .map(|_| Permit::Queue(deadline))
    }

    /// Runs one flight to its end, then releases its waiters and leaves the
    /// registry.
    async fn run(
        self: Arc<Self>,
        state: Arc<ReloadableState>,
        flight: Arc<Flight>,
        permit: Permit,
    ) {
        let started = Instant::now();
        let end = self.fly(&state, &flight, permit).await;
        // Waiters continue once the outcome is written; the audit append
        // follows in this same tracked task.
        flight.finish();
        report(&flight, end, started).await;
        let mut flights = self.flights.lock().unwrap();
        if flights
            .get(&flight.login_method_id)
            .is_some_and(|current| Arc::ptr_eq(current, &flight))
        {
            flights.remove(&flight.login_method_id);
        }
    }

    async fn fly(
        &self,
        state: &Arc<ReloadableState>,
        flight: &Flight,
        permit: Permit,
    ) -> FlightEnd {
        let _permit = match permit {
            Permit::Held(permit) => permit,
            Permit::Queue(deadline) => {
                let acquired = tokio::select! {
                    permit = Arc::clone(&self.permits).acquire_owned() => permit.ok(),
                    _ = tokio::time::sleep_until(deadline) => None,
                    _ = flight.cancel.cancelled() => None,
                };
                self.queued.fetch_sub(1, Ordering::SeqCst);
                match acquired {
                    Some(permit) => permit,
                    None if flight.cancel.is_cancelled() => return FlightEnd::Skipped("shutdown"),
                    None => return FlightEnd::Skipped("capacity"),
                }
            }
        };
        flight.enter(Phase::Starting);
        let snapshot = state.current();
        let Some(provider) = snapshot.microsoft_oidc.clone() else {
            return FlightEnd::Skipped("provider_changed");
        };
        let config_generation = provider.provider_generation();
        if !provider.config().membership_renewal() || config_generation == 0 {
            return FlightEnd::Skipped("provider_changed");
        }
        if self.throttle_active(provider.clock().now()) {
            return FlightEnd::Skipped("throttled");
        }
        let Some(key_ring) = snapshot.runtime.credential_key_ring().cloned() else {
            return FlightEnd::Skipped("store_unavailable");
        };
        let request = OidcMembershipRenewalAttemptRequest {
            login_method_id: flight.login_method_id.clone(),
            config_generation,
            now: timestamp(provider.clock().now()),
        };
        let start_ring = key_ring.clone();
        let attempt = state
            .token_store_call_from_snapshot(Arc::clone(&snapshot), move |runtime| {
                runtime
                    .managed_store()
                    .ok_or_else(|| ManagedStoreError::Unavailable("managed store".into()))?
                    .start_oidc_membership_renewal(&start_ring, &request)
            })
            .await;
        let start = match attempt {
            Ok(OidcMembershipRenewalAttempt::Started(start)) => start,
            Ok(OidcMembershipRenewalAttempt::Skipped(reason)) => {
                return FlightEnd::Skipped(reason.as_str());
            }
            Err(ManagedStoreError::VersionConflict) => {
                return FlightEnd::Skipped("snapshot_changed");
            }
            Err(_) => return FlightEnd::Skipped("store_unavailable"),
        };
        if flight.cancel.is_cancelled() {
            return FlightEnd::Skipped("shutdown");
        }
        // Audit preflight: without a writable audit store, Microsoft is not
        // contacted; the attempt's start stays recorded.
        if snapshot.runtime.check_audit_writable().await.is_err() {
            return FlightEnd::Skipped("audit_unavailable");
        }
        flight.enter(Phase::Redeeming);
        let redeemed = Instant::now();
        let outcome = tokio::select! {
            outcome = self.redeem(&provider, &start) => outcome,
            _ = flight.cancel.cancelled() => return FlightEnd::Skipped("shutdown"),
        };
        let redemption_ms = u64::try_from(redeemed.elapsed().as_millis()).unwrap_or(u64::MAX);
        let now = provider.clock().now();
        let result = match outcome.classification {
            MembershipRenewalClassification::Renewed => OidcMembershipRenewalResult::Renewed {
                issued_at: outcome.issued_at.unwrap_or_default(),
                external_group_ids: outcome.groups.clone(),
            },
            MembershipRenewalClassification::SignInRequired => {
                OidcMembershipRenewalResult::Ended(OidcMembershipRenewalEndedReason::SignInRequired)
            }
            MembershipRenewalClassification::IdentityMismatch => {
                OidcMembershipRenewalResult::Ended(
                    OidcMembershipRenewalEndedReason::IdentityMismatch,
                )
            }
            classification => OidcMembershipRenewalResult::Failed {
                code: failure_code(classification),
                observed_issued_at: outcome.issued_at,
                next_attempt_after: timestamp(
                    membership_renewal_next_attempt(
                        classification,
                        start.failure_count.saturating_add(1),
                        outcome.diagnostics.retry_after,
                        now,
                        rand::thread_rng().gen_range(-0.2..=0.2),
                    )
                    .unwrap_or(now),
                ),
            },
        };
        let rotation = outcome.refresh_token.and_then(|refresh_token| {
            OidcMembershipRenewalRotation::new(
                key_ring,
                refresh_token,
                start.material.reference().clone(),
            )
            .ok()
        });
        if !flight.submit() {
            return FlightEnd::Skipped("shutdown");
        }
        let next_attempt_after = match &result {
            OidcMembershipRenewalResult::Failed {
                next_attempt_after, ..
            } => Some(next_attempt_after.clone()),
            _ => None,
        };
        let request = OidcMembershipRenewalCommitRequest {
            fence: start.fence.clone(),
            now: timestamp(now),
            result,
            rotation,
        };
        #[cfg(test)]
        let gate = self.test.commit_gate.lock().unwrap().take();
        let written = state
            .token_store_call_from_snapshot(Arc::clone(&snapshot), move |runtime| {
                #[cfg(test)]
                if let Some(gate) = gate {
                    gate.wait();
                }
                runtime
                    .managed_store()
                    .ok_or_else(|| ManagedStoreError::Unavailable("managed store".into()))?
                    .commit_oidc_membership_renewal(request)
            })
            .await;
        let attempt = Attempt {
            classification: outcome.classification,
            diagnostics: outcome.diagnostics,
            next_attempt_after,
            redemption_ms,
        };
        match written {
            Ok(OidcMembershipRenewalCommit::Committed(committed)) => {
                flight.enter(Phase::Auditing);
                FlightEnd::Committed {
                    committed,
                    attempt,
                    snapshot,
                }
            }
            Ok(OidcMembershipRenewalCommit::Superseded)
            | Err(ManagedStoreError::VersionConflict) => FlightEnd::Superseded(attempt),
            Err(_) => FlightEnd::WriteFailed(attempt),
        }
    }

    /// Redeems the stored refresh token and classifies the response.
    async fn redeem(
        &self,
        provider: &crate::state::MicrosoftOidcProviderRuntime,
        start: &OidcMembershipRenewalStart,
    ) -> Redemption {
        let mut redemption = Redemption {
            classification: MembershipRenewalClassification::Unavailable,
            diagnostics: TokenEndpointDiagnostics::default(),
            issued_at: None,
            groups: Default::default(),
            refresh_token: None,
        };
        let Ok(metadata) = provider.metadata_for_token_validation().await else {
            return redemption;
        };
        let Some(token_endpoint) = metadata.metadata().token_endpoint() else {
            return redemption;
        };
        let Ok(request) = microsoft_refresh_token_request(
            token_endpoint.url(),
            provider.config().client_id(),
            provider.config().secrets().client_secret(),
            start.material.refresh_token(),
        ) else {
            return redemption;
        };
        let response = provider.http_client().token_request(request).await;
        let (class, diagnostics) = classify_token_endpoint_response(response);
        if diagnostics.status == Some(429) {
            let until =
                microsoft_oidc_throttle_until(diagnostics.retry_after, provider.clock().now());
            if self.record_throttle(until) {
                tracing::warn!(
                    event = "oidc_membership_renewal_throttled",
                    throttledUntil = timestamp(until).as_str(),
                    retryAfterUsable = diagnostics.retry_after.is_some(),
                    "Microsoft throttled membership renewal; no renewal starts until then"
                );
            }
        }
        redemption.diagnostics = diagnostics;
        redemption.classification = match class {
            TokenEndpointClass::Unavailable => MembershipRenewalClassification::Unavailable,
            TokenEndpointClass::Throttled => MembershipRenewalClassification::Throttled,
            TokenEndpointClass::InvalidResponse => MembershipRenewalClassification::InvalidResponse,
            TokenEndpointClass::SignInRequired => MembershipRenewalClassification::SignInRequired,
            TokenEndpointClass::ClientRejected => MembershipRenewalClassification::ClientRejected,
            TokenEndpointClass::RequestRejected => MembershipRenewalClassification::RequestRejected,
            TokenEndpointClass::Issued(tokens) => {
                let Some(id_token) = tokens.id_token.as_deref() else {
                    redemption.classification = MembershipRenewalClassification::InvalidResponse;
                    return redemption;
                };
                let access_token = tokens.access_token.clone().map(AccessToken::new);
                let validated = validate_microsoft_id_token(
                    provider,
                    metadata,
                    id_token,
                    access_token.as_ref(),
                    IdTokenReference::Renewal {
                        reference: start.material.reference(),
                        external_subject: &start.fence.external_subject,
                    },
                )
                .await;
                let validated = match validated {
                    Ok(validated) => validated,
                    Err(IdTokenRejection::KeysUnavailable) => {
                        redemption.classification = MembershipRenewalClassification::Unavailable;
                        return redemption;
                    }
                    Err(IdTokenRejection::Invalid) => {
                        redemption.classification =
                            MembershipRenewalClassification::InvalidResponse;
                        return redemption;
                    }
                    Err(IdTokenRejection::IdentityMismatch) => {
                        redemption.classification =
                            MembershipRenewalClassification::IdentityMismatch;
                        return redemption;
                    }
                };
                // A trusted observation raises the watermark whatever its
                // groups or freshness.
                redemption.issued_at = Some(validated.issued_at);
                let refresh_token = tokens.refresh_token.filter(|token| {
                    let usable =
                        !token.is_empty() && token.len() <= MICROSOFT_OIDC_MAX_REFRESH_TOKEN_BYTES;
                    if !usable {
                        tracing::warn!(
                            event = "oidc_refresh_token_unusable",
                            loginMethodId = start.fence.login_method_id.as_str(),
                            tokenBytes = token.len(),
                            maxTokenBytes = MICROSOFT_OIDC_MAX_REFRESH_TOKEN_BYTES,
                            "Microsoft returned a refresh token the Broker cannot store; the stored token is kept"
                        );
                    }
                    usable
                });
                match validated.claims.additional_claims().classify_groups() {
                    MicrosoftGroupClaimClassification::Complete(groups) => {
                        let ttl = provider.config().external_membership_ttl_seconds();
                        if membership_renewal_issued_at_stale(
                            validated.issued_at,
                            provider.clock().now(),
                            ttl,
                        ) {
                            MembershipRenewalClassification::InvalidResponse
                        } else {
                            redemption.groups = groups;
                            redemption.refresh_token = refresh_token;
                            MembershipRenewalClassification::Renewed
                        }
                    }
                    MicrosoftGroupClaimClassification::Overage
                    | MicrosoftGroupClaimClassification::Malformed(_) => {
                        redemption.refresh_token = refresh_token;
                        MembershipRenewalClassification::GroupsIncomplete
                    }
                }
            }
        };
        redemption
    }

    /// Stops new flights and cancels those whose outcome write was not
    /// submitted.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.tracker.close();
        for flight in self.flights.lock().unwrap().values() {
            flight.cancel_unsubmitted();
        }
    }

    /// Closes, then waits up to `timeout` for every renewal task, including
    /// submitted writes and their audit appends. Logs one error per renewal
    /// still unfinished, naming its login method and phase, since one that
    /// commits afterwards is never audited; returns them.
    pub(crate) async fn drain(&self, timeout: Duration) -> Vec<(String, &'static str)> {
        self.close();
        if tokio::time::timeout(timeout, self.tracker.wait())
            .await
            .is_ok()
        {
            return Vec::new();
        }
        let mut unfinished = self
            .flights
            .lock()
            .unwrap()
            .values()
            .map(|flight| (flight.login_method_id.clone(), flight.phase().as_str()))
            .collect::<Vec<_>>();
        unfinished.sort();
        for (login_method_id, phase) in &unfinished {
            tracing::error!(
                event = "oidc_membership_renewal_unfinished",
                loginMethodId = login_method_id.as_str(),
                phase = *phase,
                "a Microsoft membership renewal did not finish before shutdown; its audit record may be missing"
            );
        }
        unfinished
    }
}

/// What a redemption learned.
struct Redemption {
    classification: MembershipRenewalClassification,
    diagnostics: TokenEndpointDiagnostics,
    /// The validated token's raw `iat`, for every trusted observation.
    issued_at: Option<i64>,
    groups: std::collections::BTreeSet<String>,
    refresh_token: Option<String>,
}

/// What an attempt that reached its outcome write reports.
struct Attempt {
    classification: MembershipRenewalClassification,
    diagnostics: TokenEndpointDiagnostics,
    next_attempt_after: Option<String>,
    redemption_ms: u64,
}

enum FlightEnd {
    /// Ended without contacting Microsoft's token endpoint.
    Skipped(&'static str),
    /// The outcome write's fence failed; nothing was written.
    Superseded(Attempt),
    /// The outcome write failed.
    WriteFailed(Attempt),
    Committed {
        committed: Box<OidcMembershipRenewalCommitted>,
        attempt: Attempt,
        snapshot: Arc<RuntimeSnapshot>,
    },
}

fn failure_code(
    classification: MembershipRenewalClassification,
) -> OidcMembershipRenewalFailureCode {
    match classification {
        MembershipRenewalClassification::GroupsIncomplete => {
            OidcMembershipRenewalFailureCode::GroupsIncomplete
        }
        MembershipRenewalClassification::ClientRejected => {
            OidcMembershipRenewalFailureCode::ClientRejected
        }
        MembershipRenewalClassification::RequestRejected => {
            OidcMembershipRenewalFailureCode::RequestRejected
        }
        MembershipRenewalClassification::Throttled => OidcMembershipRenewalFailureCode::Throttled,
        MembershipRenewalClassification::Unavailable => {
            OidcMembershipRenewalFailureCode::Unavailable
        }
        MembershipRenewalClassification::InvalidResponse
        | MembershipRenewalClassification::Renewed
        | MembershipRenewalClassification::SignInRequired
        | MembershipRenewalClassification::IdentityMismatch => {
            OidcMembershipRenewalFailureCode::InvalidResponse
        }
    }
}

/// The audited reason of a failed renewal (design §9.3).
fn failure_reason(classification: MembershipRenewalClassification) -> ReasonCode {
    match classification {
        MembershipRenewalClassification::GroupsIncomplete => ReasonCode::OidcGroupClaimsIncomplete,
        MembershipRenewalClassification::SignInRequired => ReasonCode::OidcSignInRequired,
        MembershipRenewalClassification::ClientRejected => ReasonCode::OidcClientRejected,
        MembershipRenewalClassification::IdentityMismatch
        | MembershipRenewalClassification::InvalidResponse => ReasonCode::OidcIdentityInvalid,
        MembershipRenewalClassification::RequestRejected => ReasonCode::OidcProviderDenied,
        MembershipRenewalClassification::Throttled
        | MembershipRenewalClassification::Unavailable
        | MembershipRenewalClassification::Renewed => ReasonCode::OidcUnavailable,
    }
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Logs, at debug level, a request's renewal that did not start: every
/// request inside the window meets an active throttle, a full capacity or a
/// backoff while it lasts. Throttle activation and a full queue have their
/// own warnings.
fn log_skipped(login_method_id: &str, trigger: Trigger, reason: &'static str) {
    tracing::debug!(
        event = "oidc_membership_renewal",
        loginMethodId = login_method_id,
        trigger = trigger.as_str(),
        outcome = "skipped",
        reason = reason,
        "Microsoft membership renewal skipped"
    );
}

/// Logs a flight's end and, for a committed outcome, appends its audit
/// record. Tokens, raw bodies, `error_description` and group IDs are never
/// logged or audited.
async fn report(flight: &Flight, end: FlightEnd, started: Instant) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (attempt, outcome) = match &end {
        FlightEnd::Skipped(reason) => {
            // An unavailable audit or managed store is an operational
            // problem; the other reasons are ordinary.
            if matches!(*reason, "audit_unavailable" | "store_unavailable") {
                tracing::warn!(
                    event = "oidc_membership_renewal",
                    loginMethodId = flight.login_method_id.as_str(),
                    trigger = flight.trigger.as_str(),
                    outcome = "skipped",
                    reason = *reason,
                    durationMs = duration_ms,
                    "Microsoft membership renewal skipped"
                );
            } else {
                tracing::debug!(
                    event = "oidc_membership_renewal",
                    loginMethodId = flight.login_method_id.as_str(),
                    trigger = flight.trigger.as_str(),
                    outcome = "skipped",
                    reason = *reason,
                    durationMs = duration_ms,
                    "Microsoft membership renewal skipped"
                );
            }
            return;
        }
        FlightEnd::Superseded(attempt) => (attempt, "superseded"),
        FlightEnd::WriteFailed(attempt) => (attempt, "write_failed"),
        FlightEnd::Committed { attempt, .. } => (
            attempt,
            if attempt.classification == MembershipRenewalClassification::Renewed {
                "renewed"
            } else {
                "failed"
            },
        ),
    };
    let evidence = match &end {
        FlightEnd::Committed { committed, .. } => {
            committed.evidence.map(OidcMembershipEvidence::as_str)
        }
        _ => None,
    };
    let diagnostics = &attempt.diagnostics;
    macro_rules! renewal_event {
        ($level:ident, $message:literal) => {
            tracing::$level!(
                event = "oidc_membership_renewal",
                loginMethodId = flight.login_method_id.as_str(),
                trigger = flight.trigger.as_str(),
                outcome = outcome,
                classification = attempt.classification.as_str(),
                evidence = evidence.unwrap_or(""),
                durationMs = duration_ms,
                redemptionMs = attempt.redemption_ms,
                httpStatus = diagnostics.status.unwrap_or(0),
                error = diagnostics.error.unwrap_or(""),
                errorCodes = ?diagnostics.error_codes,
                nextAttemptAfter = attempt.next_attempt_after.as_deref().unwrap_or(""),
                $message
            )
        };
    }
    match outcome {
        "renewed" => renewal_event!(info, "Microsoft membership renewal ended"),
        "superseded" => renewal_event!(debug, "Microsoft membership renewal superseded"),
        "write_failed" => {
            renewal_event!(error, "Microsoft membership renewal could not be recorded")
        }
        _ => renewal_event!(warn, "Microsoft membership renewal failed"),
    }
    let FlightEnd::Committed {
        committed,
        attempt,
        snapshot,
    } = end
    else {
        return;
    };
    let record = audit_record(flight, &committed, &attempt, &snapshot);
    if snapshot.runtime.append_audit_record(&record).await.is_err() {
        tracing::error!(
            event = "oidc_membership_renewal_audit_failed",
            loginMethodId = flight.login_method_id.as_str(),
            action = record.action.as_str(),
            brokerRequestId = flight.broker_request_id.as_str(),
            "a committed Microsoft membership renewal outcome could not be audited"
        );
    }
}

fn audit_record(
    flight: &Flight,
    committed: &OidcMembershipRenewalCommitted,
    attempt: &Attempt,
    snapshot: &RuntimeSnapshot,
) -> AuditRecord {
    let renewed = attempt.classification == MembershipRenewalClassification::Renewed;
    let details = if renewed {
        json!({
            "provider": "microsoft",
            "loginMethodId": flight.login_method_id,
            "trigger": flight.trigger.as_str(),
            "effectiveGroupCount": committed.membership.groups.len(),
            "policyGroups": committed.membership.policy_groups,
            "validUntil": committed.valid_until,
            "membershipChanged": committed.membership_changed,
            "evidence": committed.evidence.map(OidcMembershipEvidence::as_str),
        })
    } else {
        json!({
            "provider": "microsoft",
            "loginMethodId": flight.login_method_id,
            "trigger": flight.trigger.as_str(),
            "classification": attempt.classification.as_str(),
            "nextAttemptAfter": attempt.next_attempt_after,
        })
    };
    AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: flight
            .request_id
            .clone()
            .unwrap_or_else(|| flight.broker_request_id.clone()),
        broker_request_id: flight.broker_request_id.clone(),
        config_generation: Some(snapshot.generation),
        policy_generation: Some(snapshot.runtime.policy_generation()),
        principal: committed.principal_id.clone(),
        principal_subject: None,
        groups: committed.membership.groups.clone(),
        service: "broker".to_string(),
        action: if renewed {
            audit_actions::OIDC_MEMBERSHIP_RENEWED
        } else {
            audit_actions::OIDC_MEMBERSHIP_RENEWAL_FAILED
        }
        .to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        credential_connection: None,
        decision: if renewed {
            Decision::Allow
        } else {
            Decision::Deny
        },
        reason_code: (!renewed).then(|| failure_reason(attempt.classification).into()),
        upstream_status: attempt.diagnostics.status,
        upstream_duration_ms: Some(attempt.redemption_ms),
        object_ids: None,
        identity_source: None,
        source: SourceContext {
            listener: "membership_renewal".to_string(),
            remote: "process".to_string(),
            proxy_chain: Vec::new(),
            agent_request_id_generated: Some(flight.request_id.is_none()),
        },
        execution_context: None,
        provider_audit: Some(json!({ "oidc": details })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_900_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn the_provider_throttle_only_grows() {
        let registry = MembershipRenewals::new();
        assert!(!registry.throttle_active(at(0)));
        assert!(registry.record_throttle(at(300)), "activated");
        assert!(!registry.record_throttle(at(10)), "never shortened");
        assert!(!registry.record_throttle(at(300)), "unchanged");
        assert_eq!(registry.throttled_until(), Some(at(300)));
        assert!(registry.throttle_active(at(299)));
        assert!(!registry.throttle_active(at(300)));
        assert!(registry.record_throttle(at(400)), "extended");
        assert_eq!(registry.throttled_until(), Some(at(400)));
    }

    /// Eight redemptions at once; a speculative flight starts only with a
    /// permit free now, a waiting one queues, at most 256 of them.
    #[tokio::test]
    async fn capacity_admits_eight_and_queues_only_waiting_flights() {
        let registry = MembershipRenewals::new();
        let held = (0..MAX_CONCURRENT_REDEMPTIONS)
            .map(|_| match registry.permit_for(None) {
                Some(Permit::Held(permit)) => permit,
                _ => panic!("a free permit"),
            })
            .collect::<Vec<_>>();
        assert!(registry.permit_for(None).is_none(), "speculative");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        for _ in 0..MAX_QUEUED_FLIGHTS {
            assert!(matches!(
                registry.permit_for(Some(deadline)),
                Some(Permit::Queue(_))
            ));
        }
        assert_eq!(registry.queued_flights(), MAX_QUEUED_FLIGHTS);
        assert!(registry.permit_for(Some(deadline)).is_none(), "queue bound");
        drop(held);
        assert!(matches!(registry.permit_for(None), Some(Permit::Held(_))));
    }

    #[test]
    fn a_full_queue_warns_at_most_once_a_minute() {
        let captured = agent_access_provider::test_support::install_trace_capture().start();
        let registry = MembershipRenewals::new();
        captured.in_scope(|| {
            registry.warn_queue_full();
            registry.warn_queue_full();
        });
        let warnings = |events: Vec<serde_json::Value>| {
            events
                .into_iter()
                .filter(|event| event["event"] == "oidc_membership_renewal_queue_full")
                .map(|event| event["level"].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(warnings(captured.take_events()), ["WARN"]);
        // A minute later it warns again.
        *registry.queue_full_warned.lock().unwrap() =
            Some(Instant::now() - QUEUE_FULL_WARNING_INTERVAL);
        captured.in_scope(|| registry.warn_queue_full());
        assert_eq!(warnings(captured.take_events()), ["WARN"]);
    }

    #[test]
    fn start_refusals_cover_shutdown_throttle_and_backoff() {
        let registry = MembershipRenewals::new();
        let mut hint = MembershipRenewalHint {
            login_method_id: "method".into(),
            valid_until: None,
            state: OidcMembershipRenewalState::Retrying,
            token_version: "version".into(),
            next_attempt_after: Some(timestamp(at(60))),
        };
        assert_eq!(registry.start_refusal(&hint, at(0)), Some("not_due"));
        assert_eq!(registry.start_refusal(&hint, at(60)), None);
        hint.next_attempt_after = None;
        assert!(registry.record_throttle(at(30)));
        assert_eq!(registry.start_refusal(&hint, at(0)), Some("throttled"));
        assert_eq!(registry.start_refusal(&hint, at(30)), None);
        registry.close();
        assert_eq!(registry.start_refusal(&hint, at(30)), Some("shutdown"));
    }

    #[test]
    fn a_submitted_flight_is_not_cancelled() {
        let flight = || Flight {
            login_method_id: "method".into(),
            trigger: Trigger::Expired,
            request_id: None,
            broker_request_id: "broker".into(),
            phase: Mutex::new(Phase::Redeeming),
            cancel: CancellationToken::new(),
            done: watch::channel(false).0,
        };
        let cancelled = flight();
        cancelled.cancel_unsubmitted();
        assert!(!cancelled.submit());
        let submitted = flight();
        assert!(submitted.submit());
        submitted.cancel_unsubmitted();
        assert!(!submitted.cancel.is_cancelled());
        assert_eq!(submitted.phase(), Phase::Committing);
    }

    #[test]
    fn failures_map_to_their_audited_reasons() {
        use MembershipRenewalClassification as C;
        for (classification, reason) in [
            (C::GroupsIncomplete, ReasonCode::OidcGroupClaimsIncomplete),
            (C::SignInRequired, ReasonCode::OidcSignInRequired),
            (C::ClientRejected, ReasonCode::OidcClientRejected),
            (C::IdentityMismatch, ReasonCode::OidcIdentityInvalid),
            (C::InvalidResponse, ReasonCode::OidcIdentityInvalid),
            (C::RequestRejected, ReasonCode::OidcProviderDenied),
            (C::Throttled, ReasonCode::OidcUnavailable),
            (C::Unavailable, ReasonCode::OidcUnavailable),
        ] {
            assert_eq!(failure_reason(classification), reason, "{classification:?}");
        }
    }
}
