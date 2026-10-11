//! Rolling-window service invocation limiter keyed by `(principal, service)`.
//!
//! Each key keeps at most [`SLOTS`] sub-buckets of `window / 60`. A bucket
//! records how many requests it admitted and when it admitted the last one;
//! the whole bucket stays counted until that last request leaves the trailing
//! window. The limiter therefore never admits more than `requests` in any
//! trailing window and is conservative by at most `window / 60`, with memory
//! per key independent of `requests`. Rejected requests are never recorded.
//!
//! The monotonic clock is read while holding the state lock, so admissions
//! are recorded in clock order; recording also tolerates a reading earlier
//! than the key's newest bucket without moving any bucket backwards.
//!
//! State is process-local and survives reloads. Idle keys whose history has
//! fully expired are pruned by an amortized sweep, never by scanning every key
//! on every request, and there is no global key-capacity rejection.
use agent_access_core::{InvocationLimit, InvocationRateLimited};
use chrono::{DateTime, Duration as ChronoDuration, DurationRound, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Sub-buckets per window.
const SUB_BUCKETS: u64 = 60;
/// Live buckets per key: the current bucket and the 60 before it.
const SLOTS: usize = SUB_BUCKETS as usize + 1;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
/// Time-based sweep interval for idle keys.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Size-based sweeps start once this many keys exist, then whenever the key
/// count doubles since the previous sweep.
const MIN_SWEEP_KEYS: usize = 1024;

/// Time source for window arithmetic (monotonic) and `retryAt` (wall clock).
pub(crate) trait LimiterClock: Send + Sync {
    /// Monotonic time since an arbitrary fixed origin.
    fn monotonic(&self) -> Duration;
    fn wall(&self) -> DateTime<Utc>;
}

pub(crate) struct SystemLimiterClock {
    origin: Instant,
}

impl SystemLimiterClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl LimiterClock for SystemLimiterClock {
    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }

    fn wall(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub(crate) struct InvocationLimiter {
    clock: Arc<dyn LimiterClock>,
    state: Mutex<LimiterState>,
}

#[derive(Default)]
struct LimiterState {
    /// principal -> service -> window. Nested maps allow borrowed lookups.
    keys: HashMap<String, HashMap<String, KeyWindow>>,
    key_count: usize,
    next_sweep_ns: u64,
    sweep_at_key_count: usize,
}

struct KeyWindow {
    window_ns: u64,
    /// Oldest first; at most [`SLOTS`] entries.
    buckets: VecDeque<Bucket>,
    /// Sum of `buckets[..].count`.
    total: u64,
}

#[derive(Clone, Copy)]
struct Bucket {
    index: u64,
    count: u32,
    /// Admission time of the bucket's most recent request.
    last_ns: u64,
}

impl KeyWindow {
    fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
            buckets: VecDeque::with_capacity(4),
            total: 0,
        }
    }

    /// Drops buckets whose last request has left the trailing window.
    fn expire(&mut self, now_ns: u64) {
        while let Some(front) = self.buckets.front() {
            if front.last_ns.saturating_add(self.window_ns) > now_ns {
                break;
            }
            self.total -= u64::from(front.count);
            self.buckets.pop_front();
        }
    }

    fn is_idle(&self, now_ns: u64) -> bool {
        self.buckets
            .back()
            .is_none_or(|newest| newest.last_ns.saturating_add(self.window_ns) <= now_ns)
    }

    /// Records one admission. A reading at or before the newest bucket joins
    /// it: bucket indexes stay increasing and `last_ns` never moves back.
    fn record(&mut self, now_ns: u64) {
        let index = bucket_index(now_ns, self.window_ns);
        match self.buckets.back_mut() {
            Some(newest) if index <= newest.index => {
                newest.count += 1;
                newest.last_ns = newest.last_ns.max(now_ns);
            }
            _ => {
                self.buckets.push_back(Bucket {
                    index,
                    count: 1,
                    last_ns: now_ns,
                });
                debug_assert!(self.buckets.len() <= SLOTS);
            }
        }
        self.total += 1;
    }

    /// Nanoseconds until enough history expires for one more request.
    fn wait_ns(&self, requests: u32, now_ns: u64) -> u64 {
        let mut remaining = self.total;
        for bucket in &self.buckets {
            remaining -= u64::from(bucket.count);
            if remaining < u64::from(requests) {
                return bucket
                    .last_ns
                    .saturating_add(self.window_ns)
                    .saturating_sub(now_ns);
            }
        }
        0
    }
}

fn bucket_index(now_ns: u64, window_ns: u64) -> u64 {
    (u128::from(now_ns) * u128::from(SUB_BUCKETS) / u128::from(window_ns)) as u64
}

impl InvocationLimiter {
    pub(crate) fn new() -> Self {
        Self::with_clock(Arc::new(SystemLimiterClock::new()))
    }

    pub(crate) fn with_clock(clock: Arc<dyn LimiterClock>) -> Self {
        Self {
            clock,
            state: Mutex::new(LimiterState {
                next_sweep_ns: duration_ns(SWEEP_INTERVAL),
                sweep_at_key_count: MIN_SWEEP_KEYS,
                ..LimiterState::default()
            }),
        }
    }

    /// Admits and records one request for `(principal, service)` under
    /// `limit`, or explains when one would be admitted. Only admitted requests
    /// are recorded. A key's history resets when its window length changes;
    /// a changed `requests` value is evaluated against the kept history.
    pub(crate) fn try_admit(
        &self,
        principal: &str,
        service: &str,
        limit: InvocationLimit,
    ) -> Result<(), InvocationRateLimited> {
        let window_ns = u64::from(limit.window_seconds()) * NANOS_PER_SECOND;
        let mut state = self.state.lock().unwrap();
        // Read under the lock so concurrent admissions record in clock order.
        let now_ns = duration_ns(self.clock.monotonic());
        state.maybe_sweep(now_ns);
        let window = state.window_mut(principal, service, window_ns);
        if window.window_ns != window_ns {
            *window = KeyWindow::new(window_ns);
        }
        window.expire(now_ns);
        if window.total < u64::from(limit.requests()) {
            window.record(now_ns);
            return Ok(());
        }
        let wait_ns = window.wait_ns(limit.requests(), now_ns);
        drop(state);
        let retry_after_seconds = wait_ns.div_ceil(NANOS_PER_SECOND).max(1);
        Err(InvocationRateLimited {
            service: service.to_string(),
            limit,
            retry_after_seconds,
            retry_at: retry_at(self.clock.wall(), retry_after_seconds),
        })
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.state.lock().unwrap().key_count
    }

    /// `(principal, service, admitted requests in history)` for every key.
    #[cfg(test)]
    pub(crate) fn state_for_test(&self) -> Vec<(String, String, u64)> {
        let state = self.state.lock().unwrap();
        let mut keys = state
            .keys
            .iter()
            .flat_map(|(principal, services)| {
                services
                    .iter()
                    .map(|(service, window)| (principal.clone(), service.clone(), window.total))
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }
}

impl LimiterState {
    /// The key's window, created on first use. Existing keys are found
    /// without allocating.
    fn window_mut(&mut self, principal: &str, service: &str, window_ns: u64) -> &mut KeyWindow {
        let exists = self
            .keys
            .get(principal)
            .is_some_and(|services| services.contains_key(service));
        if !exists {
            self.key_count += 1;
            self.keys
                .entry(principal.to_string())
                .or_default()
                .insert(service.to_string(), KeyWindow::new(window_ns));
        }
        self.keys
            .get_mut(principal)
            .and_then(|services| services.get_mut(service))
            .expect("limiter key was just ensured")
    }

    /// Amortized pruning: at most one full pass per sweep interval, plus one
    /// whenever the key count doubles, so no request scans every key.
    fn maybe_sweep(&mut self, now_ns: u64) {
        if now_ns < self.next_sweep_ns && self.key_count < self.sweep_at_key_count {
            return;
        }
        self.keys.retain(|_, services| {
            services.retain(|_, window| !window.is_idle(now_ns));
            !services.is_empty()
        });
        self.key_count = self.keys.values().map(HashMap::len).sum();
        self.next_sweep_ns = now_ns.saturating_add(duration_ns(SWEEP_INTERVAL));
        self.sweep_at_key_count = self.key_count.saturating_mul(2).max(MIN_SWEEP_KEYS);
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// The wall-clock instant `retry_after_seconds` from now, rounded up to a
/// whole second so it is never earlier than the precise admission time.
fn retry_at(now: DateTime<Utc>, retry_after_seconds: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(retry_after_seconds).unwrap_or(i64::MAX);
    let at = now + ChronoDuration::seconds(seconds);
    let floor = at.duration_trunc(ChronoDuration::seconds(1)).unwrap_or(at);
    if floor == at {
        at
    } else {
        floor + ChronoDuration::seconds(1)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Manually advanced clock for window, expiry, and retry-after tests.
    pub(crate) struct ManualClock {
        state: Mutex<(Duration, DateTime<Utc>)>,
    }

    impl ManualClock {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new((
                    Duration::ZERO,
                    Utc.with_ymd_and_hms(2026, 9, 25, 14, 3, 0).unwrap(),
                )),
            })
        }

        pub(crate) fn advance(&self, by: Duration) {
            let mut state = self.state.lock().unwrap();
            state.0 += by;
            state.1 += ChronoDuration::from_std(by).unwrap();
        }
    }

    impl LimiterClock for ManualClock {
        fn monotonic(&self) -> Duration {
            self.state.lock().unwrap().0
        }

        fn wall(&self) -> DateTime<Utc> {
            self.state.lock().unwrap().1
        }
    }

    fn limit(requests: u64, window_seconds: u64) -> InvocationLimit {
        InvocationLimit::new(requests, window_seconds).unwrap()
    }

    fn limiter() -> (Arc<ManualClock>, InvocationLimiter) {
        let clock = ManualClock::new();
        (clock.clone(), InvocationLimiter::with_clock(clock))
    }

    #[test]
    fn admits_up_to_the_limit_and_reports_the_rejection() {
        let (_clock, limiter) = limiter();
        let jira = limit(3, 60);
        for _ in 0..3 {
            limiter.try_admit("alice", "jira", jira).unwrap();
        }
        let rejected = limiter.try_admit("alice", "jira", jira).unwrap_err();
        assert_eq!(rejected.service, "jira");
        assert_eq!(rejected.limit, jira);
        assert_eq!(rejected.retry_after_seconds, 60);
        assert_eq!(
            rejected.retry_at,
            Utc.with_ymd_and_hms(2026, 9, 25, 14, 4, 0).unwrap()
        );
        // Keys are independent per principal and per service.
        limiter.try_admit("bob", "jira", jira).unwrap();
        limiter.try_admit("alice", "gitlab", jira).unwrap();
    }

    #[test]
    fn history_expires_after_the_trailing_window() {
        let (clock, limiter) = limiter();
        let two_per_ten = limit(2, 10);
        limiter.try_admit("alice", "jira", two_per_ten).unwrap();
        clock.advance(Duration::from_secs(4));
        limiter.try_admit("alice", "jira", two_per_ten).unwrap();
        let rejected = limiter.try_admit("alice", "jira", two_per_ten).unwrap_err();
        // The first request leaves the window 10s after it was admitted.
        assert_eq!(rejected.retry_after_seconds, 6);
        clock.advance(Duration::from_millis(5_999));
        assert!(limiter.try_admit("alice", "jira", two_per_ten).is_err());
        clock.advance(Duration::from_millis(1));
        limiter.try_admit("alice", "jira", two_per_ten).unwrap();
        let rejected = limiter.try_admit("alice", "jira", two_per_ten).unwrap_err();
        assert_eq!(rejected.retry_after_seconds, 4);
    }

    #[test]
    fn never_admits_more_than_the_limit_in_any_trailing_window() {
        let (clock, limiter) = limiter();
        let five_per_minute = limit(5, 60);
        let mut admitted = Vec::new();
        // Deterministic uneven arrivals over ten minutes.
        for step in 0..6_000_u64 {
            clock.advance(Duration::from_millis(37 + (step * 7919) % 211));
            let now = clock.monotonic();
            if limiter.try_admit("alice", "jira", five_per_minute).is_ok() {
                admitted.push(now);
            }
        }
        assert!(admitted.len() > 40, "{}", admitted.len());
        for (index, admitted_at) in admitted.iter().enumerate() {
            let in_window = admitted[..=index]
                .iter()
                .filter(|earlier| *admitted_at - **earlier < Duration::from_secs(60))
                .count();
            assert!(in_window <= 5, "{in_window} admissions within 60s");
        }
        // Conservative by at most one sub-bucket (1s here): the sixth
        // admission after a burst of five never waits more than 61s.
        for pair in admitted.windows(6) {
            assert!(pair[5] - pair[0] < Duration::from_secs(61) + Duration::from_millis(250));
        }
    }

    #[test]
    fn concurrent_callers_never_exceed_the_limit_in_a_window() {
        let (clock, limiter) = limiter();
        let limiter = Arc::new(limiter);
        let ten_per_minute = limit(10, 60);
        let admitted_concurrently = |limiter: &Arc<InvocationLimiter>| {
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let threads = (0..8)
                .map(|_| {
                    let limiter = limiter.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        (0..25)
                            .filter(|_| limiter.try_admit("alice", "jira", ten_per_minute).is_ok())
                            .count()
                    })
                })
                .collect::<Vec<_>>();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .sum::<usize>()
        };
        assert_eq!(admitted_concurrently(&limiter), 10);
        // Still inside the window: nothing more is admitted.
        clock.advance(Duration::from_secs(59));
        assert_eq!(admitted_concurrently(&limiter), 0);
        // Once the first admissions leave the window, exactly `requests` again.
        clock.advance(Duration::from_secs(1));
        assert_eq!(admitted_concurrently(&limiter), 10);
    }

    /// A clock that steps forward on every reading, so a reading taken before
    /// the limiter's lock would reach it out of order under contention.
    struct SteppingClock {
        now_ns: std::sync::atomic::AtomicU64,
    }

    impl LimiterClock for SteppingClock {
        fn monotonic(&self) -> Duration {
            Duration::from_nanos(
                self.now_ns
                    .fetch_add(10_000_000, std::sync::atomic::Ordering::SeqCst),
            )
        }

        fn wall(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 9, 25, 14, 3, 0).unwrap()
        }
    }

    #[test]
    fn concurrent_admissions_record_in_clock_order() {
        let limiter = Arc::new(InvocationLimiter::with_clock(Arc::new(SteppingClock {
            now_ns: std::sync::atomic::AtomicU64::new(0),
        })));
        // 10ms per reading and 1s sub-buckets: 4,000 readings span 40 buckets
        // of 100 readings each, all inside the window.
        let generous = limit(1_000_000, 60);
        let threads = (0..8)
            .map(|_| {
                let limiter = limiter.clone();
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        limiter.try_admit("alice", "jira", generous).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        let state = limiter.state.lock().unwrap();
        let window = &state.keys["alice"]["jira"];
        assert_eq!(window.total, 4_000);
        assert_eq!(window.buckets.len(), 40);
        for pair in window.buckets.iter().collect::<Vec<_>>().windows(2) {
            assert!(pair[0].index < pair[1].index);
            assert!(pair[0].last_ns < pair[1].last_ns);
        }
    }

    #[test]
    fn earlier_readings_never_move_buckets_backwards() {
        let mut window = KeyWindow::new(60 * NANOS_PER_SECOND);
        window.record(5 * NANOS_PER_SECOND);
        // A reading from an earlier bucket joins the newest bucket.
        window.record(3 * NANOS_PER_SECOND);
        assert_eq!(window.buckets.len(), 1);
        assert_eq!(window.buckets[0].index, 5);
        assert_eq!(window.buckets[0].count, 2);
        assert_eq!(window.buckets[0].last_ns, 5 * NANOS_PER_SECOND);
        // An earlier reading within the same bucket keeps the later last_ns.
        window.record(5 * NANOS_PER_SECOND + 900_000_000);
        window.record(5 * NANOS_PER_SECOND + 100_000_000);
        assert_eq!(
            window.buckets[0].last_ns,
            5 * NANOS_PER_SECOND + 900_000_000
        );
        window.record(7 * NANOS_PER_SECOND);
        window.record(6 * NANOS_PER_SECOND);
        assert_eq!(
            window
                .buckets
                .iter()
                .map(|bucket| (bucket.index, bucket.count))
                .collect::<Vec<_>>(),
            [(5, 4), (7, 2)]
        );
        assert_eq!(window.total, 6);
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds_with_a_minimum_of_one() {
        let (clock, limiter) = limiter();
        let one_per_ten = limit(1, 10);
        limiter.try_admit("alice", "jira", one_per_ten).unwrap();
        clock.advance(Duration::from_millis(8_500));
        let rejected = limiter.try_admit("alice", "jira", one_per_ten).unwrap_err();
        // 1.5s remain: rounded up to 2s, and retryAt is a whole second no
        // earlier than the admission instant.
        assert_eq!(rejected.retry_after_seconds, 2);
        assert_eq!(
            rejected.retry_at,
            Utc.with_ymd_and_hms(2026, 9, 25, 14, 3, 11).unwrap()
        );
        clock.advance(Duration::from_millis(1_499));
        let rejected = limiter.try_admit("alice", "jira", one_per_ten).unwrap_err();
        assert_eq!(rejected.retry_after_seconds, 1);
        clock.advance(Duration::from_millis(1));
        limiter.try_admit("alice", "jira", one_per_ten).unwrap();
    }

    #[test]
    fn rejected_requests_are_not_recorded() {
        let (clock, limiter) = limiter();
        let one_per_ten = limit(1, 10);
        limiter.try_admit("alice", "jira", one_per_ten).unwrap();
        for _ in 0..9 {
            clock.advance(Duration::from_secs(1));
            assert!(limiter.try_admit("alice", "jira", one_per_ten).is_err());
        }
        clock.advance(Duration::from_secs(1));
        limiter.try_admit("alice", "jira", one_per_ten).unwrap();
    }

    #[test]
    fn requests_changes_keep_history_and_window_changes_reset_it() {
        let (clock, limiter) = limiter();
        for _ in 0..3 {
            limiter.try_admit("alice", "jira", limit(3, 60)).unwrap();
        }
        assert!(limiter.try_admit("alice", "jira", limit(3, 60)).is_err());
        // A higher limit with the same window evaluates the kept history.
        limiter.try_admit("alice", "jira", limit(4, 60)).unwrap();
        assert!(limiter.try_admit("alice", "jira", limit(4, 60)).is_err());
        // A lower limit waits until enough history expires.
        clock.advance(Duration::from_secs(1));
        let rejected = limiter
            .try_admit("alice", "jira", limit(1, 60))
            .unwrap_err();
        assert_eq!(rejected.retry_after_seconds, 59);
        // A different window resets the key.
        limiter.try_admit("alice", "jira", limit(1, 30)).unwrap();
        assert!(limiter.try_admit("alice", "jira", limit(1, 30)).is_err());
    }

    #[test]
    fn memory_per_key_is_bounded_by_sub_buckets() {
        let (clock, limiter) = limiter();
        let generous = limit(1_000_000, 60);
        for _ in 0..10_000 {
            clock.advance(Duration::from_millis(13));
            limiter.try_admit("alice", "jira", generous).unwrap();
        }
        let state = limiter.state.lock().unwrap();
        let window = &state.keys["alice"]["jira"];
        assert!(window.buckets.len() <= SLOTS, "{}", window.buckets.len());
        assert_eq!(
            window.total,
            window
                .buckets
                .iter()
                .map(|bucket| u64::from(bucket.count))
                .sum::<u64>()
        );
    }

    #[test]
    fn idle_expired_keys_are_pruned_by_amortized_sweeps() {
        let (clock, limiter) = limiter();
        for principal in 0..50 {
            limiter
                .try_admit(&format!("agent-{principal}"), "jira", limit(5, 10))
                .unwrap();
        }
        limiter.try_admit("long", "jira", limit(5, 3_600)).unwrap();
        assert_eq!(limiter.key_count(), 51);
        // Before the sweep interval nothing is scanned.
        clock.advance(Duration::from_secs(30));
        limiter.try_admit("fresh", "jira", limit(5, 10)).unwrap();
        assert_eq!(limiter.key_count(), 52);
        clock.advance(Duration::from_secs(31));
        limiter.try_admit("fresh", "jira", limit(5, 10)).unwrap();
        // Only keys with live history remain: the hour window and the key
        // just admitted.
        assert_eq!(limiter.key_count(), 2);
        let state = limiter.state.lock().unwrap();
        assert!(state.keys.contains_key("long") && state.keys.contains_key("fresh"));
    }

    #[test]
    fn key_growth_triggers_a_sweep_without_rejecting_new_keys() {
        let (clock, limiter) = limiter();
        for principal in 0..MIN_SWEEP_KEYS - 1 {
            limiter
                .try_admit(&format!("agent-{principal}"), "jira", limit(1, 1))
                .unwrap();
        }
        clock.advance(Duration::from_secs(2));
        limiter.try_admit("new-1", "jira", limit(1, 1)).unwrap();
        assert_eq!(limiter.key_count(), MIN_SWEEP_KEYS);
        limiter.try_admit("new-2", "jira", limit(1, 1)).unwrap();
        assert_eq!(limiter.key_count(), 2);
    }
}
