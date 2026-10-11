//! Upstream throttling: a bounded reading of an upstream `Retry-After` and
//! the `upstream_rate_limited` error every backend reports throttling with.
//!
//! The broker's own `rate_limited` is reserved for broker limits. When an
//! upstream service throttles a request, backends return
//! [`ReasonCode::UpstreamRateLimited`] with a result carrying
//! `limitScope: "upstream"`, the `service`, and, when the upstream said how
//! long to wait, `retryAfterSeconds` and `retryAt`. The result never claims
//! the request was not dispatched or is safe to retry: a multi-step action
//! may already have performed earlier upstream calls.
//!
//! Throttling of a read-back or verification made after a mutation was
//! applied is not reported as `upstream_rate_limited`, because that invites a
//! retry that repeats the write. [`mutation_unverified_after_throttling`],
//! [`ProviderError::unverified_if_throttled`], and
//! [`ProviderError::unverified_after_throttling`] report it as
//! `mutation_verification_failed` with `mutationStatus: "applied_unverified"`,
//! `retrySafe: false`, and no retry wait. So does a batch whose later write
//! was throttled after earlier writes applied
//! ([`ProviderError::partially_applied_before_throttling`]).

use crate::{Decision, ProviderError, ReasonCode};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, TimeDelta, Utc};
use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde_json::{Map, Value, json};

/// The longest wait reported from an upstream `Retry-After`: one day.
pub const UPSTREAM_RETRY_AFTER_MAX_SECONDS: u64 = 86_400;

/// When an upstream service said it will accept requests again, bounded to
/// between one second and [`UPSTREAM_RETRY_AFTER_MAX_SECONDS`] after the
/// broker read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamRetryAfter {
    seconds: u64,
    at: DateTime<Utc>,
}

impl UpstreamRetryAfter {
    /// Reads a response's `Retry-After`. Absent, repeated, or invalid values
    /// give `None`: the wait is then unknown.
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        Self::from_headers_at(headers, Utc::now())
    }

    /// [`Self::from_headers`] relative to `now`.
    pub fn from_headers_at(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Self> {
        let mut values = headers.get_all(RETRY_AFTER).iter();
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        Self::parse_at(value.to_str().ok()?, now)
    }

    /// Parses a `Retry-After` value: delta-seconds or an HTTP-date
    /// (IMF-fixdate, or the obsolete RFC 850 and asctime forms).
    pub fn parse(value: &str) -> Option<Self> {
        Self::parse_at(value, Utc::now())
    }

    /// [`Self::parse`] relative to `now`.
    pub fn parse_at(value: &str, now: DateTime<Utc>) -> Option<Self> {
        let value = value.trim();
        let target = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            // Digits too long for u64 are still a valid, very long delay.
            let seconds = value
                .parse::<u64>()
                .unwrap_or(u64::MAX)
                .min(UPSTREAM_RETRY_AFTER_MAX_SECONDS);
            now + TimeDelta::seconds(seconds as i64)
        } else {
            parse_http_date(value)?
        };
        Some(Self::until(target, now))
    }

    /// A wait of `seconds` from now, bounded like a parsed header.
    pub fn after_seconds(seconds: u64) -> Self {
        Self::after_seconds_at(seconds, Utc::now())
    }

    /// [`Self::after_seconds`] relative to `now`.
    pub fn after_seconds_at(seconds: u64, now: DateTime<Utc>) -> Self {
        let seconds = seconds.min(UPSTREAM_RETRY_AFTER_MAX_SECONDS);
        Self::until(now + TimeDelta::seconds(seconds as i64), now)
    }

    fn until(target: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        let target = target.clamp(
            now + TimeDelta::seconds(1),
            now + TimeDelta::seconds(UPSTREAM_RETRY_AFTER_MAX_SECONDS as i64),
        );
        let millis = u64::try_from((target - now).num_milliseconds()).unwrap_or(1000);
        Self {
            seconds: millis.div_ceil(1000),
            at: ceil_to_second(target),
        }
    }

    /// Whole seconds to wait, from 1 to one day.
    pub fn seconds(&self) -> u64 {
        self.seconds
    }

    /// The earliest time to retry, in whole seconds.
    pub fn at(&self) -> DateTime<Utc> {
        self.at
    }

    /// [`Self::at`] as RFC 3339 UTC with seconds precision.
    pub fn retry_at(&self) -> String {
        self.at.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

fn ceil_to_second(value: DateTime<Utc>) -> DateTime<Utc> {
    if value.timestamp_subsec_nanos() == 0 {
        return value;
    }
    DateTime::from_timestamp(value.timestamp() + 1, 0).unwrap_or(value)
}

fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ]
    .into_iter()
    .find_map(|format| NaiveDateTime::parse_from_str(value, format).ok())
    .map(|value| value.and_utc())
}

/// When to retry, as caller-facing text: `Retry after 30s (at ...).` or
/// `Retry later.`
pub fn upstream_retry_hint(retry_after: Option<&UpstreamRetryAfter>) -> String {
    match retry_after {
        Some(retry_after) => format!(
            "Retry after {}s (at {}).",
            retry_after.seconds(),
            retry_after.retry_at()
        ),
        None => "Retry later.".to_owned(),
    }
}

/// The caller-facing message: the service and, when known, the wait.
pub fn upstream_rate_limited_message(
    service: &str,
    retry_after: Option<&UpstreamRetryAfter>,
) -> String {
    format!(
        "{service} is rate limiting requests. {}",
        upstream_retry_hint(retry_after)
    )
}

/// The `upstream_rate_limited` error for `service`.
pub fn upstream_rate_limited(
    service: &str,
    retry_after: Option<UpstreamRetryAfter>,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamRateLimited,
        upstream_rate_limited_message(service, retry_after.as_ref()),
    )
    .with_upstream_rate_limit(service, retry_after)
}

/// The caller-facing message for a mutation whose read-back or verification
/// `service` throttled.
pub fn mutation_unverified_after_throttling_message(service: &str) -> String {
    format!(
        "The mutation was applied, but {service} is rate limiting the requests that verify it, \
         so it is unverified. Do not repeat the mutation; inspect result.safeLocators first."
    )
}

/// The `mutation_verification_failed` error for a mutation that was applied
/// but whose read-back or verification `service` throttled. The result
/// reports `mutationStatus: "applied_unverified"`, `retrySafe: false`, the
/// provider's `verificationStage`, and `safeLocators` identifying what was
/// created or changed. It carries no `retryAfterSeconds` (so no
/// `Retry-After`): waiting and repeating the request would repeat the write.
pub fn mutation_unverified_after_throttling(
    service: &str,
    verification_stage: &str,
    safe_locators: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::MutationVerificationFailed,
        mutation_unverified_after_throttling_message(service),
    )
    .with_result(json!({
        "mutationStatus": "applied_unverified",
        "retrySafe": false,
        "verificationStage": verification_stage,
        "safeLocators": safe_locators,
    }))
}

impl ProviderError {
    /// For an error from a read-back or verification made after a mutation
    /// was applied: upstream throttling (`upstream_rate_limited`) becomes
    /// [`Self::unverified_after_throttling`] for the service it names. Other
    /// errors are returned unchanged.
    pub fn unverified_if_throttled(self, verification_stage: &str, safe_locators: Value) -> Self {
        if self.reason_code != ReasonCode::UpstreamRateLimited {
            return self;
        }
        let service = self
            .result
            .as_deref()
            .and_then(|result| result.get("service"))
            .and_then(Value::as_str)
            .unwrap_or("the upstream service")
            .to_owned();
        self.unverified_after_throttling(&service, verification_stage, safe_locators)
    }

    /// Reports this error as [`mutation_unverified_after_throttling`]: a
    /// mutation `service` applied but whose verification it throttled. Result
    /// fields the error already carried (for example a partial batch) are
    /// kept, except any throttling scope and wait; audit, upstream status,
    /// and object IDs are kept.
    pub fn unverified_after_throttling(
        self,
        service: &str,
        verification_stage: &str,
        safe_locators: Value,
    ) -> Self {
        let mut result = match self.result.map(|result| *result) {
            Some(Value::Object(result)) => result,
            _ => Map::new(),
        };
        for field in ["limitScope", "service", "retryAfterSeconds", "retryAt"] {
            result.remove(field);
        }
        let unverified =
            mutation_unverified_after_throttling(service, verification_stage, safe_locators);
        if let Some(Value::Object(fields)) = unverified.result.map(|result| *result) {
            result.extend(fields);
        }
        Self {
            decision: unverified.decision,
            reason_code: unverified.reason_code,
            message: unverified.message,
            result: Some(Box::new(Value::Object(result))),
            ..self
        }
    }

    /// For a batch whose later write `service` throttled after earlier writes
    /// in it were applied: [`Self::unverified_after_throttling`], because
    /// waiting and repeating the batch would repeat the applied writes. The
    /// message follows this error's own, which says what the batch did.
    /// Keep `upstream_rate_limited` only when no write in the batch applied.
    pub fn partially_applied_before_throttling(
        self,
        service: &str,
        verification_stage: &str,
        safe_locators: Value,
    ) -> Self {
        let message = format!(
            "{}: part of the batch was applied before {service} started rate limiting \
             requests. Do not repeat the batch; inspect result.safeLocators first.",
            self.message
        );
        let mut error =
            self.unverified_after_throttling(service, verification_stage, safe_locators);
        error.message = message;
        error
    }

    /// Reports this error as upstream throttling of `service`. Adds
    /// `limitScope`, `service`, and the known wait to the result, keeping
    /// every field the provider already reported there (for example
    /// `mutationStatus` and `retrySafe`). The message is left unchanged.
    pub fn with_upstream_rate_limit(
        mut self,
        service: &str,
        retry_after: Option<UpstreamRetryAfter>,
    ) -> Self {
        let mut result = match self.result.take().map(|result| *result) {
            Some(Value::Object(result)) => result,
            _ => Map::new(),
        };
        result.insert("limitScope".into(), json!("upstream"));
        result.insert("service".into(), json!(service));
        result.remove("retryAfterSeconds");
        result.remove("retryAt");
        if let Some(retry_after) = retry_after {
            result.insert("retryAfterSeconds".into(), json!(retry_after.seconds()));
            result.insert("retryAt".into(), json!(retry_after.retry_at()));
        }
        self.decision = Decision::Error;
        self.reason_code = ReasonCode::UpstreamRateLimited;
        self.result = Some(Box::new(Value::Object(result)));
        self
    }

    /// [`Self::with_upstream_rate_limit`] for an action the throttling
    /// stopped part way through: the throttling message follows this error's
    /// own, which says what the action did.
    pub fn interrupted_by_upstream_rate_limit(
        self,
        service: &str,
        retry_after: Option<UpstreamRetryAfter>,
    ) -> Self {
        let message = format!(
            "{}: {}",
            self.message,
            upstream_rate_limited_message(service, retry_after.as_ref())
        );
        let mut error = self.with_upstream_rate_limit(service, retry_after);
        error.message = message;
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-25T14:03:00.250Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn delta_seconds_are_bounded_to_one_day_and_at_least_one_second() {
        let wait = UpstreamRetryAfter::parse_at("30", now()).unwrap();
        assert_eq!(wait.seconds(), 30);
        assert_eq!(wait.retry_at(), "2026-09-25T14:03:31Z");
        let wait = UpstreamRetryAfter::parse_at(" 12 ", now()).unwrap();
        assert_eq!(wait.seconds(), 12);
        assert_eq!(
            UpstreamRetryAfter::parse_at("0", now()).unwrap().seconds(),
            1
        );
        let capped = UpstreamRetryAfter::parse_at("86401", now()).unwrap();
        assert_eq!(capped.seconds(), 86_400);
        assert_eq!(capped.retry_at(), "2026-09-26T14:03:01Z");
        let overflow = UpstreamRetryAfter::parse_at("99999999999999999999999", now()).unwrap();
        assert_eq!(overflow.seconds(), 86_400);
    }

    #[test]
    fn http_dates_in_every_rfc_9110_form_parse_relative_to_now() {
        for value in [
            "Fri, 25 Sep 2026 14:03:30 GMT",
            "Friday, 25-Sep-26 14:03:30 GMT",
            "Fri Sep 25 14:03:30 2026",
        ] {
            let wait = UpstreamRetryAfter::parse_at(value, now()).unwrap();
            assert_eq!(wait.seconds(), 30, "{value}");
            assert_eq!(wait.retry_at(), "2026-09-25T14:03:30Z", "{value}");
        }
        let single_digit_day = DateTime::parse_from_rfc3339("2026-09-05T14:03:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            UpstreamRetryAfter::parse_at("Sat Sep  5 14:04:00 2026", single_digit_day)
                .unwrap()
                .seconds(),
            60
        );
        let past = UpstreamRetryAfter::parse_at("Fri, 25 Sep 2026 14:00:00 GMT", now()).unwrap();
        assert_eq!(past.seconds(), 1);
        let far = UpstreamRetryAfter::parse_at("Fri, 01 Jan 2027 00:00:00 GMT", now()).unwrap();
        assert_eq!(far.seconds(), 86_400);
        assert_eq!(far.retry_at(), "2026-09-26T14:03:01Z");
    }

    #[test]
    fn invalid_or_ambiguous_values_leave_the_wait_unknown() {
        for value in ["", "soon", "-5", "1.5", "Fri, 25 Sep 2026 14:03:30 PST"] {
            assert_eq!(
                UpstreamRetryAfter::parse_at(value, now()),
                None,
                "{value:?}"
            );
        }
        let mut headers = HeaderMap::new();
        assert_eq!(UpstreamRetryAfter::from_headers_at(&headers, now()), None);
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));
        assert_eq!(
            UpstreamRetryAfter::from_headers_at(&headers, now()).map(|wait| wait.seconds()),
            Some(7)
        );
        headers.append(RETRY_AFTER, HeaderValue::from_static("9"));
        assert_eq!(UpstreamRetryAfter::from_headers_at(&headers, now()), None);
    }

    #[test]
    fn throttling_after_an_applied_mutation_is_unverified_without_a_wait() {
        let direct = mutation_unverified_after_throttling(
            "jira",
            "post_create_readback",
            json!({"issueKey": "OPS-1"}),
        );
        assert_eq!(direct.decision, Decision::Error);
        assert_eq!(direct.reason_code, ReasonCode::MutationVerificationFailed);
        assert_eq!(
            direct.message,
            mutation_unverified_after_throttling_message("jira")
        );
        assert!(direct.message.contains("jira is rate limiting"));
        assert!(!direct.message.contains("Retry after"));
        assert_eq!(
            direct.result.as_deref(),
            Some(&json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "post_create_readback",
                "safeLocators": {"issueKey": "OPS-1"},
            }))
        );

        let throttled =
            upstream_rate_limited("confluence", UpstreamRetryAfter::parse_at("30", now()))
                .with_result(json!({
                    "status": "partial",
                    "attachments": [{"attachmentId": "att1"}],
                    "limitScope": "upstream",
                    "service": "confluence",
                    "retryAfterSeconds": 30,
                    "retryAt": "2026-09-25T14:03:31Z",
                }))
                .with_audit(json!({"operation": "attachment.add"}))
                .with_upstream(Some(200), Some(12))
                .with_object_ids(json!({"pageId": "7"}))
                .unverified_if_throttled("post_upload_readback", json!({"pageId": "7"}));
        assert_eq!(
            throttled.reason_code,
            ReasonCode::MutationVerificationFailed
        );
        assert_eq!(
            throttled.message,
            mutation_unverified_after_throttling_message("confluence")
        );
        assert_eq!(
            throttled.result.as_deref(),
            Some(&json!({
                "status": "partial",
                "attachments": [{"attachmentId": "att1"}],
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "post_upload_readback",
                "safeLocators": {"pageId": "7"},
            }))
        );
        assert_eq!(
            throttled.audit.as_deref(),
            Some(&json!({"operation": "attachment.add"}))
        );
        assert_eq!(throttled.upstream_status, Some(200));
        assert_eq!(
            throttled.object_ids.as_deref(),
            Some(&json!({"pageId": "7"}))
        );

        let batch = ProviderError::error(ReasonCode::UpstreamFailed, "partially failed")
            .with_result(json!({"status": "partial"}))
            .unverified_after_throttling("confluence", "post_upload_readback", json!({}));
        assert_eq!(batch.reason_code, ReasonCode::MutationVerificationFailed);
        assert_eq!(batch.result.as_deref().unwrap()["status"], "partial");
        assert_eq!(
            batch.result.as_deref().unwrap()["mutationStatus"],
            "applied_unverified"
        );

        let partial = ProviderError::error(ReasonCode::UpstreamFailed, "Upload partially failed")
            .with_result(json!({"status": "partial", "attachments": [{"attachmentId": "att1"}]}))
            .partially_applied_before_throttling(
                "jira",
                "attachment_upload",
                json!({"attachmentIds": ["att1"]}),
            );
        assert_eq!(partial.reason_code, ReasonCode::MutationVerificationFailed);
        assert_eq!(
            partial.message,
            "Upload partially failed: part of the batch was applied before jira started rate \
             limiting requests. Do not repeat the batch; inspect result.safeLocators first."
        );
        assert_eq!(
            partial.result.as_deref(),
            Some(&json!({
                "status": "partial",
                "attachments": [{"attachmentId": "att1"}],
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "attachment_upload",
                "safeLocators": {"attachmentIds": ["att1"]},
            }))
        );

        let other = ProviderError::error(ReasonCode::UpstreamFailed, "failed")
            .unverified_if_throttled("post_upload_readback", json!({}));
        assert_eq!(other.reason_code, ReasonCode::UpstreamFailed);
        assert_eq!(other.message, "failed");
        assert!(other.result.is_none());
    }

    #[test]
    fn errors_name_the_service_and_merge_into_existing_results() {
        let wait = UpstreamRetryAfter::parse_at("30", now());
        let error = upstream_rate_limited("jira", wait);
        assert_eq!(error.decision, Decision::Error);
        assert_eq!(error.reason_code, ReasonCode::UpstreamRateLimited);
        assert_eq!(error.reason_code.http_status(), 429);
        assert_eq!(
            error.message,
            "jira is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:31Z)."
        );
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                "limitScope": "upstream",
                "service": "jira",
                "retryAfterSeconds": 30,
                "retryAt": "2026-09-25T14:03:31Z",
            }))
        );

        let unknown = upstream_rate_limited("gitlab", None);
        assert_eq!(
            unknown.message,
            "gitlab is rate limiting requests. Retry later."
        );
        assert_eq!(
            unknown.result.as_deref(),
            Some(&json!({"limitScope": "upstream", "service": "gitlab"}))
        );

        let merged = ProviderError::error(ReasonCode::UpstreamFailed, "partial")
            .with_result(json!({"mutationStatus": "applied", "retrySafe": false}))
            .with_upstream_rate_limit("jira", None);
        assert_eq!(merged.reason_code, ReasonCode::UpstreamRateLimited);
        assert_eq!(merged.message, "partial");
        let interrupted = ProviderError::deny(ReasonCode::UpstreamFailed, "Upload stopped")
            .with_result(json!({"status": "partial"}))
            .interrupted_by_upstream_rate_limit("jira", wait);
        assert_eq!(interrupted.decision, Decision::Error);
        assert_eq!(
            interrupted.message,
            "Upload stopped: jira is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:31Z)."
        );
        assert_eq!(interrupted.result.as_deref().unwrap()["status"], "partial");
        assert_eq!(
            interrupted.result.as_deref().unwrap()["retryAfterSeconds"],
            30
        );
        assert_eq!(
            merged.result.as_deref(),
            Some(&json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "limitScope": "upstream",
                "service": "jira",
            }))
        );
    }
}
