//! Per-principal, per-service invocation rate limits: `[limits.invocations]`
//! configuration, validation, effective-limit resolution, and the canonical
//! `rate_limited` rejection.
//!
//! The broker counts each admitted service invocation once in a rolling window
//! keyed by `(principal, service)`. This module decides which limit applies and
//! how a rejection is described; the in-memory window itself lives in the
//! broker's ingress layer.

use crate::{
    BrokerConfig, ProviderError, ReasonCode, ServiceDescriptor, is_service_name, parse_ttl_seconds,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Smallest accepted `requests` value.
pub const INVOCATION_LIMIT_MIN_REQUESTS: u32 = 1;
/// Largest accepted `requests` value.
pub const INVOCATION_LIMIT_MAX_REQUESTS: u32 = 1_000_000;
/// Shortest accepted window (`1s`).
pub const INVOCATION_LIMIT_MIN_WINDOW_SECONDS: u32 = 1;
/// Longest accepted window (`1d`).
pub const INVOCATION_LIMIT_MAX_WINDOW_SECONDS: u32 = 86_400;
/// Applies when neither a principal override, a service limit, nor a
/// configured default exists: 100 requests per `1m`.
pub const BUILT_IN_INVOCATION_LIMIT: InvocationLimit = InvocationLimit {
    requests: 100,
    window_seconds: 60,
};
/// `result.limitScope` of broker-owned per-principal invocation limits.
pub const INVOCATION_LIMIT_SCOPE_PRINCIPAL: &str = "principal";

/// `[limits.invocations]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationLimitsConfig {
    /// Default for every configured service; the built-in default applies when absent.
    #[serde(default)]
    pub default: Option<InvocationLimitConfig>,
    /// `[limits.invocations.services.<service>]` per-service defaults.
    #[serde(default)]
    pub services: BTreeMap<String, InvocationLimitConfig>,
    /// Only valid with `identity.authority = "toml"`; managed deployments keep
    /// overrides in the managed store.
    #[serde(default)]
    pub principal_overrides: Vec<PrincipalInvocationLimitConfig>,
}

/// One configured `{ requests, window }` pair.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationLimitConfig {
    pub requests: u64,
    /// Broker duration syntax (`s`, `m`, `h`, `d`), from `1s` to `1d`.
    pub window: String,
}

/// `[[limits.invocations.principal_overrides]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalInvocationLimitConfig {
    pub principal: String,
    pub service: String,
    pub requests: u64,
    pub window: String,
}

/// Why a `requests`/window pair is not a valid invocation limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvocationLimitError {
    #[error("requests must be an integer from 1 to 1000000")]
    RequestsOutOfRange,
    #[error("window must use the s, m, h, or d duration syntax, for example 30s or 1m")]
    WindowInvalid,
    #[error("window must be between 1s and 1d")]
    WindowOutOfRange,
}

/// A validated limit: at most `requests` admitted requests in any trailing
/// `window_seconds`. Serializes as `{"requests":..,"windowSeconds":..}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationLimit {
    requests: u32,
    window_seconds: u32,
}

impl InvocationLimit {
    /// Validates `requests` (1..=1,000,000) and `window_seconds` (1..=86,400).
    pub fn new(requests: u64, window_seconds: u64) -> Result<Self, InvocationLimitError> {
        let requests = u32::try_from(requests)
            .ok()
            .filter(|value| {
                (INVOCATION_LIMIT_MIN_REQUESTS..=INVOCATION_LIMIT_MAX_REQUESTS).contains(value)
            })
            .ok_or(InvocationLimitError::RequestsOutOfRange)?;
        let window_seconds = u32::try_from(window_seconds)
            .ok()
            .filter(|value| {
                (INVOCATION_LIMIT_MIN_WINDOW_SECONDS..=INVOCATION_LIMIT_MAX_WINDOW_SECONDS)
                    .contains(value)
            })
            .ok_or(InvocationLimitError::WindowOutOfRange)?;
        Ok(Self {
            requests,
            window_seconds,
        })
    }

    /// Parses a window in the broker's `s`/`m`/`h`/`d` duration syntax.
    pub fn parse(requests: u64, window: &str) -> Result<Self, InvocationLimitError> {
        let window_seconds =
            parse_ttl_seconds(window).ok_or(InvocationLimitError::WindowInvalid)?;
        Self::new(requests, window_seconds)
    }

    pub fn from_config(config: &InvocationLimitConfig) -> Result<Self, InvocationLimitError> {
        Self::parse(config.requests, &config.window)
    }

    pub fn requests(&self) -> u32 {
        self.requests
    }

    pub fn window_seconds(&self) -> u32 {
        self.window_seconds
    }

    /// The window in its shortest exact unit, for example `30s`, `1m`, `90s`, `1h`.
    pub fn window_label(&self) -> String {
        format_duration_label(u64::from(self.window_seconds))
    }
}

/// Formats seconds in the shortest exact unit: `30s`, `1m`, `90s`, `1h`, `1d`.
pub fn format_duration_label(seconds: u64) -> String {
    for (size, unit) in [(86_400, "d"), (3_600, "h"), (60, "m")] {
        if seconds >= size && seconds.is_multiple_of(size) {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

/// Formats a retry instant as RFC 3339 UTC with whole seconds (`2026-09-25T14:03:12Z`).
pub fn format_retry_at(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The limit that applies to one principal and service. Serializes as the
/// admin service-limit item: `{"service","requests","windowSeconds","overridden"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveInvocationLimit {
    pub service: String,
    pub requests: u32,
    pub window_seconds: u32,
    /// True when a principal override (TOML or managed store) supplied the limit.
    pub overridden: bool,
}

impl EffectiveInvocationLimit {
    fn new(service: &str, limit: InvocationLimit, overridden: bool) -> Self {
        Self {
            service: service.to_string(),
            requests: limit.requests,
            window_seconds: limit.window_seconds,
            overridden,
        }
    }

    pub fn limit(&self) -> InvocationLimit {
        InvocationLimit {
            requests: self.requests,
            window_seconds: self.window_seconds,
        }
    }
}

/// `[limits.invocations]` resolved once per runtime generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredInvocationLimits {
    default: InvocationLimit,
    services: BTreeMap<String, InvocationLimit>,
    /// principal -> service -> limit; populated only for TOML identity authority.
    principal_overrides: BTreeMap<String, BTreeMap<String, InvocationLimit>>,
}

impl Default for ConfiguredInvocationLimits {
    fn default() -> Self {
        Self {
            default: BUILT_IN_INVOCATION_LIMIT,
            services: BTreeMap::new(),
            principal_overrides: BTreeMap::new(),
        }
    }
}

impl ConfiguredInvocationLimits {
    /// Resolves validated configuration. Invalid entries (which validation
    /// already reports) are ignored rather than guessed at.
    pub fn from_config(config: &BrokerConfig) -> Self {
        let invocations = &config.limits.invocations;
        let default = invocations
            .default
            .as_ref()
            .and_then(|limit| InvocationLimit::from_config(limit).ok())
            .unwrap_or(BUILT_IN_INVOCATION_LIMIT);
        let services = invocations
            .services
            .iter()
            .filter_map(|(service, limit)| {
                InvocationLimit::from_config(limit)
                    .ok()
                    .map(|limit| (service.clone(), limit))
            })
            .collect();
        let mut principal_overrides: BTreeMap<String, BTreeMap<String, InvocationLimit>> =
            BTreeMap::new();
        if config.identity.authority == "toml" {
            for entry in &invocations.principal_overrides {
                if let Ok(limit) = InvocationLimit::parse(entry.requests, &entry.window) {
                    principal_overrides
                        .entry(entry.principal.clone())
                        .or_default()
                        .insert(entry.service.clone(), limit);
                }
            }
        }
        Self {
            default,
            services,
            principal_overrides,
        }
    }

    /// Service limit, else configured default, else built-in default. Ignores
    /// principal overrides.
    pub fn service_limit(&self, service: &str) -> InvocationLimit {
        self.services.get(service).copied().unwrap_or(self.default)
    }

    /// The TOML principal override for a service, if any.
    pub fn principal_override(&self, principal: &str, service: &str) -> Option<InvocationLimit> {
        self.principal_overrides
            .get(principal)
            .and_then(|services| services.get(service))
            .copied()
    }

    /// Resolves precedence given the principal's override, if any.
    pub fn effective(
        &self,
        service: &str,
        principal_override: Option<InvocationLimit>,
    ) -> EffectiveInvocationLimit {
        match principal_override {
            Some(limit) => EffectiveInvocationLimit::new(service, limit, true),
            None => EffectiveInvocationLimit::new(service, self.service_limit(service), false),
        }
    }
}

/// A broker-owned `rate_limited` rejection for one principal and service.
/// Convert with [`InvocationRateLimited::into_provider_error`]; the request
/// was not dispatched and is safe to retry after `retry_after_seconds`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRateLimited {
    pub service: String,
    pub limit: InvocationLimit,
    /// Whole seconds, at least 1.
    pub retry_after_seconds: u64,
    /// Instant after which a request would be admitted, whole seconds UTC.
    pub retry_at: DateTime<Utc>,
}

impl InvocationRateLimited {
    /// Complete on its own because agents often see only text.
    pub fn message(&self) -> String {
        let requests = self.limit.requests;
        let noun = if requests == 1 { "request" } else { "requests" };
        format!(
            "Rate limit reached for service \"{}\": {requests} {noun} per {}. Retry after {}s (at {}). The request was not executed.",
            self.service,
            self.limit.window_label(),
            self.retry_after_seconds,
            format_retry_at(self.retry_at),
        )
    }

    /// Structured error `result`.
    pub fn result(&self) -> Value {
        json!({
            "limitScope": INVOCATION_LIMIT_SCOPE_PRINCIPAL,
            "service": self.service,
            "limit": self.limit.requests,
            "windowSeconds": self.limit.window_seconds,
            "retryAfterSeconds": self.retry_after_seconds,
            "retryAt": format_retry_at(self.retry_at),
            "executionState": "not_dispatched",
            "retrySafe": true,
        })
    }

    /// `providerAudit` of the rejected request's audit record.
    pub fn audit(&self) -> Value {
        json!({
            "rateLimit": {
                "limitScope": INVOCATION_LIMIT_SCOPE_PRINCIPAL,
                "service": self.service,
                "limit": self.limit.requests,
                "windowSeconds": self.limit.window_seconds,
                "retryAfterSeconds": self.retry_after_seconds,
            }
        })
    }

    pub fn into_provider_error(self) -> ProviderError {
        ProviderError::error(ReasonCode::RateLimited, self.message())
            .with_result(self.result())
            .with_audit(self.audit())
    }
}

/// Reads a positive whole-second `retryAfterSeconds` from an error `result`.
/// Any broker error carrying it also carries the `Retry-After` header.
pub fn result_retry_after_seconds(result: Option<&Value>) -> Option<u64> {
    result?
        .get("retryAfterSeconds")?
        .as_u64()
        .filter(|seconds| *seconds > 0)
}

pub(crate) fn validate_invocation_limits(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    errors: &mut Vec<String>,
) {
    let invocations = &config.limits.invocations;
    if let Some(default) = &invocations.default {
        validate_limit("limits.invocations.default", default, errors);
    }
    for (service, limit) in &invocations.services {
        let label = format!("limits.invocations.services.{service}");
        validate_limit(&label, limit, errors);
        if !services.contains_key(service) {
            errors.push(format!("{label} references unknown service {service}"));
        }
    }
    if invocations.principal_overrides.is_empty() {
        return;
    }
    if config.identity.authority != "toml" {
        errors.push(
            "limits.invocations.principal_overrides is only valid when identity.authority = toml; managed deployments store principal overrides in the managed store"
                .to_string(),
        );
        return;
    }
    let static_principals = config
        .identity
        .sources
        .iter()
        .filter(|source| source.kind == "static_principals")
        .flat_map(|source| source.principals.iter())
        .map(|principal| principal.principal.as_str())
        .chain(std::iter::once("anonymous"))
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for (index, entry) in invocations.principal_overrides.iter().enumerate() {
        let label = format!("limits.invocations.principal_overrides[{index}]");
        if let Err(error) = InvocationLimit::parse(entry.requests, &entry.window) {
            errors.push(format!("{label}: {error}"));
        }
        if !static_principals.contains(entry.principal.as_str()) {
            errors.push(format!(
                "{label} references unknown principal {}; use a configured static principal or anonymous",
                entry.principal
            ));
        }
        if !is_service_name(&entry.service) || !services.contains_key(&entry.service) {
            errors.push(format!(
                "{label} references unknown service {}",
                entry.service
            ));
        }
        if !seen.insert((entry.principal.as_str(), entry.service.as_str())) {
            errors.push(format!(
                "{label} duplicates the override for principal {} and service {}",
                entry.principal, entry.service
            ));
        }
    }
}

fn validate_limit(label: &str, limit: &InvocationLimitConfig, errors: &mut Vec<String>) {
    if let Err(error) = InvocationLimit::from_config(limit) {
        errors.push(format!("{label}: {error}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn limits_accept_only_the_documented_ranges() {
        assert_eq!(
            InvocationLimit::parse(1, "1s").unwrap(),
            InvocationLimit {
                requests: 1,
                window_seconds: 1
            }
        );
        assert_eq!(
            InvocationLimit::parse(1_000_000, "1d")
                .unwrap()
                .window_seconds(),
            86_400
        );
        assert_eq!(
            InvocationLimit::parse(0, "1m"),
            Err(InvocationLimitError::RequestsOutOfRange)
        );
        assert_eq!(
            InvocationLimit::parse(1_000_001, "1m"),
            Err(InvocationLimitError::RequestsOutOfRange)
        );
        assert_eq!(
            InvocationLimit::parse(u64::MAX, "1m"),
            Err(InvocationLimitError::RequestsOutOfRange)
        );
        for window in ["", "0s", "1", "m", "1w", "1.5m", "-1m", " 1 m"] {
            assert_eq!(
                InvocationLimit::parse(1, window),
                Err(InvocationLimitError::WindowInvalid),
                "{window}"
            );
        }
        for window in ["86401s", "25h", "2d"] {
            assert_eq!(
                InvocationLimit::parse(1, window),
                Err(InvocationLimitError::WindowOutOfRange),
                "{window}"
            );
        }
        assert_eq!(
            InvocationLimit::new(1, 0),
            Err(InvocationLimitError::WindowOutOfRange)
        );
    }

    #[test]
    fn windows_use_the_shortest_exact_unit() {
        for (seconds, label) in [
            (1, "1s"),
            (30, "30s"),
            (60, "1m"),
            (90, "90s"),
            (120, "2m"),
            (3_600, "1h"),
            (5_400, "90m"),
            (86_400, "1d"),
        ] {
            assert_eq!(format_duration_label(seconds), label);
        }
    }

    #[test]
    fn rejection_message_result_and_audit_follow_the_contract() {
        let rejection = InvocationRateLimited {
            service: "jira".into(),
            limit: InvocationLimit::parse(20, "1m").unwrap(),
            retry_after_seconds: 12,
            retry_at: Utc.with_ymd_and_hms(2026, 9, 25, 14, 3, 12).unwrap(),
        };
        assert_eq!(
            rejection.message(),
            "Rate limit reached for service \"jira\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed."
        );
        assert_eq!(
            rejection.result(),
            json!({
                "limitScope": "principal",
                "service": "jira",
                "limit": 20,
                "windowSeconds": 60,
                "retryAfterSeconds": 12,
                "retryAt": "2026-09-25T14:03:12Z",
                "executionState": "not_dispatched",
                "retrySafe": true
            })
        );
        let error = rejection.clone().into_provider_error();
        assert_eq!(error.reason_code, ReasonCode::RateLimited);
        assert_eq!(error.reason_code.http_status(), 429);
        assert_eq!(error.message, rejection.message());
        assert_eq!(
            error.audit.as_deref().unwrap()["rateLimit"],
            json!({
                "limitScope": "principal",
                "service": "jira",
                "limit": 20,
                "windowSeconds": 60,
                "retryAfterSeconds": 12
            })
        );
        assert_eq!(
            result_retry_after_seconds(error.result.as_deref()),
            Some(12)
        );
        let single = InvocationRateLimited {
            limit: InvocationLimit::parse(1, "90s").unwrap(),
            ..rejection
        };
        assert!(single.message().contains(": 1 request per 90s."));
    }

    #[test]
    fn retry_after_is_read_only_from_positive_whole_seconds() {
        assert_eq!(result_retry_after_seconds(None), None);
        for value in [
            json!({}),
            json!({"retryAfterSeconds": 0}),
            json!({"retryAfterSeconds": -3}),
            json!({"retryAfterSeconds": 1.5}),
            json!({"retryAfterSeconds": "7"}),
            json!(["retryAfterSeconds"]),
        ] {
            assert_eq!(result_retry_after_seconds(Some(&value)), None, "{value}");
        }
        assert_eq!(
            result_retry_after_seconds(Some(&json!({"retryAfterSeconds": 30}))),
            Some(30)
        );
    }
}
