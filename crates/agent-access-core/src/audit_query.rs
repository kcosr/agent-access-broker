//! The audit query contract shared by the management API and the audit
//! storage backends: strict query-parameter parsing, validated filters,
//! caller visibility, search terms, pages, and continuation cursors.
//!
//! Everything here is backend-neutral. A backend decides only how it
//! evaluates the filters and [`AuditSearch`] terms; full-text search is the
//! part that differs most between databases. Only the SQLite backend answers
//! queries today.

use crate::is_valid_node_id;
use agent_access_provider::ReasonCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::time::Duration;
use url::form_urlencoded;

/// Items per list page when `limit` is absent, and the largest `limit`.
pub const AUDIT_QUERY_DEFAULT_LIMIT: usize = 50;
pub const AUDIT_QUERY_MAX_LIMIT: usize = 200;
/// The most records a request timeline returns.
pub const AUDIT_TIMELINE_MAX_ITEMS: usize = 100;
/// Canonical action suggestions for an audit service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditServiceOptions {
    pub service: String,
    pub actions: Vec<String>,
}

/// Canonical filter suggestions, independent of stored audit history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditOptions {
    pub services: Vec<AuditServiceOptions>,
}
/// `q` limits: characters, and terms or phrases.
pub const AUDIT_SEARCH_MAX_CHARS: usize = 256;
pub const AUDIT_SEARCH_MAX_TERMS: usize = 16;
/// The longest cursor the broker issues or accepts, in characters.
pub const AUDIT_CURSOR_MAX_CHARS: usize = 4096;
/// The message of every rejected cursor.
pub const AUDIT_CURSOR_INVALID_MESSAGE: &str =
    "cursor is invalid or stale; repeat the request without cursor";
/// The longest exact-match filter value, in bytes.
const FILTER_VALUE_MAX_BYTES: usize = 256;
const REASON_CODE_MAX_BYTES: usize = 64;
const CURSOR_VERSION: u32 = 1;

/// The values of the `phase` column and filter.
pub const AUDIT_PHASES: [&str; 7] = [
    "started",
    "completed",
    "failed",
    "canceled",
    "preflight",
    "upstream_verification",
    "success",
];
const DECISIONS: [&str; 3] = ["allow", "deny", "error"];

/// Reader pool bounds: connections (and so queries executing at once),
/// queries that may wait for a connection, and the deadline measured from
/// admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditQueryLimits {
    pub connections: usize,
    pub waiting: usize,
    pub deadline: Duration,
}

impl Default for AuditQueryLimits {
    fn default() -> Self {
        Self {
            connections: 4,
            waiting: 16,
            deadline: Duration::from_secs(5),
        }
    }
}

/// Why an audit query produced no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditQueryError {
    /// The configured audit backend does not answer queries.
    Unavailable,
    /// The reader pool already has the maximum number of waiting queries.
    ConcurrencyLimited,
    /// The query did not finish within its deadline (or was interrupted).
    Timeout,
    /// Reading the audit database failed.
    Failed(String),
}

impl AuditQueryError {
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Unavailable => ReasonCode::AuditQueryUnavailable,
            Self::ConcurrencyLimited => ReasonCode::ConcurrencyLimited,
            Self::Timeout => ReasonCode::AuditQueryTimeout,
            Self::Failed(_) => ReasonCode::OperationFailed,
        }
    }

    /// The public message. Storage details stay in service logs.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Unavailable => "the configured audit backend does not support queries",
            Self::ConcurrencyLimited => "too many audit queries are running; retry shortly",
            Self::Timeout => "the audit query exceeded its time budget; narrow the filters",
            Self::Failed(_) => "the audit query failed",
        }
    }
}

impl std::fmt::Display for AuditQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(detail) => write!(formatter, "{}: {detail}", self.message()),
            _ => formatter.write_str(self.message()),
        }
    }
}

/// The two list routes. The route and caller bind a cursor, and only the
/// admin route accepts a `principal` filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditListRoute {
    /// `GET /v1/admin/audit/events`
    Admin,
    /// `GET /v1/audit/events`
    SelfService,
}

impl AuditListRoute {
    pub fn operation(self) -> &'static str {
        match self {
            Self::Admin => "admin.audit.events.list",
            Self::SelfService => "audit.events.list",
        }
    }

    fn from_operation(operation: &str) -> Option<Self> {
        [Self::Admin, Self::SelfService]
            .into_iter()
            .find(|route| route.operation() == operation)
    }
}

/// The records a caller may see; applied inside every list and timeline
/// query and never widened by filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditVisibility {
    /// Admins: every record.
    Global,
    /// Service policy managers: records whose scope service is one of the
    /// services they manage now. Records without a scope service are never
    /// visible in this tier.
    Services(BTreeSet<String>),
    /// Managed users: records whose `principal` is the caller, whatever the
    /// scope service.
    Principal(String),
}

/// Filter parameters as the query string (or a cursor) carries them: every
/// value a string, absent filters omitted. Cursors hold the normalized form
/// produced by [`AuditEventFilters::params`], and decoding validates it
/// exactly like query parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditFilterParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
}

impl AuditFilterParams {
    /// The query parameter names, in documentation order.
    pub const NAMES: [&'static str; 14] = [
        "from",
        "to",
        "principal",
        "service",
        "scopeService",
        "action",
        "decision",
        "reasonCode",
        "phase",
        "tokenId",
        "grantId",
        "node",
        "requestId",
        "q",
    ];

    fn slot(&mut self, name: &str) -> Option<&mut Option<String>> {
        Some(match name {
            "from" => &mut self.from,
            "to" => &mut self.to,
            "principal" => &mut self.principal,
            "service" => &mut self.service,
            "scopeService" => &mut self.scope_service,
            "action" => &mut self.action,
            "decision" => &mut self.decision,
            "reasonCode" => &mut self.reason_code,
            "phase" => &mut self.phase,
            "tokenId" => &mut self.token_id,
            "grantId" => &mut self.grant_id,
            "node" => &mut self.node,
            "requestId" => &mut self.request_id,
            "q" => &mut self.q,
            _ => return None,
        })
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A parsed list request: the filters or the cursor (never both), and the
/// page size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditListParams {
    pub filters: AuditFilterParams,
    pub cursor: Option<String>,
    pub limit: usize,
}

/// Parses a list route's query string strictly: unknown, empty, or repeated
/// parameters are rejected, the self route rejects `principal`, and a
/// `cursor` may be accompanied only by `limit`.
pub fn parse_audit_list_query(
    raw_query: Option<&str>,
    route: AuditListRoute,
) -> Result<AuditListParams, String> {
    let mut params = AuditListParams {
        filters: AuditFilterParams::default(),
        cursor: None,
        limit: AUDIT_QUERY_DEFAULT_LIMIT,
    };
    let mut seen = BTreeSet::new();
    for (key, value) in form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err(format!("query parameter {key} is repeated"));
        }
        if value.is_empty() {
            return Err(format!("query parameter {key} must not be empty"));
        }
        match key.as_ref() {
            "limit" => params.limit = parse_limit(&value)?,
            "cursor" => params.cursor = Some(value.into_owned()),
            "principal" if route == AuditListRoute::SelfService => {
                return Err(format!(
                    "principal is not supported on {}; it lists only your own records",
                    route.operation()
                ));
            }
            name => match params.filters.slot(name) {
                Some(slot) => *slot = Some(value.into_owned()),
                None => return Err(format!("query parameter {key} is not supported")),
            },
        }
    }
    if params.cursor.is_some() && !params.filters.is_empty() {
        return Err("cursor may be combined only with limit".to_string());
    }
    Ok(params)
}

/// Rejects every query parameter: the timeline routes take none.
pub fn reject_audit_query_parameters(raw_query: Option<&str>) -> Result<(), String> {
    match form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()).next() {
        Some((key, _)) => Err(format!("query parameter {key} is not supported")),
        None => Ok(()),
    }
}

fn parse_limit(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=AUDIT_QUERY_MAX_LIMIT).contains(limit))
        .ok_or_else(|| format!("limit must be an integer from 1 to {AUDIT_QUERY_MAX_LIMIT}"))
}

/// A broker request ID path parameter: a UUID, returned in its canonical
/// lowercase hyphenated form.
pub fn parse_audit_broker_request_id(value: &str) -> Result<String, String> {
    uuid::Uuid::try_parse(value)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| "brokerRequestId must be a UUID".to_string())
}

/// An `action` filter: exact, or every action starting with a prefix that
/// ends in `.`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditActionFilter {
    Exact(String),
    /// The prefix, including its trailing `.`.
    Prefix(String),
}

/// One `q` term or phrase. Each must match; the backend treats the text
/// literally and never interprets full-text operators or column syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditSearchTerm {
    /// A whitespace-delimited term; `prefix` when it ended in `*`.
    Word { text: String, prefix: bool },
    /// A double-quoted phrase.
    Phrase(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSearch {
    pub terms: Vec<AuditSearchTerm>,
}

impl AuditSearch {
    /// Splits `q` on whitespace into terms; a double-quoted segment is one
    /// phrase (an unmatched quote runs to the end), and a trailing `*` on a
    /// term makes it a prefix match.
    pub fn parse(q: &str) -> Result<Self, String> {
        if q.chars().count() > AUDIT_SEARCH_MAX_CHARS {
            return Err(format!(
                "q must be at most {AUDIT_SEARCH_MAX_CHARS} characters"
            ));
        }
        if q.chars().any(|ch| ch.is_control() && !ch.is_whitespace()) {
            return Err("q must not contain control characters".to_string());
        }
        let mut terms = Vec::new();
        let mut rest = q;
        loop {
            rest = rest.trim_start();
            let Some(first) = rest.chars().next() else {
                break;
            };
            if first == '"' {
                let body = &rest[1..];
                let (phrase, after) = match body.find('"') {
                    Some(end) => (&body[..end], &body[end + 1..]),
                    None => (body, ""),
                };
                let phrase = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
                if !phrase.is_empty() {
                    terms.push(AuditSearchTerm::Phrase(phrase));
                }
                rest = after;
            } else {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                let word = &rest[..end];
                let term = match word.strip_suffix('*') {
                    Some(text) if !text.is_empty() => AuditSearchTerm::Word {
                        text: text.to_string(),
                        prefix: true,
                    },
                    _ => AuditSearchTerm::Word {
                        text: word.to_string(),
                        prefix: false,
                    },
                };
                terms.push(term);
                rest = &rest[end..];
            }
        }
        if terms.is_empty() {
            return Err("q must contain a search term".to_string());
        }
        if terms.len() > AUDIT_SEARCH_MAX_TERMS {
            return Err(format!(
                "q must have at most {AUDIT_SEARCH_MAX_TERMS} terms or phrases"
            ));
        }
        Ok(Self { terms })
    }
}

/// Validated list filters. Time bounds are absolute UTC microseconds; `from`
/// is inclusive and `to` exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEventFilters {
    pub from_us: Option<i64>,
    pub to_us: Option<i64>,
    pub principal: Option<String>,
    pub service: Option<String>,
    pub scope_service: Option<String>,
    pub action: Option<AuditActionFilter>,
    pub decision: Option<&'static str>,
    pub reason_code: Option<String>,
    pub phase: Option<&'static str>,
    pub token_id: Option<String>,
    pub grant_id: Option<String>,
    pub node: Option<String>,
    pub request_id: Option<String>,
    pub search: Option<AuditSearch>,
    params: AuditFilterParams,
}

impl AuditEventFilters {
    /// Validates filter parameters, from the query string or a decoded
    /// cursor alike.
    pub fn from_params(params: AuditFilterParams, route: AuditListRoute) -> Result<Self, String> {
        if route == AuditListRoute::SelfService && params.principal.is_some() {
            return Err(format!(
                "principal is not supported on {}; it lists only your own records",
                route.operation()
            ));
        }
        let from = params
            .from
            .as_deref()
            .map(|value| parse_instant("from", value))
            .transpose()?;
        let to = params
            .to
            .as_deref()
            .map(|value| parse_instant("to", value))
            .transpose()?;
        if let (Some(from), Some(to)) = (from, to)
            && from > to
        {
            return Err("from must not be after to".to_string());
        }
        let exact = |name: &str, value: &Option<String>| -> Result<Option<String>, String> {
            value
                .as_deref()
                .map(|value| exact_value(name, value).map(str::to_string))
                .transpose()
        };
        let action = params
            .action
            .as_deref()
            .map(|value| {
                exact_value("action", value)?;
                match value.strip_suffix('*') {
                    Some(prefix) if prefix.ends_with('.') => {
                        if prefix.len() < 2 {
                            return Err("action prefix must name a segment before .*".to_string());
                        }
                        Ok(AuditActionFilter::Prefix(prefix.to_string()))
                    }
                    _ => Ok(AuditActionFilter::Exact(value.to_string())),
                }
            })
            .transpose()?;
        let decision = params
            .decision
            .as_deref()
            .map(|value| {
                DECISIONS
                    .into_iter()
                    .find(|decision| *decision == value)
                    .ok_or_else(|| "decision must be allow, deny, or error".to_string())
            })
            .transpose()?;
        let reason_code = params
            .reason_code
            .as_deref()
            .map(|value| {
                let valid = value.len() <= REASON_CODE_MAX_BYTES
                    && value.starts_with(|ch: char| ch.is_ascii_lowercase())
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    });
                valid
                    .then(|| value.to_string())
                    .ok_or_else(|| "reasonCode must be a snake_case reason code".to_string())
            })
            .transpose()?;
        let phase = params
            .phase
            .as_deref()
            .map(|value| {
                AUDIT_PHASES
                    .into_iter()
                    .find(|phase| *phase == value)
                    .ok_or_else(|| format!("phase must be one of {}", AUDIT_PHASES.join(", ")))
            })
            .transpose()?;
        let node = params
            .node
            .as_deref()
            .map(|value| {
                is_valid_node_id(value)
                    .then(|| value.to_string())
                    .ok_or_else(|| "node must be a node ID".to_string())
            })
            .transpose()?;
        let search = params.q.as_deref().map(AuditSearch::parse).transpose()?;
        let mut normalized = params.clone();
        normalized.from = from.map(format_instant);
        normalized.to = to.map(format_instant);
        Ok(Self {
            from_us: from,
            to_us: to,
            principal: exact("principal", &params.principal)?,
            service: exact("service", &params.service)?,
            scope_service: exact("scopeService", &params.scope_service)?,
            action,
            decision,
            reason_code,
            phase,
            token_id: exact("tokenId", &params.token_id)?,
            grant_id: exact("grantId", &params.grant_id)?,
            node,
            request_id: exact("requestId", &params.request_id)?,
            search,
            params: normalized,
        })
    }

    /// The normalized parameters: time bounds as absolute RFC 3339 UTC
    /// instants with microseconds, everything else as given.
    pub fn params(&self) -> &AuditFilterParams {
        &self.params
    }
}

fn exact_value<'a>(name: &str, value: &'a str) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.len() > FILTER_VALUE_MAX_BYTES {
        return Err(format!(
            "{name} must be at most {FILTER_VALUE_MAX_BYTES} bytes"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{name} must not contain control characters"));
    }
    Ok(value)
}

/// An RFC 3339 instant as UTC epoch microseconds, rounded up: records carry
/// microsecond timestamps, so `t_us >= ceil(bound)` is exactly "not before
/// the bound" and `t_us < ceil(bound)` exactly "before the bound".
fn parse_instant(name: &str, value: &str) -> Result<i64, String> {
    let instant = DateTime::parse_from_rfc3339(value)
        .map_err(|_| format!("{name} must be an RFC 3339 instant"))?
        .with_timezone(&Utc);
    let micros = instant.timestamp_micros();
    let micros = if instant.timestamp_subsec_nanos() % 1_000 == 0 {
        micros
    } else {
        micros + 1
    };
    DateTime::<Utc>::from_timestamp_micros(micros)
        .map(|_| micros)
        .ok_or_else(|| format!("{name} is out of range"))
}

fn format_instant(micros: i64) -> String {
    DateTime::<Utc>::from_timestamp_micros(micros)
        .expect("validated audit instants are representable")
        .to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// A record's position in `(timestamp, insertion order)` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditPosition {
    pub ts_us: i64,
    pub id: i64,
}

/// One list query: the caller's visibility, the filters, the position after
/// which the page starts (newest first), and the page size.
#[derive(Clone, Debug)]
pub struct AuditEventsQuery {
    pub visibility: AuditVisibility,
    pub filters: AuditEventFilters,
    pub after: Option<AuditPosition>,
    pub limit: usize,
}

/// A list page: each item the stored record exactly as written, and the
/// position of the last item when more records follow.
#[derive(Debug)]
pub struct AuditEventsPage {
    pub items: Vec<Box<RawValue>>,
    pub next: Option<AuditPosition>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CursorBody {
    v: u32,
    route: String,
    principal: String,
    database_id: String,
    filters: AuditFilterParams,
    ts_us: i64,
    id: i64,
}

/// What a cursor is bound to: the route, the caller, and the audit database.
#[derive(Clone, Copy, Debug)]
pub struct AuditCursorBinding<'a> {
    pub route: AuditListRoute,
    pub principal: &'a str,
    pub database_id: &'a str,
}

impl AuditCursorBinding<'_> {
    /// Encodes a continuation cursor: opaque base64url JSON with the route,
    /// caller, database, normalized filters, and last position. `None` when
    /// it would exceed [`AUDIT_CURSOR_MAX_CHARS`].
    pub fn encode(&self, filters: &AuditEventFilters, position: AuditPosition) -> Option<String> {
        let body = CursorBody {
            v: CURSOR_VERSION,
            route: self.route.operation().to_string(),
            principal: self.principal.to_string(),
            database_id: self.database_id.to_string(),
            filters: filters.params().clone(),
            ts_us: position.ts_us,
            id: position.id,
        };
        let json = serde_json::to_vec(&body).expect("audit cursor serializes");
        let cursor = URL_SAFE_NO_PAD.encode(json);
        (cursor.len() <= AUDIT_CURSOR_MAX_CHARS).then_some(cursor)
    }

    /// Rejects filters whose cursor could exceed [`AUDIT_CURSOR_MAX_CHARS`],
    /// before the first page is read.
    pub fn check_pageable(&self, filters: &AuditEventFilters) -> Result<(), String> {
        let widest = AuditPosition {
            ts_us: i64::MIN,
            id: i64::MIN,
        };
        self.encode(filters, widest)
            .map(|_| ())
            .ok_or_else(|| "filters are too long to page through; shorten them".to_string())
    }

    /// Decodes a cursor issued for this route, caller, and database, and
    /// validates its filters exactly like query parameters. Every failure is
    /// [`AUDIT_CURSOR_INVALID_MESSAGE`].
    pub fn decode(&self, cursor: &str) -> Result<(AuditEventFilters, AuditPosition), String> {
        let invalid = || AUDIT_CURSOR_INVALID_MESSAGE.to_string();
        if cursor.len() > AUDIT_CURSOR_MAX_CHARS {
            return Err(invalid());
        }
        let json = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
        let body: CursorBody = serde_json::from_slice(&json).map_err(|_| invalid())?;
        if body.v != CURSOR_VERSION
            || AuditListRoute::from_operation(&body.route) != Some(self.route)
            || body.principal != self.principal
            || body.database_id != self.database_id
        {
            return Err(invalid());
        }
        let filters =
            AuditEventFilters::from_params(body.filters, self.route).map_err(|_| invalid())?;
        Ok((
            filters,
            AuditPosition {
                ts_us: body.ts_us,
                id: body.id,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> AuditFilterParams {
        let mut params = AuditFilterParams::default();
        for (name, value) in pairs {
            *params.slot(name).unwrap() = Some((*value).to_string());
        }
        params
    }

    fn filters(pairs: &[(&str, &str)]) -> Result<AuditEventFilters, String> {
        AuditEventFilters::from_params(params(pairs), AuditListRoute::Admin)
    }

    #[test]
    fn list_queries_reject_unknown_empty_repeated_and_self_principal() {
        let parse = |query: &str, route| parse_audit_list_query(Some(query), route);
        let ok = parse("service=jira&limit=10", AuditListRoute::Admin).unwrap();
        assert_eq!(ok.filters.service.as_deref(), Some("jira"));
        assert_eq!(ok.limit, 10);
        assert_eq!(
            parse_audit_list_query(None, AuditListRoute::Admin)
                .unwrap()
                .limit,
            AUDIT_QUERY_DEFAULT_LIMIT
        );
        for (query, message) in [
            ("bogus=1", "query parameter bogus is not supported"),
            ("service=", "query parameter service must not be empty"),
            ("service", "query parameter service must not be empty"),
            ("service=a&service=b", "query parameter service is repeated"),
            ("limit=0", "limit must be an integer from 1 to 200"),
            ("limit=201", "limit must be an integer from 1 to 200"),
            ("limit=ten", "limit must be an integer from 1 to 200"),
            (
                "cursor=abc&service=jira",
                "cursor may be combined only with limit",
            ),
        ] {
            assert_eq!(parse(query, AuditListRoute::Admin).unwrap_err(), message);
        }
        assert!(parse("cursor=abc&limit=5", AuditListRoute::Admin).is_ok());
        assert!(
            parse("principal=alice", AuditListRoute::SelfService)
                .unwrap_err()
                .starts_with("principal is not supported on audit.events.list")
        );
        assert!(parse("principal=alice", AuditListRoute::Admin).is_ok());
        assert!(reject_audit_query_parameters(Some("")).is_ok());
        assert!(reject_audit_query_parameters(Some("limit=1")).is_err());
    }

    #[test]
    fn filters_validate_values_and_normalize_time_bounds() {
        let parsed = filters(&[
            ("from", "2026-09-01T02:00:00+02:00"),
            ("to", "2026-09-02T00:00:00.0000001Z"),
            ("action", "admin.policy.*"),
            ("decision", "deny"),
            ("phase", "preflight"),
            ("reasonCode", "input_invalid"),
            ("node", "broker-1"),
        ])
        .unwrap();
        assert_eq!(
            parsed.params().from.as_deref(),
            Some("2026-09-01T00:00:00.000000Z")
        );
        // Sub-microsecond bounds round up.
        assert_eq!(
            parsed.params().to.as_deref(),
            Some("2026-09-02T00:00:00.000001Z")
        );
        assert_eq!(
            parsed.to_us.unwrap() - parsed.from_us.unwrap(),
            86_400_000_001
        );
        assert_eq!(
            parsed.action,
            Some(AuditActionFilter::Prefix("admin.policy.".to_string()))
        );
        assert_eq!(
            filters(&[("action", "admin.policy.grants.list")])
                .unwrap()
                .action,
            Some(AuditActionFilter::Exact(
                "admin.policy.grants.list".to_string()
            ))
        );
        for (pairs, message) in [
            (
                vec![("from", "yesterday")],
                "from must be an RFC 3339 instant",
            ),
            (
                vec![
                    ("from", "2026-09-02T00:00:00Z"),
                    ("to", "2026-09-01T00:00:00Z"),
                ],
                "from must not be after to",
            ),
            (
                vec![("decision", "maybe")],
                "decision must be allow, deny, or error",
            ),
            (
                vec![("action", ".*")],
                "action prefix must name a segment before .*",
            ),
            (
                vec![("reasonCode", "Input-Invalid")],
                "reasonCode must be a snake_case reason code",
            ),
            (vec![("node", "-bad")], "node must be a node ID"),
            (
                vec![("service", "a\u{7}b")],
                "service must not contain control characters",
            ),
        ] {
            assert_eq!(filters(&pairs).unwrap_err(), message);
        }
        assert!(
            filters(&[("phase", "streaming")])
                .unwrap_err()
                .starts_with("phase must be one of")
        );
        assert!(
            filters(&[("tokenId", &"t".repeat(257))])
                .unwrap_err()
                .contains("at most 256 bytes")
        );
        // from == to is an empty but valid range.
        assert!(
            filters(&[
                ("from", "2026-09-01T00:00:00Z"),
                ("to", "2026-09-01T00:00:00Z")
            ])
            .is_ok()
        );
    }

    #[test]
    fn search_text_splits_terms_phrases_and_prefixes_literally() {
        let search = AuditSearch::parse(
            r#"  alice  "issue view"  jir* NEAR( a OR b ) col:x "unbalanced tail"#,
        )
        .unwrap();
        assert_eq!(
            search.terms,
            vec![
                AuditSearchTerm::Word {
                    text: "alice".into(),
                    prefix: false
                },
                AuditSearchTerm::Phrase("issue view".into()),
                AuditSearchTerm::Word {
                    text: "jir".into(),
                    prefix: true
                },
                AuditSearchTerm::Word {
                    text: "NEAR(".into(),
                    prefix: false
                },
                AuditSearchTerm::Word {
                    text: "a".into(),
                    prefix: false
                },
                AuditSearchTerm::Word {
                    text: "OR".into(),
                    prefix: false
                },
                AuditSearchTerm::Word {
                    text: "b".into(),
                    prefix: false
                },
                AuditSearchTerm::Word {
                    text: ")".into(),
                    prefix: false
                },
                AuditSearchTerm::Word {
                    text: "col:x".into(),
                    prefix: false
                },
                AuditSearchTerm::Phrase("unbalanced tail".into()),
            ]
        );
        assert_eq!(
            AuditSearch::parse("*").unwrap().terms,
            vec![AuditSearchTerm::Word {
                text: "*".into(),
                prefix: false
            }]
        );
        assert_eq!(
            AuditSearch::parse("   ").unwrap_err(),
            "q must contain a search term"
        );
        assert_eq!(
            AuditSearch::parse(r#""  ""#).unwrap_err(),
            "q must contain a search term"
        );
        let seventeen = vec!["t"; 17].join(" ");
        assert!(
            AuditSearch::parse(&seventeen)
                .unwrap_err()
                .contains("at most 16")
        );
        assert!(AuditSearch::parse(&vec!["t"; 16].join(" ")).is_ok());
        assert!(
            AuditSearch::parse(&"é".repeat(257))
                .unwrap_err()
                .contains("at most 256")
        );
        assert!(AuditSearch::parse(&"é".repeat(256)).is_ok());
        assert!(AuditSearch::parse("a\u{0}b").is_err());
    }

    #[test]
    fn cursors_bind_route_principal_and_database_and_revalidate_filters() {
        let binding = AuditCursorBinding {
            route: AuditListRoute::Admin,
            principal: "alice",
            database_id: "db-1",
        };
        let filters = filters(&[
            ("from", "2026-09-01T00:00:00Z"),
            ("q", "jira*"),
            ("service", "jira"),
        ])
        .unwrap();
        let position = AuditPosition { ts_us: 42, id: 7 };
        let cursor = binding.encode(&filters, position).unwrap();
        let (decoded, decoded_position) = binding.decode(&cursor).unwrap();
        assert_eq!(decoded, filters);
        assert_eq!(decoded_position, position);

        let reject = |binding: AuditCursorBinding<'_>, cursor: &str| {
            assert_eq!(
                binding.decode(cursor).unwrap_err(),
                AUDIT_CURSOR_INVALID_MESSAGE
            );
        };
        reject(
            AuditCursorBinding {
                route: AuditListRoute::SelfService,
                ..binding
            },
            &cursor,
        );
        reject(
            AuditCursorBinding {
                principal: "bob",
                ..binding
            },
            &cursor,
        );
        reject(
            AuditCursorBinding {
                database_id: "db-2",
                ..binding
            },
            &cursor,
        );
        reject(binding, "not base64!");
        reject(binding, &URL_SAFE_NO_PAD.encode(b"{}"));
        reject(binding, &"A".repeat(AUDIT_CURSOR_MAX_CHARS + 1));
        // Filters in a cursor are validated like query parameters.
        let forged = serde_json::json!({
            "v": 1, "route": "admin.audit.events.list", "principal": "alice",
            "databaseId": "db-1", "filters": {"decision": "maybe"}, "tsUs": 1, "id": 1
        });
        reject(binding, &URL_SAFE_NO_PAD.encode(forged.to_string()));
        let self_binding = AuditCursorBinding {
            route: AuditListRoute::SelfService,
            ..binding
        };
        let forged = serde_json::json!({
            "v": 1, "route": "audit.events.list", "principal": "alice",
            "databaseId": "db-1", "filters": {"principal": "bob"}, "tsUs": 1, "id": 1
        });
        reject(self_binding, &URL_SAFE_NO_PAD.encode(forged.to_string()));
    }

    #[test]
    fn filters_that_cannot_fit_a_cursor_are_rejected_up_front() {
        let binding = AuditCursorBinding {
            route: AuditListRoute::Admin,
            principal: "alice",
            database_id: "0b5d4a4e-2b4e-4d67-9d5b-0a0f3f1c2d3e",
        };
        let long = "\"".repeat(256);
        let wide_chars = "\u{1D11E}".repeat(AUDIT_SEARCH_MAX_CHARS);
        let wide = filters(&[
            ("principal", &long),
            ("service", &long),
            ("scopeService", &long),
            ("action", &long),
            ("tokenId", &long),
            ("grantId", &long),
            ("requestId", &long),
            ("q", &wide_chars),
        ])
        .unwrap();
        assert!(binding.check_pageable(&wide).is_err());
        let typical = filters(&[("service", "jira"), ("q", "alice")]).unwrap();
        assert!(binding.check_pageable(&typical).is_ok());
    }
}
