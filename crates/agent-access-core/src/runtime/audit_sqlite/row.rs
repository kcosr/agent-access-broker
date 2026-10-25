//! Prepared `audit_events` rows: the record JSON exactly as JSONL writes it,
//! the derived query columns, and the broker-built full-text index text.

use super::super::{AuditRecord, StampedAuditRecord};
use agent_access_provider::ResourceSelector;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashSet;

/// The largest prepared size (record JSON plus full-text text) the SQLite
/// backend accepts, and the most prepared bytes in one batch transaction.
pub(super) const MAX_PREPARED_BYTES: usize = 16 * 1024 * 1024;
/// The full-text text cap per record.
pub(super) const FTS_TEXT_MAX_BYTES: usize = 32 * 1024;
/// The cap on values stored in indexed text columns.
pub(super) const INDEXED_TEXT_MAX_BYTES: usize = 1024;
/// The prepared size of the synthetic record recovery uses when no failed
/// rows were retained.
pub(super) const SYNTHETIC_RECORD_BYTES: usize = 4 * 1024;

/// One `audit_events` row and its full-text text, prepared before any
/// transaction starts.
#[derive(Clone, Debug)]
pub(super) struct PreparedRow {
    pub(super) audit_id: String,
    pub(super) node_id: String,
    pub(super) ts_us: i64,
    pub(super) broker_request_id: String,
    pub(super) agent_request_id: String,
    pub(super) principal: String,
    pub(super) service: String,
    pub(super) scope_service: Option<String>,
    pub(super) action: String,
    pub(super) decision: &'static str,
    pub(super) reason_code: Option<String>,
    pub(super) phase: Option<String>,
    pub(super) token_id: Option<String>,
    pub(super) token_class: Option<&'static str>,
    pub(super) grant_id: Option<String>,
    pub(super) execution_context: Option<String>,
    pub(super) upstream_status: Option<i64>,
    pub(super) upstream_duration_ms: Option<i64>,
    pub(super) remote: String,
    pub(super) record_json: String,
    pub(super) fts_text: String,
}

impl PreparedRow {
    /// Serializes `stamped` and derives its columns and full-text text.
    pub(super) fn prepare(stamped: &StampedAuditRecord) -> Result<Self, serde_json::Error> {
        let record_json = serde_json::to_string(stamped)?;
        let record = &stamped.record;
        let provider_audit = record.provider_audit.as_ref();
        let ts_us = match parse_timestamp_us(&record.timestamp) {
            Some(ts_us) => ts_us,
            None => {
                tracing::warn!(
                    event = "audit_timestamp_invalid",
                    auditId = stamped.audit_id.as_str(),
                    brokerRequestId = record.broker_request_id.as_str(),
                    nodeId = stamped.node_id.as_str(),
                    "audit record timestamp is not RFC 3339; indexing it at the insert time",
                );
                Utc::now().timestamp_micros()
            }
        };
        let identity = record.identity_source.as_ref();
        Ok(Self {
            audit_id: stamped.audit_id.clone(),
            node_id: stamped.node_id.clone(),
            ts_us,
            broker_request_id: indexed_text(&record.broker_request_id),
            agent_request_id: indexed_text(&record.agent_request_id),
            principal: indexed_text(&record.principal),
            service: indexed_text(&record.service),
            scope_service: scope_service(&record.service, provider_audit).map(indexed_text),
            action: indexed_text(&record.action),
            decision: record.decision.as_str(),
            reason_code: record
                .reason_code
                .as_ref()
                .map(|reason_code| indexed_text(reason_code.as_str())),
            phase: phase(provider_audit).map(str::to_string),
            token_id: identity
                .and_then(|identity| identity.token_id.as_deref())
                .map(indexed_text),
            token_class: identity
                .and_then(|identity| identity.token_class.as_ref())
                .map(|class| class.as_str()),
            grant_id: record
                .matched_grant
                .as_ref()
                .and_then(|grant| grant.grant_id.as_deref())
                .map(indexed_text),
            execution_context: record
                .execution_context
                .as_ref()
                .map(|context| context.as_str().to_string()),
            upstream_status: record.upstream_status.map(i64::from),
            upstream_duration_ms: record
                .upstream_duration_ms
                .map(|duration| i64::try_from(duration).unwrap_or(i64::MAX)),
            remote: record.source.remote.clone(),
            fts_text: fts_text(record),
            record_json,
        })
    }

    /// A fixed 4 KiB stand-in for a failed batch that had no prepared rows.
    pub(super) fn synthetic(node_id: &str) -> Self {
        let mut row = Self {
            audit_id: String::new(),
            node_id: node_id.to_string(),
            ts_us: Utc::now().timestamp_micros(),
            broker_request_id: String::new(),
            agent_request_id: String::new(),
            principal: "system".to_string(),
            service: "broker".to_string(),
            scope_service: None,
            action: "audit.recovery".to_string(),
            decision: "allow",
            reason_code: None,
            phase: None,
            token_id: None,
            token_class: None,
            grant_id: None,
            execution_context: None,
            upstream_status: None,
            upstream_duration_ms: None,
            remote: "unknown".to_string(),
            record_json: String::new(),
            fts_text: "system broker audit recovery".to_string(),
        };
        let prefix = r#"{"synthetic":""#;
        let suffix = r#""}"#;
        let fill = SYNTHETIC_RECORD_BYTES - prefix.len() - suffix.len() - row.fts_text.len();
        row.record_json = format!("{prefix}{}{suffix}", "x".repeat(fill));
        row
    }

    /// The record JSON plus the full-text text, in bytes.
    pub(super) fn prepared_bytes(&self) -> usize {
        self.record_json.len() + self.fts_text.len()
    }
}

fn parse_timestamp_us(timestamp: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc).timestamp_micros())
}

/// Truncates a value for an indexed text column to at most 1024 bytes at a
/// UTF-8 boundary. The full value stays in the record JSON.
pub(super) fn indexed_text(value: &str) -> String {
    truncate_at_char_boundary(value, INDEXED_TEXT_MAX_BYTES).to_string()
}

fn truncate_at_char_boundary(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The configured service a record is about: the record's `service` unless
/// that is `broker` (then `providerAudit.management.targetService`, if any).
fn scope_service<'a>(service: &'a str, provider_audit: Option<&'a Value>) -> Option<&'a str> {
    match service {
        "broker" => provider_audit
            .and_then(|audit| audit.get("management"))
            .and_then(|management| management.get("targetService"))
            .and_then(Value::as_str),
        service => Some(service),
    }
}

/// The first present of `providerAudit.streamPhase`,
/// `providerAudit.gateway.phase`, `providerAudit.gatewayPhase`, and
/// `providerAudit.management.phase`, and `providerAudit.auth.phase`.
fn phase(provider_audit: Option<&Value>) -> Option<&str> {
    let audit = provider_audit?;
    [
        audit.get("streamPhase"),
        audit
            .get("gateway")
            .and_then(|gateway| gateway.get("phase")),
        audit.get("gatewayPhase"),
        audit
            .get("management")
            .and_then(|management| management.get("phase")),
        audit.get("auth").and_then(|auth| auth.get("phase")),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
}

/// The indexed text: the curated fields below, never raw JSON keys, each
/// distinct value once, capped at 32 KiB at a token boundary.
fn fts_text(record: &AuditRecord) -> String {
    let mut text = FtsText::default();
    text.push(&record.principal);
    if let Some(subject) = &record.principal_subject {
        text.push(subject);
    }
    for group in &record.groups {
        text.push(group);
    }
    if let Some(identity) = &record.identity_source {
        text.push(&identity.name);
        if let Some(token_id) = &identity.token_id {
            text.push(token_id);
        }
    }
    text.push(&record.source.remote);
    for hop in &record.source.proxy_chain {
        text.push(hop);
    }
    text.push(&record.service);
    text.push(&record.action);
    if let Some(reason_code) = &record.reason_code {
        text.push(reason_code.as_str());
    }
    if let Some(context) = &record.execution_context {
        text.push(context.as_str());
    }
    for (key, values) in &record.resource_scopes {
        text.push(key);
        for value in values {
            text.push(value);
        }
    }
    if let Some(object_ids) = &record.object_ids {
        text.push_leaves(object_ids, true);
    }
    let search_grants = record
        .search_authorization
        .iter()
        .flat_map(|plan| plan.matched_grants.iter());
    for grant in record.matched_grant.iter().chain(search_grants) {
        if let Some(grant_id) = &grant.grant_id {
            text.push(grant_id);
        }
        text.push(&grant.subject);
    }
    if let Some(plan) = &record.search_authorization {
        for selector in plan
            .scope
            .clauses()
            .iter()
            .flat_map(|clause| clause.included().iter().chain(clause.excluded()))
        {
            match selector {
                ResourceSelector::Exact { value } | ResourceSelector::Namespace { value } => {
                    text.push(value)
                }
                _ => {}
            }
        }
    }
    // Before provider audit, which the cap cuts first.
    for captured in &record.audit_inputs {
        text.push(&captured.label);
        text.push_leaves(&captured.value, false);
    }
    if let Some(provider_audit) = &record.provider_audit {
        text.push_leaves(provider_audit, false);
    }
    text.finish()
}

#[derive(Default)]
struct FtsText {
    text: String,
    seen: HashSet<String>,
}

impl FtsText {
    fn is_full(&self) -> bool {
        self.text.len() > FTS_TEXT_MAX_BYTES
    }

    fn push(&mut self, value: &str) {
        let value = value.trim();
        if value.is_empty() || self.is_full() || !self.seen.insert(value.to_string()) {
            return;
        }
        if !self.text.is_empty() {
            self.text.push(' ');
        }
        self.text.push_str(value);
    }

    /// Pushes the string leaves of `value` (and number leaves when
    /// `numbers`), skipping object fields whose names end in `Sha256`.
    fn push_leaves(&mut self, value: &Value, numbers: bool) {
        if self.is_full() {
            return;
        }
        match value {
            Value::String(value) => self.push(value),
            Value::Number(number) if numbers => self.push(&number.to_string()),
            Value::Array(values) => {
                for value in values {
                    self.push_leaves(value, numbers);
                }
            }
            Value::Object(fields) => {
                for (key, value) in fields {
                    if !key.ends_with("Sha256") {
                        self.push_leaves(value, numbers);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn finish(self) -> String {
        cap_at_token_boundary(self.text, FTS_TEXT_MAX_BYTES)
    }
}

/// Cuts `text` to at most `max` bytes without splitting a token: the cut
/// lands before a character that is not alphanumeric (the tokenizer's
/// separators), and trailing separators are trimmed.
fn cap_at_token_boundary(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    loop {
        if end == 0 {
            // One token longer than the cap: cut it at a character boundary.
            end = truncate_at_char_boundary(&text, max).len();
            break;
        }
        if text.is_char_boundary(end)
            && text[end..]
                .chars()
                .next()
                .is_none_or(|next| !next.is_alphanumeric())
        {
            break;
        }
        end -= 1;
    }
    text.truncate(end);
    let trimmed = text
        .trim_end_matches(|ch: char| !ch.is_alphanumeric())
        .len();
    text.truncate(trimmed);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_auth_rows_expose_write_phase_without_changing_record_json() {
        for expected_phase in ["preflight", "success"] {
            let mut record = crate::runtime::tests::test_audit_record();
            record.service = "broker".into();
            record.action = "auth.local.password_change".into();
            record.provider_audit = Some(serde_json::json!({
                "auth": { "phase": expected_phase, "loginMethod": "local_password" }
            }));
            let stamped = StampedAuditRecord::new(record, "node-1");
            let row = PreparedRow::prepare(&stamped).unwrap();
            assert_eq!(row.phase.as_deref(), Some(expected_phase));
            assert_eq!(row.record_json, serde_json::to_string(&stamped).unwrap());
        }
        let audit = serde_json::json!({
            "management": { "phase": "management-phase" },
            "auth": { "phase": "auth-phase" }
        });
        assert_eq!(phase(Some(&audit)), Some("management-phase"));
    }

    #[test]
    fn search_audit_preserves_clauses_and_indexes_policy_selectors() {
        use agent_access_provider::SearchAuthorizationScope;
        let mut record = crate::runtime::tests::test_audit_record();
        let authority = SearchAuthorizationScope::from_selectors(
            vec![ResourceSelector::Namespace {
                value: "engineering".into(),
            }],
            vec![ResourceSelector::Namespace {
                value: "engineering/private".into(),
            }],
        )
        .union(&SearchAuthorizationScope::from_exact_values(vec![
            "engineering/private/tool".into(),
        ]));
        record.search_authorization = Some(crate::runtime::SearchAuthorizationPlan {
            scope_type: "repository".into(),
            scope: authority.clone(),
            credential_mode: "service".into(),
            matched_grants: vec![],
        });
        let summary = record
            .search_authorization
            .as_ref()
            .unwrap()
            .resource_scope_summary();
        assert_eq!(summary["repository"], ["*"]);
        let stamped = StampedAuditRecord::new(record.clone(), "node-1");
        let row = PreparedRow::prepare(&stamped).unwrap();
        let json: Value = serde_json::from_str(&row.record_json).unwrap();
        assert_eq!(
            json["searchAuthorization"]["scope"],
            serde_json::to_value(authority).unwrap()
        );
        let text = fts_text(&record);
        for selector in [
            "engineering",
            "engineering/private",
            "engineering/private/tool",
        ] {
            assert!(text.contains(selector), "{selector}: {text}");
        }
        assert!(!text.contains("clauses"));
        assert!(!text.contains("included"));
    }

    #[test]
    fn audit_inputs_index_labels_and_string_leaves_before_provider_audit() {
        let mut record = crate::runtime::tests::test_audit_record();
        record.audit_inputs = vec![crate::runtime::AuditInputValue {
            input: "query".into(),
            label: "Search".into(),
            value: serde_json::json!({"terms": ["zephyr"], "limit": 424242}),
            truncated: false,
        }];
        record.provider_audit = Some(serde_json::json!({"note": "providerfact"}));
        let text = fts_text(&record);
        let label = text.find("Search").unwrap();
        let value = text.find("zephyr").unwrap();
        let provider = text.find("providerfact").unwrap();
        assert!(label < value && value < provider, "{text}");
        // Neither input names, object keys nor numbers are terms.
        for absent in ["query", "terms", "424242"] {
            assert!(!text.contains(absent), "{absent}: {text}");
        }
    }

    #[test]
    fn indexed_text_truncates_at_a_utf8_boundary() {
        let value = format!("{}é", "a".repeat(1023));
        let truncated = indexed_text(&value);
        assert_eq!(truncated, "a".repeat(1023));
        assert_eq!(indexed_text("short"), "short");
        let exact = "b".repeat(1024);
        assert_eq!(indexed_text(&exact), exact);
    }

    #[test]
    fn token_boundary_cap_never_splits_a_token() {
        let text = format!("{} tail", "word ".repeat(10));
        let capped = cap_at_token_boundary(text.clone(), 12);
        assert_eq!(capped, "word word");
        let capped = cap_at_token_boundary("alpha-beta".to_string(), 8);
        assert_eq!(capped, "alpha");
        let capped = cap_at_token_boundary("x".repeat(20), 8);
        assert_eq!(capped, "x".repeat(8));
        assert_eq!(cap_at_token_boundary("short".to_string(), 8), "short");
    }

    #[test]
    fn synthetic_record_is_four_kib() {
        let row = PreparedRow::synthetic("node-1");
        assert_eq!(row.prepared_bytes(), SYNTHETIC_RECORD_BYTES);
        serde_json::from_str::<Value>(&row.record_json).unwrap();
    }
}
