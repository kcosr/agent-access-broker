//! Audit queries against the SQLite schema: the caller's visibility
//! predicate, the list filters, keyset paging in `(ts_us DESC, id DESC)`
//! order, and request timelines. Every value is bound as a parameter, and
//! search text reaches FTS5 only as quoted strings, so full-text operators
//! and column syntax are never interpreted.

use crate::{
    AUDIT_TIMELINE_MAX_ITEMS, AuditActionFilter, AuditEventFilters, AuditEventsQuery,
    AuditPosition, AuditSearch, AuditSearchTerm, AuditVisibility,
};
use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;

/// A list page as stored: each record's JSON and the position of the last
/// one when more records follow.
pub(super) struct StoredPage {
    pub(super) records: Vec<String>,
    pub(super) next: Option<AuditPosition>,
}

/// A `WHERE` clause and its bound values.
#[derive(Default)]
pub(super) struct Predicate {
    clauses: Vec<String>,
    values: Vec<SqlValue>,
}

impl Predicate {
    fn push(&mut self, clause: &str, values: impl IntoIterator<Item = SqlValue>) {
        self.clauses.push(clause.to_string());
        self.values.extend(values);
    }

    fn text(value: &str) -> SqlValue {
        SqlValue::Text(value.to_string())
    }

    fn sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }

    pub(super) fn visibility(&mut self, visibility: &AuditVisibility) {
        match visibility {
            AuditVisibility::Global => {}
            AuditVisibility::Services(services) if services.is_empty() => self.push("0", []),
            AuditVisibility::Services(services) => {
                let placeholders = vec!["?"; services.len()].join(", ");
                self.push(
                    &format!("scope_service IN ({placeholders})"),
                    services.iter().map(|service| Self::text(service)),
                );
            }
            AuditVisibility::Principal(principal) => {
                self.push("principal = ?", [Self::text(principal)]);
            }
        }
    }

    pub(super) fn filters(&mut self, filters: &AuditEventFilters) {
        if let Some(from) = filters.from_us {
            self.push("ts_us >= ?", [SqlValue::Integer(from)]);
        }
        if let Some(to) = filters.to_us {
            self.push("ts_us < ?", [SqlValue::Integer(to)]);
        }
        for (column, value) in [
            ("principal", &filters.principal),
            ("service", &filters.service),
            ("scope_service", &filters.scope_service),
            ("reason_code", &filters.reason_code),
            ("token_id", &filters.token_id),
            ("grant_id", &filters.grant_id),
            ("node_id", &filters.node),
        ] {
            if let Some(value) = value {
                self.push(&format!("{column} = ?"), [Self::text(value)]);
            }
        }
        for (column, value) in [("decision", filters.decision), ("phase", filters.phase)] {
            if let Some(value) = value {
                self.push(&format!("{column} = ?"), [Self::text(value)]);
            }
        }
        match &filters.action {
            Some(AuditActionFilter::Exact(action)) => {
                self.push("action = ?", [Self::text(action)]);
            }
            Some(AuditActionFilter::Prefix(prefix)) => {
                // Every action starting with `prefix` (which ends in `.`)
                // sorts at or after it and before the same text ending in
                // `/`, the next byte after `.`.
                let upper = format!("{}/", &prefix[..prefix.len() - 1]);
                self.push(
                    "action >= ? AND action < ?",
                    [Self::text(prefix), SqlValue::Text(upper)],
                );
            }
            None => {}
        }
        if let Some(request_id) = &filters.request_id {
            self.push(
                "(broker_request_id = ? OR agent_request_id = ?)",
                [Self::text(request_id), Self::text(request_id)],
            );
        }
        if let Some(search) = &filters.search {
            // `+id` keeps the match set from driving rowid lookups: the query
            // walks the time (or another filter's) index newest first and
            // probes the matches, which stays fast for common terms.
            self.push(
                "+id IN (SELECT rowid FROM audit_events_fts WHERE audit_events_fts MATCH ?)",
                [SqlValue::Text(fts5_query(search))],
            );
        }
    }

    fn after(&mut self, position: AuditPosition) {
        self.push(
            "ts_us <= ? AND (ts_us < ? OR id < ?)",
            [
                SqlValue::Integer(position.ts_us),
                SqlValue::Integer(position.ts_us),
                SqlValue::Integer(position.id),
            ],
        );
    }
}

/// Each term or phrase as an FTS5 string (`"` doubled inside), joined by
/// implicit AND; a prefix term keeps FTS5's `*` after its closing quote.
/// The tokenizer then splits the string exactly as it split the indexed
/// text, and nothing in it is read as an operator or a column filter.
pub(super) fn fts5_query(search: &AuditSearch) -> String {
    search
        .terms
        .iter()
        .map(|term| {
            let (text, prefix) = match term {
                AuditSearchTerm::Word { text, prefix } => (text.as_str(), *prefix),
                AuditSearchTerm::Phrase(text) => (text.as_str(), false),
            };
            format!(
                "\"{}\"{}",
                text.replace('"', "\"\""),
                if prefix { "*" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The SQL and values of a list query, newest first, fetching one extra row
/// to learn whether another page follows. The page's IDs are chosen first,
/// from index entries where the filters allow, so ordering never carries
/// record JSON; only the page's records are then read.
pub(super) fn list_sql(query: &AuditEventsQuery) -> (String, Vec<SqlValue>) {
    let mut predicate = Predicate::default();
    predicate.visibility(&query.visibility);
    predicate.filters(&query.filters);
    if let Some(after) = query.after {
        predicate.after(after);
    }
    let sql = format!(
        "SELECT id, ts_us, record_json FROM audit_events WHERE id IN (\
         SELECT id FROM audit_events{} ORDER BY ts_us DESC, id DESC LIMIT ?\
         ) ORDER BY ts_us DESC, id DESC",
        predicate.sql()
    );
    let mut values = predicate.values;
    values.push(SqlValue::Integer(query.limit as i64 + 1));
    (sql, values)
}

pub(super) fn list_events(
    conn: &Connection,
    query: &AuditEventsQuery,
) -> rusqlite::Result<StoredPage> {
    let (sql, values) = list_sql(query);
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            Ok((
                AuditPosition {
                    id: row.get(0)?,
                    ts_us: row.get(1)?,
                },
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let more = rows.len() > query.limit;
    rows.truncate(query.limit);
    let next = more
        .then(|| rows.last().map(|(position, _)| *position))
        .flatten();
    Ok(StoredPage {
        records: rows.into_iter().map(|(_, record)| record).collect(),
        next,
    })
}

pub(super) fn timeline_sql(
    broker_request_id: &str,
    visibility: &AuditVisibility,
) -> (String, Vec<SqlValue>) {
    let mut predicate = Predicate::default();
    predicate.push(
        "broker_request_id = ?",
        [Predicate::text(broker_request_id)],
    );
    predicate.visibility(visibility);
    let sql = format!(
        "SELECT record_json FROM audit_events{} ORDER BY ts_us ASC, id ASC LIMIT {AUDIT_TIMELINE_MAX_ITEMS}",
        predicate.sql()
    );
    (sql, predicate.values)
}

pub(super) fn request_timeline(
    conn: &Connection,
    broker_request_id: &str,
    visibility: &AuditVisibility,
) -> rusqlite::Result<Vec<String>> {
    let (sql, values) = timeline_sql(broker_request_id, visibility);
    let mut statement = conn.prepare(&sql)?;
    let records = statement
        .query_map(rusqlite::params_from_iter(values), |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    drop(statement);
    Ok(records)
}
