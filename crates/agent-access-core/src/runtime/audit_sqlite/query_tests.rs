//! Audit queries against real SQLite audit databases written by the audit
//! writer: filters, visibility tiers, search, ordering and paging, request
//! timelines, query plans, and the reader pool's lifecycle.

use super::super::tests::{TEST_NODE_ID, temp_path, test_audit_record};
use super::super::{
    AuditOpenMode, AuditRecord, AuditRuntimeRegistry, AuditSink, AuditStoreInfo,
    IdentitySourceAudit, MatchedGrantAudit,
};
use super::query::{list_sql, timeline_sql};
use super::reader::AuditReaderPool;
use super::schema::FileIdentity;
use super::tests::test_controls;
use crate::{
    AuditConfig, AuditEventFilters, AuditEventsQuery, AuditListRoute, AuditPosition,
    AuditQueryError, AuditQueryLimits, AuditStoreType, AuditVisibility, BrokerTokenClass,
    LimitsConfig, parse_audit_list_query,
};
use agent_access_provider::{Decision, ReasonCode};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

// Keep fixtures within the real retention/query window while preserving exact
// second and microsecond relationships for every append, bound and assertion.
fn epoch() -> DateTime<Utc> {
    static EPOCH: OnceLock<DateTime<Utc>> = OnceLock::new();
    *EPOCH.get_or_init(|| DateTime::from_timestamp(Utc::now().timestamp() - 3600, 0).unwrap())
}

fn at(seconds: i64) -> String {
    (epoch() + ChronoDuration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Micros, true)
}

struct Fixture {
    path: PathBuf,
    sink: AuditSink,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let path = temp_path(name);
        let sink = AuditSink::new(
            Some(&AuditConfig::new(
                AuditStoreType::Sqlite,
                path.display().to_string(),
            )),
            &LimitsConfig::default(),
            Arc::new(AuditRuntimeRegistry::new()),
            TEST_NODE_ID,
            AuditOpenMode::Startup,
        )
        .unwrap();
        Self { path, sink }
    }

    fn store(&self) -> &AuditStoreInfo {
        self.sink.store.as_ref().unwrap()
    }

    async fn append(&self, record: AuditRecord) {
        self.sink.append_required(record).await.unwrap();
    }

    /// A pool on this database with explicit limits.
    fn pool(&self, limits: AuditQueryLimits) -> AuditReaderPool {
        AuditReaderPool::with_limits(
            &self.path,
            self.store().database_id().unwrap(),
            FileIdentity::of(&self.path).unwrap(),
            limits,
        )
    }

    async fn page(
        &self,
        visibility: AuditVisibility,
        query: &str,
        after: Option<AuditPosition>,
        limit: usize,
    ) -> (Vec<String>, Option<AuditPosition>) {
        let params = parse_audit_list_query(Some(query), AuditListRoute::Admin).unwrap();
        let filters =
            AuditEventFilters::from_params(params.filters, AuditListRoute::Admin).unwrap();
        let page = self
            .store()
            .list_events(AuditEventsQuery {
                visibility,
                filters,
                after,
                limit,
            })
            .await
            .unwrap();
        (ids(&page.items), page.next)
    }

    async fn ids(&self, visibility: AuditVisibility, query: &str) -> Vec<String> {
        self.page(visibility, query, None, 200).await.0
    }

    async fn global(&self, query: &str) -> Vec<String> {
        self.ids(AuditVisibility::Global, query).await
    }
}

fn ids(items: &[Box<serde_json::value::RawValue>]) -> Vec<String> {
    items
        .iter()
        .map(|item| {
            let record: Value = serde_json::from_str(item.get()).unwrap();
            record["brokerRequestId"].as_str().unwrap().to_string()
        })
        .collect()
}

fn names(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

fn services(names: &[&str]) -> AuditVisibility {
    AuditVisibility::Services(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<BTreeSet<_>>(),
    )
}

fn record(id: &str, seconds: i64, principal: &str, service: &str, action: &str) -> AuditRecord {
    let mut record = test_audit_record();
    record.broker_request_id = id.to_string();
    record.agent_request_id = format!("agent-{id}");
    record.timestamp = at(seconds);
    record.principal = principal.to_string();
    record.service = service.to_string();
    record.action = action.to_string();
    record
}

fn with(mut record: AuditRecord, edit: impl FnOnce(&mut AuditRecord)) -> AuditRecord {
    edit(&mut record);
    record
}

/// Eight records covering every filter and the three scope-service rules.
async fn seed_filter_records(fixture: &Fixture) {
    let records = vec![
        with(record("a1", 10, "alice", "fake", "echo"), |record| {
            record.identity_source = Some(IdentitySourceAudit {
                namespace: None,
                binding_id: None,
                name: "broker".to_string(),
                kind: "broker_tokens".to_string(),
                token_header: "Authorization".to_string(),
                token_scheme: "Bearer".to_string(),
                token_class: Some(BrokerTokenClass::AgentInvoke),
                token_id: Some("tok-alice".to_string()),
                token_scopes: None,
            });
            record.matched_grant = Some(MatchedGrantAudit {
                config_index: None,
                grant_id: Some("g-fake".to_string()),
                grant_version: Some(1),
                policy_generation: None,
                subject: "user:alice".to_string(),
                priority: None,
                resources: Default::default(),
                execution_contexts: vec![],
            });
        }),
        with(record("a2", 20, "bob", "jira", "issue.view"), |record| {
            record.decision = Decision::Deny;
            record.reason_code = Some(ReasonCode::ServiceActionDenied.into());
        }),
        with(
            record("a3", 30, "alice", "broker", "admin.policy.grants.create"),
            |record| {
                record.provider_audit = Some(json!({"management": {
                    "operation": "admin.policy.grants.create",
                    "targetService": "fake",
                    "phase": "preflight"
                }}));
            },
        ),
        with(
            record("a4", 40, "alice", "broker", "tokens.list"),
            |record| {
                record.provider_audit = Some(json!({"management": {"operation": "tokens.list"}}));
            },
        ),
        with(
            record("a5", 50, "anonymous", "broker", "admin.store.status"),
            |record| {
                record.decision = Decision::Deny;
                record.reason_code = Some(ReasonCode::IdentityRequired.into());
            },
        ),
        with(
            record("a6", 60, "carol", "gitlab_git", "git.receive_pack"),
            |record| {
                record.decision = Decision::Error;
                record.reason_code = Some(ReasonCode::UpstreamFailed.into());
                record.provider_audit = Some(json!({"gateway": {"phase": "started"}}));
            },
        ),
        with(record("a7", 70, "bob", "fake", "echo"), |record| {
            record.decision = Decision::Error;
            record.reason_code = Some(ReasonCode::AuditUnavailable.into());
        }),
        with(
            record("a8", 80, "alice", "jira", "issue.comment.create"),
            |record| record.agent_request_id = "a2".to_string(),
        ),
    ];
    for record in records {
        fixture.append(record).await;
    }
}

#[tokio::test]
async fn each_filter_selects_exactly_its_records_newest_first() {
    let fixture = Fixture::new("filters.audit.sqlite");
    seed_filter_records(&fixture).await;
    let all = names(&["a8", "a7", "a6", "a5", "a4", "a3", "a2", "a1"]);
    assert_eq!(fixture.global("").await, all);
    for (query, expected) in [
        ("principal=alice", vec!["a8", "a4", "a3", "a1"]),
        ("service=broker", vec!["a5", "a4", "a3"]),
        ("scopeService=fake", vec!["a7", "a3", "a1"]),
        ("scopeService=gitlab_git", vec!["a6"]),
        ("action=echo", vec!["a7", "a1"]),
        ("action=admin.policy.*", vec!["a3"]),
        ("action=issue.*", vec!["a8", "a2"]),
        ("action=issue.view", vec!["a2"]),
        ("action=admin.*", vec!["a5", "a3"]),
        ("decision=deny", vec!["a5", "a2"]),
        ("decision=error", vec!["a7", "a6"]),
        ("reasonCode=service_action_denied", vec!["a2"]),
        ("phase=preflight", vec!["a3"]),
        ("phase=started", vec!["a6"]),
        ("phase=completed", vec![]),
        ("tokenId=tok-alice", vec!["a1"]),
        ("grantId=g-fake", vec!["a1"]),
        ("node=other-node", vec![]),
        ("requestId=a2", vec!["a8", "a2"]),
        ("requestId=agent-a5", vec!["a5"]),
        ("q=carol", vec!["a6"]),
        ("principal=alice&service=jira", vec!["a8"]),
    ] {
        assert_eq!(fixture.global(query).await, names(&expected), "{query}");
    }
    assert_eq!(fixture.global(&format!("node={TEST_NODE_ID}")).await, all);
}

#[tokio::test]
async fn time_bounds_are_inclusive_from_and_exclusive_to() {
    let fixture = Fixture::new("time-bounds.audit.sqlite");
    seed_filter_records(&fixture).await;
    let query = |from: i64, to: i64| format!("from={}&to={}", at(from), at(to));
    assert_eq!(
        fixture.global(&query(30, 60)).await,
        names(&["a5", "a4", "a3"])
    );
    assert_eq!(fixture.global(&query(30, 30)).await, Vec::<String>::new());
    assert_eq!(
        fixture.global(&format!("from={}", at(71))).await,
        names(&["a8"])
    );
    assert_eq!(
        fixture.global(&format!("to={}", at(20))).await,
        names(&["a1"])
    );
    // A bound one microsecond after a record excludes it from `from`.
    let just_after = (epoch() + ChronoDuration::seconds(10) + ChronoDuration::microseconds(1))
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    assert_eq!(
        fixture
            .global(&format!("from={just_after}&to={}", at(20)))
            .await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn visibility_tiers_bound_every_query() {
    let fixture = Fixture::new("visibility.audit.sqlite");
    seed_filter_records(&fixture).await;
    // Service managers never see records without a scope service.
    assert_eq!(
        fixture.ids(services(&["fake"]), "").await,
        names(&["a7", "a3", "a1"])
    );
    assert_eq!(
        fixture.ids(services(&["fake", "gitlab_git"]), "").await,
        names(&["a7", "a6", "a3", "a1"])
    );
    assert!(fixture.ids(services(&[]), "").await.is_empty());
    // Filters narrow but never widen the tier.
    assert_eq!(
        fixture
            .ids(services(&["fake"]), "scopeService=gitlab_git")
            .await,
        Vec::<String>::new()
    );
    assert_eq!(
        fixture.ids(services(&["fake"]), "principal=alice").await,
        names(&["a3", "a1"])
    );
    // Self visibility includes the caller's own records without a scope
    // service, such as token management.
    assert_eq!(
        fixture
            .ids(AuditVisibility::Principal("alice".to_string()), "")
            .await,
        names(&["a8", "a4", "a3", "a1"])
    );
    assert_eq!(
        fixture
            .ids(
                AuditVisibility::Principal("alice".to_string()),
                "service=jira"
            )
            .await,
        names(&["a8"])
    );
}

#[tokio::test]
async fn search_terms_phrases_and_prefixes_never_interpret_fts_syntax() {
    let fixture = Fixture::new("search.audit.sqlite");
    for (id, note) in [
        ("s1", "near a or b col x unbalanced"),
        ("s2", "issue view summary"),
        ("s3", "view issue"),
        ("s4", "jiraworkflow"),
    ] {
        fixture
            .append(with(record(id, 10, "alice", "fake", "echo"), |record| {
                record.provider_audit = Some(json!({ "note": note }));
            }))
            .await;
    }
    for (query, expected) in [
        ("q=%22issue view%22", vec!["s2"]),
        ("q=issue view", vec!["s3", "s2"]),
        ("q=jiraw*", vec!["s4"]),
        ("q=jiraw", vec![]),
        ("q=VIEW", vec!["s3", "s2"]),
        // Operators, column filters, and unbalanced quotes are literal text.
        ("q=NEAR( a OR b ) col:x %22unbalanced", vec!["s1"]),
        ("q=OR", vec!["s1"]),
        ("q=NOT", vec![]),
        ("q=AND issue", vec![]),
        ("q=note:issue", vec![]),
        ("q=*", vec![]),
        // A quote inside a term is literal; the term is one phrase.
        ("q=%22 %22 issue%22view", vec!["s2"]),
        ("q=^issue", vec!["s3", "s2"]),
    ] {
        let query = query.replace(' ', "+");
        assert_eq!(fixture.global(&query).await, names(&expected), "{query}");
    }
}

#[tokio::test]
async fn pages_follow_timestamp_then_insertion_order_by_position() {
    let fixture = Fixture::new("paging.audit.sqlite");
    for (id, seconds) in [
        ("p1", 100),
        ("p2", 100),
        ("p3", 100),
        ("p4", 90),
        ("p5", 90),
        ("p6", 80),
        ("p7", 70),
    ] {
        fixture
            .append(record(id, seconds, "alice", "fake", "echo"))
            .await;
    }
    let (first, next) = fixture.page(AuditVisibility::Global, "", None, 3).await;
    assert_eq!(first, names(&["p3", "p2", "p1"]));
    let next = next.unwrap();
    assert_eq!(
        next.ts_us,
        DateTime::parse_from_rfc3339(&at(100))
            .unwrap()
            .timestamp_micros()
    );

    // Records written after the first page: a newer one never appears in
    // later pages; a late one with an older timestamp does.
    fixture
        .append(record("newer", 200, "alice", "fake", "echo"))
        .await;
    fixture
        .append(record("late", 95, "alice", "fake", "echo"))
        .await;

    let (second, next) = fixture
        .page(AuditVisibility::Global, "", Some(next), 3)
        .await;
    assert_eq!(second, names(&["late", "p5", "p4"]));
    let (third, next) = fixture.page(AuditVisibility::Global, "", next, 3).await;
    assert_eq!(third, names(&["p6", "p7"]));
    assert!(next.is_none());

    // An exactly full last page reports no further page.
    let (all, next) = fixture.page(AuditVisibility::Global, "", None, 9).await;
    assert_eq!(all.len(), 9);
    assert!(next.is_none());
}

#[tokio::test]
async fn request_timelines_are_visible_records_oldest_first_capped() {
    let fixture = Fixture::new("timeline.audit.sqlite");
    fixture
        .append(with(
            record("t-req", 20, "alice", "fake", "echo"),
            |record| {
                record.provider_audit = Some(json!({"streamPhase": "completed"}));
            },
        ))
        .await;
    fixture
        .append(with(
            record("t-req", 10, "alice", "fake", "echo"),
            |record| {
                record.provider_audit = Some(json!({"streamPhase": "started"}));
            },
        ))
        .await;
    fixture
        .append(record(
            "t-req",
            15,
            "alice",
            "gitlab_git",
            "git.upload_pack",
        ))
        .await;
    fixture
        .append(record("other", 5, "alice", "fake", "echo"))
        .await;
    let timeline = |visibility| async {
        fixture
            .store()
            .request_timeline("t-req", visibility)
            .await
            .unwrap()
            .iter()
            .map(|item| {
                let record: Value = serde_json::from_str(item.get()).unwrap();
                (
                    record["service"].as_str().unwrap().to_string(),
                    record["timestamp"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        timeline(AuditVisibility::Global).await,
        vec![
            ("fake".to_string(), at(10)),
            ("gitlab_git".to_string(), at(15)),
            ("fake".to_string(), at(20)),
        ]
    );
    assert_eq!(timeline(services(&["fake"])).await.len(), 2);
    assert!(timeline(services(&["jira"])).await.is_empty());
    assert!(
        timeline(AuditVisibility::Principal("bob".to_string()))
            .await
            .is_empty()
    );

    for index in 0..105 {
        fixture
            .append(record("busy", 1000 + index, "alice", "fake", "echo"))
            .await;
    }
    let items = fixture
        .store()
        .request_timeline("busy", AuditVisibility::Global)
        .await
        .unwrap();
    assert_eq!(items.len(), 100);
    let first: Value = serde_json::from_str(items[0].get()).unwrap();
    assert_eq!(first["timestamp"], at(1000));
}

#[tokio::test]
async fn items_are_the_stored_records_exactly_as_written() {
    let fixture = Fixture::new("exact.audit.sqlite");
    fixture
        .append(record("exact", 10, "alice", "fake", "echo"))
        .await;
    let stored: String = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT record_json FROM audit_events", [], |row| row.get(0))
        .unwrap();
    let page = fixture
        .store()
        .list_events(AuditEventsQuery {
            visibility: AuditVisibility::Global,
            filters: AuditEventFilters::from_params(Default::default(), AuditListRoute::Admin)
                .unwrap(),
            after: None,
            limit: 50,
        })
        .await
        .unwrap();
    assert_eq!(page.items[0].get(), stored);
}

/// The detail lines of `EXPLAIN QUERY PLAN`.
fn plan(conn: &Connection, sql: &str, values: Vec<rusqlite::types::Value>) -> Vec<String> {
    let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn uses_covering_index(detail: &str, index: &str) -> bool {
    detail.split(" | ").any(|line| {
        line.contains("USING COVERING INDEX") && line.split_whitespace().any(|word| word == index)
    })
}

fn filters(query: &str) -> AuditEventFilters {
    let params = parse_audit_list_query(Some(query), AuditListRoute::Admin).unwrap();
    AuditEventFilters::from_params(params.filters, AuditListRoute::Admin).unwrap()
}

/// Plans on the baseline schema without statistics (the planner's default
/// estimates assume a large table); the scale test prints plans with real
/// statistics.
#[test]
fn single_filter_time_range_queries_use_their_index_in_order() {
    let conn = super::schema::baseline_schema_in_memory();
    let explain = |visibility: AuditVisibility, query: &str, after: Option<AuditPosition>| {
        let (sql, values) = list_sql(&AuditEventsQuery {
            visibility,
            filters: filters(query),
            after,
            limit: 50,
        });
        plan(&conn, &sql, values).join(" | ")
    };
    let range = format!("from={}&to={}", at(0), at(86_400));
    for (filter, index) in [
        ("", "audit_events_ts"),
        ("principal=alice", "audit_events_principal_ts"),
        ("service=jira", "audit_events_service_ts"),
        ("scopeService=fake", "audit_events_scope_ts"),
        ("action=echo", "audit_events_action_ts"),
        ("decision=deny", "audit_events_decision_ts"),
        ("reasonCode=input_invalid", "audit_events_reason_ts"),
        ("tokenId=tok-alice", "audit_events_token_ts"),
        ("grantId=g-fake", "audit_events_grant_ts"),
    ] {
        for query in [filter.to_string(), format!("{filter}&{range}")] {
            let query = query.trim_start_matches('&').to_string();
            for after in [None, Some(AuditPosition { ts_us: 1, id: 1 })] {
                let detail = explain(AuditVisibility::Global, &query, after);
                // The page's IDs come from the covering index in order; only
                // the outer 51-row page is sorted.
                assert!(uses_covering_index(&detail, index), "{query}: {detail}");
                assert_eq!(
                    detail.matches("TEMP B-TREE").count(),
                    1,
                    "{query}: {detail}"
                );
            }
        }
    }
    // Self and single-service tiers use their own index too.
    for (visibility, index) in [
        (
            AuditVisibility::Principal("alice".into()),
            "audit_events_principal_ts",
        ),
        (services(&["fake"]), "audit_events_scope_ts"),
    ] {
        let detail = explain(visibility, &range, None);
        assert!(uses_covering_index(&detail, index), "{detail}");
        assert_eq!(detail.matches("TEMP B-TREE").count(), 1, "{detail}");
    }
    // An action prefix is a range on the action index.
    let detail = explain(AuditVisibility::Global, "action=admin.policy.*", None);
    assert!(
        uses_covering_index(&detail, "audit_events_action_ts"),
        "{detail}"
    );
    // Search probes the match set while walking the time index, or the
    // index of another filter.
    let detail = explain(AuditVisibility::Global, "q=alice", None);
    assert!(uses_covering_index(&detail, "audit_events_ts"), "{detail}");
    assert!(
        detail.contains("audit_events_fts VIRTUAL TABLE"),
        "{detail}"
    );
    let detail = explain(AuditVisibility::Global, "q=alice&principal=alice", None);
    assert!(
        uses_covering_index(&detail, "audit_events_principal_ts"),
        "{detail}"
    );
    // Request IDs use both request indexes; timelines the broker one.
    let detail = explain(AuditVisibility::Global, "requestId=a2", None);
    assert!(detail.contains("audit_events_broker_request"), "{detail}");
    assert!(detail.contains("audit_events_agent_request"), "{detail}");
    let (sql, values) = timeline_sql("a2", &AuditVisibility::Global);
    let detail = plan(&conn, &sql, values).join(" | ");
    assert!(detail.contains("audit_events_broker_request"), "{detail}");
}

// ---------------------------------------------------------------------------
// Reader pool lifecycle
// ---------------------------------------------------------------------------

fn limits(connections: usize, waiting: usize, deadline: Duration) -> AuditQueryLimits {
    AuditQueryLimits {
        connections,
        waiting,
        deadline,
    }
}

/// Runs until interrupted.
fn endless(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c",
        [],
        |row| row.get(0),
    )
}

fn count_events(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
}

/// Query work runs on a blocking thread inside the caller's span, so what it
/// logs stays correlated with the request and inside a scoped trace capture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_work_runs_in_the_callers_span() {
    let fixture = Fixture::new("reader-span.audit.sqlite");
    let pool = fixture.pool(limits(1, 16, Duration::from_secs(5)));
    let capture = agent_access_provider::test_support::install_trace_capture().start();
    let counted = capture
        .run(pool.run(|conn| {
            tracing::info!(event = "audit_reader_test_work");
            count_events(conn)
        }))
        .await;
    assert!(counted.is_ok(), "{counted:?}");
    let events = capture.take_events();
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "audit_reader_test_work"),
        "{events:?}"
    );
}

#[tokio::test]
async fn a_query_past_its_deadline_before_starting_never_runs() {
    let fixture = Fixture::new("deadline-before.audit.sqlite");
    let pool = fixture.pool(limits(1, 16, Duration::ZERO));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let result = pool
        .run(move |conn| {
            flag.store(true, Ordering::SeqCst);
            count_events(conn)
        })
        .await;
    assert_eq!(result, Err(AuditQueryError::Timeout));
    wait_until(|| pool.admitted() == 0).await;
    assert!(!ran.load(Ordering::SeqCst));

    // Waiting for a connection counts against the deadline too.
    let pool = Arc::new(fixture.pool(limits(1, 16, Duration::from_millis(300))));
    let gate = Arc::new(Gate::default());
    let holder = {
        let pool = Arc::clone(&pool);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            pool.run(move |conn| {
                gate.wait();
                count_events(conn)
            })
            .await
        })
    };
    wait_until(|| pool.admitted() == 1).await;
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let started = Instant::now();
    let waiter = pool
        .run(move |conn| {
            flag.store(true, Ordering::SeqCst);
            count_events(conn)
        })
        .await;
    assert_eq!(waiter, Err(AuditQueryError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!ran.load(Ordering::SeqCst));
    gate.open();
    // The holder itself ran past its deadline only while blocked outside
    // SQLite, so it completes once released.
    let _ = holder.await.unwrap();
    wait_until(|| pool.admitted() == 0).await;
}

#[tokio::test]
async fn a_deadline_during_execution_interrupts_and_the_connection_is_reused() {
    let fixture = Fixture::new("deadline-during.audit.sqlite");
    fixture
        .append(record("one", 10, "alice", "fake", "echo"))
        .await;
    let pool = fixture.pool(limits(1, 16, Duration::from_secs(1)));
    assert_eq!(pool.run(count_events).await, Ok(1));
    let running = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&running);
    let started = Instant::now();
    let result = pool
        .run(move |conn| {
            flag.store(true, Ordering::SeqCst);
            endless(conn)
        })
        .await;
    assert_eq!(result, Err(AuditQueryError::Timeout));
    assert!(running.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_secs(4));
    // The interrupted connection went back to the pool and serves the next
    // query without a stale interrupt.
    wait_until(|| pool.admitted() == 0).await;
    assert_eq!(pool.open_connections(), 1);
    assert_eq!(pool.run(count_events).await, Ok(1));
    assert_eq!(pool.open_connections(), 1);
}

#[tokio::test]
async fn the_seventeenth_waiting_query_is_rejected() {
    let fixture = Fixture::new("admission.audit.sqlite");
    let pool = Arc::new(fixture.pool(limits(4, 16, Duration::from_secs(60))));
    let gate = Arc::new(Gate::default());
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let pool = Arc::clone(&pool);
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            pool.run(move |conn| {
                gate.wait();
                count_events(conn)
            })
            .await
        }));
    }
    wait_until(|| pool.admitted() == 20).await;
    assert_eq!(
        pool.run(count_events).await,
        Err(AuditQueryError::ConcurrencyLimited)
    );
    gate.open();
    for task in tasks {
        assert_eq!(task.await.unwrap(), Ok(0));
    }
    assert!(pool.open_connections() <= 4);
    assert_eq!(pool.admitted(), 0);
    assert_eq!(pool.run(count_events).await, Ok(0));
}

#[tokio::test]
async fn a_client_disconnect_interrupts_its_query() {
    let fixture = Fixture::new("disconnect.audit.sqlite");
    let pool = Arc::new(fixture.pool(limits(1, 16, Duration::from_secs(60))));
    let running = Arc::new(AtomicBool::new(false));
    let task = {
        let pool = Arc::clone(&pool);
        let running = Arc::clone(&running);
        tokio::spawn(async move {
            pool.run(move |conn| {
                running.store(true, Ordering::SeqCst);
                endless(conn)
            })
            .await
        })
    };
    wait_until(|| running.load(Ordering::SeqCst)).await;
    // Dropping the handler future is what a disconnect does.
    task.abort();
    let started = Instant::now();
    // The only connection comes back well before the 60 s deadline.
    assert_eq!(pool.run(count_events).await, Ok(0));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(pool.open_connections(), 1);
}

#[tokio::test]
async fn a_dropped_generation_drains_and_then_closes_its_readers() {
    let fixture = Fixture::new("drain.audit.sqlite");
    let pool = Arc::new(fixture.pool(limits(2, 16, Duration::from_secs(60))));
    let gate = Arc::new(Gate::default());
    // Open both connections, then keep one busy on a blocking thread whose
    // caller has gone away (as after a client disconnect), so only the
    // generation still holds the pool handle.
    let running = Arc::new(AtomicBool::new(false));
    let busy = {
        let pool = Arc::clone(&pool);
        let gate = Arc::clone(&gate);
        let running = Arc::clone(&running);
        tokio::spawn(async move {
            pool.run(move |conn| {
                running.store(true, Ordering::SeqCst);
                gate.wait();
                count_events(conn)
            })
            .await
        })
    };
    wait_until(|| running.load(Ordering::SeqCst)).await;
    assert_eq!(pool.run(count_events).await, Ok(0));
    assert_eq!(pool.open_connections(), 2);
    busy.abort();
    assert!(busy.await.unwrap_err().is_cancelled());
    let observer = pool.shared_open_connections();

    // The generation's handle is dropped: the idle reader closes at once,
    // the running query keeps its connection until it finishes.
    let pool = Arc::try_unwrap(pool).unwrap_or_else(|_| panic!("the test owns the handle"));
    drop(pool);
    assert_eq!(observer.get(), Some(1));
    gate.open();
    wait_until(|| observer.get().is_none()).await;
}

#[tokio::test]
async fn no_read_transaction_outlives_a_query() {
    let fixture = Fixture::new("wal.audit.sqlite");
    for index in 0..20 {
        fixture
            .append(record(&format!("w{index}"), index, "alice", "fake", "echo"))
            .await;
    }
    let store = fixture.store();
    for _ in 0..3 {
        let page = store
            .list_events(AuditEventsQuery {
                visibility: AuditVisibility::Global,
                filters: filters("q=alice"),
                after: None,
                limit: 5,
            })
            .await
            .unwrap();
        assert_eq!(page.items.len(), 5);
        store
            .request_timeline("w1", AuditVisibility::Global)
            .await
            .unwrap();
    }
    // With the pooled readers idle, a truncating checkpoint needs no reader
    // to finish: nothing still holds a snapshot.
    let checkpointer = Connection::open(&fixture.path).unwrap();
    // Wait for the writer if a maintenance slice holds its lock; a reader
    // snapshot would make the checkpoint report busy after the timeout.
    checkpointer.busy_timeout(Duration::from_secs(5)).unwrap();
    let (busy, log, checkpointed): (i64, i64, i64) = checkpointer
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!((busy, log, checkpointed), (0, 0, 0));
}

#[tokio::test]
async fn queries_work_while_audit_writes_fail() {
    let fixture = Fixture::new("full.audit.sqlite");
    fixture
        .append(record("before", 10, "alice", "fake", "echo"))
        .await;
    // Allow no new pages, so realistic appends fail with SQLITE_FULL.
    let conn = Connection::open(&fixture.path).unwrap();
    let pages: i64 = conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap();
    let free: i64 = conn
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .unwrap();
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap();
    test_controls(&fixture.path.display().to_string())
        .lock()
        .unwrap()
        .max_page_count = Some(pages as u64);
    let large = with(record("large", 20, "alice", "fake", "echo"), |record| {
        record.provider_audit =
            Some(json!({ "payload": "p".repeat(((free + 4) * page_size) as usize) }));
    });
    assert!(fixture.sink.append_required(large).await.is_err());

    assert_eq!(fixture.global("").await, names(&["before"]));
    assert_eq!(
        fixture
            .store()
            .request_timeline("before", AuditVisibility::Global)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn jsonl_stores_do_not_answer_queries() {
    let path = temp_path("jsonl.audit.jsonl");
    let sink = AuditSink::new(
        Some(&AuditConfig::new(
            AuditStoreType::Jsonl,
            path.display().to_string(),
        )),
        &LimitsConfig::default(),
        Arc::new(AuditRuntimeRegistry::new()),
        TEST_NODE_ID,
        AuditOpenMode::Startup,
    )
    .unwrap();
    let store = sink.store.as_ref().unwrap();
    assert!(!store.supports_queries());
    assert_eq!(
        store
            .request_timeline("x", AuditVisibility::Global)
            .await
            .unwrap_err(),
        AuditQueryError::Unavailable
    );
}

/// Blocks reader work on its blocking thread until opened.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "condition not reached");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// Scale
// ---------------------------------------------------------------------------

fn print_plan(path: &std::path::Path, query: &str) {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let (sql, values) = list_sql(&AuditEventsQuery {
        visibility: AuditVisibility::Global,
        filters: filters(query),
        after: None,
        limit: 50,
    });
    println!("  plan {query}: {}", plan(&conn, &sql, values).join(" | "));
}

/// The spec's query targets (developer hardware, not a CI gate): with
/// 1,000,000 records over 30 days, a first page (`limit` 50) filtered by any
/// single indexed column, with or without a 24-hour range, under 250 ms; a
/// single-term search under 500 ms. Run with
/// `cargo test --release -p agent-access-core audit_query_scale -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "scale measurement; run explicitly with --release"]
async fn audit_query_scale() {
    use super::super::StampedAuditRecord;
    use super::row::PreparedRow;

    const RECORDS: usize = 1_000_000;
    const PRINCIPALS: usize = 200;
    const SERVICES: [&str; 6] = [
        "jira",
        "confluence",
        "gitlab",
        "fake",
        "broker",
        "gitlab_git",
    ];
    let fixture = Fixture::new("scale.audit.sqlite");
    // Preserve the full 30-day distribution as historical data.
    let start = epoch() - ChronoDuration::days(30);
    let span_us = 30 * 86_400 * 1_000_000_i64;
    let loaded = Instant::now();
    {
        let conn = Connection::open(&fixture.path).unwrap();
        conn.execute_batch("PRAGMA synchronous = OFF;").unwrap();
        let mut next = 0;
        while next < RECORDS {
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            for index in next..(next + 10_000).min(RECORDS) {
                let service = SERVICES[index % SERVICES.len()];
                let mut record = record(
                    &uuid::Uuid::new_v4().to_string(),
                    0,
                    &format!("user{}", index % PRINCIPALS),
                    service,
                    [
                        "issue.view",
                        "page.get",
                        "mr.list",
                        "echo",
                        "tokens.list",
                        "git.upload_pack",
                    ][index % SERVICES.len()],
                );
                record.timestamp = (start
                    + ChronoDuration::microseconds(index as i64 * (span_us / RECORDS as i64)))
                .to_rfc3339_opts(SecondsFormat::Micros, true);
                if index % 7 == 0 {
                    record.decision = Decision::Deny;
                    record.reason_code = Some(ReasonCode::ServiceActionDenied.into());
                }
                record.identity_source = Some(IdentitySourceAudit {
                    namespace: None,
                    binding_id: None,
                    name: "broker".to_string(),
                    kind: "broker_tokens".to_string(),
                    token_header: "Authorization".to_string(),
                    token_scheme: "Bearer".to_string(),
                    token_class: Some(BrokerTokenClass::AgentInvoke),
                    token_id: Some(format!("tok{}", index % 1000)),
                    token_scopes: None,
                });
                record.matched_grant = Some(MatchedGrantAudit {
                    config_index: None,
                    grant_id: Some(format!("grant{}", index % 300)),
                    grant_version: Some(1),
                    policy_generation: None,
                    subject: "group:users".to_string(),
                    priority: None,
                    resources: Default::default(),
                    execution_contexts: vec![],
                });
                record.resource_scopes =
                    [("project".to_string(), vec![format!("PROJ{}", index % 50)])]
                        .into_iter()
                        .collect();
                let row =
                    PreparedRow::prepare(&StampedAuditRecord::new(record, TEST_NODE_ID)).unwrap();
                super::insert_row(&conn, &row, &row.audit_id).unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
            next += 10_000;
        }
        conn.execute_batch("PRAGMA optimize;").unwrap();
    }
    println!("loaded {RECORDS} records in {:?}", loaded.elapsed());
    let store = fixture.store();
    let middle = start + ChronoDuration::days(15);
    let range = format!(
        "from={}&to={}",
        (middle - ChronoDuration::hours(12)).to_rfc3339_opts(SecondsFormat::Secs, true),
        (middle + ChronoDuration::hours(12)).to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let mut worst_filtered = Duration::ZERO;
    for filter in [
        "principal=user7",
        "service=jira",
        "scopeService=gitlab",
        "action=echo",
        "decision=deny",
        "reasonCode=service_action_denied",
        "tokenId=tok7",
        "grantId=grant7",
    ] {
        for query in [filter.to_string(), format!("{filter}&{range}")] {
            print_plan(&fixture.path, &query);
            let started = Instant::now();
            let page = store
                .list_events(AuditEventsQuery {
                    visibility: AuditVisibility::Global,
                    filters: filters(&query),
                    after: None,
                    limit: 50,
                })
                .await
                .unwrap();
            let elapsed = started.elapsed();
            worst_filtered = worst_filtered.max(elapsed);
            println!("{query}: {} items in {elapsed:?}", page.items.len());
        }
    }
    let mut worst_search = Duration::ZERO;
    for query in [
        "q=user7",
        "q=PROJ7",
        "q=jira",
        "q=tok7",
        "q=nosuchterm",
        "q=user7 jira",
    ] {
        print_plan(&fixture.path, query);
        let started = Instant::now();
        let page = store
            .list_events(AuditEventsQuery {
                visibility: AuditVisibility::Global,
                filters: filters(&query.replace(' ', "+")),
                after: None,
                limit: 50,
            })
            .await
            .unwrap();
        let elapsed = started.elapsed();
        worst_search = worst_search.max(elapsed);
        println!("{query}: {} items in {elapsed:?}", page.items.len());
    }
    // Outside the targets: an unindexed column, a prefix range, and a
    // request ID.
    for query in ["node=elsewhere", "action=issue.*", "requestId=missing"] {
        print_plan(&fixture.path, query);
        let started = Instant::now();
        let page = store
            .list_events(AuditEventsQuery {
                visibility: AuditVisibility::Global,
                filters: filters(query),
                after: None,
                limit: 50,
            })
            .await
            .unwrap();
        println!(
            "{query}: {} items in {:?}",
            page.items.len(),
            started.elapsed()
        );
    }
    println!("worst filtered first page {worst_filtered:?}; worst search {worst_search:?}");
    assert!(worst_filtered < Duration::from_millis(250));
    assert!(worst_search < Duration::from_millis(500));
}
