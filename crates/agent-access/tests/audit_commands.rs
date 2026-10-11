//! `agent-access admin audit …` and `agent-access audit …` map to the audit
//! query routes: each filter flag to its query parameter, `--since` to an
//! absolute UTC `from`, and a continuation to `cursor` and `limit` only.
use chrono::{DateTime, TimeDelta, Utc};
use std::process::{Command, Output};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REQUEST_ID: &str = "0199a0c4-5d3e-7a41-9c2b-8f1e2d3c4b5a";

fn isolated_cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
        cmd.env_remove(key);
    }
    cmd.env("AGENT_ACCESS_CONFIG", "/dev/null");
    cmd
}

fn cli(url: &str) -> Command {
    let mut cmd = isolated_cli();
    cmd.args(["--url", url, "--no-token"]);
    cmd
}

fn run(url: &str, args: &[&str]) -> Output {
    cli(url).args(args).output().unwrap()
}

fn envelope(operation: &str, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "decision": "allow",
        "requestId": "cli-audit",
        "brokerRequestId": "broker-cli-audit",
        "operation": operation,
        "principal": "alice",
        "result": result
    })
}

fn failure(status: u16, operation: &str, reason_code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({
        "ok": false,
        "decision": if status == 403 { "deny" } else { "error" },
        "reasonCode": reason_code,
        "requestId": "cli-audit",
        "brokerRequestId": "broker-cli-audit",
        "operation": operation,
        "principal": "alice",
        "error": {"message": message}
    }))
}

fn page() -> serde_json::Value {
    serde_json::json!({
        "items": [{"auditId": "a-1", "nodeId": "broker-prod-1", "decision": "deny"}],
        "nextCursor": "eyJ2IjoxfQ"
    })
}

fn stdout_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// The query pairs of every request the server received, in order.
async fn sent_queries(server: &MockServer) -> Vec<Vec<(String, String)>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            request
                .url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

async fn mount_list(server: &MockServer, route: &str, operation: &str) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(operation, page())))
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_events_list_sends_each_filter_as_its_query_parameter() {
    let server = MockServer::start().await;
    mount_list(&server, "/v1/admin/audit/events", "admin.audit.events.list").await;

    let output = run(
        &server.uri(),
        &[
            "admin",
            "audit",
            "events",
            "list",
            "--from",
            "2026-09-25T10:00:00+02:00",
            "--to",
            "2026-09-26T00:00:00.5Z",
            "--principal",
            "alice",
            "--service",
            "broker",
            "--scope-service",
            "jira",
            "--action",
            "admin.policy.*",
            "--decision",
            "deny",
            "--reason-code",
            "policy_denied",
            "--phase",
            "upstream_verification",
            "--token-id",
            "tok-1",
            "--grant-id",
            "grant-1",
            "--node",
            "broker-prod-1",
            "--request-id",
            "req-1",
            "--query",
            "deny \"jira issue\" admin* a+b&c=d",
            "--limit",
            "25",
        ],
    );

    assert_eq!(
        stdout_json(&output),
        envelope("admin.audit.events.list", page())
    );
    assert_eq!(
        sent_queries(&server).await,
        vec![pairs(&[
            ("from", "2026-09-25T08:00:00Z"),
            ("to", "2026-09-26T00:00:00.500Z"),
            ("principal", "alice"),
            ("service", "broker"),
            ("scopeService", "jira"),
            ("action", "admin.policy.*"),
            ("decision", "deny"),
            ("reasonCode", "policy_denied"),
            ("phase", "upstream_verification"),
            ("tokenId", "tok-1"),
            ("grantId", "grant-1"),
            ("node", "broker-prod-1"),
            ("requestId", "req-1"),
            ("q", "deny \"jira issue\" admin* a+b&c=d"),
            ("limit", "25"),
        ])]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_list_resolves_since_to_an_absolute_utc_from() {
    let server = MockServer::start().await;
    mount_list(&server, "/v1/audit/events", "audit.events.list").await;
    mount_list(&server, "/v1/admin/audit/events", "admin.audit.events.list").await;

    let before = Utc::now();
    stdout_json(&run(
        &server.uri(),
        &[
            "audit",
            "events",
            "list",
            "--since",
            "24h",
            "--decision",
            "deny",
        ],
    ));
    stdout_json(&run(
        &server.uri(),
        &[
            "admin",
            "audit",
            "events",
            "list",
            "--since",
            "90m",
            "--to",
            "2030-01-01T00:00:00Z",
        ],
    ));
    let after = Utc::now();

    let sent = sent_queries(&server).await;
    assert_eq!(sent.len(), 2);
    for (query, since, rest) in [
        (&sent[0], TimeDelta::hours(24), ("decision", "deny")),
        (
            &sent[1],
            TimeDelta::minutes(90),
            ("to", "2030-01-01T00:00:00Z"),
        ),
    ] {
        assert_eq!(query.len(), 2, "{query:?}");
        assert_eq!(query[1], (rest.0.to_string(), rest.1.to_string()));
        let (name, from) = &query[0];
        assert_eq!(name, "from");
        assert!(from.ends_with('Z'), "{from}");
        let from = DateTime::parse_from_rfc3339(from).unwrap();
        // The CLI sends whole seconds, so `from` may be up to 1s earlier.
        assert!(from >= before - since - TimeDelta::seconds(1), "{from}");
        assert!(from <= after - since, "{from}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_continuation_sends_only_cursor_and_limit() {
    let server = MockServer::start().await;
    mount_list(&server, "/v1/admin/audit/events", "admin.audit.events.list").await;
    mount_list(&server, "/v1/audit/events", "audit.events.list").await;
    let cursor = "eyJyb3V0ZSI6ImFkbWluIn0-_x";

    stdout_json(&run(
        &server.uri(),
        &[
            "admin", "audit", "events", "list", "--cursor", cursor, "--limit", "10",
        ],
    ));
    stdout_json(&run(
        &server.uri(),
        &["audit", "events", "list", "--cursor", cursor],
    ));

    assert_eq!(
        sent_queries(&server).await,
        vec![
            pairs(&[("limit", "10"), ("cursor", cursor)]),
            pairs(&[("cursor", cursor)]),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_with_any_filter_is_rejected_before_sending() {
    let server = MockServer::start().await;
    let filters = [
        vec!["--from", "2026-09-25T00:00:00Z"],
        vec!["--since", "24h"],
        vec!["--to", "2026-09-25T00:00:00Z"],
        vec!["--service", "jira"],
        vec!["--scope-service", "jira"],
        vec!["--action", "jira.issue.view"],
        vec!["--decision", "deny"],
        vec!["--reason-code", "policy_denied"],
        vec!["--phase", "completed"],
        vec!["--token-id", "tok-1"],
        vec!["--grant-id", "grant-1"],
        vec!["--node", "broker-prod-1"],
        vec!["--request-id", "req-1"],
        vec!["--query", "jira"],
    ];
    let admin = filters
        .iter()
        .cloned()
        .chain([vec!["--principal", "alice"]])
        .map(|filter| (vec!["admin", "audit", "events", "list"], filter));
    let own = filters
        .iter()
        .cloned()
        .map(|filter| (vec!["audit", "events", "list"], filter));
    for (command, filter) in admin.chain(own) {
        let mut args = command.clone();
        args.extend(["--cursor", "eyJ2IjoxfQ", "--limit", "5"]);
        args.extend(&filter);
        let output = run(&server.uri(), &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("the argument '--cursor <CURSOR>' cannot be used with")
                && stderr.contains(filter[0]),
            "{args:?}: {stderr}"
        );
    }
    assert!(sent_queries(&server).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_is_not_an_option_on_the_own_records_listing() {
    let server = MockServer::start().await;
    let output = run(
        &server.uri(),
        &["audit", "events", "list", "--principal", "bob"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--principal'"));
    assert!(sent_queries(&server).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_times_and_values_are_rejected_before_sending() {
    let server = MockServer::start().await;
    for invalid in [
        vec!["--since", "1w"],
        vec!["--since", "0s"],
        vec!["--since", "24"],
        vec!["--since", "24h", "--from", "2026-09-25T00:00:00Z"],
        vec!["--from", "yesterday"],
        vec!["--from", "2026-09-25"],
        vec!["--to", "2026-09-25T00:00:00"],
        vec!["--decision", "maybe"],
        vec!["--phase", "done"],
        vec!["--limit", "ten"],
    ] {
        let mut args = vec!["admin", "audit", "events", "list"];
        args.extend(&invalid);
        let output = run(&server.uri(), &args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{invalid:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = run(
        &server.uri(),
        &["audit", "events", "list", "--since", "800000d"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--since reaches before the year 0000")
    );
    assert!(sent_queries(&server).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_inspect_uses_the_timeline_routes() {
    let server = MockServer::start().await;
    let timeline = serde_json::json!({
        "brokerRequestId": REQUEST_ID,
        "items": [{"auditId": "a-1", "phase": "started"}, {"auditId": "a-2", "phase": "completed"}]
    });
    Mock::given(method("GET"))
        .and(path(format!("/v1/admin/audit/requests/{REQUEST_ID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(envelope("admin.audit.requests.inspect", timeline.clone())),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/audit/requests/{REQUEST_ID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(envelope("audit.requests.inspect", timeline.clone())),
        )
        .expect(1)
        .mount(&server)
        .await;
    // Validation belongs to the broker; the CLI encodes the path segment.
    Mock::given(method("GET"))
        .and(path("/v1/audit/requests/not%20a%2Fuuid%3F"))
        .respond_with(failure(
            400,
            "audit.requests.inspect",
            "input_invalid",
            "brokerRequestId must be a UUID",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let admin = stdout_json(&run(
        &server.uri(),
        &["admin", "audit", "requests", "inspect", REQUEST_ID],
    ));
    assert_eq!(admin["operation"], "admin.audit.requests.inspect");
    assert_eq!(admin["result"], timeline);
    let own = stdout_json(&run(
        &server.uri(),
        &["audit", "requests", "inspect", REQUEST_ID],
    ));
    assert_eq!(own["result"], timeline);

    let rejected = run(
        &server.uri(),
        &["audit", "requests", "inspect", "not a/uuid?"],
    );
    assert_eq!(rejected.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(body["reasonCode"], "input_invalid");
    assert!(
        sent_queries(&server)
            .await
            .iter()
            .all(|query| query.is_empty())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_errors_print_the_envelope_with_the_status_exit_code() {
    for (status, reason_code, message, exit_code) in [
        (
            404,
            "audit_query_unavailable",
            "the configured audit backend does not support queries",
            3,
        ),
        (
            400,
            "input_invalid",
            "cursor is invalid or stale; repeat the request without cursor",
            3,
        ),
        (
            403,
            "broker_token_class_denied",
            "admin tokens cannot use this route",
            2,
        ),
        (
            429,
            "concurrency_limited",
            "too many audit queries are running; retry shortly",
            7,
        ),
        (
            503,
            "audit_query_timeout",
            "the audit query exceeded its time budget; narrow the filters",
            5,
        ),
        (500, "operation_failed", "the audit query failed", 5),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/audit/events"))
            .respond_with(failure(status, "audit.events.list", reason_code, message))
            .expect(1)
            .mount(&server)
            .await;
        let output = run(&server.uri(), &["audit", "events", "list"]);
        assert_eq!(output.status.code(), Some(exit_code), "{reason_code}");
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["reasonCode"], reason_code);
        assert_eq!(body["error"]["message"], message);
        // Only broker and upstream rate limits add a stderr notice.
        assert!(output.stderr.is_empty(), "{reason_code}");
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/admin/audit/requests/{REQUEST_ID}")))
        .respond_with(failure(
            404,
            "admin.audit.requests.inspect",
            "audit_request_not_found",
            "no visible audit records for this request",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let output = run(
        &server.uri(),
        &["admin", "audit", "requests", "inspect", REQUEST_ID],
    );
    assert_eq!(output.status.code(), Some(3));
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["reasonCode"], "audit_request_not_found");
}

#[test]
fn audit_commands_reject_a_literal_token_and_file_output() {
    for args in [
        vec!["audit", "events", "list"],
        vec!["audit", "requests", "inspect", REQUEST_ID],
        vec!["admin", "audit", "events", "list"],
        vec!["admin", "audit", "requests", "inspect", REQUEST_ID],
    ] {
        let output = isolated_cli()
            .args(["--url", "http://127.0.0.1:1", "--token-value", "secret"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("management commands do not accept --token-value"),
            "{args:?}"
        );

        let output = cli("http://127.0.0.1:1")
            .args(["--output", "audit.json"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--output is supported only for"),
            "{args:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_send_discovers_and_reads_both_audit_option_routes() {
    let server = MockServer::start().await;
    let types = agent_access_core::ResourceTypeRegistry::new([]).unwrap();
    let routes = agent_access_core::http_route_specs(&types)
        .into_iter()
        .filter(|route| {
            matches!(
                route.operation.as_str(),
                "audit.options" | "admin.audit.options"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 2);
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": "agent-access.catalog.v2", "identity": {}, "services": [], "routes": routes,
            "send": {"version": "agent-access.send.v1", "catalogRequired": true}
        })))
        .mount(&server)
        .await;
    for (route, operation) in [
        ("/v1/audit/options", "audit.options"),
        ("/v1/admin/audit/options", "admin.audit.options"),
    ] {
        let expected = envelope(
            operation,
            serde_json::json!({
                "services": [{"service": "broker", "actions": ["auth.local.login", "config.status"]}]
            }),
        );
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(&expected))
            .expect(1)
            .mount(&server)
            .await;
        let request = serde_json::json!({
            "version": "agent-access.send.v1", "kind": "http", "method": "GET", "route": route
        });
        let output = run(
            &server.uri(),
            &["send", "--request-json", &request.to_string()],
        );
        assert_eq!(stdout_json(&output), expected);
    }
    server.verify().await;
}
