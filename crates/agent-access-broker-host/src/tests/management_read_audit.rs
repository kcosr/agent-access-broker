//! Which management reads are audited, end to end: successful read-only
//! operations write no audit record (and so keep working while audit writes
//! fail), while their denials and failures, and the reads that reveal
//! secrets, export policy, or verify credentials, stay audited.
use super::audit_query::{Backend, audit_fixture};
use super::*;
use crate::handlers::management::common::{
    READ_ONLY_POST_CATALOG_OPERATIONS, handler_operation, is_unaudited_read,
};
use agent_access_core::{ResponseKind, RouteAccess, http_route_specs};

/// What the portal requests on every page load.
const PORTAL_LOAD_READS: [&str; 5] = [
    "/v1/auth/session",
    "/v1/tokens",
    "/v1/tokens/options",
    "/v1/credentials",
    "/v1/credentials/targets",
];

const GRANT_PROPOSAL: &str = r#"{"subjects":["user:alice"],"executionContexts":["default"],
    "service":"fake","actions":["echo"],
    "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]},"credentialMode":"service"}"#;

fn broker_request_ids(records: &[Value]) -> BTreeSet<String> {
    records
        .iter()
        .map(|record| record["brokerRequestId"].as_str().unwrap().to_string())
        .collect()
}

/// A browser-session request, with the CSRF header the portal sends, that
/// does not borrow the fixture so it can run in a spawned task.
pub(super) async fn cookie_get(
    app: Router,
    cookie: String,
    csrf: String,
    uri: &str,
) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "read-audit-cookie")
                .header("Cookie", cookie)
                .header("X-Agent-Access-CSRF", csrf)
                .header("Host", "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), response_json(response).await)
}

async fn token_get(app: Router, token: &str, uri: &str) -> (StatusCode, Value) {
    let response = authed_json_request(
        app,
        Method::GET,
        uri,
        "read-audit-token",
        "X-Agent-Token",
        format!("Bearer {token}"),
        None,
    )
    .await;
    (response.status(), response_json(response).await)
}

#[tokio::test]
async fn browser_management_reads_forbid_caching() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    fixture
        .state
        .current()
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: "alice".to_string(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "admin".to_string(),
        })
        .unwrap();

    for uri in [
        "/v1/admin/principals",
        "/v1/admin/groups",
        "/v1/tokens",
        "/v1/credentials",
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .extension(ConnectInfo(
                        "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "management-cache-read")
                    .header("Cookie", &fixture.cookie)
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{uri}"
        );
        let body = response_json(response).await;
        assert_eq!(body["ok"], true, "{uri}: {body}");
        assert_eq!(body["principal"], "alice", "{uri}: {body}");
    }
}

#[tokio::test]
async fn portal_load_reads_write_no_audit_records() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let before = broker_request_ids(&read_audit_records(&fixture.audit_path));
    assert!(!before.is_empty(), "the fixture login is audited");
    for uri in PORTAL_LOAD_READS {
        let (status, body) = cookie_get(
            fixture.app.clone(),
            fixture.cookie.clone(),
            fixture.csrf.clone(),
            uri,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body["ok"], true, "{uri}: {body}");
    }
    assert_eq!(
        broker_request_ids(&read_audit_records(&fixture.audit_path)),
        before
    );

    // An ordinary logged-out probe is also a successful read.
    let (status, body) = cookie_get(
        fixture.app.clone(),
        String::new(),
        String::new(),
        "/v1/auth/session",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["authenticated"], false);
    assert_eq!(
        broker_request_ids(&read_audit_records(&fixture.audit_path)),
        before
    );
}

async fn session_probe(app: Router, cookies: &[axum::http::HeaderValue]) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("/v1/auth/session")
        .extension(ConnectInfo(
            "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
        ))
        .header("Host", "localhost")
        .body(Body::empty())
        .unwrap();
    for cookie in cookies {
        request.headers_mut().append("Cookie", cookie.clone());
    }
    let response = app.oneshot(request).await.unwrap();
    (response.status(), response_json(response).await)
}

#[tokio::test]
async fn session_probes_distinguish_absent_invalid_and_expired_cookies() {
    use axum::http::HeaderValue;
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let before = broker_request_ids(&read_audit_records(&fixture.audit_path));
    for cookies in [
        vec![],
        vec![HeaderValue::from_static("theme=dark")],
        vec![HeaderValue::from_static("unrelated; =nameless")],
        vec![HeaderValue::from_bytes(b"unrelated=\x80").unwrap()],
        vec![HeaderValue::from_str(&fixture.cookie).unwrap()],
    ] {
        let (status, body) = session_probe(fixture.app.clone(), &cookies).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            broker_request_ids(&read_audit_records(&fixture.audit_path)),
            before
        );
    }

    for cookies in [
        vec![HeaderValue::from_str(&format!("unrelated; =nameless; {}", fixture.cookie)).unwrap()],
        vec![HeaderValue::from_str(&format!("{}; unrelated", fixture.cookie)).unwrap()],
        vec![
            HeaderValue::from_bytes(&[fixture.cookie.as_bytes(), b"; unrelated=\x80"].concat())
                .unwrap(),
        ],
        vec![
            HeaderValue::from_bytes(b"unrelated=\x80").unwrap(),
            HeaderValue::from_str(&fixture.cookie).unwrap(),
        ],
    ] {
        let (status, body) = session_probe(fixture.app.clone(), &cookies).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["authenticated"], true);
        assert_eq!(
            broker_request_ids(&read_audit_records(&fixture.audit_path)),
            before,
            "unrelated malformed cookies do not invalidate or audit a valid session"
        );
    }

    let assert_audited = |body: &Value| {
        let records = read_audit_records(&fixture.audit_path);
        let record = records
            .iter()
            .find(|record| record["brokerRequestId"] == body["brokerRequestId"])
            .expect("a presented invalid session remains audited");
        assert_eq!(record["action"], "auth.session");
        assert_eq!(record["service"], "broker");
        assert_eq!(record["principal"], "anonymous");
    };
    for cookies in [
        vec![HeaderValue::from_static("aab_session=invalid")],
        vec![HeaderValue::from_static("aab_session=")],
        vec![HeaderValue::from_static("aab_session")],
        vec![HeaderValue::from_static("aab_session =invalid")],
        vec![HeaderValue::from_static("aab_session\t=invalid")],
        vec![HeaderValue::from_bytes(b"aab_session=\x80").unwrap()],
        vec![HeaderValue::from_str(&format!("{}; {}", fixture.cookie, fixture.cookie)).unwrap()],
        vec![
            HeaderValue::from_str(&fixture.cookie).unwrap(),
            HeaderValue::from_static("aab_session=invalid"),
        ],
    ] {
        let (status, body) = session_probe(fixture.app.clone(), &cookies).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["authenticated"], false);
        assert_audited(&body);
    }

    // Expire the issued session deterministically, without sleeping.
    rusqlite::Connection::open(&fixture.store_path)
        .unwrap()
        .execute(
            "UPDATE broker_tokens SET expires_at = '2000-01-01T00:00:00Z'
             WHERE token_id IN (SELECT token_id FROM browser_sessions)",
            [],
        )
        .unwrap();
    let (status, body) = session_probe(
        fixture.app.clone(),
        &[HeaderValue::from_str(&fixture.cookie).unwrap()],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["authenticated"], false);
    assert_audited(&body);
}

#[tokio::test]
async fn logged_out_session_probes_still_enforce_and_audit_admission_limits() {
    let fixture = browser_rate_fixture(LimitsConfig {
        auth_requests_per_source_per_minute: 1,
        ..LimitsConfig::default()
    })
    .await;
    // The fixture's login already consumed the source's authentication budget.
    let (status, body) = session_probe(fixture.app.clone(), &[]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reasonCode"], "rate_limited");
    let records = read_audit_records(&fixture.audit_path);
    let record = records
        .iter()
        .find(|record| record["brokerRequestId"] == body["brokerRequestId"])
        .expect("a rejected logged-out probe remains audited");
    assert_eq!(record["service"], "broker");
    assert_eq!(record["action"], "auth.session");
    assert_eq!(record["principal"], "anonymous");
    assert_eq!(record["decision"], "deny");
}

#[tokio::test]
async fn successful_reads_work_while_audit_writes_fail() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    // Another connection holds the audit database's write lock, so every
    // audit append fails after the writer's busy timeout.
    let blocker = rusqlite::Connection::open(&fixture.audit_path).unwrap();
    blocker.busy_timeout(Duration::from_secs(10)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    // A failed read is still audited, so it fails closed.
    let audited = tokio::spawn(cookie_get(
        fixture.app.clone(),
        fixture.cookie.clone(),
        fixture.csrf.clone(),
        "/v1/tokens?includeRevoked=maybe",
    ));
    let reads = || async {
        let (status, body) = session_probe(fixture.app.clone(), &[]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["authenticated"], false);
        for uri in PORTAL_LOAD_READS {
            let (status, body) = cookie_get(
                fixture.app.clone(),
                fixture.cookie.clone(),
                fixture.csrf.clone(),
                uri,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        }
        for uri in [
            "/v1/admin/principals",
            "/v1/admin/config/status",
            "/v1/admin/policy/grants",
        ] {
            let (status, body) = token_get(fixture.app.clone(), &fixture.admin_token, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        }
    };
    let started = Instant::now();
    reads().await;
    assert!(started.elapsed() < Duration::from_secs(4));

    let (status, body) = audited.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reasonCode"], "audit_unavailable");
    // Reads keep working once the audit failure is known.
    reads().await;
    blocker.execute_batch("ROLLBACK").unwrap();
}

#[tokio::test]
async fn admin_reads_and_policy_dry_runs_write_no_audit_records() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    let before = fixture.records().len();
    let invalid_proposal = GRANT_PROPOSAL.replace(r#""echo""#, r#""no-such-action""#);
    let effective_access = r#"{"service":"fake","actions":["echo"],"executionContexts":["default"],
        "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}}"#;
    let token_boundary = r#"{"allowedExecutionContexts":["default"]}"#;
    for (token, method, uri, body) in [
        (&fixture.admin, Method::GET, "/v1/admin/store/status", None),
        (&fixture.admin, Method::GET, "/v1/admin/config/status", None),
        (&fixture.admin, Method::GET, "/v1/admin/principals", None),
        (
            &fixture.admin,
            Method::GET,
            "/v1/admin/principals/alice",
            None,
        ),
        (&fixture.admin, Method::GET, "/v1/admin/tokens", None),
        (&fixture.admin, Method::GET, "/v1/admin/policy/status", None),
        (
            &fixture.admin,
            Method::GET,
            "/v1/admin/policy/catalog",
            None,
        ),
        (
            &fixture.admin,
            Method::GET,
            "/v1/admin/policy/resources/project-test/used-by",
            None,
        ),
        (&fixture.bob, Method::GET, "/v1/admin/policy/grants", None),
        (
            &fixture.admin,
            Method::POST,
            "/v1/admin/policy/grants/validate",
            Some(GRANT_PROPOSAL),
        ),
        (
            &fixture.admin,
            Method::POST,
            "/v1/admin/policy/effective-access",
            Some(effective_access),
        ),
        (
            &fixture.bob,
            Method::POST,
            "/v1/admin/policy/effective-access",
            Some(effective_access),
        ),
        (
            &fixture.admin,
            Method::POST,
            "/v1/admin/principals/alice/agent-token-effective-access",
            Some(token_boundary),
        ),
        (
            &fixture.alice,
            Method::POST,
            "/v1/tokens/effective-access",
            Some(token_boundary),
        ),
    ] {
        let (status, response) = fixture
            .request(method, token, uri, body, "read-audit-admin")
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {response}");
    }
    // A dry run that finds the proposal invalid is still a successful read.
    let (status, response) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/policy/grants/validate",
            Some(&invalid_proposal),
            "read-audit-invalid-proposal",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["valid"], false, "{response}");
    assert_eq!(fixture.records().len(), before);
}

#[tokio::test]
async fn denied_and_failed_reads_stay_audited() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    for (token, method, uri, body, status) in [
        // A user_manage token calling admin and policy reads.
        (
            &fixture.alice,
            Method::GET,
            "/v1/admin/principals",
            None,
            403,
        ),
        (
            &fixture.carol,
            Method::GET,
            "/v1/admin/policy/grants",
            None,
            403,
        ),
        // An agent_invoke token calling self-service reads.
        (&fixture.alice_agent, Method::GET, "/v1/tokens", None, 403),
        (
            &fixture.alice_agent,
            Method::GET,
            "/v1/credentials",
            None,
            403,
        ),
        // Invalid input and not found.
        (
            &fixture.alice,
            Method::GET,
            "/v1/tokens?includeRevoked=maybe",
            None,
            400,
        ),
        (
            &fixture.admin,
            Method::GET,
            "/v1/admin/principals/nobody",
            None,
            404,
        ),
        (
            &fixture.admin,
            Method::POST,
            "/v1/admin/policy/grants/validate",
            Some("{"),
            400,
        ),
        // A service manager previewing a service they do not manage.
        (
            &fixture.bob,
            Method::POST,
            "/v1/admin/policy/effective-access",
            Some(
                r#"{"service":"gitlab","actions":["project.view"],"executionContexts":["default"],
                    "resources":{"resourceIds":[],"resourceGroupIds":[]}}"#,
            ),
            403,
        ),
    ] {
        let (actual, response) = fixture
            .request(method, token, uri, body, "read-audit-denied")
            .await;
        assert_eq!(actual.as_u16(), status, "{uri}: {response}");
        let record = fixture
            .records()
            .into_iter()
            .find(|record| record["brokerRequestId"] == response["brokerRequestId"])
            .unwrap_or_else(|| panic!("{uri} is audited: {response}"));
        assert_eq!(record["action"], response["operation"], "{uri}");
        assert_eq!(record["reasonCode"], response["reasonCode"], "{uri}");
        assert_ne!(record["decision"], "allow", "{uri}");
    }
}

/// A concrete path for a catalog route: fixture principals, services,
/// resources, and the IDs in `ids` where they exist, and unknown IDs
/// elsewhere.
pub(super) fn concrete_route(route: &str, ids: &BTreeMap<&str, String>) -> String {
    route
        .split('/')
        .map(|segment| match segment {
            "{principal}" => "alice",
            "{service}" => "fake",
            "{name}" => "default",
            "{id}" => "project-test",
            "{attribute}" => "webhookUrl",
            other => match other
                .strip_prefix('{')
                .and_then(|name| name.strip_suffix('}'))
            {
                Some(name) => ids.get(name).map_or("missing", String::as_str),
                None => other,
            },
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn read_post_body(catalog_operation: &str) -> Option<&'static str> {
    match catalog_operation {
        "tokens.effective_access" | "admin.tokens.effective_access_principal_agent" => {
            Some(r#"{"allowedExecutionContexts":["default"]}"#)
        }
        "admin.policy.effective_access" => Some(
            r#"{"service":"fake","actions":["echo"],"executionContexts":["default"],
                "resources":{"resourceIds":["project-test"],"resourceGroupIds":[]}}"#,
        ),
        "admin.policy.grants.validate" => Some(GRANT_PROPOSAL),
        _ => None,
    }
}

/// Every read route in the catalog, called for real: the response names
/// the classified handler operation, a success of an unaudited read leaves
/// no record, and every other outcome (audited reads, denials, failures)
/// is recorded under the response's `brokerRequestId`.
#[tokio::test]
async fn every_catalog_read_route_follows_its_audit_classification() {
    let fixture = audit_fixture(Backend::Sqlite).await;
    // Real IDs, so detail reads succeed: alice's agent token, a grant, and
    // one of alice's own audited requests.
    let (_, tokens) = fixture
        .request(
            Method::GET,
            &fixture.alice,
            "/v1/tokens",
            None,
            "read-setup",
        )
        .await;
    let token_id = tokens["result"][0]["tokenId"].as_str().unwrap().to_string();
    let proposal = GRANT_PROPOSAL.replacen('{', r#"{"grantId":"read-sweep","#, 1);
    let (status, created) = fixture
        .request(
            Method::POST,
            &fixture.admin,
            "/v1/admin/policy/grants",
            Some(&proposal),
            "read-setup",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (_, failed) = fixture
        .request(
            Method::GET,
            &fixture.alice,
            "/v1/tokens?includeRevoked=maybe",
            None,
            "read-setup",
        )
        .await;
    let ids = BTreeMap::from([
        ("token_id", token_id),
        ("grant_ref", "read-sweep".to_string()),
        (
            "brokerRequestId",
            failed["brokerRequestId"].as_str().unwrap().to_string(),
        ),
    ]);
    let routes = http_route_specs(fixture.state.current().runtime.resource_types());
    let mut unaudited_successes = BTreeSet::new();
    let mut audited_successes = BTreeSet::new();
    for route in routes.iter().filter(|route| {
        route.response_kind == ResponseKind::ManagementEnvelope
            && (route.method == "GET"
                || READ_ONLY_POST_CATALOG_OPERATIONS.contains(&route.operation.as_str()))
    }) {
        let operation = handler_operation(&route.operation);
        let token = match route.access {
            RouteAccess::PolicyRead
            | RouteAccess::PolicyWrite
            | RouteAccess::AdminRead
            | RouteAccess::AdminWrite => &fixture.admin,
            _ => &fixture.alice,
        };
        let uri = concrete_route(&route.route, &ids);
        let (status, response) = fixture
            .request(
                Method::from_bytes(route.method.as_bytes()).unwrap(),
                token,
                &uri,
                read_post_body(&route.operation),
                "read-audit-sweep",
            )
            .await;
        assert_eq!(response["operation"], operation, "{uri}: {response}");
        let records = fixture
            .records()
            .into_iter()
            .filter(|record| record["brokerRequestId"] == response["brokerRequestId"])
            .count();
        if status == StatusCode::OK && is_unaudited_read(operation) {
            assert_eq!(records, 0, "{uri} succeeded without audit: {response}");
            unaudited_successes.insert(operation.to_string());
        } else {
            assert!(records > 0, "{uri} ({status}) is audited: {response}");
            if status == StatusCode::OK {
                audited_successes.insert(operation.to_string());
            }
        }
    }
    // The sweep is not vacuous: the fixture serves these reads successfully.
    for operation in [
        "tokens.list",
        "tokens.inspect",
        "tokens.options",
        "tokens.effective_access",
        "credentials.list",
        "credentials.targets",
        "audit.events.list",
        "audit.requests.inspect",
        "config.status",
        "admin.store.status",
        "admin.principals.list",
        "admin.principals.inspect",
        "admin.principals.services",
        "admin.groups.list",
        "admin.rights.list",
        "admin.tokens.list",
        "admin.tokens.inspect",
        "admin.tokens.list_principal_agent",
        "admin.tokens.inspect_principal_agent",
        "admin.tokens.options_principal_agent",
        "admin.tokens.effective_access_principal_agent",
        "admin.credentials.list",
        "admin.policy.status",
        "admin.policy.catalog",
        "admin.policy.grants.list",
        "admin.policy.grants.inspect",
        "admin.policy.grants.validate",
        "admin.policy.service_managers.list",
        "admin.policy.effective_access",
        "admin.policy.resources.list",
        "admin.policy.resources.get",
        "admin.policy.resources.used_by",
        "admin.policy.resource_groups.list",
        "admin.audit.events.list",
        "admin.audit.requests.inspect",
    ] {
        assert!(
            unaudited_successes.contains(operation),
            "{operation} did not succeed: {unaudited_successes:?}"
        );
    }
    assert!(
        audited_successes.contains("admin.policy.grants.export"),
        "{audited_successes:?}"
    );
}
