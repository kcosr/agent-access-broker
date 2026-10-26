//! Command-import budgets, dispatch ordering and process cleanup through the
//! real router, runtime generations, reloads and shutdown drain, with a
//! fixture command whose `describe` can be held running.
#![cfg(unix)]
use super::imports_command::{CommandFixture, definition, request, versions};
use super::imports_foundation::import_broker;
use super::*;
use agent_access_core::BrokerTokenClass;

/// Records `<operation> <pid>` in `$MARKER`, answers only `describe`, and
/// holds `describe` while `$HOLD` exists.
const HOLDING_COMMAND: &str = r#"#!/bin/sh
echo "$1 $$" >> "$MARKER"
[ "$1" = describe ] || exit 2
while [ -e "$HOLD" ]; do sleep 0.05; done
cat "$MANIFEST"
"#;

fn manifest() -> Value {
    json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "actions": [
            {"name": "ticket.list", "description": "List tickets.", "readOnly": true,
             "inputSchema": {"type": "object", "additionalProperties": false}},
            {"name": "ticket.create", "description": "Create a ticket.",
             "inputSchema": {"type": "object", "additionalProperties": false}}
        ]
    })
}

struct Imports {
    fixture: CommandFixture,
    admin: String,
    agent: String,
}

impl Imports {
    /// `command` approved with `timeout` and `max_concurrent`, held while
    /// [`Self::hold`] is on, and an agent token of alice for `services`.
    fn new(command: &str, services: &[&str], timeout: &str, max_concurrent: u32) -> Self {
        let mut fixture = CommandFixture::with_script(command, &manifest(), HOLDING_COMMAND);
        let hold = fixture.path("hold").display().to_string();
        let entry = fixture.config.command_imports.get_mut(command).unwrap();
        entry.timeout = timeout.into();
        entry.max_concurrent = max_concurrent;
        entry.env.insert("HOLD".into(), hold);
        let admin = fixture.admin_token();
        let agent = fixture.issue(
            "alice",
            BrokerTokenClass::AgentInvoke,
            json!({"allowedServices": services, "allowedExecutionContexts": ["default"]}),
        );
        Self {
            fixture,
            admin,
            agent,
        }
    }

    fn config(&self) -> BrokerConfig {
        self.fixture.config.clone()
    }

    /// `config` with the command entry changed by `change`.
    fn changed(
        config: &BrokerConfig,
        command: &str,
        change: impl FnOnce(&mut agent_access_core::CommandImportConfig),
    ) -> BrokerConfig {
        let mut config = config.clone();
        change(config.command_imports.get_mut(command).unwrap());
        config
    }

    fn hold(&self, on: bool) {
        let path = self.fixture.path("hold");
        if on {
            std::fs::write(path, "").unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }

    /// The process IDs of the `operation` runs started so far.
    fn started(&self, operation: &str) -> Vec<i32> {
        self.fixture
            .runs()
            .iter()
            .filter_map(|run| run.strip_prefix(operation)?.trim().parse().ok())
            .collect()
    }

    /// Creates, discovers, accepts (`ticket.create` as a write) and enables
    /// `service` for `command`, and grants alice both actions.
    async fn import(&self, app: &Router, service: &str, command: &str) {
        let (status, created) = request(
            app,
            &self.admin,
            Method::POST,
            "/v1/admin/imports",
            Some(definition(service, command, &[])),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let (status, discovered) = discover(app.clone(), self.admin.clone(), service).await;
        assert_eq!(status, StatusCode::OK, "{discovered}");
        let discovered = &discovered["result"];
        let mut accept = versions(discovered);
        accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
        accept["selections"] = json!(
            discovered["preview"]["manifest"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| json!({"source": tool["definition"]["source"],
                    "action": tool["definition"]["action"],
                    "readOnly": tool["definition"]["action"] == "ticket.list"}))
                .collect::<Vec<_>>()
        );
        let (status, accepted) = request(
            app,
            &self.admin,
            Method::POST,
            &format!("/v1/admin/imports/{service}/accept"),
            Some(accept),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        let mut enable = versions(&accepted["result"]);
        enable["status"] = json!("enabled");
        let (status, enabled) = request(
            app,
            &self.admin,
            Method::POST,
            &format!("/v1/admin/imports/{service}/status"),
            Some(enable),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        assert_eq!(enabled["result"]["available"], true, "{enabled}");
        let (status, granted) = request(
            app,
            &self.admin,
            Method::POST,
            "/v1/admin/policy/grants",
            Some(
                json!({"subjects": ["user:alice"], "executionContexts": ["default"],
                "service": service, "actions": ["ticket.list", "ticket.create"],
                "resources": {"resourceIds": [], "resourceGroupIds": []},
                "credentialMode": "service"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{granted}");
    }
}

/// Runs discovery of `service` at its current versions.
async fn discover(app: Router, admin: String, service: &str) -> (StatusCode, Value) {
    let (status, current) = request(
        &app,
        &admin,
        Method::GET,
        &format!("/v1/admin/imports/{service}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    request(
        &app,
        &admin,
        Method::POST,
        &format!("/v1/admin/imports/{service}/discover"),
        Some(versions(&current["result"])),
    )
    .await
}

async fn invoke(app: Router, agent: String, service: &str, action: &str) -> (StatusCode, Value) {
    request(
        &app,
        &agent,
        Method::POST,
        &format!("/v1/invoke/{service}/{action}"),
        Some(json!({"inputs": {}})),
    )
    .await
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The process `pid` has been reaped: no process, running or zombie, has
/// its ID.
fn reaped(pid: i32) -> bool {
    // SAFETY: signal 0 only checks whether the process exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn assert_not_applied(status: StatusCode, body: &Value, expected: StatusCode, reason: &str) {
    assert_eq!(status, expected, "{body}");
    assert_eq!(body["reasonCode"], reason, "{body}");
    assert_eq!(body["result"]["mutationStatus"], "not_applied", "{body}");
    assert_eq!(body["result"]["operationDispatched"], false, "{body}");
}

fn far() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

#[tokio::test]
async fn queued_command_calls_take_their_permit_before_the_final_checks() {
    // A call's deadline counts from its admission and includes its wait for
    // a permit. The queued calls that must reach their final checks wait
    // out a reload, which a contended host slows far beyond its usual
    // fraction of a second, so they get the most `timeout` accepts.
    let imports = Imports::new("clock", &["clock"], "10m", 1);
    let config = imports.config();
    let broker = import_broker(&config).await;
    let app = broker.app();
    imports.import(&app, "clock", "clock").await;
    let registry = broker.runtime().command_registry().clone();

    // A reload that changes the command entry fences a call queued for the
    // permit; it fails without starting a process.
    let held = registry.acquire("clock", 1, far()).await.unwrap();
    let queued = tokio::spawn(invoke(
        app.clone(),
        imports.agent.clone(),
        "clock",
        "ticket.create",
    ));
    wait_until("the call queues", || registry.waiting("clock") == 1).await;
    let changed = Imports::changed(&config, "clock", |entry| {
        entry.env.insert("LANG".into(), "C.UTF-8".into());
    });
    broker.reload_config(&changed).await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_not_applied(
        status,
        &body,
        StatusCode::FORBIDDEN,
        "service_action_denied",
    );
    assert_eq!(registry.in_use("clock"), 0);

    // An unchanged reload keeps the fence: the queued call passes the final
    // checks and runs its process, which this command fails, so the write's
    // outcome is unknown.
    let held = registry.acquire("clock", 1, far()).await.unwrap();
    let queued = tokio::spawn(invoke(
        app.clone(),
        imports.agent.clone(),
        "clock",
        "ticket.create",
    ));
    wait_until("the call queues", || registry.waiting("clock") == 1).await;
    broker.reload_config(&changed).await;
    drop(held);
    let (status, body) = queued.await.unwrap();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["reasonCode"], "operation_failed", "{body}");
    assert_eq!(
        body["result"],
        json!({"mutationStatus": "unknown", "retrySafe": false, "operationDispatched": true})
    );
    assert_eq!(imports.started("invoke").len(), 1);

    // A call that gets no permit by its deadline fails upstream_timeout; a
    // read reports no receipt. The only permit stays held until both calls
    // have returned, so neither can start however slow the host is.
    let short = Imports::changed(&changed, "clock", |entry| entry.timeout = "1s".into());
    broker.reload_config(&short).await;
    let held = registry.acquire("clock", 1, far()).await.unwrap();
    let started = std::time::Instant::now();
    let (status, body) = invoke(app.clone(), imports.agent.clone(), "clock", "ticket.create").await;
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_not_applied(
        status,
        &body,
        StatusCode::GATEWAY_TIMEOUT,
        "upstream_timeout",
    );
    let (status, body) = invoke(app.clone(), imports.agent.clone(), "clock", "ticket.list").await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["reasonCode"], "upstream_timeout", "{body}");
    assert!(body["result"]["mutationStatus"].is_null(), "{body}");
    drop(held);
    assert_eq!(registry.waiting("clock"), 0);

    // Once shutdown closed the budgets, a call fails before starting.
    assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
    let (status, body) = invoke(app.clone(), imports.agent.clone(), "clock", "ticket.create").await;
    assert_not_applied(
        status,
        &body,
        StatusCode::REQUEST_TIMEOUT,
        "operation_cancelled",
    );

    // Only the call that passed its final checks started a process.
    assert_eq!(imports.started("invoke").len(), 1);
    assert_eq!(imports.started("describe").len(), 1);
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn imports_operations_and_generations_of_one_command_share_its_budget() {
    let imports = Imports::new("slow", &["alpha", "beta"], "30s", 1);
    let config = imports.config();
    let broker = import_broker(&config).await;
    let app = broker.app();
    imports.import(&app, "alpha", "slow").await;
    imports.import(&app, "beta", "slow").await;
    let registry = broker.runtime().command_registry().clone();
    assert_eq!(imports.started("describe").len(), 2);

    // A refresh of one import holds the command's only permit.
    imports.hold(true);
    let refresh = tokio::spawn(discover(app.clone(), imports.admin.clone(), "alpha"));
    wait_until("the refresh starts describe", || {
        imports.started("describe").len() == 3
    })
    .await;
    assert_eq!(registry.in_use("slow"), 1);

    // The next generation shares the budget. Its calls of the other import,
    // a describe and an invoke, wait for it and fail at their deadline
    // without starting a process.
    let short = Imports::changed(&config, "slow", |entry| entry.timeout = "1s".into());
    broker.reload_config(&short).await;
    let (status, body) = discover(app.clone(), imports.admin.clone(), "beta").await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reasonCode"], "upstream_timeout", "{body}");
    let (status, body) = invoke(app.clone(), imports.agent.clone(), "beta", "ticket.create").await;
    assert_not_applied(
        status,
        &body,
        StatusCode::GATEWAY_TIMEOUT,
        "upstream_timeout",
    );
    assert_eq!(imports.started("describe").len(), 3);
    assert!(imports.started("invoke").is_empty());
    assert_eq!(registry.in_use("slow"), 1);

    // When the refresh's describe finishes, its permit returns and the other
    // import's describe runs. The refresh was admitted before the reload, so
    // its publication is rejected as stale.
    imports.hold(false);
    let (status, body) = refresh.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reasonCode"], "version_conflict", "{body}");
    assert_eq!(registry.in_use("slow"), 0);
    let (status, body) = discover(app.clone(), imports.admin.clone(), "beta").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(imports.started("describe").len(), 4);
    assert_eq!(registry.live_processes(), 0);
    drop(app);
    let report = broker.stop().await;
    assert!(report.is_clean(), "{report:?}");
}

#[tokio::test]
async fn deadlines_and_shutdown_kill_command_processes_and_a_new_broker_has_full_budgets() {
    let imports = Imports::new("clock", &["clock"], "1s", 1);
    let config = imports.config();
    let broker = import_broker(&config).await;
    let app = broker.app();
    imports.import(&app, "clock", "clock").await;
    let registry = broker.runtime().command_registry().clone();

    // The command deadline kills and reaps a describe that does not finish.
    imports.hold(true);
    let (status, body) = discover(app.clone(), imports.admin.clone(), "clock").await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reasonCode"], "upstream_timeout", "{body}");
    let timed_out = *imports.started("describe").last().unwrap();
    assert!(reaped(timed_out));
    assert_eq!(registry.in_use("clock"), 0);
    assert_eq!(registry.live_processes(), 0);

    // Shutdown kills a running describe, reaps it and returns its permit
    // before it reports clean.
    let long = Imports::changed(&config, "clock", |entry| entry.timeout = "30s".into());
    broker.reload_config(&long).await;
    let running = tokio::spawn(discover(app.clone(), imports.admin.clone(), "clock"));
    wait_until("describe starts", || imports.started("describe").len() == 3).await;
    let pid = *imports.started("describe").last().unwrap();
    assert!(!reaped(pid));
    assert_eq!(registry.live_processes(), 1);
    drop(app);
    let report = broker.stop().await;
    assert_eq!(report.unfinished_command_processes(), 0);
    assert!(report.is_clean(), "{report:?}");
    assert!(reaped(pid));
    assert!(registry.is_closed());
    assert_eq!(registry.in_use("clock"), 0);
    assert_eq!(registry.live_processes(), 0);
    // The killed describe ends its discovery. This harness drives the router
    // from a detached task rather than a drained listener connection, so its
    // response can race the audit drain; only its failure is checked.
    let (status, body) = running.await.unwrap();
    assert_ne!(status, StatusCode::OK, "{body}");

    // Another broker on the same runtime and state starts with full budgets.
    imports.hold(false);
    let restarted = import_broker(&long).await;
    let fresh = restarted.runtime().command_registry().clone();
    assert!(!fresh.ptr_eq(&registry));
    let app = restarted.app();
    let (status, body) = discover(app.clone(), imports.admin.clone(), "clock").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(imports.started("describe").len(), 4);
    assert_eq!(fresh.in_use("clock"), 0);
    drop(app);
    let report = restarted.stop().await;
    assert!(report.is_clean(), "{report:?}");
}
