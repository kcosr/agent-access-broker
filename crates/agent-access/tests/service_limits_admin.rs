//! `agent-access admin principals service-limits` maps to the admin
//! service-limit routes and converts `--window` duration syntax to seconds.
use std::process::Command;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn command(url: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
        cmd.env_remove(key);
    }
    cmd.env("AGENT_ACCESS_CONFIG", "/dev/null");
    cmd.args([
        "--url",
        url,
        "--no-token",
        "admin",
        "principals",
        "service-limits",
    ]);
    cmd
}

fn envelope(result: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "ok": true,
        "decision": "allow",
        "requestId": "cli-service-limits",
        "brokerRequestId": "broker-cli-service-limits",
        "operation": "admin.principals.service_limits",
        "principal": "admin",
        "result": result
    }))
}

fn stdout_json(output: &std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_limits_list_set_and_clear_use_the_admin_routes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/admin/principals/alice/service-limits"))
        .respond_with(envelope(serde_json::json!([
            {"service": "jira", "requests": 100, "windowSeconds": 60, "overridden": false}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    for (window, seconds) in [("1m", 60), ("90s", 90), ("1d", 86_400)] {
        Mock::given(method("PUT"))
            .and(path("/v1/admin/principals/alice/service-limits/jira"))
            .and(body_json(
                serde_json::json!({"requests": 10, "windowSeconds": seconds}),
            ))
            .respond_with(envelope(serde_json::json!({
                "service": "jira", "requests": 10, "windowSeconds": seconds, "overridden": true
            })))
            .expect(1)
            .named(window)
            .mount(&server)
            .await;
    }
    Mock::given(method("DELETE"))
        .and(path("/v1/admin/principals/alice/service-limits/jira"))
        .respond_with(envelope(serde_json::json!({
            "service": "jira", "requests": 100, "windowSeconds": 60, "overridden": false
        })))
        .expect(1)
        .mount(&server)
        .await;

    let listed = stdout_json(
        &command(&server.uri())
            .args(["list", "alice"])
            .output()
            .unwrap(),
    );
    assert_eq!(listed["result"][0]["overridden"], false);
    for window in ["1m", "90s", "1d"] {
        let set = stdout_json(
            &command(&server.uri())
                .args([
                    "set",
                    "alice",
                    "jira",
                    "--requests",
                    "10",
                    "--window",
                    window,
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(set["result"]["overridden"], true, "{window}");
    }
    let cleared = stdout_json(
        &command(&server.uri())
            .args(["clear", "alice", "jira"])
            .output()
            .unwrap(),
    );
    assert_eq!(cleared["result"]["overridden"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_limits_encode_path_segments_and_report_broker_rejections() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/admin/principals/svc%20bot/service-limits"))
        .respond_with(envelope(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/admin/principals/alice/service-limits/jira"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "ok": false,
            "decision": "error",
            "reasonCode": "input_invalid",
            "requestId": "cli-service-limits",
            "brokerRequestId": "broker-cli-service-limits",
            "operation": "admin.principals.service_limits.set",
            "principal": "admin",
            "error": {"message": "requests must be an integer from 1 to 1000000"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    stdout_json(
        &command(&server.uri())
            .args(["list", "svc bot"])
            .output()
            .unwrap(),
    );
    // Range validation belongs to the broker; the CLI forwards the value.
    let rejected = command(&server.uri())
        .args(["set", "alice", "jira", "--requests", "0", "--window", "1m"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let body: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(body["reasonCode"], "input_invalid");
}

#[test]
fn service_limits_set_requires_requests_and_a_duration_window() {
    for args in [
        vec!["set", "alice", "jira", "--window", "1m"],
        vec!["set", "alice", "jira", "--requests", "10"],
        vec!["set", "alice", "jira", "--requests", "10", "--window", "60"],
        vec!["set", "alice", "jira", "--requests", "10", "--window", "1w"],
        vec!["set", "alice", "jira", "--requests", "10", "--window", "0s"],
        vec!["set", "alice", "jira", "--requests", "-1", "--window", "1m"],
        vec!["clear", "alice"],
    ] {
        let output = command("http://127.0.0.1:1").args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}
