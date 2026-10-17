//! HTTP 429 exits 7. Broker and upstream rate limits also repeat the broker's
//! message as one stderr line, while stdout keeps the JSON envelope and
//! nothing is retried. Synthetic broker responses stand in for the broker.
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const BROKER_LIMIT: &str = "Rate limit reached for service \"jira\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed.";
const UPSTREAM_LIMIT: &str =
    "jira is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:30Z).";

fn catalog() -> Value {
    json!({
        "version":"agent-access.catalog.v2", "identity":{}, "routes":[],
        "send":{"version":"agent-access.send.v1","catalogRequired":true},
        "services":[{
            "service":"jira", "displayName":"Jira", "surface":"invoke", "scopedMcpReady":true,
            "scopeTypes":[], "actions":[{
                "action":"issue.view", "scopedMcpName":"issue.view", "readOnly":true, "description":"View an issue",
                "requiredScopes":{}, "credentialModes":[],
                "inputSchema":{"type":"object"}, "io":{"type":"json"},
                "responseKind":"response_envelope", "exitPolicy":"invoke_decision",
                "responseFormats":["json", "markdown"]
            }]
        }]
    })
}

fn envelope(action: &str, reason_code: &str, message: &str, result: Option<Value>) -> Value {
    let mut envelope = json!({
        "agentRequestId":"agent-1", "brokerRequestId":"broker-1", "decision":"error",
        "service":"jira", "action":action, "resourceScopes":{},
        "reasonCode":reason_code, "reason":message, "error":{"message":message}
    });
    if let Some(result) = result {
        envelope["result"] = result;
    }
    envelope
}

fn rate_limits() -> [(&'static str, &'static str, Value); 2] {
    [
        (
            "rate_limited",
            BROKER_LIMIT,
            json!({
                "limitScope":"principal", "service":"jira", "limit":20, "windowSeconds":60,
                "retryAfterSeconds":12, "retryAt":"2026-09-25T14:03:12Z",
                "executionState":"not_dispatched", "retrySafe":true
            }),
        ),
        (
            "upstream_rate_limited",
            UPSTREAM_LIMIT,
            json!({
                "limitScope":"upstream", "service":"jira",
                "retryAfterSeconds":30, "retryAt":"2026-09-25T14:03:30Z"
            }),
        ),
    ]
}

async fn mount_throttled(broker: &MockServer, action: &str, body: &Value, calls: u64) {
    Mock::given(method("POST"))
        .and(path(format!("/v1/invoke/jira/{action}")))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "12")
                .set_body_json(body),
        )
        .expect(calls)
        .mount(broker)
        .await;
}

async fn start_broker() -> MockServer {
    let broker = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
        .mount(&broker)
        .await;
    broker
}

fn run(broker: &MockServer, args: &[&str], output: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    // Ambient client configuration must not change the broker exercised here.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.args(["--url", &broker.uri(), "--no-token"]);
    if let Some(output) = output {
        command.arg("--output").arg(output);
    }
    command.args(args).output().unwrap()
}

fn assert_exit_seven_with_envelope(label: &str, output: &Output, envelope: &Value) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(7), "{label}: {stderr}");
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{label}: stdout is not the JSON envelope ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(&stdout, envelope, "{label}");
    stderr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limits_exit_seven_and_repeat_the_broker_message_on_stderr() {
    const INVOKE: [&str; 4] = [
        "invoke",
        "jira.issue.view",
        "--input-json",
        r#"{"issue":"ABC-1"}"#,
    ];
    const SEND: [&str; 3] = [
        "send",
        "--request-json",
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"ABC-1"}}"#,
    ];
    const DOWNLOAD: [&str; 5] = ["jira", "issue", "attachment", "download", "ABC-1"];
    for (reason_code, message, result) in rate_limits() {
        let broker = start_broker().await;
        let view = envelope("issue.view", reason_code, message, Some(result.clone()));
        let download = envelope("attachment.download", reason_code, message, Some(result));
        mount_throttled(&broker, "issue.view", &view, 6).await;
        mount_throttled(&broker, "attachment.download", &download, 2).await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("saved");
        std::fs::write(&destination, "existing content").unwrap();
        let download_args = [&DOWNLOAD[..], &["10001"]].concat();
        let markdown = [&INVOKE[..], &["--output-format", "markdown"]].concat();
        for (label, args, output, expected) in [
            ("invoke", &INVOKE[..], None, &view),
            (
                "invoke --output",
                &INVOKE[..],
                Some(destination.as_path()),
                &view,
            ),
            ("invoke markdown", &markdown[..], None, &view),
            ("send", &SEND[..], None, &view),
            (
                "send --output",
                &SEND[..],
                Some(destination.as_path()),
                &view,
            ),
            (
                "typed jira issue view",
                &["jira", "issue", "view", "ABC-1"][..],
                None,
                &view,
            ),
            (
                "download",
                &download_args[..],
                Some(destination.as_path()),
                &download,
            ),
            (
                "download to stdout",
                &download_args[..],
                Some(Path::new("-")),
                &download,
            ),
        ] {
            let label = format!("{reason_code} {label}");
            let output = run(&broker, args, output);
            let stderr = assert_exit_seven_with_envelope(&label, &output, expected);
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.starts_with("rate limited: "))
                    .collect::<Vec<_>>(),
                [format!("rate limited: {message}")],
                "{label}: {stderr}"
            );
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                b"existing content",
                "{label}"
            );
        }
        // Each command sent exactly one invoke: nothing was retried.
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_limits_exit_seven_without_a_rate_limit_line() {
    let broker = start_broker().await;
    let body = envelope(
        "issue.view",
        "concurrency_limited",
        "concurrency limit exceeded (4)",
        None,
    );
    mount_throttled(&broker, "issue.view", &body, 1).await;
    let output = run(
        &broker,
        &["invoke", "jira.issue.view", "--input-json", "{}"],
        None,
    );
    let stderr = assert_exit_seven_with_envelope("concurrency_limited", &output, &body);
    assert!(!stderr.contains("rate limited"), "{stderr}");
    broker.verify().await;
}
