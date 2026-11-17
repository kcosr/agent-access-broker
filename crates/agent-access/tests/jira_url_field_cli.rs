//! Typed URL-field commands preserve the caller's explicit replacement guard.
//! Synthetic Broker responses isolate CLI lowering from provider verification.
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn command(directory: &Path, broker: &MockServer) -> Command {
    let config = directory.join("client.toml");
    std::fs::write(&config, "").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command
        .arg("--config")
        .arg(config)
        .args(["--url", &broker.uri(), "--no-token"]);
    command
}

fn catalog() -> Value {
    json!({
        "version":"agent-access.catalog.v2", "identity":{}, "routes":[],
        "send":{"version":"agent-access.send.v1","catalogRequired":true},
        "services":[{
            "service":"jira", "displayName":"Jira", "surface":"invoke", "scopedMcpReady":true,
            "scopeTypes":[], "actions":[{
                "action":"issue.url_field.set", "scopedMcpName":"issue.url_field.set",
                "readOnly":false, "description":"Set one URL custom field",
                "requiredScopeTypes":[], "credentialModes":[],
                "inputSchema":{"type":"object"}, "io":{"type":"json"},
                "responseKind":"response_envelope", "exitPolicy":"invoke_decision",
                "responseFormats":["json"]
            }]
        }]
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_url_field_set_sends_null_or_exact_expected_value_and_identity_guard() {
    const VALUE: &str = "https://reports.example.com/#/issues/123?view=runs&run=latest";
    const PREVIOUS: &str = "https://reports.example.com/previous/PROJ-123";
    for (by_url, saved) in [(false, false), (true, true)] {
        let broker = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
            .expect(if saved { 1 } else { 0 })
            .mount(&broker)
            .await;
        let response = json!({
            "agentRequestId":"agent-test", "brokerRequestId":"broker-test",
            "decision":"allow", "result":{
                "operation":"issue.url_field.set",
                "issue":{"id":"10001","key":"PROJ-123","project":"PROJ","webUrl":"https://example.atlassian.net/browse/PROJ-123"},
                "field":{"id":"customfield_12345","name":"Report URL","type":"url","value":VALUE},
                "changed":true
            }
        });
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.url_field.set"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.json");
        let mut command = command(directory.path(), &broker);
        command.args(["jira", "issue", "url-field", "set"]);
        let mut expected = json!({
            "fieldId":"customfield_12345", "value":VALUE, "expectedValue":null
        });
        if by_url {
            command.args([
                "--issue-url",
                "https://example.atlassian.net/browse/PROJ-123",
                "--expected-value",
                PREVIOUS,
                "--expected-issue-id",
                "10001",
            ]);
            expected["url"] = json!("https://example.atlassian.net/browse/PROJ-123");
            expected["expectedValue"] = json!(PREVIOUS);
            expected["expectedIssueId"] = json!("10001");
        } else {
            command.arg("PROJ-123");
            expected["issue"] = json!("PROJ-123");
        }
        command.args(["--field-id", "customfield_12345", "--value", VALUE]);
        if saved {
            command.arg("--output").arg(&destination);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let requests = broker.received_requests().await.unwrap();
        let invokes: Vec<_> = requests
            .iter()
            .filter(|request| request.method == "POST")
            .collect();
        assert_eq!(invokes.len(), 1);
        let body: Value = serde_json::from_slice(&invokes[0].body).unwrap();
        assert_eq!(body["inputs"], expected);
        assert!(!String::from_utf8_lossy(&invokes[0].body).contains("result.json"));
        if saved {
            let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(receipt["operationStatus"], "succeeded");
            assert_eq!(receipt["output"]["status"], "succeeded");
            let stored: Value =
                serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
            assert_eq!(stored, response);
        } else {
            let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(printed, response);
        }
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_url_field_set_rejects_missing_or_competing_issue_locators_before_network() {
    let broker = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    for locators in [
        vec![],
        vec![
            "PROJ-123",
            "--issue-url",
            "https://example.atlassian.net/browse/PROJ-123",
        ],
    ] {
        let output = command(directory.path(), &broker)
            .args([
                "jira",
                "issue",
                "url-field",
                "set",
                "--field-id",
                "customfield_12345",
                "--value",
                "https://reports.example.com/issues/PROJ-123",
            ])
            .args(locators)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("requires exactly one issue argument or --issue-url")
        );
    }
    assert!(broker.received_requests().await.unwrap().is_empty());
}
