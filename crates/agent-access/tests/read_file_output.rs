use serde_json::{Value, json};
use std::process::Command;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn catalog() -> Value {
    json!({
        "version":"agent-access.catalog.v2", "identity":{}, "routes":[],
        "send":{"version":"agent-access.send.v1","catalogRequired":true},
        "services":[{
            "service":"jira", "displayName":"Jira", "surface":"invoke", "scopedMcpReady":true,
            "scopeTypes":[], "actions":[{
                "action":"issue.view", "scopedMcpName":"issue.view", "readOnly":true, "description":"View an issue",
                "requiredScopeTypes":[], "credentialModes":[],
                "inputSchema":{"type":"object"}, "io":{"type":"json"},
                "responseKind":"response_envelope", "exitPolicy":"invoke_decision",
                "responseFormats":["json", "markdown"]
            }]
        }]
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_read_output_preserves_destination_and_exits_five() {
    for (catalog_body, markdown) in [
        (json!({}), false),
        (
            {
                let mut value = catalog();
                value["version"] = json!("unsupported");
                value
            },
            false,
        ),
        (catalog(), true),
    ] {
        let broker = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog_body))
            .expect(1)
            .mount(&broker)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agentRequestId":"test", "brokerRequestId":"test", "decision":"allow",
                "result":{"format":"markdown", "value":42}
            })))
            .expect(if markdown { 1 } else { 0 })
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.json");
        std::fs::write(&destination, b"existing content").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        command.args([
            "--url",
            &broker.uri(),
            "--no-token",
            "invoke",
            "jira.issue.view",
            "--input-json",
            "{\"issue\":\"ABC-1\"}",
        ]);
        command.arg("--output").arg(&destination);
        if markdown {
            command.args(["--output-format", "markdown"]);
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(5), "{stderr}");
        assert!(stderr.contains("malformed broker response"), "{stderr}");
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing content");
        broker.verify().await;
    }
}

#[cfg(unix)]
#[test]
fn send_rejects_non_utf8_output_path_before_network_access() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join(OsString::from_vec(vec![0xff]));
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "send",
            "--request-json",
            r#"{"kind":"invoke","service":"fake","action":"echo","input":{}}"#,
            "--output",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("must be valid UTF-8"), "{stderr}");
    assert!(!destination.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_file_output_reports_success_and_local_failure_without_repeating_operation() {
    for surface in ["typed", "invoke", "send"] {
        for (save_fails, unverified) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let broker = MockServer::start().await;
            let mut catalog = catalog();
            catalog["services"][0]["actions"][0]["action"] = json!("issue.update");
            catalog["services"][0]["actions"][0]["readOnly"] = json!(false);
            catalog["services"][0]["actions"][0]["sensitiveOutputPointers"] =
                json!(["/result/secret"]);
            Mock::given(method("GET"))
                .and(path("/v1/spec/catalog"))
                .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
                .mount(&broker)
                .await;
            let mut response = json!({"decision":"allow", "agentRequestId":"agent-request", "brokerRequestId":"broker-request", "result":{"updated":true,"secret":"not-in-receipt"}});
            if unverified {
                response["result"]["mutationStatus"] = json!("applied_unverified");
                response["result"]["retrySafe"] = json!(false);
                response["result"]["verificationStage"] = json!("mutation_response");
                response["result"]["safeLocators"] = json!({"job":"ci/build"});
            }
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join("result.json");
            let race_destination = destination.clone();
            let broker_response = response.clone();
            Mock::given(method("POST"))
                .and(path("/v1/invoke/jira/issue.update"))
                .respond_with(move |_: &wiremock::Request| {
                    if save_fails {
                        std::fs::create_dir(&race_destination).unwrap();
                    }
                    ResponseTemplate::new(200).set_body_json(broker_response.clone())
                })
                .expect(1)
                .mount(&broker)
                .await;
            let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
            command.args(["--url", &broker.uri(), "--no-token"]);
            match surface {
                "typed" => {
                    command.args(["jira", "issue", "update", "ABC-1", "--summary", "updated"]);
                }
                "invoke" => {
                    command.args([
                        "invoke",
                        "jira.issue.update",
                        "--input-json",
                        r#"{"issue":"ABC-1","summary":"updated"}"#,
                    ]);
                }
                "send" => {
                    command.args(["send", "--request-json", &json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.update","inputs":{"issue":"ABC-1","summary":"updated"}}).to_string()]);
                }
                _ => unreachable!(),
            }
            command.arg("--output").arg(&destination);
            let output = command.output().unwrap();
            let printed = if save_fails {
                &output.stderr
            } else {
                &output.stdout
            };
            assert_eq!(
                output.status.code(),
                Some(if save_fails { 1 } else { 0 }),
                "{surface}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let receipt: Value = serde_json::from_slice(printed).unwrap();
            assert_eq!(
                receipt["operationStatus"],
                if unverified {
                    "applied_unverified"
                } else {
                    "succeeded"
                }
            );
            if unverified {
                assert_eq!(receipt["mutationStatus"], "applied_unverified");
                assert_eq!(receipt["retrySafe"], false);
                assert_eq!(receipt["safeLocators"]["job"], "ci/build");
            }
            assert_eq!(
                receipt["output"]["status"],
                if save_fails { "failed" } else { "succeeded" }
            );
            assert_eq!(receipt["agentRequestId"], "agent-request");
            assert_eq!(receipt["brokerRequestId"], "broker-request");
            assert!(receipt.get("result").is_none());
            assert!(!String::from_utf8_lossy(printed).contains("not-in-receipt"));
            if save_fails {
                assert_eq!(receipt["output"]["destinationReplaced"], false);
                assert!(
                    receipt["message"]
                        .as_str()
                        .unwrap()
                        .contains("Do not repeat")
                );
                assert!(destination.is_dir());
            } else {
                assert_eq!(receipt["output"]["sensitive"], true);
                assert_eq!(
                    serde_json::from_slice::<Value>(&std::fs::read(destination).unwrap()).unwrap(),
                    response
                );
            }
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                1,
                "reservation must be removed"
            );
            broker.verify().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_denial_and_uncertain_response_do_not_claim_success_or_touch_output() {
    for (status, body, expected_exit) in [
        (
            403,
            json!({"decision":"deny", "reasonCode":"policy_denied", "agentRequestId":"agent", "brokerRequestId":"broker"}),
            2,
        ),
        (200, json!({"unexpected":"shape"}), 5),
    ] {
        let broker = MockServer::start().await;
        let mut catalog = catalog();
        catalog["services"][0]["actions"][0]["action"] = json!("issue.update");
        catalog["services"][0]["actions"][0]["readOnly"] = json!(false);
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
            .mount(&broker)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.update"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result.json");
        std::fs::write(&destination, "original").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &broker.uri(),
                "--no-token",
                "invoke",
                "jira.issue.update",
                "--input-json",
                "{}",
                "--output",
            ])
            .arg(&destination)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "original");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("operationStatus"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("operationStatus"));
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "failed operation left a reservation"
        );
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multipart_upload_responses_can_be_saved_by_typed_and_send_commands() {
    for surface in ["typed", "send"] {
        let broker = MockServer::start().await;
        let mut catalog = catalog();
        let action = &mut catalog["services"][0]["actions"][0];
        action["action"] = json!("attachment.add");
        action["readOnly"] = json!(false);
        action["io"] = json!({"type":"multipart_upload","plan":{
            "role":"attachment","metadataPointer":"/attachments","fieldNamePrefix":"file",
            "minFiles":1,"maxFiles":1,"locatorInputs":["issue"],
            "metadataFields":["field","filename","contentType","size","sha256"],"callerContentTypeAllowed":true
        }});
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
            .mount(&broker)
            .await;
        let response = json!({"decision":"allow","agentRequestId":"agent","brokerRequestId":"broker","result":{"uploaded":true}});
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/attachment.add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let upload = directory.path().join("upload.txt");
        std::fs::write(&upload, "uploaded contents").unwrap();
        let destination = directory.path().join("response.json");
        let metadata = directory.path().join("metadata.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        command.args(["--url", &broker.uri(), "--no-token"]);
        if surface == "typed" {
            command
                .args(["jira", "issue", "attach", "ABC-1"])
                .arg(&upload)
                .arg("--output")
                .arg(&destination);
        } else {
            command.args(["send", "--request-json", &json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"attachment.add","inputs":{"issue":"ABC-1"},"files":[{"role":"attachment","path":upload}],"output":{"type":"file","path":destination},"metadataOutput":{"type":"file","path":metadata}}).to_string()]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{surface}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(destination).unwrap()).unwrap(),
            response
        );
        let receipt: Value = if surface == "typed" {
            serde_json::from_slice(&output.stdout).unwrap()
        } else {
            serde_json::from_slice(&std::fs::read(metadata).unwrap()).unwrap()
        };
        assert_eq!(receipt["operationStatus"], "succeeded");
        assert_eq!(receipt["output"]["status"], "succeeded");
        assert!(receipt.get("result").is_none());
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stdout_is_emitted_before_metadata_destination_failure() {
    let broker = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
        .mount(&broker)
        .await;
    let response = json!({"decision":"allow","agentRequestId":"agent","brokerRequestId":"broker","result":{"returned":true}});
    let directory = tempfile::tempdir().unwrap();
    let metadata = directory.path().join("metadata.json");
    let race_metadata = metadata.clone();
    let broker_response = response.clone();
    Mock::given(method("POST"))
        .and(path("/v1/invoke/jira/issue.view"))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::create_dir(&race_metadata).unwrap();
            ResponseTemplate::new(200).set_body_json(broker_response.clone())
        })
        .expect(1)
        .mount(&broker)
        .await;
    let request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{},"output":{"type":"stdout"},"metadataOutput":{"type":"file","path":metadata}});
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker.uri(),
            "--no-token",
            "send",
            "--request-json",
            &request.to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        response
    );
    let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(failure["operationStatus"], "succeeded");
    assert_eq!(failure["output"]["status"], "succeeded");
    assert_eq!(failure["metadataOutput"]["status"], "failed");
    assert!(failure.get("result").is_none());
    broker.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_response_and_metadata_destinations_prevent_sensitive_mutation_dispatch() {
    for surface in ["invoke", "send"] {
        for invalid_directory in [false, true] {
            for metadata in [false, true] {
                if metadata && surface == "invoke" {
                    continue;
                }
                let broker = MockServer::start().await;
                let mut catalog = catalog();
                catalog["services"][0]["service"] = json!("gitlab");
                let action = &mut catalog["services"][0]["actions"][0];
                action["action"] = json!("project.access_token.create");
                action["readOnly"] = json!(false);
                action["sensitiveOutputPointers"] = json!(["/result/issuedToken"]);
                Mock::given(method("GET"))
                    .and(path("/v1/spec/catalog"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
                    .mount(&broker)
                    .await;
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&broker)
                    .await;
                let directory = tempfile::tempdir().unwrap();
                let invalid = if invalid_directory {
                    directory.path().join("directory")
                } else {
                    directory.path().join("missing/output.json")
                };
                if invalid_directory {
                    std::fs::create_dir(&invalid).unwrap();
                }
                let body = if metadata {
                    directory.path().join("body.json")
                } else {
                    invalid.clone()
                };
                if metadata {
                    std::fs::write(&body, "original").unwrap();
                }
                let before = std::fs::read_dir(directory.path()).unwrap().count();
                let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
                command.args(["--url", &broker.uri(), "--no-token"]);
                if surface == "invoke" {
                    command
                        .args([
                            "invoke",
                            "gitlab.project.access_token.create",
                            "--input-json",
                            "{}",
                            "--output",
                        ])
                        .arg(&body);
                } else {
                    let mut request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"project.access_token.create","inputs":{},"output":{"type":"file","path":body}});
                    if metadata {
                        request["metadataOutput"] = json!({"type":"file","path":invalid});
                    }
                    command.args(["send", "--request-json", &request.to_string()]);
                }
                let result = command.output().unwrap();
                assert_eq!(
                    result.status.code(),
                    Some(3),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let stderr = String::from_utf8_lossy(&result.stderr);
                assert!(
                    stderr.contains(invalid.to_str().unwrap()),
                    "missing destination path: {stderr}"
                );
                if !invalid_directory {
                    let cause = std::fs::metadata(&invalid).unwrap_err().to_string();
                    assert!(
                        stderr.contains(&cause),
                        "missing filesystem cause {cause:?}: {stderr}"
                    );
                }
                assert!(result.stdout.is_empty());
                assert_eq!(
                    std::fs::read_dir(directory.path()).unwrap().count(),
                    before,
                    "unused reservation leaked"
                );
                if metadata {
                    assert_eq!(std::fs::read_to_string(body).unwrap(), "original");
                }
                broker.verify().await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_send_response_releases_body_and_metadata_reservations() {
    for (status, body, exit) in [
        (
            403,
            json!({"decision":"deny","agentRequestId":"agent","brokerRequestId":"broker","reasonCode":"policy_denied"}),
            2,
        ),
        (200, json!({"malformed":true}), 5),
    ] {
        let broker = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
            .mount(&broker)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira/issue.view"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&broker)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.json");
        let metadata = directory.path().join("metadata.json");
        std::fs::write(&output, "original body").unwrap();
        std::fs::write(&metadata, "original metadata").unwrap();
        let request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"issue.view","inputs":{},"output":{"type":"file","path":output},"metadataOutput":{"type":"file","path":metadata}});
        let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &broker.uri(),
                "--no-token",
                "send",
                "--request-json",
                &request.to_string(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read_to_string(output).unwrap(), "original body");
        assert_eq!(
            std::fs::read_to_string(metadata).unwrap(),
            "original metadata"
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_upload_diagnostic_keeps_path_and_filesystem_cause_without_dispatch() {
    let broker = MockServer::start().await;
    let mut catalog = catalog();
    let action = &mut catalog["services"][0]["actions"][0];
    action["action"] = json!("attachment.add");
    action["readOnly"] = json!(false);
    action["io"] = json!({"type":"multipart_upload","plan":{
        "role":"attachment","metadataPointer":"/attachments","fieldNamePrefix":"file",
        "minFiles":1,"maxFiles":1,"locatorInputs":["issue"],
        "metadataFields":["field","filename","contentType","size","sha256"],"callerContentTypeAllowed":true
    }});
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog))
        .mount(&broker)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&broker)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let upload = directory.path().join("missing-upload.txt");
    let destination = directory.path().join("response.json");
    let metadata = directory.path().join("metadata.json");
    std::fs::write(&destination, "original response").unwrap();
    std::fs::write(&metadata, "original metadata").unwrap();
    let cause = std::fs::metadata(&upload).unwrap_err().to_string();
    let request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"jira","action":"attachment.add","inputs":{"issue":"ABC-1"},"files":[{"role":"attachment","path":upload}],"output":{"type":"file","path":destination},"metadataOutput":{"type":"file","path":metadata}});
    let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker.uri(),
            "--no-token",
            "send",
            "--request-json",
            &request.to_string(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains(upload.to_str().unwrap()),
        "missing input path: {stderr}"
    );
    assert!(
        stderr.contains(&cause),
        "missing filesystem cause {cause:?}: {stderr}"
    );
    assert!(result.stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(destination).unwrap(),
        "original response"
    );
    assert_eq!(
        std::fs::read_to_string(metadata).unwrap(),
        "original metadata"
    );
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        2,
        "failed upload leaked output reservations"
    );
    broker.verify().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwritable_output_parent_diagnostic_keeps_path_and_cause_without_dispatch() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("unwritable");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let probe = parent.join("permission-probe");
    let cause = match std::fs::File::create(&probe) {
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            error.to_string()
        }
        Ok(file) => {
            // Privileged test runners can bypass filesystem permission bits.
            drop(file);
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_file(&probe).unwrap();
            return;
        }
    };
    let broker = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(catalog()))
        .mount(&broker)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&broker)
        .await;
    let destination = parent.join("response.json");
    let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker.uri(),
            "--no-token",
            "invoke",
            "jira.issue.view",
            "--input-json",
            "{}",
            "--output",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains(destination.to_str().unwrap()),
        "missing destination path: {stderr}"
    );
    assert!(
        stderr.contains(&cause),
        "missing filesystem cause {cause:?}: {stderr}"
    );
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
    broker.verify().await;
}
