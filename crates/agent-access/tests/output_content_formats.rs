//! Real CLI processes against synthetic HTTP responses exercise client contract boundaries.
#[path = "common/presentation_failure.rs"]
mod presentation_failure;

use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Output},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

fn catalog(visible: bool) -> Value {
    let mut value = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
    if visible {
        value["services"] = json!([{"service":"jira","displayName":"Jira","surface":"invoke","scopedMcpReady":true,"scopeTypes":[],"actions":[{
            "action":"issue.view","scopedMcpName":"issue.view","description":"Read an issue","readOnly":true,
            "requiredScopeTypes":[],"credentialModes":[],"inputSchema":{"type":"object"},
            "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision",
            "outputContentFormats":["markdown","text"],"nativeOutputContentFormat":"markdown","defaultOutputContentFormat":"markdown",
            "bodyFields":[{"ownerPath":"/result","field":"description","optionalOwnerPrefixes":[],"nullableOwnerPrefixes":[],"optional":true,"nullable":true}]
        }]}]);
    }
    value
}
fn success(result: Value) -> Value {
    json!({"agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","service":"jira","action":"issue.view","result":result})
}
fn command(directory: &Path, broker: &MockServer) -> Command {
    let config = directory.join("client.toml");
    if !config.exists() {
        std::fs::write(&config, "").unwrap();
    }
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
fn invocation(
    command: &mut Command,
    surface: &str,
    exact: Option<&str>,
    preferred: Option<&str>,
    output: Option<&Path>,
) {
    match surface {
        "typed" => {
            command.args(["jira", "issue", "view", "PROJ-1"]);
        }
        "invoke" => {
            command.args([
                "invoke",
                "jira.issue.view",
                "--input-json",
                r#"{"issue":"PROJ-1"}"#,
            ]);
        }
        "send" => {
            let mut request = json!({"version":agent_access_core::SEND_SCHEMA_VERSION,"kind":"invoke","service":"jira","action":"issue.view","inputs":{"issue":"PROJ-1"}});
            if let Some(exact) = exact {
                request["outputContentFormat"] = json!(exact);
            }
            if let Some(preferred) = preferred {
                request["preferredOutputContentFormat"] = json!(preferred);
            }
            command.args(["send", "--request-json", &request.to_string()]);
        }
        _ => unreachable!(),
    }
    if surface != "send"
        && let Some(exact) = exact
    {
        command.args(["--output-content-format", exact]);
    }
    if let Some(output) = output {
        command.arg("--output").arg(output);
    }
}
fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
async fn serve_catalog(broker: &MockServer, value: Value) {
    Mock::given(method("GET"))
        .and(path("/v1/spec/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .expect(1)
        .mount(broker)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_json_entrypoint_fetches_catalog_and_preserves_unresolved_preferences() {
    for surface in ["typed", "invoke", "send"] {
        // The response's ADF source was enabled after this catalog was discovered.
        for result in [
            json!({"description":{"format":"adf","value":{"type":"doc","version":1,"content":[]}}}),
            json!({"title":"body disabled after discovery"}),
        ] {
            let broker = MockServer::start().await;
            let directory = tempfile::tempdir().unwrap();
            serve_catalog(&broker, catalog(true)).await;
            let preferred = if surface == "send" { "storage" } else { "text" };
            Mock::given(method("POST"))
                .and(path("/v1/invoke/jira/issue.view"))
                .and(body_json(
                    json!({"inputs":{"issue":"PROJ-1"},"preferredOutputContentFormat":preferred}),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(success(result.clone())))
                .expect(1)
                .mount(&broker)
                .await;
            let mut cmd = command(directory.path(), &broker);
            cmd.env("AGENT_ACCESS_PREFERRED_OUTPUT_CONTENT_FORMAT", "text");
            invocation(&mut cmd, surface, None, Some("storage"), None);
            let output = cmd.output().unwrap();
            assert_exit(&output, 0);
            let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(printed["result"], result);
            broker.verify().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_preference_overrides_environment_and_remains_separate_from_exact_selection() {
    let broker = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("client.toml"),
        "[defaults]\npreferred_output_content_format=\"adf\"\n",
    )
    .unwrap();
    serve_catalog(&broker, catalog(true)).await;
    Mock::given(method("POST"))
        .and(path("/v1/invoke/jira/issue.view"))
        .and(body_json(json!({"inputs":{"issue":"PROJ-1"},"outputContentFormat":"text","preferredOutputContentFormat":"adf"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(success(json!({"description":{"format":"text","value":"selected"}}))))
        .expect(1)
        .mount(&broker)
        .await;
    let mut cmd = command(directory.path(), &broker);
    cmd.env(
        "AGENT_ACCESS_PREFERRED_OUTPUT_CONTENT_FORMAT",
        "invalid lower-priority value",
    );
    invocation(&mut cmd, "typed", Some("text"), None, None);
    let result = cmd.output().unwrap();
    assert_exit(&result, 0);
    let response: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(response["result"]["description"]["format"], "text");
    broker.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hidden_catalog_action_retains_stdout_dispatch_and_refuses_exact_or_file_contracts() {
    for (surface, exact, file, expected_calls) in [
        ("typed", None, false, 1),
        ("invoke", None, false, 1),
        ("typed", Some("adf"), false, 0),
        ("invoke", Some("text"), false, 0),
        ("invoke", None, true, 0),
        ("send", None, false, 0),
    ] {
        let broker = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        serve_catalog(&broker, catalog(false)).await;
        Mock::given(method("POST"))
            .and(body_json(
                json!({"inputs":{"issue":"PROJ-1"},"preferredOutputContentFormat":"storage"}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(success(json!({"notDiscovered":true}))),
            )
            .expect(expected_calls)
            .mount(&broker)
            .await;
        let destination = directory.path().join("response.json");
        let mut cmd = command(directory.path(), &broker);
        cmd.env("AGENT_ACCESS_PREFERRED_OUTPUT_CONTENT_FORMAT", "storage");
        invocation(
            &mut cmd,
            surface,
            exact,
            None,
            file.then_some(destination.as_path()),
        );
        let output = cmd.output().unwrap();
        assert_exit(&output, if expected_calls == 1 { 0 } else { 3 });
        assert!(!destination.exists());
        broker.verify().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_successful_content_produces_bounded_receipt_without_replay_or_file_replacement() {
    for surface in ["typed", "invoke", "send"] {
        for file in [false, true] {
            let broker = MockServer::start().await;
            let directory = tempfile::tempdir().unwrap();
            serve_catalog(&broker, catalog(true)).await;
            let response = success(
                json!({"description":{"format":"adf","value":"PRIVATE INVALID BODY"},"mutationStatus":"applied","retrySafe":false,"safeLocators":{"issueId":"42"}}),
            );
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&broker)
                .await;
            let destination = directory.path().join("response.json");
            std::fs::write(&destination, "original").unwrap();
            let mut cmd = command(directory.path(), &broker);
            invocation(
                &mut cmd,
                surface,
                None,
                None,
                file.then_some(destination.as_path()),
            );
            let output = cmd.output().unwrap();
            assert_exit(&output, 5);
            assert!(output.stdout.is_empty());
            assert!(output.stderr.ends_with(b"\n"));
            assert_eq!(
                output.stderr.iter().filter(|&&byte| byte == b'\n').count(),
                1
            );
            let receipt: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(receipt["reasonCode"], "response_content_invalid");
            assert_eq!(receipt["operationStatus"], "succeeded");
            assert_eq!(receipt["mutationStatus"], "applied");
            assert_eq!(receipt["retrySafe"], false);
            assert_eq!(receipt["brokerRequestId"], "broker");
            assert!(receipt.get("output").is_none());
            assert!(!receipt.to_string().contains("PRIVATE"));
            assert_eq!(std::fs::read_to_string(&destination).unwrap(), "original");
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
            broker.verify().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compact_allow_outcomes_preserve_provider_status_instead_of_requiring_success_bodies() {
    for surface in ["typed", "invoke", "send"] {
        for (mutation, retry_safe) in [
            ("unknown", false),
            ("not_applied", true),
            ("applied", false),
        ] {
            let broker = MockServer::start().await;
            let directory = tempfile::tempdir().unwrap();
            let mut required_body = catalog(true);
            required_body["services"][0]["actions"][0]["bodyFields"][0]["optional"] = json!(false);
            serve_catalog(&broker, required_body).await;
            let mut response = success(json!({"mutationStatus":mutation,"retrySafe":retry_safe}));
            response["reasonCode"] = json!("verification_mismatch");
            response["reason"] = json!("Original provider outcome");
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
                .expect(1)
                .mount(&broker)
                .await;
            let mut cmd = command(directory.path(), &broker);
            invocation(&mut cmd, surface, Some("markdown"), None, None);
            let output = cmd.output().unwrap();
            assert_exit(&output, 0);
            assert!(output.stderr.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stdout).unwrap(),
                response
            );
            broker.verify().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_presentation_failure_receipt_survives_every_cli_entrypoint_and_output_mode() {
    for surface in ["typed", "invoke", "send"] {
        for (file, existing) in [(false, false), (true, false), (true, true)] {
            let broker = MockServer::start().await;
            let directory = tempfile::tempdir().unwrap();
            serve_catalog(&broker, presentation_failure::catalog()).await;
            let receipt = presentation_failure::receipt();
            Mock::given(method("POST"))
                .and(path("/v1/invoke/jira/issue.update"))
                .and(body_json(json!({
                    "inputs":presentation_failure::inputs(),
                    "outputContentFormat":"markdown"
                })))
                .respond_with(ResponseTemplate::new(502).set_body_json(receipt.clone()))
                .expect(1)
                .mount(&broker)
                .await;
            let destination = directory.path().join("response.json");
            if existing {
                // JSON output reserves a sibling temporary file before dispatch;
                // an existing regular destination is replaced only on success.
                std::fs::write(&destination, "original destination").unwrap();
            }
            let mut cmd = command(directory.path(), &broker);
            match surface {
                "typed" => {
                    cmd.args([
                        "jira",
                        "issue",
                        "update",
                        "PROJ-1",
                        "--summary",
                        "Updated title",
                        "--output-content-format",
                        "markdown",
                    ]);
                }
                "invoke" => {
                    cmd.args([
                        "invoke",
                        "jira.issue.update",
                        "--input-json",
                        &presentation_failure::inputs().to_string(),
                        "--output-content-format",
                        "markdown",
                    ]);
                }
                "send" => {
                    let request = json!({
                        "version":agent_access_core::SEND_SCHEMA_VERSION, "kind":"invoke",
                        "service":"jira", "action":"issue.update",
                        "inputs":presentation_failure::inputs(), "outputContentFormat":"markdown"
                    });
                    cmd.args(["send", "--request-json", &request.to_string()]);
                }
                _ => unreachable!(),
            }
            if file {
                cmd.arg("--output").arg(&destination);
            }
            let output = cmd.output().unwrap();
            assert_exit(&output, 4); // HTTP 502 retains the upstream-failure exit code.
            assert!(output.stderr.is_empty(), "{surface}: {output:?}");
            let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                printed, receipt,
                "{surface}, file={file}, existing={existing}"
            );
            assert!(printed.get("output").is_none());
            assert!(printed["result"].get("issue").is_none());
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(destination.to_str().unwrap())
            );
            if existing {
                assert_eq!(
                    std::fs::read_to_string(&destination).unwrap(),
                    "original destination"
                );
            } else {
                assert!(!destination.exists());
            }
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                1 + usize::from(existing)
            );
            broker.verify().await;
            assert_eq!(
                broker
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|request| request.method == "POST")
                    .count(),
                1
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_environment_settings_fail_before_every_operational_startup() {
    let broker = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    for variable in [
        "AGENT_ACCESS_READ_CONTENT_FORMAT",
        "AGENT_ACCESS_OUTPUT_FORMAT",
    ] {
        for args in [
            vec!["auth", "status"],
            vec!["config", "validate"],
            vec!["services", "list"],
            vec!["spec", "catalog"],
            vec!["mcp", "serve"],
        ] {
            let output = command(directory.path(), &broker)
                .args(args)
                .env(variable, "")
                .output()
                .unwrap();
            assert_exit(&output, 3);
            assert!(output.stdout.is_empty());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains(variable));
            if variable == "AGENT_ACCESS_READ_CONTENT_FORMAT" {
                assert!(error.contains("AGENT_ACCESS_PREFERRED_OUTPUT_CONTENT_FORMAT"));
            } else {
                assert!(error.contains("always JSON"));
                assert!(error.contains("no replacement"));
            }
        }
    }
    let help = command(directory.path(), &broker)
        .arg("--help")
        .env("AGENT_ACCESS_OUTPUT_FORMAT", "markdown")
        .output()
        .unwrap();
    assert_exit(&help, 0);
    assert!(broker.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_toml_defaults_fail_stdio_startup_with_fixed_guidance_without_config_values() {
    let broker = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    for key in ["read_content_format", "output_format"] {
        std::fs::write(
            directory.path().join("client.toml"),
            format!("[defaults]\n{key}=\"PRIVATE CONFIG VALUE\"\n"),
        )
        .unwrap();
        for args in [["mcp", "serve"], ["config", "validate"]] {
            let result = command(directory.path(), &broker)
                .args(args)
                .output()
                .unwrap();
            assert_exit(&result, 3);
            assert!(result.stdout.is_empty());
            let diagnostic = String::from_utf8_lossy(&result.stderr);
            assert!(
                diagnostic.contains(&format!("[defaults].{key}")),
                "{diagnostic}"
            );
            assert!(!diagnostic.contains("PRIVATE CONFIG VALUE"));
            if key == "read_content_format" {
                assert!(diagnostic.contains("[defaults].preferred_output_content_format"));
            } else {
                assert!(diagnostic.contains("always JSON"));
                assert!(diagnostic.contains("no replacement"));
            }
        }
    }
    std::fs::write(
        directory.path().join("client.toml"),
        "[defaults]\npreferred_output_content_format=\"PRIVATE OTHER CONFIG VALUE\"\n",
    )
    .unwrap();
    let result = command(directory.path(), &broker)
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert_exit(&result, 3);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("PRIVATE OTHER CONFIG VALUE"));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("Cannot resolve broker configuration")
    );
    assert!(broker.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_catalog_version_fails_before_all_json_dispatch_paths() {
    for surface in ["typed", "invoke", "send"] {
        let broker = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let mut old = catalog(true);
        old["version"] = json!("agent-access.catalog.v2");
        serve_catalog(&broker, old).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&broker)
            .await;
        let mut cmd = command(directory.path(), &broker);
        invocation(&mut cmd, surface, None, None, None);
        let output = cmd.output().unwrap();
        assert_exit(&output, 5);
        assert!(output.stdout.is_empty());
        broker.verify().await;
    }
}
