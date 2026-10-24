#[path = "cloudbees_smoke/job_list.rs"]
mod job_list;

use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker, RunningBroker};
use agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE;
use agent_access_provider::RESULT_METADATA_HEADER;
use base64::Engine;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const JOB: &str = "payments/build-api";
const ARTIFACT: &str = "reports/tests.xml";
const ARTIFACT_BYTES: &[u8] = b"<testsuite tests=\"1\"/>";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_read_file_output_preserves_bounds_permissions_and_existing_destinations() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("partial\n", "text/plain"))
        .expect(6)
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let token_path = temp.path().join("principal-token");
    std::fs::write(&token_path, "ci-principal-token").unwrap();
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let broker_url = broker.public_url();
    let config_path = temp.path().join("client.toml");
    std::fs::write(&config_path, format!("[service]\nurl = {broker_url:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n", token_path.display().to_string())).unwrap();
    let destination = temp.path().join("read.json");
    let inputs = json!({"controller":"team-ci","job":JOB,"buildNumber":42,"maxBytes":1024});
    let invoke_json = inputs.to_string();
    let request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"cloudbees_ci","action":"build.log.read","inputs":inputs,"output":{"type":"file","path":destination}}).to_string();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args(args)
            .output()
            .unwrap()
    };
    for args in [
        vec![
            "cloudbees-ci",
            "build",
            "log",
            "team-ci",
            JOB,
            "42",
            "--max-bytes",
            "1024",
            "--output",
            destination.to_str().unwrap(),
        ],
        vec![
            "invoke",
            "cloudbees_ci.build.log.read",
            "--input-json",
            &invoke_json,
            "--output",
            destination.to_str().unwrap(),
        ],
        vec!["send", "--request-json", &request],
    ] {
        std::fs::write(&destination, b"old contents").unwrap();
        let result = run(&args);
        assert_success("save read", &result);
        let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(
            receipt.get("result").is_none(),
            "receipt repeats content: {receipt}"
        );
        assert_eq!(receipt["output"]["path"], destination.to_str().unwrap());
        let bytes = std::fs::read(&destination).unwrap();
        assert_eq!(receipt["output"]["size"], bytes.len() as u64);
        let saved: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(saved["decision"], "allow");
        assert_eq!(saved["result"]["text"], "partial\n");
        assert_eq!(saved["result"]["sourceEnd"], 8);
        assert_eq!(saved["result"]["reachedEnd"], true);
    }
    let stdout = run(&[
        "invoke",
        "cloudbees_ci.build.log.read",
        "--input-json",
        &invoke_json,
        "--output",
        "-",
    ]);
    assert_success("stdout read", &stdout);
    let value: Value = serde_json::from_slice(&stdout.stdout).unwrap();
    assert_eq!(value["result"]["text"], "partial\n");
    assert!(value.get("output").is_none());
    let mut request_without_sink: Value = serde_json::from_str(&request).unwrap();
    request_without_sink
        .as_object_mut()
        .unwrap()
        .remove("output");
    let result = run(&[
        "send",
        "--request-json",
        &request_without_sink.to_string(),
        "--output",
        destination.to_str().unwrap(),
    ]);
    assert_success("send CLI destination", &result);

    let mut mcp = StdioMcp::start(&config_path);
    mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"read-file-output-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let listed = mcp.request("tools/list", json!({})).await;
    let tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "build.log.read")
        .unwrap();
    assert!(
        tool["inputSchema"]["properties"]
            .get("outputPath")
            .is_some()
    );
    let result = mcp
        .request(
            "tools/call",
            json!({"name":tool["name"],"arguments":{"inputs":inputs,"outputPath":destination}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    let receipt = &result["result"]["structuredContent"];
    assert!(receipt.get("result").is_none());
    assert_eq!(receipt["output"]["path"], destination.to_str().unwrap());
    let saved: Value = serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert_eq!(saved["result"]["text"], "partial\n");
    assert_eq!(saved["result"]["reachedEnd"], true);
    std::fs::write(&destination, b"keep this file").unwrap();
    let denied_inputs = json!({"controller":"team-ci","job":"payments/other-job","buildNumber":42});
    let result = mcp.request("tools/call", json!({"name":tool["name"],"arguments":{"inputs":denied_inputs,"outputPath":destination}})).await;
    assert_eq!(result["result"]["isError"], true, "{result}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"keep this file");
    mcp.finish().await;

    std::fs::write(&destination, b"keep this file").unwrap();
    let denied = run(&[
        "cloudbees-ci",
        "build",
        "log",
        "team-ci",
        "payments/other-job",
        "42",
        "--output",
        destination.to_str().unwrap(),
    ]);
    assert!(!denied.status.success());
    assert_eq!(std::fs::read(&destination).unwrap(), b"keep this file");
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/api/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"fullName":JOB,"buildable":true,"property":[]})),
        )
        .mount(&controller)
        .await;
    Mock::given(method("POST"))
        .and(path("/team-ci/job/payments/job/build-api/build"))
        .respond_with(
            ResponseTemplate::new(201).insert_header("Location", "/team-ci/queue/item/17/"),
        )
        .expect(2)
        .mount(&controller)
        .await;
    let mutation = run(&[
        "cloudbees-ci",
        "build",
        "trigger",
        "team-ci",
        JOB,
        "--output",
        destination.to_str().unwrap(),
    ]);
    assert_success("save typed trigger response", &mutation);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&destination).unwrap()).unwrap()["result"]["queueId"],
        17
    );
    let mutation_request = json!({"version":"agent-access.send.v1","kind":"invoke","service":"cloudbees_ci","action":"build.trigger","inputs":{"controller":"team-ci","job":JOB},"output":{"type":"file","path":destination}}).to_string();
    let mutation = run(&["send", "--request-json", &mutation_request]);
    assert_success("save send trigger response", &mutation);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&destination).unwrap()).unwrap()["result"]["queueId"],
        17
    );
    let ambiguous = run(&[
        "send",
        "--request-json",
        &request,
        "--output",
        destination.to_str().unwrap(),
    ]);
    assert_eq!(ambiguous.status.code(), Some(3));
    let spec_path = temp.path().join("schema.json");
    let spec = run(&[
        "spec",
        "send-schema",
        "--offline",
        "--output-format",
        "json",
        "--output",
        spec_path.to_str().unwrap(),
    ]);
    assert_success("offline spec output", &spec);
    let schema: Value = serde_json::from_slice(&std::fs::read(&spec_path).unwrap()).unwrap();
    assert!(schema.get("$schema").is_some());
    let discovery_path = temp.path().join("actions.json");
    let discovery = run(&[
        "actions",
        "list",
        "--service",
        "cloudbees_ci",
        "--output",
        discovery_path.to_str().unwrap(),
    ]);
    assert_success("discovery output", &discovery);
    assert!(serde_json::from_slice::<Value>(&std::fs::read(&discovery_path).unwrap()).is_ok());
    let requests = controller.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        10,
        "file output fetched unexpected extra content"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        2,
        "each requested build trigger must execute once"
    );
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_and_report_downloads_work_over_cli_send_http_and_stdio() {
    let controller = MockServer::start().await;
    let console = "console output\n".repeat(6000);
    let report = json!({"totalCount":1,"suites":[{"name":"suite","cases":[{"name":"failure","errorStackTrace":"details"}]}]}).to_string();
    for (endpoint, content_type, bytes) in [
        ("consoleText", "text/plain; charset=UTF-8", &console),
        ("testReport/api/json", "application/json", &report),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/team-ci/job/payments/job/build-api/42/{endpoint}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_raw(bytes.clone(), content_type))
            .expect(5)
            .mount(&controller)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(
            "/team-ci/job/payments/job/build-api/42/testReport/api/json",
        ))
        .and(query_param("tree", "suites{0,0}"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"suites":[]})))
        .with_priority(1)
        .expect(5)
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let principal_token = temp.path().join("principal-token");
    std::fs::write(&principal_token, "ci-principal-token").unwrap();
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let broker_url = broker.public_url();
    let config_path = temp.path().join("client.toml");
    std::fs::write(&config_path, format!("[service]\nurl = {broker_url:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n", principal_token.display().to_string())).unwrap();
    let mut mcp = StdioMcp::start(&config_path);
    mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cloudbees-read-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let tool_listing = mcp.request("tools/list", json!({})).await;
    let tools = tool_listing["result"]["tools"].as_array().unwrap();
    let inputs = json!({"controller":"team-ci","job":JOB,"buildNumber":42});
    for (command, action, bytes) in [
        ("log-download", "build.log.download", &console),
        ("tests-download", "build.tests.download", &report),
    ] {
        let output = temp.path().join(format!("{command}.cli"));
        let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args([
                "cloudbees-ci",
                "build",
                command,
                "team-ci",
                JOB,
                "42",
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert_success(command, &result);
        assert_eq!(std::fs::read(&output).unwrap(), bytes.as_bytes());
        let metadata: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(metadata["result"].get("text").is_none());
        assert_eq!(metadata["output"]["size"], bytes.len() as u64);
        assert_eq!(metadata["output"]["path"], output.to_str().unwrap());

        // Generic invoke plans native downloads from the same caller catalog
        // as imported commands and preserves the provider's file bytes.
        let output = temp.path().join(format!("{command}.invoke"));
        let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args([
                "invoke",
                &format!("cloudbees_ci.{action}"),
                "--input-json",
                &inputs.to_string(),
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert_success("generic invoke native download", &result);
        assert_eq!(std::fs::read(&output).unwrap(), bytes.as_bytes());
        let metadata: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(metadata["output"]["size"], bytes.len() as u64);
        assert_eq!(metadata["output"]["path"], output.to_str().unwrap());

        let output = temp.path().join(format!("{command}.send"));
        let request = temp.path().join(format!("{command}.json"));
        std::fs::write(&request, serde_json::to_vec(&json!({"version":"agent-access.send.v1","kind":"invoke","responseMode":"stream","service":"cloudbees_ci","action":action,"inputs":inputs,"output":{"type":"file","path":output}})).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args(["send", "--request-file"])
            .arg(&request)
            .output()
            .unwrap();
        assert_success("send read download", &result);
        assert_eq!(std::fs::read(&output).unwrap(), bytes.as_bytes());

        let result = reqwest::Client::new()
            .post(format!("{broker_url}/v1/invoke/cloudbees_ci/{action}"))
            .header("X-Agent-Access-Identity-Token", "ci-principal-token")
            .header(
                "X-Agent-Access-Request-Id",
                format!("read-download-{command}"),
            )
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .json(&json!({"inputs":inputs}))
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), reqwest::StatusCode::OK);
        assert!(result.headers().contains_key(RESULT_METADATA_HEADER));
        assert_eq!(result.bytes().await.unwrap().as_ref(), bytes.as_bytes());

        let tool = tools
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == action)
            .unwrap();
        let output = temp.path().join(format!("{command}.mcp"));
        let result = mcp
            .request(
                "tools/call",
                json!({"name":tool["name"],"arguments":{"inputs":inputs,"outputPath":output}}),
            )
            .await;
        assert_eq!(result["result"]["isError"], false, "{result}");
        assert_eq!(std::fs::read(&output).unwrap(), bytes.as_bytes());
    }
    mcp.finish().await;
    assert!(
        controller
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_download_destinations_are_checked_before_upstream_dispatch() {
    let controller = MockServer::start().await;
    let contents = b"downloaded console output\n";
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(contents, "text/plain"))
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let broker_url = broker.public_url();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        command.args([
            "--url",
            &broker_url,
            "--token-value",
            "ci-principal-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
        ]);
        command
    };
    let missing_parent = temp.path().join("missing/output.log");
    let directory = temp.path().join("existing-directory");
    std::fs::create_dir(&directory).unwrap();
    let preserved = temp.path().join("existing.log");
    std::fs::write(&preserved, b"preserve existing output").unwrap();
    let base_request = json!({
        "version":"agent-access.send.v1", "kind":"invoke", "responseMode":"stream",
        "service":"cloudbees_ci", "action":"build.log.download",
        "inputs":{"controller":"team-ci", "job":JOB, "buildNumber":42}
    });
    let typed_download = |destination: &std::path::Path| {
        command()
            .args([
                "cloudbees-ci",
                "build",
                "log-download",
                "team-ci",
                JOB,
                "42",
                "--output",
            ])
            .arg(destination)
            .output()
            .unwrap()
    };
    let send_download = |request: &Value| {
        command()
            .args(["send", "--request-json", &request.to_string()])
            .output()
            .unwrap()
    };
    let assert_local_rejection =
        |label: &str, result: &std::process::Output, destination: &std::path::Path| {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let diagnostic = format!(
                "{label}: status={} stdout={} stderr={stderr}",
                result.status,
                String::from_utf8_lossy(&result.stdout)
            );
            assert!(!result.status.success(), "{diagnostic}");
            assert!(
                stderr.contains(destination.to_str().unwrap()),
                "expected a local destination error; {diagnostic}"
            );
            assert!(
                result.stdout.is_empty(),
                "output started despite local preflight rejection; {diagnostic}"
            );
        };

    for invalid in [&missing_parent, &directory] {
        let result = typed_download(invalid);
        assert_local_rejection("typed download", &result, invalid);
        assert!(controller.received_requests().await.unwrap().is_empty());

        let mut request = base_request.clone();
        request["output"] = json!({"type":"file", "path":invalid});
        let result = send_download(&request);
        assert_local_rejection("send download", &result, invalid);
        assert!(controller.received_requests().await.unwrap().is_empty());

        // A metadata failure must prevent downloading either into an existing
        // file or to stdout, before any raw bytes can be consumed or emitted.
        for output in [
            json!({"type":"file", "path":preserved}),
            json!({"type":"stdout"}),
        ] {
            let mut request = base_request.clone();
            request["output"] = output;
            request["metadataOutput"] = json!({"type":"file", "path":invalid});
            let result = send_download(&request);
            assert_local_rejection("send download metadata", &result, invalid);
            assert!(controller.received_requests().await.unwrap().is_empty());
            assert_eq!(
                std::fs::read(&preserved).unwrap(),
                b"preserve existing output"
            );
        }
    }
    assert!(!missing_parent.parent().unwrap().exists());
    assert!(directory.is_dir());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);

    // Prove the same commands and authorization can download successfully;
    // the rejected calls above must fail specifically on their local paths.
    let result = typed_download(&preserved);
    assert_success("typed download after preflight rejection", &result);
    assert_eq!(std::fs::read(&preserved).unwrap(), contents);
    let metadata = temp.path().join("metadata.json");
    let mut request = base_request;
    request["output"] = json!({"type":"file", "path":preserved});
    request["metadataOutput"] = json!({"type":"file", "path":metadata});
    let result = send_download(&request);
    assert_success("send download after preflight rejection", &result);
    assert_eq!(std::fs::read(&preserved).unwrap(), contents);
    let receipt: Value = serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
    assert_eq!(receipt["output"]["size"], contents.len());
    assert_eq!(controller.received_requests().await.unwrap().len(), 2);
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn throttled_controller_reaches_cli_stderr_and_stdio_mcp_text_as_the_broker_message() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team-ci/queue/item/51/api/json"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "30")
                .set_body_string("controller throttle page"),
        )
        .expect(3)
        .mount(&controller)
        .await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(429).set_body_string("controller throttle page"))
        .expect(3)
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let principal_token = temp.path().join("principal-token");
    std::fs::write(&principal_token, "ci-principal-token").unwrap();
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let broker_url = broker.public_url();
    let config_path = temp.path().join("client.toml");
    std::fs::write(&config_path, format!("[service]\nurl = {broker_url:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n", principal_token.display().to_string())).unwrap();
    let destination = temp.path().join("saved");
    std::fs::write(&destination, "existing content").unwrap();
    let send_request = temp.path().join("send.json");
    std::fs::write(
        &send_request,
        serde_json::to_vec(&json!({
            "version":"agent-access.send.v1","kind":"invoke","responseMode":"stream",
            "service":"cloudbees_ci","action":"build.log.download",
            "inputs":{"controller":"team-ci","job":JOB,"buildNumber":42},
            "output":{"type":"file","path":destination}
        }))
        .unwrap(),
    )
    .unwrap();
    let queue_view = [
        "cloudbees-ci",
        "queue",
        "view",
        "team-ci",
        JOB,
        "--queue-id",
        "51",
    ];
    let log_download = [
        "cloudbees-ci",
        "build",
        "log-download",
        "team-ci",
        JOB,
        "42",
    ];
    let destination_arg = destination.to_str().unwrap();
    let send_arg = send_request.to_str().unwrap();
    for (label, args, wait_known) in [
        ("queue view", queue_view.to_vec(), true),
        (
            "queue view --output",
            [&["--output", destination_arg][..], &queue_view[..]].concat(),
            true,
        ),
        (
            "log download",
            [&["--output", destination_arg][..], &log_download[..]].concat(),
            false,
        ),
        (
            "send stream download",
            vec!["send", "--request-file", send_arg],
            false,
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args(&args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(7), "{label}: {stderr}");
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["reasonCode"], "upstream_rate_limited", "{label}");
        assert_eq!(envelope["result"]["limitScope"], "upstream", "{label}");
        let message = envelope["error"]["message"].as_str().unwrap();
        if wait_known {
            assert_eq!(envelope["result"]["retryAfterSeconds"], 30, "{label}");
            assert!(
                message.starts_with("cloudbees_ci is rate limiting requests. Retry after 30s (at "),
                "{label}: {message}"
            );
        } else {
            assert_eq!(
                message, "cloudbees_ci is rate limiting requests. Retry later.",
                "{label}"
            );
        }
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with("rate limited: "))
                .collect::<Vec<_>>(),
            [format!("rate limited: {message}")],
            "{label}: {stderr}"
        );
        assert!(!stderr.contains("controller throttle page"), "{label}");
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing content");
    }

    let mut mcp = StdioMcp::start(&config_path);
    mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cloudbees-throttle-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let tool_listing = mcp.request("tools/list", json!({})).await;
    let tools = tool_listing["result"]["tools"].as_array().unwrap();
    let tool = |action: &str| {
        tools
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == action)
            .unwrap()["name"]
            .clone()
    };
    for (name, arguments) in [
        (
            tool("queue.view"),
            json!({"inputs":{"controller":"team-ci","job":JOB,"queueId":51}}),
        ),
        (
            tool("build.log.download"),
            json!({"inputs":{"controller":"team-ci","job":JOB,"buildNumber":42},"outputPath":destination}),
        ),
    ] {
        let response = mcp
            .request("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        let result = &response["result"];
        assert_eq!(result["isError"], true, "{response}");
        let envelope = &result["structuredContent"];
        assert_eq!(
            envelope["reasonCode"], "upstream_rate_limited",
            "{response}"
        );
        assert_eq!(
            result["content"],
            json!([{"type":"text","text":envelope["error"]["message"]}]),
            "{response}"
        );
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("cloudbees_ci is rate limiting requests. Retry"),
            "{response}"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing content");
    }
    mcp.finish().await;
    // One upstream request per command or tool call: nothing was retried.
    controller.verify().await;
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_reasons_keep_their_wire_status_cli_exit_mcp_error_and_audit() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/team-ci/job/payments/job/build-api/42/execution/node/6/wfapi/log",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nodeId":"6", "nodeStatus":"SUCCESS", "length":65_537,
            "hasMore":false, "text":"x".repeat(65_537)
        })))
        .mount(&controller)
        .await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(vec![b'x'; 5000], "text/plain"))
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let principal_token = temp.path().join("principal-token");
    std::fs::write(&principal_token, "ci-principal-token").unwrap();
    let broker = start_broker(&Cloudbees {
        max_log_scan_bytes: 2000,
        ..Cloudbees::ci_agent(&controller)
    })
    .await;
    let broker_url = broker.public_url();
    let config_path = temp.path().join("client.toml");
    std::fs::write(&config_path, format!("[service]\nurl = {broker_url:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n", principal_token.display().to_string())).unwrap();
    let cases = [
        (
            "build.pipeline.node.log.read",
            json!({"controller":"team-ci","job":JOB,"buildNumber":42,"nodeId":"6"}),
            "cloudbees_ci_log_chunk_exceeded",
        ),
        (
            "build.log.read",
            json!({"controller":"team-ci","job":JOB,"buildNumber":42,"mode":"tail","maxBytes":1024}),
            "cloudbees_ci_log_scan_exceeded",
        ),
    ];
    for (action, inputs, reason) in &cases {
        let response = reqwest::Client::new()
            .post(format!("{broker_url}/v1/invoke/cloudbees_ci/{action}"))
            .header("X-Agent-Access-Request-Id", "cloudbees-domain-reason")
            .header("X-Agent-Access-Identity-Token", "ci-principal-token")
            .json(&json!({ "inputs": inputs }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let envelope: Value = response.json().await.unwrap();
        assert_eq!(
            status,
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            "{action}: {envelope}"
        );
        assert_eq!(envelope["decision"], "deny", "{envelope}");
        assert_eq!(envelope["reasonCode"], *reason, "{envelope}");

        let request = temp.path().join("send.json");
        std::fs::write(
            &request,
            serde_json::to_vec(&json!({
                "version":"agent-access.send.v1","kind":"invoke",
                "service":"cloudbees_ci","action":action,"inputs":inputs
            }))
            .unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args(["send", "--request-file", request.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["decision"], "deny", "{envelope}");
        assert_eq!(envelope["reasonCode"], *reason, "{envelope}");
    }

    let mut mcp = StdioMcp::start(&config_path);
    mcp.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cloudbees-domain-reason-smoke","version":"1"}})).await;
    mcp.notify("notifications/initialized", json!({}));
    let tool_listing = mcp.request("tools/list", json!({})).await;
    let tools = tool_listing["result"]["tools"].as_array().unwrap().clone();
    for (action, inputs, reason) in &cases {
        let name = tools
            .iter()
            .find(|tool| tool["_meta"]["agent-access/action"] == *action)
            .unwrap()["name"]
            .clone();
        let response = mcp
            .request(
                "tools/call",
                json!({"name":name,"arguments":{"inputs":inputs}}),
            )
            .await;
        let result = &response["result"];
        assert_eq!(result["isError"], true, "{response}");
        assert_eq!(
            result["structuredContent"]["decision"], "deny",
            "{response}"
        );
        assert_eq!(
            result["structuredContent"]["reasonCode"], *reason,
            "{response}"
        );
    }
    mcp.finish().await;

    let audit = broker.audit().unwrap().text();
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for (action, _, reason) in &cases {
        let failures = records
            .iter()
            .filter(|record| record["service"] == "cloudbees_ci" && record["action"] == *action)
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 3, "{action}: {audit}");
        for record in failures {
            assert_eq!(record["decision"], "deny", "{record}");
            assert_eq!(record["reasonCode"], *reason, "{record}");
        }
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_downloads_require_access_to_the_requested_job() {
    let controller = MockServer::start().await;
    let temp = private_tempdir();
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let url = broker.public_url();
    for (command, action) in [
        ("log-download", "build.log.download"),
        ("tests-download", "build.tests.download"),
    ] {
        let output = temp.path().join(command);
        std::fs::write(&output, "keep existing content").unwrap();
        let denied = cli(&url)
            .args([
                "cloudbees-ci",
                "build",
                command,
                "team-ci",
                "private/other-job",
                "42",
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            !denied.status.success(),
            "{command} must require the requested job grant"
        );
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            "keep existing content"
        );
        let denied: Value = reqwest::Client::new()
            .post(format!("{url}/v1/invoke/cloudbees_ci/{action}"))
            .header("X-Agent-Access-Request-Id", format!("deny-{command}"))
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .json(&json!({"inputs":{"controller":"team-ci","job":"private/other-job","buildNumber":42}}))
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(denied["decision"], "deny", "{denied}");
    }
    assert!(controller.received_requests().await.unwrap().is_empty());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_resource_discovery_reports_job_inputs_and_namespace_coverage() {
    let controller = MockServer::start().await;
    let broker = start_broker(&Cloudbees {
        grants: Grants::JobAndFolder,
        ..Cloudbees::anonymous(&controller)
    })
    .await;
    let broker_url = broker.public_url();
    let listed = cli(&broker_url)
        .args(["resource-access", "describe", "--service", "cloudbees_ci"])
        .output()
        .unwrap();
    assert_success("resource-access describe", &listed);
    let description = serde_json::from_slice::<Value>(&listed.stdout).unwrap();
    assert_eq!(
        description["registeredResources"],
        json!({
            "source": "broker_configuration",
            "items": [{
                "id": "payments-job", "type": "cloudbees_ci_job", "value": "team-ci/payments/build-api",
                "inputs": {"controller": "team-ci", "job": JOB}
            }],
            "nextCursor": null
        })
    );
    assert_eq!(description["service"], "cloudbees_ci");
    assert_eq!(description["coverageSemantics"], "single_target");
    let job_access = description["access"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "job.view")
        .unwrap();
    assert_eq!(job_access["scope"], "resource");
    assert_eq!(job_access["resourceType"], "cloudbees_ci_job");
    assert!(
        job_access["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|coverage| {
                coverage
                    == &json!({
                        "selector": {"kind": "namespace", "value": "team-ci/payments"},
                        "inputs": {"controller": "team-ci"},
                        "restricted": false
                    })
            })
    );
    // An unregistered job inside the covered folder is usable as named.
    let actions = cli(&broker_url)
        .args([
            "actions",
            "list",
            "--service",
            "cloudbees_ci",
            "--resource",
            "team-ci/payments/deploy",
        ])
        .output()
        .unwrap();
    assert_success("actions list", &actions);
    assert_eq!(
        serde_json::from_slice::<Value>(&actions.stdout).unwrap()["actions"],
        json!(["job.view"])
    );
    assert!(controller.received_requests().await.unwrap().is_empty());
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_and_http_download_archived_artifact_with_bounded_metadata() {
    let controller = MockServer::start().await;
    mount_artifact(&controller).await;
    let temp = private_tempdir();
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let broker_url = broker.public_url();

    let list = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "build",
            "artifact",
            "list",
            "team-ci",
            JOB,
            "42",
        ])
        .output()
        .unwrap();
    assert_success("artifact list", &list);
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed["result"]["buildNumber"], 42);
    assert_eq!(
        listed["result"]["artifacts"],
        json!([{
            "artifactPath": ARTIFACT, "fileName": "tests.xml"
        }])
    );

    // A pasted build URL and a permalink reach the same build.
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/api/json"))
        .and(query_param(
            "tree",
            "fullName,_class,builds[number]{0,0},lastSuccessfulBuild[number]",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
            "fullName": JOB, "builds": [], "lastSuccessfulBuild": {"number": 42}
        })))
        .expect(1)
        .mount(&controller)
        .await;
    let build_url = format!(
        "{}/team-ci/job/payments/view/all/job/build-api/42/console",
        controller.uri()
    );
    for (label, args) in [
        (
            "artifact list by url",
            vec!["--job-url", build_url.as_str()],
        ),
        (
            "artifact list by selector",
            vec!["team-ci", JOB, "--build-selector", "lastSuccessfulBuild"],
        ),
    ] {
        let located = cli(&broker_url)
            .args(["cloudbees-ci", "build", "artifact", "list"])
            .args(&args)
            .output()
            .unwrap();
        assert_success(label, &located);
        let located: Value = serde_json::from_slice(&located.stdout).unwrap();
        assert_eq!(
            located["resourceScopes"], listed["resourceScopes"],
            "{label}"
        );
        assert_eq!(located["result"]["buildNumber"], 42, "{label}");
        assert_eq!(
            located["result"]["artifacts"], listed["result"]["artifacts"],
            "{label}"
        );
    }

    let destination = temp.path().join("downloaded.xml");
    let download = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "build",
            "artifact",
            "download",
            "team-ci",
            JOB,
            "42",
            "--artifact-path",
            ARTIFACT,
            "--output",
            destination.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("artifact download", &download);
    assert_eq!(std::fs::read(destination).unwrap(), ARTIFACT_BYTES);
    let downloaded: Value = serde_json::from_slice(&download.stdout).unwrap();
    assert_eq!(downloaded["result"]["artifactPath"], ARTIFACT);
    assert_eq!(downloaded["result"]["fileName"], "tests.xml");
    assert_eq!(downloaded["result"]["size"], ARTIFACT_BYTES.len());
    assert!(downloaded["result"].get("contentBase64").is_none());

    let raw = reqwest::Client::new()
        .post(format!(
            "{broker_url}/v1/invoke/cloudbees_ci/build.artifact.download"
        ))
        .header("X-Agent-Access-Request-Id", "cloudbees-smoke-raw")
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .json(&json!({"inputs":{
            "controller":"team-ci", "job":JOB, "buildNumber":42,
            "artifactPath":ARTIFACT
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), reqwest::StatusCode::OK);
    assert_eq!(
        raw.headers()[reqwest::header::CONTENT_TYPE],
        "application/xml"
    );
    let encoded = raw.headers()[RESULT_METADATA_HEADER].to_str().unwrap();
    let metadata: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["decision"], "allow");
    assert_eq!(metadata["result"]["artifactPath"], ARTIFACT);
    assert_eq!(raw.bytes().await.unwrap().as_ref(), ARTIFACT_BYTES);

    let mcp_temp = private_tempdir();
    let principal_token = mcp_temp.path().join("principal-token");
    std::fs::write(&principal_token, "ci-principal-token").unwrap();
    let mcp_broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let mcp_broker_url = mcp_broker.public_url();
    let client_config = mcp_temp.path().join("client.toml");
    std::fs::write(
        &client_config,
        format!(
            "[service]\nurl = {:?}\n[identity]\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\ntoken_file = {:?}\n",
            mcp_broker_url, principal_token.display().to_string()
        ),
    )
    .unwrap();
    let mut mcp = StdioMcp::start(&client_config);
    let initialized = mcp
        .request(
            "initialize",
            json!({
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"cloudbees-smoke","version":"1"}
            }),
        )
        .await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    mcp.notify("notifications/initialized", json!({}));
    let listed_tools = mcp.request("tools/list", json!({})).await;
    let tools = listed_tools["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("stdio tools/list failed: {listed_tools}"));
    let download_tool = tools
        .iter()
        .find(|tool| {
            tool["_meta"]["agent-access/service"] == "cloudbees_ci"
                && tool["_meta"]["agent-access/action"] == "build.artifact.download"
        })
        .expect("stdio MCP must expose artifact download");
    assert!(
        tools
            .iter()
            .any(|tool| { tool["_meta"]["agent-access/action"] == "build.artifact.list" })
    );
    let mcp_destination = mcp_temp.path().join("mcp.xml");
    let downloaded_tool = mcp
        .request(
            "tools/call",
            json!({
                "name":download_tool["name"],
                "arguments":{"inputs":{"controller":"team-ci","job":JOB,
                    "buildNumber":42,"artifactPath":ARTIFACT},
                    "outputPath":mcp_destination}
            }),
        )
        .await;
    assert_eq!(
        downloaded_tool["result"]["isError"], false,
        "{downloaded_tool}"
    );
    assert_eq!(std::fs::read(mcp_destination).unwrap(), ARTIFACT_BYTES);
    mcp.finish().await;
    stop(mcp_broker).await;

    let requests = controller.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path().ends_with("/artifact/reports/tests.xml"))
            .count(),
        3
    );
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_some())
    );
    let audit = broker.audit().unwrap();
    let phases = audit
        .require_request(
            "cloudbees-smoke-raw",
            "cloudbees_ci",
            "build.artifact.download",
        )
        .into_iter()
        .map(|record| record["providerAudit"]["streamPhase"].clone())
        .collect::<Vec<_>>();
    assert_eq!(phases, [json!("started"), json!("completed")]);
    // The typed CLI download writes the same two records.
    assert_eq!(
        audit
            .require_action("cloudbees_ci", "build.artifact.download")
            .len(),
        4
    );
    let audit = audit.text();
    assert!(!audit.contains("<testsuite"));
    assert!(!audit.contains("basic-secret"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_log_head_returns_cursor_and_trigger_returns_queue_receipt() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_bytes(vec![b'x'; 70_000]),
        )
        .mount(&controller)
        .await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/api/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fullName": JOB, "buildable": true, "property": []
        })))
        .mount(&controller)
        .await;
    Mock::given(method("POST"))
        .and(path("/team-ci/job/payments/job/build-api/build"))
        .respond_with(
            ResponseTemplate::new(201).insert_header("Location", "/team-ci/queue/item/17/"),
        )
        .mount(&controller)
        .await;
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let broker_url = broker.public_url();

    let excerpt = reqwest::Client::new()
        .post(format!(
            "{broker_url}/v1/invoke/cloudbees_ci/build.log.read"
        ))
        .header("X-Agent-Access-Request-Id", "cloudbees-smoke-head")
        .json(&json!({"inputs":{
            "controller":"team-ci", "job":JOB, "buildNumber":42,
            "mode":"head", "maxBytes":1024
        }}))
        .send()
        .await
        .unwrap();
    let excerpt: Value = excerpt.json().await.unwrap();
    assert_eq!(excerpt["decision"], "allow", "{excerpt}");
    assert_eq!(excerpt["result"]["text"], "x".repeat(1024));
    assert_eq!(excerpt["result"]["sourceStart"], 0);
    assert_eq!(excerpt["result"]["sourceEnd"], 1024);
    assert_eq!(excerpt["result"]["stopReason"], "output_limit");
    assert_eq!(excerpt["result"]["reachedEnd"], false);
    let cursor = excerpt["result"]["nextCursor"].as_str().unwrap();
    let continued = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "build",
            "log",
            "team-ci",
            JOB,
            "42",
            "--mode",
            "head",
            "--max-bytes",
            "1024",
            "--cursor",
            cursor,
        ])
        .output()
        .unwrap();
    assert_success("continued head", &continued);
    let continued: Value = serde_json::from_slice(&continued.stdout).unwrap();
    assert_eq!(continued["result"]["sourceStart"], 1024);
    assert_eq!(continued["result"]["sourceEnd"], 2048);
    assert_eq!(continued["result"]["text"], "x".repeat(1024));
    assert_ne!(continued["result"]["nextCursor"], cursor);

    let trigger = cli(&broker_url)
        .args(["cloudbees-ci", "build", "trigger", "team-ci", JOB])
        .output()
        .unwrap();
    assert_success("build trigger", &trigger);
    let triggered: Value = serde_json::from_slice(&trigger.stdout).unwrap();
    assert_eq!(triggered["result"]["queueId"], 17);
    assert_eq!(triggered["result"]["mutationStatus"], "applied");
    assert_eq!(triggered["result"]["retrySafe"], false);

    Mock::given(method("POST"))
        .and(path("/team-ci/job/payments/job/build-api/build"))
        .respond_with(ResponseTemplate::new(201))
        .with_priority(1)
        .mount(&controller)
        .await;
    let unverified = cli(&broker_url)
        .args(["cloudbees-ci", "build", "trigger", "team-ci", JOB])
        .output()
        .unwrap();
    assert_success("trigger without queue receipt", &unverified);
    let unverified: Value = serde_json::from_slice(&unverified.stdout).unwrap();
    assert_eq!(unverified["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(unverified["result"]["retrySafe"], false);
    assert_eq!(
        unverified["result"]["verificationStage"],
        "mutation_response"
    );
    // Safe locators are action inputs a caller can pass back.
    assert_eq!(
        unverified["result"]["safeLocators"],
        json!({"controller": "team-ci", "job": JOB})
    );

    let audit = broker.audit().unwrap();
    audit.require_request("cloudbees-smoke-head", "cloudbees_ci", "build.log.read");
    // The HTTP head read and the CLI continuation.
    assert_eq!(
        audit.require_action("cloudbees_ci", "build.log.read").len(),
        2
    );
    let audit = audit.text();
    assert!(!audit.contains(&"x".repeat(128)));
    assert!(!audit.contains(cursor));
    assert!(!audit.contains("basic-secret"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continued_log_read_is_denied_without_upstream_access_after_grant_revocation() {
    let controller = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("x".repeat(8192), "text/plain"))
        .expect(1)
        .mount(&controller)
        .await;
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let broker_url = broker.public_url();
    let client = reqwest::Client::new();
    let mut inputs =
        json!({"controller":"team-ci","job":JOB,"buildNumber":42,"mode":"head","maxBytes":1024});
    let first: Value = client
        .post(format!(
            "{broker_url}/v1/invoke/cloudbees_ci/build.log.read"
        ))
        .header("X-Agent-Access-Request-Id", "cloudbees-cursor-revocation")
        .json(&json!({"inputs":inputs}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["decision"], "allow", "{first}");
    let cursor = first["result"]["nextCursor"].as_str().unwrap();
    inputs["cursor"] = json!(cursor);

    let revoked = Cloudbees {
        grants: Grants::None,
        ..Cloudbees::anonymous(&controller)
    };
    broker
        .rewrite_config(revoked.document(broker.directory(), &broker.public_url()))
        .unwrap();
    let reloaded = broker.reload().await.unwrap();
    assert!(reloaded.is_success(), "{:?}", reloaded.message());
    let denied = client
        .post(format!(
            "{broker_url}/v1/invoke/cloudbees_ci/build.log.read"
        ))
        .header("X-Agent-Access-Request-Id", "cloudbees-cursor-revocation")
        .json(&json!({"inputs":inputs}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    let denied: Value = denied.json().await.unwrap();
    assert_eq!(denied["decision"], "deny");
    assert_ne!(
        denied["reasonCode"], "input_invalid",
        "authorization must precede cursor verification: {denied}"
    );
    assert_eq!(controller.received_requests().await.unwrap().len(), 1);
    let audit = broker.audit().unwrap();
    let decisions = audit
        .require_request(
            "cloudbees-cursor-revocation",
            "cloudbees_ci",
            "build.log.read",
        )
        .into_iter()
        .map(|record| record["decision"].clone())
        .collect::<Vec<_>>();
    assert_eq!(decisions, [json!("allow"), json!("deny")]);
    let audit = audit.text();
    assert!(!audit.contains(cursor));
    assert!(!audit.contains(&"x".repeat(128)));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_log_and_queue_without_auditing_log_or_other_jobs_queue_details() {
    let controller = MockServer::start().await;
    let log_text = "build output: log-secret-never-audit\n";
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_string(log_text),
        )
        .mount(&controller)
        .await;
    Mock::given(method("GET"))
        .and(path("/team-ci/queue/item/51/api/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":51, "task":{"fullName":JOB}, "blocked":false,
            "buildable":true, "cancelled":false, "stuck":false,
            "why":"waiting for an executor", "executable":{"number":42}
        })))
        .mount(&controller)
        .await;
    Mock::given(method("GET"))
        .and(path("/team-ci/queue/item/52/api/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":52, "task":{"fullName":"payments/other-job"},
            "why":"queue-secret-never-audit"
        })))
        .mount(&controller)
        .await;
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let broker_url = broker.public_url();

    let log = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "build",
            "log",
            "team-ci",
            JOB,
            "42",
            "--mode",
            "head",
            "--max-bytes",
            "1024",
        ])
        .output()
        .unwrap();
    assert_success("build log", &log);
    let log: Value = serde_json::from_slice(&log.stdout).unwrap();
    assert_eq!(log["result"]["text"], log_text);
    assert_eq!(log["result"]["sourceStart"], 0);
    assert_eq!(log["result"]["sourceEnd"], log_text.len());
    assert_eq!(log["result"]["reachedEnd"], true);
    let search = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "build",
            "log",
            "team-ci",
            JOB,
            "42",
            "--mode",
            "search",
            "--query",
            "log-secret-never-audit",
            "--max-matches",
            "2",
        ])
        .output()
        .unwrap();
    assert_success("search build log", &search);
    let search: Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search["result"]["mode"], "search");
    assert_eq!(search["result"]["matches"].as_array().unwrap().len(), 1);
    assert!(
        search["result"]["matches"][0]["text"]
            .as_str()
            .unwrap()
            .contains("log-secret-never-audit")
    );

    let queued = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "queue",
            "view",
            "team-ci",
            JOB,
            "--queue-id",
            "51",
        ])
        .output()
        .unwrap();
    assert_success("queue view", &queued);
    let queued: Value = serde_json::from_slice(&queued.stdout).unwrap();
    assert_eq!(queued["result"]["queueId"], 51);
    assert_eq!(queued["result"]["job"], JOB);
    assert_eq!(queued["result"]["buildable"], true);
    assert_eq!(queued["result"]["buildNumber"], 42);

    let other_job = cli(&broker_url)
        .args([
            "cloudbees-ci",
            "queue",
            "view",
            "team-ci",
            JOB,
            "--queue-id",
            "52",
        ])
        .output()
        .unwrap();
    assert!(!other_job.status.success());
    let other_job: Value = serde_json::from_slice(&other_job.stdout).unwrap();
    assert_eq!(other_job["decision"], "deny");
    assert_eq!(other_job["reasonCode"], "scope_unresolved");
    assert!(!other_job.to_string().contains("queue-secret-never-audit"));

    let requests = controller.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().any(|request| {
        request.url.path() == "/team-ci/job/payments/job/build-api/42/consoleText"
            && request.url.query().is_none()
    }));
    for queue_id in [51, 52] {
        assert!(requests.iter().any(|request| {
            request.url.path() == format!("/team-ci/queue/item/{queue_id}/api/json")
        }));
    }
    let audit = broker.audit().unwrap();
    audit.require_action("cloudbees_ci", "build.log.read");
    audit.require_action("cloudbees_ci", "queue.view");
    let audit = audit.text();
    assert!(audit.contains("\"reasonCode\":\"scope_unresolved\""));
    assert!(!audit.contains("log-secret-never-audit"));
    assert!(!audit.contains("queue-secret-never-audit"));
    assert!(!audit.contains("basic-secret"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_send_downloads_artifact_to_declared_file() {
    let controller = MockServer::start().await;
    mount_artifact(&controller).await;
    let temp = private_tempdir();
    let broker = start_broker(&Cloudbees::ci_agent(&controller)).await;
    let broker_url = broker.public_url();
    let destination = temp.path().join("sent.xml");
    let request = temp.path().join("download.json");
    std::fs::write(
        &request,
        serde_json::to_vec(&json!({
        "version":"agent-access.send.v1", "kind":"invoke", "responseMode":"stream",
            "service":"cloudbees_ci", "action":"build.artifact.download",
            "inputs":{"controller":"team-ci","job":JOB,"buildNumber":42,
                      "artifactPath":ARTIFACT},
            "output":{"type":"file","path":destination}
        }))
        .unwrap(),
    )
    .unwrap();
    let sent = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "--token-value",
            "ci-principal-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "send",
            "--request-file",
            request.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("JSON send artifact download", &sent);
    assert_eq!(std::fs::read(destination).unwrap(), ARTIFACT_BYTES);
    let metadata: Value = serde_json::from_slice(&sent.stdout).unwrap();
    assert_eq!(metadata["result"]["artifactPath"], ARTIFACT);
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_redirect_to_unapproved_origin_is_rejected_without_credentials_or_signed_url_in_audit()
 {
    let controller = MockServer::start().await;
    let outside = MockServer::start().await;
    let signed_url = format!("{}/private?signature=never-log-this", outside.uri());
    mount_artifact_list(&controller).await;
    Mock::given(method("GET"))
        .and(path(
            "/team-ci/job/payments/job/build-api/42/artifact/reports/tests.xml",
        ))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", signed_url.as_str()))
        .mount(&controller)
        .await;
    let broker = start_broker(&Cloudbees::anonymous(&controller)).await;
    let broker_url = broker.public_url();

    let denied = reqwest::Client::new()
        .post(format!(
            "{broker_url}/v1/invoke/cloudbees_ci/build.artifact.download"
        ))
        .header("X-Agent-Access-Request-Id", "cloudbees-smoke-redirect")
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .json(&json!({"inputs":{
            "controller":"team-ci", "job":JOB, "buildNumber":42,
            "artifactPath":ARTIFACT
        }}))
        .send()
        .await
        .unwrap();
    assert_ne!(denied.status(), reqwest::StatusCode::OK);
    assert!(outside.received_requests().await.unwrap().is_empty());
    let audit = broker.audit().unwrap();
    let rejected = audit.require_request(
        "cloudbees-smoke-redirect",
        "cloudbees_ci",
        "build.artifact.download",
    );
    assert_eq!(rejected.len(), 1);
    let audit = audit.text();
    assert!(!audit.contains("never-log-this"));
    assert!(!audit.contains("basic-secret"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_log_reads_work_through_http_and_stdio_mcp_with_bounded_wire_output() {
    let controller = MockServer::start().await;
    // Reproduce the reported 4,590,015-byte log, including JSON-escaped text.
    let mut log_bytes = vec![b'x'; 4_590_015];
    log_bytes[..8].copy_from_slice(b"BEGIN123");
    let tail = "\u{001b}\\\"\n".repeat(16_382) + "ERROR: finished\n";
    let tail_start = log_bytes.len() - tail.len();
    log_bytes[tail_start..].copy_from_slice(tail.as_bytes());
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(log_bytes.clone(), "text/plain"))
        .mount(&controller)
        .await;
    let temp = private_tempdir();
    let principal_token = temp.path().join("principal-token");
    std::fs::write(&principal_token, "mcp-ci-agent").unwrap();
    let broker = start_broker(&Cloudbees {
        callers: Callers::Principal {
            header: "Authorization",
            scheme: "Bearer",
            token: "mcp-ci-agent",
        },
        http_mcp: true,
        ..Cloudbees::anonymous(&controller)
    })
    .await;
    let broker_url = broker.public_url();
    let client = reqwest::Client::new();
    let endpoint = format!("{broker_url}/mcp");
    let initialize = client
        .post(&endpoint)
        .header(reqwest::header::AUTHORIZATION, "Bearer mcp-ci-agent")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"cloudbees-smoke","version":"1"}
            }}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(initialize.status(), reqwest::StatusCode::OK);
    let session = initialize.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mcp_http_body(initialize).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    let notification = client
        .post(&endpoint)
        .header(reqwest::header::AUTHORIZATION, "Bearer mcp-ci-agent")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(notification.status(), reqwest::StatusCode::ACCEPTED);
    let listing = client
        .post(&endpoint)
        .header(reqwest::header::AUTHORIZATION, "Bearer mcp-ci-agent")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(listing.status(), reqwest::StatusCode::OK);
    let listing = mcp_http_body(listing).await;
    let tools = listing["result"]["tools"].as_array().unwrap();
    assert!(
        tools
            .iter()
            .any(|tool| tool["_meta"]["agent-access/action"] == "build.artifact.list")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool["_meta"]["agent-access/action"] == "build.artifact.download")
    );
    for action in ["build.log.download", "build.tests.download"] {
        assert!(
            !tools
                .iter()
                .any(|tool| tool["_meta"]["agent-access/action"] == action)
        );
    }
    for action in [
        "build.pipeline.view",
        "build.tests.details",
        "build.pending-inputs.list",
    ] {
        assert!(
            tools
                .iter()
                .any(|tool| tool["_meta"]["agent-access/action"] == action)
        );
    }
    let log_tool = tools
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "build.log.read")
        .unwrap();
    assert_log_input_schema(&log_tool["inputSchema"]["properties"]["inputs"]);
    for (id, mode) in [(3, "head"), (4, "tail"), (5, "search")] {
        let mut inputs =
            json!({"controller":"team-ci","job":JOB,"buildNumber":42,"mode":mode,"maxBytes":65536});
        if mode == "search" {
            inputs["query"] = json!("ERROR:");
        }
        let response = client.post(&endpoint)
            .header(reqwest::header::AUTHORIZATION, "Bearer mcp-ci-agent")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-11-25")
            .json(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":log_tool["name"],"arguments":{"inputs":inputs}}}))
            .send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let wire = response.bytes().await.unwrap();
        assert!(
            wire.len() < 1024 * 1024,
            "encoded MCP response exceeded the configured wire budget"
        );
        let response = decode_mcp_http_body(std::str::from_utf8(&wire).unwrap());
        assert_eq!(response["result"]["isError"], false, "{response}");
        let result = &response["result"]["structuredContent"]["result"];
        assert_eq!(result["mode"], mode);
        match mode {
            "head" => {
                assert_eq!(
                    result["text"].as_str().unwrap().as_bytes(),
                    &log_bytes[..65536]
                );
                assert!(result["nextCursor"].is_string());
                assert_eq!(result["reachedEnd"], false);
            }
            "tail" => {
                assert_eq!(
                    result["text"].as_str().unwrap().as_bytes(),
                    &log_bytes[log_bytes.len() - 65536..]
                );
                assert_eq!(result["sourceEnd"], log_bytes.len());
                assert_eq!(result["scannedBytes"], log_bytes.len());
                assert_eq!(result["reachedEnd"], true);
                // Both the structured content and textual JSON copy must be counted.
                assert!(wire.len() > 3 * 65536);
            }
            "search" => {
                assert_eq!(result["matches"].as_array().unwrap().len(), 1);
                assert!(
                    result["matches"][0]["text"]
                        .as_str()
                        .unwrap()
                        .contains("ERROR: finished")
                );
                assert_eq!(result["reachedEnd"], true);
            }
            _ => unreachable!(),
        }
    }

    let config_path = temp.path().join("client.toml");
    std::fs::write(&config_path, format!("[service]\nurl = {:?}\n[identity]\nheader = \"Authorization\"\nscheme = \"Bearer\"\ntoken_file = {:?}\n", broker_url, principal_token.display().to_string())).unwrap();
    let mut stdio = StdioMcp::start(&config_path);
    stdio.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"large-log-smoke","version":"1"}})).await;
    stdio.notify("notifications/initialized", json!({}));
    let listing = stdio.request("tools/list", json!({})).await;
    let stdio_tool = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["_meta"]["agent-access/action"] == "build.log.read")
        .unwrap();
    assert_log_input_schema(&stdio_tool["inputSchema"]["properties"]["inputs"]);
    let response = stdio.request("tools/call", json!({"name":stdio_tool["name"],"arguments":{"inputs":{"controller":"team-ci","job":JOB,"buildNumber":42,"maxBytes":65536}}})).await;
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["result"]["text"]
            .as_str()
            .unwrap()
            .as_bytes(),
        &log_bytes[log_bytes.len() - 65536..]
    );
    let encoded = serde_json::to_vec(&response).unwrap();
    assert!(encoded.len() > 3 * 65536 && encoded.len() < 1024 * 1024);
    stdio.finish().await;

    for command in ["catalog", "openapi", "send-schema"] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .arg("--config")
            .arg(&config_path)
            .args(["spec", command])
            .output()
            .unwrap();
        assert_success(command, &output);
        let spec: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            verify_log_schemas(&spec) > 0,
            "{command} is missing the log input schema"
        );
    }
    let audit = broker.audit().unwrap();
    audit.require_action("cloudbees_ci", "build.log.read");
    let audit = audit.text();
    assert!(!audit.contains("BEGIN123"));
    assert!(!audit.contains("ERROR:"));
    assert!(!audit.contains("basic-secret"));
    stop(broker).await;
}

fn assert_log_input_schema(schema: &Value) {
    let properties = &schema["properties"];
    assert_eq!(
        properties["mode"]["enum"],
        json!(["head", "tail", "search"])
    );
    assert_eq!(properties["mode"]["default"], "tail");
    assert_eq!(properties["maxBytes"]["minimum"], 1024);
    assert_eq!(properties["maxBytes"]["maximum"], 65536);
    assert_eq!(properties["maxBytes"]["default"], 16384);
    assert!(properties.get("cursor").is_some());
    assert!(properties.get("query").is_some());
    assert!(properties.get("maxMatches").is_some());
    assert!(properties.get("offset").is_none());
}

fn verify_log_schemas(value: &Value) -> usize {
    if value["action"] == "build.log.read" && value.get("readOnly").is_some() {
        assert_eq!(value["readOnly"], true);
    }
    let mut count = 0;
    if value["properties"].get("maxBytes").is_some()
        && value["properties"].get("buildNumber").is_some()
        && value["properties"].get("controller").is_some()
    {
        assert_log_input_schema(value);
        count += 1;
    }
    match value {
        Value::Object(object) => count += object.values().map(verify_log_schemas).sum::<usize>(),
        Value::Array(array) => count += array.iter().map(verify_log_schemas).sum::<usize>(),
        _ => {}
    }
    count
}

async fn mcp_http_body(response: reqwest::Response) -> Value {
    decode_mcp_http_body(&response.text().await.unwrap())
}

fn decode_mcp_http_body(body: &str) -> Value {
    if body.trim_start().starts_with('{') {
        return serde_json::from_str(body).unwrap();
    }
    let responses = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("id").is_some())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 1, "{body}");
    responses.into_iter().next().unwrap()
}

async fn mount_artifact(controller: &MockServer) {
    mount_artifact_list(controller).await;
    Mock::given(method("GET"))
        .and(path(
            "/team-ci/job/payments/job/build-api/42/artifact/reports/tests.xml",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/xml")
                .set_body_bytes(ARTIFACT_BYTES),
        )
        .mount(controller)
        .await;
}

async fn mount_artifact_list(controller: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/team-ci/job/payments/job/build-api/42/api/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "number":42,
            "artifacts":[{"relativePath":ARTIFACT,"fileName":"tests.xml"}]
        })))
        .mount(controller)
        .await;
}

/// Starts the broker assembly on `cloudbees`' configuration.
async fn start_broker(cloudbees: &Cloudbees<'_>) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    // The listener is already bound, so HTTP MCP can name its address.
    let document = cloudbees.document(application.directory(), &application.public_url());
    application.config_document(document).start().await.unwrap()
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

/// Who may call the broker, and so who holds its CloudBees CI grants.
#[derive(Clone, Copy)]
enum Callers {
    /// Anonymous callers.
    Anonymous,
    /// Only the static principal `ci-agent`, presenting `token` in `header`
    /// with `scheme`.
    Principal {
        header: &'static str,
        scheme: &'static str,
        token: &'static str,
    },
}

/// The CloudBees CI grants the configuration gives its callers.
#[derive(Clone, Copy)]
enum Grants {
    /// Every action the smokes call, on the `payments-job` resource.
    Job,
    /// As [`Self::Job`], and `job.view` on the `payments-folder` namespace
    /// resource `team-ci/payments`.
    JobAndFolder,
    /// None: the job grant is revoked.
    None,
}

/// A smoke's broker configuration: the `team-ci` controller served by
/// `controller` with its service credential, the `payments-job` resource,
/// the grants, and JSONL audit in `audit.jsonl`.
struct Cloudbees<'a> {
    controller: &'a MockServer,
    callers: Callers,
    grants: Grants,
    /// `providers.cloudbees_ci.max_log_scan_bytes`.
    max_log_scan_bytes: u64,
    /// Serves HTTP MCP at the public listener's `/mcp`, with 1 MiB responses.
    http_mcp: bool,
}

impl<'a> Cloudbees<'a> {
    /// Anonymous callers hold the job grant.
    fn anonymous(controller: &'a MockServer) -> Self {
        Self {
            controller,
            callers: Callers::Anonymous,
            grants: Grants::Job,
            max_log_scan_bytes: 16 * 1024 * 1024,
            http_mcp: false,
        }
    }

    /// Only `ci-agent`, with the raw `X-Agent-Access-Identity-Token`
    /// `ci-principal-token`, holds the job grant.
    fn ci_agent(controller: &'a MockServer) -> Self {
        Self {
            callers: Callers::Principal {
                header: "X-Agent-Access-Identity-Token",
                scheme: "raw",
                token: "ci-principal-token",
            },
            ..Self::anonymous(controller)
        }
    }

    /// The configuration document, writing its secrets to `directory`, for a
    /// broker listening at `public_url`.
    fn document(&self, directory: &FixtureDir, public_url: &str) -> String {
        let controller = self.controller.uri();
        let (identity, subject) = match self.callers {
            Callers::Anonymous => (
                r#"
[identity]
mode = "anonymous"
authority = "toml"
"#
                .to_string(),
                "group:anonymous",
            ),
            Callers::Principal {
                header,
                scheme,
                token,
            } => (
                format!(
                    r#"
[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = {header}
scheme = {scheme}

[[identity.sources.principals]]
principal = "ci-agent"
token_refs = [{token}]
"#,
                    header = toml_string(header),
                    scheme = toml_string(scheme),
                    token = secret_ref(directory, "principal-token", token),
                ),
                "user:ci-agent",
            ),
        };
        let mut document = format!(
            r#"{identity}
[credentials.service.cloudbees_ci]
type = "basic_api_token"
username_ref = {username}
token_ref = {token}

[providers.cloudbees_ci]
max_log_scan_bytes = {max_log_scan_bytes}
allowed_upstream_hosts = [{allowed}]

[providers.cloudbees_ci.controllers.team-ci]
base_url = {base_url}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "payments-job"
resource_type = "{resource_type}"
selector = {{ kind = "exact", value = "team-ci/payments/build-api" }}
allowed_execution_contexts = ["default"]

[limits]
upload_spool_dir = {spool}

[audit]
type = "jsonl"
path = {audit}
"#,
            username = secret_ref(directory, "username", "automation"),
            token = secret_ref(directory, "token", "basic-secret"),
            max_log_scan_bytes = self.max_log_scan_bytes,
            allowed = toml_string(format_args!("{controller}/team-ci/**")),
            base_url = toml_string(format_args!("{controller}/team-ci/")),
            resource_type = CLOUDBEES_CI_JOB_RESOURCE.id().as_str(),
            spool = toml_string(directory.join("upload-spool").display()),
            audit = toml_string(directory.join("audit.jsonl").display()),
        );
        if let Grants::Job | Grants::JobAndFolder = self.grants {
            document.push_str(&format!(
                r#"
[[policy.grants]]
subjects = [{subject}]
service = "cloudbees_ci"
actions = [
    "build.artifact.list",
    "build.artifact.download",
    "build.log.read",
    "build.log.download",
    "build.tests.download",
    "build.tests.details",
    "build.pipeline.view",
    "build.pipeline.node.view",
    "build.pipeline.node.log.read",
    "build.pending-inputs.list",
    "queue.view",
    "build.trigger",
]
resources = {{ resource_ids = ["payments-job"] }}
credential_mode = "service"
"#,
                subject = toml_string(subject),
            ));
        }
        if let Grants::JobAndFolder = self.grants {
            document.push_str(&format!(
                r#"
[[policy.resources]]
id = "payments-folder"
resource_type = "{resource_type}"
selector = {{ kind = "namespace", value = "team-ci/payments" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = [{subject}]
service = "cloudbees_ci"
actions = ["job.view"]
resources = {{ resource_ids = ["payments-folder"] }}
credential_mode = "service"
"#,
                resource_type = CLOUDBEES_CI_JOB_RESOURCE.id().as_str(),
                subject = toml_string(subject),
            ));
        }
        if self.http_mcp {
            document.push_str(&format!(
                r#"
[mcp]
enabled = true
public_url = {public_url}
max_response_bytes = 1048576
"#,
                public_url = toml_string(format_args!("{public_url}/mcp")),
            ));
        }
        document
    }
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A `file:` secret reference to a new private file in `directory`.
fn secret_ref(directory: &FixtureDir, name: &str, contents: &str) -> String {
    let path = directory.secret_file(name, contents).unwrap();
    toml_string(format_args!("file:{}", path.display()))
}

fn cli(broker_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args(["--url", broker_url, "--no-token"]);
    command
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: tokio::sync::mpsc::UnboundedReceiver<String>,
    next_id: u64,
}

impl StdioMcp {
    fn start(config: &std::path::Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        let mut child = command
            .arg("--config")
            .arg(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
            next_id: 1,
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc":"2.0","method":method,"params":params}));
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let line = self.responses.recv().await.expect("stdio MCP closed");
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["id"] == id {
                    return value;
                }
                assert!(
                    value.get("id").is_none(),
                    "unexpected MCP response: {value}"
                );
            }
        })
        .await
        .expect("stdio MCP response timed out")
    }

    async fn finish(mut self) {
        self.stdin.take();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "stdio MCP failed: {status}");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stdio MCP did not exit");
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
