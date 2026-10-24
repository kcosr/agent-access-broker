use super::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn settings(url: String, request_timeout_ms: u64) -> ResolvedCliSettings {
    ResolvedCliSettings {
        url,
        request_timeout_ms,
        tls: Default::default(),
        token: None,
        token_from_literal_arg: false,
        identity_header: "X-Agent-Access-Identity-Token".into(),
        identity_scheme: "raw".into(),
        allow_insecure_broker_http: false,
        read_content_format: Default::default(),
        output_format: Default::default(),
    }
}

fn allowed() -> serde_json::Value {
    serde_json::json!({"agentRequestId":"agent", "brokerRequestId":"broker", "decision":"allow", "result":{}})
}

#[test]
fn request_timeout_resolution_uses_config_and_default_without_new_options() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.toml");
    let cli = Cli::try_parse_from([
        "agent-access",
        "--config",
        config.to_str().unwrap(),
        "--no-token",
        "services",
        "describe",
        "fake",
    ])
    .unwrap();
    for (source, expected) in [
        ("[service]\nurl='http://127.0.0.1:8787'", 30_000),
        (
            "[service]\nurl='http://127.0.0.1:8787'\nrequest_timeout_ms=125000",
            125_000,
        ),
    ] {
        fs::write(&config, source).unwrap();
        let resolved = resolve_cli_settings(&cli, &config).unwrap();
        assert_eq!(resolved.request_timeout(), Duration::from_millis(expected));
    }
    fs::write(&config, "[service]\nrequest_timeout_ms=0").unwrap();
    assert!(
        resolve_cli_settings(&cli, &config)
            .unwrap_err()
            .downcast_ref::<ConfigError>()
            .unwrap()
            .errors()
            .iter()
            .any(|message| message.contains("request_timeout_ms"))
    );
    assert!(
        Cli::try_parse_from([
            "agent-access",
            "--request-timeout-ms",
            "1000",
            "services",
            "list"
        ])
        .is_err()
    );
}

#[tokio::test]
async fn request_timeout_applies_to_cli_json_upload_and_download_headers_without_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(allowed())
                .set_delay(Duration::from_secs(1)),
        )
        .expect(3)
        .mount(&server)
        .await;
    let resolved = settings(server.uri(), 100);
    let context = CliContext {
        settings: &resolved,
        output: None,
    };
    let json_error = send_invoke_parts_with_options(
        &context,
        "fake",
        "echo",
        serde_json::json!({}),
        ResponseOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(json_error.to_string(), INVOCATION_TIMEOUT_MESSAGE);
    let upload_error = send_invoke_multipart(
        &context,
        "fake.echo",
        reqwest::multipart::Form::new().text("request", "{}"),
    )
    .await
    .unwrap_err();
    assert_eq!(upload_error.to_string(), INVOCATION_TIMEOUT_MESSAGE);
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("download");
    fs::write(&destination, "original").unwrap();
    let download_error = send_download_parts(
        &context,
        "fake",
        "echo",
        serde_json::json!({}),
        &destination,
        None,
        &[],
    )
    .await
    .unwrap_err()
    .into_error();
    assert_eq!(download_error.to_string(), INVOCATION_TIMEOUT_MESSAGE);
    assert_eq!(fs::read_to_string(destination).unwrap(), "original");
    server.verify().await;
}

#[cfg(unix)]
#[tokio::test]
async fn request_timeout_includes_sending_a_slow_upload_body() {
    use std::os::fd::OwnedFd;
    for stdio in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(allowed()))
            .expect(0)
            .mount(&server)
            .await;
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = writer.write_all(b"file");
        });
        let file = tokio::fs::File::from_std(std::fs::File::from(OwnedFd::from(reader)));
        let form = reqwest::multipart::Form::new().part(
            "upload",
            reqwest::multipart::Part::stream_with_length(reqwest::Body::from(file), 4),
        );
        let resolved = settings(server.uri(), 100);
        let error = if stdio {
            mcp::tools::mcp_http_client(&resolved, false)
                .unwrap()
                .post(format!("{}/v1/invoke/fake/echo", resolved.url))
                .multipart(form)
                .send()
                .await
                .map_err(|error| invocation_request_error(error, "broker upload request failed"))
                .unwrap_err()
        } else {
            send_invoke_multipart(
                &CliContext {
                    settings: &resolved,
                    output: None,
                },
                "fake.echo",
                form,
            )
            .await
            .unwrap_err()
        };
        assert_eq!(error.to_string(), INVOCATION_TIMEOUT_MESSAGE);
        writer.join().unwrap();
        server.verify().await;
    }
}

#[tokio::test]
async fn request_timeout_can_allow_a_longer_request_without_changing_discovery_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(allowed())
                .set_delay(Duration::from_millis(200)),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({}))
                .set_delay(Duration::from_secs(1)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut resolved = settings(server.uri(), 2000);
    let context = CliContext {
        settings: &resolved,
        output: None,
    };
    let response = send_invoke_parts_with_options(
        &context,
        "fake",
        "echo",
        serde_json::json!({}),
        ResponseOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.0, 200);
    resolved.request_timeout_ms = 100;
    let error = discovery::service_describe(&resolved, "fake")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "broker discovery request failed");
    assert!(!error.contains("mutation"));
    server.verify().await;
}

/// A transport fixture that sends headers immediately, then delays its body.
/// This is not a Broker fixture; it isolates the client deadline contract.
pub(crate) async fn delayed_body_server(
    content_type: &str,
    extra_headers: &str,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
        body.len()
    );
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 8192];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 65536);
        }
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let content_length = std::str::from_utf8(&request[..header_end])
            .unwrap()
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(content_length <= 65536);
        while request.len() < header_end + content_length {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
        }
        stream.write_all(headers.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The timeout cases deliberately close the response before this write.
        let _ = stream.write_all(&body).await;
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn request_timeout_includes_json_body_but_preserves_download_body_idle_budget() {
    let (url, task) = delayed_body_server(
        "application/json",
        "",
        serde_json::to_vec(&allowed()).unwrap(),
    )
    .await;
    let resolved = settings(url, 100);
    let context = CliContext {
        settings: &resolved,
        output: None,
    };
    let error = send_invoke_parts_with_options(
        &context,
        "fake",
        "echo",
        serde_json::json!({}),
        ResponseOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), INVOCATION_TIMEOUT_MESSAGE);
    task.await.unwrap();

    let metadata = serde_json::json!({"agentRequestId":"agent", "brokerRequestId":"broker", "decision":"allow", "result":{"size":3,"sha256":format!("{:x}", Sha256::digest(b"abc")),"mutationStatus":"applied_unverified","retrySafe":false}});
    let header = format!(
        "{RESULT_METADATA_HEADER}: {}\r\n",
        BASE64.encode(serde_json::to_vec(&metadata).unwrap())
    );
    let (url, task) =
        delayed_body_server("application/octet-stream", &header, b"abc".to_vec()).await;
    let resolved = settings(url, 100);
    let context = CliContext {
        settings: &resolved,
        output: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("download");
    let (status, receipt) = send_download_parts(
        &context,
        "fake",
        "echo",
        serde_json::json!({}),
        &destination,
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(receipt["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(receipt["result"]["retrySafe"], false);
    assert_eq!(fs::read(destination).unwrap(), b"abc");
    assert_eq!(CLI_STREAMING_IDLE_TIMEOUT, Duration::from_secs(30));
    task.await.unwrap();
}
