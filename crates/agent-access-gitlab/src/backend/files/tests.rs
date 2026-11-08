use super::*;
use agent_access_provider::test_support::bearer_credential;
use futures_util::StreamExt;
use reqwest::header::HeaderValue;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BLOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTENT_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn headers(file_path: &str, size: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-gitlab-file-name", file_path.rsplit('/').next().unwrap()),
        ("x-gitlab-file-path", file_path),
        ("x-gitlab-commit-id", COMMIT),
        ("x-gitlab-blob-id", BLOB),
        ("x-gitlab-last-commit-id", COMMIT),
        ("x-gitlab-content-sha256", CONTENT_HASH),
        ("x-gitlab-ref", "main"),
        ("x-gitlab-execute-filemode", "false"),
    ] {
        headers.insert(name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
    }
    headers.insert("x-gitlab-size", size.into());
    headers
}

fn response(file_path: &str, size: u64) -> ResponseTemplate {
    headers(file_path, size)
        .iter()
        .fold(ResponseTemplate::new(200), |response, (name, value)| {
            response.insert_header(name.clone(), value.clone())
        })
}

fn backend(base: &str) -> HttpGitlabBackend {
    let config = GitlabProviderConfig {
        provisioning: GitlabProvisioningConfig::default(),
        api_base_url: format!("{base}/api/v4"),
        web_base_url: base.to_string(),
        egress_proxy: None,
        allowed_upstream_hosts: vec![format!("{base}/api/v4/**")],
        webhooks: GitlabWebhooksConfig::default(),
        attachments: GitlabUploadLimitsConfig::default(),
        content: GitlabContentConfig::default(),
        search: GitlabSearchConfig::default(),
    };
    HttpGitlabBackend::for_tests(config, ProviderLimits::default()).unwrap()
}

fn credential() -> GitlabCredential {
    GitlabCredential::from_static(bearer_credential("execution-token"))
}

fn request(file_path: &str) -> GitlabFileRequest {
    GitlabFileRequest {
        path: file_path.to_string(),
        ref_name: "main".to_string(),
    }
}

async fn collect(stream: ProviderResultStream) -> Result<Vec<u8>, ProviderStreamError> {
    match stream.source {
        ProviderResultStreamSource::Memory(bytes) => Ok(bytes),
        ProviderResultStreamSource::Stream(stream) => {
            let mut stream = stream.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk?);
            }
            Ok(bytes)
        }
    }
}

#[test]
fn metadata_preserves_unicode_and_accepts_optional_headers_absent() {
    let path = "docs/設置.md";
    let mut values = headers(path, 3);
    values.insert(
        "x-gitlab-ref",
        HeaderValue::from_bytes("分支".as_bytes()).unwrap(),
    );
    let metadata = file_metadata_from_headers(&values, path).unwrap();
    assert_eq!(metadata.file_name, "設置.md");
    assert_eq!(metadata.file_path, path);
    assert_eq!(metadata.ref_name.as_deref(), Some("分支"));
    assert_eq!(metadata.commit_id, COMMIT);
    assert_eq!(metadata.content_sha256.as_deref(), Some(CONTENT_HASH));
    for name in [
        "x-gitlab-ref",
        "x-gitlab-blob-id",
        "x-gitlab-last-commit-id",
        "x-gitlab-content-sha256",
        "x-gitlab-execute-filemode",
    ] {
        values.remove(name);
    }
    let metadata = file_metadata_from_headers(&values, path).unwrap();
    assert!(metadata.ref_name.is_none());
    assert!(metadata.blob_id.is_none());
    assert!(metadata.last_commit_id.is_none());
    assert!(metadata.content_sha256.is_none());
    assert!(metadata.execute_filemode.is_none());
}

#[test]
fn metadata_rejects_missing_duplicated_or_malformed_values_without_echoing_them() {
    for name in [
        "x-gitlab-file-name",
        "x-gitlab-file-path",
        "x-gitlab-size",
        "x-gitlab-commit-id",
    ] {
        let mut missing = headers("README.md", 3);
        missing.remove(name);
        assert!(
            file_metadata_from_headers(&missing, "README.md").is_err(),
            "{name}"
        );
    }
    for name in FILE_HEADERS
        .iter()
        .filter(|name| !name.starts_with("content-"))
    {
        let mut duplicates = headers("README.md", 3);
        duplicates.append(*name, duplicates[*name].clone());
        assert!(
            file_metadata_from_headers(&duplicates, "README.md").is_err(),
            "{name}"
        );
    }
    for (name, value) in [
        ("x-gitlab-size", "+3"),
        ("x-gitlab-size", "-1"),
        ("x-gitlab-size", "18446744073709551616"),
        ("x-gitlab-commit-id", "abcdef1"),
        ("x-gitlab-blob-id", "PRIVATE_HEADER_VALUE"),
        ("x-gitlab-last-commit-id", "PRIVATE_HEADER_VALUE"),
        ("x-gitlab-content-sha256", "PRIVATE_HEADER_VALUE"),
        ("x-gitlab-execute-filemode", "1"),
        ("x-gitlab-ref", "private\tref"),
        ("x-gitlab-file-name", "different.md"),
    ] {
        let mut invalid = headers("README.md", 3);
        invalid.insert(name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
        let error = file_metadata_from_headers(&invalid, "README.md").unwrap_err();
        assert!(matches!(error, GitlabBackendError::Protocol(_)));
        assert!(!error.to_string().contains("PRIVATE_HEADER_VALUE"));
    }
    let mut invalid = headers("README.md", 3);
    invalid.insert("x-gitlab-ref", HeaderValue::from_bytes(b"\xff").unwrap());
    assert!(file_metadata_from_headers(&invalid, "README.md").is_err());
    assert!(file_metadata_from_headers(&headers("other.md", 3), "README.md").is_err());
}

#[test]
fn metadata_bounds_combined_headers_including_content_type() {
    let mut values = headers("README.md", 3);
    values.insert(
        "content-type",
        HeaderValue::from_bytes(&vec![b'a'; GITLAB_FILE_METADATA_MAX_BYTES]).unwrap(),
    );
    assert!(file_metadata_from_headers(&values, "README.md").is_err());
}

#[tokio::test]
async fn head_reads_metadata_with_execution_authority_without_interpreting_body_length() {
    let server = MockServer::start().await;
    let path_value = "docs/設置.md";
    Mock::given(method("HEAD"))
        .and(path(
            "/api/v4/projects/42/repository/files/docs%2F%E8%A8%AD%E7%BD%AE.md",
        ))
        .and(query_param("ref", "main"))
        .and(header("Authorization", "Bearer execution-token"))
        .respond_with(
            response(path_value, 9_000_000_000).insert_header("Content-Length", "123456789"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = backend(&server.uri())
        .file_metadata(42, request(path_value), &credential())
        .await
        .unwrap();
    assert_eq!(result.value.size, 9_000_000_000);
    assert_eq!(result.value.file_path, path_value);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn raw_response_has_one_identity_and_preserves_bytes_without_using_transformed_hash() {
    let server = MockServer::start().await;
    let bytes = b"\xff\xfeh\0i\0".to_vec();
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/repository/files/README.md/raw"))
        .and(query_param("ref", "main"))
        .and(header("Authorization", "Bearer execution-token"))
        .and(header("Accept-Encoding", "identity"))
        .respond_with(response("README.md", bytes.len() as u64).set_body_bytes(bytes.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let result = backend(&server.uri())
        .raw_file("file.view", 42, request("README.md"), 100, &credential())
        .await
        .unwrap();
    assert_eq!(result.value.metadata.commit_id, COMMIT);
    assert_eq!(result.value.metadata.blob_id.as_deref(), Some(BLOB));
    assert_eq!(
        result.value.metadata.content_sha256.as_deref(),
        Some(CONTENT_HASH)
    );
    assert_eq!(collect(result.value.stream.unwrap()).await.unwrap(), bytes);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn raw_rejects_invalid_success_status_missing_headers_and_mismatched_lengths() {
    for template in [
        ResponseTemplate::new(204),
        ResponseTemplate::new(206),
        ResponseTemplate::new(200).set_body_string("abc"),
        response("README.md", 4).set_body_string("abc"),
        response("README.md", 3)
            .insert_header("Content-Encoding", "gzip")
            .set_body_string("abc"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(template)
            .mount(&server)
            .await;
        let error = backend(&server.uri())
            .raw_file(
                "file.raw.download",
                42,
                request("README.md"),
                100,
                &credential(),
            )
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, GitlabBackendError::Protocol(_)),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn head_preserves_http_failures_without_json_fallback() {
    for (status, expected) in [
        (401, GitlabBackendError::Unauthorized),
        (403, GitlabBackendError::Forbidden),
        (404, GitlabBackendError::NotFound),
        (405, GitlabBackendError::HttpStatus(405)),
        (302, GitlabBackendError::HttpStatus(302)),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let error = backend(&server.uri())
            .file_metadata(42, request("README.md"), &credential())
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn raw_stream_rejects_incomplete_or_excess_bytes_without_content_length() {
    use std::io::{Read, Write};
    for body in ["abc", "abcde"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut received = Vec::new();
            let mut buffer = [0; 1024];
            while !received.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                received.extend_from_slice(&buffer[..count]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Gitlab-File-Name: README.md\r\nX-Gitlab-File-Path: README.md\r\nX-Gitlab-Size: 4\r\nX-Gitlab-Commit-Id: {COMMIT}\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });
        let response = backend(&format!("http://{address}"))
            .raw_file(
                "file.raw.download",
                42,
                request("README.md"),
                4,
                &credential(),
            )
            .await
            .unwrap();
        let error = collect(response.value.stream.unwrap()).await.unwrap_err();
        assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
        worker.join().unwrap();
    }
}

/// No body is made available until the caller has finished, so a test cannot
/// pass by buffering or draining the declared oversized response.
#[tokio::test]
async fn oversized_response_returns_metadata_before_any_body_is_available() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (finish, finished) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 1024];
        while !received.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = socket.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            received.extend_from_slice(&buffer[..count]);
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nX-Gitlab-File-Name: README.md\r\nX-Gitlab-File-Path: README.md\r\nX-Gitlab-Size: 1000000\r\nX-Gitlab-Commit-Id: {COMMIT}\r\n\r\n"
        );
        socket.write_all(head.as_bytes()).unwrap();
        socket.flush().unwrap();
        let _ = finished.recv_timeout(Duration::from_secs(5));
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        backend(&format!("http://{address}")).raw_file(
            "file.view",
            42,
            request("README.md"),
            4,
            &credential(),
        ),
    )
    .await;
    finish.send(()).unwrap();
    worker.join().unwrap();
    let response = result
        .expect("metadata must return without reading the body")
        .unwrap();
    assert_eq!(response.value.metadata.size, 1_000_000);
    assert!(response.value.stream.is_none());
}
