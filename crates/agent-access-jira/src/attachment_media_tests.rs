use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn policy(allow: &[&str], deny: &[&str]) -> MediaTypePolicyConfig {
    MediaTypePolicyConfig {
        allow: allow.iter().map(|value| (*value).to_string()).collect(),
        deny: deny.iter().map(|value| (*value).to_string()).collect(),
    }
}

fn download_request() -> ProviderInvocation {
    InvocationBuilder::new("jira", "attachment.download")
        .inputs(json!({"issue": "PROJ-1", "attachmentId": "10055"}))
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .build()
}

#[tokio::test]
async fn download_media_policy_checks_both_declarations_before_reading_bytes() {
    struct Case {
        name: &'static str,
        policy: MediaTypePolicyConfig,
        metadata: &'static str,
        response: &'static str,
        allowed: bool,
        content_requests: usize,
    }
    let cases = [
        Case {
            name: "default permits ordinary files",
            policy: Default::default(),
            metadata: "application/pdf",
            response: "application/pdf",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "default permits distinct concrete types",
            policy: Default::default(),
            metadata: "application/zip",
            response: "application/x-zip-compressed",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "wildcards normalize case and parameters",
            policy: policy(&["IMAGE/*"], &[]),
            metadata: "Image/PNG; name=picture",
            response: "image/png",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "metadata exclusion wins",
            policy: policy(&["*/*"], &["image/*"]),
            metadata: "image/png",
            response: "application/octet-stream",
            allowed: false,
            content_requests: 0,
        },
        Case {
            name: "response exclusion wins",
            policy: policy(&["*/*"], &["text/html"]),
            metadata: "text/plain",
            response: "text/html; charset=utf-8",
            allowed: false,
            content_requests: 1,
        },
        Case {
            name: "empty allow denies before request",
            policy: policy(&[], &[]),
            metadata: "application/octet-stream",
            response: "text/plain",
            allowed: false,
            content_requests: 0,
        },
        Case {
            name: "universal deny rejects unknown before request",
            policy: policy(&["*/*"], &["*/*"]),
            metadata: "",
            response: "text/plain",
            allowed: false,
            content_requests: 0,
        },
        Case {
            name: "generic response uses allowed metadata",
            policy: policy(&["application/pdf"], &[]),
            metadata: "application/pdf",
            response: "application/octet-stream",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "generic metadata waits for response",
            policy: policy(&["application/pdf"], &[]),
            metadata: "application/octet-stream",
            response: "application/pdf",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "empty metadata waits for response",
            policy: policy(&["text/*"], &[]),
            metadata: "",
            response: "text/plain",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "unknown deny permits concrete metadata",
            policy: policy(&["application/pdf"], &["application/octet-stream"]),
            metadata: "application/pdf",
            response: "application/octet-stream",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "unknown deny rejects wholly unspecified",
            policy: policy(&["*/*"], &["application/octet-stream"]),
            metadata: "application/octet-stream",
            response: "",
            allowed: false,
            content_requests: 1,
        },
        Case {
            name: "unknown allow accepts wholly unspecified",
            policy: policy(&["application/octet-stream"], &[]),
            metadata: "",
            response: "application/octet-stream",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "all concrete types must be allowed",
            policy: policy(&["application/pdf"], &[]),
            metadata: "application/pdf",
            response: "image/png",
            allowed: false,
            content_requests: 1,
        },
        Case {
            name: "different allowed concrete types accepted",
            policy: policy(&["application/*"], &[]),
            metadata: "application/zip",
            response: "application/x-zip-compressed",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "malformed metadata denied before request",
            policy: policy(&["*/*"], &["text/html"]),
            metadata: "invalid",
            response: "text/plain",
            allowed: false,
            content_requests: 0,
        },
        Case {
            name: "malformed response denied before bytes",
            policy: policy(&["text/*"], &[]),
            metadata: "text/plain",
            response: "*/*",
            allowed: false,
            content_requests: 1,
        },
        Case {
            name: "universal accepts malformed declarations",
            policy: Default::default(),
            metadata: "invalid",
            response: "*/plain",
            allowed: true,
            content_requests: 1,
        },
        Case {
            name: "binary octet stream is concrete",
            policy: policy(&["text/plain"], &[]),
            metadata: "text/plain",
            response: "binary/octet-stream",
            allowed: false,
            content_requests: 1,
        },
    ];
    for case in cases {
        let mut config = jira_config();
        config.attachments.download_media_types = case.policy;
        // Download admission does not inherit the upload list.
        config.attachments.upload_media_types.clear();
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".to_string(), visible_issue());
        *backend.attachments.lock().unwrap() = vec![JiraAttachment {
            id: "10055".to_string(),
            filename: "report.dat".to_string(),
            size: 4,
            content_type: case.metadata.to_string(),
        }];
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_polls = polls.clone();
        backend.attachment_content.lock().unwrap().insert(
            "10055".to_string(),
            JiraAttachmentContent {
                filename: "report.dat".to_string(),
                content_type: case.response.to_string(),
                media_type_declaration: MediaTypeDeclaration::parse(case.response),
                size: Some(4),
                sha256: None,
                stream: ProviderResultStream::from_stream(
                    case.response,
                    stream::once(async move {
                        observed_polls.fetch_add(1, Ordering::SeqCst);
                        Ok(Bytes::from_static(b"data"))
                    }),
                ),
            },
        );
        let backend = Arc::new(backend);
        let provider =
            JiraProvider::with_backend(config, ProviderLimits::default(), backend.clone());
        let result = provider.invoke_checked(download_request()).await;
        assert_eq!(result.is_ok(), case.allowed, "{}: {result:?}", case.name);
        match result {
            Ok(result) => {
                assert_eq!(result.result["contentType"], case.response, "{}", case.name);
                assert_eq!(
                    result.result["metadataContentType"], case.metadata,
                    "{}",
                    case.name
                );
                assert_eq!(
                    result.stream.unwrap().content_type,
                    case.response,
                    "{}",
                    case.name
                );
            }
            Err(error) => {
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::AttachmentMediaTypeDenied,
                    "{}",
                    case.name
                );
            }
        }
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{}", case.name);
        assert_eq!(
            backend
                .credential_observations
                .lock()
                .unwrap()
                .iter()
                .filter(|observation| observation.operation == "attachment_content")
                .count(),
            case.content_requests,
            "{}",
            case.name,
        );
    }
}

#[test]
fn download_policy_does_not_authorize_uploads_or_change_jira_metadata_shape() {
    let mut limits = AttachmentLimitsConfig::default();
    let input = AttachmentInput {
        field: "file".to_string(),
        filename: "report.txt".to_string(),
        content_type: "text/plain".to_string(),
        size: 4,
        sha256: sha256_hex(b"data"),
    };
    assert_eq!(
        validate_attachment_input(&input, &limits)
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentMediaTypeDenied
    );
    limits.upload_media_types = vec!["text/plain".to_string()];
    limits.download_media_types = policy(&[], &[]);
    validate_attachment_input(&input, &limits).unwrap();
    for value in [
        json!({"id":"10055", "filename":"report.txt", "size":4}),
        json!({"id":"10055", "filename":"report.txt", "size":4, "mimeType":null}),
        json!({"id":"10055", "filename":"report.txt", "size":4, "mimeType":1}),
    ] {
        assert!(attachment_from_value(value).is_err());
    }
}

#[test]
fn download_documentation_reports_configured_media_policy() {
    let mut config = jira_config();
    config.attachments.download_media_types =
        policy(&["image/*", "application/pdf"], &["image/svg+xml"]);
    let descriptor = config.descriptor();
    let documentation = descriptor
        .action("attachment.download")
        .unwrap()
        .documentation
        .as_ref()
        .unwrap();
    assert_eq!(
        documentation["downloadMediaTypes"]["allow"],
        json!(["image/*", "application/pdf"])
    );
    assert_eq!(
        documentation["downloadMediaTypes"]["deny"],
        json!(["image/svg+xml"])
    );
}

#[tokio::test]
async fn http_download_preserves_malformed_header_classification() {
    for (headers, malformed, displayed) in [
        (&b""[..], false, "application/octet-stream"),
        (
            &b"Content-Type: text/plain; charset=utf-8\r\n"[..],
            false,
            "text/plain; charset=utf-8",
        ),
        (
            &b"Content-Type: text/plain\r\nContent-Type: text/plain\r\n"[..],
            true,
            "text/plain",
        ),
        (
            &b"Content-Type: \x80\r\n"[..],
            true,
            "application/octet-stream",
        ),
        (&b"Content-Type: */*\r\n"[..], true, "*/*"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 16_384);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n")
                .await
                .unwrap();
            socket.write_all(headers).await.unwrap();
            socket.write_all(b"\r\ndata").await.unwrap();
        });
        let mut config = jira_config();
        config.allowed_upstream_hosts = vec![format!("http://{address}/rest/api/3/**")];
        let backend = HttpJiraBackend::new_with_api_base(
            config.clone(),
            ProviderLimits::default(),
            Url::parse(&format!("http://{address}/rest/api/3/")).unwrap(),
        );
        let response = backend
            .attachment_content(
                "10055",
                &AtlassianCredential::from_static(test_credential()),
            )
            .await
            .unwrap()
            .value;
        server.await.unwrap();
        assert_eq!(response.content_type, displayed);
        assert_eq!(response.stream.content_type, displayed);
        let attachment = JiraAttachment {
            id: "10055".to_string(),
            filename: "report.txt".to_string(),
            size: 4,
            content_type: "text/plain".to_string(),
        };
        validate_download_content(&response, &attachment, &config).unwrap();
        config.attachments.download_media_types = policy(&["text/plain"], &[]);
        let checked = validate_download_content(&response, &attachment, &config);
        assert_eq!(checked.is_err(), malformed, "{headers:?}");
        if let Err(error) = checked {
            assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);
        }
    }
}
