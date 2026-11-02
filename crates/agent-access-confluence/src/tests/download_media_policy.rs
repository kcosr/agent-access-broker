use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const ACTIONS: [&str; 4] = [
    "attachment.download",
    "blog.attachment.download",
    "page.draft.attachment.download",
    "blog.draft.attachment.download",
];

fn metadata(media_type: Option<Value>) -> ConfluenceAttachment {
    let mut value = json!({
        "id": "att123",
        "title": "notes.bin",
        "pageId": "123456",
        "extensions": {"fileSize": 4}
    });
    if let Some(media_type) = media_type {
        value["metadata"] = json!({"mediaType": media_type});
    }
    attachment_from_value(value, "123456").unwrap()
}

async fn download(
    action: &str,
    config: ConfluenceProviderConfig,
    attachment: ConfluenceAttachment,
    content_type: &str,
) -> (
    Result<ProviderResult, ProviderError>,
    usize,
    Arc<AtomicUsize>,
) {
    let polls = Arc::new(AtomicUsize::new(0));
    let stream_polls = polls.clone();
    let mut content =
        ConfluenceAttachmentContent::from_bytes("notes.bin", content_type, b"data".to_vec());
    content.stream = ProviderResultStream::from_stream(
        content_type,
        stream::once(async move {
            stream_polls.fetch_add(1, Ordering::SeqCst);
            Ok(Bytes::from_static(b"data"))
        }),
    );
    let backend = Arc::new(AttachmentDownloadBackend {
        attachment,
        content,
        content_requests: Default::default(),
    });
    let provider = ConfluenceProvider::with_backend_and_signing_key(
        config,
        ProviderLimits::default(),
        backend.clone(),
        agent_access_provider::test_support::test_signing_key(7),
    );
    let is_blog = action.starts_with("blog.");
    let mut inputs = json!({"attachmentId": "att123"});
    inputs[if is_blog { "blogId" } else { "pageId" }] = json!("123456");
    if action.contains(".draft.") {
        let kind = if is_blog {
            ConfluenceDraftContentType::Blog
        } else {
            ConfluenceDraftContentType::Page
        };
        let binding = draft_invocation(action, inputs.clone());
        inputs["draftHandle"] = json!(
            provider
                .mint_draft_handle(
                    kind,
                    &draft_content("123456", kind),
                    ConfluenceDraftOrigin::New,
                    None,
                    &binding,
                )
                .unwrap()
        );
    }
    let result = provider.invoke(draft_invocation(action, inputs)).await;
    (
        result,
        backend.content_requests.load(Ordering::SeqCst),
        polls,
    )
}

async fn read_download(result: ProviderResult) -> Vec<u8> {
    match result.stream.unwrap().source {
        ProviderResultStreamSource::Memory(bytes) => bytes,
        ProviderResultStreamSource::Stream(stream) => {
            let mut stream = stream.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
    }
}

#[tokio::test]
async fn all_attachment_download_variants_default_to_all_and_keep_uploads_disabled() {
    for action in ACTIONS {
        for (declared, response) in [
            ("application/pdf", "application/octet-stream"),
            ("application/pdf", "text/plain"),
            ("invalid", "image/*"),
            ("", "application/octet-stream"),
        ] {
            let config = confluence_config();
            assert!(config.attachments.upload_media_types.is_empty());
            let (result, requests, polls) =
                download(action, config, metadata(Some(json!(declared))), response).await;
            let result = result.unwrap_or_else(|error| panic!("{action} {declared}: {error:?}"));
            assert_eq!(requests, 1, "{action}");
            assert_eq!(polls.load(Ordering::SeqCst), 0, "{action}");
            assert_eq!(read_download(result).await, b"data", "{action}");
            assert_eq!(polls.load(Ordering::SeqCst), 1, "{action}");
        }
    }
}

#[tokio::test]
async fn all_attachment_download_variants_enforce_policy_at_metadata_and_response_stages() {
    for action in ACTIONS {
        let mut config = confluence_config();
        config.attachments.download_media_types.deny = vec!["application/pdf".into()];
        let (result, requests, polls) = download(
            action,
            config,
            metadata(Some(json!("application/pdf"))),
            "application/octet-stream",
        )
        .await;
        assert_eq!(
            result.unwrap_err().reason_code(),
            ReasonCode::AttachmentMediaTypeDenied
        );
        assert_eq!(
            requests, 0,
            "{action}: denied metadata must not fetch content"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);

        let mut config = confluence_config();
        config.attachments.download_media_types.allow.clear();
        let (result, requests, _) = download(action, config, metadata(None), "text/plain").await;
        assert_eq!(
            result.unwrap_err().reason_code(),
            ReasonCode::AttachmentMediaTypeDenied
        );
        assert_eq!(
            requests, 0,
            "{action}: deny-all applies before unknown content fetch"
        );

        let mut config = confluence_config();
        config.attachments.download_media_types.deny = vec!["image/*".into()];
        let (result, requests, polls) = download(
            action,
            config,
            metadata(Some(json!("text/plain"))),
            "image/svg+xml",
        )
        .await;
        assert_eq!(
            result.unwrap_err().reason_code(),
            ReasonCode::AttachmentMediaTypeDenied
        );
        assert_eq!(requests, 1, "{action}");
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "{action}: denied body must not be read"
        );

        let mut config = confluence_config();
        config.attachments.download_media_types.allow = vec!["text/*".into()];
        config.attachments.download_media_types.deny = vec!["application/octet-stream".into()];
        let (result, _, _) = download(
            action,
            config,
            metadata(Some(json!("TEXT/PLAIN; charset=UTF-8"))),
            "application/octet-stream",
        )
        .await;
        assert_eq!(read_download(result.unwrap()).await, b"data", "{action}");
    }
}

#[test]
fn metadata_fallback_preserves_malformed_classification_without_changing_json_shape() {
    let restricted = MediaTypePolicyConfig {
        allow: vec!["text/*".into()],
        deny: vec![],
    };
    for (value, malformed, displayed) in [
        (None, false, "application/octet-stream"),
        (Some(Value::Null), false, "application/octet-stream"),
        (Some(json!("")), false, "application/octet-stream"),
        (Some(json!("invalid")), true, "application/octet-stream"),
        (Some(json!(42)), true, "application/octet-stream"),
        (Some(json!({})), true, "application/octet-stream"),
        (Some(json!("image/*")), true, "image/*"),
        (
            Some(json!("application/octet-stream")),
            false,
            "application/octet-stream",
        ),
    ] {
        let attachment = metadata(value);
        assert_eq!(attachment.content_type, displayed);
        let serialized = serde_json::to_value(&attachment).unwrap();
        assert_eq!(
            serialized,
            json!({
                "id": "att123", "pageId": "123456", "filename": "notes.bin",
                "size": 4, "contentType": displayed
            })
        );
        let declaration = attachment_media_type_declaration(&attachment);
        assert_eq!(
            restricted
                .check_download(&declaration, &MediaTypeDeclaration::parse("text/plain"))
                .is_err(),
            malformed,
        );
        assert!(
            MediaTypePolicyConfig::default()
                .check_download(&declaration, &MediaTypeDeclaration::parse("text/plain"))
                .is_ok()
        );
    }
}

#[test]
fn download_policy_and_exact_upload_policy_are_independent() {
    let mut config = confluence_config();
    let input = AttachmentInput {
        field: "file".into(),
        filename: "notes.txt".into(),
        content_type: "text/plain".into(),
        size: 4,
        sha256: sha256_hex(b"data"),
    };
    let attachment = metadata(Some(json!("application/pdf")));
    assert_eq!(
        validate_attachment_input(&input, &config.attachments)
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentMediaTypeDenied
    );
    assert!(validate_download_attachment(&attachment, &config).is_ok());

    config.attachments.upload_media_types = vec!["text/plain".into()];
    config.attachments.download_media_types.allow.clear();
    assert!(validate_attachment_input(&input, &config.attachments).is_ok());
    assert_eq!(
        validate_download_attachment(&attachment, &config)
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentMediaTypeDenied
    );
    let mut differently_cased = input;
    differently_cased.content_type = "TEXT/PLAIN".into();
    assert!(validate_attachment_input(&differently_cased, &config.attachments).is_err());
}

#[tokio::test]
async fn http_download_variants_preserve_malformed_response_headers_for_policy() {
    for action in ACTIONS {
        for (kind, malformed) in [
            ("missing", false),
            ("wildcard", true),
            ("duplicate", true),
            ("nontext", true),
        ] {
            let server = MockServer::start().await;
            let template = ResponseTemplate::new(200).set_body_bytes(b"data");
            let template = match kind {
                "missing" => template,
                "wildcard" => template.insert_header("Content-Type", "image/*"),
                "duplicate" => template
                    .append_header("Content-Type", "text/plain")
                    .append_header("Content-Type", "text/html"),
                "nontext" => template.insert_header(
                    "Content-Type",
                    reqwest::header::HeaderValue::from_bytes(b"text/\xff").unwrap(),
                ),
                _ => unreachable!(),
            };
            Mock::given(method("GET"))
                .and(path(
                    "/wiki/rest/api/content/123456/child/attachment/att123/download",
                ))
                .respond_with(template)
                .mount(&server)
                .await;
            let backend = http_confluence_backend_for_server(&server);
            let credential = AtlassianCredential::from_static(credential());
            let response = match action {
                "attachment.download" => {
                    backend
                        .attachment_content("123456", "att123", &credential)
                        .await
                }
                "blog.attachment.download" => {
                    backend
                        .blog_attachment_content("123456", "att123", &credential)
                        .await
                }
                "page.draft.attachment.download" => {
                    backend
                        .page_draft_attachment_content("123456", "att123", &credential)
                        .await
                }
                "blog.draft.attachment.download" => {
                    backend
                        .blog_draft_attachment_content("123456", "att123", &credential)
                        .await
                }
                _ => unreachable!(),
            }
            .unwrap_or_else(|error| panic!("{action} {kind}: {error:?}"));
            let restrictive = MediaTypePolicyConfig {
                allow: vec!["text/*".into()],
                deny: vec![],
            };
            assert_eq!(
                restrictive
                    .check_download(
                        &MediaTypeDeclaration::parse("text/plain"),
                        &response.value.media_type_declaration
                    )
                    .is_err(),
                malformed,
                "{action} {kind}",
            );
            assert!(
                MediaTypePolicyConfig::default()
                    .check_download(
                        &MediaTypeDeclaration::parse("text/plain"),
                        &response.value.media_type_declaration
                    )
                    .is_ok()
            );
        }
    }
}

#[test]
fn download_documentation_reports_effective_policy_on_all_download_actions() {
    let mut config = confluence_config();
    config.attachments.download_media_types = MediaTypePolicyConfig {
        allow: vec!["image/*".into()],
        deny: vec!["image/svg+xml".into()],
    };
    let descriptor = confluence_descriptor(&config);
    for action in &descriptor.actions {
        let policy = action
            .documentation
            .as_ref()
            .and_then(|doc| doc.get("downloadMediaTypes"));
        assert_eq!(
            policy.is_some(),
            ACTIONS.contains(&action.action.as_str()),
            "{}",
            action.action
        );
        if let Some(policy) = policy {
            assert_eq!(policy["allow"], json!(["image/*"]));
            assert_eq!(policy["deny"], json!(["image/svg+xml"]));
            assert!(
                policy["matching"]
                    .as_str()
                    .unwrap()
                    .contains("Every concrete")
            );
        }
    }
}
